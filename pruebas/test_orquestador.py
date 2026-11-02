"""Pruebas del orquestador (#22) sin red: TXT simulado y el recolector `ejemplo` con su respuesta grabada.

Necesitan psycopg y dnspython, así que corren dentro del contenedor de la API, con la base levantada:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_orquestador.py

Cada prueba corre en una transacción que se deshace al final: la base queda igual. Nunca consultan
en vivo los dominios de la demo (acme-demo.mx no es del equipo).

Las del límite diario por fuente (#13b, RC-184) piden la migración 008 y la semilla 005 aplicadas. En una base nueva
las carga db/init/cargar_cirdan.sh con el resto (en las pruebas aisladas, al levantar la pila con stack.sh up). La
del cambio de día entra como postgres para poner daily_used_on en ayer y se salta si el contenedor no tiene
POSTGRES_PASSWORD. Para correrla, agrega -e POSTGRES_PASSWORD al docker compose run de arriba, con la variable
exportada antes en la terminal (sin escribir su valor en el comando).
"""
import contextlib
import io
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import psycopg
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from cirdan import orquestador
from cirdan.config import config
from cirdan.db import DSN
from cirdan.orquestador import __main__ as cli
from cirdan.orquestador.txt import ConsultaTxt
from cirdan.recolectores import certspotter, crtsh, ejemplo, github, shodan
from cirdan.recolectores.contrato import Activo, Hallazgo, Resultado
from pruebas.test_certspotter import AHORA, RespaldoSimulado
from pruebas.test_crtsh import SUBDOMINIOS, CrtshSimulado

ACME = '20000000-0000-4000-8000-000000000001'
BETA = '20000000-0000-4000-8000-000000000002'
TXT_ACME = 'cirdan-verification=c41d7e2a9b06'   # token de acme-demo.mx en la semilla


class DnsSimulado:
    """Reemplaza la consulta DNS y anota si se llamó."""

    def __init__(self, consulta):
        self.consulta = consulta
        self.llamadas = []

    def __call__(self, fqdn):
        self.llamadas.append(fqdn)
        return self.consulta


def responde(*valores):
    return DnsSimulado(ConsultaTxt(tuple(valores)))


# Resultados de una corrida, para probar los reintentos sin recolector ni red
FALLA = SimpleNamespace(estado='failed', activos=[], hallazgos=[], consultas=1, avisos=[], sin_cobertura=[],
                        error='crt.sh no respondió')
BIEN = Resultado('acme-demo.mx', 'ejemplo', activos=[Activo('domain', 'acme-demo.mx'),
                                                     Activo('subdomain', 'www.acme-demo.mx')], consultas=1)

# Hallazgos armados con las funciones de cada recolector. Las pruebas de test_github.py y test_shodan.py, que no
# entran al contenedor (leen docs/ y db/), revisan que una corrida parcial dé estas partes y estos revisados.
def resultado_github(*hallazgos, revisados=None, sin_revisar=None):
    """Como github.recolectar: con la cobertura parcial, los códigos sin hallazgos van a sin_cobertura."""
    activos = [Activo('domain', 'acme-demo.mx')] + [Activo('email', h.activo) for h in hallazgos
                                                    if h.codigo == 'email_in_public_commits']
    sin_cobertura = [] if revisados is None else [c for c in github.CODIGOS if c not in {h.codigo for h in hallazgos}]
    return Resultado('acme-demo.mx', 'github', activos=activos, hallazgos=list(hallazgos), sin_cobertura=sin_cobertura,
                     revisados=revisados, sin_revisar=sin_revisar)


def secreto(repo, ruta):
    return github.hallazgo_secreto('acme-demo.mx', 'acme-demo/' + repo, {'ruta': ruta, 'regla': 'cirdan-fake-token',
                                                                         'primera_vez': '2026-09-01T12:00:00Z'}, AHORA)


def correo(usuario, *repos):
    datos = {'repos': ['acme-demo/' + r for r in repos], 'commits': 1, 'primera_vez': '2026-09-01T12:00:00Z'}
    return github.hallazgo_correo(usuario + '@acme-demo.mx', datos, AHORA)


def resultado_shodan(*puertos, revisados=None, sin_revisar=None, cves=(), omitidos=()):
    """Un resultado de Shodan con un hallazgo por (ip, puerto), sobre su activo service, y uno por (ip, CVE). omitidos son
    (ip, CVE) que el tope MAX_CVE dejó fuera. Como shodan.recolectar, SIN_LLAVE va siempre a sin_cobertura y, con la
    cobertura parcial, también los códigos sin hallazgos."""
    hosts, datos = ['acme-demo.mx'], {'tags': [], 'hostnames_ajenos': 0, 'cpes': []}
    res = Resultado('acme-demo.mx', 'shodan', revisados=revisados, sin_revisar=sin_revisar,
                    omitidos=[shodan.hallazgo_cve('acme-demo.mx', ip, cve, hosts, datos, AHORA).huella
                              for ip, cve in omitidos])
    for ip in sorted({ip for ip, _ in puertos} | {ip for ip, _ in cves}):
        res.activos.append(Activo('ip', ip, {'hosts': hosts}))
    res.hallazgos += [shodan.hallazgo_cve('acme-demo.mx', ip, cve, hosts, datos, AHORA) for ip, cve in cves]
    for ip, puerto in puertos:
        servicio = '%s:%d/tcp' % (ip, puerto)
        res.activos.append(Activo('service', servicio, {'hosts': hosts, 'parent': ip, 'ip_address': ip}))
        res.hallazgos.append(shodan.hallazgo_puerto(shodan.codigo_de_puerto(puerto), 'acme-demo.mx', servicio, ip,
                                                    puerto, hosts, datos, AHORA))
    con_hallazgos = {h.codigo for h in res.hallazgos}
    res.sin_cobertura = [] if revisados is None else [c for c in shodan.CODIGOS if c not in con_hallazgos]
    res.sin_cobertura += list(shodan.SIN_LLAVE)
    return res


# El día del límite diario, como lo calculan reserve_source_quota() y adjust_source_quota() (migración 008)
HOY_UTC = "(now() AT TIME ZONE 'UTC')::date"


def conexion_postgres():
    """Conexión como postgres, solo para preparar lo que cirdan_app no puede escribir. Sin la clave, la prueba se salta."""
    clave = config('POSTGRES_PASSWORD')
    if not clave:
        raise unittest.SkipTest('falta POSTGRES_PASSWORD: agrégala con -e POSTGRES_PASSWORD al docker compose run')
    return psycopg.connect(make_conninfo(host=config('PGHOST', '127.0.0.1'), port=config('PGPORT', '5433'),
                                         dbname=config('PGDATABASE', 'cirdan'), user=config('POSTGRES_USER', 'postgres'),
                                         password=clave), row_factory=dict_row)


class Orquestador(unittest.TestCase):

    def setUp(self):
        self.conn = psycopg.connect(DSN, row_factory=dict_row)
        self.tx = self.conn.transaction(force_rollback=True)
        self.tx.__enter__()
        self.conn.execute("SELECT set_config('app.current_org', %s, true)", (ACME,))

    def tearDown(self):
        self.tx.__exit__(None, None, None)
        self.conn.close()

    def solicitar(self, fqdn, dns, conn=None):
        return orquestador.solicitar(ACME, fqdn, consultar=dns, conn=conn or self.conn)

    def uno(self, sql, *params):
        return self.conn.execute(sql, params).fetchone()

    def en_vivo(self, s, resultados, dormir, fuentes=('ejemplo',), conn=None):
        """Corre `ejemplo` (u otras fuentes) en vivo con estos resultados seguidos, sin red ni esperas reales."""
        seguidos = iter(resultados)

        def siguiente(*a, **k):  # un resultado o una función que hace algo mientras la fuente corre
            r = next(seguidos)
            return r() if callable(r) else r
        with mock.patch.object(orquestador, 'ejecutar', siguiente), \
                mock.patch.object(orquestador, 'en_vivo_permitido', lambda fqdn: True):
            return orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=list(fuentes), conn=conn or self.conn,
                                      dormir=dormir)

    def corrida(self, scan_id):
        return self.uno('SELECT status, attempt, next_retry_at, error FROM scan_source_runs WHERE scan_id = %s', scan_id)

    def corrida_de(self, scan_id, codigo):
        return self.uno('SELECT r.status, r.attempt, r.next_retry_at, r.error, r.raw_payload FROM scan_source_runs r '
                        'JOIN data_sources d ON d.id = r.source_id WHERE r.scan_id = %s AND d.code = %s', scan_id, codigo)

    def cupo(self, codigo, conn=None):
        """(límite, usadas hoy en UTC, día guardado) de una fuente. Un día guardado anterior a hoy cuenta como 0 usadas."""
        f = (conn or self.conn).execute(
            'SELECT daily_limit, CASE WHEN daily_used_on >= %s THEN daily_used ELSE 0 END AS usadas, daily_used_on '
            'FROM data_sources WHERE code = %%s' % HOY_UTC, (codigo,)).fetchone()
        return f['daily_limit'], f['usadas'], f['daily_used_on']

    def exige_cupo(self, codigo, consultas):
        """Una prueba en vivo reserva cupo real, aunque se deshaga al final: si esta base ya no lo tiene hoy, que lo diga."""
        limite, usadas, _ = self.cupo(codigo)
        self.assertTrue(limite is None or usadas + consultas <= limite, '%s ya no tiene cupo hoy en esta base' % codigo)
        return limite, usadas

    # --------------------------------------------------------------------- acepta

    def test_1_acepta_con_autorizacion_vigente_y_txt_verificado(self):
        s = self.solicitar('acme-demo.mx', responde('v=spf1 -all', TXT_ACME))
        self.assertTrue(s.aceptada, s.detalle)
        self.assertEqual(s.txt, 'match')
        scan = self.uno('SELECT status, txt_verification_id::text FROM scans WHERE id = %s', s.scan_id)
        self.assertEqual(scan['status'], 'running')
        evidencia = self.uno('SELECT check_reason, result, observed_values FROM dns_txt_verifications WHERE id = %s',
                             scan['txt_verification_id'])
        self.assertEqual((evidencia['check_reason'], evidencia['result']), ('pre_scan', 'match'))
        self.assertIn(TXT_ACME, evidencia['observed_values'])

    def test_2_corre_el_recolector_grabado_y_cierra_el_escaneo(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        resumen = orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ejemplo'], modo='reproducir', conn=self.conn)
        self.assertEqual(resumen['status'], 'completed')
        self.assertEqual(resumen['stats'], {'assets': 2, 'findings': 1, 'new_findings': 1, 'resolved_findings': 0,
                                            'sources_ok': 1, 'sources_failed': 0})
        run = self.uno('SELECT r.status, r.attempt, r.raw_payload FROM scan_source_runs r WHERE r.scan_id = %s', s.scan_id)
        self.assertEqual((run['status'], run['attempt']), ('succeeded', 0))
        self.assertEqual(run['raw_payload']['hallazgos'], 1)
        self.assertEqual(self.uno('SELECT status FROM scans WHERE id = %s', s.scan_id)['status'], 'completed')
        score = self.uno('SELECT id::text, score, category_scores, partial_coverage FROM domain_scores WHERE scan_id = %s',
                 s.scan_id)
        self.assertIsNotNone(score)
        self.assertFalse(score['partial_coverage'])
        self.assertTrue(0 <= score['score'] <= 100)
        self.assertIn('configuration', score['category_scores'])
        aportes = self.uno('SELECT count(*) AS n FROM score_contributions WHERE score_id = %s', score['id'])['n']
        hallazgos_vigentes = self.uno("SELECT count(*) AS n FROM findings WHERE domain_id = %s "
                          "AND status IN ('open', 'accepted_risk')", s.domain_id)['n']
        self.assertEqual(aportes, hallazgos_vigentes)

        conteo_activos = self.uno('SELECT count(*) AS n FROM assets WHERE domain_id = %s', s.domain_id)['n']
        conteo_hallazgos = self.uno('SELECT count(*) AS n FROM findings WHERE domain_id = %s', s.domain_id)['n']
        self.conn.execute("UPDATE findings SET status = 'resolved', resolved_at = now() WHERE domain_id = %s "
                  "AND rule_id = (SELECT id FROM scoring_rules WHERE code = 'spf_missing' "
                  "AND rule_set_id = '90000000-0000-4000-8000-000000000001')", (s.domain_id,))
        repetido = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        orquestador.correr(ACME, repetido.scan_id, 'acme-demo.mx', fuentes=['ejemplo'], modo='reproducir', conn=self.conn)
        self.assertEqual(self.uno('SELECT count(*) AS n FROM assets WHERE domain_id = %s', s.domain_id)['n'], conteo_activos)
        self.assertEqual(self.uno('SELECT count(*) AS n FROM findings WHERE domain_id = %s', s.domain_id)['n'], conteo_hallazgos)
        self.assertEqual(self.uno("SELECT status FROM findings WHERE domain_id = %s AND rule_id = "
                      "(SELECT id FROM scoring_rules WHERE code = 'spf_missing' "
                      "AND rule_set_id = '90000000-0000-4000-8000-000000000001')",
                      s.domain_id)['status'], 'open')

    # --------------------------------------------------------------------- guardar el escaneo (#23)

    def escanear_ejemplo(self):
        """Un escaneo con la grabación de `ejemplo`: deja abierto su spf_missing. Devuelve la solicitud y el hallazgo."""
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ejemplo'], modo='reproducir', conn=self.conn)
        f = self.uno("SELECT f.id::text, f.status FROM findings f JOIN data_sources d ON d.id = f.source_id "
                     "WHERE f.domain_id = %s AND d.code = 'ejemplo'", s.domain_id)
        self.assertEqual(f['status'], 'open')
        return s, f

    def reescanear(self, resultado, fuente='ejemplo'):
        """Otro escaneo de acme-demo.mx en el que `fuente` responde con este resultado."""
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        with mock.patch.object(orquestador, 'ejecutar', lambda *a, **k: resultado):
            return s, orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=[fuente], modo='reproducir',
                                         conn=self.conn)

    def estado(self, finding_id):
        return self.uno('SELECT status, resolved_at, last_scan_id::text FROM findings WHERE id = %s', finding_id)

    def test_2b_lo_que_la_fuente_ya_no_encuentra_queda_resuelto_y_deja_de_sumar(self):
        _, f = self.escanear_ejemplo()
        s, _ = self.reescanear(BIEN)  # `ejemplo` respondió bien y ya no trae el hallazgo
        estado = self.estado(f['id'])
        self.assertEqual(estado['status'], 'resolved')
        self.assertIsNotNone(estado['resolved_at'])
        self.assertEqual(estado['last_scan_id'], s.scan_id)
        score = self.uno('SELECT id::text FROM domain_scores WHERE scan_id = %s', s.scan_id)
        self.assertIsNone(self.uno('SELECT 1 FROM score_contributions WHERE score_id = %s AND finding_id = %s',
                                   score['id'], f['id']))

    def test_2c_un_codigo_sin_cobertura_no_se_da_por_resuelto(self):
        _, f = self.escanear_ejemplo()
        self.reescanear(Resultado(**dict(vars(BIEN), sin_cobertura=['spf_missing'])))
        self.assertEqual(self.estado(f['id'])['status'], 'open')

    def test_2d_una_fuente_que_falla_no_resuelve_nada(self):
        _, f = self.escanear_ejemplo()
        self.reescanear(FALLA)
        self.assertEqual(self.estado(f['id'])['status'], 'open')

    def test_2e_riesgo_aceptado_y_falso_positivo_no_cambian(self):
        _, f = self.escanear_ejemplo()
        for decision in ('accepted_risk', 'false_positive'):
            self.conn.execute('UPDATE findings SET status = %s WHERE id = %s', (decision, f['id']))
            self.reescanear(BIEN)
            self.assertEqual(self.estado(f['id'])['status'], decision)

    def test_2f_las_caracteristicas_del_reto_quedan_en_la_evidencia(self):
        _, f = self.escanear_ejemplo()
        evidencia = self.uno('SELECT evidence FROM findings WHERE id = %s', f['id'])['evidence']
        self.assertEqual(set(evidencia['caracteristicas']), {'tipo', 'antiguedad_dias', 'exposicion', 'sensibilidad'})

    def test_2g_un_hallazgo_sin_su_activo_va_en_el_dominio_y_no_tumba_el_escaneo(self):
        caracteristicas = {'tipo': 'spf_ausente', 'antiguedad_dias': 0, 'exposicion': 'publica', 'sensibilidad': 'baja'}
        huerfano = Hallazgo('spf_missing', 'medium', 'nadie.acme-demo.mx', 'Sin SPF', {'title': 'Sin SPF'},
                            caracteristicas, 'ab' * 32)
        s, resumen = self.reescanear(Resultado(**dict(vars(BIEN), hallazgos=[huerfano])))
        self.assertEqual(resumen['status'], 'completed')
        f = self.uno("SELECT a.asset_type, a.value, f.evidence FROM findings f JOIN assets a ON a.id = f.asset_id "
                     "WHERE f.fingerprint = %s", bytes.fromhex('ab' * 32))
        self.assertEqual((f['asset_type'], f['value']), ('domain', 'acme-demo.mx'))
        self.assertEqual(f['evidence']['activo_no_encontrado'], 'nadie.acme-demo.mx')
        self.assertEqual(f['evidence']['caracteristicas'], caracteristicas)

    def conteos(self, scan_id):
        """(new_findings, resolved_findings) como quedaron en scans.stats, de donde los lee el histórico de la API v1."""
        stats = self.uno('SELECT stats FROM scans WHERE id = %s', scan_id)['stats']
        return stats['new_findings'], stats['resolved_findings']

    def con_spf(self, finding_id):
        """Una respuesta de `ejemplo` que vuelve a dar este hallazgo: la misma huella."""
        huella = self.uno("SELECT encode(fingerprint, 'hex') AS h FROM findings WHERE id = %s", finding_id)['h']
        spf = Hallazgo('spf_missing', 'medium', 'acme-demo.mx', 'Sin SPF', {'title': 'Sin SPF'},
                       {'tipo': 'spf_ausente', 'antiguedad_dias': 0, 'exposicion': 'publica', 'sensibilidad': 'baja'},
                       huella)
        return Resultado(**dict(vars(BIEN), hallazgos=[spf]))

    def test_2h_stats_cuenta_lo_que_el_escaneo_abre_y_lo_que_resuelve(self):
        """new_findings son los hallazgos que el escaneo inserta o reabre, y resolved_findings los que resuelve (RC-55)."""
        s, f = self.escanear_ejemplo()
        self.assertEqual(self.conteos(s.scan_id), (1, 0))  # spf_missing sale por primera vez
        s, _ = self.escanear_ejemplo()
        self.assertEqual(self.conteos(s.scan_id), (0, 0))  # ya estaba abierto
        s, _ = self.reescanear(BIEN)
        self.assertEqual(self.conteos(s.scan_id), (0, 1))
        s, _ = self.reescanear(self.con_spf(f['id']))
        self.assertEqual(self.conteos(s.scan_id), (1, 0))  # estaba resuelto y se reabre
        self.assertEqual(self.estado(f['id'])['status'], 'open')

    def test_2i_no_cuentan_la_fuente_caida_sin_cobertura_ni_lo_que_decidio_el_cliente(self):
        _, f = self.escanear_ejemplo()
        for resultado in (FALLA, Resultado(**dict(vars(BIEN), sin_cobertura=['spf_missing']))):
            s, _ = self.reescanear(resultado)
            self.assertEqual(self.conteos(s.scan_id), (0, 0))
        for decision in ('accepted_risk', 'false_positive'):
            self.conn.execute('UPDATE findings SET status = %s WHERE id = %s', (decision, f['id']))
            for resultado in (BIEN, self.con_spf(f['id'])):  # ni se resuelve ni se reabre
                s, _ = self.reescanear(resultado)
                self.assertEqual(self.conteos(s.scan_id), (0, 0))
            self.assertEqual(self.estado(f['id'])['status'], decision)

    def test_2j_lo_que_una_fuente_resuelve_y_otra_reabre_en_el_mismo_escaneo_no_cuenta(self):
        # Hoy dos fuentes no dan la misma huella y esto no pasa. Se simula con `ct_logs` dando la huella de `ejemplo`.
        _, f = self.escanear_ejemplo()
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        respuestas = iter([BIEN, self.con_spf(f['id'])])  # `ejemplo` ya no lo da y luego `ct_logs` sí
        with mock.patch.object(orquestador, 'ejecutar', lambda *a, **k: next(respuestas)):
            resumen = orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ejemplo', 'ct_logs'], modo='reproducir',
                                         conn=self.conn)
        self.assertEqual([r['status'] for r in resumen['sources']], ['succeeded', 'succeeded'])
        self.assertEqual(self.conteos(s.scan_id), (0, 0))  # empezó abierto y terminó abierto
        self.assertEqual(self.estado(f['id'])['status'], 'open')

    def test_2k_guarda_los_hallazgos_con_el_candado_de_su_empresa(self):
        """Dos escaneos de la misma empresa guardan sus hallazgos de uno en uno, así el segundo no cuenta como nuevo lo
        que insertó el primero. Otra empresa no espera (RC-55)."""
        self.escanear_ejemplo()  # el candado sigue tomado hasta que termina la transacción de la prueba
        otra = psycopg.connect(DSN, autocommit=True)
        self.addCleanup(otra.close)
        intentar = 'SELECT pg_try_advisory_xact_lock(hashtext(%s), hashtext(%s))'
        self.assertFalse(otra.execute(intentar, (orquestador.CANDADO_HALLAZGOS, ACME)).fetchone()[0])
        self.assertTrue(otra.execute(intentar, (orquestador.CANDADO_HALLAZGOS, BETA)).fetchone()[0])

    def abiertos(self, campo, *hallazgos):
        """{valor de evidence[campo]: estado} de esos hallazgos. Solo los de la prueba: la base puede traer otros."""
        filas = self.conn.execute('SELECT evidence->>%s AS valor, status FROM findings WHERE fingerprint = ANY(%s)',
                                  (campo, [bytes.fromhex(h.huella) for h in hallazgos])).fetchall()
        return {f['valor']: f['status'] for f in filas}

    def sin_partes(self, *hallazgos):
        """Como lo guardado antes de evidence.partes."""
        self.conn.execute("UPDATE findings SET evidence = evidence - 'partes' WHERE fingerprint = ANY(%s)",
                          ([bytes.fromhex(h.huella) for h in hallazgos],))

    def partes(self, hallazgo):
        return self.uno("SELECT evidence->'partes' AS p FROM findings WHERE fingerprint = %s",
                        bytes.fromhex(hallazgo.huella))['p']

    def test_2l_un_repo_que_no_se_pudo_clonar_no_cierra_sus_secretos(self):
        """GitHub revisó sitio pero no clonó api (#23): el secreto de api sigue abierto aunque su código traiga otros
        hallazgos, y el escaneo queda parcial. Lo que ya no sale de sitio, que sí se revisó, se cierra, y también el
        correo que solo salió en sitio, aunque su código quedó en sin_cobertura: con revisados deciden las partes. El
        correo que también salió en api sigue abierto."""
        api, sitio, viejo = secreto('api', 'config/.env'), secreto('sitio', 'web/.env'), secreto('sitio', 'web/viejo.env')
        de_sitio, de_los_dos = correo('ana', 'sitio'), correo('luis', 'api', 'sitio')
        _, resumen = self.reescanear(resultado_github(api, sitio, viejo, de_sitio, de_los_dos), 'github')
        self.assertEqual(resumen['status'], 'completed')
        self.assertEqual(self.uno("SELECT evidence->'partes' AS p FROM findings WHERE fingerprint = %s",
                                  bytes.fromhex(api.huella))['p'], ['acme-demo/api'])
        s, resumen = self.reescanear(resultado_github(sitio, revisados=['acme-demo/sitio']), 'github')
        self.assertEqual(self.abiertos('ruta', api, sitio, viejo),
                         {'config/.env': 'open', 'web/.env': 'open', 'web/viejo.env': 'resolved'})
        self.assertEqual([self.abiertos('title', h).popitem()[1] for h in (de_sitio, de_los_dos)], ['resolved', 'open'])
        self.assertEqual((resumen['status'], resumen['stats']['sources_partial']), ('partial', ['github']))
        self.assertEqual(resumen['stats']['rules_without_coverage'], ['email_in_public_commits'])   # sin hallazgos
        self.assertTrue(resumen['sources'][0]['cobertura_parcial'])
        self.assertTrue(self.uno('SELECT partial_coverage FROM domain_scores WHERE scan_id = %s',
                                 s.scan_id)['partial_coverage'])
        s, resumen = self.reescanear(resultado_github(sitio), 'github')  # una corrida completa sí lo cierra
        self.assertEqual(self.abiertos('ruta', api, sitio, viejo),
                         {'config/.env': 'resolved', 'web/.env': 'open', 'web/viejo.env': 'resolved'})
        self.assertEqual(resumen['status'], 'completed')
        self.assertNotIn('sources_partial', resumen['stats'])

    def test_2m_con_todos_los_repos_conocidos_se_cierra_lo_de_un_repo_que_ya_no_esta(self):
        """Con sin_revisar GitHub sabe cuáles son todos sus repos (#23): lo de un repo borrado o que se hizo privado se
        cierra aunque la corrida sea parcial, y lo de api, que existe y no se revisó, sigue abierto. Sin ningún hallazgo
        los dos códigos van a sin_cobertura y deciden las partes: el último secreto de sitio también se cierra."""
        api, borrado, sitio = secreto('api', 'config/.env'), secreto('borrado', 'a.env'), secreto('sitio', 'web/.env')
        de_borrado, de_api = correo('ana', 'borrado', 'sitio'), correo('luis', 'api', 'borrado')
        self.reescanear(resultado_github(api, borrado, sitio, de_borrado, de_api), 'github')
        s, resumen = self.reescanear(resultado_github(sitio, revisados=['acme-demo/sitio'],
                                                      sin_revisar=['acme-demo/api']), 'github')
        self.assertEqual(self.abiertos('ruta', api, borrado, sitio),
                         {'config/.env': 'open', 'a.env': 'resolved', 'web/.env': 'open'})
        self.assertEqual([self.abiertos('title', h).popitem()[1] for h in (de_borrado, de_api)], ['resolved', 'open'])
        self.assertEqual(resumen['status'], 'partial')
        self.reescanear(resultado_github(revisados=['acme-demo/sitio'], sin_revisar=['acme-demo/api']), 'github')
        self.assertEqual(self.abiertos('ruta', api, borrado, sitio),
                         {'config/.env': 'open', 'a.env': 'resolved', 'web/.env': 'resolved'})
        self.assertEqual(self.abiertos('title', de_api).popitem()[1], 'open')

    def test_2n_una_ip_sin_respuesta_de_internetdb_no_cierra_sus_puertos(self):
        """Shodan revisó ip_b pero ip_a no respondió (#23): los hallazgos de ip_a siguen abiertos aunque su código
        traiga otros, y el escaneo queda parcial. Lo que ya no sale de ip_b, que sí se revisó, se cierra. Con
        sin_revisar se cierra lo de ip_c, que ya no resuelve, y siguen las CVE de ip_b, que esta vez no se revisaron
        completas (por ejemplo, con 'vulns' roto)."""
        ip_a, ip_b, ip_c = '20.69.154.199', '40.65.94.253', '40.65.94.254'
        cve_b = ('CVE-2024-0001', 'CVE-2024-0002')
        antes = resultado_shodan((ip_a, 3389), (ip_b, 3389), (ip_b, 8081), (ip_b, 9000), (ip_c, 3389),
                                 cves=[(ip_b, c) for c in cve_b])
        self.reescanear(antes, 'shodan')
        rdp, servicios, cves = ([h for h in antes.hallazgos if h.codigo == c]
                                for c in ('exposed_rdp', 'exposed_service', 'known_vulnerability'))
        s, resumen = self.reescanear(resultado_shodan((ip_b, 3389), (ip_b, 8081), revisados=[ip_b]), 'shodan')
        self.assertEqual(self.abiertos('ip', *rdp), {ip_a: 'open', ip_b: 'open', ip_c: 'open'})
        self.assertEqual(self.abiertos('puerto', *servicios), {'8081': 'open', '9000': 'resolved'})
        self.assertEqual(self.abiertos('cve', *cves), dict.fromkeys(cve_b, 'open'))
        self.assertEqual((resumen['status'], resumen['stats']['sources_partial']), ('partial', ['shodan']))
        self.reescanear(resultado_shodan((ip_b, 3389), (ip_b, 8081), revisados=[ip_b],
                                         sin_revisar=[ip_a, ip_a + '/cve', ip_b + '/cve'], cves=[(ip_b, cve_b[0])]),
                        'shodan')
        self.assertEqual(self.abiertos('ip', *rdp), {ip_a: 'open', ip_b: 'open', ip_c: 'resolved'})
        self.assertEqual(self.abiertos('cve', *cves), dict.fromkeys(cve_b, 'open'))

    def test_2o_lo_guardado_sin_partes_las_saca_de_su_evidencia(self):
        """Lo guardado antes de evidence.partes (#23): el secreto las saca de 'repo', el puerto de 'ip', la CVE de 'ip'
        con '/cve' y el correo de 'repos', este solo si no se cortó en MAX_REPOS_ACTIVO. Lo de otra fuente que no
        trae partes no se cierra con la cobertura parcial."""
        self.assertIn('< %d ' % github.MAX_REPOS_ACTIVO, orquestador.PARTES)
        api, borrado = secreto('api', 'config/.env'), secreto('borrado', 'a.env')
        cinco = ['r%d' % i for i in range(github.MAX_REPOS_ACTIVO)]
        de_borrado, cortado = correo('ana', 'borrado'), correo('luis', *cinco)
        self.reescanear(resultado_github(api, borrado, de_borrado, cortado), 'github')
        self.sin_partes(api, borrado, de_borrado, cortado)
        self.reescanear(resultado_github(revisados=[], sin_revisar=['acme-demo/api', 'acme-demo/r5']), 'github')
        self.assertEqual(self.abiertos('ruta', api, borrado), {'config/.env': 'open', 'a.env': 'resolved'})
        self.assertEqual([self.abiertos('title', h).popitem()[1] for h in (de_borrado, cortado)], ['resolved', 'open'])
        ip_a, ip_b = '20.69.154.199', '40.65.94.253'
        antes = resultado_shodan((ip_a, 3389), (ip_b, 3389), cves=[(ip_a, 'CVE-2024-0001')])
        self.reescanear(antes, 'shodan')
        self.sin_partes(*antes.hallazgos)
        self.reescanear(resultado_shodan(revisados=[ip_a], sin_revisar=[ip_a + '/cve', ip_b, ip_b + '/cve']), 'shodan')
        self.assertEqual(self.abiertos('ip', *antes.hallazgos[1:]), {ip_a: 'resolved', ip_b: 'open'})
        self.assertEqual(self.abiertos('cve', antes.hallazgos[0]), {'CVE-2024-0001': 'open'})
        _, f = self.escanear_ejemplo()
        for revisados in ([], ['otro']):
            s, resumen = self.reescanear(Resultado(**dict(vars(BIEN), revisados=revisados)))
            self.assertEqual(self.estado(f['id'])['status'], 'open')
            self.assertEqual(resumen['status'], 'partial')

    def test_2p_la_api_no_muestra_las_partes_y_si_el_origen_de_crtsh(self):
        """evidence.partes es para el orquestador (#23). El origen de un certificado (crtsh o certspotter) sí sale."""
        from cirdan.api import v1
        evidencia = {'title': 'Certificado por vencer', 'origen': 'certspotter', 'partes': ['acme-demo/api'],
                     'huella': 'ab' * 32, 'caracteristicas': {'tipo': 'x'}}
        fila = dict.fromkeys(('id', 'breach_name', 'rule_code', 'asset', 'asset_type', 'category', 'source', 'severity',
                              'base_severity', 'status', 'recurrence', 'cve_id', 'cvss', 'epss', 'in_kev', 'detected_at',
                              'last_scan_id'), None)
        self.assertEqual(v1._finding(dict(fila, evidence=evidencia))['evidence'], {'origen': 'certspotter'})

    def test_2q_con_la_cobertura_parcial_lo_abierto_conserva_las_partes_que_no_se_revisaron(self):
        """Un correo que salió en api y sitio sale después solo en sitio, con api sin clonar (#23): sus partes siguen
        con api, así que no se cierra si en la siguiente corrida parcial ya no sale de sitio. Cuando api se revisa, sale
        de sus partes, y una corrida completa sin el correo lo cierra."""
        en_los_dos, en_sitio = correo('luis', 'api', 'sitio'), correo('luis', 'sitio')
        self.assertEqual(en_los_dos.huella, en_sitio.huella)
        self.reescanear(resultado_github(en_los_dos), 'github')
        self.reescanear(resultado_github(en_sitio, revisados=['acme-demo/sitio']), 'github')
        self.assertEqual(self.partes(en_sitio), ['acme-demo/sitio', 'acme-demo/api'])
        for sin_revisar in (None, ['acme-demo/api']):
            self.reescanear(resultado_github(revisados=['acme-demo/sitio'], sin_revisar=sin_revisar), 'github')
            self.assertEqual(self.abiertos('title', en_sitio).popitem()[1], 'open', sin_revisar)
        self.reescanear(resultado_github(en_sitio, revisados=['acme-demo/api', 'acme-demo/sitio']), 'github')
        self.assertEqual(self.partes(en_sitio), ['acme-demo/sitio'])   # api se revisó y el correo ya no salió ahí
        self.reescanear(resultado_github(), 'github')
        self.assertEqual(self.abiertos('title', en_sitio).popitem()[1], 'resolved')

    def test_2r_una_cve_que_el_tope_dejo_fuera_sigue_abierta(self):
        """Las CVE que MAX_CVE deja fuera van en omitidos (#23): la que se reportó antes y ahora quedó fuera sigue
        abierta, el escaneo no queda a medias por eso y una omitida que nunca se reportó no se guarda. Si ya no sale
        ni en omitidos, se cierra."""
        ip = '40.65.94.253'
        antes = resultado_shodan(cves=[(ip, 'CVE-2024-0001'), (ip, 'CVE-2024-0002')])
        nunca = resultado_shodan(cves=[(ip, 'CVE-2024-0003')]).hallazgos[0]
        self.reescanear(antes, 'shodan')
        _, resumen = self.reescanear(resultado_shodan(cves=[(ip, 'CVE-2024-0002')],
                                                      omitidos=[(ip, 'CVE-2024-0001'), (ip, 'CVE-2024-0003')]), 'shodan')
        self.assertEqual(self.abiertos('cve', *antes.hallazgos, nunca), {'CVE-2024-0001': 'open', 'CVE-2024-0002': 'open'})
        self.assertNotIn('sources_partial', resumen['stats'])
        self.reescanear(resultado_shodan(cves=[(ip, 'CVE-2024-0002')], omitidos=[(ip, 'CVE-2024-0001')],
                                         revisados=[ip, ip + '/cve']), 'shodan')   # su IP/cve se revisó: no basta
        self.assertEqual(self.abiertos('cve', *antes.hallazgos), {'CVE-2024-0001': 'open', 'CVE-2024-0002': 'open'})
        self.reescanear(resultado_shodan(cves=[(ip, 'CVE-2024-0002')]), 'shodan')
        self.assertEqual(self.abiertos('cve', *antes.hallazgos), {'CVE-2024-0001': 'resolved', 'CVE-2024-0002': 'open'})

    def test_2s_lo_guardado_sin_partes_que_vuelve_a_salir_en_una_corrida_parcial(self):
        """Un correo guardado antes de evidence.partes que vuelve a salir en una corrida parcial sin sin_revisar (#23):
        con 'repos' entero conserva el repo que no se revisó, y con 'repos' cortado en MAX_REPOS_ACTIVO queda sin partes
        y espera a una corrida completa, aunque las siguientes den sin_revisar (test_2u: si la corrida en que vuelve a
        salir da sin_revisar, lleva esas partes)."""
        cinco = ['r%d' % i for i in range(github.MAX_REPOS_ACTIVO)]
        dos, cortado = correo('rosa', 'api', 'sitio'), correo('pepe', *cinco)
        self.reescanear(resultado_github(dos, cortado), 'github')
        self.sin_partes(dos, cortado)
        revisados = ['acme-demo/r0', 'acme-demo/sitio']
        self.reescanear(resultado_github(correo('rosa', 'sitio'), correo('pepe', 'r0'), revisados=revisados), 'github')
        self.assertEqual([self.partes(h) for h in (dos, cortado)], [['acme-demo/sitio', 'acme-demo/api'], []])
        for sin_revisar in (None, ['acme-demo/api', 'acme-demo/r5']):
            self.reescanear(resultado_github(revisados=revisados, sin_revisar=sin_revisar), 'github')
            self.assertEqual([self.abiertos('title', h).popitem()[1] for h in (dos, cortado)], ['open'] * 2, sin_revisar)
        self.reescanear(resultado_github(), 'github')
        self.assertEqual([self.abiertos('title', h).popitem()[1] for h in (dos, cortado)], ['resolved'] * 2)

    def test_2t_una_parte_previa_que_ya_no_existe_no_se_conserva(self):
        """Con sin_revisar, una parte previa que no se revisó y no está ahí ya no existe, como un repo borrado (#23): no
        se conserva, y la siguiente corrida parcial sin sin_revisar ya puede cerrar el correo."""
        self.reescanear(resultado_github(correo('ines', 'api', 'borrado')), 'github')
        en_api = correo('ines', 'api')
        self.reescanear(resultado_github(en_api, revisados=['acme-demo/api'], sin_revisar=['acme-demo/sitio']), 'github')
        self.assertEqual(self.partes(en_api), ['acme-demo/api'])
        self.reescanear(resultado_github(revisados=['acme-demo/api']), 'github')
        self.assertEqual(self.abiertos('title', en_api).popitem()[1], 'resolved')

    def test_2u_lo_guardado_sin_partes_con_todos_los_repos_conocidos_lleva_los_no_revisados(self):
        """Un correo guardado antes de evidence.partes con 'repos' cortado vuelve a salir en una corrida parcial que da
        sin_revisar (#23): sus partes son los repos donde salió más los no revisados, así que se cierra cuando esos se
        revisan, sin esperar a una corrida completa, que con más de MAX_REPOS repos nunca llega."""
        cortado = correo('teo', *['r%d' % i for i in range(github.MAX_REPOS_ACTIVO)])
        self.reescanear(resultado_github(cortado), 'github')
        self.sin_partes(cortado)
        for i in range(2):   # la segunda vez parte de las [] que deja una corrida sin sin_revisar
            sin_revisar = ['acme-demo/r1'] if i else None
            self.reescanear(resultado_github(correo('teo', 'r0'), revisados=['acme-demo/r0'], sin_revisar=sin_revisar),
                            'github')
            self.assertEqual(self.partes(cortado), ['acme-demo/r0', 'acme-demo/r1'] if i else [])
        self.reescanear(resultado_github(revisados=['acme-demo/r0'], sin_revisar=['acme-demo/r1']), 'github')
        self.assertEqual(self.abiertos('title', cortado).popitem()[1], 'open')
        self.reescanear(resultado_github(revisados=['acme-demo/r0', 'acme-demo/r1']), 'github')
        self.assertEqual(self.abiertos('title', cortado).popitem()[1], 'resolved')

    def test_2v_resolved_findings_no_cuenta_lo_que_la_cobertura_parcial_deja_abierto(self):
        """resolved_findings cuenta lo que el escaneo cerró de verdad (RC-55, #23): no el secreto de un repo que no se
        revisó ni una CVE que el tope dejó fuera. El primer escaneo de cada fuente puede cerrar lo de la semilla, así
        que ahí solo se miran los nuevos."""
        api, sitio, viejo = secreto('api', 'config/.env'), secreto('sitio', 'web/.env'), secreto('sitio', 'web/viejo.env')
        s, _ = self.reescanear(resultado_github(api, sitio, viejo), 'github')
        self.assertEqual(self.conteos(s.scan_id)[0], 3)
        s, _ = self.reescanear(resultado_github(sitio, revisados=['acme-demo/sitio']), 'github')
        self.assertEqual(self.conteos(s.scan_id), (0, 1))  # cierra viejo y no api, que no se revisó
        self.assertEqual(self.abiertos('ruta', api, sitio, viejo),
                         {'config/.env': 'open', 'web/.env': 'open', 'web/viejo.env': 'resolved'})
        s, _ = self.reescanear(resultado_github(sitio), 'github')
        self.assertEqual(self.conteos(s.scan_id), (0, 1))  # la corrida completa cierra api
        ip = '40.65.94.253'
        s, _ = self.reescanear(resultado_shodan(cves=[(ip, 'CVE-2024-0001'), (ip, 'CVE-2024-0002')]), 'shodan')
        self.assertEqual(self.conteos(s.scan_id)[0], 2)
        s, _ = self.reescanear(resultado_shodan(cves=[(ip, 'CVE-2024-0002')], omitidos=[(ip, 'CVE-2024-0001')]),
                               'shodan')
        self.assertEqual(self.conteos(s.scan_id), (0, 0))  # la omitida sigue abierta
        s, _ = self.reescanear(resultado_shodan(cves=[(ip, 'CVE-2024-0002')]), 'shodan')
        self.assertEqual(self.conteos(s.scan_id), (0, 1))

    def test_2w_un_correo_guardado_en_otro_dominio_de_la_empresa_conserva_sus_partes(self):
        """La huella de un correo no lleva el dominio, así que el upsert lo trae desde otro dominio de la misma empresa
        (#23). Si salió en api y sitio y ahora sale solo en sitio, con api sin clonar, conserva api en sus partes y la
        siguiente corrida parcial no lo cierra ni lo cuenta como resuelto."""
        en_los_dos, en_sitio = correo('ana', 'api', 'sitio'), correo('ana', 'sitio')
        self.reescanear(resultado_github(en_los_dos), 'github')
        tienda = self.uno("SELECT id FROM domains WHERE fqdn = 'acme-tienda.mx'")['id']
        activo = self.uno("INSERT INTO assets (organization_id, domain_id, asset_type, value, first_seen_at, "
                          "last_seen_at) VALUES (%s, %s, 'email', %s, now(), now()) RETURNING id",
                          ACME, tienda, en_los_dos.activo)['id']
        self.conn.execute('UPDATE findings SET domain_id = %s, asset_id = %s WHERE fingerprint = %s',
                          (tienda, activo, bytes.fromhex(en_los_dos.huella)))
        self.reescanear(resultado_github(en_sitio, revisados=['acme-demo/sitio']), 'github')
        self.assertEqual(self.partes(en_sitio), ['acme-demo/sitio', 'acme-demo/api'])
        s, _ = self.reescanear(resultado_github(revisados=['acme-demo/sitio']), 'github')
        self.assertEqual(self.abiertos('title', en_sitio).popitem()[1], 'open')
        self.assertEqual(self.conteos(s.scan_id)[1], 0)

    def test_3_una_fuente_que_falla_al_reproducir_deja_el_escaneo_parcial_sin_reintento(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        # crt.sh no tiene respuestas grabadas de acme-demo.mx: falla sin salir a la red
        resumen = orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ejemplo', 'ct_logs'], modo='reproducir',
                                     conn=self.conn)
        self.assertEqual(resumen['status'], 'partial')
        fallida = self.uno("SELECT r.status, r.attempt, r.next_retry_at IS NOT NULL AS reintento, r.error FROM scan_source_runs r "
                           "JOIN data_sources d ON d.id = r.source_id WHERE r.scan_id = %s AND d.code = 'ct_logs'", s.scan_id)
        # la respuesta grabada sería la misma: no hay reintento que esperar
        self.assertEqual((fallida['status'], fallida['attempt'], fallida['reintento']), ('failed', 0, False))
        self.assertTrue(fallida['error'])
        score = self.uno('SELECT partial_coverage FROM domain_scores WHERE scan_id = %s', s.scan_id)
        self.assertTrue(score['partial_coverage'])

    def test_3b_una_fuente_con_codigos_sin_cobertura_deja_el_escaneo_parcial(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        with tempfile.TemporaryDirectory() as d, mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)):
            # respaldo de Cert Spotter grabado sin red: crt.sh caído y Cert Spotter simulado (#14b)
            cliente = crtsh.ClienteCrtsh(modo='grabar', carpeta=crtsh.carpeta_de('acme-demo.mx'), transporte=RespaldoSimulado(),
                                         dormir=lambda s: None, nueva=True)
            crtsh.recolectar('acme-demo.mx', cliente, AHORA)
            resumen = orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ct_logs'], modo='reproducir', ahora=AHORA,
                                         conn=self.conn)
        self.assertEqual(resumen['status'], 'partial')
        self.assertEqual(resumen['stats']['rules_without_coverage'], ['cert_expired', 'lookalike_domain'])
        self.assertEqual((resumen['stats']['sources_ok'], resumen['stats']['assets']), (1, 4))
        run = self.uno('SELECT status, attempt FROM scan_source_runs WHERE scan_id = %s', s.scan_id)
        self.assertEqual((run['status'], run['attempt']), ('succeeded', 0))
        self.assertEqual(self.uno('SELECT status FROM scans WHERE id = %s', s.scan_id)['status'], 'partial')
        score = self.uno('SELECT partial_coverage FROM domain_scores WHERE scan_id = %s', s.scan_id)
        self.assertTrue(score['partial_coverage'])

    def test_3c_un_escaneo_en_vivo_nunca_busca_dominios_parecidos(self):
        """Lo que corre POST /api/v1/domains/{fqdn}/scans: crt.sh solo consulta el dominio autorizado. El crt.sh es
        simulado, así que nada sale a la red aunque se deje pasar acme-demo.mx como dominio en vivo."""
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        self.exige_cupo('ct_logs', crtsh.MAX_CONSULTAS)  # en vivo, ct_logs reserva su máximo antes de correr
        t = CrtshSimulado()
        with tempfile.TemporaryDirectory() as d, mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)), \
                mock.patch.object(crtsh, '_descargar', t), \
                mock.patch.object(orquestador, 'en_vivo_permitido', lambda fqdn: True):
            resumen = orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ct_logs'], ahora=AHORA,
                                         conn=self.conn)
        consultas = [crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(u).query)['q'][0] for u in t.urls]
        self.assertEqual(consultas, ['%.acme-demo.mx'])  # ni %acme-demo% ni variantes como acme-dem0.mx
        dominios = [crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(u).query)['domain'] for u in t.cert_spotter]
        self.assertEqual(dominios, [['acme-demo.mx']])  # Cert Spotter tampoco sale del dominio autorizado
        self.assertEqual(resumen['status'], 'partial')
        self.assertEqual(resumen['stats']['rules_without_coverage'], ['lookalike_domain'])
        self.assertEqual(resumen['sources'][0]['hallazgos'], 2)  # el vencido y el que vence pronto, ningún parecido

    def test_3d_en_vivo_la_fuente_que_falla_se_reintenta_en_el_mismo_escaneo(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        esperas = []
        resumen = self.en_vivo(s, [FALLA, FALLA, BIEN], esperas.append)
        self.assertEqual(sum(esperas), 6 * 60)  # 1 y 5 minutos, de a lo más LATIDO segundos
        self.assertLessEqual(max(esperas), orquestador.LATIDO)
        run = self.corrida(s.scan_id)
        self.assertEqual((run['status'], run['attempt'], run['next_retry_at'], run['error']), ('succeeded', 2, None, None))
        self.assertEqual(self.uno('SELECT count(*) AS n FROM scan_source_runs WHERE scan_id = %s', s.scan_id)['n'], 1)
        self.assertEqual(resumen['status'], 'completed')

    def test_3e_en_vivo_despues_del_cuarto_intento_la_fuente_queda_fallida(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        esperas = []
        resumen = self.en_vivo(s, [FALLA] * 4, esperas.append)
        self.assertEqual(sum(esperas), 31 * 60)  # 1, 5 y 25 minutos
        run = self.corrida(s.scan_id)
        self.assertEqual((run['status'], run['attempt'], run['next_retry_at']), ('failed', 3, None))
        self.assertEqual(resumen['status'], 'failed')  # su única fuente falló

    def test_3f_si_dan_el_escaneo_por_caido_mientras_espera_deja_de_reintentar(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))

        def cortar(segundos):  # otra petición lo da por caído durante la espera
            self.conn.execute("UPDATE scans SET status = 'failed' WHERE id = %s", (s.scan_id,))
        resumen = self.en_vivo(s, [FALLA, BIEN], cortar)
        self.assertEqual(resumen['status'], 'failed')
        run = self.corrida(s.scan_id)
        self.assertEqual((run['status'], run['next_retry_at']), ('failed', None))
        self.assertIsNone(self.uno("SELECT 1 FROM audit_log WHERE entity_id = %s AND action = 'scan.finished'", s.scan_id))

    def test_3g_la_espera_marca_vida_en_cada_paso_y_corta_a_mitad(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        esperas = []

        def dormir(segundos):  # lo dan por caído en el primer paso de la espera de 5 minutos
            esperas.append(segundos)
            if len(esperas) == 2:
                self.conn.execute("UPDATE scans SET status = 'failed' WHERE id = %s", (s.scan_id,))
        resumen = self.en_vivo(s, [FALLA, FALLA, BIEN], dormir)
        self.assertEqual(len(esperas), 2)  # sin la marca de vida de cada paso dormiría los 5 minutos completos
        self.assertEqual(resumen['status'], 'failed')

    def test_3h_si_lo_dan_por_caido_mientras_la_fuente_corre_no_se_escribe_encima_de_su_fila(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))

        def abandonar_y_responder():  # la corrida tardó más de 30 minutos y otra petición lo dio por caído
            self.conn.execute("UPDATE scans SET updated_at = now() - interval '31 minutes' WHERE id = %s", (s.scan_id,))
            orquestador.abandonar_vencidos(self.conn, ACME, scan_id=s.scan_id)
            return BIEN
        resumen = self.en_vivo(s, [FALLA, abandonar_y_responder], lambda segundos: None)
        self.assertEqual(resumen['status'], 'failed')
        run = self.corrida(s.scan_id)
        # sigue como la dejó el abandono, que conserva el error del primer intento: no 'succeeded' sin error
        self.assertEqual((run['status'], run['attempt'], run['error']), ('failed', 1, FALLA.error))

    def test_3i_la_fila_suma_las_consultas_de_sus_intentos_y_guarda_los_errores_anteriores(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        resumen = self.en_vivo(s, [FALLA, FALLA, BIEN], lambda segundos: None)
        fuente = resumen['sources'][0]
        self.assertEqual((fuente['status'], fuente['consultas']), ('succeeded', 3))
        self.assertEqual(fuente['avisos'], ['Intento 1: crt.sh no respondió', 'Intento 2: crt.sh no respondió'])
        guardado = self.uno('SELECT raw_payload FROM scan_source_runs WHERE scan_id = %s', s.scan_id)['raw_payload']
        self.assertEqual((guardado['consultas'], guardado['avisos']), (3, fuente['avisos']))  # `ejemplo` guarda raw_payload

    def test_3i2_una_fuente_sin_cupo_tambien_se_reintenta(self):
        """crt.sh caído y Cert Spotter sin cupo: crt.sh no tiene cupo y puede volver en un minuto."""
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        sin_cupo = SimpleNamespace(**dict(vars(FALLA), error='crt.sh no respondió. Cert Spotter no respondió a '
                                          'acme-demo.mx después de 1 intento (llegó a su límite de consultas, Retry-After 3600 s)'))
        resumen = self.en_vivo(s, [sin_cupo, BIEN], lambda segundos: None)
        self.assertEqual(resumen['sources'][0]['status'], 'succeeded')

    def test_3i3_un_activo_que_dan_dos_fuentes_cuenta_una_vez_en_stats(self):
        """Hasta #23, stats.assets cuenta los (tipo, valor) distintos de las fuentes que respondieron, no la suma."""
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        www, api, mail = (Activo('subdomain', n + '.acme-demo.mx') for n in ('www', 'api', 'mail'))
        respuestas = iter([SimpleNamespace(**dict(vars(BIEN), activos=[www, api])),
                           SimpleNamespace(**dict(vars(BIEN), activos=[www, mail]))])
        with mock.patch.object(orquestador, 'ejecutar', lambda *a, **k: next(respuestas)):
            resumen = orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ejemplo', 'ct_logs'], modo='reproducir',
                                         conn=self.conn)
        self.assertEqual([f['activos'] for f in resumen['sources']], [2, 2])  # cada fuente guarda lo suyo
        self.assertEqual((resumen['status'], resumen['stats']['assets']), ('completed', 3))  # www una sola vez

    def test_3j_mientras_corre_una_fuente_un_hilo_marca_vida_y_para_al_terminar(self):
        latidos = []
        with mock.patch.object(orquestador, 'LATIDO', 0.01), \
                mock.patch.object(orquestador, '_latido', lambda org, scan_id, conn=None: latidos.append(scan_id) or True):
            with orquestador._latiendo(ACME, 'escaneo', None):  # el tope de 20 minutos no llega
                time.sleep(0.2)
            marcados = len(latidos)
            time.sleep(0.1)
        self.assertGreater(marcados, 0)
        self.assertLessEqual(len(latidos), marcados + 1)  # a lo más la marca que ya iba en camino

    def test_3k_el_hilo_de_latido_no_pasa_del_tope_de_una_corrida(self):
        latidos = []
        with mock.patch.object(orquestador, 'LATIDO', 0.01), \
                mock.patch.object(orquestador, 'TOPE_CORRIDA', timedelta(seconds=0.05)), \
                mock.patch.object(orquestador, '_latido', lambda org, scan_id, conn=None: latidos.append(scan_id) or True):
            with orquestador._latiendo(ACME, 'escaneo', None):
                time.sleep(0.3)
        self.assertTrue(1 <= len(latidos) <= 5, latidos)  # una corrida colgada deja de marcar vida

    def test_3k2_si_un_latido_falla_queda_un_aviso_en_el_log(self):
        def falla(org, scan_id, conn=None):
            raise psycopg.OperationalError('la base no respondió')
        with mock.patch.object(orquestador, 'LATIDO', 0.01), mock.patch.object(orquestador, '_latido', falla), \
                self.assertLogs('cirdan.orquestador', 'WARNING') as logs:
            with orquestador._latiendo(ACME, 'escaneo', None):
                time.sleep(0.1)
            time.sleep(0.05)
        self.assertIn('No se pudo marcar vida del escaneo escaneo: la base no respondió', logs.output[0])

    def test_3l_cada_paso_de_la_espera_escribe_la_marca_de_vida(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        frescas = []

        def dormir(segundos):  # en cada paso revisa que la marca sea de ahora y luego la envejece
            frescas.append(self.uno('SELECT updated_at = now() AS f FROM scans WHERE id = %s', s.scan_id)['f'])
            self.conn.execute("UPDATE scans SET updated_at = now() - interval '1 hour' WHERE id = %s", (s.scan_id,))
        self.en_vivo(s, [FALLA, FALLA, BIEN], dormir)
        self.assertEqual(frescas, [True] * 6)  # 1 paso de la espera de 1 minuto y 5 de la de 5

    def test_3m_cada_corrida_de_una_fuente_va_con_el_hilo_de_latido(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        dentro = []

        @contextlib.contextmanager
        def latiendo(org, scan_id, conn):
            self.assertEqual((org, scan_id), (ACME, s.scan_id))
            dentro.append(True)
            yield
            dentro.append(False)

        def responder():
            self.assertEqual(dentro, [True])  # ejecutar corre dentro de _latiendo
            return BIEN
        with mock.patch.object(orquestador, '_latiendo', latiendo):
            self.en_vivo(s, [responder], lambda segundos: None)
        self.assertEqual(dentro, [True, False])

    # ------------------------------------------------------- límite diario por fuente (#13b, RC-184)

    def test_3n_sin_cupo_la_fuente_falla_sin_llamar_al_recolector_ni_reintentar(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        limite, usadas, _ = self.cupo('ct_logs')
        self.assertIsNotNone(limite, 'la semilla 005 pone el límite diario de ct_logs')
        llamadas, esperas = [], []

        def responder():
            llamadas.append(True)
            return BIEN
        with mock.patch.object(crtsh, 'MAX_CONSULTAS', limite + 1):  # una corrida de ct_logs ya no cabe hoy
            resumen = self.en_vivo(s, [responder], esperas.append, fuentes=('ejemplo', 'ct_logs'))
        self.assertEqual(llamadas, [True])  # solo `ejemplo`: a ct_logs ni se le llamó
        self.assertEqual(esperas, [])       # sin reintento a 1, 5 ni 25 minutos
        texto = orquestador.SIN_CUPO % 'ct_logs'
        # puede quedar cupo, pero no el máximo de una corrida completa
        self.assertEqual(texto, 'Sin cupo diario: ct_logs no tiene cupo para una corrida completa hoy (día UTC).')
        run = self.corrida_de(s.scan_id, 'ct_logs')
        self.assertEqual((run['status'], run['attempt'], run['next_retry_at'], run['error']), ('failed', 0, None, texto))
        self.assertEqual((run['raw_payload']['consultas'], run['raw_payload']['avisos']), (0, [texto]))  # ct_logs guarda raw_payload
        fuente = resumen['sources'][1]
        self.assertEqual((fuente['source'], fuente['status'], fuente['error']), ('ct_logs', 'failed', texto))
        self.assertEqual((resumen['status'], resumen['stats']['sources_failed']), ('partial', 1))  # `ejemplo` sí respondió
        self.assertEqual(self.cupo('ct_logs')[1], usadas)  # la reserva que no cupo no dejó nada

    def test_3n2_si_el_cupo_se_acaba_entre_reintentos_la_fuente_queda_fallida(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        limite, usadas, _ = self.cupo('ct_logs')
        self.assertIsNotNone(limite)
        if limite - usadas < 0:  # el ajuste registra lo gastado de más: lo usado hoy puede pasar del límite
            self.skipTest('ct_logs ya gastó más que su límite hoy en esta base: no hay reserva que quepa justo')
        llamadas, esperas = [], []

        def fallar():
            llamadas.append(True)
            return FALLA
        # la primera reserva cabe justo y la consulta que gasta el primer intento deja sin lugar a la segunda
        with mock.patch.object(crtsh, 'MAX_CONSULTAS', limite - usadas):
            resumen = self.en_vivo(s, [fallar], esperas.append, fuentes=('ct_logs',))
        self.assertEqual(llamadas, [True])
        self.assertEqual(sum(esperas), 60)  # solo la espera del primer reintento
        run = self.corrida_de(s.scan_id, 'ct_logs')
        self.assertEqual((run['status'], run['attempt'], run['next_retry_at']), ('failed', 1, None))
        self.assertEqual(run['raw_payload']['avisos'], ['Intento 1: crt.sh no respondió', orquestador.SIN_CUPO % 'ct_logs'])
        self.assertEqual(resumen['status'], 'failed')  # su única fuente falló
        self.assertEqual(self.cupo('ct_logs')[1], usadas + FALLA.consultas)  # lo gastado de más se registra igual

    def test_3o_la_reserva_y_el_ajuste_dejan_en_daily_used_lo_que_se_gasto(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        reservadas = crtsh.MAX_CONSULTAS
        _, usadas = self.exige_cupo('ct_logs', 2 + reservadas)  # 2 intentos de 1 consulta y la reserva del tercero
        durante = []

        def mientras(r):
            def corrida():  # mientras corre, ya está reservado el máximo de la corrida
                durante.append(self.cupo('ct_logs')[1])
                return r
            return corrida
        resumen = self.en_vivo(s, [mientras(FALLA), mientras(FALLA), mientras(BIEN)], lambda segundos: None,
                               fuentes=('ct_logs',))
        self.assertEqual(resumen['sources'][0]['status'], 'succeeded')
        self.assertEqual(durante, [usadas + reservadas, usadas + 1 + reservadas, usadas + 2 + reservadas])
        self.assertEqual(self.cupo('ct_logs')[1], usadas + 3)  # 1 consulta por intento
        self.assertTrue(self.uno('SELECT daily_used_on = %s AS hoy FROM data_sources WHERE code = %%s' % HOY_UTC,
                                 'ct_logs')['hoy'])

    def test_3p_reproducir_no_reserva_ni_gasta_cupo(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        # con mocks y no relecturas de daily_used: otro escaneo en la misma base lo puede mover mientras tanto
        with mock.patch.object(orquestador, '_reservar', side_effect=AssertionError('reservó al reproducir')) as reservar, \
                mock.patch.object(orquestador, '_ajustar', side_effect=AssertionError('ajustó al reproducir')) as ajustar:
            resumen = orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ejemplo', 'ct_logs'], modo='reproducir',
                                         conn=self.conn)
        self.assertEqual(resumen['status'], 'partial')  # crt.sh no tiene grabación de acme-demo.mx
        self.assertEqual((reservar.call_count, ajustar.call_count), (0, 0))

    def test_3p2_un_dominio_fuera_de_dominios_en_vivo_pasa_a_reproducir_y_no_gasta_cupo(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        with mock.patch.object(orquestador, 'en_vivo_permitido', lambda fqdn: False), \
                mock.patch.object(orquestador, '_reservar', side_effect=AssertionError('reservó al reproducir')) as reservar, \
                mock.patch.object(orquestador, '_ajustar', side_effect=AssertionError('ajustó al reproducir')) as ajustar:
            resumen = orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ct_logs'], conn=self.conn)
        self.assertEqual(resumen['status'], 'failed')  # pasó a reproducir y crt.sh no tiene grabación de acme-demo.mx
        self.assertEqual((reservar.call_count, ajustar.call_count), (0, 0))

    def test_3q_sin_limite_en_daily_limit_no_se_limita(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        limite, usadas, _ = self.cupo('ejemplo')
        self.assertIsNone(limite, '`ejemplo` no tiene límite diario en las semillas')
        with mock.patch.object(ejemplo, 'MAX_CONSULTAS', 1000000):  # una reserva enorme también cabe
            resumen = self.en_vivo(s, [BIEN], lambda segundos: None)
        self.assertEqual(resumen['sources'][0]['status'], 'succeeded')
        self.assertEqual(self.cupo('ejemplo')[1], usadas + BIEN.consultas)

    def test_3r_el_cupo_de_un_dia_viejo_se_reinicia(self):
        """Como postgres deja ct_logs lleno ayer. Después corre como cirdan_app en la misma transacción, que se deshace."""
        pg = conexion_postgres()
        tx = pg.transaction(force_rollback=True)
        tx.__enter__()
        try:
            ayer = pg.execute('SELECT %s - 1 AS d' % HOY_UTC).fetchone()['d']
            pg.execute("UPDATE data_sources SET daily_used = coalesce(daily_limit, 1000), daily_used_on = %s "
                       "WHERE code = 'ct_logs'", (ayer,))
            pg.execute('SET LOCAL ROLE cirdan_app')  # desde aquí, con los permisos de la API
            pg.execute("SELECT set_config('app.current_org', %s, true)", (ACME,))
            s = self.solicitar('acme-demo.mx', responde(TXT_ACME), conn=pg)
            resumen = self.en_vivo(s, [BIEN], lambda segundos: None, fuentes=('ct_logs',), conn=pg)
            self.assertEqual(resumen['sources'][0]['status'], 'succeeded')  # lo de ayer no cuenta hoy
            fila = pg.execute('SELECT daily_used, daily_used_on = %s AS hoy FROM data_sources WHERE code = %%s' % HOY_UTC,
                              ('ct_logs',)).fetchone()
            self.assertEqual((fila['daily_used'], fila['hoy']), (BIEN.consultas, True))
            # un ajuste de ayer que llega tarde no toca el día nuevo
            pg.execute('SELECT public.adjust_source_quota(%s, %s, %s)', ('ct_logs', ayer, 50))
            self.assertEqual(self.cupo('ct_logs', pg)[1], BIEN.consultas)
        finally:
            tx.__exit__(None, None, None)
            pg.close()

    def test_3r2_el_dia_del_cupo_nunca_retrocede(self):
        """Una transacción que empezó antes de medianoche UTC ve hoy = ayer: si la fila ya está en el día nuevo, suma ahí."""
        pg = conexion_postgres()
        tx = pg.transaction(force_rollback=True)
        tx.__enter__()
        try:
            manana = pg.execute('SELECT %s + 1 AS d' % HOY_UTC).fetchone()['d']
            pg.execute("UPDATE data_sources SET daily_limit = 100, daily_used = 7, daily_used_on = %s "
                       "WHERE code = 'ct_logs'", (manana,))
            pg.execute('SET LOCAL ROLE cirdan_app')
            dia = pg.execute('SELECT public.reserve_source_quota(%s, %s) AS d', ('ct_logs', 3)).fetchone()['d']
            self.assertEqual(dia, manana)  # no vuelve a hoy ni parte de 0
            self.assertEqual(self.cupo('ct_logs', pg)[1:], (10, manana))
            pg.execute('SELECT public.adjust_source_quota(%s, %s, %s)', ('ct_logs', dia, -2))
            self.assertEqual(self.cupo('ct_logs', pg)[1], 8)
        finally:
            tx.__exit__(None, None, None)
            pg.close()

    def test_3s_las_funciones_del_cupo_rechazan_consultas_negativas_o_nulas(self):
        for n in (-1, None):
            with self.subTest(consultas=n), self.assertRaises(psycopg.Error), self.conn.transaction():
                self.conn.execute('SELECT public.reserve_source_quota(%s, %s::integer)', ('ct_logs', n))
        with self.subTest(ajuste=None), self.assertRaises(psycopg.Error), self.conn.transaction():
            # con NULL, GREATEST(daily_used + NULL, 0) daría 0 y borraría lo usado del día
            self.conn.execute('SELECT public.adjust_source_quota(%%s, %s, NULL::integer)' % HOY_UTC, ('ct_logs',))
        self.assertIsNone(self.uno('SELECT public.reserve_source_quota(%s, %s) AS dia', 'no_existe', 1)['dia'])

    def test_3t_cirdan_app_no_puede_cambiar_el_cupo_directo(self):
        for columna in ('daily_used', 'daily_used_on', 'daily_limit'):
            with self.subTest(columna=columna), self.assertRaises(psycopg.errors.InsufficientPrivilege), \
                    self.conn.transaction():
                self.conn.execute("UPDATE data_sources SET %s = NULL WHERE code = 'ct_logs'" % columna)

    # --------------------------------------------------------------------- rechaza

    def test_4_rechaza_sin_autorizacion_y_ni_consulta_el_dns(self):
        dns = responde('cirdan-verification=8f3c2a91e7b4')
        s = self.solicitar('partner-example.com', dns)
        self.assertFalse(s.aceptada)
        self.assertEqual(s.motivos, ['authorization_missing'])
        self.assertEqual(dns.llamadas, [])
        self.assertIsNone(self.uno("SELECT 1 FROM scans s JOIN domains d ON d.id = s.domain_id WHERE d.fqdn = 'partner-example.com'"))

    def test_5_rechaza_con_la_autorizacion_vencida(self):
        s = self.solicitar('old-example.net', responde('cirdan-verification=3d7f9b1e5c82'))
        self.assertFalse(s.aceptada)
        self.assertIn('authorization_expired', s.motivos)

    def test_5b_si_el_trigger_rechaza_el_motivo_sale_de_la_base_y_no_del_texto_del_error(self):
        """Segundo candado: la carta se revoca entre la revisión y la fila de scans, y el trigger la rechaza."""
        carta = self.uno("SELECT a.id::text FROM domain_authorizations a JOIN domains d ON d.id = a.domain_id "
                         "WHERE d.fqdn = 'acme-demo.mx' AND a.revoked_at IS NULL "
                         "AND current_date BETWEEN a.valid_from AND a.valid_until ORDER BY a.valid_until DESC LIMIT 1")['id']
        consulta = ConsultaTxt((TXT_ACME,))

        def revoca_y_responde(fqdn):
            self.conn.execute('UPDATE domain_authorizations SET revoked_at = now() WHERE id = %s', (carta,))
            return consulta
        s = self.solicitar('acme-demo.mx', revoca_y_responde)
        self.assertEqual((s.aceptada, s.motivos), (False, ['authorization_revoked']))  # antes salía authorization_expired

    def test_6_rechaza_si_el_txt_no_coincide_y_guarda_la_evidencia(self):
        s = self.solicitar('acme-demo.mx', responde('cirdan-verification=otro-token'))
        self.assertEqual((s.aceptada, s.motivos, s.txt), (False, ['txt_not_verified'], 'mismatch'))
        self.assertIn('no coincide', s.detalle)
        evidencia = self.uno("SELECT result FROM dns_txt_verifications WHERE domain_id = %s AND check_reason = 'pre_scan' "
                             "ORDER BY created_at DESC LIMIT 1", s.domain_id)
        self.assertEqual(evidencia['result'], 'mismatch')
        self.assertIsNone(self.uno("SELECT 1 FROM scans WHERE domain_id = %s AND status = 'running'", s.domain_id))

    def test_7_rechaza_si_no_hay_txt_o_el_dns_no_responde(self):
        sin_txt = self.solicitar('acme-demo.mx', DnsSimulado(ConsultaTxt(None)))
        self.assertEqual((sin_txt.aceptada, sin_txt.txt), (False, 'missing'))
        sin_dns = self.solicitar('acme-demo.mx', DnsSimulado(ConsultaTxt(None, error='Timeout')))
        self.assertEqual((sin_dns.aceptada, sin_dns.txt), (False, 'dns_error'))

    def test_8_no_consulta_en_vivo_un_dominio_de_la_demo(self):
        s = orquestador.solicitar(ACME, 'acme-demo.mx', conn=self.conn)  # sin DNS simulado = consulta real
        self.assertEqual((s.aceptada, s.motivos), (False, ['live_scan_not_allowed']))

    def test_9_no_permite_dos_escaneos_a_la_vez_del_mismo_dominio(self):
        self.assertTrue(self.solicitar('acme-demo.mx', responde(TXT_ACME)).aceptada)
        segunda = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        self.assertEqual((segunda.aceptada, segunda.motivos), (False, ['scan_in_progress']))

    def test_9b_un_escaneo_sin_marca_de_vida_se_da_por_caido_y_deja_pedir_otro(self):
        primero = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        fuente = self.uno("SELECT id::text FROM data_sources WHERE code = 'ejemplo'")['id']
        self.conn.execute("INSERT INTO scan_source_runs (organization_id, scan_id, source_id, status, attempt, next_retry_at) "
                          "VALUES (%s, %s, %s, 'retrying', 1, now())", (ACME, primero.scan_id, fuente))
        # la API se cortó a mitad: el escaneo quedó en running y nadie marcó que siguiera vivo
        self.conn.execute("UPDATE scans SET updated_at = now() - interval '31 minutes' WHERE id = %s", (primero.scan_id,))
        segundo = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        self.assertTrue(segundo.aceptada, segundo.motivos)
        viejo = self.uno('SELECT status, finished_at IS NOT NULL AS cerrado, stats FROM scans WHERE id = %s', primero.scan_id)
        self.assertEqual((viejo['status'], viejo['cerrado'], viejo['stats']['error']), ('failed', True, orquestador.ERROR_ABANDONO))
        run = self.corrida(primero.scan_id)
        self.assertEqual((run['status'], run['next_retry_at'], run['error']), ('failed', None, orquestador.ERROR_ABANDONO))
        self.assertTrue(self.uno("SELECT 1 FROM audit_log WHERE entity_id = %s AND action = 'scan.abandoned'", primero.scan_id))

    def test_9c_con_marca_de_vida_reciente_sigue_en_curso(self):
        primero = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        self.conn.execute("UPDATE scans SET updated_at = now() - interval '29 minutes' WHERE id = %s", (primero.scan_id,))
        segundo = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        self.assertEqual((segundo.aceptada, segundo.motivos), (False, ['scan_in_progress']))
        self.assertEqual(self.uno('SELECT status FROM scans WHERE id = %s', primero.scan_id)['status'], 'running')

    def test_9d_marcar_fallido_cierra_las_fuentes_aunque_el_escaneo_ya_no_corra(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        fuente = self.uno("SELECT id::text FROM data_sources WHERE code = 'ejemplo'")['id']
        self.conn.execute("INSERT INTO scan_source_runs (organization_id, scan_id, source_id, status, attempt, next_retry_at) "
                          "VALUES (%s, %s, %s, 'retrying', 1, now())", (ACME, s.scan_id, fuente))
        self.conn.execute("UPDATE scans SET status = 'failed' WHERE id = %s", (s.scan_id,))  # lo dieron por caído antes
        with mock.patch.object(orquestador, 'transaction', lambda org: contextlib.nullcontext(self.conn)):
            orquestador.marcar_fallido(ACME, s.scan_id, KeyboardInterrupt())  # Ctrl+C no trae texto
        run = self.corrida(s.scan_id)
        self.assertEqual((run['status'], run['next_retry_at'], run['error']), ('failed', None, 'KeyboardInterrupt'))

    def test_9e_marcar_fallido_con_ctrl_c_deja_el_motivo_en_el_escaneo(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        with mock.patch.object(orquestador, 'transaction', lambda org: contextlib.nullcontext(self.conn)):
            orquestador.marcar_fallido(ACME, s.scan_id, KeyboardInterrupt())
        scan = self.uno('SELECT status, stats FROM scans WHERE id = %s', s.scan_id)
        self.assertEqual((scan['status'], scan['stats']['error']), ('failed', 'KeyboardInterrupt'))

    def test_10_un_dominio_de_otra_empresa_no_existe_para_mi(self):
        s = self.solicitar('olmardo.com', responde('cirdan-verification=ab439d2b39a7'))
        self.assertEqual((s.aceptada, s.motivos), (False, ['domain_not_found']))

    # ---------------------------------------------------------------- línea de comandos

    def test_11_la_linea_de_comandos_muestra_el_aviso_de_cert_spotter(self):
        """Si crt.sh responde y Cert Spotter no, ct_logs queda correcto y sin error: el aviso solo se ve en la
        terminal. crt.sh y Cert Spotter son simulados, así que nada sale a la red."""
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        self.exige_cupo('ct_logs', crtsh.MAX_CONSULTAS)  # en vivo, ct_logs reserva su máximo antes de correr
        t = RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS}, limite_en=0)  # 429 en la primera página
        with tempfile.TemporaryDirectory() as d, mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)), \
                mock.patch.object(crtsh, '_descargar', t), mock.patch.object(crtsh.time, 'sleep', lambda s: None), \
                mock.patch.object(orquestador, 'en_vivo_permitido', lambda fqdn: True):
            resumen = orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ct_logs'], ahora=AHORA,
                                         conn=self.conn)
        ct_logs = resumen['sources'][0]
        self.assertEqual((ct_logs['status'], ct_logs['error'], ct_logs['avisos_omitidos']), ('succeeded', None, 0))

        def terminal(resumen):
            salida = io.StringIO()
            with mock.patch.object(cli, 'solicitar', lambda *a, **k: s), \
                    mock.patch.object(cli, 'correr', lambda *a, **k: resumen), contextlib.redirect_stdout(salida):
                self.assertEqual(cli.main(['acme-demo.mx', '--org', 'ACME']), 0)
            return salida.getvalue().splitlines()
        lineas = terminal(resumen)
        avisos = [l for l in lineas if l.startswith('    aviso: ')]
        self.assertEqual(len(avisos), 1, lineas)
        self.assertTrue(avisos[0].endswith(certspotter.SIN_COMPLEMENTO), avisos[0])
        # La corrida guarda solo 10 avisos: la terminal dice cuántos más hubo
        muchos = dict(resumen, sources=[dict(ct_logs, avisos=['aviso %d' % i for i in range(10)], avisos_omitidos=3)])
        self.assertIn('    y 3 avisos más', terminal(muchos))

    def test_11b_con_ctrl_c_la_linea_de_comandos_cierra_el_escaneo(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        cerrados = []

        def interrumpir(*a, **k):
            raise KeyboardInterrupt
        with mock.patch.object(cli, 'solicitar', lambda *a, **k: s), mock.patch.object(cli, 'correr', interrumpir), \
                mock.patch.object(cli, 'marcar_fallido', lambda org, scan_id, e: cerrados.append((scan_id, type(e)))), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                cli.main(['acme-demo.mx', '--org', 'ACME'])
        self.assertEqual(cerrados, [(s.scan_id, KeyboardInterrupt)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
