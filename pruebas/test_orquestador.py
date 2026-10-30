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
from cirdan.recolectores import certspotter, crtsh, ejemplo
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

    def reescanear(self, resultado):
        """Otro escaneo de acme-demo.mx en el que `ejemplo` responde con este resultado."""
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        with mock.patch.object(orquestador, 'ejecutar', lambda *a, **k: resultado):
            return s, orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ejemplo'], modo='reproducir',
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
