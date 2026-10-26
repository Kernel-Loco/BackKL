"""Pruebas del orquestador (#22) sin red: TXT simulado y el recolector `ejemplo` con su respuesta grabada.

Necesitan psycopg y dnspython, así que corren dentro del contenedor de la API, con la base levantada:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_orquestador.py

Cada prueba corre en una transacción que se deshace al final: la base queda igual. Nunca consultan
en vivo los dominios de la demo (acme-demo.mx no es del equipo).
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
from psycopg.rows import dict_row

from cirdan import orquestador
from cirdan.db import DSN
from cirdan.orquestador import __main__ as cli
from cirdan.orquestador.txt import ConsultaTxt
from cirdan.recolectores import certspotter, crtsh
from pruebas.test_certspotter import AHORA, RespaldoSimulado
from pruebas.test_crtsh import SUBDOMINIOS, CrtshSimulado

ACME = '20000000-0000-4000-8000-000000000001'
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
BIEN = SimpleNamespace(estado='succeeded', activos=[{}], hallazgos=[], consultas=1, avisos=[], sin_cobertura=[], error='')


class Orquestador(unittest.TestCase):

    def setUp(self):
        self.conn = psycopg.connect(DSN, row_factory=dict_row)
        self.tx = self.conn.transaction(force_rollback=True)
        self.tx.__enter__()
        self.conn.execute("SELECT set_config('app.current_org', %s, true)", (ACME,))

    def tearDown(self):
        self.tx.__exit__(None, None, None)
        self.conn.close()

    def solicitar(self, fqdn, dns):
        return orquestador.solicitar(ACME, fqdn, consultar=dns, conn=self.conn)

    def uno(self, sql, *params):
        return self.conn.execute(sql, params).fetchone()

    def en_vivo(self, s, resultados, dormir):
        """Corre `ejemplo` en vivo con estos resultados seguidos, sin red ni esperas reales."""
        seguidos = iter(resultados)

        def siguiente(*a, **k):  # un resultado o una función que hace algo mientras la fuente corre
            r = next(seguidos)
            return r() if callable(r) else r
        with mock.patch.object(orquestador, 'ejecutar', siguiente), \
                mock.patch.object(orquestador, 'en_vivo_permitido', lambda fqdn: True):
            return orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ejemplo'], conn=self.conn, dormir=dormir)

    def corrida(self, scan_id):
        return self.uno('SELECT status, attempt, next_retry_at, error FROM scan_source_runs WHERE scan_id = %s', scan_id)

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
        self.assertEqual(resumen['stats'], {'assets': 2, 'findings': 1, 'sources_ok': 1, 'sources_failed': 0})
        run = self.uno('SELECT r.status, r.attempt, r.raw_payload FROM scan_source_runs r WHERE r.scan_id = %s', s.scan_id)
        self.assertEqual((run['status'], run['attempt']), ('succeeded', 0))
        self.assertEqual(run['raw_payload']['hallazgos'], 1)
        self.assertEqual(self.uno('SELECT status FROM scans WHERE id = %s', s.scan_id)['status'], 'completed')

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

    def test_3c_un_escaneo_en_vivo_nunca_busca_dominios_parecidos(self):
        """Lo que corre POST /api/v1/domains/{fqdn}/scans: crt.sh solo consulta el dominio autorizado. El crt.sh es
        simulado, así que nada sale a la red aunque se deje pasar acme-demo.mx como dominio en vivo."""
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
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
            dentro.append(True)
            yield
            dentro.append(False)

        def responder():
            self.assertEqual(dentro, [True])  # ejecutar corre dentro de _latiendo
            return BIEN
        with mock.patch.object(orquestador, '_latiendo', latiendo):
            self.en_vivo(s, [responder], lambda segundos: None)
        self.assertEqual(dentro, [True, False])

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

    def test_10_un_dominio_de_otra_empresa_no_existe_para_mi(self):
        s = self.solicitar('olmardo.com', responde('cirdan-verification=ab439d2b39a7'))
        self.assertEqual((s.aceptada, s.motivos), (False, ['domain_not_found']))

    # ---------------------------------------------------------------- línea de comandos

    def test_11_la_linea_de_comandos_muestra_el_aviso_de_cert_spotter(self):
        """Si crt.sh responde y Cert Spotter no, ct_logs queda correcto y sin error: el aviso solo se ve en la
        terminal. crt.sh y Cert Spotter son simulados, así que nada sale a la red."""
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
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
