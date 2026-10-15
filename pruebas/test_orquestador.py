"""Pruebas del orquestador (#22) sin red: TXT simulado y el recolector `ejemplo` con su respuesta grabada.

Necesitan psycopg y dnspython, así que corren dentro del contenedor de la API, con la base levantada:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_orquestador.py

Cada prueba corre en una transacción que se deshace al final: la base queda igual. Nunca consultan
en vivo los dominios de la demo (acme-demo.mx no es del equipo).
"""
import unittest

import psycopg
from psycopg.rows import dict_row

from cirdan import orquestador
from cirdan.db import DSN
from cirdan.orquestador.txt import ConsultaTxt

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

    def test_3_una_fuente_que_falla_deja_el_escaneo_parcial_y_programa_el_reintento(self):
        s = self.solicitar('acme-demo.mx', responde(TXT_ACME))
        # crt.sh no tiene respuestas grabadas de acme-demo.mx: falla sin salir a la red
        resumen = orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['ejemplo', 'ct_logs'], modo='reproducir',
                                     conn=self.conn)
        self.assertEqual(resumen['status'], 'partial')
        fallida = self.uno("SELECT r.status, r.attempt, r.next_retry_at IS NOT NULL AS reintento, r.error FROM scan_source_runs r "
                           "JOIN data_sources d ON d.id = r.source_id WHERE r.scan_id = %s AND d.code = 'ct_logs'", s.scan_id)
        self.assertEqual((fallida['status'], fallida['attempt'], fallida['reintento']), ('retrying', 1, True))
        self.assertTrue(fallida['error'])

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

    def test_10_un_dominio_de_otra_empresa_no_existe_para_mi(self):
        s = self.solicitar('olmardo.com', responde('cirdan-verification=ab439d2b39a7'))
        self.assertEqual((s.aceptada, s.motivos), (False, ['domain_not_found']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
