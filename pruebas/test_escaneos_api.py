"""Pruebas de la API de escaneos (#22) con sesión real (biblioteca estándar).

    python -m unittest -v pruebas/test_escaneos_api.py            (con `docker compose up -d`)
    EN_VIVO=1 python -m unittest -v pruebas/test_escaneos_api.py   (además escanea olmardo.com en vivo)
"""
import os
import time
import unittest

from pruebas import sesion

SCANS = '/api/v1/domains/%s/scans'


class EscaneosApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sesion.reset()
        cls.analista = sesion.login('jordan.tate@acme-demo.mx')
        cls.gerente = sesion.login('maya.reed@acme-demo.mx')
        cls.beta = sesion.login('dana.cruz@beta-corp.mx')

    def test_1_sin_sesion_no_se_puede_pedir_un_escaneo(self):
        self.assertEqual(sesion.Client().post(SCANS % 'acme-demo.mx')[0], 401)

    def test_2_el_gerente_es_de_solo_lectura(self):
        code, body = self.gerente.post(SCANS % 'acme-demo.mx')
        self.assertEqual(code, 403)
        self.assertIn('rol', body['detail'])

    def test_3_rechazo_sin_autorizacion_con_motivo(self):
        code, body = self.analista.post(SCANS % 'partner-example.com')
        self.assertEqual(code, 409)
        self.assertEqual((body['accepted'], body['reasons']), (False, ['authorization_missing']))
        self.assertTrue(body['detail'].startswith('No se puede escanear'))

    def test_4_rechazo_con_autorizacion_vencida(self):
        code, body = self.analista.post(SCANS % 'old-example.net')
        self.assertEqual(code, 409)
        self.assertIn('authorization_expired', body['reasons'])

    def test_5_los_dominios_de_la_demo_no_se_consultan_en_vivo(self):
        code, body = self.analista.post(SCANS % 'acme-demo.mx')
        self.assertEqual((code, body['reasons']), (409, ['live_scan_not_allowed']))

    def test_6_un_dominio_de_otra_empresa_responde_404(self):
        code, body = self.beta.post(SCANS % 'acme-demo.mx')
        self.assertEqual((code, body['reasons']), (404, ['domain_not_found']))
        self.assertEqual(self.analista.get('/api/v1/scans/60000000-0000-4000-8000-000000000001')[0], 200)
        self.assertEqual(self.beta.get('/api/v1/scans/60000000-0000-4000-8000-000000000001')[0], 404)
        self.assertEqual(self.beta.get('/api/v1/scans/no-es-un-id')[0], 404)

    @unittest.skipUnless(os.environ.get('EN_VIVO') == '1', 'consulta olmardo.com en vivo: corre con EN_VIVO=1')
    def test_7_en_vivo_acepta_olmardo_y_termina_el_escaneo(self):
        admin = sesion.login('admin@olmardo.com')
        code, body = admin.post(SCANS % 'olmardo.com')
        self.assertEqual(code, 202, body)
        scan_id = body['scan']['id']
        for _ in range(60):  # crt.sh puede tardar unos minutos
            _, scan = admin.get('/api/v1/scans/' + scan_id)
            if scan['status'] != 'running':
                break
            time.sleep(5)
        if scan['status'] == 'running' and (not scan['sources'] or any(r['status'] == 'retrying' for r in scan['sources'])):
            self.skipTest('crt.sh sigue en su primera corrida o una fuente espera su reintento (1, 5 y 25 minutos): '
                          'el escaneo sigue en curso y repetir la prueba antes de que termine da 409')
        self.assertIn(scan['status'], ('completed', 'partial'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
