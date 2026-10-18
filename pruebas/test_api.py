"""Pruebas de la API de Cirdan contra el servidor local (biblioteca estándar).

Desde la raíz del repo, con todo levantado (`docker compose up -d`, DEMO_ACCOUNTS=true):
    python -m unittest -v pruebas/test_api.py

Cada empresa entra con la sesión de una cuenta de demo: la empresa sale de la sesión,
no de un encabezado (#25).
"""
import unittest

from pruebas import sesion

ACME = '20000000-0000-4000-8000-000000000001'


class ApiCirdan(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sesion.reset()
        cls.acme = sesion.login('alex.morgan@acme-demo.mx')
        cls.beta = sesion.login('dana.cruz@beta-corp.mx')

    def test_1_entra_como_rol_sin_privilegios(self):
        code, body = sesion.Client().get('/health')
        self.assertEqual(code, 200)
        self.assertEqual(body['role'], 'cirdan_app')

    def test_2_acme_ve_sus_cinco_dominios_con_score(self):
        code, body = self.acme.get('/domains')
        self.assertEqual(code, 200)
        self.assertEqual([(d['domain'], d['score'], d['level']) for d in body[:3]],
                         [('acme-demo.mx', 68, 'High'), ('acme-tienda.mx', 54, 'Medium'), ('acme-portal.mx', 31, 'Low')])
        self.assertEqual({d['domain']: d['authorization'] for d in body[3:]},
                         {'partner-example.com': 'Pending TXT', 'old-example.net': 'Expired'})

    def test_3_score_por_categoria_cuadra_con_los_pesos(self):
        code, body = self.acme.get('/domains/acme-demo.mx/score')
        self.assertEqual(code, 200)
        weighted = sum(c['score'] * c['weight'] for c in body['categories'])
        self.assertEqual(round(weighted), body['score'])
        self.assertEqual(body['score'], 68)

    def test_4_hallazgos_ordenados_por_severidad(self):
        code, body = self.acme.get('/domains/acme-demo.mx/findings')
        self.assertEqual(code, 200)
        self.assertEqual([f['severity'] for f in body], ['Critical', 'High', 'High', 'Medium'])

    def test_5_beta_no_ve_los_dominios_de_acme(self):
        code, body = self.beta.get('/domains')
        self.assertEqual(code, 200)
        self.assertNotIn('acme-demo.mx', [d['domain'] for d in body])
        code, _ = self.beta.get('/domains/acme-demo.mx/findings')
        self.assertEqual(code, 404)

    def test_6_sin_sesion_no_responde_datos_aunque_mande_el_encabezado(self):
        anonimo = sesion.Client()
        self.assertEqual(anonimo.get('/domains')[0], 401)
        self.assertEqual(anonimo.get('/domains', headers={'X-Organization': ACME})[0], 401)


if __name__ == '__main__':
    unittest.main(verbosity=2)
