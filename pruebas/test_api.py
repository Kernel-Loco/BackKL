"""Pruebas de la API de Cirdan contra el servidor local (biblioteca estándar).

Primero levanta la API desde implementacion/:
    python -m uvicorn api.main:app --port 8000
y luego:
    python -m unittest -v pruebas/test_api.py
"""
import json
import unittest
import urllib.error
import urllib.request

BASE = 'http://127.0.0.1:8000'
ACME = '20000000-0000-4000-8000-000000000001'
BETA = '20000000-0000-4000-8000-000000000002'


def get(path, org=None):
    req = urllib.request.Request(BASE + path, headers={'X-Organization': org} if org else {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


class ApiCirdan(unittest.TestCase):

    def test_1_entra_como_rol_sin_privilegios(self):
        code, body = get('/health')
        self.assertEqual(code, 200)
        self.assertEqual(body['role'], 'cirdan_app')

    def test_2_acme_ve_sus_cinco_dominios_con_score(self):
        code, body = get('/domains', ACME)
        self.assertEqual(code, 200)
        self.assertEqual([(d['domain'], d['score'], d['level']) for d in body[:3]],
                         [('acme-demo.mx', 68, 'High'), ('acme-tienda.mx', 54, 'Medium'), ('acme-portal.mx', 31, 'Low')])
        self.assertEqual({d['domain']: d['authorization'] for d in body[3:]},
                         {'partner-example.com': 'Pending TXT', 'old-example.net': 'Expired'})

    def test_3_score_por_categoria_cuadra_con_los_pesos(self):
        code, body = get('/domains/acme-demo.mx/score', ACME)
        self.assertEqual(code, 200)
        weighted = sum(c['score'] * c['weight'] for c in body['categories'])
        self.assertEqual(round(weighted), body['score'])
        self.assertEqual(body['score'], 68)

    def test_4_hallazgos_ordenados_por_severidad(self):
        code, body = get('/domains/acme-demo.mx/findings', ACME)
        self.assertEqual(code, 200)
        self.assertEqual([f['severity'] for f in body], ['Critical', 'High', 'High', 'Medium'])

    def test_5_beta_no_ve_los_dominios_de_acme(self):
        code, body = get('/domains', BETA)
        self.assertEqual(code, 200)
        self.assertNotIn('acme-demo.mx', [d['domain'] for d in body])
        code, _ = get('/domains/acme-demo.mx/findings', BETA)
        self.assertEqual(code, 404)

    def test_6_sin_organizacion_no_responde_datos(self):
        code, _ = get('/domains')
        self.assertEqual(code, 422)
        code, _ = get('/domains', 'no-es-un-uuid')
        self.assertEqual(code, 400)


if __name__ == '__main__':
    unittest.main(verbosity=2)
