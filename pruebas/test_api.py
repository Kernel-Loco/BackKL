"""Pruebas de la API de Cirdan contra el servidor local (biblioteca estándar).

Desde la raíz del repo, con todo levantado (`docker compose up -d`, DEMO_ACCOUNTS=true):
    python -m unittest -v pruebas/test_api.py

Cada empresa entra con la sesión de una cuenta de demo: la empresa sale de la sesión,
no de un encabezado (#25).
"""
import unittest
import urllib.error
import urllib.request

from pruebas import sesion

ACME = '20000000-0000-4000-8000-000000000001'
BETA = '20000000-0000-4000-8000-000000000002'


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

    def test_2_las_rutas_de_antes_de_api_v1_no_dan_datos_sin_sesion(self):
        # RC-58: /domains, /domains/{fqdn}/findings y /score solo existen con DEMO_EXPLORER=true (404 sin ella) y ahí
        # piden sesión (401). Los dos modos y sus datos los prueba pruebas/test_explorador.py dentro del contenedor.
        anonimo = sesion.Client()
        for ruta in ('/domains', '/domains/acme-demo.mx/findings', '/domains/acme-demo.mx/score'):
            with self.subTest(ruta=ruta):
                self.assertIn(anonimo.get(ruta, headers={'X-Organization': ACME})[0], (401, 404))

    def test_7_el_explorador_de_la_base_no_lee_otra_empresa_sin_sesion(self):
        # RC-58: sin DEMO_EXPLORER=true, /db no existe (404). Con ella pide sesión (401). Nunca 200 por el encabezado.
        # Los dos modos los prueba pruebas/test_explorador.py dentro del contenedor.
        code, body = sesion.Client().get('/db/tables/users/rows', headers={'X-Organization': BETA})
        self.assertIn(code, (401, 404), body)

    def test_8_toda_respuesta_trae_la_proteccion_contra_marcos_y_nosniff(self):
        # RC-283: también los errores y el 403 que da el middleware de origen antes de llegar a una ruta
        casos = (('GET', '/health', None, 200), ('GET', '/api/v1/domains', None, 401), ('GET', '/no-existe', None, 404),
                 ('GET', '/docs', None, 200), ('POST', '/api/v1/auth/logout', 'https://otro.example', 403))
        for metodo, ruta, origen, esperado in casos:
            req = urllib.request.Request(sesion.BASE + ruta, method=metodo,
                                         headers={'Origin': origen} if origen else {})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    estado, cabeceras = r.status, r.headers
            except urllib.error.HTTPError as e:
                estado, cabeceras = e.code, e.headers
            with self.subTest(ruta=ruta):
                self.assertEqual(estado, esperado)
                self.assertEqual(cabeceras.get_all('X-Frame-Options'), ['DENY'])
                self.assertEqual(cabeceras.get_all('X-Content-Type-Options'), ['nosniff'])
                self.assertEqual(cabeceras.get_all('Content-Security-Policy'), ["frame-ancestors 'none'"])


if __name__ == '__main__':
    unittest.main(verbosity=2)
