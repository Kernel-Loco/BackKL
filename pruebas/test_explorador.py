"""Pruebas del explorador de la base (/db) y de la página /demo (RC-58).

DEMO_EXPLORER se lee al arrancar la API. Por eso estas pruebas levantan dentro del contenedor dos
API propias sobre la misma base y el mismo Valkey, una sin la variable y otra con DEMO_EXPLORER=true:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_explorador.py

Las sesiones se crean con cirdan.auth.sessions, igual que al iniciar sesión, y se borran al final.
Solo leen: la base queda igual.
"""
import json
import os
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

from cirdan.auth import sessions

ACME = '20000000-0000-4000-8000-000000000001'
BETA = '20000000-0000-4000-8000-000000000002'
# Usuarios de la semilla, los mismos de cirdan/auth/demo.py
ALEX = {'user_id': '30000000-0000-4000-8000-000000000001', 'org_id': ACME, 'role': 'admin', 'email': 'alex.morgan@acme-demo.mx'}
DANA = {'user_id': '30000000-0000-4000-8000-000000000004', 'org_id': BETA, 'role': 'admin', 'email': 'dana.cruz@beta-corp.mx'}
SIN_SESION = 'Tu sesión terminó. Vuelve a iniciar sesión.'
RUTAS = ('/db/tables', '/db/tables/users/rows', '/demo')


class Api:
    """Una API propia en 127.0.0.1, con el comando del Dockerfile y las variables que se le den."""

    def __init__(self, puerto, **variables):
        self.base = 'http://127.0.0.1:%d' % puerto
        entorno = {k: v for k, v in os.environ.items() if k != 'DEMO_EXPLORER'}
        entorno.update(variables)
        self.proc = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'cirdan.api.main:app', '--host', '127.0.0.1',
                                      '--port', str(puerto), '--log-level', 'warning'], env=entorno)
        for _ in range(100):
            if self.proc.poll() is not None:
                break
            try:
                urllib.request.urlopen(self.base + '/health', timeout=1).close()
                return
            except OSError:
                time.sleep(0.2)
        self.cerrar()
        raise RuntimeError('La API de prueba no arrancó en el puerto %d' % puerto)

    def cerrar(self):
        self.proc.terminate()
        self.proc.wait(10)

    def get(self, ruta, sesion=None, org=None):
        """(código, cuerpo) de un GET con la cookie de sesión y el encabezado X-Organization que se den."""
        headers = {}
        if sesion:
            headers['Cookie'] = 'lt_session=' + sesion
        if org:
            headers['X-Organization'] = org
        try:
            with urllib.request.urlopen(urllib.request.Request(self.base + ruta, headers=headers), timeout=10) as r:
                code, tipo, raw = r.status, r.headers.get_content_type(), r.read()
        except urllib.error.HTTPError as e:
            with e:
                code, tipo, raw = e.code, e.headers.get_content_type(), e.read()
        return code, json.loads(raw) if tipo == 'application/json' else raw.decode()


class Explorador(unittest.TestCase):
    puerto = None
    variables = {}

    @classmethod
    def setUpClass(cls):
        cls.api = Api(cls.puerto, **cls.variables)
        cls.addClassCleanup(cls.api.cerrar)
        cls.acme, cls.beta = sessions.create(ALEX), sessions.create(DANA)
        cls.addClassCleanup(sessions.delete, cls.acme)
        cls.addClassCleanup(sessions.delete, cls.beta)

    def filas(self, tabla, sesion, org):
        """Filas de /db/tables/<tabla>/rows como diccionarios por columna."""
        code, body = self.api.get('/db/tables/%s/rows' % tabla, sesion, org)
        self.assertEqual(code, 200, body)
        return [dict(zip(body['columns'], r)) for r in body['rows']]


class ExploradorApagado(Explorador):
    """Sin DEMO_EXPLORER, como queda por omisión."""
    puerto = 8101

    def test_1_sin_la_variable_no_existen_db_ni_demo(self):
        for ruta in RUTAS:
            for nombre, sesion in (('sin sesión', None), ('con la sesión de Acme', self.acme)):
                with self.subTest(ruta=ruta, caso=nombre):
                    self.assertEqual(self.api.get(ruta, sesion, org=BETA)[0], 404)

    def test_2_tampoco_salen_en_la_documentacion(self):
        code, body = self.api.get('/openapi.json')
        self.assertEqual(code, 200)
        self.assertEqual([p for p in body['paths'] if p.startswith('/db')], [])
        self.assertIn('/domains', body['paths'])
        self.assertEqual(self.api.get('/domains', self.acme)[0], 200, 'el resto de la API sigue igual')


class ExploradorEncendido(Explorador):
    """Con DEMO_EXPLORER=true, solo para la demo."""
    puerto = 8102
    variables = {'DEMO_EXPLORER': 'true'}

    def test_3_sin_sesion_responde_401_aunque_mande_el_encabezado(self):
        for ruta in ('/db/tables', '/db/tables/users/rows'):
            for nombre, sesion in (('sin cookie', None), ('cookie que no es una sesión', 'no-es-una-sesion')):
                with self.subTest(ruta=ruta, caso=nombre):
                    code, body = self.api.get(ruta, sesion, org=BETA)
                    self.assertEqual((code, body['detail']), (401, SIN_SESION))
        self.assertEqual(self.api.get('/domains', org=BETA)[1]['detail'], SIN_SESION, 'la misma respuesta que /domains')

    def test_4_acme_ve_solo_lo_suyo_aunque_el_encabezado_diga_beta(self):
        code, body = self.api.get('/db/tables', self.acme, org=BETA)
        self.assertEqual(code, 200)
        self.assertEqual((body['organization'], body['role']), ('Acme Demo', 'cirdan_app'))
        filas = {t['table']: t['rows'] for t in body['tables']}
        self.assertEqual((filas['domains'], filas['findings'], filas['users']), (5, 4, 3))
        usuarios = self.filas('users', self.acme, BETA)
        self.assertEqual({u['organization_id'] for u in usuarios}, {'Acme Demo'})
        self.assertEqual(sorted(u['email'] for u in usuarios),
                         ['alex.morgan@acme-demo.mx', 'jordan.tate@acme-demo.mx', 'maya.reed@acme-demo.mx'])

    def test_5_beta_no_ve_las_filas_de_acme_ni_las_de_olmardo(self):
        code, body = self.api.get('/db/tables', self.beta, org=ACME)
        self.assertEqual(code, 200)
        self.assertEqual(body['organization'], 'Beta Corp')
        filas = {t['table']: t['rows'] for t in body['tables']}
        self.assertEqual((filas['domains'], filas['findings'], filas['users']), (1, 1, 1))
        for tabla in ('users', 'domains', 'findings', 'assets'):
            with self.subTest(tabla=tabla):
                self.assertLessEqual({f['organization_id'] for f in self.filas(tabla, self.beta, ACME)}, {'Beta Corp'})
        self.assertEqual([u['email'] for u in self.filas('users', self.beta, ACME)], ['dana.cruz@beta-corp.mx'])
        dominios = [d['fqdn'] for d in self.filas('domains', self.beta, ACME)]
        self.assertNotIn('acme-demo.mx', dominios)
        self.assertNotIn('olmardo.com', dominios)

    def test_6_la_pagina_demo_inicia_sesion_y_no_manda_el_encabezado(self):
        # La página no trae datos: los pide con la cookie. Sin sesión muestra el inicio de sesión.
        code, html = self.api.get('/demo')
        self.assertEqual(code, 200)
        for ruta in ('/api/v1/auth/me', '/api/v1/auth/login', '/api/v1/auth/mfa/verify', '/api/v1/auth/logout'):
            self.assertIn(ruta, html)
        self.assertNotIn('X-Organization', html)


if __name__ == '__main__':
    unittest.main(verbosity=2)
