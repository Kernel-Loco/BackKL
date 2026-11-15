"""Pruebas del explorador de la base (/db) y de la página /demo (RC-58).

DEMO_EXPLORER se lee al arrancar la API. Por eso estas pruebas levantan dentro del contenedor dos
API propias sobre la misma base y el mismo Valkey, una con DEMO_EXPLORER=false, como queda por
omisión, y otra con DEMO_EXPLORER=true:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_explorador.py

Las sesiones se crean con cirdan.auth.sessions, igual que al iniciar sesión, y se borran al final.
Solo leen: la base queda igual.
"""
import asyncio
import json
import os
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

from cirdan.api.explorer import TABLES
from cirdan.auth import sessions

ACME = '20000000-0000-4000-8000-000000000001'
BETA = '20000000-0000-4000-8000-000000000002'
# Usuarios de la semilla, los mismos de cirdan/auth/demo.py
ALEX = {'user_id': '30000000-0000-4000-8000-000000000001', 'org_id': ACME, 'role': 'admin', 'email': 'alex.morgan@acme-demo.mx'}
DANA = {'user_id': '30000000-0000-4000-8000-000000000004', 'org_id': BETA, 'role': 'admin', 'email': 'dana.cruz@beta-corp.mx'}
MAYA = {'user_id': '30000000-0000-4000-8000-000000000002', 'org_id': ACME, 'role': 'manager', 'email': 'maya.reed@acme-demo.mx'}
JORDAN = {'user_id': '30000000-0000-4000-8000-000000000003', 'org_id': ACME, 'role': 'analyst', 'email': 'jordan.tate@acme-demo.mx'}
SIN_SESION = 'Tu sesión terminó. Vuelve a iniciar sesión.'
SIN_PERMISO = 'Tu rol no tiene permiso para esta acción.'
RUTAS = ('/db/tables', '/db/tables/users/rows', '/demo')


class Api:
    """Una API propia en 127.0.0.1, con el comando del Dockerfile y las variables que se le den."""

    def __init__(self, puerto, **variables):
        self.base = 'http://127.0.0.1:%d' % puerto
        # false aunque haya un .env con true: config() lee primero el entorno
        entorno = dict(os.environ, DEMO_EXPLORER='false')
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
    """Con DEMO_EXPLORER=false, como queda por omisión."""
    puerto = 8101

    def test_1_por_omision_no_existen_db_ni_demo(self):
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
                    self.assertEqual(code, 401, body)
                    self.assertEqual(body['detail'], SIN_SESION)
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
        # Las 25 tablas: si una tabla nueva del explorador entra sin RLS, falla aquí. scoring_rule_texts y
        # scoring_rule_framework_mappings no tienen RLS, pero son catálogos globales que no nombran clientes.
        for tabla in TABLES:
            with self.subTest(tabla=tabla):
                filas = self.filas(tabla, self.beta, ACME)
                organizaciones = {f.get('organization_id', 'Beta Corp') for f in filas}
                permitidas = {'Beta Corp', '—'} if tabla == 'scoring_rule_sets' else {'Beta Corp'}
                self.assertLessEqual(organizaciones, permitidas)
                texto = json.dumps(filas, ensure_ascii=False).lower()
                self.assertNotIn('acme', texto)
                self.assertNotIn('olmardo', texto)
        self.assertEqual([u['email'] for u in self.filas('users', self.beta, ACME)], ['dana.cruz@beta-corp.mx'])
        dominios = [d['fqdn'] for d in self.filas('domains', self.beta, ACME)]
        self.assertNotIn('acme-demo.mx', dominios)
        self.assertNotIn('olmardo.com', dominios)

    def test_5b_de_cves_solo_las_que_nombran_sus_hallazgos(self):
        """cves no tiene RLS y la llenan los escaneos de todas las empresas (#18): una CVE que nombra un hallazgo de
        Acme la ve Acme y no Beta, y una que no nombra ningún hallazgo suyo no la ve ninguna."""
        from cirdan.db import transaction
        de_acme, de_nadie = 'CVE-2099-46001', 'CVE-2099-46002'
        with transaction(ACME) as conn:
            for cve in (de_acme, de_nadie):
                conn.execute('INSERT INTO cves (cve_id) VALUES (%s) ON CONFLICT (cve_id) DO NOTHING', (cve,))
            hallazgo = conn.execute('SELECT id FROM findings WHERE cve_id IS NULL LIMIT 1').fetchone()['id']
            conn.execute('UPDATE findings SET cve_id = %s WHERE id = %s', (de_acme, hallazgo))

        def limpiar():
            with transaction(ACME) as conn:
                conn.execute('UPDATE findings SET cve_id = NULL WHERE id = %s', (hallazgo,))
        self.addCleanup(limpiar)
        de = lambda sesion, org: [f['cve_id'] for f in self.filas('cves', sesion, org)]
        self.assertEqual(de(self.acme, BETA), [de_acme])
        self.assertEqual(de(self.beta, ACME), [])
        for sesion, cuantas in ((self.acme, 1), (self.beta, 0)):
            tablas = {t['table']: t['rows'] for t in self.api.get('/db/tables', sesion)[1]['tables']}
            self.assertEqual(tablas['cves'], cuantas)

    def test_6_la_pagina_demo_inicia_sesion_y_no_manda_el_encabezado(self):
        # La página no trae datos: los pide con la cookie. Sin sesión muestra el inicio de sesión.
        code, html = self.api.get('/demo')
        self.assertEqual(code, 200)
        for ruta in ('/api/v1/auth/me', '/api/v1/auth/login', '/api/v1/auth/mfa/verify', '/api/v1/auth/logout'):
            self.assertIn(ruta, html)
        self.assertNotIn('X-Organization', html)
        # Ya no trae los ids de las empresas para elegir una: la empresa solo sale de la sesión.
        self.assertNotIn(ACME, html)
        self.assertNotIn(BETA, html)

    def test_7_las_tablas_son_solo_para_admin(self):
        # Traen usuarios, bitácora y valores TXT, que la API solo da a Administración (GET /api/v1/domains/txt).
        for rol, datos in (('analista', JORDAN), ('gerente', MAYA)):
            token = sessions.create(datos)
            self.addCleanup(sessions.delete, token)
            for ruta in ('/db/tables', '/db/tables/users/rows', '/db/tables/dns_txt_verifications/rows'):
                with self.subTest(rol=rol, ruta=ruta):
                    code, body = self.api.get(ruta, token, org=BETA)
                    self.assertEqual(code, 403, body)
                    self.assertEqual(body['detail'], SIN_PERMISO)
            self.assertEqual(self.api.get('/api/v1/domains/txt', token)[0], 403, 'la misma regla que la API v1')
            self.assertEqual(self.api.get('/domains', token)[0], 200, 'los dominios de la página sí le responden')


class ErrorSinManejar(unittest.TestCase):
    """RC-283: el 500 de un error que ninguna ruta maneja también sale con las tres cabeceras.

    Llama a la aplicación en el mismo proceso, sin servidor, con la base de /health cambiada por una que falla.
    """

    def test_1_el_500_trae_la_proteccion_contra_marcos_y_nosniff(self):
        from cirdan.api import main

        def base_caida(*args, **kwargs):
            raise ConnectionError('base caída de prueba')

        scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': 'GET', 'scheme': 'http',
                 'path': '/health', 'raw_path': b'/health', 'query_string': b'', 'headers': [],
                 'client': ('127.0.0.1', 1), 'server': ('127.0.0.1', 80)}
        mensajes = []

        async def receive():
            return {'type': 'http.request', 'body': b'', 'more_body': False}

        async def send(mensaje):
            mensajes.append(mensaje)

        with mock.patch.object(main, 'transaction', base_caida):
            # Starlette manda el 500 y después vuelve a lanzar el error para que el servidor lo registre
            with self.assertRaises(ConnectionError):
                asyncio.run(main.app(scope, receive, send))
        inicio = [m for m in mensajes if m['type'] == 'http.response.start']
        self.assertEqual([m['status'] for m in inicio], [500])
        cabeceras = [(k.decode().lower(), v.decode()) for k, v in inicio[0]['headers']]
        for nombre, valor in main.CABECERAS_SEGURIDAD.items():
            self.assertEqual([v for k, v in cabeceras if k == nombre.lower()], [valor], nombre)
        cuerpo = b''.join(m.get('body', b'') for m in mensajes if m['type'] == 'http.response.body')
        self.assertEqual(cuerpo, b'Internal Server Error')


if __name__ == '__main__':
    unittest.main(verbosity=2)
