"""Documentación de la API y encabezado Server (comentario 10063 de RC-91).

API_DOCS se lee al arrancar la API. Por eso estas pruebas levantan dentro del contenedor tres API propias: una sin
API_DOCS, que por omisión no publica la documentación (RC-303), otra con API_DOCS=false, como la fija el despliegue, y
otra con API_DOCS=true, como se pone en una PC para ver /docs. Las tres corren con el CMD del Dockerfile, que se lee
del propio Dockerfile, así que la del despliegue manda el mismo `--no-server-header`:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" -v "$PWD/Dockerfile:/app/Dockerfile:ro" api python -m unittest -v pruebas/test_documentacion_api.py

Sin el Dockerfile montado, usan los argumentos de uvicorn que pruebas/test_despliegue.py exige en ese CMD. No tocan la
base.
"""
import json
import os
import re
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[1] / 'Dockerfile'
ENV_LOCAL = Path(__file__).resolve().parents[1] / '.env'
# Lo que pruebas/test_despliegue.py exige en el CMD del Dockerfile.
CMD_ESPERADO = ['python', '-m', 'uvicorn', 'cirdan.api.main:app', '--host', '0.0.0.0', '--port', '8000',
                '--proxy-headers', '--no-server-header']
RUTAS_DOCS = ('/openapi.json', '/docs', '/redoc')


def cmd_del_dockerfile():
    """El CMD en forma JSON del Dockerfile, con sus líneas continuadas unidas. Sin Dockerfile, CMD_ESPERADO."""
    if not DOCKERFILE.exists():
        return list(CMD_ESPERADO)
    texto = re.sub(r'\\\n\s*', '', DOCKERFILE.read_text(encoding='utf-8'))
    cmds = [l[len('CMD'):].strip() for l in texto.splitlines() if l.startswith('CMD ')]
    return json.loads(cmds[-1])


class Api:
    """Una API propia en 127.0.0.1 con el CMD del Dockerfile, otro puerto y las variables que se le den."""

    def __init__(self, puerto, **variables):
        self.base = 'http://127.0.0.1:%d' % puerto
        cmd = cmd_del_dockerfile()
        assert cmd[:3] == ['python', '-m', 'uvicorn'], cmd
        cmd[cmd.index('--host') + 1] = '127.0.0.1'
        cmd[cmd.index('--port') + 1] = str(puerto)
        entorno = dict(os.environ, DEMO_EXPLORER='false')
        for nombre, valor in variables.items():   # None quita la variable: la API usa su valor por omisión
            if valor is None:
                entorno.pop(nombre, None)
            else:
                entorno[nombre] = valor
        self.proc = subprocess.Popen([sys.executable] + cmd[1:] + ['--log-level', 'warning'], env=entorno)
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

    def get(self, ruta):
        """(código, encabezados) de un GET."""
        try:
            with urllib.request.urlopen(self.base + ruta, timeout=10) as r:
                return r.status, r.headers
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.headers


def api_docs_en_env_local():
    """Si el .env de la raíz trae API_DOCS: cirdan/config.py lo lee cuando la variable no está en el entorno. En el
    contenedor no hay .env (.dockerignore)."""
    return ENV_LOCAL.exists() and any(l.startswith('API_DOCS=') for l in ENV_LOCAL.read_text(encoding='utf-8').split())


@unittest.skipIf(api_docs_en_env_local(), 'el .env de la raíz trae API_DOCS: no se puede ver el valor por omisión')
class DocumentacionPorOmision(unittest.TestCase):
    """Sin API_DOCS en el entorno las tres rutas no existen (RC-303)."""

    @classmethod
    def setUpClass(cls):
        cls.api = Api(8105, API_DOCS=None)
        cls.addClassCleanup(cls.api.cerrar)

    def test_1_sin_rutas_de_documentacion(self):
        for ruta in RUTAS_DOCS:
            code, _ = self.api.get(ruta)
            self.assertEqual(code, 404, ruta)
        self.assertEqual(self.api.get('/health')[0], 200)


class DocumentacionApagada(unittest.TestCase):
    """Con API_DOCS=false, como en el despliegue."""

    @classmethod
    def setUpClass(cls):
        cls.api = Api(8103, API_DOCS='false')
        cls.addClassCleanup(cls.api.cerrar)

    def test_1_sin_rutas_de_documentacion(self):
        for ruta in RUTAS_DOCS:
            code, _ = self.api.get(ruta)
            self.assertEqual(code, 404, ruta)

    def test_2_sin_encabezado_server(self):
        for ruta in ('/health', '/openapi.json'):
            _, headers = self.api.get(ruta)
            self.assertIsNone(headers.get('Server'), ruta)

    def test_3_la_api_sigue_respondiendo(self):
        code, _ = self.api.get('/health')
        self.assertEqual(code, 200)

    def test_4_sin_api_docs_no_hay_csp_de_documentacion(self):
        """RC-89: la CSP de /docs y /redoc solo existe con API_DOCS=true. Sin ella, su 404 lleva la de la API."""
        for ruta in ('/docs', '/redoc'):
            _, headers = self.api.get(ruta)
            csp = headers.get('Content-Security-Policy', '')
            self.assertNotIn('cdn.jsdelivr.net', csp, ruta)
            self.assertIn("default-src 'none'", csp, ruta)


class DocumentacionPuesta(unittest.TestCase):
    """Con API_DOCS=true, como se pone en una PC: las tres rutas existen, también sin encabezado Server."""

    @classmethod
    def setUpClass(cls):
        cls.api = Api(8104, API_DOCS='true')
        cls.addClassCleanup(cls.api.cerrar)

    def test_1_rutas_de_documentacion(self):
        for ruta in RUTAS_DOCS:
            code, headers = self.api.get(ruta)
            self.assertEqual(code, 200, ruta)
            self.assertIsNone(headers.get('Server'), ruta)

    def test_2_docs_y_redoc_con_su_csp(self):
        """RC-89: la CSP de la API (default-src 'none') dejaría /docs y /redoc en blanco. Llevan la suya, que deja
        cargar swagger-ui y redoc de cdn.jsdelivr.net y sigue sin dejar meterlas en un marco."""
        for ruta in ('/docs', '/docs/oauth2-redirect', '/redoc'):
            _, headers = self.api.get(ruta)
            csp = headers.get('Content-Security-Policy', '')
            self.assertIn("script-src 'unsafe-inline' https://cdn.jsdelivr.net", csp, ruta)
            self.assertIn("frame-ancestors 'none'", csp, ruta)
            self.assertIn("base-uri 'none'", csp, ruta)
            self.assertEqual(headers.get('X-Frame-Options'), 'DENY', ruta)
        # El resto de la API sigue con la CSP que no deja cargar nada.
        for ruta in ('/openapi.json', '/health'):
            _, headers = self.api.get(ruta)
            csp = headers.get('Content-Security-Policy', '')
            self.assertTrue(csp.startswith("default-src 'none'; frame-ancestors"), ruta)
            self.assertNotIn('cdn.jsdelivr.net', csp, ruta)


if __name__ == '__main__':
    unittest.main()
