"""Documentación de la API y encabezado Server (comentario 10063 de RC-91).

API_DOCS se lee al arrancar la API. Por eso estas pruebas levantan dentro del contenedor dos API propias, una con
API_DOCS=false, como la fija el despliegue, y otra con API_DOCS=true, como queda en desarrollo. Las dos corren con el
CMD del Dockerfile, que se lee del propio Dockerfile, así que la del despliegue manda el mismo `--no-server-header`:

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
        entorno.update(variables)
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


class DocumentacionPuesta(unittest.TestCase):
    """Con API_DOCS=true, como en desarrollo: las tres rutas siguen, también sin encabezado Server."""

    @classmethod
    def setUpClass(cls):
        cls.api = Api(8104, API_DOCS='true')
        cls.addClassCleanup(cls.api.cerrar)

    def test_1_rutas_de_documentacion(self):
        for ruta in RUTAS_DOCS:
            code, headers = self.api.get(ruta)
            self.assertEqual(code, 200, ruta)
            self.assertIsNone(headers.get('Server'), ruta)


if __name__ == '__main__':
    unittest.main()
