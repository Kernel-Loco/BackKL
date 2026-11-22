"""Pruebas de RC-286: publicada por HTTPS, la API no arranca con la cookie de sesión sin Secure. Sin red.

Un origen https en ALLOWED_ORIGINS y COOKIE_SECURE distinto de true: la API no arranca y el error nombra la variable.
Con los orígenes locales (http://localhost) arranca como siempre. Las de proceso arrancan la API de verdad con el CMD
del Dockerfile en 127.0.0.1 y piden la base para /health, así que corren dentro del contenedor:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_cookie_segura.py
"""
import asyncio
import os
import subprocess
import sys
import unittest
from unittest import mock

from cirdan import config as cfg
from cirdan.api import main
from cirdan.auth import deps
from pruebas.test_documentacion_api import Api, cmd_del_dockerfile

PUBLICADO = 'https://pruebas.lowtidesec.com'
LOCALES = cfg.ORIGENES_LOCALES


def comprobar(origenes, segura):
    """Corre comprobar_cookie_segura con esos orígenes (None: sin poner) y ese COOKIE_SECURE."""
    entorno = {} if origenes is None else {'ALLOWED_ORIGINS': origenes}
    with mock.patch.dict(os.environ, entorno, clear=True), mock.patch.object(cfg, '_env_file', lambda: {}), \
            mock.patch.object(deps, 'COOKIE_SECURE', segura):
        deps.comprobar_cookie_segura()


class Regla(unittest.TestCase):
    def test_1_https_sin_secure_no_arranca(self):
        for origenes in (PUBLICADO, LOCALES + ',' + PUBLICADO, ' HTTPS://Pruebas.lowtidesec.com '):
            with self.subTest(origenes=origenes), self.assertRaises(RuntimeError) as error:
                comprobar(origenes, False)
            self.assertIn('COOKIE_SECURE', str(error.exception))

    def test_2_https_con_secure_arranca(self):
        comprobar(PUBLICADO, True)
        comprobar('https://lowtidesec.com,https://www.lowtidesec.com', True)

    def test_3_local_arranca_como_siempre(self):
        for origenes in (None, '', LOCALES, 'http://lowtidesec.com'):
            for segura in (False, True):
                with self.subTest(origenes=origenes, segura=segura):
                    comprobar(origenes, segura)

    def test_4_el_lifespan_lo_revisa_antes_que_las_llaves(self):
        # Antes que la llave del MFA, que con Key Vault puede tardar: el error sale al arrancar y sin esperar.
        async def arrancar():
            async with main.app.router.lifespan_context(main.app):
                pass

        with mock.patch.dict(os.environ, {'ALLOWED_ORIGINS': PUBLICADO}), \
                mock.patch.object(deps, 'COOKIE_SECURE', False), \
                mock.patch.object(main.totp, 'comprobar_llave') as llave, self.assertRaises(RuntimeError) as error:
            asyncio.run(arrancar())
        self.assertIn('COOKIE_SECURE', str(error.exception))
        llave.assert_not_called()


class Proceso(unittest.TestCase):
    """La API de verdad, con el CMD del Dockerfile. Sin las variables del .env que pudieran ganarle."""

    def test_5_https_sin_secure_el_proceso_termina_con_el_error(self):
        cmd = cmd_del_dockerfile()
        cmd[cmd.index('--host') + 1] = '127.0.0.1'
        cmd[cmd.index('--port') + 1] = '18286'
        entorno = dict(os.environ, ALLOWED_ORIGINS=PUBLICADO, COOKIE_SECURE='false')
        r = subprocess.run([sys.executable] + cmd[1:], env=entorno, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('COOKIE_SECURE no es true', r.stderr)

    def test_6_https_con_secure_arranca_y_responde(self):
        api = Api(18287, ALLOWED_ORIGINS=PUBLICADO, COOKIE_SECURE='true')
        try:
            self.assertEqual(api.get('/health')[0], 200)
        finally:
            api.cerrar()

    def test_7_local_sin_secure_arranca_y_responde(self):
        api = Api(18288, ALLOWED_ORIGINS=None, COOKIE_SECURE='false')
        try:
            self.assertEqual(api.get('/health')[0], 200)
        finally:
            api.cerrar()


if __name__ == '__main__':
    unittest.main()
