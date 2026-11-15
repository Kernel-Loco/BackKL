"""Pruebas de la llave del MFA desde Azure Key Vault (#49, RC-91), sin red ni base.

`keyvault._abrir` es el único punto de red. Aquí se reemplaza por un falso que anota cada petición, salvo en la prueba
de redirección, que usa un servidor en 127.0.0.1. Revisan que la llave salga de una sola variable, que el token solo
vaya a una URL de Key Vault, que se lea una vez por proceso aunque lleguen muchas peticiones juntas, los reintentos de
IMDS y que ningún error lleve el token ni el valor.

    python -m unittest -v pruebas/test_llave_totp.py
"""
import asyncio
import base64
import http.server
import importlib
import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

from cirdan.auth import keyvault, totp

URL = 'https://kv-lowtide.vault.azure.net/secrets/totp-encryption-key'
TOKEN = 'CIRDAN_FAKE_token_imds'
LLAVE = base64.urlsafe_b64encode(b'CIRDAN_FAKE_llave_de_32_bytes_ok').decode()
assert len(base64.urlsafe_b64decode(LLAVE)) == 32


def _error(codigo):
    return urllib.error.HTTPError('http://x', codigo, 'x', {}, None)


class Falso:
    """Responde como IMDS y Key Vault. `imds` y `vault` son listas de respuestas (dict) o errores, en orden."""

    def __init__(self, imds=None, vault=None):
        self.imds = list(imds or [{'access_token': TOKEN}])
        self.vault = list(vault or [{'value': LLAVE}])
        self.peticiones = []
        self.candado = threading.Lock()

    def __call__(self, req):
        with self.candado:
            self.peticiones.append(req)
            cola = self.imds if req.full_url.startswith('http://169.254.169.254/') else self.vault
            r = cola.pop(0) if len(cola) > 1 else cola[0]
        if isinstance(r, BaseException):
            raise r
        return r


class Base(unittest.TestCase):
    def setUp(self):
        totp._llave_vault = None
        self.addCleanup(setattr, totp, '_llave_vault', None)
        # Sin .env de la PC: solo cuenta lo que pone cada prueba.
        p = mock.patch('cirdan.config._env_file', return_value={})
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(keyvault.time, 'sleep')
        self.sleep = p.start()
        self.addCleanup(p.stop)

    def env(self, **valores):
        limpio = {k: v for k, v in os.environ.items() if k not in ('TOTP_ENCRYPTION_KEY', 'TOTP_KEY_VAULT_SECRET_URL')}
        limpio.update(valores)
        p = mock.patch.dict(os.environ, limpio, clear=True)
        p.start()
        self.addCleanup(p.stop)

    def falso(self, **kw):
        f = Falso(**kw)
        p = mock.patch.object(keyvault, '_abrir', f)
        p.start()
        self.addCleanup(p.stop)
        return f


class Origen(Base):
    def test_llave_directa_sin_red(self):
        self.env(TOTP_ENCRYPTION_KEY=LLAVE)
        f = self.falso()
        self.assertEqual(totp._key(), base64.urlsafe_b64decode(LLAVE))
        self.assertEqual(f.peticiones, [])

    def test_vacias_cuentan_como_sin_poner(self):
        # Lo que pasa el compose con ${VAR:-}: la otra variable manda.
        self.env(TOTP_ENCRYPTION_KEY='', TOTP_KEY_VAULT_SECRET_URL=URL)
        self.falso()
        self.assertEqual(totp._key(), base64.urlsafe_b64decode(LLAVE))
        totp._llave_vault = None
        self.env(TOTP_ENCRYPTION_KEY=LLAVE, TOTP_KEY_VAULT_SECRET_URL='')
        self.assertEqual(totp._key(), base64.urlsafe_b64decode(LLAVE))

    def test_las_dos_puestas_no_arranca(self):
        self.env(TOTP_ENCRYPTION_KEY=LLAVE, TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso()
        with self.assertRaisesRegex(RuntimeError, 'quita TOTP_ENCRYPTION_KEY'):
            totp._key()
        self.assertEqual(f.peticiones, [])

    def test_ninguna_no_arranca(self):
        self.env()
        with self.assertRaisesRegex(RuntimeError, 'TOTP_ENCRYPTION_KEY o TOTP_KEY_VAULT_SECRET_URL'):
            totp.comprobar_llave()

    def test_llave_directa_mala(self):
        for mala in ('CIRDAN_FAKE_corta', '%%%%', base64.urlsafe_b64encode(b'x' * 31).decode()):
            self.env(TOTP_ENCRYPTION_KEY=mala)
            with self.assertRaisesRegex(RuntimeError, '32 bytes') as e:
                totp._key()
            self.assertNotIn(mala, str(e.exception))

    def test_cifra_y_descifra_con_la_de_key_vault(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        self.falso()
        blob = totp.encrypt_secret('JBSWY3DPEHPK3PXP', 7)
        self.env(TOTP_ENCRYPTION_KEY=LLAVE)
        self.assertEqual(totp.decrypt_secret(blob, 7), 'JBSWY3DPEHPK3PXP')


class Peticiones(Base):
    def test_imds_y_key_vault(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso()
        totp._key()
        imds, vault = f.peticiones
        self.assertEqual(imds.full_url, 'http://169.254.169.254/metadata/identity/oauth2/token'
                                        '?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net')
        self.assertEqual(imds.get_header('Metadata'), 'true')
        self.assertIsNone(imds.get_header('Authorization'))
        self.assertEqual(vault.full_url, URL + '?api-version=7.4')
        # El token va en un encabezado que urllib no copia a una redirección.
        self.assertNotIn('Authorization', vault.headers)
        self.assertEqual(vault.unredirected_hdrs['Authorization'], 'Bearer ' + TOKEN)
        self.assertIsNone(vault.get_header('Metadata'))

    def test_una_sola_lectura_aunque_lleguen_juntas(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso()
        salida = []
        hilos = [threading.Thread(target=lambda: salida.append(totp._key())) for _ in range(20)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join()
        self.assertEqual(len(salida), 20)
        self.assertEqual(set(salida), {base64.urlsafe_b64decode(LLAVE)})
        self.assertEqual(len(f.peticiones), 2)

    def test_reintenta_imds_al_arrancar(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso(imds=[_error(404), _error(503), urllib.error.URLError('x'), {'access_token': TOKEN}])
        self.assertEqual(totp._key(), base64.urlsafe_b64decode(LLAVE))
        self.assertEqual(len(f.peticiones), 5)
        self.assertEqual([c.args[0] for c in self.sleep.call_args_list], [0, 1, 2, 4, 0])

    def test_sin_rol_no_reintenta(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso(vault=[_error(403)])
        with self.assertRaisesRegex(RuntimeError, 'Key Vault respondió HTTP 403'):
            totp._key()
        self.assertEqual(len(f.peticiones), 2)
        self.assertIsNone(totp._llave_vault)

    def test_imds_caido_se_rinde(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso(imds=[urllib.error.URLError('x')])
        with self.assertRaisesRegex(RuntimeError, r'IMDS\) no respondió'):
            totp._key()
        self.assertEqual(len(f.peticiones), 1 + len(keyvault.ESPERAS))

    def test_errores_sin_token_ni_valor(self):
        casos = [
            dict(vault=[{'value': base64.urlsafe_b64encode(b'CIRDAN_FAKE_corta').decode()}]),
            dict(vault=[{'value': 'CIRDAN_FAKE_no_base64%%'}]),
            dict(vault=[{'otro': LLAVE}]),
            dict(vault=[_error(500)]),
            dict(imds=[{'token': TOKEN}]),
            dict(imds=[['CIRDAN_FAKE_lista']]),
        ]
        for kw in casos:
            totp._llave_vault = None
            self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
            self.falso(**kw)
            with self.assertRaises(RuntimeError) as e:
                totp._key()
            texto = str(e.exception) + repr(e.exception.__cause__) + repr(e.exception.__context__)
            for secreto in (TOKEN, LLAVE, 'CIRDAN_FAKE'):
                self.assertNotIn(secreto, texto, kw)


class Url(Base):
    def test_urls_que_no_son_de_key_vault(self):
        malas = [
            'http://kv-lowtide.vault.azure.net/secrets/totp',
            'https://kv-lowtide.vault.azure.net.example.com/secrets/totp',
            'https://example.com/secrets/totp?x=.vault.azure.net',
            'https://kv-lowtide.vault.azure.net:8443/secrets/totp',
            'https://user@kv-lowtide.vault.azure.net/secrets/totp',
            'https://kv-lowtide.vault.azure.net/secrets/totp?api-version=1',
            'https://kv-lowtide.vault.azure.net/secrets/totp#x',
            'https://kv-lowtide.vault.azure.net/keys/totp',
            'https://kv-lowtide.vault.azure.net/secrets/../keys/totp',
            'https://kv-lowtide.vault.azure.net/secrets/totp_mal',
            'https://kv-lowtide.vault.azure.net/secrets/',
            'https://169.254.169.254/secrets/totp',
            'https://a.vault.azure.net/secrets/totp',
            ' ' + URL,
            URL + '\n',
            'https://kv-lowtide.vault.azure.net:abc/secrets/totp',
            'https://kv-lowtide.vault.azure.net/secrets/to\ttp',
        ]
        for mala in malas:
            totp._llave_vault = None
            self.env(TOTP_KEY_VAULT_SECRET_URL=mala)
            f = self.falso()
            with self.assertRaisesRegex(RuntimeError, 'debe ser https://', msg=mala):
                totp._key()
            self.assertEqual(f.peticiones, [], mala)

    def test_urls_buenas(self):
        for buena in (URL, URL + '/0123456789abcdef0123456789abcdef', 'https://KV-Lowtide.vault.azure.net/secrets/t'):
            self.assertEqual(keyvault.validar_url(buena), buena)


class Redireccion(unittest.TestCase):
    """Con el opener real contra 127.0.0.1: una redirección no se sigue y no lleva el token a otro servidor."""

    def _servidor(self):
        vistos = []

        class Manejador(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                vistos.append((self.path, self.headers.get('Authorization')))
                if self.path.startswith('/inicio'):
                    self.send_response(302)
                    self.send_header('Location', '/otro')
                    self.end_headers()
                else:
                    cuerpo = json.dumps({'value': LLAVE}).encode()
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(cuerpo)))
                    self.end_headers()
                    self.wfile.write(cuerpo)

            def log_message(self, *a):
                pass

        servidor = http.server.HTTPServer(('127.0.0.1', 0), Manejador)
        threading.Thread(target=servidor.serve_forever, daemon=True).start()
        self.addCleanup(servidor.server_close)
        self.addCleanup(servidor.shutdown)
        return 'http://127.0.0.1:%d' % servidor.server_port, vistos

    def test_no_sigue_redirecciones(self):
        base, vistos = self._servidor()
        req = urllib.request.Request(base + '/inicio')
        req.add_unredirected_header('Authorization', 'Bearer ' + TOKEN)
        with self.assertRaises(urllib.error.HTTPError) as e:
            keyvault._abrir(req)
        e.exception.close()
        self.assertEqual(e.exception.code, 302)
        self.assertEqual(vistos, [('/inicio', 'Bearer ' + TOKEN)])

    def test_sin_proxy(self):
        # Un HTTP_PROXY del entorno al cargar el módulo no se usa: el token de IMDS no pasa por otro servidor. El
        # proxy apunta a un puerto cerrado: si se usara, la petición fallaría.
        base, vistos = self._servidor()
        self.addCleanup(importlib.reload, keyvault)
        with mock.patch.dict(os.environ, {'HTTP_PROXY': 'http://127.0.0.1:9', 'http_proxy': 'http://127.0.0.1:9',
                                          'NO_PROXY': '', 'no_proxy': ''}):
            importlib.reload(keyvault)
            self.assertEqual(keyvault._abrir(urllib.request.Request(base + '/secreto')), {'value': LLAVE})
        self.assertEqual(vistos, [('/secreto', None)])


FALSOS = {'CIRDAN_APP_PASSWORD': 'CIRDAN_FAKE_app'}


class Arranque(Base):
    """El lifespan de la API, el que corre uvicorn al arrancar. Importar la API pide la contraseña de la base,
    pero no se conecta."""

    def _arrancar(self):
        from cirdan.api import main

        async def correr():
            async with main.app.router.lifespan_context(main.app):
                pass
        asyncio.run(correr())

    def test_la_api_no_arranca_sin_llave(self):
        self.env(**FALSOS)
        with self.assertRaisesRegex(RuntimeError, 'Falta TOTP_ENCRYPTION_KEY o TOTP_KEY_VAULT_SECRET_URL'):
            self._arrancar()

    def test_la_api_no_arranca_sin_rol_en_key_vault(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL, **FALSOS)
        self.falso(vault=[_error(403)])
        with self.assertRaisesRegex(RuntimeError, 'HTTP 403'):
            self._arrancar()

    def test_la_api_arranca_con_key_vault(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL, **FALSOS)
        f = self.falso()
        self._arrancar()
        self.assertEqual(len(f.peticiones), 2)
        self.assertEqual(totp._llave_vault[1], base64.urlsafe_b64decode(LLAVE))


if __name__ == '__main__':
    unittest.main()
