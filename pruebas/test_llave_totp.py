"""Pruebas de la llave del MFA desde Azure Key Vault (#49, RC-91), sin red ni base.

`keyvault._abrir` es el único punto de red. Aquí se reemplaza por un falso que anota cada petición, salvo en la prueba
de redirección, que usa un servidor en 127.0.0.1. El reloj y las esperas de keyvault también son falsos. Revisan que
la llave salga de una sola variable, que el token solo vaya a una URL de Key Vault con versión, que se lea una vez por
proceso aunque lleguen muchas peticiones juntas, los reintentos y el plazo de IMDS y de la bóveda, y que ningún error
lleve el token ni el valor, tampoco en el traceback.

    python -m unittest -v pruebas/test_llave_totp.py
"""
import asyncio
import base64
import http.client
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

VERSION = '0123456789abcdef0123456789abcdef'
URL = 'https://kv-lowtide.vault.azure.net/secrets/totp-encryption-key/' + VERSION
TOKEN = 'CIRDAN_FAKE_token_imds'
LLAVE = base64.urlsafe_b64encode(b'CIRDAN_FAKE_llave_de_32_bytes_ok').decode()
assert len(base64.urlsafe_b64decode(LLAVE)) == 32


def _error(codigo):
    return urllib.error.HTTPError('http://x', codigo, 'x', {}, None)


class Falso:
    """Responde como IMDS y Key Vault. `imds` y `vault` son listas de respuestas (dict) o errores, en orden. Cada
    petición adelanta el reloj falso `avanza` segundos, sin pasar de su timeout, como un intento que se agota."""

    def __init__(self, reloj, imds=None, vault=None, avanza=0):
        self.imds = list(imds or [{'access_token': TOKEN}])
        self.vault = list(vault or [{'value': LLAVE}])
        self.reloj = reloj
        self.avanza = avanza
        self.peticiones = []
        self.llamadas = []  # (hora del reloj falso, timeout)
        self.autorizacion = []  # el encabezado Authorization al momento de la petición
        self.candado = threading.Lock()

    def __call__(self, req, timeout):
        with self.candado:
            self.peticiones.append(req)
            self.llamadas.append((self.reloj[0], timeout))
            self.autorizacion.append(req.unredirected_hdrs.get('Authorization'))
            self.reloj[0] += min(self.avanza, timeout)
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
        # Reloj falso: las esperas lo adelantan sin dormir.
        self.reloj = [0.0]
        p = mock.patch.object(keyvault, '_reloj', lambda: self.reloj[0])
        p.start()
        self.addCleanup(p.stop)
        self.sleep = mock.Mock(side_effect=lambda s: self.reloj.__setitem__(0, self.reloj[0] + s))
        p = mock.patch.object(keyvault, '_dormir', self.sleep)
        p.start()
        self.addCleanup(p.stop)

    def env(self, **valores):
        limpio = {k: v for k, v in os.environ.items() if k not in ('TOTP_ENCRYPTION_KEY', 'TOTP_KEY_VAULT_SECRET_URL')}
        limpio.update(valores)
        p = mock.patch.dict(os.environ, limpio, clear=True)
        p.start()
        self.addCleanup(p.stop)

    def falso(self, **kw):
        f = Falso(self.reloj, **kw)
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
        self.assertEqual(f.autorizacion[0], None)
        self.assertEqual(vault.full_url, URL + '?api-version=7.4')
        # El token va en un encabezado que urllib no copia a una redirección, y se quita después de la petición.
        self.assertNotIn('Authorization', vault.headers)
        self.assertEqual(f.autorizacion[1], 'Bearer ' + TOKEN)
        self.assertNotIn('Authorization', vault.unredirected_hdrs)
        self.assertIsNone(vault.get_header('Metadata'))

    def test_una_sola_lectura_aunque_lleguen_juntas(self):
        # La primera petición se queda esperando hasta que los otros 19 hilos ya llamaron a _key: sin el candado de
        # totp._key, cada uno vería la caché vacía y haría su propia lectura (hallazgo 14).
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso()
        entro, soltar = threading.Event(), threading.Event()

        def lenta(req, timeout):
            if not entro.is_set():
                entro.set()
                soltar.wait(5)
            return f(req, timeout)
        p = mock.patch.object(keyvault, '_abrir', lenta)
        p.start()
        self.addCleanup(p.stop)
        salida = []
        hilos = [threading.Thread(target=lambda: salida.append(totp._key())) for _ in range(20)]
        hilos[0].start()
        self.assertTrue(entro.wait(5))
        for h in hilos[1:]:
            h.start()
        threading.Event().wait(0.3)  # tiempo real para que los 19 lleguen
        soltar.set()
        for h in hilos:
            h.join()
        self.assertEqual(len(salida), 20)
        self.assertEqual(set(salida), {base64.urlsafe_b64decode(LLAVE)})
        self.assertEqual(len(f.peticiones), 2)

    def test_otra_url_con_la_cache_llena_vuelve_a_leer(self):
        otra = URL[:-32] + 'f' * 32
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso()
        totp._key()
        self.env(TOTP_KEY_VAULT_SECRET_URL=otra)
        totp._key()
        self.assertEqual([r.full_url for r in f.peticiones[1::2]],
                         [URL + '?api-version=7.4', otra + '?api-version=7.4'])

    def test_reintenta_imds_al_arrancar(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso(imds=[_error(404), _error(503), urllib.error.URLError('x'), {'access_token': TOKEN}])
        self.assertEqual(totp._key(), base64.urlsafe_b64decode(LLAVE))
        self.assertEqual(len(f.peticiones), 5)
        self.assertEqual([c.args[0] for c in self.sleep.call_args_list], [1, 2, 4])

    def test_reintenta_key_vault(self):
        # 429 y 5xx de la bóveda también se reintentan (hallazgo 15).
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso(vault=[_error(429), _error(503), {'value': LLAVE}])
        self.assertEqual(totp._key(), base64.urlsafe_b64decode(LLAVE))
        self.assertEqual(len(f.peticiones), 4)
        self.assertEqual([c.args[0] for c in self.sleep.call_args_list], [1, 2])

    def test_respuesta_cortada_se_reintenta(self):
        # IncompleteRead y LineTooLong no son OSError (hallazgo 13).
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso(imds=[http.client.IncompleteRead(b'x'), {'access_token': TOKEN}],
                       vault=[http.client.LineTooLong('x'), {'value': LLAVE}])
        self.assertEqual(totp._key(), base64.urlsafe_b64decode(LLAVE))
        self.assertEqual(len(f.peticiones), 4)

    def test_sin_rol_no_reintenta(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso(vault=[_error(403)])
        with self.assertRaisesRegex(RuntimeError, 'Key Vault respondió HTTP 403'):
            totp._key()
        self.assertEqual(len(f.peticiones), 2)
        self.assertIsNone(totp._llave_vault)

    def test_secreto_inexistente_no_reintenta(self):
        # R1 de la ronda 2: un 404 de la bóveda (versión mal copiada) es permanente y sale en seco. El de IMDS sí se
        # reintenta (test_reintenta_imds_al_arrancar).
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso(vault=[_error(404)])
        with self.assertRaisesRegex(RuntimeError, 'Key Vault respondió HTTP 404'):
            totp._key()
        self.assertEqual(len(f.peticiones), 2)
        self.sleep.assert_not_called()

    def test_imds_caido_se_rinde(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso(imds=[urllib.error.URLError('x')])
        with self.assertRaisesRegex(RuntimeError, r'IMDS\) no respondió'):
            totp._key()
        self.assertEqual(len(f.peticiones), 1 + len(keyvault.ESPERAS))
        self.assertLess(sum(keyvault.ESPERAS), keyvault.PLAZO)

    def test_plazo_total_con_intentos_que_se_agotan(self):
        # Cada intento gasta su timeout entero. IMDS responde al séptimo y la bóveda nunca: los dos juntos no pasan
        # de PLAZO y ningún intento pide más tiempo del que queda (hallazgos 8, 11 y 15).
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
        f = self.falso(imds=[urllib.error.URLError('x')] * 6 + [{'access_token': TOKEN}],
                       vault=[urllib.error.URLError('x')], avanza=keyvault.TIMEOUT)
        with self.assertRaisesRegex(RuntimeError, r'Key Vault no respondió'):
            totp._key()
        self.assertLessEqual(self.reloj[0], keyvault.PLAZO)
        for hora, timeout in f.llamadas:
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, min(keyvault.TIMEOUT, keyvault.PLAZO - hora))
        # La bóveda alcanzó a intentar con lo que quedaba, menos que un timeout entero.
        self.assertLess(f.llamadas[-1][1], keyvault.TIMEOUT)

    def _sin_token(self, error):
        """Ni el error encadenado ni las variables de los frames de keyvault y totp guardan el token (hallazgo 5)."""
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        tb = error.__traceback__
        while tb:
            if tb.tb_frame.f_code.co_filename in (keyvault.__file__, totp.__file__):
                for nombre, valor in tb.tb_frame.f_locals.items():
                    if isinstance(valor, urllib.request.Request):
                        valor = (valor.headers, valor.unredirected_hdrs)
                    self.assertNotIn(TOKEN, repr(valor), nombre)
            tb = tb.tb_next

    def test_errores_sin_token_ni_valor(self):
        casos = [
            dict(vault=[{'value': base64.urlsafe_b64encode(b'CIRDAN_FAKE_corta').decode()}]),
            dict(vault=[{'value': 'CIRDAN_FAKE_no_base64%%'}]),
            dict(vault=[{'otro': LLAVE}]),
            dict(vault=[_error(500)]),
            dict(vault=[_error(403)]),
            dict(vault=[http.client.IncompleteRead(b'x')]),
            dict(imds=[{'token': TOKEN}]),
            dict(imds=[['CIRDAN_FAKE_lista']]),
        ]
        for kw in casos:
            totp._llave_vault = None
            self.env(TOTP_KEY_VAULT_SECRET_URL=URL)
            self.falso(**kw)
            # Sin assertRaises: guarda la excepción sin su traceback, y aquí se revisan sus frames.
            try:
                totp._key()
            except RuntimeError as e:
                error = e
            else:
                self.fail('no falló: %s' % kw)
            texto = str(error) + repr(error.__cause__) + repr(error.__context__)
            for secreto in (TOKEN, LLAVE, 'CIRDAN_FAKE'):
                self.assertNotIn(secreto, texto, kw)
            self.assertIsNotNone(error.__traceback__)
            self._sin_token(error)


class Abrir(Base):
    """keyvault._abrir con el opener reemplazado: el timeout llega a la conexión y vale para todo el cuerpo."""

    def _abrir(self, partes, avanza=0, timeout=keyvault.TIMEOUT):
        resp = mock.MagicMock()
        resp.__enter__.return_value = resp
        partes = list(partes)

        def read1(n):
            self.reloj[0] += avanza
            return partes.pop(0) if partes else b''
        resp.read1.side_effect = read1
        with mock.patch.object(keyvault._opener, 'open', return_value=resp) as abrir:
            return keyvault._abrir('req', timeout), abrir

    def test_timeout_en_la_conexion(self):
        datos, abrir = self._abrir([b'{"value": ', b'"x"}'], timeout=3)
        self.assertEqual(datos, {'value': 'x'})
        abrir.assert_called_once_with('req', timeout=3)

    def test_cuerpo_gota_a_gota(self):
        with self.assertRaises(TimeoutError):
            self._abrir([b' '] * 100, avanza=1)

    def test_cuerpo_demasiado_grande(self):
        # JSON válido de más de MAXIMO bytes: sin el límite se leería entero.
        grande = b'{"value": "' + b'x' * keyvault.MAXIMO + b'"}'
        with self.assertRaisesRegex(ValueError, 'demasiado grande'):
            self._abrir([grande[i:i + 16384] for i in range(0, len(grande), 16384)])


class Url(Base):
    def test_urls_que_no_son_de_key_vault(self):
        v = '/' + VERSION
        malas = [
            'http://kv-lowtide.vault.azure.net/secrets/totp' + v,
            'https://kv-lowtide.vault.azure.net.example.com/secrets/totp' + v,
            'https://example.com/secrets/totp' + v + '?x=.vault.azure.net',
            'https://kv-lowtide.vault.azure.net:8443/secrets/totp' + v,
            'https://user@kv-lowtide.vault.azure.net/secrets/totp' + v,
            'https://kv-lowtide.vault.azure.net/secrets/totp' + v + '?api-version=1',
            'https://kv-lowtide.vault.azure.net/secrets/totp' + v + '#x',
            'https://kv-lowtide.vault.azure.net/keys/totp' + v,
            'https://kv-lowtide.vault.azure.net/secrets/../keys/totp' + v,
            'https://kv-lowtide.vault.azure.net/secrets/totp_mal' + v,
            'https://kv-lowtide.vault.azure.net/secrets' + v,
            'https://169.254.169.254/secrets/totp' + v,
            'https://a.vault.azure.net/secrets/totp' + v,
            ' ' + URL,
            URL + '\n',
            'https://kv-lowtide.vault.azure.net:abc/secrets/totp' + v,
            'https://kv-lowtide.vault.azure.net/secrets/to\ttp' + v,
            # Sin versión, o con una que no es de Key Vault (hallazgos 1 y 6).
            'https://kv-lowtide.vault.azure.net/secrets/totp',
            'https://kv-lowtide.vault.azure.net/secrets/totp/',
            'https://kv-lowtide.vault.azure.net/secrets/totp/' + VERSION.upper(),
            'https://kv-lowtide.vault.azure.net/secrets/totp/' + VERSION[:-1],
            URL + '/',
        ]
        for mala in malas:
            totp._llave_vault = None
            self.env(TOTP_KEY_VAULT_SECRET_URL=mala)
            f = self.falso()
            with self.assertRaisesRegex(RuntimeError, 'debe ser https://', msg=mala):
                totp._key()
            self.assertEqual(f.peticiones, [], mala)

    def test_urls_buenas(self):
        for buena in (URL, 'https://KV-Lowtide.vault.azure.net/secrets/t/' + VERSION):
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
            keyvault._abrir(req, keyvault.TIMEOUT)
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
            req = urllib.request.Request(base + '/secreto')
            self.assertEqual(keyvault._abrir(req, keyvault.TIMEOUT), {'value': LLAVE})
        self.assertEqual(vistos, [('/secreto', None)])


# La API también pide la llave de las huellas de contraseña (RC-330), otra que la del MFA.
FALSOS = {'CIRDAN_APP_PASSWORD': 'CIRDAN_FAKE_app',
          'PASSWORD_HASH_ENCRYPTION_KEY': base64.urlsafe_b64encode(b'CIRDAN_FAKE_llave_huellas_32_byt').decode()}


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
