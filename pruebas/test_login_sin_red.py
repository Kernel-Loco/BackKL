"""Pruebas sin red ni base del código MFA solo con 0 a 9 (RC-315) y del logout que borra la sesión primero (RC-314).

Sin Valkey ni PostgreSQL: los dos se reemplazan por falsos. Corren dentro del contenedor, porque cirdan.auth.routes
importa fastapi, psycopg y redis:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_login_sin_red.py
"""
import contextlib
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import psycopg
import pyotp
import redis
from fastapi import Response
from pydantic import ValidationError

from cirdan.auth import routes, totp

ARABES = '١٢٣٤٥٦'            # '١٢٣٤٥٦', dígitos arábigo-índicos
ANCHO_COMPLETO = '１２３４５６'    # '１２３４５６'
A_ARABES = str.maketrans('0123456789', '٠١٢٣٤٥٦٧٨٩')
A_ANCHO_COMPLETO = str.maketrans('0123456789', ''.join(chr(0xff10 + i) for i in range(10)))
SECRETO = pyotp.random_base32(32)
AHORA = 1_800_000_000  # reloj fijo: el código válido no cambia a mitad de la prueba


def codigo_valido():
    return pyotp.TOTP(SECRETO, interval=totp.STEP_SECONDS).at(AHORA)


class CodigoSoloAscii(unittest.TestCase):
    def test_1_digitos_unicode_dan_none_sin_excepcion(self):
        for codigo in (ARABES, ANCHO_COMPLETO):
            with self.subTest(codigo=ascii(codigo)):
                self.assertIsNone(totp.verify_code(SECRETO, codigo, now=AHORA))

    def test_2_el_codigo_bueno_escrito_con_otros_digitos_tampoco_entra(self):
        # Con isdigit() estos llegaban a hmac.compare_digest, que lanza TypeError con texto no ASCII.
        bueno = codigo_valido()
        self.assertEqual(totp.verify_code(SECRETO, bueno, now=AHORA), AHORA // totp.STEP_SECONDS)
        for tabla in (A_ARABES, A_ANCHO_COMPLETO):
            with self.subTest(codigo=ascii(bueno.translate(tabla))):
                self.assertIsNone(totp.verify_code(SECRETO, bueno.translate(tabla), now=AHORA))

    def test_3_otras_formas_raras_dan_none(self):
        bueno = codigo_valido()
        for codigo in (bueno + '\n', ' ' + bueno, bueno[:5], bueno + '0', '12345٦', '', None, 123456, b'123456'):
            with self.subTest(codigo=ascii(codigo)):
                self.assertIsNone(totp.verify_code(SECRETO, codigo, now=AHORA))

    def test_4_los_tres_modelos_rechazan_digitos_unicode_y_aceptan_0_a_9(self):
        token = 'x' * 20
        modelos = ((routes.MfaIn, {'mfa_token': token}), (routes.MfaEnableIn, {}),
                   (routes.PasskeyRegisterOptionsIn, {'current_password': 'x'}))
        for modelo, resto in modelos:
            for codigo in (ARABES, ANCHO_COMPLETO, '123456\n', '12345'):
                with self.subTest(modelo=modelo.__name__, codigo=ascii(codigo)), self.assertRaises(ValidationError):
                    modelo(code=codigo, **resto)
            self.assertEqual(modelo(code='012345', **resto).code, '012345')
        self.assertIsNone(routes.PasskeyRegisterOptionsIn(current_password='x').code, 'el código sigue siendo opcional')


class BaseCaida:
    """transaction() que falla como PostgreSQL detenido."""

    def __init__(self):
        self.llamadas = []

    @contextlib.contextmanager
    def __call__(self, org_id):
        self.llamadas.append(org_id)
        raise psycopg.OperationalError('connection refused')
        yield  # nunca llega


class Logout(unittest.TestCase):
    TOKEN = 'token-de-la-cookie-que-no-va-al-log-%d' % int(time.time())

    def setUp(self):
        self.orden = []
        sesion = {'user_id': 'u-1', 'org_id': 'o-actual', 'home_org_id': 'o-casa'}
        self.sessions = mock.patch.multiple(
            routes.sessions,
            get=mock.Mock(side_effect=lambda token: dict(sesion) if token == self.TOKEN else None),
            delete=mock.Mock(side_effect=lambda token: self.orden.append(('valkey', token))))
        self.sessions.start()
        self.addCleanup(self.sessions.stop)
        self.request = SimpleNamespace(cookies={routes.COOKIE: self.TOKEN}, client=SimpleNamespace(host='203.0.113.7'))

    def _cookie_borrada(self, response, secure=None):
        # El navegador solo reemplaza la cookie si el borrado lleva el mismo nombre, Path y Secure que el set_cookie
        # de _start_session. HttpOnly y SameSite se revisan para que el borrado no quede más débil que la cookie.
        cookies = [v.decode() for k, v in response.raw_headers if k == b'set-cookie']
        self.assertEqual(len(cookies), 1, cookies)
        self.assertTrue(cookies[0].startswith(routes.COOKIE + '="";'), cookies)
        partes = [p.strip() for p in cookies[0].split(';')[1:]]
        attrs = {p.split('=', 1)[0].lower(): (p.split('=', 1)[1] if '=' in p else True) for p in partes}
        self.assertEqual(attrs.get('max-age'), '0', cookies)
        self.assertEqual(attrs.get('path'), '/', cookies)
        self.assertIs(attrs.get('httponly'), True, cookies)
        self.assertEqual(str(attrs.get('samesite')).lower(), 'lax', cookies)
        self.assertEqual('secure' in attrs, routes.COOKIE_SECURE if secure is None else secure, cookies)

    def _sin_token(self, logs):
        texto = '\n'.join(logs.output)
        self.assertNotIn(self.TOKEN, texto, 'el log nunca lleva el token')
        return texto

    def test_1_con_la_base_caida_borra_sesion_y_cookie_y_no_lanza(self):
        caida, response = BaseCaida(), Response()
        with mock.patch.object(routes, 'transaction', caida), self.assertLogs(routes.log, 'ERROR') as logs:
            self.assertIsNone(routes.logout(self.request, response))
        self.assertEqual(self.orden, [('valkey', self.TOKEN)], 'la sesión se borra de Valkey')
        self.assertEqual(caida.llamadas, ['o-casa'], 'se intentó escribir en la empresa de la cuenta')
        self._cookie_borrada(response)
        texto = '\n'.join(logs.output)
        self.assertIn('auth.logout', texto)
        self.assertIn('u-1', texto, 'el log lleva el id del usuario')
        self.assertNotIn(self.TOKEN, texto, 'el log nunca lleva el token')

    def test_2_con_la_base_arriba_escribe_el_evento_despues_de_borrar(self):
        conexion, response = object(), Response()

        @contextlib.contextmanager
        def transaccion(org_id):
            self.orden.append(('base', org_id))
            yield conexion

        with mock.patch.object(routes, 'transaction', transaccion), mock.patch.object(routes, 'audit') as audit:
            routes.logout(self.request, response)
        self.assertEqual(self.orden, [('valkey', self.TOKEN), ('base', 'o-casa')], 'primero Valkey y luego la base')
        audit.assert_called_once_with(conexion, 'o-casa', 'auth.logout', 'u-1', '203.0.113.7', 'user', 'u-1')
        self._cookie_borrada(response)

    def test_3_sin_sesion_borra_la_cookie_y_no_toca_la_base(self):
        response = Response()
        self.request.cookies = {routes.COOKIE: 'otra'}
        with mock.patch.object(routes, 'transaction', BaseCaida()) as caida:
            routes.logout(self.request, response)
        self.assertEqual(caida.llamadas, [])
        self._cookie_borrada(response)

    def test_4_si_valkey_falla_al_leer_borra_la_cookie_intenta_borrar_y_no_lanza(self):
        # Antes de RC-314 la excepción salía del logout: 500 sin Set-Cookie y la cookie seguía en el navegador.
        for falla in (redis.ConnectionError('Valkey caído'), redis.TimeoutError('Timeout reading from socket')):
            with self.subTest(falla=type(falla).__name__):
                self.orden.clear()
                routes.sessions.get.side_effect = falla
                caida, response = BaseCaida(), Response()
                with mock.patch.object(routes, 'transaction', caida), self.assertLogs(routes.log, 'ERROR') as logs:
                    self.assertIsNone(routes.logout(self.request, response))
                self.assertEqual(self.orden, [('valkey', self.TOKEN)], 'se intenta borrar la sesión igual')
                self.assertEqual(caida.llamadas, [], 'sin datos de la sesión no se escribe el evento')
                self._cookie_borrada(response)
                self.assertIn('leer la sesión', self._sin_token(logs))

    def test_5_si_valkey_falla_al_borrar_borra_la_cookie_no_escribe_el_evento_y_no_lanza(self):
        for falla in (redis.ConnectionError('Valkey caído'), redis.TimeoutError('Timeout reading from socket')):
            with self.subTest(falla=type(falla).__name__):
                routes.sessions.delete.side_effect = falla
                caida, response = BaseCaida(), Response()
                with mock.patch.object(routes, 'transaction', caida), self.assertLogs(routes.log, 'ERROR') as logs:
                    self.assertIsNone(routes.logout(self.request, response))
                routes.sessions.delete.assert_called_with(self.TOKEN)
                self.assertEqual(caida.llamadas, [], 'la sesión puede seguir en Valkey: no se escribe auth.logout')
                self._cookie_borrada(response)
                texto = self._sin_token(logs)
                self.assertIn('borrar de Valkey', texto)
                self.assertIn('u-1', texto, 'el log lleva el id del usuario')

    def test_6_si_valkey_falla_al_leer_y_al_borrar_igual_borra_la_cookie(self):
        routes.sessions.get.side_effect = redis.ConnectionError('Valkey caído')
        routes.sessions.delete.side_effect = redis.ConnectionError('Valkey caído')
        caida, response = BaseCaida(), Response()
        with mock.patch.object(routes, 'transaction', caida), self.assertLogs(routes.log, 'ERROR') as logs:
            self.assertIsNone(routes.logout(self.request, response))
        self.assertEqual(caida.llamadas, [])
        self._cookie_borrada(response)
        self.assertIn('desconocido', self._sin_token(logs))

    def test_7_el_borrado_lleva_secure_cuando_la_cookie_lo_lleva(self):
        for secure in (True, False):
            with self.subTest(secure=secure), mock.patch.object(routes, 'COOKIE_SECURE', secure), \
                    mock.patch.object(routes, 'transaction', BaseCaida()):
                response = Response()
                self.request.cookies = {routes.COOKIE: 'otra'}
                routes.logout(self.request, response)
                self._cookie_borrada(response, secure=secure)


if __name__ == '__main__':
    unittest.main()
