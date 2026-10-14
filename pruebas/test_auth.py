"""Pruebas del inicio de sesión (#25 y TOTP de RC-5) contra la API local (biblioteca estándar).

    python -m unittest -v pruebas/test_auth.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)
"""
import secrets
import time
import unittest

from pruebas import sesion
from pruebas.sesion import AUTH, PASSWORD, Client

JORDAN = 'jordan.tate@acme-demo.mx'   # analista de Acme
MAYA = 'maya.reed@acme-demo.mx'       # gerente de Acme
INVALID = 'Correo o contraseña incorrectos.'


class Login(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sesion.reset()

    def test_1_contrasena_mala_y_correo_inexistente_dan_el_mismo_mensaje(self):
        client = Client()
        code_bad, body_bad = client.post(AUTH + '/login', {'email': JORDAN, 'password': 'no-es-la-contrasena'})
        start = time.perf_counter()
        code_none, body_none = client.post(AUTH + '/login', {'email': 'nadie@acme-demo.mx', 'password': 'no-es-la-contrasena'})
        elapsed = time.perf_counter() - start
        self.assertEqual((code_bad, body_bad['detail']), (401, INVALID))
        self.assertEqual((code_none, body_none['detail']), (401, INVALID))
        self.assertGreater(elapsed, 0.02, 'el correo inexistente también debe gastar el tiempo de argon2')
        self.assertIsNone(client.cookie())

    def test_2_la_contrasena_sola_no_da_sesion(self):
        client = Client()
        code, body = client.post(AUTH + '/login', {'email': JORDAN, 'password': PASSWORD})
        self.assertEqual(code, 200)
        self.assertTrue(body['mfa_required'])
        self.assertIsNone(client.cookie(), 'sin el código no hay cookie')
        self.assertEqual(client.get(AUTH + '/me')[0], 401)
        code, body = client.post(AUTH + '/mfa/verify', {'mfa_token': body['mfa_token'], 'code': '000000'})
        self.assertEqual((code, body['detail']), (401, 'El código no es válido o ya expiró.'))

    def test_3_contrasena_y_codigo_dan_sesion_con_cookie_httponly(self):
        client = sesion.login(JORDAN)
        cookie = client.cookie()
        self.assertIsNotNone(cookie)
        self.assertTrue(cookie.has_nonstandard_attr('HttpOnly'))
        code, me = client.get(AUTH + '/me')
        self.assertEqual(code, 200)
        self.assertEqual((me['email'], me['role'], me['organization_name']), (JORDAN, 'analyst', 'Acme Demo'))
        self.assertNotIn('password_hash', me)
        self.assertNotIn('totp_secret_enc', me)

    def test_4_un_codigo_no_se_puede_usar_dos_veces(self):
        first = Client()
        _, body = first.post(AUTH + '/login', {'email': MAYA, 'password': PASSWORD})
        code = sesion.next_code(MAYA)
        self.assertEqual(first.post(AUTH + '/mfa/verify', {'mfa_token': body['mfa_token'], 'code': code})[0], 200)
        second = Client()
        _, body = second.post(AUTH + '/login', {'email': MAYA, 'password': PASSWORD})
        self.assertEqual(second.post(AUTH + '/mfa/verify', {'mfa_token': body['mfa_token'], 'code': code})[0], 401)

    def test_5_cerrar_sesion_invalida_la_cookie_en_el_servidor(self):
        client = sesion.login(JORDAN)
        stolen = client.cookie().value
        self.assertEqual(client.post(AUTH + '/logout')[0], 204)
        self.assertEqual(client.get(AUTH + '/me')[0], 401)
        replay = Client()
        self.assertEqual(replay.get(AUTH + '/me', headers={'Cookie': 'lt_session=' + stolen})[0], 401)

    def test_6_cinco_fallos_bloquean_el_correo(self):
        client = Client()
        email = 'bloqueo-%s@acme-demo.mx' % secrets.token_hex(4)
        for _ in range(5):
            self.assertEqual(client.post(AUTH + '/login', {'email': email, 'password': 'x'})[0], 401)
        code, body = client.post(AUTH + '/login', {'email': email, 'password': 'x'})
        self.assertEqual(code, 429)
        self.assertIn('Demasiados intentos', body['detail'])

    def test_7_token_de_mfa_inventado_no_sirve(self):
        code, body = Client().post(AUTH + '/mfa/verify', {'mfa_token': secrets.token_urlsafe(32), 'code': '123456'})
        self.assertEqual((code, body['detail']), (401, 'Tu verificación expiró. Inicia sesión de nuevo.'))

    def test_8_un_sitio_ajeno_no_puede_mandar_el_login(self):
        code, _ = Client().post(AUTH + '/login', {'email': JORDAN, 'password': PASSWORD}, headers={'Origin': 'https://evil.example'})
        self.assertEqual(code, 403)


if __name__ == '__main__':
    unittest.main(verbosity=2)
