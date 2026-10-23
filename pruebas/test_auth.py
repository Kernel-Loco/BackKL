"""Pruebas del inicio de sesión (#25 y TOTP de RC-5) contra la API local (biblioteca estándar).

    python -m unittest -v pruebas/test_auth.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)
"""
import secrets
import time
import unittest

from pruebas import sesion
from pruebas.sesion import AUTH, PASSWORD, Client
from pruebas.test_aislamiento import scalar

JORDAN = 'jordan.tate@acme-demo.mx'   # analista de Acme
MAYA = 'maya.reed@acme-demo.mx'       # gerente de Acme
ALEX = 'alex.morgan@acme-demo.mx'     # admin de Acme
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

    def _sin_mfa(self, email):
        """Quita el MFA a una cuenta de demo solo durante la prueba y al final le devuelve la misma fecha.
        Si una corrida anterior se cortó y la dejó sin fecha, le pone now(), como cirdan/auth/demo.py."""
        antes = scalar("SELECT coalesce(quote_literal(mfa_enabled_at), 'now()') FROM users WHERE email = '%s';" % email,
                       user='postgres')
        self.addCleanup(scalar, "UPDATE users SET mfa_enabled_at = %s WHERE email = '%s' RETURNING 1;" % (antes, email),
                        user='postgres')
        scalar("UPDATE users SET mfa_enabled_at = NULL WHERE email = '%s' RETURNING 1;" % email, user='postgres')

    def test_9_sin_mfa_la_sesion_lleva_el_rol_de_la_base(self):
        # login_lookup() ya no devuelve el rol (migración 004): sin MFA, la API lo lee con RLS.
        # El rol de la sesión se ve en lo que deja hacer: solo admin lee los TXT y el gerente no pide
        # escaneos. Un dominio que no existe responde 404 sin escribir nada.
        for email, role, txt, scan in ((JORDAN, 'analyst', 403, 404), (ALEX, 'admin', 200, 404)):
            with self.subTest(email=email):
                self._sin_mfa(email)
                client = Client()
                code, body = client.post(AUTH + '/login', {'email': email, 'password': PASSWORD})
                self.assertEqual(code, 200)
                self.assertFalse(body['mfa_required'])
                self.assertEqual((body['user']['email'], body['user']['role']), (email, role))
                self.assertIsNotNone(client.cookie())
                self.assertEqual(client.get(AUTH + '/me')[0], 200)
                self.assertEqual(client.get('/api/v1/domains/txt')[0], txt, 'solo admin lee los TXT')
                self.assertEqual(client.post('/api/v1/domains/no-existe.acme-demo.mx/scans')[0], scan,
                                 'el gerente no puede pedir escaneos')


if __name__ == '__main__':
    unittest.main(verbosity=2)
