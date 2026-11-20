"""Pruebas del inicio de sesión (#25 y TOTP de RC-5) contra la API local (biblioteca estándar).

    python -m unittest -v pruebas/test_auth.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)
"""
import http.client
import json
import pyotp
import secrets
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import altcha

from pruebas import sesion
from pruebas.sesion import AUTH, PASSWORD, Client
from pruebas.test_aislamiento import scalar

JORDAN = 'jordan.tate@acme-demo.mx'   # analista de Acme
MAYA = 'maya.reed@acme-demo.mx'       # gerente de Acme
ALEX = 'alex.morgan@acme-demo.mx'     # admin de Acme
DANA = 'dana.cruz@beta-corp.mx'       # de Beta, para las pruebas que la dejan bloqueada
INVALID = 'Correo o contraseña incorrectos.'
MFA_INVALID = 'El código no es válido o ya expiró.'
MFA_EXPIRED = 'Tu verificación expiró. Inicia sesión de nuevo.'
ADMIN_MFA_REQUIRED = 'Activa MFA para iniciar sesión con una cuenta admin.'


def codigos_malos(email, n):
    """n códigos que no sirven ahora para la cuenta (ninguno de los pasos que la API acepta)."""
    paso = int(time.time() // sesion.STEP)
    validos = {sesion.totp(sesion.SECRETS[email], s) for s in range(paso - 2, paso + 3)}
    return [c for c in ('%06d' % i for i in range(n + len(validos))) if c not in validos][:n]


def captcha_payload():
    code, challenge = Client().get(AUTH + '/captcha')
    if code != 200:
        raise AssertionError((code, challenge))
    reto = altcha.ChallengeV1(
        challenge['algorithm'], challenge['challenge'], challenge['maxNumber'],
        challenge['salt'], challenge['signature'])
    solucion = altcha.solve_challenge_v1(reto)
    if solucion is None:
        raise AssertionError('No se pudo resolver el reto ALTCHA')
    return {
        'algorithm': reto.algorithm,
        'challenge': reto.challenge,
        'number': solucion.number,
        'salt': reto.salt,
        'signature': reto.signature,
    }


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

    def test_9_sin_mfa_solo_no_admin_puede_entrar(self):
        # login_lookup() ya no devuelve el rol (migración 004): sin MFA, la API lo lee con RLS.
        # Si el rol es admin, MFA es obligatorio y no se crea sesión sin configurarlo.
        for email, role, txt, scan in ((JORDAN, 'analyst', 403, 404),):
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

            self._sin_mfa(ALEX)
            client = Client()
            code, body = client.post(AUTH + '/login', {'email': ALEX, 'password': PASSWORD})
            self.assertEqual((code, body['detail']), (403, ADMIN_MFA_REQUIRED))
            self.assertIsNone(client.cookie())

    def test_10_la_contrasena_mala_queda_en_la_bitacora(self):
        # La API escribe el fallo después de mandar el 401, para que el tiempo no delate que el correo
        # existe. Con raise HTTPException esa tarea no correría y el fallo no quedaría en la bitácora.
        contar = ("SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = '%s' "
                  "AND a.action = 'auth.login_failed' AND a.details->>'reason' = 'password';" % JORDAN)
        antes = int(scalar(contar, user='postgres'))
        code, body = Client().post(AUTH + '/login', {'email': JORDAN, 'password': 'no-es-la-contrasena'})
        self.assertEqual((code, body['detail']), (401, INVALID))
        for _ in range(50):  # hasta 5 s
            if int(scalar(contar, user='postgres')) > antes:
                break
            time.sleep(0.1)
        self.assertEqual(int(scalar(contar, user='postgres')), antes + 1)

    def test_11_si_la_bitacora_falla_la_conexion_sigue_abierta(self):
        # 'no-es-ip' no cabe en audit_log.ip_address (inet), así que la escritura del fallo truena después
        # del 401. Eso no debe cerrar la conexión, porque con un correo que no existe sigue abierta.
        # Solo aplica si la API confía en X-Forwarded-For: FORWARDED_ALLOW_IPS='*' en el .env, solo para esta prueba.
        # Por omisión docker compose no confía en nadie de fuera y la prueba se salta.
        contar = ("SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = '%s' "
                  "AND a.action = 'auth.login_failed';" % JORDAN)
        antes = int(scalar(contar, user='postgres'))
        url = urlsplit(sesion.BASE)
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
        self.addCleanup(conn.close)
        for email in (JORDAN, 'nadie@acme-demo.mx'):
            conn.request('POST', '/api/v1/auth/login', json.dumps({'email': email, 'password': 'no-es-la-contrasena', 'captcha': captcha_payload()}),
                         {'Content-Type': 'application/json', 'X-Forwarded-For': 'no-es-ip'})
            r = conn.getresponse()
            self.assertEqual((r.status, json.loads(r.read())['detail']), (401, INVALID), email)
            time.sleep(0.5)  # tiempo para que corra la escritura de la bitácora
        if int(scalar(contar, user='postgres')) != antes:
            self.skipTest('la API no confía en X-Forwarded-For y la bitácora no falló: no se probó nada')

    def test_12_con_la_contrasena_los_codigos_malos_tambien_bloquean(self):
        # La contraseña correcta ya no borra los fallos del correo y cada código malo cuenta. Antes, quien
        # tenía la contraseña repetía el login y 5 códigos sin llegar nunca al 429.
        self.addCleanup(sesion.reset)
        client = Client()
        _, body = client.post(AUTH + '/login', {'email': DANA, 'password': PASSWORD})
        guardado = body['mfa_token']
        for i, malo in enumerate(codigos_malos(DANA, 5)):
            code, body = client.post(AUTH + '/login', {'email': DANA, 'password': PASSWORD})
            self.assertEqual((code, body.get('mfa_required')), (200, True), 'login %d' % (i + 1))
            code, body = client.post(AUTH + '/mfa/verify', {'mfa_token': body['mfa_token'], 'code': malo})
            self.assertEqual((code, body['detail']), (401, MFA_INVALID), 'código %d' % (i + 1))
        code, body = client.post(AUTH + '/login', {'email': DANA, 'password': PASSWORD})
        self.assertEqual(code, 429, 'la contraseña correcta no debe saltarse el bloqueo')
        code, body = client.post(AUTH + '/mfa/verify', {'mfa_token': guardado, 'code': sesion.next_code(DANA)})
        self.assertEqual(code, 429, 'un mfa_token sacado antes tampoco debe saltárselo, ni con el código bueno')
        self.assertIsNone(client.cookie())

    def test_13_codigos_en_paralelo_no_pasan_de_cinco(self):
        # 30 códigos a la vez con el mismo mfa_token. Cada uno gasta su intento en Valkey antes de
        # revisarse, así que solo 5 se revisan. Antes todos leían attempts=0 y se revisaban todos.
        self.addCleanup(sesion.reset)
        contar = ("SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = '%s' "
                  "AND a.action = 'auth.mfa_failed';" % DANA)
        antes = int(scalar(contar, user='postgres'))
        _, body = Client().post(AUTH + '/login', {'email': DANA, 'password': PASSWORD})
        token, codigos = body['mfa_token'], codigos_malos(DANA, 30)
        salida = threading.Barrier(len(codigos))

        def intento(codigo):
            salida.wait()
            code, body = Client().post(AUTH + '/mfa/verify', {'mfa_token': token, 'code': codigo})
            return code, (body or {}).get('detail')

        with ThreadPoolExecutor(len(codigos)) as pool:
            respuestas = list(pool.map(intento, codigos))
        self.assertEqual(respuestas.count((401, MFA_INVALID)), 5, respuestas)
        self.assertEqual(respuestas.count((401, MFA_EXPIRED)), len(codigos) - 5, respuestas)
        self.assertEqual(int(scalar(contar, user='postgres')) - antes, 1,
                 'solo el primer fallo del mfa_token deja evidencia')
        code, body = Client().post(AUTH + '/mfa/verify', {'mfa_token': token, 'code': sesion.next_code(DANA)})
        self.assertEqual((code, body['detail']), (401, MFA_EXPIRED), 'gastados los 5 intentos, el token ya no sirve')

    def test_14_varios_tokens_en_paralelo_no_pasan_de_cinco(self):
        # Un código por mfa_token, 20 tokens a la vez. El límite de cada token no frena nada aquí: lo frena
        # el fallo del correo, que se cuenta antes de revisar el código. Los logins correctos no cuentan.
        self.addCleanup(sesion.reset)
        tokens = [Client().post(AUTH + '/login', {'email': DANA, 'password': PASSWORD})[1]['mfa_token'] for _ in range(20)]
        salida = threading.Barrier(len(tokens))

        def intento(par):
            token, codigo = par
            salida.wait()
            code, body = Client().post(AUTH + '/mfa/verify', {'mfa_token': token, 'code': codigo})
            return code, (body or {}).get('detail')

        with ThreadPoolExecutor(len(tokens)) as pool:
            respuestas = list(pool.map(intento, zip(tokens, codigos_malos(DANA, len(tokens)))))
        self.assertEqual(respuestas.count((401, MFA_INVALID)), 5, respuestas)
        self.assertEqual([r[0] for r in respuestas].count(429), len(tokens) - 5, respuestas)

    def test_15_entrar_bien_varias_veces_no_deja_fallos(self):
        # Cada código cuenta como fallo antes de revisarse y el correcto borra los fallos. Sin ese borrado,
        # el sexto inicio de sesión correcto en 15 min respondería 429.
        self.addCleanup(sesion.reset)
        for i in range(6):
            # Sin último código usado, el mismo código vuelve a servir y no hay que esperar 30 s por cada uno
            scalar("UPDATE users SET last_totp_step = NULL WHERE email = '%s' RETURNING 1;" % DANA, user='postgres')
            sesion._last_step.pop(DANA, None)
            client = Client()
            code, body = client.post(AUTH + '/login', {'email': DANA, 'password': PASSWORD})
            self.assertEqual(code, 200, 'login %d' % (i + 1))
            code, body = client.post(AUTH + '/mfa/verify', {'mfa_token': body['mfa_token'], 'code': sesion.next_code(DANA)})
            self.assertEqual(code, 200, 'código %d' % (i + 1))

    def test_16_el_mismo_codigo_no_pasa_en_paralelo_con_distintos_tokens(self):
        # Dos mfa_token distintos con el mismo código en paralelo: solo una petición puede gastar el step.
        self.addCleanup(sesion.reset)
        c1, c2 = Client(), Client()
        t1 = c1.post(AUTH + '/login', {'email': MAYA, 'password': PASSWORD})[1]['mfa_token']
        t2 = c2.post(AUTH + '/login', {'email': MAYA, 'password': PASSWORD})[1]['mfa_token']
        codigo = sesion.next_code(MAYA)
        salida = threading.Barrier(2)

        def intento(client, token):
            salida.wait()
            return client.post(AUTH + '/mfa/verify', {'mfa_token': token, 'code': codigo})

        with ThreadPoolExecutor(2) as pool:
            r1, r2 = list(pool.map(lambda par: intento(*par), ((c1, t1), (c2, t2))))
        estados = sorted((r1[0], r2[0]))
        self.assertEqual(estados, [200, 401], (r1, r2))

    def test_17_password_actual_tiene_limite_de_intentos(self):
        self.addCleanup(sesion.reset)
        client = sesion.login(JORDAN)
        nuevo = 'Lowtide-Demo-2026!'
        for _ in range(5):
            code, body = client.post(AUTH + '/password', {'current_password': 'incorrecta', 'new_password': nuevo})
            self.assertEqual((code, body['detail']), (401, 'La contraseña actual no es correcta.'))
        code, body = client.post(AUTH + '/password', {'current_password': 'incorrecta', 'new_password': nuevo})
        self.assertEqual(code, 429)
        self.assertIn('Demasiados intentos', body['detail'])

    def test_18_captcha_falta_o_se_reutiliza(self):
        client = Client()
        code, body = client.post(AUTH + '/login', {'email': JORDAN, 'password': 'x', 'captcha': None})
        self.assertEqual((code, body['detail']), (400, 'Resuelve el captcha e inténtalo de nuevo.'))

        payload = captcha_payload()
        code, body = client.post(AUTH + '/login', {'email': JORDAN, 'password': 'x', 'captcha': payload})
        self.assertEqual(code, 401)
        code, body = client.post(AUTH + '/login', {'email': JORDAN, 'password': 'x', 'captcha': payload})
        self.assertEqual((code, body['detail']), (400, 'Resuelve el captcha e inténtalo de nuevo.'))

    def test_19_alta_totp_con_qr(self):
        self.addCleanup(sesion.reset)
        self._sin_mfa(JORDAN)
        client = Client()
        code, body = client.post(AUTH + '/login', {'email': JORDAN, 'password': PASSWORD})
        self.assertEqual((code, body['mfa_required']), (200, False))

        code, body = client.post(AUTH + '/mfa/setup', {'current_password': 'incorrecta'})
        self.assertEqual((code, body['detail']), (401, 'La contraseña actual no es correcta.'))

        code, body = client.post(AUTH + '/mfa/setup', {'current_password': PASSWORD})
        self.assertEqual(code, 200)
        self.assertIn('setup_token', body)
        self.assertIn('qr_data_uri', body)
        self.assertTrue(body['qr_data_uri'].startswith('data:image/png;base64,'))

        totp_code = pyotp.TOTP(body['secret']).now()
        code_status, body_enable = client.post(AUTH + '/mfa/enable', {'setup_token': body['setup_token'], 'code': totp_code})
        self.assertEqual((code_status, body_enable['mfa_enabled']), (200, True))


if __name__ == '__main__':
    unittest.main(verbosity=2)
