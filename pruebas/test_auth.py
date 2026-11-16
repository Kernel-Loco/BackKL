"""Pruebas del inicio de sesión (#25 y TOTP de RC-5) contra la API local (biblioteca estándar).

    python -m unittest -v pruebas/test_auth.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)
"""
import base64
import hmac
import http.client
import json
import secrets
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

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
MAX_FALLOS = 5  # MAX_FAILS_EMAIL de cirdan/auth/sessions.py
CAPTCHA_INVALID = 'No se pudo comprobar que no eres un robot. Espera a que termine la verificación e inténtalo de nuevo.'


def codigos_malos(email, n):
    """n códigos que no sirven ahora para la cuenta (ninguno de los pasos que la API acepta)."""
    paso = int(time.time() // sesion.STEP)
    validos = {sesion.totp(sesion.SECRETS[email], s) for s in range(paso - 2, paso + 3)}
    return [c for c in ('%06d' % i for i in range(n + len(validos))) if c not in validos][:n]


class Login(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sesion.reset()

    def test_1_contrasena_mala_y_correo_inexistente_dan_el_mismo_mensaje(self):
        client = Client()
        code_bad, body_bad = sesion.post_login(client, JORDAN, 'no-es-la-contrasena')
        resuelto = sesion.captcha(client)  # fuera de la medición: resolverlo tarda más que argon2
        start = time.perf_counter()
        code_none, body_none = client.post(AUTH + '/login', {'email': 'nadie@acme-demo.mx', 'password': 'no-es-la-contrasena',
                                                             'captcha': resuelto})
        elapsed = time.perf_counter() - start
        self.assertEqual((code_bad, body_bad['detail']), (401, INVALID))
        self.assertEqual((code_none, body_none['detail']), (401, INVALID))
        self.assertGreater(elapsed, 0.02, 'el correo inexistente también debe gastar el tiempo de argon2')
        self.assertIsNone(client.cookie())

    def test_2_la_contrasena_sola_no_da_sesion(self):
        client = Client()
        code, body = sesion.post_login(client, JORDAN, PASSWORD)
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

    def test_3b_me_dice_la_inactividad_y_lo_que_falta_para_las_8_horas(self):
        # RC-328: sin estos dos campos el portal nunca da su aviso propio de las 8 h (src/lib/session/shared.ts)
        client = sesion.login(JORDAN)
        code, me = client.get(AUTH + '/me')
        self.assertEqual(code, 200)
        self.assertEqual(me['idle_timeout_seconds'], 15 * 60)
        primero = me['absolute_expires_in_seconds']
        self.assertTrue(8 * 3600 - 60 < primero <= 8 * 3600, primero)
        time.sleep(2.2)
        code, me = client.get(AUTH + '/me')
        self.assertEqual(code, 200)
        self.assertEqual(me['idle_timeout_seconds'], 15 * 60, 'la inactividad se renueva en cada petición')
        self.assertLessEqual(me['absolute_expires_in_seconds'], primero - 2,
                             'el tope de 8 h se cuenta desde que se creó la sesión, no se renueva')

    def test_4_un_codigo_no_se_puede_usar_dos_veces(self):
        first = Client()
        _, body = sesion.post_login(first, MAYA, PASSWORD)
        code = sesion.next_code(MAYA)
        self.assertEqual(first.post(AUTH + '/mfa/verify', {'mfa_token': body['mfa_token'], 'code': code})[0], 200)
        second = Client()
        _, body = sesion.post_login(second, MAYA, PASSWORD)
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
            self.assertEqual(sesion.post_login(client, email, 'x')[0], 401)
        code, body = sesion.post_login(client, email, 'x')
        self.assertEqual(code, 429)
        self.assertIn('Demasiados intentos', body['detail'])

    def test_7_token_de_mfa_inventado_no_sirve(self):
        code, body = Client().post(AUTH + '/mfa/verify', {'mfa_token': secrets.token_urlsafe(32), 'code': '123456'})
        self.assertEqual((code, body['detail']), (401, 'Tu verificación expiró. Inicia sesión de nuevo.'))

    def test_8_un_sitio_ajeno_no_puede_mandar_el_login(self):
        code, _ = sesion.post_login(Client(), JORDAN, PASSWORD, headers={'Origin': 'https://evil.example'})
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
                code, body = sesion.post_login(client, email, PASSWORD)
                self.assertEqual(code, 200)
                self.assertFalse(body['mfa_required'])
                self.assertEqual((body['user']['email'], body['user']['role']), (email, role))
                self.assertIsNotNone(client.cookie())
                self.assertEqual(client.get(AUTH + '/me')[0], 200)
                self.assertEqual(client.get('/api/v1/domains/txt')[0], txt, 'solo admin lee los TXT')
                self.assertEqual(client.post('/api/v1/domains/no-existe.acme-demo.mx/scans')[0], scan,
                                 'el gerente no puede pedir escaneos')

    def test_10_la_contrasena_mala_queda_en_la_bitacora(self):
        # La API escribe el fallo después de mandar el 401, para que el tiempo no delate que el correo
        # existe. Con raise HTTPException esa tarea no correría y el fallo no quedaría en la bitácora.
        contar = ("SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = '%s' "
                  "AND a.action = 'auth.login_failed' AND a.details->>'reason' = 'password';" % JORDAN)
        antes = int(scalar(contar, user='postgres'))
        code, body = sesion.post_login(Client(), JORDAN, 'no-es-la-contrasena')
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
        # Los dos captchas se resuelven antes de abrir la conexión: resolverlos entre una petición y otra la deja
        # inactiva más que el keep-alive de uvicorn (5 s) y la cerraría la API, no la bitácora.
        captchas = {email: sesion.captcha(Client()) for email in (JORDAN, 'nadie@acme-demo.mx')}
        url = urlsplit(sesion.BASE)
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
        self.addCleanup(conn.close)
        for email, captcha in captchas.items():
            conn.request('POST', '/api/v1/auth/login', json.dumps({'email': email, 'password': 'no-es-la-contrasena',
                                                                   'captcha': captcha}),
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
        _, body = sesion.post_login(client, DANA, PASSWORD)
        guardado = body['mfa_token']
        for i, malo in enumerate(codigos_malos(DANA, 5)):
            code, body = sesion.post_login(client, DANA, PASSWORD)
            self.assertEqual((code, body.get('mfa_required')), (200, True), 'login %d' % (i + 1))
            code, body = client.post(AUTH + '/mfa/verify', {'mfa_token': body['mfa_token'], 'code': malo})
            self.assertEqual((code, body['detail']), (401, MFA_INVALID), 'código %d' % (i + 1))
        code, body = sesion.post_login(client, DANA, PASSWORD)
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
        _, body = sesion.post_login(Client(), DANA, PASSWORD)
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
        self.assertEqual(int(scalar(contar, user='postgres')) - antes, 5, 'cada código revisado queda en la bitácora')
        code, body = Client().post(AUTH + '/mfa/verify', {'mfa_token': token, 'code': sesion.next_code(DANA)})
        self.assertEqual((code, body['detail']), (401, MFA_EXPIRED), 'gastados los 5 intentos, el token ya no sirve')

    def test_14_varios_tokens_en_paralelo_no_pasan_de_cinco(self):
        # Un código por mfa_token, 20 tokens a la vez. El límite de cada token no frena nada aquí: lo frena
        # el fallo del correo, que se cuenta antes de revisar el código. Los logins correctos no cuentan.
        self.addCleanup(sesion.reset)
        tokens = [sesion.post_login(Client(), DANA, PASSWORD)[1]['mfa_token'] for _ in range(20)]
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
            code, body = sesion.post_login(client, DANA, PASSWORD)
            self.assertEqual(code, 200, 'login %d' % (i + 1))
            code, body = client.post(AUTH + '/mfa/verify', {'mfa_token': body['mfa_token'], 'code': sesion.next_code(DANA)})
            self.assertEqual(code, 200, 'código %d' % (i + 1))


def _cambiar(resuelto, cambio):
    """El mismo captcha resuelto con un cambio aplicado a su JSON."""
    datos = json.loads(base64.b64decode(resuelto))
    cambio(datos)
    return base64.b64encode(json.dumps(datos).encode()).decode()


class Captcha(unittest.TestCase):
    """El login pide el captcha ALTCHA (RC-154): sin él, con uno inventado, manipulado o ya usado no entra nadie."""

    @classmethod
    def setUpClass(cls):
        sesion.reset()

    def _login(self, client, email, password, resuelto):
        body = {'email': email, 'password': password}
        if resuelto is not None:
            body['captcha'] = resuelto
        return client.post(AUTH + '/login', body)

    def assertRechazado(self, client, respuesta, motivo):
        code, body = respuesta
        self.assertEqual((code, body['detail']), (400, CAPTCHA_INVALID), motivo)
        self.assertNotIn('mfa_token', body, motivo)
        self.assertIsNone(client.cookie(), motivo)

    def test_1_el_reto_trae_firma_vencimiento_y_no_se_guarda(self):
        client = Client()
        req = urllib.request.Request(AUTH + '/captcha')
        with client.opener.open(req, timeout=10) as r:
            self.assertEqual(r.headers['Cache-Control'], 'no-store')
            reto = json.loads(r.read())
        params = reto['parameters']
        self.assertEqual((params['algorithm'], params['keyPrefix']), ('PBKDF2/SHA-256', '00'))
        self.assertRegex(reto['signature'], r'^[0-9a-f]{64}$')
        self.assertAlmostEqual(params['expiresAt'], time.time() + 600, delta=30)
        self.assertNotEqual(Client().get(AUTH + '/captcha')[1]['parameters']['nonce'], params['nonce'])

    def test_2_sin_captcha_o_con_uno_inventado_no_entra_ni_con_la_contrasena(self):
        client = Client()
        for resuelto, motivo in ((None, 'sin el campo'), ('', 'vacío'), ('no-es-base64!', 'basura'),
                                 (base64.b64encode(b'[1, 2]').decode(), 'JSON que no es un reto'),
                                 ('A' * 5000, 'demasiado largo')):
            code, body = self._login(client, JORDAN, PASSWORD, resuelto)
            if motivo == 'demasiado largo':
                self.assertEqual(code, 422, motivo)  # ni llega a decodificarse
                continue
            self.assertRechazado(client, (code, body), motivo)

    def test_3_un_captcha_manipulado_no_sirve(self):
        client = Client()
        cambios = {
            'contador de otro': lambda d: d['solution'].update(counter=d['solution']['counter'] + 1),
            'llave inventada': lambda d: d['solution'].update(derivedKey='00' * 32),
            'reto más barato': lambda d: d['challenge']['parameters'].update(cost=1),
            'vencimiento movido': lambda d: d['challenge']['parameters'].update(expiresAt=d['challenge']['parameters']['expiresAt'] + 3600),
            'sin firma': lambda d: d['challenge'].pop('signature'),
            'firma de otro reto': lambda d: d['challenge'].update(signature='0' * 64),
        }
        for motivo, cambio in cambios.items():
            with self.subTest(motivo):
                self.assertRechazado(client, self._login(client, JORDAN, PASSWORD, _cambiar(sesion.captcha(client), cambio)), motivo)

    def test_4_un_captcha_resuelto_por_cuenta_propia_sin_reto_de_la_api_no_sirve(self):
        # Un reto con la misma forma pero firmado con otra llave: quien no tiene la llave de la API no puede hacer los suyos.
        client = Client()
        reto = client.get(AUTH + '/captcha')[1]
        reto['parameters']['nonce'] = secrets.token_hex(16)
        reto['signature'] = hmac.new(b'otra-llave', json.dumps(reto['parameters'], sort_keys=True).encode(), 'sha256').hexdigest()
        self.assertRechazado(client, self._login(client, JORDAN, PASSWORD, sesion.solve_captcha(reto)), 'firmado con otra llave')

    def test_5_el_captcha_se_gasta_aunque_la_contrasena_falle(self):
        client = Client()
        resuelto = sesion.captcha(client)
        code, body = self._login(client, JORDAN, 'no-es-la-contrasena', resuelto)
        self.assertEqual((code, body['detail']), (401, INVALID))
        self.assertRechazado(client, self._login(client, JORDAN, PASSWORD, resuelto), 'reusado tras un 401')
        resuelto = sesion.captcha(client)
        self.assertEqual(self._login(client, JORDAN, PASSWORD, resuelto)[0], 200)
        self.assertRechazado(client, self._login(Client(), JORDAN, PASSWORD, resuelto), 'reusado tras un 200, desde otro cliente')

    def test_6_el_mismo_captcha_en_paralelo_entra_una_sola_vez(self):
        resuelto = sesion.captcha(Client())
        salida = threading.Barrier(10)

        def intento(_):
            salida.wait()
            return self._login(Client(), JORDAN, PASSWORD, resuelto)[0]

        with ThreadPoolExecutor(10) as pool:
            codigos = list(pool.map(intento, range(10)))
        self.assertEqual((codigos.count(200), codigos.count(400)), (1, 9), codigos)

    def test_7_el_captcha_malo_no_cuenta_para_el_bloqueo(self):
        # Si contara, cualquiera bloquearía un correo ajeno sin hacer la prueba de trabajo.
        client = Client()
        email = 'captcha-%s@acme-demo.mx' % secrets.token_hex(4)
        for _ in range(MAX_FALLOS + 2):
            self.assertRechazado(client, self._login(client, email, 'x', 'basura'), 'sin captcha válido')
        code, body = sesion.post_login(client, email, 'x')
        self.assertEqual((code, body['detail']), (401, INVALID), 'el correo no debe quedar bloqueado')


PASSWORD_URL = AUTH + '/password'
NUEVA = 'Marea-Baja-Prueba-2026'
MALA = 'no-es-la-contrasena-actual'
WRONG = 'La contraseña actual no es correcta.'
WRONG_LAST = 'La contraseña actual no es correcta. Por seguridad cerramos tu sesión: vuelve a iniciarla.'
COMUN = 'Esa contraseña es muy común. Elige otra.'
LOCKED = 'Demasiados intentos. Espera 15 minutos e inténtalo de nuevo.'
MAX_INTENTOS = 5  # MAX_PASSWORD_ATTEMPTS de cirdan/auth/sessions.py


def entrar(email):
    """Sesión nueva sin esperar 30 s por código: sin último código usado, el mismo vuelve a servir (como test_15)."""
    scalar("UPDATE users SET last_totp_step = NULL WHERE email = '%s' RETURNING 1;" % email, user='postgres')
    sesion._last_step.pop(email, None)
    return sesion.login(email)


def cambiar(client, actual, nueva):
    """POST /auth/password. Devuelve (código, detail, cabeceras)."""
    req = urllib.request.Request(PASSWORD_URL, json.dumps({'current_password': actual, 'new_password': nueva}).encode(),
                                 {'Content-Type': 'application/json'}, method='POST')
    try:
        with client.opener.open(req, timeout=15) as r:
            return r.status, None, r.headers
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, (json.loads(raw) if raw else {}).get('detail'), e.headers


def contar_eventos(email, action):
    return int(scalar("SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = '%s' "
                      "AND a.action = '%s';" % (email, action), user='postgres'))


class CambioContrasena(unittest.TestCase):
    """RC-290 (límite de intentos y cierre de las demás sesiones) y RC-281 (contraseñas comunes)."""

    def setUp(self):
        sesion.reset()
        self.addCleanup(sesion.reset)

    def restaurar(self, client):
        # La sesión que cambió sigue abierta: con ella se vuelve a la contraseña de demo.
        self.assertEqual(cambiar(client, NUEVA, PASSWORD)[:2], (204, None), 'no se pudo volver a la contraseña de demo')

    def test_1_cinco_malas_dan_400_y_la_sexta_429_sin_revisar(self):
        antes = contar_eventos(DANA, 'auth.password_change_locked')
        client = entrar(DANA)
        token = client.cookie().value
        for i in range(MAX_INTENTOS - 1):
            self.assertEqual(cambiar(client, MALA, NUEVA)[:2], (400, WRONG), 'intento %d' % (i + 1))
        self.assertEqual(cambiar(client, MALA, NUEVA)[:2], (400, WRONG_LAST), 'el quinto avisa que cierra la sesión')
        self.assertIsNone(client.cookie(), 'la respuesta del quinto borra la cookie')
        self.assertEqual(Client().get(AUTH + '/me', {'Cookie': 'lt_session=' + token})[0], 401,
                         'la sesión del quinto fallo ya no sirve en el servidor')
        self.assertEqual(contar_eventos(DANA, 'auth.password_change_locked') - antes, 1)
        # El login no quedó bloqueado: el contador es otro. Desde una sesión nueva, ni con la contraseña actual buena
        # se revisa: 429 con Retry-After, y la contraseña no cambió.
        otra = entrar(DANA)
        code, detail, headers = cambiar(otra, PASSWORD, NUEVA)
        self.assertEqual((code, detail, headers.get('Retry-After')), (429, LOCKED, '900'))
        self.assertEqual(sesion.post_login(Client(), DANA, NUEVA)[0], 401, 'la contraseña no debe haber cambiado')
        self.assertEqual(sesion.post_login(Client(), DANA, PASSWORD)[0], 200)
        self.assertEqual(otra.get(AUTH + '/me')[0], 200, 'el 429 no cierra la sesión')
        self.assertEqual(int(scalar("SELECT count(*) FROM audit_log WHERE details::text LIKE '%%%s%%';" % MALA,
                                    user='postgres')), 0, 'la bitácora no guarda la contraseña')

    def test_2_con_la_buena_antes_del_limite_se_cambia_como_hoy(self):
        client = entrar(DANA)
        for i in range(MAX_INTENTOS - 1):
            self.assertEqual(cambiar(client, MALA, NUEVA)[:2], (400, WRONG), 'intento %d' % (i + 1))
        self.assertEqual(cambiar(client, PASSWORD, NUEVA)[:2], (204, None))
        self.addCleanup(self.restaurar, client)
        self.assertEqual(sesion.post_login(Client(), DANA, PASSWORD)[0], 401, 'la anterior ya no entra')
        self.assertEqual(sesion.post_login(Client(), DANA, NUEVA)[0], 200, 'la nueva entra')
        self.assertEqual(client.get(AUTH + '/me')[0], 200, 'la sesión que cambió sigue abierta')
        # El cambio correcto borra los intentos: 4 malas más vuelven a ser 400 sin cerrar la sesión.
        for i in range(MAX_INTENTOS - 1):
            self.assertEqual(cambiar(client, MALA, PASSWORD)[:2], (400, WRONG), 'intento %d tras el cambio' % (i + 1))

    def test_3_seis_en_paralelo_no_revisan_mas_de_cinco(self):
        # Una sesión por petición: así el cierre de la sesión del quinto no frena a las demás antes del contador.
        antes = contar_eventos(DANA, 'auth.password_change_locked')
        clientes = [entrar(DANA) for _ in range(MAX_INTENTOS + 1)]
        salida = threading.Barrier(len(clientes))

        def intento(client):
            salida.wait()
            return cambiar(client, MALA, NUEVA)[:2]

        with ThreadPoolExecutor(len(clientes)) as pool:
            respuestas = list(pool.map(intento, clientes))
        codigos = [r[0] for r in respuestas]
        self.assertEqual((codigos.count(400), codigos.count(429)), (5, 1), respuestas)
        self.assertEqual(respuestas.count((400, WRONG_LAST)), 1, respuestas)
        self.assertEqual(contar_eventos(DANA, 'auth.password_change_locked') - antes, 1)
        self.assertEqual(sum(c.get(AUTH + '/me')[0] == 401 for c in clientes), 1, 'solo se cierra la sesión del quinto')

    def test_4_cambiar_cierra_las_demas_sesiones(self):
        primera, segunda = entrar(DANA), entrar(DANA)
        self.assertEqual(segunda.get(AUTH + '/me')[0], 200)
        self.assertEqual(cambiar(primera, PASSWORD, NUEVA)[:2], (204, None))
        self.addCleanup(self.restaurar, primera)
        self.assertEqual(segunda.get(AUTH + '/me')[0], 401, 'la otra sesión se cierra')
        self.assertEqual(primera.get(AUTH + '/me')[0], 200, 'la que cambió sigue abierta')

    def test_5_una_comun_con_otras_mayusculas_da_400_y_una_que_no_esta_204(self):
        client = entrar(DANA)
        for comun in ('1Q2W3E4R5T6Y', '123QWEasdZXC'):
            self.assertEqual(cambiar(client, PASSWORD, comun)[:2], (400, COMUN), comun)
        self.assertEqual(sesion.post_login(Client(), DANA, PASSWORD)[0], 200, 'la contraseña no cambió')
        self.assertEqual(cambiar(client, PASSWORD, NUEVA)[:2], (204, None))
        self.addCleanup(self.restaurar, client)


if __name__ == '__main__':
    unittest.main(verbosity=2)
