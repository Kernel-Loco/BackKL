"""Pruebas del inicio de sesión (#25 y TOTP de RC-5) contra la API local (biblioteca estándar).

    python -m unittest -v pruebas/test_auth.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)
"""
import base64
import hashlib
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

from pruebas import sesion, test_aislamiento
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
MAX_FALLOS_IP = 20  # MAX_FAILS_IP de cirdan/auth/sessions.py
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

    def test_16_un_codigo_con_digitos_que_no_son_0_a_9_da_422_y_no_gasta_el_token(self):
        # \d y isdigit() aceptaban '١٢٣٤٥٦' y '１２３４５６', y hmac.compare_digest tronaba con un 500 sin bitácora (RC-315).
        client = Client()
        _, body = sesion.post_login(client, MAYA, PASSWORD)
        token = body['mfa_token']
        for codigo in ('١٢٣٤٥٦', '１２３４５６'):
            code, body = client.post(AUTH + '/mfa/verify', {'mfa_token': token, 'code': codigo})
            self.assertEqual(code, 422, ascii(codigo))
        code, _ = client.post(AUTH + '/mfa/verify', {'mfa_token': token, 'code': sesion.next_code(MAYA)})
        self.assertEqual(code, 200, 'el 422 sale antes de revisar el token, así que el token sigue sirviendo')

    def test_17_treinta_contrasenas_en_paralelo_solo_revisan_cinco(self):
        # RC-270: /login cuenta el intento antes de revisar la contraseña, en un solo paso de Valkey. Antes revisaba el
        # bloqueo, luego la contraseña y contaba el fallo al final, así que las 30 leían el contador en 0 y se revisaban.
        sesion.reset()
        self.addCleanup(sesion.reset)
        contar = ("SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = '%s' "
                  "AND a.action = 'auth.login_failed' AND a.details->>'reason' = 'password';" % DANA)
        antes = int(scalar(contar, user='postgres'))
        resueltos = [sesion.captcha(Client()) for _ in range(30)]  # fuera de la carrera: resolverlos tarda
        salida = threading.Barrier(len(resueltos))

        def intento(par):
            n, resuelto = par
            salida.wait()
            code, body = Client().post(AUTH + '/login', {'email': DANA, 'password': 'CIRDAN_FAKE_mala-%d' % n,
                                                          'captcha': resuelto})
            return code, (body or {}).get('detail')

        with ThreadPoolExecutor(len(resueltos)) as pool:
            respuestas = list(pool.map(intento, enumerate(resueltos)))
        self.assertEqual(respuestas.count((401, INVALID)), MAX_FALLOS, respuestas)
        self.assertEqual([r[0] for r in respuestas].count(429), len(resueltos) - MAX_FALLOS, respuestas)
        for _ in range(50):  # la bitácora del 401 se escribe después de responder: hasta 5 s
            if int(scalar(contar, user='postgres')) - antes >= MAX_FALLOS:
                break
            time.sleep(0.1)
        time.sleep(0.5)  # por si llegara una de más
        self.assertEqual(int(scalar(contar, user='postgres')) - antes, MAX_FALLOS, 'solo 5 contraseñas se revisaron')
        self.assertEqual(_fallos(_llave_correo(DANA)), MAX_FALLOS)
        ip, = _llaves_ip()
        self.assertEqual(_fallos(ip), MAX_FALLOS, 'los 25 que recibieron 429 no le suman a la IP')
        sesion.valkey('DEL', ip)  # así el 429 que sigue solo puede salir por el correo
        code, _ = sesion.post_login(Client(), DANA, PASSWORD)
        self.assertEqual(code, 429, 'después de la carrera el correo sigue bloqueado, también con la contraseña buena')

    def test_18_el_mismo_codigo_con_dos_tokens_a_la_vez_abre_una_sola_sesion(self):
        # RC-270 (el arreglo es de RC-331): /mfa/verify lee last_totp_step sin bloquear la fila y solo guarda el paso si
        # sigue siendo menor. Para que las dos lecturas lleguen antes que cualquier escritura, una transacción aparte
        # tiene la fila bloqueada 3 s: las dos peticiones leen el mismo last_totp_step y esperan en el UPDATE. Con el
        # UPDATE sin condición, como antes, las dos abrían sesión.
        sesion.reset()
        self.addCleanup(sesion.reset)
        contar = ("SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = '%s' "
                  "AND a.action = '%%s';" % MAYA)
        antes = {a: int(scalar(contar % a, user='postgres')) for a in ('auth.mfa_failed', 'auth.login_succeeded')}
        clientes = [Client(), Client()]
        tokens = [sesion.post_login(c, MAYA, PASSWORD)[1]['mfa_token'] for c in clientes]
        codigo = sesion.next_code(MAYA)
        candado = threading.Thread(target=test_aislamiento.psql, kwargs={'user': 'postgres', 'sql': (
            "BEGIN; SELECT 1 FROM users WHERE email = '%s' FOR UPDATE; SELECT pg_sleep(3) AS rc270_candado; COMMIT;"
            % MAYA)})
        candado.start()
        self.addCleanup(candado.join)
        esperando = "SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%rc270_candado%' AND pid <> pg_backend_pid();"
        for _ in range(100):  # hasta 10 s a que la fila quede bloqueada
            if int(scalar(esperando, user='postgres')):
                break
            time.sleep(0.1)
        else:
            self.fail('la transacción que bloquea la fila no empezó')
        salida = threading.Barrier(2)

        def intento(par):
            client, token = par
            salida.wait()
            return client.post(AUTH + '/mfa/verify', {'mfa_token': token, 'code': codigo})

        with ThreadPoolExecutor(2) as pool:
            respuestas = list(pool.map(intento, zip(clientes, tokens)))
        self.assertEqual(sorted(r[0] for r in respuestas), [200, 401], respuestas)
        self.assertIn((401, {'detail': MFA_INVALID}), respuestas)
        self.assertEqual([c.cookie() is not None for c in clientes].count(True), 1, 'una sola cookie de sesión')
        self.assertEqual(int(scalar(contar % 'auth.login_succeeded', user='postgres')) - antes['auth.login_succeeded'], 1)
        self.assertEqual(int(scalar(contar % 'auth.mfa_failed', user='postgres')) - antes['auth.mfa_failed'], 1,
                         'el código usado queda en la bitácora como auth.mfa_failed')

    def test_19_veintiuna_entradas_buenas_no_bloquean_la_ip(self):
        # RC-270: /login cuenta cada intento antes de revisar la contraseña y lo devuelve si fue correcta. Sin esa
        # devolución, la entrada 21 de la misma IP en 15 min respondería 429, aunque todas fueran buenas.
        sesion.reset()
        self.addCleanup(sesion.reset)
        self._sin_mfa(JORDAN)
        for i in range(MAX_FALLOS_IP + 1):
            code, body = sesion.post_login(Client(), JORDAN, PASSWORD)
            self.assertEqual((code, body.get('mfa_required')), (200, False), 'entrada %d' % (i + 1))

    def test_20_un_429_no_le_suma_al_otro_contador(self):
        # RC-270: con la IP en su máximo, un login a otro correo responde 429 sin subir ese correo, y con el correo en
        # su máximo el 429 no sube la IP. Si contara, una IP bloqueada seguiría bloqueando correos ajenos sin límite.
        sesion.reset()
        self.addCleanup(sesion.reset)
        self.assertEqual(sesion.post_login(Client(), DANA, 'CIRDAN_FAKE_mala')[0], 401)
        ip, = _llaves_ip()
        sesion.valkey('SET', ip, str(MAX_FALLOS_IP), 'KEEPTTL')
        self.assertEqual(sesion.post_login(Client(), MAYA, 'CIRDAN_FAKE_mala')[0], 429)
        self.assertEqual(sesion.valkey('EXISTS', _llave_correo(MAYA)), ['0'], 'el 429 de la IP no cuenta para el correo')
        self.assertEqual(_fallos(ip), MAX_FALLOS_IP)
        sesion.reset()
        for _ in range(MAX_FALLOS):
            self.assertEqual(sesion.post_login(Client(), DANA, 'CIRDAN_FAKE_mala')[0], 401)
        ip, = _llaves_ip()
        self.assertEqual(sesion.post_login(Client(), DANA, PASSWORD)[0], 429)
        self.assertEqual((_fallos(_llave_correo(DANA)), _fallos(ip)), (MAX_FALLOS, MAX_FALLOS),
                         'el 429 del correo no cuenta para la IP')

    def test_21_tres_malas_y_una_buena_dejan_tres_con_vencimiento(self):
        # RC-270, con Valkey real: con TOTP la contraseña buena no borra los fallos del correo, solo devuelve su
        # intento. Los dos contadores quedan en 3 y vencen en 15 min como mucho, contados desde el primer fallo.
        sesion.reset()
        self.addCleanup(sesion.reset)
        for _ in range(3):
            self.assertEqual(sesion.post_login(Client(), MAYA, 'CIRDAN_FAKE_mala')[0], 401)
        correo, (ip,) = _llave_correo(MAYA), _llaves_ip()
        vence = {llave: int(sesion.valkey('PEXPIRETIME', llave)[0]) for llave in (correo, ip)}
        code, body = sesion.post_login(Client(), MAYA, PASSWORD)
        self.assertEqual((code, body.get('mfa_required')), (200, True))
        for llave in (correo, ip):
            self.assertEqual(_fallos(llave), 3, llave)
            self.assertIn(int(sesion.valkey('TTL', llave)[0]), range(1, 901), llave)
            self.assertEqual(int(sesion.valkey('PEXPIRETIME', llave)[0]), vence[llave], 'el login bueno no lo renueva')

    def test_22_la_devolucion_no_crea_llaves_ni_baja_una_ventana_nueva(self):
        # RC-270, con el Valkey y el código de la API: refund_login_attempt solo baja el contador de la misma ventana
        # que subió take_login_attempt. Si el contador desapareció no lo crea, y si venció y otro fallo abrió una
        # ventana nueva, ese fallo sigue contando.
        sesion.reset()
        self.addCleanup(sesion.reset)
        salida = sesion.en_api(
            'import json, time\n'
            'from cirdan.auth import sessions as s\n'
            "e, ip, v = 'rc270-ventana@ejemplo.test', '198.51.100.70', s._valkey()\n"
            'llaves = (s._email_key(e), s._ip_key(ip))\n'
            't = s.take_login_attempt(e, ip)\n'
            'v.delete(*llaves)\n'
            's.refund_login_attempt(e, ip, t)\n'
            'sin = v.exists(*llaves)\n'
            't = s.take_login_attempt(e, ip)\n'
            'for k in llaves: v.pexpire(k, 1)\n'
            'time.sleep(0.05)\n'
            's.register_fail(e, ip)\n'
            's.refund_login_attempt(e, ip, t)\n'
            'print(json.dumps([sin] + [int(v.get(k) or 0) for k in llaves] + [v.ttl(k) for k in llaves]))')
        sin, correo, ip, *ttl = json.loads(salida)
        self.assertEqual(sin, 0, 'sin contadores, la devolución no los crea')
        self.assertEqual((correo, ip), (1, 1), 'el fallo de la ventana nueva sigue contando')
        for segundos in ttl:
            self.assertIn(segundos, range(1, 901))

    def test_23_la_sexta_contrasena_mala_deja_un_solo_login_locked(self):
        # RC-302: el 429 de un correo que existe queda en la bitácora de su empresa, escrito tras la respuesta, y
        # solo el primero de su ventana de bloqueo: la séptima y la octava no suman, ni con la contraseña buena.
        sesion.reset()
        self.addCleanup(sesion.reset)
        antes = _eventos(DANA, 'auth.login_locked')
        for _ in range(MAX_FALLOS):
            self.assertEqual(sesion.post_login(Client(), DANA, 'CIRDAN_FAKE_mala')[0], 401)
        self.assertEqual(_login_con_cabeceras(DANA, 'CIRDAN_FAKE_mala'), (429, LOCKED, '900'))
        self.assertEqual(_esperar(lambda: _eventos(DANA, 'auth.login_locked'), antes + 1), antes + 1)
        for password in ('CIRDAN_FAKE_mala', PASSWORD):
            self.assertEqual(sesion.post_login(Client(), DANA, password)[0], 429)
        time.sleep(1)  # tiempo para que corriera una tarea de más
        self.assertEqual(_eventos(DANA, 'auth.login_locked'), antes + 1, 'la séptima y la octava no suman eventos')
        self.assertEqual(_ultimo_detalle(DANA, 'auth.login_locked'), {'lock': ['email']})

    def test_24_el_sexto_codigo_deja_un_solo_mfa_locked(self):
        # RC-302: con 5 códigos malos el sexto da 429 y deja auth.mfa_locked. Dos mfa_token sacados al principio no se
        # gastaron, así que llegan al bloqueo del correo: el séptimo código tampoco suma.
        sesion.reset()
        self.addCleanup(sesion.reset)
        antes = _eventos(DANA, 'auth.mfa_locked')
        guardados = [sesion.post_login(Client(), DANA, PASSWORD)[1]['mfa_token'] for _ in range(2)]
        for i, malo in enumerate(codigos_malos(DANA, MAX_FALLOS)):
            _, body = sesion.post_login(Client(), DANA, PASSWORD)
            code, body = Client().post(AUTH + '/mfa/verify', {'mfa_token': body['mfa_token'], 'code': malo})
            self.assertEqual((code, body['detail']), (401, MFA_INVALID), 'código %d' % (i + 1))
        code, body = Client().post(AUTH + '/mfa/verify', {'mfa_token': guardados[0], 'code': sesion.next_code(DANA)})
        self.assertEqual((code, body['detail']), (429, LOCKED))
        self.assertEqual(_esperar(lambda: _eventos(DANA, 'auth.mfa_locked'), antes + 1), antes + 1)
        code, _ = Client().post(AUTH + '/mfa/verify', {'mfa_token': guardados[1], 'code': sesion.next_code(DANA)})
        self.assertEqual(code, 429)
        time.sleep(1)
        self.assertEqual(_eventos(DANA, 'auth.mfa_locked'), antes + 1, 'el séptimo código no suma eventos')
        self.assertEqual(_ultimo_detalle(DANA, 'auth.mfa_locked'), {'lock': ['email']})

    def test_25_el_correo_que_no_existe_deja_una_linea_con_el_dominio_y_sin_el_correo(self):
        # RC-302, decisiones 1a y 2b: sin empresa no hay bitácora. El 401 y el primer 429 dejan una línea en el log de
        # la API con la IP y el dominio, nunca el correo. El 429 siguiente de la misma ventana no deja otra.
        sesion.reset()
        self.addCleanup(sesion.reset)
        usuario, dominio = 'nadie-%s' % secrets.token_hex(4), 'rc302-%s.test' % secrets.token_hex(4)
        email = usuario + '@' + dominio
        for _ in range(MAX_FALLOS):
            self.assertEqual(sesion.post_login(Client(), email, 'CIRDAN_FAKE_mala'), (401, {'detail': INVALID}))
        self.assertEqual(_login_con_cabeceras(email, 'CIRDAN_FAKE_mala'), (429, LOCKED, '900'))
        self.assertEqual(sesion.post_login(Client(), email, 'CIRDAN_FAKE_mala')[0], 429)

        def lineas():
            return [l for l in sesion.api_logs().splitlines() if dominio in l]
        for _ in range(50):
            if len(lineas()) >= MAX_FALLOS + 1:
                break
            time.sleep(0.1)
        time.sleep(1)
        encontradas = lineas()
        fallos = [l for l in encontradas if 'auth.login_failed de un correo que no existe' in l]
        bloqueos = [l for l in encontradas if 'auth.login_locked de un correo que no existe' in l]
        self.assertEqual((len(fallos), len(bloqueos), len(encontradas)), (MAX_FALLOS, 1, MAX_FALLOS + 1), encontradas)
        for linea in encontradas:
            self.assertIn("dominio='%s'" % dominio, linea)
            self.assertRegex(linea, r"ip='[^']+'")
        self.assertIn('bloqueo=email', bloqueos[0])
        self.assertNotIn(usuario, sesion.api_logs(), 'el correo completo nunca va al log')

    def test_26_con_la_ip_bloqueada_solo_el_primer_429_deja_evento(self):
        # RC-302: el bloqueo de la IP avisa una vez por ventana aunque cada 429 sea de otro correo.
        sesion.reset()
        self.addCleanup(sesion.reset)
        self.assertEqual(sesion.post_login(Client(), DANA, 'CIRDAN_FAKE_mala')[0], 401)
        ip, = _llaves_ip()
        sesion.valkey('SET', ip, str(MAX_FALLOS_IP), 'KEEPTTL')
        antes = {email: _eventos(email, 'auth.login_locked') for email in (MAYA, JORDAN)}
        self.assertEqual(sesion.post_login(Client(), MAYA, 'CIRDAN_FAKE_mala')[0], 429)
        self.assertEqual(_esperar(lambda: _eventos(MAYA, 'auth.login_locked'), antes[MAYA] + 1), antes[MAYA] + 1)
        self.assertEqual(_ultimo_detalle(MAYA, 'auth.login_locked'), {'lock': ['ip']})
        self.assertEqual(sesion.post_login(Client(), JORDAN, PASSWORD)[0], 429)
        time.sleep(1)
        self.assertEqual(_eventos(JORDAN, 'auth.login_locked'), antes[JORDAN], 'la IP ya avisó en esta ventana')
        self.assertEqual(_eventos(MAYA, 'auth.login_locked'), antes[MAYA] + 1)


def _eventos(email, accion):
    return int(scalar("SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = '%s' "
                      "AND a.action = '%s';" % (email, accion), user='postgres'))


def _ultimo_detalle(email, accion):
    return json.loads(scalar("SELECT a.details::text FROM audit_log a JOIN users u ON u.id = a.actor_user_id "
                             "WHERE u.email = '%s' AND a.action = '%s' ORDER BY a.occurred_at DESC LIMIT 1;"
                             % (email, accion), user='postgres'))


def _esperar(contar, meta):
    """Hasta 5 s a que contar() llegue a meta: la API escribe estos eventos después de mandar la respuesta."""
    for _ in range(50):
        if contar() >= meta:
            break
        time.sleep(0.1)
    return contar()


def _login_con_cabeceras(email, password):
    """POST /auth/login que devuelve (código, detail, Retry-After)."""
    client = Client()
    req = urllib.request.Request(sesion.BASE + AUTH + '/login', method='POST',
                                 data=json.dumps({'email': email, 'password': password,
                                                  'captcha': sesion.captcha(client)}).encode(),
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read()).get('detail'), r.headers.get('Retry-After')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()).get('detail'), e.headers.get('Retry-After')


def _llave_correo(email):
    return 'login:fail:email:' + hashlib.sha256(email.lower().encode()).hexdigest()  # _email_key de sessions.py


def _llaves_ip():
    """Los contadores de IP que hay en Valkey. La IP con la que llegan las pruebas depende de Docker: se buscan."""
    return sesion.valkey('--scan', '--pattern', 'login:fail:ip:*')


def _fallos(llave):
    return int(sesion.valkey('GET', llave)[0] or 0)


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
    """POST /auth/password. Devuelve (código, cuerpo con 200 o detail con error, cabeceras)."""
    req = urllib.request.Request(PASSWORD_URL, json.dumps({'current_password': actual, 'new_password': nueva}).encode(),
                                 {'Content-Type': 'application/json'}, method='POST')
    try:
        with client.opener.open(req, timeout=15) as r:
            raw = r.read()  # desde RC-331 responde 200 con passkeys_removed, no 204
            return r.status, (json.loads(raw) if raw else None), r.headers
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
        self.assertEqual(cambiar(client, NUEVA, PASSWORD)[:2], (200, {'passkeys_removed': 0}), 'no se pudo volver a la contraseña de demo')

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
        self.assertEqual(cambiar(client, PASSWORD, NUEVA)[:2], (200, {'passkeys_removed': 0}))
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
        self.assertEqual(cambiar(primera, PASSWORD, NUEVA)[:2], (200, {'passkeys_removed': 0}))
        self.addCleanup(self.restaurar, primera)
        self.assertEqual(segunda.get(AUTH + '/me')[0], 401, 'la otra sesión se cierra')
        self.assertEqual(primera.get(AUTH + '/me')[0], 200, 'la que cambió sigue abierta')

    def test_5_una_comun_con_otras_mayusculas_da_400_y_una_que_no_esta_200(self):
        client = entrar(DANA)
        for comun in ('1Q2W3E4R5T6Y', '123QWEasdZXC'):
            self.assertEqual(cambiar(client, PASSWORD, comun)[:2], (400, COMUN), comun)
        self.assertEqual(sesion.post_login(Client(), DANA, PASSWORD)[0], 200, 'la contraseña no cambió')
        self.assertEqual(cambiar(client, PASSWORD, NUEVA)[:2], (200, {'passkeys_removed': 0}))
        self.addCleanup(self.restaurar, client)

    def test_6_dos_cambios_a_la_vez_con_la_actual_solo_uno_gana(self):
        # Sin el lock de la fila los dos leían el hash viejo, daban 204 y ganaba el último: el de quien tuviera la vieja.
        nuevas = (NUEVA, 'Marea-Alta-Prueba-2026')
        clientes = [entrar(DANA), entrar(DANA)]
        salida = threading.Barrier(len(clientes))

        def intento(par):
            salida.wait()
            return cambiar(par[0], PASSWORD, par[1])[:2]

        with ThreadPoolExecutor(len(clientes)) as pool:
            respuestas = list(pool.map(intento, zip(clientes, nuevas)))
        ganadoras = [i for i, r in enumerate(respuestas) if r == (200, {'passkeys_removed': 0})]
        if len(ganadoras) == 1:
            ganadora = ganadoras[0]
            self.addCleanup(lambda: self.assertEqual(cambiar(clientes[ganadora], nuevas[ganadora], PASSWORD)[:2],
                                                     (200, {'passkeys_removed': 0}), 'no se pudo volver a la contraseña de demo'))
        self.assertEqual(sorted(r[0] for r in respuestas), [200, 400], respuestas)
        self.assertEqual(respuestas[1 - ganadora], (400, WRONG), respuestas)
        self.assertEqual(sesion.post_login(Client(), DANA, nuevas[ganadora])[0], 200, 'la que ganó entra')
        self.assertEqual(sesion.post_login(Client(), DANA, nuevas[1 - ganadora])[0], 401, 'la otra no')


if __name__ == '__main__':
    unittest.main(verbosity=2)
