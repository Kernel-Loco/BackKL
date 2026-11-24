"""Pruebas de las passkeys (RC-331) contra la base y la API locales, sin red (biblioteca estándar).

    python -m unittest -v pruebas/test_passkeys.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)

Las respuestas WebAuthn las arma pruebas/webauthn_falso.py con una llave P-256 de la prueba: RP ID localhost y origen
http://localhost:3000, que vienen de la lista local de orígenes. Cada prueba borra las passkeys que dejó, y las que dan
de alta una passkey directo en la base lo hacen como postgres, con la llave pública del autenticador falso.
"""
import hashlib
import os
import subprocess
import threading
import time
import unittest
import uuid

from pruebas import sesion
from pruebas.pila import exigir_desechable
from pruebas.sesion import AUTH, PASSWORD, Client
from pruebas.test_aislamiento import ACME, BETA, CONTAINER, psql, scalar
from pruebas.webauthn_falso import AT, UP, UV, Autenticador, b64url

PK = AUTH + '/passkeys'
VALKEY = os.environ.get('CIRDAN_TEST_VALKEY', 'cirdan-valkey')
JORDAN, JORDAN_ID = 'jordan.tate@acme-demo.mx', '30000000-0000-4000-8000-000000000003'
MAYA_ID = '30000000-0000-4000-8000-000000000002'
DANA, DANA_ID = 'dana.cruz@beta-corp.mx', '30000000-0000-4000-8000-000000000004'
ALEX, ALEX_ID = 'alex.morgan@acme-demo.mx', '30000000-0000-4000-8000-000000000001'  # admin de Acme
ADMIN_MFA_PASSWORD = ('Las cuentas de administrador deben activar la verificación en dos pasos. '
                      'Entra con tu correo y contraseña para activarla.')
PASSKEY_INVALID = 'No se pudo entrar con esa passkey. Inténtalo de nuevo o entra con tu correo y contraseña.'
PASSKEY_EXPIRED = 'La solicitud de la passkey venció. Inténtalo de nuevo.'
LOCKED = 'Demasiados intentos. Espera 15 minutos e inténtalo de nuevo.'
OPTIONS_LIMIT = ('Se pidieron demasiadas passkeys desde tu red. Espera 15 minutos o entra con tu correo y '
                 'contraseña.')
MAX_PASSKEY_OPTIONS_IP = 300
PASSKEY_LIMIT = 'Ya tienes 10 passkeys. Borra una para registrar otra.'


def _valkey(*args):
    exigir_desechable()
    return subprocess.run(['docker', 'exec', VALKEY, 'sh', '-c',
                           'valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning ' + ' '.join(args)],
                          check=True, capture_output=True, text=True).stdout.strip()


def _limpiar_valkey():
    _valkey('--scan --pattern "webauthn:*" | xargs -r valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning del')
    sesion.reset()


def _borrar_passkeys():
    scalar('DELETE FROM webauthn_credentials; SELECT 1;', user='postgres')


def _alta_directa(autenticador, org=ACME, user_id=JORDAN_ID, name='Prueba'):
    """Da de alta la passkey del autenticador falso como postgres, sin pasar por /register."""
    autenticador.user_handle = uuid.UUID(user_id).bytes
    return scalar("INSERT INTO webauthn_credentials (organization_id, user_id, credential_id, public_key, sign_count, name)"
                  " VALUES ('%s', '%s', '\\x%s', '\\x%s', %d, '%s') RETURNING id;"
                  % (org, user_id, autenticador.credential_id.hex(), autenticador.cose_key().hex(),
                     autenticador.sign_count, name), user='postgres')


def _bitacora(accion, user_id=JORDAN_ID, extra=''):
    return int(scalar("SELECT count(*) FROM audit_log WHERE actor_user_id = '%s' AND action = '%s' %s;"
                      % (user_id, accion, extra), user='postgres'))


def _opciones(client=None):
    code, body = (client or Client()).post(PK + '/login/options')
    assert code == 200, (code, body)
    return body


def _entrar(autenticador, client=None, **kw):
    client = client or Client()
    body = _opciones(client)
    respuesta = autenticador.entrada(body['options'], **kw)
    return client, client.post(PK + '/login/verify', {'login_token': body['login_token'], 'credential': respuesta})


def _malo(secreto_email):
    paso = int(__import__('time').time() // sesion.STEP)
    validos = {sesion.totp(sesion.SECRETS[secreto_email], s) for s in range(paso - 2, paso + 3)}
    return next(c for c in ('%06d' % i for i in range(20)) if c not in validos)


class Base(unittest.TestCase):
    """La tabla y la función de la migración 017."""

    def setUp(self):
        self.addCleanup(_borrar_passkeys)

    def test_1_rls_forzado_y_otra_empresa_no_ve_la_passkey(self):
        self.assertEqual(scalar("SELECT relrowsecurity || ',' || relforcerowsecurity FROM pg_class "
                                "WHERE oid = 'public.webauthn_credentials'::regclass;", user='postgres'), 'true,true')
        _alta_directa(Autenticador())
        self.assertEqual(scalar('SELECT count(*) FROM webauthn_credentials;', org=ACME), '1')
        self.assertEqual(scalar('SELECT count(*) FROM webauthn_credentials;', org=BETA), '0')
        self.assertEqual(scalar('SELECT count(*) FROM webauthn_credentials;'), '0')  # sin empresa no ve nada
        ok, _, err = psql("INSERT INTO webauthn_credentials (organization_id, user_id, credential_id, public_key, name) "
                          "VALUES ('%s', '%s', '\\x01', '\\x01', 'x');" % (ACME, JORDAN_ID), org=BETA)
        self.assertFalse(ok)
        self.assertIn('row-level security', err)
        # Desde otra empresa, UPDATE y DELETE no ven la fila: afectan 0 filas y la de Acme no cambia.
        for sql in ('UPDATE webauthn_credentials SET sign_count = 77 RETURNING 1',
                    'DELETE FROM webauthn_credentials RETURNING 1'):
            with self.subTest(sql):
                self.assertEqual(scalar('WITH x AS (%s) SELECT count(*) FROM x;' % sql, org=BETA), '0')
        self.assertEqual(scalar('SELECT count(*) || \',\' || max(sign_count) FROM webauthn_credentials;',
                                user='postgres'), '1,0')

    def test_2_la_funcion_de_busqueda_sigue_el_patron_de_login_lookup(self):
        config = scalar("SELECT prosecdef || ',' || array_to_string(proconfig, ';') || ','"
                        " || has_function_privilege('public', oid, 'EXECUTE') || ','"
                        " || has_function_privilege('cirdan_app', oid, 'EXECUTE') FROM pg_proc"
                        " WHERE oid = 'public.passkey_lookup(bytea)'::regprocedure;", user='postgres')
        self.assertEqual(config, 'true,search_path=pg_catalog, public, pg_temp,false,true')
        a = Autenticador()
        _alta_directa(a)
        cid = "'\\x%s'::bytea" % a.credential_id.hex()
        fila = scalar('SELECT user_id || \'|\' || organization_id || \'|\' || email FROM passkey_lookup(%s);' % cid)
        self.assertEqual(fila, '%s|%s|%s' % (JORDAN_ID, ACME, JORDAN))
        self.assertEqual(scalar("SELECT count(*) FROM passkey_lookup('\\x00'::bytea);"), '0')
        for nombre, cambio in (('usuario inactivo', "UPDATE users SET is_active = false WHERE id = '%s'" % JORDAN_ID),
                               ('empresa suspendida', "UPDATE organizations SET status = 'suspended' WHERE id = '%s'" % ACME)):
            with self.subTest(nombre):
                self.assertEqual(scalar('BEGIN; %s; SELECT count(*) FROM passkey_lookup(%s); ROLLBACK;'
                                        % (cambio, cid), user='postgres'), '0')
        self.assertEqual(scalar("SELECT is_active FROM users WHERE id = '%s';" % JORDAN_ID, user='postgres'), 't')

    def test_3_la_app_solo_cambia_contador_uso_y_respaldo(self):
        _alta_directa(Autenticador())
        ok, _, _ = psql('UPDATE webauthn_credentials SET sign_count = 1, last_used_at = now(), backed_up = true;', org=ACME)
        self.assertTrue(ok)
        for columna in ("public_key = '\\x02'", "credential_id = '\\x02'", "user_id = '%s'" % MAYA_ID, "name = 'x'",
                        'created_at = now()'):
            with self.subTest(columna):
                ok, _, err = psql('UPDATE webauthn_credentials SET %s;' % columna, org=ACME)
                self.assertFalse(ok)
                self.assertIn('permission denied', err)
        # El INSERT es por columnas: id, created_at y last_used_at los pone la base.
        for columna, valor in (('id', "'%s'" % uuid.uuid4()), ('created_at', "'2020-01-01'"),
                               ('last_used_at', "'2020-01-01'")):
            with self.subTest('INSERT con ' + columna):
                ok, _, err = psql("INSERT INTO webauthn_credentials (organization_id, user_id, credential_id, public_key, "
                                  "name, %s) VALUES ('%s', '%s', '\\x0a', '\\x01', 'x', %s);"
                                  % (columna, ACME, JORDAN_ID, valor), org=ACME)
                self.assertFalse(ok)
                self.assertIn('permission denied', err)


class Entrar(unittest.TestCase):
    """POST /passkeys/login/options y /login/verify con passkeys dadas de alta en la base."""

    def setUp(self):
        _limpiar_valkey()
        self.addCleanup(_limpiar_valkey)
        self.addCleanup(_borrar_passkeys)
        self.a = Autenticador()
        self.passkey_id = _alta_directa(self.a)

    def test_4_las_opciones_piden_verificacion_y_no_nombran_cuentas(self):
        body = _opciones()
        self.assertEqual(body['options']['rpId'], 'localhost')
        self.assertEqual(body['options']['userVerification'], 'required')
        self.assertEqual(body['options'].get('allowCredentials', []), [])
        self.assertEqual(body['expires_in_seconds'], 300)
        ttl = int(_valkey('--scan --pattern "webauthn:auth:*" | head -1 | xargs valkey-cli -a "$VALKEY_PASSWORD" '
                          '--no-auth-warning ttl'))
        self.assertTrue(0 < ttl <= 300, ttl)

    def test_5_entra_crea_sesion_cuenta_como_mfa_y_deja_bitacora(self):
        antes = _bitacora('auth.login_succeeded', extra="AND details->>'via' = 'passkey'")
        client, (code, body) = _entrar(self.a)
        self.assertEqual(code, 200, body)
        self.assertEqual(body['user']['email'], JORDAN)
        self.assertTrue(body['user']['mfa_enabled'])
        self.assertIsNotNone(client.cookie())
        self.assertEqual(client.get(AUTH + '/me')[0], 200)
        self.assertEqual(_bitacora('auth.login_succeeded', extra="AND details->>'via' = 'passkey'"), antes + 1)
        self.assertEqual(scalar("SELECT last_used_at IS NOT NULL FROM webauthn_credentials WHERE id = '%s';"
                                % self.passkey_id, user='postgres'), 't')

    def test_6_el_reto_sirve_una_sola_vez(self):
        client = Client()
        body = _opciones(client)
        respuesta = self.a.entrada(body['options'])
        envio = {'login_token': body['login_token'], 'credential': respuesta}
        self.assertEqual(client.post(PK + '/login/verify', envio)[0], 200)
        self.assertEqual(Client().post(PK + '/login/verify', envio), (401, {'detail': PASSKEY_EXPIRED}))

    def test_6b_en_paralelo_solo_entra_una(self):
        body = _opciones()
        envio = {'login_token': body['login_token'], 'credential': self.a.entrada(body['options'])}
        codigos = []
        hilos = [threading.Thread(target=lambda: codigos.append(Client().post(PK + '/login/verify', envio)[0]))
                 for _ in range(8)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join()
        self.assertEqual(sorted(codigos), [200] + [401] * 7)

    def test_7_respuestas_malas_no_entran(self):
        otro = Autenticador()
        casos = {
            'user handle de otra cuenta': {'user_handle': uuid.UUID(MAYA_ID).bytes},
            'sin verificación del usuario': {'flags': UP},
            'sin presencia': {'flags': UV},
            'otro origen': {'origin': 'https://evil.example'},
            'otro RP ID': {'rp_id': 'evil.example'},
            'firma mala': {'firma_mala': True},
            'tipo de registro': {'kind': 'webauthn.create'},
        }
        for nombre, kw in casos.items():
            with self.subTest(nombre):
                sesion.reset()
                client, (code, body) = _entrar(self.a, **kw)
                self.assertEqual((code, body), (401, {'detail': PASSKEY_INVALID}))
                self.assertIsNone(client.cookie())
        with self.subTest('passkey que no existe'):
            self.assertEqual(_entrar(otro)[1], (401, {'detail': PASSKEY_INVALID}))
        with self.subTest('sin userHandle'):
            sesion.reset()
            self.a.user_handle = b''
            self.assertEqual(_entrar(self.a)[1], (401, {'detail': PASSKEY_INVALID}))

    def test_8_los_fallos_cuentan_para_el_correo_y_bloquean(self):
        antes = _bitacora('auth.login_failed', extra="AND details->>'reason' = 'passkey'")
        bloqueadas = _bitacora('auth.login_failed', extra="AND details->>'detail' = 'locked'")
        for _ in range(5):
            self.assertEqual(_entrar(self.a, firma_mala=True)[1][0], 401)
        # Bloqueado el correo, ni la passkey buena entra, y el login con contraseña tampoco. La passkey responde el
        # mismo 401 que una que no existe: un 429 diría que la credencial es de un correo bloqueado (H8 de RC-331).
        self.assertEqual(_entrar(self.a)[1], (401, {'detail': PASSKEY_INVALID}))
        self.assertEqual(_entrar(Autenticador())[1], (401, {'detail': PASSKEY_INVALID}))
        self.assertEqual(sesion.post_login(Client(), JORDAN, PASSWORD)[0], 429)
        self.assertEqual(_bitacora('auth.login_failed', extra="AND details->>'reason' = 'passkey'"), antes + 6)
        self.assertEqual(_bitacora('auth.login_failed', extra="AND details->>'detail' = 'locked'"), bloqueadas + 1)

    def test_8b_una_passkey_que_no_existe_cuenta_para_la_ip(self):
        for _ in range(20):
            self.assertEqual(_entrar(Autenticador())[1][0], 401)
        self.assertEqual(Client().post(PK + '/login/options')[0], 429)
        self.assertEqual(sesion.post_login(Client(), JORDAN, PASSWORD)[0], 429)

    def test_8c_las_opciones_tienen_limite_por_ip_con_su_propio_mensaje(self):
        for _ in range(MAX_PASSKEY_OPTIONS_IP):
            self.assertEqual(Client().post(PK + '/login/options')[0], 200)
        self.assertEqual(Client().post(PK + '/login/options'), (429, {'detail': OPTIONS_LIMIT}))
        # Pasarse de opciones no es un fallo: el login con contraseña sigue igual.
        self.assertEqual(sesion.login(JORDAN).get(AUTH + '/me')[0], 200)

    def test_9_el_contador_debe_subir(self):
        b = Autenticador(sign_count=5)
        _alta_directa(b, name='Llave')
        self.assertEqual(_entrar(b, sign_count=5)[1], (401, {'detail': PASSKEY_INVALID}))
        sesion.reset()
        self.assertEqual(_entrar(b, sign_count=9)[1][0], 200)
        self.assertEqual(scalar("SELECT sign_count FROM webauthn_credentials WHERE name = 'Llave';", user='postgres'), '9')

    def test_9b_cuenta_inactiva_no_entra(self):
        scalar("UPDATE users SET is_active = false WHERE id = '%s' RETURNING 1;" % JORDAN_ID, user='postgres')
        try:
            self.assertEqual(_entrar(self.a)[1], (401, {'detail': PASSKEY_INVALID}))
        finally:
            scalar("UPDATE users SET is_active = true WHERE id = '%s' RETURNING 1;" % JORDAN_ID, user='postgres')

    def _con_la_fila_bloqueada(self, cambio, kw):
        """Como postgres, bloquea la fila de Jordan 3 s y luego aplica `cambio`, mientras la API ya buscó la passkey y
        espera ese bloqueo: así llega al FOR NO KEY UPDATE y al UPDATE del contador con la fila ya cambiada."""
        sql = ("BEGIN; SELECT 1 FROM users WHERE id = '%s' FOR UPDATE; SELECT pg_sleep(3); %s; COMMIT;"
               % (JORDAN_ID, cambio))
        exigir_desechable()
        bloqueo = subprocess.Popen(['docker', 'exec', '-i', CONTAINER, 'psql', '-U', 'postgres', '-d', 'cirdan', '-X',
                                    '-q', '-v', 'ON_ERROR_STOP=1'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, text=True)
        bloqueo.stdin.write(sql)
        bloqueo.stdin.close()
        # Espera a que psql ya tenga la fila bloqueada: su sesión está en pg_sleep (R5 de RC-331).
        limite = time.monotonic() + 10
        while scalar("SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%pg_sleep(3)%' "
                     "AND pid <> pg_backend_pid();", user='postgres') == '0':
            self.assertLess(time.monotonic(), limite, 'psql no tomó el bloqueo')
            time.sleep(0.05)
        try:
            return _entrar(self.a, **kw)[1]
        finally:
            self.assertEqual(bloqueo.wait(timeout=30), 0, bloqueo.stderr.read())

    def test_9b2_los_fallos_de_dentro_de_la_transaccion_dejan_bitacora(self):
        # H9 de RC-331: la cuenta se desactiva, o el contador cambia, entre passkey_lookup() y la entrada.
        casos = (('inactive', "UPDATE users SET is_active = false WHERE id = '%s'" % JORDAN_ID, 6),
                 ('sign_count_race', "UPDATE webauthn_credentials SET sign_count = 50 WHERE id = '%s'"
                  % self.passkey_id, 7))
        try:
            for motivo, cambio, contador in casos:
                with self.subTest(motivo):
                    sesion.reset()
                    scalar("UPDATE webauthn_credentials SET sign_count = 5 WHERE id = '%s' RETURNING 1;"
                           % self.passkey_id, user='postgres')
                    antes = _bitacora('auth.login_failed', extra="AND details->>'detail' = '%s'" % motivo)
                    self.assertEqual(self._con_la_fila_bloqueada(cambio, {'sign_count': contador}),
                                     (401, {'detail': PASSKEY_INVALID}))
                    self.assertEqual(_bitacora('auth.login_failed', extra="AND details->>'detail' = '%s'" % motivo),
                                     antes + 1)
                    scalar("UPDATE users SET is_active = true WHERE id = '%s' RETURNING 1;" % JORDAN_ID,
                           user='postgres')
        finally:
            scalar("UPDATE users SET is_active = true WHERE id = '%s' RETURNING 1;" % JORDAN_ID, user='postgres')

    def test_9c_con_passkey_sigue_entrando_con_contrasena_y_totp(self):
        client = sesion.login(JORDAN)
        self.assertEqual(client.get(AUTH + '/me')[0], 200)

    def test_9d_un_admin_sin_totp_no_entra_con_passkey(self):
        # RC-5: TOTP obligatorio para Admins. Una passkey registrada sin TOTP no lo salta: 403 sin sesión, sin fallo y
        # sin gastar el contador. Activarlo pide la contraseña, así que el 403 no trae token de alta.
        admin = Autenticador()
        passkey = _alta_directa(admin, user_id=ALEX_ID)
        fecha = scalar("SELECT coalesce(quote_literal(mfa_enabled_at), 'now()') FROM users WHERE id = '%s';" % ALEX_ID,
                       user='postgres')
        self.addCleanup(scalar, "UPDATE users SET mfa_enabled_at = %s WHERE id = '%s' RETURNING 1;" % (fecha, ALEX_ID),
                        user='postgres')
        scalar("UPDATE users SET mfa_enabled_at = NULL WHERE id = '%s' RETURNING 1;" % ALEX_ID, user='postgres')
        antes = _bitacora('auth.login_failed', ALEX_ID, "AND details->>'detail' = 'admin_mfa_required'")
        client, respuesta = _entrar(admin)
        self.assertEqual(respuesta, (403, {'detail': ADMIN_MFA_PASSWORD}))
        self.assertIsNone(client.cookie())
        self.assertEqual(scalar("SELECT sign_count = 0 AND last_used_at IS NULL FROM webauthn_credentials "
                                "WHERE id = '%s';" % passkey, user='postgres'), 't')
        self.assertEqual(_valkey('get login:fail:email:%s' % hashlib.sha256(ALEX.encode()).hexdigest()), '')
        limite = time.monotonic() + 5  # la bitácora se escribe después de responder
        while _bitacora('auth.login_failed', ALEX_ID, "AND details->>'detail' = 'admin_mfa_required'") == antes:
            self.assertLess(time.monotonic(), limite, 'falta auth.login_failed con admin_mfa_required')
            time.sleep(0.05)
        # Con el TOTP activo, la misma passkey entra.
        scalar("UPDATE users SET mfa_enabled_at = %s WHERE id = '%s' RETURNING 1;" % (fecha, ALEX_ID), user='postgres')
        self.assertEqual(_entrar(admin)[1][0], 200)


class Registrar(unittest.TestCase):
    """POST /passkeys/register/options y /register/verify, GET /passkeys y DELETE /passkeys/{id}."""

    @classmethod
    def setUpClass(cls):
        _limpiar_valkey()
        cls.client = sesion.login(JORDAN)

    def setUp(self):
        sesion.reset()
        self.addCleanup(_borrar_passkeys)

    def _opciones(self, client=None, code=None, password=PASSWORD):
        body = {'current_password': password}
        if code is not False:
            body['code'] = code or sesion.next_code(JORDAN)
        return (client or self.client).post(PK + '/register/options', body)

    def test_10_sin_sesion_no_hay_registro_ni_lista(self):
        self.assertEqual(Client().post(PK + '/register/options', {'current_password': PASSWORD})[0], 401)
        self.assertEqual(Client().post(PK + '/register/verify', {'credential': {}, 'name': 'x'})[0], 401)
        self.assertEqual(Client().get(PK)[0], 401)
        self.assertEqual(Client().request('DELETE', PK + '/' + str(uuid.uuid4()))[0], 401)

    def test_11_pide_contrasena_y_codigo_con_totp(self):
        self.assertEqual(self._opciones(code=False),
                         (400, {'detail': 'Escribe el código de 6 dígitos de tu app autenticadora.'}))
        self.assertEqual(self._opciones(password='otra-cosa')[0], 400)
        self.assertEqual(self._opciones(code=_malo(JORDAN)),
                         (400, {'detail': 'El código no es válido o ya expiró.'}))
        self.assertEqual(_bitacora('auth.passkey_registration_failed', extra="AND details->>'reason' = 'password'")
                         >= 1, True)

    def test_12_registra_lista_y_entra(self):
        code, body = self._opciones()
        self.assertEqual(code, 200, body)
        opciones = body['options']
        self.assertEqual(opciones['rp']['id'], 'localhost')
        self.assertEqual(opciones['user']['id'], b64url(uuid.UUID(JORDAN_ID).bytes))
        self.assertEqual(opciones['authenticatorSelection']['userVerification'], 'required')
        self.assertEqual(opciones['authenticatorSelection']['residentKey'], 'required')
        a = Autenticador()
        code, fila = self.client.post(PK + '/register/verify', {'credential': a.registro(opciones), 'name': ' Laptop '})
        self.assertEqual(code, 201, fila)
        self.assertEqual((fila['name'], fila['transports']), ('Laptop', ['hybrid', 'internal']))
        self.assertEqual(_bitacora('auth.passkey_registered', extra="AND entity_id = '%s'" % fila['id']), 1)
        code, lista = self.client.get(PK)
        self.assertEqual(code, 200)
        self.assertEqual([p['id'] for p in lista['passkeys']], [fila['id']])
        self.assertTrue(lista['available'])
        # El mismo reto no registra otra vez.
        self.assertEqual(self.client.post(PK + '/register/verify', {'credential': a.registro(opciones), 'name': 'x'}),
                         (400, {'detail': 'La solicitud venció o ya se usó. Empieza de nuevo.'}))
        sesion.reset()
        self.assertEqual(_entrar(a)[1][0], 200)

    def test_13_respuesta_mala_gasta_el_reto(self):
        opciones = self._opciones()[1]['options']
        a = Autenticador()
        for nombre, kw in (('sin verificación', {'flags': UP | AT}), ('otro origen', {'origin': 'https://evil.example'})):
            with self.subTest(nombre):
                self.assertEqual(self.client.post(PK + '/register/verify',
                                                  {'credential': a.registro(opciones, **kw), 'name': 'x'})[0], 400)
        self.assertEqual(scalar('SELECT count(*) FROM webauthn_credentials;', user='postgres'), '0')

    def test_14_el_reto_es_de_la_sesion_que_lo_pidio(self):
        otra = sesion.login(JORDAN)
        opciones = self._opciones(client=otra)[1]['options']
        self.assertEqual(self.client.post(PK + '/register/verify',
                                          {'credential': Autenticador().registro(opciones), 'name': 'x'})[0], 400)

    def test_14b_otra_sesion_no_borra_el_reto_de_esta(self):
        # H15 de RC-331: el reto va por cuenta y por sesión. Otra sesión de la cuenta, aun sin contraseña, no lo gasta.
        opciones = self._opciones()[1]['options']
        otra = sesion.login(JORDAN)
        for _ in range(3):
            self.assertEqual(otra.post(PK + '/register/verify', {'credential': {}, 'name': 'x'}),
                             (400, {'detail': 'La solicitud venció o ya se usó. Empieza de nuevo.'}))
        # Y su propio registro no reemplaza el de esta sesión.
        opciones_otra = self._opciones(client=otra)[1]['options']
        code, fila = self.client.post(PK + '/register/verify', {'credential': Autenticador().registro(opciones),
                                                               'name': 'Esta'})
        self.assertEqual(code, 201, fila)
        code, fila = otra.post(PK + '/register/verify', {'credential': Autenticador().registro(opciones_otra),
                                                         'name': 'Otra'})
        self.assertEqual(code, 201, fila)

    def test_14c_con_10_passkeys_no_se_gasta_el_codigo_ni_cuenta_fallo(self):
        # H7 de RC-331: el 409 sale antes de revisar el código.
        ids = [_alta_directa(Autenticador(), name='P%d' % n) for n in range(10)]
        codigo = sesion.next_code(JORDAN)
        for _ in range(6):  # con fallos contados, el sexto ya daría 429
            self.assertEqual(self._opciones(code=codigo), (409, {'detail': PASSKEY_LIMIT}))
        scalar("DELETE FROM webauthn_credentials WHERE id = '%s'; SELECT 1;" % ids[0], user='postgres')
        self.assertEqual(self._opciones(code=codigo)[0], 200, 'el mismo código sigue sin gastar')

    def test_15b_las_de_otra_persona_de_la_misma_empresa_no_se_ven_ni_se_borran_ni_cuentan(self):
        # H2 de RC-331: el filtro por user_id, no solo RLS. Maya es de Acme, como Jordan.
        ajenas = [_alta_directa(Autenticador(), user_id=MAYA_ID, name='De Maya %d' % n) for n in range(10)]
        self.assertEqual(self.client.request('DELETE', PK + '/' + ajenas[0])[0], 404)
        self.assertEqual(scalar("SELECT count(*) FROM webauthn_credentials WHERE user_id = '%s';" % MAYA_ID,
                                user='postgres'), '10')
        self.assertEqual(self.client.get(PK)[1]['passkeys'], [])
        code, body = self._opciones()
        self.assertEqual(code, 200, 'las 10 de Maya no cuentan para el límite de Jordan')
        self.assertEqual(body['options'].get('excludeCredentials', []), [])
        code, fila = self.client.post(PK + '/register/verify', {'credential': Autenticador().registro(body['options']),
                                                               'name': 'De Jordan'})
        self.assertEqual(code, 201, 'register/verify tampoco cuenta las de Maya: %s' % fila)

    def test_15_borrar_solo_las_propias(self):
        a = Autenticador()
        mia = _alta_directa(a)
        ajena = _alta_directa(Autenticador(), org=BETA, user_id=DANA_ID)
        self.assertEqual(self.client.request('DELETE', PK + '/' + ajena)[0], 404)
        self.assertEqual(scalar("SELECT count(*) FROM webauthn_credentials WHERE id = '%s';" % ajena, user='postgres'), '1')
        self.assertEqual(self.client.request('DELETE', PK + '/' + mia)[0], 204)
        self.assertEqual(_bitacora('auth.passkey_deleted', extra="AND entity_id = '%s'" % mia), 1)
        self.assertEqual(self.client.request('DELETE', PK + '/' + mia)[0], 404)
        sesion.reset()
        self.assertEqual(_entrar(a)[1], (401, {'detail': PASSKEY_INVALID}))

    def test_16_la_lista_no_trae_la_llave_ni_el_id_de_la_credencial(self):
        _alta_directa(Autenticador())
        _alta_directa(Autenticador(), org=BETA, user_id=DANA_ID)
        passkeys = self.client.get(PK)[1]['passkeys']
        self.assertEqual(len(passkeys), 1)
        self.assertEqual(sorted(passkeys[0]), ['backed_up', 'created_at', 'id', 'last_used_at', 'name', 'transports'])

    def test_17_cambiar_la_contrasena_borra_las_passkeys_y_el_registro_a_medias(self):
        # T1 de RC-331: una passkey dada de alta con la contraseña anterior no sigue entrando después del cambio.
        anterior = scalar("SELECT password_hash FROM users WHERE id = '%s';" % JORDAN_ID, user='postgres')
        self.addCleanup(scalar, "UPDATE users SET password_hash = '%s' WHERE id = '%s'; SELECT 1;"
                        % (anterior, JORDAN_ID), user='postgres')
        a = Autenticador()
        mia = _alta_directa(a)
        ajena = _alta_directa(Autenticador(), user_id=MAYA_ID)
        opciones = self._opciones()[1]['options']  # registro pedido con la contraseña anterior
        self.assertEqual(self.client.post(AUTH + '/password', {'current_password': 'otra-cosa',
                                                               'new_password': 'CIRDAN_FAKE_clave-331-b'})[0], 400)
        self.assertEqual(scalar("SELECT count(*) FROM webauthn_credentials WHERE id = '%s';" % mia, user='postgres'),
                         '1', 'con la contraseña actual mal no se borra nada')
        self.assertEqual(self.client.post(AUTH + '/password', {'current_password': PASSWORD,
                                                               'new_password': 'CIRDAN_FAKE_clave-331-a'}),
                         (200, {'passkeys_removed': 1}))
        self.assertEqual(scalar("SELECT count(*) FROM webauthn_credentials WHERE user_id = '%s';" % JORDAN_ID,
                                user='postgres'), '0')
        self.assertEqual(scalar("SELECT count(*) FROM webauthn_credentials WHERE id = '%s';" % ajena, user='postgres'),
                         '1', 'las de Maya, de la misma empresa, no se tocan')
        self.assertEqual(_bitacora('auth.passkey_deleted', extra="AND entity_id = '%s' AND details = "
                                   "'{\"reason\": \"password_changed\"}'::jsonb" % mia), 1)
        # El registro que se pidió antes del cambio ya no guarda su passkey.
        self.assertEqual(self.client.post(PK + '/register/verify', {'credential': Autenticador().registro(opciones),
                                                                    'name': 'Tras el cambio'}),
                         (400, {'detail': 'La solicitud venció o ya se usó. Empieza de nuevo.'}))
        self.assertEqual(scalar("SELECT count(*) FROM webauthn_credentials WHERE user_id = '%s';" % JORDAN_ID,
                                user='postgres'), '0')
        sesion.reset()
        self.assertEqual(_entrar(a)[1], (401, {'detail': PASSKEY_INVALID}))
        # Sin passkeys, el cambio responde 0.
        self.assertEqual(self.client.post(AUTH + '/password', {'current_password': 'CIRDAN_FAKE_clave-331-a',
                                                               'new_password': 'CIRDAN_FAKE_clave-331-c'}),
                         (200, {'passkeys_removed': 0}))

    def test_17b_en_paralelo_no_se_revisan_mas_de_5_contrasenas(self):
        # R3-1 de RC-331: el intento se cuenta antes de revisar la contraseña, con el contador de /password (RC-290).
        # Contado después, las 12 pasaban con el contador en 0 y se revisaban todas.
        antes = _bitacora('auth.passkey_registration_failed', extra="AND details->>'reason' = 'password'")
        codigos = []
        hilos = [threading.Thread(target=lambda n=n: codigos.append(
            self._opciones(code=False, password='CIRDAN_FAKE_mala-%d' % n)[0])) for n in range(12)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join()
        self.assertEqual(sorted(codigos), [400] * 5 + [429] * 7)
        self.assertEqual(_bitacora('auth.passkey_registration_failed', extra="AND details->>'reason' = 'password'")
                         - antes, 5)
        # El contador es el de /password: tampoco deja probar ahí.
        self.assertEqual(self.client.post(AUTH + '/password', {'current_password': PASSWORD,
                                                               'new_password': 'CIRDAN_FAKE_clave-331-d'})[0], 429)

    def test_18_la_bitacora_no_guarda_el_nombre_de_la_passkey(self):
        # T4 de RC-331: el nombre es texto libre y audit_log no se puede borrar ni anonimizar.
        opciones = self._opciones()[1]['options']
        code, fila = self.client.post(PK + '/register/verify', {'credential': Autenticador().registro(opciones),
                                                               'name': 'Pixel de Ana López'})
        self.assertEqual(code, 201, fila)
        self.assertEqual(self.client.request('DELETE', PK + '/' + fila['id'])[0], 204)
        detalles = scalar("SELECT string_agg(action || ' ' || details::text, ' | ' ORDER BY chain_seq) FROM audit_log "
                          "WHERE entity_id = '%s';" % fila['id'], user='postgres')
        self.assertEqual(detalles, 'auth.passkey_registered {"backed_up": false} | '
                                   'auth.passkey_deleted {"reason": "user"}')


if __name__ == '__main__':
    unittest.main()
