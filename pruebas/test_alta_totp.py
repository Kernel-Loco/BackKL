"""Pruebas del alta de TOTP del perfil (RC-154) contra la API local (biblioteca estándar).

    python -m unittest -v pruebas/test_alta_totp.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)

Usan a maya.reed@acme-demo.mx sin MFA durante la prueba y al final le devuelven su secreto, su fecha y su paso.
"""
import base64
import os
import subprocess
import time
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from pruebas import sesion
from pruebas.sesion import AUTH, PASSWORD, Client
from pruebas.test_aislamiento import scalar

MAYA = 'maya.reed@acme-demo.mx'
# El mismo contenedor que usa sesion.reset(): el del compose aislado cuando las pruebas corren ahí.
VALKEY = os.environ.get('CIRDAN_TEST_VALKEY', 'cirdan-valkey')
MFA_INVALID = 'El código no es válido o ya expiró.'
MFA_ALREADY = 'La verificación en dos pasos ya está activa en tu cuenta.'
MFA_SETUP_EXPIRED = 'El código QR venció o ya se usaron sus 5 intentos. Empieza de nuevo.'


def _db(campo):
    return scalar("SELECT coalesce(%s::text, 'nulo') FROM users WHERE email = '%s';" % (campo, MAYA), user='postgres')


def _bitacora(accion):
    return int(scalar("SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = '%s' "
                      "AND a.action = '%s';" % (MAYA, accion), user='postgres'))


def _sin_alta_pendiente():
    """Borra el QR pendiente que haya dejado otra prueba: cada prueba empieza sin alta en curso."""
    subprocess.run(['docker', 'exec', VALKEY, 'sh', '-c',
                    'valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning --scan --pattern "mfa:setup:*" '
                    '| xargs -r valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning del'], check=True, capture_output=True)


def _codigo(secreto, delta=0):
    return sesion.totp(secreto, int(time.time() // sesion.STEP) + delta)


def _malos(secreto, n):
    paso = int(time.time() // sesion.STEP)
    validos = {sesion.totp(secreto, s) for s in range(paso - 2, paso + 3)}
    return [c for c in ('%06d' % i for i in range(n + len(validos))) if c not in validos][:n]


class AltaTotp(unittest.TestCase):

    def setUp(self):
        sesion.reset()
        _sin_alta_pendiente()
        self.addCleanup(_sin_alta_pendiente)
        antes = scalar("SELECT coalesce(quote_literal(totp_secret_enc::text), 'NULL') || '|' || "
                       "coalesce(quote_literal(mfa_enabled_at), 'now()') FROM users WHERE email = '%s';" % MAYA,
                       user='postgres')
        secreto, fecha = antes.split('|')
        self.addCleanup(scalar, "UPDATE users SET totp_secret_enc = %s, mfa_enabled_at = %s, last_totp_step = NULL "
                                "WHERE email = '%s' RETURNING 1;" % (secreto, fecha, MAYA), user='postgres')
        self.addCleanup(sesion.reset)
        scalar("UPDATE users SET totp_secret_enc = NULL, mfa_enabled_at = NULL, last_totp_step = NULL "
               "WHERE email = '%s' RETURNING 1;" % MAYA, user='postgres')
        self.client = Client()
        code, body = sesion.post_login(self.client, MAYA, PASSWORD)
        self.assertEqual((code, body['mfa_required']), (200, False), body)

    def _setup(self, client=None):
        code, body = (client or self.client).post(AUTH + '/mfa/setup', {'current_password': PASSWORD})
        self.assertEqual(code, 200, body)
        return body

    def test_1_sin_sesion_no_hay_alta(self):
        self.assertEqual(Client().post(AUTH + '/mfa/setup', {'current_password': PASSWORD})[0], 401)
        self.assertEqual(Client().post(AUTH + '/mfa/enable', {'code': '123456'})[0], 401)

    def test_2_el_qr_trae_el_secreto_y_no_se_guarda_antes_del_codigo(self):
        antes = _bitacora('auth.mfa_setup_started')
        body = self._setup()
        uri = urlsplit(body['otpauth_uri'])
        self.assertEqual((uri.scheme, uri.netloc), ('otpauth', 'totp'))
        self.assertEqual(unquote(uri.path), '/LowTide:' + MAYA)
        query = parse_qs(uri.query)
        self.assertEqual(query['secret'], [body['secret']])
        self.assertEqual(query['issuer'], ['LowTide'])
        self.assertEqual(len(base64.b32decode(body['secret'])), 20, '160 bits')
        self.assertTrue(body['qr_svg'].startswith('data:image/svg+xml'))
        self.assertEqual(body['expires_in_seconds'], 600)
        self.assertEqual((_db('totp_secret_enc'), _db('mfa_enabled_at')), ('nulo', 'nulo'),
                         'sin un código válido la base no guarda nada')
        self.assertEqual(_bitacora('auth.mfa_setup_started'), antes + 1)
        self.assertFalse(self.client.get(AUTH + '/me')[1]['mfa_enabled'])

    def test_3_la_contrasena_mala_no_da_qr(self):
        antes = _bitacora('auth.mfa_setup_failed')
        code, body = self.client.post(AUTH + '/mfa/setup', {'current_password': 'no-es-la-contrasena'})
        self.assertEqual((code, body['detail']), (400, 'La contraseña actual no es correcta.'))
        self.assertNotIn('secret', body)
        self.assertEqual(_bitacora('auth.mfa_setup_failed'), antes + 1)
        code, body = self.client.post(AUTH + '/mfa/enable', {'code': '123456'})
        self.assertEqual((code, body['detail']), (400, MFA_SETUP_EXPIRED))

    def test_4_un_codigo_malo_no_activa(self):
        body = self._setup()
        antes = _bitacora('auth.mfa_enable_failed')
        code, resp = self.client.post(AUTH + '/mfa/enable', {'code': _malos(body['secret'], 1)[0]})
        self.assertEqual((code, resp['detail']), (400, MFA_INVALID))
        self.assertEqual((_db('totp_secret_enc'), _db('mfa_enabled_at')), ('nulo', 'nulo'))
        self.assertEqual(_bitacora('auth.mfa_enable_failed'), antes + 1)

    def test_5_el_codigo_valido_activa_y_el_login_lo_pide(self):
        body = self._setup()
        antes = _bitacora('auth.mfa_enabled')
        codigo = _codigo(body['secret'])
        code, resp = self.client.post(AUTH + '/mfa/enable', {'code': codigo})
        self.assertEqual((code, resp), (200, {'mfa_enabled': True}))
        self.assertNotEqual(_db('totp_secret_enc'), 'nulo')
        self.assertNotIn(body['secret'].encode().hex(), _db('totp_secret_enc'), 'se guarda cifrado')
        self.assertEqual(_bitacora('auth.mfa_enabled'), antes + 1)
        self.assertTrue(self.client.get(AUTH + '/me')[1]['mfa_enabled'])
        # Otro QR ya no se puede pedir con la cuenta activa.
        code, resp = self.client.post(AUTH + '/mfa/setup', {'current_password': PASSWORD})
        self.assertEqual((code, resp['detail']), (409, MFA_ALREADY))
        # El login ya pide el código, y el que activó la cuenta no sirve dos veces.
        otro = Client()
        code, resp = sesion.post_login(otro, MAYA, PASSWORD)
        self.assertEqual((code, resp['mfa_required']), (200, True))
        self.assertIsNone(otro.cookie())
        code, _ = otro.post(AUTH + '/mfa/verify', {'mfa_token': resp['mfa_token'], 'code': codigo})
        self.assertEqual(code, 401, 'el código del alta ya se usó')
        code, resp = sesion.post_login(otro, MAYA, PASSWORD)
        code, _ = otro.post(AUTH + '/mfa/verify', {'mfa_token': resp['mfa_token'], 'code': _codigo(body['secret'], 1)})
        self.assertEqual(code, 200, 'el siguiente código sí entra')

    def test_6_cinco_codigos_malos_gastan_el_qr(self):
        body = self._setup()
        for malo in _malos(body['secret'], 5):
            self.assertEqual(self.client.post(AUTH + '/mfa/enable', {'code': malo})[0], 400)
        code, resp = self.client.post(AUTH + '/mfa/enable', {'code': _codigo(body['secret'])})
        self.assertEqual((code, resp['detail']), (400, MFA_SETUP_EXPIRED), 'ni el código bueno pasa después de 5')
        self.assertEqual(_db('totp_secret_enc'), 'nulo')

    def test_7_un_qr_nuevo_reemplaza_al_anterior(self):
        viejo = self._setup()
        nuevo = self._setup()
        self.assertNotEqual(viejo['secret'], nuevo['secret'])
        self.assertEqual(self.client.post(AUTH + '/mfa/enable', {'code': _codigo(viejo['secret'])})[0], 400)
        self.assertEqual(self.client.post(AUTH + '/mfa/enable', {'code': _codigo(nuevo['secret'])})[0], 200)

    def test_9_en_valkey_el_secreto_pendiente_va_cifrado(self):
        body = self._setup()
        valores = subprocess.run(
            ['docker', 'exec', VALKEY, 'sh', '-c',
             'for k in $(valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning --scan --pattern "mfa:setup:*"); do '
             'valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning ttl "$k"; '
             'valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning get "$k"; done'],
            check=True, capture_output=True, text=True).stdout
        self.assertIn('secret_enc', valores)
        self.assertNotIn(body['secret'], valores)
        ttl = int(valores.split()[0])
        self.assertTrue(0 < ttl <= 600, ttl)

    def test_8_el_formato_del_codigo_se_revisa(self):
        self._setup()
        for malo in ('12345', '1234567', 'abcdef', ''):
            with self.subTest(codigo=malo):
                self.assertEqual(self.client.post(AUTH + '/mfa/enable', {'code': malo})[0], 422)


if __name__ == '__main__':
    unittest.main()
