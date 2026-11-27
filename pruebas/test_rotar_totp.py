"""Pruebas de la rotación de la llave del MFA (RC-295), sin red ni base.

Cubren el Hecho cuando de RC-295: la llave anterior opcional en una sola de sus dos formas, que se prueba después de la
actual; un secreto cifrado con la anterior que entra con un código bueno y queda cifrado con la actual en el mismo
UPDATE que gasta el código (en /mfa/verify y al registrar una passkey); y un secreto que no abre con ninguna llave, que
da 401 con 'Habla con el Admin.' (400 en la passkey), cuenta como fallo y deja su evento, nunca 500. También el QR
pendiente cifrado con una llave que ya no está y el comando `python -m cirdan.auth.contar_totp`. Valkey, la base, la
bitácora y Key Vault son falsos. Corren dentro del contenedor, porque cirdan.auth.routes importa fastapi y psycopg:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_rotar_totp.py
"""
import base64
import contextlib
import io
import json
import os
import re
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, Response

from cirdan.auth import contar_totp, keyvault, restablecer_mfa, routes, sessions, totp

# Los tokens falsos viven en pruebas/fixtures/ (AGENTS regla 7): el job de seguridad marca uno fuera de ahí.
FALSOS = json.loads((Path(__file__).resolve().parent / 'fixtures' / 'tokens' / 'rotar_totp.json').read_text('utf-8'))
ACTUAL = base64.urlsafe_b64encode(FALSOS['llave_actual'].encode()).decode()
ANTERIOR = base64.urlsafe_b64encode(FALSOS['llave_anterior'].encode()).decode()
OTRA = base64.urlsafe_b64encode(FALSOS['llave_otra'].encode()).decode()
assert all(len(base64.urlsafe_b64decode(v)) == 32 for v in (ACTUAL, ANTERIOR, OTRA))
VERSION = '0123456789abcdef0123456789abcdef'
URL = 'https://kv-lowtide.vault.azure.net/secrets/totp-encryption-key-v2/' + VERSION
URL_ANTERIOR = 'https://kv-lowtide.vault.azure.net/secrets/totp-encryption-key/' + VERSION
SECRETO = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
USUARIO = '30000000-0000-4000-8000-000000000001'
ORG = '20000000-0000-4000-8000-000000000001'
VARIABLES = ('TOTP_ENCRYPTION_KEY', 'TOTP_KEY_VAULT_SECRET_URL', 'TOTP_PREVIOUS_ENCRYPTION_KEY',
             'TOTP_PREVIOUS_KEY_VAULT_SECRET_URL')


def cifrar_con(llave, secreto=SECRETO, user_id=USUARIO):
    """El secreto con la forma que guarda la API (nonce, cifrado y tag, el id como dato asociado), pero con `llave`."""
    nonce = os.urandom(12)
    return nonce + AESGCM(base64.urlsafe_b64decode(llave)).encrypt(nonce, secreto.encode(), user_id.encode())


class Base(unittest.TestCase):
    def setUp(self):
        for nombre in ('_llave_vault', '_llave_vault_anterior'):
            setattr(totp, nombre, None)
            self.addCleanup(setattr, totp, nombre, None)
        p = mock.patch('cirdan.config._env_file', return_value={})
        p.start()
        self.addCleanup(p.stop)
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL)

    def env(self, **valores):
        limpio = {k: v for k, v in os.environ.items() if k not in VARIABLES}
        limpio.update(valores)
        p = mock.patch.dict(os.environ, limpio, clear=True)
        p.start()
        self.addCleanup(p.stop)


class Descifrar(Base):
    def test_1_con_la_actual_abre_sin_marca(self):
        self.assertEqual(totp.descifrar(cifrar_con(ACTUAL), USUARIO), (SECRETO, False))

    def test_2_con_la_anterior_puesta_abre_y_dice_que_fue_la_anterior(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR)
        self.assertEqual(totp.descifrar(cifrar_con(ANTERIOR), USUARIO), (SECRETO, True))
        # La actual se sigue probando primero.
        self.assertEqual(totp.descifrar(cifrar_con(ACTUAL), USUARIO), (SECRETO, False))

    def test_3_sin_la_anterior_o_con_otra_llave_da_llave_no_abre_y_nunca_invalid_tag(self):
        for env in ({'TOTP_ENCRYPTION_KEY': ACTUAL},
                    {'TOTP_ENCRYPTION_KEY': ACTUAL, 'TOTP_PREVIOUS_ENCRYPTION_KEY': OTRA}):
            with self.subTest(env=sorted(env)):
                self.env(**env)
                with self.assertRaises(totp.LlaveNoAbre):
                    totp.descifrar(cifrar_con(ANTERIOR), USUARIO)
                with self.assertRaises(totp.LlaveNoAbre):
                    totp.decrypt_secret(cifrar_con(ANTERIOR), USUARIO)

    def test_4_datos_danados_o_de_otro_usuario_dan_llave_no_abre(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR)
        bueno = cifrar_con(ACTUAL)
        for blob in (b'', b'corto', bueno[:20], bueno[:-1] + bytes([bueno[-1] ^ 1]), 'no es base64 !!', '\\xzz',
                     memoryview(bueno[:27])):
            with self.subTest(blob=repr(blob)[:30]):
                with self.assertRaises(totp.LlaveNoAbre):
                    totp.descifrar(blob, USUARIO)
        with self.assertRaises(totp.LlaveNoAbre):
            totp.descifrar(bueno, '30000000-0000-4000-8000-000000000002')

    def test_5_lee_las_formas_guardadas_bytea_memoryview_hex_y_base64(self):
        blob = cifrar_con(ACTUAL)
        for forma in (blob, memoryview(blob), '\\x' + blob.hex(), base64.b64encode(blob).decode()):
            with self.subTest(tipo=type(forma).__name__):
                self.assertEqual(totp.decrypt_secret(forma, USUARIO), SECRETO)

    def test_6_cifra_siempre_con_la_actual(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR)
        nuevo = totp.encrypt_secret(SECRETO, USUARIO)
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL)
        self.assertEqual(totp.descifrar(nuevo, USUARIO), (SECRETO, False))


class Variables(Base):
    def test_1_las_dos_formas_de_la_anterior_no_arranca(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR,
                 TOTP_PREVIOUS_KEY_VAULT_SECRET_URL=URL_ANTERIOR)
        for revisar in (totp.revisar_variables, totp.comprobar_llave):
            with self.assertRaisesRegex(RuntimeError, 'TOTP_PREVIOUS_KEY_VAULT_SECRET_URL y TOTP_PREVIOUS_ENCRYPTION_KEY'):
                revisar()

    def test_2_la_anterior_igual_a_la_actual_no_arranca(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ACTUAL)
        with self.assertRaisesRegex(RuntimeError, 'misma llave'):
            totp.revisar_variables()
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL, TOTP_PREVIOUS_KEY_VAULT_SECRET_URL=URL.upper().replace('HTTPS', 'https'))
        with self.assertRaisesRegex(RuntimeError, 'misma URL'):
            totp.revisar_variables()

    def test_3_la_anterior_mal_formada_no_arranca_sin_mostrar_su_valor(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY='CIRDAN_FAKE_corta')
        with self.assertRaises(RuntimeError) as e:
            totp.revisar_variables()
        self.assertIn('TOTP_PREVIOUS_ENCRYPTION_KEY debe ser de 32 bytes', str(e.exception))
        self.assertNotIn('CIRDAN_FAKE_corta', str(e.exception))

    def test_4_misma_llave_aunque_una_venga_de_key_vault_no_arranca(self):
        # La actual en Key Vault y la anterior directa con el mismo valor, y al revés.
        for env, valor in (({'TOTP_KEY_VAULT_SECRET_URL': URL, 'TOTP_PREVIOUS_ENCRYPTION_KEY': ACTUAL}, ACTUAL),
                           ({'TOTP_ENCRYPTION_KEY': ACTUAL, 'TOTP_PREVIOUS_KEY_VAULT_SECRET_URL': URL_ANTERIOR}, ACTUAL)):
            with self.subTest(env=sorted(env)):
                totp._llave_vault = totp._llave_vault_anterior = None
                self.env(**env)
                with mock.patch.object(keyvault, 'leer_secreto', lambda url, variable: valor):
                    totp.revisar_variables()  # sin red no se puede saber
                    with self.assertRaisesRegex(RuntimeError, 'da la misma llave que la actual'):
                        totp.comprobar_llave()

    def test_5_con_key_vault_lee_cada_una_una_vez_y_la_anterior_abre(self):
        self.env(TOTP_KEY_VAULT_SECRET_URL=URL, TOTP_PREVIOUS_KEY_VAULT_SECRET_URL=URL_ANTERIOR)
        leidas = []

        def leer(url, variable):
            leidas.append((url, variable))
            return {URL: ACTUAL, URL_ANTERIOR: ANTERIOR}[url]

        with mock.patch.object(keyvault, 'leer_secreto', leer):
            totp.comprobar_llave()
            self.assertEqual(totp.descifrar(cifrar_con(ANTERIOR), USUARIO), (SECRETO, True))
            self.assertEqual(totp.descifrar(cifrar_con(ACTUAL), USUARIO), (SECRETO, False))
        self.assertEqual(leidas, [(URL, 'TOTP_KEY_VAULT_SECRET_URL'),
                                  (URL_ANTERIOR, 'TOTP_PREVIOUS_KEY_VAULT_SECRET_URL')])

    def test_6_sin_anterior_y_vacia_cuentan_igual(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY='', TOTP_PREVIOUS_KEY_VAULT_SECRET_URL='')
        totp.revisar_variables()
        self.assertEqual(base64.urlsafe_b64encode(totp.comprobar_llave()).decode(), ACTUAL)
        self.assertIsNone(totp._llave_anterior())


class Conexion:
    """Base falsa: la fila del usuario y cada UPDATE de users que llega, con su rowcount."""

    def __init__(self, fila, guarda=True):
        self.fila, self.guarda, self.updates = fila, guarda, []

    def execute(self, sql, params=()):
        if sql.lstrip().startswith('UPDATE users SET last_totp_step'):
            self.updates.append((sql, params))
            return SimpleNamespace(rowcount=1 if self.guarda else 0)
        if sql.lstrip().startswith('UPDATE'):
            return SimpleNamespace(rowcount=1)
        return SimpleNamespace(fetchone=lambda: self.fila, fetchall=lambda: [])


class Rutas(Base):
    IP = '203.0.113.7'

    def setUp(self):
        super().setUp()
        self.eventos, self.fallos_ip = [], []
        self.conexion = None

        @contextlib.contextmanager
        def transaccion(org=None):
            yield self.conexion

        def auditar(conn, org, accion, *args, **kw):
            detalles = args[4] if len(args) > 4 else kw.get('details')
            self.eventos.append((accion, detalles))

        for parche in (mock.patch.object(routes, 'transaction', transaccion),
                       mock.patch.object(routes, 'audit', auditar),
                       mock.patch.object(routes, 'client_ip', lambda _: self.IP),
                       mock.patch.object(routes, '_clear_fails', lambda _: None),
                       mock.patch.object(sessions, 'register_mfa_fail', self.fallos_ip.append),
                       mock.patch.object(sessions, 'take_mfa_attempt', lambda *_: True),
                       mock.patch.object(sessions, 'delete_mfa', lambda _: None),
                       mock.patch.object(sessions, 'password_tag', lambda h: 'marca'),
                       mock.patch.object(routes, '_start_session',
                                         lambda response, conn, user, ip, via, anterior=None: {'email': user['email'], 'via': via})):
            parche.start()
            self.addCleanup(parche.stop)

    def fila(self, blob, **extra):
        fila = {'email': 'mfa@ejemplo.test', 'role': 'admin', 'password_hash': 'h', 'totp_secret_enc': blob,
                'last_totp_step': None, 'full_name': 'Cuenta MFA', 'mfa_enabled': True}
        fila.update(extra)
        return fila

    @staticmethod
    def codigo(paso=0):
        return pyotp.TOTP(SECRETO, interval=totp.STEP_SECONDS).at(time.time() + paso * totp.STEP_SECONDS)

    def verificar(self, blob, codigo=None, guarda=True):
        self.conexion = Conexion(self.fila(blob), guarda)
        pendiente = {'user_id': USUARIO, 'org_id': ORG, 'email': 'mfa@ejemplo.test', 'tag': 'marca'}
        with mock.patch.object(sessions, 'take_mfa', lambda _: dict(pendiente)):
            return routes.verify_mfa(routes.MfaIn(mfa_token='t' * 20, code=codigo or self.codigo()),
                                     SimpleNamespace(cookies={}), Response())

    def guardado(self):
        """El secreto que dejó el UPDATE, o None si el UPDATE no lo tocó."""
        (sql, params), = self.conexion.updates
        if 'totp_secret_enc' not in sql:
            return None
        return params[1]

    # --- /mfa/verify

    def test_1_secreto_con_la_anterior_entra_y_queda_con_la_actual(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR)
        salida = self.verificar(cifrar_con(ANTERIOR))
        self.assertEqual(salida['user'], {'email': 'mfa@ejemplo.test', 'via': 'totp'})
        nuevo = self.guardado()
        self.assertIsNotNone(nuevo)
        # Ya abre sin la anterior: quedó con la actual, en el mismo UPDATE que gastó el código.
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL)
        self.assertEqual(totp.descifrar(nuevo, USUARIO), (SECRETO, False))
        sql, params = self.conexion.updates[0]
        self.assertRegex(sql, r'last_totp_step IS NULL OR last_totp_step < %s')
        self.assertEqual((params[0], params[2], params[3]), (params[3], USUARIO, params[0]))
        self.assertEqual(self.eventos, [])
        self.assertEqual(self.fallos_ip, [])

    def test_2_con_la_actual_no_vuelve_a_cifrar(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR)
        self.verificar(cifrar_con(ACTUAL))
        self.assertIsNone(self.guardado())

    def test_3_llave_desconocida_da_401_cuenta_fallo_deja_evento_y_no_500(self):
        for env in ({'TOTP_ENCRYPTION_KEY': ACTUAL},
                    {'TOTP_ENCRYPTION_KEY': ACTUAL, 'TOTP_PREVIOUS_ENCRYPTION_KEY': ANTERIOR}):
            with self.subTest(env=sorted(env)):
                self.env(**env)
                self.eventos.clear()
                self.fallos_ip.clear()
                with self.assertRaises(HTTPException) as e:
                    self.verificar(cifrar_con(OTRA))
                self.assertEqual(e.exception.status_code, 401)
                self.assertEqual(e.exception.detail, routes.MFA_KEY_UNAVAILABLE)
                self.assertIn('Habla con el Admin', e.exception.detail)
                self.assertEqual(self.eventos, [('auth.mfa_failed', {'reason': 'key'})])
                self.assertEqual(self.fallos_ip, [self.IP])
                self.assertEqual(self.conexion.updates, [])

    def test_4_codigo_malo_con_la_anterior_no_vuelve_a_cifrar(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR)
        malo = '000000' if self.codigo() != '000000' else '111111'
        with self.assertRaises(HTTPException) as e:
            self.verificar(cifrar_con(ANTERIOR), codigo=malo)
        self.assertEqual((e.exception.status_code, e.exception.detail), (401, routes.MFA_INVALID))
        self.assertEqual(self.conexion.updates, [])
        self.assertEqual(self.eventos, [('auth.mfa_failed', None)])

    def test_5_codigo_ya_usado_por_otra_peticion_no_entra(self):
        # El UPDATE no cambia nada (otra petición gastó el paso): no entra y el secreto no se tocó en la base.
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR)
        with self.assertRaises(HTTPException) as e:
            self.verificar(cifrar_con(ANTERIOR), guarda=False)
        self.assertEqual((e.exception.status_code, e.exception.detail), (401, routes.MFA_INVALID))

    # --- registrar una passkey con el código

    def registrar_passkey(self, blob):
        self.conexion = Conexion(self.fila(blob))
        sesion = SimpleNamespace(user_id=USUARIO, own_org_id=ORG, email='mfa@ejemplo.test',
                                 token=FALSOS['token_sesion'])
        with mock.patch.object(routes.webauthn, 'configured', lambda: True), \
                mock.patch.object(sessions, 'is_locked', lambda *_: False), \
                mock.patch.object(sessions, 'take_password_attempt', lambda _: 1), \
                mock.patch.object(routes, '_clear_password_attempts', lambda _: None), \
                mock.patch.object(routes.passwords, 'verify_password', lambda *_: True), \
                mock.patch.object(routes.webauthn, 'registration_options', lambda *_: ({'o': 1}, 'reto')), \
                mock.patch.object(sessions, 'create_passkey_registration', lambda *_: None):
            return routes.passkey_register_options(
                routes.PasskeyRegisterOptionsIn(current_password='CIRDAN_FAKE_clave', code=self.codigo()), None,
                Response(), sesion)

    def test_6_passkey_con_la_anterior_registra_y_queda_con_la_actual(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR)
        self.assertEqual(self.registrar_passkey(cifrar_con(ANTERIOR))['options'], {'o': 1})
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL)
        self.assertEqual(totp.descifrar(self.guardado(), USUARIO), (SECRETO, False))

    def test_7_passkey_con_llave_desconocida_da_400_cuenta_fallo_y_deja_evento(self):
        with self.assertRaises(HTTPException) as e:
            self.registrar_passkey(cifrar_con(OTRA))
        # 400 y no 401: el portal toma un 401 como sesión cerrada.
        self.assertEqual((e.exception.status_code, e.exception.detail), (400, routes.MFA_KEY_UNAVAILABLE))
        self.assertEqual(self.eventos, [('auth.passkey_registration_failed', {'reason': 'key'})])
        self.assertEqual(self.fallos_ip, [self.IP])
        self.assertEqual(self.conexion.updates, [])

    # --- QR pendiente cifrado con una llave que ya no está

    def test_8_qr_pendiente_de_otra_llave_pide_otro_sin_500(self):
        pendiente = base64.b64encode(cifrar_con(OTRA)).decode()
        self.conexion = Conexion(self.fila(None))
        borrados = []
        sesion = SimpleNamespace(user_id=USUARIO, own_org_id=ORG, email='mfa@ejemplo.test', token='t')
        with mock.patch.object(sessions, 'take_mfa_setup', lambda _: {'secret_enc': pendiente}), \
                mock.patch.object(sessions, 'delete_mfa_setup', borrados.append):
            with self.assertRaises(HTTPException) as e:
                routes.mfa_enable(routes.MfaEnableIn(code=self.codigo()), None, sesion)
        self.assertEqual((e.exception.status_code, e.exception.detail), (400, routes.MFA_SETUP_EXPIRED))
        self.assertEqual(borrados, [USUARIO])
        self.assertEqual(self.eventos, [('auth.mfa_enable_failed', {'reason': 'key'})])
        self.assertEqual(self.fallos_ip, [self.IP])

        self.eventos.clear()
        self.fallos_ip.clear()
        pend = {'user_id': USUARIO, 'org_id': ORG, 'email': 'mfa@ejemplo.test', 'tag': 'marca', 'secret_enc': pendiente}
        with mock.patch.object(sessions, 'take_mfa_enroll', lambda _: dict(pend)):
            with self.assertRaises(HTTPException) as e:
                routes.mfa_enroll_enable(routes.MfaEnrollEnableIn(mfa_setup_token='t' * 20, code=self.codigo()), None,
                                         Response())
        self.assertEqual((e.exception.status_code, e.exception.detail), (401, routes.MFA_SETUP_EXPIRED))
        self.assertEqual(self.eventos, [('auth.mfa_enable_failed', {'via': 'login', 'reason': 'key'})])
        self.assertEqual(self.fallos_ip, [self.IP])

    def test_9_qr_pendiente_de_la_anterior_se_activa_con_la_actual(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR)
        pendiente = base64.b64encode(cifrar_con(ANTERIOR)).decode()
        guardados = []

        class ConAlta(Conexion):
            def execute(self, sql, params=()):
                if sql.startswith('UPDATE users SET totp_secret_enc'):
                    guardados.append(params[0])
                    return SimpleNamespace(rowcount=1)
                return super().execute(sql, params)

        self.conexion = ConAlta({'mfa_enabled': False})
        sesion = SimpleNamespace(user_id=USUARIO, own_org_id=ORG, email='mfa@ejemplo.test', token='t')
        with mock.patch.object(sessions, 'take_mfa_setup', lambda _: {'secret_enc': pendiente}), \
                mock.patch.object(sessions, 'delete_mfa_setup', lambda _: None), \
                mock.patch.object(sessions, 'delete_others', lambda *_: None), \
                mock.patch.object(routes, '_delete_passkeys', lambda *_: []):
            self.assertEqual(routes.mfa_enable(routes.MfaEnableIn(code=self.codigo()), None, sesion)['mfa_enabled'],
                             True)
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL)
        self.assertEqual(totp.descifrar(guardados[0], USUARIO), (SECRETO, False))


class ContarTotp(Base):
    ORG_B = '20000000-0000-4000-8000-000000000002'

    def setUp(self):
        super().setUp()
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR)
        otro = '30000000-0000-4000-8000-000000000009'
        inactiva = '30000000-0000-4000-8000-00000000000a'
        self.filas = {
            ORG: [{'id': USUARIO, 'totp_secret_enc': cifrar_con(ACTUAL), 'puede_entrar': True},
                  {'id': otro, 'totp_secret_enc': cifrar_con(ANTERIOR, user_id=otro), 'puede_entrar': True}],
            self.ORG_B: [{'id': USUARIO, 'totp_secret_enc': cifrar_con(OTRA), 'puede_entrar': True},
                         {'id': otro, 'totp_secret_enc': cifrar_con(ANTERIOR, user_id=otro), 'puede_entrar': True},
                         # Inactiva o de una empresa suspendida: nunca vuelve a cifrar y va aparte (hallazgos 2 y 7).
                         {'id': inactiva, 'totp_secret_enc': cifrar_con(ANTERIOR, user_id=inactiva),
                          'puede_entrar': False}],
        }
        self.sql = []

        @contextlib.contextmanager
        def transaccion(org=None):
            def execute(sql, params=()):
                self.sql.append((org, sql))
                return SimpleNamespace(fetchall=lambda: list(self.filas[org]))
            yield SimpleNamespace(execute=execute)

        p = mock.patch.object(contar_totp, 'transaction', transaccion)
        p.start()
        self.addCleanup(p.stop)

    def test_1_cuenta_por_empresa_y_total_sin_ids_ni_secretos(self):
        lineas = []
        total = contar_totp.contar([ORG, '', '  ' + self.ORG_B + '  ', ORG], salida=lineas.append)
        self.assertEqual(total, {'actual': 1, 'anterior': 2, 'ninguna': 1, 'sin_acceso': 1})
        self.assertEqual(lineas[:3], [
            'empresa %s: 1 con la actual, 1 con la anterior, 0 con ninguna, 0 sin acceso' % ORG,
            'empresa %s: 0 con la actual, 1 con la anterior, 1 con ninguna, 1 sin acceso' % self.ORG_B,
            'Total: 1 con la actual, 2 con la anterior, 1 con ninguna, 1 sin acceso'])
        self.assertIn('no cuentan para quitar la anterior', lineas[3])
        self.assertIn('corrige el paso 2', lineas[4])
        salida = '\n'.join(lineas)
        self.assertNotIn('30000000', salida)
        self.assertNotIn(SECRETO, salida)
        # Solo lee, con RLS de cada empresa y una vez por empresa.
        self.assertEqual([o for o, _ in self.sql], [ORG, self.ORG_B])
        self.assertTrue(all(re.match(r'\s*SELECT ', s) for _, s in self.sql))
        # Las mismas condiciones que /login para saber si la cuenta puede entrar.
        self.assertTrue(all("u.is_active AND o.status IN ('trial', 'active')" in s for _, s in self.sql))

    def test_2_una_linea_que_no_es_uuid_sale_sin_tocar_la_base(self):
        with self.assertRaisesRegex(SystemExit, 'La línea 2'):
            contar_totp.contar([ORG, "x' OR 1=1"], salida=lambda _: None)
        self.assertEqual(self.sql, [])

    def test_3_main_lee_la_entrada_y_rechaza_argumentos(self):
        with mock.patch('builtins.print') as imprime:
            contar_totp.main(['contar_totp'], entrada=io.StringIO(ORG + '\n'))
        self.assertEqual(imprime.call_args_list[-1].args[0],
                         'Total: 1 con la actual, 1 con la anterior, 0 con ninguna, 0 sin acceso')
        with self.assertRaises(SystemExit):
            contar_totp.main(['contar_totp', '--recifrar'])

    def test_4_sin_la_anterior_lo_dice_y_lo_de_la_anterior_cuenta_como_ninguna(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL)
        lineas = []
        self.assertEqual(contar_totp.contar([ORG], salida=lineas.append),
                         {'actual': 1, 'anterior': 0, 'ninguna': 1, 'sin_acceso': 0})
        self.assertIn('Sin llave anterior', lineas[0])
        # Sin la anterior puesta (el conteo de antes de rotar) no hay aviso de llave anterior equivocada.
        self.assertFalse(any('corrige el paso 2' in x for x in lineas))

    def test_5_llave_mal_puesta_sale_con_el_mensaje(self):
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ACTUAL)
        with self.assertRaisesRegex(SystemExit, 'misma llave'):
            contar_totp.main(['contar_totp'], entrada=io.StringIO(ORG))

    def test_6_entrada_vacia_sale_con_error_y_no_da_cero(self):
        # Un psql que falla deja la entrada vacía: no puede leerse como '0 con la anterior' (hallazgo 6).
        for entrada in ('', '\n  \n'):
            with self.subTest(entrada=entrada), self.assertRaises(SystemExit) as e:
                contar_totp.main(['contar_totp'], entrada=io.StringIO(entrada))
            self.assertEqual(e.exception.code, contar_totp.SIN_EMPRESAS)
        self.assertEqual(self.sql, [])

    def test_7_sin_ninguna_no_avisa_de_la_anterior(self):
        self.filas[ORG] = [self.filas[ORG][1]]
        lineas = []
        self.assertEqual(contar_totp.contar([ORG], salida=lineas.append)['anterior'], 1)
        self.assertEqual(len(lineas), 2)


class RestablecerMfa(Base):
    """El MFA de una cuenta cuyo secreto no abre con ninguna llave (hallazgos 3 y 8 de la revisión de RC-295)."""

    def setUp(self):
        super().setUp()
        self.env(TOTP_ENCRYPTION_KEY=ACTUAL, TOTP_PREVIOUS_ENCRYPTION_KEY=ANTERIOR)
        self.fila, self.sql, self.eventos, self.orgs = None, [], [], []

        @contextlib.contextmanager
        def transaccion(org=None):
            self.orgs.append(org)

            def execute(sql, params=()):
                self.sql.append((sql, params))
                return SimpleNamespace(fetchone=lambda: self.fila, rowcount=1)
            yield SimpleNamespace(execute=execute)

        def auditar(conn, org, accion, user_id=None, ip=None, entity_type=None, entity_id=None, details=None):
            self.eventos.append((org, accion, user_id, entity_type, entity_id, details))

        for parche in (mock.patch.object(restablecer_mfa, 'transaction', transaccion),
                       mock.patch.object(restablecer_mfa, 'audit', auditar)):
            parche.start()
            self.addCleanup(parche.stop)

    def correr(self, *args):
        lineas = []
        return restablecer_mfa.main(['restablecer_mfa', ORG, USUARIO, *args], salida=lineas.append), lineas

    def updates(self):
        return [s for s, _ in self.sql if s.lstrip().startswith('UPDATE')]

    def test_1_sin_si_solo_revisa(self):
        self.fila = {'totp_secret_enc': cifrar_con(OTRA)}
        hecho, lineas = self.correr()
        self.assertFalse(hecho)
        self.assertIn('--si', lineas[0])
        self.assertEqual((self.updates(), self.eventos), ([], []))
        self.assertIn('FOR UPDATE', self.sql[0][0])

    def test_2_con_si_restablece_con_rls_y_evento(self):
        self.fila = {'totp_secret_enc': cifrar_con(OTRA)}
        hecho, lineas = self.correr('--si')
        self.assertTrue(hecho)
        sql, = self.updates()
        for columna in ('totp_secret_enc = NULL', 'mfa_enabled_at = NULL', 'last_totp_step = NULL'):
            self.assertIn(columna, sql)
        self.assertEqual(self.orgs, [ORG])
        self.assertEqual(self.eventos, [(ORG, 'auth.mfa_reset', None, 'user', USUARIO, {'reason': 'key'})])
        self.assertNotIn(SECRETO, '\n'.join(lineas))

    def test_3_un_secreto_que_abre_no_se_toca(self):
        for llave, cual in ((ACTUAL, 'actual'), (ANTERIOR, 'anterior')):
            self.fila = {'totp_secret_enc': cifrar_con(llave)}
            with self.subTest(cual=cual), self.assertRaisesRegex(SystemExit, 'abre con la %s' % cual):
                self.correr('--si')
        self.assertEqual((self.updates(), self.eventos), ([], []))

    def test_4_sin_cuenta_o_sin_secreto_no_hace_nada(self):
        for fila, texto in ((None, 'No hay un usuario'), ({'totp_secret_enc': None}, 'no tiene secreto')):
            self.fila = fila
            with self.subTest(texto=texto), self.assertRaisesRegex(SystemExit, texto):
                self.correr('--si')
        self.assertEqual((self.updates(), self.eventos), ([], []))

    def test_5_argumentos_que_no_son_uuid_salen_sin_tocar_la_base(self):
        for args in ([ORG], [ORG, "x' OR 1=1"], ['otra', USUARIO, '--si'], [ORG, USUARIO, 'extra']):
            with self.subTest(args=args), self.assertRaises(SystemExit):
                restablecer_mfa.main(['restablecer_mfa', *args])
        self.assertEqual(self.sql, [])


if __name__ == '__main__':
    unittest.main()
