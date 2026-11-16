"""Pruebas de la huella de contraseña cifrada (pepper, RC-330), sin red ni base.

Cubren los puntos 1 a 6 del Hecho cuando de RC-330: formato 'lt1$' con AES-256-GCM y el id del usuario como dato
asociado, la llave de una sola variable (directa o Key Vault), la API que no arranca sin llave, la huella vieja que
entra y queda cifrada en el mismo inicio de sesión, el hash de relleno que no abre nada, la huella copiada a otro
usuario que no entra, el correo inexistente que gasta lo mismo que una contraseña equivocada y los parámetros fijos de
argon2id. `keyvault._abrir` es el único punto de red y aquí se reemplaza por un falso. La base es falsa.
Corren dentro del contenedor, porque importan argon2, cryptography y la API:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_llave_huellas.py
"""
import asyncio
import base64
import os
import statistics
import time
import unittest
from contextlib import contextmanager
from unittest import mock

from argon2 import PasswordHasher, profiles
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cirdan.auth import demo, keyvault, passwords

VERSION = '0123456789abcdef0123456789abcdef'
URL = 'https://kv-lowtide.vault.azure.net/secrets/password-hash-key/' + VERSION
URL_TOTP = 'https://kv-lowtide.vault.azure.net/secrets/totp-encryption-key/' + VERSION
TOKEN = 'CIRDAN_FAKE_token_imds'
LLAVE = base64.urlsafe_b64encode(b'CIRDAN_FAKE_llave_huellas_32_byt').decode()
LLAVE_TOTP = base64.urlsafe_b64encode(b'CIRDAN_FAKE_llave_totp_de_32_byt').decode()
assert len(base64.urlsafe_b64decode(LLAVE)) == 32 and len(base64.urlsafe_b64decode(LLAVE_TOTP)) == 32
ALEX = '30000000-0000-4000-8000-000000000001'
MAYA = '30000000-0000-4000-8000-000000000002'
ORG = '20000000-0000-4000-8000-000000000001'
CLAVE = 'Clave-De-Prueba-Larga-1'
VARIABLES = ('PASSWORD_HASH_ENCRYPTION_KEY', 'PASSWORD_HASH_KEY_VAULT_SECRET_URL', 'TOTP_ENCRYPTION_KEY',
             'TOTP_KEY_VAULT_SECRET_URL')


class Falso:
    """Responde como IMDS y Key Vault, y anota cada petición."""

    def __init__(self, vault=None):
        self.vault = vault or {'value': LLAVE}
        self.peticiones = []

    def __call__(self, req, timeout):
        self.peticiones.append(req.full_url)
        if req.full_url.startswith('http://169.254.169.254/'):
            return {'access_token': TOKEN}
        if isinstance(self.vault, BaseException):
            raise self.vault
        return self.vault


class Base(unittest.TestCase):
    def setUp(self):
        for nombre in ('_llave_vault', '_relleno'):
            setattr(passwords, nombre, None)
            self.addCleanup(setattr, passwords, nombre, None)
        p = mock.patch('cirdan.config._env_file', return_value={})
        p.start()
        self.addCleanup(p.stop)
        self.env(PASSWORD_HASH_ENCRYPTION_KEY=LLAVE)

    def env(self, **valores):
        limpio = {k: v for k, v in os.environ.items() if k not in VARIABLES}
        limpio.update(valores)
        p = mock.patch.dict(os.environ, limpio, clear=True)
        p.start()
        self.addCleanup(p.stop)

    def falso(self, **kw):
        f = Falso(**kw)
        p = mock.patch.object(keyvault, '_abrir', f)
        p.start()
        self.addCleanup(p.stop)
        return f


class Formato(Base):
    """Punto 1: 'lt1$' + AES-256-GCM de la cadena PHC, con el id del usuario como dato asociado."""

    def test_1_la_huella_es_la_cadena_phc_cifrada(self):
        huella = passwords.hash_password(CLAVE, ALEX)
        self.assertTrue(huella.startswith('lt1$'))
        self.assertNotIn('argon2', huella)
        blob = base64.urlsafe_b64decode(huella[4:])
        phc = AESGCM(base64.urlsafe_b64decode(LLAVE)).decrypt(blob[:12], blob[12:], ALEX.encode()).decode()
        self.assertTrue(phc.startswith('$argon2id$v=19$m=65536,t=3,p=4$'))
        self.assertTrue(PasswordHasher().verify(phc, CLAVE))
        self.assertTrue(passwords.verify_password(huella, CLAVE, ALEX))
        self.assertFalse(passwords.verify_password(huella, CLAVE + 'x', ALEX))
        self.assertFalse(passwords.needs_rehash(huella, ALEX))

    def test_1b_dos_huellas_de_la_misma_clave_no_se_parecen(self):
        self.assertNotEqual(passwords.hash_password(CLAVE, ALEX), passwords.hash_password(CLAVE, ALEX))

    def test_1c_el_id_en_mayusculas_es_el_mismo_usuario(self):
        huella = passwords.hash_password(CLAVE, ALEX.upper())
        self.assertTrue(passwords.verify_password(huella, CLAVE, ALEX))

    def test_1d_con_otra_llave_no_abre(self):
        huella = passwords.hash_password(CLAVE, ALEX)
        self.env(PASSWORD_HASH_ENCRYPTION_KEY=base64.urlsafe_b64encode(os.urandom(32)).decode())
        self.assertFalse(passwords.verify_password(huella, CLAVE, ALEX))
        self.assertTrue(passwords.needs_rehash(huella, ALEX))

    def test_1e_huellas_mal_formadas_no_abren_ni_truenan(self):
        buena = passwords.hash_password(CLAVE, ALEX)
        for mala in ('lt1$', 'lt1$%%%%', 'lt1$' + base64.urlsafe_b64encode(b'corto').decode(), buena[:-4],
                     buena[:10] + '!' + buena[11:], 'lt2$' + buena[4:], '', None, 12, '$argon2i$v=19$x', 'texto'):
            with self.subTest(mala=mala):
                self.assertFalse(passwords.verify_password(mala, CLAVE, ALEX))
                self.assertTrue(passwords.needs_rehash(mala, ALEX))

    def test_1f_un_id_que_no_es_uuid_no_cifra(self):
        with self.assertRaises(ValueError):
            passwords.hash_password(CLAVE, 'no-es-un-uuid')
        self.assertFalse(passwords.verify_password(passwords.hash_password(CLAVE, ALEX), CLAVE, 'no-es-un-uuid'))


class Llave(Base):
    """Puntos 1 y 2: una sola variable, y sin llave válida la API no arranca con un mensaje que la nombra."""

    def test_2_sin_ninguna_variable(self):
        self.env(PASSWORD_HASH_ENCRYPTION_KEY='', PASSWORD_HASH_KEY_VAULT_SECRET_URL='')
        with self.assertRaisesRegex(RuntimeError, 'Falta PASSWORD_HASH_ENCRYPTION_KEY o PASSWORD_HASH_KEY_VAULT_'):
            passwords.comprobar_llave()

    def test_2b_con_las_dos(self):
        self.env(PASSWORD_HASH_ENCRYPTION_KEY=LLAVE, PASSWORD_HASH_KEY_VAULT_SECRET_URL=URL)
        f = self.falso()
        with self.assertRaisesRegex(RuntimeError, 'quita PASSWORD_HASH_ENCRYPTION_KEY'):
            passwords.comprobar_llave()
        with self.assertRaisesRegex(RuntimeError, 'quita PASSWORD_HASH_ENCRYPTION_KEY'):
            passwords.revisar_variables()
        self.assertEqual(f.peticiones, [])

    def test_2c_llave_mal_formada(self):
        for mala in ('genera_tu_llave', base64.urlsafe_b64encode(os.urandom(16)).decode(), '***'):
            with self.subTest(mala=mala):
                self.env(PASSWORD_HASH_ENCRYPTION_KEY=mala)
                with self.assertRaisesRegex(RuntimeError, 'PASSWORD_HASH_ENCRYPTION_KEY debe ser de 32 bytes'):
                    passwords.comprobar_llave()

    def test_2d_la_misma_llave_que_la_del_mfa_no_vale(self):
        self.env(PASSWORD_HASH_ENCRYPTION_KEY=LLAVE, TOTP_ENCRYPTION_KEY=LLAVE)
        with self.assertRaisesRegex(RuntimeError, 'otra llave que TOTP_ENCRYPTION_KEY'):
            passwords.comprobar_llave()
        self.env(PASSWORD_HASH_KEY_VAULT_SECRET_URL=URL_TOTP, TOTP_KEY_VAULT_SECRET_URL=URL_TOTP)
        with self.assertRaisesRegex(RuntimeError, 'otro secreto que TOTP_KEY_VAULT_SECRET_URL'):
            passwords.comprobar_llave()

    def test_2e_desde_key_vault_se_lee_una_vez(self):
        self.env(PASSWORD_HASH_KEY_VAULT_SECRET_URL=URL)
        f = self.falso()
        passwords.comprobar_llave()
        huella = passwords.hash_password(CLAVE, ALEX)
        self.assertTrue(passwords.verify_password(huella, CLAVE, ALEX))
        self.assertEqual(len(f.peticiones), 2)
        self.assertTrue(f.peticiones[1].startswith(URL + '?api-version='))
        # La misma llave en el .env abre lo que se cifró con la de Key Vault.
        self.env(PASSWORD_HASH_ENCRYPTION_KEY=LLAVE)
        self.assertTrue(passwords.verify_password(huella, CLAVE, ALEX))

    def test_2f_url_mal_formada_nombra_la_variable_y_no_manda_el_token(self):
        self.env(PASSWORD_HASH_KEY_VAULT_SECRET_URL='https://otro.ejemplo.test/secrets/x/' + VERSION)
        f = self.falso()
        with self.assertRaisesRegex(RuntimeError, '^PASSWORD_HASH_KEY_VAULT_SECRET_URL debe ser https://'):
            passwords.comprobar_llave()
        self.assertEqual(f.peticiones, [])

    def test_2g_secreto_de_key_vault_mal_formado(self):
        self.env(PASSWORD_HASH_KEY_VAULT_SECRET_URL=URL)
        self.falso(vault={'value': 'corto'})
        with self.assertRaisesRegex(RuntimeError, 'PASSWORD_HASH_KEY_VAULT_SECRET_URL debe ser de 32 bytes'):
            passwords.comprobar_llave()


FALSOS = {'CIRDAN_APP_PASSWORD': 'CIRDAN_FAKE_app'}


class Arranque(Base):
    """Punto 2 con el lifespan de la API, el que corre uvicorn al arrancar."""

    def _arrancar(self):
        from cirdan.api import main

        async def correr():
            async with main.app.router.lifespan_context(main.app):
                pass
        asyncio.run(correr())

    def test_2h_la_api_no_arranca_sin_la_llave_de_las_huellas(self):
        self.env(TOTP_ENCRYPTION_KEY=LLAVE_TOTP, PASSWORD_HASH_ENCRYPTION_KEY='', **FALSOS)
        with self.assertRaisesRegex(RuntimeError, 'PASSWORD_HASH_ENCRYPTION_KEY'):
            self._arrancar()

    def test_2i_la_api_no_arranca_sin_rol_en_key_vault(self):
        import urllib.error
        self.env(TOTP_ENCRYPTION_KEY=LLAVE_TOTP, PASSWORD_HASH_ENCRYPTION_KEY='',
                 PASSWORD_HASH_KEY_VAULT_SECRET_URL=URL, **FALSOS)
        self.falso(vault=urllib.error.HTTPError('http://x', 403, 'x', {}, None))
        with mock.patch.object(keyvault, '_dormir', lambda s: None):
            with self.assertRaisesRegex(RuntimeError, 'HTTP 403'):
                self._arrancar()

    def test_2j_la_api_arranca_con_las_dos_llaves_y_deja_listo_el_relleno(self):
        self.env(TOTP_ENCRYPTION_KEY=LLAVE_TOTP, PASSWORD_HASH_ENCRYPTION_KEY=LLAVE, **FALSOS)
        self._arrancar()
        self.assertIsNotNone(passwords._relleno)


class BaseFalsa:
    """Hace de cirdan.db.transaction para el login: login_lookup() da `fila`, el SELECT del rol da 'admin' y se anota
    cada UPDATE."""

    def __init__(self, fila):
        self.fila = fila
        self.updates = []

    @contextmanager
    def transaction(self, org=None):
        yield self

    def execute(self, sql, parametros=()):
        if 'login_lookup' in sql:
            return mock.Mock(**{'fetchone.return_value': self.fila})
        if sql.startswith('UPDATE users SET password_hash'):
            self.updates.append(parametros)
            return mock.Mock(rowcount=1)
        raise AssertionError('consulta no esperada: %s' % sql)


class Login(Base):
    """Puntos 3, 4 y 5 por la ruta de /auth/login, con base y Valkey falsos."""

    def entrar(self, huella, clave=CLAVE, user_id=ALEX, existe=True):
        from cirdan.auth import routes
        base = BaseFalsa({'user_id': user_id, 'organization_id': ORG, 'password_hash': huella, 'mfa_enabled': True}
                         if existe else None)
        sesiones = mock.Mock(**{'is_locked.return_value': False, 'create_mfa.return_value': 'CIRDAN_FAKE_mfa'})
        with mock.patch.object(routes, 'transaction', base.transaction), \
                mock.patch.object(routes, 'sessions', sesiones), \
                mock.patch.object(routes, 'client_ip', return_value='127.0.0.1'):
            try:
                respuesta = routes.login(routes.LoginIn(email='alex@acme-demo.mx', password=clave), None, mock.Mock())
            except routes.HTTPException as e:
                respuesta = e
        return respuesta, base

    def test_3_la_huella_vieja_entra_y_queda_cifrada_en_el_mismo_inicio(self):
        vieja = PasswordHasher().hash(CLAVE)
        respuesta, base = self.entrar(vieja)
        self.assertEqual(respuesta['mfa_required'], True)
        self.assertEqual(len(base.updates), 1)
        nueva, user_id, anterior = base.updates[0]
        self.assertEqual((user_id, anterior), (ALEX, vieja))
        self.assertTrue(nueva.startswith('lt1$'))
        self.assertTrue(passwords.verify_password(nueva, CLAVE, ALEX))

    def test_3b_la_huella_cifrada_entra_sin_volver_a_guardarse(self):
        respuesta, base = self.entrar(passwords.hash_password(CLAVE, ALEX))
        self.assertEqual(respuesta['mfa_required'], True)
        self.assertEqual(base.updates, [])

    def test_3c_el_hash_de_relleno_no_abre_ninguna_cuenta(self):
        for intento in (demo.PASSWORD, 'lowtide-relleno-que-nunca-coincide', 'demo-only', CLAVE):
            for user_id in [c[1] for c in demo.CUENTAS.values()] + [passwords._ID_RELLENO]:
                with self.subTest(intento=intento, user_id=user_id):
                    self.assertFalse(passwords.verify_password(demo.HASH_DE_RELLENO, intento, user_id))
        respuesta, base = self.entrar(demo.HASH_DE_RELLENO, clave=demo.PASSWORD)
        self.assertEqual(respuesta.status_code, 401)
        self.assertEqual(base.updates, [])

    def test_3d_el_relleno_cifrado_no_abre_con_su_propia_clave_en_una_cuenta(self):
        relleno = passwords._huella_relleno()
        self.assertFalse(passwords.verify_password(relleno, passwords._RELLENO, ALEX))

    def test_4_la_huella_de_un_usuario_copiada_a_otro_no_entra(self):
        de_alex = passwords.hash_password(CLAVE, ALEX)
        self.assertFalse(passwords.verify_password(de_alex, CLAVE, MAYA))
        respuesta, base = self.entrar(de_alex, user_id=MAYA)
        self.assertEqual(respuesta.status_code, 401)
        self.assertEqual(base.updates, [])

    def test_5_correo_inexistente_y_clave_equivocada_hacen_el_mismo_trabajo(self):
        # Lo mismo en las dos: un descifrado AES-GCM y una verificación argon2id con los mismos parámetros.
        huella = passwords.hash_password(CLAVE, ALEX)
        passwords.comprobar_llave()
        trabajo = {}
        for caso, kw in (('inexistente', {'existe': False}), ('equivocada', {'clave': 'Otra-Clave-Larga-99'})):
            # PasswordHasher no deja reemplazar sus métodos: se envuelve entero.
            hasher = mock.Mock(wraps=passwords._hasher)
            verificar = hasher.verify
            descifrados = []

            class Contado:
                # AESGCM viene de Rust y no se puede parchar por método: se envuelve entero.
                def __init__(self, key):
                    self.aes = AESGCM(key)

                def decrypt(self, *args):
                    descifrados.append(args[2])
                    return self.aes.decrypt(*args)
            with mock.patch.object(passwords, '_hasher', hasher), \
                    mock.patch.object(passwords, 'AESGCM', Contado):
                respuesta, _ = self.entrar(huella, **kw)
            self.assertEqual(respuesta.status_code if hasattr(respuesta, 'status_code') else None, 401, caso)
            trabajo[caso] = (verificar.call_count, len(descifrados),
                             verificar.call_args.args[0].split('$')[3])
        self.assertEqual(trabajo['inexistente'], trabajo['equivocada'])
        self.assertEqual(trabajo['inexistente'][:2], (1, 1))

    def test_5b_y_tardan_lo_mismo(self):
        huella = passwords.hash_password(CLAVE, ALEX)
        passwords.comprobar_llave()

        def medir(f):
            tiempos = []
            for _ in range(7):
                inicio = time.perf_counter()
                f()
                tiempos.append(time.perf_counter() - inicio)
            return statistics.median(tiempos)
        inexistente = medir(lambda: passwords.burn_time('Otra-Clave-Larga-99'))
        equivocada = medir(lambda: passwords.verify_password(huella, 'Otra-Clave-Larga-99', ALEX))
        self.assertGreater(inexistente, 0.01, 'el correo inexistente también debe gastar el tiempo de argon2id')
        self.assertLess(abs(inexistente - equivocada) / equivocada, 0.35, (inexistente, equivocada))


class Parametros(unittest.TestCase):
    """Punto 6: argon2id fijo en RFC 9106 de poca memoria, los mismos valores de antes."""

    def test_6_parametros_fijos(self):
        self.assertIs(passwords.PARAMETROS, profiles.RFC_9106_LOW_MEMORY)
        h = passwords._hasher
        self.assertEqual((h.type.name, h.time_cost, h.memory_cost, h.parallelism, h.hash_len, h.salt_len),
                         ('ID', 3, 65536, 4, 32, 16))


if __name__ == '__main__':
    unittest.main()
