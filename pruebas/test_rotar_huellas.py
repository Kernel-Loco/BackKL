"""Pruebas de la rotación de la llave de las huellas de contraseña (RC-333), sin red ni base.

Cubren los puntos 1 a 4 del Hecho cuando de RC-333: la versión de la llave en el prefijo ('lt1$', 'lt2$'), la llave
anterior en una sola de sus dos formas y la API que no arranca si es la actual o la del MFA o si la versión es 1, la
huella de la versión anterior que entra y queda cifrada con la actual en el mismo inicio de sesión, el comando
`python -m cirdan.auth.rotar_huellas` (empresa por empresa, fila por fila con FOR NO KEY UPDATE, '--prueba' que solo
cuenta y no bloquea, conteos en la salida y en audit_log sin huellas, el evento de lo ya cambiado si la corrida se
corta y una segunda corrida que no cambia nada ni escribe eventos) y, sin la anterior, la
huella que no abre y gasta lo mismo que un correo que no existe. `keyvault._abrir` y la base son falsos.
Corren dentro del contenedor, porque importan argon2, cryptography y la API:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_rotar_huellas.py
"""
import asyncio
import base64
import json
import os
import re
import statistics
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from argon2 import PasswordHasher

from cirdan.auth import keyvault, passwords, rotar_huellas, totp
from pruebas import test_llave_huellas as llave
from pruebas.test_llave_huellas import ALEX, CLAVE, LLAVE, LLAVE_TOTP, MAYA, ORG, URL, URL_TOTP, Base

LLAVE2 = base64.urlsafe_b64encode(b'CIRDAN_FAKE_llave_huellas_v2_32b').decode()
assert len(base64.urlsafe_b64decode(LLAVE2)) == 32 and LLAVE2 not in (LLAVE, LLAVE_TOTP)
URL_ANTERIOR = 'https://kv-lowtide.vault.azure.net/secrets/password-hash-key-v1/' + llave.VERSION
ORG_B = '20000000-0000-4000-8000-000000000002'
ORG_C = '20000000-0000-4000-8000-000000000003'
DANADA = '30000000-0000-4000-8000-000000000003'
YA_NUEVA = '30000000-0000-4000-8000-000000000004'
SIN_CIFRAR = '30000000-0000-4000-8000-000000000005'
COPIADA = '30000000-0000-4000-8000-000000000006'
DE_BETA = '30000000-0000-4000-8000-000000000007'
DE_C = '30000000-0000-4000-8000-000000000008'
FALSOS = {'CIRDAN_APP_PASSWORD': 'CIRDAN_FAKE_app'}


class Rotacion(Base):

    def setUp(self):
        self._vars = {}
        super().setUp()
        self.env(TOTP_ENCRYPTION_KEY=LLAVE_TOTP)

    def env(self, **valores):
        """Base.env borra las variables que no recibe; aquí se suman a las de antes."""
        self._vars.update(valores)
        super().env(**self._vars)

    def rotada(self, **otras):
        """Después de rotar: versión 2, la llave nueva como actual y la de antes como anterior."""
        self.env(**{'PASSWORD_HASH_KEY_VERSION': '2', 'PASSWORD_HASH_ENCRYPTION_KEY': LLAVE2,
                    'PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY': LLAVE, **otras})

    def solo_la_nueva(self):
        """Versión 2 sin la anterior: como queda al final de los pasos de docs/despliegue.md."""
        self.env(PASSWORD_HASH_KEY_VERSION='2', PASSWORD_HASH_ENCRYPTION_KEY=LLAVE2,
                 PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY='', PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL='')

    def de_la_version_1(self, clave=CLAVE, user_id=ALEX):
        """Una huella cifrada con LLAVE antes de rotar."""
        self.env(PASSWORD_HASH_KEY_VERSION='1', PASSWORD_HASH_ENCRYPTION_KEY=LLAVE,
                 PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY='', PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL='')
        huella = passwords.hash_password(clave, user_id)
        self.assertTrue(huella.startswith('lt1$'))
        return huella

    def arrancar(self):
        from cirdan.api import main

        async def correr():
            async with main.app.router.lifespan_context(main.app):
                pass
        asyncio.run(correr())


class Version(Rotacion):
    """Punto 1: la versión en el prefijo, la anterior en una sola forma y cuándo la API no arranca."""

    def test_1_el_numero_del_prefijo_es_la_version(self):
        self.assertTrue(passwords.hash_password(CLAVE, ALEX).startswith('lt1$'), 'versión 1 por omisión')
        self.env(PASSWORD_HASH_KEY_VERSION='1')
        self.assertTrue(passwords.hash_password(CLAVE, ALEX).startswith('lt1$'))
        self.solo_la_nueva()
        huella = passwords.hash_password(CLAVE, ALEX)
        self.assertTrue(huella.startswith('lt2$'))
        self.assertEqual(passwords.version_de(huella), 2)
        self.assertTrue(passwords.verify_password(huella, CLAVE, ALEX))
        self.assertFalse(passwords.needs_rehash(huella, ALEX))
        self.env(PASSWORD_HASH_KEY_VERSION=' 12 ')
        self.assertTrue(passwords.hash_password(CLAVE, ALEX).startswith('lt12$'))
        self.assertEqual((passwords.version_de('lt9999$x'), passwords.version_de('lt0$x'),
                          passwords.version_de('lt01$x'), passwords.version_de('$argon2id$x')), (9999, None, None, None))

    def test_1b_una_version_que_no_es_de_1_a_9999_no_arranca(self):
        for mala in ('0', '01', '-1', 'abc', '10000', '1.0', '2x', '١'):
            with self.subTest(mala=mala):
                self.env(PASSWORD_HASH_KEY_VERSION=mala)
                with self.assertRaisesRegex(RuntimeError, '^PASSWORD_HASH_KEY_VERSION debe ser un número entero'):
                    passwords.revisar_variables()

    def test_1c_la_anterior_en_sus_dos_formas_nunca_las_dos(self):
        self.rotada(PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL=URL_ANTERIOR)
        f = self.falso()
        with self.assertRaisesRegex(RuntimeError, 'quita PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY'):
            passwords.revisar_variables()
        with self.assertRaisesRegex(RuntimeError, 'quita PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY'):
            passwords.comprobar_llave()
        self.assertEqual(f.peticiones, [])

    def test_1d_la_anterior_desde_key_vault_abre_la_version_1(self):
        vieja = self.de_la_version_1()
        self.env(PASSWORD_HASH_KEY_VERSION='2', PASSWORD_HASH_ENCRYPTION_KEY=LLAVE2,
                 PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL=URL_ANTERIOR)
        f = self.falso()  # Key Vault da LLAVE
        passwords.comprobar_llave()
        self.assertTrue(passwords.verify_password(vieja, CLAVE, ALEX))
        self.assertTrue(f.peticiones[-1].startswith(URL_ANTERIOR + '?api-version='))

    def test_1e_no_arranca_si_la_anterior_es_la_actual(self):
        self.env(PASSWORD_HASH_KEY_VERSION='2', PASSWORD_HASH_ENCRYPTION_KEY=LLAVE2,
                 PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY=LLAVE2[:10] + '*' + LLAVE2[10:])
        with self.assertRaisesRegex(RuntimeError, 'PREVIOUS_ENCRYPTION_KEY es la misma llave que'):
            passwords.revisar_variables()
        self.env(PASSWORD_HASH_ENCRYPTION_KEY='', PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY='',
                 PASSWORD_HASH_KEY_VAULT_SECRET_URL=URL, PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL=URL)
        with self.assertRaisesRegex(RuntimeError, 'es la misma URL que PASSWORD_HASH_KEY_VAULT_SECRET_URL'):
            passwords.revisar_variables()
        # Mixto: la actual directa y la anterior de Key Vault con los mismos bytes. Solo se ve al arrancar.
        self.env(PASSWORD_HASH_ENCRYPTION_KEY=LLAVE2, PASSWORD_HASH_KEY_VAULT_SECRET_URL='',
                 PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL=URL_ANTERIOR, **FALSOS)
        self.falso(vault={'value': LLAVE2})
        passwords.revisar_variables()
        with self.assertRaisesRegex(RuntimeError, 'da la misma llave que la actual'):
            self.arrancar()

    def test_1f_no_arranca_si_la_anterior_es_la_del_mfa(self):
        self.rotada(PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY=LLAVE_TOTP)
        with self.assertRaisesRegex(RuntimeError, 'PREVIOUS_ENCRYPTION_KEY debe ser otra llave que TOTP_ENCRYPTION_KEY'):
            passwords.revisar_variables()
        otra_version = URL_TOTP.replace(llave.VERSION, 'f' * 32)
        self.env(PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY='', PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL=otra_version,
                 TOTP_ENCRYPTION_KEY='', TOTP_KEY_VAULT_SECRET_URL=URL_TOTP)
        with self.assertRaisesRegex(RuntimeError, 'PREVIOUS_KEY_VAULT_SECRET_URL debe ser otro secreto que TOTP_'):
            passwords.revisar_variables()
        # Mixto: el MFA directo y la anterior de Key Vault con sus mismos bytes.
        self.env(TOTP_ENCRYPTION_KEY=LLAVE_TOTP, TOTP_KEY_VAULT_SECRET_URL='',
                 PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL=URL_ANTERIOR, **FALSOS)
        self.falso(vault={'value': LLAVE_TOTP})
        with self.assertRaisesRegex(RuntimeError, 'PREVIOUS_KEY_VAULT_SECRET_URL da la misma llave que la del MFA'):
            self.arrancar()

    def test_1g_no_arranca_con_la_anterior_y_la_version_en_1(self):
        for version in ('', '1'):
            with self.subTest(version=version):
                self.env(PASSWORD_HASH_KEY_VERSION=version, PASSWORD_HASH_ENCRYPTION_KEY=LLAVE2,
                         PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY=LLAVE, **FALSOS)
                with self.assertRaisesRegex(RuntimeError, 'sube PASSWORD_HASH_KEY_VERSION'):
                    self.arrancar()

    def test_1h_arranca_con_la_anterior_bien_puesta(self):
        self.rotada(**FALSOS)
        self.arrancar()
        self.assertTrue(passwords._huella_relleno().startswith('lt2$'))


def entrar(huella, clave=CLAVE, user_id=ALEX):
    """POST /auth/login con base y Valkey falsos, como test_llave_huellas.Login.entrar."""
    from cirdan.auth import routes
    base = llave.BaseFalsa({'user_id': user_id, 'organization_id': ORG, 'password_hash': huella, 'mfa_enabled': True})
    sesiones = mock.Mock(**{'take_login_attempt.return_value': [1, 2], 'create_mfa.return_value': 'CIRDAN_FAKE_mfa'})
    with mock.patch.object(routes, 'transaction', base.transaction), mock.patch.object(routes, 'sessions', sesiones), \
            mock.patch.object(routes, 'client_ip', return_value='127.0.0.1'), \
            mock.patch.object(routes.captcha, 'verify', return_value=True):
        try:
            respuesta = routes.login(routes.LoginIn(email='alex@acme-demo.mx', password=clave), None, mock.Mock())
        except routes.HTTPException as e:
            respuesta = e
    return respuesta, base


class Login(Rotacion):
    """Puntos 2 y 4 por la ruta de /auth/login."""

    def test_2_la_huella_anterior_entra_y_queda_cifrada_con_la_actual(self):
        vieja = self.de_la_version_1()
        self.rotada()
        self.assertTrue(passwords.verify_password(vieja, CLAVE, ALEX))
        self.assertTrue(passwords.needs_rehash(vieja, ALEX))
        respuesta, base = entrar(vieja)
        self.assertEqual(respuesta['mfa_required'], True)
        self.assertEqual(len(base.updates), 1)
        nueva, user_id, anterior = base.updates[0]
        self.assertEqual((user_id, anterior), (ALEX, vieja))
        self.assertTrue(nueva.startswith('lt2$'))
        self.assertFalse(passwords.needs_rehash(nueva, ALEX))
        self.solo_la_nueva()
        self.assertTrue(passwords.verify_password(nueva, CLAVE, ALEX), 'abre sin la anterior')
        self.de_la_version_1()
        self.assertFalse(passwords.verify_password(nueva, CLAVE, ALEX), 'ya no abre con la llave de antes')

    def test_2b_la_anterior_no_abre_una_huella_de_dos_versiones_atras(self):
        vieja = self.de_la_version_1()
        self.env(PASSWORD_HASH_KEY_VERSION='3', PASSWORD_HASH_ENCRYPTION_KEY=LLAVE2,
                 PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY=LLAVE)
        self.assertFalse(passwords.verify_password(vieja, CLAVE, ALEX))
        self.assertIsNone(passwords.recifrar(vieja, ALEX))

    def test_2c_la_huella_anterior_con_otra_clave_no_entra_ni_se_guarda(self):
        vieja = self.de_la_version_1()
        self.rotada()
        respuesta, base = entrar(vieja, clave='Otra-Clave-Larga-99')
        self.assertEqual(respuesta.status_code, 401)
        self.assertEqual(base.updates, [])

    def _relleno_gastado(self, huella):
        passwords.comprobar_llave()
        relleno = passwords._relleno_phc().split('$')[3]
        hasher = mock.Mock(wraps=passwords._hasher)
        with mock.patch.object(passwords, '_hasher', hasher):
            self.assertFalse(passwords.verify_password(huella, CLAVE, ALEX))
        self.assertEqual(hasher.verify.call_count, 1)
        self.assertEqual(hasher.verify.call_args.args[0].split('$')[3], relleno)

    def test_4_sin_la_anterior_no_abre_y_gasta_argon2id(self):
        vieja = self.de_la_version_1()
        self.solo_la_nueva()
        self._relleno_gastado(vieja)
        respuesta, base = entrar(vieja)
        self.assertEqual(respuesta.status_code, 401)
        self.assertEqual(json.loads(respuesta.body)['detail'], 'Correo o contraseña incorrectos.')
        self.assertEqual(base.updates, [])
        # Con otra llave puesta como anterior tampoco.
        self.rotada(PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY=base64.urlsafe_b64encode(os.urandom(32)).decode())
        self._relleno_gastado(vieja)

    def test_4b_y_tarda_lo_mismo_que_un_correo_inexistente(self):
        vieja = self.de_la_version_1()
        self.solo_la_nueva()
        passwords.comprobar_llave()

        def medir(f):
            tiempos = []
            for _ in range(7):
                inicio = time.perf_counter()
                f()
                tiempos.append(time.perf_counter() - inicio)
            return statistics.median(tiempos)
        inexistente = medir(lambda: passwords.burn_time('Otra-Clave-Larga-99'))
        no_abre = medir(lambda: passwords.verify_password(vieja, 'Otra-Clave-Larga-99', ALEX))
        self.assertGreater(inexistente, 0.01)
        self.assertLess(abs(inexistente - no_abre) / inexistente, 0.35, (inexistente, no_abre))


class Filas:
    def __init__(self, filas):
        self.filas = list(filas)

    def __iter__(self):
        return iter(self.filas)

    def fetchone(self):
        return self.filas[0] if self.filas else None

    def fetchall(self):
        return self.filas


class BaseRotar:
    """Hace de cirdan.db.transaction para el comando. `cuentas` es {user_id: [empresa, huella]}. Con una empresa
    solo se ven sus cuentas, como con RLS. Anota cada consulta con su transacción y su empresa."""

    def __init__(self, cuentas):
        self.cuentas = {u: list(v) for u, v in cuentas.items()}
        self.consultas = []
        self.eventos = []
        self.transacciones = 0
        self.antes_de_bloquear = None

    @contextmanager
    def transaction(self, org=None):
        self.transacciones += 1
        yield _Conexion(self, org, self.transacciones)

    def audit(self, conn, org, action, *args, **kw):
        self.eventos.append((org, action, kw.get('details')))

    def huellas(self):
        return {u: v[1] for u, v in self.cuentas.items()}


class _Conexion:
    def __init__(self, base, org, tx):
        self.base, self.org, self.tx = base, org, tx

    def _de_la_empresa(self, patron):
        assert patron.endswith('%') and '_' not in patron, patron
        return {u: h for u, (o, h) in self.base.cuentas.items() if o == self.org and h.startswith(patron[:-1])}

    def execute(self, sql, p=()):
        self.base.consultas.append((self.tx, self.org, sql, p))
        if 'password_hash_version_orgs' in sql:
            # Lo que hace la función de la 026: sin RLS y solo los ids de empresa.
            v = p[0]
            orgs = sorted({o for o, h in self.base.cuentas.values() if 1 <= v <= 9999 and h.startswith('lt%d$' % v)})
            return Filas({'organization_id': o} for o in orgs)
        if self.org is None:
            raise AssertionError('consulta a users sin empresa (sin RLS no ve nada): %s' % sql)
        if sql.startswith('SELECT id FROM users WHERE password_hash LIKE %s ORDER BY id'):
            return Filas({'id': u} for u in sorted(self._de_la_empresa(p[0])))
        if sql in ('SELECT password_hash FROM users WHERE id = %s AND password_hash LIKE %s',
                   'SELECT password_hash FROM users WHERE id = %s AND password_hash LIKE %s FOR NO KEY UPDATE'):
            if self.base.antes_de_bloquear:
                self.base.antes_de_bloquear(p[0])
            h = self._de_la_empresa(p[1]).get(p[0])
            return Filas([{'password_hash': h}] if h else [])
        if sql.startswith('UPDATE users SET password_hash = %s WHERE id = %s'):
            assert self.base.cuentas[p[1]][0] == self.org
            self.base.cuentas[p[1]][1] = p[0]
            return Filas([])
        if sql.startswith('SELECT count(*) AS n FROM users WHERE password_hash LIKE %s'):
            return Filas([{'n': len(self._de_la_empresa(p[0]))}])
        raise AssertionError('consulta no esperada: %s' % sql)


class Comando(Rotacion):
    """Punto 3: python -m cirdan.auth.rotar_huellas [--prueba]."""

    def setUp(self):
        super().setUp()
        v1 = self.de_la_version_1
        cuentas = {ALEX: [ORG, v1()], MAYA: [ORG, v1(user_id=MAYA)], DANADA: [ORG, v1(user_id=DANADA)[:-6] + 'AAAAAA'],
                   SIN_CIFRAR: [ORG, PasswordHasher().hash(CLAVE)], COPIADA: [ORG, v1(user_id=MAYA)],
                   DE_BETA: [ORG_B, v1(user_id=DE_BETA)]}
        self.rotada()
        cuentas[YA_NUEVA] = [ORG, passwords.hash_password(CLAVE, YA_NUEVA)]
        cuentas[DE_C] = [ORG_C, passwords.hash_password(CLAVE, DE_C)]
        self.base = BaseRotar(cuentas)
        for nombre, valor in (('transaction', self.base.transaction), ('audit', self.base.audit)):
            p = mock.patch.object(rotar_huellas, nombre, valor)
            p.start()
            self.addCleanup(p.stop)

    def rotar(self, prueba=False):
        salida = []
        conteo = rotar_huellas.rotar(prueba=prueba, salida=salida.append)
        return conteo, salida

    def assert_sin_huellas(self, *textos):
        texto = '\n'.join(textos)
        for prohibido in ('lt1$', 'lt2$', '$argon2', CLAVE, LLAVE, LLAVE2, *self.base.cuentas,
                          *(h for h in self.base.huellas().values())):
            self.assertNotIn(prohibido, texto)

    def test_3_con_prueba_solo_cuenta(self):
        antes = self.base.huellas()
        conteo, salida = self.rotar(prueba=True)
        self.assertEqual(conteo, (3, 2, 5))
        self.assertEqual(self.base.huellas(), antes)
        self.assertEqual(self.base.eventos, [])
        self.assertFalse([c for c in self.base.consultas if c[2].startswith('UPDATE')])
        # Ronda 1, hallazgo 9: '--prueba' solo cuenta y no bloquea filas.
        self.assertFalse([c for c in self.base.consultas if ' FOR ' in c[2]])
        self.assertEqual(salida[-1], 'Prueba sin cambios: 3 se cambiarían, 2 no abrieron, quedan 5 de la versión 1')
        self.assert_sin_huellas(*salida)

    def test_3b_cifra_con_la_actual_las_de_la_version_anterior(self):
        antes = self.base.huellas()
        conteo, salida = self.rotar()
        self.assertEqual(conteo, (3, 2, 2))
        despues = self.base.huellas()
        for user_id in (ALEX, MAYA, DE_BETA):
            with self.subTest(user_id=user_id):
                self.assertTrue(despues[user_id].startswith('lt2$'))
                self.assertNotEqual(despues[user_id], antes[user_id])
        for user_id in (DANADA, COPIADA, SIN_CIFRAR, YA_NUEVA, DE_C):
            self.assertEqual(despues[user_id], antes[user_id], user_id)
        # Sin la anterior, como al final de docs/despliegue.md, las cambiadas abren con su misma contraseña.
        self.solo_la_nueva()
        for user_id in (ALEX, MAYA, DE_BETA):
            self.assertTrue(passwords.verify_password(despues[user_id], CLAVE, user_id), user_id)
        self.assertEqual(self.base.eventos, [
            (ORG, 'auth.password_hash_rotated',
             {'from_version': 1, 'to_version': 2, 'changed': 2, 'unopened': 2, 'remaining': 2}),
            (ORG_B, 'auth.password_hash_rotated',
             {'from_version': 1, 'to_version': 2, 'changed': 1, 'unopened': 0, 'remaining': 0})])
        self.assertEqual(salida, ['empresa %s: 2 cambiadas, 2 no abrieron, quedan 2 de la versión 1' % ORG,
                                  'empresa %s: 1 cambiadas, 0 no abrieron, quedan 0 de la versión 1' % ORG_B,
                                  'Listo: 3 cambiadas, 2 no abrieron, quedan 2 de la versión 1'])
        self.assert_sin_huellas(*salida, json.dumps(self.base.eventos))

    def test_3c_empresa_por_empresa_y_fila_por_fila_con_for_no_key_update(self):
        self.rotar()
        consultas = self.base.consultas
        sin_empresa = [c for c in consultas if c[1] is None]
        self.assertEqual(len(sin_empresa), 1)
        self.assertIn('password_hash_version_orgs', sin_empresa[0][2])
        self.assertEqual(sin_empresa[0][3], (1,))
        self.assertNotIn(ORG_C, {c[1] for c in consultas}, 'la empresa sin huellas de la versión 1 no se abre')
        bloqueos = {(c[0], c[3][0]) for c in consultas if c[2].endswith(' FOR NO KEY UPDATE')}
        # Ronda 1, hallazgo 9: FOR UPDATE chocaría con el FOR KEY SHARE de la llave de audit_log a users.
        self.assertFalse([c for c in consultas if 'FOR UPDATE' in c[2]])
        self.assertTrue(bloqueos)
        for tx, org, sql, p in consultas:
            if sql.startswith('UPDATE'):
                self.assertIn((tx, p[1]), bloqueos, 'el UPDATE va en la transacción que bloqueó la fila')
        # Una transacción por cuenta: ninguna bloquea dos filas.
        por_tx = {}
        for tx, user_id in bloqueos:
            por_tx.setdefault(tx, []).append(user_id)
        self.assertTrue(all(len(v) == 1 for v in por_tx.values()))

    def test_3d_correrlo_dos_veces_no_cambia_nada_la_segunda(self):
        self.rotar()
        despues = self.base.huellas()
        eventos = list(self.base.eventos)
        conteo, salida = self.rotar()
        self.assertEqual(conteo, (0, 2, 2))
        self.assertEqual(self.base.huellas(), despues)
        self.assertEqual(salida[-1], 'Listo: 0 cambiadas, 2 no abrieron, quedan 2 de la versión 1')
        # Ronda 1, hallazgo 10: sin cambios no se escribe otro evento en la bitácora, que no se puede borrar.
        self.assertEqual(len(eventos), 2)
        self.assertEqual(self.base.eventos, eventos)

    def cortar_tras_la_primera(self, error):
        """Corta la corrida al bloquear la siguiente cuenta de ORG después de la primera que cambió."""
        def cortar(user_id):
            if sum(self.base.cuentas[u][1].startswith('lt2$') for u in (ALEX, MAYA)) == 1:
                raise error
        self.base.antes_de_bloquear = cortar

    def test_3i_si_se_corta_a_media_empresa_deja_el_evento_de_lo_ya_cambiado(self):
        # Ronda 1, hallazgos 6 y 8: la cuenta ya confirmada no se queda sin evento en audit_log.
        self.cortar_tras_la_primera(KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.rotar()
        self.assertEqual(len(self.base.eventos), 1)
        org, accion, detalles = self.base.eventos[0]
        self.assertEqual((org, accion), (ORG, 'auth.password_hash_rotated'))
        quedan = sum(o == ORG and h.startswith('lt1$') for o, h in self.base.cuentas.values())
        claves = ('from_version', 'to_version', 'changed', 'remaining', 'interrupted')
        self.assertEqual({k: detalles[k] for k in claves},
                         {'from_version': 1, 'to_version': 2, 'changed': 1, 'remaining': quedan, 'interrupted': True})
        self.assert_sin_huellas(json.dumps(self.base.eventos))
        # La siguiente corrida termina y cuenta solo lo que faltaba.
        self.base.antes_de_bloquear = None
        conteo, _ = self.rotar()
        self.assertEqual(conteo, (2, 2, 2))
        cambiadas = sum(d['changed'] for o, _, d in self.base.eventos if o == ORG)
        self.assertEqual(cambiadas, 2)
        self.assertNotIn('interrupted', self.base.eventos[-1][2])

    def test_3j_si_la_base_falla_la_salida_dice_que_quedaron_sin_evento(self):
        self.cortar_tras_la_primera(ConnectionError('la base se cayó'))

        def sin_base(*a, **kw):
            raise ConnectionError('la base se cayó')
        salida = []
        with mock.patch.object(rotar_huellas, 'audit', sin_base), self.assertRaises(ConnectionError):
            rotar_huellas.rotar(salida=salida.append)
        self.assertEqual(salida, ['empresa %s: 1 cambiadas sin evento en audit_log, la corrida se cortó' % ORG])

    def test_3l_otro_ctrl_c_mientras_escribe_el_evento_tambien_avisa(self):
        # Ronda 2, R2: el segundo Ctrl+C es BaseException y saltaba el aviso. Sale el primero, no el segundo.
        primero = KeyboardInterrupt('primero')
        self.cortar_tras_la_primera(primero)

        def otro_ctrl_c(*a, **kw):
            raise KeyboardInterrupt('segundo')
        salida = []
        with mock.patch.object(rotar_huellas, 'audit', otro_ctrl_c), self.assertRaises(KeyboardInterrupt) as e:
            rotar_huellas.rotar(salida=salida.append)
        self.assertIs(e.exception, primero)
        self.assertEqual(salida, ['empresa %s: 1 cambiadas sin evento en audit_log, la corrida se cortó' % ORG])

    def test_3m_si_la_base_falla_despues_de_la_ultima_cuenta_tambien_avisa(self):
        # Ronda 2, R3: _quedan y _evento iban fuera del try, así que la empresa quedaba cambiada sin evento ni aviso.
        def sin_base(*a, **kw):
            raise ConnectionError('la base se cayó')
        salida = []
        with mock.patch.object(rotar_huellas, '_quedan', sin_base), self.assertRaises(ConnectionError):
            rotar_huellas.rotar(salida=salida.append)
        self.assertEqual(salida, ['empresa %s: 2 cambiadas sin evento en audit_log, la corrida se cortó' % ORG])
        self.assertEqual(self.base.eventos, [])

    def test_3n_si_falla_el_evento_de_la_empresa_se_intenta_el_de_la_corrida_cortada(self):
        llamadas = []
        audit_ok = self.base.audit

        def falla_una_vez(*a, **kw):
            llamadas.append(1)
            if len(llamadas) == 1:
                raise ConnectionError('la base se cayó')
            return audit_ok(*a, **kw)
        salida = []
        with mock.patch.object(rotar_huellas, 'audit', falla_una_vez), self.assertRaises(ConnectionError):
            rotar_huellas.rotar(salida=salida.append)
        self.assertEqual(salida, [])
        self.assertEqual(len(self.base.eventos), 1)
        org, accion, detalles = self.base.eventos[0]
        self.assertEqual((org, detalles['changed'], detalles.get('interrupted')), (ORG, 2, True))

    def test_3k_con_prueba_un_corte_no_escribe_nada(self):
        llamadas = []

        def cortar(user_id):
            llamadas.append(user_id)
            if len(llamadas) == 2:
                raise KeyboardInterrupt()
        self.base.antes_de_bloquear = cortar
        with self.assertRaises(KeyboardInterrupt):
            self.rotar(prueba=True)
        self.assertEqual(self.base.eventos, [])

    def test_3e_si_un_login_la_cambio_mientras_tanto_no_la_pisa(self):
        nueva = passwords.hash_password('Otra-Clave-De-Prueba-2', ALEX)

        def login_a_la_vez(user_id):
            if user_id == ALEX:
                self.base.cuentas[ALEX][1] = nueva
        self.base.antes_de_bloquear = login_a_la_vez
        conteo, _ = self.rotar()
        self.assertEqual(conteo, (2, 2, 2))
        self.assertEqual(self.base.cuentas[ALEX][1], nueva)

    def test_3f_sin_la_anterior_no_corre(self):
        for env in ({'PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY': ''},
                    {'PASSWORD_HASH_KEY_VERSION': '1', 'PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY': '',
                     'PASSWORD_HASH_ENCRYPTION_KEY': LLAVE}):
            with self.subTest(env=env):
                self.env(**env)
                with self.assertRaisesRegex(SystemExit, '^Falta la llave anterior: pon PASSWORD_HASH_PREVIOUS_'):
                    self.rotar()
        self.assertEqual(self.base.consultas, [])

    def test_3g_main_solo_acepta_prueba_y_los_errores_salen_sin_la_llave(self):
        for argv in (['x', '--otra'], ['x', '--prueba', '--prueba'], ['x', 'prueba']):
            with self.subTest(argv=argv), self.assertRaisesRegex(SystemExit, '^Uso: python -m cirdan.auth.rotar_'):
                rotar_huellas.main(argv)
        self.env(PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY=LLAVE2)
        with self.assertRaises(SystemExit) as error:
            rotar_huellas.main(['x', '--prueba'])
        self.assertIn('es la misma llave que', str(error.exception))
        self.assertNotIn(LLAVE2, str(error.exception))
        self.assertEqual(self.base.consultas, [])
        self.rotada()
        rotar_huellas.main(['x', '--prueba'])
        self.assertEqual(self.base.eventos, [])

    def test_3h_con_la_anterior_en_key_vault(self):
        self.env(PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY='', PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL=URL_ANTERIOR)
        f = self.falso()  # Key Vault da LLAVE
        self.assertEqual(self.rotar()[0], (3, 2, 2))
        self.assertTrue(any(u.startswith(URL_ANTERIOR) for u in f.peticiones))


class Documentos(unittest.TestCase):
    """Lo que la ronda 2 encontró en la documentación del cambio."""

    RAIZ = Path(__file__).resolve().parents[1]

    def test_5_cada_funcion_del_readme_esta_en_la_migracion_que_cita(self):
        # Ronda 2: db/README.md decía que passkey_lookup llegó con la 017, y es la 018.
        texto = (self.RAIZ / 'db' / 'README.md').read_text(encoding='utf-8')
        citas = re.findall(r'`([a-z_]+)\([a-z_, ]*\)` llegó con la (?:migración )?([0-9]{3})', texto)
        self.assertIn(('passkey_lookup', '018'), citas)
        self.assertIn(('password_hash_version_orgs', '026'), citas)
        for funcion, numero in citas:
            with self.subTest(funcion=funcion):
                archivo, = (self.RAIZ / 'db' / 'migraciones').glob(numero + '_*.sql')
                self.assertIn('FUNCTION public.%s(' % funcion, archivo.read_text(encoding='utf-8'))

    def test_5b_restaurar_un_respaldo_viejo_vuelve_a_dar_el_rol_y_la_anterior(self):
        # Ronda 2, R4: el paso 7 remitía solo al paso 3 y, sin el rol sobre el secreto de antes, la API no arranca.
        texto = (self.RAIZ / 'docs' / 'despliegue.md').read_text(encoding='utf-8')
        paso7 = re.search(r'^7\. \(VM\) Quitar `PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL`.*$', texto, re.M).group(0)
        restaurar = paso7[paso7.index('Para restaurar'):]
        self.assertIn("'Key Vault Secrets User' sobre el secreto de antes, como en el paso 2", restaurar)
        self.assertIn('como en el paso 3', restaurar)


if __name__ == '__main__':
    import unittest
    unittest.main()
