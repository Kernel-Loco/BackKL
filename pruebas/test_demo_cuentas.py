"""Pruebas de cirdan/auth/demo.py: cuándo les pone contraseña y MFA a las cuentas de demo (#169, RC-287) y cuándo
se las quita (#49, RC-91).

Sin red y sin base: la transacción es falsa y cuenta los UPDATE. Corren dentro del contenedor, porque
cirdan.auth.demo importa psycopg, pyotp y argon2:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_demo_cuentas.py
"""
import base64
import io
import os
import subprocess
import sys
import unittest
from contextlib import contextmanager, redirect_stdout
from unittest import mock

from cirdan import config as configuracion
from cirdan.auth import demo, passwords

LOCALES = 'http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000'
PUBLICADO = 'https://portal.ejemplo.test'
VARIABLES = ('DEMO_ACCOUNTS', 'ALLOWED_ORIGINS')


class BaseFalsa:
    """Hace de cirdan.db.transaction: no abre conexión y guarda cada consulta."""

    def __init__(self):
        self.consultas = []

    @contextmanager
    def transaction(self, org=None):
        yield self

    def execute(self, sql, parametros=()):
        self.consultas.append((sql, parametros))


@contextmanager
def entorno(**variables):
    """Solo las `variables` dadas, sin las del contenedor ni las de un `.env`. La llave TOTP es al azar."""
    limpio = {k: v for k, v in os.environ.items() if k not in VARIABLES}
    limpio['TOTP_ENCRYPTION_KEY'] = base64.urlsafe_b64encode(os.urandom(32)).decode()
    limpio.update(variables)
    with mock.patch.dict(os.environ, limpio, clear=True), mock.patch.object(configuracion, '_env_file', dict):
        yield


def correr(**variables):
    """Corre el script como `python -m cirdan.auth.demo` con una base falsa. Da las consultas y lo que imprimió."""
    base, salida = BaseFalsa(), io.StringIO()
    with entorno(**variables), mock.patch.object(demo, 'transaction', base.transaction), redirect_stdout(salida):
        demo.main(['demo'])
    return base.consultas, salida.getvalue()


class OrigenesPublicados(unittest.TestCase):
    def publicados(self, valor):
        variables = {} if valor is None else {'ALLOWED_ORIGINS': valor}
        with entorno(**variables):
            return demo.origenes_publicados()

    def test_1_sin_la_variable_o_vacia_vale_la_lista_local(self):
        for valor in (None, '', '  ', ',', ' , '):
            with self.subTest(valor=valor):
                self.assertEqual(self.publicados(valor), [])

    def test_2_localhost_y_127_0_0_1_no_son_publicados(self):
        for valor in (LOCALES, 'http://localhost:3000', ' http://127.0.0.1:8000 , http://localhost:3000 ',
                      'https://localhost', 'HTTP://LOCALHOST:3000', 'http://localhost:3000,'):
            with self.subTest(valor=valor):
                self.assertEqual(self.publicados(valor), [])

    def test_3_un_origen_publicado_sale_aunque_venga_con_locales(self):
        self.assertEqual(self.publicados(PUBLICADO), [PUBLICADO])
        self.assertEqual(self.publicados(LOCALES + ',' + PUBLICADO), [PUBLICADO])
        self.assertEqual(self.publicados(' %s , http://localhost:3000' % PUBLICADO), [PUBLICADO])
        self.assertEqual(self.publicados('http://10.0.0.5:3000'), ['http://10.0.0.5:3000'])

    def test_4_lo_que_parece_local_y_no_lo_es_cuenta_como_publicado(self):
        for valor in ('http://localhost.ejemplo.test', 'http://localhost@ejemplo.test', 'http://127.0.0.1.ejemplo.test',
                      'http://127.0.0.10:3000', 'http://[::1]:3000', 'http://0.0.0.0:3000', 'http://localhost.:3000'):
            with self.subTest(valor=valor):
                self.assertEqual(self.publicados(valor), [valor])

    def test_5_lo_que_no_se_lee_como_origen_cuenta_como_publicado(self):
        for valor in ('localhost:3000', '127.0.0.1:3000', 'localhost', '*', 'ftp://localhost', '//localhost:3000',
                      'http://[::1', 'null'):
            with self.subTest(valor=valor):
                self.assertEqual(self.publicados(valor), [valor])

    def test_5b_una_lista_mal_separada_o_un_origen_con_algo_de_mas_cuenta_como_publicado(self):
        for valor in ('http://localhost:3000 https://portal.ejemplo.test', 'http://localhost:3000;https://x.test',
                      'http://localhost:3000;x', 'http://localhost:3000/ https://x.test',
                      'http://localhost:3000\thttps://x.test', 'http://localhost:3000https://x.test',
                      'http://localhost:3000/', 'http://localhost:3000/ruta', 'http://localhost:3000?x=1',
                      'http://localhost:3000#x', 'http://usuario@localhost:3000', 'http://localhost:',
                      'http://localhost:abc', 'http://localhost:03000', 'http://localhost:99999',
                      'http://127.0.0.1:8000 http://10.0.0.5'):
            with self.subTest(valor=valor):
                self.assertEqual(self.publicados(valor), [valor])


class Script(unittest.TestCase):
    def assertApagadas(self, consultas, salida):
        """Un UPDATE por cuenta, con el hash de relleno y sin secreto TOTP, y un aviso por cuenta."""
        self.assertEqual(len(consultas), len(demo.CUENTAS))
        for sql, parametros in consultas:
            self.assertTrue(sql.startswith('UPDATE users SET password_hash = %s, totp_secret_enc = NULL, '), sql)
            self.assertIn('mfa_enabled_at = NULL', sql)
            self.assertEqual(parametros[0], demo.HASH_DE_RELLENO)
        self.assertEqual(sorted(parametros[1] for _, parametros in consultas),
                         sorted(user_id for _, user_id, _ in demo.CUENTAS.values()))
        self.assertEqual(salida.count('cuenta de demo apagada:'), len(demo.CUENTAS))
        self.assertNotIn('cuenta de demo lista', salida)

    def test_6_con_origenes_locales_cambia_las_cinco_cuentas(self):
        for variables in ({'DEMO_ACCOUNTS': 'true'}, {'DEMO_ACCOUNTS': 'true', 'ALLOWED_ORIGINS': LOCALES},
                          {'DEMO_ACCOUNTS': 'TRUE', 'ALLOWED_ORIGINS': ''}):
            with self.subTest(variables=variables):
                consultas, salida = correr(**variables)
                self.assertEqual(len(consultas), len(demo.CUENTAS))
                self.assertTrue(all(sql.startswith('UPDATE users SET password_hash') for sql, _ in consultas))
                self.assertEqual(sorted(parametros[2] for _, parametros in consultas),
                                 sorted(user_id for _, user_id, _ in demo.CUENTAS.values()))
                self.assertEqual(salida.count('cuenta de demo lista:'), len(demo.CUENTAS))

    def test_7_con_un_origen_publicado_apaga_las_cinco_cuentas(self):
        for origenes in (PUBLICADO, LOCALES + ',' + PUBLICADO, 'localhost:3000',
                         'http://localhost:3000 ' + PUBLICADO, 'http://localhost:3000;' + PUBLICADO):
            with self.subTest(origenes=origenes):
                consultas, salida = correr(DEMO_ACCOUNTS='true', ALLOWED_ORIGINS=origenes)
                self.assertApagadas(consultas, salida)
                self.assertIn('ALLOWED_ORIGINS', salida)
                self.assertIn('se apagan las cuentas de demo', salida)

    def test_8_el_aviso_nombra_el_origen_que_lo_freno_y_no_los_locales(self):
        _, salida = correr(DEMO_ACCOUNTS='true', ALLOWED_ORIGINS=LOCALES + ',' + PUBLICADO)
        self.assertEqual(salida.splitlines()[0],
                         'ALLOWED_ORIGINS trae un origen que no es localhost ni 127.0.0.1 (%s): se apagan las cuentas '
                         'de demo, aunque DEMO_ACCOUNTS sea true. Un origen local se escribe sin barra final ni ruta, '
                         'como http://localhost:3000.' % PUBLICADO)

    def test_8b_un_origen_local_con_barra_final_tambien_frena_y_el_aviso_dice_como_escribirlo(self):
        consultas, salida = correr(DEMO_ACCOUNTS='true', ALLOWED_ORIGINS='http://localhost:3000/')
        self.assertApagadas(consultas, salida)
        self.assertIn('(http://localhost:3000/)', salida)
        self.assertIn('sin barra final ni ruta', salida)

    def test_9_sin_demo_accounts_en_true_apaga_las_cinco_cuentas(self):
        # Un volumen que ya traía las credenciales públicas (plan B del despliegue en una PC de desarrollo) deja de
        # servir para entrar (hallazgos 1 y 11 de la revisión de RC-91).
        for variables in ({}, {'DEMO_ACCOUNTS': 'false'}, {'DEMO_ACCOUNTS': ''}, {'DEMO_ACCOUNTS': '1'},
                          {'DEMO_ACCOUNTS': 'false', 'ALLOWED_ORIGINS': PUBLICADO},
                          {'DEMO_ACCOUNTS': 'false', 'ALLOWED_ORIGINS': LOCALES}):
            with self.subTest(variables=variables):
                consultas, salida = correr(**variables)
                self.assertApagadas(consultas, salida)
                self.assertEqual(salida.splitlines()[0], 'DEMO_ACCOUNTS no es true: se apagan las cuentas de demo.')

    def test_9b_el_hash_de_relleno_no_deja_entrar_con_ninguna_contrasena(self):
        for intento in (demo.PASSWORD, 'lowtide-relleno-que-nunca-coincide', '', 'demo-only'):
            with self.subTest(intento=intento):
                self.assertFalse(passwords.verify_password(demo.HASH_DE_RELLENO, intento))

    def test_9c_poner_y_apagar_tocan_las_mismas_cuentas(self):
        puestas, _ = correr(DEMO_ACCOUNTS='true')
        apagadas, _ = correr(DEMO_ACCOUNTS='false')
        self.assertEqual(sorted(p[2] for _, p in puestas), sorted(p[1] for _, p in apagadas))

    def test_10_el_codigo_totp_sigue_saliendo_y_no_toca_la_base(self):
        base, salida = BaseFalsa(), io.StringIO()
        with entorno(DEMO_ACCOUNTS='true', ALLOWED_ORIGINS=PUBLICADO), \
                mock.patch.object(demo, 'transaction', base.transaction), redirect_stdout(salida):
            demo.main(['demo', 'codigo', 'Alex.Morgan@acme-demo.mx'])
        self.assertRegex(salida.getvalue().strip(), r'^\d{6}$')
        self.assertEqual(base.consultas, [])


class ComoProceso(unittest.TestCase):
    """El módulo de verdad, como lo corre el compose, contra un puerto de 127.0.0.1 donde no escucha nadie: como
    siempre toca las cuentas (para ponerlas o para apagarlas), la conexión falla y sale con error. Así el servicio
    demo-accounts no termina bien sin haber apagado las cuentas, y la API, que lo espera, no arranca."""

    def correr(self, **variables):
        limpio = {k: v for k, v in os.environ.items() if k not in VARIABLES}
        limpio.update(variables, PGHOST='127.0.0.1', PGPORT='1', CIRDAN_APP_PASSWORD='sin-uso',
                      TOTP_ENCRYPTION_KEY=base64.urlsafe_b64encode(os.urandom(32)).decode())
        return subprocess.run([sys.executable, '-m', 'cirdan.auth.demo'], env=limpio, capture_output=True, text=True,
                              timeout=60)

    def test_11_con_un_origen_publicado_o_sin_true_va_a_la_base_a_apagarlas(self):
        for variables in ({'DEMO_ACCOUNTS': 'true', 'ALLOWED_ORIGINS': PUBLICADO}, {'DEMO_ACCOUNTS': 'false'}):
            with self.subTest(variables=variables):
                proc = self.correr(**variables)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn('se apagan las cuentas de demo', proc.stdout)
                self.assertIn('OperationalError', proc.stderr)

    def test_12_con_origenes_locales_si_va_a_la_base(self):
        proc = self.correr(DEMO_ACCOUNTS='true', ALLOWED_ORIGINS=LOCALES)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('OperationalError', proc.stderr)


if __name__ == '__main__':
    unittest.main()
