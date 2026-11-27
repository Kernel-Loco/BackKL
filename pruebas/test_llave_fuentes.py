"""Pruebas de la llave de HIBP cifrada en la base y del paso de HIBP por el orquestador (#19, RC-54), sin red.

Necesitan psycopg y cryptography, así que corren dentro del contenedor de la API, con la base levantada y la migración
032:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_llave_fuentes.py

Cada prueba con base corre en una transacción que se deshace al final: la base queda igual. HIBP se simula con un
transporte falso y un reloj simulado: nunca sale a la red. La llave es la de prueba de HIBP (32 ceros) o una falsa con
el prefijo CIRDAN_FAKE_. La de guardar una llave en data_sources entra como postgres y se salta sin POSTGRES_PASSWORD
(como en test_orquestador.py).

Hecho cuando de RC-54 que cubren: la llave va cifrada en data_sources.api_key_enc con su migración (una función
SECURITY DEFINER para leerla) y la llave de cifrado en el .env como la del MFA, las contraseñas nunca se guardan, y
sin llave la fuente queda sin cobertura, nunca en 0.
"""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import psycopg
from psycopg.rows import dict_row

from cirdan import orquestador, planes
from cirdan.db import DSN
from cirdan.recolectores import hibp, identidad, llaves
from cirdan.recolectores.contrato import Activo, Resultado
from pruebas.test_orquestador import ACME, TXT_ACME, conexion_postgres, correo, renovar_carta, responde
from pruebas.test_orquestador import resultado_github

CLAVE = base64.urlsafe_b64encode(bytes(range(32))).decode()       # llave de cifrado de prueba, no es la del .env
OTRA_CLAVE = base64.urlsafe_b64encode(bytes(range(1, 33))).decode()
LLAVE_PRUEBA = '0' * 32                                           # la llave de prueba de HIBP
LLAVE_FALSA = 'CIRDAN_FAKE_hibp_llave_0123456789'
TODAS = list(range(1, 12))                                        # actividades 1 a 11 de la plantilla 1

BRECHAS = {
    'Adobe': {'Name': 'Adobe', 'Title': 'Adobe', 'BreachDate': '2013-10-04', 'IsVerified': True,
              'DataClasses': ['Email addresses', 'Passwords'], 'Description': 'NO SE GUARDA', 'PwnCount': 152445165},
    'Nombres': {'Name': 'Nombres', 'Title': 'Nombres', 'BreachDate': '2026-06-01', 'IsVerified': True,
                'DataClasses': ['Email addresses', 'Names']},
}


def con_clave(valor=CLAVE):
    return mock.patch.dict(os.environ, {llaves.VARIABLE: valor})


class Reloj:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def dormir(self, s):
        self.t += s


class HibpSimulado:
    """Transporte falso de HIBP: el dominio responde `dominio` (200 con alias o un código) y cada correo sus brechas."""

    def __init__(self, dominio=200, alias=None, cuentas=None):
        self.dominio, self.alias, self.cuentas = dominio, alias or {'ana': ['Adobe'], 'beto': ['Nombres']}, cuentas or {}
        self.vistas = []

    def __call__(self, url, cabeceras, timeout):
        self.vistas.append((url, dict(cabeceras)))
        ruta = url[len(hibp.URL):]
        if ruta.startswith('breacheddomain/'):
            if self.dominio != 200:
                return self.dominio, None, b''
            return 200, None, json.dumps(self.alias).encode()
        if ruta.startswith('breach/'):
            return 200, None, json.dumps(BRECHAS[ruta.split('/', 1)[1]]).encode()
        if ruta.startswith('breachedaccount/'):
            cuenta = ruta.split('/', 1)[1].split('?')[0].replace('%40', '@')
            nombres = self.cuentas.get(cuenta)
            return (404, None, b'') if nombres is None else (200, None, json.dumps([BRECHAS[n] for n in nombres]).encode())
        raise AssertionError(ruta)


class Cifrado(unittest.TestCase):

    def test_1_ida_y_vuelta(self):
        with con_clave():
            blob = llaves.cifrar('hibp', LLAVE_PRUEBA)
            self.assertEqual(blob[0], llaves.VERSION)
            self.assertNotIn(LLAVE_PRUEBA.encode(), blob)
            self.assertEqual(llaves.descifrar('hibp', blob), LLAVE_PRUEBA)
            self.assertEqual(llaves.descifrar('hibp', memoryview(blob)), LLAVE_PRUEBA)  # así llega un bytea
            self.assertNotEqual(llaves.cifrar('hibp', LLAVE_PRUEBA), blob)  # nonce nuevo en cada cifrado

    def test_2_el_valor_de_otra_fuente_no_abre(self):
        with con_clave():
            blob = llaves.cifrar('shodan', LLAVE_FALSA)
            with self.assertRaises(llaves.LlaveIlegible) as e:
                llaves.descifrar('hibp', blob)
        self.assertNotIn(LLAVE_FALSA, str(e.exception))

    def test_3_otra_clave_o_un_byte_cambiado_no_abren(self):
        with con_clave():
            blob = llaves.cifrar('hibp', LLAVE_FALSA)
        roto = blob[:-1] + bytes([blob[-1] ^ 1])
        for clave, valor in ((OTRA_CLAVE, blob), (CLAVE, roto), (CLAVE, b'\x02' + blob[1:]), (CLAVE, blob[:20])):
            with self.subTest(valor=valor[:2]), con_clave(clave), self.assertRaises(llaves.LlaveIlegible) as e:
                llaves.descifrar('hibp', valor)
            self.assertNotIn(LLAVE_FALSA, str(e.exception))
            self.assertNotIn(valor.hex(), str(e.exception))

    def test_4_sin_clave_de_cifrado_o_mal_formada(self):
        for valor in ('', '   ', 'no-es-base64!', base64.urlsafe_b64encode(b'x' * 16).decode()):
            with self.subTest(valor=valor), con_clave(valor), self.assertRaises(llaves.LlaveIlegible) as e:
                llaves.cifrar('hibp', LLAVE_FALSA)
            self.assertIn(llaves.VARIABLE, str(e.exception))

    def test_5_llave_vacia_o_larga(self):
        with con_clave():
            for valor in ('', '   ', 'x' * (llaves.MAX_LLAVE + 1), None, 7):
                with self.subTest(valor=valor), self.assertRaises(ValueError):
                    llaves.cifrar('hibp', valor)

    def test_6_la_linea_de_comandos_no_muestra_la_llave(self):
        salida, errores = io.StringIO(), io.StringIO()
        with con_clave(), mock.patch.object(llaves.getpass, 'getpass', return_value=LLAVE_FALSA), \
                contextlib.redirect_stdout(salida), contextlib.redirect_stderr(errores):
            self.assertEqual(llaves._main(['cifrar', 'hibp']), 0)
        self.assertNotIn(LLAVE_FALSA, salida.getvalue() + errores.getvalue())
        self.assertRegex(salida.getvalue(), r"^UPDATE data_sources SET api_key_enc = '\\x[0-9a-f]+'::bytea, "
                                            r"key_rotated_at = now\(\), updated_at = now\(\) WHERE code = 'hibp';\n$")
        blob = bytes.fromhex(salida.getvalue().split("'\\x")[1].split("'")[0])
        with con_clave():
            self.assertEqual(llaves.descifrar('hibp', blob), LLAVE_FALSA)
        self.assertEqual(llaves._main(['otra', 'hibp']), 2)


class Base(unittest.TestCase):
    """Conexión de cirdan_app en la organización Acme que se deshace al final."""

    def setUp(self):
        self.conn = psycopg.connect(DSN, row_factory=dict_row)
        self.tx = self.conn.transaction(force_rollback=True)
        self.tx.__enter__()
        self.conn.execute("SELECT set_config('app.current_org', %s, true)", (ACME,))
        renovar_carta(self.conn)

    def tearDown(self):
        self.tx.__exit__(None, None, None)
        self.conn.close()

    def uno(self, sql, *params):
        return self.conn.execute(sql, params).fetchone()


class Funcion(Base):

    def test_7_security_definer_con_search_path_y_solo_cirdan_app(self):
        f = self.uno(
            "SELECT p.prosecdef, p.provolatile, p.proconfig, pg_get_function_result(p.oid) AS resultado, "
            "has_function_privilege('cirdan_app', p.oid, 'EXECUTE') AS app, "
            # Sin proacl (NULL) PostgreSQL da EXECUTE a PUBLIC: se lee la ACL efectiva con acldefault
            "EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a "
            "         WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS publico "
            "FROM pg_proc p WHERE p.oid = 'public.source_api_key(text)'::regprocedure")
        self.assertTrue(f['prosecdef'])
        self.assertEqual(f['provolatile'], 's')
        self.assertEqual(f['proconfig'], ['search_path=pg_catalog, public, pg_temp'])
        self.assertEqual(f['resultado'], 'bytea')
        self.assertTrue(f['app'])
        self.assertFalse(f['publico'])  # PUBLIC sin EXECUTE

    def test_8_cirdan_app_no_lee_ni_escribe_la_columna(self):
        for sql in ('SELECT api_key_enc FROM data_sources', "UPDATE data_sources SET api_key_enc = '\\x00' "
                                                           "WHERE code = 'hibp'"):
            with self.subTest(sql=sql), self.assertRaises(psycopg.errors.InsufficientPrivilege), \
                    self.conn.transaction():
                self.conn.execute(sql)

    def test_9_sin_llave_guardada_o_fuente_que_no_existe(self):
        self.assertIsNone(llaves.leer(self.conn, 'no-existe'))
        self.assertIsNone(self.uno("SELECT public.source_api_key('no-existe') AS llave")['llave'])

    def test_10_guardada_por_postgres_se_lee_y_apagada_no(self):
        with conexion_postgres() as pg, pg.transaction(force_rollback=True), con_clave():
            pg.execute("SELECT set_config('app.current_org', %s, true)", (ACME,))
            # No da por hecho que la base no tenga llave: una base con la llave real también pasa
            pg.execute("UPDATE data_sources SET api_key_enc = NULL WHERE code = 'hibp'")
            self.assertIsNone(llaves.leer(pg, 'hibp'))
            pg.execute("UPDATE data_sources SET api_key_enc = %s, key_rotated_at = now() WHERE code = 'hibp'",
                       (llaves.cifrar('hibp', LLAVE_PRUEBA),))
            self.assertEqual(llaves.leer(pg, 'hibp'), LLAVE_PRUEBA)
            # cirdan_app no lee la columna, pero sí la llave por la función SECURITY DEFINER
            pg.execute('SET LOCAL ROLE cirdan_app')
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), pg.transaction():
                pg.execute('SELECT api_key_enc FROM data_sources')
            self.assertEqual(llaves.leer(pg, 'hibp'), LLAVE_PRUEBA)
            pg.execute('RESET ROLE')
            pg.execute("UPDATE data_sources SET enabled = false WHERE code = 'hibp'")
            self.assertIsNone(llaves.leer(pg, 'hibp'))


class Orquestador(Base):
    """HIBP por el orquestador con su transporte falso: llave, correos, brechas y cobertura."""

    def setUp(self):
        super().setUp()
        # Sin el tope de escaneos a mano (RC-297): aquí se piden varios del mismo dominio en una prueba. El tope y
        # su lugar en solicitar() los prueba pruebas/test_planes.py.
        sin_tope = mock.patch.object(planes, 'check_plan_limits', return_value=None)
        sin_tope.start()
        self.addCleanup(sin_tope.stop)

    def correr(self, transporte, llave=LLAVE_PRUEBA, leer=None):
        s = orquestador.solicitar(ACME, 'acme-demo.mx', consultar=responde(TXT_ACME), conn=self.conn)
        reloj = Reloj()
        carpeta = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__('shutil').rmtree(carpeta, ignore_errors=True))

        def cliente(modo, dominio):
            return hibp.ClienteHibp(modo, carpeta, descargar=transporte, dormir=reloj.dormir, reloj=reloj)
        with mock.patch.object(hibp, 'crear_cliente', cliente), \
                mock.patch.object(orquestador, 'en_vivo_permitido', lambda fqdn: True), \
                mock.patch.object(llaves, 'leer', leer or (lambda conn, codigo: llave)):
            resumen = orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['hibp'], modo='vivo',
                                         conn=self.conn, dormir=reloj.dormir)
        return s, resumen

    def de_hibp(self, s):
        # Solo lo de este escaneo: la semilla 001 ya trae un hallazgo de HIBP en acme-demo.mx (DemoBreach-2026)
        return self.conn.execute(
            "SELECT f.id, f.status, f.evidence, r.code, b.breach_name, b.breach_date::text AS fecha, b.data_classes "
            "FROM findings f JOIN data_sources d ON d.id = f.source_id JOIN scoring_rules r ON r.id = f.rule_id "
            "LEFT JOIN breach_exposures b ON b.finding_id = f.id "
            "WHERE f.domain_id = %s AND f.last_scan_id = %s AND f.status = 'open' AND d.code = 'hibp' ORDER BY b.breach_name",
            (s.domain_id, s.scan_id)).fetchall()

    def corrida(self, scan_id):
        return self.uno("SELECT r.status, r.raw_payload, r.error FROM scan_source_runs r JOIN data_sources d "
                        "ON d.id = r.source_id WHERE r.scan_id = %s AND d.code = 'hibp'", scan_id)

    def test_11_dominio_con_brechas_deja_su_fila_en_breach_exposures(self):
        t = HibpSimulado()
        s, resumen = self.correr(t)
        filas = self.de_hibp(s)
        self.assertEqual([(f['code'], f['breach_name'], f['fecha'], f['status']) for f in filas],
                         [('breach_exposure_old', 'Adobe', '2013-10-04', 'open'),
                          ('breach_exposure_no_passwords', 'Nombres', '2026-06-01', 'open')])
        self.assertEqual(filas[0]['data_classes'], ['Email addresses', 'Passwords'])
        texto = json.dumps([f['evidence'] for f in filas])
        for nunca in ('NO SE GUARDA', '152445165', LLAVE_PRUEBA):
            self.assertNotIn(nunca, texto)
        self.assertEqual(filas[0]['evidence']['emails'], ['ana@acme-demo.mx'])
        self.assertIn('Have I Been Pwned', filas[0]['evidence']['attribution'])
        c = self.corrida(s.scan_id)
        self.assertEqual((c['status'], c['raw_payload']), ('succeeded', None))   # keep_raw_payload es false
        # La llave va solo en la cabecera de las consultas que la piden. /breach/{nombre} es pública: va sin llave
        self.assertTrue(all((cab.get('hibp-api-key') == LLAVE_PRUEBA) != ('/breach/' in u) for u, cab in t.vistas))
        self.assertTrue(all(LLAVE_PRUEBA not in u for u, _ in t.vistas))
        # Otro escaneo con la misma brecha: el mismo hallazgo y la misma fila, al día
        BRECHAS['Nombres']['DataClasses'] = ['Email addresses', 'Names', 'Phone numbers']
        self.addCleanup(BRECHAS['Nombres'].__setitem__, 'DataClasses', ['Email addresses', 'Names'])
        s2, _ = self.correr(HibpSimulado())
        otra = self.de_hibp(s2)
        self.assertEqual([f['id'] for f in otra], [f['id'] for f in filas])
        self.assertEqual(otra[1]['data_classes'], ['Email addresses', 'Names', 'Phone numbers'])
        self.assertEqual(self.uno('SELECT count(*) AS n FROM breach_exposures WHERE finding_id = ANY(%s)',
                                  [f['id'] for f in filas])['n'], 2)

    def test_12_sin_llave_queda_sin_cobertura_por_llave_y_no_en_0(self):
        t = HibpSimulado()
        s, resumen = self.correr(t, llave=None)
        self.assertEqual(t.vistas, [])
        self.assertEqual(self.corrida(s.scan_id)['status'], 'succeeded')
        stats = self.uno('SELECT stats FROM scans WHERE id = %s', s.scan_id)['stats']
        self.assertEqual(sorted(stats['rules_without_key']), sorted(hibp.CODIGOS))
        self.assertTrue(set(hibp.CODIGOS) <= set(stats['rules_without_coverage']))
        self.assertEqual(self.de_hibp(s), [])

    def test_13_llave_ilegible_no_tumba_el_escaneo_ni_sale_en_el_log(self):
        def ilegible(conn, codigo):
            raise llaves.LlaveIlegible('la llave guardada de hibp no abre con %s' % llaves.VARIABLE)
        t = HibpSimulado()
        with self.assertLogs(orquestador.log, 'WARNING') as registro:
            s, _ = self.correr(t, leer=ilegible)
        self.assertEqual(t.vistas, [])
        self.assertIn('no se pudo leer la llave', '\n'.join(registro.output))
        stats = self.uno('SELECT stats FROM scans WHERE id = %s', s.scan_id)['stats']
        self.assertEqual(sorted(stats['rules_without_key']), sorted(hibp.CODIGOS))

    def test_14_correos_de_github_abiertos_y_solo_en_vivo_la_llave(self):
        s = orquestador.solicitar(ACME, 'acme-demo.mx', consultar=responde(TXT_ACME), conn=self.conn)
        with mock.patch.object(orquestador, 'ejecutar',
                               lambda *a, **k: resultado_github(correo('ana', 'r1'), correo('beto', 'r2'))):
            orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['github'], modo='reproducir', conn=self.conn)
        self.conn.execute(
            "UPDATE findings f SET status = 'false_positive' FROM assets a WHERE a.id = f.asset_id "
            "AND a.value = 'beto@acme-demo.mx'")
        with mock.patch.object(llaves, 'leer', side_effect=AssertionError('al reproducir no se lee')):
            extras = orquestador._extras(ACME, hibp, 'hibp', s.domain_id, 'reproducir', TODAS, self.conn)
        self.assertEqual(extras, {'correos': ['ana@acme-demo.mx'], 'correos_total': 1})
        with mock.patch.object(llaves, 'leer', return_value=LLAVE_PRUEBA):
            self.assertEqual(orquestador._extras(ACME, hibp, 'hibp', s.domain_id, 'vivo', TODAS, self.conn),
                             {'correos': ['ana@acme-demo.mx'], 'correos_total': 1, 'llave': LLAVE_PRUEBA})
        # Un recolector que no pide nada no recibe nada
        from cirdan.recolectores import ejemplo
        self.assertEqual(orquestador._extras(ACME, ejemplo, 'ejemplo', s.domain_id, 'vivo', TODAS, self.conn), {})
        # Dominio no verificado en HIBP (403): consulta solo el correo abierto
        t = HibpSimulado(dominio=403, cuentas={'ana@acme-demo.mx': ['Adobe']})
        s2, _ = self.correr(t)
        cuentas = [u for u, _ in t.vistas if 'breachedaccount/' in u]
        self.assertEqual(len(cuentas), 1)
        self.assertIn('ana%40acme-demo.mx', cuentas[0])
        filas = self.de_hibp(s2)
        self.assertEqual([(f['breach_name'], f['evidence']['emails']) for f in filas], [('Adobe', ['ana@acme-demo.mx'])])

    def identidad(self, *correos, estado='succeeded', revisados=None, sin_cobertura=()):
        """Un escaneo con solo identity, que da `correos` como activos email del dominio (como identidad.recolectar).
        Después corre el reloj: la prueba va en una sola transacción y now() no cambia, así que todas las corridas que
        ya existían se llevan una hora antes y la de este escaneo queda como la más reciente."""
        s = orquestador.solicitar(ACME, 'acme-demo.mx', consultar=responde(TXT_ACME), conn=self.conn)
        activos = [Activo('domain', 'acme-demo.mx')] + [
            Activo('email', c, {'identidad': {'origenes': ['sitio'], 'donde': ['https://acme-demo.mx/']}})
            for c in correos]
        res = Resultado('acme-demo.mx', 'identity', estado=estado, activos=activos, revisados=revisados,
                        sin_cobertura=list(sin_cobertura), error='' if estado == 'succeeded' else 'no respondió')
        self.conn.execute("UPDATE scan_source_runs SET finished_at = finished_at - interval '1 hour'")
        with mock.patch.object(orquestador, 'ejecutar', lambda *a, **k: res):
            orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=['identity'], modo='reproducir',
                               conn=self.conn)
        return s

    def correos(self, domain_id, modo='reproducir', actividades=TODAS):
        return orquestador._extras(ACME, hibp, 'hibp', domain_id, modo, actividades, self.conn)['correos']

    def github(self, *nombres):
        gh = orquestador.solicitar(ACME, 'acme-demo.mx', consultar=responde(TXT_ACME), conn=self.conn)
        with mock.patch.object(orquestador, 'ejecutar',
                               lambda *a, **k: resultado_github(*[correo(n, 'r%d' % i) for i, n in enumerate(nombres)])):
            orquestador.correr(ACME, gh.scan_id, 'acme-demo.mx', fuentes=['github'], modo='reproducir', conn=self.conn)
        return gh

    def test_15_correos_de_identidad_desde_su_ultima_corrida_completa(self):
        self.identidad('carla@acme-demo.mx', 'dani@ventas.acme-demo.mx', 'eva@acme-demo.mx')
        # La corrida completa más reciente ya no ve a eva: no se consulta aunque attributes.identidad siga en su
        # activo. dani es de un subdominio y sí entra.
        s = self.identidad('carla@acme-demo.mx', 'dani@ventas.acme-demo.mx')
        cobertura = self.uno("SELECT r.coverage, r.mode FROM scan_source_runs r WHERE r.scan_id = %s", s.scan_id)
        self.assertEqual((cobertura['coverage'], cobertura['mode']), ('complete', 'reproducir'))
        marca = self.uno("SELECT attributes->>'identidad_scan' AS scan, attributes ? 'identidad_scan_vivo' AS vivo "
                         "FROM assets WHERE value = 'carla@acme-demo.mx' AND asset_type = 'email'")
        self.assertEqual((marca['scan'], marca['vivo']), (str(s.scan_id), False))   # en reproducir, sin la de vivo
        self.assertEqual(self.correos(s.domain_id), ['carla@acme-demo.mx', 'dani@ventas.acme-demo.mx'])
        # Una corrida que falló no cuenta
        self.identidad(estado='failed')
        self.assertEqual(self.correos(s.domain_id), ['carla@acme-demo.mx', 'dani@ventas.acme-demo.mx'])
        # datos-2: una corrida parcial (el sitio de dani no se pudo leer) y una sin cobertura (el sitio caído) no
        # sacan lo que no revisaron. Lo nuevo de la parcial sí entra.
        p = self.identidad('carla@acme-demo.mx', 'fer@acme-demo.mx', revisados=['acme-demo.mx'])
        self.identidad(sin_cobertura=list(identidad.CODIGOS))
        self.assertEqual([r['coverage'] for r in self.conn.execute(
            "SELECT r.coverage FROM scan_source_runs r JOIN data_sources d ON d.id = r.source_id "
            "WHERE d.code = 'identity' AND r.status = 'succeeded' ORDER BY r.finished_at DESC LIMIT 2").fetchall()],
            ['none', 'partial'])
        self.assertEqual(self.correos(p.domain_id),
                         ['carla@acme-demo.mx', 'dani@ventas.acme-demo.mx', 'fer@acme-demo.mx'])
        # datos-3: HIBP sube last_seen_at de eva y une sus attributes, pero no cambia la marca de identity: no vuelve
        h = orquestador.solicitar(ACME, 'acme-demo.mx', consultar=responde(TXT_ACME), conn=self.conn)
        visto = Resultado('acme-demo.mx', 'hibp', activos=[
            Activo('domain', 'acme-demo.mx'), Activo('email', 'eva@acme-demo.mx', {'hibp_consultado': 'x'})])
        with mock.patch.object(orquestador, 'ejecutar', lambda *a, **k: visto):
            orquestador.correr(ACME, h.scan_id, 'acme-demo.mx', fuentes=['hibp'], modo='reproducir', conn=self.conn)
        self.assertNotIn('eva@acme-demo.mx', self.correos(p.domain_id))
        # La siguiente completa sin dani y sin fer los saca
        s = self.identidad('carla@acme-demo.mx')
        self.assertEqual(self.correos(s.domain_id), ['carla@acme-demo.mx'])
        # Junto con los de GitHub, sin repetir
        self.github('ana', 'carla')
        self.assertEqual(self.correos(s.domain_id), ['ana@acme-demo.mx', 'carla@acme-demo.mx'])
        # datos-1: el hallazgo de GitHub de carla, marcado como falso positivo, pasó a otro dominio de Acme (lo mueve
        # el upsert, la huella no lleva dominio). carla tampoco entra por identidad.
        otro = self.uno("SELECT id::text AS id FROM domains WHERE fqdn <> 'acme-demo.mx' ORDER BY fqdn LIMIT 1")
        self.assertIsNotNone(otro)
        movido = self.uno(
            "INSERT INTO assets (organization_id, domain_id, asset_type, value, attributes, first_seen_at, "
            "last_seen_at) VALUES (%s, %s, 'email', 'carla@acme-demo.mx', '{}', now(), now()) "
            "RETURNING id::text AS id", ACME, otro['id'])
        self.conn.execute(
            "UPDATE findings f SET status = 'false_positive', domain_id = %s, asset_id = %s FROM assets a "
            "WHERE a.id = f.asset_id AND a.domain_id = %s AND a.value = 'carla@acme-demo.mx'",
            (otro['id'], movido['id'], s.domain_id))
        self.assertEqual(self.correos(s.domain_id), ['ana@acme-demo.mx'])
        # base-5: un correo de otro dominio con la marca de una corrida de acme-demo.mx no entra en acme-demo.mx, y el
        # otro dominio no recibe los de acme-demo.mx
        self.conn.execute(
            "INSERT INTO assets (organization_id, domain_id, asset_type, value, attributes, first_seen_at, "
            "last_seen_at) VALUES (%s, %s, 'email', 'gus@acme-demo.mx', %s, now(), now())",
            (ACME, otro['id'], json.dumps({'identidad': {}, 'identidad_scan': str(s.scan_id)})))
        self.assertEqual(self.correos(s.domain_id), ['ana@acme-demo.mx'])
        self.assertEqual(self.correos(otro['id']), [])

    def test_17_alcance_de_la_carta_modo_y_orden_de_los_correos(self):
        vivo = self.identidad('carla@acme-demo.mx')
        self.github('ana')
        # datos-5: la corrida de identity en reproducir trae una grabación vieja con eva. En vivo cuenta la última
        # corrida en vivo; al reproducir cuentan todas. acme-demo.mx no está en DOMINIOS_EN_VIVO: la primera corrida
        # se pasa a vivo a mano, con la marca que _marcar_identidad le habría puesto.
        self.conn.execute("UPDATE scan_source_runs SET mode = 'vivo' WHERE scan_id = %s", (vivo.scan_id,))
        self.conn.execute("UPDATE assets SET attributes = attributes || "
                          "jsonb_build_object('identidad_scan_vivo', %s::text) WHERE value = 'carla@acme-demo.mx' AND asset_type = 'email'", (str(vivo.scan_id),))
        s = self.identidad('carla@acme-demo.mx', 'eva@acme-demo.mx')
        with mock.patch.object(llaves, 'leer', return_value=LLAVE_PRUEBA):
            self.assertEqual(self.correos(s.domain_id, modo='vivo'), ['ana@acme-demo.mx', 'carla@acme-demo.mx'])
        self.assertEqual(self.correos(s.domain_id), ['ana@acme-demo.mx', 'carla@acme-demo.mx', 'eva@acme-demo.mx'])
        # orden-4: sin la actividad 8 no van los de identidad, sin la 4 no van los de GitHub
        def sin(*quitar):
            return [a for a in TODAS if a not in quitar]
        self.assertEqual(self.correos(s.domain_id, actividades=sin(8)), ['ana@acme-demo.mx'])
        self.assertEqual(self.correos(s.domain_id, actividades=sin(4)), ['carla@acme-demo.mx', 'eva@acme-demo.mx'])
        self.assertEqual(self.correos(s.domain_id, actividades=sin(4, 8)), [])
        self.assertEqual(self.correos(s.domain_id, actividades=None), [])
        # datos-6: primero los que HIBP nunca consultó, luego los que hace más que no consulta
        for valor, hora in (('ana@acme-demo.mx', '2026-11-20T00:00:00Z'), ('eva@acme-demo.mx', '2026-11-01T00:00:00Z')):
            self.conn.execute("UPDATE assets SET attributes = attributes || "
                              "jsonb_build_object('hibp_consultado', %s::text) WHERE domain_id = %s AND value = %s", (hora, s.domain_id, valor))
        self.assertEqual(self.correos(s.domain_id), ['carla@acme-demo.mx', 'eva@acme-demo.mx', 'ana@acme-demo.mx'])
        # El total cuenta los que había antes del tope
        with mock.patch.object(orquestador, 'MAX_CORREOS', 1):
            extras = orquestador._extras(ACME, hibp, 'hibp', s.domain_id, 'reproducir', TODAS, self.conn)
        self.assertEqual((extras['correos'], extras['correos_total']), (['carla@acme-demo.mx'], 3))

    def test_18_cobertura_de_la_corrida(self):
        def r(**k):
            return Resultado('acme-demo.mx', 'identity', **k)
        self.assertEqual(orquestador.cobertura(r(), identidad), 'complete')
        # Un código sin llave no la hace parcial: revisó todas sus partes
        self.assertEqual(orquestador.cobertura(r(sin_cobertura=['personal_email_exposed']), identidad), 'complete')
        self.assertEqual(orquestador.cobertura(r(revisados=['acme-demo.mx']), identidad), 'partial')
        self.assertEqual(orquestador.cobertura(r(revisados=[]), identidad), 'partial')
        self.assertEqual(orquestador.cobertura(r(sin_cobertura=list(identidad.CODIGOS)), identidad), 'none')
        self.assertIsNone(orquestador.cobertura(r(estado='failed', error='x'), identidad))
        # Solo identity lleva la marca del escaneo, y solo en sus correos
        res = r(activos=[Activo('email', 'a@acme-demo.mx', {'identidad': {'origenes': []}}),
                         Activo('profile', 'https://github.com/a', {'identidad': {'red': 'github'}})])
        orquestador._marcar_identidad(res, 'identity', 'S1', 'vivo')
        self.assertEqual(res.activos[0].atributos, {'identidad': {'origenes': []}, 'identidad_scan': 'S1',
                                                    'identidad_scan_vivo': 'S1'})
        self.assertEqual(res.activos[1].atributos, {'identidad': {'red': 'github'}})
        orquestador._marcar_identidad(res, 'identity', 'S2', 'reproducir')
        self.assertEqual((res.activos[0].atributos['identidad_scan'], res.activos[0].atributos['identidad_scan_vivo']),
                         ('S2', 'S1'))
        otro = Resultado('acme-demo.mx', 'github', activos=[Activo('email', 'b@acme-demo.mx', {'identidad': {}})])
        orquestador._marcar_identidad(otro, 'github', 'S1', 'vivo')
        self.assertEqual(otro.activos[0].atributos, {'identidad': {}})

    def test_16_hibp_corre_al_final_y_lee_los_correos_de_este_escaneo(self):
        # github, identity y hibp se siembran encendidas (semillas 006, 026 y 001)
        fuentes = orquestador.fuentes_activas(self.conn)
        self.assertEqual(fuentes[-1], 'hibp')
        self.assertEqual(fuentes[:-1], sorted(fuentes[:-1]))   # las demás siguen en orden de code
        self.assertTrue({'github', 'identity'} <= set(fuentes))
        # orden-5: un módulo que no se importa se queda en su lugar y falla en su turno, sin tumbar fuentes_activas
        real = orquestador.cargar

        def cargar(codigo):
            if codigo == 'github':
                raise ImportError('falta una dependencia')
            return real(codigo)
        with mock.patch.object(orquestador, 'cargar', cargar):
            self.assertEqual(orquestador.fuentes_activas(self.conn), fuentes)
        # En el escaneo normal (sin fuentes), HIBP recibe el correo que identity guardó antes en ese mismo escaneo
        s = orquestador.solicitar(ACME, 'acme-demo.mx', consultar=responde(TXT_ACME), conn=self.conn)
        orden, vistos = [], {}

        def ejecutar(modulo, fqdn, modo, **k):
            orden.append(modulo.FUENTE)
            if modulo.FUENTE == 'identity':
                return Resultado(fqdn, 'identity', activos=[
                    Activo('domain', fqdn),
                    Activo('email', 'fer@acme-demo.mx', {'identidad': {'origenes': ['sitio'], 'donde': []}})])
            if modulo.FUENTE == 'hibp':
                vistos['correos'] = list(k['extras'].get('correos', []))
            return Resultado(fqdn, modulo.FUENTE)
        with mock.patch.object(orquestador, 'ejecutar', ejecutar):
            orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', modo='reproducir', conn=self.conn)
        self.assertEqual(orden[-1], 'hibp')
        self.assertIn('fer@acme-demo.mx', vistos['correos'])


if __name__ == '__main__':
    unittest.main()
