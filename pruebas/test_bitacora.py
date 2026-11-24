"""Bitácora visible con "verificar integridad" (#86, RC-130) contra la API y la base locales (biblioteca estándar).

    python -m unittest -v pruebas/test_bitacora.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)

Hecho cuando de RC-130: la API lista la bitácora de la empresa (con RLS) y recalcula su cadena de hashes, y responde
'integra' o el primer eslabón roto. Prueba: en una copia de la base, alterar una fila con los triggers apagados rompe
la verificación (CopiaDeLaBase). La base del compose nunca se altera: la copia se crea y se borra aquí, y cada caso va
en una transacción que se deshace.

Además, del comentario de RC-332 (Ernesto, 16 nov): las filas con actor 'platform' del superadmin salen en la empresa
donde ocurrieron, sin su correo, y entran en la cadena (test_4). Decisiones de la tarjeta: solo el Admin (test_2), la
forma de AuditEntry del portal (FrontKL, src/types/api.ts) y verificar no escribe en la bitácora (test_3).

Dana es superadmin solo durante test_4, y las llaves que se crean se llaman CIRDAN_FAKE_... y se borran al terminar.
"""
import json
import subprocess
import time
import unittest

from cirdan import bitacora
from pruebas import sesion
from pruebas.pila import exigir_desechable
from pruebas.sesion import Client
from pruebas.test_aislamiento import ACME, BETA, CONTAINER, scalar
from pruebas.test_llaves_api import borrar_llaves
from pruebas.test_superadmin import (ALEX, CADENA, CAMBIO, DANA, DANA_ID, JORDAN, MAYA, hacer_superadmin,
                                     quitar_superadmin)

LISTA = '/api/v1/audit-log'
VERIFICAR = '/api/v1/audit-log/verify'
SIN_PERMISO = 'Tu rol no tiene permiso para esta acción.'
CAMPOS_PORTAL = {'id', 'occurred_at', 'actor_type', 'actor', 'action', 'entity_type', 'details'}  # AuditEntry
CAMPOS = CAMPOS_PORTAL | {'chain_seq', 'entity_id', 'ip_address'}
COPIA = 'cirdan_copia_86'


def contar(org):
    """Filas y último chain_seq de la bitácora de esa empresa, vistos como postgres."""
    filas, ultimo = scalar("SELECT count(*) || ',' || coalesce(max(chain_seq), 0) FROM audit_log"
                           " WHERE organization_id = '%s';" % org, user='postgres').split(',')
    return int(filas), int(ultimo)


def verificar_en_base(org, base='cirdan', antes=''):
    """VERIFICAR_SQL como postgres en esa base y esa empresa, en una transacción que se deshace. Con `antes`, lo corre
    primero con los triggers de usuario de audit_log apagados (solo en la copia: el ALTER toma un candado exclusivo).
    Da (revisadas, último chain_seq, chain_seq roto, motivo), con None donde no hay."""
    if antes:
        antes = 'ALTER TABLE audit_log DISABLE TRIGGER USER;\n' + antes
    sql = ("BEGIN;\n%s\nSELECT set_config('app.current_org', '%s', true);\n"
           "SELECT checked || '|' || coalesce(last_chain_seq::text, '-') || '|' || coalesce(broken_seq::text, '-')"
           " || '|' || coalesce(broken_reason, '-') FROM (%s) v;\nROLLBACK;" % (antes, org, bitacora.VERIFICAR_SQL))
    salida = postgres_en(base, sql).splitlines()[-1]
    return tuple(None if v == '-' else (v if i == 3 else int(v)) for i, v in enumerate(salida.split('|')))


def postgres_en(base, sql):
    exigir_desechable()
    proc = subprocess.run(['docker', 'exec', '-i', CONTAINER, 'psql', '-U', 'postgres', '-d', base,
                           '-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1'],
                          input=sql, capture_output=True, text=True, encoding='utf-8')
    if proc.returncode != 0:
        raise AssertionError(proc.stderr.strip())
    return proc.stdout.strip()


class Bitacora(unittest.TestCase):
    """GET /api/v1/audit-log y /audit-log/verify con las cuentas de demo."""

    @classmethod
    def setUpClass(cls):
        cls.addClassCleanup(borrar_llaves)
        cls.addClassCleanup(quitar_superadmin, DANA_ID)
        sesion.reset()
        cls.alex = sesion.login(ALEX)

    def test_1_el_admin_lee_la_bitacora_de_su_empresa_con_la_forma_del_portal(self):
        code, body = self.alex.get(LISTA)
        self.assertEqual(code, 200, body)
        filas, _ = contar(ACME)
        self.assertEqual((body['total'], body['limit'], body['offset']), (filas, 500, 0))
        self.assertEqual(len(body['items']), min(filas, 500))
        seqs = [i['chain_seq'] for i in body['items']]
        self.assertEqual(seqs, sorted(seqs, reverse=True))  # de la más nueva a la más vieja
        for item in body['items']:
            self.assertEqual(set(item), CAMPOS)
            self.assertIsInstance(item['id'], str)
            self.assertIsInstance(item['occurred_at'], str)
            self.assertIn(item['actor_type'], ('user', 'system', 'api_key', 'platform'))
            self.assertIsInstance(item['details'], dict)
            if item['actor_type'] == 'user':
                self.assertIn('@', item['actor'])
            elif item['actor_type'] in ('system', 'platform'):
                self.assertIsNone(item['actor'])
        # El inicio de sesión de Alex está y lleva su correo.
        login = next(i for i in body['items'] if i['action'] == 'auth.login_succeeded')
        self.assertEqual((login['actor_type'], login['actor']), ('user', ALEX))
        # Ninguna fila es de otra empresa.
        ids = ','.join("'%s'" % i['id'] for i in body['items'])
        self.assertEqual(scalar("SELECT count(*) FROM audit_log WHERE id IN (%s) AND organization_id <> '%s';"
                                % (ids, ACME), user='postgres'), '0')

    def test_2_solo_el_admin_con_sesion_y_rangos(self):
        for email in (MAYA, JORDAN):
            cliente = sesion.login(email)
            for ruta in (LISTA, VERIFICAR):
                with self.subTest(email=email, ruta=ruta):
                    self.assertEqual(cliente.get(ruta), (403, {'detail': SIN_PERMISO}))
        for ruta in (LISTA, VERIFICAR):
            with self.subTest(ruta=ruta, sin='sesión'):
                self.assertEqual(Client().get(ruta)[0], 401)
        # Una llave de API de Beta (plan con API) no entra: estas rutas piden la cookie de sesión.
        dana = sesion.login(DANA)
        code, llave = dana.post('/api/v1/api-keys', {'own_use': True, 'name': 'CIRDAN_FAKE_bitacora'})
        self.assertEqual(code, 201, llave)
        for ruta in (LISTA, VERIFICAR):
            with self.subTest(ruta=ruta, con='llave'):
                self.assertEqual(Client().get(ruta, headers={'Authorization': 'Bearer ' + llave['key']})[0], 401)
        for consulta in ('limit=0', 'limit=1001', 'offset=-1', 'offset=1000001', 'limit=x'):
            with self.subTest(consulta=consulta):
                self.assertEqual(self.alex.get(LISTA + '?' + consulta)[0], 422)
        code, pagina = self.alex.get(LISTA + '?limit=2&offset=1')
        self.assertEqual(code, 200, pagina)
        _, todo = self.alex.get(LISTA)
        self.assertEqual((pagina['limit'], pagina['offset'], pagina['total']), (2, 1, todo['total']))
        self.assertEqual([i['id'] for i in pagina['items']], [i['id'] for i in todo['items'][1:3]])

    def test_3_la_cadena_de_la_base_esta_integra_y_verificar_no_escribe(self):
        antes = contar(ACME)
        code, body = self.alex.get(VERIFICAR)
        self.assertEqual(code, 200, body)
        self.assertEqual(set(body), {'status', 'checked', 'last_chain_seq', 'first_broken', 'verified_at'})
        self.assertEqual((body['status'], body['first_broken']), ('intact', None))
        self.assertEqual((body['checked'], body['last_chain_seq']), antes)
        self.assertEqual(contar(ACME), antes)  # verificar es una lectura
        # Lo mismo que la fórmula de test_superadmin.py, en las dos empresas.
        for org in (ACME, BETA):
            with self.subTest(org=org):
                self.assertEqual(scalar(CADENA % org, user='postgres'), 't')
                self.assertEqual(verificar_en_base(org)[2:], (None, None))

    def test_4_el_superadmin_sale_sin_correo_y_entra_en_la_cadena(self):
        hacer_superadmin(DANA_ID)
        dana = sesion.login(DANA)
        try:
            self.assertEqual(dana.post(CAMBIO, {'organization_id': ACME})[0], 200)
            # En Acme el superadmin entra como admin: también lee la bitácora de esa empresa.
            self.assertEqual(dana.get(LISTA + '?limit=1')[0], 200)
        finally:
            quitar_superadmin(DANA_ID)
        code, body = self.alex.get(LISTA + '?limit=50')
        self.assertEqual(code, 200, body)
        fila = next(i for i in body['items'] if i['action'] == 'platform.organization_entered')
        self.assertEqual((fila['actor_type'], fila['actor'], fila['details']['platform_user_id']),
                         ('platform', None, DANA_ID))
        self.assertNotIn(DANA, json.dumps(body))
        code, verificado = self.alex.get(VERIFICAR)
        self.assertEqual((code, verificado['status']), (200, 'intact'))
        self.assertGreaterEqual(verificado['last_chain_seq'], fila['chain_seq'])


class CopiaDeLaBase(unittest.TestCase):
    """El Hecho cuando: en una copia de la base, alterar una fila con los triggers apagados rompe la verificación."""

    @classmethod
    def setUpClass(cls):
        postgres_en('postgres', 'DROP DATABASE IF EXISTS %s WITH (FORCE);' % COPIA)
        # TEMPLATE pide que nadie esté conectado a cirdan. La API abre una conexión por petición, así que se reintenta.
        for intento in range(10):
            try:
                postgres_en('postgres', 'CREATE DATABASE %s TEMPLATE cirdan;' % COPIA)
                break
            except AssertionError as e:
                if 'is being accessed by other users' not in str(e) or intento == 9:
                    raise
                time.sleep(1)
        cls.addClassCleanup(postgres_en, 'postgres', 'DROP DATABASE IF EXISTS %s WITH (FORCE);' % COPIA)
        cls.filas, cls.ultimo = map(int, postgres_en(
            COPIA, "SELECT count(*) || ',' || max(chain_seq) FROM audit_log WHERE organization_id = '%s';"
            % ACME).split(','))
        if cls.filas < 5:
            raise AssertionError('La bitácora de Acme en la copia tiene %d filas: hacen falta 5' % cls.filas)

    def verificar(self, antes=''):
        return verificar_en_base(ACME, COPIA, antes)

    def donde(self, seq):
        return "organization_id = '%s' AND chain_seq = %d" % (ACME, seq)

    def test_1_sin_tocar_nada_esta_integra(self):
        self.assertEqual(self.verificar(), (self.filas, self.ultimo, None, None))

    def test_2_cambiar_una_fila_la_rompe_en_esa_fila(self):
        antes = "UPDATE audit_log SET details = details || '{\"CIRDAN_FAKE_\": 1}' WHERE %s;" % self.donde(3)
        self.assertEqual(self.verificar(antes), (self.filas, self.ultimo, 3, 'row_hash'))
        # La fórmula de test_superadmin.py también la ve rota.
        self.assertEqual(postgres_en(COPIA, 'BEGIN; ALTER TABLE audit_log DISABLE TRIGGER USER; %s %s ROLLBACK;'
                                     % (antes, CADENA % ACME)), 'f')

    def test_3_cambiar_una_fila_y_recalcular_su_hash_la_rompe_en_la_siguiente(self):
        antes = ("UPDATE audit_log SET details = details || '{\"CIRDAN_FAKE_\": 1}' WHERE %s;\n"
                 "UPDATE audit_log SET row_hash = %s WHERE %s;" % (self.donde(3), bitacora.HASH_FILA, self.donde(3)))
        self.assertEqual(self.verificar(antes), (self.filas, self.ultimo, 4, 'prev_hash'))

    def test_4_borrar_una_fila_de_en_medio_la_rompe_en_la_siguiente(self):
        antes = 'DELETE FROM audit_log WHERE %s;' % self.donde(3)
        self.assertEqual(self.verificar(antes), (self.filas - 1, self.ultimo, 4, 'chain_seq'))

    def test_5_borrar_las_ultimas_filas_no_se_detecta(self):
        # La limitación documentada: lo que queda sigue cuadrando (docs/contrato_api_v1.md, Bitácora).
        antes = "DELETE FROM audit_log WHERE organization_id = '%s' AND chain_seq > %d;" % (ACME, self.ultimo - 2)
        self.assertEqual(self.verificar(antes), (self.filas - 2, self.ultimo - 2, None, None))

    def test_6_la_base_del_compose_no_se_toco(self):
        self.assertEqual(scalar(CADENA % ACME, user='postgres'), 't')
