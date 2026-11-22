"""Pruebas de los escaneos programados (#27, RC-52) con reloj simulado, sin red.

Necesitan psycopg y dnspython, así que corren dentro del contenedor de la API, con la base levantada y la migración 030:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_programador.py

Cada prueba corre en una transacción que se deshace al final: la base queda igual. El reloj simulado es el `ahora` de
programador.una_vuelta(): decide qué dominio ya toca y a qué hora queda el siguiente turno. El TXT se simula y los
escaneos aceptados no corren (lanzar_con los anota). Nunca consultan en vivo.

Hecho cuando de RC-52: cada dominio autorizado se vuelve a escanear según plans.scan_interval (Starter cada 7 días,
Business y Enterprise cada día) sin duplicar escaneos, y no corre sin autorización vigente ni TXT verificado.
La de una empresa suspendida entra como postgres y se salta sin POSTGRES_PASSWORD (como en test_orquestador.py).
"""
import os
import unittest
from datetime import datetime, time as hora, timedelta, timezone
from unittest import mock

import psycopg
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from cirdan import orquestador, programador
from cirdan.config import config
from cirdan.db import DSN
from cirdan.orquestador.txt import ConsultaTxt
from cirdan.programador import __main__ as servicio

ACME = '20000000-0000-4000-8000-000000000001'      # starter
BETA = '20000000-0000-4000-8000-000000000002'      # business
OLMARDO = '20000000-0000-4000-8000-000000000003'   # business
LOWTIDE = '20000000-0000-4000-8000-000000000004'   # business
EMPRESAS = (ACME, BETA, OLMARDO, LOWTIDE)

ACME_DEMO = '40000000-0000-4000-8000-000000000001'
ACME_TIENDA = '40000000-0000-4000-8000-000000000002'
ACME_PORTAL = '40000000-0000-4000-8000-000000000003'
PARTNER = '40000000-0000-4000-8000-000000000004'   # pending_verification, sin carta
OLD = '40000000-0000-4000-8000-000000000005'       # paused, carta vencida
BETA_CORP = '40000000-0000-4000-8000-000000000006'

TXT = {ACME_DEMO: 'cirdan-verification=c41d7e2a9b06', ACME_TIENDA: 'cirdan-verification=5e9a1f3c7d28',
       BETA_CORP: 'cirdan-verification=b7e1d0c4a9f2'}
CARTA = {ACME_DEMO: '41000000-0000-4000-8000-000000000001', ACME_TIENDA: '41000000-0000-4000-8000-000000000002',
         BETA_CORP: '41000000-0000-4000-8000-000000000006'}
ORG = {ACME_DEMO: ACME, ACME_TIENDA: ACME, ACME_PORTAL: ACME, PARTNER: ACME, OLD: ACME, BETA_CORP: BETA}

MEXICO = timezone(timedelta(hours=-6))  # México sin horario de verano desde 2022


class DnsSimulado:
    def __init__(self, *valores, falla=None):
        self.consulta = ConsultaTxt(tuple(valores))
        self.falla = falla
        self.llamadas = []

    def __call__(self, fqdn):
        self.llamadas.append(fqdn)
        if self.falla:
            raise self.falla
        return self.consulta


def responde(*valores):
    return DnsSimulado(*valores)


def conexion_postgres():
    clave = config('POSTGRES_PASSWORD')
    if not clave:
        raise unittest.SkipTest('falta POSTGRES_PASSWORD: agrégala con -e POSTGRES_PASSWORD al docker compose run')
    return psycopg.connect(make_conninfo(host=config('PGHOST', '127.0.0.1'), port=config('PGPORT', '5433'),
                                         dbname=config('PGDATABASE', 'cirdan'),
                                         user=config('POSTGRES_USER', 'postgres'), password=clave),
                           row_factory=dict_row)


class Base(unittest.TestCase):
    """Conexión de cirdan_app que se deshace al final, con todos los dominios de la semilla fuera de turno
    (next_scan_at = infinity) y cartas renovadas hoy para los que se prueban, así nada depende de la fecha en que
    corre."""

    def setUp(self):
        self.conn = psycopg.connect(DSN, row_factory=dict_row)
        self.tx = self.conn.transaction(force_rollback=True)
        self.tx.__enter__()
        self.conn.execute("SET LOCAL TIME ZONE 'America/Mexico_City'")  # como cirdan.db.transaction()
        for org in EMPRESAS:
            self.empresa(org)
            self.conn.execute("UPDATE domains SET next_scan_at = 'infinity'")
        for dominio, carta in CARTA.items():
            self.empresa(ORG[dominio])
            self.conn.execute(
                'INSERT INTO domain_authorizations (organization_id, domain_id, signer_name, signer_title, '
                'signer_email, signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by, '
                'template_version, activities) '
                'SELECT organization_id, domain_id, signer_name, signer_title, signer_email, '
                "signed_document_key || '.prueba', signed_document_sha256, current_date - 1, current_date + 30, "
                'accepted_by, template_version, activities FROM domain_authorizations WHERE id = %s', (carta,))
        self.t0 = self.conn.execute('SELECT now() AS t').fetchone()['t']
        self.lanzados = []

    def tearDown(self):
        self.tx.__exit__(None, None, None)
        self.conn.close()

    def empresa(self, org):
        self.conn.execute("SELECT set_config('app.current_org', %s, true)", (org,))

    def uno(self, org, sql, *params):
        self.empresa(org)
        return self.conn.execute(sql, params).fetchone()

    def vence(self, dominio, cuando=None):
        """Pone el turno del dominio (None: nunca tuvo turno, sale primero)."""
        self.empresa(ORG[dominio])
        self.conn.execute('UPDATE domains SET next_scan_at = %s WHERE id = %s', (cuando, dominio))

    def turno(self, dominio):
        return self.uno(ORG[dominio], 'SELECT next_scan_at FROM domains WHERE id = %s', dominio)['next_scan_at']

    def intervalo(self, org):
        return self.uno(org, 'SELECT p.scan_interval FROM organizations o JOIN plans p ON p.id = o.plan_id '
                             'WHERE o.id = %s', org)['scan_interval']

    def vuelta(self, ahora, dns=None, tope=10):
        dns = dns if dns is not None else responde(*TXT.values())
        return programador.una_vuelta(ahora=ahora, consultar=dns, conn=self.conn, tope=tope,
                                      lanzar_con=lambda org, scan_id, fqdn: self.lanzados.append((org, scan_id, fqdn)))

    def escaneos(self, dominio):
        self.empresa(ORG[dominio])
        return self.conn.execute("SELECT id::text, status, trigger_type, requested_by FROM scans "
                                 "WHERE domain_id = %s AND trigger_type = 'scheduled' ORDER BY queued_at, id",
                                 (dominio,)).fetchall()

    def terminar(self, dominio):
        """El escaneo en curso termina, como al cerrar correr(): deja de contar en el índice único."""
        self.empresa(ORG[dominio])
        self.conn.execute("UPDATE scans SET status = 'completed', finished_at = now() "
                          "WHERE domain_id = %s AND status IN ('queued', 'running')", (dominio,))

    def candidatos(self, ahora):
        return {r['domain_id'] for r in self.conn.execute(
            'SELECT domain_id::text FROM scheduled_scan_candidates(%s, 500)', (ahora,)).fetchall()}


class ATiempo(Base):

    def test_1_starter_cada_7_dias(self):
        self.assertEqual(self.intervalo(ACME), timedelta(days=7))
        self.vence(ACME_DEMO)
        s = self.vuelta(self.t0)
        self.assertEqual([(x.fqdn, x.aceptada) for x in s], [('acme-demo.mx', True)], [x.detalle for x in s])
        self.assertEqual(self.lanzados, [(ACME, s[0].scan_id, 'acme-demo.mx')])
        self.assertEqual(self.turno(ACME_DEMO), self.t0 + timedelta(days=7))
        escaneo = self.escaneos(ACME_DEMO)
        self.assertEqual([(e['id'], e['status'], e['requested_by']) for e in escaneo],
                         [(s[0].scan_id, 'running', None)])
        evidencia = self.uno(ACME, 'SELECT v.check_reason, v.result FROM scans s JOIN dns_txt_verifications v '
                                   'ON v.id = s.txt_verification_id WHERE s.id = %s', s[0].scan_id)
        self.assertEqual((evidencia['check_reason'], evidencia['result']), ('pre_scan', 'match'))
        self.terminar(ACME_DEMO)

        # Un minuto antes de los 7 días no sale; a los 7 días sí, y el siguiente turno es 7 días después.
        self.assertEqual(self.vuelta(self.t0 + timedelta(days=7, minutes=-1)), [])
        self.assertEqual(len(self.escaneos(ACME_DEMO)), 1)
        s2 = self.vuelta(self.t0 + timedelta(days=7))
        self.assertEqual([(x.fqdn, x.aceptada) for x in s2], [('acme-demo.mx', True)])
        self.assertEqual(self.turno(ACME_DEMO), self.t0 + timedelta(days=14))
        self.assertEqual(len(self.escaneos(ACME_DEMO)), 2)

    def test_2_business_cada_dia(self):
        self.assertEqual(self.intervalo(BETA), timedelta(days=1))
        for org in (OLMARDO, LOWTIDE):
            self.assertEqual(self.intervalo(org), timedelta(days=1))
        self.vence(BETA_CORP)
        s = self.vuelta(self.t0)
        self.assertEqual([(x.fqdn, x.aceptada) for x in s], [('beta-corp.mx', True)], [x.detalle for x in s])
        self.assertEqual(self.lanzados[0][0], BETA)
        self.assertEqual(self.turno(BETA_CORP), self.t0 + timedelta(days=1))
        self.terminar(BETA_CORP)
        self.assertEqual(self.vuelta(self.t0 + timedelta(hours=23, minutes=59)), [])
        s2 = self.vuelta(self.t0 + timedelta(days=1))
        self.assertEqual([(x.fqdn, x.aceptada) for x in s2], [('beta-corp.mx', True)])
        self.assertEqual(self.turno(BETA_CORP), self.t0 + timedelta(days=2))
        self.assertEqual(len(self.escaneos(BETA_CORP)), 2)

    def test_3_atrasado_no_se_pone_al_corriente(self):
        # Un turno vencido hace 3 semanas da un solo escaneo y el siguiente va desde ahora, no 3 escaneos seguidos.
        self.vence(ACME_DEMO, self.t0 - timedelta(days=21))
        self.assertEqual(len(self.vuelta(self.t0)), 1)
        self.terminar(ACME_DEMO)
        self.assertEqual(self.vuelta(self.t0 + timedelta(minutes=1)), [])
        self.assertEqual(self.turno(ACME_DEMO), self.t0 + timedelta(days=7))

    def test_4_primero_los_que_nunca_tuvieron_turno(self):
        self.vence(ACME_TIENDA, self.t0 - timedelta(days=1))
        self.vence(ACME_DEMO)
        self.assertEqual([x.fqdn for x in self.vuelta(self.t0, tope=1)], ['acme-demo.mx'])
        self.assertEqual([x.fqdn for x in self.vuelta(self.t0, tope=1)], ['acme-tienda.mx'])


class SinDuplicar(Base):

    def test_5_dos_vueltas_con_el_mismo_reloj_lanzan_uno(self):
        self.vence(ACME_DEMO)
        self.assertEqual(len(self.vuelta(self.t0)), 1)
        self.assertEqual(self.vuelta(self.t0), [])
        self.assertEqual(self.vuelta(self.t0 + timedelta(hours=1)), [])
        self.assertEqual(len(self.lanzados), 1)
        self.assertEqual(len(self.escaneos(ACME_DEMO)), 1)

    def test_6_otra_conexion_no_reclama_el_turno_tomado(self):
        # La conexión de la prueba toma el turno sin confirmar. Otra, con el mismo reloj, reclama 0 filas en el acto
        # (SKIP LOCKED) en vez de esperar o tomarlo también. Con un FOR UPDATE sin SKIP LOCKED esperaría y
        # lock_timeout la tumbaría.
        self.vence(ACME_DEMO, self.t0 - timedelta(days=1))
        self.empresa(ACME)
        tomado = self.conn.execute(programador.RECLAMAR_SQL, {'ahora': self.t0, 'id': ACME_DEMO}).fetchone()
        self.assertEqual(tomado['fqdn'], 'acme-demo.mx')
        with psycopg.connect(DSN, row_factory=dict_row) as otra:
            with otra.transaction(force_rollback=True):
                otra.execute("SET LOCAL lock_timeout = '2s'")
                otra.execute("SELECT set_config('app.current_org', %s, true)", (ACME,))
                otro = otra.execute(programador.RECLAMAR_SQL, {'ahora': self.t0, 'id': ACME_DEMO}).fetchone()
                self.assertIsNone(otro)

    def test_7_con_un_escaneo_en_curso_no_se_crea_otro(self):
        # El índice único de un escaneo activo por dominio sigue de tercer candado: con uno a pedido en curso, el
        # programado se rechaza por scan_in_progress y el turno queda completo, porque el que corre lo cubre.
        self.empresa(ACME)
        a_pedido = orquestador.solicitar(ACME, 'acme-demo.mx', consultar=responde(TXT[ACME_DEMO]), conn=self.conn)
        self.assertTrue(a_pedido.aceptada, a_pedido.detalle)
        self.vence(ACME_DEMO)
        s = self.vuelta(self.t0)
        self.assertEqual([(x.aceptada, x.motivos) for x in s], [(False, ['scan_in_progress'])])
        self.assertEqual(self.lanzados, [])
        self.assertEqual(self.escaneos(ACME_DEMO), [])
        self.assertEqual(self.turno(ACME_DEMO), self.t0 + timedelta(days=7))

    def test_8_tope_de_escaneos_a_la_vez(self):
        self.vence(ACME_DEMO)
        self.vence(ACME_TIENDA)
        self.assertEqual(len(self.vuelta(self.t0, tope=1)), 1)
        self.assertIsNone(self.turno(ACME_TIENDA))  # el otro sigue vencido y sale en la siguiente vuelta
        self.assertEqual(self.vuelta(self.t0, tope=0), [])
        with mock.patch.object(programador, 'en_curso', return_value=2):
            self.assertEqual(self.vuelta(self.t0, tope=2), [])
        self.assertIsNone(self.turno(ACME_TIENDA))


class SinAutorizacion(Base):

    def test_9_carta_revocada(self):
        self.vence(ACME_DEMO)
        self.empresa(ACME)
        self.conn.execute('UPDATE domain_authorizations SET revoked_at = now() WHERE domain_id = %s', (ACME_DEMO,))
        dns = responde(TXT[ACME_DEMO])
        self.assertNotIn(ACME_DEMO, self.candidatos(self.t0))
        self.assertEqual(self.vuelta(self.t0, dns), [])
        self.assertEqual(dns.llamadas, [])
        self.assertEqual(self.escaneos(ACME_DEMO), [])
        self.assertIsNone(self.turno(ACME_DEMO))

    def test_10_reloj_despues_de_la_vigencia(self):
        self.vence(ACME_DEMO)
        fin = self.uno(ACME, 'SELECT max(valid_until) AS fin FROM domain_authorizations '
                             'WHERE domain_id = %s AND revoked_at IS NULL', ACME_DEMO)['fin']
        ultimo = datetime.combine(fin, hora(23, 59), MEXICO)
        self.assertIn(ACME_DEMO, self.candidatos(ultimo))
        despues = datetime.combine(fin + timedelta(days=1), hora(0, 1), MEXICO)
        dns = responde(TXT[ACME_DEMO])
        self.assertNotIn(ACME_DEMO, self.candidatos(despues))
        self.assertEqual(self.vuelta(despues, dns), [])
        self.assertEqual(dns.llamadas, [])
        self.assertEqual(self.escaneos(ACME_DEMO), [])

    def test_11_carta_que_aun_no_empieza(self):
        self.vence(ACME_DEMO)
        inicio = self.uno(ACME, 'SELECT min(valid_from) AS inicio FROM domain_authorizations '
                                'WHERE domain_id = %s AND revoked_at IS NULL', ACME_DEMO)['inicio']
        self.assertNotIn(ACME_DEMO, self.candidatos(datetime.combine(inicio - timedelta(days=1), hora(12), MEXICO)))

    def test_12_txt_no_verificado(self):
        self.vence(ACME_DEMO)
        s = self.vuelta(self.t0, responde('cirdan-verification=otro-valor'))
        self.assertEqual([(x.aceptada, x.motivos, x.txt) for x in s], [(False, ['txt_not_verified'], 'mismatch')])
        self.assertEqual(self.lanzados, [])
        self.assertEqual(self.escaneos(ACME_DEMO), [])
        # Un rechazo por TXT se intenta otra vez a lo más en un día, no a los 7 del plan Starter.
        self.assertEqual(self.turno(ACME_DEMO), self.t0 + timedelta(days=1))
        auditado = self.uno(ACME, "SELECT details FROM audit_log WHERE action = 'scan.rejected' AND entity_id = %s "
                                  'ORDER BY chain_seq DESC LIMIT 1', ACME_DEMO)
        self.assertEqual(auditado['details']['reasons'], ['txt_not_verified'])
        evidencia = self.uno(ACME, "SELECT result FROM dns_txt_verifications WHERE domain_id = %s "
                                   "AND check_reason = 'pre_scan' ORDER BY created_at DESC LIMIT 1", ACME_DEMO)
        self.assertEqual(evidencia['result'], 'mismatch')

    def test_13_solo_dominios_verificados(self):
        self.vence(PARTNER)                  # pending_verification
        self.vence(OLD)                      # paused
        self.vence(ACME_TIENDA)
        self.vence(ACME_PORTAL)
        self.empresa(ACME)
        self.conn.execute("UPDATE domains SET status = 'paused' WHERE id = %s", (ACME_TIENDA,))
        self.conn.execute("UPDATE domains SET status = 'removed' WHERE id = %s", (ACME_PORTAL,))
        dns = responde(*TXT.values())
        self.assertEqual(self.candidatos(self.t0) & {PARTNER, OLD, ACME_TIENDA, ACME_PORTAL}, set())
        self.assertEqual(self.vuelta(self.t0, dns), [])
        self.assertEqual(dns.llamadas, [])

    def test_14_empresa_suspendida_o_cancelada(self):
        with conexion_postgres() as pg:
            with pg.transaction(force_rollback=True):
                pg.execute("UPDATE domains SET next_scan_at = NULL WHERE id = %s", (ACME_DEMO,))
                antes = {r['domain_id'] for r in pg.execute(
                    'SELECT domain_id::text FROM scheduled_scan_candidates(now(), 500)').fetchall()}
                self.assertIn(ACME_DEMO, antes)
                for estado in ('suspended', 'cancelled'):
                    pg.execute('UPDATE organizations SET status = %s WHERE id = %s', (estado, ACME))
                    filas = pg.execute(
                        'SELECT organization_id::text FROM scheduled_scan_candidates(now(), 500)').fetchall()
                    self.assertNotIn(ACME, {r['organization_id'] for r in filas}, estado)

    def test_15_fuera_de_dominios_en_vivo_no_reclama(self):
        # Sin DNS simulado solo se consultan en vivo los de DOMINIOS_EN_VIVO: acme-demo.mx se salta sin reclamar,
        # sin auditar y sin tocar la red.
        self.vence(ACME_DEMO)
        with mock.patch.dict(os.environ, {'DOMINIOS_EN_VIVO': 'olmardo.com'}), \
                mock.patch.object(orquestador.dns_txt, 'consultar_dns', side_effect=AssertionError('salió a la red')):
            s = programador.una_vuelta(ahora=self.t0, conn=self.conn, tope=10,
                                       lanzar_con=lambda *a: self.lanzados.append(a))
        self.assertEqual(s, [])
        self.assertIsNone(self.turno(ACME_DEMO))
        self.assertIsNone(self.uno(ACME, "SELECT 1 FROM audit_log WHERE action = 'scan.rejected' AND entity_id = %s "
                                         'AND created_at >= %s', ACME_DEMO, self.t0))

    def test_16_un_error_pospone_una_hora_sin_dejar_el_turno_a_medias(self):
        self.vence(ACME_DEMO)
        with self.assertLogs('cirdan.programador', 'ERROR'):
            s = self.vuelta(self.t0, DnsSimulado(falla=RuntimeError('resolver caído')))
        self.assertEqual(s, [])
        self.assertEqual(self.escaneos(ACME_DEMO), [])
        self.assertEqual(self.turno(ACME_DEMO), self.t0 + timedelta(hours=1))

    def test_17_si_no_se_puede_lanzar_queda_fallido(self):
        self.vence(ACME_DEMO)
        with mock.patch.object(orquestador, 'marcar_fallido') as marcar, self.assertLogs('cirdan.programador', 'ERROR'):
            s = programador.una_vuelta(ahora=self.t0, consultar=responde(TXT[ACME_DEMO]), conn=self.conn, tope=10,
                                       lanzar_con=mock.Mock(side_effect=RuntimeError('sin hilos')))
        self.assertEqual(len(s), 1)
        marcar.assert_called_once()
        self.assertEqual(marcar.call_args.args[:2], (ACME, s[0].scan_id))


class Funcion(Base):

    def test_18_security_definer_con_search_path_y_solo_ids(self):
        f = self.conn.execute(
            "SELECT p.prosecdef, p.provolatile, p.proconfig, pg_get_userbyid(p.proowner) AS dueno, "
            "pg_get_function_result(p.oid) AS resultado, "
            "has_function_privilege('cirdan_app', p.oid, 'EXECUTE') AS app, "
            "coalesce(array_to_string(p.proacl, ','), '') AS acl "
            "FROM pg_proc p WHERE p.oid = 'public.scheduled_scan_candidates(timestamptz, integer)'::regprocedure"
        ).fetchone()
        self.assertTrue(f['prosecdef'])
        self.assertEqual(f['provolatile'], 's')
        self.assertEqual(f['proconfig'], ['search_path=pg_catalog, public, pg_temp'])
        self.assertEqual(f['resultado'], 'TABLE(organization_id uuid, domain_id uuid)')
        self.assertTrue(f['app'])
        self.assertNotRegex(f['acl'], r'(^|,)=X')  # PUBLIC sin EXECUTE

    def test_19_tope_del_lote(self):
        self.vence(ACME_DEMO)
        self.vence(ACME_TIENDA)
        filas = self.conn.execute('SELECT domain_id::text FROM scheduled_scan_candidates(%s, 1)', (self.t0,)).fetchall()
        self.assertEqual(len(filas), 1)
        self.assertEqual(self.conn.execute('SELECT count(*) AS n FROM scheduled_scan_candidates(%s, -5)',
                                           (self.t0,)).fetchone()['n'], 0)


class Servicio(unittest.TestCase):

    def test_20_un_solo_candado(self):
        primero = servicio.tomar_candado()
        self.assertIsNotNone(primero)
        try:
            self.assertIsNone(servicio.tomar_candado())
            self.assertTrue(servicio.sigue_vivo(primero))
        finally:
            primero.close()
        self.assertFalse(servicio.sigue_vivo(primero))
        segundo = servicio.tomar_candado()
        self.assertIsNotNone(segundo)
        segundo.close()

    def test_21_una_vez_da_una_vuelta_con_candado(self):
        with mock.patch.object(programador, 'una_vuelta') as vuelta, mock.patch.object(servicio.signal, 'signal'):
            self.assertEqual(servicio.main(['--una-vez']), 0)
        vuelta.assert_called_once_with()

    def test_22_sin_candado_no_da_vuelta(self):
        otro = servicio.tomar_candado()
        try:
            with mock.patch.object(programador, 'una_vuelta') as vuelta, mock.patch.object(servicio.signal, 'signal'):
                self.assertEqual(servicio.main(['--una-vez']), 0)
            vuelta.assert_not_called()
        finally:
            otro.close()

    def test_23_variables_del_servicio(self):
        with mock.patch.dict(os.environ, {'PROGRAMADOR_INTERVALO': '', 'PROGRAMADOR_MAX_ESCANEOS': ''}):
            self.assertEqual((programador.intervalo(), programador.max_escaneos()), (60, 2))
        for malo in ('0', '-1', 'abc', '1.5'):
            with self.subTest(malo=malo), mock.patch.dict(os.environ, {'PROGRAMADOR_INTERVALO': malo}):
                with self.assertRaises(ValueError):
                    programador.intervalo()


if __name__ == '__main__':
    unittest.main(verbosity=2)
