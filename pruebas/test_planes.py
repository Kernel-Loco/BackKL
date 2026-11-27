"""Tope de escaneos a mano (RC-297): cirdan/planes.py y su lugar en orquestador.solicitar(), sin red.

Necesitan la base, así que corren dentro del contenedor de la API, como test_orquestador.py:

    docker compose run --rm -e POSTGRES_PASSWORD -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_planes.py

Casi todas corren en una transacción que se deshace al final. La de peticiones en paralelo (Paralelo) necesita que cada
petición confirme su transacción, como en la API: al terminar pasa sus escaneos a hace 2 días, fuera del día y del
enfriamiento, para que las demás pruebas de acme-demo.mx no choquen con el tope. Desde la migración 035 (RC-285)
`scans.queued_at` es inmutable incluso para `postgres`, así que Paralelo y las pruebas de enfriamiento y medianoche de
Tope mueven `queued_at` como `postgres` con `SET LOCAL session_replication_role = replica` (se saltan sin
POSTGRES_PASSWORD). Acme Demo está en Starter (on_demand_scans = false) y Beta Corp en Business (semilla 001).
"""
import contextlib
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import psycopg
from psycopg.rows import dict_row

from cirdan import orquestador, planes
from cirdan.api import escaneos
from cirdan.db import DSN, transaction
from cirdan.orquestador import Solicitud
from cirdan.recolectores import REGISTRO, cargar
from pruebas.test_orquestador import ACME, BETA, FALLA, TXT_ACME, conexion_postgres, renovar_carta, responde

TXT_BETA = 'cirdan-verification=b7e1d0c4a9f2'   # token de beta-corp.mx en la semilla
TXT_TIENDA = 'cirdan-verification=5e9a1f3c7d28'  # token de acme-tienda.mx en la semilla
CARTA_BETA = '41000000-0000-4000-8000-000000000006'


class Cuenta(unittest.TestCase):
    """El tope sale de MAX_CONSULTAS: una empresa no gasta más de la mitad del cupo diario de ninguna fuente."""

    def test_1_el_tope_cabe_en_la_mitad_del_cupo_de_cada_fuente(self):
        with psycopg.connect(DSN, row_factory=dict_row) as c:
            filas = c.execute('SELECT code, daily_limit FROM data_sources WHERE daily_limit IS NOT NULL').fetchall()
        cupos = {f['code']: f['daily_limit'] for f in filas}
        self.assertLessEqual(set(planes.FUENTES_DEL_TOPE), set(cupos), 'falta el cupo diario de una fuente del tope')
        for codigo, cupo in sorted(cupos.items()):
            if codigo not in REGISTRO:
                continue
            with self.subTest(fuente=codigo):
                maximo = cargar(codigo).MAX_CONSULTAS
                self.assertLessEqual(planes.TOPE_EMPRESA * maximo, cupo // 2,
                                     '%d escaneos de %s reservan %d de %d' % (planes.TOPE_EMPRESA, codigo,
                                                                             planes.TOPE_EMPRESA * maximo, cupo))

    def test_2_la_cuenta_escrita_sigue_igual_que_el_codigo(self):
        """El docstring de planes.py escribe la cuenta de las 3 fuentes de la tarjeta; si cambia un recolector, también."""
        with psycopg.connect(DSN, row_factory=dict_row) as c:
            cupos = {f['code']: f['daily_limit'] for f in c.execute(
                'SELECT code, daily_limit FROM data_sources WHERE code = ANY(%s)', (list(planes.FUENTES_DEL_TOPE),))}
        topes = []
        for codigo in planes.FUENTES_DEL_TOPE:
            maximo, mitad = cargar(codigo).MAX_CONSULTAS, cupos[codigo] // 2
            self.assertIn('%s / 2 = %s' % (cupos[codigo], mitad), ' '.join(planes.__doc__.split()))
            self.assertIn('%s / %s = %s' % (mitad, maximo, mitad // maximo), ' '.join(planes.__doc__.split()))
            topes.append(mitad // maximo)
        self.assertEqual(planes.TOPE_EMPRESA, min(topes))


class Logica(unittest.TestCase):
    """check_plan_limits con una fila armada: los dos planes y el Retry-After, sin base."""

    AHORA = datetime(2026, 11, 26, 23, 0, tzinfo=timezone.utc)

    def limites(self, **fila):
        base = {'on_demand_scans': False, 'empresa_hoy': 0, 'dominio_hoy': 0, 'ultimo': None, 'ahora': self.AHORA,
                'manana': datetime(2026, 11, 27, tzinfo=timezone.utc)}
        base.update(fila)
        conn = mock.Mock()
        conn.execute.return_value.fetchone.return_value = base
        return planes.check_plan_limits(ACME, 'on_demand_scan', conn, domain_id='d')

    def test_1_sin_escaneos_deja_pedir(self):
        self.assertIsNone(self.limites())

    def test_2_con_on_demand_scans_true_el_dominio_no_tiene_tope_diario(self):
        self.assertIsNone(self.limites(on_demand_scans=True, dominio_hoy=2, empresa_hoy=2))
        self.assertEqual(self.limites(on_demand_scans=False, dominio_hoy=1).motivos, ['on_demand_domain_daily_limit'])

    def test_3_el_retry_after_es_el_mayor_de_los_motivos(self):
        hace_una_hora = self.AHORA - timedelta(hours=1)
        limite = self.limites(empresa_hoy=3, dominio_hoy=1, ultimo=hace_una_hora)
        self.assertEqual(limite.motivos, ['on_demand_daily_limit', 'on_demand_domain_daily_limit', 'on_demand_cooldown'])
        self.assertEqual(limite.retry_after, 5 * 3600)   # el enfriamiento (5 h) gana a la medianoche UTC (1 h)
        self.assertEqual(self.limites(empresa_hoy=3, ultimo=hace_una_hora - timedelta(hours=6)).retry_after, 3600)

    def test_4_otra_accion_no_existe(self):
        with self.assertRaises(ValueError):
            planes.check_plan_limits(ACME, 'max_domains', mock.Mock())

    def test_5_sin_fila_de_la_empresa_no_deja_pedir(self):
        conn = mock.Mock()
        conn.execute.return_value.fetchone.return_value = None
        with self.assertRaises(RuntimeError):
            planes.check_plan_limits(ACME, 'on_demand_scan', conn, domain_id='d')


class Tope(unittest.TestCase):
    """solicitar() con el tope, en una transacción que se deshace."""

    def setUp(self):
        self.conn = psycopg.connect(DSN, row_factory=dict_row)
        self.tx = self.conn.transaction(force_rollback=True)
        self.tx.__enter__()
        self.empresa(ACME)
        renovar_carta(self.conn)

    def tearDown(self):
        self.tx.__exit__(None, None, None)
        self.conn.close()

    def empresa(self, org):
        self.conn.execute("SELECT set_config('app.current_org', %s, true)", (org,))

    def uno(self, sql, *params):
        return self.conn.execute(sql, params).fetchone()

    def pedir(self, dns=None, org=ACME, fqdn='acme-demo.mx', trigger='on_demand'):
        return orquestador.solicitar(org, fqdn, trigger=trigger, consultar=dns or responde(TXT_ACME), conn=self.conn)

    def cerrar(self, s):
        """Termina el escaneo (deja pedir otro sin scan_in_progress)."""
        self.assertTrue(s.aceptada, s.detalle)
        self.conn.execute("UPDATE scans SET status = 'completed', finished_at = now() WHERE id = %s", (s.scan_id,))

    @contextlib.contextmanager
    def como_postgres(self):
        """Abre una transacción que se deshace como postgres y la corre con SET LOCAL ROLE cirdan_app, para que
        mover_queued_at() pueda cambiar una columna inmutable desde la 035 (RC-285) dentro de la misma transacción."""
        # Deshace la carta de setUp: desde la 037 (RC-272) dos cartas sin confirmar del mismo dominio en dos conexiones
        # se esperan una a otra (candado del dominio y revocación de la anterior) y la prueba quedaría colgada.
        self.tx.__exit__(None, None, None)
        self.tx = self.conn.transaction(force_rollback=True)
        self.tx.__enter__()
        pg = conexion_postgres()
        anterior = self.conn
        try:
            with pg.transaction(force_rollback=True):
                pg.execute('SET LOCAL ROLE cirdan_app')
                self.conn = pg
                self.empresa(ACME)
                renovar_carta(pg)
                yield
        finally:
            self.conn = anterior
            pg.close()

    def mover_queued_at(self, scan_id, cuando):
        """Mueve scans.queued_at dentro de como_postgres() sin disparar scans_guard_bu (035, RC-285)."""
        self.conn.execute('RESET ROLE')
        self.conn.execute('SET LOCAL session_replication_role = replica')
        self.conn.execute('UPDATE scans SET queued_at = %s WHERE id = %%s' % cuando, (scan_id,))
        self.conn.execute('SET LOCAL session_replication_role = origin')
        self.conn.execute('SET LOCAL ROLE cirdan_app')

    def verificaciones(self):
        return self.uno('SELECT count(*) AS n FROM dns_txt_verifications')['n']

    def rechazo_sin_dns(self, motivos, **kw):
        """Pide otra vez y revisa que el tope lo frene antes del DNS, con su motivo en audit_log."""
        dns = responde(TXT_ACME if kw.get('org', ACME) == ACME else TXT_BETA)
        antes = self.verificaciones()
        s = self.pedir(dns, **kw)
        self.assertEqual((s.aceptada, s.motivos), (False, motivos))
        self.assertEqual(dns.llamadas, [], 'el tope consultó el DNS')
        self.assertEqual(self.verificaciones(), antes, 'el tope agregó una fila a dns_txt_verifications')
        self.assertGreaterEqual(s.retry_after, 1)
        bitacora = self.uno("SELECT details FROM audit_log WHERE action = 'scan.rejected' AND entity_id = %s "
                            'ORDER BY chain_seq DESC LIMIT 1', s.domain_id)['details']
        self.assertEqual((bitacora['reasons'], bitacora['retry_after']), (motivos, s.retry_after))
        return s

    def segundos_a_medianoche_utc(self):
        return self.uno("SELECT ceil(extract(epoch FROM date_trunc('day', now(), 'UTC') + interval '1 day' - now()))"
                        '::int AS s')['s']

    def test_1_sin_plan_un_escaneo_a_mano_por_dominio_al_dia(self):
        with mock.patch.object(planes, 'ENFRIAMIENTO', timedelta(0)):
            self.cerrar(self.pedir())
            s = self.rechazo_sin_dns(['on_demand_domain_daily_limit'])
        self.assertEqual(s.retry_after, self.segundos_a_medianoche_utc())

    def test_2_el_enfriamiento_frena_el_mismo_dominio(self):
        with self.como_postgres(), mock.patch.object(planes, 'TOPE_DOMINIO_SIN_PLAN', 99):
            primero = self.pedir()
            self.cerrar(primero)
            s = self.rechazo_sin_dns(['on_demand_cooldown'])
            self.assertEqual(s.retry_after, 6 * 3600)
            self.mover_queued_at(primero.scan_id, "now() - interval '5 hours'")
            self.assertEqual(self.rechazo_sin_dns(['on_demand_cooldown']).retry_after, 3600)
            self.mover_queued_at(primero.scan_id, "now() - interval '6 hours 1 second'")
            self.assertTrue(self.pedir().aceptada)

    def test_3_tope_por_empresa_y_otra_empresa_todavia_puede(self):
        with mock.patch.object(planes, 'TOPE_DOMINIO_SIN_PLAN', 99), mock.patch.object(planes, 'ENFRIAMIENTO', timedelta(0)):
            for _ in range(planes.TOPE_EMPRESA):
                self.cerrar(self.pedir())
            s = self.rechazo_sin_dns(['on_demand_daily_limit'])
            self.assertEqual(s.retry_after, self.segundos_a_medianoche_utc())
            self.assertIn('ya pidió %d escaneos' % planes.TOPE_EMPRESA, s.detalle)
            self.empresa(BETA)
            self.conn.execute(   # como renovar_carta(), con la carta de beta-corp.mx: se va con el rollback
                'INSERT INTO domain_authorizations (organization_id, domain_id, signer_name, signer_title, signer_email, '
                'signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by, template_version, '
                "activities) SELECT organization_id, domain_id, signer_name, signer_title, signer_email, "
                "signed_document_key || '.prueba', signed_document_sha256, current_date - 1, current_date + 30, "
                'accepted_by, template_version, activities FROM domain_authorizations WHERE id = %s', (CARTA_BETA,))
            beta = self.pedir(responde(TXT_BETA), org=BETA, fqdn='beta-corp.mx')
            self.assertTrue(beta.aceptada, beta.detalle)

    def test_4_cuentan_los_de_llave_de_api_y_los_fallidos(self):
        with mock.patch.object(planes, 'TOPE_DOMINIO_SIN_PLAN', 99), mock.patch.object(planes, 'ENFRIAMIENTO', timedelta(0)), \
                mock.patch.object(planes, 'TOPE_EMPRESA', 2):
            self.cerrar(self.pedir(trigger='api'))
            fallido = self.pedir()
            self.conn.execute("UPDATE scans SET status = 'failed', finished_at = now() WHERE id = %s", (fallido.scan_id,))
            self.rechazo_sin_dns(['on_demand_daily_limit'])

    def test_5_los_de_ayer_no_cuentan(self):
        with self.como_postgres(), mock.patch.object(planes, 'ENFRIAMIENTO', timedelta(0)):
            primero = self.pedir()
            self.cerrar(primero)
            self.mover_queued_at(primero.scan_id, "date_trunc('day', now(), 'UTC') - interval '1 second'")
            self.assertTrue(self.pedir().aceptada)

    def test_6_los_programados_no_pasan_por_el_tope_ni_cuentan(self):
        with mock.patch.object(planes, 'TOPE_EMPRESA', 0), \
                mock.patch.object(planes, 'check_plan_limits', wraps=planes.check_plan_limits) as revisa:
            programado = self.pedir(trigger='scheduled')
            self.assertTrue(programado.aceptada, programado.detalle)
            revisa.assert_not_called()
        self.cerrar(programado)
        self.assertTrue(self.pedir().aceptada, 'un programado contó para el tope de escaneos a mano')

    def test_7_un_escaneo_en_curso_sigue_siendo_409_sin_dns(self):
        self.assertTrue(self.pedir().aceptada)
        dns = responde(TXT_ACME)
        s = self.pedir(dns)
        self.assertEqual((s.aceptada, s.motivos, s.retry_after), (False, ['scan_in_progress'], None))
        self.assertEqual(dns.llamadas, [])

    def test_8_el_tope_va_antes_del_dns_pero_despues_de_la_carta(self):
        """Sin carta sigue saliendo authorization_missing (409), aunque la empresa ya no tenga escaneos hoy."""
        with mock.patch.object(planes, 'TOPE_EMPRESA', 0):
            s = self.pedir(fqdn='partner-example.com')
        self.assertEqual((s.motivos, s.retry_after), (['authorization_missing'], None))

    def correr_en_vivo(self, s, resultados):
        """Corre las fuentes del tope en vivo con estos resultados seguidos, sin red ni esperas reales. Cada corrida
        reserva 1 consulta (MAX_CONSULTAS parchado), así la prueba no depende del cupo que le quede hoy a esta base."""
        seguidos, esperas = iter(resultados), []
        with mock.patch.object(orquestador, 'ejecutar', lambda *a, **k: next(seguidos)), \
                mock.patch.object(orquestador, 'en_vivo_permitido', lambda fqdn: True), \
                mock.patch.object(cargar('ct_logs'), 'MAX_CONSULTAS', 1), \
                mock.patch.object(cargar('whois'), 'MAX_CONSULTAS', 1), \
                mock.patch.object(cargar('shodan'), 'MAX_CONSULTAS', 1):
            orquestador.correr(ACME, s.scan_id, 'acme-demo.mx', fuentes=list(planes.FUENTES_DEL_TOPE), conn=self.conn,
                               dormir=esperas.append)
        filas = self.conn.execute(
            'SELECT d.code, r.status, r.attempt, r.raw_payload FROM scan_source_runs r JOIN data_sources d '
            'ON d.id = r.source_id WHERE r.scan_id = %s', (s.scan_id,)).fetchall()
        return {f['code']: f for f in filas}, sum(esperas)

    def test_9_a_mano_una_fuente_del_tope_no_se_reintenta_si_ya_gasto(self):
        """B1.1: cada reintento reserva otra vez MAX_CONSULTAS. A mano, ct_logs, whois y shodan solo se reintentan si
        el intento fallido no gastó nada, así un escaneo gasta a lo más un MAX_CONSULTAS de cada una y la cuenta de
        planes.py vale con reintentos. Un programado se sigue reintentando a 1, 5 y 25 minutos."""
        nada = SimpleNamespace(**dict(vars(FALLA), consultas=0))
        a_mano = self.pedir()
        self.assertTrue(a_mano.aceptada, a_mano.detalle)
        filas, espera = self.correr_en_vivo(a_mano, [nada, FALLA] * len(planes.FUENTES_DEL_TOPE))
        self.assertEqual(espera, len(planes.FUENTES_DEL_TOPE) * 60)   # solo el reintento del intento que no gastó
        for codigo in planes.FUENTES_DEL_TOPE:
            with self.subTest(fuente=codigo, trigger='on_demand'):
                self.assertEqual((filas[codigo]['status'], filas[codigo]['attempt']), ('failed', 1))
                if filas[codigo]['raw_payload']:   # whois y shodan no guardan raw_payload (keep_raw_payload)
                    self.assertIn(orquestador.SIN_REINTENTO % codigo, filas[codigo]['raw_payload']['avisos'])
        programado = self.pedir(trigger='scheduled')
        self.assertTrue(programado.aceptada, programado.detalle)
        filas, espera = self.correr_en_vivo(programado, [FALLA] * 4 * len(planes.FUENTES_DEL_TOPE))
        self.assertEqual(espera, len(planes.FUENTES_DEL_TOPE) * 31 * 60)
        for codigo in planes.FUENTES_DEL_TOPE:
            with self.subTest(fuente=codigo, trigger='scheduled'):
                self.assertEqual((filas[codigo]['status'], filas[codigo]['attempt']), ('failed', 3))


class Paralelo(unittest.TestCase):
    """N peticiones a la vez de la misma empresa no pasan del tope (el candado de planes._candado).

    Cada una abre su propia transacción, como la API, y la confirma. Para que se encimen, la cuenta tarda ESPERA dentro
    de la transacción. Con el candado quitado pasan todas: así la prueba muestra que el candado es lo que las frena."""

    N = 6
    ESPERA = 0.4

    @classmethod
    def setUpClass(cls):
        # envejecer() mueve queued_at como postgres (035, RC-285): sin POSTGRES_PASSWORD se salta antes de confirmar
        # nada en la base, así no deja escaneos de hoy que traben a Tope ni a test_programador.
        with conexion_postgres():
            pass
        # Una carta vigente de acme-demo.mx confirmada, solo si ya no hay una (como test_escaneos_api.py test_5)
        with transaction(ACME) as c:
            c.execute(
                'INSERT INTO domain_authorizations (organization_id, domain_id, signer_name, signer_title, signer_email, '
                'signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by, template_version, '
                "activities) SELECT organization_id, domain_id, signer_name, signer_title, signer_email, "
                "signed_document_key || '.prueba', signed_document_sha256, current_date - 1, current_date + 30, "
                "accepted_by, template_version, activities FROM domain_authorizations a WHERE id IN "
                "('41000000-0000-4000-8000-000000000001', '41000000-0000-4000-8000-000000000002') "   # y acme-tienda.mx
                'AND NOT EXISTS (SELECT 1 FROM domain_authorizations v '
                'WHERE v.domain_id = a.domain_id AND v.revoked_at IS NULL AND current_date BETWEEN v.valid_from AND '
                'v.valid_until)')

    def setUp(self):
        self.ids = []
        self.addCleanup(self.envejecer)

    def envejecer(self):
        """Los escaneos confirmados de la prueba pasan a hace 2 días: ya no cuentan para el tope ni el enfriamiento.
        Desde la 035 (RC-285) queued_at es inmutable incluso para postgres, así que se mueven sin triggers."""
        if self.ids:
            with conexion_postgres() as pg, pg.transaction():
                pg.execute('SET LOCAL session_replication_role = replica')
                pg.execute("UPDATE scans SET queued_at = now() - interval '2 days', finished_at = now() - interval '2 days' "
                           'WHERE id = ANY(%s::uuid[])', (self.ids,))

    def a_la_vez(self):
        real = planes.check_plan_limits

        def lenta(*a, **k):
            r = real(*a, **k)
            time.sleep(self.ESPERA)   # dentro de la transacción, con el candado tomado si lo hay
            return r

        salida, errores = [], []
        juntos = threading.Barrier(self.N)

        def peticion():
            try:
                juntos.wait(10)
                with transaction(ACME) as c:
                    s = orquestador.solicitar(ACME, 'acme-demo.mx', consultar=responde(TXT_ACME), conn=c)
                    if s.aceptada:   # termina en la misma transacción: el siguiente no choca con scan_in_progress
                        c.execute("UPDATE scans SET status = 'completed', finished_at = now() WHERE id = %s",
                                  (s.scan_id,))
                salida.append(s)
            except Exception as e:  # noqa: BLE001 - la prueba lo muestra abajo
                errores.append(repr(e))

        with mock.patch.object(planes, 'check_plan_limits', lenta), \
                mock.patch.object(planes, 'TOPE_DOMINIO_SIN_PLAN', 99), \
                mock.patch.object(planes, 'ENFRIAMIENTO', timedelta(minutes=-5)):   # la hora de cada tx es distinta
            hilos = [threading.Thread(target=peticion, daemon=True) for _ in range(self.N)]
            for h in hilos:
                h.start()
            for h in hilos:
                h.join(60)
        self.ids += [s.scan_id for s in salida if s.aceptada]
        self.assertEqual(errores, [])
        self.assertEqual(len(salida), self.N)
        return salida

    def test_1_n_a_la_vez_no_pasan_del_tope(self):
        salida = self.a_la_vez()
        aceptadas = [s for s in salida if s.aceptada]
        self.assertEqual(len(aceptadas), planes.TOPE_EMPRESA)
        self.assertEqual({tuple(s.motivos) for s in salida if not s.aceptada}, {('on_demand_daily_limit',)})

    def test_2_sin_el_candado_pasan_de_mas(self):
        """Mutación: sin el candado, las cuentas se enciman y el tope no frena."""
        with mock.patch.object(planes, '_candado', lambda conn, org: None):
            aceptadas = [s for s in self.a_la_vez() if s.aceptada]
        self.assertGreater(len(aceptadas), planes.TOPE_EMPRESA)

    ESPERA_DNS = 1.5   # más que deadlock_timeout (1 s por omisión)

    def caido_y_dos_dominios(self):
        """B2.1: un escaneo caído de acme-tienda.mx y dos peticiones a la vez. La de acme-demo.mx toma el tope y tarda en
        el DNS. Mientras, la de acme-tienda.mx da por caído el viejo (scan.abandoned toma el candado de la cadena de
        audit_log) y pide el tope. Si la primera pide la cadena para su audit con el orden al revés, hay interbloqueo."""
        with transaction(ACME) as c:
            viejo = orquestador.solicitar(ACME, 'acme-tienda.mx', trigger='scheduled', consultar=responde(TXT_TIENDA),
                                          conn=c)
            self.assertTrue(viejo.aceptada, viejo.detalle)
            c.execute("UPDATE scans SET updated_at = now() - interval '31 minutes' WHERE id = %s", (viejo.scan_id,))
        self.ids.append(viejo.scan_id)
        en_dns = threading.Event()

        def dns_lento(fqdn):   # con el candado del tope tomado
            en_dns.set()
            time.sleep(self.ESPERA_DNS)
            return responde(TXT_ACME)(fqdn)

        salida, errores = {}, []

        def peticion(fqdn, consultar, antes=None):
            try:
                if antes:
                    antes.wait(10)
                with transaction(ACME) as c:
                    s = orquestador.solicitar(ACME, fqdn, consultar=consultar, conn=c)
                    if s.aceptada:
                        c.execute("UPDATE scans SET status = 'completed', finished_at = now() WHERE id = %s",
                                  (s.scan_id,))
                salida[fqdn] = s
            except Exception as e:  # noqa: BLE001 - la prueba lo muestra abajo
                errores.append(repr(e))

        with mock.patch.object(planes, 'TOPE_EMPRESA', 99), mock.patch.object(planes, 'TOPE_DOMINIO_SIN_PLAN', 99), \
                mock.patch.object(planes, 'ENFRIAMIENTO', timedelta(minutes=-5)):
            hilos = [threading.Thread(target=peticion, args=('acme-demo.mx', dns_lento), daemon=True),
                     threading.Thread(target=peticion, args=('acme-tienda.mx', responde(TXT_TIENDA), en_dns),
                                      daemon=True)]
            for h in hilos:
                h.start()
            for h in hilos:
                h.join(60)
        self.ids += [s.scan_id for s in salida.values() if s.aceptada]
        with transaction(ACME) as c:
            estado = c.execute('SELECT status FROM scans WHERE id = %s', (viejo.scan_id,)).fetchone()['status']
        return salida, errores, estado

    def test_3_un_escaneo_caido_no_traba_a_dos_dominios_a_la_vez(self):
        salida, errores, viejo = self.caido_y_dos_dominios()
        self.assertEqual(errores, [])
        self.assertEqual({f: s.aceptada for f, s in salida.items()}, {'acme-demo.mx': True, 'acme-tienda.mx': True})
        self.assertEqual(viejo, 'failed')   # lo dio por caído la petición de acme-tienda.mx

    def test_4_sin_el_candado_antes_de_en_curso_hay_interbloqueo(self):
        """Mutación: con el candado del tope solo dentro de check_plan_limits (el orden de antes), PostgreSQL aborta
        una de las dos con DeadlockDetected."""
        with mock.patch.object(planes, 'tomar_candado', lambda conn, org: None):
            _, errores, _ = self.caido_y_dos_dominios()
        self.assertTrue(any('DeadlockDetected' in e for e in errores), errores)


class Respuesta(unittest.TestCase):
    """POST /domains/{fqdn}/scans responde 429 con Retry-After solo cuando lo frena el tope."""

    SESION = SimpleNamespace(org_id=ACME, audit_user_id=None, audit_platform=None)

    def responder(self, solicitud):
        with mock.patch.object(orquestador, 'solicitar', return_value=solicitud), \
                mock.patch.object(escaneos, 'client_ip', return_value='203.0.113.7'):
            return escaneos.request_scan('acme-demo.mx', mock.Mock(), self.SESION)

    def test_1_el_tope_da_429_con_retry_after(self):
        r = self.responder(Solicitud('acme-demo.mx', False, ['on_demand_cooldown'], 'No se puede escanear: x.',
                                     retry_after=3600))
        self.assertEqual((r.status_code, r.headers['retry-after']), (429, '3600'))

    def test_2_los_demas_rechazos_siguen_igual(self):
        r = self.responder(Solicitud('acme-demo.mx', False, ['scan_in_progress'], 'No se puede escanear: x.'))
        self.assertEqual(r.status_code, 409)
        self.assertNotIn('retry-after', r.headers)
        r = self.responder(Solicitud('acme-demo.mx', False, ['domain_not_found'], 'No se puede escanear: x.'))
        self.assertEqual(r.status_code, 404)


if __name__ == '__main__':
    unittest.main()
