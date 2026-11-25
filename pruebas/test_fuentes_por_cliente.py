"""Fuentes por cliente (#117, RC-235) contra la API local y su base (biblioteca estándar).

    python -m unittest -v pruebas/test_fuentes_por_cliente.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)

Hecho cuando de RC-235 que se prueba aquí:
- Base: org_source_settings con RLS forzada. Una empresa no ve ni cambia lo de otra, solo osint, sin DELETE.
- API: GET y PUT /api/v1/sources. Solo el Admin cambia (el analista y el gerente reciben 403). Una fuente apagada en la
  plataforma no se enciende para un cliente (409) y una de inteligencia no se toca (422). Cada cambio va a la bitácora.
Que el orquestador no corra la fuente apagada y el score salga con cobertura parcial está en test_orquestador.py
(test_235a a test_235c) y el motivo de coverage_gaps en test_cobertura.py.
Las pruebas solo escriben filas de org_source_settings, que borran al terminar. Ninguna pide un escaneo.
"""
import unittest

from pruebas import sesion
from pruebas.sesion import Client
from pruebas.test_aislamiento import ACME, BETA, psql, scalar

JORDAN = 'jordan.tate@acme-demo.mx'   # analista de Acme
MAYA = 'maya.reed@acme-demo.mx'       # gerente de Acme
ALEX = 'alex.morgan@acme-demo.mx'     # admin de Acme
DANA = 'dana.cruz@beta-corp.mx'       # admin de Beta

FUENTES = '/api/v1/sources'
CAMPOS = {'code', 'kind', 'global_enabled', 'org_enabled', 'effective_enabled', 'can_change', 'changed_at',
          'changed_by', 'changed_by_platform'}


def postgres(sql):
    ok, out, err = psql(sql, user='postgres')
    if not ok:
        raise AssertionError(err)
    return out


def limpiar():
    postgres('DELETE FROM org_source_settings;')


def id_de(codigo):
    return scalar("SELECT id FROM data_sources WHERE code = '%s';" % codigo, user='postgres')


def usuario(email):
    return scalar("SELECT id FROM users WHERE email = '%s';" % email, user='postgres')


class FuentesPorCliente(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sesion.reset()
        limpiar()
        cls.alex = sesion.login(ALEX)
        cls.jordan = sesion.login(JORDAN)
        cls.maya = sesion.login(MAYA)
        cls.dana = sesion.login(DANA)

    def tearDown(self):
        limpiar()

    def fuente(self, cliente, codigo):
        code, body = cliente.get(FUENTES)
        self.assertEqual(code, 200, body)
        return next(i for i in body['items'] if i['code'] == codigo)

    def put(self, cliente, codigo, enabled):
        return cliente.request('PUT', '%s/%s' % (FUENTES, codigo), {'enabled': enabled})

    def bitacora(self, accion, codigo):
        return scalar("SELECT count(*) FROM audit_log WHERE action = '%s' AND entity_type = 'data_source' "
                      "AND entity_id = '%s';" % (accion, id_de(codigo)), user='postgres')

    # ------------------------------------------------------------ API

    def test_1_lista_con_el_estado_global_y_el_de_la_empresa(self):
        code, body = self.alex.get(FUENTES)
        self.assertEqual(code, 200, body)
        por_codigo = {i['code']: i for i in body['items']}
        self.assertEqual(body['total'], len(body['items']))
        self.assertNotIn('ejemplo', por_codigo)
        for item in body['items']:
            self.assertEqual(set(item), CAMPOS)
        ct = por_codigo['ct_logs']
        campos = ('kind', 'global_enabled', 'org_enabled', 'effective_enabled', 'can_change')
        self.assertEqual(tuple(ct[c] for c in campos), ('osint', True, None, True, True))
        censys = por_codigo['censys']
        self.assertEqual((censys['global_enabled'], censys['effective_enabled']), (False, False))
        for intel in ('nvd', 'first_epss', 'cisa_kev'):
            self.assertEqual((por_codigo[intel]['kind'], por_codigo[intel]['can_change']), ('intel', False))

    def test_2_solo_el_admin_lista_y_cambia(self):
        for cliente in (self.jordan, self.maya):
            self.assertEqual(cliente.get(FUENTES)[0], 403)
            self.assertEqual(self.put(cliente, 'ct_logs', False)[0], 403)
        sin_sesion = Client()
        self.assertEqual(sin_sesion.get(FUENTES)[0], 401)
        self.assertEqual(self.put(sin_sesion, 'ct_logs', False)[0], 401)
        self.assertEqual(scalar('SELECT count(*) FROM org_source_settings;', user='postgres'), '0')
        self.assertEqual(self.bitacora('source.disabled', 'ct_logs'), '0')

    def test_3_apagar_y_volver_a_encender_queda_en_la_bitacora(self):
        antes = int(self.bitacora('source.disabled', 'ct_logs'))
        code, body = self.put(self.alex, 'ct_logs', False)
        self.assertEqual(code, 200, body)
        campos = ('org_enabled', 'effective_enabled', 'changed_by', 'changed_by_platform')
        self.assertEqual(tuple(body[c] for c in campos), (False, False, ALEX, False))
        self.assertIsNotNone(body['changed_at'])
        fila = postgres("SELECT o.enabled, o.changed_by, o.changed_by_platform IS NULL FROM org_source_settings o "
                        "WHERE o.organization_id = '%s' AND o.source_id = '%s';" % (ACME, id_de('ct_logs')))
        self.assertEqual(fila, 'f|%s|t' % usuario(ALEX))
        self.assertEqual(int(self.bitacora('source.disabled', 'ct_logs')), antes + 1)
        actor = scalar("SELECT actor_type || ',' || actor_user_id || ',' || (details->>'code') FROM audit_log "
                       "WHERE action = 'source.disabled' AND entity_id = '%s' ORDER BY occurred_at DESC LIMIT 1;"
                       % id_de('ct_logs'), user='postgres')
        self.assertEqual(actor, 'user,%s,ct_logs' % usuario(ALEX))
        # Repetir el mismo estado no repite la bitácora.
        self.assertEqual(self.put(self.alex, 'ct_logs', False)[0], 200)
        self.assertEqual(int(self.bitacora('source.disabled', 'ct_logs')), antes + 1)
        encendidas = int(self.bitacora('source.enabled', 'ct_logs'))
        code, body = self.put(self.alex, 'ct_logs', True)
        self.assertEqual((code, body['org_enabled'], body['effective_enabled']), (200, True, True))
        self.assertEqual(int(self.bitacora('source.enabled', 'ct_logs')), encendidas + 1)

    def test_4_la_empresa_solo_apaga(self):
        # censys está apagada en la plataforma: no se enciende para un cliente.
        self.assertEqual(self.put(self.alex, 'censys', True)[0], 409)
        self.assertEqual(scalar('SELECT count(*) FROM org_source_settings;', user='postgres'), '0')
        # Sí se puede apagar de antemano y volver a quitar ese apagado, que no la enciende.
        self.assertEqual(self.put(self.alex, 'censys', False)[0], 200)
        code, body = self.put(self.alex, 'censys', True)
        self.assertEqual((code, body['org_enabled'], body['effective_enabled']), (200, True, False))

    def test_5_inteligencia_desconocida_y_cuerpo_invalido(self):
        for intel in ('nvd', 'first_epss', 'cisa_kev'):
            self.assertEqual(self.put(self.alex, intel, False)[0], 422, intel)
        for codigo in ('no-existe', 'ejemplo'):
            self.assertEqual(self.put(self.alex, codigo, False)[0], 404, codigo)
        for valor in ('false', 0, None):
            self.assertEqual(self.put(self.alex, 'ct_logs', valor)[0], 422, repr(valor))
        self.assertEqual(scalar('SELECT count(*) FROM org_source_settings;', user='postgres'), '0')

    def test_6_otra_empresa_no_ve_lo_que_apago_acme(self):
        self.assertEqual(self.put(self.alex, 'ct_logs', False)[0], 200)
        beta = self.fuente(self.dana, 'ct_logs')
        self.assertEqual((beta['org_enabled'], beta['effective_enabled']), (None, True))
        self.assertEqual(self.fuente(self.alex, 'ct_logs')['org_enabled'], False)

    # ------------------------------------------------------------ base

    def test_7_rls_forzada_y_permisos_de_cirdan_app(self):
        self.assertEqual(scalar("SELECT relrowsecurity::text || relforcerowsecurity::text FROM pg_class "
                                "WHERE oid = 'public.org_source_settings'::regclass;", user='postgres'), 'truetrue')
        alex = usuario(ALEX)
        ok, _, err = psql("INSERT INTO org_source_settings (organization_id, source_id, enabled, changed_by) "
                          "VALUES ('%s', '%s', false, '%s');" % (ACME, id_de('dns'), alex), org=ACME)
        self.assertTrue(ok, err)
        # Beta no la ve ni la cambia.
        self.assertEqual(scalar('SELECT count(*) FROM org_source_settings;', org=BETA), '0')
        ok, out, err = psql("UPDATE org_source_settings SET enabled = true WHERE organization_id = '%s' "
                            "RETURNING 1;" % ACME, org=BETA)
        self.assertEqual((ok, out), (True, ''), err)
        # Beta no escribe a nombre de Acme (WITH CHECK).
        ok, _, err = psql("INSERT INTO org_source_settings (organization_id, source_id, enabled, changed_by) "
                          "VALUES ('%s', '%s', false, '%s');" % (ACME, id_de('web'), alex), org=BETA)
        self.assertFalse(ok)
        self.assertIn('row-level security', err)
        # Sin DELETE para cirdan_app.
        ok, _, err = psql('DELETE FROM org_source_settings;', org=ACME)
        self.assertFalse(ok)
        self.assertIn('permission denied', err)
        self.assertEqual(scalar("SELECT enabled::text FROM org_source_settings WHERE source_id = '%s';" % id_de('dns'),
                                user='postgres'), 'false')

    def test_8_solo_osint_y_un_autor(self):
        alex = usuario(ALEX)
        ok, _, err = psql("INSERT INTO org_source_settings (organization_id, source_id, enabled, changed_by) "
                          "VALUES ('%s', '%s', false, '%s');" % (ACME, id_de('nvd'), alex), org=ACME)
        self.assertFalse(ok)
        self.assertIn('org_source_settings_solo_osint', err)
        ok, _, err = psql("INSERT INTO org_source_settings (organization_id, source_id, enabled) "
                          "VALUES ('%s', '%s', false);" % (ACME, id_de('dns')), org=ACME)
        self.assertFalse(ok)
        self.assertIn('org_source_settings_quien', err)
        # El autor es de la empresa: la FK compuesta no deja poner a una cuenta de Beta.
        ok, _, err = psql("INSERT INTO org_source_settings (organization_id, source_id, enabled, changed_by) "
                          "VALUES ('%s', '%s', false, '%s');" % (ACME, id_de('dns'), usuario(DANA)), org=ACME)
        self.assertFalse(ok)
        self.assertIn('org_source_settings_changed_by_fk', err)


if __name__ == '__main__':
    unittest.main()
