"""Pruebas de la consola multiempresa del integrador (#66, RC-126): migración 033 y /api/v1/operator.

    python -m unittest -v pruebas/test_operador.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)

Hecho cuando de RC-126, punto por punto:
1. users.role acepta 'operator' y org_delegations tiene empresa integradora, empresa cliente, quién la otorgó y
   revocada, con RLS ENABLE, FORCE y tenant_isolation, y cirdan_app sin BYPASSRLS ni escritura (test_1 y test_2).
2. Las políticas RLS que ya existían no cambian: solo hay una nueva, la de org_delegations (test_3).
3. La API lee la delegación con RLS de la integradora y cada empresa cliente con la suya: ninguna función SECURITY
   DEFINER lee org_delegations y una cuenta de otra empresa no ve las delegaciones ajenas (test_2 y test_4).
4. El riesgo de cada empresa es el score más alto de sus dominios y la lista sale ordenada por él (test_10 y test_11).
5. test_aislamiento.py sigue en verde (corre aparte, en la misma lista del CI).
6. Una empresa no delegada o una delegación revocada responden 404 (test_12 y test_13).

Además, del comentario 10270: cada lectura de un operador queda en la bitácora de la empresa cliente sin romper la
cadena (test_14), y el operador sin TOTP no entra con contraseña ni a la consola (test_15). Las cuentas normales, una
sesión sin cookie y un operador al que se le quita el rol reciben 403 o 401 (test_16 y test_17).

Jordan Tate (Analista de Acme, cuenta de demo) es operator solo durante estas pruebas: Acme hace de integradora y
Beta Corp y Grupo Olmardo le delegan. Lo que escriben como postgres lo deshacen al terminar, salvo la bitácora, que
es de solo inserción. Ninguna pide un escaneo.
"""
import unittest
import uuid

from pruebas import sesion
from pruebas.sesion import Client
from pruebas.test_aislamiento import ACME, BETA, psql, scalar
from pruebas.test_superadmin import CADENA, LOWTIDE, OLMARDO, OLMARDO_DEMO, DANA_ID, postgres

JORDAN_ID = '30000000-0000-4000-8000-000000000003'
JORDAN = 'jordan.tate@acme-demo.mx'   # analista de Acme, operator durante estas pruebas
ALEX = 'alex.morgan@acme-demo.mx'     # admin de Acme
DANA = 'dana.cruz@beta-corp.mx'       # admin de Beta

LISTA = '/api/v1/operator/organizations'
SOLO_OPERADOR = 'Solo una cuenta de operador con MFA activo puede usar la consola del integrador.'
NO_ENCONTRADA = {'detail': 'Organización no encontrada'}
MFA_OPERADOR = 'Las cuentas de operador deben tener MFA activo antes de iniciar sesión.'

# Score vigente (el último) más alto de los dominios no quitados de una empresa, calculado aparte como postgres.
RIESGO = ("SELECT coalesce(max(s.score)::text, 'null') FROM domains d LEFT JOIN LATERAL (SELECT ds.score FROM"
          " domain_scores ds WHERE ds.domain_id = d.id ORDER BY ds.computed_at DESC LIMIT 1) s ON true"
          " WHERE d.organization_id = '%s' AND d.status <> 'removed';")


def delegar(cliente, otorga):
    postgres("INSERT INTO org_delegations (organization_id, client_organization_id, granted_by)"
             " VALUES ('%s', '%s', '%s');" % (ACME, cliente, otorga))


def revocar(cliente, revoca):
    postgres("UPDATE org_delegations SET revoked_at = now(), revoked_by = '%s' WHERE organization_id = '%s'"
             " AND client_organization_id = '%s' AND revoked_at IS NULL;" % (revoca, ACME, cliente))


def limpiar():
    postgres("DELETE FROM org_delegations WHERE organization_id = '%s';" % ACME)


def rol(user_id, nombre):
    postgres("UPDATE users SET role = '%s' WHERE id = '%s';" % (nombre, user_id))


def riesgo(org):
    valor = scalar(RIESGO % org, user='postgres')
    return None if valor == 'null' else int(valor)


class Base(unittest.TestCase):
    """Migración 033, entrando como cirdan_app."""

    @classmethod
    def setUpClass(cls):
        cls.addClassCleanup(limpiar)
        limpiar()
        delegar(BETA, DANA_ID)

    def test_1_rol_operator_y_columnas_de_la_delegacion(self):
        ok, _, err = psql("BEGIN; UPDATE users SET role = 'operator' WHERE id = '%s'; ROLLBACK;" % JORDAN_ID,
                          user='postgres')
        self.assertTrue(ok, err)
        ok, _, err = psql("BEGIN; UPDATE users SET role = 'otro' WHERE id = '%s'; ROLLBACK;" % JORDAN_ID,
                          user='postgres')
        self.assertFalse(ok)
        self.assertIn('users_role_check', err)
        columnas = scalar("SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid ="
                          " 'public.org_delegations'::regclass AND attnum > 0 AND NOT attisdropped;", user='postgres')
        self.assertEqual(columnas, 'id,organization_id,client_organization_id,granted_by,granted_at,revoked_at,'
                                   'revoked_by')
        # Quien otorga es una cuenta de la empresa cliente (FK compuesta), una empresa no se delega en sí misma y
        # solo hay una delegación vigente por pareja.
        for sql, error in (("INSERT INTO org_delegations (organization_id, client_organization_id, granted_by)"
                            " VALUES ('%s', '%s', '%s');" % (ACME, OLMARDO, DANA_ID), 'org_delegations_granted_by_fk'),
                           ("INSERT INTO org_delegations (organization_id, client_organization_id, granted_by)"
                            " VALUES ('%s', '%s', '%s');" % (ACME, ACME, JORDAN_ID), 'org_delegations_otra_empresa'),
                           ("INSERT INTO org_delegations (organization_id, client_organization_id, granted_by)"
                            " VALUES ('%s', '%s', '%s');" % (ACME, BETA, DANA_ID), 'org_delegations_una_vigente')):
            with self.subTest(error=error):
                ok, _, err = psql('BEGIN; %s ROLLBACK;' % sql, user='postgres')
                self.assertFalse(ok)
                self.assertIn(error, err)

    def test_2_rls_forzado_politica_por_empresa_y_cirdan_app_solo_lee(self):
        self.assertEqual(scalar("SELECT c.relrowsecurity || ',' || c.relforcerowsecurity FROM pg_class c"
                                " WHERE c.oid = 'public.org_delegations'::regclass;", user='postgres'), 'true,true')
        self.assertEqual(scalar("SELECT string_agg(polname || ':' || polcmd || ':' || pg_get_expr(polqual, polrelid)"
                                " || ':' || pg_get_expr(polwithcheck, polrelid), '|') FROM pg_policy"
                                " WHERE polrelid = 'public.org_delegations'::regclass;", user='postgres'),
                         'tenant_isolation:*:(organization_id = app_current_org()):'
                         '(organization_id = app_current_org())')
        self.assertEqual(scalar("SELECT rolsuper || ',' || rolbypassrls FROM pg_roles WHERE rolname = 'cirdan_app';",
                                user='postgres'), 'false,false')
        self.assertEqual(scalar("SELECT string_agg(privilege_type, ',' ORDER BY privilege_type) FROM"
                                " information_schema.role_table_grants WHERE grantee = 'cirdan_app'"
                                " AND table_name = 'org_delegations';", user='postgres'), 'SELECT')
        for sql in ("INSERT INTO org_delegations (organization_id, client_organization_id, granted_by)"
                    " VALUES ('%s', '%s', '%s');" % (ACME, OLMARDO, OLMARDO_DEMO),
                    "UPDATE org_delegations SET revoked_at = now();",
                    "DELETE FROM org_delegations;"):
            with self.subTest(sql=sql):
                ok, _, err = psql('BEGIN; %s ROLLBACK;' % sql, org=ACME)
                self.assertFalse(ok)
                self.assertIn('permission denied', err)
        # La integradora ve su delegación. La cliente, otra empresa y una conexión sin empresa no ven nada.
        cuenta = "SELECT count(*) FROM org_delegations;"
        self.assertEqual(scalar(cuenta, org=ACME), '1')
        for org in (BETA, OLMARDO, LOWTIDE):
            with self.subTest(org=org):
                self.assertEqual(scalar(cuenta, org=org), '0')
        self.assertEqual(scalar(cuenta), '0')

    def test_3_las_politicas_que_ya_existian_no_cambian(self):
        """Fuera de org_delegations, cada política sigue siendo la de su migración: tenant_isolation con
        app_current_org() en las tablas por cliente, organizations por id y platform_admins_ninguna en false."""
        otras = scalar("SELECT coalesce(string_agg(c.relname || '.' || p.polname || '=' || coalesce(pg_get_expr("
                       "p.polqual, p.polrelid), '') || '/' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), ''),"
                       " ', ' ORDER BY c.relname), 'ninguna') FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid"
                       " WHERE c.relname NOT IN ('org_delegations', 'organizations', 'platform_admins')"
                       " AND NOT (p.polname = 'tenant_isolation' AND p.polcmd = '*' AND p.polpermissive"
                       " AND pg_get_expr(p.polqual, p.polrelid) = '(organization_id = app_current_org())'"
                       " AND pg_get_expr(p.polwithcheck, p.polrelid) = '(organization_id = app_current_org())');",
                       user='postgres')
        self.assertEqual(otras, 'ninguna')
        self.assertEqual(scalar("SELECT string_agg(polname || '=' || pg_get_expr(polqual, polrelid) || '/' ||"
                                " pg_get_expr(polwithcheck, polrelid), ',') FROM pg_policy"
                                " WHERE polrelid = 'public.organizations'::regclass;", user='postgres'),
                         'tenant_isolation=(id = app_current_org())/(id = app_current_org())')
        self.assertEqual(scalar("SELECT string_agg(polname || '=' || pg_get_expr(polqual, polrelid), ',') FROM"
                                " pg_policy WHERE polrelid = 'public.platform_admins'::regclass;", user='postgres'),
                         'platform_admins_ninguna=false')

    def test_4_ninguna_funcion_salta_rls_para_leer_delegaciones(self):
        self.assertEqual(scalar("SELECT coalesce(string_agg(proname, ','), 'ninguna') FROM pg_proc WHERE prosecdef"
                                " AND prosrc ILIKE '%org_delegations%';", user='postgres'), 'ninguna')


class Operador(unittest.TestCase):
    """La API con Jordan Tate como operator de Acme, con Beta y Olmardo delegadas."""

    @classmethod
    def setUpClass(cls):
        # Las limpiezas se registran antes del cambio: Jordan vuelve a analista aunque falle un login de aquí abajo.
        cls.addClassCleanup(rol, JORDAN_ID, 'analyst')
        cls.addClassCleanup(limpiar)
        sesion.reset()
        limpiar()
        rol(JORDAN_ID, 'operator')
        cls.alex = sesion.login(ALEX)
        cls.dana = sesion.login(DANA)

    jordan = None

    def setUp(self):
        # Cada prueba empieza con las dos delegaciones vigentes y Jordan como operator con TOTP.
        limpiar()
        delegar(BETA, DANA_ID)
        delegar(OLMARDO, OLMARDO_DEMO)
        rol(JORDAN_ID, 'operator')
        if Operador.jordan is None or Operador.jordan.get('/api/v1/auth/me')[0] != 200:
            Operador.jordan = sesion.login(JORDAN)

    def test_10_lista_con_el_riesgo_mas_alto_y_ordenada_por_el(self):
        code, body = self.jordan.get(LISTA)
        self.assertEqual(code, 200, body)
        self.assertEqual({i['id'] for i in body['items']}, {BETA, OLMARDO})
        self.assertEqual(body['total'], 2)
        for item in body['items']:
            with self.subTest(org=item['name']):
                self.assertEqual(item['risk_score'], riesgo(item['id']))
                self.assertEqual(set(item), {'id', 'name', 'status', 'risk_score', 'risk_band', 'domains_count'})
        claves = [(i['risk_score'] is None, -(i['risk_score'] or 0)) for i in body['items']]
        self.assertEqual(claves, sorted(claves))
        code, me = self.jordan.get('/api/v1/auth/me')
        self.assertEqual((code, me['role'], me['organization_id']), (200, 'operator', ACME))

    def test_11_una_empresa_delegada_trae_sus_dominios_y_su_riesgo(self):
        code, body = self.jordan.get('%s/%s' % (LISTA, BETA))
        self.assertEqual(code, 200, body)
        self.assertEqual((body['id'], body['name']), (BETA, 'Beta Corp'))
        self.assertEqual(body['risk_score'], riesgo(BETA))
        scores = [d['score'] for d in body['domains'] if d['score'] is not None]
        self.assertEqual(body['risk_score'], max(scores) if scores else None)
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(body['domains_count'], len(body['domains']))
        fqdns = scalar("SELECT coalesce(string_agg(fqdn::text, ',' ORDER BY fqdn), '') FROM domains"
                       " WHERE organization_id = '%s' AND status <> 'removed';" % BETA, user='postgres')
        self.assertEqual(sorted(d['fqdn'] for d in body['domains']), [f for f in fqdns.split(',') if f])

    def test_12_una_empresa_no_delegada_responde_404(self):
        for org in (LOWTIDE, ACME, str(uuid.uuid4()), 'no-es-uuid'):
            with self.subTest(org=org):
                self.assertEqual(self.jordan.get('%s/%s' % (LISTA, org)), (404, NO_ENCONTRADA))
        self.assertNotIn(LOWTIDE, {i['id'] for i in self.jordan.get(LISTA)[1]['items']})

    def test_13_una_delegacion_revocada_responde_404(self):
        self.assertEqual(self.jordan.get('%s/%s' % (LISTA, OLMARDO))[0], 200)
        revocar(OLMARDO, OLMARDO_DEMO)
        self.assertEqual(self.jordan.get('%s/%s' % (LISTA, OLMARDO)), (404, NO_ENCONTRADA))
        code, body = self.jordan.get(LISTA)
        self.assertEqual((code, [i['id'] for i in body['items']]), (200, [BETA]))
        # Revocada con la sesión abierta y sin cerrar sesión: no hay nada en caché.
        self.assertEqual(self.jordan.get('%s/%s' % (LISTA, BETA))[0], 200)

    def test_14_cada_lectura_queda_en_la_bitacora_de_la_empresa_cliente(self):
        cuenta = ("SELECT count(*) FROM audit_log WHERE organization_id = '%s' AND action = 'operator.client_data_read'"
                  " AND actor_type = 'platform' AND actor_user_id IS NULL AND details->>'platform_user_id' = '{0}'"
                  " AND details->>'operator_organization_id' = '{1}';").format(JORDAN_ID, ACME)
        antes = {org: int(scalar(cuenta % org, user='postgres')) for org in (BETA, OLMARDO, LOWTIDE)}
        self.assertEqual(self.jordan.get(LISTA)[0], 200)
        self.assertEqual(self.jordan.get('%s/%s' % (LISTA, BETA))[0], 200)
        self.assertEqual(self.jordan.get('%s/%s' % (LISTA, LOWTIDE))[0], 404)
        despues = {org: int(scalar(cuenta % org, user='postgres')) for org in (BETA, OLMARDO, LOWTIDE)}
        self.assertEqual({org: despues[org] - antes[org] for org in antes}, {BETA: 2, OLMARDO: 1, LOWTIDE: 0})
        for org in (ACME, BETA, OLMARDO):
            with self.subTest(cadena=org):
                self.assertEqual(scalar(CADENA % org, user='postgres'), 'true')

    def test_15_sin_totp_no_entra_con_contrasena_ni_a_la_consola(self):
        secreto = scalar("SELECT encode(totp_secret_enc, 'hex') FROM users WHERE id = '%s';" % JORDAN_ID,
                         user='postgres')
        habilitado = scalar("SELECT mfa_enabled_at::text FROM users WHERE id = '%s';" % JORDAN_ID, user='postgres')
        try:
            postgres("UPDATE users SET totp_secret_enc = NULL, mfa_enabled_at = NULL WHERE id = '%s';" % JORDAN_ID)
            # La sesión que ya tenía deja de entrar a la consola en la siguiente petición.
            self.assertEqual(self.jordan.get(LISTA), (403, {'detail': SOLO_OPERADOR}))
            cliente = Client()
            code, body = sesion.post_login(cliente, JORDAN, sesion.PASSWORD)
            self.assertEqual((code, body), (403, {'detail': MFA_OPERADOR}))
            self.assertIsNone(cliente.cookie())
            self.assertEqual(scalar("SELECT action FROM audit_log WHERE organization_id = '%s' AND actor_user_id ="
                                    " '%s' ORDER BY chain_seq DESC LIMIT 1;" % (ACME, JORDAN_ID), user='postgres'),
                             'auth.operator_mfa_required')
        finally:
            postgres("UPDATE users SET totp_secret_enc = decode('%s', 'hex'), mfa_enabled_at = '%s'::timestamptz"
                     " WHERE id = '%s';" % (secreto, habilitado, JORDAN_ID))
        self.assertEqual(self.jordan.get(LISTA)[0], 200)

    def test_16_otras_cuentas_reciben_403_y_sin_cookie_401(self):
        for nombre in ('alex', 'dana'):
            cliente = getattr(self, nombre)
            with self.subTest(cuenta=nombre):
                self.assertEqual(cliente.get(LISTA), (403, {'detail': SOLO_OPERADOR}))
                self.assertEqual(cliente.get('%s/%s' % (LISTA, BETA)), (403, {'detail': SOLO_OPERADOR}))
        self.assertEqual(Client().get(LISTA)[0], 401)
        # Con una cabecera de llave de API y sin cookie tampoco: la consola solo acepta la sesión.
        self.assertEqual(Client().get(LISTA, {'Authorization': 'Bearer CIRDAN_FAKE_llave'})[0], 401)

    def test_17_al_quitarle_el_rol_la_sesion_abierta_ya_no_entra(self):
        rol(JORDAN_ID, 'analyst')
        self.assertEqual(self.jordan.get(LISTA), (403, {'detail': SOLO_OPERADOR}))
        rol(JORDAN_ID, 'operator')
        self.assertEqual(self.jordan.get(LISTA)[0], 200)

    def test_18_un_operator_no_pasa_los_permisos_de_los_otros_roles(self):
        # En su propia empresa, una ruta de Admin y una de Admin o Gerente le responden 403.
        self.assertEqual(self.jordan.get('/api/v1/domains/txt')[0], 403)
        self.assertEqual(self.jordan.get('/api/v1/audit-log')[0], 403)


if __name__ == '__main__':
    unittest.main()
