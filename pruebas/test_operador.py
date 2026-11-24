"""Pruebas de la consola multiempresa del integrador (#66, RC-126): migración 033 y /api/v1/operator.

    python -m unittest -v pruebas/test_operador.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)

Hecho cuando de RC-126, punto por punto:
1. users.role acepta 'operator' y org_delegations tiene empresa integradora, empresa cliente, quién la otorgó y
   revocada, con RLS ENABLE, FORCE y tenant_isolation, y cirdan_app sin BYPASSRLS ni escritura (test_1 y test_2).
2. Las políticas RLS que ya existían no cambian: solo hay una nueva, la de org_delegations (test_3).
3. La API lee la delegación con RLS de la integradora y cada empresa cliente con la suya: ninguna función SECURITY
   DEFINER lee org_delegations y una cuenta de otra empresa no ve las delegaciones ajenas (test_2 y test_4).
4. El riesgo de cada empresa es el score vigente más alto de sus dominios y la lista sale ordenada por él (test_10 y
   test_11, con scores sembrados: uno viejo más alto que el vigente y un dominio quitado con el más alto de todos).
5. test_aislamiento.py sigue en verde (corre aparte, en la misma lista del CI).
6. Una empresa no delegada o una delegación revocada responden 404 (test_12 y test_13).

Además, del comentario 10270: cada lectura de un operador queda en la bitácora de la empresa cliente con actor
'operator', sin romper la cadena (test_5 y test_14), y el operador sin TOTP no entra con contraseña ni con passkey, y su
sesión se cierra (test_15 y test_19). Las cuentas normales, una sesión sin cookie y un operador al que se le quita el
rol reciben 403 o 401 (test_16 y test_17), y en su propia empresa un operador no lee dominios, hallazgos ni reportes
(test_18).

Jordan Tate (Analista de Acme, cuenta de demo) es operator solo durante estas pruebas: Acme hace de integradora y
Beta Corp y Grupo Olmardo le delegan. Lo que escriben como postgres lo deshacen al terminar, salvo la bitácora, que
es de solo inserción. Ninguna pide un escaneo: los scores de Beta y Olmardo entran directo en la base, sin triggers.
"""
import unittest
import uuid

from pruebas import sesion
from pruebas.sesion import Client
from pruebas.test_aislamiento import ACME, BETA, psql, scalar
from pruebas.test_passkeys import _alta_directa, _entrar, _limpiar_valkey
from pruebas.test_superadmin import CADENA, LOWTIDE, OLMARDO, OLMARDO_DEMO, DANA_ID, postgres
from pruebas.webauthn_falso import Autenticador

JORDAN_ID = '30000000-0000-4000-8000-000000000003'
JORDAN = 'jordan.tate@acme-demo.mx'   # analista de Acme, operator durante estas pruebas
ALEX = 'alex.morgan@acme-demo.mx'     # admin de Acme
DANA = 'dana.cruz@beta-corp.mx'       # admin de Beta

LISTA = '/api/v1/operator/organizations'
SOLO_OPERADOR = 'Solo una cuenta de operador con MFA activo puede usar la consola del integrador.'
NO_ENCONTRADA = {'detail': 'Organización no encontrada'}
MFA_OPERADOR = 'Las cuentas de operador deben tener MFA activo antes de iniciar sesión.'
SESION_TERMINADA = {'detail': 'Tu sesión terminó. Vuelve a iniciar sesión.'}
SIN_PERMISO = {'detail': 'Tu rol no tiene permiso para esta acción.'}
UUID_RE = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

# Las dos políticas de la 013 (013_pesos_por_organizacion.sql:27-36), tal como las devuelve pg_get_expr.
POLITICAS_013 = (
    'scoring_rule_sets.scoring_rule_sets_tenant_isolation=((organization_id IS NULL) OR (organization_id ='
    ' app_current_org()))/(organization_id = app_current_org())|'
    'scoring_rules.scoring_rules_tenant_isolation=(EXISTS ( SELECT 1\n   FROM scoring_rule_sets rs\n  WHERE ((rs.id ='
    ' scoring_rules.rule_set_id) AND ((rs.organization_id IS NULL) OR (rs.organization_id = app_current_org())))))/'
    '(EXISTS ( SELECT 1\n   FROM scoring_rule_sets rs\n  WHERE ((rs.id = scoring_rules.rule_set_id) AND'
    ' (rs.organization_id = app_current_org()))))')

# Score vigente (el último) más alto de los dominios no quitados de una empresa, calculado aparte como postgres.
RIESGO = ("SELECT coalesce(max(s.score)::text, 'null') FROM domains d LEFT JOIN LATERAL (SELECT ds.score FROM"
          " domain_scores ds WHERE ds.domain_id = d.id ORDER BY ds.computed_at DESC LIMIT 1) s ON true"
          " WHERE d.organization_id = '%s' AND d.status <> 'removed';")

# Scores de prueba (ids 7126...). beta-corp.mx tiene uno viejo de 90 y el vigente de 40, rc126-beta.mx el vigente de
# 55 y olmardo.com el vigente de 70. rc126-olmardo-quitado.mx está quitado y tiene 99: no cuenta. Así el riesgo de Beta
# es 55 (ni el 90 viejo ni el 40 de su primer dominio) y Olmardo (70) sale antes que Beta aunque por nombre va después.
BETA_DOM, OLMARDO_DOM = '40000000-0000-4000-8000-000000000006', '40000000-0000-4000-8000-000000000007'
BETA_DOM2, OLMARDO_QUITADO = '71260000-0000-4000-8000-000000000001', '71260000-0000-4000-8000-000000000002'
REGLAS = '90000000-0000-4000-8000-000000000001'
FALSO = '71260000-0000-4000-8000-0000000000ff'   # carta y TXT de los escaneos de prueba: entran sin triggers ni FK
SCORES = ((BETA, BETA_DOM, 90, '2 days'), (BETA, BETA_DOM, 40, '1 day'), (BETA, BETA_DOM2, 55, '1 day'),
          (OLMARDO, OLMARDO_DOM, 70, '1 day'), (OLMARDO, OLMARDO_QUITADO, 99, '1 day'))
RIESGO_BETA, RIESGO_OLMARDO = 55, 70


def _sembrar():
    filas = ["INSERT INTO domains (id, organization_id, fqdn, status, txt_token) VALUES"
             " ('%s', '%s', 'rc126-beta.mx', 'verified', 'rc126beta0001'),"
             " ('%s', '%s', 'rc126-olmardo-quitado.mx', 'removed', 'rc126olm0001');"
             % (BETA_DOM2, BETA, OLMARDO_QUITADO, OLMARDO)]
    for n, (org, dom, score, hace) in enumerate(SCORES, 1):
        filas.append("INSERT INTO scans (id, organization_id, domain_id, authorization_id, txt_verification_id,"
                     " trigger_type, status) VALUES ('71260000-0000-4000-8000-1000000000%02d', '%s', '%s', '%s', '%s',"
                     " 'on_demand', 'completed');" % (n, org, dom, FALSO, FALSO))
        filas.append("INSERT INTO domain_scores (id, organization_id, domain_id, scan_id, rule_set_id, score,"
                     " category_scores, reason, computed_at) VALUES ('71260000-0000-4000-8000-2000000000%02d', '%s',"
                     " '%s', '71260000-0000-4000-8000-1000000000%02d', '%s', %d, '{}', 'scan', now() - interval '%s');"
                     % (n, org, dom, n, REGLAS, score, hace))
    postgres('BEGIN; SET LOCAL session_replication_role = replica; %s COMMIT;' % ' '.join(filas))


def _quitar_semilla():
    postgres("BEGIN; SET LOCAL session_replication_role = replica;"
             " DELETE FROM domain_scores WHERE id::text LIKE '71260000-%';"
             " DELETE FROM scans WHERE id::text LIKE '71260000-%';"
             " DELETE FROM domains WHERE id::text LIKE '71260000-%'; COMMIT;")


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


def error_de(sql):
    ok, _, err = psql('BEGIN; %s ROLLBACK;' % sql, user='postgres')
    return None if ok else err


class Base(unittest.TestCase):
    """Migración 033, entrando como cirdan_app."""

    @classmethod
    def setUpClass(cls):
        cls.addClassCleanup(limpiar)
        limpiar()
        delegar(BETA, DANA_ID)

    def test_1_rol_operator_y_columnas_de_la_delegacion(self):
        self.assertIsNone(error_de("UPDATE users SET role = 'operator' WHERE id = '%s';" % JORDAN_ID))
        self.assertIn('users_role_check', error_de("UPDATE users SET role = 'otro' WHERE id = '%s';" % JORDAN_ID))
        columnas = scalar("SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid ="
                          " 'public.org_delegations'::regclass AND attnum > 0 AND NOT attisdropped;", user='postgres')
        self.assertEqual(columnas, 'id,organization_id,client_organization_id,granted_by,granted_at,revoked_at,'
                                   'revoked_by')
        alta = ("INSERT INTO org_delegations (organization_id, client_organization_id, granted_by)"
                " VALUES ('%s', '%s', '%s');")
        # Quien otorga es un admin activo de la empresa cliente (FK compuesta y trigger), una empresa no se delega en
        # sí misma, solo hay una delegación vigente por pareja y revoked_at y revoked_by van juntos.
        casos = (
            (alta % (ACME, OLMARDO, DANA_ID), 'org_delegations_granted_by_fk'),
            (alta % (ACME, ACME, JORDAN_ID), 'org_delegations_otra_empresa'),
            (alta % (ACME, BETA, DANA_ID), 'org_delegations_una_vigente'),
            ("UPDATE users SET role = 'analyst' WHERE id = '%s'; " % OLMARDO_DEMO
             + alta % (ACME, OLMARDO, OLMARDO_DEMO), 'org_delegations_quien_firma'),
            ("UPDATE users SET is_active = false WHERE id = '%s'; " % OLMARDO_DEMO
             + alta % (ACME, OLMARDO, OLMARDO_DEMO), 'org_delegations_quien_firma'),
            ("UPDATE org_delegations SET revoked_at = now() WHERE organization_id = '%s';" % ACME,
             'org_delegations_revocada'),
            ("UPDATE org_delegations SET revoked_by = '%s' WHERE organization_id = '%s';" % (DANA_ID, ACME),
             'org_delegations_revocada'),
            ("UPDATE users SET role = 'manager' WHERE id = '%s'; UPDATE org_delegations SET revoked_at = now(),"
             " revoked_by = '%s' WHERE organization_id = '%s';" % (DANA_ID, DANA_ID, ACME),
             'org_delegations_quien_firma'),
        )
        for sql, error in casos:
            with self.subTest(error=error, sql=sql):
                err = error_de(sql)
                self.assertIsNotNone(err)
                self.assertIn(error, err)
        # Lo correcto sí entra: un admin activo de Olmardo otorga y uno de Beta revoca.
        self.assertIsNone(error_de(alta % (ACME, OLMARDO, OLMARDO_DEMO)))
        self.assertIsNone(error_de("UPDATE org_delegations SET revoked_at = now(), revoked_by = '%s'"
                                   " WHERE organization_id = '%s';" % (DANA_ID, ACME)))

    def test_2_rls_forzado_politica_por_empresa_y_cirdan_app_solo_lee(self):
        self.assertEqual(scalar("SELECT c.relrowsecurity || ',' || c.relforcerowsecurity FROM pg_class c"
                                " WHERE c.oid = 'public.org_delegations'::regclass;", user='postgres'), 'true,true')
        self.assertEqual(scalar("SELECT string_agg(polname || ':' || polcmd::text || ':' || pg_get_expr(polqual,"
                                " polrelid) || ':' || pg_get_expr(polwithcheck, polrelid), '|') FROM pg_policy"
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
        app_current_org() en las tablas por cliente, organizations por id, las dos de la 013 con su expresión y
        platform_admins_ninguna en false."""
        especiales = ('org_delegations', 'organizations', 'platform_admins', 'scoring_rule_sets', 'scoring_rules')
        otras = scalar("SELECT coalesce(string_agg(c.relname || '.' || p.polname || '=' || coalesce(pg_get_expr("
                       "p.polqual, p.polrelid), '') || '/' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), ''),"
                       " ', ' ORDER BY c.relname), 'ninguna') FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid"
                       " WHERE c.relname NOT IN (%s)"
                       " AND NOT (p.polname = 'tenant_isolation' AND p.polcmd = '*' AND p.polpermissive"
                       " AND pg_get_expr(p.polqual, p.polrelid) = '(organization_id = app_current_org())'"
                       " AND pg_get_expr(p.polwithcheck, p.polrelid) = '(organization_id = app_current_org())');"
                       % ', '.join("'%s'" % t for t in especiales), user='postgres')
        self.assertEqual(otras, 'ninguna')
        self.assertEqual(scalar("SELECT string_agg(polname || '=' || pg_get_expr(polqual, polrelid) || '/' ||"
                                " pg_get_expr(polwithcheck, polrelid), ',') FROM pg_policy"
                                " WHERE polrelid = 'public.organizations'::regclass;", user='postgres'),
                         'tenant_isolation=(id = app_current_org())/(id = app_current_org())')
        self.assertEqual(scalar("SELECT string_agg(polname || '=' || pg_get_expr(polqual, polrelid), ',') FROM"
                                " pg_policy WHERE polrelid = 'public.platform_admins'::regclass;", user='postgres'),
                         'platform_admins_ninguna=false')
        self.assertEqual(scalar("SELECT string_agg(c.relname || '.' || p.polname || '=' || pg_get_expr(p.polqual,"
                                " p.polrelid) || '/' || pg_get_expr(p.polwithcheck, p.polrelid), '|' ORDER BY"
                                " c.relname) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid WHERE c.relname"
                                " IN ('scoring_rule_sets', 'scoring_rules') AND p.polcmd = '*' AND p.polpermissive;",
                                user='postgres'), POLITICAS_013)
        self.assertEqual(scalar("SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid"
                                " WHERE c.relname IN ('scoring_rule_sets', 'scoring_rules');", user='postgres'), '2')

    def test_4_ninguna_funcion_salta_rls_para_leer_delegaciones(self):
        self.assertEqual(scalar("SELECT coalesce(string_agg(proname, ','), 'ninguna') FROM pg_proc WHERE prosecdef"
                                " AND prosrc ILIKE '%org_delegations%';", user='postgres'), 'ninguna')
        self.assertEqual(scalar("SELECT prosecdef::text FROM pg_proc WHERE proname = 'org_delegations_quien_firma';",
                                user='postgres'), 'false')

    def test_5_actor_operator_en_la_bitacora_con_sus_ids(self):
        alta = ("INSERT INTO audit_log (organization_id, actor_type, actor_user_id, action, details) VALUES"
                " ('%s', 'operator', %s, 'operator.client_data_read', '%s');")
        bien = '{"operator_user_id": "%s", "operator_organization_id": "%s"}' % (JORDAN_ID, ACME)
        self.assertIsNone(error_de(alta % (BETA, 'NULL', bien)))
        for actor, details in (('NULL', '{}'), ('NULL', '{"operator_user_id": "%s"}' % JORDAN_ID),
                               ('NULL', '{"operator_user_id": "x", "operator_organization_id": "%s"}' % ACME),
                               ("'%s'" % DANA_ID, bien)):
            with self.subTest(actor=actor, details=details):
                self.assertIn('audit_log_operator_actor_check', error_de(alta % (BETA, actor, details)) or '')
        self.assertIn('audit_log_actor_type_check',
                      error_de("INSERT INTO audit_log (organization_id, actor_type, action) VALUES ('%s', 'otro',"
                               " 'x');" % BETA) or '')


class Operador(unittest.TestCase):
    """La API con Jordan Tate como operator de Acme, con Beta y Olmardo delegadas."""

    @classmethod
    def setUpClass(cls):
        # Las limpiezas se registran antes del cambio: Jordan vuelve a analista aunque falle un login de aquí abajo.
        cls.addClassCleanup(rol, JORDAN_ID, 'analyst')
        cls.addClassCleanup(limpiar)
        cls.addClassCleanup(_quitar_semilla)
        sesion.reset()
        limpiar()
        _quitar_semilla()
        _sembrar()
        rol(JORDAN_ID, 'operator')
        cls.alex = sesion.login(ALEX)
        cls.dana = sesion.login(DANA)

    jordan = None

    def setUp(self):
        # Cada prueba empieza con las dos delegaciones vigentes y Jordan como operator con TOTP y sesión abierta.
        limpiar()
        delegar(BETA, DANA_ID)
        delegar(OLMARDO, OLMARDO_DEMO)
        rol(JORDAN_ID, 'operator')
        if Operador.jordan is None or Operador.jordan.get('/api/v1/auth/me')[0] != 200:
            Operador.jordan = sesion.login(JORDAN)

    def test_10_lista_con_el_riesgo_mas_alto_y_ordenada_por_el(self):
        code, body = self.jordan.get(LISTA)
        self.assertEqual(code, 200, body)
        self.assertEqual([(i['id'], i['risk_score'], i['risk_band']) for i in body['items']],
                         [(OLMARDO, RIESGO_OLMARDO, 'high'), (BETA, RIESGO_BETA, 'medium')])
        self.assertEqual(body['total'], 2)
        for item in body['items']:
            with self.subTest(org=item['name']):
                self.assertEqual(item['risk_score'], riesgo(item['id']))
                self.assertEqual(set(item), {'id', 'name', 'status', 'risk_score', 'risk_band', 'domains_count'})
        code, me = self.jordan.get('/api/v1/auth/me')
        self.assertEqual((code, me['role'], me['organization_id']), (200, 'operator', ACME))

    def test_11_una_empresa_delegada_trae_sus_dominios_y_su_riesgo(self):
        code, body = self.jordan.get('%s/%s' % (LISTA, BETA))
        self.assertEqual(code, 200, body)
        self.assertEqual((body['id'], body['name'], body['risk_score'], body['risk_band']),
                         (BETA, 'Beta Corp', RIESGO_BETA, 'medium'))
        self.assertEqual(body['risk_score'], riesgo(BETA))
        # El score de cada dominio es el vigente (40, no el 90 viejo) y salen de más a menos riesgo.
        self.assertEqual([(d['fqdn'], d['score']) for d in body['domains']],
                         [('rc126-beta.mx', 55), ('beta-corp.mx', 40)])
        self.assertEqual(body['domains_count'], len(body['domains']))
        # En Olmardo el dominio quitado (99) no sale ni cuenta.
        code, body = self.jordan.get('%s/%s' % (LISTA, OLMARDO))
        self.assertEqual((code, body['risk_score'], [d['fqdn'] for d in body['domains']]),
                         (200, RIESGO_OLMARDO, ['olmardo.com']))

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
                  " AND actor_type = 'operator' AND actor_user_id IS NULL AND details->>'operator_user_id' = '{0}'"
                  " AND details->>'operator_organization_id' = '{1}' AND details->>'via' = 'delegation';"
                  ).format(JORDAN_ID, ACME)
        antes = {org: int(scalar(cuenta % org, user='postgres')) for org in (BETA, OLMARDO, LOWTIDE)}
        self.assertEqual(self.jordan.get(LISTA)[0], 200)
        self.assertEqual(self.jordan.get('%s/%s' % (LISTA, BETA))[0], 200)
        self.assertEqual(self.jordan.get('%s/%s' % (LISTA, LOWTIDE))[0], 404)
        despues = {org: int(scalar(cuenta % org, user='postgres')) for org in (BETA, OLMARDO, LOWTIDE)}
        self.assertEqual({org: despues[org] - antes[org] for org in antes}, {BETA: 2, OLMARDO: 1, LOWTIDE: 0})
        for org in (ACME, BETA, OLMARDO):
            with self.subTest(cadena=org):
                self.assertEqual(scalar(CADENA % org, user='postgres'), 't')
        # La admin de Beta lo ve en su bitácora como operador del integrador, no como superadmin de LowTide.
        code, body = self.dana.get('/api/v1/audit-log?limit=5')
        self.assertEqual(code, 200, body)
        lectura = next(e for e in body['items'] if e['action'] == 'operator.client_data_read')
        self.assertEqual((lectura['actor_type'], lectura['actor'], lectura['details']['operator_organization_id']),
                         ('operator', 'Operador del integrador', ACME))
        self.assertNotIn('platform_user_id', lectura['details'])

    def test_15_sin_totp_no_entra_con_contrasena_ni_a_la_consola(self):
        secreto = scalar("SELECT encode(totp_secret_enc, 'hex') FROM users WHERE id = '%s';" % JORDAN_ID,
                         user='postgres')
        habilitado = scalar("SELECT mfa_enabled_at::text FROM users WHERE id = '%s';" % JORDAN_ID, user='postgres')
        try:
            postgres("UPDATE users SET totp_secret_enc = NULL, mfa_enabled_at = NULL WHERE id = '%s';" % JORDAN_ID)
            # La sesión que ya tenía se cierra en la siguiente petición a la consola y ya no sirve para nada.
            self.assertEqual(self.jordan.get(LISTA), (401, SESION_TERMINADA))
            self.assertEqual(self.jordan.get('/api/v1/auth/me')[0], 401)
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
        Operador.jordan = sesion.login(JORDAN)
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

    def test_17_al_quitarle_el_rol_la_sesion_abierta_se_cierra(self):
        rol(JORDAN_ID, 'analyst')
        self.assertEqual(self.jordan.get(LISTA), (401, SESION_TERMINADA))
        rol(JORDAN_ID, 'operator')
        # Cerrada: volver a darle el rol no la revive.
        self.assertEqual(self.jordan.get(LISTA)[0], 401)
        Operador.jordan = sesion.login(JORDAN)
        self.assertEqual(self.jordan.get(LISTA)[0], 200)

    def test_18_un_operator_no_lee_ni_administra_su_propia_empresa(self):
        # Ni las rutas de un rol (Admin, Admin o Gerente) ni las que solo piden sesión: dominios, hallazgos, score,
        # reportes, plan de acción, exportaciones, activos y escaneos, en v1.py y en main.py.
        for ruta in ('/api/v1/domains/txt', '/api/v1/audit-log', '/api/v1/domains',
                     '/api/v1/domains/acme-demo.mx/findings', '/api/v1/domains/acme-demo.mx/score', '/api/v1/domains/acme-demo.mx/score/history',
                     '/api/v1/domains/acme-demo.mx/report', '/api/v1/domains/acme-demo.mx/action-plan',
                     '/api/v1/domains/acme-demo.mx/action-plan/export', '/api/v1/domains/acme-demo.mx/export/siem',
                     '/api/v1/domains/acme-demo.mx/findings/export', '/api/v1/domains/acme-demo.mx/assets',
                     '/api/v1/assets', '/api/v1/scans', '/api/v1/scoring/weights', '/api/v1/platform/organizations',
                     '/domains', '/domains/acme-demo.mx/score', '/domains/acme-demo.mx/findings'):
            with self.subTest(ruta=ruta):
                self.assertEqual(self.jordan.get(ruta), (403, SIN_PERMISO))
        # Su cuenta y la consola sí, y la misma ruta sigue sirviendo a una cuenta normal.
        self.assertEqual(self.jordan.get('/api/v1/auth/me')[0], 200)
        self.assertEqual(self.jordan.get(LISTA)[0], 200)
        self.assertEqual(self.alex.get('/api/v1/domains')[0], 200)

    def test_19_sin_totp_tampoco_entra_con_passkey(self):
        _limpiar_valkey()
        self.addCleanup(_limpiar_valkey)
        self.addCleanup(postgres, "DELETE FROM webauthn_credentials WHERE user_id = '%s';" % JORDAN_ID)
        autenticador = Autenticador()
        _alta_directa(autenticador)
        # Con su TOTP activo, la passkey le abre sesión.
        _, (code, body) = _entrar(autenticador)
        self.assertEqual(code, 200, body)
        secreto = scalar("SELECT encode(totp_secret_enc, 'hex') FROM users WHERE id = '%s';" % JORDAN_ID,
                         user='postgres')
        habilitado = scalar("SELECT mfa_enabled_at::text FROM users WHERE id = '%s';" % JORDAN_ID, user='postgres')
        try:
            postgres("UPDATE users SET totp_secret_enc = NULL, mfa_enabled_at = NULL WHERE id = '%s';" % JORDAN_ID)
            cliente, (code, body) = _entrar(autenticador)
            self.assertEqual((code, body), (403, {'detail': MFA_OPERADOR}))
            self.assertIsNone(cliente.cookie())
            self.assertEqual(scalar("SELECT action FROM audit_log WHERE organization_id = '%s' AND actor_user_id ="
                                    " '%s' ORDER BY chain_seq DESC LIMIT 1;" % (ACME, JORDAN_ID), user='postgres'),
                             'auth.operator_mfa_required')
            # Una cuenta que no es operator sigue entrando con passkey sin TOTP, como antes (RC-331).
            rol(JORDAN_ID, 'analyst')
            _, (code, body) = _entrar(autenticador)
            self.assertEqual(code, 200, body)
        finally:
            rol(JORDAN_ID, 'operator')
            postgres("UPDATE users SET totp_secret_enc = decode('%s', 'hex'), mfa_enabled_at = '%s'::timestamptz"
                     " WHERE id = '%s';" % (secreto, habilitado, JORDAN_ID))


if __name__ == '__main__':
    unittest.main()
