"""Pruebas del superadmin de la plataforma (RC-332): migración 017, semilla 016 y /api/v1/platform.

    python -m unittest -v pruebas/test_superadmin.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)

Hecho cuando de RC-332, punto por punto:
1. El superadmin ve todas las organizaciones y cambia a cualquiera sin cerrar sesión. Un Admin, un Gerente o un
   Analista normal recibe 403 y /auth/me le dice platform_admin false (test_10 a test_12).
2. En la empresa activa ve sus dominios y sus hallazgos y ningún dato de otra; cada lectura exitosa queda en la
   bitácora de esa empresa (test_13).
3. /auth/me, contraseña y MFA siguen funcionando con cualquier empresa activa (test_14).
4. cirdan_app no lee ni escribe platform_admins y una sesión normal no cambia de empresa aunque mande el id
   (test_1, test_2 y test_11).
5. Cada cambio y cada acción en una empresa ajena queda en su bitácora con actor 'platform', sin romper la cadena
   (test_3, test_15 y test_16).
6. Crear una llave de API en una empresa ajena responde 403 (test_13).

Además, de la revisión de riesgo: sin TOTP activo nadie es superadmin (test_2), cambiar la contraseña cierra las
demás sesiones (test_18), la sesión en una empresa ajena se cierra si esa empresa se suspende (test_19) y /auth/me
deja de decir platform_admin en cuanto se quita el permiso (test_20).

equipo@lowtidesec.com no es cuenta de demo y su contraseña no está en el repo, así que las pruebas de la API hacen
superadmin por un rato a Dana Cruz (Admin de Beta Corp) y la quitan al terminar. Ninguna pide un escaneo. Lo que
escriben como postgres lo deshacen en tearDown, salvo la bitácora, que es de solo inserción.
"""
import unittest
import uuid

from pruebas import sesion
from pruebas.sesion import Client
from pruebas.test_aislamiento import ACME, BETA, psql, scalar
from pruebas.webauthn_falso import Autenticador

OLMARDO = '20000000-0000-4000-8000-000000000003'
LOWTIDE = '20000000-0000-4000-8000-000000000004'
EQUIPO = '30000000-0000-4000-8000-000000000006'      # equipo@lowtidesec.com (semilla 015)
OLMARDO_DEMO = '30000000-0000-4000-8000-000000000005'  # admin@olmardo.com, cuenta de demo
DANA_ID = '30000000-0000-4000-8000-000000000004'
ALEX_ID = '30000000-0000-4000-8000-000000000001'
DANA = 'dana.cruz@beta-corp.mx'       # admin de Beta, superadmin solo durante estas pruebas
ALEX = 'alex.morgan@acme-demo.mx'     # admin de Acme
MAYA = 'maya.reed@acme-demo.mx'       # gerente de Acme
JORDAN = 'jordan.tate@acme-demo.mx'   # analista de Acme

LISTA = '/api/v1/platform/organizations'
CAMBIO = '/api/v1/platform/organization'
PASSKEYS = '/api/v1/auth/passkeys'
SOLO_SUPERADMIN = 'Solo el superadmin de la plataforma puede hacer esto.'
SIN_SESION = 'Tu sesión terminó. Vuelve a iniciar sesión.'
NOMBRE_LLAVE = 'CIRDAN_FAKE_superadmin'

# La cadena de la bitácora de una empresa, recalculada con la fórmula del trigger audit_log_chain() de la 001.
CADENA = ("SELECT coalesce(bool_and(ok), true) FROM (SELECT row_hash = sha256(prev_hash || convert_to(concat_ws(chr(31),"
          " coalesce(organization_id::text, ''), chain_seq::text, id::text,"
          " (extract(epoch FROM occurred_at) * 1000000)::bigint::text, actor_type, coalesce(actor_user_id::text, ''),"
          " coalesce(actor_api_key_id::text, ''), action, coalesce(entity_type, ''), coalesce(entity_id::text, ''),"
          " details::text), 'UTF8'))"
          " AND prev_hash = coalesce(lag(row_hash) OVER (ORDER BY chain_seq), decode(repeat('00', 32), 'hex'))"
          " AND chain_seq = row_number() OVER (ORDER BY chain_seq) AS ok"
          " FROM audit_log WHERE organization_id = '%s') t;")


def postgres(sql):
    ok, out, err = psql(sql, user='postgres')
    if not ok:
        raise AssertionError(err)
    return out


def hacer_superadmin(user_id):
    postgres("INSERT INTO platform_admins (user_id, note) VALUES ('%s', 'CIRDAN_FAKE_ prueba de RC-332')"
             " ON CONFLICT DO NOTHING;" % user_id)


def quitar_superadmin(user_id):
    postgres("DELETE FROM platform_admins WHERE user_id = '%s';" % user_id)


def ultima(org, accion):
    """actor_type, actor_user_id y el superadmin de details del último registro de esa acción en esa empresa."""
    return scalar("SELECT actor_type || ',' || coalesce(actor_user_id::text, '-') || ',' ||"
                  " coalesce(details->>'platform_user_id', '-') FROM audit_log WHERE organization_id = '%s'"
                  " AND action = '%s' ORDER BY chain_seq DESC LIMIT 1;" % (org, accion), user='postgres')


class Base(unittest.TestCase):
    """Migraciones 017 y 026 y semilla 016, entrando como cirdan_app."""

    def test_1_cirdan_app_no_lee_ni_escribe_platform_admins(self):
        for sql in ("SELECT count(*) FROM platform_admins;",
                    "INSERT INTO platform_admins (user_id, note) VALUES ('%s', 'x');" % ALEX_ID,
                    "DELETE FROM platform_admins;",
                    "UPDATE platform_admins SET note = 'x';"):
            with self.subTest(sql=sql):
                ok, _, err = psql('BEGIN; %s ROLLBACK;' % sql, org=LOWTIDE)
                self.assertFalse(ok)
                self.assertIn('permission denied', err)
        self.assertEqual(scalar("SELECT c.relrowsecurity || ',' || c.relforcerowsecurity FROM pg_class c"
                                " WHERE c.oid = 'public.platform_admins'::regclass;", user='postgres'), 'true,true')

    def test_2_solo_equipo_es_superadmin_y_solo_el_ve_la_lista(self):
        self.assertEqual(scalar("SELECT string_agg(user_id::text, ',' ORDER BY user_id) FROM platform_admins"
                                " WHERE note NOT LIKE 'CIRDAN_FAKE_%%';", user='postgres'), EQUIPO)
        self.assertEqual(scalar("SELECT public.is_platform_admin('%s')::text;" % OLMARDO_DEMO), 'false')
        self.assertEqual(scalar("SELECT count(*) FROM public.platform_organizations('%s');" % OLMARDO_DEMO), '0')
        # Con y sin TOTP, puestos en transacciones que se deshacen: no depende de si equipo ya lo activó en esta base.
        con_y_sin = ("BEGIN; UPDATE users SET totp_secret_enc = %s, mfa_enabled_at = %s WHERE id = '{0}';"
                     " SELECT public.is_platform_admin('{0}') || '|' || coalesce((SELECT string_agg(name, ','"
                     " ORDER BY name) FROM public.platform_organizations('{0}')), ''); ROLLBACK;")
        admin, nombres = scalar((con_y_sin % ('NULL', 'NULL')).format(EQUIPO), user='postgres').split('|')
        self.assertEqual((admin, nombres), ('false', ''))
        admin, nombres = scalar((con_y_sin % ("'\\x00'::bytea", 'now()')).format(EQUIPO), user='postgres').split('|')
        self.assertEqual(admin, 'true')
        for nombre in ('Acme Demo', 'Beta Corp', 'Grupo Olmardo', 'LowTide'):
            self.assertIn(nombre, nombres.split(','))
        self.assertEqual(scalar("SELECT public.platform_operator_requires_mfa('%s')::text;" % EQUIPO), 'true')
        self.assertEqual(scalar("SELECT public.platform_operator_requires_mfa('%s')::text;" % OLMARDO_DEMO), 'false')
        # Las funciones son SECURITY DEFINER con search_path fijo, como login_lookup().
        self.assertEqual(scalar("SELECT string_agg(proname || ':' || prosecdef || ':' || array_to_string(proconfig, ';'),"
                                " '|' ORDER BY proname) FROM pg_proc WHERE proname IN"
                                " ('is_platform_admin', 'platform_organizations', 'platform_operator_requires_mfa');",
                                user='postgres'),
                         'is_platform_admin:true:search_path=pg_catalog, public, pg_temp|'
                         'platform_operator_requires_mfa:true:search_path=pg_catalog, public, pg_temp|'
                         'platform_organizations:true:search_path=pg_catalog, public, pg_temp')

    def test_3_actor_platform_sin_usuario_y_con_su_id(self):
        base = ("BEGIN; INSERT INTO audit_log (organization_id, actor_type, actor_user_id, action, details)"
                " VALUES ('%s', 'platform', %s, 'CIRDAN_FAKE_prueba', '%s'); ROLLBACK;")
        ok, _, err = psql(base % (ACME, 'NULL', '{}'), org=ACME)
        self.assertFalse(ok)
        self.assertIn('audit_log_platform_actor_check', err)
        ok, _, err = psql(base % (ACME, "'%s'" % ALEX_ID, '{"platform_user_id": "%s"}' % DANA_ID), org=ACME)
        self.assertFalse(ok)
        self.assertIn('audit_log_platform_actor_check', err)
        for malo in ('"x"', 'null', '7'):
            with self.subTest(platform_user_id=malo):
                ok, _, err = psql(base % (ACME, 'NULL', '{"platform_user_id": %s}' % malo), org=ACME)
                self.assertFalse(ok)
                self.assertIn('audit_log_platform_actor_check', err)
        ok, _, err = psql(base % (ACME, 'NULL', '{"platform_user_id": "%s"}' % DANA_ID), org=ACME)
        self.assertTrue(ok, err)


class Superadmin(unittest.TestCase):
    """La API con Dana Cruz como superadmin por un rato."""

    @classmethod
    def setUpClass(cls):
        # Las limpiezas se registran antes de nombrar a Dana: corren aunque falle un login de aquí abajo, y Dana, con
        # credenciales de demo públicas, nunca se queda en platform_admins.
        cls.addClassCleanup(postgres, "DELETE FROM api_keys WHERE name LIKE 'CIRDAN\\_FAKE\\_%';")
        cls.addClassCleanup(quitar_superadmin, DANA_ID)
        sesion.reset()
        hacer_superadmin(DANA_ID)
        cls.alex = sesion.login(ALEX)
        cls.maya = sesion.login(MAYA)
        cls.jordan = sesion.login(JORDAN)

    dana = None

    def setUp(self):
        # Una sola sesión de Dana mientras sirva (cada inicio gasta un código TOTP y puede esperar 30 s). Las pruebas
        # que la cierran la dejan para que la siguiente inicie otra. Cada prueba empieza en Beta, su empresa.
        hacer_superadmin(DANA_ID)
        if Superadmin.dana is None or Superadmin.dana.get('/api/v1/auth/me')[0] != 200:
            Superadmin.dana = sesion.login(DANA)
        self.assertEqual(self.cambiar(BETA)[0], 200)

    def cambiar(self, org, cliente=None):
        return (cliente or self.dana).post(CAMBIO, {'organization_id': org})

    def test_10_superadmin_ve_todas_y_su_me_lo_dice(self):
        code, body = self.dana.get(LISTA)
        self.assertEqual(code, 200, body)
        por_id = {o['id']: o for o in body['items']}
        for org in (ACME, BETA, OLMARDO, LOWTIDE):
            self.assertIn(org, por_id)
        self.assertEqual(set(body['items'][0]), {'id', 'name', 'status', 'active', 'home'})
        self.assertEqual([o['id'] for o in body['items'] if o['active']], [BETA])
        self.assertEqual([o['id'] for o in body['items'] if o['home']], [BETA])
        code, me = self.dana.get('/api/v1/auth/me')
        self.assertEqual(code, 200)
        self.assertEqual((me['platform_admin'], me['home_organization_id'], me['home_organization_name'],
                          me['organization_name'], me['role']), (True, BETA, 'Beta Corp', 'Beta Corp', 'admin'))

    def test_09_operador_no_inicia_sesion_con_solo_contrasena_si_no_tiene_mfa(self):
        secreto = scalar("SELECT encode(totp_secret_enc, 'hex') FROM users WHERE id = '%s';" % DANA_ID,
                         user='postgres')
        habilitado = scalar("SELECT mfa_enabled_at::text FROM users WHERE id = '%s';" % DANA_ID, user='postgres')
        try:
            postgres("UPDATE users SET totp_secret_enc = NULL, mfa_enabled_at = NULL WHERE id = '%s';" % DANA_ID)
            cliente = Client()
            code, body = sesion.post_login(cliente, DANA, sesion.PASSWORD)
            # Sin el token de alta del Admin (RC-5): con la contraseña sola daría una sesión de superadmin (H1).
            self.assertEqual((code, body), (403, {
                'detail': 'Las cuentas de operador deben tener MFA activo antes de iniciar sesión.'
            }))
            self.assertIsNone(cliente.cookie())
        finally:
            postgres("UPDATE users SET totp_secret_enc = decode('%s', 'hex'), mfa_enabled_at = '%s'::timestamptz"
                     " WHERE id = '%s';" % (secreto, habilitado, DANA_ID))

    def test_09b_el_token_de_alta_no_sirve_si_la_cuenta_pasa_a_operador(self):
        # Un token sacado como Admin sin TOTP deja de servir si la cuenta entra a platform_admins (H1 de RC-5).
        secreto = scalar("SELECT encode(totp_secret_enc, 'hex') FROM users WHERE id = '%s';" % DANA_ID,
                         user='postgres')
        habilitado = scalar("SELECT mfa_enabled_at::text FROM users WHERE id = '%s';" % DANA_ID, user='postgres')
        try:
            postgres("UPDATE users SET totp_secret_enc = NULL, mfa_enabled_at = NULL WHERE id = '%s';" % DANA_ID)
            quitar_superadmin(DANA_ID)
            code, body = sesion.post_login(Client(), DANA, sesion.PASSWORD)
            self.assertEqual((code, body.get('mfa_setup_required')), (403, True), body)
            hacer_superadmin(DANA_ID)
            cliente = Client()
            self.assertEqual(cliente.post('/api/v1/auth/mfa/enroll/setup', {'mfa_setup_token': body['mfa_setup_token']}),
                             (401, {'detail': 'Tu verificación expiró. Inicia sesión de nuevo.'}))
            self.assertIsNone(cliente.cookie())
            self.assertEqual(scalar("SELECT totp_secret_enc IS NULL FROM users WHERE id = '%s';" % DANA_ID,
                                    user='postgres'), 't')
        finally:
            hacer_superadmin(DANA_ID)
            postgres("UPDATE users SET totp_secret_enc = decode('%s', 'hex'), mfa_enabled_at = '%s'::timestamptz"
                     " WHERE id = '%s';" % (secreto, habilitado, DANA_ID))

    def test_11_cuentas_normales_reciben_403_aunque_manden_el_id(self):
        for nombre in ('alex', 'maya', 'jordan'):
            cliente = getattr(self, nombre)
            with self.subTest(cuenta=nombre):
                self.assertEqual(cliente.get(LISTA), (403, {'detail': SOLO_SUPERADMIN}))
                self.assertEqual(self.cambiar(BETA, cliente), (403, {'detail': SOLO_SUPERADMIN}))
                code, me = cliente.get('/api/v1/auth/me')
                self.assertEqual((code, me['platform_admin'], me['organization_id']), (200, False, ACME))
                self.assertNotIn('home_organization_id', me)
        self.assertEqual(Client().get(LISTA)[0], 401)  # sin cookie
        # Una sesión iniciada antes de ser superadmin no lo es: la bandera se fija al iniciar sesión.
        hacer_superadmin(ALEX_ID)
        try:
            self.assertEqual(self.cambiar(BETA, self.alex), (403, {'detail': SOLO_SUPERADMIN}))
        finally:
            quitar_superadmin(ALEX_ID)

    def test_12_cambia_de_empresa_sin_cerrar_sesion_y_regresa_a_la_suya(self):
        code, body = self.cambiar(ACME)
        self.assertEqual((code, body), (200, {'organization_id': ACME, 'organization_name': 'Acme Demo',
                                              'role': 'admin', 'home': False}))
        code, me = self.dana.get('/api/v1/auth/me')
        self.assertEqual((me['organization_id'], me['organization_name'], me['home_organization_name'], me['email']),
                         (ACME, 'Acme Demo', 'Beta Corp', DANA))
        code, body = self.dana.get(LISTA)
        self.assertEqual([o['id'] for o in body['items'] if o['active']], [ACME])
        code, body = self.cambiar(BETA)
        self.assertEqual((code, body['role'], body['home']), (200, 'admin', True))
        self.assertEqual(self.dana.get('/api/v1/auth/me')[1]['organization_id'], BETA)
        for malo in (str(uuid.uuid4()), 'no-es-uuid'):
            with self.subTest(org=malo):
                self.assertEqual(self.cambiar(malo), (404, {'detail': 'Organización no encontrada'}))

    def test_13_en_acme_ve_solo_lo_de_acme_y_no_crea_llaves(self):
        self.assertEqual(self.cambiar(ACME)[0], 200)
        lecturas = scalar("SELECT count(*) FROM audit_log WHERE organization_id = '%s' AND action ="
                          " 'platform.client_data_read';" % ACME, user='postgres')
        self.assertEqual(self.dana.get('/api/v1/auth/me')[0], 200)
        self.assertEqual(self.dana.get(LISTA)[0], 200)
        self.assertEqual(scalar("SELECT count(*) FROM audit_log WHERE organization_id = '%s' AND action ="
                                " 'platform.client_data_read';" % ACME, user='postgres'), lecturas)
        code, body = self.dana.get('/api/v1/domains')
        self.assertEqual(code, 200)
        self.assertEqual(ultima(ACME, 'platform.client_data_read'), 'platform,-,%s' % DANA_ID)
        self.assertEqual(int(scalar("SELECT count(*) FROM audit_log WHERE organization_id = '%s' AND action ="
                                    " 'platform.client_data_read';" % ACME, user='postgres')), int(lecturas) + 1)
        self.assertEqual(scalar("SELECT details->>'route' FROM audit_log WHERE organization_id = '%s' AND action ="
                                " 'platform.client_data_read' ORDER BY chain_seq DESC LIMIT 1;" % ACME,
                                user='postgres'),
                         '/api/v1/domains')
        dominios = {d['fqdn'] for d in body['items']}
        self.assertIn('acme-demo.mx', dominios)
        self.assertNotIn('beta-corp.mx', dominios)
        # Hallazgos con Acme activa: la lista de acme-demo.mx trae exactamente sus hallazgos abiertos (leídos como
        # postgres) y ninguno de Beta. Ni la lista de beta-corp.mx ni la explicación de un hallazgo de Beta por su id
        # se ven desde Acme. Que la RLS de findings separe empresas para cualquier sesión ya lo prueba test_aislamiento
        # (test_2). Aquí se prueba que la empresa activa del superadmin es la que manda.
        abiertos = set(postgres("SELECT f.id FROM findings f JOIN domains d ON d.id = f.domain_id"
                                " WHERE d.organization_id = '%s' AND d.fqdn = 'acme-demo.mx'"
                                " AND f.status = 'open';" % ACME).split())
        de_beta = set(postgres("SELECT id FROM findings WHERE organization_id = '%s';" % BETA).split())
        self.assertTrue(abiertos, 'la semilla 001 trae hallazgos abiertos de acme-demo.mx')
        self.assertIn('80000000-0000-4000-8000-000000000011', de_beta, 'la semilla 001 trae el RDP de Beta')
        code, body = self.dana.get('/api/v1/domains/acme-demo.mx/findings')
        self.assertEqual(code, 200, body)
        vistos = {f['id'] for f in body['items']}
        self.assertEqual(vistos, abiertos)
        self.assertEqual((body['domain'], body['total']), ('acme-demo.mx', len(abiertos)))
        self.assertFalse(vistos & de_beta)
        self.assertEqual(scalar("SELECT details->'path_params'->>'fqdn' FROM audit_log WHERE organization_id = '%s'"
                                " AND action = 'platform.client_data_read' ORDER BY chain_seq DESC LIMIT 1;" % ACME,
                                user='postgres'), 'acme-demo.mx')
        lecturas = scalar("SELECT count(*) FROM audit_log WHERE organization_id = '%s' AND action ="
                          " 'platform.client_data_read';" % ACME, user='postgres')
        self.assertEqual(self.dana.get('/api/v1/domains/beta-corp.mx/findings'),
                         (404, {'detail': 'Dominio no encontrado para esta organización'}))
        self.assertEqual(scalar("SELECT count(*) FROM audit_log WHERE organization_id = '%s' AND action ="
                                " 'platform.client_data_read';" % ACME, user='postgres'), lecturas)
        self.assertEqual(self.dana.get('/api/v1/findings/80000000-0000-4000-8000-000000000011/explanation'),
                         (404, {'detail': 'Hallazgo no encontrado'}))
        self.assertEqual(self.dana.get('/api/v1/api-keys')[0], 200)
        self.assertEqual(self.dana.get('/api/v1/scoring/weights')[0], 200)
        code, body = self.dana.post('/api/v1/api-keys', {'name': NOMBRE_LLAVE, 'own_use': True})
        self.assertEqual(code, 403)
        self.assertIn('no crearlas', body['detail'])
        self.assertEqual(scalar("SELECT count(*) FROM api_keys WHERE name = '%s';" % NOMBRE_LLAVE, user='postgres'), '0')

    def test_14_me_contrasena_y_mfa_con_la_empresa_ajena_activa(self):
        self.assertEqual(self.cambiar(OLMARDO)[0], 200)
        self.assertEqual(self.dana.get('/api/v1/auth/me')[0], 200)
        # La misma contraseña como nueva: la fila de Dana solo se ve con RLS de Beta, y aquí se encuentra.
        self.assertEqual(self.dana.post('/api/v1/auth/password', {'current_password': sesion.PASSWORD,
                                                                  'new_password': sesion.PASSWORD}), (200, {'passkeys_removed': 0}))
        # Con MFA ya activo, el alta responde 409. Si no se viera la fila, respondería 401 y cerraría la sesión.
        code, body = self.dana.post('/api/v1/auth/mfa/setup', {'current_password': sesion.PASSWORD})
        self.assertEqual(code, 409, body)
        self.assertEqual(ultima(BETA, 'auth.password_changed'), 'user,%s,-' % DANA_ID)
        self.assertEqual(self.dana.post('/api/v1/auth/logout'), (204, None))
        self.assertEqual(ultima(BETA, 'auth.logout'), 'user,%s,-' % DANA_ID)

    def test_14b_passkeys_propias_con_la_empresa_ajena_activa(self):
        # R3-14 de RC-331: las rutas de passkeys usan la empresa de la cuenta. Con la ajena, register/options no veía la
        # fila de Dana, cerraba la sesión y respondía 401, y la lista salía vacía.
        self.addCleanup(postgres, "DELETE FROM webauthn_credentials WHERE user_id = '%s';" % DANA_ID)
        self.assertEqual(self.cambiar(OLMARDO)[0], 200)
        code, body = self.dana.post(PASSKEYS + '/register/options', {'current_password': sesion.PASSWORD,
                                                                     'code': sesion.next_code(DANA)})
        self.assertEqual(code, 200, body)
        code, fila = self.dana.post(PASSKEYS + '/register/verify',
                                    {'credential': Autenticador().registro(body['options']), 'name': 'Llave de Dana'})
        self.assertEqual(code, 201, fila)
        self.assertEqual(scalar("SELECT organization_id FROM webauthn_credentials WHERE id = '%s';" % fila['id'],
                                user='postgres'), BETA)
        self.assertEqual(ultima(BETA, 'auth.passkey_registered'), 'user,%s,-' % DANA_ID)
        code, lista = self.dana.get(PASSKEYS)
        self.assertEqual((code, [p['id'] for p in lista['passkeys']]), (200, [fila['id']]))
        self.assertEqual(self.dana.request('DELETE', PASSKEYS + '/' + fila['id']), (204, None))
        self.assertEqual(ultima(BETA, 'auth.passkey_deleted'), 'user,%s,-' % DANA_ID)
        # Y cambiar la contraseña con la ajena activa borra la suya, con la bitácora en Beta.
        body = self.dana.post(PASSKEYS + '/register/options', {'current_password': sesion.PASSWORD,
                                                               'code': sesion.next_code(DANA)})[1]
        self.assertEqual(self.dana.post(PASSKEYS + '/register/verify',
                                        {'credential': Autenticador().registro(body['options']), 'name': 'Otra'})[0], 201)
        self.assertEqual(self.dana.post('/api/v1/auth/password', {'current_password': sesion.PASSWORD,
                                                                  'new_password': sesion.PASSWORD}),
                         (200, {'passkeys_removed': 1}))
        self.assertEqual(self.dana.get('/api/v1/auth/me')[0], 200)

    def test_15_bitacora_en_las_dos_empresas_y_cadena_intacta(self):
        self.assertEqual(self.cambiar(ACME)[0], 200)
        self.assertEqual(ultima(BETA, 'platform.organization_switched'), 'user,%s,-' % DANA_ID)
        self.assertEqual(ultima(ACME, 'platform.organization_entered'), 'platform,-,%s' % DANA_ID)
        # En la empresa ajena solo queda el id del superadmin, no su correo.
        detalles = scalar("SELECT details::text FROM audit_log WHERE organization_id = '%s' AND action ="
                          " 'platform.organization_entered' ORDER BY chain_seq DESC LIMIT 1;" % ACME, user='postgres')
        self.assertIn(DANA_ID, detalles)
        self.assertNotIn('email', detalles)
        self.assertNotIn(DANA, detalles)
        # Revocar una llave de Acme queda a nombre del superadmin con actor 'platform'.
        llave = postgres("INSERT INTO api_keys (organization_id, name, key_prefix, key_hash, scopes, created_by, expires_at)"
                         " VALUES ('%s', '%s', 'ffff0332', sha256('CIRDAN_FAKE_332'::bytea), '{read}', '%s',"
                         " now() + interval '1 day') RETURNING id;" % (ACME, NOMBRE_LLAVE, ALEX_ID)).splitlines()[0]
        self.assertEqual(self.dana.request('DELETE', '/api/v1/api-keys/' + llave), (204, None))
        self.assertEqual(ultima(ACME, 'api_key.revoked'), 'platform,-,%s' % DANA_ID)
        for org in (ACME, BETA):
            with self.subTest(org=org):
                self.assertEqual(scalar(CADENA % org, user='postgres'), 't')

    def test_16_quitarle_el_permiso_cierra_su_sesion_en_la_empresa_ajena(self):
        self.assertEqual(self.cambiar(ACME)[0], 200)
        quitar_superadmin(DANA_ID)
        self.assertEqual(self.dana.get('/api/v1/domains'), (401, {'detail': SIN_SESION}))
        self.assertEqual(self.dana.get('/api/v1/auth/me')[0], 401)  # la sesión ya se borró

    def test_17_no_entra_a_una_empresa_suspendida(self):
        postgres("UPDATE organizations SET status = 'suspended' WHERE id = '%s';" % OLMARDO)
        try:
            code, body = self.cambiar(OLMARDO)
        finally:
            postgres("UPDATE organizations SET status = 'active' WHERE id = '%s';" % OLMARDO)
        self.assertEqual(code, 409, body)
        self.assertEqual(self.dana.get('/api/v1/auth/me')[1]['organization_id'], BETA)

    def test_18_cambiar_la_contrasena_cierra_las_demas_sesiones(self):
        otra = sesion.login(DANA)
        self.assertEqual(otra.post('/api/v1/auth/password', {'current_password': sesion.PASSWORD,
                                                             'new_password': sesion.PASSWORD}), (200, {'passkeys_removed': 0}))
        self.assertEqual(self.dana.get('/api/v1/auth/me'), (401, {'detail': SIN_SESION}))
        self.assertEqual(otra.get('/api/v1/auth/me')[0], 200)
        Superadmin.dana = otra

    def test_19_si_suspenden_la_empresa_ajena_se_cierra_su_sesion_en_ella(self):
        self.assertEqual(self.cambiar(OLMARDO)[0], 200)
        postgres("UPDATE organizations SET status = 'suspended' WHERE id = '%s';" % OLMARDO)
        try:
            self.assertEqual(self.dana.get('/api/v1/domains'), (401, {'detail': SIN_SESION}))
        finally:
            postgres("UPDATE organizations SET status = 'active' WHERE id = '%s';" % OLMARDO)
        self.assertEqual(self.dana.get('/api/v1/auth/me')[0], 401)  # la sesión ya se borró

    def test_20_me_deja_de_decir_superadmin_al_quitarle_el_permiso_en_casa(self):
        self.assertEqual(self.dana.get('/api/v1/auth/me')[1]['platform_admin'], True)
        quitar_superadmin(DANA_ID)
        code, me = self.dana.get('/api/v1/auth/me')
        self.assertEqual((code, me['platform_admin'], me['organization_id']), (200, False, BETA))
        self.assertNotIn('home_organization_id', me)
        self.assertEqual(self.dana.get(LISTA), (403, {'detail': SOLO_SUPERADMIN}))


if __name__ == '__main__':
    unittest.main()
