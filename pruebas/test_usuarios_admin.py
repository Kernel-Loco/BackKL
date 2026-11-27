"""API del Admin para los usuarios de su empresa (#141, RC-259) contra el compose desechable.

    python -m unittest -v pruebas/test_usuarios_admin.py      (con el compose desechable)

El Admin lista, cambia un rol, da de baja y de alta y registra la revisión de accesos. Otro rol recibe 403, un Admin de
otra empresa 404, nadie se quita su propio rol y la baja corta la sesión abierta y revoca las llaves de la cuenta.
Las reglas, sin base, están en pruebas/test_cuentas.py.
"""
import unittest

from pruebas import sesion
from pruebas.test_aislamiento import ACME, psql, scalar

ALEX, MAYA, JORDAN, DANA = ('alex.morgan@acme-demo.mx', 'maya.reed@acme-demo.mx', 'jordan.tate@acme-demo.mx',
                            'dana.cruz@beta-corp.mx')
ALEX_ID, MAYA_ID, JORDAN_ID = ('30000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000002',
                               '30000000-0000-4000-8000-000000000003')
USUARIOS = '/api/v1/users'
PREFIJO = 'lt_ffff0259'


def postgres(sql):
    ok, salida, err = psql(sql, user='postgres')
    if not ok:
        raise AssertionError(err)
    return salida


class UsuariosAdmin(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sesion.reset()
        cls.alex = sesion.login(ALEX)
        cls.dana = sesion.login(DANA)

    def setUp(self):
        self.seq = int(scalar("SELECT coalesce(max(chain_seq), 0) FROM audit_log WHERE organization_id = '%s';" % ACME,
                              user='postgres'))
        self.addCleanup(postgres,
                        "BEGIN; SET LOCAL session_replication_role = replica; "
                        "UPDATE users SET role = CASE id WHEN '{a}' THEN 'admin' WHEN '{m}' THEN 'manager' "
                        "ELSE 'analyst' END, is_active = true WHERE id IN ('{a}', '{m}', '{j}'); "
                        "DELETE FROM api_keys WHERE key_prefix = '{p}'; "
                        "DELETE FROM audit_log WHERE organization_id = '{o}' AND chain_seq > {s}; COMMIT;"
                        .format(a=ALEX_ID, m=MAYA_ID, j=JORDAN_ID, p=PREFIJO, o=ACME, s=self.seq))

    def ultimo_evento(self):
        return postgres("SELECT action || '|' || coalesce(actor_user_id::text, '') || '|' || coalesce(entity_id::text, '') "
                        "|| '|' || details::text FROM audit_log WHERE organization_id = '%s' AND chain_seq > %d "
                        "ORDER BY chain_seq DESC LIMIT 1;" % (ACME, self.seq))

    def test_1_el_admin_lista_su_empresa_y_otro_rol_recibe_403(self):
        code, body = self.alex.get(USUARIOS)
        self.assertEqual(code, 200, body)
        self.assertEqual({u['email'] for u in body['items']}, {ALEX, MAYA, JORDAN})
        alex = next(u for u in body['items'] if u['email'] == ALEX)
        self.assertEqual((alex['role'], alex['is_active'], alex['mfa_enabled']), ('admin', True, True))
        self.assertIn('last_login_at', alex)
        self.assertNotIn('password_hash', alex)
        self.assertNotIn('totp_secret_enc', alex)
        self.assertTrue(all(u['email'].endswith('@beta-corp.mx') for u in self.dana.get(USUARIOS)[1]['items']))
        for correo in (JORDAN, MAYA):
            with self.subTest(correo=correo):
                self.assertEqual(sesion.login(correo).get(USUARIOS)[0], 403)

    def test_2_cambiar_el_rol_deja_bitacora_y_corta_la_sesion(self):
        jordan = sesion.login(JORDAN)
        self.assertEqual(jordan.get('/api/v1/domains')[0], 200)
        code, body = self.alex.request('PATCH', '%s/%s' % (USUARIOS, JORDAN_ID),
                                       {'role': 'manager', 'reason': 'Pasa a la gerencia de TI'})
        self.assertEqual(code, 200, body)
        self.assertEqual((body['role'], body['changed'], body['sessions_closed']), ('manager', True, True))
        self.assertEqual(jordan.get('/api/v1/domains')[0], 401)
        evento = self.ultimo_evento()
        self.assertTrue(evento.startswith('user.role_changed|%s|%s|' % (ALEX_ID, JORDAN_ID)), evento)
        for texto in ('"from": "analyst"', '"to": "manager"', '"reason": "Pasa a la gerencia de TI"'):
            self.assertIn(texto, evento)

    def test_3_la_baja_revoca_sus_llaves_y_corta_la_sesion_y_el_alta_la_regresa(self):
        postgres("INSERT INTO api_keys (organization_id, name, key_prefix, key_hash, scopes, created_by, expires_at) "
                 "VALUES ('%s', 'CIRDAN_FAKE_259', '%s', sha256('CIRDAN_FAKE_259'::bytea), '{read}', '%s', "
                 "now() + interval '1 day');" % (ACME, PREFIJO, MAYA_ID))
        maya = sesion.login(MAYA)
        self.assertEqual(maya.get('/api/v1/domains')[0], 200)
        code, body = self.alex.request('PATCH', '%s/%s' % (USUARIOS, MAYA_ID),
                                       {'is_active': False, 'reason': 'Dejó la empresa'})
        self.assertEqual(code, 200, body)
        self.assertEqual((body['is_active'], body['revoked_api_keys'], body['active_api_keys']), (False, [PREFIJO], 0))
        self.assertEqual(maya.get('/api/v1/domains')[0], 401)
        self.assertEqual(scalar("SELECT revoked_at IS NOT NULL FROM api_keys WHERE key_prefix = '%s';" % PREFIJO,
                                user='postgres'), 't')
        self.assertTrue(self.ultimo_evento().startswith('user.deactivated|%s|%s|' % (ALEX_ID, MAYA_ID)))
        code, body = self.alex.request('PATCH', '%s/%s' % (USUARIOS, MAYA_ID),
                                       {'is_active': True, 'reason': 'Regresó al proyecto'})
        self.assertEqual((code, body['is_active'], body['sessions_closed']), (200, True, False), body)
        self.assertTrue(self.ultimo_evento().startswith('user.reactivated|'))
        # La llave revocada sigue revocada: una revocación no se deshace (migración 016)
        self.assertEqual(scalar("SELECT revoked_at IS NOT NULL FROM api_keys WHERE key_prefix = '%s';" % PREFIJO,
                                user='postgres'), 't')

    def test_4_reglas_propio_rol_otra_empresa_y_cuerpo_invalido(self):
        casos = (
            (self.alex, ALEX_ID, {'role': 'analyst', 'reason': 'Prueba de propio rol'}, 409),
            (self.alex, ALEX_ID, {'is_active': False, 'reason': 'Prueba de propia baja'}, 409),
            (self.alex, JORDAN_ID, {'role': 'manager'}, 422),                                # sin motivo
            (self.alex, JORDAN_ID, {'role': 'manager', 'reason': 'x' * 400}, 422),
            (self.alex, JORDAN_ID, {'role': 'operator', 'reason': 'Integrador'}, 422),
            (self.alex, JORDAN_ID, {'role': 'manager', 'reason': 'Motivo', 'email': 'x@y.z'}, 422),
            (self.alex, 'no-es-uuid', {'role': 'manager', 'reason': 'Motivo'}, 404),
            (self.dana, JORDAN_ID, {'role': 'manager', 'reason': 'Otra empresa'}, 404),
        )
        for cliente, usuario, cuerpo, esperado in casos:
            with self.subTest(usuario=usuario, cuerpo=cuerpo):
                self.assertEqual(cliente.request('PATCH', '%s/%s' % (USUARIOS, usuario), cuerpo)[0], esperado)
        self.assertEqual(scalar("SELECT role || ',' || is_active FROM users WHERE id = '%s';" % ALEX_ID,
                                user='postgres'), 'admin,true')
        self.assertEqual(int(scalar("SELECT count(*) FROM audit_log WHERE organization_id = '%s' AND chain_seq > %d "
                                    "AND action LIKE 'user.%%';" % (ACME, self.seq), user='postgres')), 0)

    def test_5_la_revision_de_accesos_queda_en_la_bitacora(self):
        code, body = self.alex.post(USUARIOS + '/access-review', {'notes': 'Revisión de prueba de RC-259'})
        self.assertEqual(code, 201, body)
        self.assertEqual((body['reviewed_by'], body['users'], body['active'], body['admins']), (ALEX, 3, 3, 1))
        self.assertEqual(body['notes'], 'Revisión de prueba de RC-259')
        self.assertIn('next_due', body)
        self.assertTrue(self.ultimo_evento().startswith('users.access_reviewed|%s||' % ALEX_ID))
        lista = self.alex.get(USUARIOS + '/access-reviews')[1]
        self.assertEqual(lista['items'][0]['notes'], 'Revisión de prueba de RC-259')
        usuarios = self.alex.get(USUARIOS)[1]
        self.assertEqual(usuarios['last_access_review']['reviewed_by'], ALEX)
        self.assertFalse(usuarios['access_review_due'])
        self.assertEqual(self.dana.get(USUARIOS + '/access-reviews')[1]['total'], 0)   # cada empresa ve las suyas
        self.assertEqual(self.alex.post(USUARIOS + '/access-review', {'notes': 5})[0], 422)

    def test_6_la_baja_o_el_cambio_de_rol_fuera_de_la_api_tambien_cortan_la_sesion(self):
        # V7.4.2 de ASVS (#75, RC-136): la API relee la cuenta en cada petición, así que un cambio hecho directo en la
        # base (el comando del operador, psql) corta la sesión abierta en la siguiente petición, sin esperar 8 h.
        casos = ((MAYA, MAYA_ID, 'is_active = false', 'is_active = true'),
                 (JORDAN, JORDAN_ID, "role = 'manager'", "role = 'analyst'"))
        for correo, usuario, cambio, regreso in casos:
            with self.subTest(cambio=cambio):
                cliente = sesion.login(correo)
                self.assertEqual(cliente.get('/api/v1/domains')[0], 200)
                postgres("UPDATE users SET %s WHERE id = '%s';" % (cambio, usuario))
                self.assertEqual(cliente.get('/api/v1/domains')[0], 401)
                # La sesión quedó cerrada, no solo rechazada: aunque la cuenta vuelva como estaba, esa cookie no sirve.
                postgres("UPDATE users SET %s WHERE id = '%s';" % (regreso, usuario))
                self.assertEqual(cliente.get('/api/v1/domains')[0], 401)
                self.assertEqual(sesion.login(correo).get('/api/v1/domains')[0], 200)
        # Las demás sesiones siguen como estaban.
        self.assertEqual(self.alex.get(USUARIOS)[0], 200)


if __name__ == '__main__':
    unittest.main()
