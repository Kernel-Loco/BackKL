"""Pruebas de la carga del dominio de prueba olmardo.com (#9b, RC-151).

Corren contra la base `cirdan` del contenedor `cirdan-pg16` con
`db/semillas/002_dominio_prueba.sql` ya cargada, entrando como `cirdan_app`
igual que `test_aislamiento.py`. Solo usan la biblioteca estándar:

    python -m unittest -v pruebas/test_dominio_prueba.py

Las pruebas 1 a 6 solo leen. La 7 y la 8 escriben dentro de una transacción
que se deshace, así que la base queda igual.
"""
import unittest

from pruebas.test_aislamiento import ACME, psql, scalar

OLMARDO = '20000000-0000-4000-8000-000000000003'
USUARIO = '30000000-0000-4000-8000-000000000005'
DOMINIO = '40000000-0000-4000-8000-000000000007'
AUTORIZACION = '41000000-0000-4000-8000-000000000007'
VERIFICACION_ALTA = '42000000-0000-4000-8000-000000000007'
TXT = 'cirdan-verification=ab439d2b39a7'
REGISTRO_UTC = '2026-10-14 00:38:02+00'      # RDAP: alta de olmardo.com en Spaceship
VERIFICADO_UTC = '2026-10-14 01:02:00+00'    # consulta manual por DoH (comentario 10093 de RC-38)


def escaneo(verificacion_nueva):
    """SQL que pide un escaneo de olmardo.com y lo deshace. Con verificacion_nueva, antes guarda un TXT
    'match' de ahora mismo, como hace el orquestador. Sin ella usa la verificación del alta."""
    nueva = ("INSERT INTO dns_txt_verifications (id, organization_id, domain_id, check_reason, expected_value,"
             " observed_values, resolver_ip, result, checked_at)"
             " VALUES ('42000000-0000-4000-8000-0000000003ff', '%(org)s', '%(dom)s', 'pre_scan', '%(txt)s',"
             " '{%(txt)s}', '1.1.1.1', 'match', now());")
    return ("BEGIN;" + (nueva if verificacion_nueva else '') +
            " INSERT INTO scans (id, organization_id, domain_id, authorization_id, txt_verification_id, trigger_type, status)"
            " VALUES ('60000000-0000-4000-8000-0000000003ff', '%(org)s', '%(dom)s', '%(aut)s', '%(ver)s',"
            " 'on_demand', 'queued') RETURNING status;"
            " ROLLBACK;") % {'org': OLMARDO, 'dom': DOMINIO, 'aut': AUTORIZACION, 'txt': TXT,
                             'ver': '42000000-0000-4000-8000-0000000003ff' if verificacion_nueva else VERIFICACION_ALTA}


class DominioDePrueba(unittest.TestCase):

    def test_1_olmardo_verificado_despues_del_registro(self):
        self.assertEqual(scalar("SELECT status || ',' || txt_token || ',' || (verified_at = '%s')"
                                " || ',' || (verified_at > '%s') FROM domains WHERE fqdn = 'olmardo.com';"
                                % (VERIFICADO_UTC, REGISTRO_UTC), org=OLMARDO),
                         'verified,ab439d2b39a7,true,true')

    def test_2_es_de_grupo_olmardo_con_plan_business_y_su_admin(self):
        self.assertEqual(scalar("SELECT o.name || ',' || p.code FROM domains d JOIN organizations o ON o.id = d.organization_id"
                                " JOIN plans p ON p.id = o.plan_id WHERE d.fqdn = 'olmardo.com';", org=OLMARDO),
                         'Grupo Olmardo,business')
        self.assertEqual(scalar("SELECT string_agg(id || ',' || role || ',' || email, ';') FROM users;", org=OLMARDO),
                         '%s,admin,admin@olmardo.com' % USUARIO)

    def test_3_carta_vigente_con_las_fechas_y_el_titular_de_la_carta(self):
        self.assertEqual(scalar("SELECT count(*) FROM domain_authorizations WHERE domain_id = '%s'"
                                " AND revoked_at IS NULL AND current_date BETWEEN valid_from AND valid_until;" % DOMINIO,
                                org=OLMARDO),
                         '1')
        self.assertEqual(scalar("SELECT a.valid_from || ',' || a.valid_until || ',' || a.signer_name || ','"
                                " || a.signer_title || ',' || a.signer_email || ',' || u.email"
                                " FROM domain_authorizations a JOIN users u ON u.id = a.accepted_by"
                                " WHERE a.id = '%s';" % AUTORIZACION, org=OLMARDO),
                         '2026-10-13,2027-10-13,Titular de olmardo.com,titular del dominio olmardo.com,'
                         'admin@olmardo.com,admin@olmardo.com')

    def test_4_verificacion_del_alta_con_el_txt_real(self):
        self.assertEqual(scalar("SELECT v.check_reason || ',' || v.result || ',' || host(v.resolver_ip) || ','"
                                " || ('%s' = ANY(v.observed_values)) || ',' || (v.checked_at = d.verified_at)"
                                " FROM dns_txt_verifications v JOIN domains d ON d.id = v.domain_id"
                                " WHERE v.domain_id = '%s';" % (TXT, DOMINIO), org=OLMARDO),
                         'onboarding,match,8.8.8.8,true,true')

    def test_5_acme_sigue_con_sus_5_dominios_y_no_ve_olmardo(self):
        self.assertEqual(scalar("SELECT count(*) || ',' || count(*) FILTER (WHERE fqdn = 'olmardo.com') FROM domains;",
                                org=ACME),
                         '5,0')

    def test_6_la_fuente_ejemplo_existe_deshabilitada(self):
        self.assertEqual(scalar("SELECT enabled::text FROM data_sources WHERE code = 'ejemplo';"), 'false')

    def test_7_escaneo_queda_en_cola_con_un_txt_reciente(self):
        ok, out, err = psql(escaneo(verificacion_nueva=True), org=OLMARDO)
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-1], 'queued')
        self.assertEqual(scalar("SELECT count(*) FROM scans;", org=OLMARDO), '0')

    def test_8_no_escanea_con_la_verificacion_vieja_del_alta(self):
        ok, _, err = psql(escaneo(verificacion_nueva=False), org=OLMARDO)
        self.assertFalse(ok)
        self.assertIn('más de 1 hora antes del escaneo', err)


if __name__ == '__main__':
    unittest.main(verbosity=2)
