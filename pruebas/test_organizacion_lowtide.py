"""Pruebas de la carga de la organización LowTide con lowtidesec.com (#210, RC-329).

Corren contra la base `cirdan` del contenedor `cirdan-pg16` con
`db/semillas/015_organizacion_lowtide.sql` ya cargada, entrando como `cirdan_app`
igual que `test_dominio_prueba.py`. Solo usan la biblioteca estándar:

    python -m unittest -v pruebas/test_organizacion_lowtide.py

Las pruebas 1 a 6 solo leen. La 7 y la 8 escriben dentro de una transacción
que se deshace, así que la base queda igual. La 7 choca si en ese momento hay
un escaneo de lowtidesec.com en cola o corriendo.
"""
import ast
import unittest
from pathlib import Path

from pruebas.test_aislamiento import ACME, psql, scalar

LOWTIDE = '20000000-0000-4000-8000-000000000004'
OLMARDO = '20000000-0000-4000-8000-000000000003'
USUARIO = '30000000-0000-4000-8000-000000000006'
DOMINIO = '40000000-0000-4000-8000-000000000008'
AUTORIZACION = '41000000-0000-4000-8000-000000000008'
VERIFICACION_ALTA = '42000000-0000-4000-8000-000000000008'
PRUEBA_TXT = '42000000-0000-4000-8000-0000000004ff'
PRUEBA_ESCANEO = '60000000-0000-4000-8000-0000000004ff'
TXT = 'cirdan-verification=be92b38a1634'
REGISTRO_UTC = '2026-11-08 03:48:25+00'      # RDAP de Verisign (comentario 10378 de RC-204)
VERIFICADO_UTC = '2026-11-15 16:33:25+00'          # consulta manual por DoH a dns.google
DESDE, HASTA = '2026-11-15', '2027-11-15'        # vigencia de la carta firmada
# sha256 del PDF firmado de la carta. El PDF no va en el repo.
SHA256_CARTA = '7db4bb7fb251a633bf2f0b2259eb9b959052c792cd8a35b6b28f4838634767a0'
RELLENO = '$argon2id$v=19$m=65536,t=3,p=4$ZGVtby1zYWx0$ZGVtby1vbmx5'   # el hash de las semillas, no abre nada


def escaneo(verificacion_nueva):
    """SQL que pide un escaneo de lowtidesec.com y lo deshace. Con verificacion_nueva, antes guarda un TXT 'match'
    de ahora mismo, como hace el orquestador. Sin ella usa la verificación del alta."""
    nueva = ("INSERT INTO dns_txt_verifications (id, organization_id, domain_id, check_reason, expected_value,"
             " observed_values, resolver_ip, result, checked_at)"
             " VALUES ('%(prueba_txt)s', '%(org)s', '%(dom)s', 'pre_scan', '%(txt)s', '{%(txt)s}', '1.1.1.1', 'match',"
             " now());")
    return ("BEGIN;" + (nueva if verificacion_nueva else '') +
            " INSERT INTO scans (id, organization_id, domain_id, authorization_id, txt_verification_id, trigger_type, status)"
            " VALUES ('%(escaneo)s', '%(org)s', '%(dom)s', '%(aut)s', '%(ver)s', 'on_demand', 'queued') RETURNING status;"
            " ROLLBACK;") % {'org': LOWTIDE, 'dom': DOMINIO, 'aut': AUTORIZACION, 'txt': TXT, 'prueba_txt': PRUEBA_TXT,
                             'escaneo': PRUEBA_ESCANEO, 'ver': PRUEBA_TXT if verificacion_nueva else VERIFICACION_ALTA}


class OrganizacionLowTide(unittest.TestCase):

    def test_1_lowtidesec_verificado_despues_del_registro(self):
        self.assertEqual(scalar("SELECT status || ',' || txt_token || ',' || (verified_at = '%s')"
                                " || ',' || (verified_at > '%s') FROM domains WHERE fqdn = 'lowtidesec.com';"
                                % (VERIFICADO_UTC, REGISTRO_UTC), org=LOWTIDE),
                         'verified,be92b38a1634,true,true')

    def test_2_es_de_lowtide_con_plan_business_y_un_solo_admin_sin_contrasena_en_el_repo(self):
        self.assertEqual(scalar("SELECT o.name || ',' || p.code FROM domains d JOIN organizations o ON o.id = d.organization_id"
                                " JOIN plans p ON p.id = o.plan_id WHERE d.fqdn = 'lowtidesec.com';", org=LOWTIDE),
                         'LowTide,business')
        self.assertEqual(scalar("SELECT string_agg(id || ',' || role || ',' || email, ';') FROM users;", org=LOWTIDE),
                         '%s,admin,equipo@lowtidesec.com' % USUARIO)
        # La semilla deja el hash de relleno y sin MFA. Si alguien ya activó la cuenta, solo se revisa que no tenga
        # el MFA a medias.
        self.assertIn(scalar("SELECT (password_hash = '%s') || ',' || (totp_secret_enc IS NULL) || ','"
                             " || (mfa_enabled_at IS NULL) FROM users WHERE id = '%s';" % (RELLENO, USUARIO), org=LOWTIDE),
                      ('true,true,true', 'false,false,false'))

    def test_3_la_cuenta_no_es_de_demo(self):
        # Sin base: cirdan/auth/demo.py no le pone contraseña ni MFA públicos a equipo@lowtidesec.com.
        demo = (Path(__file__).resolve().parents[1] / 'cirdan' / 'auth' / 'demo.py').read_text(encoding='utf-8')
        correos = [n.value for n in ast.walk(ast.parse(demo)) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertFalse([c for c in correos if 'lowtidesec' in c])

    def test_4_carta_vigente_con_sus_fechas_su_titular_y_su_huella(self):
        self.assertEqual(scalar("SELECT count(*) FROM domain_authorizations WHERE domain_id = '%s'"
                                " AND revoked_at IS NULL AND current_date BETWEEN valid_from AND valid_until;" % DOMINIO,
                                org=LOWTIDE),
                         '1')
        self.assertEqual(scalar("SELECT a.valid_from || ',' || a.valid_until || ',' || a.signer_name || ','"
                                " || a.signer_title || ',' || a.signer_email || ',' || u.email"
                                " FROM domain_authorizations a JOIN users u ON u.id = a.accepted_by"
                                " WHERE a.id = '%s';" % AUTORIZACION, org=LOWTIDE),
                         '%s,%s,Titular de lowtidesec.com,titular del dominio lowtidesec.com,'
                         'equipo@lowtidesec.com,equipo@lowtidesec.com' % (DESDE, HASTA))
        self.assertEqual(scalar("SELECT encode(signed_document_sha256, 'hex') || ',' || signed_document_key"
                                " FROM domain_authorizations WHERE id = '%s';" % AUTORIZACION, org=LOWTIDE),
                         SHA256_CARTA + ',authorizations/lowtide/lowtidesec.com_2026.pdf')

    def test_5_verificacion_del_alta_con_el_txt_real(self):
        self.assertEqual(scalar("SELECT v.check_reason || ',' || v.result || ',' || host(v.resolver_ip) || ','"
                                " || ('%s' = ANY(v.observed_values)) || ',' || (v.checked_at = d.verified_at)"
                                " FROM dns_txt_verifications v JOIN domains d ON d.id = v.domain_id"
                                " WHERE v.id = '%s';" % (TXT, VERIFICACION_ALTA), org=LOWTIDE),
                         'onboarding,match,8.8.8.8,true,true')

    def test_6_cada_empresa_ve_solo_lo_suyo(self):
        self.assertEqual(scalar("SELECT count(*) || ',' || count(*) FILTER (WHERE fqdn = 'lowtidesec.com') FROM domains;",
                                org=ACME), '5,0')
        self.assertEqual(scalar("SELECT count(*) FILTER (WHERE fqdn = 'lowtidesec.com') FROM domains;", org=OLMARDO), '0')
        self.assertEqual(scalar("SELECT string_agg(fqdn::text, ',') FROM domains;", org=LOWTIDE), 'lowtidesec.com')

    def test_7_escaneo_queda_en_cola_con_un_txt_reciente(self):
        ok, out, err = psql(escaneo(verificacion_nueva=True), org=LOWTIDE)
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-1], 'queued')
        self.assertEqual(scalar("SELECT count(*) FROM scans WHERE id = '%s';" % PRUEBA_ESCANEO, org=LOWTIDE), '0')
        self.assertEqual(scalar("SELECT count(*) FROM dns_txt_verifications WHERE id = '%s';" % PRUEBA_TXT, org=LOWTIDE),
                         '0')

    def test_8_no_escanea_con_la_verificacion_vieja_del_alta(self):
        ok, _, err = psql(escaneo(verificacion_nueva=False), org=LOWTIDE)
        self.assertFalse(ok)
        self.assertIn('más de 1 hora antes del escaneo', err)


if __name__ == '__main__':
    unittest.main(verbosity=2)
