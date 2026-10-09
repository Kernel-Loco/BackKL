"""Pruebas automáticas de aislamiento por cliente y de la bitácora de Cirdan.

Corren contra la base `cirdan` del contenedor `cirdan-pg16`, entrando como el rol
de la aplicación (`cirdan_app`, sin superusuario ni BYPASSRLS). Solo usan la
biblioteca estándar de Python:

    python -m unittest -v pruebas/test_aislamiento.py

Cada intento de escritura corre dentro de una transacción que se deshace, así
que la base queda igual después de las pruebas.
"""
import subprocess
import unittest

CONTAINER = 'cirdan-pg16'
ACME = '20000000-0000-4000-8000-000000000001'
BETA = '20000000-0000-4000-8000-000000000002'


def psql(sql, user='cirdan_app', org=None):
    """Run SQL in the container; return (ok, stdout, stderr)."""
    prefix = "SET app.current_org = '%s';\n" % org if org else ''
    proc = subprocess.run(
        ['docker', 'exec', '-i', CONTAINER, 'psql', '-U', user, '-d', 'cirdan',
         '-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1'],
        input=prefix + sql, capture_output=True, text=True, encoding='utf-8')
    return proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip()


def scalar(sql, **kw):
    ok, out, err = psql(sql, **kw)
    if not ok:
        raise AssertionError(err)
    return out.splitlines()[-1]


COUNTS = ("SELECT (SELECT count(*) FROM domains) || ',' || (SELECT count(*) FROM findings)"
          " || ',' || (SELECT count(*) FROM users);")


class AislamientoPorCliente(unittest.TestCase):

    def test_1_rol_de_la_app_sin_privilegios(self):
        self.assertEqual(scalar("SELECT rolsuper || ',' || rolbypassrls FROM pg_roles WHERE rolname = current_user;"),
                         'false,false')

    def test_2_rls_forzado_en_las_18_tablas_por_cliente(self):
        n = scalar("SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace"
                   " AND relkind = 'r' AND relrowsecurity AND relforcerowsecurity;", user='postgres')
        self.assertEqual(n, '18')

    def test_3_acme_ve_solo_sus_datos(self):
        self.assertEqual(scalar(COUNTS, org=ACME), '5,4,3')
        self.assertEqual(scalar("SELECT count(*) FROM domains WHERE organization_id <> '%s';" % ACME, org=ACME), '0')

    def test_4_beta_ve_solo_sus_datos(self):
        self.assertEqual(scalar(COUNTS, org=BETA), '1,1,1')

    def test_5_sin_cliente_no_ve_nada(self):
        self.assertEqual(scalar(COUNTS), '0,0,0')

    def test_6_no_puede_escribir_a_nombre_de_otro_cliente(self):
        ok, _, err = psql("BEGIN; INSERT INTO domains (organization_id, fqdn, status, txt_token)"
                          " VALUES ('%s', 'intruso.mx', 'pending_verification', 'rls-test-0002'); ROLLBACK;" % BETA,
                          org=ACME)
        self.assertFalse(ok)
        self.assertIn('row-level security', err)


class ReglasDeNegocio(unittest.TestCase):

    def test_7_no_escanea_con_autorizacion_vencida(self):
        ok, _, err = psql(
            "BEGIN; INSERT INTO scans (organization_id, domain_id, authorization_id, txt_verification_id, trigger_type, status)"
            " VALUES ('%s', '40000000-0000-4000-8000-000000000005', '41000000-0000-4000-8000-000000000005',"
            " '42000000-0000-4000-8000-000000000005', 'scheduled', 'queued'); ROLLBACK;" % ACME, org=ACME)
        self.assertFalse(ok)
        self.assertIn('autorización fuera de vigencia', err)

    def test_8_bitacora_no_se_modifica(self):
        ok, _, err = psql("BEGIN; UPDATE audit_log SET action = 'tampered'; ROLLBACK;", org=ACME)
        self.assertFalse(ok)
        self.assertIn('permission denied', err)
        ok, _, err = psql("BEGIN; DELETE FROM audit_log; ROLLBACK;", user='postgres')
        self.assertFalse(ok)
        self.assertIn('solo inserción', err)


if __name__ == '__main__':
    unittest.main(verbosity=2)
