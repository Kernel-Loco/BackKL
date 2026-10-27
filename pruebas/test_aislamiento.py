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


LOGIN_LOOKUP = "'login_lookup(citext)'::regprocedure"

# Ataque de la revisión de seguridad (migración 004): una vista temporal `users` que llama una
# función temporal que vuelve superusuario a cirdan_app. Si login_lookup() leyera esa vista, la
# función correría como postgres. TEMPORARY se le presta a cirdan_app dentro de la transacción,
# y el ROLLBACK lo deshace todo.
VISTA_TEMPORAL = """BEGIN;
GRANT TEMPORARY ON DATABASE cirdan TO cirdan_app;
SET LOCAL ROLE cirdan_app;
CREATE FUNCTION pg_temp.escalar() RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
  ALTER ROLE cirdan_app SUPERUSER;
  RETURN true;
END $$;
CREATE TEMP VIEW users AS
  SELECT '00000000-0000-4000-8000-0000000000aa'::uuid AS id, '%s'::uuid AS organization_id,
         'trampa'::text AS password_hash, 'admin'::text AS role, 'Trampa'::text AS full_name,
         'trampa@acme-demo.mx'::citext AS email, now() AS mfa_enabled_at,
         '\\x00'::bytea AS totp_secret_enc, pg_temp.escalar() AS is_active;
SELECT relpersistence = 't' FROM pg_class WHERE oid = 'users'::regclass;
SELECT count(*) FROM login_lookup('trampa@acme-demo.mx');
RESET ROLE;
SELECT rolsuper FROM pg_roles WHERE rolname = 'cirdan_app';
ROLLBACK;
""" % ACME


class LoginLookup(unittest.TestCase):

    def test_9_search_path_fijo_que_termina_en_pg_temp(self):
        config = scalar("SELECT prosecdef || ',' || array_to_string(proconfig, ';') FROM pg_proc WHERE oid = %s;"
                        % LOGIN_LOOKUP)
        self.assertEqual(config, 'true,search_path=pg_catalog, public, pg_temp')

    def test_10_una_vista_temporal_no_engana_a_login_lookup(self):
        ok, _, err = psql("BEGIN; CREATE TEMP VIEW users AS SELECT 1; ROLLBACK;")
        self.assertFalse(ok, 'cirdan_app no debe poder crear objetos temporales')
        self.assertIn('permission denied to create temporary tables', err)
        ok, out, err = psql(VISTA_TEMPORAL, user='postgres')
        self.assertTrue(ok, err)
        # t: para cirdan_app, `users` ya es la vista temporal. 0: login_lookup() no la leyó. f: no escaló.
        self.assertEqual(out.splitlines(), ['t', '0', 'f'])
        self.assertEqual(scalar("SELECT rolsuper FROM pg_roles WHERE rolname = 'cirdan_app';"), 'f')

    def test_11_login_lookup_devuelve_solo_4_columnas(self):
        self.assertEqual(scalar("SELECT pg_get_function_result(%s);" % LOGIN_LOOKUP),
                         'TABLE(user_id uuid, organization_id uuid, password_hash text, mfa_enabled boolean)')
        fila = scalar("SELECT * FROM login_lookup('jordan.tate@acme-demo.mx');").split('|')
        self.assertEqual(len(fila), 4)
        self.assertEqual(fila[:2], ['30000000-0000-4000-8000-000000000003', ACME])


# Funciones del límite diario por fuente (migración 008, RC-184): mismo patrón que login_lookup().
FUNCIONES_CUPO = ("'public.reserve_source_quota(text,integer)'::regprocedure",
                  "'public.adjust_source_quota(text,date,integer)'::regprocedure")


class LimiteDiario(unittest.TestCase):

    def test_12_funciones_del_cupo_con_search_path_fijo_y_sin_public(self):
        for funcion in FUNCIONES_CUPO:
            with self.subTest(funcion=funcion):
                config = scalar("SELECT prosecdef || ',' || array_to_string(proconfig, ';') || ','"
                                " || has_function_privilege('public', oid, 'EXECUTE') FROM pg_proc WHERE oid = %s;"
                                % funcion)
                self.assertEqual(config, 'true,search_path=pg_catalog, public, pg_temp,false')


if __name__ == '__main__':
    unittest.main(verbosity=2)
