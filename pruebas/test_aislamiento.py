"""Pruebas automáticas de aislamiento por cliente y de la bitácora de Cirdan.

Corren contra la base `cirdan` del contenedor `cirdan-pg16`, entrando como el rol
de la aplicación (`cirdan_app`, sin superusuario ni BYPASSRLS). Solo usan la
biblioteca estándar de Python:

    python -m unittest -v pruebas/test_aislamiento.py

Cada intento de escritura corre dentro de una transacción que se deshace, así
que la base queda igual después de las pruebas.
"""
import re
import subprocess
import unittest
from pathlib import Path

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


# Tablas por cliente: las de public con organization_id, más organizations y scoring_rules, que se nombran aparte
CON_ORG = ("FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p') "
           "AND (c.relname IN ('organizations', 'scoring_rules') "
           "OR EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid "
           "AND a.attname = 'organization_id' AND a.attnum > 0 AND NOT a.attisdropped))")
# Lectura de la política: FOR ALL ('*') o FOR SELECT ('r'). Las permisivas se suman con OR, así que basta una que
# no filtre por app_current_org() para abrir la tabla. Las restrictivas solo recortan.
LEE = "p.polrelid = c.oid AND p.polcmd IN ('*', 'r') AND p.polpermissive"
FILTRA = "coalesce(pg_get_expr(p.polqual, p.polrelid), '') LIKE '%app_current_org()%'"
SIN_AISLAMIENTO = ("SELECT coalesce(string_agg(c.relname, ',' ORDER BY c.relname), 'ninguna') " + CON_ORG +
                   " AND NOT (c.relrowsecurity AND c.relforcerowsecurity"
                   " AND EXISTS (SELECT 1 FROM pg_policy p WHERE " + LEE + " AND " + FILTRA + ")"
                   " AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE " + LEE + " AND NOT " + FILTRA + "))")


class AislamientoPorCliente(unittest.TestCase):

    def test_1_rol_de_la_app_sin_privilegios(self):
        self.assertEqual(scalar("SELECT rolsuper || ',' || rolbypassrls FROM pg_roles WHERE rolname = current_user;"),
                         'false,false')

    def test_2_rls_forzado_y_con_politica_en_toda_tabla_con_organization_id(self):
        """Sin un número fijo (comentario 10056 de RC-43): toda tabla de public con la columna organization_id lleva
        RLS con ENABLE, FORCE y una política de lectura que filtra por app_current_org(). Una tabla por cliente nueva
        entra sola en la prueba. organizations (su política compara id) y scoring_rules (va por rule_set_id) no
        tienen esa columna y se nombran aparte, para no perder lo que cubría el conteo de antes (revisión del 8 nov)."""
        self.assertGreaterEqual(int(scalar('SELECT count(*) ' + CON_ORG + ';', user='postgres')), 20)
        self.assertEqual(scalar(SIN_AISLAMIENTO + ';', user='postgres'), 'ninguna',
                         'tablas con organization_id sin RLS forzado o sin política que filtre por app_current_org()')

    def test_2b_una_politica_que_no_filtra_no_cuenta(self):
        """Revisión de riesgo del 15 nov, #8: con USING (true) Acme leería lo de Beta y test_2 daba 'ninguna'."""
        casos = {
            'rls_prueba_true': "USING (true)",
            'rls_prueba_solo_insert': "FOR INSERT WITH CHECK (organization_id = app_current_org())",
            'rls_prueba_buena_y_true': "USING (organization_id = app_current_org()); "
                                       "CREATE POLICY otra ON rls_prueba_buena_y_true FOR SELECT USING (true)",
            'rls_prueba_buena': "USING (organization_id = app_current_org())",
        }
        ddl = ''.join("CREATE TABLE %s (organization_id uuid); ALTER TABLE %s ENABLE ROW LEVEL SECURITY; "
                      "ALTER TABLE %s FORCE ROW LEVEL SECURITY; CREATE POLICY p ON %s %s;\n"
                      % (tabla, tabla, tabla, tabla, politica) for tabla, politica in casos.items())
        faltan = scalar('BEGIN;\n' + ddl + SIN_AISLAMIENTO + " AND c.relname LIKE 'rls_prueba%';\nROLLBACK;",
                        user='postgres')
        self.assertEqual(faltan, 'rls_prueba_buena_y_true,rls_prueba_solo_insert,rls_prueba_true')

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

    def test_7_juego_de_pesos_y_reglas_solo_visibles_para_su_organizacion(self):
        sql = """BEGIN;
    INSERT INTO scoring_rule_sets (organization_id, version, category_weights, is_active, validated_by, activated_at)
    SELECT app_current_org(), coalesce(max(version), 0) + 1,
           '{"infrastructure":0.25,"digital_identity":0.25,"configuration":0.25,"data_leaks":0.25}',
           false, 'prueba RLS', now()
    FROM scoring_rule_sets WHERE organization_id IS NULL OR organization_id = app_current_org();
    INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty)
    SELECT id, 'spf_missing', 'configuration', 'medium', 1, 40 FROM scoring_rule_sets
    WHERE organization_id = app_current_org() AND validated_by = 'prueba RLS';
SELECT count(*) FROM scoring_rule_sets WHERE organization_id = app_current_org();
SELECT count(*) FROM scoring_rules r JOIN scoring_rule_sets s ON s.id = r.rule_set_id
  WHERE s.organization_id = app_current_org();
SET LOCAL app.current_org = '%s';
SELECT count(*) FROM scoring_rule_sets WHERE organization_id = '%s';
SELECT count(*) FROM scoring_rules r JOIN scoring_rule_sets s ON s.id = r.rule_set_id
  WHERE s.organization_id = '%s';
ROLLBACK;""" % (BETA, ACME, ACME)
        ok, out, err = psql(sql, org=ACME)
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines(), ['1', '1', '0', '0'])


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


# Rotación de la llave de las huellas (migración 026, RC-333): el comando lista las empresas con huellas de una
# versión, que cirdan_app no ve por RLS. Mismo patrón que login_lookup().
HUELLAS_POR_VERSION = "'public.password_hash_version_orgs(integer)'::regprocedure"
# Una cuenta de Acme con la versión 77 y una de Beta con la 7, dentro de una transacción que se deshace.
VERSIONES = """BEGIN;
UPDATE users SET password_hash = 'lt77$x' WHERE id = '30000000-0000-4000-8000-000000000003';
UPDATE users SET password_hash = 'lt7$x' WHERE id = (SELECT min(id::text)::uuid FROM users WHERE organization_id = '%s');
SET LOCAL ROLE cirdan_app;
SELECT count(*) FROM users;
SELECT coalesce(string_agg(organization_id::text, ',' ORDER BY organization_id), '-') FROM password_hash_version_orgs(7);
SELECT coalesce(string_agg(organization_id::text, ',' ORDER BY organization_id), '-') FROM password_hash_version_orgs(77);
SELECT count(*) FROM password_hash_version_orgs(0);
SELECT count(*) FROM password_hash_version_orgs(10000);
SELECT count(*) FROM password_hash_version_orgs(NULL);
ROLLBACK;
""" % BETA


class HuellasPorVersion(unittest.TestCase):

    def test_12b_security_definer_con_search_path_fijo_y_sin_public(self):
        config = scalar("SELECT prosecdef || ',' || array_to_string(proconfig, ';') || ','"
                        " || has_function_privilege('public', oid, 'EXECUTE') || ','"
                        " || has_function_privilege('cirdan_app', oid, 'EXECUTE') FROM pg_proc WHERE oid = %s;"
                        % HUELLAS_POR_VERSION)
        self.assertEqual(config, 'true,search_path=pg_catalog, public, pg_temp,false,true')

    def test_12c_devuelve_solo_ids_de_empresa(self):
        self.assertEqual(scalar("SELECT pg_get_function_result(%s);" % HUELLAS_POR_VERSION),
                         'TABLE(organization_id uuid)')

    def test_12d_solo_las_empresas_con_huellas_de_esa_version(self):
        ok, out, err = psql(VERSIONES, user='postgres')
        self.assertTrue(ok, err)
        # 0: sin empresa, cirdan_app no ve ninguna cuenta. La versión 7 no es la 77 ('lt7$' no es prefijo de
        # 'lt77$'). Fuera de 1 a 9999 o NULL no devuelve nada.
        self.assertEqual(out.splitlines(), ['0', BETA, ACME, '0', '0', '0'])


# Corrección del score de Acme (migración 010 y semillas 009 y 010, RC-72): la semilla 010 apaga el
# trigger de solo inserción dentro de su transacción. Aquí se revisa que quedó encendido.
class CorreccionScore(unittest.TestCase):

    def test_13_score_sigue_de_solo_insercion_y_acepta_correction(self):
        self.assertEqual(scalar("SELECT tgenabled FROM pg_trigger WHERE tgname = 'domain_scores_block_ud';"), 'O')
        ok, _, err = psql("BEGIN; UPDATE domain_scores SET reason = 'scan'"
                          " WHERE id = 'a0000000-0000-4000-8000-000000000004'; ROLLBACK;", user='postgres')
        self.assertFalse(ok)
        self.assertIn('solo inserción', err)
        self.assertEqual(scalar("SELECT string_agg(conname, ',') FROM pg_constraint WHERE conrelid = 'domain_scores'::regclass"
                                " AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%reason%';"),
                         'domain_scores_reason_ck')
        self.assertEqual(scalar("SELECT string_agg(reason || '|' || coalesce(model_fallback_reason, '-'), ',' ORDER BY id)"
                                " FROM domain_scores WHERE id IN ('a0000000-0000-4000-8000-000000000004',"
                                " 'a0000000-0000-4000-8000-000000000005', 'a0000000-0000-4000-8000-000000000006');",
                                user='postgres'),
                         'correction|-,correction|-,correction|-')
        self.assertEqual(scalar("SELECT count(*) FROM domain_scores WHERE id IN ('a0000000-0000-4000-8000-000000000004',"
                                " 'a0000000-0000-4000-8000-000000000005', 'a0000000-0000-4000-8000-000000000006')"
                                " AND computed_at = '2026-10-29 20:16:09-06';", user='postgres'),
                         '3')


# Mapeo a marcos (migraciones 011 y 012, #68): la FK diferida de la 012 obliga a que todo texto de regla tenga su
# mapeo, así un hallazgo nunca llega a la API sin él. SET CONSTRAINTS ... IMMEDIATE la revisa en el momento y no
# en el COMMIT, y todo se deshace con ROLLBACK. La prueba 15 revisa lo que quedó en la base después de cargar todas las
# migraciones y semillas, que la prueba 4b de test_catalogo_reglas.py no ve sin base (si cada INSERT y UPDATE del mapeo
# corrió, en qué orden y en qué transacción).
class MapeoMarcos(unittest.TestCase):
    TEXTO = ("INSERT INTO scoring_rule_texts (code, title, meaning, recommendation)"
             " VALUES ('prueba_mapeo', 'Prueba', 'Prueba.', 'Prueba.');")
    MAPEO = ("INSERT INTO scoring_rule_framework_mappings (rule_code, attack_version, attack_source_url,"
             " attack_unmapped_reason, iso_version, iso_control_id, iso_control_name, iso_source_url, cis_version,"
             " cis_safeguard_id, cis_safeguard_name, cis_source_url) VALUES ('prueba_mapeo', 'Enterprise v19',"
             " 'https://attack.mitre.org/', 'Prueba', 'ISO/IEC 27001:2022', 'A.8.8', 'Prueba', 'https://www.iso.org/',"
             " 'CIS Controls v8.1', '7.1', 'Prueba', 'https://www.cisecurity.org/');")
    # Los CHECK de la 011 como están en la migración. La prueba 15 los pone en una tabla temporal igual al mapeo y
    # compara lo que escribe pg_get_constraintdef de las dos, así no depende de cómo los escribe cada versión de
    # Postgres.
    CHECKS_011 = (
        "btrim(attack_version) <> ''",
        "attack_technique_id IS NULL OR attack_technique_id ~ '^T[0-9]{4}(\\.[0-9]{3})?$'",
        "attack_source_url LIKE 'https://%'",
        "btrim(iso_version) <> ''",
        "iso_control_id ~ '^A\\.[5-8]\\.[0-9]{1,2}$'",
        "btrim(iso_control_name) <> ''",
        "iso_source_url LIKE 'https://%'",
        "btrim(cis_version) <> ''",
        "cis_safeguard_id ~ '^(?:[1-9]|1[0-8])\\.[0-9]{1,2}$'",
        "btrim(cis_safeguard_name) <> ''",
        "cis_source_url LIKE 'https://%'",
        "(attack_technique_id IS NOT NULL AND attack_technique_name IS NOT NULL"
        " AND btrim(attack_technique_name) <> '' AND attack_unmapped_reason IS NULL)"
        " OR (attack_technique_id IS NULL AND attack_technique_name IS NULL"
        " AND attack_unmapped_reason IS NOT NULL AND btrim(attack_unmapped_reason) <> '')",
    )

    def test_14_un_texto_de_regla_no_entra_ni_queda_sin_su_mapeo(self):
        self.assertEqual(scalar("SELECT coalesce(string_agg(condeferrable || ',' || condeferred, ';'), 'sin FK')"
                                " FROM pg_constraint WHERE conname = 'scoring_rule_texts_mapping_fk';", user='postgres'),
                         'true,true')
        ok, _, err = psql("BEGIN; SET CONSTRAINTS scoring_rule_texts_mapping_fk IMMEDIATE; %s ROLLBACK;" % self.TEXTO,
                          user='postgres')
        self.assertFalse(ok)
        self.assertIn('scoring_rule_texts_mapping_fk', err)
        ok, _, err = psql("BEGIN; SET CONSTRAINTS scoring_rule_texts_mapping_fk IMMEDIATE;"
                          " DELETE FROM scoring_rule_framework_mappings WHERE rule_code = 'spf_missing'; ROLLBACK;",
                          user='postgres')
        self.assertFalse(ok)
        self.assertIn('scoring_rule_texts_mapping_fk', err)
        # El texto y su mapeo en la misma transacción, en ese orden, sí entran.
        self.assertEqual(scalar("BEGIN; %s %s SET CONSTRAINTS ALL IMMEDIATE;"
                                " SELECT count(*) FROM scoring_rule_framework_mappings WHERE rule_code = 'prueba_mapeo';"
                                " ROLLBACK;" % (self.TEXTO, self.MAPEO), user='postgres'), '1')
        self.assertEqual(scalar("SELECT count(*) FROM scoring_rule_texts WHERE code = 'prueba_mapeo';", user='postgres'), '0')

    def test_15_el_mapeo_cargado_cubre_toda_regla_con_sus_versiones(self):
        def filas(sql):
            ok, out, err = psql(sql, user='postgres')
            if not ok:
                raise AssertionError(err)
            return out.splitlines()

        # Los 40 textos y los 40 mapeos con los mismos códigos, y toda regla de scoring_rules con su mapeo. El 40 son
        # las reglas de docs/codigos_reglas.md: una regla nueva lo sube.
        self.assertEqual(scalar("SELECT (SELECT count(*) FROM scoring_rule_texts) || ',' ||"
                                " (SELECT count(*) FROM scoring_rule_framework_mappings) || ',' ||"
                                " (SELECT count(DISTINCT code) FROM scoring_rules);", user='postgres'), '40,40,40')
        self.assertEqual(filas("SELECT coalesce(t.code, m.rule_code) FROM scoring_rule_texts t"
                               " FULL JOIN scoring_rule_framework_mappings m ON m.rule_code = t.code"
                               " WHERE t.code IS NULL OR m.rule_code IS NULL"
                               " UNION SELECT r.code FROM scoring_rules r"
                               " LEFT JOIN scoring_rule_framework_mappings m ON m.rule_code = r.code"
                               " WHERE m.rule_code IS NULL ORDER BY 1;"), [],
                         'códigos con texto y sin mapeo, con mapeo y sin texto, o reglas sin mapeo')
        # Las 31 reglas OSINT (recolectores #14 a #20 en docs/codigos_reglas.md) con su texto firmado por ErnestoDL,
        # como quedan después de todos los UPDATE. test_10 de pruebas/test_catalogo_reglas.py lo lee del SQL sin saber
        # qué corre.
        doc = (Path(__file__).resolve().parent.parent / 'docs' / 'codigos_reglas.md').read_text(encoding='utf-8')
        filas_doc = re.findall(r'^\|\s*\d{2}\s*\|\s*`([a-z0-9_]+)`\s*\|(?:[^|\n]*\|){3}\s*#(\d+)', doc, re.MULTILINE)
        osint = [code for code, recolector in filas_doc if 14 <= int(recolector) <= 20]
        self.assertEqual(len(osint), 31, 'docs/codigos_reglas.md ya no tiene 31 reglas de #14 a #20')
        self.assertEqual(filas("SELECT unnest(ARRAY[%s]) EXCEPT SELECT code FROM scoring_rule_texts"
                               " WHERE reviewed_by = 'ErnestoDL' ORDER BY 1;" % ', '.join("'%s'" % c for c in osint)),
                         [], 'reglas OSINT sin texto o con un texto que no firmó ErnestoDL')
        # Las versiones de los marcos de cada fila, como quedan después de todos los INSERT y UPDATE.
        self.assertEqual(filas("SELECT rule_code || ': ' || attack_version || ', ' || iso_version || ', '"
                               " || cis_version FROM scoring_rule_framework_mappings"
                               " WHERE (attack_version, iso_version, cis_version) IS DISTINCT FROM ('Enterprise v19', 'ISO/IEC 27001:2022', 'CIS Controls v8.1')"
                               " ORDER BY 1;"), [], 'mapeos con otra versión de los marcos')
        # Cada enlace de ATT&CK va fijo a la versión de su fila: a su técnica o, si no tiene, a la lista de técnicas
        # de Enterprise. Un cambio de versión cambia también los enlaces.
        self.assertEqual(filas("SELECT rule_code || ': ' || attack_source_url FROM scoring_rule_framework_mappings"
                               " WHERE attack_source_url IS DISTINCT FROM 'https://attack.mitre.org/versions/v'"
                               " || substring(attack_version FROM '^Enterprise v([0-9]+)$') || '/techniques/'"
                               " || coalesce(replace(attack_technique_id, '.', '/'), 'enterprise') || '/'"
                               " ORDER BY 1;"), [], 'enlaces de ATT&CK que no van a la versión o a la técnica de su fila')
        # Los CHECK y los NOT NULL de la 011, validados, y la FK diferida de la 012. Los NOT NULL incluyen created_at
        # y updated_at de la 012, así ninguna fila queda sin ellos.
        esperados = filas("BEGIN; CREATE TEMP TABLE checks_011 (LIKE scoring_rule_framework_mappings);"
                          + ''.join(" ALTER TABLE checks_011 ADD CHECK (%s);" % c for c in self.CHECKS_011)
                          + " SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                            " WHERE contype = 'c' AND conrelid = 'checks_011'::regclass; ROLLBACK;")
        self.assertEqual(len(set(esperados)), len(self.CHECKS_011))
        checks = filas("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE contype = 'c' AND convalidated"
                       " AND conrelid = 'scoring_rule_framework_mappings'::regclass;")
        self.assertEqual(sorted(set(esperados) - set(checks)), [], 'faltan CHECK de la 011 en el mapeo')
        nulas = ('attack_technique_id', 'attack_technique_name', 'attack_unmapped_reason')
        columnas = nulas + ('rule_code', 'attack_version', 'attack_source_url', 'iso_version', 'iso_control_id',
                            'iso_control_name', 'iso_source_url', 'cis_version', 'cis_safeguard_id',
                            'cis_safeguard_name', 'cis_source_url', 'created_at', 'updated_at')
        self.assertEqual(sorted(filas("SELECT attname || ' ' || attnotnull FROM pg_attribute"
                                      " WHERE attrelid = 'scoring_rule_framework_mappings'::regclass AND attnum > 0"
                                      " AND NOT attisdropped;")),
                         sorted('%s %s' % (c, 'false' if c in nulas else 'true') for c in columnas),
                         'columnas del mapeo o sus NOT NULL')
        self.assertEqual(filas("SELECT conrelid::regclass || ' ' || pg_get_constraintdef(oid) || ' ' || convalidated"
                               " FROM pg_constraint WHERE conname = 'scoring_rule_texts_mapping_fk';"),
                         ['scoring_rule_texts FOREIGN KEY (code) REFERENCES scoring_rule_framework_mappings(rule_code)'
                          ' DEFERRABLE INITIALLY DEFERRED true'], 'la FK de la 012 no está o no es diferida')

    def test_16_la_semilla_022_llega_a_cada_juego(self):
        # RC-239, desviación 15 de db/README.md: el orquestador rechaza un hallazgo cuyo código no está en el juego
        # activo, así que la 022 agrega las 2 reglas del saludo TLS a cada juego que no es v1, activo o no, también
        # al de una organización que cambió sus pesos, con la severidad, el peso y el tope de v1, como la 020 de los
        # contenedores. Los juegos de ACME (activo) y BETA (inactivo) se arman con las reglas de v1 sin esas 2, la
        # 022 corre otra vez y el ROLLBACK lo deshace todo.
        semilla = (Path(__file__).resolve().parent.parent / 'db' / 'semillas' / '022_reglas_tls_sitio.sql').read_text(
            encoding='utf-8')
        cuerpo = '\n'.join(l for l in semilla.splitlines() if l.strip() not in ('BEGIN;', 'COMMIT;'))
        tls = "('tls_certificate_invalid', 'tls_legacy_only')"
        juego = """
UPDATE scoring_rule_sets SET is_active = false WHERE organization_id = '%(org)s';
WITH j AS (
  INSERT INTO scoring_rule_sets (organization_id, version, category_weights, is_active)
  SELECT '%(org)s', COALESCE((SELECT max(version) FROM scoring_rule_sets WHERE organization_id = '%(org)s'), 0) + 1,
         category_weights, %(activo)s FROM scoring_rule_sets WHERE id = '90000000-0000-4000-8000-000000000001'
  RETURNING id)
INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty)
SELECT j.id, r.code, r.category, r.base_severity, r.weight, r.max_penalty FROM j CROSS JOIN scoring_rules r
 WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001' AND r.code NOT IN %(tls)s;"""
        sql = ('BEGIN;' + juego % {'org': ACME, 'activo': 'true', 'tls': tls}
               + juego % {'org': BETA, 'activo': 'false', 'tls': tls} + '\n' + cuerpo + """
SELECT s.organization_id || ' ' || s.is_active || ' ' || r.code || ' ' || r.category || ' ' || r.base_severity
       || ' ' || r.weight || ' ' || r.max_penalty
  FROM scoring_rules r JOIN scoring_rule_sets s ON s.id = r.rule_set_id
 WHERE s.organization_id IN ('%s', '%s') AND r.code IN %s ORDER BY 1;
SELECT 'sin las 2: ' || count(*) FROM scoring_rule_sets s
   WHERE (SELECT count(*) FROM scoring_rules r WHERE r.rule_set_id = s.id AND r.code IN %s) <> 2;
ROLLBACK;""" % (ACME, BETA, tls, tls))
        ok, out, err = psql(sql, user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-5:],
                         ['%s true tls_certificate_invalid infrastructure medium 1.000 10.00' % ACME,
                          '%s true tls_legacy_only infrastructure medium 1.000 10.00' % ACME,
                          '%s false tls_certificate_invalid infrastructure medium 1.000 10.00' % BETA,
                          '%s false tls_legacy_only infrastructure medium 1.000 10.00' % BETA,
                          'sin las 2: 0'])

    def test_17_la_semilla_023_llega_a_cada_juego(self):
        # RC-247, como la test_16: la 023 agrega file_share_link_in_repo a cada juego que no es v1, activo o no,
        # también al de una organización que cambió sus pesos, con la severidad, el peso y el tope de v1. Los juegos
        # de ACME (activo) y BETA (inactivo) se arman con las reglas de v1 sin esa, la 023 corre otra vez y el
        # ROLLBACK lo deshace todo.
        semilla = (Path(__file__).resolve().parent.parent / 'db' / 'semillas' / '023_regla_enlaces_nube_repos.sql'
                   ).read_text(encoding='utf-8')
        cuerpo = '\n'.join(l for l in semilla.splitlines() if l.strip() not in ('BEGIN;', 'COMMIT;'))
        enlace ="('file_share_link_in_repo')"
        juego = """
UPDATE scoring_rule_sets SET is_active = false WHERE organization_id = '%(org)s';
WITH j AS (
  INSERT INTO scoring_rule_sets (organization_id, version, category_weights, is_active)
  SELECT '%(org)s', COALESCE((SELECT max(version) FROM scoring_rule_sets WHERE organization_id = '%(org)s'), 0) + 1,
         category_weights, %(activo)s FROM scoring_rule_sets WHERE id = '90000000-0000-4000-8000-000000000001'
  RETURNING id)
INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty)
SELECT j.id, r.code, r.category, r.base_severity, r.weight, r.max_penalty FROM j CROSS JOIN scoring_rules r
 WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001' AND r.code NOT IN %(enlace)s;"""
        sql = ('BEGIN;' + juego % {'org': ACME, 'activo': 'true', 'enlace': enlace}
               + juego % {'org': BETA, 'activo': 'false', 'enlace': enlace} + '\n' + cuerpo + """
SELECT s.organization_id || ' ' || s.is_active || ' ' || r.code || ' ' || r.category || ' ' || r.base_severity
       || ' ' || r.weight || ' ' || r.max_penalty
  FROM scoring_rules r JOIN scoring_rule_sets s ON s.id = r.rule_set_id
 WHERE s.organization_id IN ('%s', '%s') AND r.code IN %s ORDER BY 1;
SELECT 'sin la regla: ' || count(*) FROM scoring_rule_sets s
   WHERE (SELECT count(*) FROM scoring_rules r WHERE r.rule_set_id = s.id AND r.code IN %s) <> 1;
ROLLBACK;""" % (ACME, BETA, enlace, enlace))
        ok, out, err = psql(sql, user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-3:],
                         ['%s true file_share_link_in_repo data_leaks medium 1.000 10.00' % ACME,
                          '%s false file_share_link_in_repo data_leaks medium 1.000 10.00' % BETA,
                          'sin la regla: 0'])

    def test_18_la_semilla_024_llega_a_cada_juego(self):
        # RC-262, desviación 15 de db/README.md: como la 023, la 024 agrega exposed_ai_service a cada juego que no es
        # v1, activo o no, también al de una organización que cambió sus pesos, con la severidad, el peso y el tope de
        # v1. Los juegos de ACME (activo) y BETA (inactivo) se arman con las reglas de v1 sin ella, la 024 corre otra
        # vez y el ROLLBACK lo deshace todo.
        semilla = (Path(__file__).resolve().parent.parent / 'db' / 'semillas' / '024_regla_ia.sql').read_text(
            encoding='utf-8')
        cuerpo = '\n'.join(l for l in semilla.splitlines() if l.strip() not in ('BEGIN;', 'COMMIT;'))
        juego = """
UPDATE scoring_rule_sets SET is_active = false WHERE organization_id = '%(org)s';
WITH j AS (
  INSERT INTO scoring_rule_sets (organization_id, version, category_weights, is_active)
  SELECT '%(org)s', COALESCE((SELECT max(version) FROM scoring_rule_sets WHERE organization_id = '%(org)s'), 0) + 1,
         category_weights, %(activo)s FROM scoring_rule_sets WHERE id = '90000000-0000-4000-8000-000000000001'
  RETURNING id)
INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty)
SELECT j.id, r.code, r.category, r.base_severity, r.weight, r.max_penalty FROM j CROSS JOIN scoring_rules r
 WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001' AND r.code <> 'exposed_ai_service';"""
        sql = ('BEGIN;' + juego % {'org': ACME, 'activo': 'true'} + juego % {'org': BETA, 'activo': 'false'}
               + "\nSELECT 'antes: ' || count(*) FROM scoring_rules r JOIN scoring_rule_sets s ON s.id = r.rule_set_id"
               " WHERE s.organization_id IN ('%s', '%s') AND r.code = 'exposed_ai_service';\n" % (ACME, BETA)
               + cuerpo + """
SELECT s.organization_id || ' ' || s.is_active || ' ' || r.code || ' ' || r.category || ' ' || r.base_severity
       || ' ' || r.weight || ' ' || r.max_penalty
  FROM scoring_rules r JOIN scoring_rule_sets s ON s.id = r.rule_set_id
 WHERE s.organization_id IN ('%s', '%s') AND r.code = 'exposed_ai_service' ORDER BY 1;
SELECT 'v1: ' || id FROM scoring_rules WHERE rule_set_id = '90000000-0000-4000-8000-000000000001'
   AND code = 'exposed_ai_service';
SELECT 'sin ella: ' || count(*) FROM scoring_rule_sets s
   WHERE NOT EXISTS (SELECT 1 FROM scoring_rules r WHERE r.rule_set_id = s.id AND r.code = 'exposed_ai_service');
ROLLBACK;""" % (ACME, BETA))
        ok, out, err = psql(sql, user='postgres')
        self.assertTrue(ok, err)
        lineas = out.splitlines()
        self.assertIn('antes: 0', lineas)
        self.assertEqual(lineas[-4:],
                         ['%s true exposed_ai_service infrastructure high 1.000 25.00' % ACME,
                          '%s false exposed_ai_service infrastructure high 1.000 25.00' % BETA,
                          'v1: 91000000-0000-4000-8000-000000000037',
                          'sin ella: 0'])

    def test_20_la_semilla_025_llega_a_cada_juego(self):
        # RC-218, como la 022 en test_16, la 023 en test_17 y la 024 en test_18: la 025 agrega las 3 reglas de
        # higiene de certificados de ct_logs a cada juego que no es v1, activo o no, con la severidad, el peso y el
        # tope de v1. Los juegos de ACME (activo) y BETA (inactivo) se arman con las reglas de v1 sin esas 3, la 025
        # corre otra vez y el ROLLBACK lo deshace.
        semilla = (Path(__file__).resolve().parent.parent / 'db' / 'semillas'
                   / '025_reglas_higiene_certificados.sql').read_text(encoding='utf-8')
        cuerpo = '\n'.join(l for l in semilla.splitlines() if l.strip() not in ('BEGIN;', 'COMMIT;'))
        codigos = "('cert_internal_name', 'cert_broad_wildcard', 'cert_new_issuer')"
        juego = """
UPDATE scoring_rule_sets SET is_active = false WHERE organization_id = '%(org)s';
WITH j AS (
  INSERT INTO scoring_rule_sets (organization_id, version, category_weights, is_active)
  SELECT '%(org)s', COALESCE((SELECT max(version) FROM scoring_rule_sets WHERE organization_id = '%(org)s'), 0) + 1,
         category_weights, %(activo)s FROM scoring_rule_sets WHERE id = '90000000-0000-4000-8000-000000000001'
  RETURNING id)
INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty)
SELECT j.id, r.code, r.category, r.base_severity, r.weight, r.max_penalty FROM j CROSS JOIN scoring_rules r
 WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001' AND r.code NOT IN %(codigos)s;"""
        sql = ('BEGIN;' + juego % {'org': ACME, 'activo': 'true', 'codigos': codigos}
               + juego % {'org': BETA, 'activo': 'false', 'codigos': codigos}
               + '\n' + cuerpo + """
SELECT s.organization_id || ' ' || s.is_active || ' ' || r.code || ' ' || r.category || ' ' || r.base_severity
       || ' ' || r.weight || ' ' || r.max_penalty
  FROM scoring_rules r JOIN scoring_rule_sets s ON s.id = r.rule_set_id
 WHERE s.organization_id IN ('%s', '%s') AND r.code IN %s ORDER BY 1;
SELECT 'sin las 3: ' || count(*) FROM scoring_rule_sets s
   WHERE (SELECT count(*) FROM scoring_rules r WHERE r.rule_set_id = s.id AND r.code IN %s) <> 3;
ROLLBACK;""" % (ACME, BETA, codigos, codigos))
        ok, out, err = psql(sql, user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-7:],
                         ['%s true cert_broad_wildcard infrastructure low 1.000 8.00' % ACME,
                          '%s true cert_internal_name infrastructure low 1.000 8.00' % ACME,
                          '%s true cert_new_issuer infrastructure medium 1.000 10.00' % ACME,
                          '%s false cert_broad_wildcard infrastructure low 1.000 8.00' % BETA,
                          '%s false cert_internal_name infrastructure low 1.000 8.00' % BETA,
                          '%s false cert_new_issuer infrastructure medium 1.000 10.00' % BETA,
                          'sin las 3: 0'])



# RC-237, migración 024: cada juego de reglas guarda dónde empiezan sus bandas medio, alto y crítico. Todo corre en
# una transacción con ROLLBACK. COMO_APP cambia a cirdan_app dentro de la sesión de postgres, así cada caso arma lo
# que necesita sin dejar nada en la base.
PESOS_IGUALES = '{"infrastructure":0.25,"digital_identity":0.25,"configuration":0.25,"data_leaks":0.25}'
COMO_APP = "SET LOCAL ROLE cirdan_app;\nSET LOCAL app.current_org = '%s';\n"
NUEVO_JUEGO = """INSERT INTO scoring_rule_sets (organization_id, version, category_weights, is_active%(columnas)s)
SELECT '%(org)s', coalesce(max(version), 0) + 1, '""" + PESOS_IGUALES + """', false%(valores)s
  FROM scoring_rule_sets WHERE organization_id = '%(org)s';
"""
ULTIMOS_CORTES = ("SELECT band_medium_from || ',' || band_high_from || ',' || band_critical_from FROM scoring_rule_sets"
                  " WHERE organization_id = '%s' ORDER BY version DESC LIMIT 1;\n")


def nuevo_juego(org, cortes=None, columnas=('band_medium_from', 'band_high_from', 'band_critical_from')):
    if cortes is None:
        return NUEVO_JUEGO % {'org': org, 'columnas': '', 'valores': ''}
    return NUEVO_JUEGO % {'org': org, 'columnas': ', ' + ', '.join(columnas),
                          'valores': ', ' + ', '.join(str(c) for c in cortes)}


class CortesDeBandas(unittest.TestCase):

    def test_19_el_global_queda_en_40_60_80_y_las_columnas_son_obligatorias(self):
        self.assertEqual(scalar("SELECT string_agg(DISTINCT band_medium_from || ',' || band_high_from || ','"
                                " || band_critical_from, ' ') FROM scoring_rule_sets WHERE organization_id IS NULL;",
                                user='postgres'), '40,60,80')
        self.assertEqual(scalar("SELECT string_agg(attname || ':' || attnotnull, ',' ORDER BY attname) FROM pg_attribute"
                                " WHERE attrelid = 'scoring_rule_sets'::regclass AND attname LIKE 'band_%';"),
                         'band_critical_from:true,band_high_from:true,band_medium_from:true')

    def test_19b_el_check_pide_enteros_en_orden_y_10_por_banda(self):
        for cortes in ((10, 20, 30), (71, 81, 91), (50, 70, 85)):
            with self.subTest(cortes=cortes):
                ok, out, err = psql('BEGIN;\n' + nuevo_juego(ACME, cortes) + ULTIMOS_CORTES % ACME + 'ROLLBACK;',
                                    user='postgres')
                self.assertTrue(ok, err)
                self.assertEqual(out.splitlines()[-1], ','.join(str(c) for c in cortes))
        for cortes in ((9, 20, 30), (40, 49, 80), (40, 60, 69), (40, 60, 92), (60, 40, 80), (40, 60, 101)):
            with self.subTest(cortes=cortes):
                ok, _, err = psql('BEGIN;\n' + nuevo_juego(ACME, cortes) + 'ROLLBACK;', user='postgres')
                self.assertFalse(ok)
                self.assertIn('scoring_rule_sets_band_cutoffs_ck', err)
        self.assertEqual(scalar("SELECT string_agg(DISTINCT format_type(atttypid, atttypmod), ',') FROM pg_attribute"
                                " WHERE attrelid = 'scoring_rule_sets'::regclass AND attname LIKE 'band_%';"), 'smallint')

    def test_19c_una_version_nueva_copia_los_cortes_de_la_anterior(self):
        sql = ('BEGIN;\n' + COMO_APP % ACME
               + nuevo_juego(ACME, (50, 70, 85)) + nuevo_juego(ACME) + ULTIMOS_CORTES % ACME
               # BETA no tiene juego propio: el primero copia los del global activo.
               + "SET LOCAL app.current_org = '%s';\n" % BETA + nuevo_juego(BETA) + ULTIMOS_CORTES % BETA
               + 'ROLLBACK;')
        ok, out, err = psql(sql, user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-2:], ['50,70,85', '40,60,80'])

    def test_19d_cortes_a_medias_no_se_completan(self):
        ok, _, err = psql('BEGIN;\n' + COMO_APP % ACME + nuevo_juego(ACME, (50,), ('band_medium_from',)) + 'ROLLBACK;',
                          user='postgres')
        self.assertFalse(ok)
        self.assertIn('null value in column', err)

    def test_19e_cirdan_app_no_cambia_los_cortes_de_una_version_creada(self):
        for columna in ('band_medium_from', 'band_high_from', 'band_critical_from'):
            with self.subTest(columna=columna):
                ok, _, err = psql('BEGIN;\n' + COMO_APP % ACME + nuevo_juego(ACME, (50, 70, 85))
                                  + "UPDATE scoring_rule_sets SET %s = %s + 1 WHERE organization_id = '%s';\n"
                                  % (columna, columna, ACME) + 'ROLLBACK;', user='postgres')
                self.assertFalse(ok)
                self.assertIn('permission denied', err)
        ok, _, err = psql("BEGIN;\n" + COMO_APP % ACME + "UPDATE scoring_rule_sets SET band_high_from = 61"
                          " WHERE organization_id IS NULL;\nROLLBACK;", user='postgres')
        self.assertFalse(ok)
        self.assertIn('permission denied', err)

    def test_19f_una_organizacion_no_ve_ni_cambia_los_cortes_de_otra(self):
        # BETA crea su juego con 50, 70 y 85. ACME no lo ve, no lo activa y no le copia los cortes.
        sql = ('BEGIN;\n' + COMO_APP % BETA + nuevo_juego(BETA, (50, 70, 85))
               + "SET LOCAL app.current_org = '%s';\n" % ACME
               + "SELECT 've ' || count(*) FROM scoring_rule_sets WHERE organization_id = '%s';\n" % BETA
               + "WITH u AS (UPDATE scoring_rule_sets SET is_active = true WHERE organization_id = '%s' RETURNING 1)"
                 " SELECT 'cambia ' || count(*) FROM u;\n" % BETA
               + nuevo_juego(ACME) + ULTIMOS_CORTES % ACME
               + "RESET ROLE;\nSELECT 'beta ' || is_active || ' ' || band_medium_from FROM scoring_rule_sets"
                 " WHERE organization_id = '%s';\n" % BETA
               + 'ROLLBACK;')
        ok, out, err = psql(sql, user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-4:], ['ve 0', 'cambia 0', '40,60,80', 'beta false 50'])
        ok, _, err = psql('BEGIN;\n' + COMO_APP % ACME + nuevo_juego(BETA, (50, 70, 85)) + 'ROLLBACK;', user='postgres')
        self.assertFalse(ok)
        self.assertIn('row-level security', err)

    def test_19g_el_global_no_se_modifica_desde_la_app(self):
        antes = scalar("SELECT string_agg(concat_ws(' ', id, is_active, band_medium_from, band_high_from, band_critical_from),"
                       " ',' ORDER BY id) FROM scoring_rule_sets WHERE organization_id IS NULL;", user='postgres')
        ok, _, err = psql("BEGIN;\n" + COMO_APP % ACME + "UPDATE scoring_rule_sets SET is_active = false"
                          " WHERE organization_id IS NULL;\nROLLBACK;", user='postgres')
        self.assertFalse(ok)
        self.assertIn('row-level security', err)
        ok, _, err = psql("BEGIN;\n" + COMO_APP % ACME + "INSERT INTO scoring_rule_sets (organization_id, version,"
                          " category_weights, is_active) VALUES (NULL, 999, '" + PESOS_IGUALES + "', false);\nROLLBACK;",
                          user='postgres')
        self.assertFalse(ok)
        self.assertIn('row-level security', err)
        self.assertEqual(scalar("SELECT string_agg(concat_ws(' ', id, is_active, band_medium_from, band_high_from,"
                                " band_critical_from), ',' ORDER BY id) FROM scoring_rule_sets"
                                " WHERE organization_id IS NULL;", user='postgres'), antes)

    def test_19h_la_funcion_del_trigger_tiene_search_path_fijo(self):
        self.assertEqual(scalar("SELECT array_to_string(proconfig, ' ') FROM pg_proc"
                                " WHERE oid = 'public.scoring_rule_sets_copiar_cortes()'::regprocedure;"),
                         'search_path=pg_catalog, public, pg_temp')
        self.assertEqual(scalar("SELECT has_function_privilege('cirdan_app', 'public.scoring_rule_sets_copiar_cortes()',"
                                " 'EXECUTE')::text;"), 'false')


if __name__ == '__main__':
    unittest.main(verbosity=2)
