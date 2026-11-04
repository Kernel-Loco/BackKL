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

        # Los 30 textos y los 30 mapeos con los mismos códigos, y toda regla de scoring_rules con su mapeo. El 30 son
        # las reglas de docs/codigos_reglas.md: una regla nueva lo sube.
        self.assertEqual(scalar("SELECT (SELECT count(*) FROM scoring_rule_texts) || ',' ||"
                                " (SELECT count(*) FROM scoring_rule_framework_mappings) || ',' ||"
                                " (SELECT count(DISTINCT code) FROM scoring_rules);", user='postgres'), '30,30,30')
        self.assertEqual(filas("SELECT coalesce(t.code, m.rule_code) FROM scoring_rule_texts t"
                               " FULL JOIN scoring_rule_framework_mappings m ON m.rule_code = t.code"
                               " WHERE t.code IS NULL OR m.rule_code IS NULL"
                               " UNION SELECT r.code FROM scoring_rules r"
                               " LEFT JOIN scoring_rule_framework_mappings m ON m.rule_code = r.code"
                               " WHERE m.rule_code IS NULL ORDER BY 1;"), [],
                         'códigos con texto y sin mapeo, con mapeo y sin texto, o reglas sin mapeo')
        # Las 25 reglas OSINT (recolectores #14 a #20 en docs/codigos_reglas.md) con su texto firmado por ErnestoDL,
        # como quedan después de todos los UPDATE. test_10 de pruebas/test_catalogo_reglas.py lo lee del SQL sin saber
        # qué corre.
        doc = (Path(__file__).resolve().parent.parent / 'docs' / 'codigos_reglas.md').read_text(encoding='utf-8')
        filas_doc = re.findall(r'^\|\s*\d{2}\s*\|\s*`([a-z0-9_]+)`\s*\|(?:[^|\n]*\|){3}\s*#(\d+)', doc, re.MULTILINE)
        osint = [code for code, recolector in filas_doc if 14 <= int(recolector) <= 20]
        self.assertEqual(len(osint), 25, 'docs/codigos_reglas.md ya no tiene 25 reglas de #14 a #20')
        self.assertEqual(filas("SELECT unnest(ARRAY[%s]) EXCEPT SELECT code FROM scoring_rule_texts"
                               " WHERE reviewed_by = 'ErnestoDL' ORDER BY 1;" % ', '.join("'%s'" % c for c in osint)),
                         [], 'reglas OSINT sin texto o con un texto que no firmó ErnestoDL')
        # Las versiones de los marcos de cada fila, como quedan después de todos los INSERT y UPDATE.
        self.assertEqual(filas("SELECT rule_code || ': ' || attack_version || ', ' || iso_version || ', '"
                               " || cis_version FROM scoring_rule_framework_mappings"
                               " WHERE (attack_version, iso_version, cis_version) IS DISTINCT FROM ('Enterprise v19', 'ISO/IEC 27001:2022', 'CIS Controls v8.1')"
                               " ORDER BY 1;"), [], 'mapeos con otra versión de los marcos')
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
