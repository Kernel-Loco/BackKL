-- =====================================================================
-- Cirdan · db/consultas/prueba_rls.sql
-- Prueba de aislamiento entre clientes (RLS) y de inmutabilidad.
-- Las secciones [5] a [8] DEBEN fallar: ahí se desactiva ON_ERROR_STOP
-- para que psql muestre cada ERROR y siga con la siguiente prueba.
-- Las [10] y [11] revisan login_lookup() (migración 004).
-- =====================================================================
\set QUIET on
\pset footer off
\pset null '(ninguna)'
\set VERBOSITY terse

\echo '[1] Rol de la aplicación'
SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'cirdan_app';

SET ROLE cirdan_app;

\echo '[2] cirdan_app con app.current_org = Acme Demo'
SET app.current_org = '20000000-0000-4000-8000-000000000001';
SELECT current_user AS rol,
       (SELECT string_agg(name, ', ') FROM organizations) AS org_visible,
       (SELECT count(*) FROM domains)   AS domains,
       (SELECT count(*) FROM findings)  AS findings,
       (SELECT count(*) FROM users)     AS users,
       (SELECT count(*) FROM audit_log) AS audit_log;

\echo '[3] cirdan_app con app.current_org = Beta Corp'
SET app.current_org = '20000000-0000-4000-8000-000000000002';
SELECT current_user AS rol,
       (SELECT string_agg(name, ', ') FROM organizations) AS org_visible,
       (SELECT count(*) FROM domains)   AS domains,
       (SELECT count(*) FROM findings)  AS findings,
       (SELECT count(*) FROM users)     AS users,
       (SELECT count(*) FROM audit_log) AS audit_log;

\echo '[4] cirdan_app sin tenant (RESET app.current_org): falla cerrada'
RESET app.current_org;
SELECT current_user AS rol,
       (SELECT string_agg(name, ', ') FROM organizations) AS org_visible,
       (SELECT count(*) FROM domains)   AS domains,
       (SELECT count(*) FROM findings)  AS findings,
       (SELECT count(*) FROM users)     AS users,
       (SELECT count(*) FROM audit_log) AS audit_log;

\set ON_ERROR_STOP off

\echo '[5] Acme intenta insertar un dominio a nombre de Beta Corp'
SET app.current_org = '20000000-0000-4000-8000-000000000001';
INSERT INTO domains (organization_id, fqdn, status, txt_token)
VALUES ('20000000-0000-4000-8000-000000000002', 'intruso.mx', 'pending_verification', 'rls-test-0001');

\echo '[6] Acme intenta escanear old-example.net (autorización vencida el 15 Aug 2026)'
INSERT INTO scans (organization_id, domain_id, authorization_id, txt_verification_id, trigger_type, status)
VALUES ('20000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000005',
        '41000000-0000-4000-8000-000000000005', '42000000-0000-4000-8000-000000000005', 'scheduled', 'queued');

\echo '[7] cirdan_app intenta UPDATE en audit_log'
UPDATE audit_log SET action = 'tampered';

RESET ROLE;
\echo '[8] postgres (superusuario) intenta UPDATE, DELETE y TRUNCATE en audit_log'
UPDATE audit_log SET action = 'tampered' WHERE chain_seq = 1;
DELETE FROM audit_log;
TRUNCATE audit_log;

\set ON_ERROR_STOP on
\echo '[9] audit_log sigue intacto'
SELECT count(*) AS rows, count(*) FILTER (WHERE action = 'tampered') AS tampered FROM audit_log;

\echo '[10] login_lookup(): search_path que termina en pg_temp, 4 columnas y cirdan_app sin TEMPORARY'
SELECT prosecdef AS security_definer,
       array_to_string(proconfig, '; ') AS config,
       pg_get_function_result(oid) AS devuelve,
       has_database_privilege('cirdan_app', current_database(), 'TEMPORARY') AS app_con_temporary
  FROM pg_proc WHERE oid = 'login_lookup(citext)'::regprocedure;

\echo '[11] cirdan_app pone una vista temporal users que lo vuelve superusuario: login_lookup() no la lee'
-- TEMPORARY se le presta a cirdan_app solo dentro de la transacción. El ROLLBACK lo deshace todo.
BEGIN;
GRANT TEMPORARY ON DATABASE cirdan TO cirdan_app;
SET LOCAL ROLE cirdan_app;
CREATE FUNCTION pg_temp.escalar() RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
  ALTER ROLE cirdan_app SUPERUSER;
  RETURN true;
END $$;
CREATE TEMP VIEW users AS
  SELECT '00000000-0000-4000-8000-0000000000aa'::uuid AS id,
         '20000000-0000-4000-8000-000000000001'::uuid AS organization_id,
         'trampa'::text AS password_hash, 'admin'::text AS role, 'Trampa'::text AS full_name,
         'trampa@ejemplo.invalid'::citext AS email, now() AS mfa_enabled_at,
         '\x00'::bytea AS totp_secret_enc, pg_temp.escalar() AS is_active;
SELECT current_user AS rol,
       (SELECT relpersistence FROM pg_class WHERE oid = 'users'::regclass) AS users_para_la_app,
       (SELECT count(*) FROM login_lookup('trampa@ejemplo.invalid')) AS filas_falsas;
RESET ROLE;
SELECT rolname, rolsuper FROM pg_roles WHERE rolname = 'cirdan_app';
ROLLBACK;
