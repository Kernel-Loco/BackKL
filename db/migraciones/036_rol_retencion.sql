-- =====================================================================
-- Cirdan · db/migraciones/036_rol_retencion.sql (#139, RC-257)
-- Rol cirdan_retention para la retención de 12 meses (sección 5.6 y
-- control 8.10 de docs/politica_seguridad_privacidad.md). Los triggers de
-- la 001 ya le dejan borrar domain_scores y score_contributions de más de
-- 12 meses; aquí se crea el rol y sus permisos. El job es cirdan/retencion.py.
--
-- Sin políticas nuevas: el job recorre empresa por empresa con
-- app.current_org, así que la política tenant_isolation de cada tabla ya le
-- deja ver y borrar solo las filas de esa empresa. Una política
-- 'USING (true)' para este rol abriría la lectura de toda la tabla y
-- pruebas/test_aislamiento.py la rechaza. La lista de empresas sale de
-- retention_orgs(), SECURITY DEFINER como password_hash_version_orgs() de
-- la 026: solo devuelve ids.
--
-- Sin superusuario ni BYPASSRLS. Solo SELECT y DELETE en las tablas que
-- purga, y SELECT e INSERT en audit_log para dejar su evento. No toca
-- audit_log, domain_authorizations ni dns_txt_verifications (van en #140,
-- RC-258). La contraseña la pone db/init/cargar_cirdan.sh con
-- CIRDAN_RETENTION_PASSWORD del .env; en una base que ya existe, con
-- \password (docs/despliegue.md). Se puede correr otra vez sin error.
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cirdan_retention') THEN
    CREATE ROLE cirdan_retention LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO cirdan_retention;
GRANT SELECT, DELETE ON public.deliveries, public.alerts, public.score_contributions, public.domain_scores,
  public.breach_exposures, public.findings, public.assets, public.reports, public.scan_source_runs, public.scans
  TO cirdan_retention;
GRANT SELECT, INSERT ON public.audit_log TO cirdan_retention;

CREATE OR REPLACE FUNCTION public.retention_orgs()
RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$ SELECT id FROM public.organizations ORDER BY id $$;

REVOKE ALL ON FUNCTION public.retention_orgs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.retention_orgs() TO cirdan_retention;

COMMENT ON FUNCTION public.retention_orgs() IS
  'Ids de las empresas para el job de retención (RC-257). Solo cirdan_retention la ejecuta; después trabaja empresa por empresa con RLS.';

COMMIT;
