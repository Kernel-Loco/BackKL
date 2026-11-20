-- =====================================================================
-- Cirdan · db/migraciones/026_huellas_por_version.sql (RC-333)
-- Rotar la llave de las huellas de contraseña sin dejar fuera a nadie.
-- El comando cirdan/auth/rotar_huellas.py vuelve a cifrar con la llave
-- actual las huellas de la versión anterior (de lt1$ a lt2$), empresa
-- por empresa con RLS. cirdan_app no puede listar las empresas, porque
-- organizations tiene RLS forzado: esta función le da solo los ids de
-- las empresas que todavía tienen huellas de una versión. No devuelve
-- huellas, correos, ids de usuario ni conteos.
-- Se aplica sola en una base con datos (AGENTS.md, flujo 7):
--   docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/026_huellas_por_version.sql
-- =====================================================================
SET client_encoding = 'UTF8';

BEGIN;

CREATE OR REPLACE FUNCTION public.password_hash_version_orgs(p_version integer)
RETURNS TABLE (organization_id uuid)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT DISTINCT u.organization_id
    FROM public.users u
   WHERE p_version BETWEEN 1 AND 9999
     AND starts_with(u.password_hash, 'lt' || p_version::text || '$')
$$;

COMMENT ON FUNCTION public.password_hash_version_orgs(integer) IS
  'Rotación de la llave de las huellas (RC-333): ids de las empresas con al menos una huella de contraseña de la versión p_version (prefijo lt<versión>$). No devuelve huellas, correos, ids de usuario ni conteos. SECURITY DEFINER porque organizations y users tienen RLS forzado. Su search_path termina en pg_temp, como login_lookup().';

REVOKE ALL ON FUNCTION public.password_hash_version_orgs(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.password_hash_version_orgs(integer) TO cirdan_app;

COMMIT;
