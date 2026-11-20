-- =====================================================================
-- Cirdan · db/migraciones/016_api_key_lookup.sql (RC-129, #87)
-- Llaves de API para integradores. La tabla api_keys ya existe desde la
-- 001, con RLS forzado. Aquí llega lo que falta en la base:
-- 1. api_key_lookup(p_hash): busca una llave por el SHA-256 de la llave
--    completa. Es SECURITY DEFINER, igual que login_lookup() de la 004,
--    porque api_keys tiene RLS forzado y la empresa no se conoce hasta
--    encontrar la llave. Solo devuelve una llave que sirve: sin revocar,
--    sin vencer, de una empresa activa y con un plan que incluye la API
--    (plans.api_and_siem, Business y Enterprise). No devuelve el hash, el
--    prefijo ni el nombre. touch dice si ya pasó un minuto desde el último
--    uso guardado, para que la API no escriba en cada petición.
-- 2. cirdan_app ya no puede cambiar toda la fila de una llave: solo
--    last_used_at, revoked_at y updated_at. Así la aplicación no puede
--    cambiarle el hash, el alcance ni la vigencia a una llave que ya existe.
--    Tampoco puede escribir created_at al crearla: el CHECK de 90 días se
--    mide contra created_at, y con una fecha futura la llave duraría años.
--    Igual que con scans.queued_at en la 001, el INSERT queda por columnas.
-- 3. Una llave revocada no se puede volver a activar (trigger).
-- Corre en una sola transacción y se puede correr otra vez sin error.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

CREATE OR REPLACE FUNCTION public.api_key_lookup(p_hash bytea)
RETURNS TABLE (
  key_id          uuid,
  organization_id uuid,
  domain_id       uuid,
  scopes          text[],
  touch           boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT k.id, k.organization_id, k.domain_id, k.scopes,
         k.last_used_at IS NULL OR k.last_used_at < now() - interval '1 minute'
    FROM public.api_keys k
    JOIN public.organizations o ON o.id = k.organization_id
    JOIN public.plans p ON p.id = o.plan_id
   WHERE k.key_hash = p_hash
     AND k.revoked_at IS NULL
     AND k.expires_at > now()
     AND o.status IN ('trial', 'active')
     AND p.api_and_siem
$$;

COMMENT ON FUNCTION public.api_key_lookup(bytea) IS
  'Llave de API vigente a partir del SHA-256 de la llave completa: su id, empresa, dominio (NULL = toda la empresa), alcances y si toca guardar el último uso. No devuelve nada si la llave está revocada o vencida, si la empresa no está activa o si su plan no incluye la API. SECURITY DEFINER porque antes de encontrar la llave no hay app.current_org. Su search_path termina en pg_temp para que una tabla o vista temporal no la engañe.';

REVOKE ALL ON FUNCTION public.api_key_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.api_key_lookup(bytea) TO cirdan_app;

-- La 001 daba UPDATE sobre toda la tabla. Se deja solo lo que la API cambia.
REVOKE UPDATE ON public.api_keys FROM cirdan_app;
GRANT UPDATE (last_used_at, revoked_at, updated_at) ON public.api_keys TO cirdan_app;

-- La 001 también daba INSERT sobre toda la tabla. Sin created_at, que toma su valor por omisión,
-- la vigencia máxima de 90 días la garantiza la base y no solo la API.
REVOKE INSERT ON public.api_keys FROM cirdan_app;
GRANT INSERT (organization_id, domain_id, name, key_prefix, key_hash, scopes, created_by, expires_at)
  ON public.api_keys TO cirdan_app;

CREATE OR REPLACE FUNCTION public.api_keys_revocation_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'api_keys: una llave revocada no se vuelve a activar ni cambia su fecha de revocación'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS api_keys_revocation_bu ON public.api_keys;
CREATE TRIGGER api_keys_revocation_bu BEFORE UPDATE ON public.api_keys
  FOR EACH ROW EXECUTE FUNCTION public.api_keys_revocation_guard();

COMMIT;
