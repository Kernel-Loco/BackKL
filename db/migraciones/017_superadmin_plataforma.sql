-- =====================================================================
-- Cirdan · db/migraciones/017_superadmin_plataforma.sql (RC-332)
-- Superadmin de la plataforma: una cuenta que elige con qué empresa trabaja
-- y, dentro de ella, actúa como Admin. RLS no cambia: la API sigue fijando
-- app.current_org con una sola empresa por transacción y cirdan_app sigue sin
-- BYPASSRLS. Lo que llega aquí:
-- 1. platform_admins: quién es superadmin. No tiene organization_id ni
--    políticas, lleva ENABLE y FORCE RLS y cirdan_app no tiene ningún
--    permiso sobre ella. Solo se escribe como postgres (semilla 016 o a
--    mano) y la app solo la lee con las dos funciones de abajo. Va aparte y
--    no como columna de users porque cirdan_app puede escribir toda la fila
--    de users (001): con una columna, un error de la app bastaría para
--    nombrar a otro superadmin.
-- 2. is_platform_admin(p_user): si la cuenta está en platform_admins, sigue
--    activa, tiene la verificación en dos pasos activa y su empresa está en
--    'trial' o 'active'. Sin TOTP no hay superadmin: con solo la contraseña la
--    sesión nace con platform_admin false, y si se le quita el TOTP la sesión
--    abierta en una empresa ajena se cierra en la siguiente petición.
-- 3. platform_organizations(p_user): id, nombre y estado de todas las
--    empresas, solo si p_user es superadmin. Es el único cruce entre
--    empresas y no devuelve ningún dato de sus tablas.
-- 4. actor_type 'platform' en audit_log. Las FK compuestas de la 001
--    (organization_id, actor_user_id) -> users no dejan poner como autor a
--    una cuenta de otra empresa. En la empresa ajena la acción queda con
--    actor 'platform', actor_user_id NULL y el id de la cuenta en
--    details->>'platform_user_id' (lo exige un CHECK, con forma de uuid).
-- Las dos funciones son SECURITY DEFINER de postgres con search_path fijo y
-- EXECUTE solo para cirdan_app, como login_lookup() de la 004. Igual que
-- login_lookup(), confían en el p_user que les pasa la API: la API solo les
-- pasa el user_id de la sesión, nunca un id que mande el cliente. El uuid de
-- equipo@lowtidesec.com es público (semilla 015), así que un endpoint que les
-- pasara un id del cliente expondría la lista de empresas.
-- Corre en una sola transacción y se puede correr otra vez sin error.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

-- Los ALTER de audit_log toman ACCESS EXCLUSIVE: si la API la tiene ocupada, falla en 5 s sin cambiar nada y se
-- vuelve a correr, en vez de dejar esperando a cada login y escaneo (como la 012 y la 015).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS public.platform_admins (
  user_id    uuid PRIMARY KEY REFERENCES public.users (id),
  granted_at timestamptz NOT NULL DEFAULT now(),
  note       text NOT NULL CHECK (length(btrim(note)) > 0)
);

COMMENT ON TABLE public.platform_admins IS
  'Superadmins de la plataforma (RC-332). Sin permisos para cirdan_app: la API solo la lee con is_platform_admin() y platform_organizations(). Se escribe como postgres.';

ALTER TABLE public.platform_admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.platform_admins FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.platform_admins FROM PUBLIC;
REVOKE ALL ON public.platform_admins FROM cirdan_app;

CREATE OR REPLACE FUNCTION public.is_platform_admin(p_user uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.platform_admins pa
      JOIN public.users u ON u.id = pa.user_id
      JOIN public.organizations o ON o.id = u.organization_id
     WHERE pa.user_id = p_user
       AND u.is_active
       AND u.mfa_enabled_at IS NOT NULL
       AND u.totp_secret_enc IS NOT NULL
       AND o.status IN ('trial', 'active'))
$$;

COMMENT ON FUNCTION public.is_platform_admin(uuid) IS
  'Superadmin (RC-332): true si la cuenta está en platform_admins, sigue activa, tiene TOTP activo y su empresa está en trial o active. SECURITY DEFINER porque cirdan_app no puede leer platform_admins. Su search_path termina en pg_temp, como login_lookup().';

REVOKE ALL ON FUNCTION public.is_platform_admin(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_platform_admin(uuid) TO cirdan_app;

CREATE OR REPLACE FUNCTION public.platform_organizations(p_user uuid)
RETURNS TABLE (organization_id uuid, name text, status text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT o.id, o.name, o.status
    FROM public.organizations o
   WHERE public.is_platform_admin(p_user)
   ORDER BY o.name, o.id
$$;

COMMENT ON FUNCTION public.platform_organizations(uuid) IS
  'Superadmin (RC-332): id, nombre y estado de todas las empresas, solo si p_user es superadmin. Si no, no devuelve filas. No lee ninguna tabla por cliente. SECURITY DEFINER porque organizations tiene RLS forzado.';

REVOKE ALL ON FUNCTION public.platform_organizations(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.platform_organizations(uuid) TO cirdan_app;

-- El CHECK de actor_type de la 001 no tiene nombre propio: PostgreSQL le dio audit_log_actor_type_check.
ALTER TABLE public.audit_log DROP CONSTRAINT IF EXISTS audit_log_actor_type_check;
ALTER TABLE public.audit_log ADD CONSTRAINT audit_log_actor_type_check
  CHECK (actor_type IN ('user', 'api_key', 'system', 'platform'));
ALTER TABLE public.audit_log DROP CONSTRAINT IF EXISTS audit_log_platform_actor_check;
ALTER TABLE public.audit_log ADD CONSTRAINT audit_log_platform_actor_check
  CHECK (actor_type <> 'platform' OR (organization_id IS NOT NULL AND actor_user_id IS NULL
                                      AND actor_api_key_id IS NULL
                                      -- coalesce: sin la clave el ~ da NULL, y un CHECK con NULL deja pasar la fila.
                                      AND coalesce(details->>'platform_user_id'
                                          ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', false)));

COMMIT;
