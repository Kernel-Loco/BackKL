-- =====================================================================
-- Cirdan · db/migraciones/004_login_lookup_seguro.sql (RC-58)
-- Endurece login_lookup() de la migración 002, que corre como postgres.
-- 1. Su search_path no tenía pg_temp, y en ese caso PostgreSQL busca
--    primero en el esquema temporal de la sesión. cirdan_app podía crear una
--    vista temporal llamada users que llamara a una función suya, y la
--    función de login la leía en lugar de la tabla. Esa función corría como
--    postgres y podía volver superusuario a cirdan_app. Ahora el search_path
--    termina en pg_temp y las tablas van con esquema (public.users y
--    public.organizations).
-- 2. Devuelve solo lo que usa el login: user_id, organization_id,
--    password_hash y mfa_enabled. El rol se lee después con RLS ya fijada,
--    como en /mfa/verify (cirdan/auth/routes.py).
-- 3. Quita TEMPORARY a PUBLIC en esta base. Ni la API ni las pruebas crean
--    objetos temporales, y sin ellos cirdan_app no puede poner una vista
--    temporal en lugar de una tabla en otra función SECURITY DEFINER.
-- Como cambia lo que devuelve, CREATE OR REPLACE no sirve: se borra y se
-- crea de nuevo en la misma transacción. Se puede correr otra vez sin error.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

BEGIN;

DROP FUNCTION public.login_lookup(public.citext);

CREATE FUNCTION public.login_lookup(p_email public.citext)
RETURNS TABLE (
  user_id         uuid,
  organization_id uuid,
  password_hash   text,
  mfa_enabled     boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT u.id, u.organization_id, u.password_hash,
         u.mfa_enabled_at IS NOT NULL AND u.totp_secret_enc IS NOT NULL
    FROM public.users u
    JOIN public.organizations o ON o.id = u.organization_id
   WHERE u.email = p_email
     AND u.is_active
     AND o.status IN ('trial', 'active')
$$;

COMMENT ON FUNCTION public.login_lookup(public.citext) IS
  'Login: id, empresa, hash de la contraseña y si tiene MFA de un correo activo de una empresa activa. SECURITY DEFINER porque antes del login no hay app.current_org. Su search_path termina en pg_temp para que una tabla o vista temporal no la engañe. El rol y el secreto TOTP se leen con RLS ya fijada la empresa.';

REVOKE ALL ON FUNCTION public.login_lookup(public.citext) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.login_lookup(public.citext) TO cirdan_app;

-- El nombre de la base no va fijo: es la base donde corre la migración.
DO $$
BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END $$;

COMMIT;
