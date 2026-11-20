-- =====================================================================
-- Cirdan · db/migraciones/027_mfa_operador.sql (#66)
-- Las cuentas con acceso de operador a la consola multiempresa deben
-- completar MFA antes de iniciar una sesión con contraseña.
-- `is_platform_admin()` solo devuelve true cuando TOTP ya está activo;
-- esta función consulta la pertenencia por separado para que una cuenta
-- sin TOTP no pueda iniciar sesión como usuario normal por contraseña.
-- =====================================================================

BEGIN;

CREATE OR REPLACE FUNCTION public.platform_operator_requires_mfa(p_user uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.platform_admins
     WHERE user_id = p_user
  )
$$;

COMMENT ON FUNCTION public.platform_operator_requires_mfa(uuid) IS
  'Indica si una cuenta pertenece a platform_admins, incluso si todavía no tiene TOTP. La API la consulta después de verificar la contraseña para impedir que un operador inicie sesión sin MFA. SECURITY DEFINER porque cirdan_app no puede leer platform_admins.';

REVOKE ALL ON FUNCTION public.platform_operator_requires_mfa(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.platform_operator_requires_mfa(uuid) TO cirdan_app;

COMMIT;
