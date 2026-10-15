-- =====================================================================
-- Cirdan · db/migraciones/002_login.sql (#25, RC-58)
-- Inicio de sesión sin abrir RLS: al iniciar sesión todavía no se sabe la
-- empresa de quien entra, y cirdan_app solo ve usuarios de app.current_org.
-- login_lookup() corre con los permisos de su dueño (postgres) y devuelve
-- únicamente lo necesario para verificar la contraseña de UN correo.
-- Es la función login_lookup del DBML (desviación 4 de db/README.md).
-- =====================================================================

BEGIN;

CREATE FUNCTION login_lookup(p_email citext)
RETURNS TABLE (
  user_id         uuid,
  organization_id uuid,
  password_hash   text,
  role            text,
  full_name       text,
  email           citext,
  mfa_enabled     boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT u.id, u.organization_id, u.password_hash, u.role, u.full_name, u.email,
         u.mfa_enabled_at IS NOT NULL AND u.totp_secret_enc IS NOT NULL
    FROM users u
    JOIN organizations o ON o.id = u.organization_id
   WHERE u.email = p_email
     AND u.is_active
     AND o.status IN ('trial', 'active')
$$;

COMMENT ON FUNCTION login_lookup(citext) IS
  'Login: datos para verificar la contraseña de un correo activo de una empresa activa. SECURITY DEFINER porque antes del login no hay app.current_org. No devuelve el secreto TOTP: ese se lee con RLS ya fijada la empresa.';

REVOKE ALL ON FUNCTION login_lookup(citext) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION login_lookup(citext) TO cirdan_app;

COMMIT;
