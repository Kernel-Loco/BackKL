-- =====================================================================
-- Cirdan · db/semillas/016_superadmin_lowtide.sql (RC-332)
-- equipo@lowtidesec.com, el admin de la organización LowTide de la semilla
-- 015 (RC-329), pasa a ser superadmin de la plataforma: elige con qué empresa
-- trabaja y en ella actúa como Admin (migración 017). No crea cuentas ni
-- cambia su contraseña, su MFA ni su rol. Va por correo y no por id para que
-- sirva igual en una base donde la cuenta se dio de alta con otro id. Si la
-- cuenta no existe, no hace nada. Se puede correr otra vez sin error.
-- Mientras la cuenta no tenga TOTP activo, is_platform_admin() de la 017 da
-- false: entra solo como Admin de LowTide hasta que active la verificación en
-- dos pasos y vuelva a iniciar sesión.
-- pruebas/test_superadmin.py revisa esta carga.
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO platform_admins (user_id, note)
SELECT id, 'Superadmin de LowTide (RC-332, decisión de Ernesto del 16 nov 2026)'
  FROM users
 WHERE email = 'equipo@lowtidesec.com'
ON CONFLICT (user_id) DO NOTHING;

COMMIT;
