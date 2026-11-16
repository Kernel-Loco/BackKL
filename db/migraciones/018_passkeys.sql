-- =====================================================================
-- Cirdan · db/migraciones/018_passkeys.sql (RC-331)
-- Passkeys (WebAuthn) como otra forma de entrar, junto a contraseña y TOTP.
-- 1. webauthn_credentials: una fila por passkey registrada. Guarda solo lo
--    público (id de la credencial, llave pública COSE, contador, transports,
--    aaguid y si el proveedor la respalda). La llave privada nunca sale del
--    autenticador. RLS ENABLE, FORCE y la política tenant_isolation, como las
--    tablas por cliente de la 001.
-- 2. passkey_lookup(p_credential_id): busca la credencial al iniciar sesión.
--    Es SECURITY DEFINER, igual que login_lookup() de la 004, porque antes de
--    entrar no hay app.current_org. Solo devuelve la credencial de un usuario
--    activo de una empresa en trial o active. Nunca devuelve el nombre de la
--    passkey ni datos de otras credenciales.
-- 3. cirdan_app solo cambia de una fila el contador, el último uso y el
--    respaldo. El INSERT va por columnas: created_at y last_used_at los pone
--    la base.
-- Solo crea: no toca filas que ya existen. Se revierte con
-- DROP FUNCTION public.passkey_lookup(bytea); DROP TABLE public.webauthn_credentials;
-- Corre en una sola transacción y se puede correr otra vez sin error.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

CREATE TABLE IF NOT EXISTS public.webauthn_credentials (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  user_id         uuid NOT NULL,
  -- La especificación pide como máximo 1023 bytes (WebAuthn nivel 3, credential ID).
  credential_id   bytea NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
  public_key      bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 2048),
  sign_count      bigint NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
  transports      text[] NOT NULL DEFAULT '{}'
                  CHECK (transports <@ ARRAY['ble','cable','hybrid','internal','nfc','smart-card','usb']::text[]),
  aaguid          uuid,
  backed_up       boolean NOT NULL DEFAULT false,
  name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_used_at    timestamptz,
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, user_id) REFERENCES public.users (organization_id, id)
);
CREATE INDEX IF NOT EXISTS webauthn_credentials_user_idx ON public.webauthn_credentials (organization_id, user_id);

COMMENT ON TABLE public.webauthn_credentials IS
  'Passkeys (WebAuthn) de cada usuario (RC-331). Solo la parte pública: la llave privada vive en el autenticador. Entrar con una exige verificación del usuario y cuenta como MFA.';

ALTER TABLE public.webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webauthn_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON public.webauthn_credentials;
CREATE POLICY tenant_isolation ON public.webauthn_credentials
  USING (organization_id = app_current_org()) WITH CHECK (organization_id = app_current_org());

REVOKE ALL ON public.webauthn_credentials FROM PUBLIC;
REVOKE ALL ON public.webauthn_credentials FROM cirdan_app;
GRANT SELECT, DELETE ON public.webauthn_credentials TO cirdan_app;
GRANT INSERT (organization_id, user_id, credential_id, public_key, sign_count, transports, aaguid, backed_up, name)
  ON public.webauthn_credentials TO cirdan_app;
GRANT UPDATE (sign_count, last_used_at, backed_up) ON public.webauthn_credentials TO cirdan_app;

CREATE OR REPLACE FUNCTION public.passkey_lookup(p_credential_id bytea)
RETURNS TABLE (
  passkey_id      uuid,
  user_id         uuid,
  organization_id uuid,
  email           text,
  public_key      bytea,
  sign_count      bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT c.id, c.user_id, c.organization_id, u.email::text, c.public_key, c.sign_count
    FROM public.webauthn_credentials c
    JOIN public.users u ON u.id = c.user_id AND u.organization_id = c.organization_id
    JOIN public.organizations o ON o.id = c.organization_id
   WHERE c.credential_id = p_credential_id
     AND u.is_active
     AND o.status IN ('trial', 'active')
$$;

COMMENT ON FUNCTION public.passkey_lookup(bytea) IS
  'Login con passkey: id de la fila, usuario, empresa, correo, llave pública y contador de la credencial, solo si el usuario está activo y su empresa en trial o active. SECURITY DEFINER porque antes del login no hay app.current_org. Su search_path termina en pg_temp para que una tabla o vista temporal no la engañe. El rol se lee después con RLS ya fijada.';

REVOKE ALL ON FUNCTION public.passkey_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.passkey_lookup(bytea) TO cirdan_app;

COMMIT;
