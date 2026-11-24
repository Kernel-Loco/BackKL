-- =====================================================================
-- Cirdan · db/migraciones/033_delegaciones_operador.sql (#66, RC-126)
-- Consola multiempresa del integrador. Una empresa cliente delega en una
-- empresa integradora, y las cuentas 'operator' del integrador ven la lista
-- de empresas delegadas con su riesgo (/api/v1/operator, cirdan/api/operador.py).
-- Lo que llega aquí:
-- 1. users.role suma 'operator'. Un operator no pasa ningún require_roles()
--    de la API: en su propia empresa no administra ni lee hallazgos, solo
--    entra a la consola. Sin TOTP activo no inicia sesión con contraseña ni
--    con enlace y la consola le responde 403 (comentario 10270, punto 2).
-- 2. org_delegations: organization_id es la empresa integradora (la dueña
--    de la fila para RLS), client_organization_id la empresa cliente,
--    granted_by quién la otorgó (una cuenta de la empresa cliente, con FK
--    compuesta), granted_at, y revoked_at y revoked_by cuando se revoca.
--    Una sola delegación sin revocar por pareja. Una empresa no se delega
--    en sí misma.
-- 3. RLS con ENABLE, FORCE y tenant_isolation, que filtra por
--    app_current_org() como las 18 tablas de la 001. cirdan_app solo tiene
--    SELECT: una delegación se da o se revoca como postgres (a mano o con
--    un script), nunca desde la API.
-- Las políticas RLS que ya existen no cambian y no hay ninguna función
-- SECURITY DEFINER nueva. La API lee la delegación con RLS de la empresa
-- integradora y luego, en otra transacción, los datos de cada empresa
-- cliente con RLS de esa empresa: una sola empresa por transacción.
-- El superadmin de RC-332 (platform_admins, 017) sigue aparte.
-- Corre en una sola transacción y se puede correr otra vez sin error.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

-- El ALTER de users toma ACCESS EXCLUSIVE: si la API la tiene ocupada, falla en 5 s sin cambiar nada y se vuelve a
-- correr, en vez de dejar esperando a cada login (como la 017).
SET LOCAL lock_timeout = '5s';

-- El CHECK de role de la 001 no tiene nombre propio: PostgreSQL le dio users_role_check.
ALTER TABLE public.users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE public.users ADD CONSTRAINT users_role_check
  CHECK (role IN ('analyst', 'manager', 'admin', 'operator'));

CREATE TABLE IF NOT EXISTS public.org_delegations (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id        uuid NOT NULL REFERENCES public.organizations (id),
  client_organization_id uuid NOT NULL REFERENCES public.organizations (id),
  granted_by             uuid NOT NULL,
  granted_at             timestamptz NOT NULL DEFAULT now(),
  revoked_at             timestamptz,
  revoked_by             uuid,
  UNIQUE (organization_id, id),
  CONSTRAINT org_delegations_otra_empresa CHECK (organization_id <> client_organization_id),
  CONSTRAINT org_delegations_revocada CHECK (revoked_by IS NULL OR revoked_at IS NOT NULL),
  CONSTRAINT org_delegations_revocada_despues CHECK (revoked_at IS NULL OR revoked_at >= granted_at),
  -- Quien otorga o revoca es una cuenta de la empresa cliente: la FK compuesta lo exige, como las de la 001.
  CONSTRAINT org_delegations_granted_by_fk FOREIGN KEY (client_organization_id, granted_by)
    REFERENCES public.users (organization_id, id),
  CONSTRAINT org_delegations_revoked_by_fk FOREIGN KEY (client_organization_id, revoked_by)
    REFERENCES public.users (organization_id, id)
);

COMMENT ON TABLE public.org_delegations IS
  'Delegaciones de una empresa cliente en una empresa integradora (#66, RC-126). organization_id es la integradora, dueña de la fila para RLS. cirdan_app solo lee. Se otorga o revoca como postgres.';

CREATE UNIQUE INDEX IF NOT EXISTS org_delegations_una_vigente
  ON public.org_delegations (organization_id, client_organization_id) WHERE revoked_at IS NULL;

ALTER TABLE public.org_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_delegations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON public.org_delegations;
CREATE POLICY tenant_isolation ON public.org_delegations
  USING (organization_id = app_current_org()) WITH CHECK (organization_id = app_current_org());

REVOKE ALL ON public.org_delegations FROM PUBLIC;
REVOKE ALL ON public.org_delegations FROM cirdan_app;
GRANT SELECT ON public.org_delegations TO cirdan_app;

COMMIT;
