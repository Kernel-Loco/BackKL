-- =====================================================================
-- Cirdan · db/migraciones/033_delegaciones_operador.sql (#66, RC-126)
-- Consola multiempresa del integrador. Una empresa cliente delega en una
-- empresa integradora, y las cuentas 'operator' del integrador ven la lista
-- de empresas delegadas con su riesgo (/api/v1/operator, cirdan/api/operador.py).
-- Lo que llega aquí:
-- 1. users.role suma 'operator'. Con su cookie, un operator solo usa
--    /api/v1/auth/* (su propia cuenta) y /api/v1/operator: cualquier otra
--    ruta le responde 403 (cirdan/auth/deps.py, current_session), así que en
--    su propia empresa no administra ni lee dominios ni hallazgos. Sin TOTP
--    activo no inicia sesión con contraseña, con enlace ni con passkey, y si
--    se le quita el TOTP o el rol, su sesión se cierra en la siguiente
--    petición a la consola (comentario 10270, punto 2). El rol se da o se
--    quita como postgres: después hay que cerrar las sesiones abiertas de la
--    cuenta (ver db/README.md).
-- 2. org_delegations: organization_id es la empresa integradora (la dueña
--    de la fila para RLS), client_organization_id la empresa cliente,
--    granted_by quién la otorgó, granted_at, y revoked_at y revoked_by
--    cuando se revoca (van los dos o ninguno). Quien otorga o revoca es un
--    admin activo de la empresa cliente: la FK compuesta pide una cuenta de
--    esa empresa y el trigger org_delegations_quien_firma pide el rol y que
--    esté activa. Una sola delegación sin revocar por pareja. Una empresa no
--    se delega en sí misma.
-- 3. RLS con ENABLE, FORCE y tenant_isolation, que filtra por
--    app_current_org() como las 18 tablas de la 001. cirdan_app solo tiene
--    SELECT: una delegación se da o se revoca como postgres (a mano o con
--    un script), nunca desde la API.
-- 4. actor_type 'operator' en audit_log. Cada lectura del operador queda en
--    la bitácora de la empresa cliente con actor 'operator' (no 'platform',
--    que es el superadmin de RC-332), actor_user_id NULL (la FK compuesta
--    pide una cuenta de la cliente) y en details el id de la cuenta y de la
--    empresa integradora (lo exige un CHECK, con forma de uuid).
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

-- Los ALTER de users y audit_log toman ACCESS EXCLUSIVE: si la API las tiene ocupadas, falla en 5 s sin cambiar
-- nada y se vuelve a correr, en vez de dejar esperando a cada login (como la 017).
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
  CONSTRAINT org_delegations_revocada CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
  CONSTRAINT org_delegations_revocada_despues CHECK (revoked_at IS NULL OR revoked_at >= granted_at),
  -- Quien otorga o revoca es una cuenta de la empresa cliente: la FK compuesta lo exige, como las de la 001.
  CONSTRAINT org_delegations_granted_by_fk FOREIGN KEY (client_organization_id, granted_by)
    REFERENCES public.users (organization_id, id),
  CONSTRAINT org_delegations_revoked_by_fk FOREIGN KEY (client_organization_id, revoked_by)
    REFERENCES public.users (organization_id, id)
);

-- Si la tabla ya existía de una corrida anterior de esta misma migración, el CHECK de revocada queda en los dos
-- sentidos.
ALTER TABLE public.org_delegations DROP CONSTRAINT IF EXISTS org_delegations_revocada;
ALTER TABLE public.org_delegations ADD CONSTRAINT org_delegations_revocada
  CHECK ((revoked_at IS NULL) = (revoked_by IS NULL));

COMMENT ON TABLE public.org_delegations IS
  'Delegaciones de una empresa cliente en una empresa integradora (#66, RC-126). organization_id es la integradora, dueña de la fila para RLS. cirdan_app solo lee. Se otorga o revoca como postgres, a nombre de un admin activo de la cliente.';

CREATE UNIQUE INDEX IF NOT EXISTS org_delegations_una_vigente
  ON public.org_delegations (organization_id, client_organization_id) WHERE revoked_at IS NULL;

-- Quien otorga (al crearla) o revoca (al poner revoked_by) es un admin activo de la empresa cliente. La FK compuesta
-- ya pide que sea de esa empresa. Corre con los permisos de quien escribe (postgres), no es SECURITY DEFINER.
CREATE OR REPLACE FUNCTION public.org_delegations_quien_firma() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF (TG_OP = 'INSERT' OR NEW.granted_by IS DISTINCT FROM OLD.granted_by) AND NOT EXISTS (
      SELECT 1 FROM public.users u WHERE u.organization_id = NEW.client_organization_id AND u.id = NEW.granted_by
         AND u.role = 'admin' AND u.is_active) THEN
    RAISE EXCEPTION 'org_delegations_quien_firma: granted_by debe ser un admin activo de la empresa cliente'
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.revoked_by IS NOT NULL AND (TG_OP = 'INSERT' OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by)
     AND NOT EXISTS (
      SELECT 1 FROM public.users u WHERE u.organization_id = NEW.client_organization_id AND u.id = NEW.revoked_by
         AND u.role = 'admin' AND u.is_active) THEN
    RAISE EXCEPTION 'org_delegations_quien_firma: revoked_by debe ser un admin activo de la empresa cliente'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION public.org_delegations_quien_firma() FROM PUBLIC;

DROP TRIGGER IF EXISTS org_delegations_quien_firma ON public.org_delegations;
CREATE TRIGGER org_delegations_quien_firma BEFORE INSERT OR UPDATE OF granted_by, revoked_by
  ON public.org_delegations FOR EACH ROW EXECUTE FUNCTION public.org_delegations_quien_firma();

ALTER TABLE public.org_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_delegations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON public.org_delegations;
CREATE POLICY tenant_isolation ON public.org_delegations
  USING (organization_id = app_current_org()) WITH CHECK (organization_id = app_current_org());

REVOKE ALL ON public.org_delegations FROM PUBLIC;
REVOKE ALL ON public.org_delegations FROM cirdan_app;
GRANT SELECT ON public.org_delegations TO cirdan_app;

-- actor_type 'operator' (punto 4). El CHECK de la 017 se rehace con el valor nuevo.
ALTER TABLE public.audit_log DROP CONSTRAINT IF EXISTS audit_log_actor_type_check;
ALTER TABLE public.audit_log ADD CONSTRAINT audit_log_actor_type_check
  CHECK (actor_type IN ('user', 'api_key', 'system', 'platform', 'operator'));
ALTER TABLE public.audit_log DROP CONSTRAINT IF EXISTS audit_log_operator_actor_check;
ALTER TABLE public.audit_log ADD CONSTRAINT audit_log_operator_actor_check
  CHECK (actor_type <> 'operator' OR (organization_id IS NOT NULL AND actor_user_id IS NULL
                                      AND actor_api_key_id IS NULL
                                      -- coalesce: sin la clave el ~ da NULL, y un CHECK con NULL deja pasar la fila.
                                      AND coalesce(details->>'operator_user_id'
                                          ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', false)
                                      AND coalesce(details->>'operator_organization_id'
                                          ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', false)));

COMMIT;
