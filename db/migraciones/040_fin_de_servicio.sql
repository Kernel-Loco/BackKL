-- =====================================================================
-- Cirdan · db/migraciones/040_fin_de_servicio.sql (#140, RC-258)
-- Borrado al terminar el servicio y cancelación de usuarios del portal
-- (sección 5.6 y control 8.10 de docs/politica_seguridad_privacidad.md).
--
-- 1. organizations.service_ended_at: cuándo terminó el servicio de la
--    empresa. Lo pone el comando del operador (cirdan/fin_servicio.py) junto
--    con status = 'cancelled'.
-- 2. users.cancelled_at: cuándo se canceló la cuenta. Al cancelarla se borran
--    la huella de la contraseña y la semilla TOTP; el nombre y el correo se
--    anonimizan al vencer el plazo (job de retención, RC-257).
-- 3. block_mutation(): además de lo de más de 12 meses, cirdan_retention
--    puede borrar los scores y sus aportes de una empresa con
--    service_ended_at. Sin esto, score_contributions apunta a findings y no
--    se podía borrar nada de lo que entró en un score. audit_log,
--    domain_authorizations y dns_txt_verifications siguen inmutables: su
--    plazo queda como riesgo aceptado (sección 9 de la política).
-- 4. Permisos de cirdan_retention para el fin de servicio, siempre con RLS de
--    la empresa: UPDATE de status y service_ended_at en organizations, de
--    status en domains, de is_active, full_name y email en users (para
--    desactivar y anonimizar) y SELECT en organizations, domains, users,
--    domain_authorizations (el correo de quien firmó, para la confirmación).
-- Se puede correr otra vez sin error.
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

ALTER TABLE public.organizations ADD COLUMN IF NOT EXISTS service_ended_at timestamptz;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS cancelled_at timestamptz;

COMMENT ON COLUMN public.organizations.service_ended_at IS
  'Cuándo terminó el servicio de la empresa (RC-258). Con valor, cirdan_retention borra sus hallazgos, activos, scores y reportes.';
COMMENT ON COLUMN public.users.cancelled_at IS
  'Cuándo se canceló la cuenta (RC-258): sin huella ni TOTP desde ese momento; nombre y correo anonimizados al vencer el plazo.';

CREATE OR REPLACE FUNCTION block_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  -- Excepciones de retención: solo DELETE y solo cirdan_retention. IF anidados: PL/pgSQL no corta un AND, y cada
  -- tabla solo tiene sus columnas (039).
  IF TG_OP = 'DELETE' AND current_user = 'cirdan_retention' THEN
    IF TG_TABLE_NAME IN ('domain_scores', 'score_contributions') THEN
      -- Fin del servicio de la empresa (RC-258)
      IF EXISTS (SELECT 1 FROM organizations o
                  WHERE o.id = OLD.organization_id AND o.service_ended_at IS NOT NULL) THEN
        RETURN OLD;
      END IF;
    END IF;
    -- Filas de más de 12 meses (001, RC-257)
    IF TG_TABLE_NAME = 'domain_scores' THEN
      IF OLD.computed_at < now() - interval '12 months' THEN
        RETURN OLD;
      END IF;
    ELSIF TG_TABLE_NAME = 'score_contributions' THEN
      IF EXISTS (SELECT 1 FROM domain_scores s
                  WHERE s.id = OLD.score_id AND s.computed_at < now() - interval '12 months') THEN
        RETURN OLD;
      END IF;
    END IF;
  END IF;
  RAISE EXCEPTION '% es de solo inserción: % bloqueado por trigger', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'insufficient_privilege';
END $$;

GRANT SELECT ON public.organizations, public.domains, public.users, public.domain_authorizations
  TO cirdan_retention;
GRANT UPDATE (status, service_ended_at, updated_at) ON public.organizations TO cirdan_retention;
GRANT UPDATE (status, updated_at) ON public.domains TO cirdan_retention;
GRANT UPDATE (is_active, full_name, email, updated_at) ON public.users TO cirdan_retention;
GRANT SELECT, UPDATE (revoked_at, updated_at) ON public.api_keys TO cirdan_retention;

COMMIT;
