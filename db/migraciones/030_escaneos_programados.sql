-- =====================================================================
-- Cirdan · db/migraciones/030_escaneos_programados.sql (#27, RC-52)
-- Escaneos programados: cada dominio autorizado se vuelve a escanear según
-- plans.scan_interval de su empresa (Starter cada 7 días, Business y
-- Enterprise cada día). Los pide el servicio programador
-- (cirdan/programador), que corre como cirdan_app igual que la API.
--
-- Lo que llega aquí es una sola función, scheduled_scan_candidates(p_now,
-- p_limit): los dominios que ya toca escanear, de todas las empresas. Hace
-- falta SECURITY DEFINER porque organizations, domains y
-- domain_authorizations tienen RLS forzado y el programador no sabe de
-- antemano qué empresa toca. Devuelve solo (organization_id, domain_id), sin
-- fqdn ni datos de la carta: con eso el programador fija app.current_org y
-- todo lo demás (reclamar el turno, revisar la carta y el TXT, crear el
-- escaneo) lo hace dentro de la empresa, con RLS. La función no escribe nada
-- ni decide sola: orquestador.solicitar() y el trigger
-- scans_require_authorization siguen exigiendo carta vigente y TXT 'match'
-- de la última hora.
--
-- Candidato: dominio 'verified', empresa en 'trial' o 'active', con una
-- carta no revocada y vigente en p_now::date (en la zona de la sesión, que
-- cirdan/db.py fija en America/Mexico_City, la misma con que solicitar() y el
-- trigger usan current_date) y next_scan_at vacío o ya vencido en p_now.
-- Primero los que nunca tuvieron turno y luego los más atrasados.
--
-- Sin tabla nueva ni columna nueva: domains.next_scan_at y su índice
-- domains_next_scan_idx vienen de la 001. Se puede correr otra vez sin error.
--
--   docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/030_escaneos_programados.sql
--
-- Va antes de encender el programador. La API no la usa.
-- =====================================================================
SET client_encoding = 'UTF8';
BEGIN;

CREATE OR REPLACE FUNCTION public.scheduled_scan_candidates(p_now timestamptz, p_limit integer)
RETURNS TABLE (organization_id uuid, domain_id uuid)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT d.organization_id, d.id
    FROM public.domains d
    JOIN public.organizations o ON o.id = d.organization_id
   WHERE d.status = 'verified'
     AND o.status IN ('trial', 'active')
     AND (d.next_scan_at IS NULL OR d.next_scan_at <= p_now)
     AND EXISTS (SELECT 1 FROM public.domain_authorizations a
                  WHERE a.domain_id = d.id AND a.organization_id = d.organization_id
                    AND a.revoked_at IS NULL
                    AND p_now::date BETWEEN a.valid_from AND a.valid_until)
   ORDER BY d.next_scan_at NULLS FIRST, d.id
   LIMIT least(greatest(coalesce(p_limit, 0), 0), 500)
$$;

COMMENT ON FUNCTION public.scheduled_scan_candidates(timestamptz, integer) IS
  'Escaneos programados (RC-52): organization_id y domain_id de los dominios verified de empresas trial o active, con carta no revocada y vigente en p_now::date y next_scan_at vacío o <= p_now, primero los vacíos y luego los más atrasados, hasta p_limit (tope 500). No devuelve fqdn ni datos de la carta y no escribe nada. SECURITY DEFINER porque organizations, domains y domain_authorizations tienen RLS forzado. Su search_path termina en pg_temp, como login_lookup().';

REVOKE ALL ON FUNCTION public.scheduled_scan_candidates(timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.scheduled_scan_candidates(timestamptz, integer) TO cirdan_app;

COMMIT;
