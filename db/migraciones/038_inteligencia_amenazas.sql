-- Cargador de CISA KEV y EPSS (RC-127). No comparte credenciales con la API.
BEGIN;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cirdan_intel') THEN
    CREATE ROLE cirdan_intel LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO cirdan_intel;
GRANT SELECT ON public.cves TO cirdan_intel;
GRANT INSERT (cve_id, epss_score, epss_percentile, in_kev, kev_date_added, intel_updated_at)
  ON public.cves TO cirdan_intel;
GRANT UPDATE (epss_score, epss_percentile, in_kev, kev_date_added, intel_updated_at, updated_at)
  ON public.cves TO cirdan_intel;
COMMENT ON TABLE public.cves IS
  'Inteligencia de vulnerabilidades: el orquestador inserta CVE y datos NVD sin actualizar; cirdan_intel actualiza EPSS y CISA KEV.';
COMMIT;
