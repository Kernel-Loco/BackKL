-- =====================================================================
-- Cirdan · db/migraciones/014_cves_desde_recolectores.sql (#18, RC-46)
-- La visita web (cirdan/recolectores/visita.py) trae de la NVD la
-- descripción, el CVSS y la fecha de cada CVE que reporta, y la API los
-- lee de cves (LEFT JOIN de cirdan/api/v1.py). Hasta ahora cirdan_app
-- solo podía insertar el stub (cve_id). Con esta migración también
-- inserta esas cuatro columnas, solo al crear la fila: no recibe UPDATE,
-- así que una CVE que ya está no cambia y el orquestador usa
-- ON CONFLICT (cve_id) DO NOTHING. EPSS, KEV e intel_updated_at siguen
-- siendo solo del cargador diario de inteligencia.
-- =====================================================================
SET client_encoding = 'UTF8';
BEGIN;

GRANT INSERT (description, cvss_base_score, cvss_vector, published_at) ON cves TO cirdan_app;

COMMENT ON TABLE cves IS 'Inteligencia de vulnerabilidades local: CVSS de NVD, EPSS de FIRST y CISA KEV en una fila por CVE, cargada una vez al día. El worker inserta stubs o, si el recolector la trae de la NVD, la fila con descripción, CVSS y fecha (014). Nunca actualiza: el cargador diario es el único que actualiza.';

COMMIT;
