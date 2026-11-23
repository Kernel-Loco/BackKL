-- =====================================================================
-- Cirdan · db/migraciones/032_llave_fuentes.sql (#19, RC-54)
-- Llaves de API de las fuentes, cifradas en data_sources.api_key_enc. La
-- primera es la de Have I Been Pwned (fila 'hibp').
--
-- cirdan_app no puede leer esa columna (GRANT por columna de la 001) ni
-- hacer UPDATE en data_sources. Esta migración le da una sola función,
-- source_api_key(p_code), que devuelve el bytea cifrado de una fuente
-- habilitada, o NULL si no tiene llave, está apagada o no existe. La base
-- nunca ve la llave en claro: el orquestador la descifra con AES-256-GCM y
-- SOURCE_KEYS_ENCRYPTION_KEY del .env (cirdan/recolectores/llaves.py). La
-- llave la guarda Ernesto como postgres con el UPDATE de
-- docs/servicios_externos.md, que también pone key_rotated_at.
--
-- SECURITY DEFINER con search_path que termina en pg_temp, REVOKE de PUBLIC
-- y EXECUTE solo a cirdan_app, como la 027 y la 030. No escribe nada.
-- api_key_enc y key_rotated_at vienen de la 001.
--
-- También suma a scan_source_runs dos columnas que el orquestador llena en
-- cada corrida, para elegir los correos que identity (#20) pasa a HIBP
-- (orquestador.CORREOS_SQL): coverage ('complete' si revisó todas sus
-- partes, 'partial' si solo algunas, 'none' si no revisó nada, NULL si no
-- respondió) y mode ('vivo', 'grabar' o 'reproducir'). Las corridas de
-- antes quedan en NULL. cirdan_app ya tiene SELECT, INSERT y UPDATE sobre
-- la tabla (001) y RLS no cambia. Se puede correr otra vez sin error.
--
--   docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/032_llave_fuentes.sql
--
-- Va antes de reconstruir la API con el recolector de HIBP y antes de
-- reconstruir o reiniciar el programador, que usa el mismo orquestador. Sin
-- ella el orquestador no puede guardar ninguna corrida (escribe coverage y
-- mode) y todo escaneo, manual o programado, falla, además de no leer la
-- llave.
-- =====================================================================
SET client_encoding = 'UTF8';
BEGIN;

CREATE OR REPLACE FUNCTION public.source_api_key(p_code text)
RETURNS bytea
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT s.api_key_enc
    FROM public.data_sources s
   WHERE s.code = p_code
     AND s.enabled
$$;

COMMENT ON FUNCTION public.source_api_key(text) IS
  'Llave de API de una fuente (RC-54): data_sources.api_key_enc de la fuente p_code si está habilitada, o NULL. Es el bytea cifrado con AES-256-GCM (versión, nonce, texto cifrado y tag): la base nunca ve la llave en claro y el orquestador la descifra con SOURCE_KEYS_ENCRYPTION_KEY. SECURITY DEFINER porque cirdan_app no puede leer api_key_enc. No escribe nada. Su search_path termina en pg_temp, como login_lookup().';

REVOKE ALL ON FUNCTION public.source_api_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.source_api_key(text) TO cirdan_app;

ALTER TABLE public.scan_source_runs
  ADD COLUMN IF NOT EXISTS coverage text
    CONSTRAINT scan_source_runs_coverage_valida CHECK (coverage IN ('complete', 'partial', 'none')),
  ADD COLUMN IF NOT EXISTS mode text
    CONSTRAINT scan_source_runs_mode_valido CHECK (mode IN ('vivo', 'grabar', 'reproducir'));

COMMENT ON COLUMN public.scan_source_runs.coverage IS
  'Qué partes revisó la fuente en esta corrida (RC-54): complete (todas, aunque algún código quede sin cobertura por falta de llave), partial (solo algunas), none (ninguna) o NULL si no respondió o es de antes de la migración 032.';
COMMENT ON COLUMN public.scan_source_runs.mode IS
  'Modo de la corrida (RC-54): vivo, grabar o reproducir. NULL en las de antes de la migración 032. Un escaneo en vivo no toma los correos de identity de una corrida en reproducir.';

COMMIT;
