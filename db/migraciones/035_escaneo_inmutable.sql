-- =====================================================================
-- Cirdan · db/migraciones/035_escaneo_inmutable.sql (#167, RC-285)
-- Un escaneo ya creado no cambia de carta, TXT, dominio ni fecha.
-- Lo que llega aquí:
-- 1. cirdan_app pierde el UPDATE de toda la tabla scans (001:618) y queda
--    con UPDATE (status, finished_at, stats, updated_at), las cuatro
--    columnas que cambia el orquestador (cirdan/orquestador/__init__.py,
--    abandonar_vencidos, la marca de vida y el cierre del escaneo).
-- 2. scans_guard(): un trigger BEFORE UPDATE rechaza el cambio de cualquier
--    otra columna, también como postgres u otro rol, igual que
--    domain_authorizations_guard() de la 001. El trigger de la carta y el
--    TXT (scans_require_authorization, 001:565) solo corre en el INSERT, así
--    que sin esto un UPDATE podía cambiar authorization_id,
--    txt_verification_id, domain_id o queued_at sin esa revisión.
--    Una columna que se sume a scans en otra migración queda inmutable
--    hasta que esa migración la agregue a la lista de scans_guard().
-- Corre en una sola transacción y se puede correr otra vez sin error.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

-- El CREATE TRIGGER toma un candado sobre scans: si un escaneo la tiene ocupada, falla en 5 s sin cambiar nada y se
-- vuelve a correr (como la 017).
SET LOCAL lock_timeout = '5s';

REVOKE UPDATE ON public.scans FROM cirdan_app;
GRANT UPDATE (status, finished_at, stats, updated_at) ON public.scans TO cirdan_app;

CREATE OR REPLACE FUNCTION public.scans_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['status', 'finished_at', 'stats', 'updated_at'])
     IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'finished_at', 'stats', 'updated_at']) THEN
    RAISE EXCEPTION 'scans: un escaneo ya creado solo cambia status, finished_at, stats y updated_at'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION public.scans_guard() IS
  'RC-285: un escaneo ya creado solo cambia status, finished_at, stats y updated_at. La carta, el TXT, el dominio, la empresa, quién lo pidió y queued_at, que el trigger de la carta revisó en el INSERT, no cambian para ningún rol.';

DROP TRIGGER IF EXISTS scans_guard_bu ON public.scans;
CREATE TRIGGER scans_guard_bu BEFORE UPDATE ON public.scans
  FOR EACH ROW EXECUTE FUNCTION public.scans_guard();

COMMIT;
