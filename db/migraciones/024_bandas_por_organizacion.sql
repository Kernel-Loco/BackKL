-- =====================================================================
-- Cirdan · db/migraciones/024_bandas_por_organizacion.sql (RC-237, #118)
-- Bandas de riesgo por cliente: cada juego de reglas guarda dónde empiezan
-- sus bandas medio, alto y crítico, junto con sus pesos (013). El bajo
-- siempre empieza en 0 y el crítico termina en 100.
-- - Los juegos que ya existen, el global y los de cada organización,
--   quedan con los cortes de hoy: 40, 60 y 80.
-- - Un juego nuevo que no manda sus cortes copia los del anterior: el de
--   la última versión de la misma organización o, si la organización aún
--   no tiene uno, el global activo. El primer juego global lleva 40, 60
--   y 80 (la semilla 001 corre después de las migraciones).
-- - El CHECK exige enteros en orden y al menos 10 valores enteros en cada
--   banda: bajo de 0 al corte medio menos 1, y así hasta crítico, del
--   corte crítico a 100 (por eso el crítico empieza a lo más en 91).
-- - cirdan_app sigue solo con UPDATE de is_active (013): los cortes de una
--   versión no cambian después de creada, así cada fila de domain_scores
--   se explica con los cortes de su rule_set_id.
-- La letra de RC-232 y el piso salen de estos cortes (cirdan/score/criterio.py).
-- =====================================================================
SET client_encoding = 'UTF8';
BEGIN;

ALTER TABLE scoring_rule_sets
  ADD COLUMN band_medium_from smallint,
  ADD COLUMN band_high_from smallint,
  ADD COLUMN band_critical_from smallint;

UPDATE scoring_rule_sets
   SET band_medium_from = 40, band_high_from = 60, band_critical_from = 80
 WHERE band_medium_from IS NULL;

ALTER TABLE scoring_rule_sets
  ALTER COLUMN band_medium_from SET NOT NULL,
  ALTER COLUMN band_high_from SET NOT NULL,
  ALTER COLUMN band_critical_from SET NOT NULL;

ALTER TABLE scoring_rule_sets
  ADD CONSTRAINT scoring_rule_sets_band_cutoffs_ck CHECK (
    band_medium_from >= 10
    AND band_high_from - band_medium_from >= 10
    AND band_critical_from - band_high_from >= 10
    AND band_critical_from <= 91
  );

-- Copia los cortes del juego anterior cuando el INSERT no trae ninguno. Si trae
-- solo una parte, no completa nada y el NOT NULL lo rechaza. Corre con los
-- permisos de quien inserta: con cirdan_app, la RLS de la 013 solo le deja ver
-- los juegos de su organización y el global.
CREATE OR REPLACE FUNCTION public.scoring_rule_sets_copiar_cortes() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  anterior record;
BEGIN
  IF NEW.band_medium_from IS NOT NULL OR NEW.band_high_from IS NOT NULL OR NEW.band_critical_from IS NOT NULL THEN
    RETURN NEW;
  END IF;
  SELECT s.band_medium_from, s.band_high_from, s.band_critical_from INTO anterior
    FROM public.scoring_rule_sets s
   WHERE s.organization_id IS NOT DISTINCT FROM NEW.organization_id
   ORDER BY s.version DESC
   LIMIT 1;
  IF NOT FOUND AND NEW.organization_id IS NOT NULL THEN
    SELECT s.band_medium_from, s.band_high_from, s.band_critical_from INTO anterior
      FROM public.scoring_rule_sets s
     WHERE s.organization_id IS NULL AND s.is_active
     LIMIT 1;
  END IF;
  IF FOUND THEN
    NEW.band_medium_from := anterior.band_medium_from;
    NEW.band_high_from := anterior.band_high_from;
    NEW.band_critical_from := anterior.band_critical_from;
  ELSE
    NEW.band_medium_from := 40;
    NEW.band_high_from := 60;
    NEW.band_critical_from := 80;
  END IF;
  RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION public.scoring_rule_sets_copiar_cortes() FROM PUBLIC;

DROP TRIGGER IF EXISTS scoring_rule_sets_copiar_cortes_bi ON public.scoring_rule_sets;
CREATE TRIGGER scoring_rule_sets_copiar_cortes_bi BEFORE INSERT ON public.scoring_rule_sets
  FOR EACH ROW EXECUTE FUNCTION public.scoring_rule_sets_copiar_cortes();

COMMENT ON COLUMN scoring_rule_sets.band_medium_from IS
  'Primer score de la banda medio de este juego (RC-237). El bajo va de 0 a este valor menos 1.';
COMMENT ON COLUMN scoring_rule_sets.band_high_from IS
  'Primer score de la banda alto de este juego (RC-237). Un hallazgo crítico vigente deja el dominio al menos aquí.';
COMMENT ON COLUMN scoring_rule_sets.band_critical_from IS
  'Primer score de la banda crítico de este juego (RC-237). Dos o más hallazgos críticos vigentes dejan el dominio al menos aquí.';

COMMIT;
