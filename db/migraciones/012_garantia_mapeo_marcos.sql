-- =====================================================================
-- Cirdan · db/migraciones/012_garantia_mapeo_marcos.sql (#68, RC-131)
-- Arreglos a scoring_rule_framework_mappings, que creó la 011. La 011 ya
-- entró a dev y no se edita.
-- 1. FK de scoring_rule_texts.code a scoring_rule_framework_mappings.
--    La 011 revisó una sola vez, al aplicarse, que todo texto tuviera su
--    mapeo. Con esta FK la base lo exige siempre: un texto nuevo (y, por
--    la FK de la 003, una regla nueva) no entra sin su mapeo, y un mapeo
--    no se borra mientras su texto exista. Sin ella, un hallazgo de una
--    regla sin mapeo hace que la API responda 500 en toda la lista de
--    hallazgos del dominio (_marcos en cirdan/api/v1.py).
--    Es DEFERRABLE INITIALLY DEFERRED porque la FK de la 011 va al revés
--    (del mapeo al texto): la migración que agregue una regla inserta el
--    texto y el mapeo en la misma transacción, en ese orden, y esta FK se
--    revisa en el COMMIT. Para borrar una regla, en una sola transacción
--    se borra la regla, después el mapeo y al final el texto.
-- 2. created_at y updated_at en el mapeo, como en las demás tablas
--    (convención 10 de db/README.md). En las 30 filas de la 011 quedan con
--    la hora en que se aplica esta migración, no con la de la 011.
-- Necesita la 011. No agrega tablas, índices, triggers ni políticas:
-- solo una FK (60 en total).
-- Corre en una sola transacción y se puede correr otra vez sin error.
-- En una base que ya existe se aplica a mano, antes de reconstruir la API
-- (ver db/README.md).
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

DO $$
DECLARE
  faltantes text[];
BEGIN
  IF to_regclass('public.scoring_rule_framework_mappings') IS NULL THEN
    RAISE EXCEPTION 'Falta la migración 011: no existe scoring_rule_framework_mappings';
  END IF;
  SELECT array_agg(t.code ORDER BY t.code)
    INTO faltantes
    FROM scoring_rule_texts t
    LEFT JOIN scoring_rule_framework_mappings m ON m.rule_code = t.code
   WHERE m.rule_code IS NULL;
  IF faltantes IS NOT NULL THEN
    RAISE EXCEPTION 'Faltan mapeos a marcos para reglas: %', faltantes;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'scoring_rule_texts_mapping_fk'
                    AND conrelid = 'public.scoring_rule_texts'::regclass) THEN
    ALTER TABLE scoring_rule_texts
      ADD CONSTRAINT scoring_rule_texts_mapping_fk FOREIGN KEY (code)
      REFERENCES scoring_rule_framework_mappings (rule_code)
      DEFERRABLE INITIALLY DEFERRED;
  END IF;
END $$;

COMMENT ON CONSTRAINT scoring_rule_texts_mapping_fk ON scoring_rule_texts IS
  'Todo texto (y toda regla) tiene su mapeo a marcos (migración 012). Se revisa en el COMMIT: el texto y su mapeo entran en la misma transacción.';

ALTER TABLE scoring_rule_framework_mappings
  ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

COMMENT ON COLUMN scoring_rule_framework_mappings.created_at IS
  'Cuándo entró el mapeo. En las 30 filas de la 011 es la hora en que se aplicó la 012.';
COMMENT ON COLUMN scoring_rule_framework_mappings.updated_at IS
  'Cuándo cambió el mapeo por última vez. La migración que lo corrija pone updated_at = now().';

COMMIT;
