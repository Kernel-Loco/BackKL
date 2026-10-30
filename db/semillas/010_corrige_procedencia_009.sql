-- =====================================================================
-- Cirdan · db/semillas/010_corrige_procedencia_009.sql (RC-72). Necesita la migración 010
-- La primera versión de la semilla 009 guardó los tres scores de Acme con
-- reason 'rules_change', model_fallback_reason 'artefacto_ml_no_disponible'
-- y computed_at '2026-10-28 16:21:57-06'. No hubo cambio de reglas, nadie
-- intentó usar el modelo y esa hora es un segundo después del merge del
-- PR 69 (068d7cd, 16:21:56), no la del cálculo. La 009 ya trae los datos
-- ciertos. Esta semilla corrige las tres filas en las bases que cargaron la
-- versión anterior.
--
-- domain_scores es de solo inserción, así que el trigger domain_scores_block_ud
-- se apaga solo dentro de esta transacción y solo para estas tres filas, con
-- los valores viejos exactos en el WHERE. Corre como postgres, dueño de la
-- tabla. El score, las notas y los aportes no cambian. Cada fila corregida
-- deja en audit_log lo que decía antes y lo que dice ahora. Es la desviación
-- 16 de db/README.md.
--
-- En una base nueva, o si ya se corrió, no encuentra filas y no hace nada.
-- Al final falla si alguna de las tres filas existe sin la corrección.
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

ALTER TABLE domain_scores DISABLE TRIGGER domain_scores_block_ud;

WITH corregidas AS (
  UPDATE domain_scores
     SET reason = 'correction',
         model_fallback_reason = NULL,
         computed_at = '2026-10-29 20:16:09-06'
   WHERE id IN ('a0000000-0000-4000-8000-000000000004',
                'a0000000-0000-4000-8000-000000000005',
                'a0000000-0000-4000-8000-000000000006')
     AND reason = 'rules_change'
     AND method = 'rules'
     AND model_fallback_reason = 'artefacto_ml_no_disponible'
     AND computed_at = '2026-10-28 16:21:57-06'
  RETURNING id, organization_id
)
INSERT INTO audit_log (organization_id, actor_type, action, entity_type, entity_id, details)
SELECT organization_id, 'system', 'score.corrected', 'domain_score', id,
       jsonb_build_object(
         'archivo', 'db/semillas/010_corrige_procedencia_009.sql',
         'antes', jsonb_build_object('reason', 'rules_change',
                                     'model_fallback_reason', 'artefacto_ml_no_disponible',
                                     'computed_at', '2026-10-28T16:21:57-06:00'),
         'despues', jsonb_build_object('reason', 'correction',
                                       'model_fallback_reason', NULL,
                                       'computed_at', '2026-10-29T20:16:09-06:00'))
  FROM corregidas
 ORDER BY id;

ALTER TABLE domain_scores ENABLE TRIGGER domain_scores_block_ud;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM domain_scores
              WHERE id IN ('a0000000-0000-4000-8000-000000000004',
                           'a0000000-0000-4000-8000-000000000005',
                           'a0000000-0000-4000-8000-000000000006')
                AND (reason <> 'correction' OR model_fallback_reason IS NOT NULL
                     OR computed_at <> '2026-10-29 20:16:09-06')) THEN
    RAISE EXCEPTION 'semilla 010: hay un score de Acme de la 009 sin corregir';
  END IF;
END $$;

COMMIT;
