-- =====================================================================
-- Cirdan · db/migraciones/009_version_modelo_score.sql (#36, RC-61)
-- Registra qué versión ML produjo cada score y por qué se usaron reglas
-- cuando el modelo no estuvo disponible o no superó el baseline de #34.
-- Los scores históricos de rules permanecen con model_version NULL.
-- =====================================================================
BEGIN;

ALTER TABLE domain_scores
  ADD COLUMN model_version text,
  ADD COLUMN model_fallback_reason text,
  ADD CONSTRAINT domain_scores_model_version_ck CHECK (
    (method = 'rules' AND model_version IS NULL)
    OR (method = 'ml' AND model_version IS NOT NULL)
  );

COMMENT ON COLUMN domain_scores.model_version IS
  'Versión del clasificador que calculó el score; NULL cuando se usaron reglas.';
COMMENT ON COLUMN domain_scores.model_fallback_reason IS
  'Motivo por el que este escaneo usó reglas aunque hubiera integración ML disponible.';

COMMIT;
