-- =====================================================================
-- Cirdan · db/migraciones/010_motivo_correccion_score.sql (RC-72)
-- Agrega 'correction' a domain_scores.reason. Es el motivo de una fila que
-- corrige un score guardado mal, sin escaneo, sin cambio de reglas y sin
-- inteligencia nueva. La semilla 009 la usa para los scores de Acme que la
-- 001 escribió a mano. 'rules_change' queda para un juego de reglas nuevo
-- (backlog #32) e 'intel_update' para la carga diaria de CVE (#69).
-- Se puede correr otra vez sin error.
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

ALTER TABLE domain_scores DROP CONSTRAINT IF EXISTS domain_scores_reason_check;
ALTER TABLE domain_scores DROP CONSTRAINT IF EXISTS domain_scores_reason_ck;
ALTER TABLE domain_scores
  ADD CONSTRAINT domain_scores_reason_ck
  CHECK (reason IN ('scan', 'intel_update', 'rules_change', 'correction'));

COMMENT ON COLUMN domain_scores.reason IS
  'Por qué se calculó: scan (escaneo), intel_update (inteligencia nueva de un CVE), rules_change (juego de reglas nuevo) o correction (corrige un score guardado mal, migración 010).';

COMMIT;
