-- =====================================================================
-- Cirdan · db/semillas/009_score_demo_motor.sql (RC-72). Necesita la migración 010
-- La semilla 001 guardó a mano el score de los tres dominios de Acme (68,
-- 54 y 31) antes de que existiera el motor de score (#31, RC-60). Esos
-- números no salen de sus hallazgos: los cuatro abiertos de acme-demo.mx
-- dan 60 con el motor, y acme-tienda.mx y acme-portal.mx no tienen
-- hallazgos, así que dan 0. Por eso el plan de acción mostraba 'Actual 68'
-- junto a 'Score estimado: 16 (−44)'.
--
-- domain_scores y score_contributions no aceptan UPDATE ni DELETE (la única
-- excepción es la semilla 010, desviación 16 de db/README.md), y la 001 no se
-- edita. Aquí se agrega una fila nueva por dominio con reason
-- 'correction' (migración 010): no hubo escaneo, cambio de reglas ni
-- inteligencia nueva, solo se corrige un número que nadie calculó. Los
-- valores salen de motor.calcular con las reglas v1 y los hallazgos de la
-- 001, por reglas y sin ML, así que model_version y model_fallback_reason
-- van en NULL: nadie intentó usar el modelo. computed_at es la hora del
-- commit a6c7fc8 (PR 80), que guardó este cálculo. Los scores de
-- septiembre quedan en el histórico.
--
-- La primera versión de esta semilla decía 'rules_change', 'artefacto_ml_no_disponible'
-- y '2026-10-28 16:21:57-06', y nada de eso pasó. La semilla 010 corrige
-- esas filas en las bases que ya la cargaron.
--
-- Se puede correr otra vez sin error: no repite filas.
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO domain_scores (id, organization_id, domain_id, scan_id, rule_set_id, score, category_scores, reason, method, model_fallback_reason, partial_coverage, computed_at) VALUES
 ('a0000000-0000-4000-8000-000000000004','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',
  '60000000-0000-4000-8000-000000000001','90000000-0000-4000-8000-000000000001', 60,
  '{"infrastructure": 45.0, "digital_identity": 0.0, "configuration": 10.0, "data_leaks": 40.0}','correction','rules',NULL,false,'2026-10-29 20:16:09-06'),
 ('a0000000-0000-4000-8000-000000000005','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000002',
  '60000000-0000-4000-8000-000000000002','90000000-0000-4000-8000-000000000001', 0,
  '{"infrastructure": 0.0, "digital_identity": 0.0, "configuration": 0.0, "data_leaks": 0.0}','correction','rules',NULL,false,'2026-10-29 20:16:09-06'),
 ('a0000000-0000-4000-8000-000000000006','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000003',
  '60000000-0000-4000-8000-000000000003','90000000-0000-4000-8000-000000000001', 0,
  '{"infrastructure": 0.0, "digital_identity": 0.0, "configuration": 0.0, "data_leaks": 0.0}','correction','rules',NULL,false,'2026-10-29 20:16:09-06')
ON CONFLICT DO NOTHING;

-- Un aporte por hallazgo abierto de acme-demo.mx, con los factores que arma el motor.
INSERT INTO score_contributions (id, organization_id, score_id, finding_id, rule_id, penalty, severity, factors) VALUES
 ('a1000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','a0000000-0000-4000-8000-000000000004',
  '80000000-0000-4000-8000-000000000001','91000000-0000-4000-8000-000000000001', 40.00, 'critical',
  '{"rules": [{"label": "Severidad 100 x peso 1 (tope 40)", "points": 40.0}], "severity_points": 100, "rule_weight": 1.0, "uncapped_penalty": 100.0, "max_penalty": 40.0}'),
 ('a1000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001','a0000000-0000-4000-8000-000000000004',
  '80000000-0000-4000-8000-000000000002','91000000-0000-4000-8000-000000000002', 20.00, 'high',
  '{"rules": [{"label": "Severidad 75 x peso 0.4 (tope 20)", "points": 20.0}], "severity_points": 75, "rule_weight": 0.4, "uncapped_penalty": 30.0, "max_penalty": 20.0}'),
 ('a1000000-0000-4000-8000-000000000004','20000000-0000-4000-8000-000000000001','a0000000-0000-4000-8000-000000000004',
  '80000000-0000-4000-8000-000000000003','91000000-0000-4000-8000-000000000003', 25.00, 'high',
  '{"rules": [{"label": "Severidad 75 x peso 0.4 (tope 25)", "points": 25.0}], "severity_points": 75, "rule_weight": 0.4, "uncapped_penalty": 30.0, "max_penalty": 25.0}'),
 ('a1000000-0000-4000-8000-000000000005','20000000-0000-4000-8000-000000000001','a0000000-0000-4000-8000-000000000004',
  '80000000-0000-4000-8000-000000000004','91000000-0000-4000-8000-000000000005', 10.00, 'medium',
  '{"rules": [{"label": "Severidad 50 x peso 0.5 (tope 10)", "points": 10.0}], "severity_points": 50, "rule_weight": 0.5, "uncapped_penalty": 25.0, "max_penalty": 10.0}')
ON CONFLICT DO NOTHING;

COMMIT;
