-- =====================================================================
-- Cirdan · db/semillas/020_reglas_portada.sql (#111, RC-228)
-- Las reglas directory_listing y debug_page_exposed de la portada de la
-- visita web (cirdan/recolectores/portada.py), en la categoría
-- configuration, con weight 1.000 y el tope de su severidad como las 23
-- reglas de la 004: medium 10 y high 25.
-- Necesita la migración 019, que va ANTES que esta semilla: trae sus
-- textos y su mapeo, y la FK de scoring_rules.code pide el texto.
--
-- 1. Las dos reglas en el juego v1 global (ids 31 y 32 de
--    docs/codigos_reglas.md).
-- 2. Las mismas dos en cada otro juego que ya existe, también los de una
--    organización (migración 013): un juego nuevo copia las reglas del
--    anterior, y sin estas un hallazgo de la portada haría fallar la
--    fuente web entera de esa organización (contrato.validar).
-- Ningún score anterior cambia: ningún hallazgo guardado trae estos
-- códigos (db/README.md, desviación 15).
--
-- Se puede correr otra vez sin error: si la regla ya está en un juego no
-- la toca.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

-- Un juego que la API crea mientras corre esta semilla (PUT /api/v1/scoring/weights copia las
-- reglas del anterior) espera al COMMIT y ya copia las dos reglas, como en la 006.
LOCK TABLE scoring_rule_sets IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO scoring_rules (id, rule_set_id, code, category, base_severity, weight, max_penalty) VALUES
 ('91000000-0000-4000-8000-000000000031','90000000-0000-4000-8000-000000000001','directory_listing',           'configuration',    'medium',   1.000, 10.00),
 ('91000000-0000-4000-8000-000000000032','90000000-0000-4000-8000-000000000001','debug_page_exposed',          'configuration',    'high',     1.000, 25.00)
ON CONFLICT (rule_set_id, code) DO NOTHING;

INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty)
SELECT s.id, r.code, r.category, r.base_severity, r.weight, r.max_penalty
  FROM scoring_rule_sets s
  JOIN scoring_rules r ON r.rule_set_id = '90000000-0000-4000-8000-000000000001'
                      AND r.code IN ('directory_listing', 'debug_page_exposed')
 WHERE s.id <> '90000000-0000-4000-8000-000000000001'
ON CONFLICT (rule_set_id, code) DO NOTHING;

COMMIT;
