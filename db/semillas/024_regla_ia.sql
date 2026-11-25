-- =====================================================================
-- Cirdan · db/semillas/024_regla_ia.sql (#144, RC-262)
-- La regla exposed_ai_service de Shodan InternetDB
-- (cirdan/recolectores/shodan.py), en la categoría infrastructure, high,
-- con weight 1.000 y el tope de su severidad como las 23 reglas de la
-- 004: high 25.
-- Necesita la migración 023, que va ANTES que esta semilla: trae su texto
-- y su mapeo, y la FK de scoring_rules.code pide el texto.
--
-- 1. La regla en el juego v1 global (id 37 de docs/codigos_reglas.md).
-- 2. La misma en cada otro juego que ya existe, también los de una
--    organización (migración 013): un juego nuevo copia las reglas del
--    anterior, y sin esta un puerto de inteligencia artificial haría
--    fallar la fuente shodan entera de esa organización (contrato.validar).
-- Ningún score anterior cambia: ningún hallazgo guardado trae este código
-- (db/README.md, desviación 15).
-- Los hallazgos sí cambian en el siguiente escaneo: un exposed_service ya
-- guardado en uno de estos 8 puertos tiene otra huella (_huella de
-- shodan.py usa el código). En la siguiente corrida completa de shodan el
-- orquestador lo cierra como 'resolved' y abre un exposed_ai_service con
-- detected_at de ese día. Si el viejo estaba en accepted o false_positive
-- se queda así y el nuevo sale 'open': hay que marcarlo otra vez.
--
-- El LOCK pone en fila esta semilla y un PUT /scoring/weights que corra al
-- mismo tiempo: sin él, la API podría copiar el juego anterior antes del
-- COMMIT de la semilla y crear un juego nuevo que la copia del paso 2 no ve.
--
-- Se puede correr otra vez sin error: si la regla ya está en un juego no
-- la toca.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

LOCK TABLE scoring_rule_sets IN SHARE MODE;

INSERT INTO scoring_rules (id, rule_set_id, code, category, base_severity, weight, max_penalty) VALUES
 ('91000000-0000-4000-8000-000000000037','90000000-0000-4000-8000-000000000001','exposed_ai_service',          'infrastructure',   'high',     1.000, 25.00)
ON CONFLICT (rule_set_id, code) DO NOTHING;

INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty)
SELECT s.id, r.code, r.category, r.base_severity, r.weight, r.max_penalty
  FROM scoring_rule_sets s
  JOIN scoring_rules r ON r.rule_set_id = '90000000-0000-4000-8000-000000000001'
                      AND r.code = 'exposed_ai_service'
 WHERE s.id <> '90000000-0000-4000-8000-000000000001'
ON CONFLICT (rule_set_id, code) DO NOTHING;

COMMIT;
