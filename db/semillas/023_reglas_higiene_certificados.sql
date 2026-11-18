-- =====================================================================
-- Cirdan · db/semillas/023_reglas_higiene_certificados.sql (RC-218, #14)
-- Reglas 36 a 38 del juego v1: cert_internal_name, cert_broad_wildcard y
-- cert_new_issuer, las 3 de higiene de certificados de ct_logs
-- (cirdan/recolectores/crtsh.py). Necesita la migración 022, que trae
-- sus textos y su mapeo.
--
-- Van en los juegos que ya existen y no en un juego nuevo
-- (db/README.md, desviación 15): ningún hallazgo guardado usa estos
-- códigos, así que ningún score cambia, y el orquestador rechaza un
-- hallazgo cuyo código no está en el juego activo con que se escanea.
-- Primero v1 con sus ids fijos y luego, por copia de v1, cada otro
-- juego que ya existe, activo o no (el global de otra versión o el de
-- una organización, que la API crea al cambiar pesos), como la semilla
-- 022 del saludo TLS. No toca otras reglas ni category_weights.
-- weight 1.000 con max_penalty 8.00 en las low y 10.00 en la medium,
-- como toda regla nueva fuera de digital_identity.
-- Se puede correr otra vez sin error y sin cambiar nada.
-- El LOCK espera a un cambio de pesos que esté en curso y frena los
-- nuevos hasta el COMMIT: así ningún juego se queda sin las 3
-- reglas por copiarse de otro mientras esto corre.
-- En una base que ya existe se aplica a mano después de la 022 y antes
-- de reconstruir la API (ver db/README.md).
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

LOCK TABLE scoring_rule_sets IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO scoring_rules (id, rule_set_id, code, category, base_severity, weight, max_penalty) VALUES
 ('91000000-0000-4000-8000-000000000036','90000000-0000-4000-8000-000000000001','cert_internal_name',          'infrastructure',   'low',      1.000,  8.00),
 ('91000000-0000-4000-8000-000000000037','90000000-0000-4000-8000-000000000001','cert_broad_wildcard',         'infrastructure',   'low',      1.000,  8.00),
 ('91000000-0000-4000-8000-000000000038','90000000-0000-4000-8000-000000000001','cert_new_issuer',             'infrastructure',   'medium',   1.000, 10.00)
ON CONFLICT (rule_set_id, code) DO NOTHING;

-- Cada otro juego que ya existe, activo o no, con la misma regla de v1.
INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty)
SELECT s.id, r.code, r.category, r.base_severity, r.weight, r.max_penalty
  FROM scoring_rule_sets s
 CROSS JOIN scoring_rules r
 WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001'
   AND r.code IN ('cert_internal_name', 'cert_broad_wildcard', 'cert_new_issuer')
   AND s.id <> r.rule_set_id
ON CONFLICT (rule_set_id, code) DO NOTHING;

COMMIT;
