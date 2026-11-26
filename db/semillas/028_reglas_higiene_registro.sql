-- =====================================================================
-- Cirdan · db/semillas/028_reglas_higiene_registro.sql (RC-221, #104)
-- Reglas 41 a 43 del juego v1: domain_transfer_unlocked y dnssec_missing
-- de whois (cirdan/recolectores/rdap.py) y dns_single_provider de dns
-- (cirdan/recolectores/registros_dns.py), las 3 de higiene del registro
-- del dominio. Necesita la migración 034, que trae sus textos y su mapeo.
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
-- En una base que ya existe se aplica a mano después de la migración 034 y antes
-- de reconstruir la API (ver db/README.md).
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

LOCK TABLE scoring_rule_sets IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO scoring_rules (id, rule_set_id, code, category, base_severity, weight, max_penalty) VALUES
 ('91000000-0000-4000-8000-000000000041','90000000-0000-4000-8000-000000000001','domain_transfer_unlocked',    'infrastructure',   'medium',   1.000, 10.00),
 ('91000000-0000-4000-8000-000000000042','90000000-0000-4000-8000-000000000001','dnssec_missing',              'infrastructure',   'low',      1.000,  8.00),
 ('91000000-0000-4000-8000-000000000043','90000000-0000-4000-8000-000000000001','dns_single_provider',         'infrastructure',   'low',      1.000,  8.00)
ON CONFLICT (rule_set_id, code) DO NOTHING;

-- Cada otro juego que ya existe, activo o no, con la misma regla de v1.
INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty)
SELECT s.id, r.code, r.category, r.base_severity, r.weight, r.max_penalty
  FROM scoring_rule_sets s
 CROSS JOIN scoring_rules r
 WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001'
   AND r.code IN ('domain_transfer_unlocked', 'dnssec_missing', 'dns_single_provider')
   AND s.id <> r.rule_set_id
ON CONFLICT (rule_set_id, code) DO NOTHING;

COMMIT;
