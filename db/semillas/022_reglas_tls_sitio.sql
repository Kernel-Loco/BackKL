-- =====================================================================
-- Cirdan · db/semillas/022_reglas_tls_sitio.sql (RC-239, #121)
-- Reglas 34 y 35 del juego v1: tls_certificate_invalid y tls_legacy_only,
-- las 2 del saludo TLS de la visita web (cirdan/recolectores/visita.py).
-- Necesita la migración 021, que trae sus textos y su mapeo.
--
-- Van en los juegos que ya existen y no en un juego nuevo
-- (db/README.md, desviación 15): ningún hallazgo guardado usa estos
-- códigos, así que ningún score cambia, y el orquestador rechaza un
-- hallazgo cuyo código no está en el juego activo con que se escanea.
-- Primero v1 con sus ids fijos y luego, por copia de v1, cada otro
-- juego que ya existe, activo o no (el global de otra versión o el de
-- una organización, que la API crea al cambiar pesos), como la semilla
-- 020 de los contenedores. No toca otras reglas ni category_weights.
-- weight 1.000 y max_penalty 10.00, como toda regla medium nueva fuera
-- de digital_identity.
-- Se puede correr otra vez sin error y sin cambiar nada.
-- El LOCK espera a un cambio de pesos que esté en curso y frena los
-- nuevos hasta el COMMIT: así ningún juego se queda sin las 2
-- reglas por copiarse de otro mientras esto corre.
-- En una base que ya existe se aplica a mano después de la 021 y antes
-- de reconstruir la API (ver db/README.md).
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

LOCK TABLE scoring_rule_sets IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO scoring_rules (id, rule_set_id, code, category, base_severity, weight, max_penalty) VALUES
 ('91000000-0000-4000-8000-000000000034','90000000-0000-4000-8000-000000000001','tls_certificate_invalid',     'infrastructure',   'medium',   1.000, 10.00),
 ('91000000-0000-4000-8000-000000000035','90000000-0000-4000-8000-000000000001','tls_legacy_only',             'infrastructure',   'medium',   1.000, 10.00)
ON CONFLICT (rule_set_id, code) DO NOTHING;

-- Cada otro juego que ya existe, activo o no, con la misma regla de v1.
INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty)
SELECT s.id, r.code, r.category, r.base_severity, r.weight, r.max_penalty
  FROM scoring_rule_sets s
 CROSS JOIN scoring_rules r
 WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001'
   AND r.code IN ('tls_certificate_invalid', 'tls_legacy_only')
   AND s.id <> r.rule_set_id
ON CONFLICT (rule_set_id, code) DO NOTHING;

COMMIT;
