-- =====================================================================
-- Cirdan · db/semillas/023_regla_enlaces_nube_repos.sql (RC-247)
-- Regla 36 del juego v1: file_share_link_in_repo, un enlace para
-- compartir de Google Drive, OneDrive o SharePoint, o Dropbox, en un
-- repo público (cirdan/recolectores/github.py, #16).
-- Necesita la migración 022, que trae su texto y su mapeo.
--
-- Va en los juegos que ya existen y no en un juego nuevo
-- (db/README.md, desviación 15): ningún hallazgo guardado usa este
-- código, así que ningún score cambia, y el orquestador rechaza un
-- hallazgo cuyo código no está en el juego activo con que se escanea.
-- Primero v1 con su id fijo y luego, por copia de v1, cada otro juego
-- que ya existe, activo o no (el global de otra versión o el de una
-- organización, que la API crea al cambiar pesos), como la semilla 022
-- del saludo TLS. No toca otras reglas ni category_weights.
-- weight 1.000 y max_penalty 10.00, como toda regla medium nueva fuera
-- de digital_identity.
-- Se puede correr otra vez sin error y sin cambiar nada.
-- El LOCK espera a un cambio de pesos que esté en curso y frena los
-- nuevos hasta el COMMIT: así ningún juego se queda sin la regla por
-- copiarse de otro mientras esto corre.
-- En una base que ya existe se aplica a mano después de la 022 y antes
-- de reconstruir la API (ver db/README.md).
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

LOCK TABLE scoring_rule_sets IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO scoring_rules (id, rule_set_id, code, category, base_severity, weight, max_penalty) VALUES
 ('91000000-0000-4000-8000-000000000036','90000000-0000-4000-8000-000000000001','file_share_link_in_repo',     'data_leaks',       'medium',   1.000, 10.00)
ON CONFLICT (rule_set_id, code) DO NOTHING;

-- Cada otro juego que ya existe, activo o no, con la misma regla de v1.
INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty)
SELECT s.id, r.code, r.category, r.base_severity, r.weight, r.max_penalty
  FROM scoring_rule_sets s
 CROSS JOIN scoring_rules r
 WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001'
   AND r.code = 'file_share_link_in_repo'
   AND s.id <> r.rule_set_id
ON CONFLICT (rule_set_id, code) DO NOTHING;

COMMIT;
