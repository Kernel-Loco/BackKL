-- =====================================================================
-- Cirdan · db/migraciones/007_comentario_revisor.sql (RC-66, #30)
-- Corrige el comentario de scoring_rule_texts.reviewed_by que puso la
-- 003. Desde el 26 oct 2026 (PR 56 y migración 006) los textos que no
-- son de OSINT los revisa alguien de otra área o Ernesto, como dicen
-- db/cirdan_esquema.dbml y docs/codigos_reglas.md.
-- Solo cambia el comentario de la columna. No cambia datos, textos,
-- reglas, pesos ni permisos. Nunca se edita la 003.
-- Se puede correr otra vez sin error y deja el mismo comentario.
-- Falla sin cambiar nada si falta la tabla de la 003.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

-- El comentario lleva acentos y se guarda en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

COMMENT ON COLUMN scoring_rule_texts.reviewed_by IS 'Quién revisó el texto (en las reglas OSINT, Ernesto, y en el resto alguien de otra área o Ernesto). NULL mientras no se revise.';

COMMIT;
