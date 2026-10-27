-- =====================================================================
-- Cirdan · db/migraciones/006_firma_reglas_extras.sql (RC-66, #30)
-- Llena reviewed_by de las 5 reglas de #62 a #64, que revisa Ernesto
-- (decisión del 26 oct 2026, PR 56). Con eso quedan firmadas las 30
-- reglas del juego v1.
-- No cambia textos, la tabla, las reglas, los pesos ni los topes.
-- Un UPDATE por código con WHERE code = '...', como pide
-- docs/codigos_reglas.md. Nunca se edita la 003 ni la 005.
-- Corre en una sola transacción. Se puede correr otra vez sin error,
-- pero vuelve a mover updated_at. Después de una migración que vuelva a
-- cambiar o firmar estas filas, falla sin cambiar nada. Volver a correr
-- la 005 después de esta también falla sin cambiar nada, porque estas
-- filas ya no tienen el revisor que espera la 005.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

-- Las huellas que se revisan abajo son de los textos en UTF8, aunque
-- psql corra en una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

-- Nadie más escribe la tabla entre la revisión y los UPDATE. La API,
-- que solo lee, sigue funcionando.
LOCK TABLE scoring_rule_texts IN SHARE ROW EXCLUSIVE MODE;

-- Antes de cambiar nada revisa las 5 filas. Cada texto tiene que ser el
-- que dejó la 005, o el de la 003 en api_auth_not_declared, que la 005
-- no toca, y la fila no puede estar firmada por alguien que no es quien
-- la firma aquí. antes y despues son el md5 del título, qué significa y
-- qué hacer, separados por un salto de línea, con los bytes de una base
-- UTF8. Son iguales porque esta migración no cambia textos.
DO $$
DECLARE
  faltan text;
  distintos text;
BEGIN
  IF current_setting('server_encoding') <> 'UTF8' THEN
    RAISE EXCEPTION 'La 006 compara los textos en UTF8 y esta base usa %.', current_setting('server_encoding');
  END IF;
  SELECT string_agg(e.code, ', ') FILTER (WHERE t.code IS NULL),
         string_agg(e.code, ', ') FILTER (WHERE t.code IS NOT NULL AND (
           md5(t.title || E'\n' || t.meaning || E'\n' || t.recommendation) NOT IN (e.antes, e.despues)
           OR (t.reviewed_by IS NOT NULL AND t.reviewed_by IS DISTINCT FROM e.revisor)))
    INTO faltan, distintos
    FROM (VALUES
      ('public_bucket', '40ad96bf428a5ba3601c22fdebf2804b', '40ad96bf428a5ba3601c22fdebf2804b', 'ErnestoDL'),
      ('subdomain_takeover_risk', 'b688922c68a6897921bb55aa7fc81a9f', 'b688922c68a6897921bb55aa7fc81a9f', 'ErnestoDL'),
      ('exposed_api_docs', 'fa31331d086fa694706ff67158e2c175', 'fa31331d086fa694706ff67158e2c175', 'ErnestoDL'),
      ('api_auth_not_declared', 'c1e81de8f8d417dc2a3de59810a612b0', 'c1e81de8f8d417dc2a3de59810a612b0', 'ErnestoDL'),
      ('secret_in_container_image', '4f3a3b6ee76aa43037c9c6dc8f9aa088', '4f3a3b6ee76aa43037c9c6dc8f9aa088', 'ErnestoDL')
    ) AS e(code, antes, despues, revisor)
    LEFT JOIN scoring_rule_texts t ON t.code = e.code;
  IF faltan IS NOT NULL THEN
    RAISE EXCEPTION 'Faltan los textos de la migración 003 para: %. Aplica primero la 003 y la 005.', faltan;
  END IF;
  IF distintos IS NOT NULL THEN
    RAISE EXCEPTION 'Estos textos no son los que dejó la 005, o ya los firmó otra persona: %. Aplica primero la 005 o revísalos.', distintos;
  END IF;
END $$;

-- En orden de id de la regla, como la 003.
UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'public_bucket';

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'subdomain_takeover_risk';

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'exposed_api_docs';

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'api_auth_not_declared';

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'secret_in_container_image';

COMMIT;
