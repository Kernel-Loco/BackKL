-- =====================================================================
-- Cirdan · db/semillas/016_subfinder_commoncrawl.sql (RC-184, #14b)
-- Prende la fuente subfinder (cirdan/recolectores/subfinder.py), que la
-- semilla 005 sembró apagada, y le pone el límite diario de su única
-- fuente, commoncrawl. La 005 no se edita: esta semilla cambia lo que
-- ella puso. Necesita la migración 008 y la semilla 005: sin la fila de
-- subfinder falla sin cambiar nada.
--
-- La 005 pedía tres cosas para prenderla:
--   (a) los términos de las fuentes: el 15 nov se revisaron las 20 de
--       subfinder 2.17.0 y solo commoncrawl permite el uso automático y
--       mostrar sus datos a terceros (decisión 6 de
--       docs/servicios_externos.md). FUENTES_SUBFINDER queda solo con ella.
--   (b) una grabación de olmardo.com, que no va en git: se hace en cada
--       PC o en la VM antes de aplicar esta semilla, si la demo corre en
--       reproducir. Sin ella subfinder queda 'failed' en reproducir.
--   (c) que el contenedor escriba en respuestas_grabadas/: el Dockerfile
--       le da esa carpeta al usuario cirdan.
--
-- subfinder: 300 consultas por día, o sea 50 corridas por día, las mismas
-- que daba la 005. Desde esta semilla una consulta es una petición HTTP,
-- como en las demás fuentes: commoncrawl pide collinfo.json y un CDX por
-- cada uno de los últimos 5 años, así que una corrida hace a lo más 6
-- (MAX_CONSULTAS de subfinder.py) y el orquestador reserva 6. Si un año
-- no tiene capturas del dominio, commoncrawl deja de buscar y hace menos,
-- pero subfinder no dice cuántas, así que cada corrida cuenta 6.
--
-- Se puede correr otra vez sin error: solo cambia el límite si tiene el
-- 400 de la 005, así no pisa uno puesto a mano. Si ese límite es menor
-- que 6 no cabe ninguna corrida: la semilla lo avisa con un WARNING y no
-- lo cambia.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM data_sources WHERE code = 'subfinder') THEN
        RAISE EXCEPTION 'falta la fila de subfinder en data_sources: aplica antes la semilla 005';
    END IF;
END $$;

UPDATE data_sources SET enabled = true
 WHERE code = 'subfinder' AND enabled = false;

UPDATE data_sources SET daily_limit = 300
 WHERE code = 'subfinder' AND daily_limit = 400;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM data_sources WHERE code = 'subfinder' AND daily_limit < 6) THEN
        RAISE WARNING 'subfinder tiene un límite diario menor que 6, lo que reserva una corrida: no le cabe ninguna';
    END IF;
END $$;

COMMIT;
