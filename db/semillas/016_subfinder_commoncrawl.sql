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
--       docs/servicios_externos.md). Desde el 15 nov subfinder.py ya no
--       corre el binario: pide el índice de Common Crawl directo.
--   (b) una grabación de olmardo.com, que no va en git: se hace en cada
--       PC o en la VM antes de aplicar esta semilla, si la demo corre en
--       reproducir. Sin ella subfinder sale 'succeeded' en reproducir con
--       el aviso de que no se revisó Common Crawl, y sin subdominios.
--   (c) que el contenedor escriba en respuestas_grabadas/subfinder/: el
--       Dockerfile le da esa carpeta, y solo esa, al usuario cirdan.
--
-- subfinder: 390 consultas por día. Desde esta semilla una consulta es una
-- petición HTTP, como en las demás fuentes: subfinder.py pide
-- collinfo.json y el CDX de cada uno de los 12 índices más recientes de
-- Common Crawl, y pide otra vez, hasta 2 veces, el CDX que da 500, 502 o
-- 504, con 12 reintentos en toda la corrida. Una corrida sin fallas hace
-- 13 y una de peor caso 25 (MAX_CONSULTAS de subfinder.py). El
-- orquestador reserva 25 antes de cada corrida y al terminar ajusta a las
-- que se hicieron: caben 29 corridas por día sin fallas (la 30 pide
-- 377 + 25 = 402 y queda sin cupo), 15 a la vez y 15 de peor caso. Un
-- escaneo con Common Crawl caído gasta a lo más 100 (4 corridas de 25).
-- Un índice sin capturas del dominio también es una petición.
--
-- Orden: primero se reconstruye la API con este código y después se
-- aplica la semilla. La imagen anterior corre el binario con las 8
-- fuentes de la 005 y, con subfinder prendido, las consultaría. En una
-- base nueva no hay paso a mano: db/init/cargar_cirdan.sh aplica todas
-- las semillas en cuanto el volumen está vacío y lee db/ del checkout, no
-- de la imagen. Por eso, después de un git pull, la base se levanta
-- siempre con `docker compose up -d --build`, nunca con `up` solo.
--
-- Se puede correr otra vez sin error: solo cambia el límite si tiene el
-- 400 de la 005, así no pisa uno puesto a mano. Si ese límite es menor
-- que 25 no cabe ninguna corrida: la semilla lo avisa con un WARNING y no
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

UPDATE data_sources SET daily_limit = 390
 WHERE code = 'subfinder' AND daily_limit = 400;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM data_sources WHERE code = 'subfinder' AND daily_limit < 25) THEN
        RAISE WARNING 'subfinder tiene un límite diario menor que 25, lo que reserva una corrida: no le cabe ninguna';
    END IF;
END $$;

COMMIT;
