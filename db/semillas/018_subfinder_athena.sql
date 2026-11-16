-- =====================================================================
-- Cirdan · db/semillas/018_subfinder_athena.sql (RC-184, #14b)
-- Baja el límite diario de subfinder de 390 a 100 porque desde esta
-- semilla subfinder.py ya no pide el CDX de index.commoncrawl.org (13
-- peticiones por corrida, hasta 25) sino una consulta de Amazon Athena
-- sobre el URL Index columnar de Common Crawl, en la cuenta de AWS de
-- LowTide (us-east-1, workgroup CC_ATHENA_WORKGROUP). La 017 no se edita:
-- esta semilla cambia lo que ella puso. Necesita la semilla 017.
--
-- Una consulta del límite es una StartQueryExecution, lo que cobra
-- Athena. Una corrida pide a lo más 3 (MAX_CONSULTAS de subfinder.py): el
-- ALTER TABLE que agrega las particiones de un crawl nuevo (DDL, Athena no
-- lo cobra), el SELECT y un reintento si Athena falla por su lado. Lo
-- normal es 1, o 2 el día que sale un crawl nuevo. El orquestador reserva
-- 3 antes de cada corrida y al terminar ajusta a las que se hicieron:
-- caben 33 corridas de peor caso por día y 98 de una consulta (la 99
-- pide 98 + 3 = 101 y queda sin cupo).
--
-- Costo: el workgroup corta toda consulta que lea más de 1 GB (0.005 USD
-- a 5 USD el TB), y subfinder.py no consulta si el workgroup no tiene ese
-- tope. 100 consultas son a lo más 0.50 USD al día. Una consulta podada
-- por url_surtkey lee unos MB.
--
-- Orden: primero se reconstruye la API con este código y después se
-- aplica la semilla. En una base nueva no hay paso a mano:
-- db/init/cargar_cirdan.sh aplica todas las semillas con el volumen
-- vacío.
--
-- Se puede correr otra vez sin error: solo cambia el límite si tiene el
-- 390 de la 017, así no pisa uno puesto a mano. Si ese límite es menor
-- que 3 no cabe ninguna corrida: la semilla lo avisa con un WARNING y no
-- lo cambia.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM data_sources WHERE code = 'subfinder') THEN
        RAISE EXCEPTION 'falta la fila de subfinder en data_sources: aplica antes las semillas 005 y 017';
    END IF;
END $$;

UPDATE data_sources SET daily_limit = 100
 WHERE code = 'subfinder' AND daily_limit = 390;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM data_sources WHERE code = 'subfinder' AND daily_limit < 3) THEN
        RAISE WARNING 'subfinder tiene un límite diario menor que 3, lo que reserva una corrida: no le cabe ninguna';
    END IF;
END $$;

COMMIT;
