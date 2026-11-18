-- =====================================================================
-- Cirdan · db/semillas/019_subfinder_apagado.sql (RC-337, con RC-184)
-- Apaga otra vez la fuente subfinder (cirdan/recolectores/subfinder.py),
-- que la semilla 017 prendió. La 017 no se edita: esta semilla cambia lo
-- que ella puso. Necesita la semilla 005: sin la fila de subfinder falla
-- sin cambiar nada.
--
-- Por qué: el CDX del índice de Common Crawl (index.commoncrawl.org), la
-- única fuente de subfinder, responde 504 casi siempre. Su nginx corta a
-- los ~10 s porque la cola del servidor del índice va llena, también en
-- la consulta más barata, desde la PC de una persona del equipo y desde
-- la VM, con una petición a la vez y 1 s entre ellas. En el escaneo en
-- vivo de olmardo.com del 17 nov fallaron 19 de las 24 peticiones al CDX
-- y el escaneo quedó 'partial' con 7 de 12 índices saltados. Más
-- reintentos no alcanzan dentro del tope de tiempo de la corrida y van
-- contra lo que pide Common Crawl (bajar el ritmo). Detalle en la
-- decisión 6 de docs/servicios_externos.md.
--
-- Apagada, el orquestador no la corre (solo corre las filas con enabled)
-- y un escaneo no queda 'partial' por ella. Los subdominios siguen
-- saliendo de ct_logs. El límite diario de 390 de la 017 no se toca, así
-- que para prenderla de nuevo basta con otra semilla que ponga
-- enabled = true, cuando haya otra ruta al índice que responda.
--
-- No importa el orden con la API: la imagen de la API no cambia con esta
-- semilla. En una base nueva db/init/cargar_cirdan.sh aplica la 005, la
-- 017 y esta, en ese orden, y la fuente queda apagada.
--
-- Se puede correr otra vez sin error: solo cambia la fila si está
-- prendida, y no toca ninguna otra columna ni otra fuente.
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

UPDATE data_sources SET enabled = false
 WHERE code = 'subfinder' AND enabled = true;

COMMIT;
