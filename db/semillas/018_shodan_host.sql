-- =====================================================================
-- Cirdan · db/semillas/018_shodan_host.sql (RC-337, con RC-220)
-- Sube el límite diario de la fuente shodan (cirdan/recolectores/shodan.py)
-- porque la corrida ahora también puede pedir la API de host de Shodan
-- (GET /shodan/host/{ip}) cuando SHODAN_API_KEY está puesta. La 011 no se
-- edita: esta semilla cambia el límite que ella puso.
-- Necesita la migración 008 y las semillas 007 y 011.
--
-- shodan: 2140 consultas por día. Una corrida reserva a lo más 214
-- (MAX_CONSULTAS de shodan.py: los 184 de la 011 más 10 IP con 3 intentos
-- en la API de host), así que en el peor caso siguen cabiendo 10 corridas
-- por día. Sin la llave la API de host no corre y la corrida gasta lo de
-- antes. El orquestador ajusta la reserva a lo gastado.
--
-- Este límite es del recolector, no del plan de Shodan
-- (docs/servicios_externos.md).
--
-- Se puede correr otra vez sin error: solo cambia la fila si no tiene
-- límite o si tiene el 1840 de la 011, así no pisa uno puesto a mano. Si
-- ese límite es menor que 214 no cabe ninguna corrida y shodan queda
-- 'failed' con 'Sin cupo diario' en cada escaneo en vivo: la semilla lo
-- avisa con un WARNING y no lo cambia. Sin esta semilla nada se rompe:
-- con el 1840 de la 011 caben 8 corridas del peor caso por día.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

UPDATE data_sources SET daily_limit = 2140
 WHERE code = 'shodan' AND (daily_limit IS NULL OR daily_limit = 1840);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM data_sources WHERE code = 'shodan' AND daily_limit < 214) THEN
        RAISE WARNING 'shodan tiene un límite diario menor que 214, lo que reserva una corrida: no le cabe ninguna';
    END IF;
END $$;

COMMIT;
