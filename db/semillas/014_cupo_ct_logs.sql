-- =====================================================================
-- Cirdan · db/semillas/014_cupo_ct_logs.sql (RC-226, #109)
-- Sube el límite diario de la fuente ct_logs (cirdan/recolectores/crtsh.py)
-- porque desde #109 cada escaneo busca dominios parecidos en crt.sh. La
-- 005 no se edita: esta semilla cambia el límite que ella puso.
-- Necesita la migración 008 y la semilla 005.
--
-- ct_logs: 400 consultas por día. Antes una corrida reservaba a lo más 18
-- y con las 200 de la 005 cabían 11 corridas de peor caso. Ahora reserva
-- 36 (MAX_CONSULTAS de crtsh.py: las 2 búsquedas del dominio con 3
-- intentos, 4 páginas de Cert Spotter con 2 intentos y 11 búsquedas de
-- parecidos con 2 intentos) y con 200 solo cabían 5. Con 400 vuelven a
-- caber 11 corridas de peor caso. Un escaneo normal gasta 14 (la del
-- dominio, 2 de Cert Spotter, %marca% y 10 variantes) y el orquestador
-- ajusta la reserva a lo gastado, así que caben 27 escaneos en vivo por
-- día UTC en toda la plataforma (26 de 14 más la reserva de 36 del
-- último): el 28 deja ct_logs en 'failed' por cupo.
--
-- Se puede correr otra vez sin error: solo cambia la fila si tiene el 200
-- de la 005, así no pisa un límite puesto a mano. Si ese límite es menor
-- que 36 no cabe ninguna corrida y ct_logs queda 'failed' con 'Sin cupo
-- diario' en cada escaneo en vivo: la semilla lo avisa con un WARNING y
-- no lo cambia.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

UPDATE data_sources SET daily_limit = 400
 WHERE code = 'ct_logs' AND daily_limit = 200;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM data_sources WHERE code = 'ct_logs' AND daily_limit < 36) THEN
        RAISE WARNING 'ct_logs tiene un límite diario menor que 36, lo que reserva una corrida: no le cabe ninguna';
    END IF;
END $$;

COMMIT;
