-- =====================================================================
-- Cirdan · db/semillas/011_shodan_nombres.sql (RC-55, #23)
-- Sube el límite diario de la fuente shodan (cirdan/recolectores/shodan.py)
-- porque MAX_NOMBRES pasó de 10 a 50. Con más nombres de los que se
-- resuelven no se saben todas las IP del dominio y la corrida queda
-- parcial sin sin_revisar, así que un dominio con más de 10 nombres nunca
-- cerraba lo de una IP que ya no es suya. La 007 no se edita: esta
-- semilla cambia el límite que ella puso.
-- Necesita la migración 008 y la semilla 007.
--
-- shodan: 1840 consultas por día. Una corrida reserva a lo más 184
-- (MAX_CONSULTAS de shodan.py: 2 páginas de Cert Spotter con 2 intentos,
-- 50 nombres con 3 intentos de su A y 10 IP con 3 intentos en InternetDB),
-- así que en el peor caso siguen cabiendo 10 corridas por día, como con
-- la 007. Las IP que se consultan en InternetDB siguen en 10 por corrida:
-- lo que sube es el número de A. Una corrida normal gasta mucho menos y
-- el orquestador ajusta la reserva a lo gastado, así que con el límite
-- nuevo caben más corridas reales por día y pueden subir las consultas
-- a InternetDB, que no publica un límite.
--
-- Se puede correr otra vez sin error: solo cambia la fila si no tiene
-- límite o si tiene el 640 de la 007, así no pisa uno puesto a mano. Si
-- ese límite es menor que 184 no cabe ninguna corrida y shodan queda
-- 'failed' con 'Sin cupo diario' en cada escaneo en vivo: la semilla lo
-- avisa con un WARNING y no lo cambia.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

UPDATE data_sources SET daily_limit = 1840
 WHERE code = 'shodan' AND (daily_limit IS NULL OR daily_limit = 640);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM data_sources WHERE code = 'shodan' AND daily_limit < 184) THEN
        RAISE WARNING 'shodan tiene un límite diario menor que 184, lo que reserva una corrida: no le cabe ninguna';
    END IF;
END $$;

COMMIT;
