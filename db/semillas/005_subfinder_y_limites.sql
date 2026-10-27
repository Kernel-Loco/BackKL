-- =====================================================================
-- Cirdan · db/semillas/005_subfinder_y_limites.sql (RC-184, #13b)
-- Fila de la fuente subfinder (cirdan/recolectores/subfinder.py) y límite
-- diario de ct_logs y subfinder. Necesita la migración 008, que trae
-- daily_limit: sin ella falla sin cambiar nada.
-- daily_limit cuenta consultas HTTP por día UTC de toda la plataforma, y
-- el orquestador reserva el máximo de una corrida (MAX_CONSULTAS del
-- recolector) antes de llamarla y ajusta a lo gastado al terminar.
--
-- ct_logs: 200 consultas por día. Cuidan el volumen total que la
-- plataforma le pide a crt.sh y a Cert Spotter en un día: una corrida
-- reserva a lo más 18 (MAX_CONSULTAS de crtsh.py, con sus reintentos), así
-- que en el peor caso caben 11 corridas, y unas 66 normales de 3
-- consultas. El límite por hora de Cert Spotter sin llave (unas 10) no lo
-- cuida este número: lo cubre su 429, que no se reintenta
-- (SIN_REINTENTO en cirdan/recolectores/certspotter.py).
-- subfinder: 400 consultas por día, o sea 50 corridas por día por las 8
-- fuentes de su lista blanca (FUENTES_SUBFINDER). Para subfinder una
-- consulta es una fuente consultada en una corrida, no una petición HTTP:
-- rapiddns y thc paginan y subfinder no lo deja ver sin -stats. Es un tope
-- prudente: se revisa con #8 (RC-40) cuando se revisen los términos de
-- cada fuente. Si la lista blanca cambia, el límite cambia con otra
-- semilla, no editando esta.
--
-- Se puede correr otra vez sin error: no repite la fila de subfinder y no
-- pisa un límite de ct_logs que alguien ya haya puesto.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

-- Recolector pasivo de subdominios (RC-184). keep_raw_payload igual que
-- ct_logs: el resumen de la corrida no trae credenciales ni datos de brechas.
-- Sembrada apagada (enabled = false), como censys en la semilla 001 ('en
-- evaluación'), para que la demo en reproducir no la muestre fallida. Se
-- prende con otra semilla cuando se cumplan las tres:
--   (a) #8 (RC-40) revisó los términos de las 8 fuentes de la lista blanca,
--   (b) hay una grabación de subfinder para olmardo.com, y
--   (c) el contenedor puede escribir en respuestas_grabadas/ (hoy no: el
--       Dockerfile copia cirdan/ como root).
INSERT INTO data_sources (id, code, kind, enabled, keep_raw_payload, rate_limit_per_min, daily_limit) VALUES
 ('50000000-0000-4000-8000-000000000011', 'subfinder', 'osint', false, true, NULL, 400)
ON CONFLICT (code) DO NOTHING;

UPDATE data_sources SET daily_limit = 200
 WHERE code = 'ct_logs' AND daily_limit IS NULL;

COMMIT;
