-- =====================================================================
-- Cirdan · db/semillas/007_shodan.sql (RC-49, #17)
-- Límite diario de la fuente shodan (cirdan/recolectores/shodan.py):
-- servicios y CVE que Shodan InternetDB ya vio en las IP públicas del
-- dominio. La fila ya existe en la semilla 001 (encendida y con
-- keep_raw_payload), que no se edita: aquí solo se pone su daily_limit.
-- Necesita la migración 008, que trae daily_limit: sin ella falla sin
-- cambiar nada.
--
-- shodan: 640 consultas por día. Una corrida reserva a lo más 64
-- (MAX_CONSULTAS de shodan.py: 2 páginas de Cert Spotter con 2 intentos,
-- 10 nombres con 3 intentos de su A y 10 IP con 3 intentos en InternetDB),
-- así que en el peor caso caben 10 corridas por día. InternetDB no publica
-- un límite: un 429 no se reintenta y deja la fuente sin cobertura en lugar
-- de fallida. Las páginas de Cert Spotter que pide shodan cuentan aquí y no
-- en el límite de ct_logs, pero gastan el mismo cupo por hora sin llave de
-- Cert Spotter, y cada reintento del orquestador (1, 5 y 25 min) las vuelve
-- a pedir (README.md, Recolector de Shodan, Cupo).
--
-- Se puede correr otra vez sin error: solo cambia la fila si todavía no
-- tiene límite, así no pisa uno que se haya puesto a mano.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

-- enabled y keep_raw_payload se quedan como los sembró la 001 (true y true).
-- El orquestador corre la fuente en cuanto 'shodan' está en REGISTRO
-- (cirdan/recolectores/__init__.py), también en la demo con reproducir.
UPDATE data_sources SET daily_limit = 640 WHERE code = 'shodan' AND daily_limit IS NULL;

COMMIT;
