-- =====================================================================
-- Cirdan · db/semillas/008_whois.sql (RC-166, #15b)
-- Límite diario de la fuente whois (cirdan/recolectores/rdap.py):
-- registrador, fechas y vencimiento del dominio por RDAP, con el servidor
-- que da el bootstrap de IANA. La fila ya existe en la semilla 001
-- (encendida y con keep_raw_payload), que no se edita: aquí solo se pone su
-- daily_limit. Necesita la migración 008, que trae daily_limit: sin ella
-- falla sin cambiar nada.
--
-- whois: 60 consultas por día. Una corrida reserva a lo más 6
-- (MAX_CONSULTAS de rdap.py: el bootstrap de IANA y el dominio, cada uno con
-- 3 intentos), así que en el peor caso caben 10 corridas por día, como
-- shodan. Si RDAP no responde, la fuente queda succeeded con el registro
-- 'No disponible' y domain_expiring_soon sin cobertura, así que el
-- orquestador no la reintenta ni gasta más cupo.
--
-- Se puede correr otra vez sin error: solo cambia la fila si todavía no
-- tiene límite, así no pisa uno que se haya puesto a mano.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

-- enabled y keep_raw_payload se quedan como los sembró la 001 (true y true).
-- El orquestador corre la fuente en cuanto 'whois' está en REGISTRO
-- (cirdan/recolectores/__init__.py), también en la demo con reproducir.
UPDATE data_sources SET daily_limit = 60 WHERE code = 'whois' AND daily_limit IS NULL;

COMMIT;
