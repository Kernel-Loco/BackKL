-- =====================================================================
-- Cirdan · db/semillas/013_api_docs.sql (#63, RC-118)
-- Da de alta la fuente api_docs: la actividad 9 del Anexo A de la carta
-- (cirdan/recolectores/api_docs.py). Pide por https, solo con GET, una
-- lista fija de 10 rutas de documentación (Swagger y OpenAPI) en cada
-- sitio del dominio y cuenta, en el documento, las funciones que no
-- declaran autenticación. Nunca llama a las funciones documentadas.
-- Necesita la migración 008 (daily_limit) y la 015 (el tipo de activo
-- 'api_doc'), que va ANTES que esta semilla.
--
-- La fuente se siembra APAGADA (enabled = false). La actividad 9 es
-- nueva en el Anexo A y rige desde el 13 de noviembre de 2026, y una
-- actividad nueva se avisa a cada cliente con 5 días hábiles antes de
-- activarla (carta, cláusula del Anexo A). Se enciende con otra semilla
-- cuando ese aviso esté dado: mientras tanto ningún escaneo la corre.
--
-- api_docs: 2640 consultas por día. Una corrida reserva a lo más 264
-- (MAX_CONSULTAS de api_docs.py: 2 páginas de Cert Spotter con 2
-- intentos, 20 A con 3 intentos y 20 sitios con 10 rutas cada uno, sin
-- reintentos), así que en el peor caso caben 10 corridas por día, como
-- shodan y web.
-- keep_raw_payload = true: el resumen de la corrida no trae secretos (de
-- cada documento solo guarda formato, versión, título y conteos).
--
-- Se puede correr otra vez sin error: si la fila ya está no la toca.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO data_sources (id, code, kind, enabled, keep_raw_payload, rate_limit_per_min, daily_limit) VALUES
 ('50000000-0000-4000-8000-000000000014', 'api_docs', 'osint', false, true, NULL, 2640)
ON CONFLICT (code) DO NOTHING;

COMMIT;
