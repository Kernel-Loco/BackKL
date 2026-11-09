-- =====================================================================
-- Cirdan · db/semillas/012_visita_web.sql (#18, RC-46)
-- Da de alta la fuente web: la visita de la actividad 6 del Anexo A de la
-- carta (cirdan/recolectores/visita.py). Pide la página principal de cada
-- sitio del dominio por https y saca sus tecnologías, la versión sin
-- soporte con endoflife.date y las CVE con la NVD.
-- Necesita la migración 008 (daily_limit) y, para guardar las CVE con su
-- CVSS, la 014.
--
-- web: 1840 consultas por día. Una corrida reserva a lo más 184
-- (MAX_CONSULTAS de visita.py: 2 páginas de Cert Spotter con 2 intentos,
-- 20 A con 3 intentos, 20 sitios con la página y hasta 3 redirecciones,
-- 10 productos de endoflife.date y 10 CPE de la NVD con 2 intentos cada
-- uno), así que en el peor caso caben 10 corridas por día, como shodan.
-- keep_raw_payload = true: el resumen de la corrida no trae secretos (de
-- las cookies solo guarda el nombre).
--
-- Se puede correr otra vez sin error: si la fila ya está no la toca.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO data_sources (id, code, kind, enabled, keep_raw_payload, rate_limit_per_min, daily_limit) VALUES
 ('50000000-0000-4000-8000-000000000013', 'web', 'osint', true, true, NULL, 1840)
ON CONFLICT (code) DO NOTHING;

COMMIT;
