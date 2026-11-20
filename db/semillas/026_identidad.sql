-- =====================================================================
-- Cirdan · db/semillas/026_identidad.sql (#20, RC-56)
-- Da de alta la fuente identity: la identidad pasiva
-- (cirdan/recolectores/identidad.py). Lee la portada de cada sitio del
-- dominio (actividad 6 del Anexo A de la carta, la misma visita de la
-- fuente web), los correos del certificado de ese mismo saludo TLS, los
-- commits de la organización de GitHub declarada y el correo público de
-- los perfiles de GitHub enlazados desde el sitio, por la API sin token.
-- Nunca entra a cuentas ni navega con sesión.
-- Necesita la migración 028, que va ANTES que esta semilla: la fuente
-- queda encendida y sin el tipo 'profile' en el CHECK un escaneo que
-- encuentra un perfil queda failed.
--
-- identity: 1710 consultas por día. Una corrida reserva a lo más 171
-- (MAX_CONSULTAS de identidad.py: 2 páginas de Cert Spotter con 2
-- intentos, 20 A con 3 intentos, 20 sitios con la página y hasta 3
-- redirecciones, y 9 peticiones a la API de GitHub con 3 intentos: la
-- lista de repos, 5 páginas de commits y 3 perfiles), así que en el peor
-- caso caben 10 corridas por día, como web.
-- keep_raw_payload = false: el resumen de la corrida trae los correos
-- del dominio.
--
-- Se puede correr otra vez sin error: si la fila ya está no la toca.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO data_sources (id, code, kind, enabled, keep_raw_payload, rate_limit_per_min, daily_limit) VALUES
 ('50000000-0000-4000-8000-000000000015', 'identity', 'osint', true, false, NULL, 1710)
ON CONFLICT (code) DO NOTHING;

COMMIT;
