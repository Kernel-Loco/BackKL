-- =====================================================================
-- Cirdan · db/semillas/006_github.sql (RC-50, #16)
-- Fila de la fuente github (cirdan/recolectores/github.py): secretos y
-- correos en los repos públicos de la organización de GitHub que la
-- empresa declaró (ORGS_GITHUB_DECLARADAS). Necesita la migración 008, que
-- trae daily_limit: sin ella falla sin cambiar nada.
--
-- github: 400 consultas por día. Una corrida reserva a lo más 16
-- (MAX_CONSULTAS de github.py: perfil y página de repos con sus 3 intentos
-- más 10 clones), así que en el peor caso caben 25 corridas por día. La
-- cuota de la API de GitHub sin token (60 por hora por IP) no la cuida este
-- número: lo cubre su 403 o 429, que no se reintenta y deja la fuente sin
-- cobertura en lugar de fallida.
--
-- Se puede correr otra vez sin error: no repite la fila de github.
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

-- Sembrada encendida (enabled = true): el escaneo solo corre las fuentes
-- con enabled, y un dominio sin organización declarada no consulta nada
-- (queda sin cobertura). El orquestador reserva las 16 antes de llamar al
-- recolector: si no caben en el límite del día, la fuente queda failed por
-- falta de cupo aunque el dominio no tenga organización declarada. keep_raw_payload = false: es una fuente de
-- secretos y el resumen de la corrida no se guarda (politica_uso_etico.md).
INSERT INTO data_sources (id, code, kind, enabled, keep_raw_payload, rate_limit_per_min, daily_limit) VALUES
 ('50000000-0000-4000-8000-000000000012', 'github', 'osint', true, false, NULL, 400)
ON CONFLICT (code) DO NOTHING;

COMMIT;
