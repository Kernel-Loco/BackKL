SET client_encoding = 'UTF8';
-- =====================================================================
-- Cirdan · db/semillas/027_alcance_cartas.sql (#26, RC-59)
-- Alcance de las cartas de las semillas 001, 002 y 015, que corren
-- después de la migración 029 cuando el volumen está vacío. Misma regla
-- que la 029: toda carta firmada hasta hoy es de la plantilla 1 y
-- autoriza las actividades 1 a 11 de su Anexo A.
-- Solo toca las cartas sin alcance, así que en una base que ya tiene la
-- 029 no cambia nada. domain_authorizations es inmutable salvo
-- revoked_at, por eso el guardia se apaga solo dentro de la transacción.
-- =====================================================================

BEGIN;

ALTER TABLE domain_authorizations DISABLE TRIGGER domain_authorizations_guard_ud;
UPDATE domain_authorizations
   SET template_version = 1, activities = ARRAY[1,2,3,4,5,6,7,8,9,10,11]::smallint[]
 WHERE template_version IS NULL;
ALTER TABLE domain_authorizations ENABLE TRIGGER domain_authorizations_guard_ud;

COMMIT;
