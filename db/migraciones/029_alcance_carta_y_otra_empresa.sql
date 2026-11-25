SET client_encoding = 'UTF8';
-- =====================================================================
-- Cirdan · db/migraciones/029_alcance_carta_y_otra_empresa.sql (#26, RC-59)
--
-- 1. Un dominio que otra empresa ya verificó (verified o en pausa) no
--    se puede dar de alta ni verificar en otra. Varias empresas pueden
--    tenerlo pendiente: gana la primera que publica el TXT. Con RLS la
--    API no ve los dominios ajenos, así que lo revisa un trigger SECURITY
--    DEFINER. Avisa con unique_violation y la restricción
--    'domains_fqdn_otra_organizacion'. Un candado por fqdn ordena a dos
--    empresas que dan de alta o verifican el mismo nombre a la vez.
--
-- 2. domain_authorizations guarda el alcance de la carta: la versión de
--    la plantilla (docs/plantilla_carta_autorizacion.md) y las
--    actividades de su Anexo A que firmó la empresa (propuesta 10251).
--    cirdan/alcance_carta.py dice qué actividad usa cada fuente y el
--    orquestador salta las que la carta no autoriza.
--    Las dos columnas van juntas. NULL es una carta de antes de esta
--    migración: el orquestador no corre ninguna fuente con ella.
--    Regla de datos de las cartas que ya existen: la plantilla 1 es la
--    del Anexo A con las actividades 1 a 11, sin cambios desde el
--    18 oct 2026 (git log de la plantilla), así que toda carta firmada
--    hasta hoy queda con la versión 1 y las 11 actividades. Las semillas
--    corren después de las migraciones con el volumen vacío, por eso la
--    semilla 027 aplica la misma regla a sus cartas.
--    domain_authorizations es inmutable salvo revoked_at
--    (domain_authorizations_guard de la 001). Para llenar las cartas
--    viejas el guardia se apaga solo dentro de esta transacción.
-- =====================================================================

BEGIN;

-- 1. Dominio de otra empresa --------------------------------------------

CREATE FUNCTION public.domains_fqdn_otra_organizacion() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  IF NEW.status <> 'removed' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended(lower(NEW.fqdn::text), 59));
    IF EXISTS (SELECT 1 FROM public.domains d
                WHERE d.fqdn = NEW.fqdn
                  AND d.organization_id <> NEW.organization_id
                  AND d.status IN ('verified', 'paused')) THEN
      RAISE EXCEPTION 'el dominio ya está verificado por otra organización'
        USING ERRCODE = 'unique_violation', CONSTRAINT = 'domains_fqdn_otra_organizacion';
    END IF;
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION public.domains_fqdn_otra_organizacion() IS
  'RC-59: rechaza el alta o el cambio de un dominio si otra empresa ya tiene el mismo fqdn en verified o paused. SECURITY DEFINER porque domains tiene RLS forzado y la empresa que da de alta no ve los dominios ajenos. Toma pg_advisory_xact_lock(hashtextextended(lower(fqdn), 59)) para que dos empresas no lo pasen a la vez. Su search_path termina en pg_temp, como login_lookup().';

REVOKE ALL ON FUNCTION public.domains_fqdn_otra_organizacion() FROM PUBLIC;

CREATE TRIGGER domains_fqdn_otra_organizacion_iu
  BEFORE INSERT OR UPDATE OF fqdn, status, organization_id ON domains
  FOR EACH ROW EXECUTE FUNCTION public.domains_fqdn_otra_organizacion();

-- 2. Alcance de la carta ------------------------------------------------

ALTER TABLE domain_authorizations
  ADD COLUMN template_version smallint,
  ADD COLUMN activities smallint[],
  ADD CONSTRAINT domain_authorizations_alcance_juntos
    CHECK ((template_version IS NULL) = (activities IS NULL)),
  ADD CONSTRAINT domain_authorizations_plantilla_valida
    CHECK (template_version IS NULL OR template_version = 1),
  ADD CONSTRAINT domain_authorizations_actividades_validas
    CHECK (activities IS NULL OR (cardinality(activities) BETWEEN 1 AND 11
           AND array_position(activities, NULL) IS NULL
           AND activities <@ ARRAY[1,2,3,4,5,6,7,8,9,10,11]::smallint[]));

COMMENT ON COLUMN domain_authorizations.template_version IS
  'RC-59: versión de la plantilla de la carta que firmó la empresa. 1 = Anexo A con las actividades 1 a 11. NULL = carta de antes de la 029, sin alcance: el orquestador no corre ninguna fuente.';
COMMENT ON COLUMN domain_authorizations.activities IS
  'RC-59: actividades del Anexo A que autoriza la carta. cirdan/alcance_carta.py liga cada fuente a su actividad.';

ALTER TABLE domain_authorizations DISABLE TRIGGER domain_authorizations_guard_ud;
UPDATE domain_authorizations
   SET template_version = 1, activities = ARRAY[1,2,3,4,5,6,7,8,9,10,11]::smallint[]
 WHERE template_version IS NULL;
ALTER TABLE domain_authorizations ENABLE TRIGGER domain_authorizations_guard_ud;

COMMIT;
