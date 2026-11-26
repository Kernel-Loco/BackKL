-- =====================================================================
-- 034 · Fuentes por cliente (#117, RC-235)
--
-- 1. org_source_settings: por empresa y fuente OSINT, si la empresa la apagó, quién la cambió y cuándo.
--    Sin fila, la fuente sigue lo que diga data_sources.enabled. Con fila, la fuente corre solo si está encendida
--    en data_sources y en la fila: la empresa solo puede apagar. Una fuente apagada en data_sources (censys,
--    subfinder) no se enciende para un cliente.
-- 2. Solo fuentes osint. Las de intel (nvd, first_epss, cisa_kev) son de la plataforma: un trigger rechaza la fila.
-- 3. Quien cambia es un admin de la empresa (changed_by, FK compuesta a users como las de la 001) o el superadmin de
--    la plataforma de RC-332 cuando actúa en otra empresa (changed_by_platform, FK simple a users). Uno de los dos.
-- 4. RLS con ENABLE, FORCE y tenant_isolation. cirdan_app lee, inserta y cambia enabled y quién y cuándo. Sin DELETE:
--    volver a encender deja la fila con enabled en true, que es lo mismo que no tenerla.
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS public.org_source_settings (
  organization_id     uuid NOT NULL REFERENCES public.organizations (id),
  source_id           uuid NOT NULL REFERENCES public.data_sources (id),
  enabled             boolean NOT NULL,
  changed_by          uuid,
  changed_by_platform uuid REFERENCES public.users (id),
  changed_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, source_id),
  CONSTRAINT org_source_settings_quien CHECK ((changed_by IS NULL) <> (changed_by_platform IS NULL)),
  CONSTRAINT org_source_settings_changed_by_fk FOREIGN KEY (organization_id, changed_by)
    REFERENCES public.users (organization_id, id)
);

COMMENT ON TABLE public.org_source_settings IS
  'Fuentes OSINT que una empresa apagó (#117, RC-235). Sin fila la fuente sigue data_sources.enabled. La empresa solo apaga: una fuente corre si está encendida en data_sources y aquí. Solo osint. cirdan_app lee, inserta y actualiza, sin DELETE.';

-- La fuente es osint. Corre con los permisos de quien escribe: cirdan_app puede leer data_sources.kind.
CREATE OR REPLACE FUNCTION public.org_source_settings_solo_osint() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.data_sources d WHERE d.id = NEW.source_id AND d.kind = 'osint') THEN
    RAISE EXCEPTION 'org_source_settings_solo_osint: solo se apagan por empresa las fuentes osint'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION public.org_source_settings_solo_osint() FROM PUBLIC;

DROP TRIGGER IF EXISTS org_source_settings_solo_osint ON public.org_source_settings;
CREATE TRIGGER org_source_settings_solo_osint BEFORE INSERT OR UPDATE OF source_id
  ON public.org_source_settings FOR EACH ROW EXECUTE FUNCTION public.org_source_settings_solo_osint();

ALTER TABLE public.org_source_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_source_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON public.org_source_settings;
CREATE POLICY tenant_isolation ON public.org_source_settings
  USING (organization_id = app_current_org()) WITH CHECK (organization_id = app_current_org());

REVOKE ALL ON public.org_source_settings FROM PUBLIC;
REVOKE ALL ON public.org_source_settings FROM cirdan_app;
GRANT SELECT, INSERT ON public.org_source_settings TO cirdan_app;
GRANT UPDATE (enabled, changed_by, changed_by_platform, changed_at) ON public.org_source_settings TO cirdan_app;

COMMIT;
