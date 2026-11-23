SET client_encoding = 'UTF8';
-- =====================================================================
-- Cirdan · db/migraciones/031_solicitudes_de_firma.sql (#26b, RC-211)
--
-- Firma de la carta de autorización con Mifiel desde el portal.
--
-- 1. signature_requests: una fila por carta que el Admin manda a firmar
--    con la API de Mifiel (camino B). Guarda el fqdn y no domain_id
--    porque el dominio puede nacer al confirmar la carta firmada, igual
--    que en el alta de RC-59. RLS ENABLE, FORCE y tenant_isolation.
--    Una sola abierta (creating, sent o signed) por empresa y fqdn.
-- 2. signature_requests_guard: INSERT solo en creating y sin resultados.
--    UPDATE solo con las transiciones de la tabla de abajo y solo en las
--    columnas que cada una puede cambiar. DELETE y TRUNCATE bloqueados:
--    la solicitud es evidencia de cómo se obtuvo la carta.
-- 3. domain_authorizations suma signature_request_id, signature_provider,
--    evidence_key (XML de Mifiel), evidence_sha256 y signed_at. Solo se
--    llenan en el INSERT: el guard de la 001 compara la fila completa
--    menos revoked_at. Las sirven el camino B (al confirmar una solicitud
--    firmada) y el A (PDF firmado y XML hechos en la web de Mifiel).
-- 4. domain_authorizations_from_request_bi: con signature_request_id,
--    la carta tiene que copiar tal cual lo que se firmó y venir de
--    producción: una firma del sandbox no tiene validez legal.
--
-- Solo crea y agrega columnas NULL: no cambia filas que ya existen.
-- Se revierte con DROP TABLE public.signature_requests CASCADE y
-- ALTER TABLE domain_authorizations DROP COLUMN de las 5 columnas.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

BEGIN;

-- 1. Solicitudes de firma -----------------------------------------------

CREATE TABLE IF NOT EXISTS public.signature_requests (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id       uuid NOT NULL REFERENCES public.organizations(id),
  provider              text NOT NULL CHECK (provider IN ('mifiel')),
  environment           text NOT NULL CHECK (environment IN ('sandbox', 'production')),
  fqdn                  citext NOT NULL CHECK (char_length(fqdn::text) BETWEEN 1 AND 253
                                               AND fqdn::text = lower(fqdn::text)),
  provider_document_id  text CHECK (char_length(provider_document_id) BETWEEN 1 AND 100),
  status                text NOT NULL DEFAULT 'creating'
                        CHECK (status IN ('creating', 'sent', 'signed', 'accepted', 'rejected',
                                          'cancelled', 'expired', 'failed')),
  signer_name           text NOT NULL CHECK (char_length(signer_name) BETWEEN 1 AND 200),
  signer_title          text NOT NULL CHECK (char_length(signer_title) BETWEEN 1 AND 200),
  signer_email          citext NOT NULL CHECK (char_length(signer_email::text) BETWEEN 3 AND 254),
  valid_from            date NOT NULL,
  valid_until           date NOT NULL,
  template_version      smallint NOT NULL CHECK (template_version = 1),
  activities            smallint[] NOT NULL
                        CHECK (cardinality(activities) BETWEEN 1 AND 11
                               AND array_position(activities, NULL) IS NULL
                               AND activities <@ ARRAY[1,2,3,4,5,6,7,8,9,10,11]::smallint[]),
  unsigned_document_key text NOT NULL,
  unsigned_sha256       bytea NOT NULL CHECK (octet_length(unsigned_sha256) = 32),
  signed_document_key   text,
  signed_sha256         bytea CHECK (octet_length(signed_sha256) = 32),
  evidence_key          text,
  evidence_sha256       bytea CHECK (octet_length(evidence_sha256) = 32),
  provider_signed_at    timestamptz,
  requested_by          uuid NOT NULL,
  decided_by            uuid,
  decided_at            timestamptz,
  last_checked_at       timestamptz,
  last_error            text CHECK (char_length(last_error) <= 200),
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  CHECK (valid_until > valid_from),
  CONSTRAINT signature_requests_resultados_juntos
    CHECK (num_nulls(signed_document_key, signed_sha256, evidence_key, evidence_sha256) IN (0, 4)),
  CONSTRAINT signature_requests_firmada_con_archivos
    CHECK (status NOT IN ('signed', 'accepted') OR signed_document_key IS NOT NULL),
  CONSTRAINT signature_requests_enviada_con_documento
    CHECK (status IN ('creating', 'failed') OR provider_document_id IS NOT NULL),
  CONSTRAINT signature_requests_decision_junta
    CHECK ((decided_by IS NULL) = (decided_at IS NULL)),
  UNIQUE (organization_id, id),
  UNIQUE (provider, environment, provider_document_id),
  FOREIGN KEY (organization_id, requested_by) REFERENCES public.users (organization_id, id),
  FOREIGN KEY (organization_id, decided_by)   REFERENCES public.users (organization_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS signature_requests_una_abierta_uq
  ON public.signature_requests (organization_id, fqdn) WHERE status IN ('creating', 'sent', 'signed');
CREATE INDEX IF NOT EXISTS signature_requests_org_created_idx
  ON public.signature_requests (organization_id, created_at DESC);

COMMENT ON TABLE public.signature_requests IS
  'RC-211: carta de autorización mandada a firmar con la API de Mifiel. El Admin la confirma y entonces nace la fila de domain_authorizations (y el dominio, si no existía). Inmutable salvo las transiciones de signature_requests_guard(). Nunca se borra.';
COMMENT ON COLUMN public.signature_requests.fqdn IS
  'Dominio de la carta, en minúsculas. No es FK: el dominio puede no existir hasta que se confirma la carta firmada.';
COMMENT ON COLUMN public.signature_requests.unsigned_document_key IS
  'Llave opaca de cirdan/cartas.py del PDF que se mandó a firmar. Cifrado con AES-GCM y AAD organization_id:id de esta solicitud:llave (no el domain_id, que puede no existir todavía). Lo mismo vale para signed_document_key y evidence_key.';
COMMENT ON COLUMN public.signature_requests.unsigned_sha256 IS
  'SHA-256 de los bytes exactos que se mandaron a Mifiel. Se compara con original_hash del documento antes de darla por firmada.';
COMMENT ON COLUMN public.signature_requests.evidence_key IS
  'XML de Mifiel: el archivo con validez legal, con la constancia NOM-151 dentro.';
COMMENT ON COLUMN public.signature_requests.last_error IS
  'Texto corto propio de la API. Nunca la respuesta de Mifiel, que trae nombres y correos.';

-- 2. Guard de transiciones ----------------------------------------------
-- De         A          Columnas que puede cambiar (además de updated_at)
-- creating   sent       provider_document_id (de NULL a valor), last_checked_at
-- creating   failed     last_error, last_checked_at
-- sent       sent       last_checked_at, last_error
-- sent       signed     signed_document_key, signed_sha256, evidence_key, evidence_sha256,
--                       provider_signed_at (de NULL a valor), last_checked_at, last_error
-- sent       rejected   last_checked_at, last_error
-- sent       expired    last_checked_at, last_error
-- sent       cancelled  decided_by, decided_at (de NULL a valor), last_checked_at, last_error
-- signed     cancelled  decided_by, decided_at (de NULL a valor)
-- signed     accepted   decided_by, decided_at (de NULL a valor), con su domain_authorizations
-- accepted, rejected, cancelled, expired y failed no cambian.

CREATE OR REPLACE FUNCTION public.signature_requests_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  libres text[];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'signature_requests no se borra' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'creating'
       OR num_nonnulls(NEW.provider_document_id, NEW.signed_document_key, NEW.signed_sha256, NEW.evidence_key,
                       NEW.evidence_sha256, NEW.provider_signed_at, NEW.decided_by, NEW.decided_at,
                       NEW.last_checked_at, NEW.last_error) > 0 THEN
      RAISE EXCEPTION 'signature_requests: una solicitud nueva empieza en creating y sin resultados'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  libres := CASE
    WHEN OLD.status = 'creating' AND NEW.status = 'sent'
         AND OLD.provider_document_id IS NULL AND NEW.provider_document_id IS NOT NULL
      THEN ARRAY['provider_document_id', 'last_checked_at']
    WHEN OLD.status = 'creating' AND NEW.status IN ('creating', 'failed')
      THEN ARRAY['last_error', 'last_checked_at']
    WHEN OLD.status = 'sent' AND NEW.status IN ('sent', 'rejected', 'expired')
      THEN ARRAY['last_checked_at', 'last_error']
    WHEN OLD.status = 'sent' AND NEW.status = 'signed'
         AND num_nulls(OLD.signed_document_key, OLD.signed_sha256, OLD.evidence_key, OLD.evidence_sha256,
                       OLD.provider_signed_at) = 5
      THEN ARRAY['signed_document_key', 'signed_sha256', 'evidence_key', 'evidence_sha256',
                 'provider_signed_at', 'last_checked_at', 'last_error']
    WHEN OLD.status = 'sent' AND NEW.status = 'cancelled' AND OLD.decided_by IS NULL
      THEN ARRAY['decided_by', 'decided_at', 'last_checked_at', 'last_error']
    WHEN OLD.status = 'signed' AND NEW.status IN ('cancelled', 'accepted') AND OLD.decided_by IS NULL
      THEN ARRAY['decided_by', 'decided_at']
  END;
  IF libres IS NULL
     OR (to_jsonb(NEW) - libres - 'status' - 'updated_at') <> (to_jsonb(OLD) - libres - 'status' - 'updated_at') THEN
    RAISE EXCEPTION 'signature_requests: cambio no permitido de % a %', OLD.status, NEW.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.status IN ('cancelled', 'accepted') AND NEW.decided_by IS NULL THEN
    RAISE EXCEPTION 'signature_requests: % pide quién lo decidió', NEW.status USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status = 'accepted' AND NOT EXISTS (
       SELECT 1 FROM public.domain_authorizations a
        WHERE a.organization_id = NEW.organization_id AND a.signature_request_id = NEW.id) THEN
    RAISE EXCEPTION 'signature_requests: accepted pide la carta en domain_authorizations'
      USING ERRCODE = 'check_violation';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;

COMMENT ON FUNCTION public.signature_requests_guard() IS
  'RC-211: transiciones permitidas de signature_requests (tabla en la 031). Corre como invocador: con RLS solo ve las cartas de la misma empresa.';

DROP TRIGGER IF EXISTS signature_requests_guard_iud ON public.signature_requests;
CREATE TRIGGER signature_requests_guard_iud BEFORE INSERT OR UPDATE OR DELETE ON public.signature_requests
  FOR EACH ROW EXECUTE FUNCTION public.signature_requests_guard();
DROP TRIGGER IF EXISTS signature_requests_block_trunc ON public.signature_requests;
CREATE TRIGGER signature_requests_block_trunc BEFORE TRUNCATE ON public.signature_requests
  FOR EACH STATEMENT EXECUTE FUNCTION block_mutation();

-- RLS y permisos --------------------------------------------------------

ALTER TABLE public.signature_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.signature_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON public.signature_requests;
CREATE POLICY tenant_isolation ON public.signature_requests
  USING (organization_id = app_current_org()) WITH CHECK (organization_id = app_current_org());

REVOKE ALL ON public.signature_requests FROM PUBLIC;
REVOKE ALL ON public.signature_requests FROM cirdan_app;
GRANT SELECT ON public.signature_requests TO cirdan_app;
GRANT INSERT (id, organization_id, provider, environment, fqdn, signer_name, signer_title, signer_email,
              valid_from, valid_until, template_version, activities, unsigned_document_key, unsigned_sha256,
              requested_by)
  ON public.signature_requests TO cirdan_app;
GRANT UPDATE (provider_document_id, status, signed_document_key, signed_sha256, evidence_key, evidence_sha256,
              provider_signed_at, decided_by, decided_at, last_checked_at, last_error, updated_at)
  ON public.signature_requests TO cirdan_app;

-- 3. Columnas nuevas de domain_authorizations ---------------------------

ALTER TABLE domain_authorizations
  ADD COLUMN IF NOT EXISTS signature_request_id uuid,
  ADD COLUMN IF NOT EXISTS signature_provider   text,
  ADD COLUMN IF NOT EXISTS evidence_key         text,
  ADD COLUMN IF NOT EXISTS evidence_sha256      bytea,
  ADD COLUMN IF NOT EXISTS signed_at            timestamptz;

ALTER TABLE domain_authorizations
  DROP CONSTRAINT IF EXISTS domain_authorizations_firma_valida,
  ADD CONSTRAINT domain_authorizations_firma_valida CHECK (
        (signature_provider IS NULL OR signature_provider = 'mifiel')
    AND (evidence_key IS NULL) = (evidence_sha256 IS NULL)
    AND (evidence_sha256 IS NULL OR octet_length(evidence_sha256) = 32)
    AND (signature_provider IS NULL) = (evidence_key IS NULL)
    AND (signature_request_id IS NULL OR signature_provider IS NOT NULL)
    AND (signed_at IS NULL OR signature_provider IS NOT NULL)),
  DROP CONSTRAINT IF EXISTS domain_authorizations_signature_request_fk,
  ADD CONSTRAINT domain_authorizations_signature_request_fk
    FOREIGN KEY (organization_id, signature_request_id)
    REFERENCES public.signature_requests (organization_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS domain_authorizations_signature_request_uq
  ON domain_authorizations (signature_request_id) WHERE signature_request_id IS NOT NULL;

COMMENT ON COLUMN domain_authorizations.signature_request_id IS
  'RC-211: solicitud de Mifiel de la que salió la carta (camino B). NULL si se subió a mano (RC-59) o en la web de Mifiel (camino A).';
COMMENT ON COLUMN domain_authorizations.signature_provider IS
  'RC-211: mifiel si la carta trae el XML de Mifiel. NULL = PDF subido a mano o de semilla.';
COMMENT ON COLUMN domain_authorizations.evidence_key IS
  'RC-211: llave opaca de cirdan/cartas.py del XML de Mifiel. Con solicitud, el AAD lleva el id de la solicitud. Sin ella, el domain_id.';
COMMENT ON COLUMN domain_authorizations.evidence_sha256 IS
  'RC-211: SHA-256 de los bytes exactos del XML de Mifiel.';
COMMENT ON COLUMN domain_authorizations.signed_at IS
  'RC-211: fecha de firma que reporta Mifiel. NULL si no la reportó o si se subió desde la web.';

-- 4. La carta copia lo que se firmó -------------------------------------

CREATE OR REPLACE FUNCTION public.domain_authorizations_from_request() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  r public.signature_requests%ROWTYPE;
  dominio citext;
BEGIN
  IF NEW.signature_request_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT * INTO r FROM public.signature_requests
   WHERE id = NEW.signature_request_id AND organization_id = NEW.organization_id;
  SELECT d.fqdn INTO dominio FROM public.domains d
   WHERE d.id = NEW.domain_id AND d.organization_id = NEW.organization_id;
  IF r.id IS NULL OR r.status <> 'signed' OR r.environment <> 'production'
     OR dominio IS DISTINCT FROM r.fqdn
     OR (NEW.signer_name, NEW.signer_title, NEW.signer_email, NEW.valid_from, NEW.valid_until,
         NEW.template_version, NEW.activities, NEW.signed_document_key, NEW.signed_document_sha256,
         NEW.evidence_key, NEW.evidence_sha256, NEW.signature_provider, NEW.signed_at)
        IS DISTINCT FROM
        (r.signer_name, r.signer_title, r.signer_email, r.valid_from, r.valid_until,
         r.template_version, r.activities, r.signed_document_key, r.signed_sha256,
         r.evidence_key, r.evidence_sha256, r.provider, r.provider_signed_at) THEN
    RAISE EXCEPTION 'domain_authorizations: la carta no coincide con la solicitud firmada'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION public.domain_authorizations_from_request() IS
  'RC-211: una carta ligada a una solicitud de firma exige la solicitud en signed, de producción (una firma del sandbox no tiene validez legal) y de la misma empresa, el mismo fqdn y los mismos datos, archivos y huellas. Corre como invocador y con RLS.';

DROP TRIGGER IF EXISTS domain_authorizations_from_request_bi ON domain_authorizations;
CREATE TRIGGER domain_authorizations_from_request_bi BEFORE INSERT ON domain_authorizations
  FOR EACH ROW EXECUTE FUNCTION public.domain_authorizations_from_request();

COMMIT;
