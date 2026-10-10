-- =====================================================================
-- Cirdan (Kernel Loco · reto IKUSI VELATIA) · db/migraciones/001_esquema_inicial.sql
-- Traducción a PostgreSQL 16 del modelo lógico cirdan_esquema.dbml:
-- 23 tablas en 7 grupos, 57 FK (las de tenant son compuestas), RLS con
-- ENABLE + FORCE en las 18 tablas por cliente, triggers de inmutabilidad,
-- cadena de hashes en audit_log, autorización forzada en scans y
-- keep_raw_payload en scan_source_runs.
-- Enumerados como text + CHECK (no CREATE TYPE), PK uuid.
-- Desviaciones respecto al DBML: ver db/README.md.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Rol de la aplicación: no es superusuario, no es dueño de las tablas y no
-- tiene BYPASSRLS, así que las políticas siempre le aplican.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cirdan_app') THEN
    CREATE ROLE cirdan_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

-- Tenant actual. El NULLIF es obligatorio: tras un SET/RESET la variable
-- queda en '' y ''::uuid fallaría con 22P02 en vez de devolver vacío.
CREATE FUNCTION app_current_org() RETURNS uuid
LANGUAGE sql STABLE AS
$$ SELECT NULLIF(current_setting('app.current_org', true), '')::uuid $$;

-- ===================== clientes_y_acceso =====================

CREATE TABLE plans (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code              text NOT NULL UNIQUE CHECK (code IN ('starter','business','enterprise')),
  max_domains       smallint NOT NULL CHECK (max_domains > 0),
  scan_interval     interval NOT NULL,
  on_demand_scans   boolean NOT NULL,
  api_and_siem      boolean NOT NULL,
  monthly_price_mxn numeric(10,2) NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organizations (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name                  text NOT NULL,
  plan_id               uuid NOT NULL REFERENCES plans(id),
  status                text NOT NULL CHECK (status IN ('trial','active','suspended','cancelled')),
  domain_limit_override smallint,
  alert_score_threshold smallint NOT NULL DEFAULT 60 CHECK (alert_score_threshold BETWEEN 0 AND 100),
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  email           citext NOT NULL UNIQUE,
  full_name       text NOT NULL,
  role            text NOT NULL CHECK (role IN ('analyst','manager','admin')),
  password_hash   text NOT NULL,
  totp_secret_enc bytea,
  mfa_enabled_at  timestamptz,
  last_totp_step  bigint,
  is_active       boolean NOT NULL DEFAULT true,
  last_login_at   timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id)
);

-- ===================== dominios_y_autorizacion =====================

CREATE TABLE domains (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  fqdn            citext NOT NULL,
  status          text NOT NULL CHECK (status IN ('pending_verification','verified','paused','removed')),
  txt_token       text NOT NULL UNIQUE,
  verified_at     timestamptz,
  next_scan_at    timestamptz,
  last_scan_at    timestamptz,
  added_by        uuid,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, fqdn),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, added_by) REFERENCES users (organization_id, id)
);
CREATE UNIQUE INDEX domains_fqdn_verified_uq ON domains (fqdn) WHERE status = 'verified';
CREATE INDEX domains_next_scan_idx ON domains (next_scan_at) WHERE status = 'verified';

CREATE TABLE api_keys (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  domain_id       uuid,
  name            text NOT NULL,
  key_prefix      text NOT NULL UNIQUE,
  key_hash        bytea NOT NULL UNIQUE,
  scopes          text[] NOT NULL,
  created_by      uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  last_used_at    timestamptz,
  revoked_at      timestamptz,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at <= created_at + interval '90 days'),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, domain_id)  REFERENCES domains (organization_id, id),
  FOREIGN KEY (organization_id, created_by) REFERENCES users (organization_id, id)
);

CREATE TABLE domain_authorizations (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id        uuid NOT NULL REFERENCES organizations(id),
  domain_id              uuid NOT NULL,
  signer_name            text NOT NULL,
  signer_title           text NOT NULL,
  signer_email           citext NOT NULL,
  signed_document_key    text NOT NULL,
  signed_document_sha256 bytea NOT NULL,
  valid_from             date NOT NULL,
  valid_until            date NOT NULL,
  revoked_at             timestamptz,
  accepted_by            uuid NOT NULL,
  created_at             timestamptz NOT NULL DEFAULT now(),
  CHECK (valid_until > valid_from),
  UNIQUE (organization_id, domain_id, id),
  FOREIGN KEY (organization_id, domain_id)   REFERENCES domains (organization_id, id),
  FOREIGN KEY (organization_id, accepted_by) REFERENCES users (organization_id, id)
);
CREATE INDEX domain_authorizations_valid_until_idx ON domain_authorizations (valid_until) WHERE revoked_at IS NULL;

CREATE TABLE dns_txt_verifications (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  domain_id       uuid NOT NULL,
  check_reason    text NOT NULL CHECK (check_reason IN ('onboarding','daily','pre_scan')),
  expected_value  text NOT NULL,
  observed_values text[],
  resolver_ip     inet NOT NULL,
  result          text NOT NULL CHECK (result IN ('match','missing','mismatch','dns_error')),
  checked_at      timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, domain_id, id),
  FOREIGN KEY (organization_id, domain_id) REFERENCES domains (organization_id, id)
);
CREATE INDEX dns_txt_verifications_domain_checked_idx ON dns_txt_verifications (domain_id, checked_at DESC);

-- ===================== escaneos_e_ingesta =====================

CREATE TABLE data_sources (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code               text NOT NULL UNIQUE,
  kind               text NOT NULL CHECK (kind IN ('osint','intel')),
  enabled            boolean NOT NULL,
  keep_raw_payload   boolean NOT NULL,
  api_key_enc        bytea,
  key_rotated_at     timestamptz,
  rate_limit_per_min smallint,
  last_success_at    timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scans (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id     uuid NOT NULL REFERENCES organizations(id),
  domain_id           uuid NOT NULL,
  authorization_id    uuid NOT NULL,
  txt_verification_id uuid NOT NULL,
  trigger_type        text NOT NULL CHECK (trigger_type IN ('scheduled','on_demand','api')),
  requested_by        uuid,
  status              text NOT NULL CHECK (status IN ('queued','running','completed','partial','failed')),
  queued_at           timestamptz NOT NULL DEFAULT now(),
  finished_at         timestamptz,
  stats               jsonb,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, domain_id) REFERENCES domains (organization_id, id),
  FOREIGN KEY (organization_id, domain_id, authorization_id)
    REFERENCES domain_authorizations (organization_id, domain_id, id),
  FOREIGN KEY (organization_id, domain_id, txt_verification_id)
    REFERENCES dns_txt_verifications (organization_id, domain_id, id),
  FOREIGN KEY (organization_id, requested_by) REFERENCES users (organization_id, id)
);
CREATE UNIQUE INDEX scans_one_active_per_domain_uq ON scans (domain_id) WHERE status IN ('queued','running');
CREATE INDEX scans_org_domain_idx ON scans (organization_id, domain_id, queued_at DESC);

CREATE TABLE scan_source_runs (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  scan_id         uuid NOT NULL,
  source_id       uuid NOT NULL REFERENCES data_sources(id),
  status          text NOT NULL CHECK (status IN ('pending','running','succeeded','retrying','failed')),
  attempt         smallint NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 3),
  next_retry_at   timestamptz,
  raw_payload     jsonb,
  error           text,
  finished_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, source_id),
  FOREIGN KEY (organization_id, scan_id) REFERENCES scans (organization_id, id)
);
CREATE INDEX scan_source_runs_retry_idx ON scan_source_runs (next_retry_at) WHERE status = 'retrying';

-- ===================== activos_y_hallazgos =====================

CREATE TABLE assets (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  domain_id       uuid NOT NULL,
  parent_asset_id uuid,
  asset_type      text NOT NULL CHECK (asset_type IN ('domain','subdomain','ip','service','certificate','email')),
  value           text NOT NULL,
  ip_address      inet,
  attributes      jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at   timestamptz NOT NULL,
  last_seen_at    timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (domain_id, asset_type, value),
  UNIQUE (organization_id, domain_id, id),
  FOREIGN KEY (organization_id, domain_id) REFERENCES domains (organization_id, id),
  FOREIGN KEY (organization_id, domain_id, parent_asset_id) REFERENCES assets (organization_id, domain_id, id)
);

-- ===================== inteligencia_y_score (catálogos) =====================

CREATE TABLE cves (
  cve_id           text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  description      text,
  cvss_base_score  numeric(3,1) CHECK (cvss_base_score BETWEEN 0 AND 10),
  cvss_vector      text,
  epss_score       numeric(6,5),
  epss_percentile  numeric(6,5),
  in_kev           boolean NOT NULL DEFAULT false,
  kev_date_added   date,
  published_at     timestamptz,
  intel_updated_at timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cves_in_kev_idx ON cves (cve_id) WHERE in_kev;

CREATE TABLE scoring_rule_sets (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  version          smallint NOT NULL UNIQUE,
  category_weights jsonb NOT NULL,
  is_active        boolean NOT NULL,
  validated_by     text,
  activated_at     timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX scoring_rule_sets_one_active_uq ON scoring_rule_sets ((true)) WHERE is_active;

CREATE TABLE scoring_rules (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_set_id   uuid NOT NULL REFERENCES scoring_rule_sets(id),
  code          text NOT NULL,
  category      text NOT NULL CHECK (category IN ('infrastructure','digital_identity','configuration','data_leaks')),
  base_severity text NOT NULL CHECK (base_severity IN ('critical','high','medium','low')),
  weight        numeric(4,3) NOT NULL,
  max_penalty   numeric(5,2) NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (rule_set_id, code)
);

-- ===================== activos_y_hallazgos (cont.) =====================

CREATE TABLE findings (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  domain_id       uuid NOT NULL,
  asset_id        uuid NOT NULL,
  rule_id         uuid NOT NULL REFERENCES scoring_rules(id),
  cve_id          text REFERENCES cves(cve_id),
  source_id       uuid NOT NULL REFERENCES data_sources(id),
  fingerprint     bytea NOT NULL,
  severity        text NOT NULL CHECK (severity IN ('critical','high','medium','low')),
  status          text NOT NULL CHECK (status IN ('open','resolved','accepted_risk','false_positive')),
  evidence        jsonb NOT NULL,
  detected_at     timestamptz NOT NULL,
  last_scan_id    uuid,
  resolved_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, fingerprint),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, domain_id) REFERENCES domains (organization_id, id),
  FOREIGN KEY (organization_id, domain_id, asset_id) REFERENCES assets (organization_id, domain_id, id),
  FOREIGN KEY (organization_id, last_scan_id) REFERENCES scans (organization_id, id)
    ON DELETE SET NULL (last_scan_id)
);
CREATE INDEX findings_org_domain_status_sev_idx ON findings (organization_id, domain_id, status, severity);
CREATE INDEX findings_open_cve_idx ON findings (cve_id) WHERE status = 'open';

CREATE TABLE breach_exposures (
  finding_id      uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  breach_name     text NOT NULL,
  breach_date     date,
  data_classes    text[] NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, finding_id) REFERENCES findings (organization_id, id)
);

-- ===================== inteligencia_y_score (por cliente) =====================

CREATE TABLE domain_scores (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id),
  domain_id        uuid NOT NULL,
  scan_id          uuid NOT NULL,
  rule_set_id      uuid NOT NULL REFERENCES scoring_rule_sets(id),
  score            smallint NOT NULL CHECK (score BETWEEN 0 AND 100),
  category_scores  jsonb NOT NULL,
  reason           text NOT NULL CHECK (reason IN ('scan','intel_update','rules_change')),
  method           text NOT NULL DEFAULT 'rules' CHECK (method IN ('rules','ml')),
  partial_coverage boolean NOT NULL DEFAULT false,
  computed_at      timestamptz NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, domain_id) REFERENCES domains (organization_id, id),
  FOREIGN KEY (organization_id, scan_id)   REFERENCES scans (organization_id, id)
);
CREATE INDEX domain_scores_org_domain_computed_idx ON domain_scores (organization_id, domain_id, computed_at DESC);

CREATE TABLE score_contributions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  score_id        uuid NOT NULL,
  finding_id      uuid NOT NULL,
  rule_id         uuid NOT NULL REFERENCES scoring_rules(id),
  penalty         numeric(5,2) NOT NULL,
  severity        text NOT NULL CHECK (severity IN ('critical','high','medium','low')),
  factors         jsonb NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (score_id, finding_id),
  FOREIGN KEY (organization_id, score_id)   REFERENCES domain_scores (organization_id, id),
  FOREIGN KEY (organization_id, finding_id) REFERENCES findings (organization_id, id)
);

-- ===================== entrega_e_integraciones =====================

CREATE TABLE integrations (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id   uuid NOT NULL REFERENCES organizations(id),
  kind              text NOT NULL CHECK (kind IN ('webhook','siem_cef','email')),
  name              text NOT NULL,
  endpoint          text NOT NULL,
  secret_enc        bytea,
  secret_rotated_at timestamptz,
  config            jsonb NOT NULL DEFAULT '{}'::jsonb,
  enabled           boolean NOT NULL DEFAULT true,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id)
);

CREATE TABLE alerts (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  domain_id       uuid NOT NULL,
  event_type      text NOT NULL CHECK (event_type IN ('finding.created','finding.resolved','score.above_threshold','authorization.expiring','scan.partial')),
  finding_id      uuid,
  score_id        uuid,
  severity        text NOT NULL CHECK (severity IN ('critical','high','medium','low')),
  payload         jsonb NOT NULL,
  detected_at     timestamptz NOT NULL,
  acknowledged_by uuid,
  acknowledged_at timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CHECK ((event_type LIKE 'finding.%') = (finding_id IS NOT NULL)),
  CHECK ((event_type = 'score.above_threshold') = (score_id IS NOT NULL)),
  CHECK ((acknowledged_by IS NULL) = (acknowledged_at IS NULL)),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, domain_id)       REFERENCES domains (organization_id, id),
  FOREIGN KEY (organization_id, finding_id)      REFERENCES findings (organization_id, id),
  FOREIGN KEY (organization_id, score_id)        REFERENCES domain_scores (organization_id, id),
  FOREIGN KEY (organization_id, acknowledged_by) REFERENCES users (organization_id, id)
);
CREATE INDEX alerts_org_detected_idx ON alerts (organization_id, detected_at DESC);

CREATE TABLE reports (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  domain_id       uuid,
  kind            text NOT NULL CHECK (kind IN ('pdf_report','weekly_summary')),
  period_start    date NOT NULL,
  period_end      date NOT NULL,
  status          text NOT NULL CHECK (status IN ('queued','ready','failed')),
  generated_at    timestamptz,
  storage_key     text,
  file_sha256     bytea,
  requested_by    uuid,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, domain_id)    REFERENCES domains (organization_id, id),
  FOREIGN KEY (organization_id, requested_by) REFERENCES users (organization_id, id)
);

CREATE TABLE deliveries (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  integration_id  uuid NOT NULL,
  alert_id        uuid,
  report_id       uuid,
  status          text NOT NULL CHECK (status IN ('pending','retrying','delivered','dead')),
  attempt         smallint NOT NULL DEFAULT 0,
  next_attempt_at timestamptz,
  message_id      text NOT NULL UNIQUE,
  response_status smallint,
  last_error      text,
  detected_at     timestamptz NOT NULL,
  delivered_at    timestamptz,
  latency_ms      integer GENERATED ALWAYS AS
                    ((extract(epoch FROM (delivered_at - detected_at)) * 1000)::integer) STORED,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CHECK (num_nonnulls(alert_id, report_id) = 1),
  UNIQUE (integration_id, alert_id),
  UNIQUE (integration_id, report_id),
  FOREIGN KEY (organization_id, integration_id) REFERENCES integrations (organization_id, id),
  FOREIGN KEY (organization_id, alert_id)       REFERENCES alerts (organization_id, id),
  FOREIGN KEY (organization_id, report_id)      REFERENCES reports (organization_id, id)
);
CREATE INDEX deliveries_next_attempt_idx ON deliveries (next_attempt_at) WHERE status IN ('pending','retrying');

-- ===================== auditoria =====================

CREATE TABLE audit_log (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid REFERENCES organizations(id),
  chain_seq        bigint NOT NULL,
  actor_type       text NOT NULL CHECK (actor_type IN ('user','api_key','system')),
  actor_user_id    uuid,
  actor_api_key_id uuid,
  action           text NOT NULL,
  entity_type      text,
  entity_id        uuid,
  ip_address       inet,
  details          jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
  prev_hash        bytea NOT NULL,
  row_hash         bytea NOT NULL UNIQUE,
  created_at       timestamptz NOT NULL DEFAULT now(),
  CHECK (organization_id IS NOT NULL OR (actor_user_id IS NULL AND actor_api_key_id IS NULL)),
  UNIQUE NULLS NOT DISTINCT (organization_id, chain_seq),
  FOREIGN KEY (organization_id, actor_user_id)    REFERENCES users (organization_id, id),
  FOREIGN KEY (organization_id, actor_api_key_id) REFERENCES api_keys (organization_id, id)
);

-- =====================================================================
-- Triggers
-- =====================================================================

-- Cadena de hashes por organización (organization_id NULL = cadena de plataforma).
CREATE FUNCTION audit_log_chain() RETURNS trigger
LANGUAGE plpgsql SET TimeZone = 'UTC' AS $$
DECLARE
  v_seq  bigint;
  v_prev bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(coalesce(NEW.organization_id::text, 'platform'), 0));
  SELECT chain_seq, row_hash INTO v_seq, v_prev
    FROM audit_log
   WHERE organization_id IS NOT DISTINCT FROM NEW.organization_id
   ORDER BY chain_seq DESC LIMIT 1;
  NEW.chain_seq := coalesce(v_seq, 0) + 1;
  NEW.prev_hash := coalesce(v_prev, decode(repeat('00', 32), 'hex'));
  NEW.row_hash  := sha256(NEW.prev_hash || convert_to(concat_ws(chr(31),
                     coalesce(NEW.organization_id::text, ''), NEW.chain_seq::text, NEW.id::text,
                     (extract(epoch FROM NEW.occurred_at) * 1000000)::bigint::text,
                     NEW.actor_type, coalesce(NEW.actor_user_id::text, ''), coalesce(NEW.actor_api_key_id::text, ''),
                     NEW.action, coalesce(NEW.entity_type, ''), coalesce(NEW.entity_id::text, ''),
                     NEW.details::text), 'UTF8'));
  RETURN NEW;
END $$;
CREATE TRIGGER audit_log_chain_bi BEFORE INSERT ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_chain();

-- Inmutabilidad: bloquea UPDATE, DELETE y TRUNCATE para todos (también superusuario).
CREATE FUNCTION block_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  -- Excepción de retención: solo DELETE, solo cirdan_retention, solo filas de más de 12 meses.
  IF TG_OP = 'DELETE' AND current_user = 'cirdan_retention' THEN
    IF TG_TABLE_NAME = 'domain_scores' AND OLD.computed_at < now() - interval '12 months' THEN
      RETURN OLD;
    ELSIF TG_TABLE_NAME = 'score_contributions' AND EXISTS (
            SELECT 1 FROM domain_scores s
             WHERE s.id = OLD.score_id AND s.computed_at < now() - interval '12 months') THEN
      RETURN OLD;
    END IF;
  END IF;
  RAISE EXCEPTION '% es de solo inserción: % bloqueado por trigger', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER audit_log_block_ud BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION block_mutation();
CREATE TRIGGER audit_log_block_trunc BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION block_mutation();
CREATE TRIGGER dns_txt_verifications_block_ud BEFORE UPDATE OR DELETE ON dns_txt_verifications
  FOR EACH ROW EXECUTE FUNCTION block_mutation();
CREATE TRIGGER dns_txt_verifications_block_trunc BEFORE TRUNCATE ON dns_txt_verifications
  FOR EACH STATEMENT EXECUTE FUNCTION block_mutation();
CREATE TRIGGER domain_scores_block_ud BEFORE UPDATE OR DELETE ON domain_scores
  FOR EACH ROW EXECUTE FUNCTION block_mutation();
CREATE TRIGGER domain_scores_block_trunc BEFORE TRUNCATE ON domain_scores
  FOR EACH STATEMENT EXECUTE FUNCTION block_mutation();
CREATE TRIGGER score_contributions_block_ud BEFORE UPDATE OR DELETE ON score_contributions
  FOR EACH ROW EXECUTE FUNCTION block_mutation();
CREATE TRIGGER score_contributions_block_trunc BEFORE TRUNCATE ON score_contributions
  FOR EACH STATEMENT EXECUTE FUNCTION block_mutation();

-- domain_authorizations: inmutable salvo UPDATE de revoked_at.
CREATE FUNCTION domain_authorizations_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND (to_jsonb(NEW) - 'revoked_at') = (to_jsonb(OLD) - 'revoked_at') THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'domain_authorizations es inmutable (solo se puede fijar revoked_at): % bloqueado', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER domain_authorizations_guard_ud BEFORE UPDATE OR DELETE ON domain_authorizations
  FOR EACH ROW EXECUTE FUNCTION domain_authorizations_guard();
CREATE TRIGGER domain_authorizations_block_trunc BEFORE TRUNCATE ON domain_authorizations
  FOR EACH STATEMENT EXECUTE FUNCTION block_mutation();

-- Autorización forzada: no se escanea sin autorización vigente y TXT 'match' de la última hora.
CREATE FUNCTION scans_require_authorization() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  a domain_authorizations%ROWTYPE;
  t dns_txt_verifications%ROWTYPE;
BEGIN
  SELECT * INTO a FROM domain_authorizations WHERE id = NEW.authorization_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'escaneo bloqueado: la autorización no existe' USING ERRCODE = 'check_violation';
  END IF;
  IF a.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'escaneo bloqueado: la autorización fue revocada el %', a.revoked_at USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.queued_at::date NOT BETWEEN a.valid_from AND a.valid_until THEN
    RAISE EXCEPTION 'escaneo bloqueado: autorización fuera de vigencia (% a %)', a.valid_from, a.valid_until
      USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO t FROM dns_txt_verifications WHERE id = NEW.txt_verification_id;
  IF NOT FOUND OR t.result <> 'match' THEN
    RAISE EXCEPTION 'escaneo bloqueado: la verificación TXT no tiene result = match' USING ERRCODE = 'check_violation';
  END IF;
  IF t.checked_at NOT BETWEEN NEW.queued_at - interval '1 hour' AND NEW.queued_at THEN
    RAISE EXCEPTION 'escaneo bloqueado: la verificación TXT es de % (más de 1 hora antes del escaneo)', t.checked_at
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER scans_require_authorization_bi BEFORE INSERT ON scans
  FOR EACH ROW EXECUTE FUNCTION scans_require_authorization();

-- keep_raw_payload: si la fuente no lo permite (HIBP), raw_payload debe ser NULL.
CREATE FUNCTION scan_source_runs_raw_payload_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.raw_payload IS NOT NULL
     AND NOT (SELECT keep_raw_payload FROM data_sources WHERE id = NEW.source_id) THEN
    RAISE EXCEPTION 'la fuente % no permite guardar raw_payload',
      (SELECT code FROM data_sources WHERE id = NEW.source_id) USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER scan_source_runs_raw_payload_biu BEFORE INSERT OR UPDATE ON scan_source_runs
  FOR EACH ROW EXECUTE FUNCTION scan_source_runs_raw_payload_guard();

-- =====================================================================
-- Row-Level Security: 18 tablas por cliente, ENABLE + FORCE, falla cerrada.
-- =====================================================================
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','api_keys','domains','domain_authorizations','dns_txt_verifications',
                           'scans','scan_source_runs','assets','findings','breach_exposures',
                           'domain_scores','score_contributions','integrations','alerts','deliveries',
                           'reports','audit_log']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (organization_id = app_current_org()) '
                   'WITH CHECK (organization_id = app_current_org())', t);
  END LOOP;
END $$;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON organizations
  USING (id = app_current_org()) WITH CHECK (id = app_current_org());

-- =====================================================================
-- Privilegios de cirdan_app (mínimos)
-- =====================================================================
GRANT USAGE ON SCHEMA public TO cirdan_app;
GRANT SELECT ON plans, scoring_rule_sets, scoring_rules, cves TO cirdan_app;
GRANT INSERT (cve_id) ON cves TO cirdan_app;
GRANT SELECT (id, code, kind, enabled, keep_raw_payload, key_rotated_at, rate_limit_per_min, last_success_at)
  ON data_sources TO cirdan_app;                      -- api_key_enc no se puede leer
GRANT SELECT ON organizations TO cirdan_app;
GRANT UPDATE (name, alert_score_threshold) ON organizations TO cirdan_app;
GRANT SELECT, INSERT, UPDATE ON users, api_keys, domains, scan_source_runs, assets,
  findings, breach_exposures, integrations, alerts, deliveries, reports TO cirdan_app;
-- scans: la app no puede fijar queued_at (siempre now()), así que no puede
-- fechar un escaneo en el pasado para usar una autorización ya vencida.
GRANT SELECT, UPDATE ON scans TO cirdan_app;
GRANT INSERT (id, organization_id, domain_id, authorization_id, txt_verification_id, trigger_type,
              requested_by, status, finished_at, stats) ON scans TO cirdan_app;
GRANT SELECT, INSERT ON dns_txt_verifications, domain_scores, score_contributions, audit_log TO cirdan_app;
GRANT SELECT, INSERT ON domain_authorizations TO cirdan_app;
GRANT UPDATE (revoked_at) ON domain_authorizations TO cirdan_app;

-- =====================================================================
-- Comentarios (notas del DBML)
-- =====================================================================
COMMENT ON TABLE plans IS 'Catálogo de los tres planes comerciales. Fija el tope de dominios, la frecuencia de escaneo y si el plan incluye API, webhooks y SIEM. Los límites los aplica check_plan_limits() en FastAPI, no un trigger.';
COMMENT ON TABLE organizations IS 'Cliente (tenant). Raíz del aislamiento por Row-Level Security (su política compara id, no organization_id) y dueño del umbral de alerta. El rol web solo puede cambiar name y alert_score_threshold.';
COMMENT ON TABLE users IS 'Usuarios del portal con rol y MFA (argon2 + TOTP). Las sesiones web de 15 min viven en Valkey, no aquí. Nunca se borran porque la bitácora los referencia.';
COMMENT ON TABLE api_keys IS 'Llaves de la API REST, con alcance a un dominio o a toda la organización. Solo se guarda el hash: la llave completa se muestra una vez.';
COMMENT ON TABLE domains IS 'Dominios raíz que el cliente quiere monitorear, con su token TXT de propiedad. Pueden darse de alta desde el portal o por API. No se escanean sin TXT verificado y autorización firmada vigente.';
COMMENT ON TABLE domain_authorizations IS 'Autorización firmada por quien tiene facultad sobre el dominio, con vigencia. Solo se carga desde el portal. Inmutable salvo revoked_at: renovar crea otra fila.';
COMMENT ON TABLE dns_txt_verifications IS 'Evidencia de cada consulta del registro TXT: al dar de alta, en la revisión diaria y justo antes de cada escaneo. Solo inserción y no se purga.';
COMMENT ON TABLE data_sources IS 'Catálogo de fuentes externas: plugins OSINT que corren en cada escaneo y feeds de inteligencia diarios. Guarda cifradas las llaves de API de la plataforma y decide si se conserva la respuesta cruda.';
COMMENT ON TABLE scans IS 'Una ejecución de recolección pasiva sobre un dominio. Queda ligada, por FK compuestas del mismo dominio, a la autorización vigente y a la verificación TXT que la permitieron.';
COMMENT ON TABLE scan_source_runs IS 'Resultado de cada fuente dentro de un escaneo. Controla reintentos y cobertura parcial y guarda la respuesta cruda sanitizada solo si la fuente lo permite.';
COMMENT ON TABLE assets IS 'Inventario normalizado de la superficie expuesta: dominio, subdominios, IP, servicios, certificados y correos.';
COMMENT ON TABLE findings IS 'Problema de seguridad sobre un activo. Se deduplica entre escaneos y es la unidad que se puntúa, se alerta y se exporta. Se guarda antes de enviarse a cualquier destino.';
COMMENT ON TABLE breach_exposures IS 'Hecho de que un activo aparece en una brecha pública (Have I Been Pwned): un correo del dominio en una brecha, o el propio dominio o subdominio como sitio vulnerado. Por diseño no existe columna para contraseñas, hashes ni tokens.';
COMMENT ON TABLE cves IS 'Inteligencia de vulnerabilidades local: CVSS de NVD, EPSS de FIRST y CISA KEV en una fila por CVE, cargada una vez al día. El worker solo inserta stubs, el cargador diario es el único que actualiza.';
COMMENT ON TABLE scoring_rule_sets IS 'Versión completa del juego de reglas y pesos de las 4 categorías del score, validada con el socio formador. Un cambio de cualquier peso crea un juego nuevo. Inmutable una vez activado.';
COMMENT ON TABLE scoring_rules IS 'Reglas con pesos que clasifican hallazgos y calculan el score. Cada juego de reglas copia todas las reglas, así (rule_set_id, code) identifica la fila exacta usada.';
COMMENT ON TABLE domain_scores IS 'Histórico del score de 0 a 100 por dominio y por categoría. Alimenta la tendencia de 12 meses y la alerta por umbral. Solo inserción, y solo el rol de retención borra filas de más de 12 meses.';
COMMENT ON TABLE score_contributions IS 'Desglose explicable del score: cuánto aporta cada hallazgo, con qué regla y por qué factores, con los valores de inteligencia congelados al calcular. Solo inserción.';
COMMENT ON TABLE integrations IS 'Destinos de entrega configurados por el cliente: webhook firmado, SIEM por CEF sobre TLS o correo. El resumen semanal es un evento más de una integración de correo.';
COMMENT ON TABLE alerts IS 'Evento a notificar (outbox). Se inserta en la misma transacción que el hallazgo o el score que lo causa.';
COMMENT ON TABLE deliveries IS 'Cada envío de una alerta o un informe a un destino, con reintentos en la misma fila y las marcas de tiempo que miden las alertas en menos de 60 s.';
COMMENT ON TABLE reports IS 'Informes PDF generados con WeasyPrint, a petición o como resumen semanal por correo.';
COMMENT ON TABLE audit_log IS 'Bitácora de solo inserción con cadena de hashes SHA-256 por organización, más una cadena de plataforma. Triggers bloquean UPDATE, DELETE y TRUNCATE para todos. No se purga.';
