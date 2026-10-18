-- =====================================================================
-- Cirdan · db/semillas/001_datos_demo.sql
-- Datos canónicos de la organización "Acme Demo" (Cirdan_cambios_Figma.md)
-- más "Beta Corp", que solo sirve para la prueba de aislamiento RLS.
-- UUID fijos para que cada recarga sea idéntica. Fechas en hora del
-- centro de México (-06). IPs de documentación (RFC 5737).
-- password_hash, totp_secret_enc y sha256 de documentos son marcadores
-- de demostración, no secretos reales.
-- Se carga como postgres (superusuario), que no pasa por RLS.
-- =====================================================================
BEGIN;

-- ---------- catálogos globales ----------
INSERT INTO plans (id, code, max_domains, scan_interval, on_demand_scans, api_and_siem, monthly_price_mxn) VALUES
 ('10000000-0000-4000-8000-000000000001','starter',      5, '7 days', false, false,  2500.00),
 ('10000000-0000-4000-8000-000000000002','business',    25, '1 day',  false, true,   7500.00),
 ('10000000-0000-4000-8000-000000000003','enterprise', 100, '1 day',  true,  true,  18000.00);

INSERT INTO data_sources (id, code, kind, enabled, keep_raw_payload, rate_limit_per_min) VALUES
 ('50000000-0000-4000-8000-000000000001','ct_logs',    'osint', true,  true,   60),
 ('50000000-0000-4000-8000-000000000002','dns',        'osint', true,  true,  300),
 ('50000000-0000-4000-8000-000000000003','whois',      'osint', true,  true,   30),
 ('50000000-0000-4000-8000-000000000004','shodan',     'osint', true,  true,   60),
 ('50000000-0000-4000-8000-000000000005','hibp',       'osint', true,  false,  10),
 ('50000000-0000-4000-8000-000000000006','censys',     'osint', false, true,   60),  -- en evaluación
 ('50000000-0000-4000-8000-000000000007','nvd',        'intel', true,  true,   50),
 ('50000000-0000-4000-8000-000000000008','first_epss', 'intel', true,  true,   60),
 ('50000000-0000-4000-8000-000000000009','cisa_kev',   'intel', true,  true,   60);

INSERT INTO scoring_rule_sets (id, version, category_weights, is_active, activated_at) VALUES
 ('90000000-0000-4000-8000-000000000001', 1,
  '{"infrastructure": 0.30, "digital_identity": 0.20, "configuration": 0.20, "data_leaks": 0.30}',
  true, '2026-09-01 08:00-06');

INSERT INTO scoring_rules (id, rule_set_id, code, category, base_severity, weight, max_penalty) VALUES
 ('91000000-0000-4000-8000-000000000001','90000000-0000-4000-8000-000000000001','breach_exposure',  'data_leaks',       'critical', 1.000, 40.00),
 ('91000000-0000-4000-8000-000000000002','90000000-0000-4000-8000-000000000001','cert_expired',     'infrastructure',   'high',     0.400, 20.00),
 ('91000000-0000-4000-8000-000000000003','90000000-0000-4000-8000-000000000001','outdated_software','infrastructure',   'high',     0.400, 25.00),
 ('91000000-0000-4000-8000-000000000004','90000000-0000-4000-8000-000000000001','exposed_rdp',      'infrastructure',   'high',     0.200, 25.00),
 ('91000000-0000-4000-8000-000000000005','90000000-0000-4000-8000-000000000001','dmarc_missing',    'configuration',    'medium',   0.500, 10.00),
 ('91000000-0000-4000-8000-000000000006','90000000-0000-4000-8000-000000000001','spf_missing',      'configuration',    'low',      0.500,  8.00),
 ('91000000-0000-4000-8000-000000000007','90000000-0000-4000-8000-000000000001','lookalike_domain', 'digital_identity', 'medium',   1.000, 15.00);

-- ---------- organizaciones y usuarios ----------
INSERT INTO organizations (id, name, plan_id, status, alert_score_threshold) VALUES
 ('20000000-0000-4000-8000-000000000001','Acme Demo','10000000-0000-4000-8000-000000000001','active',60),
 ('20000000-0000-4000-8000-000000000002','Beta Corp','10000000-0000-4000-8000-000000000002','active',60);

INSERT INTO users (id, organization_id, email, full_name, role, password_hash, totp_secret_enc, mfa_enabled_at, is_active) VALUES
 ('30000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','alex.morgan@acme-demo.mx','Alex Morgan','admin',
  '$argon2id$v=19$m=65536,t=3,p=4$ZGVtby1zYWx0$ZGVtby1vbmx5', '\x00', '2026-09-01 09:30-06', true),
 ('30000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','maya.reed@acme-demo.mx','Maya Reed','manager',
  '$argon2id$v=19$m=65536,t=3,p=4$ZGVtby1zYWx0$ZGVtby1vbmx5', '\x00', '2026-09-01 11:00-06', true),
 ('30000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001','jordan.tate@acme-demo.mx','Jordan Tate','analyst',
  '$argon2id$v=19$m=65536,t=3,p=4$ZGVtby1zYWx0$ZGVtby1vbmx5', NULL, NULL, true),
 ('30000000-0000-4000-8000-000000000004','20000000-0000-4000-8000-000000000002','dana.cruz@beta-corp.mx','Dana Cruz','admin',
  '$argon2id$v=19$m=65536,t=3,p=4$ZGVtby1zYWx0$ZGVtby1vbmx5', '\x00', '2026-09-15 09:00-06', true);

-- ---------- dominios ----------
INSERT INTO domains (id, organization_id, fqdn, status, txt_token, verified_at, next_scan_at, last_scan_at, added_by) VALUES
 ('40000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','acme-demo.mx','verified','c41d7e2a9b06',
  '2026-09-01 10:00-06','2026-10-07 14:20-06','2026-09-30 14:20-06','30000000-0000-4000-8000-000000000001'),
 ('40000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','acme-tienda.mx','verified','5e9a1f3c7d28',
  '2026-09-01 10:05-06','2026-10-06 09:12-06','2026-09-29 09:12-06','30000000-0000-4000-8000-000000000001'),
 ('40000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001','acme-portal.mx','verified','a2b8c6e4f019',
  '2026-09-01 10:10-06','2026-10-04 18:45-06','2026-09-27 18:45-06','30000000-0000-4000-8000-000000000001'),
 ('40000000-0000-4000-8000-000000000004','20000000-0000-4000-8000-000000000001','partner-example.com','pending_verification','8f3c2a91e7b4',
  NULL, NULL, NULL, '30000000-0000-4000-8000-000000000001'),
 ('40000000-0000-4000-8000-000000000005','20000000-0000-4000-8000-000000000001','old-example.net','paused','3d7f9b1e5c82',
  '2025-08-15 12:00-06', NULL, NULL, '30000000-0000-4000-8000-000000000001'),
 ('40000000-0000-4000-8000-000000000006','20000000-0000-4000-8000-000000000002','beta-corp.mx','verified','b7e1d0c4a9f2',
  '2026-09-15 10:00-06','2026-10-03 10:00-06', NULL, '30000000-0000-4000-8000-000000000004');

-- ---------- autorizaciones firmadas ----------
-- partner-example.com no tiene autorización cargada todavía (Pending TXT, vigencia "—").
INSERT INTO domain_authorizations (id, organization_id, domain_id, signer_name, signer_title, signer_email,
  signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by) VALUES
 ('41000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',
  'Acme Demo Security','Security Office','security@acme-demo.mx','authorizations/acme-demo/acme-demo.mx_2026.pdf',
  sha256('demo:acme-demo.mx'), '2026-09-01','2026-12-31','30000000-0000-4000-8000-000000000001'),
 ('41000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000002',
  'Acme Demo Security','Security Office','security@acme-demo.mx','authorizations/acme-demo/acme-tienda.mx_2026.pdf',
  sha256('demo:acme-tienda.mx'), '2026-09-01','2026-12-31','30000000-0000-4000-8000-000000000001'),
 ('41000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000003',
  'Acme Demo Security','Security Office','security@acme-demo.mx','authorizations/acme-demo/acme-portal.mx_2026.pdf',
  sha256('demo:acme-portal.mx'), '2026-09-01','2026-12-31','30000000-0000-4000-8000-000000000001'),
 ('41000000-0000-4000-8000-000000000005','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000005',
  'Old Example IT','IT Department','it@old-example.net','authorizations/acme-demo/old-example.net_2025.pdf',
  sha256('demo:old-example.net'), '2025-08-15','2026-08-15','30000000-0000-4000-8000-000000000001'),
 ('41000000-0000-4000-8000-000000000006','20000000-0000-4000-8000-000000000002','40000000-0000-4000-8000-000000000006',
  'Dana Cruz','CISO','dana.cruz@beta-corp.mx','authorizations/beta-corp/beta-corp.mx_2026.pdf',
  sha256('demo:beta-corp.mx'), '2026-09-15','2026-12-31','30000000-0000-4000-8000-000000000004');

-- ---------- verificaciones TXT (solo inserción) ----------
INSERT INTO dns_txt_verifications (id, organization_id, domain_id, check_reason, expected_value, observed_values, resolver_ip, result, checked_at) VALUES
 -- alta
 ('42000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001','onboarding',
  'cirdan-verification=c41d7e2a9b06','{cirdan-verification=c41d7e2a9b06}','1.1.1.1','match','2026-09-01 10:00-06'),
 ('42000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000002','onboarding',
  'cirdan-verification=5e9a1f3c7d28','{cirdan-verification=5e9a1f3c7d28}','1.1.1.1','match','2026-09-01 10:05-06'),
 ('42000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000003','onboarding',
  'cirdan-verification=a2b8c6e4f019','{cirdan-verification=a2b8c6e4f019}','1.1.1.1','match','2026-09-01 10:10-06'),
 ('42000000-0000-4000-8000-000000000004','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000004','onboarding',
  'cirdan-verification=8f3c2a91e7b4','{}','1.1.1.1','missing','2026-10-01 16:10-06'),
 ('42000000-0000-4000-8000-000000000005','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000005','daily',
  'cirdan-verification=3d7f9b1e5c82','{cirdan-verification=3d7f9b1e5c82}','1.1.1.1','match','2026-10-01 06:00-06'),
 ('42000000-0000-4000-8000-000000000006','20000000-0000-4000-8000-000000000002','40000000-0000-4000-8000-000000000006','onboarding',
  'cirdan-verification=b7e1d0c4a9f2','{cirdan-verification=b7e1d0c4a9f2}','1.1.1.1','match','2026-09-15 10:00-06'),
 -- justo antes de cada escaneo
 ('42000000-0000-4000-8000-000000000011','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001','pre_scan',
  'cirdan-verification=c41d7e2a9b06','{cirdan-verification=c41d7e2a9b06}','1.1.1.1','match','2026-09-30 14:19:20-06'),
 ('42000000-0000-4000-8000-000000000012','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000002','pre_scan',
  'cirdan-verification=5e9a1f3c7d28','{cirdan-verification=5e9a1f3c7d28}','1.1.1.1','match','2026-09-29 09:11:30-06'),
 ('42000000-0000-4000-8000-000000000013','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000003','pre_scan',
  'cirdan-verification=a2b8c6e4f019','{cirdan-verification=a2b8c6e4f019}','1.1.1.1','match','2026-09-27 18:44:10-06');

-- ---------- escaneos (el trigger valida autorización vigente y TXT de la última hora) ----------
INSERT INTO scans (id, organization_id, domain_id, authorization_id, txt_verification_id, trigger_type, status, queued_at, finished_at, stats) VALUES
 ('60000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',
  '41000000-0000-4000-8000-000000000001','42000000-0000-4000-8000-000000000011','scheduled','completed',
  '2026-09-30 14:20-06','2026-09-30 14:24:10-06','{"assets": 6, "new_findings": 3, "resolved_findings": 0}'),
 ('60000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000002',
  '41000000-0000-4000-8000-000000000002','42000000-0000-4000-8000-000000000012','scheduled','completed',
  '2026-09-29 09:12-06','2026-09-29 09:15:40-06', NULL),
 ('60000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000003',
  '41000000-0000-4000-8000-000000000003','42000000-0000-4000-8000-000000000013','scheduled','completed',
  '2026-09-27 18:45-06','2026-09-27 18:48:20-06', NULL);

-- Una fila por fuente en el escaneo de acme-demo.mx. HIBP nunca guarda raw_payload.
INSERT INTO scan_source_runs (id, organization_id, scan_id, source_id, status, attempt, raw_payload, finished_at) VALUES
 ('61000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','60000000-0000-4000-8000-000000000001',
  '50000000-0000-4000-8000-000000000001','succeeded',1,'{"certificates_seen": 4}','2026-09-30 14:21:05-06'),
 ('61000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','60000000-0000-4000-8000-000000000001',
  '50000000-0000-4000-8000-000000000002','succeeded',1,'{"_dmarc.acme-demo.mx": "NXDOMAIN"}','2026-09-30 14:20:40-06'),
 ('61000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001','60000000-0000-4000-8000-000000000001',
  '50000000-0000-4000-8000-000000000003','succeeded',1,'{"registrar": "demo"}','2026-09-30 14:20:50-06'),
 ('61000000-0000-4000-8000-000000000004','20000000-0000-4000-8000-000000000001','60000000-0000-4000-8000-000000000001',
  '50000000-0000-4000-8000-000000000004','succeeded',1,'{"open_ports": [443]}','2026-09-30 14:22:30-06'),
 ('61000000-0000-4000-8000-000000000005','20000000-0000-4000-8000-000000000001','60000000-0000-4000-8000-000000000001',
  '50000000-0000-4000-8000-000000000005','succeeded',1, NULL,'2026-09-30 14:22:10-06');

-- ---------- activos ----------
INSERT INTO assets (id, organization_id, domain_id, parent_asset_id, asset_type, value, ip_address, attributes, first_seen_at, last_seen_at) VALUES
 ('70000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001', NULL,
  'domain','acme-demo.mx', NULL, '{"dns": {"mx": true, "dmarc": null}}','2026-09-01 10:00-06','2026-09-30 14:24-06'),
 ('70000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001','70000000-0000-4000-8000-000000000001',
  'subdomain','dev.acme-demo.mx', NULL, '{"source": "ct_logs"}','2026-09-02 10:30-06','2026-09-30 14:24-06'),
 ('70000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001','70000000-0000-4000-8000-000000000001',
  'subdomain','www.acme-demo.mx', NULL, '{"source": "ct_logs"}','2026-09-02 10:30-06','2026-09-30 14:24-06'),
 ('70000000-0000-4000-8000-000000000004','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001','70000000-0000-4000-8000-000000000002',
  'certificate', encode(sha256('demo-cert:dev.acme-demo.mx'), 'hex'), NULL,
  '{"subject": "dev.acme-demo.mx", "not_after": "2026-09-12"}','2026-09-02 10:30-06','2026-09-30 14:24-06'),
 ('70000000-0000-4000-8000-000000000005','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001','70000000-0000-4000-8000-000000000003',
  'ip','198.51.100.10','198.51.100.10','{}','2026-09-02 10:30-06','2026-09-30 14:24-06'),
 ('70000000-0000-4000-8000-000000000006','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001','70000000-0000-4000-8000-000000000005',
  'service','198.51.100.10:443/tcp','198.51.100.10','{"cms_version_status": "outdated"}','2026-09-02 10:30-06','2026-09-30 14:24-06'),
 -- Beta Corp
 ('70000000-0000-4000-8000-000000000011','20000000-0000-4000-8000-000000000002','40000000-0000-4000-8000-000000000006', NULL,
  'domain','beta-corp.mx', NULL, '{}','2026-09-15 10:00-06','2026-09-28 08:00-06'),
 ('70000000-0000-4000-8000-000000000012','20000000-0000-4000-8000-000000000002','40000000-0000-4000-8000-000000000006', NULL,
  'service','192.0.2.50:3389/tcp','192.0.2.50','{"service": "rdp"}','2026-09-28 08:00-06','2026-09-28 08:00-06');

-- ---------- hallazgos (fingerprint = SHA-256(code || asset_id || breach/cve)) ----------
INSERT INTO findings (id, organization_id, domain_id, asset_id, rule_id, source_id, fingerprint, severity, status, evidence, detected_at, last_scan_id) VALUES
 ('80000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',
  '70000000-0000-4000-8000-000000000001','91000000-0000-4000-8000-000000000001','50000000-0000-4000-8000-000000000005',
  sha256(convert_to('breach_exposure' || '70000000-0000-4000-8000-000000000001' || 'DemoBreach-2026', 'UTF8')),
  'critical','open','{"title": "12 corporate emails found in public data breaches", "emails_exposed": 12}',
  '2026-09-30 14:22:10-06','60000000-0000-4000-8000-000000000001'),
 ('80000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',
  '70000000-0000-4000-8000-000000000002','91000000-0000-4000-8000-000000000002','50000000-0000-4000-8000-000000000004',
  sha256(convert_to('cert_expired' || '70000000-0000-4000-8000-000000000002', 'UTF8')),
  'high','open','{"title": "Subdomain dev.acme-demo.mx with expired TLS certificate", "port": 443, "not_after": "2026-09-12"}',
  '2026-09-30 14:22:30-06','60000000-0000-4000-8000-000000000001'),
 ('80000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',
  '70000000-0000-4000-8000-000000000003','91000000-0000-4000-8000-000000000003','50000000-0000-4000-8000-000000000004',
  sha256(convert_to('outdated_software' || '70000000-0000-4000-8000-000000000003', 'UTF8')),
  'high','open','{"title": "CMS running outdated version with known vulnerabilities", "port": 443}',
  '2026-09-30 14:22:30-06','60000000-0000-4000-8000-000000000001'),
 ('80000000-0000-4000-8000-000000000004','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',
  '70000000-0000-4000-8000-000000000001','91000000-0000-4000-8000-000000000005','50000000-0000-4000-8000-000000000002',
  sha256(convert_to('dmarc_missing' || '70000000-0000-4000-8000-000000000001', 'UTF8')),
  'medium','open','{"title": "Domain missing DMARC record", "record": "_dmarc.acme-demo.mx", "observed": "NXDOMAIN"}',
  '2026-09-02 10:30-06','60000000-0000-4000-8000-000000000001'),
 -- Beta Corp
 ('80000000-0000-4000-8000-000000000011','20000000-0000-4000-8000-000000000002','40000000-0000-4000-8000-000000000006',
  '70000000-0000-4000-8000-000000000012','91000000-0000-4000-8000-000000000004','50000000-0000-4000-8000-000000000004',
  sha256(convert_to('exposed_rdp' || '70000000-0000-4000-8000-000000000012', 'UTF8')),
  'high','open','{"title": "Remote Desktop (RDP) exposed to the internet", "port": 3389}',
  '2026-09-28 08:00-06', NULL);

-- Solo el hecho de la exposición: no hay columna para contraseñas, hashes ni tokens.
INSERT INTO breach_exposures (finding_id, organization_id, breach_name, breach_date, data_classes) VALUES
 ('80000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','DemoBreach-2026','2026-06-18',
  '{"Email addresses","Passwords","Usernames"}');

-- ---------- score (más alto = más exposición) ----------
INSERT INTO domain_scores (id, organization_id, domain_id, scan_id, rule_set_id, score, category_scores, reason, method, partial_coverage, computed_at) VALUES
 ('a0000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',
  '60000000-0000-4000-8000-000000000001','90000000-0000-4000-8000-000000000001', 68,
  '{"infrastructure": 80, "digital_identity": 55, "configuration": 30, "data_leaks": 90}','scan','rules',false,'2026-09-30 14:24:30-06'),
 ('a0000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000002',
  '60000000-0000-4000-8000-000000000002','90000000-0000-4000-8000-000000000001', 54,
  '{"infrastructure": 60, "digital_identity": 50, "configuration": 40, "data_leaks": 60}','scan','rules',false,'2026-09-29 09:16-06'),
 ('a0000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000003',
  '60000000-0000-4000-8000-000000000003','90000000-0000-4000-8000-000000000001', 31,
  '{"infrastructure": 40, "digital_identity": 30, "configuration": 20, "data_leaks": 30}','scan','rules',false,'2026-09-27 18:49-06');

-- Explicación del hallazgo de brecha: una fila por (score, hallazgo); las reglas que lo
-- explican van en factors (valores congelados al calcular).
INSERT INTO score_contributions (id, organization_id, score_id, finding_id, rule_id, penalty, severity, factors) VALUES
 ('a1000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','a0000000-0000-4000-8000-000000000001',
  '80000000-0000-4000-8000-000000000001','91000000-0000-4000-8000-000000000001', 24.00, 'critical',
  '{"rules": [{"label": "Breach less than 6 months ago", "points": 12},
              {"label": "Includes admin accounts", "points": 8},
              {"label": "Breach includes passwords", "points": 6},
              {"label": "Finding seen previously", "points": -2}],
    "emails_exposed": 12, "breach_date": "2026-06-18"}');

-- ---------- entrega ----------
INSERT INTO integrations (id, organization_id, kind, name, endpoint, config, enabled) VALUES
 ('b0000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','email','Manager alerts and weekly summary',
  'maya.reed@acme-demo.mx','{"events": ["score.above_threshold", "report.weekly_summary"], "min_severity": "high"}', true);

INSERT INTO alerts (id, organization_id, domain_id, event_type, score_id, severity, payload, detected_at) VALUES
 ('b1000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',
  'score.above_threshold','a0000000-0000-4000-8000-000000000001','high',
  '{"domain": "acme-demo.mx", "score": 68, "threshold": 60, "level": "High"}','2026-09-30 14:25-06');

INSERT INTO reports (id, organization_id, domain_id, kind, period_start, period_end, status, generated_at, storage_key, requested_by) VALUES
 ('b2000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',
  'weekly_summary','2026-09-23','2026-09-30','ready','2026-09-30 14:40-06','reports/acme-demo/2026-09-30_weekly_summary.pdf', NULL),
 ('b2000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001', NULL,
  'pdf_report','2026-09-01','2026-09-30','ready','2026-09-30 14:45-06','reports/acme-demo/2026-09-30_executive.pdf',
  '30000000-0000-4000-8000-000000000002');

INSERT INTO deliveries (id, organization_id, integration_id, alert_id, report_id, status, attempt, message_id, response_status, detected_at, delivered_at) VALUES
 ('b3000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','b0000000-0000-4000-8000-000000000001',
  'b1000000-0000-4000-8000-000000000001', NULL,'delivered',1,'msg_b1000000_0001',250,'2026-09-30 14:25:00-06','2026-09-30 14:25:04.2-06'),
 ('b3000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','b0000000-0000-4000-8000-000000000001',
  NULL,'b2000000-0000-4000-8000-000000000001','delivered',1,'msg_b2000000_0001',250,'2026-09-30 14:40:00-06','2026-09-30 14:40:06.5-06');

-- ---------- bitácora (chain_seq, prev_hash y row_hash los calcula el trigger) ----------
INSERT INTO audit_log (id, organization_id, actor_type, actor_user_id, action, entity_type, entity_id, details, occurred_at) VALUES
 ('c0000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','user','30000000-0000-4000-8000-000000000001',
  'domain.added','domain','40000000-0000-4000-8000-000000000001','{"fqdn": "acme-demo.mx"}','2026-09-01 09:40-06');
INSERT INTO audit_log (id, organization_id, actor_type, actor_user_id, action, entity_type, entity_id, details, occurred_at) VALUES
 ('c0000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','user','30000000-0000-4000-8000-000000000001',
  'authorization.uploaded','domain_authorization','41000000-0000-4000-8000-000000000001','{"fqdn": "acme-demo.mx", "valid_until": "2026-12-31"}','2026-09-01 09:55-06');
INSERT INTO audit_log (id, organization_id, actor_type, actor_user_id, action, entity_type, entity_id, details, occurred_at) VALUES
 ('c0000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001','user','30000000-0000-4000-8000-000000000002',
  'organization.threshold_changed','organization','20000000-0000-4000-8000-000000000001','{"alert_score_threshold": 60}','2026-09-15 11:02-06');
INSERT INTO audit_log (id, organization_id, actor_type, action, entity_type, entity_id, details, occurred_at) VALUES
 ('c0000000-0000-4000-8000-000000000004','20000000-0000-4000-8000-000000000001','system',
  'finding.severity_changed','finding','80000000-0000-4000-8000-000000000001','{"from": "high", "to": "critical"}','2026-09-30 14:24:30-06');
INSERT INTO audit_log (id, organization_id, actor_type, action, entity_type, entity_id, details, occurred_at) VALUES
 ('c0000000-0000-4000-8000-000000000005','20000000-0000-4000-8000-000000000001','system',
  'alert.created','alert','b1000000-0000-4000-8000-000000000001','{"event_type": "score.above_threshold", "score": 68}','2026-09-30 14:25-06');
INSERT INTO audit_log (id, organization_id, actor_type, actor_user_id, action, entity_type, entity_id, details, occurred_at) VALUES
 ('c0000000-0000-4000-8000-000000000006','20000000-0000-4000-8000-000000000001','user','30000000-0000-4000-8000-000000000002',
  'report.downloaded','report','b2000000-0000-4000-8000-000000000002','{"kind": "pdf_report"}','2026-09-30 14:47-06');
INSERT INTO audit_log (id, organization_id, actor_type, actor_user_id, action, entity_type, entity_id, details, occurred_at) VALUES
 ('c0000000-0000-4000-8000-000000000011','20000000-0000-4000-8000-000000000002','user','30000000-0000-4000-8000-000000000004',
  'domain.added','domain','40000000-0000-4000-8000-000000000006','{"fqdn": "beta-corp.mx"}','2026-09-15 09:50-06');
INSERT INTO audit_log (id, organization_id, actor_type, action, details, occurred_at) VALUES
 ('c0000000-0000-4000-8000-000000000021', NULL,'system','chain.verified','{"chains": 2, "ok": true}','2026-10-02 03:00-06');

COMMIT;
