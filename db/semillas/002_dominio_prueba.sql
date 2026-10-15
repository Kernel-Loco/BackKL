-- =====================================================================
-- Cirdan · db/semillas/002_dominio_prueba.sql (#9b, RC-151)
-- Dominio de prueba del equipo: olmardo.com (Grupo Olmardo, empresa ficticia),
-- con su token TXT publicado y su autorización, para que el orquestador (#22)
-- lo pueda escanear en vivo. Va en una empresa aparte para no cambiar los
-- conteos de Acme Demo y Beta Corp que revisa pruebas/test_aislamiento.py.
--
-- PENDIENTE (#6, #9b): signed_document_sha256 es provisional. Cuando exista la
-- carta firmada con la plantilla de #6, se reemplaza por su sha256 real:
--   decode('<sha256 del PDF>', 'hex')
-- y se actualizan quién firma y signed_document_key.
-- =====================================================================

BEGIN;

-- Fuente de pruebas sin red (recolector `ejemplo`). Deshabilitada: el orquestador
-- solo la usa cuando una prueba la pide explícitamente.
INSERT INTO data_sources (id, code, kind, enabled, keep_raw_payload, rate_limit_per_min) VALUES
 ('50000000-0000-4000-8000-000000000010', 'ejemplo', 'osint', false, true, NULL);

INSERT INTO organizations (id, name, plan_id, status, alert_score_threshold) VALUES
 ('20000000-0000-4000-8000-000000000003', 'Grupo Olmardo', '10000000-0000-4000-8000-000000000001', 'active', 60);

-- La contraseña y el MFA reales los pone cirdan/auth/demo.py (DEMO_ACCOUNTS=true).
INSERT INTO users (id, organization_id, email, full_name, role, password_hash, totp_secret_enc, mfa_enabled_at, is_active) VALUES
 ('30000000-0000-4000-8000-000000000005', '20000000-0000-4000-8000-000000000003', 'admin@olmardo.com', 'Equipo Kernel Loco', 'admin',
  '$argon2id$v=19$m=65536,t=3,p=4$ZGVtby1zYWx0$ZGVtby1vbmx5', NULL, NULL, true);

-- txt_token sin el prefijo: el TXT publicado es cirdan-verification=ab439d2b39a7.
INSERT INTO domains (id, organization_id, fqdn, status, txt_token, verified_at, added_by) VALUES
 ('40000000-0000-4000-8000-000000000007', '20000000-0000-4000-8000-000000000003', 'olmardo.com', 'verified', 'ab439d2b39a7',
  '2026-10-13 10:00-06', '30000000-0000-4000-8000-000000000005');

INSERT INTO domain_authorizations (id, organization_id, domain_id, signer_name, signer_title, signer_email,
  signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by) VALUES
 ('41000000-0000-4000-8000-000000000007', '20000000-0000-4000-8000-000000000003', '40000000-0000-4000-8000-000000000007',
  'Equipo Kernel Loco', 'Dueño del dominio de prueba', 'admin@olmardo.com',
  'authorizations/olmardo/olmardo.com_2026.pdf',
  sha256(convert_to('PROVISIONAL: reemplazar por el sha256 de la carta firmada (#6, #9b)', 'UTF8')),
  '2026-10-01', '2027-06-30', '30000000-0000-4000-8000-000000000005');

-- Verificación del alta, igual que en el resto de la semilla. Antes de cada escaneo
-- el orquestador hace una nueva con check_reason = 'pre_scan'.
INSERT INTO dns_txt_verifications (id, organization_id, domain_id, check_reason, expected_value, observed_values, resolver_ip, result, checked_at) VALUES
 ('42000000-0000-4000-8000-000000000007', '20000000-0000-4000-8000-000000000003', '40000000-0000-4000-8000-000000000007', 'onboarding',
  'cirdan-verification=ab439d2b39a7', '{cirdan-verification=ab439d2b39a7}', '1.1.1.1', 'match', '2026-10-13 10:00-06');

COMMIT;
