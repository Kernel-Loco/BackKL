-- =====================================================================
-- Cirdan · db/semillas/002_dominio_prueba.sql (#9b, RC-151)
-- Dominio de prueba del equipo: olmardo.com (Grupo Olmardo, empresa ficticia),
-- con su token TXT publicado y su autorización, para que el orquestador (#22)
-- lo pueda escanear en vivo. Va en una empresa aparte para no cambiar los
-- conteos de Acme Demo y Beta Corp que revisa pruebas/test_aislamiento.py.
-- pruebas/test_dominio_prueba.py revisa esta carga.
--
-- olmardo.com se registró el 13 oct 2026 a las 18:38 hora de Monterrey
-- (RDAP: 2026-10-14T00:38:02Z). Ninguna fecha de este archivo es anterior.
-- =====================================================================

BEGIN;

-- Fuente de pruebas sin red (recolector `ejemplo`). Deshabilitada: el orquestador
-- solo la usa cuando una prueba la pide explícitamente.
INSERT INTO data_sources (id, code, kind, enabled, keep_raw_payload, rate_limit_per_min) VALUES
 ('50000000-0000-4000-8000-000000000010', 'ejemplo', 'osint', false, true, NULL);

-- Plan Business, el del perfil de Grupo Olmardo (#97, RC-210) y el de la carta.
INSERT INTO organizations (id, name, plan_id, status, alert_score_threshold) VALUES
 ('20000000-0000-4000-8000-000000000003', 'Grupo Olmardo', '10000000-0000-4000-8000-000000000002', 'active', 60);

-- La contraseña y el MFA reales los pone cirdan/auth/demo.py (DEMO_ACCOUNTS=true).
INSERT INTO users (id, organization_id, email, full_name, role, password_hash, totp_secret_enc, mfa_enabled_at, is_active) VALUES
 ('30000000-0000-4000-8000-000000000005', '20000000-0000-4000-8000-000000000003', 'admin@olmardo.com', 'Equipo Kernel Loco', 'admin',
  '$argon2id$v=19$m=65536,t=3,p=4$ZGVtby1zYWx0$ZGVtby1vbmx5', NULL, NULL, true);

-- txt_token sin el prefijo: el TXT publicado es cirdan-verification=ab439d2b39a7.
-- verified_at es la primera verificación del TXT en la raíz. Se hizo a mano por
-- DNS sobre HTTPS (dns.google, 8.8.8.8) a las 01:02 UTC del 14 oct 2026, que son
-- las 19:02 del 13 oct en Monterrey (comentario 10093 de RC-38).
INSERT INTO domains (id, organization_id, fqdn, status, txt_token, verified_at, added_by) VALUES
 ('40000000-0000-4000-8000-000000000007', '20000000-0000-4000-8000-000000000003', 'olmardo.com', 'verified', 'ab439d2b39a7',
  '2026-10-13 19:02-06', '30000000-0000-4000-8000-000000000005');

-- Carta de la plantilla de #6. La firma el titular de olmardo.com como persona
-- física el 19 de octubre de 2026, con vigencia del 19 de octubre de 2026 al
-- 19 de octubre de 2027. La carta nombra el producto LowTide.
-- Aquí solo van valores de rol. El nombre real de quien firma solo está en el
-- PDF firmado, ligado por su sha256.
-- signed_document_sha256 es el sha256 de ese PDF. El PDF no va en el repo: está
-- en la carpeta compartida del equipo.
INSERT INTO domain_authorizations (id, organization_id, domain_id, signer_name, signer_title, signer_email,
  signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by) VALUES
 ('41000000-0000-4000-8000-000000000007', '20000000-0000-4000-8000-000000000003', '40000000-0000-4000-8000-000000000007',
  'Titular de olmardo.com', 'titular del dominio olmardo.com', 'contacto@olmardo.com',
  'authorizations/olmardo/olmardo.com_2026.pdf',
  decode('359f2f33929ac3fa63856d5d99c2037751356d785e860b0138064b811d2acffe', 'hex'),
  '2026-10-19', '2027-10-19', '30000000-0000-4000-8000-000000000005');

-- Verificación del alta, igual que en el resto de la semilla. Es la consulta
-- manual de verified_at: DNS sobre HTTPS con dns.google (8.8.8.8) a las 01:02 UTC
-- del 14 oct 2026 (comentario 10093 de RC-38). Antes de cada escaneo el
-- orquestador hace una nueva con check_reason = 'pre_scan'.
INSERT INTO dns_txt_verifications (id, organization_id, domain_id, check_reason, expected_value, observed_values, resolver_ip, result, checked_at) VALUES
 ('42000000-0000-4000-8000-000000000007', '20000000-0000-4000-8000-000000000003', '40000000-0000-4000-8000-000000000007', 'onboarding',
  'cirdan-verification=ab439d2b39a7', '{cirdan-verification=ab439d2b39a7}', '8.8.8.8', 'match', '2026-10-13 19:02-06');

COMMIT;
