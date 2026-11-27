-- =====================================================================
-- Cirdan · db/semillas/015_organizacion_lowtide.sql (#210, RC-329)
-- Organización LowTide con el dominio del producto, lowtidesec.com, para que
-- LowTide se analice a sí mismo en las demos del 27 nov y del 4 dic. Va en
-- una empresa aparte para no cambiar los conteos de Acme Demo, Beta Corp y
-- Grupo Olmardo que revisan pruebas/test_aislamiento.py y
-- pruebas/test_dominio_prueba.py. pruebas/test_organizacion_lowtide.py revisa
-- esta carga.
--
-- lowtidesec.com se registró el 8 nov 2026 a las 03:48:25 UTC, 21:48 del 7 nov
-- en Monterrey (RDAP de Verisign, comentario 10378 de RC-204). Ninguna fecha de
-- este archivo es anterior.
-- =====================================================================

BEGIN;

-- Plan Business, como Grupo Olmardo y como dice la carta.
INSERT INTO organizations (id, name, plan_id, status, alert_score_threshold) VALUES
 ('20000000-0000-4000-8000-000000000004', 'LowTide', '10000000-0000-4000-8000-000000000002', 'active', 60);

-- Único admin. Lleva el hash de relleno de la 002, que no abre nada: la
-- contraseña y el MFA se los pone el equipo fuera del repo. No está en
-- cirdan/auth/demo.py, así que DEMO_ACCOUNTS no la toca.
INSERT INTO users (id, organization_id, email, full_name, role, password_hash, totp_secret_enc, mfa_enabled_at, is_active) VALUES
 ('30000000-0000-4000-8000-000000000006', '20000000-0000-4000-8000-000000000004', 'equipo@lowtidesec.com', 'Equipo LowTide', 'admin',
  '$argon2id$v=19$m=65536,t=3,p=4$ZGVtby1zYWx0$ZGVtby1vbmx5', NULL, NULL, true);

-- txt_token sin el prefijo: el TXT publicado es cirdan-verification=be92b38a1634.
-- verified_at es la primera verificación del TXT en la raíz, hecha a mano por
-- DNS sobre HTTPS (dns.google, 8.8.8.8). Ver dns_txt_verifications abajo.
INSERT INTO domains (id, organization_id, fqdn, status, txt_token, verified_at, added_by) VALUES
 ('40000000-0000-4000-8000-000000000008', '20000000-0000-4000-8000-000000000004', 'lowtidesec.com', 'verified', 'be92b38a1634',
  '2026-11-15 16:33:25+00', '30000000-0000-4000-8000-000000000006');

-- Carta de la plantilla de #6 (docs/plantilla_carta_autorizacion.md). La firma
-- el titular de lowtidesec.com como persona física, que también firma por el
-- equipo, con vigencia de un año. Aquí solo van valores de rol: el nombre de
-- quien firma solo está en el PDF firmado, ligado por su sha256. El PDF no va
-- en el repo.
INSERT INTO domain_authorizations (id, organization_id, domain_id, signer_name, signer_title, signer_email,
  signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by) VALUES
 ('41000000-0000-4000-8000-000000000008', '20000000-0000-4000-8000-000000000004', '40000000-0000-4000-8000-000000000008',
  'Titular de lowtidesec.com', 'titular del dominio lowtidesec.com', 'equipo@lowtidesec.com',
  'authorizations/lowtide/lowtidesec.com_2026.pdf',
  decode('7db4bb7fb251a633bf2f0b2259eb9b959052c792cd8a35b6b28f4838634767a0', 'hex'),
  '2026-11-15', '2027-11-15', '30000000-0000-4000-8000-000000000006');

-- Verificación del alta: la consulta manual de verified_at. Antes de cada
-- escaneo el orquestador hace una nueva con check_reason = 'pre_scan'.
-- El SPF del dominio va como su huella sha256 (RC-272, migración 037).
INSERT INTO dns_txt_verifications (id, organization_id, domain_id, check_reason, expected_value, observed_values, resolver_ip, result, checked_at) VALUES
 ('42000000-0000-4000-8000-000000000008', '20000000-0000-4000-8000-000000000004', '40000000-0000-4000-8000-000000000008', 'onboarding',
  'cirdan-verification=be92b38a1634', '{sha256:4f88df0aee5ae3b699e9554518943da6118bf28aab0480c3d55a8f64691eb6d1,cirdan-verification=be92b38a1634}', '8.8.8.8', 'match', '2026-11-15 16:33:25+00');

COMMIT;
