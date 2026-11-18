-- =====================================================================
-- Cirdan · db/migraciones/019_textos_tls_sitio.sql (RC-239, #121)
-- Texto, firma y mapeo a marcos de las 2 reglas del saludo TLS de la
-- visita web (cirdan/recolectores/visita.py):
-- - tls_certificate_invalid: el certificado del sitio no se pudo
--   verificar (vencido, autofirmado, de otro nombre, de un emisor que
--   no se reconoce o sin su intermedio, o con llave o firma débil).
-- - tls_legacy_only: el sitio no acepta TLS 1.2 ni 1.3.
-- Las dos salen del mismo saludo de la visita, sin otra conexión.
-- Las reglas de scoring_rules van en la semilla 020, que necesita esta
-- migración antes (la FK de scoring_rules.code a scoring_rule_texts).
-- El texto y su mapeo entran en la misma transacción por la FK diferida
-- de la 012. Los textos los revisa y los firma ErnestoDL.
-- Mapeo como el de cert_expired después de la 012: sin técnica de
-- ATT&CK, ISO/IEC 27001:2022 A.8.24 y CIS Controls v8.1 3.10.
-- Se puede correr otra vez sin error: lo que ya está no cambia, pero
-- vuelve a mover updated_at de los 2 textos. Si un texto guardado no es
-- el de esta migración o lo firmó otra persona, se detiene sin firmar.
-- En una base que ya existe se aplica a mano antes de la semilla 020 y
-- antes de reconstruir la API (ver db/README.md).
-- =====================================================================

-- Los textos llevan acentos, aunque psql corra en una consola con otra
-- página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO scoring_rule_texts (code, title, meaning, recommendation) VALUES
 ('tls_certificate_invalid',
  'Un sitio de la empresa presenta un certificado de seguridad que los navegadores no aceptan',
  'Al visitar el sitio como lo haría cualquier persona, el certificado que entregó estaba vencido, era de otro nombre, lo firmó el mismo sitio, venía de una autoridad que no se reconoce o sin su certificado intermedio, o usaba una llave o una firma débil. Quien entra ve una alerta del navegador y la conexión deja de ser confiable, porque nadie puede comprobar que habla con el sitio de verdad.',
  'Pide a quien administra el sitio que instale un certificado vigente de una autoridad reconocida, emitido para ese nombre y con su cadena completa. Pídele también que active la renovación automática para que no vuelva a pasar.'),
 ('tls_legacy_only',
  'Un sitio de la empresa solo acepta versiones viejas del protocolo de cifrado',
  'Al visitar el sitio como lo haría cualquier persona, el servidor rechazó las versiones del protocolo de cifrado que hoy usan los navegadores, así que solo acepta versiones viejas que ya se consideran inseguras. Los navegadores actuales no pueden abrir el sitio, y quien lo visite con un programa viejo queda expuesto a que alguien lea o cambie lo que manda.',
  'Pide a quien administra el sitio que active las versiones actuales del protocolo de cifrado en el servidor y que apague las viejas. Si el servidor ya no se puede actualizar, pídele que lo cambie por uno con soporte.')
ON CONFLICT (code) DO NOTHING;

-- Antes de firmar, como la 006: cada texto tiene que ser el de esta
-- migración (si ya había otro, el INSERT de arriba no lo cambió) y no
-- puede estar firmado por otra persona. El md5 es del título, qué
-- significa y qué hacer, separados por un salto de línea, en UTF8.
DO $$
DECLARE
  distintos text;
BEGIN
  IF current_setting('server_encoding') <> 'UTF8' THEN
    RAISE EXCEPTION 'La 019 compara los textos en UTF8 y esta base usa %.', current_setting('server_encoding');
  END IF;
  SELECT string_agg(e.code, ', ') FILTER (WHERE t.code IS NULL
           OR md5(t.title || E'\n' || t.meaning || E'\n' || t.recommendation) <> e.texto
           OR (t.reviewed_by IS NOT NULL AND t.reviewed_by IS DISTINCT FROM e.revisor))
    INTO distintos
    FROM (VALUES
      ('tls_certificate_invalid', '3d339830c2ce7f18f61b678d2b356c0a', 'ErnestoDL'),
      ('tls_legacy_only', '42f34822475b07c5b3d94b1cb3329e18', 'ErnestoDL')
    ) AS e(code, texto, revisor)
    LEFT JOIN scoring_rule_texts t ON t.code = e.code;
  IF distintos IS NOT NULL THEN
    RAISE EXCEPTION 'Estos textos no son los de la 019, o ya los firmó otra persona: %. Revísalos antes de firmar.', distintos;
  END IF;
END $$;

UPDATE scoring_rule_texts SET reviewed_by = 'ErnestoDL', updated_at = now() WHERE code = 'tls_certificate_invalid';
UPDATE scoring_rule_texts SET reviewed_by = 'ErnestoDL', updated_at = now() WHERE code = 'tls_legacy_only';

INSERT INTO scoring_rule_framework_mappings (
  rule_code, attack_version, attack_technique_id, attack_technique_name, attack_source_url, attack_unmapped_reason,
  iso_version, iso_control_id, iso_control_name, iso_source_url,
  cis_version, cis_safeguard_id, cis_safeguard_name, cis_source_url
) VALUES
  ('tls_certificate_invalid', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
   'Ninguna técnica de ATT&CK nombra un certificado inválido del sitio como algo que un adversario busca o usa.',
   'ISO/IEC 27001:2022', 'A.8.24', 'Protección criptográfica', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '3.10', 'Cifrado de datos en tránsito', 'https://www.cisecurity.org/controls/v8-1'),
  ('tls_legacy_only', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
   'Ninguna técnica de ATT&CK nombra un sitio que solo acepta versiones viejas del cifrado como algo que un adversario busca o usa.',
   'ISO/IEC 27001:2022', 'A.8.24', 'Protección criptográfica', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '3.10', 'Cifrado de datos en tránsito', 'https://www.cisecurity.org/controls/v8-1')
ON CONFLICT (rule_code) DO NOTHING;

COMMIT;
