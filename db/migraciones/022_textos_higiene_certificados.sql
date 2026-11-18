-- =====================================================================
-- Cirdan · db/migraciones/022_textos_higiene_certificados.sql (RC-218, #14)
-- Texto, firma y mapeo a marcos de las 3 reglas de higiene de
-- certificados que ct_logs saca de los mismos registros de Certificate
-- Transparency que ya lee (cirdan/recolectores/crtsh.py), sin otra
-- consulta:
-- - cert_internal_name: un nombre de un certificado vigente o vencido
--   hace menos de 365 días lleva una etiqueta de la lista de
--   cirdan/recolectores/nombres_internos.py (dev, staging, vpn, jenkins).
-- - cert_broad_wildcard: un certificado vigente con *.dominio del dominio
--   autorizado.
-- - cert_new_issuer: un certificado vigente de los últimos 90 días de una
--   organización emisora que no está en ningún certificado anterior del
--   dominio, cuando hay al menos 3 anteriores.
-- Las reglas de scoring_rules van en la semilla 023, que necesita esta
-- migración antes (la FK de scoring_rules.code a scoring_rule_texts).
-- El texto y su mapeo entran en la misma transacción por la FK diferida
-- de la 012. Los textos los revisa y los firma ErnestoDL.
-- Mapeo: cert_internal_name con T1596.003 (buscar en certificados
-- digitales), A.8.31 y CIS 16.8, como debug_page_exposed de la 020.
-- cert_broad_wildcard sin técnica, con A.8.24 y CIS 3.10, como
-- cert_expired. cert_new_issuer con T1588.004 (obtener certificados
-- digitales), A.8.24 y CIS 3.10.
-- Se puede correr otra vez sin error: lo que ya está no cambia, pero
-- vuelve a mover updated_at de los 3 textos. Si un texto guardado no es
-- el de esta migración o lo firmó otra persona, se detiene sin firmar.
-- En una base que ya existe se aplica a mano antes de la semilla 023 y
-- antes de reconstruir la API (ver db/README.md).
-- =====================================================================

-- Los textos llevan acentos, aunque psql corra en una consola con otra
-- página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO scoring_rule_texts (code, title, meaning, recommendation) VALUES
 ('cert_internal_name',
  'Un certificado público de la empresa deja ver el nombre de un sistema interno',
  'Los registros públicos de certificados, que cualquiera puede consultar, muestran un nombre del dominio que delata un entorno de pruebas, un acceso remoto o una herramienta interna, como dev, staging o jenkins. Quien prepara un ataque usa esos nombres para saber dónde buscar, porque esos sistemas suelen estar menos cuidados que el sitio principal.',
  'Pide a quien administra los sistemas que revise si ese nombre necesita estar en internet. Si es solo de uso interno, pídele que lo saque de internet o que solo se pueda entrar desde la red de la empresa, con un certificado de una autoridad interna, que no queda en los registros públicos.'),
 ('cert_broad_wildcard',
  'Un certificado de la empresa sirve para cualquier nombre de su dominio',
  'Hay un certificado vigente para todos los nombres bajo el dominio de la empresa, un comodín. Los servidores que lo usan comparten la misma llave privada, así que basta con que alguien la robe de uno solo para hacerse pasar por cualquier sitio de la empresa.',
  'Pide a quien administra los sitios que use un certificado con el nombre de cada sitio, o comodines solo para grupos pequeños de sitios, y que la llave del comodín viva en el menor número posible de servidores.'),
 ('cert_new_issuer',
  'Una autoridad que nunca había emitido para la empresa emitió un certificado nuevo',
  'En los últimos 90 días apareció en los registros públicos un certificado vigente para el dominio de la empresa, emitido por una autoridad de certificación que no aparece en ninguno de sus certificados anteriores. Puede ser un cambio de proveedor que nadie anotó, o un certificado que la empresa no pidió y que alguien podría usar para hacerse pasar por ella.',
  'Pide a quien administra los certificados que confirme si la empresa pidió ese certificado y, si no, que solicite a la autoridad que lo revoque. Pídele también que publique en la configuración del dominio la lista de autoridades que la empresa sí usa, así las demás se niegan a emitirle certificados.')
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
    RAISE EXCEPTION 'La 022 compara los textos en UTF8 y esta base usa %.', current_setting('server_encoding');
  END IF;
  SELECT string_agg(e.code, ', ') FILTER (WHERE t.code IS NULL
           OR md5(t.title || E'\n' || t.meaning || E'\n' || t.recommendation) <> e.texto
           OR (t.reviewed_by IS NOT NULL AND t.reviewed_by IS DISTINCT FROM e.revisor))
    INTO distintos
    FROM (VALUES
      ('cert_internal_name', 'a4d3d99d56a7694b5c1343e32fd6ced3', 'ErnestoDL'),
      ('cert_broad_wildcard', '3ec816374c8214f4c562d145e75c0312', 'ErnestoDL'),
      ('cert_new_issuer', '1242cd9b5a214f86dd62adf180c09936', 'ErnestoDL')
    ) AS e(code, texto, revisor)
    LEFT JOIN scoring_rule_texts t ON t.code = e.code;
  IF distintos IS NOT NULL THEN
    RAISE EXCEPTION 'Estos textos no son los de la 022, o ya los firmó otra persona: %. Revísalos antes de firmar.', distintos;
  END IF;
END $$;

UPDATE scoring_rule_texts SET reviewed_by = 'ErnestoDL', updated_at = now() WHERE code = 'cert_internal_name';
UPDATE scoring_rule_texts SET reviewed_by = 'ErnestoDL', updated_at = now() WHERE code = 'cert_broad_wildcard';
UPDATE scoring_rule_texts SET reviewed_by = 'ErnestoDL', updated_at = now() WHERE code = 'cert_new_issuer';

INSERT INTO scoring_rule_framework_mappings (
  rule_code, attack_version, attack_technique_id, attack_technique_name, attack_source_url, attack_unmapped_reason,
  iso_version, iso_control_id, iso_control_name, iso_source_url,
  cis_version, cis_safeguard_id, cis_safeguard_name, cis_source_url
) VALUES
  ('cert_internal_name', 'Enterprise v19', 'T1596.003', 'Buscar en certificados digitales',
   'https://attack.mitre.org/versions/v19/techniques/T1596/003/', NULL,
   'ISO/IEC 27001:2022', 'A.8.31', 'Separación de entornos de desarrollo, prueba y producción',
   'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '16.8', 'Separación de sistemas de producción y no producción',
   'https://www.cisecurity.org/controls/v8-1'),
  ('cert_broad_wildcard', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
   'Ninguna técnica de ATT&CK nombra un certificado comodín del dominio como algo que un adversario busca o usa.',
   'ISO/IEC 27001:2022', 'A.8.24', 'Protección criptográfica', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '3.10', 'Cifrado de datos en tránsito', 'https://www.cisecurity.org/controls/v8-1'),
  ('cert_new_issuer', 'Enterprise v19', 'T1588.004', 'Obtener certificados digitales',
   'https://attack.mitre.org/versions/v19/techniques/T1588/004/', NULL,
   'ISO/IEC 27001:2022', 'A.8.24', 'Protección criptográfica', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '3.10', 'Cifrado de datos en tránsito', 'https://www.cisecurity.org/controls/v8-1')
ON CONFLICT (rule_code) DO NOTHING;

COMMIT;
