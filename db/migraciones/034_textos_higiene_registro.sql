-- =====================================================================
-- Cirdan · db/migraciones/034_textos_higiene_registro.sql (RC-221, #104)
-- Texto, firma y mapeo a marcos de las 3 reglas de higiene del registro
-- del dominio, que salen de datos que ya se consultan, sin otra consulta:
-- - domain_transfer_unlocked (whois, cirdan/recolectores/rdap.py): el
--   estado del registro no trae client ni server transfer prohibited.
-- - dnssec_missing (whois, rdap.py): el registro dice que la delegación
--   no está firmada.
-- - dns_single_provider (dns, cirdan/recolectores/registros_dns.py):
--   todos los NS del dominio comparten el mismo dominio registrable.
-- Las reglas de scoring_rules van en la semilla 028, que necesita esta
-- migración antes (la FK de scoring_rules.code a scoring_rule_texts).
-- El texto y su mapeo entran en la misma transacción por la FK diferida
-- de la 012. Los textos los revisa y los firma ErnestoDL.
-- Mapeo: domain_transfer_unlocked con T1584.001 (tomar dominios o
-- subdominios), A.8.9 y CIS 4.1, la configuración segura del registro.
-- dnssec_missing sin técnica, con A.8.21 y CIS 4.1. dns_single_provider
-- sin técnica, con A.8.21 y CIS 12.2 (arquitectura de red segura).
-- Se puede correr otra vez sin error: lo que ya está no cambia, pero
-- vuelve a mover updated_at de los 3 textos. Si un texto guardado no es
-- el de esta migración o lo firmó otra persona, se detiene sin firmar.
-- En una base que ya existe se aplica a mano antes de la semilla 028 y
-- antes de reconstruir la API (ver db/README.md).
-- =====================================================================

-- Los textos llevan acentos, aunque psql corra en una consola con otra
-- página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO scoring_rule_texts (code, title, meaning, recommendation) VALUES
 ('domain_transfer_unlocked',
  'El dominio de la empresa se puede llevar a otro registrador sin destrabarlo antes',
  'El registro público del dominio no tiene puesto el candado que impide pasarlo a otro registrador. Si alguien entra a la cuenta del registrador o engaña a su soporte, puede llevarse el dominio y quedarse con el sitio y el correo de la empresa.',
  'Pide a quien administra el dominio que active el candado de transferencia en el panel del registrador. Pídele también que proteja esa cuenta con una contraseña única y un segundo paso al entrar, y que solo quite el candado cuando la empresa decida cambiar de registrador.'),
 ('dnssec_missing',
  'Las respuestas sobre el dominio de la empresa no van firmadas',
  'El registro público dice que el dominio no tiene activada la firma de sus respuestas, la extensión de seguridad que deja comprobar que la dirección de un sitio o de un servidor de correo de la empresa es la verdadera. Sin ella, alguien que se ponga en medio de la red puede dar una dirección falsa y llevar a las personas a un sitio que no es el de la empresa.',
  'Pide a quien administra el dominio que active la firma en el proveedor que publica sus nombres y que la dé de alta en el registrador. En muchos proveedores se activa con un solo botón.'),
 ('dns_single_provider',
  'Todos los servidores de nombres del dominio de la empresa son de un solo proveedor',
  'Los servidores que le dicen a internet dónde están el sitio y el correo de la empresa son todos del mismo proveedor. Si ese proveedor se cae o sufre un ataque, nadie puede encontrar el sitio ni mandar correo a la empresa, aunque sus equipos sigan funcionando.',
  'Pide a quien administra el dominio que valore sumar un segundo proveedor que publique los mismos nombres. Si se queda con uno solo, pídele que confirme que ese proveedor reparte sus servidores en redes distintas y que tiene un plan para seguir funcionando si falla.')
ON CONFLICT (code) DO NOTHING;

-- Antes de firmar, como la 025: cada texto tiene que ser el de esta
-- migración (si ya había otro, el INSERT de arriba no lo cambió) y no
-- puede estar firmado por otra persona. El md5 es del título, qué
-- significa y qué hacer, separados por un salto de línea, en UTF8.
DO $$
DECLARE
  distintos text;
BEGIN
  IF current_setting('server_encoding') <> 'UTF8' THEN
    RAISE EXCEPTION 'La 034 compara los textos en UTF8 y esta base usa %.', current_setting('server_encoding');
  END IF;
  SELECT string_agg(e.code, ', ') FILTER (WHERE t.code IS NULL
           OR md5(t.title || E'\n' || t.meaning || E'\n' || t.recommendation) <> e.texto
           OR (t.reviewed_by IS NOT NULL AND t.reviewed_by IS DISTINCT FROM e.revisor))
    INTO distintos
    FROM (VALUES
      ('domain_transfer_unlocked', 'fb65b63e46d451326c4eb4f8080670ae', 'ErnestoDL'),
      ('dnssec_missing', '0e07a6cebd5ecb9e3adc3f09f0df4dda', 'ErnestoDL'),
      ('dns_single_provider', '2c90f7374ca0cf2b519893e3829a4dfe', 'ErnestoDL')
    ) AS e(code, texto, revisor)
    LEFT JOIN scoring_rule_texts t ON t.code = e.code;
  IF distintos IS NOT NULL THEN
    RAISE EXCEPTION 'Estos textos no son los de la 034, o ya los firmó otra persona: %. Revísalos antes de firmar.', distintos;
  END IF;
END $$;

UPDATE scoring_rule_texts SET reviewed_by = 'ErnestoDL', updated_at = now() WHERE code = 'domain_transfer_unlocked';
UPDATE scoring_rule_texts SET reviewed_by = 'ErnestoDL', updated_at = now() WHERE code = 'dnssec_missing';
UPDATE scoring_rule_texts SET reviewed_by = 'ErnestoDL', updated_at = now() WHERE code = 'dns_single_provider';

INSERT INTO scoring_rule_framework_mappings (
  rule_code, attack_version, attack_technique_id, attack_technique_name, attack_source_url, attack_unmapped_reason,
  iso_version, iso_control_id, iso_control_name, iso_source_url,
  cis_version, cis_safeguard_id, cis_safeguard_name, cis_source_url
) VALUES
  ('domain_transfer_unlocked', 'Enterprise v19', 'T1584.001', 'Tomar dominios o subdominios',
   'https://attack.mitre.org/versions/v19/techniques/T1584/001/', NULL,
   'ISO/IEC 27001:2022', 'A.8.9', 'Gestión segura de configuración', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '4.1', 'Proceso de configuración segura', 'https://www.cisecurity.org/controls/v8-1'),
  ('dnssec_missing', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
   'Ninguna técnica de ATT&CK nombra una delegación del dominio sin firmar como algo que un adversario busca o usa.',
   'ISO/IEC 27001:2022', 'A.8.21', 'Seguridad de servicios de red', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '4.1', 'Proceso de configuración segura', 'https://www.cisecurity.org/controls/v8-1'),
  ('dns_single_provider', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
   'Ninguna técnica de ATT&CK nombra que los servidores de nombres de un dominio sean de un solo proveedor.',
   'ISO/IEC 27001:2022', 'A.8.21', 'Seguridad de servicios de red', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '12.2', 'Arquitectura de red segura', 'https://www.cisecurity.org/controls/v8-1')
ON CONFLICT (rule_code) DO NOTHING;

COMMIT;
