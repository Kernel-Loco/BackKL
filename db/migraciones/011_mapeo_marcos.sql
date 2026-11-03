-- Cirdan · mapeo de reglas a MITRE ATT&CK, ISO/IEC 27001:2022 y CIS Controls v8.1 (#68).
-- Solo guarda identificadores, nombres breves propios y enlaces; no reproduce textos
-- de ISO ni de CIS. El uso comercial de CIS Controls requiere permiso de CIS.
BEGIN;

CREATE TABLE scoring_rule_framework_mappings (
  rule_code                text PRIMARY KEY REFERENCES scoring_rule_texts(code) ON DELETE RESTRICT,
  attack_version           text NOT NULL CHECK (btrim(attack_version) <> ''),
  attack_technique_id      text CHECK (attack_technique_id IS NULL OR attack_technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
  attack_technique_name    text,
  attack_source_url        text NOT NULL CHECK (attack_source_url LIKE 'https://%'),
  attack_unmapped_reason   text,
  iso_version              text NOT NULL CHECK (btrim(iso_version) <> ''),
  iso_control_id           text NOT NULL CHECK (iso_control_id ~ '^A\.[5-8]\.[0-9]{1,2}$'),
  iso_control_name         text NOT NULL CHECK (btrim(iso_control_name) <> ''),
  iso_source_url           text NOT NULL CHECK (iso_source_url LIKE 'https://%'),
  cis_version              text NOT NULL CHECK (btrim(cis_version) <> ''),
  cis_safeguard_id         text NOT NULL CHECK (cis_safeguard_id ~ '^(?:[1-9]|1[0-8])\.[0-9]{1,2}$'),
  cis_safeguard_name       text NOT NULL CHECK (btrim(cis_safeguard_name) <> ''),
  cis_source_url           text NOT NULL CHECK (cis_source_url LIKE 'https://%'),
  CHECK (
    (attack_technique_id IS NOT NULL AND attack_technique_name IS NOT NULL
      AND btrim(attack_technique_name) <> ''
      AND attack_unmapped_reason IS NULL)
    OR
    (attack_technique_id IS NULL AND attack_technique_name IS NULL
      AND attack_unmapped_reason IS NOT NULL AND btrim(attack_unmapped_reason) <> '')
  )
);

COMMENT ON TABLE scoring_rule_framework_mappings IS
  'Mapeo global por código de regla. Contiene identificadores, nombres breves propios y fuentes, no textos copiados de ISO o CIS. El uso comercial de CIS Controls requiere permiso de CIS.';
GRANT SELECT ON scoring_rule_framework_mappings TO cirdan_app;

INSERT INTO scoring_rule_framework_mappings (
  rule_code, attack_version, attack_technique_id, attack_technique_name, attack_source_url, attack_unmapped_reason,
  iso_version, iso_control_id, iso_control_name, iso_source_url,
  cis_version, cis_safeguard_id, cis_safeguard_name, cis_source_url
) VALUES
  ('breach_exposure', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La exposición en una brecha no demuestra que se haya usado una técnica adversaria.',
   'ISO/IEC 27001:2022', 'A.5.17', 'Protección de credenciales', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '5.2', 'Contraseñas únicas', 'https://www.cisecurity.org/controls/v8-1'),
  ('cert_expired', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Un certificado vencido describe una debilidad de configuración, no una técnica ejecutada.',
   'ISO/IEC 27001:2022', 'A.8.24', 'Protección criptográfica', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '12.6', 'Comunicaciones seguras', 'https://www.cisecurity.org/controls/v8-1'),
  ('outdated_software', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'El software sin soporte no demuestra explotación ni una técnica adversaria.',
   'ISO/IEC 27001:2022', 'A.8.8', 'Gestión de vulnerabilidades', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '2.2', 'Software con soporte', 'https://www.cisecurity.org/controls/v8-1'),
  ('exposed_rdp', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Un servicio RDP expuesto no demuestra que un adversario haya accedido a él.',
   'ISO/IEC 27001:2022', 'A.8.20', 'Seguridad de redes', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '4.4', 'Cortafuegos en servidores', 'https://www.cisecurity.org/controls/v8-1'),
  ('dmarc_missing', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La ausencia de DMARC describe una debilidad preventiva, no una técnica de suplantación observada.',
   'ISO/IEC 27001:2022', 'A.5.14', 'Transferencia segura de información', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '9.5', 'Autenticidad del correo del dominio', 'https://www.cisecurity.org/controls/v8-1'),
  ('spf_missing', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La ausencia de SPF describe una debilidad preventiva, no una técnica de suplantación observada.',
   'ISO/IEC 27001:2022', 'A.5.14', 'Transferencia segura de información', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '9.5', 'Autenticidad del correo del dominio', 'https://www.cisecurity.org/controls/v8-1'),
  ('lookalike_domain', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Un dominio parecido es un indicador potencial; no confirma una técnica adversaria.',
   'ISO/IEC 27001:2022', 'A.5.7', 'Inteligencia de amenazas', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '7.1', 'Proceso de gestión de vulnerabilidades', 'https://www.cisecurity.org/controls/v8-1'),
  ('cert_expiring_soon', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Un certificado próximo a vencer describe mantenimiento pendiente, no una técnica ejecutada.',
   'ISO/IEC 27001:2022', 'A.8.24', 'Protección criptográfica', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '12.6', 'Comunicaciones seguras', 'https://www.cisecurity.org/controls/v8-1'),
  ('domain_expiring_soon', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Un registro próximo a vencer no demuestra toma ni uso adversario del dominio.',
   'ISO/IEC 27001:2022', 'A.8.21', 'Seguridad de servicios de red', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '1.1', 'Inventario de activos de la empresa', 'https://www.cisecurity.org/controls/v8-1'),
  ('spf_allow_all', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Una política SPF permisiva describe una debilidad preventiva, no una técnica observada.',
   'ISO/IEC 27001:2022', 'A.5.14', 'Transferencia segura de información', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '9.5', 'Autenticidad del correo del dominio', 'https://www.cisecurity.org/controls/v8-1'),
  ('dmarc_policy_none', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Una política DMARC de solo observación no demuestra una técnica adversaria.',
   'ISO/IEC 27001:2022', 'A.5.14', 'Transferencia segura de información', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '9.5', 'Autenticidad del correo del dominio', 'https://www.cisecurity.org/controls/v8-1'),
  ('secret_in_public_repo', 'Enterprise v19', 'T1552.001', 'Credenciales en archivos',
   'https://attack.mitre.org/techniques/T1552/001/', NULL,
   'ISO/IEC 27001:2022', 'A.8.4', 'Protección del código fuente', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '16.12', 'Revisiones de seguridad en el código', 'https://www.cisecurity.org/controls/v8-1'),
  ('email_in_public_commits', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La publicación de una dirección de correo no demuestra una técnica adversaria.',
   'ISO/IEC 27001:2022', 'A.5.34', 'Protección de datos personales', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '3.3', 'Restricción de acceso a datos', 'https://www.cisecurity.org/controls/v8-1'),
  ('breach_exposure_old', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La antigüedad de una brecha no demuestra el uso actual de credenciales ni una técnica ejecutada.',
   'ISO/IEC 27001:2022', 'A.5.17', 'Protección de credenciales', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '5.2', 'Contraseñas únicas', 'https://www.cisecurity.org/controls/v8-1'),
  ('breach_exposure_no_passwords', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La brecha no contiene credenciales de acceso y no demuestra una técnica adversaria.',
   'ISO/IEC 27001:2022', 'A.5.34', 'Protección de datos personales', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '3.3', 'Restricción de acceso a datos', 'https://www.cisecurity.org/controls/v8-1'),
  ('personal_email_exposed', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La exposición de una dirección no demuestra su uso en una técnica adversaria.',
   'ISO/IEC 27001:2022', 'A.5.34', 'Protección de datos personales', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '3.3', 'Restricción de acceso a datos', 'https://www.cisecurity.org/controls/v8-1'),
  ('email_pattern_exposed', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Un patrón de correo inferible no demuestra que se haya ejecutado una técnica adversaria.',
   'ISO/IEC 27001:2022', 'A.5.34', 'Protección de datos personales', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '3.3', 'Restricción de acceso a datos', 'https://www.cisecurity.org/controls/v8-1'),
  ('exposed_remote_admin', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La exposición de una herramienta de administración remota no demuestra su uso por un adversario.',
   'ISO/IEC 27001:2022', 'A.8.20', 'Seguridad de redes', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '4.4', 'Cortafuegos en servidores', 'https://www.cisecurity.org/controls/v8-1'),
  ('exposed_file_sharing', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Un puerto de archivos expuesto no demuestra que un adversario lo haya usado.',
   'ISO/IEC 27001:2022', 'A.8.20', 'Seguridad de redes', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '4.4', 'Cortafuegos en servidores', 'https://www.cisecurity.org/controls/v8-1'),
  ('exposed_database', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Una base de datos expuesta no demuestra acceso ni exfiltración por un adversario.',
   'ISO/IEC 27001:2022', 'A.8.3', 'Restricción de acceso a información', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '3.3', 'Restricción de acceso a datos', 'https://www.cisecurity.org/controls/v8-1'),
  ('exposed_ot_device', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La exposición de un equipo OT no demuestra una técnica ejecutada contra él.',
   'ISO/IEC 27001:2022', 'A.8.20', 'Seguridad de redes', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '12.2', 'Arquitectura de red segura', 'https://www.cisecurity.org/controls/v8-1'),
  ('exposed_iot_device', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La exposición de un dispositivo conectado no demuestra su uso por un adversario.',
   'ISO/IEC 27001:2022', 'A.8.20', 'Seguridad de redes', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '4.7', 'Gestión de cuentas predeterminadas', 'https://www.cisecurity.org/controls/v8-1'),
  ('exposed_service', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Un servicio expuesto no demuestra que se haya usado en una técnica adversaria.',
   'ISO/IEC 27001:2022', 'A.8.20', 'Seguridad de redes', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '4.8', 'Desactivación de servicios innecesarios', 'https://www.cisecurity.org/controls/v8-1'),
  ('known_vulnerability', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La detección de una vulnerabilidad conocida no demuestra su explotación.',
   'ISO/IEC 27001:2022', 'A.8.8', 'Gestión de vulnerabilidades', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '7.6', 'Escaneo de activos expuestos', 'https://www.cisecurity.org/controls/v8-1'),
  ('server_version_disclosed', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La divulgación de una versión describe información disponible, no una técnica adversaria ejecutada.',
   'ISO/IEC 27001:2022', 'A.8.9', 'Gestión segura de configuración', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '4.1', 'Proceso de configuración segura', 'https://www.cisecurity.org/controls/v8-1'),
  ('public_bucket', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La configuración pública del almacenamiento no demuestra que un adversario haya accedido a los datos.',
   'ISO/IEC 27001:2022', 'A.8.3', 'Restricción de acceso a información', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '3.3', 'Restricción de acceso a datos', 'https://www.cisecurity.org/controls/v8-1'),
  ('subdomain_takeover_risk', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'Un posible subdominio abandonado no demuestra que haya sido tomado por un adversario.',
   'ISO/IEC 27001:2022', 'A.8.9', 'Gestión segura de configuración', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '1.1', 'Inventario de activos de la empresa', 'https://www.cisecurity.org/controls/v8-1'),
  ('exposed_api_docs', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La documentación accesible no demuestra que se haya ejecutado una técnica contra la API.',
   'ISO/IEC 27001:2022', 'A.8.3', 'Restricción de acceso a información', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '16.10', 'Principios de diseño seguro', 'https://www.cisecurity.org/controls/v8-1'),
  ('api_auth_not_declared', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/techniques/enterprise/',
   'La documentación sin declaración de autenticación no demuestra que el acceso esté desprotegido ni que se haya abusado de él.',
   'ISO/IEC 27001:2022', 'A.8.3', 'Restricción de acceso a información', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '6.8', 'Control de acceso por funciones', 'https://www.cisecurity.org/controls/v8-1'),
  ('secret_in_container_image', 'Enterprise v19', 'T1552.001', 'Credenciales en archivos',
   'https://attack.mitre.org/techniques/T1552/001/', NULL,
   'ISO/IEC 27001:2022', 'A.8.4', 'Protección del código fuente', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '16.12', 'Revisiones de seguridad en el código', 'https://www.cisecurity.org/controls/v8-1')
ON CONFLICT (rule_code) DO NOTHING;

DO $$
DECLARE
  faltantes text[];
BEGIN
  SELECT array_agg(t.code ORDER BY t.code)
    INTO faltantes
    FROM scoring_rule_texts t
    LEFT JOIN scoring_rule_framework_mappings m ON m.rule_code = t.code
   WHERE m.rule_code IS NULL;
  IF faltantes IS NOT NULL THEN
    RAISE EXCEPTION 'Faltan mapeos a marcos para reglas: %', faltantes;
  END IF;
END $$;

COMMIT;
