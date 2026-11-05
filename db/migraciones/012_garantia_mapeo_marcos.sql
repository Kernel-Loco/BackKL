-- =====================================================================
-- Cirdan · db/migraciones/012_garantia_mapeo_marcos.sql (#68, RC-131)
-- Arreglos a scoring_rule_framework_mappings, que creó la 011. La 011 ya
-- entró a dev y no se edita.
-- 1. FK de scoring_rule_texts.code a scoring_rule_framework_mappings.
--    La 011 revisó una sola vez, al aplicarse, que todo texto tuviera su
--    mapeo. Con esta FK la base lo exige siempre: un texto nuevo (y, por
--    la FK de la 003, una regla nueva) no entra sin su mapeo, y un mapeo
--    no se borra mientras su texto exista. Sin ella, un hallazgo de una
--    regla sin mapeo hace que la API responda 500 en toda la lista de
--    hallazgos del dominio (_marcos en cirdan/api/v1.py).
--    Es DEFERRABLE INITIALLY DEFERRED porque la FK de la 011 va al revés
--    (del mapeo al texto): la migración que agregue una regla inserta el
--    texto y el mapeo en la misma transacción, en ese orden, y esta FK se
--    revisa en el COMMIT. Solo una regla que nunca se usó (sin filas en
--    findings ni en score_contributions, que no admite DELETE) se puede
--    borrar: en una sola transacción se borran sus filas de scoring_rules
--    en todos los juegos, después el mapeo y al final el texto.
--    Como las dos tablas se apuntan entre sí, un respaldo con --data-only
--    ya no se restaura sin --disable-triggers. Se respalda la base
--    completa con pg_dump -Fc.
-- 2. created_at y updated_at en el mapeo, como en las demás tablas
--    (convención 10 de db/README.md). En las 30 filas de la 011 quedan con
--    la hora en que se aplica esta migración, no con la de la 011.
-- 3. Correcciones del mapeo de la 011, con UPDATE por código y
--    updated_at = now(), sin tocar rule_code ni created_at ni las versiones:
--    - ATT&CK: una técnica va solo cuando la relación es directa, es decir,
--      cuando la descripción de la técnica en ATT&CK Enterprise v19 nombra
--      lo que detecta la regla como lo que un adversario busca, adquiere o
--      usa. Si no, va sin técnica y la razón dice que ninguna la nombra.
--      Quedan 25 reglas con técnica y 5 sin ella. Las 5 de puertos abiertos
--      (servicios, bases de datos, archivos compartidos y equipos IoT y OT)
--      van con T1596.005, que nombra los puertos abiertos y los banners que
--      un adversario busca en las bases de escaneos públicas.
--    - Los enlaces de ATT&CK van fijos a la v19 (/versions/v19/), a la
--      técnica o a la lista de técnicas de Enterprise, así muestran la
--      versión que dice attack_version y no la vigente del sitio.
--    - ISO y CIS: el control que corresponde a lo que pide el texto de la
--      regla en 10 reglas (certificados, correos, dominio por vencer,
--      dominio parecido, subdominio que otra persona podría tomar y clave en
--      una imagen de contenedor), con 11 cambios: 2 de ISO y 9 de CIS.
--    - El comentario de la tabla dice lo que de verdad guarda.
--    Cada UPDATE solo toca las filas que siguen con el valor de la 011: en
--    ATT&CK, las que tienen un enlace sin /versions/, y en ISO y CIS, las
--    que tienen el control de la 011. Si se vuelve a correr no encuentra
--    ninguna y no mueve updated_at, y tampoco deshace una migración
--    posterior que cambie el mapeo (por ejemplo, la que pase a la v20).
-- Necesita la 011. No agrega tablas, índices, triggers ni políticas:
-- solo una FK (60 en total).
-- Corre en una sola transacción y se puede correr otra vez sin error y
-- sin frenar las lecturas del mapeo. La primera vez espera a lo más 5 s
-- cada bloqueo que pide. Mientras espera el del ADD COLUMN, las lecturas
-- nuevas del mapeo (y las de la API que lo leen) esperan detrás de ella,
-- también a lo más 5 s, y después hasta su COMMIT, que llega enseguida.
-- Si otra sesión tiene las tablas, falla sin cambiar nada y se vuelve a
-- correr.
-- En una base que ya existe se aplica a mano, antes de reconstruir la API
-- (ver db/README.md).
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

SET LOCAL lock_timeout = '5s';

DO $$
DECLARE
  faltantes text[];
BEGIN
  IF to_regclass('public.scoring_rule_framework_mappings') IS NULL THEN
    RAISE EXCEPTION 'Falta la migración 011: no existe scoring_rule_framework_mappings';
  END IF;
  SELECT array_agg(t.code ORDER BY t.code)
    INTO faltantes
    FROM scoring_rule_texts t
    LEFT JOIN scoring_rule_framework_mappings m ON m.rule_code = t.code
   WHERE m.rule_code IS NULL;
  IF faltantes IS NOT NULL THEN
    RAISE EXCEPTION 'Faltan mapeos a marcos para reglas: %', faltantes;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'scoring_rule_texts_mapping_fk'
                    AND conrelid = 'public.scoring_rule_texts'::regclass) THEN
    ALTER TABLE scoring_rule_texts
      ADD CONSTRAINT scoring_rule_texts_mapping_fk FOREIGN KEY (code)
      REFERENCES scoring_rule_framework_mappings (rule_code)
      DEFERRABLE INITIALLY DEFERRED;
  END IF;
  -- ADD COLUMN IF NOT EXISTS pide ACCESS EXCLUSIVE aunque la columna ya exista, así que se revisa antes.
  IF NOT EXISTS (SELECT 1 FROM pg_attribute
                  WHERE attrelid = 'public.scoring_rule_framework_mappings'::regclass
                    AND attname = 'created_at' AND NOT attisdropped) THEN
    ALTER TABLE scoring_rule_framework_mappings
      ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_attribute
                  WHERE attrelid = 'public.scoring_rule_framework_mappings'::regclass
                    AND attname = 'updated_at' AND NOT attisdropped) THEN
    ALTER TABLE scoring_rule_framework_mappings
      ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
  END IF;
END $$;

COMMENT ON CONSTRAINT scoring_rule_texts_mapping_fk ON scoring_rule_texts IS
  'Todo texto (y toda regla) tiene su mapeo a marcos (migración 012). Se revisa en el COMMIT: el texto y su mapeo entran en la misma transacción.';

COMMENT ON COLUMN scoring_rule_framework_mappings.created_at IS
  'Cuándo entró el mapeo. En las 30 filas de la 011 es la hora en que se aplicó la 012.';
COMMENT ON COLUMN scoring_rule_framework_mappings.updated_at IS
  'Cuándo cambió el mapeo por última vez. La migración que lo corrija pone updated_at = now().';

-- 3. Correcciones del mapeo de la 011. ATT&CK de las 30 reglas: técnica solo
-- si su descripción en Enterprise v19 nombra lo que detecta la regla, y el
-- enlace fijo a la v19.
UPDATE scoring_rule_framework_mappings m
   SET attack_technique_id = v.tecnica,
       attack_technique_name = v.nombre,
       attack_source_url = v.enlace,
       attack_unmapped_reason = v.razon,
       updated_at = now()
  FROM (VALUES
    ('breach_exposure', 'T1589.001', 'Recopilar credenciales de la víctima',
     'https://attack.mitre.org/versions/v19/techniques/T1589/001/', NULL),
    ('breach_exposure_old', 'T1589.001', 'Recopilar credenciales de la víctima',
     'https://attack.mitre.org/versions/v19/techniques/T1589/001/', NULL),
    ('breach_exposure_no_passwords', 'T1589.002', 'Recopilar correos de la víctima',
     'https://attack.mitre.org/versions/v19/techniques/T1589/002/', NULL),
    ('email_in_public_commits', 'T1589.002', 'Recopilar correos de la víctima',
     'https://attack.mitre.org/versions/v19/techniques/T1589/002/', NULL),
    ('personal_email_exposed', 'T1589.002', 'Recopilar correos de la víctima',
     'https://attack.mitre.org/versions/v19/techniques/T1589/002/', NULL),
    ('email_pattern_exposed', 'T1589.003', 'Recopilar nombres de empleados',
     'https://attack.mitre.org/versions/v19/techniques/T1589/003/', NULL),
    ('secret_in_public_repo', 'T1593.003', 'Buscar en repositorios de código públicos',
     'https://attack.mitre.org/versions/v19/techniques/T1593/003/', NULL),
    ('secret_in_container_image', 'T1552.001', 'Credenciales en archivos',
     'https://attack.mitre.org/versions/v19/techniques/T1552/001/', NULL),
    ('lookalike_domain', 'T1583.001', 'Adquirir dominios',
     'https://attack.mitre.org/versions/v19/techniques/T1583/001/', NULL),
    ('domain_expiring_soon', 'T1583.001', 'Adquirir dominios',
     'https://attack.mitre.org/versions/v19/techniques/T1583/001/', NULL),
    ('subdomain_takeover_risk', 'T1584.001', 'Tomar dominios o subdominios',
     'https://attack.mitre.org/versions/v19/techniques/T1584/001/', NULL),
    ('dmarc_missing', 'T1684.002', 'Suplantación de correo',
     'https://attack.mitre.org/versions/v19/techniques/T1684/002/', NULL),
    ('dmarc_policy_none', 'T1684.002', 'Suplantación de correo',
     'https://attack.mitre.org/versions/v19/techniques/T1684/002/', NULL),
    ('spf_missing', 'T1684.002', 'Suplantación de correo',
     'https://attack.mitre.org/versions/v19/techniques/T1684/002/', NULL),
    ('spf_allow_all', 'T1684.002', 'Suplantación de correo',
     'https://attack.mitre.org/versions/v19/techniques/T1684/002/', NULL),
    ('exposed_rdp', 'T1133', 'Servicios remotos externos',
     'https://attack.mitre.org/versions/v19/techniques/T1133/', NULL),
    ('exposed_remote_admin', 'T1133', 'Servicios remotos externos',
     'https://attack.mitre.org/versions/v19/techniques/T1133/', NULL),
    ('known_vulnerability', 'T1190', 'Explotar una aplicación expuesta a internet',
     'https://attack.mitre.org/versions/v19/techniques/T1190/', NULL),
    ('server_version_disclosed', 'T1592.002', 'Recopilar el software de la víctima',
     'https://attack.mitre.org/versions/v19/techniques/T1592/002/', NULL),
    ('public_bucket', 'T1530', 'Datos en almacenamiento en la nube',
     'https://attack.mitre.org/versions/v19/techniques/T1530/', NULL),
    ('cert_expired', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
     'Ninguna técnica de ATT&CK nombra un certificado vencido del sitio como algo que un adversario busca o usa.'),
    ('cert_expiring_soon', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
     'Ninguna técnica de ATT&CK nombra un certificado por vencer como algo que un adversario busca o usa.'),
    ('outdated_software', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
     'Ninguna técnica de ATT&CK nombra el software sin soporte. La explotación de una aplicación expuesta pide una falla conocida, y esa es otra regla.'),
    ('exposed_file_sharing', 'T1596.005', 'Buscar en bases de datos de escaneos',
     'https://attack.mitre.org/versions/v19/techniques/T1596/005/', NULL),
    ('exposed_database', 'T1596.005', 'Buscar en bases de datos de escaneos',
     'https://attack.mitre.org/versions/v19/techniques/T1596/005/', NULL),
    ('exposed_ot_device', 'T1596.005', 'Buscar en bases de datos de escaneos',
     'https://attack.mitre.org/versions/v19/techniques/T1596/005/', NULL),
    ('exposed_iot_device', 'T1596.005', 'Buscar en bases de datos de escaneos',
     'https://attack.mitre.org/versions/v19/techniques/T1596/005/', NULL),
    ('exposed_service', 'T1596.005', 'Buscar en bases de datos de escaneos',
     'https://attack.mitre.org/versions/v19/techniques/T1596/005/', NULL),
    ('exposed_api_docs', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
     'Ninguna técnica de ATT&CK nombra la documentación pública de una API como algo que un adversario busca o usa.'),
    ('api_auth_not_declared', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
     'Ninguna técnica de ATT&CK nombra una documentación de API que no declara su autenticación.')
  ) AS v (code, tecnica, nombre, enlace, razon)
 WHERE m.rule_code = v.code
   -- Solo las filas que siguen con el enlace de la 011, que no lleva /versions/.
   AND m.attack_source_url NOT LIKE 'https://attack.mitre.org/versions/%';

-- ISO y CIS: el control que corresponde a lo que pide el texto de la regla.
-- Cada UPDATE solo toca las filas que siguen con el control de la 011
-- (columnas _011 de VALUES).
UPDATE scoring_rule_framework_mappings m
   SET iso_control_id = v.iso,
       iso_control_name = v.nombre,
       updated_at = now()
  FROM (VALUES
    ('domain_expiring_soon', 'A.8.21', 'Seguridad de servicios de red', 'A.5.9', 'Inventario de activos'),
    ('secret_in_container_image', 'A.8.4', 'Protección del código fuente', 'A.5.17', 'Protección de credenciales')
  ) AS v (code, iso_011, nombre_011, iso, nombre)
 WHERE m.rule_code = v.code
   AND (m.iso_control_id, m.iso_control_name) = (v.iso_011, v.nombre_011);

UPDATE scoring_rule_framework_mappings m
   SET cis_safeguard_id = v.cis,
       cis_safeguard_name = v.nombre,
       updated_at = now()
  FROM (VALUES
    ('cert_expired', '12.6', 'Comunicaciones seguras', '3.10', 'Cifrado de datos en tránsito'),
    ('cert_expiring_soon', '12.6', 'Comunicaciones seguras', '3.10', 'Cifrado de datos en tránsito'),
    ('lookalike_domain', '7.1', 'Proceso de gestión de vulnerabilidades', '17.4', 'Proceso de respuesta a incidentes'),
    ('domain_expiring_soon', '1.1', 'Inventario de activos de la empresa', '15.1', 'Inventario de proveedores de servicios'),
    ('email_in_public_commits', '3.3', 'Restricción de acceso a datos', '14.2', 'Capacitación contra la ingeniería social'),
    ('breach_exposure_no_passwords', '3.3', 'Restricción de acceso a datos', '14.2', 'Capacitación contra la ingeniería social'),
    ('personal_email_exposed', '3.3', 'Restricción de acceso a datos', '14.2', 'Capacitación contra la ingeniería social'),
    ('email_pattern_exposed', '3.3', 'Restricción de acceso a datos', '14.2', 'Capacitación contra la ingeniería social'),
    ('subdomain_takeover_risk', '1.1', 'Inventario de activos de la empresa', '12.3', 'Gestión segura de la infraestructura de red')
  ) AS v (code, cis_011, nombre_011, cis, nombre)
 WHERE m.rule_code = v.code
   AND (m.cis_safeguard_id, m.cis_safeguard_name) = (v.cis_011, v.nombre_011);

COMMENT ON TABLE scoring_rule_framework_mappings IS
  'Mapeo global por código de regla a ATT&CK, ISO/IEC 27001 y CIS Controls. Guarda identificadores, un nombre breve en español (algunos coinciden con el título traducido) y la fuente, no la descripción ni el texto de ISO, CIS ni MITRE. El uso comercial de CIS Controls requiere permiso de CIS.';

COMMIT;
