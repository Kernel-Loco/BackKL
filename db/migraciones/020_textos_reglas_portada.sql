-- =====================================================================
-- Cirdan · db/migraciones/020_textos_reglas_portada.sql (#111, RC-228)
-- Textos, firma y mapeo a marcos de las dos reglas que da la portada de
-- la visita web (cirdan/recolectores/portada.py), con la misma página que
-- ya baja la visita, sin ninguna petición nueva:
--   directory_listing (medium): la página es un listado de directorio de
--     Apache, nginx, lighttpd o IIS. CWE-548.
--   debug_page_exposed (high): la página es una página de depuración de
--     Django, Werkzeug, Laravel, Symfony, ASP.NET o PHP. CWE-215.
-- Las reglas van en la semilla 021, que se aplica DESPUÉS de esta
-- migración: la FK de scoring_rules.code pide que el texto exista, y el
-- juego v1 lo crea la semilla 001, que se carga después de las
-- migraciones (db/init/cargar_cirdan.sh). Así lo pide docs/codigos_reglas.md
-- (Cómo agregar un código).
-- El texto y su mapeo van en la misma transacción, en ese orden: la FK
-- diferida de la 012 revisa en el COMMIT que todo texto tenga su mapeo.
-- Los textos los firma ErnestoDL, que los revisó en el PR de RC-228.
-- ATT&CK: directory_listing va sin técnica, como exposed_api_docs, porque
-- ninguna técnica de Enterprise v19 nombra un listado de carpetas.
-- debug_page_exposed va con T1592.002, como server_version_disclosed: la
-- página dice qué programas y versiones usa el sitio.
-- Se puede correr otra vez: los INSERT no tocan lo que ya está. El UPDATE
-- de la firma vuelve a poner ErnestoDL: no la corras otra vez si una
-- migración posterior cambió el texto con otra firma.
-- =====================================================================

-- Los textos llevan acentos y se guardan en UTF8, aunque psql corra en una
-- consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO scoring_rule_texts (code, title, meaning, recommendation) VALUES
 ('directory_listing', 'El sitio muestra la lista de sus archivos', 'La página principal del sitio es una lista de los archivos y carpetas que guarda su servidor, en vez de una página hecha para los visitantes. Cualquiera puede ver y bajar esos archivos, también copias de respaldo o configuraciones que no deberían estar a la vista.', 'Desactiva el listado de carpetas en el servidor del sitio y pon una página de inicio. Revisa qué archivos quedaron a la vista y quita los que no deban ser públicos.'),
 ('debug_page_exposed', 'El sitio muestra una página de errores para programadores', 'El sitio está en modo de pruebas y, cuando algo falla, muestra el detalle técnico del error con partes de su código, rutas internas y versiones de sus programas. Un atacante usa ese detalle para entender cómo está hecho el sitio y preparar un ataque.', 'Apaga el modo de pruebas del sitio y muestra una página de error sencilla. Revisa si el detalle que se mostró dejó ver contraseñas o llaves y cámbialas.')
ON CONFLICT (code) DO NOTHING;

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'directory_listing';

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'debug_page_exposed';

INSERT INTO scoring_rule_framework_mappings (
  rule_code, attack_version, attack_technique_id, attack_technique_name, attack_source_url, attack_unmapped_reason,
  iso_version, iso_control_id, iso_control_name, iso_source_url,
  cis_version, cis_safeguard_id, cis_safeguard_name, cis_source_url
) VALUES
  ('directory_listing', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
   'Ninguna técnica de ATT&CK nombra el listado de las carpetas de un sitio como algo que un adversario busca o usa.',
   'ISO/IEC 27001:2022', 'A.8.9', 'Gestión segura de configuración', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '4.1', 'Proceso de configuración segura', 'https://www.cisecurity.org/controls/v8-1'),
  ('debug_page_exposed', 'Enterprise v19', 'T1592.002', 'Recopilar el software de la víctima',
   'https://attack.mitre.org/versions/v19/techniques/T1592/002/', NULL,
   'ISO/IEC 27001:2022', 'A.8.31', 'Separación de entornos de desarrollo, prueba y producción',
   'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '16.8', 'Separación de sistemas de producción y no producción',
   'https://www.cisecurity.org/controls/v8-1')
ON CONFLICT (rule_code) DO NOTHING;

COMMIT;
