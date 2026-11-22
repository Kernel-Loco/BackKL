-- =====================================================================
-- Cirdan · db/migraciones/022_texto_enlaces_nube_repos.sql (RC-247)
-- Texto, firma y mapeo a marcos de la regla file_share_link_in_repo del
-- recolector de GitHub (#16, cirdan/recolectores/github.py): un enlace
-- para compartir de Google Drive, OneDrive o SharePoint, o Dropbox, en
-- un repo público de la organización declarada. Lo reconocen las reglas
-- cirdan-enlace-* de gitleaks_cirdan.toml solo por su forma: nada abre,
-- sigue ni valida el enlace, y la evidencia no lo guarda.
-- La regla de scoring_rules va en la semilla 023, que necesita esta
-- migración antes (la FK de scoring_rules.code a scoring_rule_texts).
-- El texto y su mapeo entran en la misma transacción por la FK diferida
-- de la 012. El texto lo revisa y lo firma ErnestoDL.
-- Mapeo: ATT&CK T1593.003, como secret_in_public_repo después de la
-- 012 (quien ataca busca en los repos de código públicos), e ISO/IEC
-- 27001:2022 A.8.3 y CIS Controls v8.1 3.3, como public_bucket (el
-- enlace da acceso a los archivos sin pedir cuenta).
-- Se puede correr otra vez sin error: lo que ya está no cambia, pero
-- vuelve a mover updated_at del texto. Si el texto guardado no es el de
-- esta migración o lo firmó otra persona, se detiene sin firmar.
-- En una base que ya existe se aplica a mano antes de la semilla 023 y
-- antes de reconstruir la API (ver db/README.md).
-- =====================================================================

-- El texto lleva acentos, aunque psql corra en una consola con otra
-- página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO scoring_rule_texts (code, title, meaning, recommendation) VALUES
 ('file_share_link_in_repo',
  'Un repositorio público de la empresa guarda un enlace para compartir archivos de la nube',
  'Un repositorio público de la empresa en GitHub guarda, en su versión actual o en su historial, un enlace para compartir archivos o carpetas de un servicio en la nube como Google Drive o Dropbox, y muchos de esos enlaces dejan abrir o bajar los archivos a quien tenga el enlace, sin cuenta y sin que nadie lo apruebe. La revisión solo reconoce la forma del enlace y nunca lo abre, así que no sabe qué hay detrás ni si todavía funciona.',
  'Pide a quien publicó el enlace que revise a dónde lleva y quién puede abrirlo y, si no tiene que ser público, que le quite el acceso o lo borre en el servicio y comparta los archivos solo con quien los necesita. Quitar el enlace del repositorio no basta, porque sigue en el historial y alguien pudo copiarlo.')
ON CONFLICT (code) DO NOTHING;

-- Antes de firmar, como la 006: el texto tiene que ser el de esta
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
      ('file_share_link_in_repo', '232e56a7d96729a11d1d43abd6739030', 'ErnestoDL')
    ) AS e(code, texto, revisor)
    LEFT JOIN scoring_rule_texts t ON t.code = e.code;
  IF distintos IS NOT NULL THEN
    RAISE EXCEPTION 'Este texto no es el de la 022, o ya lo firmó otra persona: %. Revísalo antes de firmar.', distintos;
  END IF;
END $$;

UPDATE scoring_rule_texts SET reviewed_by = 'ErnestoDL', updated_at = now() WHERE code = 'file_share_link_in_repo';

INSERT INTO scoring_rule_framework_mappings (
  rule_code, attack_version, attack_technique_id, attack_technique_name, attack_source_url, attack_unmapped_reason,
  iso_version, iso_control_id, iso_control_name, iso_source_url,
  cis_version, cis_safeguard_id, cis_safeguard_name, cis_source_url
) VALUES
  ('file_share_link_in_repo', 'Enterprise v19', 'T1593.003', 'Buscar en repositorios de código públicos',
   'https://attack.mitre.org/versions/v19/techniques/T1593/003/', NULL,
   'ISO/IEC 27001:2022', 'A.8.3', 'Restricción de acceso a información', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '3.3', 'Restricción de acceso a datos', 'https://www.cisecurity.org/controls/v8-1')
ON CONFLICT (rule_code) DO NOTHING;

COMMIT;
