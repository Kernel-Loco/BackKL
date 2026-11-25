-- =====================================================================
-- Cirdan · db/migraciones/023_texto_ia_internetdb.sql (#144, RC-262)
-- Texto, firma y mapeo a marcos de la regla exposed_ai_service (high),
-- que da Shodan InternetDB (cirdan/recolectores/shodan.py) cuando una IP
-- del dominio tiene abierto un puerto por omisión de un servidor de modelos,
-- una interfaz o una base de vectores de inteligencia artificial: Ollama
-- (11434), LM Studio (1234), Gradio (7860), ComfyUI (8188), Ray Dashboard
-- (8265), Qdrant (6333 y 6334) o Milvus (19530).
-- Sale de la misma consulta pasiva de siempre, sin ninguna petición nueva.
-- InternetDB no dice si el servicio pide autenticación ni qué responde:
-- por eso el texto dice 'puede permitir' y no 'permite'.
-- La regla va en la semilla 024, que se aplica DESPUÉS de esta migración:
-- la FK de scoring_rules.code pide que el texto exista, y el juego v1 lo
-- crea la semilla 001, que se carga después de las migraciones
-- (db/init/cargar_cirdan.sh). Así lo pide docs/codigos_reglas.md (Cómo
-- agregar un código).
-- El texto y su mapeo van en la misma transacción, en ese orden: la FK
-- diferida de la 012 revisa en el COMMIT que todo texto tenga su mapeo.
-- El texto lo firma ErnestoDL, que lo revisó en el PR de RC-262.
-- ATT&CK: sin técnica, como exposed_database y exposed_service. Un puerto
-- abierto no demuestra que un adversario lo haya usado, y ATT&CK
-- Enterprise v19 no tiene una técnica para servicios de inteligencia
-- artificial expuestos. ISO A.8.20 y CIS 4.4, como exposed_container_api.
-- Se puede correr otra vez sin error: lo que ya está no cambia, pero
-- vuelve a mover updated_at del texto. Si el texto guardado no es el de
-- esta migración o lo firmó otra persona, se detiene sin firmar.
-- =====================================================================

-- El texto lleva acentos y se guarda en UTF8, aunque psql corra en una
-- consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO scoring_rule_texts (code, title, meaning, recommendation) VALUES
 ('exposed_ai_service', 'Servicio de inteligencia artificial abierto a internet', 'Según un buscador público de equipos en internet, un equipo de la empresa tenía abierto un puerto de los que suelen usar los servidores de modelos de inteligencia artificial, sus pantallas de prueba o sus bases de datos, como Ollama o Qdrant. Varios de esos servicios no piden verificar quién entra si nadie lo configura, y entonces puede permitir que alguien de fuera use los modelos a costa de la empresa o lea los datos que guardan.', 'Pide a tu proveedor de sistemas que cierre ese puerto a internet y deje que solo lo usen los equipos de la empresa que lo necesitan. Confirma con quien administra ese servicio que pida una contraseña o una llave para entrar.')
ON CONFLICT (code) DO NOTHING;

-- Antes de firmar, como la 021: el texto tiene que ser el de esta
-- migración (si ya había otro, el INSERT de arriba no lo cambió) y no
-- puede estar firmado por otra persona. El md5 es del título, qué
-- significa y qué hacer, separados por un salto de línea, en UTF8.
DO $$
DECLARE
  distintos text;
BEGIN
  IF current_setting('server_encoding') <> 'UTF8' THEN
    RAISE EXCEPTION 'La 023 compara el texto en UTF8 y esta base usa %.', current_setting('server_encoding');
  END IF;
  SELECT string_agg(e.code, ', ') FILTER (WHERE t.code IS NULL
           OR md5(t.title || E'\n' || t.meaning || E'\n' || t.recommendation) <> e.texto
           OR (t.reviewed_by IS NOT NULL AND t.reviewed_by IS DISTINCT FROM e.revisor))
    INTO distintos
    FROM (VALUES
      ('exposed_ai_service', 'a9ae18446bafcc72600541f750fadf9f', 'ErnestoDL')
    ) AS e(code, texto, revisor)
    LEFT JOIN scoring_rule_texts t ON t.code = e.code;
  IF distintos IS NOT NULL THEN
    RAISE EXCEPTION 'Este texto no es el de la 023, o ya lo firmó otra persona: %. Revísalo antes de firmar.', distintos;
  END IF;
END $$;

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'exposed_ai_service';

INSERT INTO scoring_rule_framework_mappings (
  rule_code, attack_version, attack_technique_id, attack_technique_name, attack_source_url, attack_unmapped_reason,
  iso_version, iso_control_id, iso_control_name, iso_source_url,
  cis_version, cis_safeguard_id, cis_safeguard_name, cis_source_url
) VALUES
  ('exposed_ai_service', 'Enterprise v19', NULL, NULL, 'https://attack.mitre.org/versions/v19/techniques/enterprise/',
   'Un servicio de inteligencia artificial expuesto no demuestra que se haya usado en una técnica adversaria.',
   'ISO/IEC 27001:2022', 'A.8.20', 'Seguridad de redes', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '4.4', 'Cortafuegos en servidores', 'https://www.cisecurity.org/controls/v8-1')
ON CONFLICT (rule_code) DO NOTHING;

COMMIT;
