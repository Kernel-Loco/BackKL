-- =====================================================================
-- Cirdan · db/semillas/003_titulos_espanol.sql (RC-17)
-- Los hallazgos de la semilla 001 traen el título en inglés (venían de Figma),
-- pero el contrato de plugin (#13) y el de API (#21) piden títulos en español.
-- Se corrigen aquí para no editar la semilla 001.
-- =====================================================================

BEGIN;

UPDATE findings SET evidence = jsonb_set(evidence, '{title}', to_jsonb(t.titulo))
  FROM (VALUES
    ('80000000-0000-4000-8000-000000000001'::uuid, '12 correos de la empresa aparecen en brechas de datos públicas'),
    ('80000000-0000-4000-8000-000000000002'::uuid, 'El subdominio dev.acme-demo.mx tiene el certificado TLS vencido'),
    ('80000000-0000-4000-8000-000000000003'::uuid, 'El sitio usa una versión vieja de su CMS con vulnerabilidades conocidas'),
    ('80000000-0000-4000-8000-000000000004'::uuid, 'Falta el registro DMARC en acme-demo.mx'),
    ('80000000-0000-4000-8000-000000000011'::uuid, 'Escritorio remoto (RDP) expuesto a internet')
  ) AS t(id, titulo)
 WHERE findings.id = t.id;

COMMIT;
