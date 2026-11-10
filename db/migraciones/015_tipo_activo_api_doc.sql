-- =====================================================================
-- Cirdan · db/migraciones/015_tipo_activo_api_doc.sql (#63, RC-118)
-- Agrega el tipo de activo 'api_doc' al CHECK de assets.asset_type: un
-- documento Swagger u OpenAPI, o la página de Swagger UI o de ReDoc, que
-- un sitio del dominio deja a la vista. Lo guarda la fuente api_docs
-- (cirdan/recolectores/api_docs.py) con la URL del documento como valor
-- y su sitio como activo padre.
--
-- Solo cambia el CHECK: las filas que ya están cumplen el nuevo, que
-- acepta los seis tipos de antes y uno más. Va en una sola transacción,
-- así la tabla nunca queda sin su CHECK. Va ANTES que la semilla 013 y
-- antes de reconstruir la API: sin esta migración, guardar un 'api_doc'
-- falla por el CHECK y el escaneo queda failed.
--
-- Se puede correr otra vez sin error: quita el CHECK si está y lo pone
-- de nuevo con los siete tipos.
-- =====================================================================
SET client_encoding = 'UTF8';
BEGIN;

-- El CHECK nuevo pide el candado exclusivo de assets y revisa sus filas.
-- Si otra sesión tiene la tabla ocupada, la migración falla a los 5 s en
-- vez de dejar formadas detrás de ella las lecturas del portal: se corre
-- otra vez más tarde.
SET LOCAL lock_timeout = '5s';

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_asset_type_check;
ALTER TABLE assets ADD CONSTRAINT assets_asset_type_check
  CHECK (asset_type IN ('domain','subdomain','ip','service','certificate','email','api_doc'));

COMMENT ON COLUMN assets.asset_type IS 'Tipo de activo: domain, subdomain, ip, service, certificate, email o api_doc (015: la documentación de un servicio web a la vista, con su URL en value).';
COMMENT ON TABLE assets IS 'Inventario normalizado de la superficie expuesta: dominio, subdominios, IP, servicios, certificados, correos y documentos de API (015).';

COMMIT;
