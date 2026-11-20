-- =====================================================================
-- Cirdan · db/migraciones/026_tipo_activo_perfil.sql (#20, RC-56)
-- Agrega el tipo de activo 'profile' al CHECK de assets.asset_type: un
-- perfil público ligado a la empresa (GitHub, GitLab, LinkedIn, X,
-- Facebook, Instagram, YouTube o TikTok), enlazado desde un sitio del
-- dominio o de un usuario de GitHub con commits firmados con un correo
-- del dominio. Lo guarda la fuente identity
-- (cirdan/recolectores/identidad.py) con la URL https del perfil como
-- valor.
--
-- Solo cambia el CHECK: las filas que ya están cumplen el nuevo, que
-- acepta los siete tipos de antes y uno más. Va en una sola transacción,
-- así la tabla nunca queda sin su CHECK. Va ANTES que la semilla 026 y
-- antes de reconstruir la API: sin esta migración, guardar un 'profile'
-- falla por el CHECK y el escaneo queda failed.
--
-- Se puede correr otra vez sin error: quita el CHECK si está y lo pone
-- de nuevo con los ocho tipos.
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
  CHECK (asset_type IN ('domain','subdomain','ip','service','certificate','email','api_doc','profile'));

COMMENT ON COLUMN assets.asset_type IS 'Tipo de activo: domain, subdomain, ip, service, certificate, email, api_doc o profile (026: un perfil público ligado a la empresa, con su URL https en value).';
COMMENT ON TABLE assets IS 'Inventario normalizado de la superficie expuesta: dominio, subdominios, IP, servicios, certificados, correos, documentos de API y perfiles públicos (026).';

COMMIT;
