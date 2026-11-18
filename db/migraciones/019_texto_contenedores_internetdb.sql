-- =====================================================================
-- Cirdan · db/migraciones/019_texto_contenedores_internetdb.sql (#17, RC-224)
-- Texto, firma y mapeo a marcos de la regla exposed_container_api (high),
-- que da Shodan InternetDB (cirdan/recolectores/shodan.py) cuando una IP
-- del dominio tiene abierto un puerto de los que suelen usar Docker (2375 y
-- 2376), etcd (2379 y 2380), Kubernetes (6443) o kubelet (10250 y 10255).
-- Sale de la misma consulta pasiva de siempre, sin ninguna petición nueva.
-- InternetDB no dice si el servicio pide autenticación: por eso el texto
-- dice 'puede permitir' y no 'permite'.
-- La regla va en la semilla 020, que se aplica DESPUÉS de esta migración:
-- la FK de scoring_rules.code pide que el texto exista, y el juego v1 lo
-- crea la semilla 001, que se carga después de las migraciones
-- (db/init/cargar_cirdan.sh). Así lo pide docs/codigos_reglas.md (Cómo
-- agregar un código).
-- El texto y su mapeo van en la misma transacción, en ese orden: la FK
-- diferida de la 012 revisa en el COMMIT que todo texto tenga su mapeo.
-- El texto lo firma ErnestoDL, que lo revisó en el PR de RC-224.
-- ATT&CK: T1133, como exposed_remote_admin. La descripción de la técnica
-- en Enterprise v19 nombra la API de Docker, el servidor de la API de
-- Kubernetes y el kubelet expuestos como servicios remotos que un
-- adversario usa para entrar.
-- Se puede correr otra vez: los INSERT no tocan lo que ya está. El UPDATE
-- de la firma vuelve a poner ErnestoDL: no la corras otra vez si una
-- migración posterior cambió el texto con otra firma.
-- =====================================================================

-- El texto lleva acentos y se guarda en UTF8, aunque psql corra en una
-- consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

INSERT INTO scoring_rule_texts (code, title, meaning, recommendation) VALUES
 ('exposed_container_api', 'Puerto para manejar contenedores abierto a internet', 'Según un buscador público de equipos en internet, un equipo de la empresa tenía abierto un puerto de los que suelen usar Docker o Kubernetes para manejar sus contenedores y guardar su configuración. Si de verdad es uno de esos servicios y no pide verificar quién entra, puede permitir que alguien de fuera tome el control de los contenedores o lea las claves que guardan.', 'Pide a tu proveedor de sistemas que cierre ese puerto a internet y deje que solo lo usen los equipos de la empresa que lo necesitan. Confirma con quien administra esos servicios que pidan un certificado o una contraseña para entrar.')
ON CONFLICT (code) DO NOTHING;

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'exposed_container_api';

INSERT INTO scoring_rule_framework_mappings (
  rule_code, attack_version, attack_technique_id, attack_technique_name, attack_source_url, attack_unmapped_reason,
  iso_version, iso_control_id, iso_control_name, iso_source_url,
  cis_version, cis_safeguard_id, cis_safeguard_name, cis_source_url
) VALUES
  ('exposed_container_api', 'Enterprise v19', 'T1133', 'Servicios remotos externos',
   'https://attack.mitre.org/versions/v19/techniques/T1133/', NULL,
   'ISO/IEC 27001:2022', 'A.8.20', 'Seguridad de redes', 'https://www.iso.org/standard/27001',
   'CIS Controls v8.1', '4.4', 'Cortafuegos en servidores', 'https://www.cisecurity.org/controls/v8-1')
ON CONFLICT (rule_code) DO NOTHING;

COMMIT;
