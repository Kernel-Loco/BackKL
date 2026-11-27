-- =====================================================================
-- Cirdan · db/migraciones/036_bitacora_ip_y_hora.sql (#176, RC-294)
-- La IP de cada evento de audit_log entra en la cadena de hashes, y la app
-- ya no fija la hora ni los campos de la cadena.
-- Lo que llega aquí:
-- 1. audit_log suma chain_version, la versión de la fórmula del row_hash de
--    esa fila. Las filas que ya existen quedan en 1 y siguen verificando
--    con la fórmula de la 001. Las nuevas quedan en 2: el trigger la fija
--    siempre, llegue lo que llegue.
-- 2. audit_log_chain() calcula la versión 2: la de la 001 más la versión
--    al principio y ip_address (como texto de inet, con su máscara) antes
--    de details. Con los triggers apagados, cambiar la IP de una fila de la
--    versión 2 rompe la verificación, y pasarla a la versión 1 también,
--    porque su row_hash se calculó con la fórmula 2.
-- 3. cirdan_app pierde el INSERT de toda la tabla (001:621) y queda con
--    INSERT solo en las columnas que manda audit() (cirdan/db.py):
--    organization_id, actor_type, actor_user_id, action, entity_type,
--    entity_id, ip_address y details. Sin occurred_at la app no puede fechar
--    un evento en el pasado, y sin id, chain_seq, prev_hash, row_hash,
--    chain_version ni created_at no toca la cadena. postgres sigue fijando
--    occurred_at, como la semilla 001 de demo.
-- La verificación (cirdan/bitacora.py, RC-130) sigue el orden de chain_seq
-- y no revisa el orden de las horas: una hora fuera de orden por
-- milisegundos, porque el DEFAULT clock_timestamp() se toma antes del
-- candado del trigger, no la da por rota.
-- Corre en una sola transacción y se puede correr otra vez sin error.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

-- Los ALTER de audit_log toman ACCESS EXCLUSIVE: si la API la tiene ocupada, falla en 5 s sin cambiar nada y se
-- vuelve a correr, en vez de dejar esperando a cada evento (como la 017).
SET LOCAL lock_timeout = '5s';

-- DEFAULT 1 al agregarla: las filas que ya existen quedan con la fórmula de la 001, sin reescribir la tabla (el
-- trigger de solo inserción no corre). Después el DEFAULT pasa a 2, aunque el trigger la fija igual.
ALTER TABLE public.audit_log ADD COLUMN IF NOT EXISTS chain_version smallint NOT NULL DEFAULT 1;
ALTER TABLE public.audit_log ALTER COLUMN chain_version SET DEFAULT 2;
ALTER TABLE public.audit_log DROP CONSTRAINT IF EXISTS audit_log_chain_version_check;
ALTER TABLE public.audit_log ADD CONSTRAINT audit_log_chain_version_check CHECK (chain_version IN (1, 2));

COMMENT ON COLUMN public.audit_log.chain_version IS
  'RC-294: versión de la fórmula del row_hash. 1 = la de la 001, sin ip_address (las filas de antes de la 036). 2 = la versión, los campos de la 001 e ip_address. La fija audit_log_chain().';

CREATE OR REPLACE FUNCTION public.audit_log_chain() RETURNS trigger
LANGUAGE plpgsql SET TimeZone = 'UTC' AS $$
DECLARE
  v_seq  bigint;
  v_prev bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(coalesce(NEW.organization_id::text, 'platform'), 0));
  SELECT chain_seq, row_hash INTO v_seq, v_prev
    FROM audit_log
   WHERE organization_id IS NOT DISTINCT FROM NEW.organization_id
   ORDER BY chain_seq DESC LIMIT 1;
  NEW.chain_seq     := coalesce(v_seq, 0) + 1;
  NEW.prev_hash     := coalesce(v_prev, decode(repeat('00', 32), 'hex'));
  NEW.chain_version := 2;
  NEW.row_hash      := sha256(NEW.prev_hash || convert_to(concat_ws(chr(31),
                         NEW.chain_version::text,
                         coalesce(NEW.organization_id::text, ''), NEW.chain_seq::text, NEW.id::text,
                         (extract(epoch FROM NEW.occurred_at) * 1000000)::bigint::text,
                         NEW.actor_type, coalesce(NEW.actor_user_id::text, ''), coalesce(NEW.actor_api_key_id::text, ''),
                         NEW.action, coalesce(NEW.entity_type, ''), coalesce(NEW.entity_id::text, ''),
                         coalesce(NEW.ip_address::text, ''),
                         NEW.details::text), 'UTF8'));
  RETURN NEW;
END $$;

COMMENT ON FUNCTION public.audit_log_chain() IS
  'Cadena de hashes por organización (NULL = plataforma). Desde la 036 (RC-294) calcula la versión 2 del row_hash, con chain_version e ip_address. La misma fórmula está en cirdan/bitacora.py (HASH_FILA) y en pruebas/test_superadmin.py (CADENA): si cambia aquí, cambia allá.';

REVOKE INSERT ON public.audit_log FROM cirdan_app;
GRANT INSERT (organization_id, actor_type, actor_user_id, action, entity_type, entity_id, ip_address, details)
  ON public.audit_log TO cirdan_app;

COMMIT;
