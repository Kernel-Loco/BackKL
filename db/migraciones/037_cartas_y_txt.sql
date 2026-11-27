-- =====================================================================
-- Cirdan · db/migraciones/037_cartas_y_txt.sql (#154, RC-272)
-- Una carta nueva revoca la anterior, una revocación no se deshace y el TXT
-- se guarda sin datos de más.
-- Lo que llega aquí:
-- 1. domain_authorizations_guard(): revoked_at solo pasa de NULL a una
--    fecha. Volver a NULL o cambiar la fecha se rechaza para todos los
--    roles. Un UPDATE que deja revoked_at igual pasa, como antes. Lo demás
--    de la carta sigue inmutable y el DELETE sigue bloqueado. La función y
--    su trigger conservan el nombre, que la semilla 027 y la 029 usan.
-- 2. domain_authorizations_una_vigente() (BEFORE INSERT): toma un candado
--    del dominio hasta el final de la transacción, así dos cartas del mismo
--    dominio se cargan una tras otra. Si la carta nueva empieza después de
--    hoy y el dominio tiene otra vigente hoy, la rechaza: la empresa la
--    carga el día que empieza (decisión 1 de Ernesto, 24 nov). Hoy es la
--    fecha de la Ciudad de México, la misma que usan la API, el
--    orquestador y el trigger de scans.
-- 3. domain_authorizations_reemplaza() (AFTER INSERT, una vez por
--    sentencia): revoca, con la hora de la carga, las cartas sin revocar del
--    mismo dominio y deja por cada una un evento authorization.superseded en
--    audit_log, con actor system y en details la carta que la reemplaza
--    (replaced_by). Esa revocación no es la de la sección 8 de la carta: no
--    dispara el borrado de su sección 6. Quien borre al revocar (RC-258) se
--    salta las cartas con ese evento. Una carta que ya venció al cargarse
--    (hoy de la Ciudad de México) no revoca nada. Dos cartas sin revocar del
--    mismo dominio en una sola sentencia se rechazan: si no, cada una
--    revocaría a la otra y el dominio se quedaría sin carta. Corre como
--    quien inserta y con RLS, así que solo toca cartas de su empresa.
-- 4. dns_txt_verifications.observed_values solo guarda valores
--    cirdan-verification=<token en hex> y, de cualquier otro TXT, su huella
--    sha256:<64 hex> del texto en UTF-8. Un CHECK con
--    txt_observados_validos() rechaza cualquier otro valor. El orquestador
--    filtra antes de insertar (cirdan/orquestador/txt.py, guardables) y el
--    alta ya guardaba solo el valor esperado.
-- 5. Las filas que ya existen en dns_txt_verifications se reescriben con el
--    mismo filtro y en el mismo orden (decisión 2 de Ernesto, 24 nov): es la
--    única vez que se apaga su trigger de solo inserción, dentro de esta
--    transacción. result, checked_at y lo demás no cambian, así que 'match',
--    'mismatch' y 'missing' siguen igual.
-- Corre en una sola transacción y se puede correr otra vez sin error.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

SET client_encoding = 'UTF8';

BEGIN;

-- Los ALTER de las dos tablas toman candados fuertes: si la API las tiene ocupadas, falla en 5 s sin cambiar nada y
-- se vuelve a correr (como la 017).
SET LOCAL lock_timeout = '5s';

-- 1. Una revocación no se deshace -----------------------------------------

CREATE OR REPLACE FUNCTION public.domain_authorizations_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND (to_jsonb(NEW) - 'revoked_at') = (to_jsonb(OLD) - 'revoked_at') THEN
    IF OLD.revoked_at IS NULL OR NEW.revoked_at IS NOT DISTINCT FROM OLD.revoked_at THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'domain_authorizations: una revocación no se deshace ni cambia de fecha'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RAISE EXCEPTION 'domain_authorizations es inmutable (solo se puede fijar revoked_at): % bloqueado', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END $$;

COMMENT ON FUNCTION public.domain_authorizations_guard() IS
  'Una carta es inmutable salvo revoked_at, que solo pasa de NULL a una fecha (RC-272). No se borra.';

-- 2. Una carta futura no entra mientras haya otra vigente -----------------

CREATE OR REPLACE FUNCTION public.domain_authorizations_una_vigente() RETURNS trigger
LANGUAGE plpgsql SET TimeZone = 'America/Mexico_City' AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.domain_id::text, 272));
  IF NEW.revoked_at IS NULL AND NEW.valid_from > current_date AND EXISTS (
       SELECT 1 FROM public.domain_authorizations a
        WHERE a.organization_id = NEW.organization_id AND a.domain_id = NEW.domain_id
          AND a.revoked_at IS NULL AND current_date BETWEEN a.valid_from AND a.valid_until) THEN
    RAISE EXCEPTION 'domain_authorizations: el dominio tiene una carta vigente y la nueva empieza el %; se carga el día que empieza', NEW.valid_from
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION public.domain_authorizations_una_vigente() IS
  'RC-272: candado del dominio hasta el final de la transacción y, si la carta nueva empieza después de hoy (Ciudad de México) y el dominio tiene otra vigente, la rechaza. Corre como invocador y con RLS.';

DROP TRIGGER IF EXISTS domain_authorizations_una_vigente_bi ON public.domain_authorizations;
CREATE TRIGGER domain_authorizations_una_vigente_bi BEFORE INSERT ON public.domain_authorizations
  FOR EACH ROW EXECUTE FUNCTION public.domain_authorizations_una_vigente();

-- 3. La carta nueva revoca las anteriores ---------------------------------

-- Va por sentencia, con las cartas nuevas en `nuevas`: un trigger por fila ve las demás filas de la misma sentencia y
-- dos cartas del mismo dominio en un solo INSERT se revocarían una a otra.
CREATE OR REPLACE FUNCTION public.domain_authorizations_reemplaza() RETURNS trigger
LANGUAGE plpgsql SET TimeZone = 'America/Mexico_City' AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM nuevas WHERE revoked_at IS NULL
              GROUP BY organization_id, domain_id HAVING count(*) > 1) THEN
    RAISE EXCEPTION 'domain_authorizations: dos cartas del mismo dominio en una sola sentencia; se cargan una por una'
      USING ERRCODE = 'check_violation';
  END IF;
  WITH revocadas AS (
    UPDATE public.domain_authorizations a
       SET revoked_at = now()
      FROM nuevas n
     WHERE n.revoked_at IS NULL AND n.valid_until >= current_date
       AND a.organization_id = n.organization_id AND a.domain_id = n.domain_id
       AND a.id <> n.id AND a.revoked_at IS NULL
    RETURNING a.id, a.organization_id, n.id AS replaced_by)
  INSERT INTO public.audit_log (organization_id, actor_type, action, entity_type, entity_id, details)
  SELECT r.organization_id, 'system', 'authorization.superseded', 'domain_authorization', r.id,
         jsonb_build_object('replaced_by', r.replaced_by::text)
    FROM revocadas r ORDER BY r.id;
  RETURN NULL;
END $$;

COMMENT ON FUNCTION public.domain_authorizations_reemplaza() IS
  'RC-272: una vez por sentencia. Cada carta nueva sin revocar y no vencida (hoy de la Ciudad de México) revoca con now() las demás sin revocar del mismo dominio y deja authorization.superseded en audit_log con replaced_by. Dos cartas sin revocar del mismo dominio en una sentencia se rechazan. No dispara el borrado de la sección 6 de la carta. Corre como invocador y con RLS.';

DROP TRIGGER IF EXISTS domain_authorizations_reemplaza_ai ON public.domain_authorizations;
CREATE TRIGGER domain_authorizations_reemplaza_ai AFTER INSERT ON public.domain_authorizations
  REFERENCING NEW TABLE AS nuevas
  FOR EACH STATEMENT EXECUTE FUNCTION public.domain_authorizations_reemplaza();

-- 4. observed_values sin datos de más -------------------------------------

CREATE OR REPLACE FUNCTION public.txt_observados_validos(valores text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT coalesce(bool_and(coalesce(v ~ '^(cirdan-verification=[0-9a-f]{8,64}|sha256:[0-9a-f]{64})$', false)), true)
    FROM unnest(valores) AS u(v)
$$;

COMMENT ON FUNCTION public.txt_observados_validos(text[]) IS
  'RC-272: cada valor de dns_txt_verifications.observed_values es cirdan-verification=<token en hex> o sha256:<64 hex>. NULL o vacío pasa.';

-- 5. Las filas que ya existen, con el mismo filtro ------------------------

ALTER TABLE public.dns_txt_verifications DISABLE TRIGGER dns_txt_verifications_block_ud;
UPDATE public.dns_txt_verifications t
   SET observed_values = (
         SELECT array_agg(CASE WHEN v ~ '^cirdan-verification=[0-9a-f]{8,64}$' THEN v
                               ELSE 'sha256:' || encode(sha256(convert_to(v, 'UTF8')), 'hex') END ORDER BY n)
                FILTER (WHERE v IS NOT NULL)
           FROM unnest(t.observed_values) WITH ORDINALITY AS u(v, n))
 WHERE NOT public.txt_observados_validos(t.observed_values);
ALTER TABLE public.dns_txt_verifications ENABLE TRIGGER dns_txt_verifications_block_ud;

ALTER TABLE public.dns_txt_verifications DROP CONSTRAINT IF EXISTS dns_txt_verifications_observed_values_check;
ALTER TABLE public.dns_txt_verifications ADD CONSTRAINT dns_txt_verifications_observed_values_check
  CHECK (public.txt_observados_validos(observed_values));

COMMENT ON COLUMN public.dns_txt_verifications.observed_values IS
  'RC-272: los TXT del dominio en la consulta, en su orden. Solo el valor cirdan-verification=<token> va tal cual. Cualquier otro va como sha256:<hex> de su texto en UTF-8.';

COMMIT;
