-- =====================================================================
-- Cirdan · db/migraciones/008_limite_diario_fuentes.sql (RC-184, #13b)
-- Límite diario de consultas por fuente, de toda la plataforma y no de cada
-- empresa, para no agotar el cupo de una fuente externa (Cert Spotter sin
-- llave da unas 10 consultas por hora) ni abusar de las gratuitas.
-- 1. data_sources gana daily_limit (NULL = sin límite), daily_used y
--    daily_used_on. Se cuentan consultas HTTP, como Resultado.consultas
--    del contrato de recolectores. El día es UTC y va explícito en el SQL,
--    (now() AT TIME ZONE 'UTC')::date, porque las cuotas de los proveedores
--    se cuentan en UTC y una conexión sin cirdan/db.py no fija la zona.
-- 2. El contador solo se mueve con dos funciones SECURITY DEFINER de
--    postgres, como login_lookup() de la 004: reserve_source_quota()
--    reserva antes de cada corrida y adjust_source_quota() ajusta al
--    terminar a lo que de verdad se gastó. cirdan_app no recibe UPDATE
--    sobre data_sources, solo puede leer las tres columnas y ejecutar las
--    dos funciones. Con ellas sí puede mover daily_used del día a su gusto,
--    porque adjust_source_quota() acepta cualquier delta: lo que evitan
--    las funciones es darle UPDATE sobre las demás columnas (enabled,
--    keep_raw_payload, daily_limit), no que reporte de menos lo gastado.
-- 3. La reserva es un solo UPDATE condicional: con READ COMMITTED, dos
--    escaneos a la vez (hilos de la API o la línea de comandos en otro
--    proceso) esperan el candado de la fila y el segundo vuelve a evaluar
--    la condición con el valor nuevo, así que juntos no pasan el límite.
--    El día del contador nunca retrocede: si una transacción que empezó
--    antes de medianoche UTC reserva después de otra que ya marcó el día
--    nuevo, suma sobre el día nuevo en lugar de reiniciarlo a ayer.
-- 4. Margen aceptado en el cambio de día: una corrida que reservó antes de
--    medianoche UTC y ajusta después ya no toca el día nuevo (el ajuste no
--    hace nada si el día cambió), así que lo que gaste después de
--    medianoche no cuenta en él. El día nuevo puede pasar su límite hasta
--    en el MAX_CONSULTAS de esa corrida.
-- No agrega tablas, FK, índices, triggers ni políticas: los conteos de
-- db/README.md siguen iguales. Los límites de ct_logs y subfinder los pone
-- la semilla 005. Se puede correr otra vez sin error.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

-- Los comentarios llevan acentos y se guardan en UTF8, aunque psql corra en
-- una consola con otra página de códigos.
SET client_encoding = 'UTF8';

BEGIN;

ALTER TABLE public.data_sources
  ADD COLUMN IF NOT EXISTS daily_limit   integer
    CONSTRAINT data_sources_daily_limit_check CHECK (daily_limit >= 0),
  ADD COLUMN IF NOT EXISTS daily_used    integer NOT NULL DEFAULT 0
    CONSTRAINT data_sources_daily_used_check CHECK (daily_used >= 0),
  ADD COLUMN IF NOT EXISTS daily_used_on date;

COMMENT ON COLUMN public.data_sources.daily_limit IS 'Máximo de consultas HTTP por día UTC de toda la plataforma (RC-184, #13b). NULL = sin límite. 0 = ninguna consulta.';
COMMENT ON COLUMN public.data_sources.daily_used IS 'Consultas HTTP reservadas o gastadas en el día daily_used_on. Solo lo mueven reserve_source_quota() y adjust_source_quota().';
COMMENT ON COLUMN public.data_sources.daily_used_on IS 'Día UTC al que corresponde daily_used. NULL si la fuente nunca reservó. Si es anterior a hoy (UTC), la siguiente reserva parte de 0. Nunca retrocede.';

-- Reserva p_requests consultas de hoy (UTC) para la fuente p_code y devuelve
-- el día reservado, que se pasa después a adjust_source_quota(). Devuelve
-- NULL sin cambiar nada si no caben o si la fuente no existe. Si la fila ya
-- tiene un día posterior a v_hoy, reserva en ese día: el día no retrocede.
CREATE OR REPLACE FUNCTION public.reserve_source_quota(p_code text, p_requests integer)
RETURNS date
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  -- now() es la hora de inicio de la transacción, así que v_hoy puede ser
  -- ayer aunque otra transacción ya haya marcado la fila con el día nuevo.
  v_hoy date := (now() AT TIME ZONE 'UTC')::date;
  v_dia date;
BEGIN
  IF p_requests IS NULL OR p_requests < 0 THEN
    RAISE EXCEPTION 'reserve_source_quota: p_requests debe ser un entero mayor o igual a 0'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  -- Un solo enunciado: si otra reserva tiene la fila, este espera su candado
  -- y vuelve a evaluar el WHERE con el valor ya confirmado.
  -- El día efectivo es GREATEST(v_hoy, COALESCE(daily_used_on, v_hoy)): nunca
  -- retrocede. daily_used_on >= v_hoy es lo mismo que decir que el día
  -- efectivo es el guardado, y entonces se suma sobre lo usado; si no (día
  -- viejo o NULL), el día efectivo es v_hoy y se parte de 0.
  UPDATE public.data_sources AS s
     SET daily_used    = CASE WHEN s.daily_used_on >= v_hoy THEN s.daily_used ELSE 0 END + p_requests,
         daily_used_on = GREATEST(v_hoy, COALESCE(s.daily_used_on, v_hoy))
   WHERE s.code = p_code
     AND (s.daily_limit IS NULL
          OR CASE WHEN s.daily_used_on >= v_hoy THEN s.daily_used ELSE 0 END + p_requests <= s.daily_limit)
  RETURNING s.daily_used_on INTO v_dia;

  -- RETURNING da la fila ya cambiada: v_dia es el día efectivo, el que se
  -- pasa después a adjust_source_quota(). Sin fila (no cabe o no existe),
  -- v_dia queda NULL.
  RETURN v_dia;
END
$$;

COMMENT ON FUNCTION public.reserve_source_quota(text, integer) IS
  'Límite diario por fuente (RC-184, #13b): reserva p_requests consultas del día UTC para la fuente p_code en un solo UPDATE atómico. El día efectivo es GREATEST(hoy, daily_used_on) y nunca retrocede: si daily_used_on es anterior o NULL parte de 0. Devuelve el día efectivo, o NULL sin cambiar nada si no caben en daily_limit o la fuente no existe. p_requests NULL o negativo es error. SECURITY DEFINER para que cirdan_app no necesite UPDATE sobre data_sources, aunque con esta función y adjust_source_quota() puede mover daily_used del día. Su search_path termina en pg_temp, como login_lookup().';

-- Suma p_delta (puede ser negativo) a lo usado el día p_day, sin bajar de 0
-- y sin revisar el límite: lo gastado de más se registra igual. Si el día ya
-- cambió no hace nada, porque lo reservado ayer ya no cuenta, y lo que la
-- corrida gastó después de medianoche UTC tampoco entra al día nuevo (margen
-- aceptado, punto 4 del encabezado). Acepta cualquier delta, así que quien
-- tenga EXECUTE puede mover daily_used del día.
CREATE OR REPLACE FUNCTION public.adjust_source_quota(p_code text, p_day date, p_delta integer)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  -- Con p_delta NULL, GREATEST(NULL, 0) daría 0 y borraría lo usado.
  IF p_delta IS NULL THEN
    RAISE EXCEPTION 'adjust_source_quota: p_delta no puede ser NULL'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  UPDATE public.data_sources AS s
     SET daily_used = GREATEST(s.daily_used + p_delta, 0)
   WHERE s.code = p_code
     AND s.daily_used_on = p_day;
END
$$;

COMMENT ON FUNCTION public.adjust_source_quota(text, date, integer) IS
  'Límite diario por fuente (RC-184, #13b): al terminar una corrida suma p_delta (lo gastado menos lo reservado, puede ser negativo) a daily_used solo si daily_used_on = p_day, sin bajar de 0 y sin revisar daily_limit. Si el día ya cambió no hace nada, así que lo gastado después de medianoche UTC por una corrida que reservó antes no cuenta en el día nuevo (margen de hasta su MAX_CONSULTAS). Acepta cualquier delta: cirdan_app puede mover daily_used del día con ella. p_delta NULL es error. SECURITY DEFINER, como reserve_source_quota().';

REVOKE ALL ON FUNCTION public.reserve_source_quota(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.adjust_source_quota(text, date, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.reserve_source_quota(text, integer) TO cirdan_app;
GRANT EXECUTE ON FUNCTION public.adjust_source_quota(text, date, integer) TO cirdan_app;

-- El GRANT de la 001 es por columna, así que una columna nueva no entra sola.
-- Solo lectura: el contador cambia por las funciones de arriba.
GRANT SELECT (daily_limit, daily_used, daily_used_on) ON public.data_sources TO cirdan_app;

COMMIT;
