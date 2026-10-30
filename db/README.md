# Base de datos de Cirdan (PostgreSQL 16)

Implementación real del modelo lógico de Cirdan ([`cirdan_esquema.dbml`](cirdan_esquema.dbml), en esta carpeta, que se ve como diagrama pegando su contenido en el editor de la izquierda de https://dbdiagram.io/d), creada el 2 oct 2026 en un contenedor Docker local y mostrada en vivo en la revisión del 2 oct.

## Carpetas

| Carpeta | Qué tiene |
|---|---|
| `migraciones/` | Cambios de esquema numerados (`NNN_descripcion.sql`), en orden. Una migración que ya entró a dev no se edita, se agrega otra |
| `semillas/` | Datos de demo y de prueba, que se cargan después de las migraciones |
| `consultas/` | Scripts de psql que se corren a mano sobre la base cargada |

| Archivo | Qué hace |
|---|---|
| `cirdan_esquema.dbml` | Modelo lógico de la base (24 tablas en 7 grupos: las 23 de la migración inicial más la de la 003). Lo que la base hace distinto está en «Decisiones y desviaciones respecto al DBML» |
| `migraciones/001_esquema_inicial.sql` | Extensiones, rol, función de tenant, 23 tablas, índices, triggers, RLS, GRANT y COMMENT ON TABLE |
| `migraciones/002_login.sql` | Función `login_lookup()` para iniciar sesión sin abrir RLS (#25) |
| `migraciones/003_textos_reglas.sql` | Tabla `scoring_rule_texts` con el título, qué significa y qué hacer de las 30 reglas del juego v1, y la FK de `scoring_rules.code` a esa tabla, para que toda regla tenga texto (RC-66, #30). Catálogo global sin RLS, `cirdan_app` solo lee |
| `migraciones/004_login_lookup_seguro.sql` | Endurece `login_lookup()`: `search_path` que termina en `pg_temp`, tablas con esquema y solo las 4 columnas que usa el login. Quita TEMPORARY a PUBLIC en la base (RC-58) |
| `migraciones/005_textos_revisados.sql` | Corrige 23 textos de `scoring_rule_texts` según la revisión de RC-66 del 25 oct 2026 y llena `reviewed_by` de las 25 reglas OSINT (#14 a #20). Las 5 de #62 a #64 siguen en NULL |
| `migraciones/006_firma_reglas_extras.sql` | Llena `reviewed_by` de las 5 reglas de #62 a #64, que revisó Ernesto (RC-66). No cambia textos. Con ella quedan firmadas las 30 reglas del juego v1 |
| `migraciones/007_comentario_revisor.sql` | Corrige el comentario de `scoring_rule_texts.reviewed_by` que puso la 003: el resto de los textos lo revisa alguien de otra área o Ernesto (RC-66). Solo cambia el comentario |
| `migraciones/008_limite_diario_fuentes.sql` | Límite diario de consultas por fuente (RC-184, #13b): `daily_limit`, `daily_used` y `daily_used_on` en `data_sources` (día UTC) y las funciones `reserve_source_quota()` y `adjust_source_quota()`, SECURITY DEFINER de `postgres`, que son lo único que mueve el contador. `cirdan_app` no tiene UPDATE: lee las columnas y ejecuta las funciones, y con ellas puede mover `daily_used` del día (el ajuste acepta cualquier delta) |
| `migraciones/009_version_modelo_score.sql` | Guarda la versión del clasificador ML y el motivo de fallback a reglas en cada snapshot de score (#36) |
| `semillas/001_datos_demo.sql` | Datos canónicos con UUID fijos (recarga idéntica). También trae los catálogos: planes, fuentes y el juego de reglas v1 |
| `semillas/002_dominio_prueba.sql` | Dominio de prueba olmardo.com (Grupo Olmardo, plan Business) con su TXT verificado el 13 oct 2026 y su carta firmada el 19 oct 2026, con vigencia del 19 oct 2026 al 19 oct 2027 (#9b), y la fuente `ejemplo` deshabilitada para las pruebas del orquestador. Guarda el sha256 del PDF firmado, que no va en el repo. Lo revisa `pruebas/test_dominio_prueba.py` |
| `semillas/003_titulos_espanol.sql` | Títulos en español de los hallazgos demo, como piden los contratos #13 y #21 (RC-17) |
| `semillas/004_reglas_recolectores.sql` | Reglas 08 a 30 del juego v1, las de los recolectores #14 a #20 y las previstas de #62 a #64, con weight 1.000 y tope por severidad (RC-66, #30). No toca las 7 de la semilla 001 |
| `semillas/005_subfinder_y_limites.sql` | Fuente `subfinder` (recolector pasivo de subdominios), sembrada apagada, y límite diario de `ct_logs` (200 consultas) y `subfinder` (400, 50 corridas de 8 fuentes), con el porqué de cada número (RC-184, #13b). Necesita la 008 |
| `semillas/006_github.sql` | Fuente `github` (secretos y correos en los repos públicos de la organización declarada), sembrada encendida, con `keep_raw_payload` = false y límite diario de 400 consultas, 25 corridas de 16 (RC-50, #16). Necesita la 008 |
| `semillas/007_shodan.sql` | Límite diario de la fuente `shodan` (servicios y CVE que Shodan InternetDB ya vio en las IP públicas del dominio): 640 consultas, 10 corridas de 64 (RC-49, #17). La fila ya la sembró la 001, encendida, y no se edita. Necesita la 008 |
| `semillas/008_whois.sql` | Límite diario de la fuente `whois` (registrador, fechas y vencimiento del dominio por RDAP): 60 consultas, 10 corridas de 6 (RC-166, #15b). La fila ya la sembró la 001, encendida, y no se edita. Necesita la migración 008 |
| `consultas/portal.sql` | (a) dashboard y KPIs, (b) hallazgos más críticos, (c) score por categoría, (d) explicación del hallazgo de brechas |
| `consultas/prueba_rls.sql` | Aislamiento entre clientes, falla cerrada, autorización forzada, bitácora inmutable, que `login_lookup()` no lee una vista temporal y que las funciones del límite diario tienen `search_path` fijo y no son de PUBLIC |
| `consultas/conteo_tablas.sql` | Las 24 tablas con filas y RLS, más el resumen de objetos |

## Qué se creó

- Contenedor `cirdan-pg16` (imagen `postgres:16.15`), puerto `127.0.0.1:5433`, volumen `cirdan-pg16-data`, zona horaria America/Mexico_City.
- Base `cirdan` con las 24 tablas en los 7 grupos del DBML, 58 FK (compuestas por `organization_id` y, donde importa, `domain_id`, más la de `scoring_rules.code` a `scoring_rule_texts` de la migración 003), 68 índices (únicos, parciales y de consulta), 13 triggers y 18 políticas RLS.
- Rol de aplicación `cirdan_app`: sin superusuario, sin `BYPASSRLS`, con privilegios mínimos (sin UPDATE/DELETE en `audit_log`, `domain_scores`, `score_contributions` ni `dns_txt_verifications`; en `domain_authorizations` solo puede cambiar `revoked_at`; en `scans` no puede fijar `queued_at`; no puede leer `data_sources.api_key_enc` ni hacer UPDATE en `data_sources`: desde la 008 el contador diario solo lo mueven `reserve_source_quota()` y `adjust_source_quota()`, que `cirdan_app` sí puede ejecutar, así que puede mover `daily_used` del día porque el ajuste acepta cualquier delta). Desde la migración 004 tampoco puede crear tablas ni vistas temporales.
- RLS con ENABLE + FORCE en las 18 tablas por cliente. Las políticas comparan `organization_id` (o `id` en `organizations`) con `app_current_org()`, que devuelve `NULLIF(current_setting('app.current_org', true), '')::uuid`. Sin tenant no se ve nada.
- Triggers: cadena de hashes SHA-256 por organización en `audit_log` (chain_seq, prev_hash, row_hash); bloqueo de UPDATE, DELETE y TRUNCATE en `audit_log`, `dns_txt_verifications`, `domain_scores` y `score_contributions`; `domain_authorizations` inmutable salvo `revoked_at`; `scans` exige autorización vigente y TXT `match` de la última hora; `scan_source_runs` rechaza `raw_payload` si la fuente tiene `keep_raw_payload = false` (HIBP).
- Datos de Acme Demo (plan Starter), los mismos de las pantallas de Figma, más Beta Corp solo para la prueba de aislamiento. La semilla 002 agrega Grupo Olmardo (plan Business) con el dominio de prueba olmardo.com.
- Límite diario por fuente (migración 008 y semilla 005): `ct_logs` 200 y `subfinder` 400 consultas por día UTC, de toda la plataforma. La semilla 006 pone 400 a `github`, donde cada intento a la API de GitHub y cada clon cuentan como consulta, y la semilla 007 pone 640 a `shodan`, donde cuentan cada intento HTTP (Cert Spotter e InternetDB) y cada A. Las demás fuentes quedan sin límite (`daily_limit` NULL). Para `subfinder` una consulta es una fuente de su lista blanca consultada en una corrida, no una petición HTTP.
- `subfinder` queda sembrada apagada (`enabled = false`), como `censys` en la semilla 001. Se prende con otra semilla cuando #8 (RC-40) revise los términos de sus 8 fuentes, haya una grabación de `subfinder` para olmardo.com y el contenedor pueda escribir en `respuestas_grabadas/` (hoy no, el Dockerfile copia `cirdan/` como root). Así la demo en reproducir de S12 no la muestra fallida.
- `github` sí queda sembrada encendida (semilla 006): un dominio sin organización declarada en `ORGS_GITHUB_DECLARADAS` no consulta nada, y en reproducir un dominio sin grabación no falla. En los dos casos la fuente queda `succeeded` con sus 2 códigos sin cobertura. La excepción es el cupo: el orquestador reserva las 16 consultas de `github` antes de llamar al recolector, así que si ya no caben en el límite del día la fuente queda `failed` por falta de cupo, aunque el dominio no tenga organización declarada.

## Cómo cargarla

**Lo normal es no hacerlo a mano:** `docker compose up -d` (ver el README de la raíz) crea el contenedor `cirdan-pg16` y `db/init/cargar_cirdan.sh` carga la base la primera vez. Los pasos de abajo sirven para cargarla sin compose o para entender qué hace ese script.

En Windows corre estos comandos en Git Bash, no en PowerShell, porque PowerShell no acepta el operador `<`.

1. Copia `.env.example` como `.env` y cambia las dos contraseñas.
2. Crea el contenedor con la contraseña de `postgres` que pusiste en `POSTGRES_PASSWORD`:

```bash
docker run -d --name cirdan-pg16 -e POSTGRES_PASSWORD=<POSTGRES_PASSWORD> -e TZ=America/Mexico_City -e PGTZ=America/Mexico_City -p 127.0.0.1:5433:5432 -v cirdan-pg16-data:/var/lib/postgresql/data postgres:16.15
```

Si el contenedor ya existe (por ejemplo, queda detenido después de reiniciar la PC), no repitas `docker run`, porque choca con el nombre. Arráncalo con `docker start cirdan-pg16`.

3. Espera a que Postgres termine de arrancar. La primera vez tarda unos segundos, y si no esperas, `psql` falla con `No such file or directory`:

```bash
until docker exec cirdan-pg16 pg_isready -h 127.0.0.1 -U postgres; do sleep 1; done
```

4. Desde la raíz del repo, crea la base, carga los scripts y dale al rol `cirdan_app` la contraseña de `CIRDAN_APP_PASSWORD` (la API entra con ella):

```bash
docker exec -i cirdan-pg16 psql -U postgres -d postgres -c "DROP DATABASE IF EXISTS cirdan;" -c "CREATE DATABASE cirdan;"
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/001_esquema_inicial.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/002_login.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/003_textos_reglas.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/004_login_lookup_seguro.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/005_textos_revisados.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/006_firma_reglas_extras.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/007_comentario_revisor.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/008_limite_diario_fuentes.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/009_version_modelo_score.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -c "ALTER ROLE cirdan_app PASSWORD '<CIRDAN_APP_PASSWORD>';"
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/001_datos_demo.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/002_dominio_prueba.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/003_titulos_espanol.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/004_reglas_recolectores.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/005_subfinder_y_limites.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/006_github.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/007_shodan.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/consultas/portal.sql
docker exec -i cirdan-pg16 sh -c 'psql -U postgres -d cirdan -v ON_ERROR_STOP=1 2>&1' < db/consultas/prueba_rls.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/consultas/conteo_tablas.sql
```

`prueba_rls.sql` se corre con `sh -c '... 2>&1'` para que los ERROR esperados salgan en orden junto a su etiqueta. En ese script, las secciones [5] a [8] desactivan `ON_ERROR_STOP` porque deben fallar.

### Aplicar una migración nueva a una base que ya existe

`cargar_cirdan.sh` solo corre con el volumen vacío, así que una base creada antes de una migración no la tiene. Para no borrar la base, aplica a mano cada migración que falte, en orden y desde la raíz del repo.

Para la 004, primero actualiza el código y reconstruye la API con `docker compose up -d --build`. Con la 004, `login_lookup()` ya no devuelve el rol. La API anterior lo leía de ahí y su login sin MFA daría 500. La API de esta versión lo lee con RLS en `/login` y funciona antes y después de aplicar la 004. Ya con esa API arriba, aplica la 004:

```bash
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/004_login_lookup_seguro.sql
```

La 004 corre en una sola transacción: si algo falla, la base queda como estaba. Se puede correr otra vez sin error. Comprueba el resultado con `prueba_rls.sql` (secciones [10] y [11]) o con `python -m unittest -v pruebas/test_aislamiento.py`.

Para el catálogo de reglas (RC-66) primero se trae el código (`git pull`) y, antes de reconstruir la API con `docker compose up -d --build`, se aplica la migración 003 y después la semilla 004. Al revés que con la 004, aquí la base va primero: la API de esta versión lee `scoring_rule_texts` y sin la tabla la explicación de un hallazgo, `/api/v1/scoring/weights` y `/db/tables` fallan, mientras que la API anterior no lee la tabla y funciona igual con ella. La 003 crea `scoring_rule_texts`, inserta los 30 textos y agrega la FK de `scoring_rules.code`, que se valida contra las 7 reglas que la base ya tiene. La semilla 004 agrega al juego v1 las 23 reglas nuevas, que necesitan sus textos de la 003. `cargar_cirdan.sh` tampoco vuelve a correr las semillas en una base que ya existe:

```bash
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/003_textos_reglas.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/004_reglas_recolectores.sql
```

Las dos corren en una sola transacción cada una y se pueden correr otra vez sin error: la 003 no repite la tabla, los textos ni la FK, y la semilla 004 salta las reglas que ya existen. La 003 sí vuelve a poner su comentario de `reviewed_by`, así que en una base que ya tiene la 007 se vuelve a correr la 007 después.

La 005 solo cambia textos y `reviewed_by`, y la API los lee de la base en cada petición, así que no hace falta reconstruirla si ya la reconstruiste después de la 003. Desde el `git pull` hasta aplicarla, `pruebas/test_api_v1.py` falla porque `docs/api_v1/pesos.json` y `explicacion.json` ya traen los textos nuevos. Antes de aplicarla, respalda la base. El respaldo queda dentro del contenedor y se pierde si se recrea:

```bash
MSYS_NO_PATHCONV=1 docker exec cirdan-pg16 pg_dump -U postgres -Fc -f /tmp/cirdan_antes_005.dump cirdan
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/005_textos_revisados.sql
```

Corre en una sola transacción. Antes de cambiar nada revisa las 29 filas que toca, y falla sin cambiar nada si falta un texto de la 003, si un texto no es el de la 003 ni el de la 005 o si una fila ya la firmó alguien que no es quien la firma la 005. Se puede correr otra vez sin error y sin cambiar textos, pero vuelve a mover `updated_at`. Después de una migración que vuelva a cambiar o firmar esas filas, falla sin cambiar nada. Esta consulta dice si ya está aplicada: da `25|5` (las 25 reglas OSINT firmadas por ErnestoDL y las 5 de #62 a #64 sin revisar) y antes de la 005 da `0|30`. Ya aplicada, `python -m unittest -v pruebas/test_api_v1.py` pasa:

```bash
docker exec cirdan-pg16 psql -U postgres -d cirdan -tAc "SELECT count(*) FILTER (WHERE reviewed_by = 'ErnestoDL'), count(*) FILTER (WHERE reviewed_by IS NULL) FROM scoring_rule_texts"
```

Cuando dé `25|5` y la prueba pase, borra el respaldo con `MSYS_NO_PATHCONV=1 docker exec cirdan-pg16 rm /tmp/cirdan_antes_005.dump`. Si después un texto queda mal, se corrige con una migración nueva y no restaurando el respaldo, que regresaría toda la base.

La 006 solo llena `reviewed_by` de las 5 reglas de #62 a #64, así que no hace falta reconstruir la API ni cambiar `docs/api_v1/`, que no traen el revisor. Va después de la 005:

```bash
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/006_firma_reglas_extras.sql
```

Corre en una sola transacción. Antes de cambiar nada revisa las 5 filas, y falla sin cambiar nada si falta un texto de la 003, si un texto no es el que dejó la 005 o si una fila ya la firmó alguien que no es ErnestoDL. Se puede correr otra vez sin error, pero vuelve a mover `updated_at`. Después de la 006, volver a correr la 005 falla sin cambiar nada, porque esas 5 filas ya no tienen el revisor que espera la 005. La consulta de arriba da `30|0` cuando la 006 ya está aplicada y `25|5` antes.

La 007 solo cambia el comentario de la columna `reviewed_by`, así que tampoco hace falta reconstruir la API. Va después de la 006, aunque solo necesita la tabla de la 003:

```bash
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/007_comentario_revisor.sql
```

Corre en una sola transacción, se puede correr otra vez sin error y falla sin cambiar nada si falta la tabla de la 003. Para revisarla:

```bash
docker exec cirdan-pg16 psql -U postgres -d cirdan -tAc "SELECT col_description('scoring_rule_texts'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid = 'scoring_rule_texts'::regclass AND attname = 'reviewed_by'))"
```

Con la 007 da el comentario que termina en `alguien de otra área o Ernesto). NULL mientras no se revise.` y antes el de la 003. Si alguien vuelve a correr la 003, su comentario regresa sin error y se vuelve a correr la 007. `pruebas/test_catalogo_reglas.py` revisa sin base que el último comentario de las migraciones diga lo mismo que `db/cirdan_esquema.dbml`.

Para el límite diario por fuente (RC-184, #13b) la base va antes de reconstruir la API, como con la 003. Primero se trae el código (`git pull`), después se aplican la 008 y la semilla 005, en ese orden, y al final se reconstruye la API con `docker compose up -d --build api` (antes, `docker compose --dry-run up -d --build api` dice si también se recrearían `cirdan-pg16` o `cirdan-valkey`). El orquestador de esta versión llama a `reserve_source_quota()` en cada fuente en vivo o al grabar, y sin la 008 todo escaneo en vivo o al grabar queda `failed` sin correr ninguna fuente. La API anterior no lee las columnas nuevas ni conoce `subfinder`, así que funciona igual con la 008 y la semilla 005 aplicadas. La semilla 005 necesita la columna `daily_limit` de la 008:

```bash
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/008_limite_diario_fuentes.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/005_subfinder_y_limites.sql
```

Cada una corre en una sola transacción y se puede correr otra vez sin error: la 008 no repite columnas y vuelve a crear las funciones con lo mismo, y la semilla 005 no repite la fila de `subfinder` ni pisa un límite de `ct_logs` ya puesto. La 008 no agrega tablas, FK, índices, triggers ni políticas, así que los conteos de arriba no cambian. Para revisarlas:

```bash
docker exec cirdan-pg16 psql -U postgres -d cirdan -tAc "SELECT code, daily_limit, enabled FROM data_sources WHERE daily_limit IS NOT NULL ORDER BY code"
```

Con las dos da `ct_logs|200|t` y `subfinder|400|f` (sembrada apagada). Que las dos funciones tengan `search_path` fijo y no sean de PUBLIC lo revisan la sección [12] de `prueba_rls.sql` y la prueba 12 de `pruebas/test_aislamiento.py`. El día del contador es UTC, explícito en las funciones, y no el de México que fija `cirdan/db.py`: a las 18:00 de Monterrey empieza otro día de cupo. El día nunca retrocede: una reserva hecha en una transacción que empezó antes de medianoche UTC suma sobre el día nuevo si otra ya lo marcó. Margen aceptado: una corrida que reservó antes de medianoche UTC y ajusta después no toca el día nuevo, así que ese día puede pasar su límite hasta en el `MAX_CONSULTAS` de esa corrida.

Para la fuente `github` (RC-50, #16) basta la semilla 006, que necesita la 008. El orden con la API no importa: la API anterior salta las fuentes sin recolector en `REGISTRO`, y la nueva sin la semilla no corre `github`, porque el escaneo solo toma las fuentes de `data_sources`. Va antes de reconstruir la API para que el primer escaneo ya la incluya:

```bash
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/006_github.sql
docker exec cirdan-pg16 psql -U postgres -d cirdan -tAc "SELECT code, enabled, keep_raw_payload, daily_limit FROM data_sources WHERE code = 'github'"
```

Da `github|t|f|400`. Corre en una sola transacción y se puede correr otra vez sin error: no repite la fila ni pisa una que ya exista. No agrega tablas ni políticas.

Para la fuente `shodan` (RC-49, #17) basta la semilla 007, que necesita la 008. Va antes de reconstruir la API, como la 006: la fila `shodan` ya está encendida desde la 001, así que una API con #17 sin la 007 la corre en todo escaneo sin límite diario (`daily_limit` NULL):

```bash
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/007_shodan.sql
docker exec cirdan-pg16 psql -U postgres -d cirdan -tAc "SELECT code, enabled, keep_raw_payload, daily_limit FROM data_sources WHERE code = 'shodan'"
```

Da `shodan|t|t|640`. Corre en una sola transacción y se puede correr otra vez sin error: solo pone el límite si la fila todavía no tiene uno, así no pisa uno puesto a mano. No agrega tablas ni políticas. Las páginas de Cert Spotter que pide `shodan` cuentan en su límite, no en el de `ct_logs`.

Para la fuente `whois` (RC-166, #15b) basta la semilla 008, que necesita la migración 008. Va antes de reconstruir la API, como la 007: la fila `whois` ya está encendida desde la 001, así que una API con #15b sin la semilla 008 la corre en todo escaneo sin límite diario:

```bash
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/008_whois.sql
docker exec cirdan-pg16 psql -U postgres -d cirdan -tAc "SELECT code, enabled, keep_raw_payload, daily_limit FROM data_sources WHERE code = 'whois'"
```

Da `whois|t|t|60`. Corre en una sola transacción y se puede correr otra vez sin error: solo pone el límite si la fila todavía no tiene uno. No agrega tablas ni políticas.

Para integrar el clasificador ML (#36), la API necesita las columnas de la migración 009 antes de desplegarse; la migración inicial ya acepta `method = 'ml'`. En una base existente, aplica 009 sin recrearla:

```bash
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/009_version_modelo_score.sql
```

La 009 corre en una sola transacción y agrega `model_version` y `model_fallback_reason` a `domain_scores`. Scores históricos de reglas quedan con ambas columnas en `NULL`. Para verificar el esquema:

```bash
docker exec cirdan-pg16 psql -U postgres -d cirdan -tAc "SELECT column_name FROM information_schema.columns WHERE table_name = 'domain_scores' AND column_name IN ('model_version', 'model_fallback_reason') ORDER BY column_name"
```

Debe devolver ambas columnas. En una base nueva, `cargar_cirdan.sh` aplica 009 junto con las migraciones anteriores.

## Decisiones y desviaciones respecto al DBML

Las desviaciones 1, 2 y 3 se pasaron al DBML el 9 oct, así que hoy la base y el DBML ya coinciden en esos tres puntos. Se dejan en la lista para explicar por qué cambió el modelo.

1. **Severidad `critical`.** El DBML solo permite high, medium y low, pero el portal usa Critical. Se agregó `critical` a `findings.severity`, `score_contributions.severity`, `alerts.severity` y `scoring_rules.base_severity`.
2. **Categorías del score.** Se usan las del portal (Infrastructure, Digital Identity, Configuration y Data Leaks: `infrastructure`, `digital_identity`, `configuration`, `data_leaks`) en lugar de exposed_services, vulnerabilities, configuration y breaches. Pesos del juego v1: 30, 20, 20 y 30 %.
3. **Sentido del score.** Más alto = más exposición. La alerta salta cuando el score llega al umbral (60) o lo pasa, así que `alerts.event_type` usa `score.above_threshold` en lugar de `score.below_threshold`. `score_contributions.penalty` conserva el nombre, pero son puntos que suben la exposición.
4. **Roles.** Solo se creó `cirdan_app`; las tablas pertenecen a `postgres`. No se crearon cirdan_owner, cirdan_maint, cirdan_web, cirdan_worker, cirdan_definer, cirdan_dispatcher ni cirdan_retention, ni las funciones api_key_lookup y audit_platform_append. `login_lookup` llegó con la migración 002 (#25): es SECURITY DEFINER de `postgres` y solo `cirdan_app` puede ejecutarla. La migración 004 le fija `search_path = pg_catalog, public, pg_temp`, le pone esquema a sus tablas y la deja devolver solo `user_id`, `organization_id`, `password_hash` y `mfa_enabled`. La 008 agrega `reserve_source_quota()` y `adjust_source_quota()` con el mismo patrón (dueño `postgres`, `search_path` que termina en `pg_temp`, tablas con esquema y EXECUTE solo para `cirdan_app`), para que la app mueva el contador diario sin UPDATE sobre `data_sources`. La excepción de retención del trigger ya compara `current_user = 'cirdan_retention'`.
5. **Variable de tenant.** Se usa `app.current_org` con `app_current_org()`, como dice el DBML.
6. **Trigger de `scans`.** Valida vigencia y antigüedad del TXT contra `queued_at` (que por defecto es `now()`), para poder cargar escaneos históricos de la demo. Solo `postgres` puede fijar `queued_at`: `cirdan_app` tiene GRANT INSERT por columna sin `queued_at`, así que para la app siempre es `now()` y no puede fechar un escaneo en el pasado para usar una autorización vencida.
7. **Título del hallazgo.** El DBML no tiene columna de título. Va en `findings.evidence->>'title'`. Los nombres de fuente (HIBP API, Shodan, DNS) se traducen en la consulta desde `data_sources.code`.
8. **Explicación del score.** `UNIQUE (score_id, finding_id)` permite una fila por hallazgo, así que las 4 reglas (+12, +8, +6 y -2) van en `score_contributions.factors->'rules'` y `penalty = 24.00`.
9. **New y Recurring.** No son estados en la base. Se derivan: abierto y detectado en el último escaneo = New; abierto y visto antes = Recurring.
10. **Convenciones.** Se agregó `created_at` en todas las tablas y `updated_at` en las que cambian, como dicen las convenciones del DBML.
11. **Escaneos.** Se cargó un escaneo por cada dominio con score (3), porque `domain_scores.scan_id` es NOT NULL. Solo el de acme-demo.mx tiene filas en `scan_source_runs`.
12. **Valores que no vienen en los datos de Figma** (ilustrativos): las notas por categoría de acme-tienda.mx (60, 50, 40, 60) y acme-portal.mx (40, 30, 20, 30), elegidas para que el ponderado dé 54 y 31; pesos y topes de las reglas; nombre y fecha de la brecha (`DemoBreach-2026`, 18 Jun 2026); activos con IPs de documentación; tokens TXT salvo el de partner-example.com; hashes de contraseña y secretos (marcadores). partner-example.com no tiene autorización cargada (vigencia "—") y old-example.net está en `paused`.
13. **Sin filas en `api_keys` ni `cves`.** El plan Starter no incluye API, y ningún hallazgo de la demo apunta a un CVE.
14. **Fuera de la base, como dice el DBML.** check_plan_limits (FastAPI), el cifrado AES-GCM y la verificación diaria de la cadena. Hoy solo existe el cifrado del secreto TOTP (`cirdan/auth/totp.py`). check_plan_limits y la verificación diaria son plan, igual que los roles y las funciones del punto 4. El DBML es el diseño objetivo, y sus notas marcan qué existe hoy en dev y qué tarjeta trae lo que falta.
15. **Juego v1 completado después de activarse.** El DBML dice que un juego es inmutable una vez activado y que cambiar un peso crea un juego nuevo. Aun así, v1 se completó con las 30 reglas de #14 a #20 y de #62 a #64 antes de #31 (RC-60), porque todavía ningún score se calcula con un juego. La semilla 004 agrega las 23 reglas nuevas con weight 1.000 y no cambia las 7 de la semilla 001 ni `category_weights`. Desde #31, cualquier cambio de reglas o pesos crea v2 (RC-66, #30).
