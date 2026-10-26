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
| `semillas/001_datos_demo.sql` | Datos canónicos con UUID fijos (recarga idéntica). También trae los catálogos: planes, fuentes y el juego de reglas v1 |
| `semillas/002_dominio_prueba.sql` | Dominio de prueba olmardo.com (Grupo Olmardo, plan Business) con su TXT verificado el 13 oct 2026 y su carta firmada el 19 oct 2026, con vigencia del 19 oct 2026 al 19 oct 2027 (#9b), y la fuente `ejemplo` deshabilitada para las pruebas del orquestador. Guarda el sha256 del PDF firmado, que no va en el repo. Lo revisa `pruebas/test_dominio_prueba.py` |
| `semillas/003_titulos_espanol.sql` | Títulos en español de los hallazgos demo, como piden los contratos #13 y #21 (RC-17) |
| `semillas/004_reglas_recolectores.sql` | Reglas 08 a 30 del juego v1, las de los recolectores #14 a #20 y las previstas de #62 a #64, con weight 1.000 y tope por severidad (RC-66, #30). No toca las 7 de la semilla 001 |
| `consultas/portal.sql` | (a) dashboard y KPIs, (b) hallazgos más críticos, (c) score por categoría, (d) explicación del hallazgo de brechas |
| `consultas/prueba_rls.sql` | Aislamiento entre clientes, falla cerrada, autorización forzada, bitácora inmutable y que `login_lookup()` no lee una vista temporal |
| `consultas/conteo_tablas.sql` | Las 24 tablas con filas y RLS, más el resumen de objetos |

## Qué se creó

- Contenedor `cirdan-pg16` (imagen `postgres:16.14`), puerto `127.0.0.1:5433`, volumen `cirdan-pg16-data`, zona horaria America/Mexico_City.
- Base `cirdan` con las 24 tablas en los 7 grupos del DBML, 58 FK (compuestas por `organization_id` y, donde importa, `domain_id`, más la de `scoring_rules.code` a `scoring_rule_texts` de la migración 003), 68 índices (únicos, parciales y de consulta), 13 triggers y 18 políticas RLS.
- Rol de aplicación `cirdan_app`: sin superusuario, sin `BYPASSRLS`, con privilegios mínimos (sin UPDATE/DELETE en `audit_log`, `domain_scores`, `score_contributions` ni `dns_txt_verifications`; en `domain_authorizations` solo puede cambiar `revoked_at`; en `scans` no puede fijar `queued_at`; no puede leer `data_sources.api_key_enc`). Desde la migración 004 tampoco puede crear tablas ni vistas temporales.
- RLS con ENABLE + FORCE en las 18 tablas por cliente. Las políticas comparan `organization_id` (o `id` en `organizations`) con `app_current_org()`, que devuelve `NULLIF(current_setting('app.current_org', true), '')::uuid`. Sin tenant no se ve nada.
- Triggers: cadena de hashes SHA-256 por organización en `audit_log` (chain_seq, prev_hash, row_hash); bloqueo de UPDATE, DELETE y TRUNCATE en `audit_log`, `dns_txt_verifications`, `domain_scores` y `score_contributions`; `domain_authorizations` inmutable salvo `revoked_at`; `scans` exige autorización vigente y TXT `match` de la última hora; `scan_source_runs` rechaza `raw_payload` si la fuente tiene `keep_raw_payload = false` (HIBP).
- Datos de Acme Demo (plan Starter), los mismos de las pantallas de Figma, más Beta Corp solo para la prueba de aislamiento. La semilla 002 agrega Grupo Olmardo (plan Business) con el dominio de prueba olmardo.com.

## Cómo cargarla

**Lo normal es no hacerlo a mano:** `docker compose up -d` (ver el README de la raíz) crea el contenedor `cirdan-pg16` y `db/init/cargar_cirdan.sh` carga la base la primera vez. Los pasos de abajo sirven para cargarla sin compose o para entender qué hace ese script.

En Windows corre estos comandos en Git Bash, no en PowerShell, porque PowerShell no acepta el operador `<`.

1. Copia `.env.example` como `.env` y cambia las dos contraseñas.
2. Crea el contenedor con la contraseña de `postgres` que pusiste en `POSTGRES_PASSWORD`:

```bash
docker run -d --name cirdan-pg16 -e POSTGRES_PASSWORD=<POSTGRES_PASSWORD> -e TZ=America/Mexico_City -e PGTZ=America/Mexico_City -p 127.0.0.1:5433:5432 -v cirdan-pg16-data:/var/lib/postgresql/data postgres:16.14
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
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -c "ALTER ROLE cirdan_app PASSWORD '<CIRDAN_APP_PASSWORD>';"
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/001_datos_demo.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/002_dominio_prueba.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/003_titulos_espanol.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/004_reglas_recolectores.sql
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

Las dos corren en una sola transacción cada una y se pueden correr otra vez sin error: la 003 no repite la tabla, los textos ni la FK, y la semilla 004 salta las reglas que ya existen.

La 005 solo cambia textos y `reviewed_by`, y la API los lee de la base en cada petición, así que no hace falta reconstruirla si ya la reconstruiste después de la 003. Desde el `git pull` hasta aplicarla, `pruebas/test_api_v1.py` falla porque `docs/api_v1/pesos.json` y `explicacion.json` ya traen los textos nuevos. Antes de aplicarla, respalda la base. El respaldo queda dentro del contenedor y se pierde si se recrea:

```bash
MSYS_NO_PATHCONV=1 docker exec cirdan-pg16 pg_dump -U postgres -Fc -f /tmp/cirdan_antes_005.dump cirdan
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/005_textos_revisados.sql
```

Corre en una sola transacción. Antes de cambiar nada revisa las 29 filas que toca, y falla sin cambiar nada si falta un texto de la 003, si un texto no es el de la 003 ni el de la 005 o si una regla OSINT la firmó otra persona. Se puede correr otra vez sin error y sin cambiar textos, pero vuelve a mover `updated_at`. Esta consulta dice si ya está aplicada: da `25|5` (las 25 reglas OSINT firmadas por ErnestoDL y las 5 de #62 a #64 sin revisar) y antes de la 005 da `0|30`. Ya aplicada, `python -m unittest -v pruebas/test_api_v1.py` pasa:

```bash
docker exec cirdan-pg16 psql -U postgres -d cirdan -tAc "SELECT count(*) FILTER (WHERE reviewed_by = 'ErnestoDL'), count(*) FILTER (WHERE reviewed_by IS NULL) FROM scoring_rule_texts"
```

## Decisiones y desviaciones respecto al DBML

Las desviaciones 1, 2 y 3 se pasaron al DBML el 9 oct, así que hoy la base y el DBML ya coinciden en esos tres puntos. Se dejan en la lista para explicar por qué cambió el modelo.

1. **Severidad `critical`.** El DBML solo permite high, medium y low, pero el portal usa Critical. Se agregó `critical` a `findings.severity`, `score_contributions.severity`, `alerts.severity` y `scoring_rules.base_severity`.
2. **Categorías del score.** Se usan las del portal (Infrastructure, Digital Identity, Configuration y Data Leaks: `infrastructure`, `digital_identity`, `configuration`, `data_leaks`) en lugar de exposed_services, vulnerabilities, configuration y breaches. Pesos del juego v1: 30, 20, 20 y 30 %.
3. **Sentido del score.** Más alto = más exposición. La alerta salta cuando el score llega al umbral (60) o lo pasa, así que `alerts.event_type` usa `score.above_threshold` en lugar de `score.below_threshold`. `score_contributions.penalty` conserva el nombre, pero son puntos que suben la exposición.
4. **Roles.** Solo se creó `cirdan_app`; las tablas pertenecen a `postgres`. No se crearon cirdan_owner, cirdan_maint, cirdan_web, cirdan_worker, cirdan_definer, cirdan_dispatcher ni cirdan_retention, ni las funciones api_key_lookup y audit_platform_append. `login_lookup` llegó con la migración 002 (#25): es SECURITY DEFINER de `postgres` y solo `cirdan_app` puede ejecutarla. La migración 004 le fija `search_path = pg_catalog, public, pg_temp`, le pone esquema a sus tablas y la deja devolver solo `user_id`, `organization_id`, `password_hash` y `mfa_enabled`. La excepción de retención del trigger ya compara `current_user = 'cirdan_retention'`.
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
