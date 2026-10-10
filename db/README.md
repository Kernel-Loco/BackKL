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
| `cirdan_esquema.dbml` | Modelo lógico del que sale la migración inicial (23 tablas en 7 grupos). Lo que la base hace distinto está en «Decisiones y desviaciones respecto al DBML» |
| `migraciones/001_esquema_inicial.sql` | Extensiones, rol, función de tenant, 23 tablas, índices, triggers, RLS, GRANT y COMMENT ON TABLE |
| `semillas/001_datos_demo.sql` | Datos canónicos con UUID fijos (recarga idéntica). También trae los catálogos: planes, fuentes y el juego de reglas v1 |
| `consultas/portal.sql` | (a) dashboard y KPIs, (b) hallazgos más críticos, (c) score por categoría, (d) explicación del hallazgo de brechas |
| `consultas/prueba_rls.sql` | Aislamiento entre clientes, falla cerrada, autorización forzada y bitácora inmutable |
| `consultas/conteo_tablas.sql` | Las 23 tablas con filas y RLS, más el resumen de objetos |

## Qué se creó

- Contenedor `cirdan-pg16` (imagen `postgres:16.14`), puerto `127.0.0.1:5433`, volumen `cirdan-pg16-data`, zona horaria America/Mexico_City.
- Base `cirdan` con las 23 tablas en los 7 grupos del DBML, 57 FK (compuestas por `organization_id` y, donde importa, `domain_id`), 67 índices (únicos, parciales y de consulta), 13 triggers y 18 políticas RLS.
- Rol de aplicación `cirdan_app`: sin superusuario, sin `BYPASSRLS`, con privilegios mínimos (sin UPDATE/DELETE en `audit_log`, `domain_scores`, `score_contributions` ni `dns_txt_verifications`; en `domain_authorizations` solo puede cambiar `revoked_at`; en `scans` no puede fijar `queued_at`; no puede leer `data_sources.api_key_enc`).
- RLS con ENABLE + FORCE en las 18 tablas por cliente. Las políticas comparan `organization_id` (o `id` en `organizations`) con `app_current_org()`, que devuelve `NULLIF(current_setting('app.current_org', true), '')::uuid`. Sin tenant no se ve nada.
- Triggers: cadena de hashes SHA-256 por organización en `audit_log` (chain_seq, prev_hash, row_hash); bloqueo de UPDATE, DELETE y TRUNCATE en `audit_log`, `dns_txt_verifications`, `domain_scores` y `score_contributions`; `domain_authorizations` inmutable salvo `revoked_at`; `scans` exige autorización vigente y TXT `match` de la última hora; `scan_source_runs` rechaza `raw_payload` si la fuente tiene `keep_raw_payload = false` (HIBP).
- Datos de Acme Demo (plan Starter), los mismos de las pantallas de Figma, más Beta Corp solo para la prueba de aislamiento.

## Cómo cargarla

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
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -c "ALTER ROLE cirdan_app PASSWORD '<CIRDAN_APP_PASSWORD>';"
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/semillas/001_datos_demo.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/consultas/portal.sql
docker exec -i cirdan-pg16 sh -c 'psql -U postgres -d cirdan -v ON_ERROR_STOP=1 2>&1' < db/consultas/prueba_rls.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/consultas/conteo_tablas.sql
```

`prueba_rls.sql` se corre con `sh -c '... 2>&1'` para que los ERROR esperados salgan en orden junto a su etiqueta. En ese script, las secciones [5] a [8] desactivan `ON_ERROR_STOP` porque deben fallar.

## Decisiones y desviaciones respecto al DBML

Las desviaciones 1, 2 y 3 se pasaron al DBML el 9 oct, así que hoy la base y el DBML ya coinciden en esos tres puntos. Se dejan en la lista para explicar por qué cambió el modelo.

1. **Severidad `critical`.** El DBML solo permite high, medium y low, pero el portal usa Critical. Se agregó `critical` a `findings.severity`, `score_contributions.severity`, `alerts.severity` y `scoring_rules.base_severity`.
2. **Categorías del score.** Se usan las del portal (Infrastructure, Digital Identity, Configuration y Data Leaks: `infrastructure`, `digital_identity`, `configuration`, `data_leaks`) en lugar de exposed_services, vulnerabilities, configuration y breaches. Pesos del juego v1: 30, 20, 20 y 30 %.
3. **Sentido del score.** Más alto = más exposición. La alerta salta cuando el score llega al umbral (60) o lo pasa, así que `alerts.event_type` usa `score.above_threshold` en lugar de `score.below_threshold`. `score_contributions.penalty` conserva el nombre, pero son puntos que suben la exposición.
4. **Roles.** Solo se creó `cirdan_app`; las tablas pertenecen a `postgres`. No se crearon cirdan_owner, cirdan_maint, cirdan_web, cirdan_worker, cirdan_definer, cirdan_dispatcher ni cirdan_retention, ni las funciones login_lookup, api_key_lookup y audit_platform_append. La excepción de retención del trigger ya compara `current_user = 'cirdan_retention'`.
5. **Variable de tenant.** Se usa `app.current_org` con `app_current_org()`, como dice el DBML.
6. **Trigger de `scans`.** Valida vigencia y antigüedad del TXT contra `queued_at` (que por defecto es `now()`), para poder cargar escaneos históricos de la demo. Solo `postgres` puede fijar `queued_at`: `cirdan_app` tiene GRANT INSERT por columna sin `queued_at`, así que para la app siempre es `now()` y no puede fechar un escaneo en el pasado para usar una autorización vencida.
7. **Título del hallazgo.** El DBML no tiene columna de título. Va en `findings.evidence->>'title'`. Los nombres de fuente (HIBP API, Shodan, DNS) se traducen en la consulta desde `data_sources.code`.
8. **Explicación del score.** `UNIQUE (score_id, finding_id)` permite una fila por hallazgo, así que las 4 reglas (+12, +8, +6 y -2) van en `score_contributions.factors->'rules'` y `penalty = 24.00`.
9. **New y Recurring.** No son estados en la base. Se derivan: abierto y detectado en el último escaneo = New; abierto y visto antes = Recurring.
10. **Convenciones.** Se agregó `created_at` en todas las tablas y `updated_at` en las que cambian, como dicen las convenciones del DBML.
11. **Escaneos.** Se cargó un escaneo por cada dominio con score (3), porque `domain_scores.scan_id` es NOT NULL. Solo el de acme-demo.mx tiene filas en `scan_source_runs`.
12. **Valores que no vienen en los datos de Figma** (ilustrativos): las notas por categoría de acme-tienda.mx (60, 50, 40, 60) y acme-portal.mx (40, 30, 20, 30), elegidas para que el ponderado dé 54 y 31; pesos y topes de las reglas; nombre y fecha de la brecha (`DemoBreach-2026`, 18 Jun 2026); activos con IPs de documentación; tokens TXT salvo el de partner-example.com; hashes de contraseña y secretos (marcadores). partner-example.com no tiene autorización cargada (vigencia "—") y old-example.net está en `paused`.
13. **Sin filas en `api_keys` ni `cves`.** El plan Starter no incluye API, y ningún hallazgo de la demo apunta a un CVE.
14. **Fuera de la base, como dice el DBML.** check_plan_limits (FastAPI), el cifrado AES-GCM y la verificación diaria de la cadena.
