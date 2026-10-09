# Cirdan: base de datos implementada (PostgreSQL 16)

Implementación real del modelo lógico de Cirdan (`cirdan_esquema.dbml`), creada el 2 oct 2026 en un contenedor Docker local y mostrada en vivo en la revisión del 2 oct.

## Qué se creó

- Contenedor `cirdan-pg16` (imagen `postgres:16.14`), puerto `127.0.0.1:5433`, volumen `cirdan-pg16-data`, zona horaria America/Mexico_City.
- Base `cirdan` con las 23 tablas en los 7 grupos del DBML, 57 FK (compuestas por `organization_id` y, donde importa, `domain_id`), 67 índices (únicos, parciales y de consulta), 13 triggers y 18 políticas RLS.
- Rol de aplicación `cirdan_app`: sin superusuario, sin `BYPASSRLS`, con privilegios mínimos (sin UPDATE/DELETE en `audit_log`, `domain_scores`, `score_contributions` ni `dns_txt_verifications`; en `domain_authorizations` solo puede cambiar `revoked_at`; en `scans` no puede fijar `queued_at`; no puede leer `data_sources.api_key_enc`).
- RLS con ENABLE + FORCE en las 18 tablas por cliente. Las políticas comparan `organization_id` (o `id` en `organizations`) con `app_current_org()`, que devuelve `NULLIF(current_setting('app.current_org', true), '')::uuid`. Sin tenant no se ve nada.
- Triggers: cadena de hashes SHA-256 por organización en `audit_log` (chain_seq, prev_hash, row_hash); bloqueo de UPDATE, DELETE y TRUNCATE en `audit_log`, `dns_txt_verifications`, `domain_scores` y `score_contributions`; `domain_authorizations` inmutable salvo `revoked_at`; `scans` exige autorización vigente y TXT `match` de la última hora; `scan_source_runs` rechaza `raw_payload` si la fuente tiene `keep_raw_payload = false` (HIBP).
- Datos de Acme Demo (plan Starter), los mismos de las pantallas de Figma, más Beta Corp solo para la prueba de aislamiento.

## Archivos

| Archivo | Qué hace |
|---|---|
| `01_esquema.sql` | Extensiones, rol, función de tenant, 23 tablas, índices, triggers, RLS, GRANT y COMMENT ON TABLE |
| `02_datos_demo.sql` | Datos canónicos con UUID fijos (recarga idéntica) |
| `03_consultas.sql` | (a) dashboard y KPIs, (b) hallazgos más críticos, (c) score por categoría, (d) explicación del hallazgo de brechas |
| `04_prueba_rls.sql` | Aislamiento entre clientes, falla cerrada, autorización forzada y bitácora inmutable |
| `05_conteo_tablas.sql` | Las 23 tablas con filas y RLS, más el resumen de objetos |
| `api/` | API inicial en FastAPI y la página `/demo` |
| `docs/` | Criterio de criticidad (#29) |
| `score/` | Bandas, piso, ponderado y alerta del criterio de criticidad (#29) |
| `recolectores/` | Recolectores OSINT pasivos. Por ahora crt.sh (#14) |
| `respuestas_grabadas/` | Respuestas grabadas de cada recolector para las pruebas y el respaldo de las demos |
| `pruebas/` | Pruebas automáticas de la base, de la API, del criterio de criticidad y de crt.sh |
| `.env.example` | Variables que necesita todo lo anterior. Se copia como `.env` y se le ponen contraseñas propias. `.env` no se sube al repositorio |

## Cómo correrlo

1. Copia `.env.example` como `.env` y cambia las dos contraseñas.
2. Crea el contenedor con la contraseña de `postgres` que pusiste en `POSTGRES_PASSWORD`:

```bash
docker run -d --name cirdan-pg16 -e POSTGRES_PASSWORD=<POSTGRES_PASSWORD> -e TZ=America/Mexico_City -e PGTZ=America/Mexico_City -p 127.0.0.1:5433:5432 -v cirdan-pg16-data:/var/lib/postgresql/data postgres:16.14
```

3. Crea la base, carga los scripts y dale al rol `cirdan_app` la contraseña de `CIRDAN_APP_PASSWORD` (la API entra con ella):

```bash
docker exec -i cirdan-pg16 psql -U postgres -d postgres -c "DROP DATABASE IF EXISTS cirdan;" -c "CREATE DATABASE cirdan;"
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < 01_esquema.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -c "ALTER ROLE cirdan_app PASSWORD '<CIRDAN_APP_PASSWORD>';"
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < 02_datos_demo.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < 03_consultas.sql
docker exec -i cirdan-pg16 sh -c 'psql -U postgres -d cirdan -v ON_ERROR_STOP=1 2>&1' < 04_prueba_rls.sql
docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < 05_conteo_tablas.sql
```

`04_prueba_rls.sql` se corre con `sh -c '... 2>&1'` para que los ERROR esperados salgan en orden junto a su etiqueta. En ese script, las secciones [5] a [8] desactivan `ON_ERROR_STOP` porque deben fallar.

## Decisiones y desviaciones respecto al DBML

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

## Pruebas automáticas

`pruebas/test_aislamiento.py` corre 8 pruebas con la biblioteca estándar de Python (sin instalar nada) contra la base `cirdan`, entrando como `cirdan_app`: rol sin privilegios, RLS forzado en 18 tablas, Acme ve solo lo suyo (5 dominios, 4 hallazgos, 3 usuarios), Beta Corp ve 1, 1 y 1, sin cliente se ve 0, no se puede escribir a nombre de otro cliente, no se puede escanear con la autorización vencida y la bitácora no se modifica. Cada escritura va en una transacción que se deshace.

```bash
python -m unittest -v pruebas/test_aislamiento.py
```

El 2 oct 2026 pasaron 8 de 8.

## API inicial (FastAPI)

`api/main.py` expone 4 endpoints de solo lectura: `GET /health`, `GET /domains`, `GET /domains/{fqdn}/findings` y `GET /domains/{fqdn}/score`. Entra como `cirdan_app` (contraseña en `.env`, `CIRDAN_APP_PASSWORD`) y en cada petición fija `app.current_org` con el encabezado `X-Organization`, así que el aislamiento lo aplica RLS. Un dominio de otro cliente responde 404. En producción el cliente se identificará con su llave de API (tabla `api_keys`).

```bash
python -m pip install fastapi uvicorn "psycopg[binary]"
python -m uvicorn api.main:app --port 8000      # documentación en http://127.0.0.1:8000/docs
python -m unittest -v pruebas/test_aislamiento.py pruebas/test_api.py
```

El 2 oct 2026 pasaron las 14 pruebas (8 de la base y 6 de la API).

## Vista visual de la base (para la demo)

Con la API arriba, abre **http://127.0.0.1:8000/demo**. Muestra las 23 tablas agrupadas con las filas que ve el cliente elegido (Acme Demo, Beta Corp o sin cliente), las filas reales de la tabla que selecciones (sin columnas secretas), los dominios con su score y, al elegir uno, su desglose por categoría y sus hallazgos. El botón "Intentar como Beta Corp" muestra el 404 al pedir un dominio de Acme. Todo pasa por el rol `cirdan_app`, así que lo que se ve es lo que RLS deja ver. Archivos: `api/explorer.py` y `api/demo.html`.

## Recolector de crt.sh (#14)

`recolectores/crtsh.py` lee los logs públicos de Certificate Transparency en crt.sh, sin tocar los servidores del dominio. Devuelve los subdominios como activos y tres tipos de hallazgo:

| Código de regla | Severidad base | Cuándo |
|---|---|---|
| `cert_expired` | high | El certificado más reciente de un nombre venció hace menos de un año (más viejo, el nombre queda solo como activo) |
| `cert_expiring_soon` | medium | El certificado más reciente vence en menos de 30 días |
| `lookalike_domain` | medium | Un dominio parecido tiene un certificado vigente o vencido hace menos de 90 días: contiene la marca, usa otro TLD o tiene un error tipográfico |

Cada hallazgo trae título en español, evidencia, las características del reto (tipo, antigüedad, exposición y sensibilidad) y una huella SHA-256 estable para no duplicarlo entre escaneos. Si crt.sh no responde después de 3 intentos, la fuente queda en `failed` sin activos ni hallazgos. Si solo fallan las variantes de dominios parecidos, el escaneo sigue y quedan avisos.

```bash
python -m recolectores.crtsh acme-demo.mx                        # en vivo
python -m recolectores.crtsh acme-demo.mx --sin-parecidos        # en vivo, solo subdominios y certificados (una consulta)
python -m recolectores.crtsh acme-demo.mx --grabar               # en vivo y graba en respuestas_grabadas/crtsh/acme-demo.mx/
python -m recolectores.crtsh acme-demo.mx --grabar --completar   # solo consulta lo que aún no está grabado
python -m recolectores.crtsh acme-demo.mx --reproducir           # solo con las respuestas grabadas, sin red
python -m recolectores.crtsh acme-demo.mx --json                 # el resultado completo en JSON
python -m unittest -v pruebas/test_crtsh.py                      # 33 pruebas sin red
```

Sin `--json` imprime un resumen en español para leer en una demo: los activos con su fecha de vencimiento y cada hallazgo con su severidad (alta, media) y sus características. Los datos conservan los códigos de la base (`high`, `medium`). Con `--reproducir`, la primera línea dice de cuándo es la grabación. Esa fecha va dentro de cada archivo grabado, así que no cambia al copiarlo o clonar el repo. Si falta alguna respuesta grabada, lo dice en una sola línea y no lo cuenta como falla de crt.sh. Código de salida: 0 bien, 1 si queda en `failed` y 2 si quedan avisos.

El día anterior a cada sesión y control se graba la respuesta real del dominio de prueba con `--grabar`. Cada dominio graba en su propia carpeta. `--grabar` la vacía y marca el inicio en cuanto crt.sh responde (si no responde, código 1, la grabación anterior queda intacta), así lo que no se grabe hoy, porque falló, se omitió por saturación o se interrumpió, aparece en la línea Faltan de `--reproducir` y nunca se mezcla con respuestas de días anteriores. Si crt.sh deja la grabación a medias (código de salida 2), se repite con `--grabar --completar` hasta que salga 0: solo vuelve a consultar lo que no se grabó desde ese inicio. La demo usa `--reproducir` como respaldo.

## Criterio de criticidad (#29)

Más alto = más riesgo. Bandas 0 a 39 bajo, 40 a 59 medio, 60 a 79 alto y 80 a 100 crítico, ancladas al ejemplo del reto (68 = riesgo alto). Regla de piso: un hallazgo crítico vigente deja el dominio al menos en 60, y dos o más, al menos en 80. La alerta se crea cuando el score llega al umbral o lo pasa. El criterio completo, con ejemplos y quién usa qué, está en `docs/criterio_criticidad.md`, y su código en `score/criterio.py`.

```bash
python -m unittest -v pruebas/test_criterio.py   # 13 pruebas, sin base de datos
```
