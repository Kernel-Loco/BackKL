# Auditoría interna de LowTide (ISO/IEC 27001:2022, cláusula 9.2)

Tarjeta #178 (RC-296). Primera auditoría interna, del 24 nov 2026. Corte de la evidencia: BackKL `origin/dev` en 6a44872, la configuración de GitHub y Jira a las 22:36 del 24 nov 2026 (hora de Monterrey). Sus resultados entran en la [revisión por la dirección](revision_por_la_direccion.md) del mismo día.

## 1. Programa de auditoría

1. Frecuencia: una auditoría al semestre, y otra antes de cargar la carta del primer cliente real o de un cambio de alcance de la sección 1 de la política.
2. Cada auditoría toma una muestra distinta de controles marcados 'Existe', empezando por los que no entraron en la anterior, y vuelve a revisar los hallazgos abiertos.
3. Sus resultados se informan en la siguiente revisión por la dirección (cláusula 9.3) y se guardan en este archivo, versionado en git. Una auditoría nueva suma su sección y no borra las anteriores.

## 2. Alcance

1. La política de seguridad y privacidad LT-POL-001, versión 2.6 del 24 nov 2026 ([`politica_seguridad_privacidad.md`](politica_seguridad_privacidad.md)).
2. Su declaración de aplicabilidad, la sección 4 de la política, con 36 controles o grupos de controles marcados 'Existe'.
3. Fuera de esta auditoría: los controles marcados 'En parte', 'Falta' o 'Del proveedor', que ya dicen lo que les falta, la VM en vivo, la carta y la política de uso ético (#6).

## 3. Criterio

1. Lo que la política afirma de cada control en su columna 'Cómo se cumple en LowTide', contrastado con el repositorio (archivo:línea), la configuración de GitHub de BackKL y FrontKL y Jira.
2. Un control 'Existe' es conforme si tiene evidencia cada afirmación que copia la columna 'Qué afirma la política' de la sección 5. Son las afirmaciones técnicas que se pueden comprobar contra el repositorio, GitHub o Jira. Las de proceso que esa columna no copia, como que otra persona revise cada PR (5.3) o el congelamiento (8.32), no se revisaron en esta auditoría.
3. Un hallazgo es una no conformidad menor si una afirmación de la fila no se cumple, y una observación si el control se cumple pero el texto ya no dice lo que hay.

## 4. Quién la hizo y su limitación

1. Auditor: Ernesto De Luna Quintero, coordinación y OSINT del equipo Kernel Loco.
2. La evidencia la juntó y la cotejó Claude Code, un asistente de IA, y la revisó un segundo agente de IA que solo leyó el repositorio. Ernesto la firma al aprobar el PR que la trae (sección 10 de la política).
3. Limitación: Ernesto coordina el equipo, escribió la política y es autor de varios de los controles revisados, así que revisa su propio trabajo y esta auditoría no cumple la objetividad e imparcialidad que pide la cláusula 9.2. Se eligió así para no depender de nadie antes del congelamiento del 25 nov. La compensan que toda la evidencia es pública y repetible (archivo:línea, comandos de `gh` o clave de Jira) y la revisión del segundo agente. La siguiente auditoría la hace alguien que no escribió la política (decisión 7 del acta).

## 5. Muestra

13 de los 36 controles 'Existe', elegidos porque cada afirmación se puede revisar contra el repositorio, la configuración de GitHub o Jira, y para cubrir acceso, cambios, fugas, entornos, registros e inventario.

| Control | Qué afirma la política | Evidencia | Resultado |
|---|---|---|---|
| 5.3 Separación de funciones | `dev` y `main` de BackKL no aceptan un merge sin pruebas, seguridad y CodeQL en verde, y los de FrontKL sin pruebas y Analyze, también para los administradores (RC-254) | `gh api repos/Kernel-Loco/BackKL/branches/dev/protection` y `main`: checks `pruebas`, `Analyze (python)` y `seguridad`, `enforce_admins` activo. FrontKL `dev` y `main`: `pruebas` y `Analyze (javascript-typescript)`, `enforce_admins` activo. RC-254 en Done | Conforme |
| 5.9 Inventario de activos | `servicios_externos.md` lista cada servicio y anota el 2FA de cada cuenta | `docs/servicios_externos.md:17` (tabla), `:56` (2FA de cada cuenta, RC-255) y `:112` (términos de los proveedores, RC-256). RC-255 en Done. Pero `:122` y `:143` dicen que el plan Core 1 de Have I Been Pwned está sin comprar, y se compró el 23 nov (RC-54, comentario 10612, y recibo en el comentario 10611 de RC-40) | Conforme, con la observación H3 |
| 5.15 Control de acceso | RLS con ENABLE y FORCE en las tablas por cliente | Ver 8.3 | Conforme |
| 5.33 Protección de registros | `audit_log` de solo inserción con cadena de hashes SHA-256. Falta revisar la cadena (#86) | `db/migraciones/001_esquema_inicial.sql:436-485` (tabla, `prev_hash`, `row_hash`, la función `audit_log_chain` y su trigger) y `:505-508` (triggers de solo inserción). La revisión de la cadena ya existe: `GET /api/v1/audit-log/verify` en `cirdan/api/bitacora.py:29-31` | Conforme, con la observación H2 |
| 8.2 Accesos privilegiados | `cirdan_app` nunca es superusuario ni tiene BYPASSRLS | `db/migraciones/001_esquema_inicial.sql:20` (`NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`) | Conforme |
| 8.3 Restricción de acceso | RLS con ENABLE, FORCE y su política en toda tabla con `organization_id` | Las 22 tablas con `organization_id` de `db/migraciones/` tienen las tres: 17 en el bucle de `001_esquema_inicial.sql:585-597`, `scoring_rule_sets` en `013_pesos_por_organizacion.sql:25-27`, `webauthn_credentials` en `018_passkeys.sql:50-53`, `signature_requests` en `031_solicitudes_de_firma.sql:184-187`, `org_delegations` en `033_delegaciones_operador.sql:114-117` y `org_source_settings` en `034_fuentes_por_organizacion.sql:54-58` | Conforme |
| 8.4 Acceso al código | Repos públicos sin secretos. Nadie sube directo a `dev` ni a `main` | Las cuatro ramas piden PR. gitleaks en cada PR (ver 8.12). Pero BackKL `dev` tiene `allow_force_pushes` activo, a diferencia de BackKL `main` y de FrontKL | No conformidad menor H1 |
| 8.6 Gestión de la capacidad | Cupo diario por fuente que reserva cada corrida antes de consultar | `cirdan/orquestador/__init__.py:83-86` y `_reservar` en `:760`, con `reserve_source_quota()` de la migración 008 | Conforme |
| 8.8 Vulnerabilidades técnicas | Dependabot cada semana y CodeQL en cada PR y cada semana | `.github/dependabot.yml:10`, `:26`, `:31` y `:46` (`interval: weekly` para pip, docker, docker-compose y github-actions). CodeQL corre en cada PR como check obligatorio (ver 5.3). La alerta 8 de CodeQL, media, está abierta desde el 18 nov y su plazo de 30 días vence el 18 dic | Conforme. La alerta va al objetivo 2 del acta |
| 8.9 Configuración | Todo en `docker-compose.yml`, con imágenes fijadas y puertos solo en 127.0.0.1 | `docker-compose.yml:7` (`postgres:16.15`), `:30` (`valkey/valkey:8.1.11`) y los tres puertos publicados en `:16`, `:34` y `:135`, todos en 127.0.0.1. La imagen propia parte de `python:3.15-slim` (`Dockerfile:57`), que fija la versión menor y no el parche | Conforme, con la observación H4 |
| 8.12 Prevención de fugas | gitleaks como pre-commit y en el job de seguridad del CI sobre toda la historia, con `.gitleaks.toml` | `.pre-commit-config.yaml:5-8`, `.github/workflows/seguridad.yml:25` (todo el historial) y `.gitleaks.toml`. `seguridad` es check obligatorio de BackKL (ver 5.3) | Conforme |
| 8.31 Separación de entornos | El candado de `pruebas/pila.py` no deja correr las pruebas contra `cirdan-pg16`, `cirdan-valkey` ni `cirdan-api` | `pruebas/pila.py:18-20` (`DESARROLLO = {'cirdan-pg16', 'cirdan-valkey', 'cirdan-api'}`). RC-254 en Done | Conforme |
| 8.32 Gestión de cambios | Migraciones numeradas que no se editan y PR con la clave de Jira | `.github/workflows/pruebas.yml:31-45` frena un PR con una migración fuera de `NNN_descripcion.sql` o con un hueco en la numeración. Van de la 001 a la 033 sin huecos. Las ramas piden PR (ver 8.4) | Conforme |

Resultado: 9 conformes sin hallazgo, 3 conformes con una observación (5.9, 5.33 y 8.9) y 1 no conformidad menor (8.4). 5.15 se cubre con la evidencia de 8.3.

## 6. Hallazgos

Ninguno tiene tarjeta todavía. El texto de cada tarjeta propuesta espera el OK de Ernesto antes de crearla en Jira.

### H1. BackKL `dev` acepta force push (control 8.4, no conformidad menor)

1. Qué se vio: `gh api repos/Kernel-Loco/BackKL/branches/dev/protection` da `allow_force_pushes.enabled: true`. BackKL `main`, FrontKL `dev` y FrontKL `main` lo tienen en `false`, y el respaldo de la protección de ramas del 9 oct lo tenía en `false` también en BackKL `dev`. No se sabe cuándo ni quién lo cambió.
2. Por qué importa: el control dice que nadie sube directo a `dev`, y la regla 12 del equipo prohíbe `push --force` y reescribir historial ya subido. Con la opción activa, la regla depende de cada persona y no de GitHub.
3. Decisión: corregir. Tarjeta propuesta, 'BackKL: `dev` sin force push, igual que `main`'. Está lista cuando `gh api repos/Kernel-Loco/BackKL/branches/dev/protection` da `allow_force_pushes.enabled: false` sin cambiar los checks obligatorios ni `enforce_admins`, y la tarjeta anota la salida antes y después. Es un cambio de configuración de GitHub, no de código, así que cabe en el congelamiento.

### H2. El control 5.33 dice que falta revisar la cadena (observación)

1. Qué se vio: la fila dice 'Falta revisar la cadena (#86)', pero `GET /api/v1/audit-log/verify` ya recalcula la cadena de hashes (`cirdan/api/bitacora.py:29-31`).
2. Decisión: corregir el texto. Va en la tarjeta propuesta en H3.

### H3. Textos que esperan a tarjetas que ya están en Done (observación)

1. Qué se vio al leer la sección 4, fuera de la muestra: 5.14 y 8.24 dicen que el TLS de entrada llega con RC-91, 8.15 dice que la IP real llega con el despliegue de RC-91 y 8.13 dice que falta el respaldo automático en la VM. RC-91 está en Done desde el 15 nov y RC-233 (respaldo diario) también está en Done. Esta auditoría no revisó si esos controles ya se cumplen, solo que su texto todavía espera a tarjetas cerradas.
2. Dentro de la muestra (5.9): `docs/servicios_externos.md:122` y `:143` dicen que el plan Core 1 de Have I Been Pwned está sin comprar, y RC-54 lo compró el 23 nov (comentario 10612).
3. Decisión: corregir el texto. Tarjeta propuesta, 'Política y servicios externos: textos al día tras RC-91, RC-233 y RC-54'. Está lista cuando 5.14, 8.13, 8.15, 8.24 y 5.33 de la política y las líneas de Have I Been Pwned de `servicios_externos.md` dicen lo que hay hoy, con archivo:línea o clave RC, cada control sube o no su estado según esa evidencia, y el docx sigue al md. Solo documento.

### H4. La imagen propia fija la versión menor de Python y no el parche (observación)

1. Qué se vio: `Dockerfile:57` usa `python:3.15-slim`, así que dos construcciones del mismo commit pueden traer parches distintos de Python. Las imágenes de `docker-compose.yml` sí fijan el parche.
2. Decisión: se acepta. Dependabot revisa la imagen cada semana (`.github/dependabot.yml:22-26`) y Trivy la revisa en cada PR y frena con cualquier vulnerabilidad crítica (`.github/workflows/imagenes.yml:3`). Hasta la siguiente auditoría.
