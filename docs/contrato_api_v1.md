# Contrato de API v1 (#21)

Lo que devolverá la API v1 de Cirdan, con un JSON de ejemplo por respuesta en [`api_v1/`](api_v1/). Lo usan el portal (RC-17a, #40a), el dataset de ML (#33) y, como plan B, las demos: si la API no está arriba, el portal puede leer estos archivos tal cual. Los ejemplos salen de los datos demo de `db/semillas/001_datos_demo.sql` (Acme Demo), así que la API real debe devolver lo mismo con esa base. `pruebas/test_contrato_api.py` revisa que los ejemplos cumplan el criterio de criticidad (#29) y el contrato de plugin (#13).

## Reglas generales

- **Prefijo:** todo cuelga de `/api/v1`, que es lo que el portal ya tiene en `NEXT_PUBLIC_API_URL`. `/health` se queda fuera del prefijo para Docker y el monitoreo.
- **Cliente:** cada respuesta trae solo los datos de la empresa de quien llama, porque RLS filtra en la base. En el portal la empresa sale de la sesión (cookie httpOnly) y en integraciones de la llave de API (`api_keys`). Mientras no exista el login (Germán), el modo demo sigue aceptando el encabezado `X-Organization` como la API actual.
- **Nombres de campos en inglés y valores con los códigos de la base:** `critical`, `infrastructure`, `ct_logs`, `open`. El portal muestra los nombres en español con `src/config/labels.ts`. La única excepción es `caracteristicas`, que conserva las claves en español del contrato de plugin (#13) para que el dataset de ML use los mismos nombres de punta a punta.
- **Fechas:** ISO 8601 con zona, en hora de la Ciudad de México (`2026-09-30T14:24:30-06:00`). Las que son solo día, como la vigencia de una autorización, van como `2026-12-31`.
- **Listas:** `{"items": [...], "total": n}`. Cuando haya paginación se agregan `limit` y `offset` sin romper lo demás.
- **Errores:** el formato de FastAPI, `{"detail": "texto en español"}` ([`error.json`](api_v1/error.json)). 400 parámetro inválido, 401 sin sesión, 404 no existe o es de otra empresa (se ven igual a propósito), 409 escaneo rechazado por autorización o TXT (#22), 422 falta un campo.
- **Campos nuevos:** se pueden agregar sin cambiar de versión. Quitar o renombrar uno pide `/api/v2`.

## Endpoints

| Método y ruta | Ejemplo | Qué devuelve |
|---|---|---|
| `GET /api/v1/domains` | [`dominios.json`](api_v1/dominios.json) | Dominios de la empresa con su autorización, TXT, si se pueden escanear, score y conteo de hallazgos abiertos |
| `GET /api/v1/domains/{fqdn}/findings` | [`hallazgos.json`](api_v1/hallazgos.json) | Hallazgos del dominio, de más a menos severo. `?status=open` por defecto |
| `GET /api/v1/domains/{fqdn}/score` | [`score.json`](api_v1/score.json) | El score más reciente con su desglose por categoría |
| `GET /api/v1/domains/{fqdn}/score/history` | [`historico.json`](api_v1/historico.json) | Todos los scores del dominio, del más viejo al más nuevo |
| `GET /api/v1/findings/{id}/explanation` | [`explicacion.json`](api_v1/explicacion.json) | Por qué el hallazgo tiene su severidad y cuánto suma al score |
| `GET /api/v1/scoring/weights` | [`pesos.json`](api_v1/pesos.json) | El juego de reglas activo: pesos, bandas, piso, umbral y reglas |

## Dominio (`dominios.json`)

| Campo | Qué es |
|---|---|
| `status` | `domains.status`: `pending_verification`, `verified`, `paused` o `removed` |
| `authorization.status` | `valid`, `expired`, `revoked` o `missing`, según la autorización firmada más reciente |
| `txt.status` | `verified` si la última consulta encontró el registro, `missing` si no |
| `scan_eligibility` | `can_scan` es `true` solo con autorización `valid`, TXT `verified` y dominio `verified`. Si es `false`, `reasons` dice por qué: `authorization_missing`, `authorization_expired`, `authorization_revoked`, `txt_not_verified`, `domain_paused` o `domain_removed`. El orquestador (#22) vuelve a consultar el TXT justo antes de escanear, así que esto es lo que el portal muestra, no el permiso final |
| `score`, `band` | El score más reciente y su banda (#29). `null` si nunca se ha escaneado |
| `open_findings` | Hallazgos abiertos por severidad |

## Hallazgo (`hallazgos.json`)

| Campo | Qué es |
|---|---|
| `title` | En español y en lenguaje simple (`evidence.title` en la base) |
| `asset`, `asset_type` | El activo al que pertenece y su tipo (`assets.asset_type`) |
| `category`, `rule_code` | La categoría del reto y el código de su regla (`scoring_rules`) |
| `source` | `data_sources.code`: `ct_logs`, `dns`, `whois`, `shodan`, `hibp` o `censys` |
| `severity`, `base_severity` | La vigente y la de su regla. Son distintas cuando el motor la subió (#29) |
| `status` | `open`, `resolved`, `accepted_risk` o `false_positive` |
| `recurrence` | `new` si apareció en el último escaneo, `recurring` si ya venía de antes |
| `cve_id`, `cvss`, `epss`, `in_kev` | Datos de la CVE cuando el hallazgo tiene una. Si no, `null`, `null`, `null` y `false` |
| `evidence` | Lo que prueba el hallazgo, sin `title`. Nunca contraseñas, tokens ni datos de brechas más allá del hecho |
| `caracteristicas` | Las 4 del reto con las mismas claves y valores del [contrato de plugin](contrato_plugin.md#esquema-del-resultado): `tipo`, `antiguedad_dias`, `exposicion` (`directa` o `publica`) y `sensibilidad` (`baja`, `media` o `alta`) |

## Score (`score.json`) e histórico (`historico.json`)

| Campo | Qué es |
|---|---|
| `score`, `band` | El score final y su banda |
| `weighted`, `floor`, `floor_applied` | La suma ponderada, el piso por hallazgos críticos y si el piso subió el score. El portal muestra el aviso del piso cuando `floor_applied` es `true` (#29) |
| `critical_open` | Hallazgos que cuentan para el piso: `critical` y `open` o `accepted_risk` |
| `method` | `rules` o `ml` (#36) |
| `rule_set_version` | Versión del juego de reglas con que se calculó |
| `reason` | `scan`, `intel_update` o `rules_change` |
| `partial_coverage` | `true` si alguna fuente falló en ese escaneo |
| `categories` | En `score.json`, una fila por categoría con nota, banda y peso, en el orden del reto. En `historico.json`, un objeto `{categoría: nota}` para graficar |
| `alert` | El umbral de la empresa y si este score dispara `score.above_threshold` |

## Explicación (`explicacion.json`)

Viene de `score_contributions`. `penalty` es lo que el hallazgo suma a la nota de su categoría y `factors` lo desglosa, así que la suma de `points` es `penalty`, y nunca pasa de `max_penalty` de su regla. `summary` explica en una frase por qué tiene su severidad, con el criterio de «Qué hace crítico a un hallazgo» de #29. Con `method = 'ml'`, `shap` trae la contribución de cada característica según #35, como `[{"feature": "antiguedad_dias", "value": 104, "contribution": 0.21}]`. Con `rules` es `null`.

## Pesos (`pesos.json`)

Los del juego de reglas v1 de la base: infraestructura 30 %, identidad digital 20 %, configuración 20 % y fugas de datos 30 %, con las bandas, el piso y el umbral de `cirdan/score/criterio.py`. Emilio los confirmó para este contrato, por eso `validated_by` dice `Emilio`. Si cambian, se crea el juego v2 (#32) y se actualizan este archivo y la semilla.

## Qué cambia respecto a la API actual

La API inicial (#2) sigue igual hasta que se implemente v1. Las diferencias:

- Prefijo `/api/v1`.
- Códigos de la base en lugar de nombres para mostrar (`high`, no `High`).
- Más campos: ids, `scan_eligibility`, `caracteristicas`, piso y alerta.
- El histórico, la explicación y los pesos tienen endpoint propio.

En el portal, `FindingSource` cambia `ct` por `ct_logs` y agrega `whois`.
