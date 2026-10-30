# Contrato de API v1 (#21)

Lo que devuelve la API v1 de Cirdan (`cirdan/api/v1.py`), con un JSON de ejemplo por respuesta en [`api_v1/`](api_v1/). El portal (RC-17a, #40a) ya lee la API v1 real con la sesión (`src/services/queries.ts` en FrontKL). Si la API no está arriba, el portal no lee estos archivos en su lugar. Siguen sirviendo de plan B en las demos. FrontKL tiene una copia en `src/mocks/api/contrato.ts`, que hoy solo usa el alta simulada de dominios (#26). El dataset de ML (#33, RC-65) todavía no los usa. Los ejemplos salen de los datos demo de `db/semillas/001_datos_demo.sql` (Acme Demo) y de la corrección de su score en `db/semillas/009_score_demo_motor.sql`, así que la API real debe devolver lo mismo con esa base. `pruebas/test_contrato_api.py` revisa que los ejemplos cumplan el criterio de criticidad (#29) y el contrato de plugin (#13).

## Reglas generales

- **Prefijo:** todo cuelga de `/api/v1`. En el portal (FrontKL), el navegador llama a `/api/v1` en el propio portal y `next.config.ts` reenvía esas rutas a FastAPI en `API_INTERNAL_URL`, así que la cookie de sesión es del mismo sitio. Las lecturas que hace el servidor de Next van directo a `API_INTERNAL_URL` (`src/lib/apiServer.ts`). `/health` se queda fuera del prefijo para Docker y el monitoreo.
- **Cliente:** cada respuesta trae solo los datos de la empresa de quien llama, porque RLS filtra en la base. La empresa sale de la sesión (cookie httpOnly `lt_session`), que se crea al iniciar sesión en `/api/v1/auth` con contraseña y, si la cuenta lo tiene activo, código MFA (#25). La API nunca toma la empresa de un encabezado: ninguna ruta acepta `X-Organization`. `/db/tables` y `/db/tables/{table}/rows`, que usa la página `/demo`, solo existen con `DEMO_EXPLORER=true`, también toman la empresa de la sesión y solo responden al rol `admin` (RC-58). La tabla `api_keys` existe en la base, pero la API todavía no acepta llaves de API.
- **Nombres de campos en inglés y valores con los códigos de la base:** `critical`, `infrastructure`, `ct_logs`, `open`. El portal muestra los nombres en español con `src/config/labels.ts`. La única excepción es `caracteristicas`, que conserva las claves en español del contrato de plugin (#13) para que el dataset de ML use los mismos nombres de punta a punta.
- **Fechas:** ISO 8601 con zona, en hora de la Ciudad de México (`2026-09-30T14:24:30-06:00`). Las que son solo día, como la vigencia de una autorización, van como `2026-12-31`.
- **Listas:** `{"items": [...], "total": n}`. Cuando haya paginación se agregan `limit` y `offset` sin romper lo demás.
- **Errores:** el formato de FastAPI, `{"detail": "texto en español"}` ([`error.json`](api_v1/error.json)). 400 parámetro inválido, 401 sin sesión, 404 no existe o es de otra empresa (se ven igual a propósito), 409 escaneo rechazado por autorización o TXT (#22), 422 falta un campo.
- **Campos nuevos:** se pueden agregar sin cambiar de versión. Quitar o renombrar uno pide `/api/v2`.

## Endpoints

| Método y ruta | Ejemplo | Qué devuelve |
|---|---|---|
| `GET /api/v1/domains` | [`dominios.json`](api_v1/dominios.json) | Dominios de la empresa con su autorización, TXT, si se pueden escanear, score y conteo de hallazgos abiertos |
| `GET /api/v1/domains/{fqdn}/findings` | [`hallazgos.json`](api_v1/hallazgos.json) | Hallazgos abiertos del dominio, de más a menos severo. Todavía no hay filtro `?status` |
| `GET /api/v1/domains/{fqdn}/score` | [`score.json`](api_v1/score.json) | El score más reciente con su desglose por categoría |
| `GET /api/v1/domains/{fqdn}/score/history` | [`historico.json`](api_v1/historico.json) | Todos los scores del dominio, del más viejo al más nuevo |
| `GET /api/v1/findings/{id}/explanation` | [`explicacion.json`](api_v1/explicacion.json) | Por qué el hallazgo tiene su severidad y cuánto suma al score |
| `GET /api/v1/scoring/weights` | [`pesos.json`](api_v1/pesos.json) | El juego de reglas activo: pesos, bandas, piso, umbral y reglas |
| `GET /api/v1/domains/{fqdn}/action-plan` | — | Acciones abiertas agrupadas por regla, con su recomendación y reducción estimada de score (#42) |
| `POST /api/v1/domains/{fqdn}/action-plan/simulate` | — | Score contrafactual al resolver varias acciones, sin guardar cambios (#70) |
| `GET /api/v1/domains/{fqdn}/action-plan/export?formato=csv\|json` | — | Descarga el plan; CSV UTF-8 con BOM y escape contra fórmulas |

La simulación recibe `{"action_ids": ["spf_missing", "secret_in_public_repo"]}`. `action_ids` usa los ids de acciones devueltos por el plan, en este momento códigos de regla. La respuesta incluye score y banda antes/después, reducción y notas por categoría. Las acciones desconocidas o sin hallazgos abiertos responden 422. La simulación no escribe hallazgos, scores ni bitácora. En el plan y en la simulación, el score, la banda y las notas 'antes' son las del último score guardado, las mismas de `/score`. Si el dominio no tiene score guardado, salen del motor. El 'después' se recalcula con el motor (#31) y la reducción es lo que baja el motor al resolver esas acciones, así que nunca es negativa. Si el score guardado no cuadra con los hallazgos de ese momento (un escaneo en curso o caído), 'antes' menos la reducción puede no dar 'después'.

## Dominio (`dominios.json`)

| Campo | Qué es |
|---|---|
| `status` | `domains.status`: `pending_verification`, `verified` o `paused`. Los dominios en `removed` no salen en la lista |
| `authorization.status` | `valid`, `expired`, `revoked` o `missing`. Se toma la autorización vigente y, si no hay, la que vence más tarde. Una que todavía no entra en vigor cuenta como `missing` |
| `txt.status` | `verified` si la última consulta encontró el registro, `missing` si no |
| `scan_eligibility` | `can_scan` es `true` solo con autorización `valid`, TXT `verified` y dominio `verified`. Si es `false`, `reasons` dice por qué: `authorization_missing`, `authorization_not_started`, `authorization_expired`, `authorization_revoked`, `txt_not_verified` o `domain_paused`. El orquestador (#22) vuelve a consultar el TXT justo antes de escanear, así que esto es lo que el portal muestra, no el permiso final |
| `score`, `band` | El score más reciente y su banda (#29). `null` si nunca se ha escaneado |
| `open_findings` | Hallazgos abiertos por severidad |

## Hallazgo (`hallazgos.json`)

| Campo | Qué es |
|---|---|
| `title` | En español y en lenguaje simple (`evidence.title` en la base) |
| `asset`, `asset_type` | El activo al que pertenece y su tipo (`assets.asset_type`) |
| `category`, `rule_code` | La categoría del reto y el código de su regla (`scoring_rules`) |
| `source` | `data_sources.code`: `ct_logs`, `dns`, `whois`, `shodan`, `hibp` o `censys` |
| `severity`, `base_severity` | La severidad del último score (incluye la predicción ML cuando se usó `method = 'ml'`; si no hay contribución, la guardada en el hallazgo) y la de su regla. Son distintas cuando el motor la subió (#29) o el score usó ML (#36) |
| `status` | Hoy siempre es `open`, porque el endpoint solo trae abiertos. En la base también existen `resolved`, `accepted_risk` y `false_positive` |
| `recurrence` | `new` si apareció en el último escaneo, `recurring` si ya venía de antes |
| `cve_id`, `cvss`, `epss`, `in_kev` | Datos de la CVE cuando el hallazgo tiene una. Si no, `null`, `null`, `null` y `false` |
| `evidence` | Lo que prueba el hallazgo, sin `title`, `huella`, `caracteristicas` ni `partes`. Nunca contraseñas, tokens ni datos de brechas más allá del hecho |
| `caracteristicas` | Las 4 del reto con las mismas claves y valores del [contrato de plugin](contrato_plugin.md#esquema-del-resultado): `tipo`, `antiguedad_dias`, `exposicion` (`directa` o `publica`) y `sensibilidad` (`baja`, `media` o `alta`) |

## Score (`score.json`) e histórico (`historico.json`)

| Campo | Qué es |
|---|---|
| `score`, `band` | El score final y su banda |
| `weighted`, `floor`, `floor_applied` | La suma ponderada, el piso por hallazgos críticos y si el piso subió el score. El portal muestra el aviso del piso cuando `floor_applied` es `true` (#29) |
| `floor_message` | Explicación en español del piso cuando aplica; `null` si el ponderado ya alcanza el mínimo |
| `critical_open` | Hallazgos que cuentan para el piso: `critical` y `open` o `accepted_risk` |
| `method` | `rules` o `ml` (#36) |
| `model_version` | Versión del clasificador; `null` si el score se calculó con reglas |
| `model_fallback_reason` | Motivo por el que este score usó reglas; `null` cuando se usó ML |
| `rule_set_version` | Versión del juego de reglas con que se calculó |
| `reason` | `scan`, `intel_update`, `rules_change` o `correction`. `correction` corrige un score guardado mal, sin escaneo ni cambio de reglas, como el de acme-demo.mx en `db/semillas/009_score_demo_motor.sql` |
| `partial_coverage` | `true` si alguna fuente falló en ese escaneo, no pudo revisar alguno de sus códigos (`sin_cobertura`) o revisó solo una parte de sus repos o IP (`revisados`) |
| `categories` | En `score.json`, una fila por categoría con nota, banda y peso, en el orden del reto. En `historico.json`, un objeto `{categoría: nota}` para graficar |
| `new_findings`, `resolved_findings` | Solo en el histórico: hallazgos nuevos y resueltos por el escaneo de ese punto, de `scans.stats`. Nuevos son los que el escaneo insertó y los que reabrió porque estaban resueltos. Resueltos son los que su fuente respondió y ya no dio, nunca los de una fuente caída ni lo que se queda abierto por `omitidos`, por `sin_cobertura` o, en una corrida parcial, porque queda sin partes o trae una que no se revisó (detalle en `docs/contrato_plugin.md`). Un escaneo cerrado antes de que el orquestador los contara (RC-55) no los guardó y da `null`, no 0. Lo que guardaron las fuentes de un escaneo que terminó `failed` o que el orquestador dio por caído no cuenta en ningún punto. Dan 0 en un recálculo (`reason` distinto de `scan`), que no encuentra ni resuelve hallazgos. El portal muestra un guion en los recálculos y en `null`. Con `partial_coverage` muestra los conteos, que no cuentan lo de la fuente que falló ni lo que no se revisó. Los puntos de `historico.json` no los traen |
| `alert` | El umbral de la empresa y si este score dispara `score.above_threshold` |

## Explicación (`explicacion.json`)

Viene de `score_contributions`. `penalty` es lo que el hallazgo suma a la nota de su categoría, no al score final, y `factors` lo desglosa, así que la suma de `points` es `penalty`. `max_penalty` es el tope de su regla para cada hallazgo: un hallazgo nunca suma más que eso, pero varios hallazgos de la misma regla suman cada uno su `penalty`. `summary` explica en una frase por qué tiene su severidad, con el criterio de «Qué hace crítico a un hallazgo» de #29. `method` indica qué método calculó el score. Con `method = 'ml'`, `shap` trae la contribución de cada característica según #35, como `[{"feature": "antiguedad_dias", "value": 104, "contribution": 0.21}]`. Si el modelo cargó pero no superó el baseline, `method = 'rules'` y la respuesta aún puede incluir SHAP como explicación sin aplicar la predicción al score; si el artefacto no cargó o falló la inferencia, los campos explicativos son `null`.

Los textos de la regla salen del catálogo `scoring_rule_texts` (#30), uno por código, en lenguaje simple y sin siglas. Siempre llegan los tres, nunca `null`, porque la migración 003 obliga a que toda regla tenga su texto. `model_version` identifica el clasificador que calculó el score; `explanation_model_version` identifica el que produjo la explicación y puede existir aunque el score haya usado reglas. `model_prediction` es la severidad predicha. `confidence` es la salida no calibrada de `predict_proba`, y `shap` contiene las tres características de mayor magnitud. La confianza es una señal del modelo, no una probabilidad verificada:

| Campo | Qué es |
|---|---|
| `title` | El título del hallazgo (`evidence.title`), igual que en `hallazgos.json`. No es el de la regla |
| `rule_title` | El título de la regla, el mismo para todos los hallazgos con ese `rule_code` |
| `meaning` | Qué significa el hallazgo, en una o dos frases |
| `recommendation` | Qué hacer, en una o dos frases |

## Pesos (`pesos.json`)

Los del juego de reglas v1 de la base: infraestructura 30 %, identidad digital 20 %, configuración 20 % y fugas de datos 30 %, con las bandas, el piso y el umbral de `cirdan/score/criterio.py`. Emilio los confirmó para este contrato, por eso `validated_by` dice `Emilio`. Si cambian, se crea el juego v2 (#32) y se actualizan este archivo y la semilla.
La API real devuelve `validated_by` en `null`, porque la semilla no lo llena.

`rules` trae las 30 reglas del juego v1 en orden de id: las 7 de la semilla 001 y las 23 de la semilla 004 (#14 a #20 y las previstas de #62 a #64). `pruebas/test_api_v1.py` las compara una por una con la API.

| Campo | Qué es |
|---|---|
| `code`, `category`, `base_severity` | El código de la regla, su categoría y la severidad con que nace un hallazgo |
| `weight` | Peso dentro de su categoría. Con la suma por categoría no cambia la nota, y las 23 reglas nuevas llevan `1.0` |
| `max_penalty` | Lo más que suma cada hallazgo de esta regla a la nota de su categoría. El tope es por hallazgo, no por regla |
| `title`, `meaning`, `recommendation` | Título, qué significa y qué hacer, de `scoring_rule_texts` (#30). Son los mismos que la explicación da como `rule_title`, `meaning` y `recommendation` |

## Qué cambia respecto a la API inicial

La API v1 ya existe en `cirdan/api/v1.py`. La API inicial (#2) sigue en `cirdan/api/main.py`, sin prefijo y ya con sesión. Las diferencias:

- Prefijo `/api/v1`.
- Códigos de la base en lugar de nombres para mostrar (`high`, no `High`).
- Más campos: ids, `scan_eligibility`, `caracteristicas`, piso y alerta.
- El histórico, la explicación y los pesos tienen endpoint propio.

En el portal, `FindingSource` ya usa `ct_logs` en lugar de `ct` y ya incluye `whois` (`src/types/findings.ts`).
