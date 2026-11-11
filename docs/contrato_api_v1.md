# Contrato de API v1 (#21)

Lo que devuelve la API v1 de Cirdan (`cirdan/api/v1.py`), con un JSON de ejemplo por respuesta en [`api_v1/`](api_v1/). El portal (RC-17a, #40a) ya lee la API v1 real con la sesión (`src/services/queries.ts` en FrontKL). Si la API no está arriba, el portal no lee estos archivos en su lugar. Siguen sirviendo de plan B en las demos. FrontKL tiene una copia en `src/mocks/api/contrato.ts`, que hoy solo usa el alta simulada de dominios (#26). El dataset de ML (#33, RC-65) todavía no los usa. Los ejemplos salen de los datos demo de `db/semillas/001_datos_demo.sql` (Acme Demo) y de la corrección de su score en `db/semillas/009_score_demo_motor.sql`, así que la API real debe devolver lo mismo con esa base. `pruebas/test_contrato_api.py` revisa que los ejemplos cumplan el criterio de criticidad (#29) y el contrato de plugin (#13).

## Reglas generales

- **Prefijo:** todo cuelga de `/api/v1`. En el portal (FrontKL), el navegador llama a `/api/v1` en el propio portal y `next.config.ts` reenvía esas rutas a FastAPI en `API_INTERNAL_URL`, así que la cookie de sesión es del mismo sitio. Las lecturas que hace el servidor de Next van directo a `API_INTERNAL_URL` (`src/lib/apiServer.ts`). `/health` se queda fuera del prefijo para Docker y el monitoreo.
- **Cliente:** cada respuesta trae solo los datos de la empresa de quien llama, porque RLS filtra en la base. La empresa sale de la sesión (cookie httpOnly `lt_session`), que se crea al iniciar sesión en `/api/v1/auth` con contraseña y, si la cuenta lo tiene activo, código MFA (#25). La API nunca toma la empresa de un encabezado: ninguna ruta acepta `X-Organization`. `/db/tables` y `/db/tables/{table}/rows`, que usa la página `/demo`, solo existen con `DEMO_EXPLORER=true`, también toman la empresa de la sesión y solo responden al rol `admin` (RC-58). Un integrador entra con una llave de API en `Authorization: Bearer` en vez de la cookie (#87): ahí la empresa sale de la fila de la llave. Ver [Llaves de API](#llaves-de-api-87).
- **Nombres de campos en inglés y valores con los códigos de la base:** `critical`, `infrastructure`, `ct_logs`, `open`. El portal muestra los nombres en español con `src/config/labels.ts`. La única excepción es `caracteristicas`, que conserva las claves en español del contrato de plugin (#13) para que el dataset de ML use los mismos nombres de punta a punta.
- **Fechas:** ISO 8601 con zona, en hora de la Ciudad de México (`2026-09-30T14:24:30-06:00`). Las que son solo día, como la vigencia de una autorización, van como `2026-12-31`.
- **Listas:** `{"items": [...], "total": n}`. Cuando haya paginación se agregan `limit` y `offset` sin romper lo demás.
- **Errores:** el formato de FastAPI, `{"detail": "texto en español"}` ([`error.json`](api_v1/error.json)). 400 parámetro inválido, 401 sin sesión o con una llave de API que no es válida, venció o fue revocada, 403 el rol o el plan no lo permite, 404 no existe o es de otra empresa (se ven igual a propósito), 409 escaneo rechazado por autorización o TXT (#22), 422 falta un campo.
- **Campos nuevos:** se pueden agregar sin cambiar de versión. Quitar o renombrar uno pide `/api/v2`.

## Endpoints

| Método y ruta | Ejemplo | Qué devuelve |
|---|---|---|
| `GET /api/v1/domains` | [`dominios.json`](api_v1/dominios.json) | Dominios de la empresa con su autorización, TXT, si se pueden escanear, score y conteo de hallazgos abiertos |
| `GET /api/v1/domains/{fqdn}/findings` | [`hallazgos.json`](api_v1/hallazgos.json) | Hallazgos abiertos del dominio, de más a menos severo. Todavía no hay filtro `?status` |
| `GET /api/v1/domains/{fqdn}/score` | [`score.json`](api_v1/score.json) | El score más reciente con su letra (`grade`), su desglose por categoría, sus hallazgos por subcategoría (`subcategories`) y los 5 KRI con su cobertura (`kris`, #114) |
| `GET /api/v1/domains/{fqdn}/score/history` | [`historico.json`](api_v1/historico.json) | Todos los scores del dominio, del más viejo al más nuevo |
| `GET /api/v1/findings/{id}/explanation` | [`explicacion.json`](api_v1/explicacion.json) | Por qué el hallazgo tiene su severidad y cuánto suma al score |
| `GET /api/v1/scoring/weights` | [`pesos.json`](api_v1/pesos.json) | El juego de reglas activo: pesos, bandas, letras (`grades`, #114), piso, umbral y reglas |
| `GET /api/v1/domains/{fqdn}/action-plan` | — | Acciones abiertas agrupadas por regla, con su recomendación y reducción estimada de score (#42) |
| `POST /api/v1/domains/{fqdn}/action-plan/simulate` | — | Score contrafactual al resolver varias acciones, sin guardar cambios (#70) |
| `GET /api/v1/domains/{fqdn}/action-plan/export?formato=csv\|json` | — | Descarga el plan; CSV UTF-8 con BOM y escape contra fórmulas |
| `GET /api/v1/domains/{fqdn}/findings/export?formato=csv\|json` | — | Descarga los hallazgos abiertos del dominio (#24). El JSON es igual a `/findings` y el CSV trae una fila por hallazgo |
| `GET /api/v1/domains/{fqdn}/score/compare?desde=<score_id>&hasta=<score_id>` | — | Compara hallazgo por hallazgo dos puntos de `/score/history` (#24): cuáles son nuevos, cuáles ya no están y cuáles siguen, con su severidad y sus puntos en cada uno |
| `GET /api/v1/domains/{fqdn}/score/compare/export?desde=…&hasta=…&formato=csv\|json` | — | Descarga la comparación |

Comparación y exportaciones (#24, RC-57). Las tres rutas piden autorización firmada vigente: un dominio de la empresa sin ella responde 403 y uno de otra empresa 404, como el resto de la API. Un `score_id` que no es del dominio, que no existe o que no es un UUID responde 404. La comparación usa los aportes que cada score guardó en `score_contributions`, que son la foto de los hallazgos vigentes (open y accepted_risk) en ese momento. `change` es `new` (está en `hasta` y no en `desde`), `gone` (al revés) o `kept`, y `severity_changed` marca los que siguen con otra severidad. `gone` no dice por qué ya no está: `status_now` trae el estado de hoy. `summary` cuenta cada caso. Los scores de la semilla 001 solo guardaron el aporte de la brecha, así que comparar contra ellos marca como nuevos los demás hallazgos. Los CSV van en UTF-8 con BOM y fin de línea CRLF, y toda celda de texto que empiece con =, +, -, @, tabulador o retorno de carro lleva una comilla al inicio (OWASP). Como Excel con separador ';' y LibreOffice con ';' o tabulador parten la celda ahí, también lleva comilla un inicio de fórmula (aunque tenga comillas dobles antes) que sigue a un ';', un tabulador o un salto de línea, y la celda con ';' o tabulador va entre comillas. Ese escape a mitad del texto también aplica al CSV y al JSON del plan. Los números no se escapan. Las listas y la evidencia van como JSON en una celda. El JSON de estas descargas no se escapa, porque no lo abre una hoja de cálculo. El del plan sí, como antes.

La simulación recibe `{"action_ids": ["spf_missing", "secret_in_public_repo"]}`. `action_ids` usa los ids de acciones devueltos por el plan, en este momento códigos de regla. La respuesta incluye score y banda antes/después, reducción y notas por categoría. Las acciones desconocidas o sin hallazgos abiertos responden 422. La simulación no escribe hallazgos, scores ni bitácora. En el plan y en la simulación, el score, la banda y las notas 'antes' son las del último score guardado, las mismas de `/score`. Si el dominio no tiene score guardado, salen del motor. El 'después' se recalcula con el motor (#31) y la reducción es lo que baja el motor al resolver esas acciones, así que nunca es negativa. Si el score guardado no cuadra con los hallazgos de ese momento (un escaneo en curso o caído), 'antes' menos la reducción puede no dar 'después'.

## Llaves de API (#87)

Para que un integrador lea la API sin la sesión del portal. Las crea, lista y revoca el Administrador, con su sesión.

| Método y ruta | Qué hace |
|---|---|
| `POST /api/v1/api-keys` | Crea una llave. Antes revisa en la base que la cuenta siga activa y siga siendo Admin: si no, responde 401 y borra la sesión. Recibe `name` (1 a 80 caracteres), `domain` (opcional: sin él la llave ve todos los dominios de la empresa) y `expires_in_days` (1 a 90, por omisión 90). Responde 201 con la llave completa en `key`. Es la única vez que se muestra |
| `GET /api/v1/api-keys` | Las llaves de la empresa: `id`, `name`, `key_prefix`, `domain`, `scopes`, `created_by`, `created_at`, `expires_at`, `last_used_at`, `revoked_at` y `status` (`active`, `expired` o `revoked`). Nunca trae la llave |
| `DELETE /api/v1/api-keys/{id}` | Revoca la llave. Responde 204, también si ya estaba revocada. No se puede deshacer |

- **La llave** tiene la forma `lt_<8 hexadecimales>_<43 caracteres>`. La base solo guarda el prefijo (`lt_` y los 8 hexadecimales) y el SHA-256 de la llave completa, así que no se puede recuperar: si se pierde, se revoca y se crea otra.
- **Cómo se usa:** en el encabezado `Authorization: Bearer <llave>`. Con ese encabezado la cookie no cuenta: una llave que no sirve responde 401 aunque la petición traiga una sesión vigente.
- **Qué lee:** solo lecturas. Los `GET` de la tabla de Endpoints, `GET /api/v1/domains/{fqdn}/assets`, `GET /api/v1/scans` y `GET /api/v1/scans/{id}`. No entra a `/api/v1/auth`, a `/api/v1/api-keys`, a `GET /api/v1/domains/txt` ni a ningún `POST` o `PUT`: ahí responde 401, porque esas rutas solo conocen la sesión.
- **Aislamiento:** el mismo que con sesión. La llave solo ve los datos de su empresa, y la de un dominio solo ese dominio: los demás dominios de su empresa responden 404, igual que los de otra empresa. En la comparación de scores, un hallazgo que aportó al score del dominio y hoy pertenece a otro dominio de la empresa sale, para la llave de un dominio, con `asset`, `asset_type` y `status_now` en `null` y con el código de la regla como `title`. Sus puntos y su severidad en cada score sí salen, porque son del score de su dominio.
- **Vigencia:** máximo 90 días. Vencida o revocada responde 401. También responde 401 si la empresa queda suspendida o baja a un plan sin API, y vuelve a servir si la empresa regresa a un plan con API antes de que la llave venza.
- **Plan:** crear una llave pide un plan con API (Business o Enterprise). En otro plan responde 403. Listar y revocar no lo piden.
- **Tope:** 20 llaves vigentes por empresa. La siguiente responde 409 hasta que se revoque una.
- **Último uso:** `last_used_at` se actualiza a lo más una vez por minuto.
- **Bitácora:** crear y revocar quedan en `audit_log` como `api_key.created` y `api_key.revoked`, con el prefijo y nunca con la llave.

## Dominio (`dominios.json`)

| Campo | Qué es |
|---|---|
| `status` | `domains.status`: `pending_verification`, `verified` o `paused`. Los dominios en `removed` no salen en la lista |
| `authorization.status` | `valid`, `expired`, `revoked` o `missing`. Se toma la autorización vigente y, si no hay, la que vence más tarde. Una que todavía no entra en vigor cuenta como `missing` |
| `txt.status` | `verified` si la última consulta encontró el registro, `missing` si no |
| `scan_eligibility` | `can_scan` es `true` solo con autorización `valid`, TXT `verified` y dominio `verified`. Si es `false`, `reasons` dice por qué: `authorization_missing`, `authorization_not_started`, `authorization_expired`, `authorization_revoked`, `txt_not_verified` o `domain_paused`. El orquestador (#22) vuelve a consultar el TXT justo antes de escanear, así que esto es lo que el portal muestra, no el permiso final |
| `score`, `band`, `grade` | El score más reciente, su banda (#29) y su letra de la A a la F (#114). `null` si nunca se ha escaneado |
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
| `grade` | La letra del score final, ya con el piso: A de 0 a 19, B de 20 a 39, C de 40 a 59, D de 60 a 79 y F de 80 a 100. No hay E. Va en `score.json` y en cada punto del histórico (#114, [`criterio_criticidad.md`](criterio_criticidad.md)). Con `partial_coverage` en `true` lleva el mismo aviso que el score |
| `weighted`, `floor`, `floor_applied` | La suma ponderada, el piso por hallazgos críticos y si el piso subió el score. El portal muestra el aviso del piso cuando `floor_applied` es `true` (#29) |
| `floor_message` | Explicación en español del piso cuando aplica; `null` si el ponderado ya alcanza el mínimo |
| `critical_open` | Hallazgos que cuentan para el piso: `critical` y `open` o `accepted_risk` |
| `method` | `rules` o `ml` (#36) |
| `model_version` | Versión del clasificador; `null` si el score se calculó con reglas |
| `model_fallback_reason` | Motivo por el que este score usó reglas; `null` cuando se usó ML |
| `rule_set_version` | Versión del juego de reglas con que se calculó |
| `reason` | `scan`, `intel_update`, `rules_change` o `correction`. `correction` corrige un score guardado mal, sin escaneo ni cambio de reglas, como el de acme-demo.mx en `db/semillas/009_score_demo_motor.sql` |
| `partial_coverage` | `true` si alguna fuente falló en ese escaneo, no pudo revisar alguno de sus códigos (`sin_cobertura`) o revisó solo una parte de sus repos, IP o certificados de `ct_logs` (`revisados`) |
| `categories` | En `score.json`, una fila por categoría con nota, banda y peso, en el orden del reto. En `historico.json`, un objeto `{categoría: nota}` para graficar |
| `new_findings`, `resolved_findings` | Solo en el histórico: hallazgos nuevos y resueltos por el escaneo de ese punto, de `scans.stats`. Nuevos son los que el escaneo insertó y los que reabrió porque estaban resueltos. Resueltos son los que su fuente respondió y ya no dio, nunca los de una fuente caída ni lo que se queda abierto por `omitidos`, por `sin_cobertura` de una fuente que revisó todo o, en una corrida parcial, porque queda sin partes o trae una que no se revisó, salvo un `cert_expiring_soon` cuyo certificado ya venció (detalle en `docs/contrato_plugin.md`). Un escaneo cerrado antes de que el orquestador los contara (RC-55) no los guardó y da `null`, no 0. Lo que guardaron las fuentes de un escaneo que terminó `failed` o que el orquestador dio por caído no cuenta en ningún punto. Dan 0 en un recálculo (`reason` distinto de `scan`), que no encuentra ni resuelve hallazgos. El portal muestra un guion en los recálculos y en `null`. Con `partial_coverage` muestra los conteos, que no cuentan lo de la fuente que falló, lo de un código en `sin_cobertura` de una fuente que revisó todo ni lo que salió de una parte (repo, IP o certificado) que existe y no se revisó, salvo un `cert_expiring_soon` ya vencido. Los puntos de `historico.json` no los traen |
| `weekly_changes` | Solo en el histórico: resumen cuando el escaneo tuvo activos o hallazgos nuevos, o cuando el inventario creció más de 20 % frente al escaneo anterior completado/parcial de los últimos 7 días. `new_asset` y `new_finding` indican novedades en ese escaneo; `assets_growth_over_20_percent` usa los conteos `assets` de ambos escaneos y exige superar estrictamente 20 %. `assets_growth_percent` es `null` si no existe un escaneo anterior o si el anterior queda fuera de 7 días; cuando existe, sus identificador y fecha se incluyen como referencia. En recálculos y puntos sin novedades, el campo completo es `null`. Los activos nuevos se cuentan por su primera fecha de observación dentro del intervalo del escaneo; no se exponen sus nombres aquí |
| `subcategories` | Solo en `score.json` (#114): una fila por subcategoría del mapa, en su orden, con `category`, `subcategory` (la clave), `name`, `findings` (hallazgos vigentes en ese score) y `penalty` (lo que suman sus aportes de `score_contributions`). Salen todas, también las que están en 0. Si un aporte es de una regla que el mapa no conoce o tiene en otra categoría, va en una fila `other` de la categoría de su regla. Si esa regla es de un KRI, su aporte sigue contando en el KRI |
| `kris` | Solo en `score.json` (#114): los 5 KRI, en su orden. `kri` es la clave y `name` el nombre. `status` es `ok` (todas sus fuentes corrieron completas y ninguna regla suya quedó sin cobertura), `partial` (hay datos pero no de todo), `no_coverage` (alguna de sus fuentes corrió y no respondió en el escaneo del score, ninguna corrió o ninguna regla suya se revisó, porque quedó sin cobertura o porque su fuente no corrió) o `no_source_yet` (aún no tiene fuente, como `reputation`). `findings`, `max_severity` y `penalty` son sus hallazgos vigentes, su severidad más alta y lo que suman. Con `no_coverage` o `no_source_yet` los tres van en `null`, nunca en cero: el portal no los pinta como sin riesgo. Con `ok` o `partial` y sin hallazgos, `max_severity` es `null`, y solo con `ok` un cero quiere decir que no se encontró nada: con `partial` el portal pone aviso. `subcategories` y `sources` dicen qué junta y qué fuentes lo alimentan, `sources_failed` cuáles no respondieron, `sources_not_run` cuáles no corrieron en ese escaneo, `sources_partial` cuáles revisaron solo una parte y `rules_without_coverage` qué reglas suyas quedaron sin cobertura en ese escaneo (no trae las de una fuente que no corrió). `sources_partial` va por fuente, no por regla. Los KRI no cubren todo el score |
| `kri_map_version` | Solo en `score.json`: versión del mapa de subcategorías y KRI (`cirdan/score/subcategorias.py`) |
| `alert` | El umbral de la empresa y si este score dispara `score.above_threshold`. Usa el score de 0 a 100, no la letra |

Los `kris` de `score.json` son los de la semilla de demo (`db/semillas/001_datos_demo.sql`, que no se edita), y `pruebas/test_api_v1.py` los compara con lo que la API devuelve con esa semilla. Por eso tienen dos cosas que un escaneo real no da:

- Certificados cuenta el `cert_expired` de dev.acme-demo.mx, que la semilla atribuye a `shodan` (ver `hallazgos.json`). En un escaneo real esa regla solo la emite `ct_logs`. Un KRI junta sus aportes por código de regla, sin mirar qué fuente trajo el hallazgo.
- Exposición de servicios sale con `rules_without_coverage` vacío y el score con `partial_coverage` en `false`, porque el escaneo sembrado no guarda `rules_without_coverage` en `scans.stats`. En un escaneo real `shodan` deja siempre `exposed_iot_device` y `exposed_ot_device` sin cobertura (`SIN_LLAVE` en `cirdan/recolectores/shodan.py`), así que esas dos reglas salen en `rules_without_coverage` del KRI y el score sale con `partial_coverage` en `true`.

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

Los del juego de reglas v1 de la base: infraestructura 30 %, identidad digital 20 %, configuración 20 % y fugas de datos 30 %, con las bandas, las letras (`grades`, #114), el piso y el umbral de `cirdan/score/criterio.py`. Emilio los confirmó para este contrato, por eso `validated_by` dice `Emilio`. Si cambian, se crea el juego v2 (#32) y se actualizan este archivo y la semilla.
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
