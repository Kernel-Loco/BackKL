# Cirdan · Backend (BackKL)

Backend de Cirdan, la plataforma de gestión de la superficie de ataque externa con OSINT pasivo del reto IKUSI VELATIA: la base de datos, la API, los recolectores OSINT y el criterio de criticidad.

## Carpetas

| Carpeta | Qué tiene |
|---|---|
| `cirdan/api/` | API inicial en FastAPI y la página `/demo` |
| `cirdan/recolectores/` | Contrato de plugin (#13), recolectores OSINT pasivos (crt.sh, #14, y uno de ejemplo para pruebas) y sus respuestas grabadas, que usan las pruebas y el respaldo de las demos |
| `cirdan/score/` | Bandas, piso, ponderado y alerta del criterio de criticidad (#29) |
| `db/` | Base PostgreSQL 16: migraciones, semillas y consultas |
| `docs/` | Documentos del proyecto, con su índice |
| `pruebas/` | Pruebas automáticas de la base, de la API, del criterio de criticidad, del contrato de plugin y de crt.sh |
| `.env.example` | Variables que necesita todo lo anterior. Se copia como `.env` en la raíz y se le ponen contraseñas propias. `.env` no se sube al repositorio |

Todos los comandos se corren desde la raíz del repo.

## Base de datos

23 tablas (18 con Row-Level Security por cliente y 5 catálogos compartidos), datos de Acme Demo y Beta Corp, y el rol `cirdan_app` sin privilegios de más. Qué se creó, cómo cargarla y las decisiones respecto al DBML están en [`db/README.md`](db/README.md).

## Pruebas automáticas

`pruebas/test_aislamiento.py` corre 8 pruebas con la biblioteca estándar de Python (sin instalar nada) contra la base `cirdan`, entrando como `cirdan_app`: rol sin privilegios, RLS forzado en 18 tablas, Acme ve solo lo suyo (5 dominios, 4 hallazgos, 3 usuarios), Beta Corp ve 1, 1 y 1, sin cliente se ve 0, no se puede escribir a nombre de otro cliente, no se puede escanear con la autorización vencida y la bitácora no se modifica. Cada escritura va en una transacción que se deshace.

```bash
python -m unittest -v pruebas/test_aislamiento.py
```

El 2 oct 2026 pasaron 8 de 8.

## API inicial (FastAPI)

`cirdan/api/main.py` expone 4 endpoints de solo lectura: `GET /health`, `GET /domains`, `GET /domains/{fqdn}/findings` y `GET /domains/{fqdn}/score`. Entra como `cirdan_app` (contraseña en `.env`, `CIRDAN_APP_PASSWORD`) y en cada petición fija `app.current_org` con el encabezado `X-Organization`, así que el aislamiento lo aplica RLS. Un dominio de otro cliente responde 404. En producción el cliente se identificará con su llave de API (tabla `api_keys`).

```bash
python -m pip install fastapi uvicorn "psycopg[binary]"
python -m uvicorn cirdan.api.main:app --port 8000      # documentación en http://127.0.0.1:8000/docs
python -m unittest -v pruebas/test_aislamiento.py pruebas/test_api.py
```

El 2 oct 2026 pasaron las 14 pruebas (8 de la base y 6 de la API).

## Vista visual de la base (para la demo)

Con la API arriba, abre **http://127.0.0.1:8000/demo**. Muestra las 23 tablas agrupadas con las filas que ve el cliente elegido (Acme Demo, Beta Corp o sin cliente), las filas reales de la tabla que selecciones (sin columnas secretas), los dominios con su score y, al elegir uno, su desglose por categoría y sus hallazgos. El botón "Intentar como Beta Corp" muestra el 404 al pedir un dominio de Acme. Todo pasa por el rol `cirdan_app`, así que lo que se ve es lo que RLS deja ver. Archivos: `cirdan/api/explorer.py` y `cirdan/api/demo.html`.

## Recolector de crt.sh (#14)

`cirdan/recolectores/crtsh.py` lee los logs públicos de Certificate Transparency en crt.sh, sin tocar los servidores del dominio. Devuelve los subdominios como activos y tres tipos de hallazgo:

| Código de regla | Severidad base | Cuándo |
|---|---|---|
| `cert_expired` | high | El certificado más reciente de un nombre venció hace menos de un año (más viejo, el nombre queda solo como activo) |
| `cert_expiring_soon` | medium | El certificado más reciente vence en menos de 30 días |
| `lookalike_domain` | medium | Un dominio parecido tiene un certificado vigente o vencido hace menos de 90 días: contiene la marca, usa otro TLD o tiene un error tipográfico |

Cada hallazgo trae título en español, evidencia, las características del reto (tipo, antigüedad, exposición y sensibilidad) y una huella SHA-256 estable para no duplicarlo entre escaneos. Si crt.sh no responde después de 3 intentos, la fuente queda en `failed` sin activos ni hallazgos. Si solo fallan las variantes de dominios parecidos, el escaneo sigue y quedan avisos.

```bash
python -m cirdan.recolectores.crtsh acme-demo.mx                        # en vivo
python -m cirdan.recolectores.crtsh acme-demo.mx --sin-parecidos        # en vivo, solo subdominios y certificados (una consulta)
python -m cirdan.recolectores.crtsh acme-demo.mx --grabar               # en vivo y graba en cirdan/recolectores/respuestas_grabadas/crtsh/acme-demo.mx/
python -m cirdan.recolectores.crtsh acme-demo.mx --grabar --completar   # solo consulta lo que aún no está grabado
python -m cirdan.recolectores.crtsh acme-demo.mx --reproducir           # solo con las respuestas grabadas, sin red
python -m cirdan.recolectores.crtsh acme-demo.mx --json                 # el resultado completo en JSON
python -m unittest -v pruebas/test_crtsh.py                             # 37 pruebas sin red
```

Sin `--json` imprime un resumen en español para leer en una demo: los activos con su fecha de vencimiento y cada hallazgo con su severidad (alta, media) y sus características. Los datos conservan los códigos de la base (`high`, `medium`). Con `--reproducir`, la primera línea dice de cuándo es la grabación. Esa fecha va dentro de cada archivo grabado, así que no cambia al copiarlo o clonar el repo. Si falta alguna respuesta grabada, lo dice en una sola línea y no lo cuenta como falla de crt.sh. Código de salida: 0 bien, 1 si queda en `failed` y 2 si quedan avisos.

El día anterior a cada sesión y control se graba la respuesta real del dominio de prueba con `--grabar`. Cada dominio graba en su propia carpeta. `--grabar` la vacía y marca el inicio en cuanto crt.sh responde (si no responde, código 1, la grabación anterior queda intacta), así lo que no se grabe hoy, porque falló, se omitió por saturación o se interrumpió, aparece en la línea Faltan de `--reproducir` y nunca se mezcla con respuestas de días anteriores. Si crt.sh deja la grabación a medias (código de salida 2), se repite con `--grabar --completar` hasta que salga 0: solo vuelve a consultar lo que no se grabó desde ese inicio. La demo usa `--reproducir` como respaldo.

## Criterio de criticidad (#29)

Más alto = más riesgo. Bandas 0 a 39 bajo, 40 a 59 medio, 60 a 79 alto y 80 a 100 crítico, ancladas al ejemplo del reto (68 = riesgo alto). Regla de piso: un hallazgo crítico vigente deja el dominio al menos en 60, y dos o más, al menos en 80. La alerta se crea cuando el score llega al umbral o lo pasa. El criterio completo, con ejemplos y quién usa qué, está en `docs/criterio_criticidad.md`, y su código en `cirdan/score/criterio.py`.

```bash
python -m unittest -v pruebas/test_criterio.py   # 13 pruebas, sin base de datos
```

## Contrato de plugin (#13)

Todos los recolectores cumplen `cirdan/recolectores/contrato.py`:
- el esquema de activos y hallazgos, con las 4 características del reto
- la interfaz `FUENTE`, `crear_cliente()` y `recolectar()`
- el filtro de alcance
- los reintentos de `scan_source_runs` a 1, 5 y 25 minutos
- las respuestas grabadas

El orquestador usa `ejecutar()`, que nunca deja que un recolector tumbe el escaneo y deja en `failed` un resultado que no cumple el contrato o que es de otro dominio. `cargar(fuente)` devuelve el recolector de cada `data_sources.code`, y `ejemplo` sirve para probar sin red. El detalle está en `docs/contrato_plugin.md`.

```bash
python -m unittest -v pruebas/test_contrato.py   # 36 pruebas, sin red
```
