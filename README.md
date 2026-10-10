# Cirdan · Backend (BackKL)

Backend de Cirdan, la plataforma de gestión de la superficie de ataque externa con OSINT pasivo del reto IKUSI VELATIA: la base de datos, la API, los recolectores OSINT y el criterio de criticidad. El portal web (Next.js) está en [FrontKL](https://github.com/Kernel-Loco/FrontKL). Por ahora usa datos simulados y todavía no llama a esta API.

## Carpetas

| Carpeta | Qué tiene |
|---|---|
| `cirdan/api/` | API inicial en FastAPI y la página `/demo` |
| `cirdan/recolectores/` | Contrato de plugin (#13), recolectores OSINT pasivos (crt.sh, #14, y uno de ejemplo para pruebas) y sus respuestas grabadas para el respaldo de las demos (hoy solo está la del recolector de ejemplo) |
| `cirdan/score/` | Bandas, piso, ponderado y alerta del criterio de criticidad (#29) |
| `db/` | Base PostgreSQL 16: migraciones, semillas y consultas |
| `docs/` | Documentos del proyecto, con su índice |
| `pruebas/` | Pruebas automáticas de la base, de la API, del criterio de criticidad, del contrato de plugin y de crt.sh |
| `.env.example` | Plantilla del `.env`, que se copia en la raíz con contraseñas propias y nunca se sube al repositorio. Solo lo lee la API, que sin él no arranca: toma `CIRDAN_APP_PASSWORD` y `PGPORT`. `POSTGRES_PASSWORD` se usa al crear el contenedor. Los recolectores, el criterio y sus pruebas no lo necesitan |

## Requisitos

- Git y Python 3.13 (también funciona con 3.11).
- Docker encendido (en Windows, Docker Desktop). La base corre en el contenedor `cirdan-pg16`.
- Una terminal bash. En Windows, Git Bash: PowerShell no acepta la redirección `<` que usan los comandos de [`db/README.md`](db/README.md).

## Cómo empezar

Todos los comandos se corren desde la raíz del repo.

1. Clona el repo: `git clone https://github.com/Kernel-Loco/BackKL.git` y `cd BackKL`.
2. Crea el contenedor y carga la base con la sección «Cómo cargarla» de [`db/README.md`](db/README.md), que empieza por copiar `.env.example` como `.env`.
3. Crea un entorno virtual y actívalo. En Git Bash: `python -m venv .venv` y `source .venv/Scripts/activate`. En Linux o macOS: `python3 -m venv .venv` y `source .venv/bin/activate` (en Ubuntu y Debian, antes `sudo apt install python3-venv`).
4. Instala lo que usa la API (el `requirements.txt` llega con #7): `python -m pip install fastapi uvicorn "psycopg[binary]"`.
5. Corre las pruebas que no usan la base ni la red: `python -m unittest -v pruebas/test_criterio.py pruebas/test_contrato.py pruebas/test_crtsh.py` (86 pruebas).
6. Sigue con las secciones de abajo: las pruebas de la base, la API y su vista en http://127.0.0.1:8000/demo.

## Base de datos

23 tablas (18 con Row-Level Security por cliente y 5 catálogos compartidos), datos de Acme Demo y Beta Corp, y el rol `cirdan_app` sin privilegios de más. Qué se creó, cómo cargarla y las decisiones respecto al DBML están en [`db/README.md`](db/README.md).

## Pruebas de la base

`pruebas/test_aislamiento.py` corre 8 pruebas con la biblioteca estándar de Python (sin instalar paquetes) contra la base `cirdan` del contenedor `cirdan-pg16`, que debe estar cargado y encendido (`docker start cirdan-pg16` si se apagó, por ejemplo al reiniciar la PC). No usa el `.env`: entra con `docker exec` y el `psql` del contenedor, como `cirdan_app` y, en 2 pruebas, como `postgres`. Revisa el rol sin privilegios, RLS forzado en 18 tablas, Acme ve solo lo suyo (5 dominios, 4 hallazgos, 3 usuarios), Beta Corp ve 1, 1 y 1, sin cliente se ve 0, no se puede escribir a nombre de otro cliente, no se puede escanear con la autorización vencida y la bitácora no se modifica. Cada escritura va en una transacción que se deshace.

```bash
python -m unittest -v pruebas/test_aislamiento.py
```

El 2 oct 2026 pasaron 8 de 8.

## API inicial (FastAPI)

`cirdan/api/main.py` expone 4 endpoints de solo lectura: `GET /health`, `GET /domains`, `GET /domains/{fqdn}/findings` y `GET /domains/{fqdn}/score`. `cirdan/api/explorer.py` agrega los 2 que usa `/demo`, `GET /db/tables` y `GET /db/tables/{table}/rows`, así que `/docs` muestra 6. Entra como `cirdan_app` (contraseña en `.env`, `CIRDAN_APP_PASSWORD`) y en cada petición fija `app.current_org` con el encabezado `X-Organization`, así que el aislamiento lo aplica RLS. Un dominio de otro cliente responde 404. En producción el cliente se identificará con su llave de API (tabla `api_keys`).

Para probarlos en `/docs` con «Try it out», pon en `X-Organization` el id de Acme Demo (`20000000-0000-4000-8000-000000000001`) o el de Beta Corp (`20000000-0000-4000-8000-000000000002`). Sin el encabezado, los de `/domains` responden 422.

```bash
python -m uvicorn cirdan.api.main:app --port 8000      # se queda corriendo. Documentación en http://127.0.0.1:8000/docs
```

Con la API corriendo, en otra terminal y también desde la raíz del repo (activa ahí el entorno con `source .venv/Scripts/activate`, o `source .venv/bin/activate` en Linux o macOS):

```bash
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

Cada hallazgo trae título en español, evidencia, las características del reto (tipo, antigüedad, exposición y sensibilidad) y una huella SHA-256 estable para no duplicarlo entre escaneos. Para los subdominios consulta primero `%.dominio`. Si crt.sh no responde después de 3 intentos, busca por nombre con otros 3, sigue con lo que encuentre y deja un aviso de que pueden faltar subdominios. Si tampoco responde a esa búsqueda, la fuente queda en `failed` sin activos ni hallazgos. Si solo fallan las variantes de dominios parecidos, el escaneo sigue y quedan avisos.

```bash
python -m cirdan.recolectores.crtsh acme-demo.mx                        # en vivo
python -m cirdan.recolectores.crtsh acme-demo.mx --sin-parecidos        # en vivo, solo subdominios y certificados (una consulta, dos si falla la primera)
python -m cirdan.recolectores.crtsh acme-demo.mx --grabar               # en vivo y graba en cirdan/recolectores/respuestas_grabadas/crtsh/acme-demo.mx/
python -m cirdan.recolectores.crtsh acme-demo.mx --grabar --completar   # solo consulta lo que aún no está grabado
python -m cirdan.recolectores.crtsh acme-demo.mx --reproducir           # solo con las respuestas grabadas, sin red (antes hay que grabar)
python -m cirdan.recolectores.crtsh acme-demo.mx --json                 # el resultado completo en JSON
python -m unittest -v pruebas/test_crtsh.py                             # 37 pruebas sin red
```

Sin `--json` imprime un resumen en español para leer en una demo: los activos con su fecha de vencimiento y cada hallazgo con su severidad (alta, media) y sus características. Los datos conservan los códigos de la base (`high`, `medium`). Con `--reproducir`, la primera línea dice de cuándo es la grabación. Esa fecha va dentro de cada archivo grabado, así que no cambia al copiarlo o clonar el repo. Si faltan respuestas grabadas, las lista en una sola línea Faltan y no lo cuenta como falla de crt.sh (código 2). Si falta la de `%.dominio` pero está la búsqueda por nombre, usa esa y también sale con código 2. Solo si faltan las dos queda en `failed` (código 1). Código de salida: 0 bien, 1 si queda en `failed` y 2 si quedan avisos.

El día anterior a cada sesión y control se graba la respuesta real del dominio de prueba con `--grabar`. Cada dominio graba en su propia carpeta. `--grabar` la vacía y marca el inicio en cuanto crt.sh responde (si no responde, código 1, la grabación anterior queda intacta), así lo que no se grabe hoy, porque falló, se omitió por saturación o se interrumpió, aparece en la línea Faltan de `--reproducir` y nunca se mezcla con respuestas de días anteriores. Si crt.sh deja la grabación a medias (código de salida 2), se repite con `--grabar --completar` hasta que salga 0: solo vuelve a consultar lo que no se grabó desde ese inicio. La demo usa `--reproducir` como respaldo. Por ahora el repo no trae grabaciones de crt.sh, así que en un clon nuevo `--reproducir` queda en `failed` hasta correr `--grabar` en esa PC.

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
