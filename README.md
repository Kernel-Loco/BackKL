# Cirdan · Backend (BackKL)

Backend de Cirdan, la plataforma de gestión de la superficie de ataque externa con OSINT pasivo del reto IKUSI VELATIA: la base de datos, la API, los recolectores OSINT y el criterio de criticidad. El portal web (Next.js) está en [FrontKL](https://github.com/Kernel-Loco/FrontKL). Por ahora usa datos simulados y todavía no llama a esta API.

## Carpetas

| Carpeta | Qué tiene |
|---|---|
| `cirdan/api/` | API en FastAPI y la página `/demo` |
| `cirdan/auth/` | Inicio de sesión (#25): contraseña con argon2id, MFA con TOTP, sesiones en Valkey y cuentas de demo |
| `cirdan/recolectores/` | Contrato de plugin (#13), recolectores OSINT pasivos (crt.sh, #14, y uno de ejemplo para pruebas) y sus respuestas grabadas para el respaldo de las demos (hoy solo está la del recolector de ejemplo) |
| `cirdan/score/` | Bandas, piso, ponderado y alerta del criterio de criticidad (#29) |
| `db/` | Base PostgreSQL 16: migraciones, semillas y consultas |
| `docs/` | Documentos del proyecto, con su índice |
| `pruebas/` | Pruebas automáticas de la base, de la API, del contrato de API v1, del criterio de criticidad, del contrato de plugin y de crt.sh |
| `.env.example` | Plantilla del `.env`, que se copia en la raíz con contraseñas propias y nunca se sube al repositorio. La leen `docker compose` y la API. Los recolectores, el criterio y sus pruebas no la necesitan |
| `docker-compose.yml`, `Dockerfile` | Levantan PostgreSQL 16 (`cirdan-pg16`), Valkey (`cirdan-valkey`) y la API (`cirdan-api`), todo en `127.0.0.1`. `db/init/cargar_cirdan.sh` carga la base la primera vez |
| `requirements.txt` | Librerías de la API con versión fija |
| `LICENSE`, `NOTICE` | Licencia Apache-2.0 y atribuciones de HIBP y DB-IP (CC BY 4.0) |
| `.pre-commit-config.yaml` | gitleaks antes de cada commit, para que ningún secreto llegue al repo |

## Requisitos

- Git y Docker encendido (en Windows y macOS, Docker Desktop).
- Python 3.11 o más reciente, solo para correr las pruebas desde tu PC (usan la biblioteca estándar).

## Cómo empezar

Todos los comandos se corren desde la raíz del repo.

1. Clona el repo: `git clone https://github.com/Kernel-Loco/BackKL.git` y `cd BackKL`.
2. Copia `.env.example` como `.env`, cambia las tres contraseñas (`POSTGRES_PASSWORD`, `CIRDAN_APP_PASSWORD` y `VALKEY_PASSWORD`) y genera `TOTP_ENCRYPTION_KEY` con el comando que trae el archivo.
3. Levanta todo: `docker compose up -d --build`. La primera vez crea la base `cirdan` y carga migraciones y semillas (tarda unos segundos). La API queda en http://127.0.0.1:8000.
4. Comprueba: `curl http://127.0.0.1:8000/health` responde 200 con `"role": "cirdan_app"`, y `docker compose ps` muestra los tres contenedores `healthy`.
5. Corre las pruebas: `python -m unittest pruebas/test_aislamiento.py pruebas/test_api.py pruebas/test_auth.py` (22, contra la base y la API) y `python -m unittest pruebas/test_criterio.py pruebas/test_contrato.py pruebas/test_crtsh.py pruebas/test_contrato_api.py` (117, sin base ni red).
6. Instala el candado de secretos una vez: `pip install pre-commit && pre-commit install`. Desde ahí gitleaks revisa cada commit.

Otros comandos: `docker compose logs -f api` (ver la API), `docker compose down` (apagar, la base se conserva) y `docker compose down -v` (borrar la base para volver a cargarla desde cero en el siguiente `up`). Para revisar todo el historial con gitleaks: `docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:v8.21.2 git /repo`.

Para trabajar en la API sin reconstruir la imagen: `docker compose stop api`, crea un entorno virtual (`python3 -m venv .venv` y `source .venv/bin/activate`, o `source .venv/Scripts/activate` en Git Bash), `pip install -r requirements.txt` y `python -m uvicorn cirdan.api.main:app --port 8000 --reload`. Fuera de Docker la API lee el `.env` de la raíz.

## Base de datos

23 tablas (18 con Row-Level Security por cliente y 5 catálogos compartidos), datos de Acme Demo y Beta Corp, y el rol `cirdan_app` sin privilegios de más. Qué se creó, cómo cargarla y las decisiones respecto al DBML están en [`db/README.md`](db/README.md).

## Pruebas de la base

`pruebas/test_aislamiento.py` corre 8 pruebas con la biblioteca estándar de Python (sin instalar paquetes) contra la base `cirdan` del contenedor `cirdan-pg16`, que debe estar encendido (`docker compose up -d` si se apagó, por ejemplo al reiniciar la PC). No usa el `.env`: entra con `docker exec` y el `psql` del contenedor, como `cirdan_app` y, en 2 pruebas, como `postgres`. Revisa el rol sin privilegios, RLS forzado en 18 tablas, Acme ve solo lo suyo (5 dominios, 4 hallazgos, 3 usuarios), Beta Corp ve 1, 1 y 1, sin cliente se ve 0, no se puede escribir a nombre de otro cliente, no se puede escanear con la autorización vencida y la bitácora no se modifica. Cada escritura va en una transacción que se deshace.

```bash
python -m unittest -v pruebas/test_aislamiento.py
```

El 14 oct 2026 pasaron 8 de 8 con la base levantada por `docker compose`.

## Inicio de sesión (#25)

Correo y contraseña, y después el código de 6 dígitos de una app autenticadora (TOTP). Al verificar el código, la API entrega una cookie `lt_session` (httpOnly, SameSite=Lax, Secure en producción con `COOKIE_SECURE=true`) que solo lleva un token aleatorio. La sesión vive en Valkey, guardada bajo el SHA-256 del token: expira a los 15 min sin actividad y a las 8 h aunque haya actividad, y al cerrar sesión se borra del servidor.

| Endpoint | Qué hace |
|---|---|
| `POST /api/v1/auth/login` | Correo y contraseña. Con MFA activo responde `{mfa_required: true, mfa_token}` (válido 5 min y 5 intentos) |
| `POST /api/v1/auth/mfa/verify` | `mfa_token` y código. Crea la sesión y pone la cookie |
| `POST /api/v1/auth/logout` | Borra la sesión en Valkey y la cookie |
| `GET /api/v1/auth/me` | Usuario de la sesión (nunca el hash ni el secreto TOTP) |
| `POST /api/v1/auth/password` | Cambia la contraseña (mínimo 12 caracteres) |

Seguridad:
- **Contraseñas con argon2id.** Si el correo no existe, el mensaje y el tiempo son los mismos que con una contraseña equivocada, así que no se puede saber qué correos existen.
- **Bloqueo:** 5 fallos por correo o 20 por IP en 15 min responden 429.
- **El secreto TOTP** se guarda cifrado con AES-256-GCM (llave `TOTP_ENCRYPTION_KEY`, fuera de la base). `last_totp_step` impide usar dos veces el mismo código.
- **Contra CSRF:** las escrituras con un `Origin` que no esté en `ALLOWED_ORIGINS` responden 403.
- Cada inicio, fallo, código equivocado, cierre de sesión y cambio de contraseña queda en la bitácora (`auth.*`).
- **La búsqueda del correo al iniciar sesión** usa `login_lookup()` (migración 002), porque antes del login no hay empresa para RLS. El secreto TOTP se lee después, ya con RLS.

### Cuentas de demo

Con `DEMO_ACCOUNTS=true` en el `.env` (solo desarrollo, nunca en producción), cada `docker compose up` les pone contraseña y MFA a los usuarios de la semilla (`cirdan/auth/demo.py`).

| Correo | Rol | Empresa |
|---|---|---|
| `alex.morgan@acme-demo.mx` | Administrador | Acme Demo |
| `maya.reed@acme-demo.mx` | Gerente | Acme Demo |
| `jordan.tate@acme-demo.mx` | Analista | Acme Demo |
| `dana.cruz@beta-corp.mx` | Administrador | Beta Corp (para probar el aislamiento) |

Contraseña de las cuatro: `Lowtide-Demo-2026`. **La guía completa para el equipo, con las claves para la app autenticadora y qué hacer si algo falla, está en [`docs/cuentas_de_prueba.md`](docs/cuentas_de_prueba.md).** Para el código MFA rápido:

```bash
docker compose exec api python -m cirdan.auth.demo codigo jordan.tate@acme-demo.mx
```

## API (FastAPI)

`cirdan/api/main.py` expone `GET /health` (público) y, con sesión, `GET /domains`, `GET /domains/{fqdn}/findings` y `GET /domains/{fqdn}/score`, además de las rutas de `/api/v1/auth`. Entra como `cirdan_app` y en cada petición fija `app.current_org` **con la empresa de la sesión**, así que el aislamiento lo aplica RLS. Ya no se acepta el encabezado `X-Organization` (#25): sin sesión, la respuesta es 401, y un dominio de otra empresa responde 404.

`cirdan/api/explorer.py` agrega los 2 endpoints que usa `/demo`, `GET /db/tables` y `GET /db/tables/{table}/rows`. Es el único lugar donde sigue el modo demo con `X-Organization`.

Con `docker compose up -d` la API ya está corriendo; su documentación está en http://127.0.0.1:8000/docs.

```bash
python -m unittest -v pruebas/test_aislamiento.py pruebas/test_api.py pruebas/test_auth.py
```

El 14 oct 2026 pasaron las 22 pruebas (8 de la base, 6 de la API y 8 del inicio de sesión) con todo levantado por `docker compose`. Las de la API y del login entran con las cuentas de demo (`pruebas/sesion.py`).

## Vista visual de la base (para la demo)

Con la API arriba, abre **http://127.0.0.1:8000/demo**. Muestra las 23 tablas agrupadas con las filas que ve el cliente elegido (Acme Demo, Beta Corp o sin cliente), las filas reales de la tabla que selecciones (sin columnas secretas), los dominios con su score y, al elegir uno, su desglose por categoría y sus hallazgos. El botón "Intentar como Beta Corp" muestra el 404 al pedir un dominio de Acme. Todo pasa por el rol `cirdan_app`, así que lo que se ve es lo que RLS deja ver. Archivos: `cirdan/api/explorer.py` y `cirdan/api/demo.html`.

## Recolector de crt.sh (#14)

`cirdan/recolectores/crtsh.py` lee los logs públicos de Certificate Transparency en crt.sh, sin tocar los servidores del dominio. Devuelve los subdominios como activos y tres tipos de hallazgo:

| Código de regla | Severidad base | Cuándo |
|---|---|---|
| `cert_expired` | high | El certificado más reciente de un nombre venció hace menos de un año, el nombre todavía resuelve en DNS y no lo cubre un certificado comodín vigente de su dominio padre. Si no, el nombre queda solo como activo. Un comodín vencido (`*.nombre`) siempre cuenta |
| `cert_expiring_soon` | medium | El certificado más reciente vence en menos de 30 días y le queda menos de un tercio de su vida, así los de vida corta que se renuevan solos no cuentan |
| `lookalike_domain` | medium | Un dominio parecido tiene un certificado vigente o vencido hace menos de 90 días: contiene la marca, usa otro TLD o tiene un error tipográfico |

Cada hallazgo trae título en español, evidencia, las características del reto (tipo, antigüedad, exposición y sensibilidad) y una huella SHA-256 estable para no duplicarlo entre escaneos. Para los subdominios consulta primero `%.dominio`. Si crt.sh no responde después de 3 intentos, busca por nombre con otros 3, sigue con lo que encuentre y deja un aviso de que pueden faltar subdominios. Si tampoco responde a esa búsqueda, la fuente queda en `failed` sin activos ni hallazgos. Si solo fallan las variantes de dominios parecidos, el escaneo sigue y quedan avisos. Consulta el DNS de los nombres con certificado vencido. Al grabar consulta el de todos los nombres con certificado vigente o vencido hace menos de un año, así una reproducción de días después tiene las respuestas que necesita. Esas respuestas se graban y se reproducen como las de crt.sh.

Los ejemplos usan olmardo.com, el dominio de prueba del equipo (Grupo Olmardo, empresa ficticia). Una consulta en vivo solo se corre sobre un dominio con carta de autorización vigente, nunca sobre uno de terceros, y `--grabar` solo se usa con el dominio de prueba. acme-demo.mx es un dato de la semilla y no es del equipo: no lo consultes en vivo.

```bash
python -m cirdan.recolectores.crtsh olmardo.com                         # en vivo
python -m cirdan.recolectores.crtsh olmardo.com --sin-parecidos         # en vivo, solo subdominios y certificados (una consulta, dos si falla la primera)
python -m cirdan.recolectores.crtsh olmardo.com --grabar                # en vivo y graba en cirdan/recolectores/respuestas_grabadas/crtsh/olmardo.com/
python -m cirdan.recolectores.crtsh olmardo.com --grabar --completar    # solo consulta lo que aún no está grabado
python -m cirdan.recolectores.crtsh olmardo.com --reproducir            # solo con las respuestas grabadas, sin red (antes hay que grabar)
python -m cirdan.recolectores.crtsh olmardo.com --json                  # el resultado completo en JSON
python -m unittest -v pruebas/test_crtsh.py                             # 47 pruebas sin red
```

Sin `--json` imprime un resumen en español para leer en una demo: los activos con su fecha de vencimiento y cada hallazgo con su severidad (alta, media) y sus características. Los datos conservan los códigos de la base (`high`, `medium`). Con `--reproducir`, la primera línea dice de cuándo es la grabación. Esa fecha va dentro de cada archivo grabado, así que no cambia al copiarlo o clonar el repo. Si faltan respuestas grabadas, las lista en una sola línea Faltan y no lo cuenta como falla de crt.sh (código 2). Si falta la de `%.dominio` pero está la búsqueda por nombre, usa esa y también sale con código 2. Solo si faltan las dos queda en `failed` (código 1). Código de salida: 0 bien, 1 si queda en `failed` y 2 si quedan avisos.

El día anterior a cada sesión y control se graba la respuesta real del dominio de prueba con `--grabar`. Cada dominio graba en su propia carpeta. `--grabar` la vacía y marca el inicio en cuanto crt.sh responde (si no responde, código 1, la grabación anterior queda intacta), así lo que no se grabe hoy, porque falló, se omitió por saturación o se interrumpió, aparece en la línea Faltan de `--reproducir` y nunca se mezcla con respuestas de días anteriores. Si crt.sh deja la grabación a medias (código de salida 2), se repite con `--grabar --completar` hasta que salga 0: solo vuelve a consultar lo que no se grabó desde ese inicio. La demo usa `--reproducir` como respaldo. Por ahora el repo no trae grabaciones de crt.sh, así que en un clon nuevo `--reproducir` queda en `failed` hasta correr `--grabar` en esa PC.

## Criterio de criticidad (#29)

Más alto = más riesgo. Bandas 0 a 39 bajo, 40 a 59 medio, 60 a 79 alto y 80 a 100 crítico, ancladas al ejemplo del reto (68 = riesgo alto). Regla de piso: un hallazgo crítico vigente deja el dominio al menos en 60, y dos o más, al menos en 80. La alerta se crea cuando el score llega al umbral o lo pasa. El criterio completo, con ejemplos y quién usa qué, está en `docs/criterio_criticidad.md`, y su código en `cirdan/score/criterio.py`.

```bash
python -m unittest -v pruebas/test_criterio.py   # 13 pruebas, sin base de datos
```

## Contrato de API v1 (#21)

Lo que devolverá la API v1 (`/api/v1`): dominios, hallazgos, score, histórico, explicación y pesos, con un JSON de ejemplo por respuesta en `docs/api_v1/`. El portal y el dataset de ML los usan mientras la API v1 no esté lista, y sirven de plan B en las demos. El detalle está en `docs/contrato_api_v1.md`.

```bash
python -m unittest -v pruebas/test_contrato_api.py   # 21 pruebas, sin base ni red
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
