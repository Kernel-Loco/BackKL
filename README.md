# Cirdan · Backend (BackKL)

Backend de Cirdan, la plataforma de gestión de la superficie de ataque externa con OSINT pasivo del reto IKUSI VELATIA: la base de datos, la API, los recolectores OSINT y el criterio de criticidad. El portal web (Next.js) está en [FrontKL](https://github.com/Kernel-Loco/FrontKL). Desde el 14 y 15 oct 2026 inicia sesión con esta API (#25) y lee sus datos de la API v1 con esa sesión. Siguen simulados en el portal el alta de dominios y la verificación TXT (#26), los reportes, usuarios, llaves de API, webhooks, alertas y bitácora.

## Carpetas

| Carpeta | Qué tiene |
|---|---|
| `cirdan/api/` | API en FastAPI y la página `/demo` (solo con `DEMO_EXPLORER=true`) |
| `cirdan/auth/` | Inicio de sesión (#25): contraseña con argon2id, MFA con TOTP, sesiones en Valkey y cuentas de demo |
| `cirdan/orquestador/` | Orquestador de escaneos (#22): solo escanea con autorización vigente y TXT verificado |
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
5. Corre las pruebas: `python -m unittest pruebas/test_aislamiento.py pruebas/test_dominio_prueba.py pruebas/test_api.py pruebas/test_auth.py pruebas/test_escaneos_api.py pruebas/test_api_v1.py` (54, contra la base y la API), `docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest pruebas/test_orquestador.py pruebas/test_explorador.py` (19, el orquestador y el explorador de la base dentro del contenedor) y `python -m unittest pruebas/test_criterio.py pruebas/test_contrato.py pruebas/test_crtsh.py pruebas/test_certspotter.py pruebas/test_contrato_api.py pruebas/test_catalogo_reglas.py` (172, sin base ni red).
6. Instala el candado de secretos una vez: `pip install pre-commit && pre-commit install`. Desde ahí gitleaks revisa cada commit.

Otros comandos: `docker compose logs -f api` (ver la API), `docker compose down` (apagar, la base se conserva) y `docker compose down -v` (borrar la base para volver a cargarla desde cero en el siguiente `up`). Para revisar todo el historial con gitleaks: `docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:v8.21.2 git /repo`.

Para trabajar en la API sin reconstruir la imagen: `docker compose stop api`, crea un entorno virtual (`python3 -m venv .venv` y `source .venv/bin/activate`, o `source .venv/Scripts/activate` en Git Bash), `pip install -r requirements.txt` y `python -m uvicorn cirdan.api.main:app --port 8000 --reload`. Fuera de Docker la API lee el `.env` de la raíz.

## Base de datos

24 tablas (18 con Row-Level Security por cliente y 6 catálogos compartidos), datos de Acme Demo y Beta Corp, el dominio de prueba olmardo.com de Grupo Olmardo, y el rol `cirdan_app` sin privilegios de más. Qué se creó, cómo cargarla y las decisiones respecto al DBML están en [`db/README.md`](db/README.md).

## Pruebas de la base

`pruebas/test_aislamiento.py` corre 11 pruebas con la biblioteca estándar de Python (sin instalar paquetes) contra la base `cirdan` del contenedor `cirdan-pg16`, que debe estar encendido (`docker compose up -d` si se apagó, por ejemplo al reiniciar la PC). No usa el `.env`: entra con `docker exec` y el `psql` del contenedor, como `cirdan_app` y, en 3 pruebas, como `postgres`. Revisa el rol sin privilegios, RLS forzado en 18 tablas, Acme ve solo lo suyo (5 dominios, 4 hallazgos, 3 usuarios), Beta Corp ve 1, 1 y 1, sin cliente se ve 0, no se puede escribir a nombre de otro cliente, no se puede escanear con la autorización vencida y la bitácora no se modifica. También revisa `login_lookup()` (migración 004): su `search_path` termina en `pg_temp`, devuelve solo 4 columnas y una vista temporal `users` no la engaña ni vuelve superusuario a `cirdan_app`. Cada escritura va en una transacción que se deshace. Si tu base se creó antes de la migración 004, esas 3 pruebas fallan hasta que la apliques a mano, como dice [`db/README.md`](db/README.md#aplicar-una-migración-nueva-a-una-base-que-ya-existe).

```bash
python -m unittest -v pruebas/test_aislamiento.py
```

El 14 oct 2026 pasaron 8 de 8 con la base levantada por `docker compose`.

`pruebas/test_dominio_prueba.py` corre 8 pruebas sobre la carga de `db/semillas/002_dominio_prueba.sql`, también con `docker exec` y como `cirdan_app`. Revisa que olmardo.com quedó verificado después de su registro, que es de Grupo Olmardo con plan Business y su admin, y que la carta va del 19 oct 2026 al 19 oct 2027, con los datos de rol del titular y el sha256 del PDF firmado. También revisa la verificación TXT del alta, que Acme no ve olmardo.com y que la fuente `ejemplo` está deshabilitada. Las pruebas 7 y 8 escriben en una transacción que se deshace. La 7 comprueba que un escaneo de olmardo.com queda en cola con un TXT `match` reciente. La 8 comprueba que no se puede escanear con la verificación vieja del alta.

```bash
python -m unittest -v pruebas/test_aislamiento.py pruebas/test_dominio_prueba.py
```

El 19 oct 2026 pasaron las 16 (8 de aislamiento y 8 del dominio de prueba) con la base levantada por `docker compose`.

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
- **Contraseñas con argon2id.** Si el correo no existe, el mensaje y el tiempo son los mismos que con una contraseña equivocada, así que no se puede saber qué correos existen. Por eso el fallo se escribe en la bitácora después de mandar el 401.
- **Bloqueo:** 5 fallos por correo o 20 por IP en 15 min responden 429. Un código equivocado también cuenta como fallo, y la contraseña correcta no borra los fallos hasta que el código sea correcto. Cada código gasta su intento antes de revisarse, así que las peticiones en paralelo tampoco pasan de 5.
- **El secreto TOTP** se guarda cifrado con AES-256-GCM (llave `TOTP_ENCRYPTION_KEY`, fuera de la base). `last_totp_step` impide usar dos veces el mismo código.
- **Contra CSRF:** las escrituras con un `Origin` que no esté en `ALLOWED_ORIGINS` responden 403.
- Cada inicio, fallo, código equivocado, cierre de sesión y cambio de contraseña queda en la bitácora (`auth.*`).
- **La búsqueda del correo al iniciar sesión** usa `login_lookup()` (migraciones 002 y 004), porque antes del login no hay empresa para RLS. Solo devuelve el id, la empresa, el hash y si la cuenta tiene MFA. Su `search_path` termina en `pg_temp` y `cirdan_app` no puede crear objetos temporales, así que nadie puede cambiarle la tabla `users` por una vista temporal. El rol y el secreto TOTP se leen después, ya con RLS.

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

**API v1 del portal (RC-17)**, en `cirdan/api/v1.py`, con la forma del contrato #21 y siempre con sesión:

| Endpoint | Qué devuelve |
|---|---|
| `GET /api/v1/domains` | Dominios con autorización, TXT, si se pueden escanear, score y hallazgos abiertos |
| `GET /api/v1/domains/{fqdn}/findings` | Hallazgos abiertos con las 4 características del reto |
| `GET /api/v1/domains/{fqdn}/score` y `/score/history` | Score con desglose, piso y alerta; y su histórico |
| `GET /api/v1/findings/{id}/explanation` | Por qué es crítico: factores, penalización y recomendación |
| `GET /api/v1/scoring/weights` | Juego de reglas activo |
| `GET /api/v1/domains/{fqdn}/assets` y `GET /api/v1/scans` | Activos y escaneos (provisionales: aún no están en el contrato) |
| `GET /api/v1/domains/txt` | Registro TXT de cada dominio (solo Admin) |

Con los datos demo de Acme responden igual que los JSON de `docs/api_v1/` (lo revisa `pruebas/test_api_v1.py`). Mientras #23 no guarde las características del reto en la evidencia, la API las calcula con las mismas reglas del contrato. La semilla `003_titulos_espanol.sql` pone en español los títulos de los hallazgos demo.

`cirdan/api/explorer.py` agrega la página `/demo` y los 2 endpoints que usa, `GET /db/tables` y `GET /db/tables/{table}/rows`. Solo existen con `DEMO_EXPLORER=true` (ver Vista visual de la base). Piden sesión y toman la empresa de la sesión, como el resto de la API. Las tablas solo las ve el rol Admin, como `GET /api/v1/domains/txt`, porque traen usuarios, bitácora y valores TXT. Ninguna ruta acepta ya `X-Organization` (RC-58).

Con `docker compose up -d` la API ya está corriendo; su documentación está en http://127.0.0.1:8000/docs.

```bash
python -m unittest -v pruebas/test_aislamiento.py pruebas/test_api.py pruebas/test_auth.py
```

El 14 oct 2026 pasaron las 22 pruebas (8 de la base, 6 de la API y 8 del inicio de sesión) con todo levantado por `docker compose`. Las de la API y del login entran con las cuentas de demo (`pruebas/sesion.py`).

## Orquestador de escaneos (#22)

`cirdan/orquestador/` arranca los escaneos. **Solo escanea un dominio con autorización firmada vigente y con el registro TXT `cirdan-verification=<txt_token>` verificado justo antes.** Si falta algo, no escanea y dice por qué.

1. **Revisa el dominio y la autorización:** que el dominio esté verificado y no en pausa, y que haya una carta sin revocar con la fecha de hoy dentro de su vigencia.
2. **Consulta el TXT en DNS** (1.1.1.1, con `dnspython`) y guarda la evidencia en `dns_txt_verifications` con `check_reason = 'pre_scan'` y su resultado (`match`, `mismatch`, `missing` o `dns_error`).
3. **Solo con todo en orden crea la fila en `scans`.** El trigger de la base vuelve a exigir carta vigente y TXT `match` de la última hora: es el segundo candado.
4. **Corre cada recolector** con `contrato.ejecutar()` (#13) y llena `scan_source_runs` con `siguiente_estado()`. Una fuente que falla queda en `retrying`, los reintentos los programa #27, y el escaneo termina `partial`. También termina `partial` si una fuente respondió pero dejó códigos en `sin_cobertura`, por ejemplo crt.sh con el respaldo de Cert Spotter: esos códigos van en `stats.rules_without_coverage` y no se muestran como 0. crt.sh nunca busca dominios parecidos desde un escaneo (ver Recolector de crt.sh), así que `lookalike_domain` siempre va ahí y un escaneo con crt.sh arriba también termina `partial`. Guardar activos y hallazgos en la base es de #23.

Los motivos de rechazo usan los códigos de `scan_eligibility.reasons` del contrato #21: `authorization_missing`, `authorization_expired`, `txt_not_verified`, `domain_paused`, etc., más `scan_in_progress` y `live_scan_not_allowed`. Cada aceptación y cada rechazo quedan en la bitácora (`scan.requested`, `scan.rejected` y `scan.finished`).

**Solo se consultan en vivo los dominios de `DOMINIOS_EN_VIVO`** (`.env`, por defecto `olmardo.com`). Los de la demo, como acme-demo.mx, no son del equipo: pedir su escaneo responde `live_scan_not_allowed`.

| Endpoint | Qué hace |
|---|---|
| `POST /api/v1/domains/{fqdn}/scans` | Pide un escaneo. Solo Analista y Administrador (el Gerente recibe 403). 202 si se acepta, y el escaneo corre en segundo plano; 409 con `detail` y `reasons` si no; 404 si el dominio no es de tu organización |
| `GET /api/v1/scans/{id}` | Estado del escaneo y de cada fuente |

Desde la terminal (plan B de la demo):

```bash
docker compose exec api python -m cirdan.orquestador olmardo.com                     # aceptado: dominio de prueba en vivo
docker compose exec api python -m cirdan.orquestador partner-example.com --org ACME  # rechazado: falta la autorización
docker compose exec api python -m cirdan.orquestador old-example.net --org ACME      # rechazado: en pausa y carta vencida
```

**Dominio de prueba:** olmardo.com (Grupo Olmardo, empresa ficticia, plan Business) está en `db/semillas/002_dominio_prueba.sql` (#9b). Trae su token TXT, verificado a mano el 13 oct 2026 a las 19:02 hora de Monterrey (RC-38), y su carta, que el titular del dominio firmó el 19 oct 2026, con vigencia del 19 oct 2026 al 19 oct 2027. La semilla guarda el sha256 del PDF firmado. El PDF no va en el repo. Su administrador es `admin@olmardo.com` (ver `docs/cuentas_de_prueba.md`).

El 14 oct 2026: las 10 pruebas sin red del orquestador y las 6 de la API de escaneos pasaron, y el escaneo en vivo de olmardo.com se aceptó y terminó `completed`. El dominio todavía no tiene sitio, pero desde el 13 oct 2026 sí tiene certificados en los logs de Certificate Transparency. El escaneo del 14 oct y la grabación del 18 oct fueron antes de la carta firmada, cuando el dominio ya era del equipo. El escaneo usó la vigencia provisional de la semilla anterior.

## Vista visual de la base (para la demo)

Solo existe con `DEMO_EXPLORER=true` en el `.env`. Por omisión es `false` y entonces `/demo` y `/db` responden 404. Nunca va en `true` en producción. Con la línea puesta, corre `docker compose up -d --build` y abre **http://127.0.0.1:8000/demo** (también sirve `localhost:8000`). La página inicia sesión desde su propio origen. La API lo permite porque `ALLOWED_ORIGINS` ya trae esos dos orígenes. Desde otro origen, el inicio de sesión responde 403. Sin sesión, la página solo muestra el inicio de sesión y no trae datos.

La página pide correo, contraseña y código MFA de una cuenta de demo con rol Admin (`alex.morgan@acme-demo.mx` o `dana.cruz@beta-corp.mx`) y muestra solo la empresa de esa sesión: las 24 tablas agrupadas con las filas que ve, las filas reales de la tabla que selecciones (sin columnas secretas), los dominios con su score y, al elegir uno, su desglose por categoría y sus hallazgos. Para ver otra empresa, cierra sesión y entra con su cuenta. Con la sesión de Beta Corp (`dana.cruz@beta-corp.mx`), el botón 'Intentar como Beta Corp' muestra el 404 al pedir los hallazgos de acme-demo.mx, que es de Acme. Con la de Acme, el botón dice 'Intentar como Acme Demo' y responde 200. Con una cuenta de Analista o Gerente, las tablas responden 403 y la página lo dice, pero los dominios y el botón sí funcionan. Todo pasa por el rol `cirdan_app`, así que lo que se ve es lo que RLS deja ver. Archivos: `cirdan/api/explorer.py` y `cirdan/api/demo.html`. Sus pruebas, `pruebas/test_explorador.py`, levantan dentro del contenedor una API con la variable en `false` y otra con `true`.

## Recolector de crt.sh (#14)

`cirdan/recolectores/crtsh.py` lee los logs públicos de Certificate Transparency en crt.sh, sin tocar los servidores del dominio. Devuelve los subdominios como activos y tres tipos de hallazgo:

| Código de regla | Severidad base | Cuándo |
|---|---|---|
| `cert_expired` | high | El certificado más reciente de un nombre venció hace menos de un año, el nombre todavía resuelve en DNS y no lo cubre un certificado comodín vigente de su dominio padre. Si no, el nombre queda solo como activo. Un comodín vencido (`*.nombre`) siempre cuenta |
| `cert_expiring_soon` | medium | El certificado más reciente vence en menos de 30 días y le queda menos de un tercio de su vida, así los de vida corta que se renuevan solos no cuentan |
| `lookalike_domain` | medium | Solo con `--con-parecidos`. Un dominio parecido tiene un certificado vigente o vencido hace menos de 90 días: contiene la marca, usa otro TLD o tiene un error tipográfico |

Cada hallazgo trae título en español, evidencia, las características del reto (tipo, antigüedad, exposición y sensibilidad) y una huella SHA-256 estable para no duplicarlo entre escaneos ni al cambiar de fuente: la de los certificados usa su vigencia, que crt.sh y Cert Spotter dan igual. Para los subdominios consulta primero `%.dominio`. Si crt.sh no responde después de 3 intentos, busca por nombre con otros 3, sigue con lo que encuentre y deja un aviso de que pueden faltar subdominios. Si tampoco responde a esa búsqueda, usa el respaldo de Cert Spotter (abajo). Si crt.sh responde, también consulta Cert Spotter y suma los certificados vigentes que crt.sh no trae. Con `--con-parecidos`, si solo fallan las variantes de dominios parecidos, sigue y quedan avisos. Consulta el DNS de los nombres con certificado vencido. Al grabar consulta el de todos los nombres con certificado vigente o vencido hace menos de un año, así una reproducción de días después tiene las respuestas que necesita. Esas respuestas se graban y se reproducen como las de crt.sh.

**Dominios parecidos solo con `--con-parecidos`.** Para buscarlos se consulta en crt.sh `%marca%` (si la marca tiene 5 letras o más) y hasta 10 variantes del dominio (otros TLD, homoglifos y errores tipográficos), que pueden ser de terceros. Por eso la búsqueda va apagada por defecto (`parecidos=False` en `recolectar()`). El orquestador y `POST /api/v1/domains/{fqdn}/scans` nunca la prenden, porque `contrato.ejecutar()` no pasa `parecidos`. En la terminal solo se prende con `--con-parecidos`. Úsalo solo cuando ErnestoDL apruebe las variantes que consulta: `%marca%` y las de `candidatos_parecidos()`. Sin esa búsqueda, `lookalike_domain` queda en `sin_cobertura` y el resumen dice `Cobertura parcial`, nunca 0 parecidos. `--sin-parecidos` se sigue aceptando y hace lo mismo que no ponerlo.

**Cert Spotter, complemento y respaldo (#14b).** En cada corrida `cirdan/recolectores/certspotter.py` también pide los certificados a la API de Cert Spotter (SSLMate), `https://api.certspotter.com/v1/issuances`, con el dominio y sus subdominios, página por página hasta una vacía, con el mismo agente. crt.sh no siempre lee todos los logs: el 23 oct 2026 no tenía ninguno de los 3 certificados de Let's Encrypt de olmardo.com, que Cert Spotter sí tenía. Si crt.sh responde, el resultado suma los certificados de Cert Spotter que crt.sh no trae. Un certificado que está en las dos fuentes se reconoce por su vigencia y sus nombres del dominio, y se queda el de crt.sh. Si Cert Spotter no responde, sigue con lo de crt.sh y un aviso de que pueden faltar subdominios y certificados vigentes (código 2). Si crt.sh no responde a ninguna de las dos búsquedas de subdominios, los subdominios y certificados vigentes salen solo de Cert Spotter. Un 429 (su límite por hora) no se reintenta, porque otro intento solo gastaría cupo. Si falla una página después de la primera, sigue con lo que llegó y avisa que pueden faltar subdominios y renovaciones recientes, así que un certificado por vencer puede estar ya renovado. Los subdominios salen como activos y los certificados por vencer como hallazgos, igual que con crt.sh. Cada activo y cada hallazgo dicen de dónde salieron: `origen` es `crtsh` (con `crtsh_id` y `serie`) o `certspotter` (con `certspotter_id` y `sha256`). Cert Spotter solo da certificados que no han vencido y no busca dominios parecidos, así que con crt.sh caído el resultado deja `cert_expired` y `lookalike_domain` en `sin_cobertura` y trae un aviso: el portal los marca como cobertura parcial y no como 0. Con crt.sh caído tampoco se prueban las variantes. Un código en `sin_cobertura` nunca trae hallazgos. `lookalike_domain` también queda ahí si crt.sh responde pero ninguna búsqueda de parecidos responde, o si no se buscaron, que es lo predeterminado. Si Cert Spotter tampoco responde, la fuente queda en `failed` sin activos ni hallazgos. Sin llave de API Cert Spotter permite unas 10 consultas por hora de un dominio con sus subdominios. Cada página es una consulta: un escaneo pide casi siempre 2 (la página y la vacía que cierra) y nunca más de 4 páginas, y cada intento fallido también cuenta. Como complemento hace 2 intentos de a lo más 20 s, porque crt.sh ya respondió, y como respaldo hace 3, como crt.sh. El complemento gasta el mismo cupo que el respaldo: unos 5 escaneos en una hora lo agotan y los siguientes siguen con lo de crt.sh y el aviso, pero si en esa hora crt.sh tampoco responde, el respaldo recibe 429 y la fuente queda en `failed`. Antes de una demo en vivo no gastes el cupo en ensayos durante la hora anterior. Una emisión de Cert Spotter que no se puede leer (sin id que sirva, con fechas que no son ISO o sin lista de nombres) se salta con el aviso de que pueden faltar subdominios y renovaciones recientes, así que un certificado por vencer puede estar ya renovado, y si ninguna se puede leer cuenta como que Cert Spotter no respondió, sin reintento. Un comodín que Cert Spotter marca como revocado no cubre a otros nombres, aunque crt.sh también lo traiga.

Los ejemplos usan olmardo.com, el dominio de prueba del equipo (Grupo Olmardo, empresa ficticia). Una consulta en vivo solo se corre sobre un dominio con carta de autorización vigente, nunca sobre uno de terceros, y `--grabar` solo se usa con el dominio de prueba. acme-demo.mx es un dato de la semilla y no es del equipo: no lo consultes en vivo.

```bash
python -m cirdan.recolectores.crtsh olmardo.com                         # en vivo, solo subdominios y certificados (una consulta a crt.sh, dos si falla la primera, y casi siempre 2 a Cert Spotter)
python -m cirdan.recolectores.crtsh olmardo.com --con-parecidos         # en vivo y además dominios parecidos, solo cuando ErnestoDL apruebe las variantes
python -m cirdan.recolectores.crtsh olmardo.com --grabar                # en vivo y graba en cirdan/recolectores/respuestas_grabadas/crtsh/olmardo.com/
python -m cirdan.recolectores.crtsh olmardo.com --grabar --completar    # solo consulta lo que aún no está grabado
python -m cirdan.recolectores.crtsh olmardo.com --reproducir            # solo con las respuestas grabadas, sin red (antes hay que grabar)
python -m cirdan.recolectores.crtsh olmardo.com --json                  # el resultado completo en JSON
python -m unittest -v pruebas/test_crtsh.py                             # 50 pruebas sin red
python -m unittest -v pruebas/test_certspotter.py                       # 37 pruebas sin red de Cert Spotter
```

Sin `--json` imprime un resumen en español para leer en una demo: los activos con su fecha de vencimiento y cada hallazgo con su severidad (alta, media) y sus características. Los datos conservan los códigos de la base (`high`, `medium`). Con `--reproducir`, la primera línea dice de cuándo es la grabación. Esa fecha va dentro de cada archivo grabado, así que no cambia al copiarlo o clonar el repo. Si faltan respuestas grabadas, las lista en una sola línea Faltan y no lo cuenta como falla de crt.sh (código 2). Si falta la de `%.dominio` pero está la búsqueda por nombre, usa esa y también sale con código 2. Si faltan las dos usa el respaldo de Cert Spotter grabado, y solo si tampoco está queda en `failed` (código 1). Con el respaldo, la primera línea dice `Cert Spotter (crt.sh no respondió)` y hay una línea `Cobertura parcial` con los códigos que no se revisaron. Si respondieron las dos fuentes, dice `crt.sh y Cert Spotter`. Si crt.sh está grabado pero falta la página de Cert Spotter, como en una grabación de antes del 25 oct, sigue con lo de crt.sh, la página va en la línea Faltan (código 2) y la primera línea dice `crt.sh`. Código de salida: 0 bien, 1 si queda en `failed` y 2 si quedan avisos, también con el respaldo de Cert Spotter o si Cert Spotter no respondió.

El día anterior a cada sesión y control se graba la respuesta real del dominio de prueba con `--grabar`. Cada dominio graba en su propia carpeta. `--grabar` la vacía y marca el inicio en cuanto crt.sh o Cert Spotter responde (si ninguno responde, código 1, la grabación anterior queda intacta), así lo que no se grabe hoy, porque falló, se omitió por saturación o se interrumpió, aparece en la línea Faltan de `--reproducir` y nunca se mezcla con respuestas de días anteriores. Si crt.sh deja la grabación a medias (código de salida 2), se repite con `--grabar --completar` hasta que salga 0: solo vuelve a consultar lo que no se grabó desde ese inicio. Con el respaldo de Cert Spotter el código 2 es lo esperado. Con crt.sh arriba, un código 2 porque Cert Spotter no respondió o no dio todas sus páginas (por ejemplo por un 429) puede dejar la grabación sin certificados que crt.sh no ve: el comando lo avisa, y se repite con `--grabar --completar` cuando Cert Spotter vuelva a responder. Si `--completar` encuentra a crt.sh arriba sobre un respaldo, sus certificados se unen a los de Cert Spotter ya grabados, que conservan su fecha, y la grabación deja de ser respaldo. El comando lo avisa antes de consultar. Si crt.sh no responde al grabar y Cert Spotter sí, también se graba que crt.sh no respondió (`falla_subdominios_<dominio>.json` y `falla_<dominio>.json`), así `--reproducir` repite el respaldo igual que en vivo, con los mismos avisos. Si solo falla `%.dominio` y responde la búsqueda por nombre, se graba `falla_subdominios_<dominio>.json`, así `--reproducir` repite ese aviso. Las páginas de Cert Spotter se graban en la misma carpeta (`certspotter_<dominio>.json` y `certspotter_<dominio>_despues_<id>.json`). `--grabar --completar` vuelve a probar crt.sh sin repetir la consulta a Cert Spotter, y si crt.sh ya responde, la grabación queda como una normal, con las dos fuentes. En una grabación de antes del 25 oct con crt.sh arriba, `--grabar --completar` pide las páginas de Cert Spotter y el DNS de los nombres que no lo tengan grabado, así que la grabación queda con respuestas de dos días y la primera línea de `--reproducir` muestra la fecha más vieja. Para una demo conviene un `--grabar` nuevo. Una grabación con dominios parecidos lleva `--con-parecidos` en `--grabar`, en `--grabar --completar` y en `--reproducir`. Sin él, `--reproducir` los deja en `Cobertura parcial`. La demo usa `--reproducir` como respaldo. Por ahora el repo no trae grabaciones de crt.sh, así que en un clon nuevo `--reproducir` queda en `failed` hasta correr `--grabar` en esa PC.

El 18 oct 2026 se grabó olmardo.com. crt.sh no respondió (3 tiempos agotados en `%.olmardo.com` y 3 errores 502 en `olmardo.com`) y el respaldo dio 3 activos (olmardo.com con 2 comodines, reservas.olmardo.com y camaras.olmardo.com, todos vencen el 12 ene 2027), sin hallazgos y con `cert_expired` y `lookalike_domain` en `sin_cobertura`. Después, `--grabar --completar` encontró a crt.sh arriba, pero solo con el comodín de Cloudflare (SSL.com): le faltan los 3 certificados de Let's Encrypt que sí tiene Cert Spotter. De las variantes, tres dieron 502, siete se omitieron por saturación y `%olmardo%` volvió vacío. Esa pasada reemplazó el respaldo, así que en la PC donde se grabó la carpeta de olmardo.com volvió a tener el respaldo (3 activos), que es el que se propone para la demo de la S12 (RC-47), y la grabación de crt.sh (1 activo) se guardó aparte. `--reproducir` sobre esa carpeta da los 3 activos y la línea de cobertura parcial, sin red. Ninguna de las dos va en el repo: para la demo hay que copiar la carpeta a la PC o a la imagen desde donde corra. Desde el 25 oct #14 consulta siempre Cert Spotter, así que una grabación nueva con crt.sh arriba ya trae los certificados de Let's Encrypt.

## Criterio de criticidad (#29)

Más alto = más riesgo. Bandas 0 a 39 bajo, 40 a 59 medio, 60 a 79 alto y 80 a 100 crítico, ancladas al ejemplo del reto (68 = riesgo alto). Regla de piso: un hallazgo crítico vigente deja el dominio al menos en 60, y dos o más, al menos en 80. La alerta se crea cuando el score llega al umbral o lo pasa. El criterio completo, con ejemplos y quién usa qué, está en `docs/criterio_criticidad.md`, y su código en `cirdan/score/criterio.py`.

```bash
python -m unittest -v pruebas/test_criterio.py   # 13 pruebas, sin base de datos
```

## Catálogo de reglas (#30)

El juego de reglas v1 tiene 30 reglas en las 4 categorías: las 7 de la semilla 001 y las 23 de `db/semillas/004_reglas_recolectores.sql`, una por cada código que emiten o van a emitir #14 a #20 y las extras previstas #62 a #64. Cada regla tiene su título, qué significa y qué hacer en `scoring_rule_texts` (migración 003), en español simple y sin siglas. La lista de códigos, con su categoría, severidad base, tope, recolector y estado, y cómo agregar uno nuevo, está en `docs/codigos_reglas.md`. La prueba falla si un recolector declara en `CODIGOS` un código sin regla o con otra severidad, si una regla no tiene texto o si la lista no coincide con las semillas. Cada recolector debe emitir solo los códigos de su `CODIGOS`, y lo que emite de verdad la prueba solo lo revisa en `ejemplo`.

```bash
python -m unittest -v pruebas/test_catalogo_reglas.py   # 11 pruebas, sin base ni red
```

## Contrato de API v1 (#21)

Lo que devuelve la API v1 (`/api/v1`): dominios, hallazgos, score, histórico, explicación y pesos, con un JSON de ejemplo por respuesta en `docs/api_v1/`. La API v1 ya existe (ver API arriba) y el portal la lee desde el 15 oct 2026. Hoy los JSON de ejemplo los usan las pruebas de este repo y los datos simulados del portal. Los usará el dataset de ML (#33, RC-65). También sirven de plan B en las demos. El detalle está en `docs/contrato_api_v1.md`.

```bash
python -m unittest -v pruebas/test_contrato_api.py   # 23 pruebas, sin base ni red
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
python -m unittest -v pruebas/test_contrato.py   # 38 pruebas, sin red
```
