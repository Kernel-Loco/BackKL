# Cirdan · Backend (BackKL)

Backend de Cirdan, la plataforma de gestión de la superficie de ataque externa con OSINT pasivo del reto IKUSI VELATIA: la base de datos, la API, los recolectores OSINT y el criterio de criticidad. El portal web (Next.js) está en [FrontKL](https://github.com/Kernel-Loco/FrontKL). Desde el 14 y 15 oct 2026 inicia sesión con esta API (#25) y lee sus datos de la API v1 con esa sesión. Siguen simulados en el portal el alta de dominios y la verificación TXT (#26), los reportes, usuarios, llaves de API, webhooks, alertas y bitácora.

## Carpetas

| Carpeta | Qué tiene |
|---|---|
| `cirdan/api/` | API en FastAPI y la página `/demo` (solo con `DEMO_EXPLORER=true`) |
| `cirdan/auth/` | Inicio de sesión (#25): contraseña con argon2id, MFA con TOTP, sesiones en Valkey y cuentas de demo |
| `cirdan/ml/` | Dataset semisintético del ML (#33, RC-65): plantillas, características del reto, armado del lote y acuerdo entre etiquetadores. El método está en `docs/dataset_ml.md` |
| `cirdan/orquestador/` | Orquestador de escaneos (#22): solo escanea con autorización vigente y TXT verificado |
| `cirdan/recolectores/` | Contrato de plugin (#13), recolectores OSINT pasivos (crt.sh con Cert Spotter, #14 y #14b, subfinder en modo pasivo, #14b, DNS con SPF y DMARC, #15, secretos y correos en GitHub, #16, servicios y CVE con Shodan InternetDB, #17, registrador y vencimiento del dominio con RDAP y WHOIS por el puerto 43 como respaldo, #15b, y uno de ejemplo para pruebas), la ubicación de las IP con la base local de DB-IP Lite (`geoip.py`, #15b, no es un recolector) y sus respuestas grabadas para el respaldo de las demos (hoy solo está la del recolector de ejemplo) |
| `cirdan/score/` | Criterio de criticidad (#29) y cálculo explicable por hallazgo, categoría y dominio (#31) |
| `datos/` | Datos del ML. En `datos/ml/rc65/` están el lote, la copia de cada etiquetador, las etiquetas del LLM y el dataset (#33, RC-65). En `datos/geo/` van las bases de DB-IP Lite, que se bajan a mano y no se suben al repo (ver Geolocalización y ASN de las IP) |
| `db/` | Base PostgreSQL 16: migraciones, semillas y consultas |
| `docs/` | Documentos del proyecto, con su índice |
| `pruebas/` | Pruebas automáticas de la base, de la API, del contrato de API v1, del criterio de criticidad, del contrato de plugin, de crt.sh, de Cert Spotter, de subfinder, del DNS, de GitHub, de Shodan, de RDAP con WHOIS y de la geolocalización de las IP |
| `.env.example` | Plantilla del `.env`, que se copia en la raíz con contraseñas propias y nunca se sube al repositorio. La leen `docker compose` y la API. Los recolectores, el criterio y sus pruebas no la necesitan |
| `docker-compose.yml`, `Dockerfile` | Levantan PostgreSQL 16 (`cirdan-pg16`), Valkey (`cirdan-valkey`) y la API (`cirdan-api`), todo en `127.0.0.1`. `db/init/cargar_cirdan.sh` carga la base la primera vez. La imagen de la API trae los binarios de subfinder 2.17.0 y gitleaks 8.21.2, y git (ver Recolector de subfinder y Recolector de GitHub), y copia las bases de DB-IP Lite que haya en `datos/geo/` (ver Geolocalización y ASN de las IP) |
| `requirements.txt` | Librerías de la API con versión fija |
| `LICENSE`, `NOTICE` | Licencia Apache-2.0, atribuciones de HIBP y DB-IP (CC BY 4.0, por las bases de `datos/geo/`) y las licencias MIT de subfinder y gitleaks, que van en la imagen |
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
5. Corre las pruebas: `python -m unittest pruebas/test_aislamiento.py pruebas/test_dominio_prueba.py pruebas/test_api.py pruebas/test_auth.py pruebas/test_escaneos_api.py pruebas/test_api_v1.py` (56, contra la base y la API. Se saltan 2: una sin `EN_VIVO=1`, que también consulta InternetDB, el bootstrap de IANA y el registro RDAP del dominio, y test_11 de test_auth.py sin `FORWARDED_ALLOW_IPS='*'`), `docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest pruebas/test_orquestador.py pruebas/test_explorador.py` (49, el orquestador y el explorador de la base dentro del contenedor) y `python -m unittest pruebas/test_criterio.py pruebas/test_motor_score.py pruebas/test_contrato.py pruebas/test_crtsh.py pruebas/test_certspotter.py pruebas/test_contrato_api.py pruebas/test_catalogo_reglas.py pruebas/test_subfinder.py pruebas/test_registros_dns.py pruebas/test_github.py pruebas/test_shodan.py pruebas/test_rdap.py pruebas/test_geoip.py` (453, sin base ni red. Se saltan 2 de test_github.py que piden git y gitleaks, ver Recolector de GitHub) y `python -m unittest pruebas/test_dataset_ml.py` (68, el lote del ML de RC-65, también sin base ni red).
6. Instala el candado de secretos una vez: `pip install pre-commit && pre-commit install`. Desde ahí gitleaks revisa cada commit.

Otros comandos: `docker compose logs -f api` (ver la API), `docker compose down` (apagar, la base se conserva) y `docker compose down -v` (borrar la base para volver a cargarla desde cero en el siguiente `up`). Para revisar todo el historial con gitleaks: `docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:v8.21.2 git /repo`.

Para trabajar en la API sin reconstruir la imagen: `docker compose stop api`, crea un entorno virtual (`python3 -m venv .venv` y `source .venv/bin/activate`, o `source .venv/Scripts/activate` en Git Bash), `pip install -r requirements.txt` y `python -m uvicorn cirdan.api.main:app --port 8000 --reload`. Fuera de Docker la API lee el `.env` de la raíz.

## Base de datos

24 tablas (18 con Row-Level Security por cliente y 6 catálogos compartidos), datos de Acme Demo y Beta Corp, el dominio de prueba olmardo.com de Grupo Olmardo, y el rol `cirdan_app` sin privilegios de más. Qué se creó, cómo cargarla y las decisiones respecto al DBML están en [`db/README.md`](db/README.md).

## Pruebas de la base

`pruebas/test_aislamiento.py` corre 12 pruebas con la biblioteca estándar de Python (sin instalar paquetes) contra la base `cirdan` del contenedor `cirdan-pg16`, que debe estar encendido (`docker compose up -d` si se apagó, por ejemplo al reiniciar la PC). No usa el `.env`: entra con `docker exec` y el `psql` del contenedor, como `cirdan_app` y, en 3 pruebas, como `postgres`. Revisa el rol sin privilegios, RLS forzado en 18 tablas, Acme ve solo lo suyo (5 dominios, 4 hallazgos, 3 usuarios), Beta Corp ve 1, 1 y 1, sin cliente se ve 0, no se puede escribir a nombre de otro cliente, no se puede escanear con la autorización vencida y la bitácora no se modifica. También revisa `login_lookup()` (migración 004): su `search_path` termina en `pg_temp`, devuelve solo 4 columnas y una vista temporal `users` no la engaña ni vuelve superusuario a `cirdan_app`. Cada escritura va en una transacción que se deshace. Si tu base se creó antes de la migración 004, esas 3 pruebas fallan hasta que la apliques a mano, como dice [`db/README.md`](db/README.md#aplicar-una-migración-nueva-a-una-base-que-ya-existe). La prueba 12 revisa las funciones del límite diario (migración 008): `reserve_source_quota()` y `adjust_source_quota()` son SECURITY DEFINER, su `search_path` termina en `pg_temp` y PUBLIC no las ejecuta. Sin la 008 falla hasta que la apliques igual.

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
4. **Corre cada recolector** con `contrato.ejecutar()` (#13) y llena `scan_source_runs` con `siguiente_estado()`. En vivo, una fuente que falla queda en `retrying` y se vuelve a correr en el mismo escaneo a 1, 5 y 25 minutos. No se reintenta al reproducir, porque la respuesta grabada sería la misma, ni al grabar, porque cada intento volvería a vaciar la grabación: la fuente queda en `failed`. La fila de la fuente suma las consultas de todos sus intentos y guarda en sus avisos los errores de los anteriores. En vivo y al grabar, antes de cada intento reserva el cupo del día de la fuente, y una fuente sin cupo queda en `failed` sin reintento (ver Límite diario por fuente). Si no se recupera, el escaneo termina `partial` si otra fuente respondió, o `failed` si ninguna respondió. También termina `partial` si una fuente respondió pero dejó códigos en `sin_cobertura`, por ejemplo crt.sh con el respaldo de Cert Spotter: esos códigos van en `stats.rules_without_coverage` y no se muestran como 0. crt.sh nunca busca dominios parecidos desde un escaneo (ver Recolector de crt.sh), así que `lookalike_domain` siempre va ahí y un escaneo con crt.sh arriba también termina `partial`. Guardar activos y hallazgos en la base es de #23.

Los motivos de rechazo usan los códigos de `scan_eligibility.reasons` del contrato #21: `authorization_missing`, `authorization_expired`, `txt_not_verified`, `domain_paused`, etc., más `scan_in_progress` y `live_scan_not_allowed`. Cada aceptación y cada rechazo quedan en la bitácora (`scan.requested`, `scan.rejected`, `scan.finished` y `scan.abandoned`).

**Un escaneo no se queda en `running` para siempre.** Mientras corre, marca que sigue vivo en `scans.updated_at` cada minuto, también mientras espera un reintento. Una sola corrida deja de marcar a los 20 minutos, así una fuente colgada no lo deja en curso para siempre. Si la API se reinicia o se corta a mitad, pasados 30 minutos sin marca el escaneo queda `failed` (`scan.abandoned`) al pedir otro escaneo del dominio o al consultar los escaneos. Así el índice único deja pedir el siguiente. El escaneo de la API corre en un hilo aparte para no ocupar uno de los que atienden peticiones.

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

La salida da el estado de cada fuente y, debajo, hasta 10 de sus avisos, como que Cert Spotter no respondió aunque crt.sh sí. Si hubo más, dice cuántos. `GET /api/v1/scans/{id}` todavía no da esos avisos.

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

**Cert Spotter, complemento y respaldo (#14b).** En cada corrida `cirdan/recolectores/certspotter.py` también pide los certificados a la API de Cert Spotter (SSLMate), `https://api.certspotter.com/v1/issuances`, con el dominio y sus subdominios, página por página hasta una vacía, con el mismo agente. crt.sh no siempre lee todos los logs: el 23 oct 2026 no tenía ninguno de los 3 certificados de Let's Encrypt de olmardo.com, que Cert Spotter sí tenía. Si crt.sh responde, el resultado suma los certificados de Cert Spotter que crt.sh no trae. Un certificado que está en las dos fuentes se reconoce por su vigencia y sus nombres del dominio, y se queda el de crt.sh. Si Cert Spotter no responde, sigue con lo de crt.sh y un aviso de que pueden faltar subdominios y certificados vigentes (código 2). Si crt.sh no responde a ninguna de las dos búsquedas de subdominios, los subdominios y certificados vigentes salen solo de Cert Spotter. Un 429 (su límite por hora) no se reintenta, porque otro intento solo gastaría cupo. Si falla una página después de la primera, sigue con lo que llegó y avisa que pueden faltar subdominios y renovaciones recientes, así que un certificado por vencer puede estar ya renovado. Los subdominios salen como activos y los certificados por vencer como hallazgos, igual que con crt.sh. Cada activo y cada hallazgo dicen de dónde salieron: `origen` es `crtsh` (con `crtsh_id` y `serie`) o `certspotter` (con `certspotter_id` y `sha256`). Cert Spotter solo da certificados que no han vencido y no busca dominios parecidos, así que con crt.sh caído el resultado deja `cert_expired` y `lookalike_domain` en `sin_cobertura` y trae un aviso: el portal los marca como cobertura parcial y no como 0. Con crt.sh caído tampoco se prueban las variantes. Un código en `sin_cobertura` nunca trae hallazgos. `lookalike_domain` también queda ahí si crt.sh responde pero ninguna búsqueda de parecidos responde, o si no se buscaron, que es lo predeterminado. Si Cert Spotter tampoco responde, la fuente queda en `failed` sin activos ni hallazgos. Sin llave de API Cert Spotter permite unas 10 consultas por hora de un dominio con sus subdominios. Cada página es una consulta: un escaneo pide casi siempre 2 (la página y la vacía que cierra) y nunca más de 4 páginas, y cada intento fallido también cuenta. Como complemento hace 2 intentos de a lo más 20 s, porque crt.sh ya respondió, y como respaldo hace 3, como crt.sh. El complemento gasta el mismo cupo que el respaldo, y el recolector de Shodan (#17) pide del mismo cupo otras 2 páginas por escaneo (hasta 4 con sus intentos): con `ct_logs` y `shodan` encendidas, unos 2 o 3 escaneos en una hora lo agotan. Los siguientes siguen con lo de crt.sh y el aviso, y Shodan solo revisa la raíz, pero si en esa hora crt.sh tampoco responde, el respaldo recibe 429 y la fuente queda en `failed`. Antes de una demo en vivo no ensayes escaneos en la hora anterior. Una emisión de Cert Spotter que no se puede leer (sin id que sirva, con fechas que no son ISO o sin lista de nombres) se salta con el aviso de que pueden faltar subdominios y renovaciones recientes, así que un certificado por vencer puede estar ya renovado, y si ninguna se puede leer cuenta como que Cert Spotter no respondió, sin reintento. Un comodín que Cert Spotter marca como revocado no cubre a otros nombres, aunque crt.sh también lo traiga.

Los ejemplos usan olmardo.com, el dominio de prueba del equipo (Grupo Olmardo, empresa ficticia). Una consulta en vivo solo se corre sobre un dominio con carta de autorización vigente, nunca sobre uno de terceros, y `--grabar` solo se usa con el dominio de prueba. acme-demo.mx es un dato de la semilla y no es del equipo: no lo consultes en vivo.

```bash
python -m cirdan.recolectores.crtsh olmardo.com                         # en vivo, solo subdominios y certificados (una consulta a crt.sh, dos si falla la primera, y casi siempre 2 a Cert Spotter)
python -m cirdan.recolectores.crtsh olmardo.com --con-parecidos         # en vivo y además dominios parecidos, solo cuando ErnestoDL apruebe las variantes
python -m cirdan.recolectores.crtsh olmardo.com --grabar                # en vivo y graba en cirdan/recolectores/respuestas_grabadas/crtsh/olmardo.com/
python -m cirdan.recolectores.crtsh olmardo.com --grabar --completar    # solo consulta lo que aún no está grabado
python -m cirdan.recolectores.crtsh olmardo.com --reproducir            # solo con las respuestas grabadas, sin red (antes hay que grabar)
python -m cirdan.recolectores.crtsh olmardo.com --json                  # el resultado completo en JSON
python -m unittest -v pruebas/test_crtsh.py                             # 52 pruebas sin red
python -m unittest -v pruebas/test_certspotter.py                       # 38 pruebas sin red de Cert Spotter
```

Sin `--json` imprime un resumen en español para leer en una demo: los activos con su fecha de vencimiento en UTC, como la dan los certificados, y cada hallazgo con su severidad (alta, media) y sus características. Los datos conservan los códigos de la base (`high`, `medium`). Con `--reproducir`, la primera línea dice de cuándo es la grabación, en la hora local y con su desfase de UTC (dentro del contenedor de la API, la hora local es UTC). Esa fecha va dentro de cada archivo grabado, así que no cambia al copiarlo o clonar el repo. Si faltan respuestas grabadas, las lista en una sola línea Faltan y no lo cuenta como falla de crt.sh (código 2). Si falta la de `%.dominio` pero está la búsqueda por nombre, usa esa y también sale con código 2. Si faltan las dos usa el respaldo de Cert Spotter grabado, y solo si tampoco está queda en `failed` (código 1). Con el respaldo, la primera línea dice `Cert Spotter (crt.sh no respondió)` y hay una línea `Cobertura parcial` con los códigos que no se revisaron. Si respondieron las dos fuentes, dice `crt.sh y Cert Spotter`. Si crt.sh está grabado pero falta la página de Cert Spotter, como en una grabación de antes del 25 oct, sigue con lo de crt.sh, la página va en la línea Faltan (código 2) y la primera línea dice `crt.sh`. Código de salida: 0 bien, 1 si queda en `failed` y 2 si quedan avisos, también con el respaldo de Cert Spotter o si Cert Spotter no respondió.

El día anterior a cada sesión y control se graba la respuesta real del dominio de prueba con `--grabar`. Cada dominio graba en su propia carpeta. `--grabar` la vacía y marca el inicio en cuanto crt.sh o Cert Spotter responde (si ninguno responde, código 1, la grabación anterior queda intacta), así lo que no se grabe hoy, porque falló, se omitió por saturación o se interrumpió, aparece en la línea Faltan de `--reproducir` y nunca se mezcla con respuestas de días anteriores. Si crt.sh deja la grabación a medias (código de salida 2), se repite con `--grabar --completar` hasta que salga 0: solo vuelve a consultar lo que no se grabó desde ese inicio. Con el respaldo de Cert Spotter el código 2 es lo esperado. Con crt.sh arriba, un código 2 porque Cert Spotter no respondió o no dio todas sus páginas (por ejemplo por un 429) puede dejar la grabación sin certificados que crt.sh no ve: el comando lo avisa, y se repite con `--grabar --completar` cuando Cert Spotter vuelva a responder. Si `--completar` encuentra a crt.sh arriba sobre un respaldo, sus certificados se unen a los de Cert Spotter ya grabados, que conservan su fecha, y la grabación deja de ser respaldo. El comando lo avisa antes de consultar. Si crt.sh no responde al grabar y Cert Spotter sí, también se graba que crt.sh no respondió (`falla_subdominios_<dominio>.json` y `falla_<dominio>.json`), así `--reproducir` repite el respaldo igual que en vivo, con los mismos avisos. Si solo falla `%.dominio` y responde la búsqueda por nombre, se graba `falla_subdominios_<dominio>.json`, así `--reproducir` repite ese aviso. Las páginas de Cert Spotter se graban en la misma carpeta (`certspotter_<dominio>.json` y `certspotter_<dominio>_despues_<id>.json`). `--grabar --completar` vuelve a probar crt.sh sin repetir la consulta a Cert Spotter, y si crt.sh ya responde, la grabación queda como una normal, con las dos fuentes. En una grabación de antes del 25 oct con crt.sh arriba, `--grabar --completar` pide las páginas de Cert Spotter y el DNS de los nombres que no lo tengan grabado, así que la grabación queda con respuestas de dos días y la primera línea de `--reproducir` muestra la fecha más vieja. Para una demo conviene un `--grabar` nuevo. Una grabación con dominios parecidos lleva `--con-parecidos` en `--grabar`, en `--grabar --completar` y en `--reproducir`. Sin él, `--reproducir` los deja en `Cobertura parcial`. La demo usa `--reproducir` como respaldo. Por ahora el repo no trae grabaciones de crt.sh, así que en un clon nuevo `--reproducir` queda en `failed` hasta correr `--grabar` en esa PC.

El 18 oct 2026 se grabó olmardo.com. crt.sh no respondió (3 tiempos agotados en `%.olmardo.com` y 3 errores 502 en `olmardo.com`) y el respaldo dio 3 activos (olmardo.com con 2 comodines, reservas.olmardo.com y camaras.olmardo.com, todos vencen el 12 ene 2027), sin hallazgos y con `cert_expired` y `lookalike_domain` en `sin_cobertura`. Después, `--grabar --completar` encontró a crt.sh arriba, pero solo con el comodín de Cloudflare (SSL.com): le faltan los 3 certificados de Let's Encrypt que sí tiene Cert Spotter. De las variantes, tres dieron 502, siete se omitieron por saturación y `%olmardo%` volvió vacío. Esa pasada reemplazó el respaldo, así que en la PC donde se grabó la carpeta de olmardo.com volvió a tener el respaldo (3 activos), que es el que se propone para la demo de la S12 (RC-47), y la grabación de crt.sh (1 activo) se guardó aparte. `--reproducir` sobre esa carpeta da los 3 activos y la línea de cobertura parcial, sin red. Ninguna de las dos va en el repo: para la demo hay que copiar la carpeta a la PC o a la imagen desde donde corra. `.gitignore` deja fuera todo lo de `respuestas_grabadas/crtsh/` menos `.gitkeep`, así que un `git add` no lo sube. La imagen de la API sí copia las que haya en la PC al construirse: después de un `--grabar` nuevo hay que reconstruirla para que `python -m cirdan.orquestador olmardo.com --modo reproducir` use la grabación nueva. Desde el 25 oct #14 consulta siempre Cert Spotter, así que una grabación nueva con crt.sh arriba ya trae los certificados de Let's Encrypt.

## Recolector de subfinder (#14b)

`cirdan/recolectores/subfinder.py` corre [subfinder](https://github.com/projectdiscovery/subfinder) 2.17.0 en modo pasivo: pide a fuentes públicas los subdominios que ya conocen del dominio. Es un recolector aparte, con su propia fila `subfinder` en `data_sources` (`db/semillas/005_subfinder_y_limites.sql`), y no un complemento de crt.sh. Solo da activos: cada subdominio sale como activo `subdomain`, igual que los de #14, con `fuente` = `subfinder` y en `origen` la lista de las fuentes de subfinder que lo vieron. No emite hallazgos (su `CODIGOS` está vacío), así que no necesita reglas en el catálogo.

**Sembrado apagado.** La semilla 005 deja la fila `subfinder` con `enabled` = false, como `censys` en la semilla 001, así que un escaneo no la corre y la demo de la S12 en `reproducir` no la muestra fallida. Se prende con otra semilla cuando se cumplan las tres: (a) #8 (RC-40) revisó los términos de las 8 fuentes, (b) hay una grabación de subfinder para olmardo.com y (c) el contenedor puede escribir en `respuestas_grabadas/`. Hoy no puede, porque el `Dockerfile` copia `cirdan/` como root, y eso sigue pausado fuera de RC-184.

**Solo fuentes de una lista blanca fija.** subfinder recibe con `-s` estas 8 fuentes, que no piden llave: `anubis`, `crtname`, `digitorus`, `hackertarget`, `rapiddns`, `subdomaincenter`, `submd` y `thc`. No se usa su lista por omisión, que cambia entre versiones. Como cinturón, `-es` excluye siempre:

| Fuente excluida | Por qué |
|---|---|
| `crtsh` y `certspotter` | Duplican a #14 y gastarían el cupo de crt.sh y de Cert Spotter fuera del límite diario de `ct_logs` |
| `censys` | Sus términos prohíben dar sus datos a terceros (ver la semilla 001, que la deja deshabilitada) |
| `hudsonrock`, `intelx` y `leakix` | Son datos de brechas, de equipos infectados y de filtraciones. Chocan con no usar credenciales filtradas y con no guardar datos de brechas más allá del hecho (`docs/contrato_plugin.md`) |

**Qué no hace.** No resuelve nombres en DNS, no prueba nombres por fuerza bruta y no busca de forma recursiva: nunca lleva `-active`, `-nW`, `-oI`, `-ip`, `-all`, `-r`, `-rL` ni `-recursive`. No usa llaves de API. Con `-duc` no le pregunta a ProjectDiscovery si hay versión nueva. Corre con un entorno limpio, solo `PATH`, `HOME` y `XDG_CONFIG_HOME` en una carpeta temporal que se borra al terminar, así ninguna variable de la API (contraseñas, `TOTP_ENCRYPTION_KEY` ni llaves) llega al proceso.

**No toca los servidores de la empresa.** Solo consulta a las 8 fuentes, que reciben el dominio, como avisa la carta. subfinder pone en cada petición un User-Agent de navegador al azar y no deja cambiarlo. Eso no choca con la sección 9 de la plantilla de la carta (`docs/plantilla_carta_autorizacion.md:79`), que habla del User-Agent de las peticiones que ve la empresa: subfinder no le manda ninguna. La fila 1 del Anexo A de esa plantilla ya nombra a subfinder en modo pasivo. Falta revisar los términos de cada una de las 8 fuentes con #8 (RC-40) antes de usarlo fuera de olmardo.com.

**Riesgo aceptado: sin verificar TLS.** subfinder 2.17.0 no verifica el certificado TLS de sus fuentes (`InsecureSkipVerify` en `pkg/subscraping/agent.go`). Se acepta porque no les manda llaves ni datos de la empresa, solo el dominio, y lo único que recibe son nombres: un nombre falso solo agrega un activo, que #23 cruzará con las demás fuentes.

Normaliza cada nombre (minúsculas, sin punto final y sin `*.` al inicio), descarta los que no son del dominio o no son nombres válidos con un aviso que dice cuántos, junta las fuentes de un mismo nombre y no devuelve el propio dominio como subdominio. Si una fuente falla deja el aviso `subfinder: la fuente X no respondió` y sigue con las demás. Si la enumeración llega a su tiempo máximo (`-max-time 5`, 5 minutos), subfinder la corta y sale con 0 con lo que tenga: el resultado sigue en `succeeded`, con el aviso `subfinder: la lista puede estar incompleta (llegó a su tiempo máximo)`. Si fallan todas, si subfinder sale con un código distinto de 0 o si el proceso no termina en 360 s, cuenta como que la fuente no respondió: queda en `failed` y en vivo el orquestador la reintenta a 1, 5 y 25 minutos. Hasta #23, que guardará los activos en la base, un subdominio repetido entre fuentes (por ejemplo, uno que también trae `ct_logs`) cuenta una sola vez en `stats.assets` del escaneo.

**Consultas.** Para el límite diario, una consulta de subfinder es una fuente consultada en una corrida, no una petición HTTP: `rapiddns` y `thc` paginan, y subfinder no dice cuántas peticiones hizo sin `-stats`, que no se lee. Cada corrida en vivo o al grabar cuenta 8 (una por fuente de la lista blanca, `MAX_CONSULTAS`), y 0 al reproducir.

Las respuestas se graban con el contrato (#13) en `cirdan/recolectores/respuestas_grabadas/subfinder/<dominio>/`, y al reproducir solo se leen, sin correr subfinder ni usar la red. `.gitignore` deja fuera todo lo de esa carpeta menos `.gitkeep`, como con crt.sh. Hoy no se puede grabar dentro del contenedor: el `Dockerfile` copia `cirdan/` como root y el usuario `cirdan` no escribe en `respuestas_grabadas/` (pausado). Se usa el primer `subfinder` que haya en el `PATH`; en la imagen de la API es `/usr/local/bin/subfinder` 2.17.0. Si no hay ninguno, la corrida cuenta como fuente caída, con el error `subfinder no está instalado`, y en vivo se reintenta a 1, 5 y 25 minutos como cualquier otra. Sus pruebas no lo necesitan: simulan el binario.

```bash
python -m unittest -v pruebas/test_subfinder.py   # 26 pruebas, sin red y sin el binario
```

**Versión.** El `Dockerfile` baja el zip del release de cada arquitectura (amd64 y arm64) con su sha256 fijo y deja la licencia en `/usr/share/licenses/subfinder/LICENSE.md` (ver `NOTICE`). Dependabot no vigila esta versión: para subirla se cambian las dos URL y los dos hash del `Dockerfile` con los del archivo `checksums.txt` del release nuevo, y la versión en `NOTICE`.

## Recolector de DNS (#15)

`cirdan/recolectores/registros_dns.py` pregunta a 1.1.1.1 y 8.8.8.8 (nunca al DNS del sistema ni a los servidores del dominio) los registros A, AAAA, MX, NS y TXT del dominio autorizado y el TXT de `_dmarc.<dominio>`: 6 consultas por corrida, de a lo más 3 intentos cada una. No necesita llave. Usa dnspython, que ya está en `requirements.txt` y en la imagen de la API. Si no lo tienes en tu PC, el módulo carga y sus pruebas pasan (usan un resolvedor simulado), pero una consulta real falla con `ImportError` hasta que corras `pip install -r requirements.txt`. Devuelve estos hallazgos:

| Código de regla | Severidad base | Cuándo |
|---|---|---|
| `spf_missing` | low | No hay un solo TXT `v=spf1` en la raíz (ninguno, o dos o más), o el único termina en `?all` o no tiene `all` ni `redirect=` |
| `spf_allow_all` | medium | El SPF termina en `+all` o en `all` sin calificador |
| `dmarc_missing` | medium | No hay un solo TXT `v=DMARC1` en `_dmarc.<dominio>`, o el único tiene un `p` ausente o no válido, o un `sp` no válido, y su `rua` no trae un URI con esquema |
| `dmarc_policy_none` | medium | El DMARC trae `p=none`: observa pero no bloquea los correos falsos. También si trae un `p` ausente o no válido, o un `sp` no válido, y su `rua` trae al menos un URI con esquema (`esquema:resto` en alguna de sus partes separadas por coma), porque así lo toma un receptor (RFC 7489, 6.6.3 paso 6) |

Un TXT es SPF si empieza con `v=spf1` sin distinguir mayúsculas y seguido de un espacio o del fin del texto, sin recortarlo (RFC 7208, 4.5): con un espacio al inicio o un tabulador después de `v=spf1` no es SPF. Es DMARC según RFC 7489, 6.4: la `v` sin distinguir mayúsculas, espacios o tabuladores opcionales alrededor del `=` y `DMARC1` exacto en mayúsculas, seguido de punto y coma, espacio, tabulador o el fin. Un `v=dmarc1` en minúsculas no es DMARC y cuenta como otro TXT. Los nombres de etiqueta (`p`, `sp`, `rua`) y los valores de política no distinguen mayúsculas.

Una falla del DNS no cuenta como «no hay registro». Un NXDOMAIN de `_dmarc.<dominio>` o una respuesta vacía (NoAnswer) sí lo son y dan `dmarc_missing` o `spf_missing`, pero un tiempo agotado o un SERVFAIL deja un aviso y, si fue el TXT de la raíz o el de `_dmarc`, sus códigos quedan en `sin_cobertura` y el resumen dice `Cobertura parcial`. Si la raíz no existe (NXDOMAIN), no hay activos ni hallazgos: la fuente deja un aviso y los 4 códigos van a `sin_cobertura`. Si fallan las 6 consultas la fuente queda en `failed` para que el orquestador la reintente. `sp=none` y `pct` menor a 100 no generan hallazgo, y un `redirect=` sin `all` solo da un aviso, porque no se sigue.

Los A y AAAA salen como activos `ip` con `host` igual al dominio y con su país, ASN, proveedor y CDN de la base local de DB-IP Lite (ver Geolocalización y ASN de las IP), y los MX y NS que están dentro del dominio como activos `subdomain`. Los de un tercero (Cloudflare, Google) y todo el resto del DNS quedan solo en `atributos['dns']` del activo `domain`. Hasta que #23 guarde activos y hallazgos, no se escribe nada en `assets` ni en `findings`. De los TXT que no son SPF ni DMARC solo se guarda el nombre antes del igual y cuántos hay, nunca el valor: el `cirdan-verification=<token>` del dominio no sale en el resultado, en el resumen ni en las grabaciones.

Una consulta en vivo a un dominio solo se corre con carta de autorización vigente y con el OK de la persona, y `--grabar` solo con el dominio de prueba. Las pruebas no consultan nada.

Con `dns` en `REGISTRO` y encendida en `data_sources` (la semilla 001 la siembra así), la fuente corre en todo escaneo. Un escaneo en modo reproducir, o uno en vivo de un dominio fuera de `DOMINIOS_EN_VIVO`, necesita una grabación de DNS del dominio en `cirdan/recolectores/respuestas_grabadas/dns/<dominio>/`, y el repo no trae ninguna. Sin ella, la fuente `dns` queda `failed` y el escaneo termina `partial` si otra fuente respondió. Para una demo hay que grabarla con `--grabar` (con el OK de la persona) y copiarla a la PC o a la imagen desde donde corra, que se reconstruye porque copia `cirdan/` al construirse.

```bash
python -m cirdan.recolectores.registros_dns olmardo.com                 # en vivo, solo el dominio autorizado (con OK de la persona)
python -m cirdan.recolectores.registros_dns olmardo.com --grabar        # en vivo y graba en cirdan/recolectores/respuestas_grabadas/dns/olmardo.com/
python -m cirdan.recolectores.registros_dns olmardo.com --reproducir    # solo con lo grabado, sin red (antes hay que grabar)
python -m cirdan.recolectores.registros_dns olmardo.com --json          # el resultado completo en JSON
python -m unittest -v pruebas/test_registros_dns.py                     # 71 pruebas, sin red ni dnspython
```

Código de salida: 0 bien, 1 si queda en `failed` y 2 si quedan avisos. `--grabar` vacía la grabación anterior del dominio solo cuando al menos una consulta responde, y una consulta que falló no se graba. `.gitignore` deja fuera todo lo de `respuestas_grabadas/dns/` menos `.gitkeep`, así que un `git add` no lo sube.

## Recolector de GitHub (#16)

`cirdan/recolectores/github.py` revisa los repos públicos de la organización de GitHub que la empresa declaró como suya y busca claves de acceso y correos del dominio en su versión actual y en todo su historial. Tiene su propia fila `github` en `data_sources` (`db/semillas/006_github.sql`), sembrada encendida y con `keep_raw_payload` = false. Devuelve:

| Código de regla | Severidad base | Cuándo |
|---|---|---|
| `secret_in_public_repo` | critical | gitleaks halla una clave en un archivo de un repo, en la versión actual o solo en el historial. Uno por repo, ruta y regla, sobre el activo `domain` |
| `email_in_public_commits` | low | Un correo del dominio o de un subdominio sale como autor o como quien subió un commit. Uno por correo, sobre su activo `email` |

**Solo la organización declarada.** `ORGS_GITHUB_DECLARADAS` (en `.env` y `docker-compose.yml`) lleva pares `dominio=org` separados por comas, por omisión `olmardo.com=olmardo`. Hace de campo 'Organización de GitHub de la empresa' de la carta hasta la tabla de #64. Un dominio sin par, o con `ninguna`, no consulta nada: la fuente queda `succeeded`, con sus 2 códigos en `sin_cobertura` y un aviso, así el portal dice 'sin cobertura' y no 0. Nunca deduce la organización del nombre del dominio, porque la política prohíbe adivinar nombres de recursos. Del perfil solo guarda si GitHub la verificó y si su sitio o su correo son del dominio, como dato de confianza en `atributos['github']` del activo `domain`, junto con los repos revisados y cuántos se saltaron.

**Qué consulta.** `GET /orgs/<org>` y una página de `GET /orgs/<org>/repos` (hasta 100, por último push), sin token y con 3 intentos cada una. Luego clona con `git clone --bare --no-tags` por https hasta 10 repos que no sean fork ni deshabilitados, de hasta 100 MB, del push más reciente al más viejo. Los archivados entran, y los de tamaño 0 también, porque GitHub calcula el tamaño cada hora y un repo recién creado sale con 0 aunque ya tenga commits. git corre sin hooks, solo con https, revisando los objetos al recibirlos, sin pedir credenciales y con un entorno limpio (`PATH` y un `HOME` temporal), así ninguna variable de la API llega al proceso. Un nombre de organización o de repo que empiece con `-`, que traiga `/` o `..`, o que no sea un nombre de GitHub, nunca llega a la línea de comandos. Lo demás es local, sobre el clon: gitleaks 8.21.2 con `cirdan/recolectores/gitleaks_cirdan.toml` (sus reglas de omisión más una para los tokens falsos `CIRDAN_FAKE_`, que `generic-api-key` descarta por la palabra 'fake'), que salta los archivos de más de 100 MB, y `git log` para los correos.

**Nunca guarda un secreto ni un nombre.** gitleaks corre con `--redact` y su reporte se lee por lista blanca: regla, ruta y fecha. Si un hallazgo trae el valor sin redactar, la corrida se descarta completa: queda sin cobertura con un aviso, sin grabar nada y sin reintentos, porque daría lo mismo. La huella es el sha256 de código, repo, ruta y regla, así no depende del valor, que no se usa, no se guarda ni sale del proceso. De `git log` solo salen los correos, nunca los nombres. Los que no son del dominio (noreply, gmail, parecidos) y los del dominio con forma inválida se descartan y solo se cuentan en un aviso. El título del hallazgo de correo no lleva el correo, que va en su activo, porque el título puede salir de la plataforma (`docs/politica_uso_etico.md`). Ni la salida de error de git o gitleaks ni el texto de una excepción llegan al resultado: `scan_source_runs.error` se guarda aunque `keep_raw_payload` sea false, así que toda falla sale con un texto fijo. El clon, el reporte y la salida de `git log` viven en una carpeta temporal `cirdan-github-*` que no puede pasar de 300 MB mientras corre git o gitleaks y que se borra al terminar. Un proceso que se pasa de tiempo o de disco se mata con sus hijos. Cada corrida en vivo empieza borrando las carpetas de más de una hora que haya dejado una API caída a medias o que el sistema no dejó borrar. Por los procesos que deja git al matarlo, el servicio `api` de `docker-compose.yml` corre con `init: true`.

**Límites y cobertura.** 120 s por clon, 120 s por gitleaks, 60 s por `git log`, 20 MB de salida de `git log`, 300 MB de disco por repo y 6 minutos por corrida, que también corta las consultas a la API. Un repo que no se revisó (por tamaño, por nombre, por pasar de 10, por el tiempo, por el disco o porque falló) deja un aviso de cobertura parcial, y cada código que quedó sin hallazgos va a `sin_cobertura`. Un código que ya trae hallazgos no puede ir ahí, así que solo queda el aviso. Si no se pudo revisar ningún repo, la fuente queda `failed` y en vivo se reintenta a 1, 5 y 25 minutos. Si `git` o `gitleaks` no están instalados, también, pero lo sabe antes de consultar la API.

**Cuota de GitHub.** Sin token, la API da 60 consultas por hora por IP. Un 403 o un 429 no se reintenta ni deja la fuente `failed`, porque el orquestador la reintentaría reservando 16 consultas cada vez: queda `succeeded` con los 2 códigos en `sin_cobertura` y un aviso. Para el límite diario cada intento a la API y cada clon cuentan como consulta: hasta 16 por corrida (`MAX_CONSULTAS`), y la semilla 006 pone 400 por día, 25 corridas. El orquestador reserva las 16 antes de llamar al recolector, así que si ya no caben en el día la fuente queda `failed` por falta de cupo, aunque el dominio no tenga organización declarada. Un token llegará con #8 (RC-40), nunca en una variable `GITHUB_TOKEN`.

**Grabación.** Se graba solo lo ya limpio en `cirdan/recolectores/respuestas_grabadas/github/<dominio>/` (ver `docs/contrato_plugin.md`), todo al final y solo si la corrida terminó. Al reproducir no consulta GitHub ni corre procesos. Sin grabación del dominio, reproducir da los 2 códigos en `sin_cobertura` y un aviso, no `failed`, así la demo de acme-demo.mx no muestra la fuente caída. A diferencia de crt.sh, la línea de comandos rechaza vivo y `--grabar` para un dominio que no esté en `DOMINIOS_EN_VIVO`. La imagen trae git y gitleaks, pero el usuario `cirdan` no escribe en `respuestas_grabadas/`, así que se graba dentro del contenedor montando solo la carpeta de GitHub. Después, `grep -r CIRDAN_FAKE_` sobre esa carpeta debe dar 0, y se reconstruye la API (con `docker compose --dry-run up -d --build api` antes), porque la imagen copia `cirdan/` con la grabación.

```bash
docker compose run --rm -v "$(pwd -W)/cirdan/recolectores/respuestas_grabadas/github:/app/cirdan/recolectores/respuestas_grabadas/github" api python -m cirdan.recolectores.github olmardo.com --grabar   # en vivo, con el OK de la persona. En macOS y Linux va "$PWD/..."
python -m cirdan.recolectores.github olmardo.com --reproducir    # solo con lo grabado, sin red ni procesos
python -m unittest -v pruebas/test_github.py                     # 59 pruebas sin red. Se saltan 2 que piden git y gitleaks
docker compose run --rm -v "$(pwd -W)/pruebas:/app/pruebas:ro" -v "$(pwd -W)/db:/app/db:ro" -v "$(pwd -W)/docs:/app/docs:ro" api python -m unittest pruebas.test_github.Integracion   # las 2, con git y gitleaks reales sobre un repo local
```

Código de salida: 0 bien, 1 si queda en `failed` y 2 si quedan avisos. Hasta que #23 (RC-55) guarde activos y hallazgos, nada de esto llega a `assets` ni a `findings`.

**Versión.** El `Dockerfile` baja el tar.gz del release de gitleaks 8.21.2 para cada arquitectura (el release llama x64 a amd64) con su sha256 de `gitleaks_8.21.2_checksums.txt`, y deja la licencia en `/usr/share/licenses/gitleaks/LICENSE` (ver `NOTICE`). Es la misma versión del pre-commit. Dependabot no la vigila: para subirla se cambian las dos URL y los dos hash del `Dockerfile`, la versión en `NOTICE` y la de `.pre-commit-config.yaml`.

## Recolector de Shodan / InternetDB (#17)

`cirdan/recolectores/shodan.py` toma lo que Shodan ya vio en las IP públicas del dominio, con Shodan InternetDB (`https://internetdb.shodan.io/<ip>`), que no pide llave. Nunca le pide a Shodan que escanee nada ni toca un servidor del dominio. Usa la fila `shodan` de `data_sources` que ya sembró la 001 (encendida y con `keep_raw_payload`), y la semilla 007 le pone su límite diario. Arma su lista de IP en tres pasos:

1. **Nombres:** los del dominio en los certificados vigentes de Cert Spotter (2 páginas, sin el `*.` de los comodines), más la raíz, hasta 10. Nunca adivina un nombre. Los nombres de otras fuentes no se usan, porque eso necesita pasar datos entre fuentes (#23).
2. **IP:** el A de cada nombre con 1.1.1.1 y 8.8.8.8, como el recolector de DNS. Sin AAAA, porque InternetDB es solo IPv4.
3. **Servicios:** una consulta a InternetDB por cada IP pública, hasta 10, con un segundo entre una y otra. Solo consulta IPv4 globales que no sean multicast, reservadas ni del relay 6to4 (192.88.99.0/24). No consulta las de los rangos de Cloudflare (verificados contra cloudflare.com/ips-v4 el 27 oct 2026) ni las que llegan por una cadena CNAME en la que cualquier nombre, intermedio o final, es de un CDN o borde compartido de la lista `SUFIJOS_CDN` de `shodan.py` (Cloudflare, CloudFront, Akamai, Fastly, Azure CDN y Front Door, Bunny, Imperva, Vercel con `cname.vercel-dns.com` y los numerados `vercel-dns-NNN.com`, Netlify con `netlify.app` y `netlify.com`, Shopify, GitHub Pages y Heroku): de una IP de CDN solo se registra que existe (`docs/politica_uso_etico.md`, punto 5). La cadena sale de la misma respuesta del A, sin consultas extra. Esos sufijos son los públicos conocidos y no se verificaron en vivo. Tampoco consulta las de un ASN que es solo de un CDN o un proxy inverso (`CDN_POR_ASN` de `geoip.py`: Cloudflare, Fastly, Akamai, Imperva, Sucuri, Bunny y Edgio), aunque no haya CNAME a la vista, con la base local de DB-IP Lite (#15b). Un ASN mixto de nube y CDN (Amazon, Microsoft, Google) no cuenta, porque una IP suya puede ser un servidor de la empresa: ahí el CDN sale solo por el CNAME, y si no se ve en uno no se detecta. Tampoco se detecta sin CNAME un CDN cuyo ASN no esté en esa lista (CDN77, Edgecast u otros), ni ninguno si falta la base de ASN de DB-IP: entonces esas IP se consultan igual y el aviso de base faltante lo dice. Si InternetDB igual marca la IP con el tag `cdn`, sus datos se descartan con un aviso.

Devuelve un activo `ip` por IP, con `hosts` (los nombres que resuelven a ella), su país, ASN y proveedor de DB-IP Lite (también las que no se consultan) y lo que dijo InternetDB (con `fuente_datos` = 'Shodan InternetDB' solo si InternetDB sí respondió por esa IP), un activo `service` por puerto (`<ip>:<puerto>/<protocolo>`, con `parent` e `ip_address` = su IP) y estos hallazgos:

| Código de regla | Severidad base | Cuándo |
|---|---|---|
| `exposed_rdp` | high | Puerto 3389 |
| `exposed_remote_admin` | high | Puertos 22, 23, 5900, 5901, 5985 y 5986 |
| `exposed_file_sharing` | high | Puertos 21, 139, 445, 548, 873 y 2049 |
| `exposed_database` | high | Puertos 1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211 y 27017 |
| `exposed_service` | low | Cualquier otro puerto, como 8080. Los industriales (102, 502, 789, 1911, 2404, 4911, 9600, 20000, 44818 y 47808) llevan `puerto_industrial` en la evidencia |
| `known_vulnerability` | medium | Cada CVE que Shodan deduce de la versión que vio, sobre el activo `ip`, con la CVE como clave y hasta 25 por IP, las más recientes, con un aviso de cuántas se omitieron |

Los puertos 80 y 443 y los de correo (25, 110, 143, 465, 587, 993 y 995) dan su activo `service` sin hallazgo. Los tags y las CPE solo van a los atributos. Con el tag `honeypot` esa IP no da servicios ni hallazgos, solo un aviso. De los nombres que trae InternetDB solo se guardan los del dominio. Los demás solo se cuentan.

**Datos sin fecha.** InternetDB no dice cuándo vio cada puerto ni si es tcp o udp. Cada hallazgo lleva `vigencia` = 'sin_fecha', `fuente_sin_fecha` y `nota_vigencia`, que dice que InternetDB no fecha sus datos y que pueden ser de quien tuvo la IP antes. El protocolo es tcp salvo los puertos que solo tienen sentido en udp (123, 161, 500, 1900, 5353, 5683 y 47808), y el activo `service` lleva `protocolo_supuesto`. Solo si InternetDB trae en la IP nombres de otro dominio, la evidencia lleva además `posible_dato_de_otro_dueno` y queda un aviso. 20.69.154.199, la VM de camaras.olmardo.com, no lleva esa marca, porque InternetDB no trae nombres para ella: el 27 oct seguía con el puerto 50000 del dueño anterior y no con el 8080, y #17 lo reporta como `exposed_service` sobre `20.69.154.199:50000/tcp` con 'sin_fecha' y su `nota_vigencia` (`docs/hallazgos_esperados.md`, filas 10 y 11).

**Sin llave y cobertura.** Sin la llave de Shodan (#8, RC-40) no hay API de host: `exposed_iot_device`, `exposed_ot_device` y `outdated_software` van siempre a `sin_cobertura`. Si algo quedó sin revisar (Cert Spotter caído o con 429, los topes de 10 nombres o de 10 IP, un A o una IP sin respuesta, una respuesta 200 de InternetDB vacía, 'null', sin `ports` o con campos que no se pueden leer, el 429 de InternetDB o los 6 minutos de la corrida), los códigos de la tabla sin hallazgos también van ahí. Solo un 404 de InternetDB es 'sin datos' y no cuenta como falla. Las esperas entre intentos, el tiempo del A y el plazo de cada petición HTTP nunca pasan de lo que le queda a la corrida. Ese plazo cubre toda la lectura de la respuesta, así que un servidor que manda el cuerpo de a poco se corta, pero no cubre la búsqueda del nombre del servidor. Un 429 no se reintenta y corta las IP que faltan. Si no queda ninguna IP que consultar, la fuente queda `succeeded` con 0 hallazgos y un aviso. Si Cert Spotter y todos los A fallaron, o todas las IP fallaron por la red, queda `failed` y en vivo se reintenta.

**Cupo.** Cada intento de cada petición HTTP o DNS cuenta como consulta: hasta 64 por corrida (`MAX_CONSULTAS`: 2 páginas de Cert Spotter con 2 intentos, 10 A con 3 y 10 IP con 3), y la semilla 007 pone 640 por día, 10 corridas. Las páginas de Cert Spotter que pide Shodan cuentan en el límite diario de `shodan`, no en el de `ct_logs`, pero gastan el mismo cupo por hora sin llave de Cert Spotter (ver Cert Spotter, complemento y respaldo): con `ct_logs` y `shodan`, unos 2 o 3 escaneos por hora, y no se ensaya en la hora anterior a la demo. Si `shodan` queda `failed`, el orquestador la reintenta a 1, 5 y 25 minutos, y cada intento vuelve a pedir Cert Spotter. InternetDB no publica un límite. El A usa dnspython, como el recolector de DNS: si no está en tu PC, el módulo carga y sus pruebas pasan, pero una consulta real falla hasta que corras `pip install -r requirements.txt`.

**Grabación.** Se graba solo lo ya limpio en `cirdan/recolectores/respuestas_grabadas/shodan/<dominio>/` (ver `docs/contrato_plugin.md`), todo al final y solo si la corrida no tuvo ninguna falla. Los únicos recortes que no impiden grabar son los topes fijos (2 páginas de Cert Spotter, 10 nombres, 10 IP y 25 CVE por IP), porque otra corrida los repetiría igual. Con cualquier falla (un 429 o un 4xx de Cert Spotter o de InternetDB, una página o una emisión de Cert Spotter que no se puede leer, una falla de red o del DNS, una respuesta de InternetDB vacía, 'null' o con campos rotos, o el tope de tiempo), `--grabar` no escribe nada, deja la grabación anterior, pone el aviso de que no se grabó primero y sale con código 3, o con 1 si la falla dejó la fuente en `failed` (por ejemplo, todas las IP caídas): en los dos casos repítelo más tarde. Sin grabación del dominio, reproducir da los 9 códigos en `sin_cobertura` y un aviso, no `failed`. Como en GitHub, la línea de comandos rechaza vivo y `--grabar` para un dominio que no esté en `DOMINIOS_EN_VIVO`, y el usuario `cirdan` no escribe en `respuestas_grabadas/`, así que se graba dentro del contenedor montando solo la carpeta de Shodan y después se reconstruye la API (con `docker compose --dry-run up -d --build api` antes).

**Atribución y licencia.** Los datos son de Shodan: cada hallazgo, cada activo `service` y cada activo `ip` que InternetDB respondió llevan `fuente_datos` = 'Shodan InternetDB'. InternetDB pide un plan de pago para uso comercial. El reto es académico, y #8 (RC-40) revisa los términos antes de cualquier otro uso.

Con `shodan` en `REGISTRO` y encendida en `data_sources`, la fuente corre en todo escaneo. Un escaneo en vivo de olmardo.com consulta Cert Spotter, el DNS e InternetDB, así que `EN_VIVO=1` de `pruebas/test_escaneos_api.py` también consulta InternetDB.

```bash
docker compose run --rm -v "$(pwd -W)/cirdan/recolectores/respuestas_grabadas/shodan:/app/cirdan/recolectores/respuestas_grabadas/shodan" api python -m cirdan.recolectores.shodan olmardo.com --grabar   # en vivo, con el OK de la persona. En macOS y Linux va "$PWD/..."
python -m cirdan.recolectores.shodan olmardo.com --reproducir    # solo con lo grabado, sin red
python -m cirdan.recolectores.shodan olmardo.com --json          # el resultado completo en JSON
python -m unittest -v pruebas/test_shodan.py                     # 52 pruebas, sin red ni dnspython
```

Código de salida: 0 si la corrida fue completa, 1 si queda en `failed`, 2 si la cobertura quedó parcial y 3 si `--grabar` no escribió por una falla y dejó la grabación anterior. El aviso fijo de los límites (solo IPv4 y sin llave) sale en toda corrida y no cuenta. Hasta que #23 (RC-55) guarde activos y hallazgos, nada de esto llega a `assets` ni a `findings`.

## Recolector de RDAP (#15b)

`cirdan/recolectores/rdap.py` lee el registro del dominio con RDAP, el reemplazo de WHOIS (JSON por HTTPS, sin llave), y usa WHOIS por el puerto 43 solo como respaldo. Usa la fila `whois` de `data_sources` que ya sembró la 001 (encendida y con `keep_raw_payload`), y la semilla 008 le pone su límite diario. Casi siempre hace dos consultas por corrida, ninguna a un servidor del dominio:

1. **Bootstrap de IANA** (`https://data.iana.org/rdap/dns.json`, RFC 9224): da el servidor RDAP del TLD. Gana el sufijo más largo del dominio que tenga servicio (para `empresa.com.mx`, primero `com.mx` y después `mx`) y solo se usa una URL https.
2. **Registro:** `<servidor>domain/<dominio>`. Una redirección que sale de https se corta.

**Respaldo por WHOIS (puerto 43, RFC 3912).** Desde el 28 ene 2025 los gTLD ya no están obligados a ofrecer WHOIS, así que RDAP va primero. WHOIS entra solo si el bootstrap no tiene servidor RDAP https para el TLD (el caso principal es .mx y .com.mx, que NIC México no ofrece por RDAP) o si RDAP no respondió, en el bootstrap o en el registro. No entra con el 404 de RDAP ni cuando RDAP responde sin vencimiento o con una fecha rota, porque es el mismo registro y diría lo mismo. Primero le pregunta a `whois.iana.org` por el TLD (solo la última etiqueta, por ejemplo `mx`) y toma su línea `whois:`, sin tabla fija de servidores. Si viene vacía, el TLD no tiene WHOIS. Después pide el dominio a ese servidor, el del registro del TLD (a Verisign con `domain ` delante). Nunca sigue `Registrar WHOIS Server` ni otra referencia a un registrador, porque el WHOIS del registrador sí trae al registrante. Solo se conecta a IP públicas. De la respuesta solo lee las llaves de `CAMPOS_WHOIS` (dominio, registrador, IANA ID, fechas, estados, servidores de nombre y DNSSEC): contactos, correos, teléfonos y direcciones no se leen ni se graban. Cada consulta tiene 2 intentos (espera de 5 s) y un plazo de 10 s que cubre también la búsqueda del nombre del servidor, la conexión y cada lectura. Mientras corre RDAP se guardan 30 s de la corrida para el respaldo.

Devuelve un activo `domain` con `registrador`, `registrador_iana`, `registrado`, `vence`, `ultimo_cambio` (en UTC), `estado_registro`, `servidores_nombre` y `dnssec`. Cuando el registro respondió por RDAP con el dominio lleva `servidor_rdap` y `fuente_datos` = 'RDAP', y cuando respondió por el puerto 43, `servidor_whois` y `fuente_datos` = 'WHOIS', con los estados de WHOIS en la forma de RDAP. De las demás entidades (registrante, contactos y abuso) no lee ni graba nada, porque pueden ser datos personales. Una entidad registrar que además es registrant, administrative, technical o billing tampoco cuenta como registrador. Un dato que el registro no da sale 'No disponible', no vacío. Si ni RDAP ni WHOIS responden, todos salen así. La geolocalización y el ASN de las IP no son de esta fuente: van en los activos `ip` de DNS y de Shodan (ver Geolocalización y ASN de las IP).

| Código de regla | Severidad base | Cuándo |
|---|---|---|
| `domain_expiring_soon` | medium | El vencimiento cae a menos de 30 días del escaneo. Si ya pasó y el registro sigue publicado no sale: queda un aviso con la fecha, porque el texto de la regla habla de lo que vence en los siguientes 30 días |

**Cobertura.** Si no se sabe el vencimiento (ni RDAP ni WHOIS respondieron, el TLD no tiene RDAP ni WHOIS, el registro responde 404 o no conoce el dominio por WHOIS, o no publica la fecha, o la publica rota o imposible, es decir anterior o igual al registro o de hace más de un año), `domain_expiring_soon` va a `sin_cobertura` con un aviso y el activo sale con 'No disponible'. Cuando el registro sale de WHOIS queda un aviso que dice a qué servidor se le pidió y por qué. Un JSON muy anidado o una fecha fuera del calendario dan lo mismo, y un evento o un campo de otro tipo se ignora. La fuente queda `succeeded` y no `failed`, como pide RC-166, así que el escaneo termina `partial` pero el orquestador no la reintenta. Cada consulta RDAP tiene 3 intentos (esperas de 5 y 15 s) y un plazo de 15 s que cubre toda la lectura. La corrida entera tiene 2 minutos. Un 429 o un 4xx, salvo el 408, no se reintentan.

**Cupo.** Cada intento de cada petición HTTP y de cada consulta al puerto 43 cuenta como consulta: hasta 10 por corrida (`MAX_CONSULTAS`: 2 consultas RDAP con 3 intentos y 2 WHOIS con 2), y la semilla 008 pone 60 por día, 6 corridas en el peor caso. Una corrida normal gasta 2 (3 en .mx) y el orquestador ajusta la reserva a lo gastado. El comentario de la semilla 008 todavía habla de 6 consultas y 10 corridas, de antes del respaldo.

**Grabación.** Se graba en `cirdan/recolectores/respuestas_grabadas/whois/<dominio>/`, al final y solo si la corrida no tuvo ninguna falla: el bootstrap reducido al servicio del dominio (`bootstrap.json`) y la respuesta RDAP reducida a lo que se lee, con la forma de RDAP, sin contactos, solo con los valores que pasan los mismos filtros que al leerla y con un evento por acción, así no se graba texto libre (`rdap_<dominio>.json`). Si hubo respaldo, también el servidor WHOIS que dio IANA para el TLD (`whois-iana_<tld>.json`) y la respuesta WHOIS ya reducida a las llaves que se leen (`whois_<dominio>.json`), nunca el texto crudo. Un 404 del registro y un TLD sin RDAP, con su WHOIS o sin él, sí se graban. Si RDAP falló y WHOIS respondió, el resultado sale completo pero no se graba. Con cualquier falla, o si algo no se puede guardar en UTF-8, `--grabar` no escribe, deja la grabación anterior y sale con código 3. Sin grabación del dominio, `reproducir` da el activo con 'No disponible', `domain_expiring_soon` en `sin_cobertura` y un aviso, no `failed`. Una grabación rota sí queda `failed`.

**Lo que se probó en vivo (28 oct).** El respaldo con olmardo.com, con RDAP simulado caído: whois.iana.org dio `whois.verisign-grs.com` para `com` y Verisign respondió con el mismo registrador, fechas, estado, servidores de nombre y DNSSEC que la grabación de RDAP, en 2 consultas y sin grabar. La geolocalización, con las bases de 2026-10 dentro de la imagen (ver Geolocalización y ASN de las IP). Falta whois.mx, porque el equipo no tiene un dominio .mx propio para probarlo. Las pruebas automáticas siguen sin red.

Con `whois` en `REGISTRO` y encendida en `data_sources`, la fuente corre en todo escaneo. La semilla 008 va antes de reconstruir la API (ver `db/README.md`). Un escaneo en vivo de olmardo.com consulta el bootstrap de IANA y el RDAP de Verisign, así que `EN_VIVO=1` de `pruebas/test_escaneos_api.py` también los consulta.

```bash
docker compose run --rm -v "$(pwd -W)/cirdan/recolectores/respuestas_grabadas/whois:/app/cirdan/recolectores/respuestas_grabadas/whois" api python -m cirdan.recolectores.rdap olmardo.com --grabar   # en vivo, con el OK de la persona. En macOS y Linux va "$PWD/..."
python -m cirdan.recolectores.rdap olmardo.com --reproducir    # solo con lo grabado, sin red
python -m cirdan.recolectores.rdap olmardo.com --json          # el resultado completo en JSON
python -m unittest -v pruebas/test_rdap.py                     # 36 pruebas, sin red (tampoco al puerto 43)
```

Código de salida: 0 si la corrida fue completa, 1 si queda en `failed`, 2 si la cobertura quedó parcial y 3 si `--grabar` no escribió por una falla y dejó la grabación anterior. Hasta que #23 (RC-55) guarde activos y hallazgos, nada de esto llega a `assets` ni a `findings`.

## Geolocalización y ASN de las IP (#15b)

`cirdan/recolectores/geoip.py` da el país, el ASN y el proveedor de una IP con dos bases locales de DB-IP Lite, IP to ASN Lite e IP to Country Lite, en formato MMDB, sin llave ni cuota y con licencia CC BY 4.0. No es un recolector: no está en `REGISTRO`, no tiene fila en `data_sources` ni `MAX_CONSULTAS` y nunca consulta la red, así que no gasta cupo. Lo usan las fuentes que crean activos `ip`, DNS y Shodan. Cada activo `ip` lleva `pais` (ISO 3166 de dos letras), `asn`, `proveedor`, `fuente_geo` = 'DB-IP Lite' (la atribución) y `base_geo` con las bases que se usaron, por ejemplo `dbip-asn-lite-2026-10`, y `cdn` si su ASN es solo de un CDN o un proxy inverso (`CDN_POR_ASN`). Un ASN mixto de nube y CDN (Amazon, Microsoft, Google) no cuenta como CDN. Una IP que no es global (privada, de documentación, multicast) sale 'No disponible' sin buscarla, también en `fuente_geo` y `base_geo`: solo se atribuye a DB-IP lo que salió de una base suya. City Lite (121 MB) no se usa: el país cubre la ubicación que promete la carta.

**Sin base, todo sale 'No disponible'.** Si `datos/geo/` no tiene las bases, si no está instalado `maxminddb` o si una base no abre, lo de esa base sale 'No disponible' (el país, o el ASN y el proveedor, y `fuente_geo` y `base_geo` también si no abrió ninguna) y la fuente agrega un aviso que nombra solo lo que se perdió, una vez por corrida y solo si hubo alguna IP global que ubicar. Sin la base de ASN, el aviso de Shodan dice además que las IP de un CDN sin CNAME conocido no se pudieron descartar por ASN y se consultaron igual. La fuente no falla por eso. La ubicación no se graba: al reproducir sale de la base que esté en ese momento, por eso va `base_geo` en cada activo.

**Cómo poner las bases.** DB-IP publica las dos cada mes, normalmente el día 1, con el mes en la URL. No hay URL sin fecha y el 28 oct 2026 solo respondían los dos últimos meses, así que la imagen no las baja al construirse. Se bajan a mano (con el OK de la persona, es una descarga):

| Base | URL (con el mes, por ejemplo 2026-10) | Comprimida | Descomprimida |
|---|---|---|---|
| IP to ASN Lite | `https://download.db-ip.com/free/dbip-asn-lite-AAAA-MM.mmdb.gz` | 5.2 MB | 9.1 MB |
| IP to Country Lite | `https://download.db-ip.com/free/dbip-country-lite-AAAA-MM.mmdb.gz` | 4.1 MB | 8.0 MB |

1. Descomprime las dos con `gzip -d dbip-asn-lite-AAAA-MM.mmdb.gz dbip-country-lite-AAAA-MM.mmdb.gz`, sin cambiarles el nombre: solo se toman archivos que se llamen `dbip-asn-lite-AAAA-MM.mmdb` y `dbip-country-lite-AAAA-MM.mmdb`. Se usan tal como las publica DB-IP.
2. Déjalas en `datos/geo/`. `.gitignore` deja fuera todo lo de esa carpeta menos `.gitkeep`, así que un `git add` no las sube. Si hay varios meses, se toma el más nuevo. A la imagen solo entran `.gitkeep` y los archivos `dbip-asn-lite-*.mmdb` y `dbip-country-lite-*.mmdb` (`.dockerignore`): los `.gz`, City Lite y lo demás se quedan fuera. Los meses viejos sí entrarían sin usarse, así que conviene borrarlos al poner los nuevos.
3. Reconstruye la imagen, que copia `datos/geo/` en `/app/datos/geo` (con `docker compose --dry-run up -d --build api` antes): `docker compose up -d --build api`. `maxminddb` ya está en `requirements.txt` y en la imagen.

Para revisar una IP sin descargar nada: `docker compose exec api python -m cirdan.recolectores.geoip 40.65.94.253`. Imprime lo que da cada IP más su CDN por ASN, y sale con código 1 si falta una base.

**Atribución.** La de DB-IP está en `NOTICE` y en `fuente_geo` de cada activo `ip` que se buscó en una base.

```bash
python -m unittest -v pruebas/test_geoip.py   # 23 pruebas, sin red, sin maxminddb y sin bases
```

## Límite diario por fuente (#13b)

Cada fuente tiene un límite diario de consultas, como promete la carta. Vive en su fila de `data_sources` (migración 008): `daily_limit` es el límite de toda la plataforma (vacío quiere decir sin límite), `daily_used` lo gastado y `daily_used_on` el día de ese conteo. El día es UTC, así que en Monterrey cambia a las 18:00. Se cuenta en las consultas de cada recolector, las mismas de `consultas` en su resultado: peticiones HTTP en `ct_logs`, consultas DNS en `dns`, fuentes consultadas en `subfinder` y peticiones a la API más clones en `github`, peticiones HTTP más consultas DNS en `shodan` y peticiones HTTP más consultas al puerto 43 en `whois`. La semilla 005 pone 200 por día a `ct_logs` y 50 corridas por día a `subfinder` (50 por las 8 fuentes de su lista blanca, aunque la deja apagada, ver Recolector de subfinder), y explica de dónde sale cada número. La semilla 006 pone 400 por día a `github`, 25 corridas de a lo más 16, la semilla 007 pone 640 por día a `shodan`, 10 corridas de a lo más 64, y la semilla 008 pone 60 por día a `whois`, 6 corridas de a lo más 10 (2 consultas RDAP y 2 WHOIS por el puerto 43, con sus intentos). `dns` queda sin límite (`daily_limit` vacío), aunque reserva y cuenta sus consultas igual: hasta 18 consultas DNS por corrida (`MAX_CONSULTAS`, 6 consultas de a lo más 3 intentos). Para subfinder una consulta es una fuente consultada en una corrida, no una petición HTTP.

En vivo y al grabar, el orquestador reserva antes de cada intento el máximo que puede gastar una corrida de esa fuente (`MAX_CONSULTAS` de su recolector) y, al terminar, ajusta a lo que de verdad gastó. Así dos escaneos a la vez, o uno de la API y otro de `python -m cirdan.orquestador`, nunca pasan el límite. `cirdan_app` no tiene `UPDATE` sobre `data_sources`: el conteo del día solo se mueve con dos funciones de la base, que `cirdan_app` sí puede llamar, y el ajuste acepta cualquier diferencia. En el cambio de día UTC, una corrida que reservó antes de la medianoche y gasta después puede pasar el límite del día nuevo hasta en su `MAX_CONSULTAS`: es un margen aceptado. Si la reserva no cabe, la fuente queda en `failed` con el error `Sin cupo diario` y sin reintento, y el escaneo termina `partial` o `failed` como con cualquier fuente caída. Al reproducir no se reserva ni se gasta, así una demo con grabación nunca se queda sin cupo. Correr un recolector desde la terminal, por ejemplo `python -m cirdan.recolectores.crtsh`, no pasa por el orquestador y no cuenta. El detalle está en `docs/contrato_plugin.md`.

Las pruebas del límite están en `pruebas/test_orquestador.py` y piden la migración 008 y la semilla 005 aplicadas. `test_3r`, la del cambio de día, entra como `postgres` para poner `daily_used_on` en ayer y se salta si el contenedor no tiene `POSTGRES_PASSWORD`. Para correrla, exporta antes la variable en la terminal y agrega `-e POSTGRES_PASSWORD` (sin su valor) al comando: `docker compose run --rm -e POSTGRES_PASSWORD -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest pruebas/test_orquestador.py`.

## Criterio de criticidad (#29)

Más alto = más riesgo. Bandas 0 a 39 bajo, 40 a 59 medio, 60 a 79 alto y 80 a 100 crítico, ancladas al ejemplo del reto (68 = riesgo alto). Regla de piso: un hallazgo crítico vigente deja el dominio al menos en 60, y dos o más, al menos en 80. La alerta se crea cuando el score llega al umbral o lo pasa. El criterio completo, con ejemplos y quién usa qué, está en `docs/criterio_criticidad.md`, y su código en `cirdan/score/criterio.py`.

```bash
python -m unittest -v pruebas/test_criterio.py   # 13 pruebas, sin base de datos
```

El motor de score de #31 calcula aportes por hallazgo, notas por categoría, ponderado y piso crítico. La fórmula acordada y el texto que explica el piso están en `docs/criterio_criticidad.md`.

```bash
python -m unittest -v pruebas/test_motor_score.py   # sin base de datos
```

## Catálogo de reglas (#30)

El juego de reglas v1 tiene 30 reglas en las 4 categorías: las 7 de la semilla 001 y las 23 de `db/semillas/004_reglas_recolectores.sql`, una por cada código que emiten o van a emitir #14 a #20 y las extras previstas #62 a #64. Cada regla tiene su título, qué significa y qué hacer en `scoring_rule_texts` (migración 003, con las correcciones de la 005), en español simple y sin siglas. La lista de códigos, con su categoría, severidad base, tope, recolector y estado, y cómo agregar uno nuevo, está en `docs/codigos_reglas.md`. La prueba falla si un recolector declara en `CODIGOS` un código sin regla o con otra severidad, si una regla no tiene texto o si la lista no coincide con las semillas. Cada recolector debe emitir solo los códigos de su `CODIGOS`, y lo que emite de verdad la prueba solo lo revisa en `ejemplo`.

```bash
python -m unittest -v pruebas/test_catalogo_reglas.py   # 14 pruebas, sin base ni red
```

## Contrato de API v1 (#21)

Lo que devuelve la API v1 (`/api/v1`): dominios, hallazgos, score, histórico, explicación y pesos, con un JSON de ejemplo por respuesta en `docs/api_v1/`. La API v1 ya existe (ver API arriba) y el portal la lee desde el 15 oct 2026. Hoy los JSON de ejemplo los usan las pruebas de este repo, y el portal tiene una copia en sus datos simulados que no se actualiza sola. Los usará el dataset de ML (#33, RC-65). También sirven de plan B en las demos. El detalle está en `docs/contrato_api_v1.md`.

```bash
python -m unittest -v pruebas/test_contrato_api.py   # 24 pruebas, sin base ni red
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
python -m unittest -v pruebas/test_contrato.py   # 40 pruebas, sin red
```
