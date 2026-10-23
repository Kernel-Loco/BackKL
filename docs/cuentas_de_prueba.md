# Cuentas de prueba y cómo pasar el MFA

Cuentas para entrar al portal LowTide en tu PC mientras desarrollamos. Son **solo de demostración**: la contraseña y los secretos de MFA son públicos a propósito y nunca deben usarse fuera de desarrollo.

## Antes de entrar

1. **Backend:** en BackKL, ten en el `.env` la línea `DEMO_ACCOUNTS=true` (viene así en `.env.example`) y levántalo con `docker compose up -d --build`. El `--build` hace que la imagen traiga el código actual cada vez que haces pull. Cada vez que arranca, el contenedor `demo-accounts` les pone contraseña y MFA a estas cuentas.
2. **Portal:** en FrontKL, `npm run dev` y abre **http://localhost:3000**. Tiene que ser el puerto 3000: la API solo acepta inicios de sesión del portal en ese puerto y de su propia página en el 8000. Rechaza los que vienen de otro origen.
3. **Explorador de la base (opcional):** pon `DEMO_EXPLORER=true` en el `.env` de BackKL y vuelve a levantarlo con `docker compose up -d --build`, porque la API lee esa línea al arrancar. Luego abre **http://127.0.0.1:8000/demo** y entra con `alex.morgan@acme-demo.mx` o `dana.cruz@beta-corp.mx`. Las tablas solo las ve un Administrador. Más detalle en 'Vista visual de la base' del README.

## Las cuentas

La contraseña es la misma para las cinco: **`Lowtide-Demo-2026`**

| Correo | Rol en el portal | Empresa | Qué ve |
|---|---|---|---|
| `jordan.tate@acme-demo.mx` | Analista | Acme Demo | Dashboard, Dominios y autorización (solo la lista), Detalle de dominio, Hallazgos y Reportes e histórico |
| `maya.reed@acme-demo.mx` | Gerente | Acme Demo | Dashboard, Dominios, Detalle de dominio y Reportes e histórico, solo lectura |
| `alex.morgan@acme-demo.mx` | Administrador | Acme Demo | Todo lo anterior, más registrar dominios, verificar el TXT, Políticas de alerta y la sección Administración |
| `dana.cruz@beta-corp.mx` | Administrador | Beta Corp | Solo los datos de Beta Corp. Sirve para comprobar que una empresa no ve los datos de otra |
| `admin@olmardo.com` | Administrador | Grupo Olmardo | El dominio de prueba del equipo, olmardo.com: el único que el orquestador escanea en vivo (#22) |

## Cómo pasar el MFA (verificación en dos pasos)

Después de la contraseña, el portal pide un código de 6 dígitos que cambia cada 30 segundos. Hay dos formas de obtenerlo.

### Opción 1: con tu app autenticadora (la más cómoda)

Sirve Google Authenticator, Microsoft Authenticator, Authy, 1Password u otra parecida. Se configura una sola vez por cuenta:

1. En la app, elige **Agregar cuenta** → **Ingresar una clave de configuración** (o «clave manual»; no hace falta escanear un QR).
2. Escribe un nombre (por ejemplo, `LowTide Analista`) y la **clave** de la tabla.
3. Si la app pregunta el tipo, elige **Basada en el tiempo** (TOTP, 6 dígitos, 30 segundos).

| Cuenta | Clave (secreto TOTP) |
|---|---|
| `jordan.tate@acme-demo.mx` (Analista) | `OZTNVMHSFGXI7VAG2ACGA7TSNCUE3S6H` |
| `maya.reed@acme-demo.mx` (Gerente) | `3BU6UYVDTBEQMASX2IGWUOJGGJBXMLZW` |
| `alex.morgan@acme-demo.mx` (Administrador) | `UGXK2GMMQ65BHJLIVR6NNDOAKMMRVLW5` |
| `dana.cruz@beta-corp.mx` (Administrador, Beta Corp) | `CMPPTNCOFPU3YUPJB4KJGFDMN5QZPXOV` |
| `admin@olmardo.com` (Administrador, Grupo Olmardo) | `SNSA4TTR4FCTTDMKEYMPWGD6ZAKG3G5B` |

Desde ahí, la app muestra el código de cada cuenta. Las claves son fijas: aunque reconstruyas Docker, no hace falta volver a agregarlas. Están en `CUENTAS` de `cirdan/auth/demo.py`.

### Opción 2: pedirle el código al backend

Desde la carpeta BackKL, con Docker corriendo:

```bash
docker compose exec api python -m cirdan.auth.demo codigo jordan.tate@acme-demo.mx
```

Imprime el código vigente de esa cuenta. Cámbiale el correo para las otras. Escríbelo antes de que pasen 30 segundos.

## Si algo falla

| Mensaje en el portal | Qué pasa y qué hacer |
|---|---|
| «Correo o contraseña incorrectos.» | Revisa el correo y la contraseña. Si cambiaste la contraseña desde «Mi perfil», vuelve a la de demo con `docker compose run --rm demo-accounts`. Si `DEMO_ACCOUNTS` no está en `true`, las cuentas no tienen contraseña válida |
| «El código no es válido o ya expiró.» | Espera al siguiente código: **con la misma cuenta, un código no se puede usar dos veces**, aunque sea en otra pestaña u otro navegador. Revisa también que la hora de tu celular o PC esté en automático |
| «Tu verificación expiró. Inicia sesión de nuevo.» | Pasaron más de 5 minutos o hubo 5 códigos equivocados después de la contraseña. Vuelve a escribir correo y contraseña |
| «Demasiados intentos. Espera 15 minutos…» | Hubo 5 fallos con ese correo (o 20 desde tu PC). Espera 15 minutos o desbloquéalo con el comando de abajo |
| La pantalla regresa al login con «Tu sesión expiró…» | Pasaron 15 minutos sin actividad, o 8 horas desde que entraste. Vuelve a iniciar sesión |
| «Origen no permitido» o el login no responde | El portal no está en http://localhost:3000, o el backend no está corriendo (`docker compose ps` debe mostrar los contenedores `healthy`) |

Para desbloquear todos los correos bloqueados, desde BackKL:

```bash
docker compose exec valkey sh -c 'valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning --scan --pattern "login:fail:*" | xargs -r valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning del'
```

## Lo que no funciona todavía

- **Registro abierto y «¿Olvidaste tu contraseña?»** todavía no tienen backend; esas pantallas lo dicen al enviarlas. Las cuentas nuevas las creará un Administrador por invitación.
- **Captcha** (RC-5): pendiente.
- **Los datos del portal** (dominios, hallazgos, score, reportes) siguen simulados hasta conectar la API v1 (RC-17). El inicio de sesión, la sesión, el rol y el perfil sí son reales.
