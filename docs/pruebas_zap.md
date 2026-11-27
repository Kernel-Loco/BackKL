# Pruebas de seguridad web con ZAP (RC-89, #51)

ZAP en modo de escaneo activo completo contra el producto final en la VM, por `https://lowtidesec.com`, con una cuenta de prueba autenticada. Es la única prueba activa que este documento permite. Las reglas generales están en `docs/politica_uso_etico.md` (sección de pruebas activas) y en `docs/despliegue.md` (por qué no va por `pruebas.lowtidesec.com` ni por SSH).

## Cabeceras que el escaneo debe encontrar

| Cabecera | Portal (páginas) | API (`/api/v1/*` a través del portal) |
|---|---|---|
| `Content-Security-Policy` | Con nonce nuevo en cada página, `script-src 'self' 'nonce-…' 'strict-dynamic'` y `frame-ancestors 'none'` (FrontKL `src/lib/csp.ts`, la pone `src/proxy.ts`) | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` (`cirdan/api/main.py`). El reporte en HTML y `/demo` llevan la suya, también con `frame-ancestors 'none'` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (FrontKL `next.config.ts`) | Igual (`cirdan/api/main.py`) |
| `X-Frame-Options` | `DENY` | `DENY` |
| `X-Content-Type-Options` | `nosniff` | `nosniff` |
| `Referrer-Policy` | `same-origin` | `no-referrer` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), usb=()` | Igual |
| `Cache-Control` | `private, no-cache, no-store, max-age=0, must-revalidate, no-transform` (`src/proxy.ts`) | `no-store` en toda respuesta, también el 500; una ruta que pone el suyo lo conserva (`cirdan/api/main.py`, #75) |

HSTS va sin `preload` (decisión del 22 nov): hstspreload.org acepta el dominio de quien lo inscriba y salir de la lista tarda meses. Cloudflare no pone HSTS: lo ponen el portal y la API, que quedan en git con sus pruebas.

El portal usa `same-origin` y no `no-referrer` (decisión del 22 nov): con `no-referrer` el navegador manda `Origin: null` en un POST de formulario normal y la API lo rechaza. Con `same-origin` el Referer completo solo va dentro de `lowtidesec.com` y nada sale hacia otros sitios. La API se queda con `no-referrer` porque solo responde JSON.

### Lo que Cloudflare inyecta en las páginas

La CSP del portal solo deja correr scripts con el nonce de la página. Un script que Cloudflare meta en el HTML no lo lleva y el navegador lo bloquea (en el peor caso, con un error de hidratación de React). Por eso las páginas salen con `Cache-Control: no-transform`, que según la documentación de Cloudflare apaga Email Address Obfuscation y el script de JavaScript detections de Bot Fight Mode. El costo, aceptado el 22 nov: ni Next ni Cloudflare comprimen una respuesta con `no-transform`, así que el HTML de las páginas va sin gzip (los archivos de `_next/static` sí van comprimidos). Las páginas de no encontrado se quedan sin `no-transform`, porque Next pone ahí su propio `Cache-Control`.

La documentación de Cloudflare no dice que `no-transform` apague todo lo demás. Antes de la ventana Ernesto revisa en el panel de `lowtidesec.com` que estas opciones sigan apagadas, y al leer el reporte, que ninguna alerta de CSP venga de un script de `/cdn-cgi/`:

| Opción del panel | Dónde | Qué inyecta |
|---|---|---|
| Email Address Obfuscation | Scrape Shield | `email-decode.min.js` en cada página cuyo HTML trae un correo, como `arco@lowtidesec.com` en los términos, la privacidad y las pantallas de acceso |
| Rocket Loader | Speed, Optimization | Reescribe todos los `<script>` de la página |
| Web Analytics con instalación automática | Analytics & Logs, Web Analytics | El beacon de `static.cloudflareinsights.com` |
| Zaraz | Zaraz | Su script de terceros |
| Bot Fight Mode | Security, Bots | JavaScript detections. Según Cloudflare le pone el nonce de la CSP, y con `no-transform` no lo inyecta |

## Lo que pone Ernesto antes de la ventana

1. Una organización de pruebas con una cuenta de prueba (rol `admin`, para que ZAP vea las pantallas de administración). Nunca las cuentas de demo, las de Grupo Olmardo ni `equipo@lowtidesec.com`. La organización no tiene dominios de clientes: el escaneo no debe crear escaneos de terceros.
2. `pg_dump` de la VM justo antes de empezar, y la ventana lejos del 27 nov (versión congelada y sesión S16).
3. En Cloudflare, durante la ventana, una regla temporal de Skip para la IP desde donde corre ZAP, y Bot Fight Mode apagado si está prendido (la regla no lo salta en el plan gratis). Sin eso el reporte mezcla los bloqueos de Cloudflare con LowTide.
4. La sesión de ZAP. El valor de la cookie no se escribe en archivos del repo, en el reporte ni en el historial de la terminal. Mientras el contenedor de ZAP existe, `docker inspect` lo muestra en su configuración (`-e ZAP_AUTH_HEADER_VALUE`). `--rm` la borra al salir, y si Docker se cae a media corrida se borra el contenedor a mano con `docker rm`:
   1. Ernesto entra con la cuenta de prueba en una ventana normal del navegador, no privada (contraseña y MFA son suyas), y copia el valor de la cookie `lt_session` desde las herramientas de desarrollo (Application o Almacenamiento, Cookies).
   2. Cierra la pestaña sin cerrar sesión. Cerrar sesión invalida la cookie en el servidor y ZAP se quedaría sin sesión. La pestaña no se deja abierta porque el aviso de inactividad del portal (FrontKL `src/components/IdleTimeout.tsx`) llama a `POST /api/v1/auth/logout` al vencer, y eso también borra en el servidor la sesión que usa ZAP. La ventana es normal para poder cerrar sesión al final con esa misma cookie.
   3. En la terminal donde corre ZAP la pega en un prompt sin eco, que no queda en el historial (en PowerShell, `Read-Host` no guarda lo que se escribe, y la línea del comando no lleva el valor):

      ```powershell
      $s = Read-Host -AsSecureString 'lt_session'; $env:ZAP_LT_SESSION = [System.Net.NetworkCredential]::new('', $s).Password; Remove-Variable s
      ```

      En bash: `read -rs ZAP_LT_SESSION && export ZAP_LT_SESSION`. Nunca `$env:ZAP_LT_SESSION = '…'` ni `export ZAP_LT_SESSION=…` con el valor escrito: ese sí queda en el historial.
   4. `ZAP_AUTH_HEADER_VALUE` se arma con esa variable en esa misma terminal: en bash, con el prefijo del `docker run` de abajo, y en PowerShell, con la línea que va antes del `docker run`. El `docker run` la pasa con `-e` sin `=valor`. En otra terminal, o sin esa línea en PowerShell, no existe y ZAP correría sin sesión.

## Cómo se corre

Imagen `ghcr.io/zaproxy/zaproxy:stable` con el plan de `docs/zap/plan.yaml` (Automation Framework):

```
ZAP_AUTH_HEADER_VALUE="lt_session=$ZAP_LT_SESSION" docker run --rm -e ZAP_AUTH_HEADER=Cookie -e ZAP_AUTH_HEADER_SITE=lowtidesec.com -e ZAP_AUTH_HEADER_VALUE -v "$PWD/docs/zap:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap.sh -cmd -autorun /zap/wrk/plan.yaml
```

En Git Bash de Windows el comando va con `MSYS_NO_PATHCONV=1` delante, o la ruta `/zap/wrk/plan.yaml` sale convertida a una ruta de Windows y ZAP no encuentra el plan.

En PowerShell, antes del `docker run` (sin el prefijo de bash): `$env:ZAP_AUTH_HEADER_VALUE = "lt_session=$env:ZAP_LT_SESSION"`, y al terminar `Remove-Item Env:ZAP_AUTH_HEADER_VALUE`.

- Contexto: `https://lowtidesec.com` con todo lo que cuelga de ahí. Fuera de alcance cualquier otro host (Cloudflare `cdn-cgi`, `altcha.org`).
- Sesión: las variables `ZAP_AUTH_HEADER`, `ZAP_AUTH_HEADER_VALUE` y `ZAP_AUTH_HEADER_SITE` de ZAP ponen `Cookie: lt_session=…` solo en las peticiones cuyo host contiene `lowtidesec.com` (ZAP compara si lo contiene, no si es igual, así que también valdría para un host como `xlowtidesec.com`). El escaneo no sale del contexto de abajo, y el valor de la cookie no aparece en la salida de ZAP. No va en el Replacer: ZAP 2.17 no sustituye `${ZAP_LT_SESSION}` dentro de sus reglas y manda el texto literal, así que todo da 401 (corrida del 22 nov a las 18:34, hora de Monterrey, probado después contra un eco local). Una regla del Replacer pone `Origin: https://lowtidesec.com` en cada petición a `https://lowtidesec.com` (campo `url` de la regla), porque la API rechaza los POST con otro Origin.
- Antes de leer el reporte, revisar que ZAP sí tuvo sesión: `/dashboard` no debe aparecer con redirección a `/auth/expirada` y en la bitácora de la API las peticiones de ZAP a `GET /api/v1/auth/me` dan 200.
- Rutas excluidas del escaneo activo, porque cierran la sesión, mandan correos, gastan cuota de un tercero o consultan dominios ajenos:
  - Todo `/api/v1/auth/*` menos `GET /api/v1/auth/me`, y las pantallas de login, alta y recuperar contraseña: cerrarían la sesión, cambiarían la contraseña, la MFA o las passkeys, o bloquearían la cuenta de prueba por intentos fallidos.
  - `POST /api/v1/domains/{fqdn}/scans` (lanza consultas en vivo a fuentes externas) y `POST /api/v1/domains/{fqdn}/txt/verify` (consulta DNS en vivo).
  - `POST /api/v1/domains/{fqdn}/assistant` (gasta la cuota de Groq y Workers AI).
  - Si al correrlo ya hay rutas que mandan correos (enlace de acceso de RC-63, invitaciones) o que hacen peticiones salientes (webhooks), se agregan a `excludePaths` de `plan.yaml` antes de la ventana.
- Ritmo: 2 hilos y 100 ms entre peticiones. Sin pruebas de denegación de servicio: `plan.yaml` apaga una por una las reglas 40044 (Billion Laughs), 10053 (Apache Range Header DoS), 30001 (Buffer Overflow), 30002 (Format String Error) y 30003 (Integer Overflow Error), así que no depende de qué reglas traiga la imagen. Si una versión nueva de ZAP trae otra regla de denegación de servicio, se agrega ahí.

## Al cerrar la ventana

1. Ernesto quita la regla de Skip de Cloudflare y vuelve a prender Bot Fight Mode si estaba prendido.
2. Cerrar la sesión de la cuenta de prueba en el portal, desde la misma ventana del paso 4, para que el valor de `lt_session` deje de servir. Luego borrar las variables (`Remove-Item Env:ZAP_LT_SESSION, Env:ZAP_AUTH_HEADER_VALUE -ErrorAction SilentlyContinue` en PowerShell, `unset ZAP_LT_SESSION ZAP_AUTH_HEADER_VALUE` en bash) y cerrar esa terminal. Si ya no se puede cerrar sesión con esa cookie, la sesión vence sola a los 15 minutos sin peticiones (`cirdan/auth/sessions.py`, `IDLE_SECONDS`), siempre que nadie siga usando el valor. Desactivar la cuenta (`is_active = false`) no borra su sesión en Valkey, que con uso dura hasta el tope de 8 h (`ABSOLUTE_SECONDS`): antes de darla por cerrada se revisa que el usuario no tenga sesiones vivas en Valkey, y luego se desactiva la cuenta.
3. Revisar en la base que solo cambió la organización de pruebas. Si algo más cambió, se restaura con el `pg_dump`.

## Reporte

El reporte de ZAP va en `docs/zap/reporte_zap.html` y la tabla de abajo lleva cada alerta media o alta con su estado. El Hecho cuando pide cero altas abiertas y cada media corregida o justificada.

Este resultado es evidencia de la revisión con OWASP ASVS 5.0 nivel 1 (#75): [`asvs_nivel1.md`](asvs_nivel1.md), y sus alertas medias y baja entran como hallazgos del pentest (#58b): [`pentest.md`](pentest.md). El `Cache-Control` que faltaba en `/api/v1/auth/me` se agregó ahí a toda respuesta de la API.

| Alerta | Riesgo | Dónde | Estado | Por qué |
|---|---|---|---|---|
| 10055 CSP: style-src unsafe-inline (5 URL) | Media | Portal | Justificada | React escribe atributos `style` y el widget de altcha mete su `<style>`. Un nonce no cubre atributos, y con nonce el navegador ignora `'unsafe-inline'`. Los scripts sí van solo con nonce |
| 10202 Absence of Anti-CSRF Tokens (2) | Media | Portal, `/dashboard/perfil` | Justificada | El formulario de cambio de contraseña del perfil lleva `method="post"`, pero el envío lo hace el navegador con JavaScript (`event.preventDefault()` y `fetch` con cuerpo JSON a `/api/v1/auth/*`, FrontKL `src/components/screens/perfil/ChangePasswordForm.tsx`). El POST a la página no cambia nada: el portal no usa Server Actions. La API se protege sin token: la cookie `lt_session` va con `SameSite=Lax` (`cirdan/auth/routes.py`, `set_cookie`), así que un POST desde otro sitio no la lleva, una escritura con `Origin` ajeno da 403 (`cirdan/api/main.py`, `same_origin_writes`) y cambiar la contraseña pide la actual |
| 10035 Strict-Transport-Security Header Not Set (2) | Baja | Dos fuentes `.woff2` de `_next/static/media` | Corregida | Son copias que Cloudflare guardó en caché antes de que el portal pusiera HSTS (el reporte trae `Age: 618263`, y el 23 nov la misma fuente salió en vivo con `cf-cache-status: HIT` y sin HSTS). El portal pone HSTS en todas sus rutas (`next.config.ts`, `source: "/:path*"`), y las páginas y la API lo llevan. Como esos archivos tienen nombre por hash y caché de un año, la copia vieja no se va sola: se corrige purgando la caché de Cloudflare. Ernesto la purgó el 23 nov a las 10:00 (su cierre de #51), y el 25 nov las fuentes salen con HSTS también desde la caché (`cf-cache-status: HIT`, #58b) |

Las informativas no piden arreglo. 10058 (GET for POST) es el mismo formulario del perfil mandado por GET: la página solo se pinta y no lee esos parámetros. 10024 y 10031 son los formularios de usuarios, llaves y dominios mandados por GET con datos de ZAP. Esas páginas no leen la URL, y lo que 10031 encontró en atributos son valores fijos del formulario: `90` en el atributo `max` de los días (`API_KEY_MAX_DAYS`, `ApiKeysManager.tsx`) y `analista` en un `<option value>` del rol (`UsersManager.tsx`).

Corrida del 22 nov de 2026, de 20:28 a 22:00 (hora de Monterrey), con ZAP 2.17.0 y la cuenta de prueba de la organización de pruebas con rol `admin`. La VM corría BackKL 9a8b1e6 y FrontKL 4af8e71. ZAP tuvo sesión todo el tiempo: 16 906 `GET /api/v1/auth/me` con 200 y ninguno con 401 en la bitácora de la API. Alertas por riesgo: 0 altas, 2 medias (7 casos), 1 baja (2 casos) y 7 informativas (17 casos). En la base solo cambió la organización de pruebas (un inicio de sesión en la bitácora), y la cuenta de prueba quedó desactivada al terminar.
