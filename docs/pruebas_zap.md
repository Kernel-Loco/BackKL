# Pruebas de seguridad web con ZAP (RC-89, #51)

ZAP en modo de escaneo activo completo contra el producto final en la VM, por `https://lowtidesec.com`, con una cuenta de prueba autenticada. Es la única prueba activa que este documento permite. Las reglas generales están en `docs/politica_uso_etico.md` (sección de pruebas activas) y en `docs/despliegue.md` (por qué no va por `pruebas.lowtidesec.com` ni por SSH).

## Cabeceras que el escaneo debe encontrar

| Cabecera | Portal (páginas) | API (`/api/v1/*` a través del portal) |
|---|---|---|
| `Content-Security-Policy` | Con nonce nuevo en cada página, `script-src 'self' 'nonce-…' 'strict-dynamic'` y `frame-ancestors 'none'` (FrontKL `src/lib/csp.ts`, la pone `src/proxy.ts`) | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` (`cirdan/api/main.py`). El reporte en HTML y `/demo` llevan la suya, también con `frame-ancestors 'none'` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (FrontKL `next.config.ts`) | Igual (`cirdan/api/main.py`) |
| `X-Frame-Options` | `DENY` | `DENY` |
| `X-Content-Type-Options` | `nosniff` | `nosniff` |
| `Referrer-Policy` | `no-referrer` | `no-referrer` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), usb=()` | Igual |

HSTS va sin `preload` (decisión del 22 nov): hstspreload.org acepta el dominio de quien lo inscriba y salir de la lista tarda meses. Cloudflare no pone HSTS: lo ponen el portal y la API, que quedan en git con sus pruebas.

## Lo que pone Ernesto antes de la ventana

1. Una organización de pruebas con una cuenta de prueba (rol `admin`, para que ZAP vea las pantallas de administración). Nunca las cuentas de demo, las de Grupo Olmardo ni `equipo@lowtidesec.com`. La organización no tiene dominios de clientes: el escaneo no debe crear escaneos de terceros.
2. `pg_dump` de la VM justo antes de empezar, y la ventana lejos del 27 nov (versión congelada y sesión S16).
3. En Cloudflare, durante la ventana, una regla temporal de Skip para la IP desde donde corre ZAP, y Bot Fight Mode apagado si está prendido (la regla no lo salta en el plan gratis). Sin eso el reporte mezcla los bloqueos de Cloudflare con LowTide.
4. La sesión de ZAP. El valor de la cookie no se escribe en archivos, en el reporte ni en el historial de la terminal:
   1. Ernesto entra con la cuenta de prueba en una ventana normal del navegador, no privada (contraseña y MFA son suyas), y copia el valor de la cookie `lt_session` desde las herramientas de desarrollo (Application o Almacenamiento, Cookies).
   2. Cierra la pestaña sin cerrar sesión. Cerrar sesión invalida la cookie en el servidor y ZAP se quedaría sin sesión. La ventana es normal para poder cerrar sesión al final con esa misma cookie.
   3. En la terminal donde corre ZAP la pega en un prompt sin eco, que no queda en el historial (en PowerShell, `Read-Host` no guarda lo que se escribe, y la línea del comando no lleva el valor):

      ```powershell
      $s = Read-Host -AsSecureString 'lt_session'; $env:ZAP_LT_SESSION = [System.Net.NetworkCredential]::new('', $s).Password; Remove-Variable s
      ```

      En bash: `read -rs ZAP_LT_SESSION && export ZAP_LT_SESSION`. Nunca `$env:ZAP_LT_SESSION = '…'` ni `export ZAP_LT_SESSION=…` con el valor escrito: ese sí queda en el historial.
   4. `docker run -e ZAP_LT_SESSION` (sin `=valor`) toma la variable de esa misma terminal. En otra terminal no existe y ZAP correría sin sesión.

## Cómo se corre

Imagen `ghcr.io/zaproxy/zaproxy:stable` con el plan de `docs/zap/plan.yaml` (Automation Framework):

```
docker run --rm -e ZAP_LT_SESSION -v "$PWD/docs/zap:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap.sh -cmd -autorun /zap/wrk/plan.yaml
```

- Contexto: `https://lowtidesec.com` con todo lo que cuelga de ahí. Fuera de alcance cualquier otro host (Cloudflare `cdn-cgi`, `altcha.org`).
- Sesión: dos reglas del Replacer ponen `Cookie: lt_session=${ZAP_LT_SESSION}` y `Origin: https://lowtidesec.com` en cada petición a `https://lowtidesec.com`, y solo ahí (campo `url` de cada regla): la cookie no sale hacia otros hosts. La API rechaza los POST con otro Origin, y sin la cookie ZAP no tendría sesión.
- Rutas excluidas del escaneo activo, porque cierran la sesión, mandan correos, gastan cuota de un tercero o consultan dominios ajenos:
  - Todo `/api/v1/auth/*` menos `GET /api/v1/auth/me`, y las pantallas de login, alta y recuperar contraseña: cerrarían la sesión, cambiarían la contraseña, la MFA o las passkeys, o bloquearían la cuenta de prueba por intentos fallidos.
  - `POST /api/v1/domains/{fqdn}/scans` (lanza consultas en vivo a fuentes externas) y `POST /api/v1/domains/{fqdn}/txt/verify` (consulta DNS en vivo).
  - `POST /api/v1/domains/{fqdn}/assistant` (gasta la cuota de Groq y Workers AI).
  - Si al correrlo ya hay rutas que mandan correos (enlace de acceso de RC-63, invitaciones) o que hacen peticiones salientes (webhooks), se agregan a `excludePaths` de `plan.yaml` antes de la ventana.
- Ritmo: 2 hilos y 100 ms entre peticiones. Sin pruebas de denegación de servicio: `plan.yaml` apaga una por una las reglas 40044 (Billion Laughs), 10053 (Apache Range Header DoS), 30001 (Buffer Overflow), 30002 (Format String Error) y 30003 (Integer Overflow Error), así que no depende de qué reglas traiga la imagen. Si una versión nueva de ZAP trae otra regla de denegación de servicio, se agrega ahí.

## Al cerrar la ventana

1. Ernesto quita la regla de Skip de Cloudflare y vuelve a prender Bot Fight Mode si estaba prendido.
2. Cerrar la sesión de la cuenta de prueba en el portal, desde la misma ventana del paso 4, para que el valor de `lt_session` deje de servir. Luego borrar la variable (`Remove-Item Env:ZAP_LT_SESSION` en PowerShell, `unset ZAP_LT_SESSION` en bash) y cerrar esa terminal.
3. Revisar en la base que solo cambió la organización de pruebas. Si algo más cambió, se restaura con el `pg_dump`.

## Reporte

El reporte de ZAP va en `docs/zap/reporte_zap.html` y la tabla de abajo lleva cada alerta media o alta con su estado. El Hecho cuando pide cero altas abiertas y cada media corregida o justificada.

| Alerta | Riesgo | Dónde | Estado | Por qué |
|---|---|---|---|---|
| CSP: style-src unsafe-inline (esperada) | Media | Portal | Justificada | React escribe atributos `style` y el widget de altcha mete su `<style>`. Un nonce no cubre atributos, y con nonce el navegador ignora `'unsafe-inline'`. Los scripts sí van solo con nonce |

Fecha de la corrida, versión de ZAP, commit de BackKL y FrontKL en la VM y número de alertas por riesgo: pendiente hasta correrlo.
