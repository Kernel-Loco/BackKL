# LowTide revisado con OWASP ASVS 5.0 nivel 1 (#75, RC-136)

«Practicamos lo que predicamos»: los 70 requisitos de nivel 1 de OWASP ASVS 5.0.0, cada uno marcado **Cumple**,
**No cumple** o **No aplica**, con su evidencia. Cada «No cumple» lleva su riesgo y su arreglo, y cada «No aplica» su
porqué. La versión pública, sin rutas ni detalles de las fallas abiertas, está en `https://lowtidesec.com/seguridad/asvs`
(`FrontKL/src/config/asvs.ts`). Las dos se cambian juntas.

## Alcance y versión

- **Qué se revisó:** el producto que corre en `https://lowtidesec.com` (portal FrontKL, API BackKL, PostgreSQL y
  Valkey detrás de Cloudflare Tunnel, `docs/despliegue.md`). No entra la pila de respaldo (`pruebas.lowtidesec.com`).
- **Código revisado:** `dev` del 23 nov 2026, BackKL `ef34063` y FrontKL `fd64ea2`. El escaneo de ZAP corrió el 22 nov
  contra la VM con BackKL `9a8b1e6` y FrontKL `4af8e71`.
- **Lista de requisitos:** [`asvs/asvs_5.0.0_nivel1.json`](asvs/asvs_5.0.0_nivel1.json), el extracto del JSON oficial
  de OWASP con su sha256. `pruebas/test_asvs.py` revisa que estén los 70, cada uno una sola vez.
- **Evidencia válida:**
  - **CI**: una prueba que corre en `.github/workflows/pruebas.yml`, o Trivy, Dependabot y CodeQL (#12);
  - **ZAP**: el escaneo activo del 22 nov (#51), en [`pruebas_zap.md`](pruebas_zap.md) y `zap/reporte_zap.html`;
  - **Código** o **configuración**: con su ruta;
  - **En vivo**: comprobado contra `lowtidesec.com` el 23 nov, con el comando a la vista.
- **Actualización del 27 nov 2026:** V7.4.2 pasa a «Cumple» con la baja y el cambio de rol de RC-259 (BackKL PR 309) y la
  cuenta releída en cada petición, y V7.2.4 con la sesión anterior cerrada al entrar. Las dos llegan con esta tarjeta.
  V12.1.1 se volvió a probar en vivo ese día y sigue igual. La página pública responde en `https://lowtidesec.com`.
- **Revisó:** GermanMZtec. Revisa los estados Ernesto en el PR.

## Resumen

| Capítulo | Requisitos | Cumple | No cumple | No aplica |
|---|---|---|---|---|
| V1 Codificación y saneamiento | 8 | 7 | 0 | 1 |
| V2 Validación y lógica de negocio | 4 | 4 | 0 | 0 |
| V3 Seguridad del frontend web | 8 | 7 | 1 | 0 |
| V4 API y servicios web | 2 | 1 | 0 | 1 |
| V5 Manejo de archivos | 4 | 4 | 0 | 0 |
| V6 Autenticación | 13 | 13 | 0 | 0 |
| V7 Manejo de sesiones | 6 | 6 | 0 | 0 |
| V8 Autorización | 4 | 4 | 0 | 0 |
| V9 Tokens autocontenidos | 4 | 0 | 0 | 4 |
| V10 OAuth y OIDC | 5 | 0 | 0 | 5 |
| V11 Criptografía | 3 | 3 | 0 | 0 |
| V12 Comunicación segura | 3 | 2 | 1 | 0 |
| V13 Configuración | 1 | 1 | 0 | 0 |
| V14 Protección de datos | 2 | 2 | 0 | 0 |
| V15 Código y arquitectura seguros | 3 | 3 | 0 | 0 |
| V16 Bitácora y errores | 0 | 0 | 0 | 0 |
| V17 WebRTC | 0 | 0 | 0 | 0 |
| **Total** | **70** | **57** | **2** | **11** |

Ningún «No cumple» deja leer datos de otra empresa ni entrar sin contraseña. Los dos, con su arreglo, están en
[Pendientes](#pendientes).

## Requisitos

| ID | Requisito | Estado | Evidencia | Riesgo y arreglo o justificación | Texto público |
|---|---|---|---|---|---|
| V1.2.1 | Codificar la salida según su contexto (HTML, atributos, cabeceras) | Cumple | Código: el portal pinta con React, que escapa todo texto, y ningún componente usa `dangerouslySetInnerHTML` (lo revisan `FrontKL/src/lib/asistente.test.mjs` y `FrontKL/src/lib/inventario.test.mjs`). El reporte HTML escapa cada valor con `html.escape` (`cirdan/reporte.py`). La API solo responde JSON | — | El portal y los reportes escapan todo lo que muestran. |
| V1.2.2 | Codificar los datos en URLs dinámicas y permitir solo protocolos seguros | Cumple | Código: los enlaces del portal con datos usan `encodeURIComponent` (`FrontKL/src/components/screens/activos/AssetsInventory.tsx`). Los enlaces externos salen de configuración fija, nunca de datos del cliente. Los enlaces de los correos los arma la API con `PORTAL_URL` (`cirdan/auth/routes.py`) | — | Los enlaces se arman codificando cada dato y nunca con protocolos peligrosos. |
| V1.2.3 | Escapar al construir JavaScript o JSON dinámico | Cumple | Código: la API arma el JSON con el serializador de FastAPI y el portal con `JSON.stringify`. No hay scripts armados con texto | — | El JSON siempre lo arma una librería, nunca concatenando texto. |
| V1.2.4 | Consultas parametrizadas contra inyección en la base | Cumple | Código: psycopg con parámetros (`%s`) en toda consulta. Los nombres dinámicos de `/demo` usan `psycopg.sql` (`cirdan/api/explorer.py`). CI: CodeQL de GitHub en cada PR (`docs/politica_seguridad_privacidad.md`, control 8.8) | — | Todas las consultas a la base van parametrizadas. |
| V1.2.5 | Proteger contra inyección de comandos del sistema | Cumple | Código: los únicos programas externos, `git` y `gitleaks`, se llaman con `subprocess` y una lista de argumentos, sin `shell=True` ni `os.system` (`cirdan/recolectores/github.py`, `cirdan/recolectores/gitleaks_reglas.py`) | — | Los programas externos se llaman sin pasar por una consola. |
| V1.3.1 | Sanear el HTML de editores WYSIWYG | No aplica | — | LowTide no acepta HTML de nadie: no hay editor enriquecido y todo campo de texto se guarda y se muestra como texto. | No aplica: LowTide no acepta HTML de los usuarios. |
| V1.3.2 | No usar `eval()` ni ejecución dinámica de código | Cumple | Código: no hay `eval`, `exec` ni `new Function` en la API ni en el portal. Los `eval` de `cirdan/auth/sessions.py` son scripts Lua fijos de Valkey, sin datos del usuario en el código | — | No se ejecuta código armado con datos de los usuarios. |
| V1.5.1 | Parsers XML sin entidades externas (XXE) | Cumple | Código: la evidencia XML de Mifiel se revisa con expat y se rechaza cualquier DOCTYPE o declaración de entidad (`_xml_bien_formado` en `cirdan/api/firmas.py`). No hay otro parser XML | — | El único XML que se lee rechaza DTD y entidades externas. |
| V2.1.1 | Documentar las reglas de validación de la entrada | Cumple | Configuración: `docs/contrato_api_v1.md` documenta cada campo de entrada (formato, largo, valores permitidos) y los errores 400 y 422. Los modelos de Pydantic de `cirdan/auth/routes.py` y `cirdan/api/v1.py` llevan los mismos límites | — | Las reglas de cada dato de entrada están documentadas. |
| V2.2.1 | Validar la entrada contra lo esperado (listas permitidas, rangos) | Cumple | Código: Pydantic con largo y tipo en cada cuerpo; el alta de dominio valida FQDN, fechas, actividades del 1 al 11 y el PDF (`_datos_alta` en `cirdan/api/v1.py`). CI: `pruebas/test_alta_dominio.py`, `pruebas/test_api_v1.py` | — | La API valida cada dato que recibe con reglas de lo permitido. |
| V2.2.2 | Validar en el servidor, no solo en el cliente | Cumple | Código: toda regla del portal (largo de contraseña, correo, campos) también la revisa la API. CI: `pruebas/test_auth.py` y `pruebas/test_contrasenas_comunes.py` llaman a la API sin pasar por el portal | — | Cada validación se repite en el servidor. |
| V2.3.1 | Flujos de varios pasos en orden y sin saltarse pasos | Cumple | Código: el código MFA necesita el `mfa_token` de un login correcto (5 min, 5 intentos); el alta de TOTP y de passkeys exige su paso 1 en la misma sesión; un dominio no se escanea sin carta vigente ni TXT verificado, lo que también exige un trigger de la base (`cirdan/auth/sessions.py`, `cirdan/orquestador/`). CI: `pruebas/test_auth.py`, `pruebas/test_alta_totp.py`, `pruebas/test_passkeys.py`, `pruebas/test_orquestador.py` | — | Los pasos del inicio de sesión y del alta de dominios no se pueden saltar. |
| V3.2.1 | Evitar que el navegador interprete una respuesta fuera de contexto | Cumple | Código: toda respuesta de la API lleva `Content-Security-Policy: default-src 'none'` y `nosniff` (`cirdan/api/main.py`); las descargas van con `Content-Disposition: attachment` (`cirdan/api/v1.py`). CI: `pruebas/test_api.py` (prueba 8). ZAP sin alertas de tipo de contenido | — | Las respuestas de la API y las descargas no se pueden abrir como página. |
| V3.2.2 | Mostrar texto como texto, no como HTML | Cumple | Código: React pinta todo como texto y no se usa `dangerouslySetInnerHTML` ni `innerHTML`. CI: `FrontKL/src/lib/asistente.test.mjs` lo revisa en el panel del asistente | — | Lo que escribe un usuario siempre se muestra como texto. |
| V3.3.1 | Cookies con `Secure` y prefijo `__Host-` o `__Secure-` | No cumple | Código: `lt_session` lleva `Secure` (la API no arranca sin `COOKIE_SECURE=true` con un origen https, `cirdan/auth/deps.py`, `pruebas/test_cookie_segura.py`), `HttpOnly` y `SameSite=Lax`, pero no tiene prefijo | Riesgo bajo: sin el prefijo, un subdominio comprometido podría plantar una cookie con el mismo nombre. Con HSTS en subdominios y `Secure`, no hay un subdominio propio que lo permita hoy. Arreglo: renombrar a `__Host-lt_session` en la API y el portal, y cerrar las sesiones abiertas al desplegar. Toca la sesión, así que va en su propia tarjeta con revisión | En corrección: la cookie de sesión ya es segura y solo para el sitio; falta darle el prefijo que lo garantiza en el navegador. |
| V3.4.1 | HSTS de al menos un año en todas las respuestas | Cumple | Código: `max-age=31536000; includeSubDomains` en la API (`cirdan/api/main.py`) y en el portal (`FrontKL/next.config.ts`). CI: `pruebas/test_api.py`. ZAP: verificado en vivo el 23 nov; la baja 10035 eran dos fuentes viejas en caché de Cloudflare, ya purgadas | — | Todo el sitio obliga al navegador a usar HTTPS durante un año. |
| V3.4.2 | CORS con un origen fijo o validado | Cumple | Código: la API no pone `Access-Control-Allow-Origin` en ninguna respuesta (no hay `CORSMiddleware` en `cirdan/api/main.py`), y el navegador la llama por el mismo origen del portal | — | Ningún otro sitio puede leer las respuestas de la API. |
| V3.5.1 | Proteger contra CSRF las peticiones que no pasan por preflight | Cumple | Código: cookie `SameSite=Lax` y toda escritura con un `Origin` que no está en `ALLOWED_ORIGINS` responde 403 (`same_origin_writes` en `cirdan/api/main.py`). CI: `pruebas/test_api.py` (prueba 8). ZAP: la media 10202 quedó justificada por estas dos defensas (`docs/pruebas_zap.md`) | — | Las acciones solo se aceptan desde el propio portal. |
| V3.5.2 | Que no se pueda llamar sin preflight a lo que depende de él | Cumple | Código: no se depende del preflight. Además, FastAPI solo lee como JSON un cuerpo con `Content-Type: application/json`, así que un formulario HTML de otro sitio da 422 | — | No hace falta el preflight de CORS: el origen se revisa siempre. |
| V3.5.3 | Las acciones sensibles no usan métodos seguros como GET | Cumple | Código: toda escritura es POST, PUT, PATCH o DELETE (`cirdan/api/v1.py`, `cirdan/auth/routes.py`). Las GET solo leen; las descargas dejan su registro en la bitácora. El GET `/auth/expirada` del portal solo borra la cookie del navegador que lo visita | — | Ninguna acción que cambia datos se hace con un simple enlace. |
| V4.1.1 | `Content-Type` correcto, con charset en los tipos de texto | Cumple | Código: la API responde `application/json` (que no lleva charset, RFC 8259); CSV, HTML y NDJSON van con `charset=utf-8` (`cirdan/api/v1.py`). En vivo: `curl -sD - https://lowtidesec.com/api/v1/auth/me` | — | Cada respuesta declara su tipo y su codificación. |
| V4.4.1 | WebSocket solo sobre TLS | No aplica | — | LowTide no usa WebSocket: el portal habla con la API por HTTPS. | No aplica: LowTide no usa WebSocket. |
| V5.2.1 | Aceptar solo archivos de un tamaño que se pueda procesar | Cumple | Código: la carta en PDF tiene un tope de 5 MB (`MAX_CARTA` en `cirdan/api/v1.py`) y todo cuerpo un tope global con 413 (`TopeDeCuerpo` en `cirdan/api/main.py`). CI: `pruebas/test_alta_dominio.py`, `pruebas/test_tope_cuerpo.py` | — | Los archivos que se suben tienen un tamaño máximo. |
| V5.2.2 | Revisar que la extensión y el contenido correspondan | Cumple | Código: la carta debe empezar con `%PDF-` y terminar con `%%EOF`; la evidencia de Mifiel debe ser XML bien formado (`cirdan/api/v1.py`, `cirdan/api/firmas.py`). CI: `pruebas/test_alta_dominio.py`, `pruebas/test_firma.py` | — | Se revisa que cada archivo sea de verdad del tipo que dice. |
| V5.3.1 | Archivos subidos nunca se ejecutan en el servidor | Cumple | Código: las cartas se guardan cifradas con AES-256-GCM en un volumen privado, fuera de cualquier carpeta pública, y nunca se sirven directo (`cirdan/cartas.py`) | — | Los archivos subidos se guardan cifrados y nunca se ejecutan. |
| V5.3.2 | Rutas de archivos con nombres internos, no del usuario | Cumple | Código: el nombre de cada carta es un UUID al azar y se abre con `O_EXCL` y `O_NOFOLLOW` (`cirdan/cartas.py`). El nombre del archivo del usuario no se usa | — | Los archivos se guardan con nombres que genera LowTide. |
| V6.1.1 | Documentar los controles contra fuerza bruta y relleno de credenciales | Cumple | Configuración: `README.md`, sección «Inicio de sesión»: captcha ALTCHA, bloqueo con 5 fallos por correo o 20 por IP en 15 min, tope del cambio de contraseña y cómo se evita el bloqueo malicioso (contadores aparte del login) | — | Los límites contra ataques de contraseñas están documentados. |
| V6.2.1 | Contraseñas de al menos 8 caracteres (se recomiendan 15) | Cumple | Código: mínimo 12 y máximo 128 en la API (`MIN_LENGTH` en `cirdan/auth/passwords.py`) y en el portal (`FrontKL/src/lib/validation.ts`). CI: `pruebas/test_auth.py` | — | Las contraseñas tienen al menos 12 caracteres. |
| V6.2.2 | Se puede cambiar la contraseña | Cumple | Código: `POST /api/v1/auth/password` (`cirdan/auth/routes.py`) y la pantalla Mi perfil. CI: `pruebas/test_auth.py` | — | Cada persona puede cambiar su contraseña desde su perfil. |
| V6.2.3 | El cambio pide la contraseña actual y la nueva | Cumple | Código: `PasswordIn` exige `current_password` y `new_password`, con 5 intentos por usuario en 15 min (`cirdan/auth/routes.py`). CI: `pruebas/test_auth.py` | — | Para cambiarla se pide la contraseña actual. |
| V6.2.4 | Revisar las nuevas contra las 3000 más comunes | Cumple | Código: 46 146 contraseñas comunes de SecLists, sin importar mayúsculas, en el cambio y en la recuperación (`revisar_nueva` en `cirdan/auth/passwords.py`). CI: `pruebas/test_contrasenas_comunes.py`, `pruebas/test_recuperar.py` | — | Se rechazan las contraseñas comunes. |
| V6.2.5 | Sin reglas de composición (mayúsculas, números, símbolos) | Cumple | Código: la API y el portal solo revisan el largo (`cirdan/auth/passwords.py`, `FrontKL/src/lib/validation.ts`) | — | Cualquier combinación de caracteres es válida. |
| V6.2.6 | Campos de contraseña con `type=password` | Cumple | Código: los formularios de login, recuperación, cambio, MFA y passkeys usan `type="password"` (`FrontKL/src/components/auth/forms/LoginForm.tsx`, `FrontKL/src/components/screens/perfil/ChangePasswordForm.tsx`) | — | Las contraseñas se escriben ocultas. |
| V6.2.7 | Permitir pegar y los gestores de contraseñas | Cumple | Código: ningún campo de contraseña bloquea el pegado, y todos llevan `autoComplete="current-password"` o `"new-password"` para los gestores. CI: `FrontKL/src/lib/loginLink.test.mjs` | — | Funcionan el pegado y los gestores de contraseñas. |
| V6.2.8 | Verificar la contraseña tal cual, sin recortar ni cambiar mayúsculas | Cumple | Código: argon2id verifica la cadena completa; ni la API ni el portal recortan espacios ni pasan a minúsculas, y más de 128 caracteres da un error, no un recorte (`cirdan/auth/routes.py`, `FrontKL/src/lib/validation.ts`) | — | La contraseña se revisa exactamente como se escribió. |
| V6.3.1 | Controles contra fuerza bruta según la documentación | Cumple | Código: `cirdan/auth/sessions.py` y `cirdan/auth/captcha.py`. CI: `pruebas/test_auth.py`, `pruebas/test_bloqueo_ip.py`, `pruebas/test_captcha.py`. ZAP: 16 906 peticiones con sesión sin bloquear la cuenta | — | Hay captcha y bloqueo por intentos fallidos. |
| V6.3.2 | Sin cuentas por omisión como `admin` o `root` | Cumple | Código: no hay cuentas por omisión. Las de demo quedan apagadas fuera de una PC de desarrollo: sin `DEMO_ACCOUNTS=true`, o con un origen publicado, `cirdan/auth/demo.py` les quita la contraseña y el MFA. CI: `pruebas/test_demo_cuentas.py`; `docker-compose.despliegue.yml` fija `DEMO_ACCOUNTS=false` | — | No existen cuentas con nombres o contraseñas por omisión. |
| V6.4.1 | Contraseñas iniciales o códigos de activación al azar, de un uso y que vencen | Cumple | Código: LowTide no genera contraseñas iniciales. Una cuenta nueva no tiene contraseña usable y la pone su dueño con el enlace de recuperación: token de 256 bits (`secrets.token_urlsafe(32)`), un solo uso y 30 min (`RESET_SECONDS` en `cirdan/auth/sessions.py`). CI: `pruebas/test_recuperar.py` | — | No hay contraseñas iniciales: cada persona pone la suya con un enlace de un solo uso. |
| V6.4.2 | Sin pistas ni preguntas secretas | Cumple | Código: no existen en la API ni en el portal | — | No hay pistas ni preguntas secretas. |
| V7.2.1 | La sesión se verifica en un servicio confiable del servidor | Cumple | Código: cada petición busca la sesión en Valkey (`current_session` en `cirdan/auth/deps.py`); el portal no decide nada por su cuenta | — | Cada sesión se revisa en el servidor en cada petición. |
| V7.2.2 | Tokens de sesión dinámicos, no secretos fijos | Cumple | Código: un token nuevo por inicio de sesión (`sessions.create` en `cirdan/auth/sessions.py`). Las llaves de API son aparte, para sistemas, y se pueden revocar (`cirdan/auth/api_keys.py`) | — | Cada inicio de sesión crea un token nuevo. |
| V7.2.3 | Tokens de referencia únicos, de un CSPRNG y con 128 bits o más | Cumple | Código: `secrets.token_urlsafe(32)`, 256 bits; Valkey guarda solo su SHA-256 (`cirdan/auth/sessions.py`) | — | El token de sesión tiene 256 bits al azar y no se guarda en claro. |
| V7.2.4 | Token nuevo al autenticarse, y se termina el anterior | Cumple | Código: cada login, código MFA, enlace o passkey crea un token nuevo y, antes, borra de Valkey la sesión de la cookie que trae la petición (`_start_session` en `cirdan/auth/routes.py`, desde el 27 nov, #75). Así no hay fijación de sesión y el token anterior del mismo navegador deja de servir. CI: `pruebas/test_auth.py` (prueba 5b: al volver a entrar, el token viejo da 401) | — | Cada inicio de sesión crea un token nuevo y cierra en el servidor la sesión anterior del mismo navegador. |
| V7.4.1 | Al cerrar sesión o vencer, la sesión ya no sirve | Cumple | Código: el logout borra la sesión en Valkey y la cookie, aunque falle la bitácora; vence a los 15 min sin uso y a las 8 h (`cirdan/auth/routes.py`, `cirdan/auth/sessions.py`). CI: `pruebas/test_auth.py` (prueba 5), `pruebas/test_login_sin_red.py` | — | Al cerrar sesión, o a los 15 minutos sin uso, la sesión deja de servir en el servidor. |
| V7.4.2 | Al desactivar o borrar una cuenta, se cierran todas sus sesiones | Cumple | Código: la baja y el cambio de rol del Admin (`PATCH /api/v1/users/{id}`, RC-259) y la cancelación al terminar el servicio (`cirdan/fin_servicio.py`, RC-258) cierran todas las sesiones del índice `sess-user:` (`cerrar_sesiones` en `cirdan/auth/cuentas.py`). Además, `current_session` relee la cuenta en cada petición (`cuenta_vigente` en `cirdan/auth/deps.py`, desde el 27 nov, #75): si ya no está activa, se borró o cambió de rol fuera de la API, la sesión se cierra en esa petición. CI: `pruebas/test_usuarios_admin.py` (pruebas 2, 3 y 6) y `pruebas/test_fin_servicio.py` | — | Al dar de baja una cuenta o cambiarle el rol, todas sus sesiones abiertas se cierran de inmediato. |
| V8.1.1 | Documentar las reglas de acceso por función y por dato | Cumple | Configuración: `docs/contrato_api_v1.md` dice qué rol usa cada ruta y que cada empresa solo ve lo suyo (RLS); los permisos del portal están en `FrontKL/src/config/permissions.ts` | — | Está documentado qué puede hacer cada rol y qué datos ve cada empresa. |
| V8.2.1 | Acceso a funciones solo con permiso explícito | Cumple | Código: `require_roles` y `api_key_or_roles` (`cirdan/auth/deps.py`); el gerente recibe 403 en hallazgos y comparaciones (RC-280). CI: `pruebas/test_api_v1.py`, `pruebas/test_superadmin.py`, `pruebas/test_llaves_api.py` | — | Cada función revisa el rol antes de responder. |
| V8.2.2 | Acceso a datos solo con permiso sobre cada dato (IDOR, BOLA) | Cumple | Código: seguridad por fila (RLS) forzada en la base; la API entra con un rol sin `BYPASSRLS` y la empresa sale de la sesión, nunca de un encabezado (`db/migraciones/001_esquema_inicial.sql`, `cirdan/db.py`). CI: `pruebas/test_aislamiento.py` revisa toda tabla con `organization_id` | — | La base de datos aísla a cada empresa: nadie ve datos de otra. |
| V8.3.1 | Autorizar en el servidor, no en el cliente | Cumple | Código: el rol y la empresa se revisan en la API y en la base; lo que oculta el portal también lo niega la API (RC-280). CI: `pruebas/test_api_v1.py` | — | Los permisos se revisan en el servidor, no solo en la pantalla. |
| V9.1.1 | Validar la firma o el MAC de los tokens autocontenidos | No aplica | — | LowTide no usa tokens autocontenidos (JWT ni otros): la sesión, el paso del MFA y los enlaces son tokens opacos que se buscan en Valkey. | No aplica: LowTide no usa tokens tipo JWT. |
| V9.1.2 | Solo algoritmos de una lista permitida para esos tokens | No aplica | — | Igual que V9.1.1: no hay tokens autocontenidos. | No aplica: LowTide no usa tokens tipo JWT. |
| V9.1.3 | Llaves de esos tokens solo de fuentes confiables | No aplica | — | Igual que V9.1.1: no hay tokens autocontenidos. | No aplica: LowTide no usa tokens tipo JWT. |
| V9.2.1 | Respetar la vigencia (`nbf`, `exp`) de esos tokens | No aplica | — | Igual que V9.1.1. La vigencia de los tokens opacos la pone Valkey (`cirdan/auth/sessions.py`). | No aplica: LowTide no usa tokens tipo JWT. |
| V10.4.1 | El servidor OAuth valida las redirect URI exactas | No aplica | — | LowTide no es un servidor de autorización OAuth ni usa OAuth u OIDC para entrar. Las passkeys son WebAuthn, otra cosa. | No aplica: LowTide no usa OAuth. |
| V10.4.2 | Código de autorización de un solo uso | No aplica | — | Igual que V10.4.1: LowTide no emite ni usa códigos ni tokens de OAuth. | No aplica: LowTide no usa OAuth. |
| V10.4.3 | Código de autorización de vida corta | No aplica | — | Igual que V10.4.1: LowTide no emite ni usa códigos ni tokens de OAuth. | No aplica: LowTide no usa OAuth. |
| V10.4.4 | Solo los grants que cada cliente necesita | No aplica | — | Igual que V10.4.1: LowTide no emite ni usa códigos ni tokens de OAuth. | No aplica: LowTide no usa OAuth. |
| V10.4.5 | Contra la repetición de refresh tokens | No aplica | — | Igual que V10.4.1: LowTide no emite ni usa códigos ni tokens de OAuth. | No aplica: LowTide no usa OAuth. |
| V11.3.1 | Sin modos de bloque inseguros (ECB) ni rellenos débiles | Cumple | Código: todo cifrado es AES-256-GCM (`cirdan/auth/passwords.py`, `cirdan/cartas.py`, `cirdan/auth/totp.py`) | — | Los datos se cifran con AES-256-GCM. |
| V11.3.2 | Solo cifrados aprobados, como AES-GCM | Cumple | Código: AES-256-GCM con `cryptography` y nonce de 96 bits al azar en cada cifrado | — | Solo se usan cifrados aprobados. |
| V11.4.1 | Solo funciones hash aprobadas; nunca MD5 con fines criptográficos | Cumple | Código: argon2id para contraseñas, SHA-256 para tokens y la cadena de la bitácora, HMAC-SHA256 en el captcha. SHA-1 solo aparece donde el protocolo de otro lo fija: el rango de Pwned Passwords y el `shasum` de npm junto a su SHA-512 (`cirdan/auth/passwords.py`, `cirdan/recolectores/huellas.py`). MD5 solo en las migraciones, para ver si un texto cambió, sin fin criptográfico | — | Contraseñas con argon2id y tokens con SHA-256; ningún hash débil protege datos. |
| V12.1.1 | Solo TLS 1.2 y 1.3, con 1.3 de preferencia | No cumple | En vivo, 23 nov y de nuevo el 27 nov: `openssl s_client -connect lowtidesec.com:443 -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0'` conecta con TLS 1.1, y con `-tls1` con TLS 1.0. Sin forzar la versión, negocia TLS 1.3. El TLS lo termina Cloudflare | Riesgo bajo: un navegador moderno nunca baja a 1.0 o 1.1, pero un cliente viejo sí podría y esas versiones tienen fallas conocidas. Arreglo: en Cloudflare, SSL/TLS > Edge Certificates > Minimum TLS Version = TLS 1.2. Lo hace Ernesto; el paso ya está en `docs/despliegue.md` con la comprobación | En corrección: el sitio prefiere TLS 1.3; falta apagar en el borde las versiones viejas 1.0 y 1.1. |
| V12.2.1 | TLS en toda conexión con servicios externos, sin bajar a HTTP | Cumple | Configuración: «Always Use HTTPS» y HSTS en Cloudflare (`docs/despliegue.md`). En vivo: `curl -sI http://lowtidesec.com/login` responde 301 a `https://`. Los servicios HTTP de terceros que llama la API van solo por `https://`; las consultas DNS y WHOIS de los recolectores no son servicios HTTP y van sin cifrar por su protocolo (control 8.24 de `docs/politica_seguridad_privacidad.md`) | — | Todo el tráfico va por HTTPS. |
| V12.2.2 | Certificados de confianza pública | Cumple | En vivo, 23 nov: el certificado de `lowtidesec.com` es de Let's Encrypt y vence el 6 feb 2027 | — | El sitio usa un certificado de una autoridad pública. |
| V13.4.1 | Desplegar sin metadatos de control de versiones (`.git`) | Cumple | Configuración: `.dockerignore` deja fuera `.git` en BackKL y FrontKL. En vivo, 23 nov: `/.git/HEAD` y `/.git/config` responden 404 | — | El despliegue no lleva archivos del repositorio. |
| V14.2.1 | Datos sensibles solo en el cuerpo o en cabeceras, nunca en la URL | Cumple | Código: la sesión va en una cookie, las llaves de API en `Authorization: Bearer` (`cirdan/auth/api_keys.py`) y los tokens de los enlaces del correo después de `#` (`/login/enlace#t=`, `/forgot-password/reset#t=`), que el navegador no manda al servidor (`cirdan/auth/routes.py`) | — | Ningún token ni llave viaja en la URL. |
| V14.3.1 | Borrar del cliente los datos de la sesión al terminarla | Cumple | Código: al cerrar sesión el portal recarga la página por `/auth/expirada`, que borra la cookie aunque la API esté caída, y no queda nada de la sesión en el DOM (`FrontKL/src/lib/session/logout.ts`). El `mfa_token` vive solo en la memoria de la pestaña (`FrontKL/src/lib/flowStorage.ts`); en `localStorage` solo queda el tema claro u oscuro | — | Al cerrar sesión, el navegador no conserva datos de la cuenta. |
| V15.1.1 | Documentar plazos, según el riesgo, para corregir componentes vulnerables | Cumple | Configuración: control 8.8 de `docs/politica_seguridad_privacidad.md`: crítica antes de desplegar, alta 7 días, media 30, baja en la siguiente actualización; el resto en 7 días (objetivo 3). Los plazos por severidad se agregaron en esta revisión; los confirma Ernesto en el PR | — | Hay plazos escritos para corregir librerías con vulnerabilidades, según su gravedad. |
| V15.2.1 | Ningún componente fuera de esos plazos | Cumple | CI: Trivy frena una imagen con críticas (`.github/workflows/imagenes.yml`), Dependabot cada semana (`.github/dependabot.yml`), `npm audit` en FrontKL. Medición del 17 nov: 0 alertas abiertas de Dependabot y CodeQL, y ningún PR de Dependabot de más de 7 días (objetivos 2 y 3 de la política) | — | Las librerías se revisan cada semana y no hay vulnerabilidades abiertas fuera de plazo. |
| V15.3.1 | Devolver solo los campos necesarios | Cumple | Código: cada ruta elige sus columnas en el SQL; `/auth/me` nunca trae la huella ni el secreto TOTP, las llaves de API nunca traen la llave y las passkeys nunca la llave pública (`cirdan/auth/routes.py`, `cirdan/api/llaves.py`). El contrato con ejemplos está en `docs/api_v1/` y lo revisa `pruebas/test_contrato_api.py` | — | La API solo devuelve los campos que cada pantalla necesita. |

## Extras de nivel 2 que ya se cumplen

| ID | Requisito | Evidencia |
|---|---|---|
| V6.2.12 | Revisar las contraseñas nuevas contra las filtradas | Pwned Passwords con k-anonimato en el cambio y la recuperación (RC-334, BackKL PR 236). `pruebas/test_contrasenas_filtradas.py` y la prueba en vivo del 20 nov en la VM |
| V3.4.1 (nivel 2) | HSTS también en los subdominios | `includeSubDomains` en la API y el portal |
| V3.4.3 (nivel 2) | CSP con `object-src 'none'` y `base-uri 'none'` | CSP con nonce del portal (`FrontKL/src/lib/csp.ts`) y `default-src 'none'` en la API, verificadas en vivo por ZAP el 23 nov |

Además, desde esta revisión toda respuesta de la API lleva `Cache-Control: no-store`, salvo la que ya traiga el suyo
(`cirdan/api/main.py`, `pruebas/test_api.py`, pruebas 8 y 9). Cierra lo que había quedado abierto en ZAP:
`/api/v1/auth/me` sin `Cache-Control`.

## Pendientes

| Requisito | Riesgo | Arreglo | Quién | Tarjeta |
|---|---|---|---|---|
| V12.1.1 solo TLS 1.2 y 1.3 | Bajo | Cloudflare: Minimum TLS Version = TLS 1.2, y comprobar con `openssl` | Ernesto | Sin tarjeta: es un ajuste |
| V3.3.1 prefijo de la cookie | Bajo | `__Host-lt_session` en la API y el portal | Por asignar | Propuesta |

Cuando se arregle uno, su fila pasa a «Cumple» con la evidencia nueva, aquí y en `FrontKL/src/config/asvs.ts`, y
sale de esta tabla.
