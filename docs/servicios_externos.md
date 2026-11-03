# Servicios externos de LowTide: cuentas, llaves, costos y plan B (#8, RC-40)

**Al 3 nov 2026.** Una fila por servicio externo que LowTide usa o va a usar, con la cuenta del equipo y su dueño, el plan, el costo, el límite, el vencimiento de la llave y el plan B. Los límites y el uso real salen del código de `cirdan/recolectores/` y de las semillas de `db/semillas/`. Las cuentas, los precios y los pagos salen de Jira: RC-37, RC-38 y RC-40, y la tarjeta de cada servicio. Lo que no está en Jira ni en el código va como **por confirmar**, con su pregunta numerada al final.

Aquí nunca va una llave, un token, una contraseña ni un código de respaldo. De cada llave solo se nombra su variable de `.env`. Si la variable todavía no existe en el código, se marca como propuesta.

## Resumen

- **Hoy el código no usa ninguna llave de un servicio externo.** Los recolectores de `REGISTRO` (`cirdan/recolectores/__init__.py`) consultan sin cuenta: crt.sh, Cert Spotter, DNS público, RDAP y WHOIS, la API pública de GitHub e InternetDB. `.env.example` solo trae variables de la base, Valkey, cookies, la llave del MFA (`TOTP_ENCRYPTION_KEY`) y las listas `DOMINIOS_EN_VIVO` y `ORGS_GITHUB_DECLARADAS`.
- **Gasto real al 3 nov: 9.08 USD**, el dominio de prueba olmardo.com, que pagó Ernesto el 13 oct. El presupuesto en efectivo del Gantt V3 es de 23.45 USD.
- **Cuello de botella de las demos:** Cert Spotter sin llave da unas 10 consultas por hora, y cada escaneo en vivo le hace unas 4 (2 de `ct_logs` y 2 de `shodan`). Con 2 o 3 escaneos en vivo se acaba el cupo de esa hora. No se ensaya en la hora anterior a una demo.

## Tabla

| Servicio | Para qué (tarjeta) | Cuenta del equipo y su dueño | Plan | Costo | Límite y uso real | Llave y su vencimiento | Plan B |
|---|---|---|---|---|---|---|---|
| crt.sh | Subdominios y certificados (#14, fuente `ct_logs`) | Ninguna: consulta anónima | Gratis | 0 | crt.sh no publica cuota. Una corrida hace a lo más 18 consultas junto con Cert Spotter (`MAX_CONSULTAS`, `crtsh.py:93`), con 3 intentos y esperas de 5 y 15 s. `ct_logs` tiene 200 consultas por día (semilla 005) | No usa llave | Cert Spotter da los subdominios y certificados vigentes. En las demos, `--reproducir` con la respuesta grabada |
| Cert Spotter (SSLMate) | Complemento y respaldo de crt.sh (#14b). `shodan.py` también lo usa para sacar nombres | Ninguna: consulta anónima | Gratis sin llave | 0 | Unas 10 consultas por hora sin llave (`certspotter.py:18-19`). Hasta 4 páginas por corrida en `ct_logs` y 2 páginas con 2 intentos en `shodan`. Un 429 no se reintenta | No usa llave. Llave de SSLMate: por decidir (pregunta 11) | crt.sh. Si ninguno responde, `ct_logs` queda en `failed` y la demo usa la grabación |
| DNS | Registros A, AAAA, MX, NS, TXT y DMARC (#15) y el TXT de verificación | Ninguna: resolvedores públicos 1.1.1.1 y 8.8.8.8 | Gratis | 0 | 5 s por consulta con sus dos resolvedores, 3 intentos y 18 consultas por corrida a lo más (`registros_dns.py:82-89`). Sin límite diario (`daily_limit` vacío) | No usa llave | El otro resolvedor. Respuestas grabadas en las demos |
| RDAP y WHOIS | Registro y vencimiento del dominio (#15b, fuente `whois`) | Ninguna: bootstrap de IANA, RDAP del registro y WHOIS por el puerto 43 | Gratis | 0 | 15 s por petición, 120 s por corrida, `Retry-After` hasta 15 s y 10 consultas por corrida a lo más (`rdap.py:115-135`). 60 consultas por día (semilla 008): 6 corridas en el peor caso | No usa llave | WHOIS por el puerto 43 si RDAP no responde. Si tampoco, el registro sale 'No disponible' y `domain_expiring_soon` queda sin cobertura |
| GitHub | Secretos y correos en los repos públicos de la organización declarada (#16) | El recolector no usa cuenta. Los repos son de la organización Kernel-Loco. Sus dueños: **por confirmar** (pregunta 2) | Gratis | 0 | API sin token: 60 consultas por hora por IP (`github.py:60`). Una corrida hace 2 consultas a la API y hasta 10 clones (`MAX_CONSULTAS` 16). 400 por día (semilla 006) | Sin token hoy. Si se agrega: `GITHUB_TOKEN` (propuesta), de grano fino, de solo lectura de repos públicos y con vencimiento explícito no antes del 15 dic | Sin cuota, un 403 o 429 deja la fuente sin cobertura, no fallida. Respuestas grabadas del 27 oct |
| InternetDB (Shodan) | Puertos y CVE de las IP del dominio (#17, fuente `shodan`) | Ninguna: consulta anónima | Gratis | 0 | No publica límite. Hasta 10 IP por corrida, 1 s entre una y otra, 10 s por petición y 3 intentos (`shodan.py:144-150`). `shodan` tiene 1840 consultas por día (semilla 011) y una corrida reserva 184 en el peor caso | No usa llave | Respuestas grabadas del 27 oct. Sin datos de una IP, sus códigos quedan sin cobertura |
| Shodan (API con llave) | `exposed_iot_device`, `exposed_ot_device` y `outdated_software`, y el escaneo bajo demanda de la IP sembrada de #10 | **Por confirmar** (pregunta 3) | Membresía o mejora académica | 49 USD, o 0 con la mejora académica (RC-37, comentario 10043). Fuera del presupuesto en efectivo | Sin llave esos 3 códigos van siempre a `sin_cobertura` (`SIN_LLAVE`, `shodan.py:131`) | `SHODAN_API_KEY` (propuesta). En Jira no consta que exista la llave | InternetDB, que no da esos 3 códigos |
| HIBP | Correos del dominio en brechas (#19, RC-54) | **Por confirmar** (pregunta 10). La búsqueda por dominio pide verificar el dominio en el panel de HIBP del equipo | El plan más bajo (Core 1), 1 mes, cancelado al cierre | 5.29 USD (RC-37, comentario 10043) | La fila `hibp` existe (semilla 001, 10 por minuto, sin guardar la respuesta cruda), pero aún no hay recolector en `REGISTRO` | `HIBP_API_KEY` (propuesta). Si se compra el 5 nov por un mes, vence hacia el 5 dic, **antes del 15 dic** (pregunta 10) | Sin llave o sin dominio verificado, el portal dice 'Sin cobertura de HIBP', nunca 0 (RC-54). En la demo, una respuesta grabada |
| Docker Hub | Imágenes base del CI y de la VM (`postgres:16.15`, `valkey/valkey:8.1.10` y `python:3.14-slim`) y la extra de contenedores públicos (#64, RC-120) | **Por confirmar** (pregunta 4) | Gratis | 0 | Hoy el CI baja las imágenes sin `docker login` (`.github/workflows/pruebas.yml`), con el límite de descargas anónimas por IP. #64 solo bajará manifiestos y configuración, nunca capas | Token de solo lectura en los secretos de GitHub Actions y en el `.env` de la VM: `DOCKERHUB_USERNAME` y `DOCKERHUB_TOKEN` (propuesta), con vencimiento no antes del 15 dic | Reintentar el CI. Cada imagen va fijada a su versión |
| Proveedor de IA | Prueba de #38b (RC-185): modelo principal y de respaldo del chatbot #38 con 20 preguntas sobre los datos demo, con el resultado anotado aquí | **Por confirmar** (pregunta 5) | **Por confirmar** | **Por confirmar** | **Por confirmar** | **Por confirmar**. Variable propuesta según el proveedor que se elija | **Por confirmar**: el modelo de respaldo que pide #38b |
| Captcha | Login (RC-5) | Ninguna: ALTCHA, autoalojado y open source | Gratis | 0 | Sin límite externo: la propia API genera y revisa el reto | Sin llave de un tercero. La llave HMAC del reto es interna y va en `.env` (`ALTCHA_HMAC_KEY`, propuesta) | No aplica: no depende de un tercero |
| Correo | Correo transaccional (#28c, RC-170). Desde el 23 oct es el camino principal para iniciar sesión (comentario 10152) | **Por confirmar** (pregunta 7) | Plan gratis por API HTTPS, porque las VM bloquean el puerto 25 de salida. Proveedor sin elegir: la tarjeta pone de ejemplo Resend o Brevo | 0 si cabe en el plan gratis | **Por confirmar**: el envío diario del plan que se elija | **Por confirmar**. Variable propuesta según el proveedor | **Por confirmar**. Se envía desde un subdominio de lowtidesec.com con SPF, DKIM y DMARC `p=quarantine` |
| VM | Despliegue (#49, RC-91) | **Por confirmar** (pregunta 1) | Azure for Students: 100 USD de crédito sin tarjeta, VM de 2 vCPU y 4 GB, con alertas de presupuesto al 50 % y 80 % (RC-91) | Unos 43 USD del crédito, no en efectivo (RC-37, comentario 10043) | El crédito de la cuenta | Sin llave de API. Token de Cloudflare solo para la zona del producto (propuesta de RC-91, comentario 10063). El acceso a la VM no va aquí | El mismo compose en una PC del equipo con Cloudflare Tunnel en lowtidesec.com, sin abrir puertos (RC-91) |
| Dominio olmardo.com | Dominio de prueba (#9, RC-38) | Spaceship y Cloudflare en la cuenta @tec.mx de Ernesto, con 2FA. Germán es segundo administrador de Cloudflare, con 2FA. Los códigos de respaldo de Spaceship los guardan Ernesto e Israel | Registro .com por 1 año. DNS en Cloudflare Free | 9.08 USD, pagó Ernesto | No aplica | Vence el 14 oct 2027 UTC, sin renovación automática (10.18 USD si se renueva) | La zona tiene dos administradores. La renovación la deciden los cuatro |
| Dominio lowtidesec.com | Dominio del producto: portal, API, correo y túnel (#96d, RC-204) | **Por confirmar** (pregunta 8) | Registro .com por 1 año. DNS en Cloudflare Free cuando se active la zona | Presupuesto de 9.08 USD, el precio de antes del 1 nov. **Sin compra registrada** en RC-40 ni en RC-204 | No aplica | **Por confirmar** | Sin él, la VM y el correo no tienen dominio propio |
| Teams Workflows | Alertas en vivo a Teams (#65, RC-114) | **Por confirmar** (pregunta 6): hay que probar que una cuenta @tec.mx puede crear el flujo | Workflows de Teams con la cuenta del Tec | 0 para el equipo | **Por confirmar** | La URL del flujo lleva su firma: va cifrada en `integrations.secret_enc`, nunca en el repo (RC-114) | **Por confirmar** |

## Otros servicios que usa el código

No están en la lista de la tarjeta, pero son de terceros y van aquí para que #52 los cuente.

| Servicio | Para qué | Cuenta | Costo | Límite | Nota |
|---|---|---|---|---|---|
| Cloudflare Free | DNS de olmardo.com y, más adelante, de lowtidesec.com | La de olmardo.com es la cuenta @tec.mx de Ernesto, con Germán como segundo administrador (RC-38, comentarios 10169 y 10178) | 0 | Plan Free | Al activar una zona, Cloudflare emite certificados que salen en crt.sh |
| Azure for Students, VM de la siembra | `camaras` y `reservas` de olmardo.com (#10, RC-42), aparte de la VM de #49 | Azure for Students de Ernesto (RC-42, comentarios 10147 y 10156) | Del crédito de esa cuenta. Cifra: **por confirmar** | El crédito de la cuenta | Dos Standard_B2ats_v2 en West US 2 |
| DB-IP Lite | País, ASN y proveedor de cada IP (`cirdan/recolectores/geoip.py`) | Ninguna | 0 | Sin cuota: se baja a mano cada mes y se usa sin red | Licencia CC BY 4.0, con atribución en `NOTICE` |
| subfinder y sus 8 fuentes | Subdominios pasivos (#14b, RC-184): `anubis`, `crtname`, `digitorus`, `hackertarget`, `rapiddns`, `subdomaincenter`, `submd` y `thc` | Ninguna: no piden llave | 0 | 400 consultas por día (semilla 005) | Sembrada apagada hasta que #8 revise los términos de las 8 fuentes (`db/semillas/005_subfinder_y_limites.sql`). **Pendiente** (pregunta 12) |
| GitHub Actions | CI de BackKL (#11) y CodeQL | Organización Kernel-Loco | 0 en repos públicos | Sin tope de minutos en repos públicos | Corre `.github/workflows/pruebas.yml` |

## Gasto real y tope (para #52)

| Concepto | Presupuesto (Gantt V3, 13 oct) | Gasto real | Quién pagó | Comprobante | Estado |
|---|---|---|---|---|---|
| olmardo.com | 9.08 USD | 9.08 USD de lista (8.88 del registro y 0.20 de cuota de ICANN). El monto cobrado es el del comprobante | Ernesto, 13 oct | `Recibo_Spaceship_olmardo_13oct.pdf`, adjunto en RC-40: recibo de PayPal con la tarjeta tapada | Pagado |
| lowtidesec.com | 9.08 USD | **Por confirmar** | **Por confirmar** | **Por confirmar** | Sin compra registrada |
| HIBP, 1 mes | 5.29 USD | 0 | **Por confirmar** | **Por confirmar** | Compra prevista la semana del 2 nov (RC-54) o el 5 nov (RC-37) |
| **Total en efectivo** | **23.45 USD** (412.72 MXN a 17.60, unos 103 MXN por persona) | **9.08 USD** | | | |
| Fuera del efectivo: VM de #49 | Unos 43 USD del crédito de Azure for Students | **Por confirmar** | | | |
| Fuera del total: llave de Shodan | 49 USD, o 0 con la mejora académica | **Por confirmar** | | | |

- El presupuesto sale de RC-37 (comentarios 10043, 10075 y 10076) y de RC-40 (comentario 10081). Los dominios defensivos no entran (RC-40, comentario 10064).
- **Tope de gasto:** el Hecho cuando pide que lo acuerden los cuatro. El Gantt V3 trae 23.45 USD, pero en Jira no consta ese acuerdo (pregunta 9).
- **Renovaciones:** ninguna está encendida. olmardo.com costaría 10.18 USD en oct 2027, y la renovación la deciden los cuatro.

## Dónde viven las llaves

- **En `.env`**, nunca en el repo ni en Jira. `.env` está fuera de git (`.gitignore:1`). Cada llave nueva entra a `.env.example` con un valor de ejemplo, como `TOTP_ENCRYPTION_KEY`.
- **Cifradas en la base, en `data_sources.api_key_enc`** (`db/migraciones/001_esquema_inicial.sql:158`), con `key_rotated_at` para la fecha de rotación. Hoy ninguna fila la usa. `cirdan_app` no puede leer esa columna (`001_esquema_inicial.sql:610-611`). Para usarla, la API necesita una función `SECURITY DEFINER`, como `reserve_source_quota()` de la migración 008, y la llave de cifrado en `.env`, como hace el MFA con AES-GCM (`cirdan/auth/totp.py:13-22`). Lo hace la tarjeta que agregue la primera llave, con su migración.
- **En el CI y en la VM**, `docker login` con un token de Docker Hub de solo lectura. Hoy el CI no hace `docker login` y la VM no existe.

## Hecho cuando, punto por punto

| Punto | Estado al 3 nov |
|---|---|
| Tabla en el repo con una fila por servicio y sus columnas | Hecho: este documento. Lo que depende de cuentas que no están en Jira va como por confirmar |
| Ninguna llave vence antes del 15 dic, y los tokens de GitHub se crean con vencimiento explícito | Hoy no hay llaves en uso. Las propuestas piden vencimiento no antes del 15 dic. La de HIBP, si se compra el 5 nov por un mes, vence hacia el 5 dic (pregunta 10) |
| El tope de gasto lo acuerdan los cuatro, y se anota quién pagó con su comprobante | Pagos: olmardo.com, con comprobante. Tope: falta el acuerdo de los cuatro (pregunta 9) |
| Llaves en variables de entorno y cifradas en `data_sources.api_key_enc` | La columna existe y nadie la usa. Queda para la primera llave |
| El CI (#11) y la VM (#49) hacen `docker login` con un token de solo lectura | Pendiente: el CI no lo hace y la VM no existe (pregunta 4) |
| El captcha de RC-5 es ALTCHA, autoalojado y open source | Decidido. Todavía no está en el código de BackKL ni de FrontKL (RC-5 sigue In Progress) |
| El 19 oct se revisa si InternetDB o Shodan muestran el servicio sembrado de #10 y, si no, se pide un escaneo bajo demanda con la llave de Shodan | No hay comentario del 19 oct. El 22 y el 27 oct InternetDB traía datos viejos de la IP de `camaras` (el puerto 50000 de su dueño anterior) y no el 8080 sembrado (RC-42, comentario 10147, y RC-49, comentarios 10188 y 10189). El 29 oct seguía igual. El escaneo bajo demanda no se pidió porque no hay llave de Shodan (pregunta 3) |
| La prueba de que una cuenta @tec.mx puede crear un flujo de Workflows de Teams (#65) | Pendiente: no consta en Jira (pregunta 6) |

## Preguntas abiertas

### Para Israel

1. **VM (#49):** ¿con qué cuenta de Azure for Students se crea la VM y de quién es? ¿Cuánto crédito le queda, qué tamaño y región lleva y cuánto cuesta al mes? ¿Ya están las alertas al 50 % y 80 %?
2. **GitHub:** ¿quiénes son dueños (owners) de la organización Kernel-Loco? ¿Creaste algún token de GitHub para el proyecto? Si sí, ¿para qué, con qué permisos y cuándo vence?
3. **Shodan:** ¿se pidió la mejora académica o se compra la membresía de 49 USD? ¿Con qué cuenta y quién paga? Sin llave no se puede pedir el escaneo bajo demanda de la IP de `camaras`.
4. **Docker Hub:** ¿el equipo tiene cuenta de Docker Hub? ¿De quién es? ¿Creas un token de solo lectura, con vencimiento no antes del 15 dic, para el CI y la VM?
5. **Proveedor de IA (#38b):** ¿cuáles son el modelo principal y el de respaldo del chatbot #38? ¿Con qué cuenta, plan y costo, cuándo vence la llave y qué dio la prueba de las 20 preguntas?
6. **Teams (#65):** ¿ya probaste que una cuenta @tec.mx puede crear un flujo de Workflows de Teams? ¿Con qué cuenta y qué salió?

### Para Germán

7. **Correo (#28c):** ¿qué proveedor elegiste, con qué cuenta y de quién es? ¿Cuántos correos al día da su plan gratis y qué hay de plan B si se acaba?
8. **lowtidesec.com (#96d):** ¿ya se compró? Si sí: ¿quién pagó, cuánto (el .com subió el 1 nov), con qué cuenta, cuándo vence y dónde está el comprobante?

### Para decidir entre los cuatro

9. **Tope de gasto:** ¿se acuerda el tope en 23.45 USD en efectivo, como el Gantt V3?
10. **HIBP:** ¿quién la compra y con qué cuenta? Comprada el 5 nov por un mes vence hacia el 5 dic, antes del 15 dic que pide el Hecho cuando. ¿Se compra el 15 nov o más tarde, o basta que dure hasta la sesión final del 4 dic?
11. **Cert Spotter:** ¿se pide una llave de SSLMate para subir el cupo por hora, o se queda sin llave con la regla de no ensayar antes de una demo?

### Para Ernesto

12. **subfinder:** revisar los términos de uso de las 8 fuentes, que pide la semilla 005 antes de encenderla. Es leer las páginas de cada fuente en vivo, así que pide OK antes.
