# Hallazgos esperados de olmardo.com (#10b)

Esta es la lista de lo que LowTide debe encontrar en olmardo.com, el dominio de prueba del equipo (Grupo Olmardo, empresa ficticia). La usan #14 a #20 para probar su hallazgo, #47 para enseñar las 4 categorías en S12 y #84 para medir cobertura y falsos positivos.

**Revisado el 18 oct 2026 a las 19:35, hora de Monterrey,** solo con DNS sobre HTTPS (dns.google) y Cert Spotter. No se hizo ninguna petición a un sitio o servicio de olmardo.com.

## Cómo leer las tablas

- **Fuente:** el recolector que lo encuentra. Hoy solo #14 (crt.sh) está en dev. #14b (Cert Spotter) está en el PR 17. #15 vence el 21 oct, #15b el 23 oct, #16 y #17 el 27 oct, #18 el 6 nov y #20 el 13 nov.
- **Código:** la regla del catálogo de #30. 'Semilla 001' quiere decir que ya está en `db/semillas/001_datos_demo.sql`. 'Propuesto' quiere decir que sale de la lista de códigos para #30 y todavía no está en dev. `cert_expiring_soon` ya lo emite `cirdan/recolectores/crtsh.py`, pero falta en la semilla 001.
- **Severidad:** la base de la regla. El motor de score (#31) la puede subir.
- **Se ve desde:** la primera fecha en que la fuente lo puede ver si la siembra se hace a tiempo.
- **Hoy:** 'Existe' o 'Pendiente', según la revisión del 18 oct.
- **Depende de:** lo que falta de @GermanMZtec. 'VM' es la máquina virtual de Azure, 'GitHub' es la organización olmardo y 'Correo' es el correo @olmardo.com. 'Zona' es el acceso a la zona de olmardo.com en Cloudflare.

## Lista por fuente

| # | Elemento sembrado | Fuente | Código esperado | Categoría | Severidad | Se ve desde | Hoy | Depende de |
|---|---|---|---|---|---|---|---|---|
| 1 | Certificado de reservas.olmardo.com. Let's Encrypt, emitido el 13 oct, vence el 12 ene 2027 | #14 crt.sh y #14b Cert Spotter | Ninguno. Queda como activo `subdomain` | No aplica | No aplica | 13 oct | Existe (Cert Spotter 17772119077) | Nada |
| 2 | Certificado de camaras.olmardo.com. Igual que el anterior | #14 y #14b | Ninguno. Queda como activo `subdomain` | No aplica | No aplica | 13 oct | Existe (Cert Spotter 17772281649) | Nada |
| 3 | Comodines de Cloudflare para olmardo.com y \*.olmardo.com. Let's Encrypt y SSL.com, vencen el 12 ene 2027. No son de la siembra | #14 y #14b | Ninguno. Queda como activo `domain` con `comodin` = true | No aplica | No aplica | 13 y 14 oct | Existen (Cert Spotter 17771264516 y 17778865245) | Nada |
| 4 | Efecto de esos comodines: el certificado vencido de un subdominio de primer nivel (reservas, camaras o eventos) no sale como hallazgo | #14 | Ninguno. El nombre queda con `cubierto_por_comodin` = olmardo.com | No aplica | No aplica | 31 oct, cuando vence el de eventos | Existe. Los comodines siguen vigentes hasta el 12 ene 2027 | Decisión del equipo (ver 'Pendientes') |
| 5 | Certificado de vida corta de eventos.olmardo.com. Perfil shortlived de Let's Encrypt (160 h), sin renovación automática | #14, y #14b si crt.sh falla | `cert_expiring_soon` (en crtsh.py, falta en la semilla 001) | Infraestructura | Media | Jueves 29 oct en la mañana, hasta que vence el sábado 31 oct | Pendiente. Se emite el sábado 24 oct de 20:00 a 23:59. Hoy eventos no existe en DNS ni en CT | Zona |
| 6 | Un solo SPF en la raíz y ningún `_dmarc` | #15 DNS | `dmarc_missing` (semilla 001) | Configuración | Media | 21 oct, cuando llegue #15 | A medias. `_dmarc` no existe, como se quiere. El SPF todavía falta | Zona |
| 7 | Página de cámara IP en el puerto 8080 de una VM, en camaras.olmardo.com | #17 InternetDB | `exposed_service` (propuesto), sobre `<IP>:8080/tcp` | Infraestructura | Baja | Cuando Shodan escanee la IP. #17 llega el 27 oct | Pendiente. camaras no resuelve, así que no apunta a ninguna VM | VM |
| 8 | La misma cámara, vista con la API de host de Shodan o con su respuesta grabada | #17 con la llave de #8 | `exposed_iot_device` (propuesto), sobre la IP | Infraestructura | Alta | Igual que la fila 7, si hay llave | Pendiente | VM y llave de Shodan (#8) |
| 9 | Organización de GitHub olmardo con un repo público que trae un token falso `CIRDAN_FAKE_` | #16 GitHub | `secret_in_public_repo` (propuesto), sobre olmardo.com | Fugas | Crítica | Al subir el token. #16 llega el 27 oct | Pendiente. No se revisó GitHub. En DNS no hay TXT de verificación de dominio de GitHub | GitHub |
| 10 | Commits en ese repo con un correo @olmardo.com como autor | #16 | `email_in_public_commits` (propuesto), sobre el activo `email` | Identidad digital | Baja | Igual que la fila 9 | Pendiente | GitHub y Correo |
| 11 | Sitio de pruebas en reservas.olmardo.com en 'Solo DNS', con cabecera Server con versión y una página que dice que es de pruebas | #18 tecnologías web | `server_version_disclosed` (propuesto), sobre reservas.olmardo.com | Configuración | Baja | Al publicar el sitio. #18 llega el 6 nov | Pendiente. reservas no resuelve | VM |
| 12 | Correo de contacto en el sitio | #20 identidad pasiva | Ninguno si es un buzón @olmardo.com, que queda como activo `email`. `personal_email_exposed` (propuesto) solo si es un correo gratuito, como uno de gmail.com, ligado a la empresa | Identidad digital | Media, solo en ese caso | Al publicar el sitio. #20 llega el 13 nov | Pendiente. No hay sitio ni MX | Correo y VM |
| 13 | Enlace del sitio a un perfil público | #20 | Ninguno. El perfil es un activo de identidad. Da `personal_email_exposed` solo si muestra un correo personal | Identidad digital | Media, solo en ese caso | Al publicar el sitio. #20 llega el 13 nov | Pendiente | VM, y GitHub si el perfil es la página de la organización |

Notas por fila:

- **Fila 5:** la regla de #14 pide menos de 30 días y menos de un tercio de vida (53 h). Si se emite entre las 20:00 y las 23:59 del 24 oct, sale 'por vencer' desde el 29 oct entre las 05:40 y las 10:40, y vence el 31 oct entre las 11:00 y las 16:00, hora de Monterrey. Así sale en la grabación del jueves 29 a mediodía y en vivo en S12, el viernes 30. eventos no necesita registro A para esto, solo el TXT `_acme-challenge.eventos` del DNS-01. Ningún otro certificado debe llevar ese nombre, porque uno que vence después tapa el 'por vencer'.
- **Fila 6:** si el correo @olmardo.com tiene que recibir mensajes, por ejemplo para verificarlo en GitHub, Email Routing de Cloudflare crea los MX y su propio SPF. Ese debe ser el único SPF. Dos registros `v=spf1` cuentan como `spf_missing`.
- **Filas 7 y 8:** InternetDB solo muestra el puerto cuando Shodan escanea la IP, y eso puede tardar días. Hay que levantar la VM cuanto antes y consultar su IP en InternetDB ese día, como pide #10. Los puertos 80 y 443 no dan hallazgo.
- **Fila 9:** el token sale como crítico esté en la versión actual o solo en el historial. #16 guarda tipo, repo, ruta y huella, nunca el valor.
- **Fila 11:** con una versión al día solo debe salir `server_version_disclosed`. Con una versión sin soporte también saldría `outdated_software` (alta) y quizá `known_vulnerability` (media).
- **Filas 12 y 13:** #20 lee el perfil una sola vez y sin iniciar sesión. Si la red pide sesión, solo guarda el enlace y deja un aviso. Por la regla del 12 oct no se crea una persona ficticia.

## Las 4 categorías desde el 30 oct

| Categoría | Hallazgo esperado | Fila | Hoy |
|---|---|---|---|
| Infraestructura | `cert_expiring_soon` de eventos (del 29 al 31 oct) y `exposed_service` del 8080 | 5 y 7 | Pendientes |
| Configuración | `dmarc_missing` | 6 | La condición ya se cumple. Falta #15 |
| Identidad digital | `email_in_public_commits` | 10 | Pendiente |
| Fugas | `secret_in_public_repo` | 9 | Pendiente |

**Score esperado:** con el token falso abierto hay un hallazgo crítico vigente. Por la regla de piso de [`criterio_criticidad.md`](criterio_criticidad.md), el score de olmardo.com queda por lo menos en 60, la banda Alto. Grupo Olmardo tiene umbral 60 en `db/semillas/002_dominio_prueba.sql`, así que también sale la alerta `score.above_threshold`.

## Lo que no debe salir

Si alguno de estos sale en olmardo.com, #84 lo cuenta como posible falso positivo.

| Código | Por qué no debe salir |
|---|---|
| `spf_missing` | Después de sembrar el SPF. Hoy sí sale, porque no hay SPF |
| `dmarc_policy_none` | No hay `_dmarc` |
| `cert_expired` | Todos los certificados están vigentes. El de eventos, ya vencido, queda cubierto por el comodín (fila 4) |
| `cert_expiring_soon` en reservas, camaras o olmardo.com | Les quedan más de 30 días hasta el 13 dic 2026, después de S16. Cloudflare renueva solo sus comodines |
| `lookalike_domain` | Olmardo es un nombre inventado que estaba libre el 12 oct. Solo crt.sh lo cubre, porque Cert Spotter no busca por contenido |
| `domain_expiring_soon` | El registro de olmardo.com vence el 14 oct 2027 |
| `breach_exposure` y sus variantes | El dominio es nuevo y sus correos no están en brechas. Sin llave de Have I Been Pwned la fuente queda en `failed` con `sin_llave`, no en 0 |
| `outdated_software` y `known_vulnerability` | Si el Server del sitio y la cámara usan versiones al día (fila 11) |
| `exposed_service` en el puerto 22 | Azure abre SSH por defecto. Si el 22 queda abierto a internet sale otro `exposed_service`. Hay que limitarlo a la IP del equipo o cerrarlo |
| `exposed_rdp`, `exposed_remote_admin`, `exposed_file_sharing`, `exposed_database` y `exposed_ot_device` | La VM solo debe tener abierto el 8080 |

## Certificados en los registros públicos (CT)

Las fechas son las de Cert Spotter, en UTC. Let's Encrypt atrasa una hora el inicio, así que los de reservas y camaras se emitieron el 13 oct en la noche, hora de Monterrey.

| Nombres | Emisor | Cert Spotter | Desde (UTC) | Vence (UTC) | Origen | Qué da |
|---|---|---|---|---|---|---|
| olmardo.com, \*.olmardo.com | Let's Encrypt YE2 | 17771264516 | 14 oct 2026 00:04 | 12 ene 2027 00:04 | Universal SSL de Cloudflare | Activo `domain` |
| reservas.olmardo.com | Let's Encrypt YE2 | 17772119077 | 14 oct 2026 01:10 | 12 ene 2027 01:10 | Siembra de #10 (DNS-01) | Activo `subdomain` |
| camaras.olmardo.com | Let's Encrypt YE1 | 17772281649 | 14 oct 2026 01:23 | 12 ene 2027 01:23 | Siembra de #10 (DNS-01) | Activo `subdomain` |
| olmardo.com, \*.olmardo.com | SSL.com (Cloudflare TLS Issuing ECC CA 4) | 17778865245 | 14 oct 2026 10:24 | 12 ene 2027 01:00 | Universal SSL de Cloudflare | Activo `domain` |
| eventos.olmardo.com | Let's Encrypt, perfil shortlived | Pendiente | Se emite el 25 oct 2026, de 02:00 a 05:59 | 31 oct 2026, de 17:00 a 22:00 | Siembra de #10 | `cert_expiring_soon` del 29 al 31 oct |

Total TLS de Cloudflare debe seguir apagado, porque emite certificados por nombre para los registros con proxy.

## Subdominios e IP

La IP es la que da el DNS. Si sale una IP de Cloudflare, el registro quedó con proxy y #17 y #18 lo descartan como CDN.

| Nombre | Para qué | Registro esperado | IP a la que resuelve | Hoy (dns.google) |
|---|---|---|---|---|
| olmardo.com | Raíz | TXT de verificación de #9, un SPF y ningún A | Ninguna | NS de Cloudflare y el TXT de verificación. Sin A, sin MX y sin SPF |
| reservas.olmardo.com | Sitio de pruebas (#10b) | A en 'Solo DNS' | Por llenar con la IP de la VM | No resuelve. Solo queda el TXT `_acme-challenge` del 13 oct |
| camaras.olmardo.com | Cámara IP en el 8080 (#10), en una VM aparte de la de #49 | A en 'Solo DNS' | Por llenar con la IP de la VM | No resuelve. Solo queda el TXT `_acme-challenge` del 13 oct |
| eventos.olmardo.com | Solo el certificado de vida corta | Ninguno, salvo el TXT `_acme-challenge.eventos` al emitir | Ninguna | No existe |
| \_dmarc.olmardo.com | Debe faltar | Ninguno | No aplica | No existe, como se quiere |

## Pendientes

- **Vencido visible:** mientras \*.olmardo.com esté vigente, ningún certificado vencido de primer nivel sale como hallazgo. Para enseñar uno hay dos caminos: ponerlo en un nombre de segundo nivel que resuelva, como x.eventos.olmardo.com, o cambiar la regla de #14. Lo deciden #10, #30 y #14.
- **Catálogo (#30):** los códigos marcados 'propuesto' y `cert_expiring_soon` tienen que entrar al catálogo antes de que sus recolectores lleguen a dev.
- **Limpieza:** borrar los dos TXT `_acme-challenge` de reservas y camaras que quedaron del 13 oct. No son hallazgo.
- **Al sembrar:** llenar la columna de IP de esta lista y comentar en RC-165 lo sembrado, con horas e IP.

## Cómo se revisó

```bash
curl -s "https://dns.google/resolve?name=olmardo.com&type=TXT"
curl -s "https://dns.google/resolve?name=_dmarc.olmardo.com&type=TXT"
curl -s "https://dns.google/resolve?name=reservas.olmardo.com&type=A"
curl -s "https://api.certspotter.com/v1/issuances?domain=olmardo.com&include_subdomains=true&expand=dns_names&expand=issuer"
```

En dns.google, `Status` 3 quiere decir que el nombre no existe. `Status` 0 sin `Answer` quiere decir que el nombre existe pero no tiene registros de ese tipo.
