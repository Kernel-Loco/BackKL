# Hallazgos esperados de olmardo.com (#10b)

Esta es la lista de lo que LowTide debe encontrar en olmardo.com, el dominio de prueba del equipo (Grupo Olmardo, empresa ficticia). La usan #14 a #20 para probar su hallazgo, #47 para enseñar las 4 categorías en S12 y #84 para medir cobertura y falsos positivos.

**Revisado el 18 oct 2026 a las 19:35, a las 20:02 y a las 20:13, hora de Monterrey,** solo con DNS sobre HTTPS (dns.google) y Cert Spotter. No se hizo ninguna petición a un sitio o servicio de olmardo.com. Las consultas están en 'Cómo se revisó'.

**Actualizado el 22 oct 2026** con el estado de la zona, de las VM y de los recolectores en dev, y otra vez a las 22:45, después de poner los registros A. Ese día el DNS se consultó con nslookup contra 8.8.8.8 y 1.1.1.1, y las páginas de las VM se probaron por su IP.

## Cómo leer las tablas

- **Fuente:** el recolector que lo encuentra. La lista va en el orden de las tarjetas: #14, #15, #15b, #16, #17, #18, #19 y #20. Hoy en dev están #14 (crt.sh) y, desde el PR 17 (19 oct), #14b (Cert Spotter) dentro del mismo recolector: como respaldo y, desde RC-184 (25 oct), también en cada corrida, para sumar los certificados que crt.sh no trae. #15 tenía fecha del 21 oct y no está en dev ni hay PR. #15b llega el 23 oct, #16 y #17 el 27 oct, #18 y #19 el 6 nov y #20 el 13 nov.
- **Código:** la regla del catálogo de #30. 'Semilla 001' quiere decir que ya está en `db/semillas/001_datos_demo.sql`. 'Propuesto' quiere decir que sale de la lista de códigos para #30 y todavía no está en dev. `cert_expiring_soon` ya lo emite `cirdan/recolectores/crtsh.py`, pero falta en la semilla 001.
- **Severidad:** la base de la regla. El motor de score (#31) la puede subir.
- **Se ve desde:** la primera fecha en que la fuente lo puede ver si la siembra se hace a tiempo.
- **Hoy:** 'Existe' (o 'Existen'), 'A medias' o 'Pendiente', según la revisión del 18 oct, actualizada el 22 oct.
- **Fechas:** hora de Monterrey (UTC-6). Los vencimientos de certificados y del registro van en UTC, como los dan Cert Spotter y el registrador. La tabla de CT va toda en UTC.
- **Depende de:** lo que falta. 'VM' son las 2 VM de Azure, una para reservas y otra para camaras. Desde el 22 oct están en la suscripción Azure for Students de Ernesto, en el grupo rg-olmardo. 'Zona' es la zona de olmardo.com en Cloudflare, que administra Ernesto. 'GitHub' es la organización olmardo y 'Correo' es el correo @olmardo.com, de la siembra 2 (RC-165). Los sembró Ernesto el 23 oct.

## Lista por fuente

| # | Elemento sembrado | Fuente | Código esperado | Categoría | Severidad | Se ve desde | Hoy | Depende de |
|---|---|---|---|---|---|---|---|---|
| 1 | Certificado de reservas.olmardo.com. Let's Encrypt, emitido el 13 oct, vence el 12 ene 2027 | #14 crt.sh y #14b Cert Spotter | Ninguno. Queda como activo `subdomain` | No aplica | No aplica | 13 oct | Existe (Cert Spotter 17772119077) | Nada |
| 2 | Certificado de camaras.olmardo.com. Igual que el anterior | #14 y #14b | Ninguno. Queda como activo `subdomain` | No aplica | No aplica | 13 oct | Existe (Cert Spotter 17772281649) | Nada |
| 3 | Comodines de Cloudflare para olmardo.com y \*.olmardo.com. Let's Encrypt y SSL.com, vencen el 12 ene 2027. No son de la siembra | #14 y #14b | Ninguno. Queda como activo `domain` con `comodin` = true | No aplica | No aplica | 13 y 14 oct | Existen (Cert Spotter 17771264516 y 17778865245) | Nada |
| 4 | Efecto de esos comodines: el certificado vencido de un subdominio de primer nivel (reservas, camaras o eventos) no sale como hallazgo | #14 | Ninguno. El nombre queda con `cubierto_por_comodin` = olmardo.com | No aplica | No aplica | 31 oct, cuando vence el de eventos | Existe. Los comodines siguen vigentes hasta el 12 ene 2027 | Decisión del equipo (ver 'Pendientes') |
| 5 | Certificado de vida corta de eventos.olmardo.com. Perfil shortlived de Let's Encrypt (160 h), sin renovación automática | #14 con #14b | `cert_expiring_soon` (en crtsh.py, falta en la semilla 001) | Infraestructura | Media | Jueves 29 oct en la mañana, hasta que vence el sábado 31 oct | Programado. Lo emite sola la VM de reservas el sábado 24 oct a las 21:00, con validación HTTP, y reintenta cada 15 min hasta las 23:30. Se ensayó con el entorno de prueba de Let's Encrypt el 22 oct (DNS-01) y el 23 oct (HTTP), con perfil shortlived de 160 h, y funcionó. Esos certificados de prueba no son de confianza y ya se borraron | Nada |
| 6 | Un solo SPF en la raíz y ningún `_dmarc` | #15 DNS | `dmarc_missing` (semilla 001) | Configuración | Media | Cuando llegue #15, que no está en dev | Existe. El SPF `v=spf1 -all` está en la raíz desde el 19 oct y `_dmarc` no existe, como se quiere | #15 |
| 7 | Registro de olmardo.com, que vence el 14 oct 2027, y las IP a las que resuelven reservas y camaras | #15b RDAP e IP | Ninguno, solo activos. Registrador y vencimiento van en el activo `domain`, y hosting, ASN, país y CDN en los activos `ip`. `domain_expiring_soon` (propuesto) no sale | No aplica | No aplica | 23 oct, cuando llegue #15b | Existe. El registro existe y reservas y camaras resuelven a sus VM desde el 22 oct a las 22:29 (40.65.94.253 y 20.69.154.199) | #15b |
| 8 | Organización de GitHub olmardo con un repo público que trae un token falso `CIRDAN_FAKE_` | #16 GitHub | `secret_in_public_repo` (propuesto), sobre olmardo.com | Fugas | Crítica | Al subir el token. #16 llega el 27 oct | Existe desde el 23 oct: el repo público olmardo/sitio-reservas trae `RESERVAS_API_TOKEN=CIRDAN_FAKE_...` en `config/despliegue.env`, en la versión actual. El README dice que es inventado. La organización no tiene el dominio verificado: no existe `_gh-olmardo-o.olmardo.com` | #16 |
| 9 | Commits en ese repo con un correo @olmardo.com como autor | #16 | `email_in_public_commits` (propuesto), sobre el activo `email` | Identidad digital | Baja | Igual que la fila 8 | Existe desde el 23 oct: los 2 commits de olmardo/sitio-reservas tienen como autor 'Grupo Olmardo <contacto@olmardo.com>' | #16 |
| 10 | Página de cámara IP en el puerto 8080 de una VM, en camaras.olmardo.com | #17 InternetDB | `exposed_service` (propuesto), sobre `<IP>:8080/tcp` | Infraestructura | Baja | Cuando Shodan escanee la IP. #17 llega el 27 oct | A medias. Desde el 22 oct camaras.olmardo.com resuelve a su VM (20.69.154.199), que sirve la página en el 8080 y solo abre ese puerto. InternetDB, 22 oct: solo datos viejos de quien tuvo esa IP antes (puerto 50000) | Que Shodan la escanee |
| 11 | La misma cámara, vista con la API de host de Shodan o con su respuesta grabada | #17 con la llave de #8 | `exposed_iot_device` (propuesto), sobre la IP | Infraestructura | Alta | Igual que la fila 10, si hay llave | Pendiente | Llave de Shodan (#8) |
| 12 | Sitio de pruebas en reservas.olmardo.com en 'Solo DNS', con cabecera Server con versión y una página que dice que es de pruebas | #18 tecnologías web | `server_version_disclosed` (propuesto), sobre reservas.olmardo.com | Configuración | Baja | Al publicar el sitio. #18 llega el 6 nov | Existe. Desde el 22 oct reservas.olmardo.com resuelve a su VM (40.65.94.253), que sirve en el 80 una página que dice que es de pruebas, con `Server: nginx/1.24.0 (Ubuntu)` | #18 |
| 13 | Correos @olmardo.com, como el de los commits (fila 9). El dominio se registró el 13 oct (14 oct en UTC), así que sus correos no deben estar en brechas | #19 Have I Been Pwned | Ninguno. Sin llave, la fuente queda en `failed` con `sin_llave`. Con llave y sin brechas, queda en `succeeded` con 0 hallazgos | No aplica | No aplica | 6 nov, cuando llegue #19. La llave se compra la semana del 2 nov | Pendiente. #19 no está en dev. El correo contacto@olmardo.com ya existe en el sitio y en los commits, pero no recibe mensajes porque no hay MX | La llave de #19 |
| 14 | Correo de contacto en el sitio | #20 identidad pasiva | Ninguno si es un buzón @olmardo.com, que queda como activo `email`. `personal_email_exposed` (propuesto) solo si es un correo gratuito, como uno de gmail.com, ligado a la empresa | Identidad digital | Media, solo en ese caso | Al publicar el sitio. #20 llega el 13 nov | Existe desde el 23 oct: reservas.olmardo.com muestra contacto@olmardo.com, un buzón del dominio, así que no da `personal_email_exposed`. No hay MX, así que no recibe mensajes | #20 |
| 15 | Enlace del sitio a un perfil público | #20 | Ninguno. El perfil es un activo de identidad. Da `personal_email_exposed` solo si muestra un correo personal | Identidad digital | Media, solo en ese caso | Al publicar el sitio. #20 llega el 13 nov | Existe desde el 23 oct: reservas.olmardo.com enlaza a github.com/olmardo, la página de la organización. No hay persona ficticia | #20 |

Notas por fila:

- **Fila 5:** la regla de #14 pide menos de 30 días y menos de un tercio de vida (53 h). Si se emite entre las 20:00 y las 23:59 del 24 oct, sale 'por vencer' desde el 29 oct entre las 05:40 y las 09:39, y vence el 31 oct entre las 11:00 y las 14:59, hora de Monterrey. Así sale en la grabación del jueves 29 a mediodía y en vivo en S12, el viernes 30. Desde el 23 oct eventos tiene un registro A a la VM de reservas (40.65.94.253), para que el certificado se valide por HTTP sin poner un TXT a mano. No da hallazgo: es un subdominio más en la IP de reservas. Ningún otro certificado debe llevar ese nombre, porque uno que vence después tapa el 'por vencer'.
- **Fila 6:** si el correo @olmardo.com tiene que recibir mensajes, por ejemplo para verificarlo en GitHub, Email Routing de Cloudflare crea los MX y su propio SPF. Ese debe ser el único SPF. Dos registros `v=spf1` cuentan como `spf_missing`.
- **Fila 7:** #15b no da hallazgo en olmardo.com, porque faltan más de 30 días para que venza el registro. `domain_expiring_soon` se prueba con una respuesta grabada (#13). Si una IP sale como CDN de Cloudflare, el registro quedó con proxy y #17 y #18 la descartan.
- **Fila 8:** el token sale como crítico esté en la versión actual o solo en el historial. #16 guarda tipo, repo, ruta y huella, nunca el valor.
- **Filas 10 y 11:** InternetDB solo muestra el puerto cuando Shodan escanea la IP, y eso puede tardar días. Hay que levantar la VM cuanto antes y consultar su IP en InternetDB ese día, como pide #10. Los puertos 80 y 443 no dan hallazgo.
- **Fila 12:** con una versión al día solo debe salir `server_version_disclosed`. Con una versión sin soporte también saldría `outdated_software` (alta) y quizá `known_vulnerability` (media).
- **Fila 13:** sin llave, el portal dice 'Sin cobertura de HIBP', nunca 0. Con llave, #19 usa la búsqueda por dominio si olmardo.com está verificado en Have I Been Pwned. Si no, consulta el correo de la fila 9. Si no hay correo que consultar, la fuente queda en `failed` con `sin_cobertura`.
- **Filas 14 y 15:** #20 lee el perfil una sola vez y sin iniciar sesión. Si la red pide sesión, solo guarda el enlace y deja un aviso. Por la regla del 12 oct no se crea una persona ficticia.

## Las 4 categorías desde el 30 oct

| Categoría | Hallazgo esperado | Fila | Hoy |
|---|---|---|---|
| Infraestructura | `cert_expiring_soon` de eventos (del 29 al 31 oct) y `exposed_service` del 8080 | 5 y 10 | Pendientes. La cámara ya resuelve y responde en el 8080. Falta que Shodan la vea y el certificado del 24 oct |
| Configuración | `dmarc_missing` | 6 | La condición ya se cumple. Falta #15, que no está en dev |
| Identidad digital | `email_in_public_commits` | 9 | Sembrado el 23 oct. Falta #16 |
| Fugas | `secret_in_public_repo` | 8 | Sembrado el 23 oct. Falta #16 |

**Score esperado:** con el token falso abierto hay un hallazgo crítico vigente. Por la regla de piso de [`criterio_criticidad.md`](criterio_criticidad.md), el score de olmardo.com queda por lo menos en 60, la banda Alto. Grupo Olmardo tiene umbral 60 en `db/semillas/002_dominio_prueba.sql`, así que también sale la alerta `score.above_threshold`.

## Lo que no debe salir

Si alguno de estos sale en olmardo.com, #84 lo cuenta como posible falso positivo.

| Código | Por qué no debe salir |
|---|---|
| `spf_missing` | Ya hay un solo SPF, `v=spf1 -all`, desde el 19 oct. Si se prende Email Routing para el correo (filas 9, 13 y 14), ese SPF se reemplaza por el de Email Routing, porque dos `v=spf1` dan `spf_missing` |
| `spf_allow_all` | El SPF sembrado debe terminar en `~all` o en `-all`. Solo sale con `+all` o con `all` sin calificador. Con `?all` saldría `spf_missing` |
| `dmarc_policy_none` | No hay `_dmarc` |
| `cert_expired` | Todos los certificados están vigentes. El de eventos, ya vencido, queda cubierto por el comodín (fila 4) |
| `cert_expiring_soon` en reservas, camaras o olmardo.com | Les quedan más de 30 días hasta el 13 dic 2026 en UTC, después de S16. Cloudflare renueva solo sus comodines |
| `lookalike_domain` | El equipo no registró ninguna variante de olmardo.com. Si sale una, es de un tercero y no viene de la siembra. Por la [política de uso ético](politica_uso_etico.md) ese dominio no se revisa, porque no tiene carta. Queda solo como evidencia. Solo crt.sh cubre este código, porque Cert Spotter no busca por contenido. Desde el PR 27 (20 oct) el orquestador no busca parecidos, así que en un escaneo normal `lookalike_domain` queda en `sin_cobertura`: cobertura parcial, no 0. #84 no lo cuenta como acierto |
| `domain_expiring_soon` | El registro de olmardo.com vence el 14 oct 2027 (fila 7) |
| `breach_exposure` y sus variantes | El dominio es nuevo y sus correos no están en brechas. Sin llave de Have I Been Pwned la fuente queda en `failed` con `sin_llave`, no en 0 (fila 13) |
| `email_pattern_exposed` | Pide al menos 3 correos de personas distintas con el mismo formato. Solo se siembran el correo de los commits y el del sitio, y los buzones genéricos, como contacto, no cuentan |
| `outdated_software` y `known_vulnerability` | Si el Server del sitio y la cámara usan versiones al día (fila 12) |
| `exposed_service` en el puerto 22 | Azure abre SSH por defecto. Las 2 VM se crearon el 22 oct con el 22 cerrado y se administran con `az vm run-command` |
| `exposed_rdp`, `exposed_remote_admin`, `exposed_file_sharing`, `exposed_database` y `exposed_ot_device` | La VM de la cámara solo abre el 8080 y la de reservas solo el 80, que no da hallazgo |

## Certificados en los registros públicos (CT)

Las fechas son las de Cert Spotter, en UTC. Let's Encrypt atrasa una hora el inicio, así que los de reservas y camaras se emitieron el 13 oct en la noche, hora de Monterrey. El de eventos se emite de 02:00 a 05:59 UTC del 25 oct, así que su inicio queda de 01:00 a 04:59 y vence 160 h después.

| Nombres | Emisor | Cert Spotter | Desde (UTC) | Vence (UTC) | Origen | Qué da |
|---|---|---|---|---|---|---|
| olmardo.com, \*.olmardo.com | Let's Encrypt YE2 | 17771264516 | 14 oct 2026 00:04 | 12 ene 2027 00:04 | Universal SSL de Cloudflare | Activo `domain` |
| reservas.olmardo.com | Let's Encrypt YE2 | 17772119077 | 14 oct 2026 01:10 | 12 ene 2027 01:10 | Siembra de #10 (DNS-01) | Activo `subdomain` |
| camaras.olmardo.com | Let's Encrypt YE1 | 17772281649 | 14 oct 2026 01:23 | 12 ene 2027 01:23 | Siembra de #10 (DNS-01) | Activo `subdomain` |
| olmardo.com, \*.olmardo.com | SSL.com (Cloudflare TLS Issuing ECC CA 4) | 17778865245 | 14 oct 2026 10:24 | 12 ene 2027 01:00 | Universal SSL de Cloudflare | Activo `domain` |
| eventos.olmardo.com | Let's Encrypt, perfil shortlived | Pendiente | 25 oct 2026, de 01:00 a 04:59 | 31 oct 2026, de 17:00 a 20:59 | Siembra de #10 | `cert_expiring_soon` del 29 al 31 oct |

## Subdominios e IP

La IP es la que da el DNS. Si sale una IP de Cloudflare, el registro quedó con proxy y #17 y #18 lo descartan como CDN. Reservas y camaras van en VM distintas, así que dan IP distintas.

| Nombre | Para qué | Registro esperado | IP a la que resuelve | Hoy (dns.google) |
|---|---|---|---|---|
| olmardo.com | Raíz | TXT de verificación de #9, un SPF y ningún A. Si el correo recibe mensajes, también los MX de Email Routing | Ninguna | NS de Cloudflare, el TXT de verificación y el SPF `v=spf1 -all` (desde el 19 oct). Sin A, sin AAAA y sin MX |
| reservas.olmardo.com | Sitio de pruebas (#10b) | A en 'Solo DNS' | 40.65.94.253, la VM de reservas | Resuelve desde el 22 oct a las 22:29. El TXT `_acme-challenge` del 13 oct se borró el 19 oct |
| camaras.olmardo.com | Cámara IP en el 8080 (#10), en una VM aparte de la de #49 | A en 'Solo DNS' | 20.69.154.199, la VM de camaras | Resuelve desde el 22 oct a las 22:29. El TXT `_acme-challenge` del 13 oct se borró el 19 oct |
| eventos.olmardo.com | El certificado de vida corta | A en 'Solo DNS', para validar el certificado por HTTP | 40.65.94.253, la VM de reservas | Resuelve desde el 23 oct a las 06:31 |
| \_dmarc.olmardo.com | Debe faltar | Ninguno | No aplica | No existe, como se quiere |

## Pendientes

- **Vencido visible:** mientras \*.olmardo.com esté vigente, ningún certificado vencido de primer nivel sale como hallazgo. Para enseñar uno hay dos caminos: ponerlo en un nombre de segundo nivel que resuelva, como x.eventos.olmardo.com, o cambiar la regla de #14. Lo deciden #10, #30 y #14.
- **Catálogo (#30):** los códigos marcados 'propuesto' y `cert_expiring_soon` tienen que entrar al catálogo antes de que sus recolectores lleguen a dev.
- **Registros de prueba borrados:** el 22 oct se borraron los A de cam, sub1 y sub2, que apuntaban a IP de documentación (203.0.113.10 a 203.0.113.12) y no eran de la siembra. La zona queda con camaras, reservas, el SPF y el TXT de verificación.

## Cómo se revisó

Solo se consultaron nombres de olmardo.com. No se consultó ninguna variante del nombre.

```bash
curl -s "https://dns.google/resolve?name=olmardo.com&type=NS"
curl -s "https://dns.google/resolve?name=olmardo.com&type=TXT"
curl -s "https://dns.google/resolve?name=olmardo.com&type=A"
curl -s "https://dns.google/resolve?name=olmardo.com&type=AAAA"
curl -s "https://dns.google/resolve?name=olmardo.com&type=MX"
curl -s "https://dns.google/resolve?name=_dmarc.olmardo.com&type=TXT"
curl -s "https://dns.google/resolve?name=reservas.olmardo.com&type=A"
curl -s "https://dns.google/resolve?name=camaras.olmardo.com&type=A"
curl -s "https://dns.google/resolve?name=eventos.olmardo.com&type=A"
curl -s "https://dns.google/resolve?name=_acme-challenge.reservas.olmardo.com&type=TXT"
curl -s "https://dns.google/resolve?name=_acme-challenge.camaras.olmardo.com&type=TXT"
curl -s "https://dns.google/resolve?name=_gh-olmardo-o.olmardo.com&type=TXT"
curl -s "https://api.certspotter.com/v1/issuances?domain=olmardo.com&include_subdomains=true&expand=dns_names&expand=issuer"
```

En dns.google, `Status` 3 quiere decir que el nombre no existe. `Status` 0 sin `Answer` quiere decir que el nombre existe pero no tiene registros de ese tipo. El SPF se busca en la respuesta TXT de la raíz. GitHub no pone su TXT de verificación en la raíz. Lo pone en `_gh-<org>-o.olmardo.com`, por eso esa consulta va aparte. Se agregó en la revisión de las 20:13.
