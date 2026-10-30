# Contrato de plugin de los recolectores (#13)

Todos los recolectores OSINT (#14 a #20) cumplen este contrato, y el orquestador (#22) solo habla con ellos a través de él. Así se puede agregar una fuente sin tocar el orquestador, que es lo que pide el reto con «módulos integrables como plugins independientes». El código está en `cirdan/recolectores/contrato.py` y las pruebas en `pruebas/test_contrato.py`.

## Qué expone cada recolector

Cada recolector es un módulo de `cirdan/recolectores/` con cinco cosas:

| Nombre | Qué es |
|---|---|
| `FUENTE` | El código de su fila en `data_sources`, por ejemplo `ct_logs` |
| `CODIGOS` | Diccionario de código de regla a la severidad base de su regla, con todos los códigos que puede emitir. `pruebas/test_catalogo_reglas.py` falla si falta o si no coincide con el catálogo (#30). Un recolector que solo da activos lo deja vacío, como `subfinder` |
| `MAX_CONSULTAS` | Entero de 0 o más: el máximo de consultas de una corrida de `recolectar()` como la llama `ejecutar()`, contando todos sus reintentos. Es lo que el orquestador reserva del límite diario antes de cada corrida y tiene que contar igual que `Resultado.consultas`. `ct_logs` tiene 18 (2 búsquedas de crt.sh y 4 páginas de Cert Spotter, con 3 intentos cada una), `dns` 18 (6 consultas DNS con 3 intentos cada una), `subfinder` una por cada fuente de su lista blanca, `github` 16 (perfil y página de repos con 3 intentos cada una y hasta 10 clones), `shodan` 64 (2 páginas de Cert Spotter con 2 intentos, 10 A con 3 intentos y 10 IP de InternetDB con 3 intentos) y `ejemplo` 0. En `dns` una consulta es una pregunta a 1.1.1.1 u 8.8.8.8, y en `subfinder` es una fuente consultada en la corrida y no una petición HTTP: rapiddns y thc paginan, y subfinder no deja ver cuántas páginas pidió sin `-stats` |
| `crear_cliente(modo, dominio)` | Su cliente para `vivo`, `grabar` o `reproducir` |
| `recolectar(dominio, cliente=None, ahora=None, propios=())` | Devuelve un `Resultado`. `propios` son los otros dominios de la misma empresa. Puede aceptar más opciones, pero lo que consulte fuera del dominio autorizado va apagado por defecto, porque `ejecutar()` solo pasa estas cuatro |

Además se registra en `REGISTRO` de `cirdan/recolectores/__init__.py`, y `cargar(fuente)` devuelve su módulo. Hoy están `ct_logs` (crt.sh con Cert Spotter como complemento y respaldo, #14 y #14b), `dns` (registros DNS con SPF y DMARC, #15), `subfinder` (#14b, RC-184), `github` (secretos y correos en los repos públicos de la organización declarada, #16, RC-50), `shodan` (servicios y CVE que Shodan InternetDB ya vio en las IP públicas del dominio, #17, RC-49) y `ejemplo`, que no consulta nada y sirve para probar el orquestador sin red. `subfinder` es una fuente aparte, con su propia fila en `data_sources`, no un complemento de `ct_logs`. Corre subfinder solo en modo pasivo, con una lista blanca fija de fuentes públicas y sin resolver nombres ni tocar los servidores de la empresa. Da activos `subdomain` con `fuente` y `origen` (las fuentes de subfinder que vieron el nombre) en sus atributos y ningún hallazgo, así que su `CODIGOS` va vacío. Está registrado, pero la semilla 005 siembra su fila apagada (`enabled = false`), como `censys` en la semilla 001, así que un escaneo normal no lo corre. Se prende con otra semilla cuando #8 (RC-40) revise los términos de sus 8 fuentes, haya una grabación de subfinder de olmardo.com y el contenedor pueda escribir en `respuestas_grabadas/` (hoy no puede, porque el Dockerfile copia `cirdan/` como root).

## Esquema del resultado

**Resultado:** `dominio`, `fuente`, `estado` (`succeeded` o `failed`), `consultas` (entero, peticiones hechas con reintentos), `error` (texto), `avisos` (lista de textos), `activos`, `hallazgos` y `sin_cobertura`. Un resultado `failed` no trae activos ni hallazgos. Todo tiene que poder guardarse como JSON y sin el carácter nulo, que Postgres no acepta.

**sin_cobertura:** los códigos de regla que la fuente no pudo revisar en esta corrida, sin repetir y del catálogo si se pasa. Por ejemplo, con crt.sh caído el respaldo de Cert Spotter no da certificados vencidos ni dominios parecidos, así que `ct_logs` pone `cert_expired` y `lookalike_domain`. También pone `lookalike_domain` si crt.sh responde pero ninguna búsqueda de parecidos responde, o si no se buscaron, que es lo predeterminado y lo que siempre pasa en un escaneo. Es cobertura parcial: un código ahí nunca se muestra como 0 hallazgos y no puede traer hallazgos (`validar()` lo revisa). Si la fuente revisó todo, va vacía. `dns` hace lo mismo con el DNS: si una consulta de TXT se agota o responde SERVFAIL, sus códigos de SPF o de DMARC van aquí, porque una falla no es lo mismo que «no hay registro» (esa sí da `spf_missing` o `dmarc_missing`). Un NXDOMAIN de `_dmarc.<dominio>` o una respuesta vacía (NoAnswer) sí cuentan como «no hay registro». Si la raíz no existe (NXDOMAIN), no hay activos ni hallazgos y los 4 códigos (`spf_missing`, `spf_allow_all`, `dmarc_missing` y `dmarc_policy_none`) van aquí, con un aviso.

**Activo**, que va a la tabla `assets`:

| Campo | Regla |
|---|---|
| `tipo` | `domain`, `subdomain`, `ip`, `service`, `certificate` o `email`, igual que `assets.asset_type` |
| `valor` | El nombre, la IP, `ip:puerto/protocolo`, el correo o la huella del certificado. Los nombres, las IP y los correos tienen que ser válidos. No se repite con el mismo tipo |
| `atributos` | Va a `assets.attributes`. Los tipos `ip`, `service` y `certificate` llevan `host` (o `hosts`, si son varios nombres) con nombres válidos para el filtro de alcance. Sin eso no cumplen el contrato |

**Hallazgo**, que va a la tabla `findings`:

| Campo | Regla |
|---|---|
| `codigo` | El código de su regla (`scoring_rules.code`). Tiene que existir en el catálogo (#30), que lista [`codigos_reglas.md`](codigos_reglas.md). `pruebas/test_catalogo_reglas.py` revisa que cada código de `CODIGOS` del recolector tenga regla con la misma severidad. El recolector emite solo códigos de su `CODIGOS` |
| `severidad` | La severidad base de su regla: `critical`, `high`, `medium` o `low`. El motor de score la puede subir (#29) |
| `activo` | El valor del activo al que pertenece: el dominio o uno de los activos del mismo resultado |
| `titulo` | En español y en lenguaje simple. También va en `evidencia['title']`, porque la base guarda ahí el título |
| `evidencia` | Lo que prueba el hallazgo. Nunca contraseñas, tokens completos ni datos de brechas más allá del hecho |
| `caracteristicas` | Las 4 del reto, que usa el clasificador (#33, #34). Ver la tabla de abajo |
| `huella` | sha256 en hexadecimal, estable entre escaneos. #23 la guarda en la evidencia |
| `clave` | Opcional. Distingue hallazgos del mismo código sobre el mismo activo, por ejemplo cada dominio parecido, un CVE o una brecha. #23 calcula `findings.fingerprint` como SHA-256 del código, el `asset_id` y el CVE, la brecha o esta clave, así que dos hallazgos con el mismo código, activo y clave son el mismo |

**Características del reto:**

| Campo | Valores |
|---|---|
| `tipo` | Código corto en minúsculas con guion bajo, por ejemplo `certificado_vencido` o `spf_faltante` |
| `antiguedad_dias` | Entero de 0 o más: días desde que empezó la exposición o desde que se vio por primera vez |
| `exposicion` | `directa` si el activo responde en internet (un servicio o un panel), `publica` si es un dato público (un certificado, un registro DNS, una brecha o un repositorio) |
| `sensibilidad` | `baja`, `media` o `alta`, según lo que expone |

El hallazgo de ejemplo del contrato de API (#21) trae `caracteristicas` con estos mismos campos y valores: [`api_v1/hallazgos.json`](api_v1/hallazgos.json), descrito en [`contrato_api_v1.md`](contrato_api_v1.md).

## Filtro de alcance

Solo se aceptan activos del dominio autorizado:

- `domain` y `subdomain`: el dominio o un subdominio suyo. `acme-demo.mx.evil.com` y `xacme-demo.mx` quedan fuera.
- `email`: su dominio está en el alcance.
- `ip`, `service` y `certificate`: su `host` (o alguno de `hosts`) está en el alcance.

Lo que queda fuera se descarta, junto con los hallazgos que le pertenecen, y queda un aviso. Un hallazgo de dominio parecido pertenece al dominio de la empresa, y el dominio parecido solo va en la evidencia, así que no se descarta.

## Qué hace el orquestador con cada recolector

El orquestador llama a `ejecutar(recolector, dominio, modo, ahora, propios, codigos)`, nunca a `recolectar()` directo. `ejecutar()`:

1. Si el dominio no es un nombre válido, la fuente queda en `failed` sin llamar al recolector. Si es válido, crea el cliente del modo pedido y llama a `recolectar()` con el dominio autorizado, en minúsculas y sin punto final, `ahora` y `propios`. No pasa ninguna otra opción, así que crt.sh nunca busca dominios parecidos desde un escaneo: esa búsqueda consulta variantes del dominio que pueden ser de terceros y solo se prende en la terminal con `--con-parecidos`.
2. Si el recolector lanza cualquier excepción, devuelve un resultado `failed` con el error. El escaneo sigue con las demás fuentes.
3. Revisa el resultado con `validar()` contra este esquema y, si se le pasan, contra los códigos del catálogo. También revisa que sea del dominio autorizado y de la fuente del recolector, y que se pueda guardar como JSON. Si no cumple, la fuente queda en `failed` con los primeros incumplimientos en el error.
4. Aplica el filtro de alcance.

Una fuente que respondió con códigos en `sin_cobertura` queda `succeeded` en `scan_source_runs`, pero el escaneo termina `partial` y esos códigos van en `scans.stats.rules_without_coverage`. Así el portal marca la cobertura parcial y un escaneo así no cierra los hallazgos de esos códigos (#23).

En `scans.stats.assets` el orquestador cuenta los activos distintos (tipo y valor) de las fuentes que respondieron, no la suma por fuente: un subdominio que dan `ct_logs` y `subfinder` cuenta una vez. El resumen de cada fuente sigue diciendo cuántos dio ella. Guardarlos y juntar sus atributos es de #23.

En `scans.stats.new_findings` cuenta los hallazgos que el escaneo dejó abiertos y antes no lo estaban: los que insertó por primera vez y los que reabrió porque estaban en `resolved`. No cuenta los que ya estaban abiertos, aunque vinieran de otro dominio de la empresa con la misma huella, ni los que el cliente marcó como riesgo aceptado o falso positivo, que no cambian. `scans.stats.resolved_findings` cuenta los que el escaneo pasó a `resolved` porque su fuente respondió y ya no los dio, así que nunca los de una fuente caída ni los códigos en `sin_cobertura`. Un hallazgo que una fuente resuelve y otra reabre en el mismo escaneo quedó como estaba y no cuenta en ninguno. El histórico de la API v1 los lee de ahí (#23, RC-55).

## Reintentos

Hay dos niveles:

- **Dentro de una corrida**, para fallas de segundos como un 502 pasajero: `con_reintentos()` hace hasta 3 intentos, con esperas de 5 y 15 segundos entre ellos. Un error HTTP 4xx, salvo 408 y 429, no se reintenta y lo interpreta el recolector, porque la fuente sí respondió: un 404 de HIBP significa «sin brechas». crt.sh sigue esta misma regla en su cliente.
- **Entre corridas**, en `scan_source_runs`: `siguiente_estado()` da el `status`, el `attempt` y el `next_retry_at`. En vivo, el orquestador (#22) espera ese tiempo y vuelve a correr la fuente en el mismo escaneo, en la misma fila. Al reproducir o grabar no reintenta y la fuente queda en `failed`.

| Corrida | Resultado | Queda en |
|---|---|---|
| attempt 0 | failed | `retrying`, attempt 1, otra vez en 1 minuto |
| attempt 1 | failed | `retrying`, attempt 2, en 5 minutos |
| attempt 2 | failed | `retrying`, attempt 3, en 25 minutos |
| attempt 3 | failed | `failed`: el escaneo termina `partial`, o `failed` si ninguna fuente respondió (#23) |
| cualquiera | succeeded | `succeeded` |
| cualquiera | sin cupo diario | `failed` en ese mismo attempt, sin reintento y sin llamar al recolector (ver abajo) |

## Límite diario por fuente

Cada fila de `data_sources` tiene un límite diario de consultas de toda la plataforma, no de cada empresa, porque las cuotas de las fuentes son de la plataforma (#13b, RC-184). Vive en tres columnas de `data_sources` de la migración 008: `daily_limit` (NULL es sin límite), `daily_used` y `daily_used_on`. El día se corta en UTC, escrito en el SQL, y no en la zona de México que fija cada transacción de la app. Se cuenta en consultas como `Resultado.consultas` y `MAX_CONSULTAS`, así que en `dns` cada unidad es una consulta DNS y en `subfinder` una fuente consultada en la corrida, no una petición HTTP. `cirdan_app` no tiene UPDATE sobre `data_sources`: solo lee las tres columnas y ejecuta `reserve_source_quota()` y `adjust_source_quota()`, dos funciones SECURITY DEFINER como `login_lookup`. Con ellas sí mueve `daily_used` del día: la reserva respeta el límite, pero el ajuste acepta cualquier delta, así que el límite lo cuida el orquestador y no un permiso de la base.

- **Reserva.** En `vivo` y en `grabar`, antes de cada corrida, también de cada reintento, el orquestador reserva `MAX_CONSULTAS` del recolector en una transacción corta propia. La reserva es un solo UPDATE atómico, así que dos escaneos a la vez, o la API y la línea de comandos del orquestador, nunca pasan el límite. Si el día guardado es anterior a hoy, la cuenta empieza de 0, y el día guardado nunca retrocede.
- **Ajuste.** Al terminar la corrida, el orquestador ajusta a lo que de verdad gastó (`Resultado.consultas`): devuelve lo que sobró o suma lo que se pasó, que se registra igual. Si el día ya cambió, no ajusta. Si algo falla entre la reserva y el ajuste, lo reservado se queda.
- **Cambio de día.** Una corrida que reservó antes de la medianoche UTC y consulta después queda contada en el día viejo, y su ajuste no toca el día nuevo. Lo que consultó después de la medianoche no cuenta en el día nuevo, que así puede pasar su límite hasta en el `MAX_CONSULTAS` de esa fuente. Es un margen aceptado y la lógica del ajuste no cambia por eso.
- **Sin cupo.** Si la reserva no cabe, la fuente queda `failed` con el error `Sin cupo diario: <code> no tiene cupo para una corrida completa hoy (día UTC).`, que también va en los avisos de su resumen. Puede quedar algo de cupo, pero no el máximo de una corrida. No se llama al recolector y no se reintenta a 1, 5 ni 25 minutos, porque esperar no devuelve un cupo diario. El escaneo queda `partial` o `failed` con la regla de siempre.
- **Reproducir no gasta.** Al reproducir no se reserva ni se ajusta, así que las demos no gastan cupo ni se bloquean. Un escaneo de un dominio fuera de `DOMINIOS_EN_VIVO` pasa a reproducir y tampoco gasta.
- **La línea de comandos de un recolector no cuenta.** `python -m cirdan.recolectores.crtsh <dominio> --grabar` corre sin base ni orquestador, así que lo que consulta no pasa por el límite diario. Úsala con la misma mesura.

## Respuestas grabadas

La clase `Grabadora` guarda y reproduce las respuestas de una fuente para un dominio en `cirdan/recolectores/respuestas_grabadas/<recolector>/<dominio>/`. Cada respuesta es un archivo `{grabado, consulta, datos}`. La fecha va dentro del archivo porque git y las copias cambian la del sistema.

| Modo | Qué hace |
|---|---|
| `vivo` | Consulta la fuente y no toca el disco |
| `grabar` | Consulta y guarda. Con `nueva`, vacía la carpeta y marca el inicio con la primera respuesta válida, así una grabación fallida deja intacta la anterior. Con `completar`, reutiliza lo grabado desde ese inicio. `crear_cliente('grabar', dominio)` empieza una grabación nueva |
| `reproducir` | Solo lee del disco. Si falta una respuesta, lanza `SinGrabacion`. El recolector puede tomarla como aviso, como hace crt.sh con las variantes, pero si llega a `ejecutar()` la fuente queda en `failed` igual que con cualquier otra excepción |

Las pruebas de cada recolector usan respuestas grabadas o un transporte simulado, nunca la red. El día anterior a cada sesión se graba el dominio de prueba como respaldo de la demo. En crt.sh se usa `python -m cirdan.recolectores.crtsh <dominio> --grabar`. La misma carpeta guarda las páginas de Cert Spotter, que se consulta en cada corrida, y la falla de crt.sh si no responde, así `--reproducir` repite lo mismo con los mismos avisos. Si la primera página de Cert Spotter no llegó al grabar, esa falla no se graba y `--reproducir` la muestra como respuesta faltante. Si faltó una de las siguientes, sale el aviso de que pueden faltar subdominios y renovaciones recientes, así que un certificado por vencer puede estar ya renovado. En los dos casos se completa con `--grabar --completar`.

El recolector de DNS (#15) se graba con `python -m cirdan.recolectores.registros_dns <dominio> --grabar`, en `cirdan/recolectores/respuestas_grabadas/dns/<dominio>/`. Cada consulta (A, AAAA, MX, NS, TXT de la raíz y TXT de `_dmarc`) es un archivo y solo se graba lo ya limpio, sin los TXT que no sean un SPF o un DMARC completos. Una consulta que falló no se graba, y al reproducir su ausencia sale como aviso y deja sus códigos en `sin_cobertura`. Sus activos `ip` llevan `host` con el dominio, y los MX y NS del propio dominio salen como `subdomain`. Todo el DNS va también en `atributos['dns']` del activo `domain`, porque no hay tipo de activo para un registro. Desde un escaneo, el orquestador los guarda en `assets` y `findings` (#23).

El recolector de GitHub (#16) se graba con `python -m cirdan.recolectores.github <dominio> --grabar`, en `cirdan/recolectores/respuestas_grabadas/github/<dominio>/`, y solo graba lo ya limpio: el perfil y la lista de repos filtrados y, por repo, los secretos reducidos (regla, ruta y fecha) y los correos del dominio ya validados. Nunca el clon, el reporte de gitleaks ni un valor. Graba todo al final y solo si la corrida terminó, así una grabación fallida deja intacta la anterior. Sin grabación del dominio, `reproducir` no queda `failed`: da sus 2 códigos en `sin_cobertura` y un aviso. Tampoco queda `failed` una corrida que gitleaks entregó sin redactar: se descarta sin grabar, con el mismo `sin_cobertura`, porque reintentarla daría lo mismo. Cada archivo lleva en el nombre 12 caracteres del sha256 de su consulta, para que dos repos que solo difieren en caracteres que `nombre_archivo()` cambia por `_` no compartan archivo.

El recolector de Shodan (#17) se graba con `python -m cirdan.recolectores.shodan <dominio> --grabar`, en `cirdan/recolectores/respuestas_grabadas/shodan/<dominio>/`, y como el de GitHub graba todo al final y solo si la corrida terminó. Solo se graba una corrida sin ninguna falla. Los únicos recortes que no lo impiden son los topes deterministas (las 2 páginas de Cert Spotter, 10 nombres, 10 IP y 25 CVE por IP). Cualquier falla (un 429 o un 4xx de Cert Spotter o de InternetDB, una página o una emisión de Cert Spotter que no se puede leer, una falla de red o del DNS, una respuesta de InternetDB vacía, 'null' o con campos rotos, o el tope de tiempo) deja intacta la grabación anterior, con el aviso de que no se grabó al principio de los avisos y código de salida 3, o 1 si la falla dejó la fuente en `failed`. Solo guarda lo ya limpio: las páginas de Cert Spotter reducidas a lo que lee `certspotter.certificado()` (`certspotter_<dominio>.json`), cada A con su estado, sus IP y su cadena CNAME completa (`a_<nombre>.json`) y cada IP de InternetDB con sus puertos, tags, CPE y CVE válidos y solo los nombres del dominio (`internetdb_<ip>.json`). Nunca graba una falla, así que `--reproducir` siempre repite una corrida sin fallas. Un dominio sin IP que consultar igual deja grabados su página de Cert Spotter y el A de la raíz. Sin grabación del dominio, `reproducir` no queda `failed`: da sus 9 códigos en `sin_cobertura` (los 6 de `CODIGOS` y los 3 de `SIN_LLAVE`) y un aviso. Sus activos `ip` llevan `hosts` con los nombres que resuelven a esa IP, y sus activos `service` llevan `parent` e `ip_address` con su IP.

El recolector de RDAP (#15b, fuente `whois`) se graba con `python -m cirdan.recolectores.rdap <dominio> --grabar`, en `cirdan/recolectores/respuestas_grabadas/whois/<dominio>/`, y como el de Shodan graba todo al final y solo si la corrida no tuvo ninguna falla. Guarda el bootstrap de IANA reducido al servicio que cubre el dominio (`bootstrap.json`) y la respuesta RDAP reducida a lo que se lee, con la forma de RDAP (`rdap_<dominio>.json`): del registrador solo su nombre y su IANA Registrar ID, y nada de las demás entidades (registrante, contactos y abuso). Cada valor pasa el mismo filtro que al leerlo y queda un evento por acción, así no se graba texto libre, y si algo no se puede guardar en UTF-8 no se graba nada y queda la grabación anterior. Al reproducir, esa respuesta pasa otra vez por `leer_rdap()`, así una grabación rota queda `failed`. El 404 del registro y un TLD sin servidor RDAP https sí se graban, porque otra corrida daría lo mismo. Si hubo respaldo por WHOIS en el puerto 43 (TLD sin RDAP, como .mx, o RDAP que no respondió), también guarda el servidor WHOIS que dio whois.iana.org para el TLD (`whois-iana_<tld>.json`) y la respuesta WHOIS ya reducida a las llaves de `CAMPOS_WHOIS` (`whois_<dominio>.json`), nunca el texto crudo, así que contactos, correos, teléfonos y direcciones no se leen ni se graban. Si RDAP falló y WHOIS respondió, el resultado sale completo pero no se graba. Al reproducir, esa respuesta pasa otra vez por `leer_whois()`. Una grabación de un TLD sin RDAP hecha antes del respaldo, sin `whois-iana`, da lo mismo que entonces. Si ni RDAP ni WHOIS responden, la fuente no queda `failed`: da el activo `domain` con 'No disponible', `domain_expiring_soon` en `sin_cobertura` y un aviso, como pide RC-166. Sin grabación del dominio, `reproducir` da lo mismo con su propio aviso.

El país, el ASN y el proveedor de los activos `ip` de DNS y de Shodan (#15b, `cirdan/recolectores/geoip.py`) no se graban: salen de la base local de DB-IP Lite en `datos/geo/`, sin red, también al reproducir. Por eso cada activo `ip` que sí se buscó en una base lleva `fuente_geo` = 'DB-IP Lite' y `base_geo` con las bases que se usaron (por ejemplo `dbip-asn-lite-2026-10`). Una IP que no es global, o una corrida sin ninguna base, lleva 'No disponible' en los dos. Sin la base de ASN, Shodan no puede descartar por ASN las IP de un CDN sin CNAME conocido y las consulta igual, y el aviso de base faltante lo dice. Al reproducir con otra base que la de la grabación, una IP puede cambiar de CDN por ASN. En Shodan, una IP que al grabar se marcó como CDN por ASN no se consultó ni se grabó: si la base del momento ya no trae ese ASN (o no hay base de ASN), la IP se pide a la grabación y no está. La corrida sale con cobertura parcial (código de salida 2), el aviso 'shodan: no hay respuesta grabada para internetdb:<ip>', esa IP con `internetdb` = 'sin_respuesta' y los códigos sin hallazgos en `sin_cobertura`. La grabación no guarda la marca de CDN, así que para repetir la corrida completa hay que reproducir con la misma base.

## Cómo agregar un recolector

1. Su fila en `data_sources` con su código y su `daily_limit`, o NULL si la fuente no tiene cuota.
2. El módulo en `cirdan/recolectores/` con `FUENTE`, `CODIGOS` (código de regla y su severidad base), `MAX_CONSULTAS`, `crear_cliente()` y `recolectar()`, que usa `Grabadora` para sus respuestas. Un código nuevo se agrega como dice [`codigos_reglas.md`](codigos_reglas.md).
3. Su línea en `REGISTRO`.
4. Una prueba sin red que compruebe `validar(resultado, codigos=<los del catálogo>) == []`.
5. Los títulos en español, y nada que no sea observación pasiva.
6. Si en una corrida no puede revisar alguno de sus códigos, lo pone en `sin_cobertura` en lugar de dejarlo en 0 hallazgos.
7. Si alguna consulta sale del dominio autorizado, como los dominios parecidos de crt.sh, va apagada por defecto y sus códigos quedan en `sin_cobertura`. `ejecutar()` nunca la prende.

## Lo que no es de este contrato

- La limpieza de datos es de #13b.
- El orquestador guarda en la base lo de cada fuente que respondió, sin duplicar por la huella, y da por resuelto lo que la fuente ya no encontró (#23).
