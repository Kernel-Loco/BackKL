# Política de uso ético y alcance de LowTide

Tarjeta #6 (RC-36). La política de seguridad y privacidad de la tarjeta #78 integrará estas reglas.

LowTide es el nombre comercial del servicio. Cirdan es su nombre clave y se queda en los identificadores técnicos, como el prefijo del TXT `cirdan-verification=`, el User-Agent `cirdan-osint`, el prefijo `CIRDAN_FAKE_` de los tokens falsos y los nombres del paquete, la base, los contenedores, las variables de entorno y los archivos.

Aplica al equipo Kernel Loco, a quien contribuya a los repositorios de LowTide y a las empresas que usen el servicio, que la aceptan en la sección 10 de su carta. Va junto con la [plantilla de carta de autorización](plantilla_carta_autorizacion.md). Es un documento académico, no una opinión jurídica.

## 1. Solo se analizan dominios autorizados

1. Ningún dominio se analiza sin dos pruebas: una carta de autorización firmada y vigente, y un registro TXT `cirdan-verification=<token>` publicado en el dominio que prueba que la empresa lo controla.
2. La base lo exige para todo análisis que pasa por el orquestador. La tabla `scans` no acepta un análisis sin una autorización vigente y sin revocar, ni sin una verificación del TXT con resultado `match` de la última hora ([`db/README.md`](../db/README.md), sección 'Qué se creó'). Un recolector que se corre a mano, como `python -m cirdan.recolectores.crtsh`, no pasa por esa revisión. Por eso aplica la regla 5.
3. Se firma una carta por cada dominio raíz. Lo que la carta no describe no está autorizado.
4. Si la empresa revoca la carta, quien reciba el aviso pone el dominio en pausa ese mismo día y registra la revocación en LowTide a más tardar el siguiente día hábil, como dice la sección 8 de la carta. Desde la pausa no se inicia ningún análisis nuevo. Una revocación no se deshace: para volver a analizar, la empresa firma una carta nueva. Si la empresa quita el TXT, LowTide deja de iniciar análisis desde su siguiente revisión.
5. Nunca se usa un dominio de terceros como objetivo de un análisis ni de una consulta en vivo, tampoco 'solo para probar'. La única excepción es la búsqueda de dominios parecidos: LowTide busca el nombre del dominio autorizado y hasta 10 variantes suyas solo en los registros públicos de certificados (Anexo A de la carta, actividad 1).
6. Para probar se usan las pruebas sin red y las respuestas grabadas. Una consulta en vivo hecha a mano, fuera del orquestador, solo se hace con el dominio de prueba del equipo y con confirmación previa de quien coordine.
7. `--grabar` solo se usa con el dominio de prueba del equipo, el día anterior a una sesión o a un control, como respaldo de la demo. Nunca se usa para probar, porque vacía la grabación anterior del dominio en cuanto la fuente responde. El orquestador analiza a las empresas en modo `vivo`, nunca en `grabar`.
8. El filtro de alcance de `ejecutar()` descarta todo activo que no sea del dominio autorizado ([`docs/contrato_plugin.md`](contrato_plugin.md), sección 'Filtro de alcance'). En un análisis, todo recolector se llama a través de `ejecutar()`, nunca con `recolectar()` directo. El CLI de un recolector no pasa por ese filtro y solo se usa con el dominio de prueba del equipo.
9. Los ejemplos de la documentación solo usan el dominio de prueba del equipo o nombres reservados para ejemplos (`example.com`, `.example` o `.test`). Ningún README ni comentario enseña una consulta en vivo a un dominio que el equipo no controla.
10. Todo análisis deja rastro de quién lo autorizó, cuándo se hizo, qué datos se pidieron y a qué fuentes. Cada fila de `scans` apunta a la carta que lo autoriza y a la verificación del TXT que lo dejó pasar, y guarda quién lo pidió (o si fue programado), cuándo empezó y cuándo terminó. `scan_source_runs` guarda cada fuente que corrió, su resultado y su error. `audit_log` anota cuando se pide, se rechaza y termina cada análisis, en una cadena de hashes que no se puede editar ni borrar. Un recolector que se corre a mano no deja este rastro en la base. Por eso solo se usa como dicen los puntos 6 y 8.

## 2. Solo se observa, nunca se ataca

1. LowTide solo lee información que cualquiera puede consultar en internet o en servicios de terceros: registros públicos de certificados, fuentes públicas de subdominios en modo pasivo, DNS público, datos de registro del dominio, repositorios públicos de GitHub, la configuración de imágenes públicas de Docker Hub, datos que ya publican servicios como Shodan y Have I Been Pwned, y las páginas públicas de los sitios.
2. Las únicas peticiones directas a los sitios del dominio son las que lista el Anexo A de la carta: visitas web normales, la lectura de páginas públicas y, cuando exista, la lectura de hasta 10 rutas fijas de documentación de APIs. Fuera de esos sitios, la única otra petición directa es la comprobación anónima de si un bucket ligado al dominio se puede listar (actividad 10), sin listar ni descargar archivos. Todas salen de la IP y con el User-Agent de la sección 9 de la carta, y respetan el límite diario y los términos de uso de cada fuente.
3. Está prohibido:
   - explotar vulnerabilidades
   - probar contraseñas por fuerza bruta
   - adivinar subdominios o rutas por fuerza bruta o con listas de palabras, fuera de las 10 rutas fijas del punto 2
   - adivinar nombres de recursos en la nube
   - escanear puertos de forma activa o pedirle a otro servicio que lo haga
   - hacer pruebas de carga o de denegación de servicio
   - usar o validar credenciales filtradas
   - hacer phishing o ingeniería social
   - entrar a cuentas o a contenido privado, o navegar con una sesión
   - llamar a los servicios que documenta una API
   - descargar archivos de buckets o capas de imágenes de contenedores
4. Única excepción: el equipo puede pedir a Shodan que escanee la IP del servicio sembrado en su propio dominio de prueba (tarjetas #8 y #10), solo mientras esa IP sea de la máquina virtual del equipo, y nunca la de un cliente.
5. De las IPs de un CDN solo se registra que existen: no se buscan en Shodan ni se les atribuyen tecnologías. Los buckets enlazados cuyo nombre no contiene el dominio se registran como dependencia externa, sin consultarlos.
6. Si una función nueva necesita algo que no está en esta sección, primero se cambian esta política y la plantilla de carta, con su PR revisado (sección 11).

## 3. Lo que sí ataca solo va contra LowTide

Las pruebas activas (ZAP en modo activo, pruebas de penetración y el reto de hackeo para el grupo) solo se hacen contra el despliegue de LowTide en su máquina virtual, con cuentas de prueba y sin datos reales de ninguna empresa. Nunca contra el dominio de un cliente, la PC del plan B ni infraestructura de terceros, aunque esté en la misma nube. No incluyen denegación de servicio ni ingeniería social, y siguen las reglas de pruebas de penetración del proveedor de nube. El reto de hackeo solo empieza con permiso escrito del profesor y con sus reglas y su alcance publicados (tarjeta #85).

## 4. Datos personales y secretos

1. De lo que encuentran los hallazgos, LowTide no guarda contraseñas ni el valor de un secreto. De un secreto guarda solo su tipo, el repositorio, la ruta y una huella. La evidencia de un hallazgo nunca guarda tokens completos ni datos de brechas más allá del hecho.
2. Si un secreto o una contraseña llega a guardarse por error, ese mismo día se borra de la base, de las grabaciones y de los registros, se anota si quedó en un respaldo y se avisa a la empresa para que lo cambie. Por eso la evidencia nunca se copia a tablas de solo inserción como `audit_log`, `domain_scores` o `score_contributions`, de donde no se puede borrar. Si un secreto llega a un repositorio, se revoca o se cambia de inmediato, porque el historial publicado no se reescribe.
3. Solo se tratan correos del dominio autorizado. LowTide solo liga datos de una persona cuando un hallazgo lo necesita, como un correo con su brecha o con el commit donde aparece, no la busca fuera de las fuentes del Anexo A de la carta, y su información no se usa para vigilar, evaluar ni sancionar a empleados.
4. La base rechaza guardar en `scan_source_runs.raw_payload` la respuesta cruda de Have I Been Pwned, y el recolector tampoco la copia en la evidencia de un hallazgo ni en los atributos de un activo. Toda fuente que pueda traer secretos, correos o datos de brechas se da de alta en `data_sources` con `keep_raw_payload = false`.
5. Todo token falso que se siembra o se usa en pruebas lleva el prefijo `CIRDAN_FAKE_` y solo vive en `pruebas/fixtures/` o en el repositorio sembrado de la organización de GitHub del dominio de prueba (tarjeta #10b).
6. Nunca se sube al repositorio un `.env`, una contraseña, una llave ni un token. Los repositorios son públicos. Se nombran las variables, nunca sus valores.
7. Los papeles de cada parte ante la LFPDPPP (la empresa como responsable y el equipo como encargado), la retención y el borrado los fijan la carta de autorización y la política de privacidad de la tarjeta #78.
8. Si una vulneración de seguridad de LowTide (la máquina virtual, la base o un respaldo) afecta datos de una empresa, el equipo le avisa en el plazo de la sección 6 de su carta para que ella informe a las personas afectadas, y avisa al profesor.

## 5. Datos de terceros

1. Lo que LowTide ve de terceros, como un dominio parecido o un bucket enlazado de otra empresa, solo se registra como evidencia. Nunca se consulta más ni se contacta a su dueño.
2. Si LowTide hace una petición fuera del alcance o recibe datos que no debía, como el contenido de un bucket o de una página privada, se detiene el análisis y no se explora más. Ese mismo día se borra lo recibido de la base, de las grabaciones y de los registros, y solo queda una nota de qué pasó, cuándo y con qué fuente, sin el contenido. La nota va en un lugar privado del equipo, como Jira, nunca en un issue o PR de los repositorios, que son públicos. Se avisa ese mismo día a quien coordine, o a otro integrante si fue quien coordina, y si el afectado es un tercero se informa al profesor.
3. Lo que el filtro de alcance descarta por su cuenta y deja como aviso no es un incidente.
4. Lo que devuelve una fuente externa no se da por cierto hasta revisarlo. Antes de guardarlo o de usarlo en el score, se revisa que tenga el formato del contrato de plugin y que sea del dominio autorizado, y se descarta lo que no cumple. `ejecutar()` deja en `failed` la fuente cuyo resultado no cumple el contrato, por ejemplo con un nombre, un correo o una IP inválidos, y el filtro de alcance descarta lo que no es del dominio ([`docs/contrato_plugin.md`](contrato_plugin.md), sección 'Qué hace el orquestador con cada recolector'). La limpieza de los datos de cada fuente llega con la tarjeta #13b.

## 6. Confidencialidad, demostraciones y cartas

1. Los resultados de una empresa solo los ven el equipo y esa empresa. Los terceros de la sección 6 de la carta solo reciben lo que ahí se dice, como el proveedor de IA, que recibe el título, la categoría y la severidad de los hallazgos, sin correos. Un integrador solo los ve si la carta de la empresa lo nombra.
2. Las demostraciones, las láminas y los repositorios solo usan datos de empresas ficticias (Acme Demo, Beta Corp y Grupo Olmardo) o datos de un cliente anonimizados y con su permiso por escrito.
3. Las respuestas reales grabadas de un dominio que no sea del equipo nunca se suben a un repositorio. Las respuestas inventadas para pruebas, como la del recolector `ejemplo`, sí se pueden subir.
4. Los nombres que se siembran en certificados del dominio de prueba quedan para siempre en registros públicos. No llevan nombres de personas reales, de terceros ni el nombre comercial del producto.
5. Antes de cargar una carta en LowTide, un integrante del equipo comprueba que el dominio, la razón social y quien firma coincidan con la copia del poder y de la identificación que pide la sección 1 de la carta, y lo anota en la bitácora.
6. La carta del dominio de prueba la firma como persona física el integrante a cuyo nombre se registra el dominio. No se inventan razón social, RFC, escritura ni notario.

## 7. Uso aceptable para las empresas

1. Una empresa solo puede dar de alta dominios que son suyos. Si un integrador actúa por otra empresa, la carta la firma la dueña del dominio.
2. No puede usar LowTide para analizar a competidores o proveedores sin su carta, para preparar ataques, para vigilar o sancionar a sus empleados ni para dar acceso al servicio a otra empresa.
3. Ninguna empresa real, incluido el socio formador de la tarjeta #76, da de alta un dominio mientras la API elija a la empresa con el encabezado `X-Organization` (hasta la tarjeta #25) o mientras `/docs`, `/openapi.json`, `/demo` y `/db/tables` estén abiertos sin sesión.

## 8. Si alguien rompe estas reglas

1. Se detiene el análisis y se quita el acceso a quien rompió la regla. Si es usuario de una empresa, se desactiva su cuenta del portal o se revoca su llave de la API. Si fue la empresa, además se pausa el dominio y se registra la revocación de su carta. Si es integrante del equipo, se cambian las llaves y contraseñas de las fuentes, la máquina virtual y la base que haya usado, mientras el profesor revisa el caso.
2. Si los datos son de una empresa cliente, se le avisa por el contacto de la sección 9 de su carta. Si el afectado es un tercero, el equipo no lo contacta por su cuenta (regla 5.1). Quien coordine lo informa al profesor ese mismo día y el profesor decide si se le avisa y cómo.
3. Se documenta qué pasó en un lugar privado del equipo, como una tarjeta de Jira, sin datos sensibles, y nunca en un issue o PR de los repositorios, que son públicos. La carta, su huella sha256 y la bitácora del caso se conservan como prueba, como permite la sección 6 de la carta.
4. Si quien rompió las reglas es integrante del equipo, quien coordine, u otro integrante si fue quien coordina, lo informa por escrito al profesor ese mismo día. Las consecuencias las decide el Tec según su Código de Ética y el Reglamento General de Estudiantes, no el equipo. En la siguiente retrospectiva el equipo revisa cómo evitar que se repita.

## 9. Por qué estos límites

- El Código Penal Federal castiga a quien, sin autorización, modifique, destruya, provoque pérdida, conozca o copie información de sistemas o equipos de informática protegidos por algún mecanismo de seguridad (art. 211 bis 1). Las penas son mayores si los sistemas son del Estado, de seguridad pública o de instituciones del sistema financiero (arts. 211 bis 2, 211 bis 4 y 211 bis 6), suben hasta en una mitad si la información se usa en provecho propio o ajeno (art. 211 bis 7), y los arts. 211 bis 3 y 211 bis 5 castigan también a quien, estando autorizado, actúa indebidamente en sistemas del Estado o del sistema financiero. Por eso LowTide solo observa información pública, solo con autorización firmada y nunca hace más de lo que dice la carta.
- La Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP, DOF 20 de marzo de 2025) protege los datos personales que aparecen en los hallazgos, como los correos de empleados, exempleados y proveedores. Que un dato se vea en internet no lo vuelve 'fuente de acceso público', porque la ley solo llama así a lo que se puede consultar por disposición de ley y excluye lo obtenido de forma ilícita, como una brecha (art. 2, fracción X). Por eso se minimiza lo que se guarda, la empresa es la responsable y avisa a esas personas en su aviso de privacidad, y el equipo trata los datos por cuenta de ella como persona encargada (art. 2, fracción XII).
- El reto IKUSI VELATIA pide que toda la información provenga de fuentes abiertas, sin explotación, fuerza bruta ni acceso no autorizado, y que solo se generen reportes de dominios con autorización registrada.

## 10. Cómo se cumplen en el código

| Regla | Cómo se cumple | Estado |
|---|---|---|
| Solo dominios con carta vigente y TXT verificado | Trigger en `scans` y orquestador | Existen los dos. El orquestador es de la tarjeta #22 |
| Solo activos del dominio autorizado | Filtro de alcance de `ejecutar()` | Existe. El CLI de un recolector no pasa por él |
| Cada empresa solo ve sus datos | RLS con ENABLE y FORCE en las 18 tablas por cliente | Existe en la base. Desde la tarjeta #25 la API toma la empresa de la sesión. Solo el modo demo de `/demo` y `/db/tables` usa todavía el encabezado `X-Organization` |
| La carta no se edita | `domain_authorizations` inmutable salvo `revoked_at` | Existe |
| Una revocación no se deshace | Bloquear que `revoked_at` vuelva a NULL | Falta. Hoy el trigger deja regresarlo. Una migración que lo impide está propuesta en un comentario de la tarjeta #26 (13 oct), sin decidir |
| Revocar una carta desde el portal | Pantalla o API para fijar `revoked_at` | Falta. Propuesto en el mismo comentario de la tarjeta #26 (13 oct), sin decidir |
| Sin respuesta cruda de HIBP | `scan_source_runs` rechaza `raw_payload` de esa fuente | Existe |
| Fuentes con secretos sin respuesta cruda | `keep_raw_payload = false` en `data_sources` | Falta para GitHub, que llega con la tarjeta #16 |
| Pruebas sin fuentes externas | Fuera de la prueba opcional de `test_escaneos_api.py` con `EN_VIVO=1`, que escanea el dominio de prueba del equipo, las pruebas de `pruebas/` nunca consultan fuentes externas ni DNS real. Las de la base, la API, el inicio de sesión, los escaneos y el orquestador usan la base y la API locales | Existe como convención, sin bloqueo de red |
| Ningún secreto entra al repositorio | gitleaks como pre-commit y en el CI, más una revisión de todo el historial | El pre-commit existe (`.pre-commit-config.yaml`) y el README dice cómo revisar todo el historial. El CI llega con la tarjeta #12 |
| Ejemplos sin dominios ajenos | README y comentarios con el dominio de prueba o nombres reservados | En parte. Las consultas en vivo del README y de `crtsh.py` usan olmardo.com, el dominio de prueba del equipo, y ningún ejemplo enseña una consulta en vivo a otro dominio. Pero los comandos rechazados del README y del orquestador usan partner-example.com y old-example.net, `contrato_plugin.md` usa evil.com y las cuentas de la demo usan acme-demo.mx, y ninguno es un nombre reservado |
| Cada análisis deja rastro | `scans` con su carta, su verificación del TXT y quién lo pidió, `scan_source_runs` por fuente y `audit_log` con su cadena de hashes | Existe para los análisis del orquestador. El CLI de un recolector no deja rastro. Un análisis que se cae por un error inesperado queda `failed` en `scans`, pero sin su registro de fin en `audit_log`. Falta guardar los activos y hallazgos de cada análisis (#23) y revisar la cadena de `audit_log` (#86) |
| Datos de fuentes externas no confiables | `ejecutar()` revisa el contrato y aplica el filtro de alcance | Existen la revisión del contrato y el filtro. La limpieza de los datos de cada fuente llega con la tarjeta #13b |

## 11. Cambios a esta política

Esta política cambia solo por PR a `dev`, con revisión de quien lleve seguridad en el equipo, o de quien le toque revisar según el backlog si esa persona hizo el cambio. Cada cambio que amplíe lo que hace LowTide cambia también la plantilla de carta. Una actividad que no está en la carta firmada de una empresa no se activa para ella hasta que firme una carta nueva. Las que ya están en el Anexo A de su carta se activan con el aviso de 5 días hábiles que dice ese anexo.
