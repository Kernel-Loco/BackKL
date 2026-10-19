# Carta de autorización para el análisis pasivo de exposición en internet

Plantilla de LowTide (tarjeta #6, RC-36). Va junto con la [política de uso ético](politica_uso_etico.md), que la carta pide aceptar en su sección 10.

- Los campos entre corchetes los llena la empresa. Lo que guarda la base está marcado con (base). La tabla `domain_authorizations` también guarda la ruta del PDF firmado, su huella sha256 y quién lo cargó. El alcance (plan, GitHub, Docker Hub y exclusiones) solo queda en el PDF.
- Se firma una carta por cada dominio raíz, porque la base guarda una autorización por dominio.
- Un administrador de la empresa sube el PDF firmado al portal (máximo 5 MB). LowTide guarda su huella sha256.
- Plantilla académica del equipo Kernel Loco. Antes de usarla con un cliente real, incluido el dominio del socio formador de la tarjeta #76, debe revisarla un abogado o el área legal de esa empresa.

---

[Ciudad], a [día] de [mes] de [año].

Para: [nombres completos de los integrantes], estudiantes del Tecnológico de Monterrey que integran el equipo Kernel Loco y operan el servicio LowTide, en adelante 'el equipo'.

## 1. Quién autoriza

[Nombre completo] (base: signer_name), en su carácter de [representante legal o apoderado] (base: signer_title) de [razón social], con RFC [RFC] y domicilio en [domicilio], con poder para actos de administración según la escritura pública número [número] del [fecha], otorgada ante el notario público número [número] de [ciudad], facultades que declara que no le han sido revocadas ni limitadas y de las que entrega copia junto con su identificación oficial, autoriza al equipo a analizar con el servicio LowTide la exposición en internet del dominio, la organización de GitHub y los namespaces de Docker Hub de la sección 2.

## 2. Alcance

- Dominio autorizado: [dominio raíz] (base: domains.fqdn, ligado por domain_id) y todos sus subdominios.
- Plan contratado: [Starter, Business o Enterprise].
- Organización de GitHub de la empresa, si existe: [nombre o 'ninguna']. LowTide también busca la organización de GitHub ligada al dominio y los usuarios de GitHub que usan un correo del dominio.
- Namespaces de Docker Hub de la empresa: [nombres o 'ninguno'].
- Queda fuera cualquier dominio no listado. De las IPs que pertenecen a un CDN solo se registra que existen: no se buscan en Shodan ni se les atribuyen tecnologías. Los buckets que el sitio enlaza y cuyo nombre no contiene el dominio se registran como dependencia externa, sin consultarlos.
- Las visitas a los sitios del dominio pueden pasar por proveedores como un CDN o un hosting compartido, y la empresa declara que tiene derecho a autorizarlas.

## 3. Qué hace LowTide

LowTide solo observa información que cualquiera puede consultar en internet o en servicios de terceros, sin entrar a sistemas de la empresa. Que sea visible no la vuelve 'fuente de acceso público' para la LFPDPPP, por eso aplica la sección 6.

Consulta registros públicos de certificados, fuentes públicas de subdominios, el DNS público, los datos de registro del dominio (RDAP), los repositorios públicos de GitHub de la sección 2, los servicios expuestos que ya publica Shodan, los correos del dominio que aparecen en brechas conocidas según Have I Been Pwned, y los correos y perfiles públicos ligados al dominio.

LowTide hace tres tipos de peticiones directas a los sitios del dominio: visitas web normales para leer sus cabeceras y tecnologías, la lectura de sus páginas públicas para encontrar correos y perfiles y, cuando la actividad 9 esté disponible, peticiones GET a un máximo de 10 rutas fijas de documentación de APIs. No hace ninguna otra petición a los servidores del dominio. Además, cuando la actividad 10 esté disponible, hace una petición anónima a los buckets de nube ligados al dominio para saber si se pueden listar.

LowTide analiza el dominio de forma automática con la frecuencia del plan: cada 7 días en Starter y cada día en Business y Enterprise. Solo el plan Enterprise puede pedir análisis adicionales a solicitud. El Anexo A lista cada actividad, su fuente, si toca los servidores del dominio y la fecha prevista desde la que el servicio la realiza.

## 4. Qué está prohibido

LowTide no explota vulnerabilidades, no prueba contraseñas por fuerza bruta, no adivina subdominios ni rutas por fuerza bruta, no escanea puertos de forma activa ni pide a Shodan o a otro servicio que escanee las IPs de la empresa, no hace pruebas de carga ni de denegación de servicio, no usa ni valida credenciales filtradas, no hace phishing ni ingeniería social, no entra a cuentas ni a contenido privado, no llama a los servicios que documenta una API, no descarga archivos de buckets ni capas de imágenes de contenedores y no adivina nombres de recursos en la nube. Cualquier acción que esta carta no describe no está autorizada.

## 5. Verificación del dominio

Para comprobar que controla el dominio, la empresa publica en él el registro TXT `cirdan-verification=[token]` que le entrega el portal y lo deja publicado mientras quiera el servicio. LowTide revisa ese registro cada día y antes de cada análisis, y si no lo encuentra no analiza.

Si la empresa verifica su dominio en Have I Been Pwned para la cuenta del equipo, LowTide consulta todo el dominio y el equipo ve qué correos aparecen en brechas. Si no lo verifica, solo se consultan los correos que LowTide encontró, y el portal marca 'sin cobertura de HIBP' donde no llega.

## 6. Datos personales

Son datos personales los correos del dominio que aparezcan en el sitio, en certificados, en commits públicos o en brechas, los usuarios de GitHub con correo del dominio, los perfiles públicos ligados al dominio y el nombre, cargo y correo de quien firma esta carta. Pueden ser de empleados, exempleados o proveedores. LowTide descarta los correos que no son del dominio.

- La empresa es la responsable de esos datos y el equipo los trata por cuenta de la empresa, solo para este análisis y con las medidas de seguridad de la política de seguridad de LowTide. Los integrantes guardan confidencialidad aun después del curso.
- Para hacer el análisis, algunos terceros reciben datos: Have I Been Pwned recibe el dominio o los correos encontrados, Shodan e InternetDB reciben las IPs del dominio, GitHub y Docker Hub reciben los nombres de la organización y de los namespaces, las fuentes de subdominios reciben el dominio y el proveedor de IA del portal recibe el título, la categoría y la severidad de los hallazgos, sin correos. LowTide se aloja en [proveedor y región].
- LowTide no guarda contraseñas ni el valor de un secreto, solo su tipo, su ubicación y una huella. Si alguno llega a guardarse por error, el equipo lo borra y avisa al contacto de la empresa en cuanto lo detecta.
- Los hallazgos resueltos, los análisis, las alertas y los reportes se borran 12 meses después. Un hallazgo abierto se conserva mientras siga abierto. Al terminar el servicio, o antes si la empresa lo pide por escrito, el equipo borra sus hallazgos, activos y reportes en un plazo de [30] días y le confirma el borrado. La carta firmada, los datos de quien firma, las verificaciones del registro TXT, los scores y la bitácora se conservan [plazo] solo como prueba de la autorización y de lo que hizo cada persona.
- Si una vulneración de seguridad afecta estos datos, el equipo avisa a la empresa en un plazo de [24] horas para que ella informe a las personas afectadas.
- Si un empleado ejerce sus derechos ARCO ante el equipo, el equipo reenvía la solicitud a la empresa en un plazo de [5] días hábiles y sigue sus instrucciones.
- La empresa informa a sus empleados de este monitoreo en su aviso de privacidad. El aviso de privacidad del equipo, para los datos de quien firma y de los usuarios del portal, está en [enlace].

## 7. Confidencialidad

Los resultados son información sensible de seguridad. Solo los ve el equipo. No se muestran a los profesores, al socio formador, en Canvas, en los repositorios públicos ni en demostraciones sin permiso escrito de la empresa o sin anonimizarlos. Las respuestas grabadas de los análisis nunca se suben a un repositorio. Lo que LowTide vea de terceros, como dominios parecidos, solo se registra como evidencia y nunca se consulta ni se contacta a sus dueños.

## 8. Vigencia, revocación y suspensión

- Esta autorización vale del [fecha de inicio] (base: valid_from) al [fecha de fin] (base: valid_until).
- La empresa la puede revocar en cualquier momento con un escrito o un correo al contacto del equipo de la sección 9. El equipo pone el dominio en pausa ese mismo día y registra la revocación en LowTide a más tardar el siguiente día hábil. Desde la pausa no se inicia ningún análisis nuevo. Un análisis que ya esté en curso termina, pero no se inicia otro.
- Una revocación no se deshace. Para volver a analizar, la empresa firma una carta nueva.
- Para suspender sin revocar, la empresa lo pide al mismo contacto y el equipo pone el dominio en pausa.
- Si la empresa quita el registro TXT de la sección 5, LowTide deja de iniciar análisis desde su siguiente revisión, sin esperar al equipo.
- Al revocar o al vencer la carta se aplica el borrado de la sección 6.

## 9. Contactos e identificación del tráfico

- Empresa, para avisos y para suspender el análisis: [nombre], [correo], [teléfono].
- Equipo: [nombre], [papel en el equipo], [correo].
- Las peticiones de LowTide salen de la IP [IP de salida] y se identifican con el User-Agent [User-Agent de LowTide], para que la empresa las reconozca y no las bloquee ni las reporte como ataque. Si la empresa ve tráfico que no corresponde a esta carta, avisa al contacto del equipo, que detiene el análisis y lo revisa.
- Los hallazgos, incluidos los críticos, se ven en el portal en cuanto termina cada análisis. El servicio es académico y no tiene un horario de atención garantizado.

## 10. Declaraciones de la empresa

- Es titular o controla el dominio, la organización de GitHub y los namespaces de Docker Hub de la sección 2, y tiene derecho a autorizar el análisis de todos sus subdominios.
- Avisará al equipo si vende o deja el dominio. En ese caso esta carta termina.
- Sabe que LowTide es un servicio académico y gratuito, sin garantía de encontrar todo lo que está expuesto.
- Conoce y acepta la política de uso ético de LowTide (`docs/politica_uso_etico.md` en el repositorio BackKL), en especial su sección 7.

## Firmas

Por [razón social]

Nombre: [nombre completo]
Cargo: [cargo]
Correo: [correo] (base: signer_email)
Fecha: [fecha]
Firma: ______________________________

Por el equipo

Nombre: [nombre completo] Firma: ______________________________
Nombre: [nombre completo] Firma: ______________________________
Nombre: [nombre completo] Firma: ______________________________
Nombre: [nombre completo] Firma: ______________________________
Fecha: [fecha]

---

## Anexo A. Actividades, fuentes y fechas previstas

| # | Actividad | Fuente | ¿Toca los servidores del dominio? | Desde (prevista) |
|---|---|---|---|---|
| 1 | Subdominios y certificados vencidos o por vencer, y dominios parecidos | Registros públicos de certificados (crt.sh y, desde el 23 oct 2026, Cert Spotter), fuentes públicas de subdominios con subfinder en modo pasivo, sin fuerza bruta, y DNS público para saber si un nombre todavía resuelve | No | 15 oct 2026 |
| 2 | Registros A, AAAA, MX, TXT y NS, y configuración de SPF y DMARC | DNS público | No, son consultas DNS normales | 21 oct 2026 |
| 3 | Registrador, fechas y vencimiento del dominio, y ubicación, proveedor y CDN de sus IPs | RDAP (WHOIS por el puerto 43 solo como respaldo) y una base local de geolocalización (DB-IP Lite) | No | 23 oct 2026 |
| 4 | Secretos expuestos y correos en commits | Repositorios públicos de la organización de GitHub ligada al dominio | No | 27 oct 2026 |
| 5 | Servicios y dispositivos expuestos | Shodan e InternetDB, con datos que ya recolectaron | No | 27 oct 2026 |
| 6 | Tecnologías web, servidor y versiones | Visita web normal a los sitios del dominio | Sí, como cualquier visitante | 6 nov 2026 |
| 7 | Correos del dominio en brechas conocidas | Have I Been Pwned, por dominio si la empresa lo verificó o por cada correo encontrado si no | No | 6 nov 2026 |
| 8 | Correos y perfiles públicos ligados al dominio | El sitio público, los commits de la organización de GitHub, los usuarios de GitHub con correo del dominio, los perfiles públicos enlazados desde el sitio y los certificados | Solo la lectura de las páginas públicas del sitio | 13 nov 2026 |
| 9 | Documentación de APIs expuesta (función extra, puede no estar disponible) | Hasta 10 rutas fijas de documentación en subdominios autorizados, solo GET y sin llamar a los servicios documentados | Sí, solo esas rutas | 13 nov 2026 |
| 10 | Almacenamiento en la nube público (función extra, puede no estar disponible) | Comprobación anónima de si un bucket se puede listar, solo cuando sale de un CNAME del dominio o cuando el sitio lo enlaza y su nombre contiene el dominio, sin listar ni descargar archivos. También detecta un CNAME que apunta a un bucket que ya no existe | No toca los servidores del dominio, pero sí hace una petición anónima al bucket en el proveedor de nube | 20 nov 2026 |
| 11 | Imágenes de contenedores (función extra, puede no estar disponible) | Configuración de las imágenes públicas de los namespaces de Docker Hub declarados en la sección 2, sin descargar sus capas | No | 23 nov 2026 |

- Las actividades 9 y 10 corren en cada análisis desde que estén disponibles. La 11 solo corre si la empresa declara namespaces de Docker Hub en la sección 2.
- Las fechas son informativas y pueden moverse. Una actividad no se realiza antes de estar disponible en el servicio, y el equipo avisa al contacto de la empresa al menos [5] días hábiles antes de activar una nueva.
- Cada fuente tiene un límite diario de consultas.
