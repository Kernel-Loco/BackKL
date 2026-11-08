# Política de seguridad y privacidad de LowTide

Tarjeta #78 (RC-39). Versión 1 del 7 nov 2026.

Esta política integra las reglas de la [política de uso ético y alcance](politica_uso_etico.md) de la tarjeta #6 (RC-36) en un sistema de gestión con la metodología de ISO/IEC 27001:2022 y los controles de ISO/IEC 27002:2022, y trae el aviso de privacidad conforme a la Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP, DOF 20 de marzo de 2025, última reforma DOF 14 de noviembre de 2025). Va junto con la [plantilla de carta de autorización](plantilla_carta_autorizacion.md), que remite a esta política en su sección 6.

Es un documento académico del equipo Kernel Loco, no una opinión jurídica ni una certificación. Los nombres de los controles de ISO van como identificador y nombre breve en español, sin el texto de la norma. Lo que todavía no existe se dice como pendiente en la sección 9, sin inventar datos.

## 1. Alcance

1. Cubre el servicio LowTide completo: el backend (BackKL), el portal (FrontKL), la base PostgreSQL, Valkey, la máquina virtual del despliegue, los proveedores de la sección 5.8 y las cuentas de las fuentes externas.
2. Aplica al equipo Kernel Loco, a quien contribuya a los repositorios y a las empresas que usen el servicio, que la aceptan al firmar su carta (sección 10 de la carta).
3. Cubre tres grupos de personas titulares de datos: los empleados, exempleados y proveedores de una empresa cliente cuyos datos aparecen en los hallazgos, los usuarios del portal y la persona que firma la carta.
4. Alcance territorial: empresas en México. Para una empresa en la Unión Europea faltaría el contrato de encargado del artículo 28 del RGPD, las cláusulas contractuales tipo de la Decisión de Ejecución (UE) 2021/914 para la transferencia a México y a los proveedores de IA de la sección 5.8, la evaluación de interés legítimo y el aviso a los empleados del artículo 14 del RGPD. Ese contrato también pediría cambiar la carta (subencargados, borrado o devolución al terminar y auditorías) y resolver el borrado al terminar el servicio de la sección 9. Para los proveedores de Estados Unidos cabe además el Marco de Privacidad de Datos UE y EE. UU. (Decisión de Ejecución (UE) 2023/1795).

## 2. Metodología de ISO/IEC 27001:2022

LowTide sigue las cláusulas 4 a 10 de la norma en la medida que cabe en un proyecto académico de un semestre.

| Cláusula | Qué pide | Cómo lo hace LowTide |
|---|---|---|
| 4. Contexto | Saber qué se protege, para quién y con qué límites | El reto IKUSI VELATIA, la sección 1 de esta política y el inventario de servicios de [`servicios_externos.md`](servicios_externos.md) |
| 5. Liderazgo | Una política aprobada y papeles asignados | Esta política y la de #6, aprobadas por PR a `dev`. Coordinación y OSINT, Ernesto. Seguridad, QA y documentación, Germán. Backend e infraestructura, Israel. Datos, ML y portal, Emilio |
| 6. Planificación | Evaluar riesgos y elegir controles | El modelo de amenazas STRIDE de RC-142, los riesgos aceptados que documenta el README (por ejemplo, subfinder sin verificar TLS) y la declaración de aplicabilidad de la sección 4. Reducido: no hay objetivos de seguridad medibles (cláusula 6.2) |
| 7. Apoyo | Recursos, competencia, comunicación y documentos | Las reglas del equipo, los README, la guía de cuentas de prueba y esta política, versionados en git |
| 8. Operación | Aplicar los controles | Las reglas en el código de la sección 4 y el rastro de cada análisis (#6, regla 1.10) |
| 9. Evaluación | Medir y revisar | El CI de pruebas en cada PR, CodeQL y las revisiones de PR. Las pruebas activas contra el propio despliegue llegan con #51, #58b y #85. Reducido: no hay auditoría interna (cláusula 9.2) ni revisión por la dirección (cláusula 9.3) formales |
| 10. Mejora | Corregir y aprender | Las retrospectivas de cada sprint y la sección 8 de #6 para cuando alguien rompe una regla |

Un riesgo nuevo se trata así: se anota en la tarjeta que lo encuentra, se decide si se corrige, se acepta o se evita, y si se acepta se documenta en el README o en esta política con su porqué.

## 3. Reglas que se integran de la política de uso ético (#6)

La política de #6 sigue vigente y es la que fija qué puede hacer LowTide. Esta política la toma como base y agrega los controles y la privacidad. Si las dos chocan, en alcance y actividades manda #6 y en datos personales manda esta.

| Regla de #6 | Sección de #6 | Control de la sección 4 |
|---|---|---|
| Solo dominios con carta firmada y TXT verificado, que la base exige con un trigger en `scans` | 1 | 5.15, 8.3 y 5.31 |
| Solo observación pasiva, con lista cerrada de prohibiciones | 2 | 5.10 y 5.31 |
| Lo que ataca solo va contra LowTide | 3 | 8.29 y 8.34 |
| Sin contraseñas ni valores de secretos, solo huellas | 4 | 8.11 y 5.34 |
| Borrado el mismo día de lo guardado por error y aviso a la empresa | 4 y 5 | 5.24 a 5.26 y 8.10 |
| Datos de terceros solo como evidencia | 5 | 5.34 |
| Confidencialidad y demostraciones con empresas ficticias | 6 | 5.12, 6.6 y 8.33 |
| Uso aceptable para las empresas | 7 | 5.10 |
| Qué pasa si alguien rompe las reglas | 8 | 6.4, 5.24 y 5.26 |
| Rastro de cada análisis | 1 | 8.15 y 5.33 |

## 4. Controles del Anexo A que aplican

Es la declaración de aplicabilidad de LowTide. Estado: Existe, En parte, Falta o Del proveedor, cuando lo cubre la nube.

### 4.1 Controles organizacionales

| Control | Cómo se cumple en LowTide | Estado |
|---|---|---|
| 5.1 Políticas de seguridad | Esta política y la de #6, que solo cambian por PR (sección 10) | Existe |
| 5.2 Papeles y responsabilidades | La tabla de la cláusula 5 y los responsables por rol del backlog | Existe |
| 5.3 Separación de funciones | Cada PR lo revisa otra persona según el backlog, y uno con migración o que toque RLS lo revisa Ernesto. Excepción: los PR de Ernesto no piden revisión desde el 27 oct, y los cubren el CI y CodeQL. La excepción vale también para los cambios a esta política y a la de #6, aunque la sección 11 de #6 pida la revisión de quien lleve seguridad | En parte |
| 5.7 Inteligencia de amenazas | CVSS de NVD, EPSS de FIRST y CISA KEV en la tabla `cves`, con cargador diario | Falta. La tabla existe sin filas (#69, RC-127) |
| 5.9 Inventario de activos | [`servicios_externos.md`](servicios_externos.md) lista cada servicio, cuenta, costo, llave y respaldo | Existe |
| 5.10 Uso aceptable | Secciones 2 y 7 de #6 y sección 4 de la carta | Existe |
| 5.12 Clasificación de la información | Los resultados de una empresa son información sensible de seguridad (sección 7 de la carta). Los secretos y las respuestas crudas no se guardan | Existe |
| 5.14 Transferencia de información | La sección 6 de la carta dice qué recibe cada tercero. La API y el portal van por TLS en el despliegue | En parte. El despliegue con TLS llega con RC-91 |
| 5.15 Control de acceso | Roles Analista, Gerente y Admin, y RLS con ENABLE y FORCE en las tablas por cliente | Existe |
| 5.16 Gestión de identidades | Un usuario por persona con correo único y baja lógica con `is_active`, que el login respeta. Hoy una cuenta solo se desactiva por SQL | En parte |
| 5.17 Información de autenticación | Contraseñas con argon2id y semilla TOTP cifrada con AES-256-GCM. Las llaves de la API se guardarán solo como SHA-256, según el diseño de #87, que todavía no tiene llaves ni endpoint para crearlas | Existe. Las llaves de la API, en diseño |
| 5.18 Derechos de acceso | Hoy los usuarios y sus roles solo llegan por las semillas o por SQL. El plan es que el Admin de cada empresa dé y quite roles | Falta la pantalla o la API del Admin y una revisión periódica de accesos |
| 5.19 a 5.22 Proveedores | Cada proveedor se elige por sus términos (que no entrene con los datos, que no los guarde) y se anota en `servicios_externos.md` con su fecha de revisión | En parte. No hay acuerdos firmados con los proveedores y falta revisar los términos de las fuentes de subfinder |
| 5.23 Servicios en la nube | VM en Azure for Students, DNS y Workers AI en Cloudflare, respaldo de IA en Groq. Tokens con el menor permiso y con vencimiento | En parte. La VM llega con RC-91. Falta exigir 2FA en la organización de GitHub y anotar el 2FA de cada cuenta en `servicios_externos.md` |
| 5.24 a 5.28 Incidentes | Secciones 4.2, 4.8, 5.2 y 8 de #6: se detiene, se borra, se avisa el mismo día a quien coordine y a la empresa en el plazo de la carta, y se documenta en un lugar privado | Existe como procedimiento |
| 5.29 y 5.30 Continuidad | Plan B: el mismo compose en una PC del equipo con Cloudflare Tunnel. Respaldo de la demo con respuestas grabadas | En parte. Sin prueba de recuperación escrita |
| 5.31 Requisitos legales | LFPDPPP y artículos 211 bis del Código Penal Federal (sección 6) | Existe |
| 5.32 Propiedad intelectual | `LICENSE` y `NOTICE` con las atribuciones de MITRE y CIS. De ISO solo se usan identificadores y nombres breves, sin copiar el texto de la norma | Existe |
| 5.33 Protección de registros | `audit_log` de solo inserción con cadena de hashes SHA-256. Las cartas no se editan | Existe. Falta revisar la cadena (#86) |
| 5.34 Privacidad y datos personales | La sección 5 de esta política | Existe en el documento. Ver pendientes |
| 5.36 Cumplimiento de políticas | El CI de pruebas, CodeQL y las pruebas de las reglas de #6 que corren sin red | Existe |
| 5.37 Procedimientos documentados | README de BackKL y FrontKL, `db/README.md` y la guía de cuentas de prueba | Existe |

### 4.2 Controles de personas

| Control | Cómo se cumple en LowTide | Estado |
|---|---|---|
| 6.3 Concientización | Las reglas del equipo que todos cargan al trabajar y esta política | Existe |
| 6.4 Proceso disciplinario | Lo decide el Tec con su Código de Ética y el Reglamento General de Estudiantes (sección 8.4 de #6) | Existe |
| 6.5 Responsabilidades al terminar | La confidencialidad sigue después del curso (sección 6 de la carta) | Existe |
| 6.6 Confidencialidad | Sección 6 de #6 y secciones 6 y 7 de la carta | Existe |
| 6.7 Trabajo remoto | El equipo trabaja desde sus PC. Las grabaciones reales y las bases geo no se suben a los repositorios | Existe |
| 6.8 Reporte de eventos | Quien vea un incidente avisa el mismo día a quien coordine (sección 5.2 de #6) | Existe |

### 4.3 Controles físicos

Los controles 7.1 a 7.6, 7.11 y 7.12 (perímetro, entradas, oficinas, vigilancia, amenazas físicas, trabajo en áreas seguras, servicios de soporte y cableado) son del proveedor de nube, porque LowTide no tiene instalaciones propias. Aplican seis, sobre todo a las PC del equipo:

| Control | Cómo se cumple en LowTide | Estado |
|---|---|---|
| 7.7 Escritorio y pantalla limpios | Las demostraciones solo muestran empresas ficticias (sección 6 de #6). Propuesta: bloquear la PC al dejarla | En parte |
| 7.8 Ubicación y protección de equipos | Las PC son de cada integrante y las protege cada quien. La VM la ubica y protege el proveedor | En parte. Del proveedor para la VM |
| 7.9 Equipos fuera de las instalaciones | Las PC del equipo no guardan datos reales de empresas, solo de las empresas ficticias y del dominio de prueba. Excepción: la PC del plan B (5.29) corre el compose con los datos reales mientras dure la contingencia | En parte |
| 7.10 Medios de almacenamiento | Los respaldos de la base se guardan fuera de los repositorios, que son públicos | En parte |
| 7.13 Mantenimiento de equipos | Cada integrante mantiene su PC, sin registro escrito. La VM la mantiene el proveedor | En parte. Del proveedor para la VM |
| 7.14 Borrado seguro de equipos | Propuesta: al terminar el curso se borran la VM, los respaldos y las grabaciones | Falta |

### 4.4 Controles tecnológicos

| Control | Cómo se cumple en LowTide | Estado |
|---|---|---|
| 8.1 Equipos de usuario | PC personales del equipo, sin datos reales salvo la del plan B (7.9) | En parte |
| 8.2 Accesos privilegiados | `cirdan_app` nunca es superusuario ni tiene BYPASSRLS | Existe |
| 8.3 Restricción de acceso | RLS con ENABLE, FORCE y su política en toda tabla con `organization_id`. La API toma la empresa de la sesión | Existe |
| 8.4 Acceso al código | Repos públicos sin secretos. Nadie sube directo a `dev` ni a `main` | Existe |
| 8.5 Autenticación segura | Sesión de 15 min de inactividad y 8 h como máximo, bloqueo con 5 fallos por correo o 20 por IP en 15 min, y verificación en dos pasos con TOTP en la que un código no se reusa. Hoy la verificación en dos pasos es opcional, solo la tienen las cuentas de demo y no hay endpoint para darse de alta en ella | En parte. Exigirla al Admin es el plan de RC-5 |
| 8.6 Gestión de la capacidad | Cupo diario por fuente (`data_sources.daily_limit`) que reserva cada corrida antes de consultar | Existe |
| 8.8 Vulnerabilidades técnicas | Dependabot cada semana y CodeQL con la configuración por omisión de GitHub (Python y Actions), en cada PR y cada semana | Existe |
| 8.9 Configuración | Todo en `docker-compose.yml`, con imágenes fijadas y puertos solo en 127.0.0.1 | Existe |
| 8.10 Borrado de información | Los plazos de la sección 5.6 | Falta. El rol de retención no tiene tarjeta todavía |
| 8.11 Enmascaramiento | De un secreto solo se guarda tipo, repo, ruta y huella. gitleaks corre con `--redact` | Existe |
| 8.12 Prevención de fugas | gitleaks como pre-commit, `.gitignore` de `.env` y de las grabaciones, y tokens falsos con prefijo `CIRDAN_FAKE_` | En parte. El CI no revisa secretos en el repo |
| 8.13 Respaldos | Respaldos manuales de la base antes de algunas sesiones, como las del 29 y 30 oct | En parte. Falta respaldo automático en la VM |
| 8.15 Registros | `audit_log` con quién, qué, cuándo y desde qué IP, y `scan_source_runs` por fuente | Existe |
| 8.16 Monitoreo | Alertas de presupuesto de Azure | Falta un monitoreo de la VM y de la API |
| 8.17 Sincronización de relojes | El TOTP acepta un paso de desfase y la base exige un TXT verificado en la última hora, así que los dos dependen de la hora del servidor | Falta revisar la sincronización de hora de la VM (RC-91) |
| 8.20 Seguridad de redes | Base, Valkey y API solo en 127.0.0.1. En el despliegue, Cloudflare Tunnel sin abrir puertos | En parte |
| 8.24 Criptografía | argon2id, AES-256-GCM, SHA-256 y TLS hacia las fuentes externas, salvo subfinder, que es un riesgo aceptado. Van sin cifrar las consultas DNS por el puerto 53 y el WHOIS por el puerto 43, que es el camino principal para los dominios .mx | En parte. El TLS de entrada llega con RC-91 |
| 8.25 Desarrollo seguro | Ramas por tarjeta, PR a `dev`, CI de pruebas y CodeQL | Existe |
| 8.26 Requisitos de seguridad | OWASP ASVS para sesiones y autenticación | Existe |
| 8.27 Arquitectura segura | RLS con FORCE en las tablas por cliente, rol de la API sin privilegios y base y Valkey sin puertos públicos | Existe |
| 8.28 Codificación segura | CodeQL y revisión de PR | Existe |
| 8.29 Pruebas de seguridad | ZAP activo, pentest y reto de hackeo solo contra el propio despliegue | Falta. Llegan con #51, #58b y #85 |
| 8.31 Separación de entornos | El CI corre las pruebas de base y API en una base desechable. En local corren contra la base del contenedor `cirdan-pg16`. `dev` y `main` separados | En parte |
| 8.32 Gestión de cambios | Migraciones numeradas que no se editan, PR con la clave de Jira y congelamiento desde el 25 nov | Existe |
| 8.33 Información de prueba | Empresas ficticias (Acme Demo, Beta Corp y Grupo Olmardo) y tokens `CIRDAN_FAKE_` | Existe |
| 8.34 Protección durante pruebas | Las pruebas que atacan nunca tocan a un cliente ni a terceros (sección 3 de #6) | Existe |

### 4.5 Controles reducidos y controles que no aplican

1. Reducidos: 5.4 a 5.6, 5.8, 5.11, 5.13 y 5.35 aplican a un equipo de cuatro sin auditoría externa y se cubren con la cláusula 5 y las reglas del equipo. 8.7 (malware) aplica a las PC del equipo y queda como propuesta: antivirus activo en cada PC, y en la VM solo las imágenes fijadas del compose.
2. No aplican: 6.1 y 6.2 (verificación y términos de contratación), porque no hay empleados. 8.14 (redundancia), 8.18 (programas utilitarios), 8.19 (instalación de software), 8.21 y 8.22 (servicios y separación de redes), 8.23 (filtrado web) y 8.30 (desarrollo externo), porque no hay oficina, red propia ni desarrollo externo.

## 5. Privacidad y aviso de privacidad (LFPDPPP 2025)

### 5.1 Quién responde por cada dato

| Titulares | Datos | Responsable | Papel del equipo |
|---|---|---|---|
| Empleados, exempleados y proveedores de la empresa cliente | Los de la sección 5.3 | La empresa cliente | Persona encargada: trata los datos por cuenta de la empresa (art. 2, fracción XII) |
| Usuarios del portal | Los de la sección 5.2 | El equipo | Responsable (art. 2, fracciones XIV y XVI) |
| Quien firma la carta | Nombre, cargo, correo e identificación | El equipo | Responsable |

'El equipo' son sus integrantes, personas físicas, con el nombre que dice el encabezado de la carta (art. 2, fracciones XIV y XVI). La empresa avisa a sus empleados en su propio aviso de privacidad (sección 6 de la carta). Para eso la sección 5.4 trae un texto modelo.

### 5.2 Aviso de privacidad integral de LowTide

Es el aviso del equipo para los usuarios del portal y para quien firma la carta. Sigue las fracciones del artículo 15.

1. Identidad y domicilio del responsable (fracción I): pendiente de RC-207. Ver la sección 9.
2. Datos que se tratan (fracción II):
   - De los usuarios del portal: nombre, correo, empresa, rol, la huella argon2id de la contraseña, la semilla TOTP cifrada, la fecha del último acceso, la IP de cada evento de la bitácora y, cuando exista el chatbot de #38, las preguntas que le escriban.
   - De quien firma la carta: nombre, cargo, correo, la copia de su identificación y del poder que pide la sección 1 de la carta, y la huella sha256 de la carta.
   - Ningún dato sensible (art. 2, fracción VI) ni financiero.
3. Finalidades (fracción III): dar acceso al portal y a la API, proteger las cuentas (verificación en dos pasos, bloqueo por intentos y bitácora), probar quién autorizó cada análisis y responder dudas sobre los hallazgos. Todas son necesarias para el servicio que la empresa contrató. Basta el consentimiento tácito al poner este aviso a disposición de la persona (art. 7), porque no hay datos sensibles ni financieros. No hay finalidades secundarias: los datos no se usan para publicidad, perfiles ni para entrenar modelos.
4. Opciones para limitar el uso (fracción IV): como no hay finalidades secundarias ni transferencias que pidan consentimiento, no hace falta una lista de exclusión. Quien no quiera que su pregunta llegue al proveedor de IA puede no usar el chatbot, y cada hallazgo ya trae qué significa y qué hacer.
5. Derechos ARCO (fracción V): como dice la sección 5.7.
6. Cambios al aviso (fracción VI): se avisan en el portal al iniciar sesión y por correo a los usuarios activos, con 5 días hábiles de anticipación (propuesta).
7. Revocación del consentimiento (art. 7): se pide por el buzón ARCO de RC-207, sin efectos retroactivos. Al revocar, la cuenta se desactiva y sus datos pasan al bloqueo de la sección 5.6.
8. Quién más recibe los datos: como personas encargadas que los tratan por cuenta del equipo, Cloudflare (Workers AI para el chatbot, DNS y túnel), Groq (respaldo del chatbot) y Microsoft Azure (hospedaje, región pendiente de RC-91). Las tres son empresas de Estados Unidos y pueden tratar los datos fuera de México. Al chatbot solo llega lo que dice la sección 5.8. No hay transferencias a terceros.

Aviso simplificado para el inicio de sesión y para los formularios del portal (art. 16, fracción II):

'El equipo Kernel Loco, con domicilio en [domicilio, pendiente de RC-207], trata tu nombre, correo, empresa y rol, los registros de acceso y, si usas el chat, tus preguntas, para darte acceso a LowTide, proteger tu cuenta, dejar rastro de cada análisis y responder tus dudas sobre los hallazgos. No los usamos para nada más. Si no quieres que tus preguntas lleguen al proveedor de IA, no uses el chat. El aviso de privacidad integral, con tus derechos ARCO y cómo revocar tu consentimiento, está en [enlace, pendiente de RC-207].'

### 5.3 Datos de empleados que LowTide trata por cuenta de la empresa

1. Qué datos: los correos del dominio autorizado que aparecen en el sitio, en certificados, en commits públicos o en brechas, el nombre y la fecha de cada brecha en que aparece un correo (Have I Been Pwned), los usuarios de GitHub con correo del dominio y los perfiles públicos ligados al dominio (identidad pasiva). Pueden ser de empleados, exempleados o proveedores. LowTide descarta los correos que no son del dominio.
2. Para qué: medir qué expone la empresa en internet, calcular su score y darle un plan de acción, por ejemplo, cambiar la contraseña de una cuenta que salió en una brecha o quitar un secreto de un repositorio.
3. Para qué no: nunca para vigilar, evaluar ni sancionar a un empleado (sección 4.3 de #6). Tampoco se busca a la persona fuera de las fuentes del Anexo A de la carta.
4. Por qué no basta con que el dato esté en internet: la ley solo llama fuente de acceso público a lo que se puede consultar por disposición de ley, y excluye lo de procedencia ilícita, como una brecha (art. 2, fracción X). Por eso el artículo 9, fracción II, no exime del consentimiento, y la empresa como responsable debe informar a sus empleados en su aviso de privacidad (art. 14), que vale como consentimiento tácito si no se oponen (art. 7). Como los datos no se obtienen directo de cada persona, la empresa da a conocer el cambio de su aviso (art. 17).

### 5.4 Texto modelo para el aviso de privacidad de la empresa

La empresa puede agregar este párrafo a su aviso de privacidad para empleados. Lo adapta su área legal.

'Para proteger a la empresa y a su personal, monitoreamos de forma pasiva la información pública de nuestro dominio, con el servicio LowTide. Esto puede incluir tu correo de trabajo cuando aparece en sitios públicos, en certificados, en repositorios públicos o en brechas de seguridad conocidas, con el nombre y la fecha de cada brecha, tu usuario de GitHub si usa ese correo y los perfiles públicos ligados al dominio. Para saber si tu correo salió en una brecha, se consulta en el servicio Have I Been Pwned. Nunca se guardan contraseñas ni se usan las filtradas. Los resultados solo los ven el área de seguridad y el proveedor del servicio, no se usan para evaluarte ni sancionarte. Un hallazgo se borra 12 meses después de resolverse y tu correo 12 meses después de que deje de verse en las fuentes públicas. Puedes ejercer tus derechos ARCO con [contacto de privacidad de la empresa].'

### 5.5 Minimización

1. Nunca se guardan contraseñas, hashes de contraseñas filtradas, tokens completos ni el valor de un secreto. De un secreto, solo tipo, repositorio, ruta y huella. De una brecha, solo el hecho (sección 4 de #6).
2. La base no tiene columna para contraseñas, hashes ni tokens de brechas (`breach_exposures`) y rechaza guardar la respuesta cruda de Have I Been Pwned.
3. Las fuentes que pueden traer secretos o correos van con `keep_raw_payload = false`.
4. El proveedor de IA recibe el título, la categoría y la severidad de los hallazgos, sin correos, y la pregunta que escribe el usuario (sección 5.8).
5. La evidencia nunca se copia a tablas de solo inserción, de donde no se podría borrar.

### 5.6 Retención y borrado

| Dato | Cuánto se conserva | Fuente |
|---|---|---|
| Hallazgos resueltos, análisis, alertas y reportes | 12 meses | Sección 6 de la carta |
| Hallazgo abierto | Mientras siga abierto | Sección 6 de la carta |
| Hallazgos, activos y reportes al terminar el servicio, o antes si la empresa lo pide por escrito | Se borran en un plazo de [30] días, con confirmación. Hoy el esquema no lo permite: un hallazgo que ya entró en un score no se puede borrar antes de 12 meses, ni sus activos (sección 9) | Sección 6 de la carta |
| Activos, con los correos de empleados encontrados | Se purgan tras 12 meses sin verse si ya no tienen hallazgos (plan) | Nota de `assets` en el esquema |
| Histórico del score | 12 meses | Nota de `domain_scores` en el esquema y sección 6 de la carta |
| Sesión web y verificación en dos pasos pendiente | 15 min de inactividad con un máximo de 8 h, y 5 min, en Valkey, que no guarda nada en disco. Los contadores de fallos por correo y por IP duran 15 min | `cirdan/auth/sessions.py` |
| Carta, datos de quien firma, verificaciones del TXT y bitácora | Mientras dura el servicio se usan para autorizar cada análisis. Al terminar la carta pasan a bloqueo por [plazo], solo como prueba de la autorización y de lo que hizo cada persona: en ese tiempo no se usan para nada más (art. 2, fracción III), y al final se suprimen o se anonimizan. Hoy el esquema no deja borrar ni cambiar esas tablas, así que en la práctica se guardan para siempre (sección 9) | Sección 6 de la carta. El plazo está pendiente |
| Usuarios del portal | Baja lógica. Al cancelar la cuenta se borran la huella de la contraseña y la semilla TOTP, y su nombre y correo pasan a bloqueo y al final se anonimizan. Hoy no se borran ni se anonimizan porque el esquema no lo prevé (sección 9) | Nota de `users` en el esquema |
| Algo guardado por error (un secreto o datos fuera del alcance) | Se borra el mismo día | Secciones 4.2 y 5.2 de #6 |

### 5.7 Derechos ARCO y a quién se dirigen

| Quién los ejerce | Ante quién | Qué hace el equipo |
|---|---|---|
| Empleado, exempleado o proveedor de una empresa cliente | La empresa, que es la responsable | Si la solicitud llega al equipo, la reenvía a la empresa en [5] días hábiles y sigue sus instrucciones (sección 6 de la carta). Si la persona pide el acceso creyendo que el equipo es el responsable, basta con indicarle que no lo es (art. 32), y además se reenvía a la empresa |
| Usuario del portal o quien firma la carta | El equipo, por el buzón ARCO de RC-207 | Responde como dicen los artículos 28 a 34 |

Cómo se tramita ante el equipo:

1. La solicitud trae nombre y domicilio o medio para recibir respuesta, la identificación de la persona o de su representante, qué datos (salvo en el derecho de acceso), qué derecho y cualquier otro elemento que ayude a localizar los datos (art. 28).
2. El equipo responde en un máximo de 20 días hábiles y, si procede, lo hace efectivo en los 15 siguientes. Cada plazo se puede ampliar una vez por un periodo igual (art. 31).
3. Es gratis, salvo el costo de copias o envío (art. 34).
4. Atiende las solicitudes quien coordine el equipo (art. 29, propuesta).
5. Si la persona pide cancelar su cuenta, se desactiva, se borran la huella de su contraseña y su semilla TOTP, y sus demás datos quedan en bloqueo, solo para las responsabilidades nacidas del tratamiento y por el plazo de prescripción. Al terminar el bloqueo se anonimizan su nombre y su correo y se le avisa (art. 24). La cadena de la bitácora no lo impide, porque solo usa el identificador del usuario. Hoy falta cómo hacerlo (sección 9).
6. Si el equipo no responde, o si la persona no está conforme con la respuesta, puede acudir a la Secretaría Anticorrupción y Buen Gobierno. Si hubo respuesta, tiene 15 días desde que se le comunicó (arts. 2, fracción XV, y 40).

### 5.8 Proveedor de IA y la transferencia que implica

1. El chatbot de #38, que todavía no está en el código, explicará los hallazgos en español. El proveedor principal será Cloudflare Workers AI con `gpt-oss-120b` y el respaldo Groq con el mismo modelo, que solo recibirá preguntas si Workers AI falla (decisión 4 de RC-40, 7 nov, prueba de RC-185).
2. Qué reciben: el título, la categoría y la severidad de los hallazgos de la empresa, sin correos, y la pregunta que escribe el usuario. Es el mismo texto de la sección 6 de la carta. Si el usuario escribe un dato personal en su pregunta, ese dato llega al proveedor. Por eso el portal pedirá no escribir datos personales en el chat.
3. Qué hacen con eso: ninguno de los dos entrena con las preguntas ni las guarda después de la petición. Cloudflare por los términos de uso de datos de Workers AI y Groq por su Services Agreement (4.2) con Zero Data Retention activado (`servicios_externos.md`, revisado el 7 nov).
4. Dónde: son empresas de Estados Unidos y pueden procesar fuera de México. Es una comunicación internacional de datos.
5. Cómo se califica: los proveedores tratan los datos solo para responder por cuenta del equipo, como personas encargadas. La ley no llama transferencia a la comunicación a una persona encargada (art. 2, fracción XX). Que lo sean depende de sus términos, que no se han revisado con un abogado (sección 9). El aviso integral los nombra en su punto 8, como pide la tarjeta. Si se considerara transferencia, el aviso tendría que traer la cláusula para aceptarla o no y el equipo tendría que comunicar el aviso al proveedor (art. 35), o caber en un caso del artículo 36.
6. Otros proveedores que reciben datos para dar el servicio, también como encargados: Azure, que aloja la VM (región pendiente de RC-91), y Cloudflare, para DNS y el túnel.
7. Las fuentes de la sección 6 de la carta no son encargadas: Have I Been Pwned, Shodan, GitHub y las demás dan su propio servicio con sus términos. Son terceros que reciben la consulta: el dominio, las IPs o los correos encontrados, nunca datos de usuarios del portal. Mandar a Have I Been Pwned los correos de empleados puede ser una transferencia de la empresa, que es la responsable. Por eso la carta la nombra en su sección 6 y el texto modelo de la sección 5.4 se la avisa a los empleados. Si el área legal de la empresa la califica como transferencia, su aviso debe traer además la cláusula para aceptarla o no (art. 35), o caber en un caso del artículo 36.

### 5.9 Vulneraciones de seguridad

Si una vulneración afecta datos de una empresa, el equipo le avisa en [24] horas (sección 6 de la carta) para que ella informe de inmediato a sus empleados afectados (art. 19). Si afecta datos de usuarios del portal o de quien firma, el equipo les avisa directo y de inmediato. En los dos casos se sigue la sección 4.8 de #6 y se avisa al profesor.

## 6. Validez legal

1. LowTide solo observa información pública, con carta firmada y TXT verificado. Esa es la base para no caer en el acceso ilícito del Código Penal Federal: el artículo 211 bis 1 castiga a quien sin autorización modifique, destruya, provoque pérdida, conozca o copie información de sistemas protegidos por algún mecanismo de seguridad, con 3 meses a 2 años de prisión según el caso. Las penas son mayores si los sistemas son del Estado o de seguridad pública (art. 211 bis 2) o de instituciones del sistema financiero (art. 211 bis 4), y suben hasta en una mitad si la información se usa en provecho propio o ajeno (art. 211 bis 7). El detalle está en la sección 9 de #6.
2. La LFPDPPP obliga al responsable a seguir los principios de licitud, finalidad, lealtad, consentimiento, calidad, proporcionalidad, información y responsabilidad (art. 5), a dar un aviso de privacidad con lo que pide el artículo 15, a tener medidas de seguridad administrativas, técnicas y físicas (art. 18), que son los controles de la sección 4, y a guardar confidencialidad aun después de terminar la relación (art. 20).
3. Incumplir tiene multas desde 100 hasta 320,000 veces la UMA, más una multa adicional de 100 a 320,000 veces la UMA si las infracciones persisten, y con datos sensibles pueden subir hasta el doble (arts. 58 y 59) y la ley tipifica como delito provocar con ánimo de lucro una vulneración de las bases bajo custodia (art. 62).
4. La autoridad es la Secretaría Anticorrupción y Buen Gobierno (art. 2, fracción XV), que tomó las funciones del INAI.
5. El Reglamento que cita la ley todavía debe armonizarse con ella (transitorio Décimo Segundo del decreto). Esta política no se apoya en el Reglamento, salvo en las medidas compensatorias del artículo 17 para avisar a exempleados con los que la empresa ya no tiene contacto, que la ley remite a él.
6. Esta política no reemplaza la revisión del área legal de cada empresa. La carta, la verificación del TXT y la bitácora son la prueba de que cada análisis estaba autorizado.

## 7. Pros y contras

| Decisión | Pros | Contras |
|---|---|---|
| Solo observación pasiva | No toca los sistemas de la empresa, queda fuera del artículo 211 bis 1 y es lo que pide el reto | No confirma si un servicio expuesto es explotable |
| Carta firmada y TXT verificado, exigidos por la base | Prueba de autorización y de control del dominio, que no depende de la disciplina del equipo | Alta más lenta para la empresa |
| La empresa es la responsable y el equipo el encargado | Pone el aviso a los empleados en quien tiene la relación con ellos | La empresa debe cambiar su aviso antes del primer análisis |
| Solo huellas, nunca valores ni contraseñas | Un robo de la base no filtra secretos ni contraseñas | No se puede mostrar el secreto exacto, solo dónde está |
| 12 meses de retención | Alcanza para la tendencia del score | Falta el rol que borra (sección 9) |
| IA en la nube con plan gratis | 0 USD, sin GPU propia, sin entrenar con los datos | Datos fuera de México y cupo diario limitado |
| Alcance solo en México | Un solo marco legal, más simple de cumplir | Una filial europea del socio no puede usarlo todavía |
| Documento académico | Rápido de mantener junto con el código | No es una opinión jurídica ni una certificación |

## 8. Cómo se usa en las entregas

1. En la sesión S14 (13 nov) se muestra el resumen: alcance, controles, aviso y pendientes.
2. Alimenta el documento integrado de Etapas (#59, 27 nov) y la presentación al consejo (#61).
3. La hoja de ruta (RC-161) lleva una línea sobre el alcance territorial del punto 4 de la sección 1.

## 9. Pendientes

| Pendiente | De qué depende |
|---|---|
| Identidad y domicilio del responsable, buzón ARCO y enlace del aviso integral en la carta y en el portal | RC-207, que espera la compra de lowtidesec.com (RC-204) |
| Proveedor y región del hospedaje, que la carta deja como [proveedor y región] | La VM de RC-91 |
| Plazo de conservación de la carta, de los datos de quien firma, de las verificaciones del TXT y de la bitácora, que la carta deja como [plazo]. Debe ser el plazo de prescripción, con supresión o anonimización al final. Hoy el esquema no deja borrar ni cambiar `domain_authorizations`, `dns_txt_verifications` ni `audit_log`, ni prevé anonimizar `users`, así que esos datos se guardan para siempre. La cadena de hashes de `audit_log` solo usa el identificador del actor, así que anonimizar nombre y correo de `users` no la rompe | Decisión del equipo y tarjeta de base por crear |
| Rol de retención que borre lo de más de 12 meses | Tarjeta por crear |
| Borrado en [30] días al terminar el servicio: hoy no se puede, porque `score_contributions` referencia a `findings` y solo el rol de retención puede borrar scores, y solo los de más de 12 meses. Hace falta una excepción por organización o anonimizar antes de prometerlo | Tarjeta de base por crear |
| Cancelación de un usuario del portal: hoy solo hay baja lógica, y una cuenta solo se desactiva por SQL. Falta el bloqueo y la anonimización de su nombre y correo, y avisarle al terminar (art. 24) | Tarjeta por crear |
| Que Cloudflare, Groq y Azure sean personas encargadas según sus términos, y cómo se califica mandar correos de empleados a Have I Been Pwned | Revisión legal, antes del primer cliente real |
| Página del aviso de privacidad y aviso simplificado en el portal | Tarjeta de FrontKL por crear, después de RC-207 |
| Revisión periódica de accesos, monitoreo, respaldo automático y prueba de recuperación | El despliegue de RC-91 |
| Documentos del RGPD del punto 4 de la sección 1 | Solo si una empresa de la Unión Europea lo pide |

## 10. Cambios a esta política

Como la de #6, cambia solo por PR a `dev`, con revisión de quien lleve seguridad en el equipo, o de quien le toque revisar según el backlog si esa persona hizo el cambio (sección 11 de #6). Los PR de Ernesto no piden revisión desde el 27 oct (control 5.3). Un cambio que amplíe qué datos se tratan o quién los recibe cambia también la sección 6 de la carta y se avisa a las empresas y a los usuarios como dice el punto 6 de la sección 5.2.
