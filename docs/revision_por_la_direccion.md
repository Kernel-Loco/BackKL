# Revisión por la dirección de LowTide (ISO/IEC 27001:2022, cláusula 9.3)

Tarjeta #178 (RC-296). Acta de la primera revisión por la dirección del sistema de gestión de la [política de seguridad y privacidad](politica_seguridad_privacidad.md) LT-POL-001, versión 2.6.

## Datos de la revisión

1. Fecha: 24 nov 2026. Corte de los datos: 22:36 (hora de Monterrey), con BackKL `origin/dev` en 6a44872.
2. Quién la hizo: Ernesto De Luna Quintero, que coordina el equipo y responde por la política y sus objetivos (cláusula 5 y sección 2.1 de la política). Es la dirección del sistema de gestión de LowTide.
3. Cómo: Claude Code, un asistente de IA, juntó los datos con los comandos de la sección 2.1 y redactó el acta. Ernesto la firma al aprobar el PR que la trae (sección 10 de la política), y con eso quedan tomadas las decisiones de abajo.
4. Revisión anterior: ninguna, es la primera.

## Entradas

### 1. Acciones de la revisión anterior

No hay, porque es la primera. Las acciones de esta revisión son las decisiones del final y la siguiente revisión empieza por ellas.

### 2. Cambios de contexto y de partes interesadas

1. LowTide corre en una VM de Azure for Students con el portal en lowtidesec.com desde el 15 nov 2026 (RC-91 en Done).
2. La versión v1.0-rc quedó etiquetada el 24 nov 2026 (commit 597034c). El código se congela el 25 nov, la sesión con el socio S16 es el 27 nov y la final el 4 dic.
3. Proveedores nuevos desde la versión 2.0 de la política: Resend para el correo de inicio de sesión (RC-289), Groq como respaldo del asistente de IA (RC-77) y Have I Been Pwned con el plan Core 1 para olmardo.com, comprado el 23 nov (RC-54, comentario 10612, y recibo en el comentario 10611 de RC-40). Su renovación se canceló, así que vale hasta el 24 dic 2026. `servicios_externos.md` todavía no lo dice (H3 de la auditoría).
4. Funciones nuevas que cambian el tratamiento de datos o el acceso: passkeys (RC-331), la consola multiempresa del operador (RC-332) y el asistente de IA (RC-77). Cada una cambió la política con su PR.
5. Partes interesadas sin cambio: IKUSI VELATIA como socio formador, los profesores del Tec y el equipo. Grupo Olmardo sigue como empresa ficticia de demostración, ahora con cuentas reales en la VM que da de alta Ernesto. No hay ningún cliente real.

### 3. Desempeño de la seguridad

Medición de los objetivos de la sección 2.1, con los mismos comandos y fuentes que la línea base del 17 nov.

| Objetivo | Resultado del 24 nov | Meta | Cumple |
|---|---|---|---|
| 1. Pruebas en cada cambio | 219 de 219 PR fusionados en `dev` con el job `pruebas` en verde. BackKL, 177 de 177, del PR 77 al 286. FrontKL, 42 de 42, del PR 85 al 141 | 100 % | Sí |
| 2. Alertas atendidas | 1 abierta: la alerta 8 de CodeQL en BackKL, `py/overly-large-range`, media, en `cirdan/recolectores/portada.py:79`, desde el 18 nov (PR 204, RC-228). FrontKL, 0. Dependabot, 0 abiertas en los dos. Descartadas sin motivo, 0: las 4 descartadas de BackKL tienen su comentario | 0 y 0 | No |
| 3. Parches al día | BackKL PR 196 (grupo pip), abierto el 17 nov a las 22:45. Al corte de las 22:36 lleva 6 días y 23 h 51 min, y pasa de 7 días a las 22:45, antes de que termine el 24 nov. FrontKL PR 127 a 131, abiertos el 23 nov | 0 de más de 7 días al 24 nov | Sí al corte, no al cierre del 24 nov |
| 4. Pendientes de la sección 9 con decisión | Desde la línea base del 17 nov, 3 de sus 19 filas se cerraron al quitarse con los PR 199 (RC-274), 200 (RC-289) y 202 (RC-271), y RC-255 sumó 1 fila nueva. Quedan 17, ninguna aceptada con quién, cuándo, por qué y hasta cuándo antes de esta revisión. Esta revisión acepta las 17 (decisión 1) | Todas | En parte: las 17 quedan aceptadas en esta acta, pero la tabla de la sección 9 todavía no lo dice (decisión 9) |
| 5. Revisión de accesos | 0 revisiones. RC-259 sigue en To Do | La primera antes del 25 nov | No |

Otros datos de desempeño: Dependabot corre cada semana y CodeQL en cada PR y cada semana, y los checks obligatorios de las ramas siguen como los dejó RC-254 (control 5.3 de la auditoría).

### 4. Resultados de la auditoría interna

La [auditoría interna](auditoria_interna.md) del 24 nov revisó 13 de los 36 controles marcados 'Existe': 9 conformes, 3 conformes con una observación y 1 no conformidad menor. Hallazgos:

1. H1, no conformidad menor: BackKL `dev` acepta force push (control 8.4).
2. H2, observación: el control 5.33 dice que falta revisar la cadena de la bitácora, que ya se revisa con `GET /api/v1/audit-log/verify`.
3. H3, observación: 5.14, 8.13, 8.15 y 8.24 siguen esperando a RC-91 o RC-233, que ya están en Done, y `servicios_externos.md` dice que el plan Core 1 de Have I Been Pwned está sin comprar.
4. H4, observación: la imagen propia fija la versión menor de Python y no el parche.
5. Limitación: la hizo Ernesto, que escribió la política, así que no es imparcial (sección 4 de la auditoría).

### 5. Objetivos

Se cumple 1 de 5 y el 4 en parte. El 4 queda completo cuando la tabla de la sección 9 cite esta acta. El 2 falla por la alerta 8, que se corrige dentro del congelamiento (decisión 4). El 3 falla por PR de Dependabot que el congelamiento deja fuera (decisión 5). El 5 porque la revisión de accesos depende de RC-259. Los objetivos siguen siendo los cinco de la sección 2.1, sin cambiar sus metas.

### 6. Riesgos

1. El modelo de amenazas STRIDE de RC-142 sigue vigente (RC-142 en Done).
2. Los 17 pendientes de la sección 9 son los riesgos conocidos que no se corrigen antes del congelamiento. Se aceptan en la decisión 1.
3. Riesgo nuevo de la auditoría: el force push en BackKL `dev` (H1).
4. La cuenta Blayt05 sin 2FA en la organización Kernel-Loco sigue como excepción aceptada el 22 nov (control 5.23).
5. Have I Been Pwned deja de responder para olmardo.com después del 24 dic 2026, cuando vence el plan Core 1. Para la final del 4 dic no cambia nada.

### 7. Oportunidades de mejora

1. Que la siguiente auditoría la haga alguien que no escribió la política.
2. Corregir H1 a H3 con las tarjetas propuestas.
3. Que la revisión de accesos tenga su ruta con RC-259 y el monitoreo de RC-260 mande datos, para que entren como objetivos medibles.

## Decisiones

1. Se aceptan las 17 filas de la sección 9 de la política, con lo que dice la tabla de abajo. Las acepta Ernesto De Luna Quintero el 24 nov 2026. El motivo común es que no hay ningún cliente real: solo se firman y se cargan cartas de las empresas ficticias y del dominio de prueba (fila 1 de la sección 9).
2. H1 se corrige con la tarjeta propuesta en la auditoría, 'BackKL: `dev` sin force push, igual que `main`'. Ernesto cambia la configuración de GitHub después de crearla.
3. H2 y H3 se corrigen con la tarjeta propuesta 'Política y servicios externos: textos al día tras RC-91, RC-233 y RC-54'. H4 se acepta hasta la siguiente auditoría.
4. Objetivo 2: la alerta 8 se corrige con una tarjeta nueva, 'Recolector de portada: rango de caracteres de la alerta 8 de CodeQL'. Está lista cuando la alerta 8 queda cerrada en GitHub como corregida, `portada.py` sigue quitando de la evidencia los mismos caracteres de control y una prueba lo comprueba. Es una corrección de un error, así que entra en el congelamiento. Su plazo del control 8.8, 30 días por ser media, vence el 18 dic.
5. Objetivo 3: se acepta que los PR de Dependabot abiertos (BackKL 196 y FrontKL 127 a 131) esperen hasta después de la final del 4 dic, porque desde el 25 nov solo entran correcciones de errores (regla 5 del equipo). Si uno trae una vulnerabilidad alta o crítica, entra antes, con los plazos del control 8.8.
6. Objetivo 5: se acepta sin cumplir hasta RC-259. Si RC-259 no llega antes de la final del 4 dic, Ernesto hace la revisión de las cuentas reales de la VM a mano y la escribe en la política con su fecha, como prevé el objetivo.
7. La siguiente auditoría interna la hace alguien que no escribió la política, antes del primer cliente real o en el siguiente semestre, lo que llegue antes, con una muestra que empiece por los 23 controles 'Existe' que no entraron en esta.
8. La siguiente medición de los objetivos va antes de la final del 4 dic (sección 2.1). La siguiente revisión por la dirección va antes del primer cliente real o tras el primer mes de datos de RC-260, lo que llegue antes, y empieza por estas decisiones.
9. La sección 2.1 suma el resultado del 24 nov y la tabla de la sección 9 cita esta acta en el siguiente cambio de la política, después de que se fusione RC-272 (en To Do en Jira), que también cambia la sección 9. Mientras, la fila de la cláusula 9 de la sección 2 remite a esta acta.
10. Las tres tarjetas de las decisiones 2 a 4 se crean en Jira con el OK de Ernesto, con el texto de este documento.

### Pendientes aceptados de la sección 9

| Fila de la sección 9 | Por qué se acepta | Hasta cuándo |
|---|---|---|
| Identidad y domicilio del responsable de los datos del portal y de quien firma | No hay cliente real y la fila ya prohíbe firmar o cargar su carta | El primer cliente real |
| Proveedor y región del hospedaje en la carta | La VM ya corre en Azure (RC-91), pero las cartas vigentes son de empresas ficticias y del dominio de prueba | El siguiente cambio de la carta o el primer cliente real, lo que llegue antes |
| Plazo de conservación de la carta, de quien firma, del TXT, de la bitácora y de las solicitudes ARCO | Los datos guardados son de empresas ficticias y del dominio de prueba, y el plazo lo decide el equipo | El cierre del curso, el 4 dic 2026, cuando se decide qué se exporta (control 7.14) |
| Rol de retención de 12 meses | Ningún dato del servicio tiene 12 meses, porque el proyecto empezó en oct 2026 | El 1 oct 2027 o el primer cliente real, lo que llegue antes |
| Borrado en [30] días al vencer o revocarse la última carta | No hay cliente real cuyos datos haya que borrar | El primer cliente real |
| Cancelación de un usuario del portal | Las cuentas son del equipo, de las empresas ficticias y de Grupo Olmardo, y las da de alta y de baja el equipo | El primer cliente real |
| Cortar las sesiones al desactivar una cuenta o cancelar una empresa | Una sesión dura 8 h como máximo y las cuentas las maneja el equipo | El primer cliente real |
| Carreras del bloqueo que quedan | Solo dejan revisar unos intentos de más con peticiones en paralelo, y el Admin sigue con verificación en dos pasos obligatoria | La primera versión después de la final del 4 dic |
| IP real en la bitácora y en el bloqueo por IP | RC-91 ya está en Done y falta revisar si la VM pasa la IP real (H3) | La tarjeta de H3 |
| Guardar en `observed_values` solo el TXT de verificación | Lo lleva RC-272, en To Do | Que se fusione RC-272 |
| Cartas de un dominio, revocación y cambios a la carta y a #6 | RC-272 lleva la parte de base, y la carta y #6 cambian antes del primer cliente real | Que se fusione RC-272 para la base, y el primer cliente real para la carta y #6 |
| Canal ARCO durante el bloqueo, después del curso | Es una decisión del equipo para cuando termine el curso | El cierre del curso, el 4 dic 2026 |
| Encargados, papel del Tec, Have I Been Pwned y revisión legal | No hay cliente real. Lo de Have I Been Pwned con olmardo.com ya se revisó el 23 nov | El primer cliente real |
| Campo en la carta para un integrador | Ningún integrador lo ha pedido | Que un integrador lo pida |
| Revisión de accesos, monitoreo, respaldo automático y prueba de recuperación | RC-259 y RC-260 siguen en To Do. RC-233, el respaldo diario, ya está en Done y su parte se revisa con H3 | RC-259 y RC-260, y la decisión 6 para la revisión de accesos |
| 2FA obligatoria en Kernel-Loco | La aceptó Ernesto el 22 nov por la cuenta Blayt05 | Que Blayt05 active su 2FA o el cierre del curso, lo que llegue antes |
| Documentos del RGPD | El alcance territorial es México (sección 1, punto 4) | Que una empresa de la Unión Europea lo pida |
