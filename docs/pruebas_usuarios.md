# Pruebas con usuarios en la VM (#50, RC-93)

Tres personas ajenas al equipo hacen solas, con un guion, las 5 tareas básicas de LowTide en el despliegue de la VM
(#49): entrar, dar de alta un dominio, ver el score y su porqué, revisar el plan de acción y descargar un reporte. Se
anota si completan cada tarea, cuánto tardan y dónde se atoran. Al final contestan el cuestionario SUS (propuesta de
Ernesto del 4 nov). Cada tarea que alguien no completa queda en una tarjeta con su arreglo. Este documento es el
reporte y se presenta en S16 (#54, 27 nov).

`pruebas/test_pruebas_usuarios.py` revisa el guion, que no haya datos personales y, cuando ya hay resultados, que cada
SUS, el promedio y el resumen salgan de las respuestas.

## Estado

| Qué | Estado |
|---|---|
| Fecha de las sesiones | Pendiente: antes del congelamiento del 25 nov |
| Quién modera y quién anota | Pendiente |
| Las 3 personas | Pendiente: reclutadas, sin datos aquí |
| Cuentas, cartas de prueba y `pg_dump` en la VM | Pendiente (Ernesto) |
| Resultados | Sin sesiones todavía |

## Quiénes participan

Tres personas que no son del equipo y nunca han usado LowTide. No necesitan saber de seguridad: el producto es para
quien dirige TI en una pyme, y la prueba busca lo que alguien nuevo no entiende.

Aquí solo aparecen como **P1, P2 y P3**, con un perfil general («estudiante de otra carrera», «trabaja en TI»). Nunca
su nombre, correo, teléfono, edad exacta ni escuela o empresa.

## Lo que pone Ernesto antes de las sesiones

1. **Tres cuentas de rol `admin` en Grupo Olmardo**, la empresa ficticia del equipo, que ya tiene olmardo.com
   escaneado: `pruebas-p1@lowtidesec.com`, `pruebas-p2@lowtidesec.com` y `pruebas-p3@lowtidesec.com`.
   - Sin MFA: la tarea 1 es correo, contraseña y captcha.
   - Cada contraseña va en una tarjeta de papel que se le da a la persona al empezar.
   - Los correos son del equipo a propósito: `audit_log` es de solo inserción y guarda quién entró. Así no queda
     ningún dato de los participantes en la base.
2. **olmardo.com con un escaneo reciente y su carta vigente.** Sin carta vigente, el reporte de la tarea 5 da 403.
3. **Una carta de prueba en PDF por persona**, con la plantilla, para `prueba-p1.example`, `prueba-p2.example` y
   `prueba-p3.example`. Son dominios ficticios: pasan la validación del alta y nunca se verifican, así que nunca se
   escanean. Cada persona usa uno distinto, porque el mismo dominio dos veces en una empresa da 409; si las sesiones
   se repiten, se usan nombres nuevos (`prueba-p1b.example`), porque uno dado de baja sigue ocupando el suyo. El PDF va
   en el escritorio de la laptop.
   - **Quien firma es ficticio y va impreso en la carta y en la tarjeta de la tarea:** «Firmante de Prueba», cargo
     «Director de TI», correo `pruebas-firma@lowtidesec.com`, vigencia de hoy a fin de año y las actividades que
     trae la carta. El alta guarda esos datos en `domain_authorizations`, que no se puede borrar: nunca deben ser los
     de la persona que hace la prueba.
4. **`pg_dump` de la VM** antes de la primera sesión.
5. **La laptop del equipo**, con un navegador limpio. Entre persona y persona: cerrar sesión, borrar historial y
   descargas, y dejar el PDF de la siguiente. Las sesiones son en persona y en esa laptop: la IP que queda en la
   bitácora es la del equipo.

## Consentimiento

Quien modera lo lee en voz alta y la persona lo firma en papel antes de empezar:

> Te invitamos a probar LowTide, un proyecto escolar del equipo. Vas a hacer 5 tareas cortas en el sitio y al final
> contestar 10 preguntas. Lo que evaluamos es el sitio, no a ti: si algo no se entiende, es un problema nuestro.
> Tomamos notas y medimos el tiempo de cada tarea; no grabamos la pantalla, ni tu voz, ni tu cara. Usas una cuenta de
> prueba del equipo y una empresa ficticia: no escribes datos tuyos. En el reporte del proyecto solo apareces como
> «P1», «P2» o «P3» con una descripción general, sin tu nombre. Puedes parar cuando quieras, sin dar razones. Esta
> hoja se guarda fuera del repositorio y se destruye al cerrar el curso.

Las hojas firmadas no van al repo. Se guardan fuera de línea y se destruyen al cerrar el curso, como los demás datos
de la sección 5.6 de [`politica_seguridad_privacidad.md`](politica_seguridad_privacidad.md).

## Protocolo de quien modera

1. Dos personas del equipo: una modera y otra anota. Quien anota lleva el cronómetro y la hoja de la sección
   Resultados.
2. Se lee la introducción tal cual:

   > Gracias por ayudarnos. Imagina que diriges TI en Grupo Olmardo y tu jefa te pidió revisar qué tan expuesta está
   > la empresa en internet. Te voy a leer 5 tareas, una por una. Mientras las haces, di en voz alta lo que piensas,
   > lo que buscas y lo que te confunde. No te puedo decir dónde hacer clic: eso es lo que queremos ver. Si te atoras,
   > dímelo y pasamos a la siguiente.

3. Cada tarea se lee tal cual, se le da a la persona en una tarjeta y el cronómetro empieza al terminar de leerla.
4. Lo que sí se contesta: repetir la tarea, «Haz lo que harías tú» y «¿Qué esperabas ver?». Lo que no: dónde está algo,
   qué botón usar o si va bien.
5. **Una tarea se da por no completada** si la persona pide ayuda y se le da, se rinde o pasa su tiempo límite. Se le
   dice «Gracias, pasemos a la siguiente» y se deja el sitio donde la siguiente tarea pueda empezar.
6. Quien anota escribe, por tarea, si se completó, el tiempo (`mm:ss`) y **dónde se atoró**: la pantalla y lo que
   buscaba o dijo. Una tarea completada también puede tener dónde se atoró.
7. Al terminar las 5 tareas, la persona contesta el cuestionario SUS en papel, sin que nadie del equipo lo vea
   mientras lo llena.

## Guion de las tareas

### T1 · Entrar

**Se lee:** «Entra a LowTide con la cuenta de la tarjeta.»

**Éxito:** ve el tablero de Grupo Olmardo.

**Límite:** 3 min

### T2 · Dar de alta un dominio

**Se lee:** «Grupo Olmardo compró otro dominio, el de la tarjeta. Agrégalo a LowTide con la carta de autorización que
está en el escritorio. Los datos de quien firma vienen en la tarjeta.»

**La tarjeta trae:** el dominio (`prueba-p1.example`…) y los datos ficticios de quien firma. Si la persona empieza a
escribir datos suyos, quien modera la detiene y le señala la tarjeta: eso no cuenta como ayuda.

**Éxito:** el dominio aparece en la lista de dominios, aunque falte verificar su TXT.

**Límite:** 8 min

### T3 · Ver el score y su porqué

**Se lee:** «¿Qué calificación tiene olmardo.com? ¿Cuál es el hallazgo que más la baja y por qué es grave?»

**Éxito:** dice la calificación (letra o número) y nombra el hallazgo que más pesa, con su explicación en sus palabras.

**Límite:** 8 min

### T4 · Revisar el plan de acción

**Se lee:** «Si solo pudieras arreglar una cosa esta semana en olmardo.com, ¿cuál sería según LowTide y cuánto
mejoraría la calificación?»

**Éxito:** dice la primera acción del plan y su impacto estimado.

**Límite:** 3 min

### T5 · Descargar un reporte

**Se lee:** «Tu jefa quiere un reporte de olmardo.com para leerlo en su computadora. Descárgalo.»

**Éxito:** queda en descargas el reporte ejecutivo de olmardo.com, en PDF o en HTML. La tarjeta «Reportes» de
Histórico trae datos de ejemplo: si la persona descarga de ahí, no cuenta como éxito y se anota dónde se atoró.

**Límite:** 3 min

## Cuestionario SUS

La System Usability Scale (Brooke, 1996), en la versión en español de Sevilla-Gonzalez y colaboradores (JMIR Human
Factors, 2020). Cada frase se contesta de 1 (totalmente en desacuerdo) a 5 (totalmente de acuerdo). Ernesto revisa la
redacción contra la publicada antes de imprimirla.

1. Creo que me gustaría usar este sistema con frecuencia.
2. Encontré el sistema innecesariamente complejo.
3. Pensé que el sistema era fácil de usar.
4. Creo que necesitaría el apoyo de una persona con conocimientos técnicos para poder usar este sistema.
5. Encontré que las distintas funciones del sistema estaban bien integradas.
6. Pensé que había demasiada inconsistencia en el sistema.
7. Imagino que la mayoría de las personas aprendería a usar este sistema muy rápido.
8. Encontré el sistema muy complicado de usar.
9. Me sentí muy seguro al usar el sistema.
10. Necesité aprender muchas cosas antes de poder empezar a usar este sistema.

**Cálculo:** a cada respuesta impar se le resta 1, y a 5 se le resta cada respuesta par. Las 10 cifras se suman y la
suma se multiplica por 2.5. Da de 0 a 100. Como referencia, 68 es el promedio de muchos estudios.

## Al cerrar

1. Desactivar las cuentas `pruebas-p1`, `pruebas-p2` y `pruebas-p3`.
2. Dar de baja los dominios `prueba-p*.example` de Grupo Olmardo: `status = 'removed'` en `domains` y `revoked_at` en
   su fila de `domain_authorizations`. No se borran: `domain_authorizations` solo deja fijar `revoked_at`.
3. Revisar en la base que solo cambió lo esperado. Lo que queda, y está bien que quede porque no trae datos de los
   participantes:
   - las filas de `domain_authorizations` de los dominios ficticios, con el firmante ficticio, y sus cartas cifradas;
   - en `audit_log`, que es de solo inserción, los inicios de sesión de las cuentas `pruebas-p*`, con la IP de la red
     del equipo, y el alta de cada dominio ficticio.

   Si cambió algo más, como un dato de olmardo.com o de otra empresa, se restaura con el `pg_dump`.
4. Guardar las hojas de consentimiento y las del SUS fuera del repo, y pasar aquí solo P1, P2 o P3, el perfil y las
   respuestas.

## Resultados

### Participantes

| Persona | Perfil | Fecha |
|---|---|---|

### Tareas

| Persona | Tarea | Completada | Tiempo | Dónde se atoró |
|---|---|---|---|---|

### SUS

| Persona | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | SUS |
|---|---|---|---|---|---|---|---|---|---|---|---|

SUS promedio: pendiente

### Hallazgos y tarjetas

Cada tarea no completada va aquí con su arreglo, y su tarjeta se crea en Jira con ese texto; en la columna Tarjeta va
su clave (`RC-NNN`). Lo que se atoró en una tarea completada también puede ir, como mejora.

| ID | Persona | Tarea | Dónde se atoró | Arreglo propuesto | Tarjeta |
|---|---|---|---|---|---|

### Para S16

El tiempo mediano es el de quienes completaron la tarea, redondeado al segundo (medio segundo hacia arriba).

| Tarea | Completaron | Tiempo mediano |
|---|---|---|
