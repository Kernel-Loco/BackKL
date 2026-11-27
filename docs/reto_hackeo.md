# Reto de hackeo para el grupo (#85, RC-157)

Otros equipos del grupo atacan LowTide para encontrar lo que se nos pasó. Cada reporte queda registrado aquí con su
arreglo, y los de severidad Alta se corrigen antes del congelamiento del 25 nov. Se muestra en S16 junto con ZAP
([`pruebas_zap.md`](pruebas_zap.md), #51) y el pentest ([`pentest.md`](pentest.md), #58b).

El marco lo fija la sección 3 de [`politica_uso_etico.md`](politica_uso_etico.md): las pruebas activas solo van contra
el despliegue de LowTide en su VM, con cuentas de prueba y sin datos reales de ninguna empresa, sin denegación de
servicio ni ingeniería social, y el reto solo empieza con permiso escrito del profesor y con estas reglas publicadas.

## Estado

| Qué | Estado | Dato |
|---|---|---|
| Permiso escrito del profesor | Pendiente de confirmar | Fecha y quién lo dio: — |
| Reglas y alcance publicados | Este documento | Se comparte con el grupo antes de la ventana |
| Ventana | Pendiente de confirmar | Planeada del 16 al 20 nov. Si no se corrió, el equipo fija otra, lejos del 25 y del 27 nov |
| Cuentas de prueba y alias de correo | Pendiente (Ernesto) | Ver «Lo que pone Ernesto antes de la ventana» |
| Reportes | Sin reportes registrados al 22 nov | Ver «Registro» |

Sin el permiso escrito, el reto no empieza.

Si la ventana nueva queda después del 25 nov, una Alta reportada en ella ya no cabe antes del congelamiento: se
corrige en cuanto se confirma y en S16 se presenta como abierta, con su plan de arreglo. Romper el congelamiento
para meter el arreglo lo decide Ernesto.

## Alcance

**Dentro:** solo `https://lowtidesec.com`, el portal y la API (`/api/v1`) que el portal reenvía, en la VM del
despliegue (#49). Se entra con las cuentas de prueba que da Ernesto: cada equipo en su propia organización de
pruebas.

**Fuera**, aunque responda o esté en la misma nube:

- Cualquier otro host o dominio: los dominios de clientes, `olmardo.com`, los dominios de demo (`acme-demo.mx` y los
  demás), `pruebas.lowtidesec.com` y la PC del plan B (RC-277).
- La infraestructura de terceros: Cloudflare, Azure, Resend, GitHub, Groq y Workers AI. Ni sus paneles ni sus cuentas.
- Las cuentas de demo, las de Grupo Olmardo, `equipo@lowtidesec.com` y las organizaciones y cuentas de prueba de
  otros equipos. Llegar a ellas es un hallazgo de severidad Alta que se reporta, no algo que se explora.
- Las personas: el equipo, el profesor y quien use el portal.

## Reglas

1. Sin denegación de servicio: nada de inundar la API, ni pruebas de carga o de agotar recursos.
2. Sin ingeniería social: no escribir al equipo, al profesor ni a nadie haciéndose pasar por otro, ni pedir
   contraseñas, códigos o enlaces.
3. Sin fuerza bruta masiva contra el login: la API bloquea por correo y por IP, y basta con mostrar que el bloqueo
   existe o que no.
4. No pedir el enlace para entrar por correo (#28, RC-63) más de lo necesario: cada correo gasta el cupo diario de
   Resend, que comparte todo el portal.
5. Sin pivotear: lo que se obtenga no se usa para atacar otros sistemas.
6. Si se llega a datos de otra organización, de un cliente o a un secreto, se para ahí, no se copian ni se guardan
   y se reporta de inmediato.
7. Se respetan las reglas de pruebas de penetración de Azure, el proveedor de la VM.
8. Solo dentro de la ventana.
9. Nada se publica antes de que el equipo corrija o justifique el reporte.

## Lo que pone Ernesto antes de la ventana

1. Una organización de pruebas por equipo, cada una con su cuenta de prueba. RLS separa organizaciones, no cuentas
   dentro de una: con una organización compartida, un equipo podría ver o cambiar lo de otro sin romper nada. Nunca
   las cuentas de demo, las de Grupo Olmardo ni `equipo@lowtidesec.com`. Las organizaciones no tienen dominios de
   clientes, así que nadie puede lanzar escaneos de terceros.
2. `pg_dump` de la VM justo antes de empezar.
3. El alias `seguridad@lowtidesec.com` con Email Routing de Cloudflare, como `arco@`, hacia el buzón del equipo.
4. La ventana lejos del 25 nov (congelamiento) y del 27 nov (sesión S16).

Sin regla de Skip en Cloudflare: a diferencia de ZAP, el grupo ataca como cualquiera desde internet, y lo que bloquee
Cloudflare cuenta como una defensa del despliegue.

## Cómo reportar

Un correo por hallazgo a `seguridad@lowtidesec.com`, con:

- Equipo y cuenta de prueba que se usó.
- Título corto.
- URL o ruta de la API.
- Pasos para reproducirlo.
- Impacto: qué se pudo ver, cambiar o hacer.
- Fecha y hora.

Sin datos de otras cuentas ni capturas con información de otras organizaciones. El equipo responde con su número de
reporte (`R-01`, `R-02`…) y lo anota en el registro.

**Datos de quien reporta.** Del correo solo se usan el nombre del equipo y el reporte. La dirección de quien escribe
y su nombre pasan por Cloudflare Email Routing hasta el buzón del equipo, como los de `arco@`, y no van al
registro ni al repo. Los correos del reto se borran al cerrar su registro, después de S16. Los avisos de tráfico que llegan al mismo alias siguen la sección 5.6 de la política de seguridad y privacidad.

## Clasificación

La hacen Germán o Ernesto, con la misma escala que el reporte de ZAP:

| Severidad | Cuándo | Qué se hace |
|---|---|---|
| Alta | Acceso a datos o cuentas de otra organización o de otro equipo, saltar el login, el MFA, RLS o la carta de autorización, ejecutar código en el servidor o leer secretos | Se corrige antes del 25 nov |
| Media | Requiere condiciones especiales o solo afecta a la propia cuenta del que reporta | Corregido o justificado |
| Baja | Endurecimiento: algo que no da acceso por sí solo | Se anota y se corrige si cabe |
| Informativa | Observación sin impacto | Se anota |

Un reporte repetido se une al primero que llegó, con el estado `duplicado`.

## Al cerrar la ventana

1. Borrar o desactivar las cuentas de prueba.
2. Revisar en la base que solo cambiaron las organizaciones de pruebas. Si algo más cambió, se revierte solo eso,
   comparando con el `pg_dump` de antes de la ventana. Nunca se restaura la base completa: borraría los cambios
   legítimos de esos días y la cadena de `audit_log`, que es de solo inserción.
3. No quitar el alias `seguridad@lowtidesec.com`: el User-Agent de LowTide y la página /seguridad mandan ahí a quien ve su tráfico.

## Registro

Una fila por reporte. Sin el exploit completo: solo lo necesario para entender el arreglo. Estados: `abierto`,
`corregido`, `justificado` o `duplicado`. Un reporte de severidad Alta no se justifica: solo sale de `abierto` como
`corregido`, con su arreglo (`#NN` del PR, su enlace o el SHA del commit), o como `duplicado`.

| ID | Fecha | Equipo | Título | Severidad | Estado | Arreglo | Por qué |
|---|---|---|---|---|---|---|---|

Al 22 nov no hay reportes registrados, y el estado del reto está por confirmar.
