# Política de uso ético de Cirdan

## Objetivo

Esta política define el marco ético y operativo para el uso de Cirdan, la plataforma de gestión de la superficie de ataque externa con observación pasiva. Tiene como fin asegurar que el análisis se haga solo sobre dominios con autorización expresa, sin afectar ni poner en riesgo los sistemas del cliente.

## Alcance

Aplica a:

- usuarios del portal,
- analistas y administradores,
- el orquestador, los recolectores y los servicios de lectura pública,
- todo uso de la plataforma con dominios y organizaciones gestionadas por Cirdan.

## Regla 1: solo dominios autorizados

Cirdan solo puede revisar, analizar y registrar dominios con una autorización vigente en la base de datos. Esto incluye:

- una carta de autorización firmada por quien tiene facultad sobre el dominio,
- una vigencia activa en la tabla `domain_authorizations`,
- ausencia de revocación de la autorización,
- validación del dominio y del registro TXT cuando corresponde antes del escaneo.

Si no existe una autorización válida, el dominio no puede ser escaneado ni analizado como parte de la superficie del cliente.

## Regla 2: observación pasiva, nunca ataque

El uso de Cirdan es exclusivamente de observación pasiva. Esto significa que:

- solo se consultan fuentes públicas y autorizadas,
- no se prueba ni se explota vulnerabilidad alguna,
- no se intenta acceder a servicios internos ni a infraestructura no autorizada,
- no se realizan pruebas de penetración ni ataques de ningún tipo,
- no se toca ni se altera el servidor del dominio salvo lo estrictamente necesario para verificar la identidad del dominio en DNS o una autorización pública.

La intención del proyecto es analizar riesgo, no comprometer sistemas ni causar interrupciones.

## Regla 3: datos mínimos necesarios

Solo se recopilan y se almacenan los datos estrictamente necesarios para la operación del servicio:

- dominio,
- metadatos de validación y autorización,
- hallazgos y activos relevantes,
- resultados de fuentes públicas,
- información técnica necesaria para la evaluación de riesgo.

No se debe conservar, compartir ni reutilizar información fuera del alcance del contrato de servicio ni de la autorización del dominio.

## Regla 4: límites de uso y voluntariedad

Cirdan no puede usarse para:

- hacer seguimientos no autorizados,
- revisar dominios ajenos sin carta vigente,
- consultar servicios o sistemas fuera del dominio autorizado,
- extraer datos sensibles de terceros sin consentimiento y necesidad operativa,
- usar la plataforma para vigilancia, acoso, espionaje o actividades ilícitas.

Todo análisis debe estar ligado a un dominio concretamente autorizado y a un propósito de seguridad legítimo.

## Regla 5: trazabilidad y responsabilidad

Cada evento relevante debe quedar trazado en la bitácora de la plataforma para poder responder preguntas sobre:

- quién autorizó la revisión,
- cuándo se revisó el dominio,
- qué datos se consultaron,
- qué fuentes se utilizaron,
- qué resultados se generaron y qué criterio los clasificó.

La trazabilidad es indispensable para la auditoría, la revisión ética y la defensa del proyecto.

## Regla 6: uso responsable de fuentes externas

Los recolectores y la API deben tratar las fuentes externas como datos no confiables por defecto. Antes de tomar decisiones de riesgo:

- se valida el dominio objetivo,
- se revisa la autorización vigente,
- se comprueba la fuente,
- se descarta información contradictoria o no relevante.

Las pruebas y las consultas a internet deben usarse con criterio, sin sobrepasar el alcance del servicio ni causar ruido innecesario en los proveedores externos.

## Regla 7: no se usará Cirdan para actividades nocivas

La plataforma está orientada a la observación y la gestión de riesgo, no a la actividad maliciosa. Queda prohibido:

- escanear dominios sin autorización,
- atacar infraestructura, exponer servicios o provocar denegación de servicio,
- realizar scraping masivo o explotación no consentida,
- reutilizar hallazgos para actividades fuera de la seguridad legítima.

## Responsabilidad del equipo

Todo miembro del equipo debe:

- revisar que el dominio esté autorizado antes de cualquier análisis,
- respetar el principio de observación pasiva,
- proteger la confidencialidad y la trazabilidad de los resultados,
- reportar dudas o casos de posible uso indebido.

Si una revisión no está claramente autorizada, no se debe hacer.

## Documento relacionado

La carta de autorización y su vigencia forman parte de la base de datos en `domain_authorizations`, y su cumplimiento es condición necesaria para que el orquestador permita un escaneo.
