# Plantilla de carta de autorización

Esta plantilla se usa para registrar la autorización formal del titular del dominio antes de que Cirdan pueda revisar el nombre de dominio y sus activos públicos.

La carta debe quedar guardada en la base con la información que corresponde a `domain_authorizations`:

- dominio
- nombre de quien firma
- cargo de quien firma
- correo de quien firma
- fecha de inicio
- fecha de fin
- firma del responsable

## Modelo de carta

```
CARTA DE AUTORIZACIÓN DE REVISIÓN PASIVA

Día: [dd/mm/aaaa]

A la atención de Cirdan

Por la presente, el suscrito/a:

- Nombre completo: [nombre completo del firmante]
- Cargo: [cargo / puesto del firmante]
- Correo electrónico: [correo corporativo]
- Dominio autorizado: [dominio.com]

Declaro expresamente que tengo la facultad para autorizar la revisión pasiva del dominio anterior, y que autorizo a Cirdan a:

- consultar fuentes públicas y autorizadas del dominio,
- revisar certificados, DNS, registros públicos y metadatos relacionados,
- registrar evidencias mínimas de riesgo para fines de seguridad,
- mantener los datos necesarios dentro del alcance de la plataforma,
- realizar la observación de forma pasiva, sin afectar ni intervenir en los sistemas del dominio.

La presente autorización tendrá vigencia desde el [dd/mm/aaaa] hasta el [dd/mm/aaaa].

Durante este período, el dominio queda bajo la política de uso ético de Cirdan y solo se permite la observación pasiva, nunca el ataque ni la manipulación del servicio.

Firma del responsable
____________________________________

Nombre: [nombre completo]
Cargo: [cargo]
Correo: [correo]
Dominio: [dominio.com]
```

## Datos mínimos que se deben registrar en la base

En la tabla `domain_authorizations`, se debe guardar al menos lo siguiente:

- `domain_id`: dominio asociado
- `signer_name`: nombre de quien firma
- `signer_title`: cargo de quien firma
- `signer_email`: correo de quien firma
- `valid_from`: fecha de inicio de la autorización
- `valid_until`: fecha de fin de la autorización
- `signed_document_key`: clave o referencia del documento firmado
- `signed_document_sha256`: hash SHA-256 del documento firmado

## Requisitos de la autorización

La carta debe cumplir estas condiciones:

- ser firmada por alguien con poder para autorizar la revisión del dominio,
- reconocer que la actividad es de observación pasiva,
- dejar claro que no se atacará ni se interferirá con los servicios del dueño,
- incluir una vigencia explícita,
- ser conservada como evidencia de la autorización.

## Importante

Sin una carta válida y vigente, el dominio no puede pasar a la fase de escaneo ni de revisión automatizada.
