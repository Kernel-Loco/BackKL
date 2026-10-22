# Dataset semisintético del ML (#33)

Lote de hallazgos ficticios que se etiqueta a ciegas para entrenar el clasificador alta, media y baja (#34). Es la tarjeta RC-65. Los etiquetadores aparecen como `etiquetador_1` a `etiquetador_4`. Aparte hay un etiquetador LLM declarado, que no es una persona y nunca vota (ver [Etiquetador LLM](#etiquetador-llm)).

**Esta rama se sube a GitHub solo cuando estén todas las etiquetas.** El maestro y las plantillas dicen la clase esperada y la severidad de cada fila. Si alguien los lee antes de etiquetar, el etiquetado deja de ser ciego.

## Archivos

| Archivo | Qué es |
|---|---|
| `cirdan/ml/plantillas.py` | Las 24 plantillas y el mapa de severidad base de cada código |
| `cirdan/ml/caracteristicas.py` | Tipo, antigüedad, exposición y sensibilidad de un hallazgo, con la rúbrica |
| `cirdan/ml/generar_lote.py` | Arma el lote con semilla fija y escribe el maestro y las copias |
| `cirdan/ml/acuerdo.py` | Junta las etiquetas, arma el dataset y mide el acuerdo |
| `datos/ml/rc65/copias/etiquetador_N.csv` | Lo que ve cada etiquetador |
| `datos/ml/rc65/maestro.jsonl` | Un hallazgo por línea con todo lo que el etiquetador no ve |
| `datos/ml/rc65/etiquetas/etiquetador_N.csv` | Las etiquetas devueltas: `id`, `etiqueta` y `nota` |
| `datos/ml/rc65/etiquetas/llm.csv` y `llm_repeticion.csv` | Las etiquetas del etiquetador LLM, con las mismas columnas |
| `datos/ml/rc65/dataset.csv` y `acuerdo.json` | Los escribe `acuerdo.py` cuando llegan las etiquetas |
| `pruebas/test_dataset_ml.py` | Pruebas sin base ni red |

El lote son archivos. No toca la base.

## Códigos y severidad base

Se usan los 8 códigos que existen en dev: las 7 reglas de `db/semillas/001_datos_demo.sql:36-42` y `cert_expiring_soon`, que solo está en `cirdan/recolectores/crtsh.py:79` mientras #30 no la agregue al catálogo. La severidad base sale de un solo mapa, `REGLAS` en `plantillas.py`. Las pruebas revisan que coincida con esas dos fuentes. `severity` es igual a `base_severity` porque el motor de score (#31) todavía no está en dev. Si #30 o #31 cambian una severidad base, se cambia el mapa, se regenera el lote y se recalcula `clase_reglas`.

## Plantillas

Una plantilla es un código con una variante de contexto. Son 3 por código, 24 en total. Cada variante usa evidencia que un recolector da hoy o va a dar: crt.sh (#14), DNS con MX (#15), Shodan (#17), versiones (#18) y HIBP (#19). Dentro de cada plantilla cambian la empresa, el activo y las fechas. En las de brechas y software también cambian la brecha, la versión y su CVE, que salen de un catálogo fijo. En varias plantillas el rango cruza un umbral, por ejemplo la edad de la brecha, para que la antigüedad pese.

Cada plantilla tiene una clase esperada en `plantillas.py`. Solo sirve para balancear el lote, unas 140 filas por clase. Nunca es la etiqueta.

| Plantilla | Código | Variante | Filas | Partición |
|---|---|---|---|---|
| `brecha_contrasenas_reciente` | `breach_exposure` | Brecha con contraseñas de hace menos de 6 meses | 24 | entrenamiento |
| `brecha_contrasenas_vieja` | `breach_exposure` | Brecha con contraseñas de hace más de 3 años | 24 | prueba |
| `brecha_solo_correos` | `breach_exposure` | Brecha solo con correos, nombres o usuarios, de 2 meses a 4 años | 13 | entrenamiento |
| `software_panel_kev` | `outdated_software` | Panel de acceso sin soporte con una CVE en KEV, EPSS de 0.027 a 0.974 | 24 | entrenamiento |
| `software_servidor_con_soporte` | `outdated_software` | Aplicación con soporte y una CVE con CVSS de 4.0 a 6.5, EPSS de 0.001 a 0.296 | 13 | prueba |
| `software_libreria_sitio_estatico` | `outdated_software` | Librería sin soporte en un sitio informativo, sin CVE | 16 | entrenamiento |
| `rdp_produccion` | `exposed_rdp` | RDP de un servidor de producción, visto por primera vez hace 2 a 400 días | 24 | entrenamiento |
| `rdp_pruebas` | `exposed_rdp` | RDP de un equipo de pruebas | 23 | prueba |
| `rdp_sin_ver_6_meses` | `exposed_rdp` | RDP que no se ve desde hace más de 6 meses | 13 | entrenamiento |
| `vencido_sitio_de_acceso` | `cert_expired` | Sitio de inicio de sesión con el certificado vencido hace menos de 30 días | 23 | entrenamiento |
| `vencido_api_o_correo` | `cert_expired` | API o correo con el certificado vencido hace 5 a 200 días | 13 | prueba |
| `vencido_sin_contenido` | `cert_expired` | Subdominio que resuelve sin contenido, con el certificado vencido hace más de 6 meses | 16 | entrenamiento |
| `por_vencer_sitio_principal` | `cert_expiring_soon` | Sitio principal con certificado de 90 días y menos de 7 para vencer | 13 | entrenamiento |
| `por_vencer_api_o_correo` | `cert_expiring_soon` | API o correo con certificado de 90 días y 8 a 20 para vencer | 13 | prueba |
| `por_vencer_sitio_secundario` | `cert_expiring_soon` | Sitio secundario con certificado de un año y 20 a 29 días para vencer | 16 | entrenamiento |
| `dmarc_con_mx` | `dmarc_missing` | Dominio con MX y SPF que manda correo, visto por primera vez hace 1 a 500 días | 13 | entrenamiento |
| `dmarc_sin_mx` | `dmarc_missing` | Dominio sin MX, con un SPF que no autoriza a nadie a enviar (`v=spf1 -all`) | 16 | entrenamiento |
| `dmarc_subdominio_campanas` | `dmarc_missing` | Subdominio de campañas con MX de un proveedor de envíos | 13 | prueba |
| `spf_sin_mx` | `spf_missing` | Dominio sin MX, con DMARC p=reject | 24 | entrenamiento |
| `spf_con_mx_y_dmarc_reject` | `spf_missing` | Dominio con MX y DMARC p=reject | 24 | prueba |
| `spf_con_mx_sin_dmarc` | `spf_missing` | Dominio con MX y sin DMARC, visto por primera vez hace 1 a 400 días | 24 | entrenamiento |
| `parecido_reciente_login_o_pago` | `lookalike_domain` | Parecido con la marca y login, pagos, acceso o cuenta, con su primer certificado de hace menos de 30 días | 13 | entrenamiento |
| `parecido_viejo` | `lookalike_domain` | Error tipográfico con certificados desde hace más de un año, el último vencido hace 20 a 85 días | 15 | entrenamiento |
| `parecido_otro_tld` | `lookalike_domain` | La marca con otro TLD, sin nombres sospechosos, primer certificado de hace 10 a 800 días | 15 | prueba |

Las plantillas de `cert_expiring_soon` cumplen la regla del tercio de vida de crt.sh (`crtsh.py:66-67` y 392). `spf_missing` lleva 24 filas por plantilla, 72 en total. Así, aun si las etiquetas siguieran al código, baja tendría más de 60.

Todo es ficticio y se puede publicar: empresas con nombres inventados bajo `.com.example` (RFC 2606), IP de documentación (RFC 5737), brechas DemoBreach, productos de demostración y CVE del año 2099. Todos los hallazgos son de un escaneo del 20 oct 2026. Lo que se repite entre filas no se contradice, y las pruebas lo revisan:

- Cada empresa tiene un perfil de correo fijo (MX, SPF y DMARC). Las brechas solo salen en empresas con MX.
- Cada brecha tiene una sola fecha y las mismas clases de datos en todas sus filas.
- Cada versión de un producto tiene un solo fin de soporte, y cada CVE el mismo CVSS, EPSS y KEV.
- Un host tiene un solo hallazgo de certificado.
- Los errores tipográficos y los otros TLD de `lookalike_domain` salen de las variantes que crt.sh consulta (`crtsh.candidatos_parecidos`), con `.example` al final.

## Características y rúbrica

`caracteristicas.calcular()` da las 4 características del reto con las claves y valores del contrato de plugin (#13).

| Característica | Cómo sale |
|---|---|
| `tipo` | Del código de regla, con los mismos nombres que `cirdan/api/v1.py:20-25` |
| `antiguedad_dias` | Días hasta el escaneo desde `breach_date` en brechas, `not_after` o `vence` en certificados vencidos, `not_before` en certificados por vencer, el primer certificado en dominios parecidos y `primera_vez` en los demás. Si la evidencia no trae esa fecha, desde `detected_at`, o `asset_first_seen` en `outdated_software` y `exposed_rdp`, como `v1.py:67-74` |
| `exposicion` | `directa` en `outdated_software` y `exposed_rdp`, y cuando el activo es una `ip` o un `service` (`v1.py:26` y 80). En los demás casos `publica` |
| `sensibilidad` | La rúbrica de abajo, a partir de la evidencia |

La rúbrica de sensibilidad vive en una sola función, `caracteristicas.sensibilidad()`. Se basa en lo que expone el hallazgo, no en su severidad:

- **alta** si expone credenciales, acceso remoto a un sistema o datos personales.
- **media** si expone un servicio, el correo o información interna sin acceso directo.
- **baja** si solo expone información pública, un activo sin uso o algo que otro registro ya protege.

| Código | alta | media | baja |
|---|---|---|---|
| `breach_exposure` | La brecha trae contraseñas o datos personales, como teléfonos o direcciones | Solo correos, nombres o usuarios | |
| `exposed_rdp` | Acceso remoto visto en los últimos 180 días | No se ve desde hace más de 180 días | |
| `outdated_software`, `cert_expired`, `cert_expiring_soon` | El host pide usuario y contraseña | API, correo, una aplicación o sin dato de uso | Sitio informativo o sin contenido |
| `dmarc_missing` | | Cualquier otro caso, porque alguien puede suplantar su correo | Sin MX y con `v=spf1 -all`: el dominio dice que no manda correo |
| `spf_missing` | | Sin DMARC que rechace | Con DMARC p=reject, que ya rechaza el correo suplantado |
| `lookalike_domain` | El parecido o sus nombres llevan login, acceso, pago, cuenta, verifica o seguridad | | Sin esas palabras. No expone datos de la empresa |

Hoy la API (`cirdan/api/v1.py:26-27`) y crt.sh (`crtsh.py:390`, 398 y 435) ponen la sensibilidad fija por código. Que adopten `calcular()` va en otra tarjeta, antes de #36. Hasta entonces el modelo verá en producción valores distintos a los del entrenamiento. `calcular()` ya lee lo que crt.sh pone hoy en la evidencia (`vence` y `primer_certificado`). crt.sh no pone `not_before` en `cert_expiring_soon` y ningún recolector pone `primera_vez`. Para esos casos quien llama pasa `detectado` y `activo_visto`. La tarjeta de adopción debe agregar `not_before` a la evidencia de crt.sh.

## Bloque común y reparto

- Son 425 hallazgos: 142 de clase esperada alta, 141 de media y 142 de baja.
- El bloque común tiene 60 filas: 20 por clase esperada y al menos 2 por plantilla. Lo etiquetan los 4.
- Las otras 365 se reparten en turno entre `etiquetador_2`, `etiquetador_3` y `etiquetador_4`, 122, 122 y 121. Cada uno revisa 181 o 182 filas.
- `etiquetador_1` solo etiqueta el bloque común, porque armó el lote y conoce la clase esperada de cada plantilla.

En el maestro, `bloque` es `comun` o `reparto` y `asignado_a` dice quién etiqueta cada fila.

## Lo que ve cada etiquetador

Cada copia es un CSV UTF-8 con BOM, para que Excel muestre los acentos. Cada etiquetador recibe su propio orden barajado, con ids opacos que no dicen nada de la plantilla. El orden no sigue la severidad.

Columnas: `id`, `titulo`, `tipo_de_activo`, `activo`, `fuente`, `evidencia`, `cve`, `cvss`, `epss`, `kev`, `etiqueta` y `nota`. La evidencia va en texto, con sus fechas y cuántos días han pasado. `etiqueta` y `nota` van vacías.

No trae `rule_code`, `severity` ni `base_severity`, ni `penalty`, `factors` o `summary` (`docs/api_v1/explicacion.json`), la recomendación, la plantilla, la clase esperada, el tipo, la exposición ni la sensibilidad. Las pruebas revisan que ningún valor de las copias traiga esos códigos ni palabras como crítico, alta, media, baja o severidad.

## Maestro

`maestro.jsonl` trae un hallazgo por línea con los campos de #21 (`docs/api_v1/hallazgos.json:5-23`), en el mismo orden, y además `plantilla`, `particion`, `clase_esperada`, `bloque` y `asignado_a`. Va ordenado por id.

## Partición

`particion` pone en prueba una plantilla de cada código, 8 en total, con 2 de clase esperada alta, 4 de media y 2 de baja. Son 138 filas de prueba y 287 de entrenamiento. Así #34 separa por plantilla y cada tipo aparece en entrenamiento. Ninguna plantilla de prueba tiene el mismo tipo, exposición y sensibilidad que una de entrenamiento de otra clase esperada, porque con esas características el modelo no podría distinguirlas. Es una propuesta que se confirma en #34.

Lo que mide la prueba: dentro de una plantilla solo cambia la antigüedad. En 5 de las 8 plantillas de prueba hay una de entrenamiento con el mismo tipo, exposición y sensibilidad, y en las otras 3 esa combinación no sale en entrenamiento. Así que la prueba mide si el modelo acierta con otras antigüedades y con combinaciones nuevas, no con evidencia nueva.

## Etiqueta final y acuerdo

`dataset.csv` trae `id`, `plantilla`, `particion`, `tipo`, `antiguedad_dias`, `exposicion`, `sensibilidad`, `etiqueta`, `n_etiquetas` y `clase_reglas`. No trae la clase esperada.

- Fuera del bloque común, la etiqueta es la de su etiquetador.
- En el bloque común, la etiqueta final es la de la mayoría entre `etiquetador_2`, `etiquetador_3` y `etiquetador_4`. Si los 3 difieren, queda media. La de `etiquetador_1` solo cuenta en el acuerdo.
- `n_etiquetas` cuenta las etiquetas de personas que decidieron la final: 3 en el bloque común y 1 fuera. Es 0 en las filas que llenó el LLM.
- Si falta uno de los 3, la final del bloque común sale de los otros 2. Si no coinciden queda media, y `n_etiquetas` es 2.
- `clase_reglas` es la severidad de la regla en clases: crítica y alta cuentan como alta, media como media y baja como baja (`docs/criterio_criticidad.md:48`).

`acuerdo.json` trae:

- El kappa de Fleiss en el bloque común con los 4 y sin `etiquetador_1`, que conoce la clase esperada.
- El acuerdo simple, que es la parte de las filas en que todos coinciden, y el kappa de Cohen por pares.
- Cuántas filas del bloque común quedaron en media por no tener mayoría.
- Qué parte de las etiquetas coincide con `clase_reglas` y con `sensibilidad`: en las finales, en cada partición y por etiquetador.
- Cuántas filas quedan por clase y por partición, y si hay al menos 60 por clase. `por_clase_solo_personas` cuenta por clase sin las filas del LLM.
- `linea_base_prueba`: el F1 macro en el set de prueba de predecir `clase_reglas` y de copiar `sensibilidad`.
- `lote_trivial`, que es verdadero si el 90 % o más de las etiquetas finales coincide con `clase_reglas`. En ese caso el clasificador solo empataría con las reglas, y se dice.
- `rubrica_trivial`, que es verdadero si el 90 % o más coincide con `sensibilidad`. En ese caso el modelo casi solo puede copiar la rúbrica, y se dice.
- `llm`, la comparación del etiquetador LLM con las personas. Se explica abajo.

#34 tiene que reportar en el mismo set de prueba el F1 macro de las reglas, el de copiar la sensibilidad y el del modelo. Los dos primeros ya vienen en `linea_base_prueba`. Si el modelo no supera a copiar la sensibilidad, no aprendió más que la rúbrica.

Si alguien no entrega, sus filas del reparto salen del dataset y lo demás sigue, salvo que las cubra el LLM. `acuerdo.json` lo dice en `faltan`.

## Etiquetador LLM

Además de las personas hay un etiquetador LLM. Está declarado: no es una persona y sus etiquetas nunca van a nombre de nadie del equipo. Es Claude Opus 5.5 (`claude-opus-5-5`), corrido el 22 oct 2026.

Etiquetó a ciegas, solo con el texto del Excel:

- Cada hallazgo le llegó con lo mismo que ve un etiquetador: id, título, tipo de activo, activo, fuente, evidencia y, cuando hay, CVE, CVSS, EPSS y KEV.
- Las instrucciones son las de la hoja Instrucciones del Excel, con el mismo criterio. Solo se quitó lo que es para una persona, como la entrega.
- No vio el maestro, las plantillas ni el repo.
- Etiquetó las 425 filas en orden al azar, en 5 partes de 85, cada una con un agente nuevo.
- Etiquetó otra vez las 60 del bloque común, en otro orden y con otro agente. Así se ve si repite sus etiquetas.

`etiquetador_1` ya no entrega etiquetas, porque armó el lote y las suyas no serían a ciegas. En `acuerdo.json` sale en `faltan`. Nada más cambia.

### Archivos

| Archivo | Qué es |
|---|---|
| `datos/ml/rc65/etiquetas/llm.csv` | Las etiquetas del LLM de las 425 filas del maestro: `id`, `etiqueta` y `nota` |
| `datos/ml/rc65/etiquetas/llm_repeticion.csv` | La segunda pasada del LLM en las 60 filas del bloque común, con las mismas columnas |

Los dos son opcionales. Si están, `acuerdo.py` los revisa igual que los de las personas: ids del maestro (o del bloque común en la repetición), sin repetir, sin faltantes y con alta, media o baja. La repetición sin `llm.csv` también es un error. Con un error no escribe nada. Si no están, todo funciona como antes y `llm.esta` es falso. El prompt y lo que recibió cada agente no están en el repo.

### Cómo se usa

- **No vota.** No entra en la etiqueta final del bloque común, que siguen decidiendo `etiquetador_2`, `etiquetador_3` y `etiquetador_4`. Tampoco entra en el kappa de Fleiss (`los_4` y `sin_etiquetador_1`) ni en el kappa de Cohen entre personas.
- **Se compara aparte**, en la sección `llm` de `acuerdo.json`.
- **Cubre a quien no entrega, con condición.** Mira el kappa del LLM contra la etiqueta final de las personas en el bloque común. Si es de 0.6 o más (`UMBRAL_LLM`) y falta el archivo de `etiquetador_2`, `etiquetador_3` o `etiquetador_4`, sus filas del reparto se llenan con la etiqueta del LLM. Si es menor o no se puede calcular, esas filas salen del dataset y `llm.motivo` dice por qué.
- **Nunca llena el bloque común.** Esas filas solo llevan etiquetas de personas.
- En `dataset.csv`, `n_etiquetas` 0 marca las filas del LLM: no tienen ninguna etiqueta de persona. Las columnas no cambian.
- `por_clase_solo_personas` cuenta las filas por clase sin las del LLM. Lo demás (`al_menos_60_por_clase`, `linea_base_prueba`, `coincidencia`, `lote_trivial` y `rubrica_trivial`) sale del dataset completo.

La sección `llm` de `acuerdo.json` trae:

| Clave | Qué es |
|---|---|
| `esta` | Si hay `llm.csv` |
| `umbral_kappa` | 0.6 |
| `contra_final_personas` | Filas, kappa de Cohen y acuerdo simple contra la etiqueta final de las personas en el bloque común. Solo cuenta las filas que tienen etiqueta final de personas |
| `contra_cada_persona` | Lo mismo contra cada etiquetador que entregó |
| `repeticion` | Kappa y acuerdo simple entre las dos pasadas del bloque común. `null` si no está `llm_repeticion.csv` |
| `coincidencia` | Qué parte de sus 425 etiquetas coincide con `clase_reglas` y con `sensibilidad` |
| `alcanza_umbral` | Si el kappa contra la etiqueta final es de 0.6 o más |
| `cubre_faltantes` | Si llenó filas de alguien que no entregó |
| `motivo` | Por qué cubre o no cubre |
| `filas_cubiertas` | Cuántas filas llenó, por etiquetador |

## Cómo regenerar el lote

```bash
python -m cirdan.ml.generar_lote                 # escribe datos/ml/rc65/copias/ y maestro.jsonl
python -m unittest -v pruebas/test_dataset_ml.py # 53 pruebas sin base ni red
```

La semilla es fija (`SEMILLA = 65`). La misma semilla da los mismos bytes, y una prueba revisa que el lote del repo sea el que sale de ella. `.gitattributes` marca `datos/ml/` sin conversión de fin de línea para que esa comparación sirva en cualquier sistema. Si cambias una plantilla o el mapa de severidades, regenera el lote antes de repartirlo. Después de repartirlo, no lo regeneres: las copias que ya tienen los etiquetadores dejarían de coincidir con el maestro.

## Cómo medir el acuerdo

Las etiquetas devueltas van en `datos/ml/rc65/etiquetas/etiquetador_N.csv`, con las columnas `id` y `etiqueta`, y `nota` si se quiere. Luego:

```bash
python -m cirdan.ml.acuerdo    # escribe datos/ml/rc65/dataset.csv y acuerdo.json
```

Revisa que cada archivo traiga justo los ids de su copia, sin repetir, y que cada etiqueta sea alta, media o baja. Hace lo mismo con `llm.csv` y `llm_repeticion.csv` si están. Si encuentra un error, o si no hay etiquetas de personas, no escribe nada y sale con código 1. En la terminal da una línea del LLM, con su kappa contra las personas y las filas que cubre. Cuando ya existe `dataset.csv`, una prueba revisa que haya al menos 60 filas por clase en las etiquetas finales. Antes de eso se salta. Otra prueba revisa que `llm.csv` y `llm_repeticion.csv` del repo pasen la revisión.

## Riesgos conocidos

- Las severidades base son públicas en el repo y en el portal. Algunos títulos repiten la columna Ejemplos de `docs/criterio_criticidad.md:41-46`, por ejemplo 'Dominio parecido con certificado' (`crtsh.py:427`), 'Certificado vencido' y 'Falta el registro DMARC'. Son los títulos que dan los recolectores, así que se dejan igual.
- La sensibilidad de la rúbrica es la misma en todas las filas de una plantilla. Coincide con la clase esperada en 399 de las 425 filas y en las 138 de prueba. Si las etiquetas siguen la clase esperada, copiar la sensibilidad da F1 macro 1.0 en prueba y las reglas dan 0.70. Por eso `acuerdo.json` trae `linea_base_prueba` y `rubrica_trivial`.
- La clase baja depende de lecturas que el criterio no fija, porque el criterio pone la suplantación en media. Por eso las plantillas baja de correo traen la protección que la evita: DMARC p=reject en `spf_missing` y `v=spf1 -all` sin MX en `dmarc_missing`. El parecido viejo ya no tiene un certificado vigente. Aun así, `parecido_otro_tld` (15 filas) puede salir media, y `por_vencer_sitio_secundario` (16) también, porque la columna Ejemplos del criterio pone en media un certificado que vence en menos de 30 días. Si las dos salen media quedan unas 111 de clase baja. Si quedan menos de 60, `acuerdo.json` lo dice en `al_menos_60_por_clase`.
- Las variantes con MX, KEV, EPSS o el uso del host usan evidencia que hoy ningún recolector da. Llegará con #15, #17 y #18. Hasta entonces, en producción el modelo verá menos variación que en el lote.
- Con 60 filas en el bloque común, el intervalo del kappa es ancho. El kappa del LLM contra las personas, que decide si cubre a quien no entrega, sale de esas mismas 60 filas.
- Si #30 trae códigos nuevos, el modelo no los conoce.
