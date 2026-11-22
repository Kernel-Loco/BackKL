# Medición de cobertura y falsos positivos (#84)

## Alcance y fecha

Esta es una **línea base del catálogo en `dev`**, no un resultado del último escaneo. Corresponde a la revisión `451e58d6ece110789b7e4baf9ce5782495ab900b` del 20 nov 2026 y a las 40 reglas del juego v1 documentadas en [`codigos_reglas.md`](codigos_reglas.md). La siembra se describe en [`hallazgos_esperados.md`](hallazgos_esperados.md). El catálogo y la siembra pueden cambiar; sus datos históricos no prueban el estado actual de olmardo.com.

| Estado del catálogo | Reglas | Porcentaje de 40 |
|---|---:|---:|
| Lo emite hoy | 32 | 80 % |
| Planeado | 5 | 12,5 % |
| Previsto | 3 | 7,5 % |

«Lo emite hoy» solo indica que un recolector registrado declara el código: no acredita que la fuente esté activada, que haya corrido, que cubra todos los activos ni que haya detectado la siembra. Las dependencias de reglas aún no emitidas están en la columna «Qué falta» del catálogo. Las limitaciones de reglas emitidas se documentan en su sección «Cobertura parcial».

Para reproducir el conteo en la revisión que se quiera evaluar, desde la raíz del repositorio:

```powershell
python -m unittest pruebas.test_catalogo_reglas
python -c "from collections import Counter; from pruebas.test_catalogo_reglas import FILAS_DOC; print(len(FILAS_DOC), dict(Counter(f[6] for f in FILAS_DOC)))"
```

La primera orden comprueba la tabla contra las semillas y los códigos declarados por los recolectores. La segunda cuenta los estados de esa tabla; al cambiar de revisión, actualizar el cuadro y su referencia si se desea una línea base nueva.

## Las cinco categorías de superficie moderna

IoT y OT se agrupan en una categoría para esta tabla; no se agrupan las cuatro categorías del score. Una regla puede señalar una superficie sin demostrar todas las formas de exposición de esa superficie.

| Superficie | Reglas y tarjetas | Capacidad en el catálogo | Último escaneo de olmardo.com | Siembra detectada |
|---|---|---|---|---|
| IoT y OT | `exposed_iot_device`, `exposed_ot_device` · RC-220 y RC-337 | Ambos códigos se emiten. Sin la API de host de Shodan la ausencia de etiquetas no demuestra cobertura completa. | Sin evidencia disponible en el repositorio para identificar el último escaneo y su cobertura. | Sin verificar. La cámara de la fila 11 de la siembra esperaba `exposed_iot_device`; su nota es histórica. |
| APIs | `exposed_api_docs`, `api_auth_not_declared` · RC-118 | Ambos códigos se emiten; la fuente `api_docs` está apagada por la semilla 013 hasta dar el aviso de la actividad. La autenticación no declarada no demuestra que la API esté abierta. | Sin evidencia disponible del último escaneo. | Sin siembra de API documentada en la lista de #10b; no evaluable. |
| Nube | `public_bucket`, `subdomain_takeover_risk` · RC-119; `file_share_link_in_repo` · RC-247 | Los dos primeros están previstos; el enlace compartido se emite, pero no verifica la exposición de un bucket. | Sin evidencia disponible del último escaneo. | Sin siembra de nube documentada en la lista de #10b; no evaluable. |
| Contenedores | `secret_in_container_image` · RC-120; `exposed_container_api` · RC-224 | El secreto en imagen está previsto; la API expuesta se emite. No equivale a analizar imágenes. | Sin evidencia disponible del último escaneo. | Sin siembra de contenedores documentada en la lista de #10b; no evaluable. |
| Secretos | `secret_in_public_repo` · RC-50 | Se emite. La revisión de repos puede ser parcial. | Sin evidencia disponible del último escaneo. | La fila 8 de #10b documenta un token falso sembrado; falta cotejar su detección en el escaneo seleccionado. |

Las cinco tienen al menos un código declarado por algún recolector, pero **eso no demuestra que el último escaneo haya cubierto cinco categorías ni que se cumpla la meta de al menos dos**. Para el deck #59b deben usarse los resultados verificados de la corrida, no este conteo de capacidad.

## Cómo medir una corrida

1. Identificar dominio autorizado, ID, fecha, versión y estado del **último escaneo terminado** de olmardo.com y conservar la referencia a su evidencia. No lanzar un escaneo nuevo para rellenar una medición sin la autorización y alcance vigentes.
2. Para cada regla y activo sembrado, cotejar la evidencia del mismo escaneo con la condición esperada vigente en ese momento: código, activo, fuente y ventana temporal. El certificado de la fila 5, por ejemplo, solo era «por vencer» del 29 al 31 oct. Un código igual en otro activo no es acierto.
3. Revisar `scan_source_runs`, `stats.sources_partial`, `sin_cobertura`, `revisados`, `sin_revisar` y `omitidos` cuando correspondan. El score ofrece `coverage_gaps` con los códigos y motivos descritos en el [contrato de la API](contrato_api_v1.md); sin corridas sale vacío y eso no demuestra cobertura. Una fuente apagada, fallida, parcial o sin evidencia suficiente no equivale a una detección negativa. Registrar «sin cobertura» o «no evaluable» para las partes no revisadas.
4. En la tabla de las cinco superficies registrar por separado si la regla se revisó en esa corrida y si la siembra se detectó, con ID o referencia de evidencia. Para la meta de dos categorías contar solo superficies con revisión y evidencia suficientes; no sumar códigos ni tratar una fuente parcial como cobertura completa.

Para medir la detección de la siembra, definir antes el conjunto de casos esperados vigentes y dentro del alcance del escaneo. Un **verdadero positivo (VP)** es un caso confirmado como detectado en su activo; un **falso negativo (FN)** es un caso no detectado cuya fuente y parte se revisaron suficientemente. Contar aparte los casos sin cobertura, fuera de vigencia y sin evidencia; no convertirlos en FN. Reportar `VP / (VP + FN)` como proporción detectada entre los casos evaluables, junto con los conteos de VP, FN y casos no evaluables. Con denominador cero es **no evaluable**. Una proporción con casos pendientes describe solo los evaluados y no la detección completa de la siembra.

## Falsos positivos

[`hallazgos_esperados.md`](hallazgos_esperados.md) enumera lo que no debe salir y las condiciones bajo las que esa expectativa vale. Una coincidencia es **posible falso positivo**, no un error confirmado: contrastar el activo, el tiempo, la fuente y el alcance con una revisión humana y registrar la justificación. No clasificar automáticamente como falso el puerto 50000 histórico de InternetDB ni como acierto un dominio parecido de terceros, según las notas de esa lista.

Para una muestra revisada del mismo escaneo, reportar el número de hallazgos **confirmados falsos** sobre el total de hallazgos de la muestra que fueron revisados y clasificados (confirmados verdaderos o falsos): `FP / (VP + FP)`. Informar ambos conteos, la selección de la muestra, fecha y casos pendientes. Este porcentaje es la **proporción de falsos entre alertas revisadas**, no la tasa estadística `FP / (FP + VN)`, que requiere conocer también los verdaderos negativos. No contar como verdaderos los no revisados, ni inferir verdaderos negativos en fuentes sin cobertura. Si el denominador es cero, el porcentaje es **no evaluable**, no 0 %.

**Resultado real pendiente:** no se dispone aquí del identificador y evidencia del último escaneo de producción ni de una revisión de sus hallazgos. Hasta cotejarlos con la siembra vigente no se puede afirmar detección, cobertura de la meta ni una cifra de falsos positivos.
