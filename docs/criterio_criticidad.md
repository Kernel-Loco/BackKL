# Criterio de criticidad (#29)

Responde al comentario 10 del socio formador en la revisión del 2 de octubre: «Checar bien cómo es que definimos que un dominio es crítico o no». Se presenta al socio en la sesión S10 (#90).

**En una frase:** un dominio es crítico cuando su score llega a 80, y llega ahí por lo menos cuando tiene dos o más hallazgos críticos vigentes. Un solo hallazgo crítico lo deja por lo menos en alto.

## Sentido del score

**Más alto = más riesgo.** Cada dominio tiene un score de 0 a 100 y una nota de 0 a 100 en cada una de las 4 categorías del reto: infraestructura, identidad digital, configuración y fugas de datos.

## Bandas

| Banda | Score | Qué significa |
|---|---|---|
| Bajo | 0 a 39 | Exposición menor. Se atiende en el plan de acción normal. |
| Medio | 40 a 59 | Hay hallazgos que conviene corregir pronto. |
| Alto | 60 a 79 | Con el umbral por defecto, desde aquí se dispara la alerta. |
| Crítico | 80 a 100 | Exposición grave. Requiere atención inmediata. |

Las bandas están ancladas al ejemplo del reto: un dominio con 68 está en **riesgo alto**. El reto muestra ese 68 con barras de 80, 55, 40 y 90 y no publica sus pesos. Con los pesos v1 esas barras darían 70, que también es alto. El ancla es la banda, no el número exacto. Las notas de cada categoría usan las mismas bandas para su color en el portal.

## Cómo se calcula el score de un dominio

1. El motor de score (#31) calcula la nota de cada categoría con las reglas del catálogo (#30). Con `method = 'ml'` (#36), la severidad de cada hallazgo sale del clasificador con la correspondencia de la sección «Severidad de cada hallazgo», y el ponderado y el piso se aplican igual. Si el clasificador no supera a las reglas (#34), el score sigue con `method = 'rules'`.
2. **Ponderado:** la suma de cada nota por su peso en el juego de reglas activo. Los pesos suman 1 y cambian solo con una versión nueva del juego de reglas (#32). En el juego v1 son infraestructura 30 %, identidad digital 20 %, configuración 20 % y fugas de datos 30 %. El resultado se redondea al entero, con .5 hacia arriba.
3. **Piso:** si el dominio tiene un hallazgo crítico vigente, su score queda al menos en 60, que es la banda alto. Con dos o más, queda al menos en 80, que es la banda crítico.
4. **Score final:** el mayor entre el ponderado y el piso. Si el piso lo subió, el detalle del score lo dice (#31).

### Por qué hay un piso

El ponderado es un promedio. Un dominio con todas sus categorías limpias y una sola fuga de credenciales crítica podría quedar en bajo, y el promedio escondería lo más grave. El piso evita eso.

### Qué cuenta para el piso

- Hallazgos con severidad vigente `critical` (`findings.severity`).
- Con estado `open` o `accepted_risk`. Un riesgo aceptado sigue contando en el score (#80). Los `resolved` y los `false_positive` no cuentan.
- El piso aplica al score global del dominio. Las notas por categoría no tienen piso.

## Qué hace crítico a un hallazgo

| Severidad | Criterio | Ejemplos |
|---|---|---|
| Crítica (`critical`) | Alguien de fuera lo puede aprovechar ya, sin pasos extra, y obtiene acceso a cuentas, sistemas o datos | Correos de la empresa en una brecha reciente que incluye contraseñas, un secreto vigente en un repositorio público |
| Alta (`high`) | Exposición seria que necesita otro paso o una condición para aprovecharse | Escritorio remoto expuesto a internet, software sin soporte con vulnerabilidades conocidas, certificado vencido |
| Media (`medium`) | Facilita un ataque, como la suplantación, pero no da acceso por sí sola | Falta DMARC, dominio parecido con certificado, certificado que vence en menos de 30 días |
| Baja (`low`) | Falta una buena práctica y el impacto es menor | Falta SPF |

El catálogo (#30) asigna con este criterio la severidad base de cada regla. El etiquetado a ciegas (#33b a #33d) usa las mismas definiciones: crítica y alta cuentan como la clase alta del modelo, media como media y baja como baja.

## Ejemplos con los pesos v1

| Caso | Infraestructura, identidad, configuración, fugas | Críticos vigentes | Ponderado | Piso | Score | Banda |
|---|---|---|---|---|---|---|
| Demo acme-demo.mx | 80, 55, 30, 90 | 1 | 68 | 60 | 68 | Alto |
| Demo acme-tienda.mx | 60, 50, 40, 60 | 0 | 54 | 0 | 54 | Medio |
| Un dominio como acme-portal.mx con una fuga crítica abierta, que sube su nota de fugas a 70 | 40, 30, 20, 70 | 1 | 43 | 60 | 60 | Alto |
| El mismo con dos hallazgos críticos | 40, 30, 20, 70 | 2 | 43 | 80 | 80 | Crítico |

En el tercer caso la nota de fugas queda en alto, pero el ponderado da 43, que es medio. Sin el piso, el dominio quedaría en medio aunque tiene una fuga crítica abierta.

## Alerta

La alerta `score.above_threshold` se crea en cada cálculo en que el score queda **en el umbral o arriba** (score >= umbral), aunque haya bajado respecto al anterior. Si queda abajo, no se crea. Evitar alertas repetidas para un dominio que se queda arriba del umbral es una propuesta para #65, no cambia este criterio. El umbral por defecto es 60 y cada empresa lo puede cambiar (`organizations.alert_score_threshold`). Con el umbral por defecto, la alerta coincide con el inicio de la banda alto.

## Severidad de cada hallazgo

- La pone su regla del catálogo (#30) con su severidad base: `critical`, `high`, `medium` o `low`.
- El motor puede subirla por sus factores, por ejemplo un hallazgo con regla `high` que pasa a `critical`, y lo registra en la bitácora como `finding.severity_changed`.
- Con la versión A del ML (#34 a #36), el clasificador predice alta, media o baja. **Propuesta para #36, que confirma Emilio:** baja corresponde a `low`, media a `medium` y alta a `high`. Alta queda en `critical` cuando el motor por reglas ya dejó el hallazgo en `critical`, por su regla o por sus factores. El modelo nunca baja un hallazgo que el motor por reglas dejó en `critical`. Así lo que cuenta para el piso queda definido también con `method = 'ml'`. Si Emilio lo decide en #34, alta también pasa a `critical` cuando la probabilidad de alta supera un corte, y así el modelo puede marcar críticos que las reglas no ven.

## Quién usa qué

| Tarjeta | Qué toma de este criterio |
|---|---|
| #4 Plan V3 | La hoja «Criterio de riesgo» del Gantt V3 |
| #30 Catálogo de reglas | La severidad base de cada regla con el criterio de «Qué hace crítico a un hallazgo» |
| #31 Motor de score | `score_dominio()` y el aviso en el detalle cuando aplica el piso, por ejemplo «subido a 60 por 1 hallazgo crítico vigente, la suma ponderada da 43» |
| #33b a #33d Etiquetado a ciegas | Las definiciones de severidad para etiquetar alta, media y baja |
| #34 Clasificador y #36 Integración del ML | Las clases alta, media y baja y su correspondencia con las severidades |
| RC-17 Portal | La banda y su nombre junto al score global del dashboard, y el aviso del piso cuando aplica |
| #41 Portal | El nombre de la severidad de cada hallazgo en el panel «por qué es crítico», que la explica con SHAP (#35). La banda del dominio no va en ese panel |
| #65 Alertas | `dispara_alerta()` |

## Código

`score/criterio.py` implementa las bandas, el piso, el ponderado y la alerta. Las pruebas están en `pruebas/test_criterio.py`:

```bash
python -m unittest -v pruebas/test_criterio.py
```

## Pregunta para el socio en S10

¿Las bandas y la regla de piso coinciden con cómo IKUSI prioriza a sus clientes?
