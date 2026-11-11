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

## Letras de la A a la F (#114)

Cada score lleva además una letra, que se entiende más rápido que el número. A es menos riesgo y F es más. No hay E. La letra sale del score final, ya con la regla de piso, y nunca contradice a la banda: A y B parten el bajo a la mitad.

| Letra | Score | Banda |
|---|---|---|
| A | 0 a 19 | Bajo |
| B | 20 a 39 | Bajo |
| C | 40 a 59 | Medio |
| D | 60 a 79 | Alto |
| F | 80 a 100 | Crítico |

Por el piso, un dominio con un hallazgo crítico vigente tiene al menos D, y con dos o más tiene F. La letra es solo otra forma de leer el score: la alerta y el umbral siguen con el número de 0 a 100. Si el score tiene cobertura parcial (`partial_coverage`), la letra lleva el mismo aviso que el score. Las notas por categoría no llevan letra.

## Cómo se calcula el score de un dominio

1. El motor de score (#31) calcula la nota de cada categoría con las reglas del catálogo (#30). Con `method = 'ml'` (#36), la severidad de cada hallazgo sale del clasificador con la correspondencia de la sección «Severidad de cada hallazgo», y el ponderado y el piso se aplican igual. Si el clasificador no supera a las reglas (#34), el score sigue con `method = 'rules'`.
2. **Ponderado:** la suma de cada nota por su peso en el juego de reglas activo. Los pesos suman 1 y cambian solo con una versión nueva del juego de reglas (#32). En el juego v1 son infraestructura 30 %, identidad digital 20 %, configuración 20 % y fugas de datos 30 %. El resultado se redondea al entero, con .5 hacia arriba.
3. **Piso:** si el dominio tiene un hallazgo crítico vigente, su score queda al menos en 60, que es la banda alto. Con dos o más, queda al menos en 80, que es la banda crítico.
4. **Score final:** el mayor entre el ponderado y el piso. Si el piso lo subió, el detalle del score lo dice (#31).

### Aporte de cada hallazgo (#31)

Para el método `rules`, cada severidad equivale a puntos (low = 25, medium = 50, high = 75 y critical = 100). El aporte de un hallazgo vigente a su categoría es `min(max_penalty, puntos_de_severidad × peso_de_regla)`. Se suman los aportes por categoría hasta un máximo de 100; los hallazgos `resolved` y `false_positive` no aportan, mientras `open` y `accepted_risk` sí. El motor conserva severidad, regla, penalización y factores en `score_contributions` para explicar cada cálculo. Si una fuente falla, deja reglas sin cobertura o revisa solo una parte de sus repos, IP o certificados (`ct_logs`), el score se guarda con `partial_coverage = true`.

### Por qué hay un piso

El ponderado es un promedio. Un dominio con todas sus categorías limpias y una sola fuga de credenciales crítica podría quedar en bajo, y el promedio escondería lo más grave. El piso evita eso.

### Qué cuenta para el piso

- Hallazgos con severidad vigente `critical` (`findings.severity`).
- Con estado `open` o `accepted_risk`. Un riesgo aceptado sigue contando en el score (#80). Los `resolved` y los `false_positive` no cuentan.
- El piso aplica al score global del dominio. Las notas por categoría no tienen piso.

## Subcategorías y KRI (#114)

Son una vista sobre el score que ya existe. No cambian el cálculo ni la base: se calculan al leer con los aportes que el score guardó en `score_contributions` y con las corridas de `scan_source_runs` de su escaneo. El mapa vive en `cirdan/score/subcategorias.py` y lleva versión (`VERSION`, hoy 1).

**Subcategorías.** Cada código de regla del catálogo (#30) cae en una subcategoría de su categoría. De cada una, la API da cuántos hallazgos vigentes tiene y cuánto suman sus aportes. Las subcategorías de una categoría suman su nota, salvo que la nota haya llegado al tope de 100.

| Categoría | Subcategoría | Clave | Reglas |
|---|---|---|---|
| Infraestructura | Certificados | `certificates` | `cert_expired`, `cert_expiring_soon` |
| Infraestructura | Exposición de servicios | `exposed_services` | `exposed_rdp`, `exposed_remote_admin`, `exposed_file_sharing`, `exposed_database`, `exposed_ot_device`, `exposed_iot_device`, `exposed_service` |
| Infraestructura | Documentación de APIs expuesta | `exposed_apis` | `exposed_api_docs`, `api_auth_not_declared` |
| Infraestructura | Software vulnerable o sin soporte | `vulnerable_software` | `outdated_software`, `known_vulnerability` |
| Infraestructura | Registro del dominio | `domain_registration` | `domain_expiring_soon` |
| Identidad digital | Suplantación | `impersonation` | `lookalike_domain` |
| Identidad digital | Correos expuestos | `exposed_emails` | `email_in_public_commits`, `personal_email_exposed`, `email_pattern_exposed` |
| Configuración | Correo | `email` | `spf_missing`, `spf_allow_all`, `dmarc_missing`, `dmarc_policy_none` |
| Configuración | Configuración de servidores | `server_configuration` | `server_version_disclosed`, `subdomain_takeover_risk` |
| Fugas de datos | Brechas de datos | `breaches` | `breach_exposure`, `breach_exposure_old`, `breach_exposure_no_passwords` |
| Fugas de datos | Secretos expuestos | `exposed_secrets` | `secret_in_public_repo`, `secret_in_container_image` |
| Fugas de datos | Almacenamiento público | `public_storage` | `public_bucket` |

**KRI.** Encima de las 4 categorías van 5 indicadores clave de riesgo. Cada uno junta subcategorías, aunque sean de categorías distintas, y dice qué fuentes lo alimentan. De cada KRI la API da sus hallazgos vigentes, su severidad más alta, que le da el color en el portal, y lo que suman sus aportes.

| KRI | Clave | Subcategorías | Fuentes |
|---|---|---|---|
| Certificados | `certificates` | `certificates` | `ct_logs` |
| Exposición de servicios | `service_exposure` | `exposed_services`, `exposed_apis` | `shodan`, `api_docs` |
| Correo | `email` | `email` | `dns` |
| Suplantación | `impersonation` | `impersonation` | `ct_logs` |
| Reputación | `reputation` | Ninguna todavía | Ninguna todavía |

**Los KRI no cubren todo el score.** Una regla puede quedar sin KRI y sigue contando en su categoría y en el score. Hoy quedan fuera de los KRI el software vulnerable, el registro del dominio, los correos expuestos, la configuración de servidores y toda la categoría de fugas de datos.

**Un KRI sin datos completos nunca se pinta como sin riesgo.** Su estado (`status`) es uno de cuatro:

- `ok`: todas sus fuentes corrieron completas en el escaneo del score y ninguna regla suya quedó sin cobertura. Solo aquí un cero quiere decir que no se encontró nada.
- `partial` (cobertura parcial): hay datos, pero no de todo. Alguna de sus fuentes no corrió en ese escaneo (`sources_not_run`, por ejemplo `api_docs` mientras siga apagada), revisó solo una parte (`sources_partial`) o dejó alguna regla suya sin cobertura (`rules_without_coverage`). Trae sus hallazgos, su severidad y su suma, y el portal lo muestra con aviso: un cero aquí no es sin riesgo.
- `no_coverage` (sin cobertura): alguna de sus fuentes corrió y no respondió (`sources_failed`), ninguna corrió, o todas sus reglas quedaron sin cobertura aunque la fuente respondiera, como Correo cuando el dominio no existe en el DNS. Sus hallazgos, su severidad y su suma van en `null`, no en cero.
- `no_source_yet` (sin fuente todavía): el KRI aún no tiene fuente. Así sale Reputación hasta que RC-234 esté en dev. También va en `null`.

Las subcategorías no dependen de la cobertura: siempre muestran los aportes del score guardado. Si un aporte es de una regla que el mapa no conoce, o que otro juego de reglas puso en otra categoría, va en una fila `other` (Sin clasificar) de la categoría de su regla y no cuenta en ningún KRI, para que las subcategorías sigan sumando la nota.

Para agregar un código de regla, ponlo en una subcategoría de su categoría y sube `VERSION`. `pruebas/test_catalogo_reglas.py` falla sin base si una regla de las semillas no tiene subcategoría, si su subcategoría es de otra categoría o si las fuentes de un KRI no son las que emiten sus reglas. `pruebas/test_api_v1.py` revisa contra la base que cada regla de cada juego tenga subcategoría de su categoría y que las fuentes de cada KRI existan en `data_sources`.

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
| Demo acme-demo.mx, con sus cuatro hallazgos abiertos | 45, 0, 10, 40 | 1 | 28 | 60 | 60 | Alto |
| Un dominio sin hallazgos críticos | 60, 50, 40, 60 | 0 | 54 | 0 | 54 | Medio |
| Un dominio con una fuga crítica y notas altas | 80, 55, 30, 90 | 1 | 68 | 60 | 68 | Alto |
| Un dominio con una fuga crítica abierta, que sube su nota de fugas a 70 | 40, 30, 20, 70 | 1 | 43 | 60 | 60 | Alto |
| El mismo con dos hallazgos críticos | 40, 30, 20, 70 | 2 | 43 | 80 | 80 | Crítico |

En el cuarto caso la nota de fugas queda en alto, pero el ponderado da 43, que es medio. Sin el piso, el dominio quedaría en medio aunque tiene una fuga crítica abierta.

## Alerta

La alerta `score.above_threshold` se crea en cada cálculo en que el score queda **en el umbral o arriba** (score >= umbral), aunque haya bajado respecto al anterior. Si queda abajo, no se crea. Evitar alertas repetidas para un dominio que se queda arriba del umbral es una propuesta para #65, no cambia este criterio. El umbral por defecto es 60 y cada empresa lo puede cambiar (`organizations.alert_score_threshold`). Con el umbral por defecto, la alerta coincide con el inicio de la banda alto.

## Severidad de cada hallazgo

- La pone su regla del catálogo (#30) con su severidad base: `critical`, `high`, `medium` o `low`.
- El motor puede subirla por sus factores, por ejemplo un hallazgo con regla `high` que pasa a `critical`, y lo registra en la bitácora como `finding.severity_changed`.
- Con la versión A del ML (#34 a #36), el clasificador predice alta, media o baja. **Propuesta para #36, que confirma Emilio:** baja corresponde a `low`, media a `medium` y alta a `high`. Alta queda en `critical` cuando el motor por reglas ya dejó el hallazgo en `critical`, por su regla o por sus factores. El modelo nunca baja un hallazgo que el motor por reglas dejó en `critical`. Así lo que cuenta para el piso queda definido también con `method = 'ml'`. Si Emilio lo decide en #34, alta también pasa a `critical` cuando la probabilidad de alta supera un corte, y así el modelo puede marcar críticos que las reglas no ven.

La v1 usa ExtraTrees sobre 425 filas etiquetadas por un LLM, con una partición fija por plantilla de 287 para entrenamiento y 138 para prueba. No hay revisión humana de esas etiquetas: el macro-F1 de 0.724 frente a 0.588 de reglas y 0.615 de sensibilidad es una comparación experimental, no validación clínica/operativa ni garantía de producción. `confidence` es la salida de `predict_proba` y no está calibrada; sirve como señal del modelo, no como probabilidad verificada. El clasificador solo se usa para calcular el score si supera el baseline de reglas. Si no lo supera, el score sigue por reglas y la predicción/SHAP quedan disponibles como explicación; si falta el artefacto o falla la inferencia, el snapshot registra `method = 'rules'` y el motivo, sin explicación ML.

## Quién usa qué

| Tarjeta | Qué toma de este criterio |
|---|---|
| #4 Plan V3 | La hoja «Criterio de riesgo» del Gantt V3 |
| #30 Catálogo de reglas | La severidad base de cada regla con el criterio de «Qué hace crítico a un hallazgo» |
| #31 Motor de score | `score_dominio()` y el aviso en el detalle cuando aplica el piso, por ejemplo «subido a 60 por 1 hallazgo crítico vigente, la suma ponderada da 43» |
| #33b a #33d Etiquetado a ciegas | Las definiciones de severidad para etiquetar alta, media y baja |
| #34 Clasificador y #36 Integración del ML | Las clases alta, media y baja y su correspondencia con las severidades |
| RC-17 Portal | La banda y su nombre junto al score global del dashboard, y el aviso del piso cuando aplica |
| #114 Letras, subcategorías y KRI | `letra()` y el mapa de `cirdan/score/subcategorias.py`. El portal muestra la letra junto al score, agrupa los hallazgos por subcategoría y pone los 5 KRI encima de las 4 categorías |
| #41 Portal | El nombre de la severidad de cada hallazgo en el panel «por qué es crítico», que la explica con SHAP (#35). La banda del dominio no va en ese panel |
| #65 Alertas | `dispara_alerta()` |

## Código

`cirdan/score/criterio.py` implementa las bandas, las letras, el piso, el ponderado y la alerta, y `cirdan/score/subcategorias.py` el mapa de subcategorías y KRI. Las pruebas están en `pruebas/test_criterio.py`:

```bash
python -m unittest -v pruebas/test_criterio.py
```

## Pregunta para el socio en S10

¿Las bandas y la regla de piso coinciden con cómo IKUSI prioriza a sus clientes?
