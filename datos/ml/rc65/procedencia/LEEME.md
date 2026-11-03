# Procedencia de las etiquetas de los LLM (RC-65)

Lo que recibió y lo que devolvió cada agente que etiquetó el lote, tal cual. De aquí salen `etiquetas/llm.csv`, `llm_repeticion.csv`, `llm_sonnet.csv` y `llm_haiku.csv`, y `pruebas/test_dataset_ml.py` revisa que salgan byte a byte. Son etiquetas de LLM declarados, no de personas (ver Etiquetador LLM en `docs/dataset_ml.md`).

## Corridas

| Modelo | Fecha, hora de Monterrey | Flujo de Claude Code | Entrada y agente | Salida | CSV |
|---|---|---|---|---|---|
| Claude Opus 5.5 (`claude-opus-5-5`) | 22 oct 2026, 13:30 a 13:33 | `wf_2a88e094-71c` | `lote_1` (`acb631c8b0177a091`), `lote_2` (`a6595c687e275bc74`), `lote_3` (`a4d7ad0435e297ade`), `lote_4` (`a303ec04767fab687`) y `lote_5` (`a048d8b444be8e01f`) | `salida_opus.json`, de `lote_1` a `lote_5` | `llm.csv` |
| Claude Opus 5.5 (`claude-opus-5-5`) | 22 oct 2026, 13:30 a 13:31 | `wf_2a88e094-71c` | `comun_repeticion` (`a9ea2e8264e4e48b7`) | `salida_opus.json`, en `comun_repeticion` | `llm_repeticion.csv` |
| Claude Sonnet 5.5 (`claude-sonnet-5-5`) | 22 oct 2026, 18:26 a 18:28 | `wf_be5c7844-76d` | `comun_repeticion` (`a6f3ec2c369f1cb0f`) | `salida_sonnet.json` | `llm_sonnet.csv` |
| Claude Haiku 5.5 (`claude-haiku-5-5`) | 22 oct 2026, 18:26 a 18:28 | `wf_be5c7844-76d` | `comun_repeticion` (`a5846b26899ad7dcb`) | `salida_haiku.json` | `llm_haiku.csv` |

Son 8 agentes nuevos: 6 de Opus, uno por archivo de `entrada/`, y uno de Sonnet y otro de Haiku, los dos con `comun_repeticion.txt`. Ninguno vio las etiquetas de otro.

Antes, a las 13:30, un primer flujo de Opus (`wf_8a59ea88-d3b`) se detuvo a los 4 segundos sin etiquetas. Cada uno de sus agentes intentó leer el archivo que le dio ese flujo, con un nombre que no es de `entrada/` y que no existía, y no hizo nada más. Ninguno vio un hallazgo. No cuenta entre los 8. Se comprobó el 2 nov en el registro de Claude Code de cada uno de sus agentes y en el de la conversación que lo lanzó, donde la carpeta local de la que leía ese flujo no tenía esos archivos.

## Archivos

| Archivo | Qué es |
|---|---|
| `prompt.txt` | El prompt de los 8 agentes. Solo cambian `<carpeta>`, una carpeta local fuera del repo, `<archivo>`, su archivo de `entrada/`, y `<N>`, que es 85 en los lotes y 60 en `comun_repeticion` |
| `esquema_salida.json` | El esquema con que cada agente devolvió sus etiquetas: `id`, `etiqueta` (alta, media o baja) y `nota` |
| `entrada/lote_1.txt` a `lote_5.txt` | Las 425 filas del maestro en orden al azar, 85 por archivo y sin repetir |
| `entrada/comun_repeticion.txt` | Las 60 filas del bloque común en otro orden, el de `random.Random(7).shuffle` sobre sus ids ordenados |
| `salida_opus.json` | La salida del flujo de Opus tal cual. Por cada archivo de entrada trae `etiquetas`, en el orden de la entrada, y `faltan`, los ids que el agente no devolvió. `faltan` está vacío en los 6 y en `wf_2a88e094-71c` no hubo reintentos |
| `salida_sonnet.json` y `salida_haiku.json` | Las etiquetas que devolvió cada agente, tal cual |

Cada hallazgo de `entrada/` trae lo mismo que su fila en las copias del Excel (`copias/`): id, título, tipo de activo, activo, fuente, evidencia y, cuando hay, CVE, CVSS, EPSS y KEV. En dos filas el CVSS 4.0 sale como 4. No trae la regla, la severidad, la plantilla, la clase esperada ni las características.

## Cómo se comprobó

El 2 nov 2026, en el registro de Claude Code de cada uno de los 8 agentes de la tabla de corridas:

- Recibió `prompt.txt` con los tres cambios de arriba y el esquema de `esquema_salida.json`. Claude Code le agrega a todo agente su contexto de siempre (fecha, entorno, herramientas y el índice de memoria del usuario) y el mensaje del chat que lanzó el flujo. Nada de eso trae el maestro, las plantillas, la clase esperada ni otras etiquetas.
- Hizo una sola lectura, la de su archivo completo, igual línea por línea al de `entrada/`. No usó otra herramienta. Luego devolvió sus etiquetas.
- Lo que devolvió es igual a su parte de `salida_opus.json`, a `salida_sonnet.json` o a `salida_haiku.json`.

Los registros no se suben porque traen rutas y datos de la PC del autor.

## Cómo salen los CSV

De cada salida se toman las etiquetas ordenadas por id, con `id`, `etiqueta` y `nota` sin espacios al inicio ni al final, y se escriben con `csv.writer` de Python, que termina cada línea con CRLF. `llm.csv` junta `lote_1` a `lote_5`. Lo revisa la clase `Procedencia` de `pruebas/test_dataset_ml.py`, que también revisa que cada agente devolviera justo los ids de su entrada y que la entrada sea el texto de las copias.

Nada de esta carpeta se edita. Si cambia un CSV de `etiquetas/`, una salida o un archivo de `entrada/`, la prueba falla. `prompt.txt` y este LEEME no tienen prueba, y del esquema solo se revisan campos y valores.
