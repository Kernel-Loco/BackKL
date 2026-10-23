"""ML de Cirdan: dataset semisintético etiquetado a ciegas (#33, RC-65).

- plantillas.py: las 24 plantillas del lote y la severidad base de cada código.
- caracteristicas.py: tipo, antigüedad, exposición y sensibilidad de un hallazgo, con la rúbrica.
- generar_lote.py: arma el lote con semilla fija, el maestro y la copia de cada etiquetador.
- acuerdo.py: junta las etiquetas, arma dataset.csv, mide el acuerdo (kappa) y compara al etiquetador LLM.

El método completo está en docs/dataset_ml.md.
"""
