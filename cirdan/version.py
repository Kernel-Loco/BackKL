"""Versión de LowTide (#18, RC-46, comentario 10281 punto 1).

Una sola versión para todo el build: la declara la API (cirdan/api/main.py) y va en el User-Agent de toda petición de
las fuentes y la visita web (cirdan/recolectores/contrato.py, AGENTE). Es la versión con la que se etiqueta el
código: 1.0-rc al congelar el 25 nov (etiqueta v1.0-rc) y 1.0 en la entrega final (v1.0). Quien pone la etiqueta sube
este valor en el mismo PR de dev a main.
"""

VERSION = '1.0-rc'
