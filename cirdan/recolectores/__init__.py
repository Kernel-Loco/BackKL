"""Recolectores OSINT pasivos de Cirdan. Cada uno consulta una fuente pública y
devuelve activos y hallazgos del dominio autorizado, sin tocar sus servidores.
Todos cumplen el contrato de plugin de cirdan/recolectores/contrato.py (#13)."""
import importlib

# data_sources.code -> módulo del recolector. 'ejemplo' es solo para pruebas.
REGISTRO = {'ct_logs': 'cirdan.recolectores.crtsh', 'ejemplo': 'cirdan.recolectores.ejemplo'}


def cargar(fuente):
    """El módulo del recolector de una fuente, para pasarlo a contrato.ejecutar()."""
    if fuente not in REGISTRO:
        raise KeyError('no hay recolector para la fuente %r' % fuente)
    return importlib.import_module(REGISTRO[fuente])
