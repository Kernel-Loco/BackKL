"""Recolector de ejemplo (#13): cumple el contrato sin consultar ninguna fuente.

Sirve para probar el orquestador (#22) y la normalización (#23) sin red. Con 'reproducir' lee
respuestas_grabadas/ejemplo/<dominio>/resultado.json. Con 'vivo' o 'grabar' arma un resultado fijo:
el dominio, su www y un hallazgo spf_missing (regla del catálogo demo). No está en data_sources:
es solo para pruebas.
"""
import hashlib

from recolectores.contrato import CARPETA_GRABADAS as RAIZ
from recolectores.contrato import Activo, Grabadora, Hallazgo, Resultado

FUENTE = 'ejemplo'
CARPETA_GRABADAS = RAIZ / 'ejemplo'


def crear_cliente(modo, dominio):
    return Grabadora(CARPETA_GRABADAS / dominio.strip().lower().rstrip('.'), modo, nueva=(modo == 'grabar'))


def _fijo(dominio):
    titulo = 'Falta el registro SPF en %s' % dominio
    return {
        'activos': [{'tipo': 'domain', 'valor': dominio, 'atributos': {}},
                    {'tipo': 'subdomain', 'valor': 'www.' + dominio, 'atributos': {}}],
        'hallazgos': [{'codigo': 'spf_missing', 'severidad': 'low', 'activo': dominio, 'titulo': titulo,
                       'evidencia': {'title': titulo, 'registro': dominio, 'observado': 'sin TXT v=spf1'},
                       'caracteristicas': {'tipo': 'spf_faltante', 'antiguedad_dias': 0, 'exposicion': 'publica',
                                           'sensibilidad': 'baja'},
                       'huella': hashlib.sha256(('%s|spf_missing|%s' % (FUENTE, dominio)).encode()).hexdigest()}],
    }


def recolectar(dominio, cliente=None, ahora=None, propios=()):
    dominio = dominio.strip().lower().rstrip('.')
    cliente = cliente or crear_cliente('vivo', dominio)
    del_disco, datos = cliente.de_disco('resultado')
    if not del_disco:
        datos = _fijo(dominio)
        cliente.guardar('resultado', datos)
    return Resultado(dominio, FUENTE, activos=[Activo(**a) for a in datos['activos']],
                     hallazgos=[Hallazgo(**h) for h in datos['hallazgos']])
