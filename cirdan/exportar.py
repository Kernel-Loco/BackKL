"""Celdas de CSV seguras para Excel (#24, RC-57) y el escape que comparte el plan de acción (#42).

Títulos, banners y evidencia vienen de sitios ajenos. Una celda que empieza con =, +, - o @, o con un
tabulador o un retorno de carro, Excel la puede tomar como fórmula, así que se le antepone una comilla
(OWASP, CSV Injection). Solo se escapa el texto: un número negativo sigue siendo número.
Excel con separador de lista ';' (es-ES, es-CO, es-AR) o LibreOffice con ';' o tabulador parten la celda
en ese carácter, así que también lleva comilla lo que sigue a un ';', un tabulador o un salto de línea, y
la celda con ';' o tabulador va entre comillas.
El CSV va en UTF-8 con BOM para que Excel en español lea bien los acentos.
"""
import io
import json
import re
from datetime import date, datetime
from decimal import Decimal

INICIOS_DE_FORMULA = ('=', '+', '-', '@', '\t', '\r')
# Un inicio de fórmula justo después de un separador que Excel o LibreOffice podrían usar.
# Las comillas dobles de en medio no cuentan: en x;"=cmd Excel cierra la comilla vacía y deja =cmd.
_TRAS_SEPARADOR = re.compile(r'(?<=[;\t\r\n])(?="*[=+\-@\t\r])')
_PIDE_COMILLAS = re.compile(r'[",;\t\r\n]')
BOM = '﻿'


def escapar_formula(value):
    """Antepone una comilla al texto que Excel podría ejecutar. Recorre listas y diccionarios."""
    if isinstance(value, str):
        value = _TRAS_SEPARADOR.sub("'", value)
        return "'" + value if value.startswith(INICIOS_DE_FORMULA) else value
    if isinstance(value, list):
        return [escapar_formula(item) for item in value]
    if isinstance(value, dict):
        return {key: escapar_formula(item) for key, item in value.items()}
    return value


def celda(value):
    """Texto de una celda: vacío para None, JSON para listas y diccionarios, ISO 8601 para fechas."""
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float, Decimal)):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return escapar_formula(str(value))


def campo(texto):
    """Entre comillas si trae coma, comilla doble, ';', tabulador o salto de línea (csv.writer no cubre ';' ni tab)."""
    return '"%s"' % texto.replace('"', '""') if _PIDE_COMILLAS.search(texto) else texto


def csv_con_bom(encabezados, filas):
    """CSV con BOM, fin de línea CRLF y cada celda pasada por celda() y campo()."""
    salida = io.StringIO(newline='')
    for fila in (encabezados, *filas):
        salida.write(','.join(campo(celda(v)) for v in fila) + '\r\n')
    return BOM + salida.getvalue()
