"""Celdas de CSV seguras para Excel (#24, RC-57) y el escape que comparte el plan de acción (#42).

Títulos, banners y evidencia vienen de sitios ajenos. Una celda que empieza con =, +, - o @, o con un
tabulador o un retorno de carro, Excel la puede tomar como fórmula, así que se le antepone una comilla
(OWASP, CSV Injection). Solo se escapa el texto: un número negativo sigue siendo número.
El CSV va en UTF-8 con BOM para que Excel en español lea bien los acentos.
"""
import csv
import io
import json
from datetime import date, datetime
from decimal import Decimal

INICIOS_DE_FORMULA = ('=', '+', '-', '@', '\t', '\r')
BOM = '﻿'


def escapar_formula(value):
    """Antepone una comilla al texto que Excel podría ejecutar. Recorre listas y diccionarios."""
    if isinstance(value, str) and value.startswith(INICIOS_DE_FORMULA):
        return "'" + value
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


def csv_con_bom(encabezados, filas):
    """CSV con BOM, fin de línea CRLF y cada celda pasada por celda()."""
    salida = io.StringIO(newline='')
    writer = csv.writer(salida, lineterminator='\r\n')
    writer.writerow([celda(e) for e in encabezados])
    for fila in filas:
        writer.writerow([celda(v) for v in fila])
    return BOM + salida.getvalue()
