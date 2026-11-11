"""Comparación hallazgo por hallazgo entre dos scores guardados del mismo dominio (#24, RC-57).

Cada score guarda en score_contributions un aporte por hallazgo vigente (open o accepted_risk) en ese
momento, así que esos aportes son la foto de qué hallazgos tenía el dominio en ese escaneo o recálculo.
Comparar dos fotos dice qué hallazgo es nuevo, cuál ya no está y cuál sigue, y si cambió su severidad.
'gone' no dice por qué ya no está: puede estar resuelto, marcado como falso positivo o, si 'desde' es
más nuevo que 'hasta', ser uno que apareció después. El estado de hoy va en status_now.
"""
from cirdan.exportar import csv_con_bom

CAMBIOS = ('new', 'gone', 'kept')
_ORDEN_SEVERIDAD = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

ENCABEZADOS_CSV = (
    'dominio', 'desde_score_id', 'desde_fecha', 'hasta_score_id', 'hasta_fecha', 'hallazgo_id', 'cambio',
    'cambio_severidad', 'titulo', 'regla', 'categoria', 'activo', 'tipo_activo', 'severidad_desde',
    'severidad_hasta', 'puntos_desde', 'puntos_hasta', 'estado_actual',
)


def comparar(aportes_desde, aportes_hasta):
    """Une los aportes de los dos scores por finding_id.

    Cada aporte trae finding_id, severity, penalty, title, rule_code, category, asset, asset_type y status.
    title, asset, asset_type y status llegan del hallazgo de hoy. Con una llave de API de un solo dominio,
    asset, asset_type y status vienen en None si el hallazgo hoy es de otro dominio (cirdan/api/v1.py).
    Devuelve los renglones de 'items' y el resumen con los conteos por cambio.
    """
    desde = {a['finding_id']: a for a in aportes_desde}
    hasta = {a['finding_id']: a for a in aportes_hasta}
    items = []
    for finding_id in desde.keys() | hasta.keys():
        antes, despues = desde.get(finding_id), hasta.get(finding_id)
        base = despues or antes
        cambio = 'new' if antes is None else 'gone' if despues is None else 'kept'
        severidad_desde = antes['severity'] if antes else None
        severidad_hasta = despues['severity'] if despues else None
        items.append({
            'finding_id': finding_id,
            'change': cambio,
            'severity_changed': cambio == 'kept' and severidad_desde != severidad_hasta,
            'title': base['title'], 'rule_code': base['rule_code'], 'category': base['category'],
            'asset': base['asset'], 'asset_type': base['asset_type'],
            'severity_from': severidad_desde, 'severity_to': severidad_hasta,
            'penalty_from': float(antes['penalty']) if antes else None,
            'penalty_to': float(despues['penalty']) if despues else None,
            'status_now': base['status'],
        })
    items.sort(key=lambda i: (CAMBIOS.index(i['change']),
                              _ORDEN_SEVERIDAD[i['severity_to'] or i['severity_from']],
                              i['rule_code'], i['asset'] or '', i['finding_id']))
    resumen = {c: sum(1 for i in items if i['change'] == c) for c in CAMBIOS}
    resumen['severity_changed'] = sum(1 for i in items if i['severity_changed'])
    return items, resumen


def exportar_csv(comparacion):
    d, h = comparacion['from'], comparacion['to']
    filas = [(comparacion['domain'], d['score_id'], d['computed_at'], h['score_id'], h['computed_at'],
              i['finding_id'], i['change'], i['severity_changed'], i['title'], i['rule_code'], i['category'],
              i['asset'], i['asset_type'], i['severity_from'], i['severity_to'], i['penalty_from'], i['penalty_to'],
              i['status_now']) for i in comparacion['items']]
    return csv_con_bom(ENCABEZADOS_CSV, filas)
