"""Plan de acción agrupado y simulación sin persistencia (#42, #70)."""
import csv
import io
import json

from cirdan.score import criterio, motor


ESTADOS_PLAN = {'open'}


def _hallazgos_con_severidad(hallazgos, severidades):
    preparados = []
    for hallazgo in hallazgos:
        copia = dict(hallazgo)
        if severidades and copia['id'] in severidades:
            copia['severity'] = severidades[copia['id']]
        preparados.append(copia)
    return preparados


def simular(hallazgos, reglas, pesos_categoria, action_ids, severidades=None):
    """Devuelve el score contrafactual al resolver las acciones seleccionadas, sin escribir."""
    codigos_abiertos = {h['rule_code'] for h in hallazgos if h['status'] in ESTADOS_PLAN}
    seleccion = set(action_ids)
    if not seleccion:
        raise ValueError('selecciona al menos una acción')
    desconocidos = seleccion - codigos_abiertos
    if desconocidos:
        raise ValueError('acción desconocida o sin hallazgos abiertos: %s' % ', '.join(sorted(desconocidos)))

    preparados = _hallazgos_con_severidad(hallazgos, severidades)
    restantes = [
        {**hallazgo, 'status': 'resolved'}
        if hallazgo['status'] == 'open' and hallazgo['rule_code'] in seleccion
        else hallazgo
        for hallazgo in preparados
    ]
    antes = motor.calcular(preparados, reglas, pesos_categoria)
    despues = motor.calcular(restantes, reglas, pesos_categoria)
    return {
        'score_before': antes['score'],
        'score_after': despues['score'],
        'score_reduction': antes['score'] - despues['score'],
        'band_before': antes['banda'],
        'band_after': despues['banda'],
        'category_scores_before': antes['category_scores'],
        'category_scores_after': despues['category_scores'],
        'floor_message_after': despues['floor_message'],
        'method': 'ml' if severidades is not None else 'rules',
    }


def construir_plan(dominio, hallazgos, reglas, pesos_categoria, method='rules', severidades=None,
                   partial_coverage=False):
    """Agrupa por regla/recomendación y calcula el impacto individual de cada acción."""
    preparados = _hallazgos_con_severidad(hallazgos, severidades)
    antes = motor.calcular(preparados, reglas, pesos_categoria)
    grupos = {}
    for hallazgo in preparados:
        if hallazgo['status'] not in ESTADOS_PLAN:
            continue
        codigo = hallazgo['rule_code']
        regla = reglas.get(codigo)
        if regla is None:
            raise ValueError('hallazgo sin regla activa: %s' % codigo)
        grupo = grupos.setdefault(codigo, {
            'id': codigo,
            'rule_code': codigo,
            'category': regla['category'],
            'recommendation': regla['recommendation'],
            'finding_ids': [],
        })
        grupo['finding_ids'].append(hallazgo['id'])

    acciones = []
    for codigo, grupo in grupos.items():
        impacto = simular(preparados, reglas, pesos_categoria, [codigo], severidades)
        acciones.append({
            **grupo,
            'finding_count': len(grupo['finding_ids']),
            'score_after': impacto['score_after'],
            'score_reduction': impacto['score_reduction'],
        })
    acciones.sort(key=lambda accion: (-accion['score_reduction'], accion['category'], accion['id']))
    return {
        'domain': dominio,
        'score_before': antes['score'],
        'band_before': antes['banda'],
        'category_scores_before': antes['category_scores'],
        'method': method,
        'partial_coverage': partial_coverage,
        'actions': acciones,
        'total': len(acciones),
    }


def escapar_formula(value):
    """Evita que texto de hallazgos se ejecute como fórmula al abrir las exportaciones."""
    if isinstance(value, str) and value.startswith(('=', '+', '-', '@')):
        return "'" + value
    if isinstance(value, list):
        return [escapar_formula(item) for item in value]
    if isinstance(value, dict):
        return {key: escapar_formula(item) for key, item in value.items()}
    return value


def exportar_json(plan):
    return json.dumps(escapar_formula(plan), ensure_ascii=False, separators=(',', ':'))


def exportar_csv(plan):
    salida = io.StringIO(newline='')
    writer = csv.writer(salida, lineterminator='\r\n')
    writer.writerow(('dominio', 'accion', 'categoria', 'recomendacion', 'hallazgos', 'ids_hallazgo', 'score_antes', 'score_despues', 'reduccion_score'))
    for accion in plan['actions']:
        writer.writerow((
            escapar_formula(plan['domain']),
            escapar_formula(accion['id']),
            escapar_formula(accion['category']),
            escapar_formula(accion['recommendation']),
            accion['finding_count'],
            escapar_formula(';'.join(accion['finding_ids'])),
            plan['score_before'],
            accion['score_after'],
            accion['score_reduction'],
        ))
    return '\ufeff' + salida.getvalue()
