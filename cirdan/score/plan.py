"""Plan de acción agrupado y simulación sin persistencia (#42, #70), por regla o por activo y en orden acumulado
(RC-263)."""
import csv
import io
import json
from decimal import ROUND_HALF_UP, Decimal

from cirdan.exportar import escapar_formula  # noqa: F401 (también lo importan las pruebas)
from cirdan.score import criterio, motor


ESTADOS_PLAN = {'open'}
AGRUPACIONES = ('regla', 'activo')


def _hallazgos_con_severidad(hallazgos, severidades):
    preparados = []
    for hallazgo in hallazgos:
        copia = dict(hallazgo)
        if severidades and copia['id'] in severidades:
            copia['severity'] = severidades[copia['id']]
        preparados.append(copia)
    return preparados


def _actual(recalculado, guardado, cortes=None):
    """Score 'Actual': el último guardado, el mismo que muestran /score y /domains. Sin score guardado, el recalculado.
    Su banda sale de los cortes del juego con que se guardó (RC-237), los mismos con que se recalcula el 'después'."""
    if guardado is None:
        return recalculado
    return {'score': guardado['score'], 'banda': criterio.banda(guardado['score'], cortes),
            'category_scores': guardado['category_scores']}


def simular(hallazgos, reglas, pesos_categoria, action_ids, severidades=None, guardado=None, cortes=None):
    """Devuelve el score contrafactual al resolver las acciones seleccionadas, sin escribir.

    El 'después' se recalcula con el motor y la reducción es lo que baja el motor al resolverlas, así que nunca
    es negativa aunque el score guardado no cuadre con los hallazgos de ahora (escaneo en curso o caído).
    """
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
    vigente = motor.calcular(preparados, reglas, pesos_categoria, cortes)
    antes = _actual(vigente, guardado, cortes)
    despues = motor.calcular(restantes, reglas, pesos_categoria, cortes)
    return {
        'score_before': antes['score'],
        'score_after': despues['score'],
        'score_reduction': vigente['score'] - despues['score'],
        'band_before': antes['banda'],
        'band_after': despues['banda'],
        'category_scores_before': antes['category_scores'],
        'category_scores_after': despues['category_scores'],
        'floor_message_after': despues['floor_message'],
        'method': 'ml' if severidades is not None else 'rules',
    }


class _Puntaje:
    """El score del motor al resolver un conjunto de hallazgos, sin volver a recorrerlos todos (RC-263).

    Parte de los aportes de motor.calcular() sobre los hallazgos vigentes: cada uno ya trae su penalización con el
    tope de su regla. La nota de una categoría es la suma de las penalizaciones que siguen vigentes, hasta 100 (como el
    min() del motor, que con sumandos no negativos da lo mismo), redondeada a centésimas, y el score global es el mayor
    entre el ponderado redondeado y el piso de los críticos que quedan, como criterio.score_dominio(). Los cortes y los
    pesos se validan una vez, con motor.calcular() sobre el vigente, y cada candidato solo recalcula las categorías que
    toca. Las pruebas comparan este score con motor.calcular() y con score_dominio().
    """

    def __init__(self, preparados, reglas, pesos_categoria, cortes):
        self.vigente = motor.calcular(preparados, reglas, pesos_categoria, cortes)
        por_id = {h['id']: h for h in preparados}
        self.aporte = {}
        for a in self.vigente['contributions']:
            hallazgo = por_id[a['finding_id']]
            self.aporte[a['finding_id']] = (reglas[hallazgo['rule_code']]['category'], a['penalty'],
                                            a['severity'] == 'critical')
        self.peso = {c: Decimal(str(pesos_categoria[c])) for c in criterio.CATEGORIAS}
        self.pisos = tuple(criterio.piso(n, cortes) for n in (0, 1, 2))

        self._suma = {c: Decimal('0') for c in criterio.CATEGORIAS}
        for categoria, penalizacion, _ in self.aporte.values():
            self._suma[categoria] += penalizacion

    def inicio(self):
        """Las sumas por categoría y los críticos de todos los hallazgos vigentes (una copia)."""
        return dict(self._suma), self.vigente['critical_open']

    def quita(self, finding_ids):
        """Lo que se resta por categoría (solo las que toca) y en críticos al resolver esos hallazgos. Los que no
        puntúan no restan."""
        resta = {}
        criticos = 0
        for fid in finding_ids:
            if fid in self.aporte:
                categoria, penalizacion, critico = self.aporte[fid]
                resta[categoria] = resta.get(categoria, Decimal('0')) + penalizacion
                criticos += critico
        return resta, criticos

    def parte(self, categoria, suma):
        """Lo que aporta una categoría al ponderado: su nota de 0 a 100 en centésimas por su peso."""
        return min(Decimal('100'), suma).quantize(Decimal('0.01')) * self.peso[categoria]

    def final(self, ponderado, criticos):
        redondeado = int(ponderado.quantize(Decimal('1'), rounding=ROUND_HALF_UP))
        return max(redondeado, self.pisos[min(criticos, 2)])

    def score(self, suma, criticos):
        return self.final(sum(self.parte(c, suma[c]) for c in criterio.CATEGORIAS), criticos)

    def sin(self, finding_ids):
        """El score al resolver solo esos hallazgos."""
        suma, criticos = self.inicio()
        resta, menos = self.quita(finding_ids)
        return self.score({c: suma[c] - resta.get(c, Decimal('0')) for c in criterio.CATEGORIAS}, criticos - menos)


class _Avance:
    """Lo ya resuelto mientras se arma el orden acumulado: sumas por categoría, críticos y el ponderado."""

    def __init__(self, puntaje):
        self.puntaje = puntaje
        self.suma, self.criticos = puntaje.inicio()
        self.partes = {c: puntaje.parte(c, self.suma[c]) for c in criterio.CATEGORIAS}
        self.ponderado = sum(self.partes.values())
        self.score = puntaje.final(self.ponderado, self.criticos)

    def con(self, resta, menos):
        """El score al resolver además esa acción, recalculando solo las categorías que toca."""
        ponderado = self.ponderado
        for c, r in resta.items():
            ponderado += self.puntaje.parte(c, self.suma[c] - r) - self.partes[c]
        return self.puntaje.final(ponderado, self.criticos - menos)

    def resuelve(self, accion, resta, menos):
        score = self.con(resta, menos)
        for c, r in resta.items():
            self.suma[c] -= r
            nueva = self.puntaje.parte(c, self.suma[c])
            self.ponderado += nueva - self.partes[c]
            self.partes[c] = nueva
        self.criticos -= menos
        accion['score_reduction_acumulado'] = self.score - score
        accion['score_after_acumulado'] = score
        self.score = score


def _acumular(acciones, puntaje):
    """score_reduction_acumulado y score_after_acumulado en el orden dado: lo que baja el motor al resolver cada acción
    después de todas las de arriba. Nunca es negativo y la última deja el score de resolver todo."""
    avance = _Avance(puntaje)
    for accion in acciones:
        avance.resuelve(accion, *puntaje.quita(accion['finding_ids']))
    return acciones


def _orden_voraz(acciones, puntaje, desempate):
    """Ordena las acciones de forma voraz y les pone la acumulada: primero la que más baja el score sola y luego, una
    por una, la que más lo baja sobre lo ya resuelto. Con empate, `desempate` (categoría e id).

    Las acciones que restan lo mismo (por categoría y en críticos) dan el mismo score en cada ronda, así que se prueba
    una por grupo, la primera del desempate que sigue pendiente, y cada prueba solo recalcula las categorías que toca.
    Con miles de activos suele haber pocos grupos (reglas por severidad), aunque en el peor caso cada ronda prueba
    todas las que quedan.
    """
    avance = _Avance(puntaje)
    posicion = sorted(range(len(acciones)), key=lambda i: desempate(acciones[i]))
    grupos = {}   # firma -> índices pendientes en orden de desempate
    for i in posicion:
        resta, menos = puntaje.quita(acciones[i]['finding_ids'])
        grupos.setdefault((tuple(sorted(resta.items())), menos), []).append(i)
    rango = {i: n for n, i in enumerate(posicion)}
    siguiente = {firma: 0 for firma in grupos}
    ordenadas = []
    for _ in range(len(acciones)):
        mejor = None
        for firma, indices in grupos.items():
            k = siguiente[firma]
            if k == len(indices):
                continue
            resta, menos = dict(firma[0]), firma[1]
            clave = (avance.con(resta, menos), rango[indices[k]])   # con empate gana el primero del desempate
            if mejor is None or clave < mejor[0]:
                mejor = (clave, firma, resta, menos)
        _, firma, resta, menos = mejor
        i = grupos[firma][siguiente[firma]]
        siguiente[firma] += 1
        avance.resuelve(acciones[i], resta, menos)
        ordenadas.append(acciones[i])
    return ordenadas


def _regla(reglas, codigo):
    regla = reglas.get(codigo)
    if regla is None:
        raise ValueError('hallazgo sin regla activa: %s' % codigo)
    return regla


def _grupos_por_regla(preparados, reglas):
    grupos = {}
    for hallazgo in preparados:
        if hallazgo['status'] not in ESTADOS_PLAN:
            continue
        codigo = hallazgo['rule_code']
        regla = _regla(reglas, codigo)
        grupo = grupos.setdefault(codigo, {
            'id': codigo,
            'rule_code': codigo,
            'category': regla['category'],
            'recommendation': regla['recommendation'],
            'finding_ids': [],
        })
        grupo['finding_ids'].append(hallazgo['id'])
    return grupos


def _grupos_por_activo(preparados, reglas):
    """Una acción por activo con hallazgos abiertos: sus hallazgos de todas las reglas y la recomendación de cada regla,
    por categoría y código. `category` es la primera de sus categorías en orden alfabético, para el desempate."""
    grupos = {}
    for hallazgo in preparados:
        if hallazgo['status'] not in ESTADOS_PLAN:
            continue
        codigo = hallazgo['rule_code']
        regla = _regla(reglas, codigo)
        activo = hallazgo.get('asset_id')
        if not activo:
            raise ValueError('hallazgo sin activo: %s' % hallazgo['id'])
        grupo = grupos.setdefault(activo, {
            'id': activo,
            'asset_id': activo,
            'asset_type': hallazgo.get('asset_type'),
            'asset_value': hallazgo.get('asset_value'),
            'recommendations': {},
            'finding_ids': [],
        })
        grupo['recommendations'].setdefault(codigo, {'rule_code': codigo, 'category': regla['category'],
                                                     'recommendation': regla['recommendation']})
        grupo['finding_ids'].append(hallazgo['id'])
    for grupo in grupos.values():
        recomendaciones = sorted(grupo['recommendations'].values(), key=lambda r: (r['category'], r['rule_code']))
        grupo['recommendations'] = recomendaciones
        grupo['rule_codes'] = [r['rule_code'] for r in recomendaciones]
        grupo['categories'] = sorted({r['category'] for r in recomendaciones})
        grupo['category'] = grupo['categories'][0]
    return grupos


def construir_plan(dominio, hallazgos, reglas, pesos_categoria, method='rules', severidades=None,
                   partial_coverage=False, guardado=None, cortes=None, agrupar='regla'):
    """Agrupa por regla/recomendación (o por activo con `agrupar='activo'`, RC-263) y calcula el impacto de cada acción:
    el individual (score_after y score_reduction, resolviéndola sola) y el acumulado (resolviéndola después de las de
    arriba). Por regla el orden es el de hoy, por lo que baja cada acción sola, así que la respuesta y el CSV solo suman
    las columnas acumuladas. Por activo el orden es voraz.

    `cortes`: los de bandas del juego del score (RC-237). Mueven el piso y la banda del antes y del después.
    """
    if agrupar not in AGRUPACIONES:
        raise ValueError("agrupar debe ser 'regla' o 'activo'")
    preparados = _hallazgos_con_severidad(hallazgos, severidades)
    puntaje = _Puntaje(preparados, reglas, pesos_categoria, cortes)
    antes = _actual(puntaje.vigente, guardado, cortes)
    grupos = (_grupos_por_regla if agrupar == 'regla' else _grupos_por_activo)(preparados, reglas)

    acciones = []
    for grupo in grupos.values():
        if agrupar == 'regla':   # el individual de siempre, con simular()
            impacto = simular(preparados, reglas, pesos_categoria, [grupo['id']], severidades, guardado, cortes)
            despues, reduccion = impacto['score_after'], impacto['score_reduction']
        else:
            despues = puntaje.sin(grupo['finding_ids'])
            reduccion = puntaje.vigente['score'] - despues
        acciones.append({
            **grupo,
            'finding_count': len(grupo['finding_ids']),
            'score_after': despues,
            'score_reduction': reduccion,
        })
    if agrupar == 'regla':   # el orden de hoy (RC-72): lo que baja sola, categoría e id
        acciones.sort(key=lambda accion: (-accion['score_reduction'], accion['category'], accion['id']))
        acciones = _acumular(acciones, puntaje)
    else:
        acciones = _orden_voraz(acciones, puntaje, lambda accion: (accion['category'], accion['id']))
    return {
        'domain': dominio,
        'score_before': antes['score'],
        'band_before': antes['banda'],
        'category_scores_before': antes['category_scores'],
        'method': method,
        'partial_coverage': partial_coverage,
        'grouping': agrupar,
        'actions': acciones,
        'total': len(acciones),
    }


def exportar_json(plan):
    return json.dumps(escapar_formula(plan), ensure_ascii=False, separators=(',', ':'))


def exportar_csv(plan):
    """El CSV del plan. Por regla, las columnas de siempre y al final la reducción acumulada y el score que deja. Por
    activo además el valor y tipo del activo y sus reglas, con las categorías y recomendaciones juntas (';' y ' | ')."""
    salida = io.StringIO(newline='')
    writer = csv.writer(salida, lineterminator='\r\n')
    por_activo = plan.get('grouping') == 'activo'
    writer.writerow(('dominio', 'accion', 'categoria', 'recomendacion', 'hallazgos', 'ids_hallazgo', 'score_antes',
                     'score_despues', 'reduccion_score', 'reduccion_acumulada', 'score_despues_acumulado')
                    + (('activo', 'tipo_activo', 'reglas') if por_activo else ()))
    for accion in plan['actions']:
        if por_activo:
            categoria = ';'.join(accion['categories'])
            recomendacion = ' | '.join(r['recommendation'] or '' for r in accion['recommendations'])
        else:
            categoria, recomendacion = accion['category'], accion['recommendation']
        fila = (
            escapar_formula(plan['domain']),
            escapar_formula(accion['id']),
            escapar_formula(categoria),
            escapar_formula(recomendacion),
            accion['finding_count'],
            escapar_formula(';'.join(accion['finding_ids'])),
            plan['score_before'],
            accion['score_after'],
            accion['score_reduction'],
            accion['score_reduction_acumulado'],
            accion['score_after_acumulado'],
        )
        if por_activo:
            fila += (escapar_formula(accion['asset_value']), escapar_formula(accion['asset_type']),
                     escapar_formula(';'.join(accion['rule_codes'])))
        writer.writerow(fila)
    return '﻿' + salida.getvalue()
