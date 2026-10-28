"""Cálculo explicable del score a partir de hallazgos y reglas activas (#31)."""
from decimal import Decimal

from cirdan.score import criterio

PUNTOS_SEVERIDAD = {
    'low': Decimal('25'),
    'medium': Decimal('50'),
    'high': Decimal('75'),
    'critical': Decimal('100'),
}
ESTADOS_PUNTUABLES = {'open', 'accepted_risk'}


def _decimal_texto(valor):
    texto = format(valor, 'f')
    return texto.rstrip('0').rstrip('.') if '.' in texto else texto


def mensaje_piso(calculo, criticos=None):
    """Explica el aumento del score global cuando el piso supera el ponderado."""
    criticos = calculo['critical_open'] if criticos is None else criticos
    if not calculo['piso_aplicado']:
        return None
    cuenta = 'hallazgo crítico vigente' if criticos == 1 else 'hallazgos críticos vigentes'
    return 'Subido a %s por %s %s; la suma ponderada da %s.' % (
        calculo['score'], criticos, cuenta, calculo['ponderado'])


def calcular(hallazgos, reglas, pesos_categoria):
    """Calcula notas de categoría, score global y aportes congelables en la base.

    Cada hallazgo vigente aporta min(max_penalty, puntos_severidad * peso_regla).
    Las notas de categoría suman esos aportes hasta 100; el score global aplica
    los pesos del juego activo y el piso de hallazgos críticos de #29.
    """
    notas = {categoria: Decimal('0') for categoria in criterio.CATEGORIAS}
    aportes = []
    criticos = 0

    for hallazgo in hallazgos:
        if hallazgo['status'] not in ESTADOS_PUNTUABLES:
            continue

        codigo = hallazgo['rule_code']
        if codigo not in reglas:
            raise ValueError('hallazgo sin regla activa: %s' % codigo)
        regla = reglas[codigo]
        severidad = hallazgo['severity']
        if severidad not in PUNTOS_SEVERIDAD:
            raise ValueError('severidad inválida para %s: %s' % (codigo, severidad))

        peso = Decimal(str(regla['weight']))
        maximo = Decimal(str(regla['max_penalty']))
        bruto = PUNTOS_SEVERIDAD[severidad] * peso
        penalizacion = min(bruto, maximo)
        categoria = regla['category']
        notas[categoria] = min(Decimal('100'), notas[categoria] + penalizacion)
        criticos += severidad == 'critical'
        factor = 'Severidad %s x peso %s (tope %s)' % (
            PUNTOS_SEVERIDAD[severidad], _decimal_texto(peso), _decimal_texto(maximo))
        aportes.append({
            'finding_id': hallazgo['id'],
            'rule_id': regla['id'],
            'severity': severidad,
            'penalty': penalizacion,
            'factors': {
                'rules': [{'label': factor, 'points': float(penalizacion)}],
                'severity_points': int(PUNTOS_SEVERIDAD[severidad]),
                'rule_weight': float(peso),
                'uncapped_penalty': float(bruto),
                'max_penalty': float(maximo),
            },
        })

    notas = {categoria: float(nota.quantize(Decimal('0.01'))) for categoria, nota in notas.items()}
    global_ = criterio.score_dominio(notas, pesos_categoria, criticos)
    resultado = {
        'category_scores': notas,
        'critical_open': criticos,
        **global_,
        'contributions': aportes,
    }
    resultado['floor_message'] = mensaje_piso(resultado)
    return resultado