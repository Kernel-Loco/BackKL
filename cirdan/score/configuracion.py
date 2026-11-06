"""Validación y resolución del juego de pesos activo (#32)."""
from decimal import Decimal, InvalidOperation

from psycopg.types.json import Jsonb

from cirdan.score import criterio, motor


def validar_pesos(pesos):
    """Devuelve pesos normalizados o falla si no son las cuatro categorías y suman exactamente 1."""
    if not isinstance(pesos, dict) or set(pesos) != set(criterio.CATEGORIAS):
        raise ValueError('se requieren exactamente las cuatro categorías del score')

    decimales = {}
    for categoria in criterio.CATEGORIAS:
        valor = pesos[categoria]
        if isinstance(valor, bool):
            raise ValueError('cada peso debe ser un número entre 0 y 1')
        try:
            peso = Decimal(str(valor))
        except (InvalidOperation, ValueError):
            raise ValueError('cada peso debe ser un número entre 0 y 1') from None
        if not peso.is_finite() or not Decimal('0') <= peso <= Decimal('1'):
            raise ValueError('cada peso debe ser un número entre 0 y 1')
        decimales[categoria] = peso

    if sum(decimales.values()) != Decimal('1'):
        raise ValueError('los pesos deben sumar 1')
    return {categoria: float(peso) for categoria, peso in decimales.items()}


def juego_activo(conn, org):
    """Prefiere el set de la organización y usa el global como plantilla si aún no tiene uno."""
    return conn.execute(
        'SELECT id::text, version, category_weights, activated_at, validated_by, organization_id::text '
        'FROM scoring_rule_sets WHERE is_active AND (organization_id = %s OR organization_id IS NULL) '
        'ORDER BY CASE WHEN organization_id = %s THEN 0 ELSE 1 END, version DESC LIMIT 1',
        (org, org),
    ).fetchone()


def recalcular_scores(conn, org, rule_set_id, pesos):
    """Inserta un snapshot rules_change por dominio con score previo, sin modificar históricos."""
    anteriores = conn.execute(
        'SELECT DISTINCT ON (domain_id) domain_id::text, scan_id::text, id::text AS score_id, '
        'partial_coverage, method, model_version, model_fallback_reason '
        'FROM domain_scores WHERE organization_id = %s '
        'ORDER BY domain_id, computed_at DESC, created_at DESC, id DESC',
        (org,),
    ).fetchall()
    if not anteriores:
        return 0

    reglas = {regla['code']: regla for regla in conn.execute(
        'SELECT id::text, code, category, weight, max_penalty FROM scoring_rules WHERE rule_set_id = %s',
        (rule_set_id,),
    ).fetchall()}
    campos_explicativos = ('confidence', 'shap', 'model_prediction', 'explanation_model_version')

    for anterior in anteriores:
        filas = conn.execute(
            'SELECT f.id::text AS id, r.code AS rule_code, f.severity, f.status, '
            'previous.severity AS score_severity, previous.factors AS previous_factors '
            'FROM findings f JOIN scoring_rules r ON r.id = f.rule_id '
            'LEFT JOIN score_contributions previous ON previous.finding_id = f.id AND previous.score_id = %s '
            'WHERE f.organization_id = %s AND f.domain_id = %s AND f.status = ANY(%s) ORDER BY f.id',
            (anterior['score_id'], org, anterior['domain_id'], list(motor.ESTADOS_PUNTUABLES)),
        ).fetchall()
        hallazgos = []
        factores_previos = {}
        for fila in filas:
            if anterior['method'] == 'ml':
                if fila['score_severity'] is None:
                    raise ValueError('faltan severidades ML congeladas para recalcular el dominio %s' %
                                     anterior['domain_id'])
                fila['severity'] = fila['score_severity']
            hallazgos.append(fila)
            factores_previos[fila['id']] = fila['previous_factors'] or {}

        calculo = motor.calcular(hallazgos, reglas, pesos)
        for aporte in calculo['contributions']:
            anteriores_factors = factores_previos.get(aporte['finding_id'], {})
            for campo in campos_explicativos:
                if campo in anteriores_factors:
                    aporte['factors'][campo] = anteriores_factors[campo]

        score_id = conn.execute(
            'INSERT INTO domain_scores (organization_id, domain_id, scan_id, rule_set_id, score, category_scores, '
            'reason, method, model_version, model_fallback_reason, partial_coverage, computed_at) '
            "VALUES (%s, %s, %s, %s, %s, %s, 'rules_change', %s, %s, %s, %s, now()) RETURNING id::text",
            (org, anterior['domain_id'], anterior['scan_id'], rule_set_id, calculo['score'],
             Jsonb(calculo['category_scores']), anterior['method'], anterior['model_version'],
             anterior['model_fallback_reason'], anterior['partial_coverage']),
        ).fetchone()['id']

        for aporte in calculo['contributions']:
            conn.execute(
                'INSERT INTO score_contributions (organization_id, score_id, finding_id, rule_id, penalty, severity, factors) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (org, score_id, aporte['finding_id'], aporte['rule_id'], aporte['penalty'], aporte['severity'],
                 Jsonb(aporte['factors'])),
            )
    return len(anteriores)