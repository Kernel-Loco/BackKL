"""Criterio de criticidad de Cirdan (#29): bandas, regla de piso y alerta.

Más alto = más riesgo. El score de un dominio es la suma ponderada de sus 4
categorías con los pesos del juego de reglas activo. La regla de piso lo sube
cuando hay hallazgos críticos, para que el promedio no esconda lo grave. El
documento completo está en docs/criterio_criticidad.md. Lo usan el motor de
score (#31), la integración del ML (#36), el portal (RC-17) y las alertas (#65).
"""
from decimal import ROUND_HALF_UP, Decimal

# (desde, hasta, código, nombre): códigos como las severidades de la base, nombres para mostrar
BANDAS = (
    (0, 39, 'low', 'bajo'),
    (40, 59, 'medium', 'medio'),
    (60, 79, 'high', 'alto'),
    (80, 100, 'critical', 'crítico'),
)
CATEGORIAS = ('infrastructure', 'digital_identity', 'configuration', 'data_leaks')
UMBRAL_ALERTA = 60                       # organizations.alert_score_threshold por defecto
PISO_UN_CRITICO = 60                     # un hallazgo crítico vigente: el dominio queda al menos en alto
PISO_VARIOS_CRITICOS = 80                # dos o más: el dominio queda en crítico
ESTADOS_VIGENTES = ('open', 'accepted_risk')  # un riesgo aceptado sigue contando en el score (#80)


def banda(score):
    """Código de la banda ('low', 'medium', 'high' o 'critical') de un score de 0 a 100."""
    if not 0 <= score <= 100:
        raise ValueError('el score va de 0 a 100: %r' % score)
    for desde, hasta, codigo, _ in BANDAS:
        if desde <= score <= hasta:
            return codigo
    raise ValueError('score sin banda: %r' % score)  # solo con valores no enteros entre bandas, como 39.5


def nombre_banda(score):
    """Nombre en español de la banda de un score: bajo, medio, alto o crítico."""
    codigo = banda(score)
    return next(nombre for _, _, c, nombre in BANDAS if c == codigo)


def cuenta_para_piso(severidad, estado):
    """Un hallazgo cuenta para el piso si es crítico y sigue vigente (abierto o con riesgo aceptado)."""
    return severidad == 'critical' and estado in ESTADOS_VIGENTES


def piso(criticos):
    """Score mínimo del dominio según cuántos hallazgos críticos vigentes tiene."""
    if criticos < 0:
        raise ValueError('criticos no puede ser negativo')
    return 0 if criticos == 0 else PISO_UN_CRITICO if criticos == 1 else PISO_VARIOS_CRITICOS


def _redondear(x):
    return int(Decimal(str(x)).quantize(Decimal('1'), rounding=ROUND_HALF_UP))


def score_dominio(categorias, pesos, criticos=0):
    """Score global de un dominio.

    `categorias`: nota de 0 a 100 por categoría. `pesos`: los del juego de reglas activo, que suman 1.
    `criticos`: hallazgos que cumplen cuenta_para_piso(). Devuelve el ponderado, el piso, el score final
    (el mayor de los dos), su banda y si el piso lo subió, para que el detalle del score lo explique.
    """
    if set(categorias) != set(CATEGORIAS) or set(pesos) != set(CATEGORIAS):
        raise ValueError('se esperan las 4 categorías: %s' % ', '.join(CATEGORIAS))
    if abs(sum(pesos.values()) - 1) > 1e-9:
        raise ValueError('los pesos deben sumar 1, suman %s' % sum(pesos.values()))
    for c, v in categorias.items():
        if not 0 <= v <= 100:
            raise ValueError('la nota de %s va de 0 a 100: %r' % (c, v))
    ponderado = _redondear(sum(Decimal(str(categorias[c])) * Decimal(str(pesos[c])) for c in CATEGORIAS))
    minimo = piso(criticos)
    score = max(ponderado, minimo)
    return {'ponderado': ponderado, 'piso': minimo, 'score': score, 'banda': banda(score),
            'piso_aplicado': score > ponderado}


def dispara_alerta(score, umbral=UMBRAL_ALERTA):
    """La alerta score.above_threshold se crea cuando el score llega al umbral o lo pasa."""
    return score >= umbral
