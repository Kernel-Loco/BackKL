"""Criterio de criticidad de Cirdan (#29): bandas, regla de piso y alerta, con los cortes de cada cliente (RC-237).

Más alto = más riesgo. El score de un dominio es la suma ponderada de sus 4
categorías con los pesos del juego de reglas activo. La regla de piso lo sube
cuando hay hallazgos críticos, para que el promedio no esconda lo grave. El
documento completo está en docs/criterio_criticidad.md. Lo usan el motor de
score (#31), la integración del ML (#36), el portal (RC-17) y las alertas (#65).

Los cortes de las bandas (dónde empiezan medio, alto y crítico) son del juego de reglas con que se calculó cada score
(scoring_rule_sets, migración 024). Cada función los recibe como parámetro y, sin ellos, usa los de la plantilla.
"""
from decimal import ROUND_HALF_UP, Decimal

# Cortes de la plantilla global: los de hoy. Cada organización puede mover los suyos en su juego de reglas (RC-237).
# El bajo siempre empieza en 0 y el crítico termina en 100.
CORTES_PLANTILLA = {'medium': 40, 'high': 60, 'critical': 80}
ANCHO_MINIMO_BANDA = 10                  # valores enteros por banda, como el CHECK de la migración 024
# (código, nombre): códigos como las severidades de la base, nombres para mostrar
NOMBRES_BANDA = (('low', 'bajo'), ('medium', 'medio'), ('high', 'alto'), ('critical', 'crítico'))


def validar_cortes(cortes):
    """Cortes {'medium', 'high', 'critical'} como enteros en orden con al menos 10 valores por banda, o ValueError.

    Es la misma regla que el CHECK scoring_rule_sets_band_cutoffs_ck de la migración 024: bajo de 0 a medium - 1,
    medio de medium a high - 1, alto de high a critical - 1 y crítico de critical a 100.
    """
    if not isinstance(cortes, dict) or set(cortes) != set(CORTES_PLANTILLA):
        raise ValueError('los cortes son medium, high y critical')
    for valor in cortes.values():
        if isinstance(valor, bool) or not isinstance(valor, int):
            raise ValueError('cada corte debe ser un número entero')
    medio, alto, critico = cortes['medium'], cortes['high'], cortes['critical']
    if not (ANCHO_MINIMO_BANDA <= medio and medio + ANCHO_MINIMO_BANDA <= alto
            and alto + ANCHO_MINIMO_BANDA <= critico and critico <= 101 - ANCHO_MINIMO_BANDA):
        raise ValueError('los cortes deben ir en orden y dejar al menos %s puntos en cada banda' % ANCHO_MINIMO_BANDA)
    return {'medium': medio, 'high': alto, 'critical': critico}


def _cortes(cortes):
    return dict(CORTES_PLANTILLA) if cortes is None else validar_cortes(cortes)


def bandas(cortes=None):
    """(desde, hasta, código, nombre) de cada banda con los cortes dados o los de la plantilla."""
    c = _cortes(cortes)
    limites = (0, c['medium'], c['high'], c['critical'], 101)
    return tuple((limites[i], limites[i + 1] - 1, codigo, nombre) for i, (codigo, nombre) in enumerate(NOMBRES_BANDA))


def letras(cortes=None):
    """(desde, hasta, letra): A es menos riesgo y F es más (#114, RC-232). No hay E. Las letras siguen a las bandas:
    A y B parten el bajo a la mitad (B empieza en medium // 2), C es medio, D es alto y F es crítico."""
    c = _cortes(cortes)
    mitad = c['medium'] // 2
    return ((0, mitad - 1, 'A'), (mitad, c['medium'] - 1, 'B'), (c['medium'], c['high'] - 1, 'C'),
            (c['high'], c['critical'] - 1, 'D'), (c['critical'], 100, 'F'))


# Las de la plantilla, para la documentación y las pruebas. El código que muestra un score usa las de su juego.
BANDAS = bandas()
LETRAS = letras()
CATEGORIAS = ('infrastructure', 'digital_identity', 'configuration', 'data_leaks')
UMBRAL_ALERTA = 60                       # organizations.alert_score_threshold por defecto, no se mueve con los cortes
PISO_UN_CRITICO = CORTES_PLANTILLA['high']           # un hallazgo crítico vigente: el dominio queda al menos en alto
PISO_VARIOS_CRITICOS = CORTES_PLANTILLA['critical']  # dos o más: el dominio queda en crítico
ESTADOS_VIGENTES = ('open', 'accepted_risk')  # un riesgo aceptado sigue contando en el score (#80)


def banda(score, cortes=None):
    """Código de la banda ('low', 'medium', 'high' o 'critical') de un score de 0 a 100 con los cortes de su juego."""
    if not 0 <= score <= 100:
        raise ValueError('el score va de 0 a 100: %r' % score)
    for desde, hasta, codigo, _ in bandas(cortes):
        if desde <= score <= hasta:
            return codigo
    raise ValueError('score sin banda: %r' % score)  # solo con valores no enteros entre bandas, como 39.5


def nombre_banda(score, cortes=None):
    """Nombre en español de la banda de un score: bajo, medio, alto o crítico."""
    codigo = banda(score, cortes)
    return next(nombre for c, nombre in NOMBRES_BANDA if c == codigo)


def letra(score, cortes=None):
    """Letra de la A a la F del score final de un dominio, ya con la regla de piso (#114), con los cortes de su juego."""
    codigo = banda(score, cortes)   # valida el rango y que sea un entero con banda
    for desde, hasta, calificacion in letras(cortes):
        if desde <= score <= hasta:
            return calificacion
    raise ValueError('score sin letra: %r (banda %s)' % (score, codigo))


def cuenta_para_piso(severidad, estado):
    """Un hallazgo cuenta para el piso si es crítico y sigue vigente (abierto o con riesgo aceptado)."""
    return severidad == 'critical' and estado in ESTADOS_VIGENTES


def piso(criticos, cortes=None):
    """Score mínimo del dominio según cuántos hallazgos críticos vigentes tiene: uno lo deja en el inicio de su banda
    alto y dos o más en el inicio de crítico, con los cortes de su juego (RC-237)."""
    if criticos < 0:
        raise ValueError('criticos no puede ser negativo')
    c = _cortes(cortes)
    return 0 if criticos == 0 else c['high'] if criticos == 1 else c['critical']


def _redondear(x):
    return int(Decimal(str(x)).quantize(Decimal('1'), rounding=ROUND_HALF_UP))


def score_dominio(categorias, pesos, criticos=0, cortes=None):
    """Score global de un dominio.

    `categorias`: nota de 0 a 100 por categoría. `pesos`: los del juego de reglas activo, que suman 1.
    `criticos`: hallazgos que cumplen cuenta_para_piso(). Devuelve el ponderado, el piso, el score final
    (el mayor de los dos), su banda y si el piso lo subió, para que el detalle del score lo explique.
    `cortes`: los del juego de reglas (RC-237). Sin ellos, los de la plantilla.
    """
    cortes = _cortes(cortes)
    if set(categorias) != set(CATEGORIAS) or set(pesos) != set(CATEGORIAS):
        raise ValueError('se esperan las 4 categorías: %s' % ', '.join(CATEGORIAS))
    if abs(sum(pesos.values()) - 1) > 1e-9:
        raise ValueError('los pesos deben sumar 1, suman %s' % sum(pesos.values()))
    for c, v in categorias.items():
        if not 0 <= v <= 100:
            raise ValueError('la nota de %s va de 0 a 100: %r' % (c, v))
    ponderado = _redondear(sum(Decimal(str(categorias[c])) * Decimal(str(pesos[c])) for c in CATEGORIAS))
    minimo = piso(criticos, cortes)
    score = max(ponderado, minimo)
    return {'ponderado': ponderado, 'piso': minimo, 'score': score, 'banda': banda(score, cortes),
            'piso_aplicado': score > ponderado}


def dispara_alerta(score, umbral=UMBRAL_ALERTA):
    """La alerta score.above_threshold se crea cuando el score llega al umbral o lo pasa."""
    return score >= umbral
