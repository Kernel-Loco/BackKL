"""La tarjeta adaptable de Microsoft Teams y las reglas de la URL del flujo (#65, RC-114). Sin base ni red.

El canal de Teams recibe la alerta por un flujo de Workflows ("Cuando se recibe una solicitud de webhook de Teams"),
que publica la tarjeta en el canal. La URL del flujo lleva su firma (`sig`) en la consulta: quien la tenga puede
publicar en el canal, así que se guarda cifrada (`integrations.secret_enc`) y en `endpoint` solo va el host.

Solo se aceptan URL https de los hosts de Workflows de Microsoft: la API no publica a cualquier sitio que le pasen
(SSRF), y la URL no lleva usuario, contraseña ni puerto distinto de 443.
"""
import re
from urllib.parse import urlsplit

# Hosts de Workflows (Power Automate / Logic Apps) a los que publica el flujo de Teams.
HOSTS_PERMITIDOS = ('.logic.azure.com', '.environment.api.powerplatform.com', '.api.powerplatform.com')
URL_MAXIMA = 2048
MAX_INTENTOS = 5
# Espera antes de cada reintento, en segundos: 10 s, 1 min, 5 min y 30 min. Al quinto fallo la entrega queda 'dead'.
ESPERAS = (10, 60, 300, 1800)
TITULO_MAXIMO = 200
_CORREO = re.compile(r'[\w.+-]+@[\w-]+(\.[\w-]+)+')


class UrlInvalida(ValueError):
    """La URL del flujo no sirve. El mensaje nunca repite la URL, que lleva la firma."""


def validar_url(url):
    """El host de la URL del flujo, o UrlInvalida."""
    if not isinstance(url, str) or not url.strip() or len(url.strip()) > URL_MAXIMA:
        raise UrlInvalida('Pega la URL del flujo de Workflows de Teams (hasta %d caracteres).' % URL_MAXIMA)
    try:
        partes = urlsplit(url.strip())
        puerto = partes.port
    except ValueError:
        raise UrlInvalida('La URL del flujo no es válida.') from None
    host = (partes.hostname or '').lower()
    if partes.scheme != 'https' or partes.username or partes.password or puerto not in (None, 443):
        raise UrlInvalida('La URL del flujo debe ser https, sin usuario ni puerto.')
    if not host.endswith(HOSTS_PERMITIDOS):
        raise UrlInvalida('La URL debe ser de un flujo de Workflows de Microsoft (%s).' % ', '.join(HOSTS_PERMITIDOS))
    if 'sig=' not in partes.query:
        raise UrlInvalida('La URL del flujo no trae su firma (sig). Cópiala completa desde Workflows.')
    return host


def espera(intento):
    """Segundos antes del siguiente intento después del intento número `intento` (1 es el primero), o None si ya no
    hay otro y la entrega queda 'dead'."""
    if intento >= MAX_INTENTOS:
        return None
    return ESPERAS[min(intento, len(ESPERAS)) - 1]


def sin_correos(texto):
    """El texto sin direcciones de correo: la tarjeta sale del portal a un canal de Teams."""
    return _CORREO.sub('[correo]', texto or '')[:TITULO_MAXIMO]


def _hechos(*pares):
    return [{'title': titulo, 'value': str(valor)} for titulo, valor in pares if valor not in (None, '')]


SEVERIDADES = {'critical': 'Crítica', 'high': 'Alta', 'medium': 'Media', 'low': 'Baja'}


def tarjeta(evento, payload, portal=None):
    """El mensaje para el flujo de Teams: un attachment con la tarjeta adaptable 1.4 de la alerta."""
    dominio = payload.get('domain', '')
    if evento == 'finding.created':
        titulo = 'LowTide · Hallazgo crítico nuevo en %s' % dominio
        hechos = _hechos(('Hallazgo', sin_correos(payload.get('title'))),
                         ('Severidad', SEVERIDADES.get(payload.get('severity'), payload.get('severity'))),
                         ('Regla', payload.get('rule_code')), ('Detectado', payload.get('detected_at')))
        enlace = '%s/dashboard/hallazgos?dominio=%s' % (portal, dominio) if portal else None
    elif evento == 'score.above_threshold':
        titulo = 'LowTide · El riesgo de %s pasó el umbral' % dominio
        hechos = _hechos(('Score', payload.get('score')), ('Umbral', payload.get('threshold')),
                         ('Score anterior', payload.get('previous_score')), ('Calculado', payload.get('computed_at')))
        enlace = '%s/dashboard/dominios/%s' % (portal, dominio) if portal else None
    elif evento == 'test':
        titulo = 'LowTide · Prueba de la integración con Teams'
        hechos = _hechos(('Resultado', 'Si ves este mensaje, las alertas llegarán a este canal.'))
        enlace = portal
    else:
        raise ValueError('evento sin tarjeta: %s' % evento)
    cuerpo = [{'type': 'TextBlock', 'text': titulo, 'weight': 'Bolder', 'size': 'Medium', 'wrap': True},
              {'type': 'FactSet', 'facts': hechos}]
    contenido = {'$schema': 'http://adaptivecards.io/schemas/adaptive-card.json', 'type': 'AdaptiveCard',
                 'version': '1.4', 'body': cuerpo}
    if enlace:
        contenido['actions'] = [{'type': 'Action.OpenUrl', 'title': 'Abrir en LowTide', 'url': enlace}]
    return {'type': 'message', 'attachments': [{'contentType': 'application/vnd.microsoft.card.adaptive',
                                                'contentUrl': None, 'content': contenido}]}
