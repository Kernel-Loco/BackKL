"""Cert Spotter (SSLMate), respaldo de crt.sh (#14b).

Cert Spotter lee los mismos logs de Certificate Transparency que crt.sh, sin tocar los servidores del
dominio. crtsh.py lo usa solo cuando crt.sh no responde, así un escaneo sigue con subdominios y
certificados por vencer. No es una fuente aparte: sus consultas cuentan en la fuente ct_logs y sus
respuestas se graban en la carpeta de crt.sh del dominio con la misma Grabadora, así --reproducir
repite el respaldo sin red.

Lo que no da:
- certificados vencidos: la API solo devuelve certificados que todavía no vencen,
- dominios parecidos: solo busca el dominio y sus subdominios.
Por eso el resultado deja cert_expired y lookalike_domain en sin_cobertura (cobertura parcial, no 0).

Sin llave de API el límite es pequeño (unas 10 consultas por hora de un dominio con sus
subdominios), así que solo se usa como respaldo.
"""
import urllib.parse

URL = 'https://api.certspotter.com/v1/issuances'
NOMBRE = 'Cert Spotter'
ORIGEN = 'certspotter'       # va en los atributos y la evidencia: de dónde salió el certificado
PREFIJO = 'certspotter:'     # consulta de la grabadora: certspotter_<dominio>.json
MAX_PAGINAS = 10             # cada página es una consulta del límite por hora
SIN_COBERTURA = ['cert_expired', 'lookalike_domain']
AVISO = ('crt.sh no respondió. Los subdominios y certificados vigentes salen de Cert Spotter (SSLMate), que no da '
         'certificados vencidos ni dominios parecidos')


def consulta(dominio, despues=None):
    """Texto de la consulta para la grabadora. Cada página se graba aparte."""
    return PREFIJO + dominio + (':despues:%s' % despues if despues else '')


def url(dominio, despues=None):
    parametros = [('domain', dominio), ('include_subdomains', 'true'), ('expand', 'dns_names'), ('expand', 'issuer')]
    if despues:
        parametros.append(('after', despues))
    return URL + '?' + urllib.parse.urlencode(parametros)


def certificado(emision):
    """Una emisión de Cert Spotter con la forma de un certificado de crt.sh, la que usa crtsh._subdominios.

    No trae número de serie: la huella del hallazgo usa cert_sha256 en su lugar.
    """
    emisor = emision.get('issuer')
    if isinstance(emisor, dict):
        emisor = emisor.get('name') or emisor.get('friendly_name')
    nombres = [n for n in emision.get('dns_names') or () if isinstance(n, str)]
    return {'id': emision.get('id'), 'origen': ORIGEN, 'issuer_name': emisor if isinstance(emisor, str) else '',
            'common_name': '', 'name_value': '\n'.join(nombres), 'not_before': emision.get('not_before'),
            'not_after': emision.get('not_after'), 'serial_number': '', 'cert_sha256': emision.get('cert_sha256') or ''}


def certificados(cliente, dominio, max_paginas=MAX_PAGINAS):
    """(certificados, completos) del dominio y sus subdominios, página por página hasta una vacía.

    `cliente.pedir(consulta, url, fuente)` hace cada petición con reintentos y la graba o la reproduce
    (ClienteCrtsh). Lanza FuenteNoResponde si una página no llega. `completos` es False si se cortó en
    `max_paginas`.
    """
    emisiones, despues = [], None
    for _ in range(max_paginas):
        pagina = [e for e in cliente.pedir(consulta(dominio, despues), url(dominio, despues), NOMBRE)
                  if isinstance(e, dict)]
        if not pagina:
            return [certificado(e) for e in emisiones], True
        emisiones += pagina
        despues = pagina[-1].get('id')
        if not despues:
            break
    return [certificado(e) for e in emisiones], False
