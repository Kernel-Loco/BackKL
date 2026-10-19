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
subdominios), así que solo se usa como respaldo. Cada escaneo pide a lo más MAX_PAGINAS páginas y un
429 (límite alcanzado) no se reintenta: otro intento solo gastaría cupo. Si falla una página después
de la primera, el resultado sigue con lo que llegó y un aviso de que pueden faltar subdominios.
"""
import urllib.parse

from cirdan.recolectores.contrato import FuenteNoResponde

URL = 'https://api.certspotter.com/v1/issuances'
NOMBRE = 'Cert Spotter'
ORIGEN = 'certspotter'       # va en los atributos y la evidencia: de dónde salió el certificado
PREFIJO = 'certspotter:'     # consulta de la grabadora: certspotter_<dominio>.json
MAX_PAGINAS = 4              # cada página es una consulta del límite por hora (unas 10), la vacía que cierra también
SIN_REINTENTO = (429,)       # límite por hora alcanzado: reintentar a los 5 o 15 s solo gasta cupo
SIN_COBERTURA = ['cert_expired', 'lookalike_domain']
AVISO = ('crt.sh no respondió. Los subdominios y certificados vigentes salen de Cert Spotter (SSLMate), que no da '
         'certificados vencidos ni dominios parecidos')
INCOMPLETO = 'Cert Spotter no dio todas las páginas: pueden faltar subdominios'


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

    No trae número de serie: la huella del hallazgo usa la vigencia, que crt.sh y Cert Spotter dan igual.
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

    `cliente.pedir(consulta, url, fuente, ...)` hace cada petición con reintentos y la graba o la reproduce
    (ClienteCrtsh). Lanza FuenteNoResponde si la primera página no llega. Si falla una de las siguientes, devuelve
    lo que ya llegó con `completos` en False, igual que si se cortó en `max_paginas`. Al reproducir, una página
    que no se grabó es SinGrabacion, que hereda de FuenteNoResponde, así sale lo mismo que en vivo.
    """
    emisiones, despues = [], None
    for _ in range(max_paginas):
        try:
            respuesta = cliente.pedir(consulta(dominio, despues), url(dominio, despues), NOMBRE,
                                      sin_reintento=SIN_REINTENTO, texto=dominio)
        except FuenteNoResponde:
            if not emisiones:
                raise
            break
        pagina = [e for e in respuesta if isinstance(e, dict)]
        if not pagina:
            return [certificado(e) for e in emisiones], True
        emisiones += pagina
        despues = pagina[-1].get('id')
        if not despues:
            break
    return [certificado(e) for e in emisiones], False
