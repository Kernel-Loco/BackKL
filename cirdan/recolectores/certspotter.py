"""Cert Spotter (SSLMate), complemento y respaldo de crt.sh (#14b).

Cert Spotter lee logs de Certificate Transparency, sin tocar los servidores del dominio. crtsh.py lo
consulta en cada corrida:
- si crt.sh responde, suma los certificados vigentes que crt.sh no trae. crt.sh no siempre lee todos los
  logs: el 23 oct 2026 no tenía ninguno de los certificados de Let's Encrypt de olmardo.com, que Cert
  Spotter sí tenía. Si Cert Spotter no responde, queda lo de crt.sh con un aviso,
- si crt.sh no responde, los subdominios y certificados vigentes salen solo de Cert Spotter.
No es una fuente aparte: sus consultas cuentan en la fuente ct_logs y sus respuestas se graban en la
carpeta de crt.sh del dominio con la misma Grabadora, así --reproducir lo repite sin red.

Lo que no da:
- certificados vencidos: la API solo devuelve certificados que todavía no vencen,
- dominios parecidos: solo busca el dominio y sus subdominios.
Por eso, cuando es respaldo, el resultado deja cert_expired y lookalike_domain en sin_cobertura
(cobertura parcial, no 0).

Sin llave de API el límite es pequeño (unas 10 consultas por hora de un dominio con sus
subdominios), y el complemento gasta el mismo cupo que necesita el respaldo. Cada corrida pide a lo más
MAX_PAGINAS páginas, y casi siempre 2 (la página y la vacía que cierra). Un 429 (límite alcanzado) no se
reintenta: otro intento solo gastaría cupo. Como complemento usa menos intentos y menos espera
(COMPLEMENTO), porque crt.sh ya respondió y un Cert Spotter lento no debe detener el escaneo. Si falla
una página después de la primera, o una emisión no se puede leer, el resultado sigue con lo que llegó y
un aviso de que pueden faltar subdominios. Una página con emisiones de las que ninguna se puede leer
cuenta como una que no llegó, sin reintento, y si es la primera, como que Cert Spotter no respondió.
"""
import re
import urllib.parse
from datetime import datetime

from cirdan.recolectores.contrato import FuenteNoResponde

URL = 'https://api.certspotter.com/v1/issuances'
NOMBRE = 'Cert Spotter'
ORIGEN = 'certspotter'       # va en los atributos y la evidencia: de dónde salió el certificado
PREFIJO = 'certspotter:'     # consulta de la grabadora: certspotter_<dominio>.json
MAX_PAGINAS = 4              # cada página es una consulta del límite por hora (unas 10), la vacía que cierra también
SIN_REINTENTO = (429,)       # límite por hora alcanzado: reintentar a los 5 o 15 s solo gasta cupo
COMPLEMENTO = {'intentos': 2, 'timeout': 20}  # con crt.sh arriba, como las variantes de parecidos de crtsh.py
SIN_COBERTURA = ['cert_expired', 'lookalike_domain']
AVISO = ('crt.sh no respondió. Los subdominios y certificados vigentes salen de Cert Spotter (SSLMate), que no da '
         'certificados vencidos ni dominios parecidos')
INCOMPLETO = 'Cert Spotter no dio todas las páginas o alguna emisión no se pudo leer: pueden faltar subdominios'
SIN_COMPLEMENTO = ('No se completó lo de crt.sh con Cert Spotter: pueden faltar subdominios y certificados vigentes que '
                   'crt.sh no trae')  # va después del error. crt.sh sí respondió y el resultado sigue con lo suyo


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
    `revocado` lo marca Cert Spotter (crt.sh no lo da): un comodín revocado ya no cubre a otros nombres.
    """
    emisor = emision.get('issuer')
    if isinstance(emisor, dict):
        emisor = emisor.get('name') or emisor.get('friendly_name')
    nombres = emision.get('dns_names')
    nombres = [n for n in nombres if isinstance(n, str)] if isinstance(nombres, list) else []
    return {'id': emision.get('id'), 'origen': ORIGEN, 'issuer_name': emisor if isinstance(emisor, str) else '',
            'common_name': '', 'name_value': '\n'.join(nombres), 'not_before': emision.get('not_before'),
            'not_after': emision.get('not_after'), 'serial_number': '', 'cert_sha256': emision.get('cert_sha256') or '',
            'revocado': emision.get('revoked') is True}


ID_VALIDO = re.compile(r'[0-9A-Za-z_-]{1,64}')  # va en el nombre del archivo de la página siguiente


def _fecha_legible(texto):
    try:
        datetime.fromisoformat(texto.replace('Z', ''))  # igual que crtsh._fecha
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def legible(emision):
    """Si la emisión trae un id que sirve para pedir la página siguiente y no contarla dos veces, su vigencia y la
    lista de nombres. Una que no se puede leer no se usa y deja el resultado incompleto, con aviso."""
    return (isinstance(emision, dict) and isinstance(emision.get('id'), (str, int)) and
            not isinstance(emision.get('id'), bool) and bool(emision.get('id')) and
            ID_VALIDO.fullmatch(str(emision.get('id'))) is not None and
            _fecha_legible(emision.get('not_before')) and _fecha_legible(emision.get('not_after')) and
            isinstance(emision.get('dns_names'), list))


def pagina_legible(respuesta):
    """Una página vacía cierra la lista. Una con emisiones sirve si al menos una es legible(). Si no, cliente.pedir la
    trata como una respuesta que no llegó: no la graba, así una grabación nueva no borra la anterior."""
    return not respuesta or any(legible(e) for e in respuesta)


def certificados(cliente, dominio, max_paginas=MAX_PAGINAS, **opciones):
    """(certificados, completos) del dominio y sus subdominios, página por página hasta una vacía.

    `cliente.pedir(consulta, url, fuente, ...)` hace cada petición con reintentos y la graba o la reproduce
    (ClienteCrtsh). `opciones` (intentos, timeout) pasan a esa llamada, por ejemplo COMPLEMENTO. Lanza
    FuenteNoResponde si la primera página no llega o si no trae ninguna emisión que se pueda leer (pagina_legible).
    Si falla una de las siguientes, devuelve lo que ya llegó con `completos` en False, igual que si se cortó en
    `max_paginas` o si se saltó una emisión que no es legible(). Al reproducir, una página que no se grabó es
    SinGrabacion, que hereda de FuenteNoResponde, así sale lo mismo que en vivo.
    """
    emisiones, despues, raras = [], None, 0
    for _ in range(max_paginas):
        try:
            respuesta = cliente.pedir(consulta(dominio, despues), url(dominio, despues), NOMBRE,
                                      sin_reintento=SIN_REINTENTO, valida=pagina_legible, texto=dominio, **opciones)
        except FuenteNoResponde:
            if not emisiones:
                raise
            break
        pagina = [e for e in respuesta if legible(e)]
        raras += len(respuesta) - len(pagina)
        if not pagina:
            if raras and not emisiones:  # solo desde una grabación de antes de pagina_legible
                raise FuenteNoResponde('%s respondió a %s, pero ninguna emisión se pudo leer' % (NOMBRE, dominio))
            return [certificado(e) for e in emisiones], not raras
        emisiones += pagina
        despues = pagina[-1]['id']
    return [certificado(e) for e in emisiones], False
