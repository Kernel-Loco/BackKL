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
- dominios parecidos: solo busca el dominio y sus subdominios,
- lo que depende de los vencidos (RC-218): un nombre interno cuenta también en un certificado que venció hace menos
  de un año, y sin los vencidos no se sabe qué autoridades usaba antes el dominio.
Por eso, cuando es respaldo, el resultado deja cert_expired, cert_internal_name, cert_new_issuer y lookalike_domain en
sin_cobertura (cobertura parcial, no 0). Con revisados en None el orquestador no cierra lo abierto de esos códigos.

Sin llave de API el límite es pequeño (unas 10 consultas por hora de un dominio con sus
subdominios), y el complemento gasta el mismo cupo que necesita el respaldo. Cada corrida pide a lo más
MAX_PAGINAS páginas, y casi siempre 2 (la página y la vacía que cierra). Un 429 (límite alcanzado) no se
reintenta: otro intento solo gastaría cupo. Como complemento usa menos intentos y menos espera
(COMPLEMENTO), porque crt.sh ya respondió y un Cert Spotter lento no debe detener el escaneo. Si falla
una página después de la primera, o una emisión no se puede leer, el resultado sigue con lo que llegó y
un aviso de que pueden faltar subdominios. Una página con emisiones de las que ninguna se puede leer
cuenta como una que no llegó, sin reintento, y si es la primera, como que Cert Spotter no respondió.

Una sola consulta por página en cada escaneo (RC-326): ct_logs, shodan, la visita web y api_docs piden las mismas
páginas del dominio. Dentro de un escaneo (un_escaneo, que abre orquestador.correr) la primera fuente que pide una
página sale a la red y las demás reciben lo mismo que recibió ella: el cuerpo, un 429 con su Retry-After o una falla de
red, sin otra petición (descargar). Así un escaneo en vivo hace 2 consultas cuando el dominio cabe en una página (la
página y la vacía que cierra), y hasta 4 si no, porque ct_logs pide hasta MAX_PAGINAS y las demás solo las COMPARTIDAS.
Un 429 no se vuelve a pedir en ese escaneo. Lo que se repite es lo que dio transporte.descargar, y cada fuente lo lee
con su propio cliente: deja los mismos avisos de hoy y lo graba en su carpeta como si viniera de la red. Lo repetido no
cuenta en las consultas del cliente (repetida), así el cupo diario de cada fuente (migración 008) cuenta solo lo que
salió, y no se reintenta: otro intento daría lo mismo. Un reintento del orquestador a 1, 5 o 25 minutos sí vuelve a
pedir lo que falló, salvo un 429 (nuevo_intento). Solo se guardan las COMPARTIDAS primeras páginas, las que piden todas
las fuentes. Al reproducir no hay red y nada cambia. Fuera de un escaneo (la terminal de cada recolector, las pruebas)
cada fuente pide lo suyo, como antes.
"""
import contextlib
import contextvars
import http.client
import re
import urllib.error
import urllib.parse
from datetime import datetime

from cirdan.recolectores import transporte
from cirdan.recolectores.contrato import FuenteNoResponde

URL = 'https://api.certspotter.com/v1/issuances'
NOMBRE = 'Cert Spotter'
ORIGEN = 'certspotter'       # va en los atributos y la evidencia: de dónde salió el certificado
PREFIJO = 'certspotter:'     # consulta de la grabadora: certspotter_<dominio>.json
MAX_PAGINAS = 4              # cada página es una consulta del límite por hora (unas 10), la vacía que cierra también
COMPARTIDAS = 2              # las páginas que piden todas las fuentes de un escaneo (shodan.PAGINAS_CT): se guardan
SIN_REINTENTO = (429,)       # límite por hora alcanzado: reintentar a los 5 o 15 s solo gasta cupo
COMPLEMENTO = {'intentos': 2, 'timeout': 20}  # con crt.sh arriba: un Cert Spotter lento no detiene el escaneo
SIN_COBERTURA = ['cert_expired', 'cert_internal_name', 'cert_new_issuer', 'lookalike_domain']
SOLO = ('Los subdominios y certificados vigentes salen de Cert Spotter (SSLMate), que no da certificados vencidos ni '
        'dominios parecidos: quedan sin revisar los vencidos, los nombres internos, las autoridades nuevas y los '
        'parecidos')
AVISO = 'crt.sh no respondió. ' + SOLO
AVISO_DANADA = 'La grabación de crt.sh está dañada. ' + SOLO  # al reproducir: crt.sh sí pudo haber respondido
INCOMPLETO = ('Cert Spotter no dio todas las páginas o alguna emisión no se pudo leer: pueden faltar subdominios y '
              'renovaciones recientes, así que un certificado por vencer puede estar ya renovado')
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


# ---------------------------------------------------------------- una consulta por página en cada escaneo (RC-326)

# URL pedida -> _Respuesta de la última vez que salió a la red en este escaneo. None fuera de un escaneo. Las fuentes de
# un escaneo corren una tras otra en el mismo hilo (orquestador.correr): no hace falta candado. Un hilo nuevo no hereda
# el escaneo y pediría lo suyo, como antes: más consultas, nunca datos de otro escaneo.
_ESCANEO = contextvars.ContextVar('certspotter_escaneo', default=None)
# False mientras certificados() pide una página después de las COMPARTIDAS: solo ct_logs la pide, así que no se guarda.
_COMPARTIDA = contextvars.ContextVar('certspotter_compartida', default=True)
# Lo que dice Cert Spotter (o la red hasta él) y se repite a las demás fuentes. No se repite un ValueError: es el tope
# de bytes, el tipo o el https del cliente que pidió, y otra fuente con otro tope sí podría leer esa página.
REPETIBLES = (urllib.error.HTTPError, transporte.PlazoVencido, transporte.Redirigida, OSError,
              http.client.HTTPException)


@contextlib.contextmanager
def un_escaneo():
    """Mientras dura el bloque, cada página de Cert Spotter sale a la red una sola vez (descargar). Al salir se olvida
    todo: nada pasa a otro escaneo ni a otra organización."""
    marca = _ESCANEO.set({})
    try:
        yield
    finally:
        _ESCANEO.reset(marca)


class _Respuesta:
    """Lo último que dio la red a una página: `exito` con el cuerpo en `valor`, o el error. `cerrada` cuando la fuente
    que la pidió ya terminó sus intentos: desde ahí descargar la repite. Mientras no, sus reintentos salen a la red."""
    __slots__ = ('exito', 'valor', 'cerrada')

    def __init__(self, exito, valor):
        self.exito, self.valor, self.cerrada = exito, valor, False


def repetida(pedida):
    """True si en este escaneo ya se pidió `pedida` (una URL de url()) a la red: descargar repetirá lo último que dio,
    sin salir a la red. Quien llama hace un solo intento y no lo cuenta en sus consultas. El cliente la llama antes de
    sus intentos de cada página: como las fuentes corren una tras otra, la que la pidió ya terminó, y su respuesta se
    cierra aquí. Así sus propios reintentos, que no llaman a repetida, sí salen a la red."""
    respuestas = _ESCANEO.get()
    respuesta = respuestas.get(pedida) if respuestas is not None else None
    if respuesta is None:
        return False
    respuesta.cerrada = True
    return True


def nuevo_intento():
    """El orquestador la llama antes de cada reintento de una fuente (a 1, 5 o 25 minutos): olvida las fallas
    guardadas, así el reintento vuelve a salir a la red, como antes de RC-326. Un 429 se queda: Cert Spotter ya dijo
    que no hay cupo y otra petición solo lo gastaría. Los cuerpos que llegaron bien también se quedan."""
    respuestas = _ESCANEO.get()
    if respuestas is None:
        return
    for pedida in [p for p, r in respuestas.items() if not r.exito and getattr(r.valor, 'code', None) not in
                   SIN_REINTENTO]:
        del respuestas[pedida]


def _copia(error):
    """Otra instancia del mismo error, sin traceback, sin __context__ y sin la respuesta: lo que se guarda y lo que
    recibe cada fuente que lo repite. Así lo guardado no retiene los marcos ni el cuerpo parcial de quien lo pidió, y
    ninguna fuente ve lo que otra le haya hecho a la excepción. Un HTTPError va nuevo, con el código, el texto y las
    cabeceras (el Retry-After de un 429) y sin el cuerpo. Los demás conservan sus args y sus atributos (el destino de
    una Redirigida, el errno de un OSError)."""
    if isinstance(error, urllib.error.HTTPError):
        return urllib.error.HTTPError(error.url, error.code, error.msg, error.hdrs, None)
    copia = type(error).__new__(type(error), *error.args)
    copia.args = error.args  # un OSError con su propio __init__ (RemoteDisconnected) no los toma en __new__
    if isinstance(error, OSError):  # solo los que trae: uno en None cambia el texto del error
        for campo in ('errno', 'strerror', 'filename', 'filename2'):
            if getattr(error, campo) is not None:
                setattr(copia, campo, getattr(error, campo))
    copia.__dict__.update(vars(error))
    return copia


def descargar(req, plazo, tope, cronometro=None):
    """transporte.descargar(req, plazo, tope, cronometro), salvo para una página de Cert Spotter dentro de un escaneo:
    si ya está cerrada (repetida), repite lo último que dio la red sin salir a ella. Un cuerpo de más de `tope` bytes da
    el mismo ValueError que transporte.descargar, así cada fuente conserva su tope. Una página después de las
    COMPARTIDAS no se guarda: ninguna otra fuente la pide. Las demás URL pasan tal cual."""
    respuestas = _ESCANEO.get()
    pedida = req.full_url
    if respuestas is None or not _COMPARTIDA.get() or not pedida.startswith(URL + '?'):
        return transporte.descargar(req, plazo, tope, cronometro)
    respuesta = respuestas.get(pedida)
    if respuesta is not None and respuesta.cerrada:
        if not respuesta.exito:
            raise _copia(respuesta.valor)
        if len(respuesta.valor) > tope:
            raise ValueError('respuesta de más de %d bytes' % tope)
        return respuesta.valor
    try:
        cuerpo = transporte.descargar(req, plazo, tope, cronometro)
    except REPETIBLES as e:
        respuestas[pedida] = _Respuesta(False, _copia(e))
        raise
    except BaseException:  # el tope de este cliente: lo de un intento anterior ya no es lo último que dio la red
        respuestas.pop(pedida, None)
        raise
    respuestas[pedida] = _Respuesta(True, cuerpo)
    return cuerpo


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
    SinGrabacion, que hereda de FuenteNoResponde, así sale lo mismo que en vivo. Un archivo dañado de la grabación
    (crtsh.GrabacionDanada, también FuenteNoResponde) corta igual que una página que no llegó: sigue lo que ya se leyó
    y ClienteCrtsh lo anota en `danados`, con lo que crtsh.recolectar nombra el archivo y no cierra nada, salvo el por
    vencer cuya fecha ya pasó (crtsh.DANADA).
    """
    emisiones, despues, raras = [], None, 0
    for numero in range(max_paginas):
        marca = _COMPARTIDA.set(numero < COMPARTIDAS)  # las que nadie más pide no se guardan en el escaneo (RC-326)
        try:
            respuesta = cliente.pedir(consulta(dominio, despues), url(dominio, despues), NOMBRE,
                                      sin_reintento=SIN_REINTENTO, valida=pagina_legible, texto=dominio, **opciones)
        except FuenteNoResponde:
            if not emisiones:
                raise
            break
        finally:
            _COMPARTIDA.reset(marca)
        pagina = [e for e in respuesta if legible(e)]
        raras += len(respuesta) - len(pagina)
        if not pagina:
            if raras and not emisiones:  # solo desde una grabación de antes de pagina_legible
                raise FuenteNoResponde('%s respondió a %s, pero ninguna emisión se pudo leer' % (NOMBRE, dominio))
            return [certificado(e) for e in emisiones], not raras
        emisiones += pagina
        despues = pagina[-1]['id']
    return [certificado(e) for e in emisiones], False
