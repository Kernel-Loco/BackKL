"""Documentación de APIs a la vista: actividad 9 del Anexo A de la carta (#63, RC-118).

Pide por https, solo con GET, una lista fija de RUTAS de documentación (Swagger y OpenAPI) en los sitios del dominio
autorizado. Si una responde con un documento Swagger 2.0 u OpenAPI 3.x, o con la página de Swagger UI o de ReDoc, da
exposed_api_docs. Del documento cuenta las funciones (ruta y método) que no declaran autenticación y, si hay alguna, da
api_auth_not_declared. Es lo que dice el documento: nunca se llama a una función documentada.

Qué se pide, todo dentro del Anexo A:
1. Los nombres del dominio en Cert Spotter más la raíz, hasta MAX_SITIOS, como la visita web (visita.py).
2. El A de cada nombre con 1.1.1.1 y 8.8.8.8 (shodan._resolver_a). Un nombre sin A, o solo con IP que no son
   públicas, no se visita.
3. GET https://<nombre><ruta> por cada ruta de RUTAS, con el User-Agent de la carta (contrato.AGENTE): una petición a
   la vez, PAUSA_RUTA segundos antes de cada una y sin reintentos. Ninguna redirección se sigue, ni dentro del
   dominio: la ruta a la que manda no está en la lista. La conexión va solo a direcciones públicas y por IPv4
   (transporte.visitar). Con un 443 cerrado, una falla de la red, un reto del WAF o un 429 se deja ese sitio: no se
   piden sus demás rutas. Nunca se pide una URL que venga dentro de un documento (servers, host, basePath, la url de
   Swagger UI) ni otra ruta, ni se manda otro método.

Cómo se cuenta (leer). Una función es un método HTTP de una ruta de `paths`. Declara autenticación si su `security`
(la suya, y si no trae, la global del documento) es una lista con al menos un requisito y ninguno vacío. No la declara
si no hay `security` ni propio ni global, si es una lista vacía o si trae un requisito vacío ({}), que deja entrar sin
identificarse. Vale igual para Swagger 2.0 y OpenAPI 3.x. Solo se lee JSON: el repo no trae lector de YAML.

Cobertura (#23). Las partes son los sitios (sus nombres). Un sitio queda revisado si todas sus rutas respondieron
algo que se entiende (un documento, un 404, un 401, una redirección), o si no tiene A, no es público o rechaza el 443.
Queda sin revisar si no respondió, si dio un reto o un límite de peticiones, un error del servidor (5xx), un documento
más grande que MAX_BYTES o si se acabó el tiempo. Lo que se encontró antes de la falla sí se reporta.

Qué se guarda. Del documento solo el resumen (resumir): formato, versión, título, cuántas funciones tiene, cuántas no
declaran autenticación y hasta MAX_MUESTRA de esas (método y ruta). Nunca el documento, sus parámetros, sus ejemplos
ni sus servidores, ni en vivo ni en la grabación. Cada documento es un activo `api_doc` con su URL.

Uso, desde la raíz del repo:
  python -m cirdan.recolectores.api_docs olmardo.com --reproducir
"""
import argparse
import hashlib
import http.client
import json
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from datetime import date, datetime, timezone

from cirdan.ml import caracteristicas as rubrica
from cirdan.recolectores import borde, certspotter, contrato, shodan, transporte, visita
from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import NOMBRE_VALIDO, Activo, FuenteNoResponde, Hallazgo, Resultado, SinGrabacion
from cirdan.recolectores.shodan import RespuestaIlegible, SinTiempo

FUENTE = 'api_docs'
CARPETA_GRABADAS = RAIZ_GRABADAS / 'api_docs'
TIPO_ACTIVO = 'api_doc'

# Código de regla -> severidad base. Los dos están en el catálogo desde la semilla 004, con su texto y su mapeo.
CODIGOS = {'exposed_api_docs': 'medium', 'api_auth_not_declared': 'medium'}

# La lista fija de la actividad 9: a lo más MAX_RUTAS, y solo estas. No se arma ninguna otra, ni con palabras ni con
# lo que diga una respuesta. Cambiarla es cambiar el código, con su PR.
MAX_RUTAS = 10
RUTAS = (
    '/openapi.json',              # FastAPI y muchas otras
    '/swagger.json',              # Swagger 2.0
    '/v3/api-docs',               # springdoc (OpenAPI 3)
    '/v2/api-docs',               # springfox (Swagger 2.0)
    '/api-docs',
    '/swagger/v1/swagger.json',   # Swashbuckle (ASP.NET)
    '/api/openapi.json',
    '/api/swagger.json',
    '/swagger-ui/',               # la página de Swagger UI
    '/docs',                      # Swagger UI de FastAPI, ReDoc
)
# Solo en estas una página cuenta como la de Swagger UI o ReDoc: en las demás se espera un documento JSON, y una
# página de respaldo que nombre a swagger-ui no lo es.
RUTAS_UI = ('/swagger-ui/', '/docs')
# La actividad 9 del Anexo A rige desde este día: antes, la línea de comandos solo reproduce.
VIGENTE_DESDE = date(2026, 11, 13)

AGENTE = contrato.AGENTE
ACEPTA = 'application/json,text/html;q=0.9,*/*;q=0.1'
PAGINAS_CT = shodan.PAGINAS_CT
INTENTOS_CT = shodan.INTENTOS_CT
TIMEOUT_CT = shodan.TIMEOUT_CT
MAX_SITIOS = visita.MAX_SITIOS    # los mismos nombres que la visita web, con la raíz
TIMEOUT_RUTA = 10                 # segundos de cada petición, de getaddrinfo al último byte
PAUSA_RUTA = 1                    # segundos antes de cada petición a un sitio, salvo la primera de la corrida
MAX_BYTES = 2 * 1024 * 1024       # bytes del cuerpo que se leen: un documento más grande queda sin revisar
MAX_BYTES_CT = 8 * 1024 * 1024    # tope de una página de Cert Spotter, como en la visita web
MAX_ERRORES = 3                   # errores del servidor (5xx) de un sitio con los que se dejan sus demás rutas
MAX_MUESTRA = 10                  # funciones que no declaran autenticación que van en la evidencia
MAX_TEXTO = 200                   # caracteres de una ruta documentada o de un título que se guardan
MAX_HTML = 256 * 1024             # caracteres de una página en los que se busca la marca de Swagger UI o ReDoc
MAX_CABEZA = 4096                 # caracteres de un documento cortado en los que se busca 'openapi' o 'swagger'
TIEMPO_CORRIDA = 600              # segundos de toda la corrida: ninguna petición empieza después
MIN_RESTANTE = 5                  # con menos segundos que esto ya no se empieza otro sitio ni otra ruta
# Peor caso de una corrida para el límite diario (#13b): cada intento de cada petición.
MAX_CONSULTAS = PAGINAS_CT * INTENTOS_CT + MAX_SITIOS * shodan.INTENTOS + MAX_SITIOS * len(RUTAS)

METODOS = ('get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace')
CAMBIAN_DATOS = ('POST', 'PUT', 'PATCH', 'DELETE')   # van primero en la muestra
FORMATOS = {'openapi': 'OpenAPI', 'swagger': 'Swagger', 'ui': 'página de documentación',
            'grande': 'documento que no se leyó completo'}
DOCUMENTOS = ('openapi', 'swagger')   # los formatos que se leen: traen título, funciones y huella
MARCAS_UI = ('swagger-ui', 'swaggeruibundle', '<redoc', 'redoc.standalone')
_VERSION = re.compile(r'[0-9][0-9A-Za-z.+-]{0,19}', re.A)
_HUELLA_DOC = re.compile(r'[0-9a-f]{16}')
# Lo que no se guarda de un texto del documento: controles, invisibles y marcas de dirección (cambian cómo se lee
# en el portal), mitades sueltas de un par (la base no las acepta), uso privado y sin asignar.
_RARAS = ('Cc', 'Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp')
_LLAVE = re.compile(r'[A-Za-z0-9_:.~%+=-]{20,}', re.A)
_CORTE = re.compile(r'[?;#]')

# Topes deterministas: lo que dejan fuera no impide grabar.
TOPES = ('paginas', 'sitios')
# Por qué una petición no terminó (la clave 'sin_respuesta'). Solo FALLAS_DE_RED cuentan como una falla de la corrida
# (no se graba): las demás son un dato estable del sitio.
SIN_RESPUESTA = ('tiempo', 'red', 'certificado', 'tls', 'no_publica')
FALLAS_DE_RED = ('tiempo', 'red')
MOTIVOS = {'tiempo': 'no respondió a tiempo', 'red': 'la conexión falló',
           'certificado': 'su certificado no se pudo verificar', 'tls': 'no se pudo negociar TLS con el sitio',
           'no_publica': 'su nombre resolvió solo a direcciones que no son públicas',
           'grabacion': 'la grabación no trae sus rutas', 'dns': 'el DNS no respondió a su A',
           'reto': 'respondió con un reto o un límite de peticiones',
           'error_http': 'respondió con un error del servidor (5xx)',
           'grande': 'un documento pasa de %d MB y no se leyó' % (MAX_BYTES // (1024 * 1024)),
           'sin_tiempo': 'se acabó el tiempo de la corrida'}

SIN_GRABACION_DOMINIO = ('api_docs: no hay grabación de la documentación de APIs de este dominio, no se pidió '
                         'ninguna ruta')
PARCIAL = 'api_docs: cobertura parcial'
NO_SE_GRABO = ('api_docs: la corrida tuvo fallas (la red, el tiempo o una respuesta que no se puede leer), no se '
               'grabó y la grabación anterior sigue igual: repite --grabar más tarde')
NOTA = 'Es lo que dice el documento: las funciones no se llamaron ni se probaron, y puede que sí pidan identificación.'
TITULO_EXPUESTA = 'Documentación de un servicio web a la vista en %s'
TITULO_AUTENTICACION = 'La documentación de %s no declara autenticación en %s'


# ---------------------------------------------------------------- lectura del documento

def _texto(x, tope=MAX_TEXTO):
    """Un texto del documento como se guarda: cortado a `tope` y con ? en vez de cada carácter de _RARAS. None si
    no es texto."""
    if not isinstance(x, str):
        return None
    return ''.join('?' if unicodedata.category(c) in _RARAS else c for c in x[:tope])


def _ruta_visible(ruta):
    """Una ruta documentada como va en la muestra: sin consulta, parámetros ni fragmento, y con … en vez de un tramo
    que parece un correo o una llave (20 caracteres o más con algún dígito). La evidencia nunca guarda un token ni
    un dato personal, aunque el documento los traiga en una ruta."""
    tramos = _CORTE.split(ruta, maxsplit=1)[0].split('/')
    return _texto('/'.join(
        '…' if '@' in t or '%40' in t or (_LLAVE.fullmatch(t) and any(c.isdigit() for c in t)) else t
        for t in tramos))


def declara(seguridad):
    """True si un `security` declara autenticación: una lista con al menos un requisito y ninguno vacío. None (no
    viene), [], [{}] o un valor que no es una lista no la declaran."""
    return isinstance(seguridad, list) and bool(seguridad) and all(isinstance(r, dict) and bool(r) for r in seguridad)


def _version(documento):
    """('openapi' o 'swagger', versión) de un documento OpenAPI 3.x o Swagger 2.0, o None si no es ninguno."""
    for llave, mayor in (('openapi', '3.'), ('swagger', '2.')):
        valor = documento.get(llave)
        if isinstance(valor, (int, float)) and not isinstance(valor, bool):
            valor = str(valor)   # algunos generadores escriben swagger: 2.0 como número
        if isinstance(valor, str) and valor.startswith(mayor) and _VERSION.fullmatch(valor):
            return llave, valor
    return None


def leer(documento):
    """El resumen de un documento Swagger 2.0 u OpenAPI 3.x ya leído como JSON, o None si no es uno.

    {'formato', 'version', 'titulo', 'operaciones', 'sin_declarar', 'muestra', 'huella'}: cuántas funciones (método
    y ruta) tiene, cuántas no declaran autenticación (declara) y hasta MAX_MUESTRA de esas, primero las que crean,
    cambian o borran datos. `huella` distingue un documento de otro del mismo sitio. Lo que no tiene la forma
    esperada (una ruta que no es un objeto, un método que no existe) se salta."""
    if not isinstance(documento, dict):
        return None
    version = _version(documento)
    if version is None:
        return None
    rutas = documento.get('paths')
    general = documento.get('security')
    funciones = []
    for ruta, metodos in (rutas.items() if isinstance(rutas, dict) else ()):
        if not isinstance(ruta, str) or not ruta.startswith('/') or not isinstance(metodos, dict):
            continue
        for metodo, funcion in metodos.items():
            if not isinstance(metodo, str) or metodo.lower() not in METODOS or not isinstance(funcion, dict):
                continue
            propia = funcion.get('security')
            if propia is None:   # no viene, o viene en null: vale el general
                propia = general
            funciones.append((ruta, metodo.upper(), declara(propia)))
    funciones.sort()
    abiertas = sorted(((m not in CAMBIAN_DATOS, r, m) for r, m, ok in funciones if not ok))
    info = documento.get('info')
    huella = hashlib.sha256(json.dumps([version, funciones], ensure_ascii=True).encode('ascii', 'replace')).hexdigest()
    return {'formato': version[0], 'version': version[1],
            'titulo': _texto(info.get('title')) if isinstance(info, dict) else None,
            'operaciones': len(funciones), 'sin_declarar': len(abiertas),
            'muestra': ['%s %s' % (m, _ruta_visible(r)) for _, r, m in abiertas[:MAX_MUESTRA]],
            'huella': huella[:16]}


def analizar(cuerpo, cortado=False):
    """Lo que hay en el cuerpo de una respuesta 200: el resumen de leer() si es un documento, {'formato': 'ui'} si
    es la página de Swagger UI o de ReDoc, {'formato': 'grande'} si es un documento que no cupo en MAX_BYTES (un
    JSON cortado que nombra 'openapi' o 'swagger' en su principio), o None. Nunca lanza por el contenido."""
    texto = cuerpo.decode('utf-8-sig', errors='replace') if isinstance(cuerpo, (bytes, bytearray)) else cuerpo
    if not isinstance(texto, str):
        return None
    texto = texto.lstrip('﻿')
    inicio = texto.lstrip()[:1]
    if inicio == '{':
        try:
            documento = json.loads(texto)
        except (ValueError, RecursionError):
            cabeza = texto[:MAX_CABEZA]
            return {'formato': 'grande'} if cortado and ('"openapi"' in cabeza or '"swagger"' in cabeza) else None
        return leer(documento)
    pagina = texto[:MAX_HTML].lower()
    return {'formato': 'ui'} if any(marca in pagina for marca in MARCAS_UI) else None


def resumir(estado, cabeceras, cuerpo, cortado=False):
    """La respuesta de una ruta como se analiza y se graba: {'estado', 'reto'} si es un reto o un límite de peticiones
    del WAF (borde.reto), y si no {'estado', 'doc'} con lo que dio analizar() en un 200 o None. Del cuerpo y de las
    cabeceras no queda nada más."""
    reto = borde.reto(estado, cabeceras, cuerpo)
    if reto:
        return {'estado': estado, 'reto': reto}
    return {'estado': estado, 'doc': analizar(cuerpo, cortado) if estado == 200 else None}


def _doc_valido(doc):
    if doc is None:
        return True
    if not isinstance(doc, dict) or doc.get('formato') not in FORMATOS:
        return False
    if doc['formato'] not in DOCUMENTOS:
        return True
    enteros = all(shodan._entero(doc.get(k)) and doc[k] >= 0 for k in ('operaciones', 'sin_declarar'))
    muestra = doc.get('muestra')
    return (enteros and doc['sin_declarar'] <= doc['operaciones']
            and isinstance(doc.get('version'), str) and bool(_VERSION.fullmatch(doc['version']))
            and (doc.get('titulo') is None or isinstance(doc['titulo'], str))
            and isinstance(muestra, list) and len(muestra) <= MAX_MUESTRA and all(isinstance(m, str) for m in muestra)
            and isinstance(doc.get('huella'), str) and bool(_HUELLA_DOC.fullmatch(doc['huella'])))


def limpiar(datos):
    """La respuesta de una ruta con una de sus formas: {'rechazada': True} (443 cerrado), {'sin_respuesta': motivo},
    {'redirige': True, 'codigo'}, {'estado', 'reto'} o {'estado', 'doc'}. ValueError si no tiene ninguna (una
    grabación rota). El destino de una redirección no se guarda: nunca se sigue."""
    if not isinstance(datos, dict):
        raise ValueError('forma inesperada')
    if datos.get('rechazada') is True:
        return {'rechazada': True}
    if 'sin_respuesta' in datos:
        if datos['sin_respuesta'] not in SIN_RESPUESTA:
            raise ValueError('forma inesperada')
        return {'sin_respuesta': datos['sin_respuesta']}
    if datos.get('redirige'):
        codigo = datos.get('codigo')
        return {'redirige': True, 'codigo': codigo if shodan._entero(codigo) else None}
    estado = datos.get('estado')
    if not shodan._entero(estado):
        raise ValueError('forma inesperada')
    if 'reto' in datos:
        reto = datos['reto']
        if not isinstance(reto, dict):
            raise ValueError('forma inesperada')
        proveedor, motivo = reto.get('proveedor'), reto.get('motivo')
        return {'estado': estado, 'reto': {'proveedor': proveedor if isinstance(proveedor, str) else None,
                                           'estado': estado, 'motivo': motivo if isinstance(motivo, str) else None}}
    doc = datos.get('doc')
    if not _doc_valido(doc):
        raise ValueError('forma inesperada')
    if isinstance(doc, dict) and doc['formato'] in DOCUMENTOS:
        doc = {'formato': doc['formato'], 'version': doc['version'], 'titulo': _texto(doc['titulo']),
               'operaciones': doc['operaciones'], 'sin_declarar': doc['sin_declarar'],
               'muestra': [_texto(m, MAX_TEXTO + 8) for m in doc['muestra']], 'huella': doc['huella']}
    elif isinstance(doc, dict):
        doc = {'formato': doc['formato']}
    return {'estado': estado, 'doc': doc}


# ---------------------------------------------------------------- red

def _descargar_ct(url, timeout, cronometro=None):
    """El cuerpo de una página de Cert Spotter, de a lo más MAX_BYTES_CT, con el plazo absoluto de
    transporte.descargar. Una respuesta más grande o una redirección dan RespuestaIlegible."""
    cronometro = cronometro or time.monotonic
    req = urllib.request.Request(url, headers={'User-Agent': AGENTE, 'Accept': 'application/json'})
    try:
        return transporte.descargar(req, cronometro() + timeout, MAX_BYTES_CT, cronometro)
    except transporte.PlazoVencido:
        raise SinTiempo('api_docs: la respuesta tardó más de %s s' % timeout) from None
    except (transporte.Redirigida, ValueError) as e:
        raise RespuestaIlegible('api_docs: %s' % e) from None


def _visitar(url, timeout, cronometro=None):
    """La respuesta a GET `url`, ya resumida (resumir), en una sola petición sin reintentos y dentro de `timeout`
    segundos. La única función que pide a un sitio del cliente: las pruebas la cambian con mock.patch.object. Una
    redirección no se sigue y su destino no se guarda. Nunca lanza por el sitio: lo que no terminó es
    {'sin_respuesta': motivo}."""
    cronometro = cronometro or time.monotonic
    req = urllib.request.Request(url, headers={'User-Agent': AGENTE, 'Accept': ACEPTA}, method='GET')
    try:
        estado, cabeceras, cuerpo, cortado = transporte.visitar(req, cronometro() + timeout, MAX_BYTES, cronometro)
    except transporte.Redirigida as e:
        return {'redirige': True, 'codigo': e.codigo}
    except transporte.PlazoVencido:
        return {'sin_respuesta': 'tiempo'}
    except urllib.error.URLError as e:
        if isinstance(e.reason, ConnectionRefusedError):
            return {'rechazada': True}
        return {'sin_respuesta': visita._motivo(e)}
    except ConnectionRefusedError:
        return {'rechazada': True}
    except (OSError, http.client.HTTPException, ValueError) as e:
        return {'sin_respuesta': visita._motivo(e)}
    return resumir(estado, cabeceras, cuerpo, cortado)


class ClienteApiDocs(shodan.ClienteShodan):
    """El cliente de shodan.py (Cert Spotter y el A, con sus reintentos, el tiempo de la corrida y la grabación) con
    las peticiones a las rutas de documentación (ruta). `visitar(url, timeout)` pide a un sitio: si no se pasa,
    _visitar, buscada en el módulo en cada consulta."""
    PREFIJO = 'api_docs: '
    TIEMPO_CORRIDA = TIEMPO_CORRIDA
    TOPES = TOPES

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, visitar=None, **otros):
        super().__init__(modo=modo, carpeta=carpeta, **otros)
        self.visitar = visitar
        self.pedidas = 0       # peticiones a sitios de esta corrida, para el ritmo fijo

    def _transporte(self, url, timeout):
        return _descargar_ct(url, timeout)

    def ruta(self, host, ruta):
        """La respuesta de https://<host><ruta> ya limpia (limpiar). `ruta` tiene que ser una de RUTAS: con otra
        lanza ValueError sin pedir nada. Antes de cada petición, salvo la primera, espera PAUSA_RUTA. Lanza SinTiempo
        si a la corrida ya no le alcanza para la petición, y SinGrabacion al reproducir sin ella."""
        if ruta not in RUTAS:
            raise ValueError('api_docs: %r no está en la lista fija de rutas' % (ruta,))
        url = 'https://%s%s' % (host, ruta)
        consulta = 'ruta:%s:%s' % (host, ruta)
        del_disco, datos = self._de_disco(consulta)
        if del_disco:
            try:
                return limpiar(datos)
            except (ValueError, KeyError, TypeError, AttributeError):   # una grabación editada o de otra versión
                raise FuenteNoResponde('api_docs: la grabación de %s no se puede leer' % url) from None
        if self.pedidas:
            self.dormir(PAUSA_RUTA)
        limite = min(TIMEOUT_RUTA, self.restante())
        if limite < shodan.MIN_INTENTO:
            raise SinTiempo('api_docs: se acabó el tiempo de la corrida antes de pedir %s' % url)
        self.pedidas += 1
        self.consultas += 1
        datos = limpiar((self.visitar or _visitar)(url, limite))
        if datos.get('sin_respuesta') == 'tiempo' and limite < TIMEOUT_RUTA:
            # No tuvo sus TIMEOUT_RUTA segundos: lo que se acabó fue la corrida, no es que el sitio no responda
            raise SinTiempo('api_docs: se acabó el tiempo de la corrida mientras se pedía %s' % url)
        if datos.get('sin_respuesta') in FALLAS_DE_RED:
            self.fallas += 1
        self._grabar(consulta, datos)
        return datos


def carpeta_de(dominio):
    """Carpeta de la grabación de un dominio."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' consulta, 'reproducir' usa la grabación del dominio y 'grabar' empieza
    una grabación nueva."""
    return ClienteApiDocs(modo=modo, carpeta=carpeta_de(dominio), nueva=(modo == 'grabar'))


# ---------------------------------------------------------------- hallazgos

def _huella(codigo, dominio, activo, clave=''):
    """No lleva lo observado (la versión ni los conteos), así el hallazgo no se duplica entre escaneos."""
    return hashlib.sha256('|'.join((FUENTE, codigo, dominio, activo, clave)).encode('utf-8')).hexdigest()


def _funciones(n):
    return '1 función' if n == 1 else '%d funciones' % n


def _describir(url, doc):
    """Lo que va de un documento en la evidencia y en los atributos."""
    return {'url': url, 'formato': FORMATOS[doc['formato']], 'version': doc.get('version')}


def _hallazgo(codigo, dominio, activo, tipo, titulo, evidencia, ahora, host):
    evidencia = dict(evidencia, title=titulo, fuente=FUENTE, uso='api')
    caracteristicas = rubrica.calcular(codigo, tipo, evidencia, ahora)
    return Hallazgo(codigo, CODIGOS[codigo], activo, titulo, evidencia, caracteristicas,
                    _huella(codigo, dominio, activo), partes=[host])


class _Sitio:
    """Lo que la corrida sabe de un sitio: su estado, sus documentos y si quedó revisado."""

    def __init__(self, nombre):
        self.nombre = nombre
        self.estado = None       # 'sin_a', 'no_publica', 'sin_https', 'revisado' o 'sin_revisar', si se llegó a saber
        self.docs = []           # (ruta, doc) de cada ruta que dio un documento o la página de documentación
        self.falta = None        # el motivo de MOTIVOS si quedó sin revisar

    def sin_revisar(self, motivo):
        if self.falta is None:
            self.falta = motivo


def _pedir_rutas(res, cliente, sitio):
    """Pide las RUTAS de un sitio, en orden, y deja en `sitio` lo que respondieron. SinTiempo sale de aquí."""
    errores = 0
    for i, ruta in enumerate(RUTAS):
        if cliente.restante() < MIN_RESTANTE:
            raise SinTiempo('api_docs: se acabó el tiempo de la corrida')
        respuesta = cliente.ruta(sitio.nombre, ruta)
        if respuesta.get('rechazada'):
            if i == 0:
                sitio.estado = 'sin_https'    # no hay sitio https: no hay nada que revisar
            else:
                sitio.sin_revisar('red')      # respondía y dejó de hacerlo
                cliente.fallas += 1           # una falla de red de la corrida: no se graba
            return
        if 'sin_respuesta' in respuesta:
            sitio.sin_revisar(respuesta['sin_respuesta'])
            return
        if 'reto' in respuesta:
            reto = respuesta['reto']
            quien = borde.PROVEEDORES.get(reto.get('proveedor'))
            res.avisos.append('api_docs: %s respondió con un reto o un límite de peticiones%s (%s): su documentación '
                              'queda sin revisar, no en 0' % (sitio.nombre, ' de %s' % quien if quien else '',
                                                              respuesta['estado']))
            sitio.sin_revisar('reto')
            return
        if respuesta.get('redirige'):
            continue
        if respuesta['estado'] >= 500:
            sitio.sin_revisar('error_http')
            errores += 1
            if errores >= MAX_ERRORES:
                break
            continue
        doc = respuesta.get('doc')
        if not doc or (doc['formato'] == 'ui' and ruta not in RUTAS_UI):
            continue
        if doc['formato'] == 'grande':
            sitio.sin_revisar('grande')   # está a la vista, pero sus funciones no se contaron
        sitio.docs.append((ruta, doc))
    sitio.estado = 'revisado' if sitio.falta is None else 'sin_revisar'


def _reportar(res, sitio, dominio, ahora):
    """Los activos y hallazgos de un sitio con documentación."""
    host = sitio.nombre
    tipo = 'domain' if host == dominio else 'subdomain'
    unicos, repetidos = [], {}
    for ruta, doc in sitio.docs:
        url = 'https://%s%s' % (host, ruta)
        # El mismo documento en otra ruta es un solo activo, y la página y el documento sin leer, uno por sitio
        primero = next((u for u, d in unicos if d['formato'] == doc['formato']
                        and (doc['formato'] not in DOCUMENTOS or d.get('huella') == doc.get('huella'))), None)
        if primero:
            repetidos.setdefault(primero, []).append(url)
        else:
            unicos.append((url, doc))
    documentos = [_describir(url, doc) for url, doc in unicos]
    estado = {'fuente': FUENTE, 'estado': 'con_documentacion' if unicos else (sitio.estado or 'sin_revisar'),
              'documentos': documentos}
    if sitio.falta:
        estado['sin_revisar'] = MOTIVOS[sitio.falta]
    res.activos.append(Activo(tipo, host, {'api_docs': estado}))
    if not unicos:
        return
    res.hallazgos.append(_hallazgo('exposed_api_docs', dominio, host, tipo, TITULO_EXPUESTA % host,
                                   {'host': host, 'url': unicos[0][0], 'documentos': documentos}, ahora, host))
    for url, doc in unicos:
        leido = doc['formato'] in DOCUMENTOS
        # Siempre las mismas llaves: la base mezcla los atributos con los guardados y una que falte no se borra
        atributos = dict(_describir(url, doc), host=host, parent=host, fuente=FUENTE,
                         tambien_en=repetidos.get(url, []), titulo=doc['titulo'] if leido else None,
                         operaciones=doc['operaciones'] if leido else None,
                         no_declaran_autenticacion=doc['sin_declarar'] if leido else None)
        del atributos['url']
        res.activos.append(Activo(TIPO_ACTIVO, url, atributos))
        if not leido or not doc['sin_declarar']:
            continue
        titulo = TITULO_AUTENTICACION % (host, '%d de %s' % (doc['sin_declarar'], _funciones(doc['operaciones'])))
        evidencia = dict(_describir(url, doc), host=host, operaciones=doc['operaciones'],
                         sin_declarar=doc['sin_declarar'], muestra=list(doc['muestra']), nota=NOTA)
        res.hallazgos.append(_hallazgo('api_auth_not_declared', dominio, url, TIPO_ACTIVO, titulo, evidencia, ahora,
                                       host))


# ---------------------------------------------------------------- punto de entrada

def _sin_cobertura(res, aviso):
    res.avisos.append(aviso)
    res.sin_cobertura = list(CODIGOS)
    return res


def recolectar(dominio, cliente=None, ahora=None, propios=()):
    """Documentación de APIs a la vista en los sitios del dominio. `propios` no se usa."""
    dominio = dominio.strip().lower().rstrip('.')
    res = Resultado(dominio, FUENTE)
    if not NOMBRE_VALIDO.fullmatch(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res
    cliente = cliente or crear_cliente('vivo', dominio)
    if cliente.modo == 'reproducir' and not cliente.hay_grabacion():
        return _sin_cobertura(res, SIN_GRABACION_DOMINIO)
    try:
        cliente.empezar()
        _revisar(res, cliente, dominio, ahora or datetime.now(timezone.utc))
    finally:
        res.consultas = cliente.consultas
    return res


def _revisar(res, cliente, dominio, ahora):
    parcial, todos_los_nombres = [], True

    # 1. Nombres de Cert Spotter, más la raíz
    try:
        certs, completos = certspotter.certificados(cliente, dominio, max_paginas=PAGINAS_CT, intentos=INTENTOS_CT,
                                                    timeout=TIMEOUT_CT)
        ct_respondio = True
        if not completos:
            res.avisos.append('api_docs: Cert Spotter no dio todas sus páginas, pueden faltar sitios del dominio')
            parcial.append('paginas' if not cliente.fallas and not cliente.raras_ct else 'ct')
            todos_los_nombres = False
    except FuenteNoResponde as e:
        certs, ct_respondio, todos_los_nombres = [], False, False
        res.avisos.append('%s. Solo se revisó la raíz' % e)
        parcial.append('ct')
    nombres = shodan._nombres(dominio, certs)
    if len(nombres) > MAX_SITIOS:
        res.avisos.append('api_docs: se revisaron %d de %d nombres del dominio (MAX_SITIOS)'
                          % (MAX_SITIOS, len(nombres)))
        nombres = visita._elegir(nombres, ahora, cliente)
        parcial.append('sitios')
        todos_los_nombres = False

    # 2. El A y las rutas de cada nombre
    sitios = {nombre: _Sitio(nombre) for nombre in nombres}
    fallas_dns, sin_tiempo = 0, []
    for i, nombre in enumerate(nombres):
        sitio = sitios[nombre]
        if cliente.restante() < MIN_RESTANTE:
            sin_tiempo = nombres[i:]
            break
        try:
            registro = cliente.resolver_a(nombre)
        except SinTiempo:
            sin_tiempo = nombres[i:]
            break
        except SinGrabacion:
            sitio.sin_revisar('grabacion')
            continue
        except FuenteNoResponde:
            fallas_dns += 1
            sitio.sin_revisar('dns')
            continue
        if registro['estado'] != 'ok':
            sitio.estado = 'sin_a'
            continue
        if not any(transporte.publica(ip) for ip in registro['ips']):
            sitio.estado = 'no_publica'
            continue
        try:
            _pedir_rutas(res, cliente, sitio)
        except SinTiempo:
            sin_tiempo = nombres[i:]
            break
        except SinGrabacion:
            sitio.sin_revisar('grabacion')
        except FuenteNoResponde as e:   # una grabación que no se puede leer
            res.avisos.append(str(e))
            sitio.sin_revisar('grabacion')
            parcial.append('ilegible')
    for nombre in sin_tiempo:
        sitios[nombre].sin_revisar('sin_tiempo')
    if sin_tiempo:
        res.avisos.append('api_docs: se acabó el tiempo de la corrida antes de terminar %s'
                          % visita._cuantos(len(sin_tiempo), 'sitio', 'sitios'))
        parcial.append('tiempo')
    if not ct_respondio and fallas_dns == len(nombres):
        raise FuenteNoResponde('api_docs: no respondieron Cert Spotter ni el DNS de %s' % dominio)
    if fallas_dns:
        res.avisos.append('api_docs: el DNS no respondió al A de %s' % visita._cuantos(fallas_dns, 'nombre', 'nombres'))
        parcial.append('a')

    # 3. Activos y hallazgos: lo que se encontró se reporta aunque al sitio le haya faltado otra ruta
    for host in sorted(sitios, key=lambda h: (h != dominio, h)):
        sitio = sitios[host]
        if sitio.docs or sitio.estado in ('revisado', 'sin_revisar', 'sin_https'):
            _reportar(res, sitio, dominio, ahora)

    # 4. Cobertura
    faltan = [h for h, s in sitios.items() if s.falta]
    hechos = [h for h, s in sitios.items() if not s.falta]
    por_motivo = {}
    for h in faltan:
        por_motivo.setdefault(sitios[h].falta, []).append(h)
    for motivo, hosts in sorted(por_motivo.items()):
        if motivo not in ('reto', 'sin_tiempo', 'dns'):   # esos ya tienen su aviso
            res.avisos.append('api_docs: %s sin revisar: %s (%s)' % (visita._cuantos(len(hosts), 'sitio', 'sitios'),
                                                                   MOTIVOS[motivo], visita._lista(sorted(hosts))))
    lista = faltan if todos_los_nombres else None
    revisados, sin_revisar, sin_cobertura = borde.cobertura(hechos, lista, list(CODIGOS))
    if sin_cobertura and res.hallazgos:
        # Ningún sitio quedó revisado completo, pero alguno dio hallazgos antes de que le faltara otra ruta: se
        # reportan y la corrida queda parcial, sin cerrar nada de lo que no se revisó.
        revisados, sin_revisar, sin_cobertura = [], (sorted(faltan) if lista is not None else None), []
    res.revisados, res.sin_revisar, res.sin_cobertura = revisados, sin_revisar, sin_cobertura
    if revisados is not None or sin_cobertura:
        res.avisos.append('%s, se revisaron %d de %d sitios' % (PARCIAL, len(hechos), len(sitios)))
    if cliente.modo == 'grabar' and cliente.degradada(parcial):
        res.avisos.insert(0, NO_SE_GRABO)
    else:
        cliente.terminar()
    return res


# ---------------------------------------------------------------- línea de comandos

def resumen(res):
    lineas = ['%s · %s · %s · %d consultas' % (res.dominio, res.fuente, res.estado, res.consultas)]
    if res.error:
        lineas.append('error: ' + res.error)
    for a in res.activos:
        if a.tipo == TIPO_ACTIVO:
            version = a.atributos.get('version') or ''
            lineas.append('  %s %s: %s %s' % (a.tipo, a.valor, a.atributos['formato'], version))
    for h in res.hallazgos:
        lineas.append('  [%s] %s' % (h.severidad, h.titulo))
    if res.sin_cobertura:
        lineas.append('Cobertura parcial: no se revisaron %s.' % ' ni '.join(res.sin_cobertura))
    lineas += ['aviso: ' + a for a in res.avisos]
    return '\n'.join(lineas)


def codigo_salida(res):
    """0 si terminó completa, 1 si la fuente quedó en 'failed', 2 con cobertura parcial y 3 si --grabar no escribió."""
    if res.estado == 'failed':
        return 1
    if NO_SE_GRABO in res.avisos:
        return 3
    return 2 if res.sin_cobertura or res.revisados is not None else 0


def _main(argv=None, hoy=None):
    p = argparse.ArgumentParser(description='Documentación de APIs a la vista, actividad 9 (sin --reproducir consulta '
                                            'en vivo)')
    p.add_argument('dominio')
    modo = p.add_mutually_exclusive_group()
    modo.add_argument('--grabar', action='store_true', help='consulta en vivo y graba las respuestas')
    p.epilog = ('En vivo y con --grabar las consultas no pasan por el límite diario de la fuente (eso lo hace el '
                'orquestador) y solo se permiten desde el %s.' % VIGENTE_DESDE.isoformat())
    modo.add_argument('--reproducir', action='store_true', help='usa solo lo grabado, sin red')
    args = p.parse_args(argv)
    dominio = args.dominio.strip().lower().rstrip('.')
    elegido = 'grabar' if args.grabar else 'reproducir' if args.reproducir else 'vivo'
    if elegido != 'reproducir' and not shodan._en_vivo_permitido(dominio):
        print('%s no está en DOMINIOS_EN_VIVO: solo se puede --reproducir' % dominio, file=sys.stderr)
        return 1
    if elegido != 'reproducir' and (hoy or datetime.now(timezone.utc).date()) < VIGENTE_DESDE:
        print('la actividad 9 del Anexo A rige desde el %s: antes solo se puede --reproducir'
              % VIGENTE_DESDE.isoformat(), file=sys.stderr)
        return 1
    res = contrato.ejecutar(sys.modules[__name__], dominio, elegido)
    print(resumen(res))
    return codigo_salida(res)


if __name__ == '__main__':
    sys.exit(_main())
