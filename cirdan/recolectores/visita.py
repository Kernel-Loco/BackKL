"""Visita web normal de la actividad 6 del Anexo A de la carta (#18, RC-46, comentarios 10281, 10283 y 10334).

Pide la página principal de cada sitio del dominio por https, como un navegador, y saca de la respuesta sus
tecnologías (huellas.py), el CDN o WAF que tiene delante (borde.py), si la versión ya no tiene soporte
(outdated_software, con endoflife.date, soporte.py), las CVE conocidas de esa versión (known_vulnerability, con la
API 2.0 de la NVD, nvd.py), si sus cabeceras Server o X-Powered-By dicen la versión (server_version_disclosed) y,
con el título y el primer encabezado de la misma página (portada.py, #111, RC-228), si es un listado de directorio
(directory_listing) o una página de depuración (debug_page_exposed), también la de un 4xx o un 5xx, sin ninguna
petición más. Las CVE van además en Resultado.cves, que el orquestador guarda en la tabla cves.

Qué se pide, todo pasivo o dentro del Anexo A:
1. Los nombres del dominio en Cert Spotter (las mismas PAGINAS_CT de shodan.py) más la raíz, hasta MAX_SITIOS.
2. El A de cada nombre con 1.1.1.1 y 8.8.8.8 (shodan._resolver_a): la cadena CNAME y las IP van a borde.detectar().
   Un nombre sin A, o solo con IP que no son públicas, no se visita.
3. Una sola petición GET https://<nombre>/ por sitio, con el User-Agent de la carta (contrato.AGENTE, sección 9) y un
   ritmo fijo: una petición a la vez y PAUSA_SITIO segundos antes de cada una, sin reintentos. La conexión va solo a
   direcciones públicas (transporte._conectar, que revisa la misma lista a la que se conecta) y el certificado se
   revisa. Se siguen a lo más MAX_REDIRECCIONES redirecciones, solo a https en el puerto 443 de un nombre del dominio.
   Una redirección a otro dominio no se sigue: solo se guarda a qué nombre manda. Nunca se pide otra ruta, ni un
   script, ni se envía un formulario, ni se reintenta para saltar un reto del WAF.
   Si el 443 rechaza la conexión o no la acepta en todo su plazo (una nube que descarta los paquetes de un puerto
   cerrado da tiempo al conectar, no rechazo: transporte.SinConexion), se pide una sola vez GET http://<nombre>/ en el
   puerto 80 (transporte.PUERTOS_HTTP), con TIMEOUT_HTTP, el mismo filtro de IP públicas y sin seguir su redirección.
   Si da una página, esa es la visita del sitio (_recorrer). Un 443 que conectó y no terminó, o una falla de la red,
   es pasajero: cuenta como falla y no se prueba el 80, así una caída momentánea no cambia el sitio por el del 80.
4. endoflife.date (una vez por producto, MAX_PRODUCTOS) y la NVD (una vez por CPE con versión, MAX_CPE, con PAUSA_NVD
   segundos entre una y otra, el ritmo de la NVD sin llave), solo para lo que soporte.py y nvd.py pueden revisar.
   El ritmo de la NVD es de todo el proceso (RITMO_NVD): dos escaneos a la vez salen de la misma IP y comparten las
   5 peticiones cada 30 s, y un reintento también espera su turno.

Con más de MAX_SITIOS nombres se visitan la raíz y un bloque de los demás que cambia con el día (_elegir): ninguno
queda siempre fuera. La conexión a un sitio va solo por IPv4, como su A.

Cobertura (#23). Las partes son los sitios (sus nombres), salvo las de tls_certificate_invalid y tls_legacy_only,
que son 'tls:<sitio>' (RC-239, _cobertura_tls). Un sitio queda revisado si su visita terminó y todo lo que
pedían sus tecnologías llegó: también un nombre sin A, uno sin sitio en el 443 ni en el 80 o uno que redirige a
otro dominio o uno cuyo A solo trae IP que no son públicas (no tiene sitio público). Queda sin revisar si no se
pudo visitar (tiempo, red, certificado, o al conectar no quedó ninguna IP pública), si respondió con un error del
servidor (5xx), con un reto o bloqueo del WAF, si las huellas no vieron toda la respuesta o si faltó la respuesta de endoflife.date o de la NVD
de una de sus tecnologías. borde.cobertura() lo pasa al Resultado. Con todos los nombres de Cert Spotter se sabe
cuáles faltan (sin_revisar), y si no, o si hay un comodín y un sitio no llegó a responder (OPACOS: pudo
redirigir a un nombre que solo cubre el comodín), solo cuáles se revisaron.

Qué se guarda. Del sitio, en los atributos de su domain o subdomain: 'web' (estado de la visita, la URL final, el
estado HTTP y a dónde redirige), 'borde' (borde.detectar(), None si no se vio un CDN) y 'tecnologias' (nombre,
versión y categorías). Si la visita no terminó, 'borde' y 'tecnologias' no se escriben y queda lo último que se vio.
De las cookies solo se guarda el nombre: el valor se borra al leer la respuesta, también en vivo, así la grabación y
el análisis no lo tienen nunca. Del cuerpo se lee a lo más MAX_BYTES_SITIO y se graba como texto. La respuesta de la
NVD se graba reducida a lo que lee nvd.leer() (_reducir_nvd).

El cliente es el de shodan.py (Cert Spotter, el A, los reintentos, el tiempo de la corrida y la grabación) con su
propio prefijo, su tiempo y su transporte (ClienteWeb). Lo que un tope determinista deja fuera no impide grabar
(TOPES). Una corrida con fallas (la red, el tiempo, un 429 o un 403 de la NVD) no pisa la grabación anterior.

Uso, desde la raíz del repo:
  python -m cirdan.recolectores.visita olmardo.com --reproducir
"""
import argparse
import codecs
import hashlib
import http.client
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from cirdan.ml import caracteristicas as rubrica
from cirdan.recolectores import (borde, certspotter, contrato, geoip, huellas, nvd, portada, shodan, soporte,
                                 transporte, turno)
from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import (NOMBRE_VALIDO, Activo, FuenteNoResponde, Hallazgo, Resultado, SinGrabacion,
                                          en_alcance_nombre)
from cirdan.recolectores.shodan import LimiteAlcanzado, RespuestaIlegible, SinTiempo

FUENTE = 'web'
CARPETA_GRABADAS = RAIZ_GRABADAS / 'web'

# Código de regla -> severidad base. Los tres primeros existen en el catálogo de reglas (semillas 001 y 004), los dos
# de portada.py en la semilla 021 (RC-228) y los dos del saludo TLS en la semilla 022 (#121, RC-239).
CODIGOS = dict(soporte.CODIGOS, **nvd.CODIGOS, server_version_disclosed='low', **portada.CODIGOS,
               tls_certificate_invalid='medium', tls_legacy_only='medium')

# El saludo TLS de la visita (#121, RC-239): el mismo de la petición, con el contexto de transporte.py, que revisa el
# certificado y el nombre y pide TLS 1.2 como mínimo. No hay otro saludo para confirmar nada: ni sin revisar el
# certificado ni con un mínimo más bajo.
# verify_code de OpenSSL (X509_V_ERR_*) -> motivo de tls_certificate_invalid. Otro código da 'otro'.
MOTIVOS_CERTIFICADO = {10: 'vencido', 18: 'autofirmado', 19: 'autofirmado', 62: 'otro_nombre', 66: 'debil',
                       67: 'debil', 68: 'debil', 20: 'emisor_desconocido'}
TEXTO_CERTIFICADO = {'vencido': 'un certificado vencido', 'autofirmado': 'un certificado autofirmado',
                     'otro_nombre': 'un certificado de otro nombre', 'debil': 'un certificado con llave o firma débil',
                     'emisor_desconocido': 'un certificado de un emisor que no se reconoce o sin su intermedio',
                     'otro': 'un certificado que no se pudo verificar'}
# El 20 de OpenSSL no distingue un intermedio que el servidor no manda de un emisor privado (la autoridad interna de la
# empresa): la nota dice las dos cosas.
NOTA_CADENA = ('Si el certificado es de una autoridad pública y al servidor le falta mandar el intermedio, algunos '
               'navegadores lo completan solos y el sitio puede abrir en unos y fallar en otros. Si es de una autoridad '
               'privada de la empresa, ningún navegador público lo acepta.')
# Razones de OpenSSL de un saludo que falló por la versión: el servidor mandó la alerta protocol_version, o contestó
# con TLS 1.1 o anterior y el cliente lo rechazó por debajo de su mínimo. WRONG_VERSION_NUMBER no cuenta: es lo que da
# un servidor que no habla TLS en el 443 (por ejemplo, HTTP en texto plano).
ALERTAS_VERSION = frozenset({'TLSV1_ALERT_PROTOCOL_VERSION', 'UNSUPPORTED_PROTOCOL', 'VERSION_TOO_LOW'})
# Las dos reglas del saludo llevan como parte 'tls:<sitio>', no el sitio: se revisan en cuanto el saludo terminó, aunque
# lo demás del sitio quede sin revisar (un reto, un 5xx, la NVD), y así un certificado renovado se cierra.
PARTE_TLS = 'tls:'
CODIGOS_TLS = ('tls_certificate_invalid', 'tls_legacy_only')
MINIMO_TLS = 'TLSv1.2'
_NOMBRE_TLS = re.compile(r'[A-Za-z0-9_.-]{1,64}', re.A)   # TLSv1.3, TLS_AES_256_GCM_SHA384, ECDHE-RSA-AES128-GCM-SHA256

# Cabeceras que revelan el programa del servidor y una versión: 'nginx/1.24.0 (Ubuntu)', 'PHP/8.1.2'. Sin número de
# versión ('nginx', 'cloudflare', 'Express') no hay hallazgo.
CABECERAS_VERSION = ('server', 'x-powered-by')
_CON_VERSION = re.compile(r'[A-Za-z][\w.+-]*/v?[0-9]+(\.[0-9]+)*', re.A)
MAX_VALOR_CABECERA = 200     # caracteres del valor de la cabecera en la evidencia
# Lo que se guarda de las cabeceras de una visita (limpiar_visita): sin esto, 100 cabeceras de 64 KiB (los topes de
# http.client) iban enteras a la grabación, también desde un 80 en texto plano. borde y huellas nunca leen más de
# borde.MAX_VALOR caracteres de un valor, y uno más largo no lo leen: con uno de sobra el análisis no cambia.
MAX_PARES = 100              # cabeceras de una respuesta, el tope de http.client
MAX_LARGO_CABECERA = borde.MAX_VALOR + 1

AGENTE = contrato.AGENTE
ACEPTA = 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1'
IDIOMA = 'es-MX,es;q=0.9,en;q=0.5'

PAGINAS_CT = shodan.PAGINAS_CT
INTENTOS_CT = shodan.INTENTOS_CT
TIMEOUT_CT = shodan.TIMEOUT_CT
MAX_SITIOS = 20              # nombres que se visitan, con la raíz
MAX_REDIRECCIONES = 3        # redirecciones que se siguen por sitio, dentro del dominio
TIMEOUT_SITIO = 10           # segundos de cada petición a un sitio, de getaddrinfo al último byte
# Segundos de la petición al 80 cuando el 443 no conectó. Un sitio con el 443 y el 80 que descartan los paquetes
# tarda PAUSA_SITIO + TIMEOUT_SITIO + PAUSA_SITIO + TIMEOUT_HTTP (17 s, 22 s si el 80 tuviera TIMEOUT_SITIO): MAX_SITIOS
# así caben en TIEMPO_CORRIDA - RESERVA_APIS y dejan 110 s para Cert Spotter y las A (Http.test_12 de test_visita).
# Una cadena de redirecciones lenta puede tardar más; ahí SinTiempo deja el resto sin revisar, como antes.
TIMEOUT_HTTP = 5
PAUSA_SITIO = 1              # segundos antes de cada petición a un sitio, salvo la primera de la corrida
MAX_BYTES_SITIO = 4 * huellas.MAX_HTML   # bytes del cuerpo: huellas lee MAX_HTML caracteres, de hasta 4 bytes
MAX_URL = 2048               # caracteres de la URL de una redirección que se sigue
INTENTOS_API = 2             # intentos por consulta a endoflife.date o a la NVD
TIMEOUT_API = 20             # segundos por consulta a endoflife.date o a la NVD
PAUSA_EOL = 1                # segundos entre una consulta a endoflife.date y la siguiente
PAUSA_NVD = nvd.PAUSA_NVD    # segundos entre una consulta a la NVD y la siguiente (5 por 30 s sin llave, con margen)
MAX_PRODUCTOS = 10           # productos que se consultan en endoflife.date por corrida
MAX_CPE = 10                 # CPE que se consultan en la NVD por corrida
MAX_BYTES_API = 8 * 1024 * 1024   # tope de una respuesta de Cert Spotter, endoflife.date o la NVD
TIEMPO_CORRIDA = 600         # segundos de toda la corrida: ninguna consulta empieza después
MIN_RESTANTE = 5             # con menos segundos que esto ya no se empieza otro sitio ni otra consulta
# Segundos que los sitios le dejan a endoflife.date y a la NVD: sin esto, unos sitios lentos se comen la corrida y
# ninguna tecnología se revisa.
RESERVA_APIS = 150
# Peor caso de una corrida para el límite diario (#13b): cada intento de cada petición. La petición por http del 80
# solo va cuando el primer https se rechazó o no conectó, así que ese sitio no siguió redirecciones: usa 2 de sus
# 1 + MAX_REDIRECCIONES peticiones posibles y el peor caso no cambia.
MAX_CONSULTAS = (PAGINAS_CT * INTENTOS_CT + MAX_SITIOS * shodan.INTENTOS + MAX_SITIOS * (1 + MAX_REDIRECCIONES)
                 + MAX_PRODUCTOS * INTENTOS_API + MAX_CPE * INTENTOS_API)

# Topes deterministas: lo que dejan fuera no impide grabar.
TOPES = ('paginas', 'sitios', 'productos', 'cpe')
# Motivos de una visita que no dio la página del sitio: pudo redirigir a un nombre que no se conoce. Un 5xx o un reto
# cuentan, porque la raíz que hoy da 502 ayer redirigía a www. No son FALLAS_DE_RED: sí se graban.
OPACOS = ('tiempo', 'red', 'certificado', 'tls', 'tls_viejo', 'no_publica', 'grabacion', 'dns', 'sin_tiempo', 'redirecciones',
          'reto', 'error_http')
# Por qué un sitio no se pudo visitar (la clave 'sin_respuesta' de la visita). Solo estas cuentan como una falla de
# la corrida (no se graba): las demás son un dato estable del sitio.
FALLAS_DE_RED = ('tiempo', 'red')
MOTIVOS = {'tiempo': 'no respondió a tiempo', 'red': 'la conexión falló', 'certificado': 'su certificado no se pudo '
           'verificar', 'tls': 'no se pudo negociar TLS con el sitio',
           'tls_viejo': 'no acepta TLS 1.2 ni 1.3',
           'no_publica':'su nombre resolvió solo a direcciones que no son públicas',
           'redirecciones': 'redirigió más de %d veces' % MAX_REDIRECCIONES,
           'no_https': 'redirige fuera de https o a otro puerto', 'ilegible': 'redirige a una dirección que no se '
           'puede leer', 'grabacion': 'la grabación no trae su visita', 'dns': 'el DNS no respondió a su A',
           'huellas': 'las huellas no vieron toda la respuesta', 'eol': 'faltó la respuesta de endoflife.date',
           'nvd_falta': 'faltó la respuesta de la NVD', 'tope': 'una de sus tecnologías quedó fuera del tope de '
           'consultas', 'reto': 'respondió con un reto o bloqueo', 'error_http': 'respondió con un error del servidor (5xx)',
           'portada': 'no se pudieron leer el título y el encabezado de su página', 'borde': 'no se pudieron leer sus datos de borde',
           'sin_tiempo': 'se acabó el tiempo de la corrida'}

SIN_GRABACION_DOMINIO = 'web: no hay grabación de la visita web de este dominio, no se visitaron sus sitios'
PARCIAL = 'web: cobertura parcial'
NO_SE_GRABO = ('web: la corrida tuvo fallas (la red, el tiempo, un límite de consultas o una respuesta que no se puede '
               'leer), no se grabó y la grabación anterior sigue igual: repite --grabar más tarde')
_CHARSET = re.compile(r'charset\s*=\s*["\']?([A-Za-z0-9_.:-]{1,40})', re.A)
CVE_VALIDO = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}')


# ---------------------------------------------------------------- red

def _descargar_api(url, timeout, cronometro=None):
    """El cuerpo de la respuesta de Cert Spotter, endoflife.date o la NVD, de a lo más MAX_BYTES_API, con el plazo
    absoluto de transporte.descargar. Una respuesta más grande o una redirección dan RespuestaIlegible, nunca un error
    que tumbe la corrida. Va por certspotter.descargar: una página de Cert Spotter que otra fuente ya pidió en este
    escaneo no sale a la red (RC-326)."""
    cronometro = cronometro or time.monotonic
    req = urllib.request.Request(url, headers={'User-Agent': AGENTE, 'Accept': 'application/json'})
    try:
        return certspotter.descargar(req, cronometro() + timeout, MAX_BYTES_API, cronometro)
    except transporte.PlazoVencido:
        raise SinTiempo('web: la respuesta tardó más de %s s' % timeout) from None
    except transporte.Redirigida as e:
        raise RespuestaIlegible('web: %s' % e) from None
    except ValueError as e:
        raise RespuestaIlegible('web: %s' % e) from None


# Errores de ssl que son de la conexión y no del sitio: se cortó a medias o no terminó. Cuentan como 'red'.
_TLS_PASAJERO = (ssl.SSLEOFError, ssl.SSLZeroReturnError, ssl.SSLSyscallError, ssl.SSLWantReadError,
                 ssl.SSLWantWriteError)


def _falla(error):
    """{'sin_respuesta': motivo} de MOTIVOS de una petición a un sitio que no terminó. Un certificado que no se pudo
    verificar lleva su verify_code (un entero de OpenSSL, o None si no vino)."""
    motivo = _motivo(error)
    if motivo != 'certificado':
        return {'sin_respuesta': motivo}
    razon = error.reason if isinstance(error, urllib.error.URLError) else error
    codigo = getattr(razon, 'verify_code', None)
    return {'sin_respuesta': 'certificado', 'verify_code': codigo if shodan._entero(codigo) else None}


def _motivo(error):
    """El motivo de MOTIVOS de una petición a un sitio que no terminó."""
    razon = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(razon, transporte.NoPublica):
        return 'no_publica'
    if isinstance(razon, ssl.SSLCertVerificationError):
        return 'certificado'
    if isinstance(razon, ssl.SSLError) and not isinstance(razon, _TLS_PASAJERO):
        if getattr(razon, 'reason', None) in ALERTAS_VERSION:
            return 'tls_viejo'   # no acepta TLS 1.2 ni 1.3: no se baja el mínimo para ver cuál acepta (#122)
        return 'tls'   # el sitio no negocia TLS con este cliente (protocolo o cifrado): es fijo del sitio, no de la red
    if isinstance(razon, (TimeoutError, socket.timeout)):
        return 'tiempo'
    return 'red'


def _visitar(url, timeout, cronometro=None, saludo=None, limpiar=True):
    """La respuesta de un sitio a GET `url`, ya limpia (limpiar_visita), en una sola petición sin reintentos y dentro
    de `timeout` segundos. La única función que pide a un sitio del cliente: las pruebas la cambian con
    mock.patch.object. Nunca lanza por el sitio: lo que no terminó es {'sin_respuesta': motivo}.
    `saludo` son las llaves extra que transporte llena del saludo TLS ({'correos': None} trae los correos del
    certificado, para identidad.py, #20). Con `limpiar` en False la página sale sin limpiar_visita: quien llama la
    reduce."""
    cronometro = cronometro or time.monotonic
    req = urllib.request.Request(url, headers={'User-Agent': AGENTE, 'Accept': ACEPTA, 'Accept-Language': IDIOMA})
    req.saludo = dict(saludo or {})   # transporte lo llena con la versión y el cifrado del saludo TLS (RC-239)
    try:
        estado, cabeceras, cuerpo, cortado = transporte.visitar(req, cronometro() + timeout, MAX_BYTES_SITIO,
                                                                cronometro)
    except transporte.Redirigida as e:
        redirige = {'redirige': e.destino if isinstance(e.destino, str) else None, 'codigo': e.codigo}
        if 'correos' in req.saludo:   # identidad.py lee los correos del certificado que dio la redirección
            redirige['tls'] = dict(req.saludo)
        return redirige
    except transporte.SinConexion:   # ninguna IP aceptó la conexión: el puerto descarta los paquetes
        return {'sin_respuesta': 'tiempo', 'al_conectar': True}
    except transporte.PlazoVencido:
        return {'sin_respuesta': 'tiempo'}
    except urllib.error.URLError as e:
        if isinstance(e.reason, ConnectionRefusedError):
            return {'rechazada': True}
        return _falla(e)
    except ConnectionRefusedError:
        return {'rechazada': True}
    except (OSError, http.client.HTTPException, ValueError) as e:
        return _falla(e)
    visita = {'estado': estado, 'cabeceras': cabeceras, 'cuerpo': _texto(cuerpo, cabeceras), 'cortado': cortado}
    if req.saludo:
        visita['tls'] = dict(req.saludo)
    return limpiar_visita(visita) if limpiar else visita


def _texto(cuerpo, cabeceras):
    """El cuerpo como texto, con el charset de su Content-Type si Python lo conoce, y si no UTF-8. Lo que no se puede
    decodificar queda como U+FFFD. Un charset que no es de texto (base64, zlib, rot13) o que no acepta 'replace' (idna,
    undefined) cae a UTF-8: nunca lanza."""
    tipo = next((v for k, v in cabeceras if isinstance(k, str) and k.lower() == 'content-type'), '') or ''
    m = _CHARSET.search(tipo) if isinstance(tipo, str) else None
    if m:
        try:
            info = codecs.lookup(m.group(1))
            if getattr(info, '_is_text_encoding', True):
                return cuerpo.decode(info.name, errors='replace')
        except (LookupError, UnicodeError, TypeError, ValueError):
            pass
    return cuerpo.decode('utf-8', errors='replace')


def _sin_valores(valor):
    """Una Set-Cookie con solo los nombres de sus cookies ('PHPSESSID=, lang='), sin valores ni atributos."""
    nombres = []
    for pedazo in huellas._SEPARA_COOKIES.split(valor):
        nombre, igual, _ = pedazo.split(';', 1)[0].partition('=')
        nombre = nombre.strip()
        if igual and nombre and nombre not in nombres:   # sin '=' el texto es el valor, no un nombre
            nombres.append(nombre)
    return ', '.join('%s=' % n for n in nombres)


def limpiar_visita(datos):
    """La visita como se analiza y se graba: estado HTTP entero, cabeceras como pares de textos con la Set-Cookie
    sin valores, el cuerpo como texto y si se cortó. Una redirección, un 443 cerrado o una falla quedan con su forma.
    ValueError si no tiene ninguna de esas formas (una grabación rota)."""
    if not isinstance(datos, dict):
        raise ValueError('forma inesperada')
    if 'redirige' in datos:
        destino = datos['redirige']
        if destino is not None and not isinstance(destino, str):
            raise ValueError('forma inesperada')
        codigo = datos.get('codigo')
        return {'redirige': destino[:MAX_URL + 1] if destino else None,
                'codigo': codigo if shodan._entero(codigo) else None}
    if datos.get('rechazada') is True:
        return {'rechazada': True}
    if 'sin_respuesta' in datos:
        if datos['sin_respuesta'] not in MOTIVOS:
            raise ValueError('forma inesperada')
        if datos['sin_respuesta'] == 'tiempo' and datos.get('al_conectar') is True:
            return {'sin_respuesta': 'tiempo', 'al_conectar': True}   # transporte.SinConexion: el puerto no conectó
        if datos['sin_respuesta'] == 'certificado':   # una grabación de antes de RC-239 no trae verify_code
            codigo = datos.get('verify_code')
            return {'sin_respuesta': 'certificado', 'verify_code': codigo if shodan._entero(codigo) else None}
        return {'sin_respuesta': datos['sin_respuesta']}
    estado, cabeceras, cuerpo = datos.get('estado'), datos.get('cabeceras'), datos.get('cuerpo')
    if not shodan._entero(estado) or not isinstance(cabeceras, (list, tuple)) or not isinstance(cuerpo, str):
        raise ValueError('forma inesperada')
    pares = []
    for par in cabeceras[:MAX_PARES]:
        if not isinstance(par, (list, tuple)) or len(par) != 2 or not all(isinstance(x, str) for x in par):
            raise ValueError('forma inesperada')
        nombre, valor = par
        valor = _sin_valores(valor) if nombre.lower() == 'set-cookie' else valor
        pares.append([nombre[:MAX_LARGO_CABECERA], valor[:MAX_LARGO_CABECERA]])
    limpia = {'estado': estado, 'cabeceras': pares, 'cuerpo': cuerpo, 'cortado': datos.get('cortado') is True}
    tls = _saludo(datos.get('tls'))
    if tls:
        limpia['tls'] = tls
    return limpia


def _saludo(tls):
    """{version, cifrado} del saludo TLS de una visita, con solo nombres como 'TLSv1.3' o 'TLS_AES_256_GCM_SHA384', o
    None si no vino o no se puede leer. Una grabación de antes de RC-239, o una visita por http, no lo trae."""
    if not isinstance(tls, dict):
        return None
    salida = {k: tls[k] for k in ('version', 'cifrado')
              if isinstance(tls.get(k), str) and _NOMBRE_TLS.fullmatch(tls[k])}
    return salida or None


def _reducir_nvd(datos):
    """La respuesta de la NVD con solo lo que lee nvd.leer(): el conteo de la página y de cada CVE su id, estado,
    fecha, descripciones y métricas. Sin configuraciones ni referencias, que son lo que pesa."""
    if not isinstance(datos, dict):
        return datos
    salida = {k: datos[k] for k in ('resultsPerPage', 'startIndex', 'totalResults') if k in datos}
    vulns = datos.get('vulnerabilities')
    if not isinstance(vulns, list):
        return salida
    salida['vulnerabilities'] = [
        {'cve': {k: v['cve'][k] for k in ('id', 'vulnStatus', 'published', 'descriptions', 'metrics') if k in v['cve']}}
        if isinstance(v, dict) and isinstance(v.get('cve'), dict) else v for v in vulns]
    return salida


class _Ritmo:
    """El turno de una fuente que limita por IP (la NVD sin llave: 5 peticiones cada 30 s): entre el inicio de una
    petición y el de la siguiente pasan `pausa` segundos, las pida quien las pida. Un candado lo hace seguro entre los
    hilos de dos escaneos a la vez (cirdan/api/escaneos.py corre cada escaneo en su hilo, en un solo proceso)."""

    def __init__(self, pausa):
        self.pausa, self.candado, self.siguiente = pausa, threading.Lock(), None

    def turno(self, ahora):
        """Los segundos que hay que esperar desde `ahora` para la siguiente petición. Aparta ese turno: quien llame
        después espera `pausa` segundos más."""
        with self.candado:
            inicio = ahora if self.siguiente is None else max(ahora, self.siguiente)
            self.siguiente = inicio + self.pausa
            return inicio - ahora


# El de todos los clientes del proceso que usan el reloj del sistema. Un cliente con su propio cronómetro (las pruebas)
# lleva el suyo, porque sus tiempos no se pueden comparar con los de otro reloj.
RITMO_NVD = _Ritmo(PAUSA_NVD)


class ClienteWeb(shodan.ClienteShodan):
    """El cliente de shodan.py (Cert Spotter y el A, con sus reintentos, el tiempo de la corrida y la grabación) con
    las peticiones a los sitios (sitio) y a endoflife.date y la NVD (api). `visitar(url, timeout)` pide a un sitio:
    si no se pasa, _visitar, buscada en el módulo en cada consulta."""
    PREFIJO = 'web: '
    TIEMPO_CORRIDA = TIEMPO_CORRIDA
    TOPES = TOPES
    # Cómo queda cada visita antes de analizarla y de grabarla. identidad.py (#20, RC-56) pone la suya, que solo
    # guarda lo ya reducido.
    limpiar = staticmethod(limpiar_visita)

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, visitar=None, **otros):
        super().__init__(modo=modo, carpeta=carpeta, **otros)
        self.visitar = visitar
        self.pedidas = 0       # peticiones a sitios de esta corrida, para el ritmo fijo
        self.vistas = {}       # consulta -> visita de esta corrida: ninguna URL se pide dos veces
        self.ritmo_nvd = RITMO_NVD if otros.get('cronometro') is None else _Ritmo(PAUSA_NVD)

    def _transporte(self, url, timeout):
        return _descargar_api(url, timeout)

    def sitio(self, url, contar=True, timeout=TIMEOUT_SITIO):
        """La visita a `url` ya limpia (limpiar_visita), con `timeout` segundos. Antes de cada petición, salvo la
        primera, espera PAUSA_SITIO. Con `contar` en False una falla de red no se suma a self.fallas: la cuenta quien
        llama (_recorrer, que antes prueba el 80).
        Una URL que ya se pidió en esta corrida (el salto intermedio de otra redirección) da la misma visita, sin
        otra petición. Lanza SinTiempo si a la corrida ya no le alcanza para la petición, también si la petición
        empezó con menos de `timeout` porque se acababa la corrida y no terminó, y SinGrabacion al reproducir
        sin ella."""
        consulta = 'sitio:%s:%s' % (urllib.parse.urlsplit(url).hostname or '',
                                    hashlib.sha256(url.encode('utf-8')).hexdigest()[:16])
        if consulta in self.vistas:
            return self.vistas[consulta]
        try:
            del_disco, datos = self._de_disco(consulta)
            if del_disco:
                self.vistas[consulta] = self.limpiar(datos)
                return self.vistas[consulta]
        except (ValueError, KeyError, TypeError, AttributeError):   # una grabación truncada o editada
            raise FuenteNoResponde(self.PREFIJO + 'la grabación de %s no se puede leer' % url) from None
        if self.pedidas:
            self.dormir(PAUSA_SITIO)
        quedan = self.restante()
        limite = min(timeout, quedan)
        if limite < shodan.MIN_INTENTO:
            raise SinTiempo(self.PREFIJO + 'se acabó el tiempo de la corrida antes de visitar %s' % url)
        # Una petición a la vez por host también entre escaneos (turno.py): espera a que el host quede libre.
        host = urllib.parse.urlsplit(url).hostname or ''
        with turno.turno(host, quedan - shodan.MIN_INTENTO) as espero:
            if espero:
                limite = min(timeout, self.restante())   # lo que le quedó a la corrida después de esperar el turno
                if limite < shodan.MIN_INTENTO:
                    raise SinTiempo(self.PREFIJO + 'se acabó el tiempo de la corrida antes de visitar %s' % url)
            self.pedidas += 1
            self.consultas += 1
            crudo = (self.visitar or _visitar)(url, limite)
        datos = self.limpiar(crudo)
        if datos.get('sin_respuesta') == 'tiempo' and limite < timeout:
            # No tuvo sus `timeout` segundos: lo que se acabó fue la corrida, no es que el sitio no responda
            raise SinTiempo(self.PREFIJO + 'se acabó el tiempo de la corrida mientras se visitaba %s' % url)
        if contar and datos.get('sin_respuesta') in FALLAS_DE_RED:
            self.fallas += 1
        self._grabar(consulta, datos)
        self.vistas[consulta] = datos
        return datos

    def api(self, consulta, url, que, pausa=0, reducir=None, limite_403=False, ritmo=False):
        """El JSON de endoflife.date o de la NVD (None con un 404), con INTENTOS_API intentos. Con `limite_403` un 403
        es el límite de consultas (la NVD sin llave responde 403 cuando se pasa): lanza LimiteAlcanzado. Con `ritmo`
        cada intento, también el reintento, espera su turno de la NVD (self.ritmo_nvd), y lanza SinTiempo si a la
        corrida no le alcanza para esperarlo."""
        try:
            del_disco, datos = self._de_disco(consulta)
        except (ValueError, KeyError, TypeError, AttributeError):
            raise FuenteNoResponde('web: la grabación de %s no se puede leer' % que) from None
        if del_disco:
            return datos

        def turno():
            espera = self.ritmo_nvd.turno(self.cronometro())
            if espera > 0:
                if self.restante() - espera < shodan.MIN_INTENTO:
                    raise SinTiempo('web: se acabó el tiempo de la corrida antes de consultar %s' % que)
                self.dormir(espera)

        def pedir():
            if pausa:
                self.dormir(pausa)
            try:
                crudo = self._http(url, INTENTOS_API, TIMEOUT_API, que, turno=turno if ritmo else None)
            except RespuestaIlegible as e:
                if limite_403 and str(e).endswith(' respondió 403'):
                    raise LimiteAlcanzado('web: %s llegó a su límite de consultas (403)' % que) from None
                raise
            return reducir(crudo) if reducir and crudo is not None else crudo
        datos = self._consultar(consulta, pedir)
        self._grabar(consulta, datos)
        return datos


def _error_servidor(visita):
    estado = visita.get('estado')
    return isinstance(estado, int) and not isinstance(estado, bool) and estado >= 500


def _sin_consulta(url):
    """La URL sin consulta ni ';parámetros' (jsessionid, PHPSESSID, state de OAuth): así va en atributos y evidencia.
    La grabación usa la URL completa como clave."""
    partes = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((partes.scheme, partes.netloc, partes.path.split(';', 1)[0] or '/', '', ''))


def carpeta_de(dominio):
    """Carpeta de la grabación de un dominio."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' consulta, 'reproducir' usa la grabación del dominio y 'grabar' empieza
    una grabación nueva."""
    return ClienteWeb(modo=modo, carpeta=carpeta_de(dominio), nueva=(modo == 'grabar'))


# ---------------------------------------------------------------- sitios

def _siguiente(destino, dominio):
    """(url, motivo) de una redirección: la URL que se visita después, o None y el motivo de MOTIVOS si no se sigue.
    Se sigue solo a https, en el puerto 443 y a un nombre del dominio. La URL se arma de nuevo sin usuario ni
    fragmento, y con la ruta y la consulta en ASCII. A otro dominio da (None, None): el sitio ya no es del dominio."""
    if not isinstance(destino, str) or len(destino) > MAX_URL:
        return None, 'ilegible'
    try:
        partes = urllib.parse.urlsplit(destino.strip())
        puerto = partes.port
    except ValueError:
        return None, 'ilegible'
    host = shodan._nombre(partes.hostname or '')
    if not host:
        return None, 'ilegible'
    if not en_alcance_nombre(host, dominio):
        return None, None
    if partes.scheme.lower() != 'https' or puerto not in (None, 443):
        return None, 'no_https'
    seguros = "/%:@!$&'()*+,;=-._~"
    ruta = urllib.parse.quote(partes.path or '/', safe=seguros)
    consulta = urllib.parse.quote(partes.query, safe=seguros + '?')
    return 'https://%s%s%s' % (host, ruta, '?' + consulta if consulta else ''), None


def _recorrer(cliente, dominio, nombre, sitios=None, saltos=None):
    """(host final, url final, visita, redirige_a) de la visita a https://<nombre>/ con sus redirecciones dentro del
    dominio. redirige_a es el nombre de otro dominio al que manda, o None. Un salto a otro sitio que ya se visitó (o
    ya quedó sin revisar) en `sitios` no se pide otra vez: da ese host con la visita {'ya_visitado': True}.
    Si el primer https se rechazó o no conectó (_sin_puerto), se pide http://<nombre>/ una vez (_http). Si da una
    página, esa es la visita. Si el 80 conectó y no terminó, o falló la red, no se sabe si tiene sitio: es una falla
    y el sitio queda sin revisar. Un 443 que conectó y no terminó es pasajero: falla, y el 80 no se prueba.
    Si se da la lista `saltos`, se le agregan los hosts intermedios de la cadena, sin `nombre` ni el host final
    (alcance1 de RC-56)."""
    url = 'https://%s/' % nombre
    for salto in range(MAX_REDIRECCIONES + 1):
        visita = cliente.sitio(url, contar=salto > 0)
        if salto == 0 and _sin_puerto(visita):
            plano = _http(cliente, nombre)
            if plano is not None and 'estado' in plano:
                return nombre, 'http://%s/' % nombre, plano, None
            if plano is not None and plano.get('sin_respuesta') in FALLAS_DE_RED and not _sin_puerto(plano):
                cliente.fallas += 1
                return nombre, 'http://%s/' % nombre, plano, None
        if salto == 0 and visita.get('sin_respuesta') in FALLAS_DE_RED:
            # La que sitio() no contó: un 443 que conectó y no terminó, o uno que no conectó y sin página en el 80.
            # Un 443 rechazado prueba que el nombre tiene quien conteste: con el 80 cerrado o sin conectar, no tiene
            # sitio. Uno que no conecta puede ser una máquina apagada, y eso no es revisarlo.
            cliente.fallas += 1
        if 'redirige' not in visita:
            return urllib.parse.urlsplit(url).hostname, url, visita, None
        if salto == MAX_REDIRECCIONES:
            return urllib.parse.urlsplit(url).hostname, url, {'sin_respuesta': 'redirecciones'}, None
        siguiente, motivo = _siguiente(visita['redirige'], dominio)
        if siguiente is None:
            host = urllib.parse.urlsplit(url).hostname
            if motivo:
                return host, url, {'sin_respuesta': motivo}, None
            otro = None
            try:
                otro = shodan._nombre(urllib.parse.urlsplit(visita['redirige']).hostname or '')
            except ValueError:
                pass
            return host, url, {'fuera': True}, otro
        if saltos is not None and salto > 0:
            saltos.append(urllib.parse.urlsplit(url).hostname)
        destino = urllib.parse.urlsplit(siguiente).hostname
        previo = (sitios or {}).get(destino)
        if destino != nombre and previo is not None and (previo.web is not None or previo.falta is not None):
            return destino, siguiente, {'ya_visitado': True}, None
        url = siguiente
    raise AssertionError('no se llega aquí')


def _sin_puerto(visita):
    """True si la visita no conectó: rechazo, o el plazo se acabó sin que ninguna IP aceptara la conexión."""
    return bool(visita.get('rechazada') or (visita.get('sin_respuesta') == 'tiempo' and visita.get('al_conectar')))


def _http(cliente, nombre):
    """La visita a http://<nombre>/ en el puerto 80, con TIMEOUT_HTTP, o None si no se pudo pedir: una grabación de
    antes que no trae esa petición (SinGrabacion) o la corrida ya no tenía tiempo (SinTiempo). En los dos casos queda
    lo que dio el 443, que ya se sabía. Su redirección no se sigue: un 80 que manda al 443 no tiene otra página. Su
    falla la cuenta _recorrer."""
    try:
        return cliente.sitio('http://%s/' % nombre, contar=False, timeout=TIMEOUT_HTTP)
    except (SinGrabacion, SinTiempo):
        return None


def _versiones(cabeceras):
    """[{cabecera, valor}] de las cabeceras Server y X-Powered-By que traen una versión, con el valor cortado."""
    vistas = []
    for nombre, valor in cabeceras or ():
        if nombre.lower() in CABECERAS_VERSION and _CON_VERSION.search(valor):
            par = {'cabecera': nombre, 'valor': valor.strip()[:MAX_VALOR_CABECERA]}
            if par not in vistas:
                vistas.append(par)
    return vistas


def _version_expuesta(sitio, dominio, ahora):
    """server_version_disclosed del sitio, uno por sitio con todas sus cabeceras. La huella no lleva el valor, así
    el hallazgo sigue siendo el mismo si la versión cambia."""
    codigo = 'server_version_disclosed'
    tipo = 'domain' if sitio.nombre == dominio else 'subdomain'
    cabeceras = ' y '.join(dict.fromkeys(c['cabecera'] for c in sitio.expuestas))
    evidencia = {'title': 'El sitio %s dice la versión de su servidor en %s' % (sitio.nombre, cabeceras),
                 'cabeceras': [dict(c) for c in sitio.expuestas], 'host': sitio.nombre, 'url': sitio.url}
    return Hallazgo(codigo, CODIGOS[codigo], sitio.nombre, evidencia['title'], evidencia,
                    rubrica.calcular(codigo, tipo, evidencia, ahora), _huella(codigo, dominio, sitio.nombre),
                    partes=[sitio.nombre])


def _saludo_fallido(sitio, dominio, ahora):
    """tls_certificate_invalid o tls_legacy_only del sitio, del mismo saludo de su visita (#121, RC-239). La evidencia
    dice el host, la URL y el motivo, sin copiar el certificado. La huella no lleva el motivo, así un certificado que
    pasa de vencido a autofirmado sigue siendo el mismo hallazgo."""
    tipo = 'domain' if sitio.nombre == dominio else 'subdomain'
    if 'certificado' in sitio.saludo:
        codigo, verify_code = 'tls_certificate_invalid', sitio.saludo['certificado']
        motivo = MOTIVOS_CERTIFICADO.get(verify_code, 'otro')
        evidencia = {'title': 'El sitio %s presenta %s' % (sitio.nombre, TEXTO_CERTIFICADO[motivo]),
                     'host': sitio.nombre, 'url': sitio.url, 'motivo': motivo, 'verify_code': verify_code}
        if motivo == 'emisor_desconocido':
            evidencia['nota'] = NOTA_CADENA
    else:
        codigo = 'tls_legacy_only'
        evidencia = {'title': 'El sitio %s no acepta TLS 1.2 ni 1.3' % sitio.nombre, 'host': sitio.nombre,
                     'url': sitio.url, 'minimo': MINIMO_TLS}
    return Hallazgo(codigo, CODIGOS[codigo], sitio.nombre, evidencia['title'], evidencia,
                    rubrica.calcular(codigo, tipo, evidencia, ahora), _huella(codigo, dominio, sitio.nombre),
                    partes=[PARTE_TLS + sitio.nombre])


def _de_portada(sitio, candidato, dominio, ahora):
    """directory_listing o debug_page_exposed del sitio, uno por código. La evidencia lleva la firma de portada.py que
    coincidió y el título de la página sin secretos, nunca el HTML. La huella no lleva la firma, así el hallazgo es el
    mismo si cambia el programa que lo muestra."""
    codigo = candidato['codigo']
    tipo = 'domain' if sitio.nombre == dominio else 'subdomain'
    if codigo == 'directory_listing':
        titulo = 'El sitio %s muestra la lista de sus archivos' % sitio.nombre
    else:
        titulo = 'El sitio %s muestra una página de depuración de %s' % (sitio.nombre, candidato['servidor'])
    evidencia = {'title': titulo, 'firma': candidato['firma'], 'servidor': candidato['servidor'],
                 'firmas_version': portada.VERSION, 'titulo_pagina': candidato['titulo_pagina'],
                 'cwe': portada.CWE[codigo], 'estado_http': sitio.web['estado_http'], 'host': sitio.nombre,
                 'url': sitio.url}
    return Hallazgo(codigo, CODIGOS[codigo], sitio.nombre, titulo, evidencia,
                    rubrica.calcular(codigo, tipo, evidencia, ahora), _huella(codigo, dominio, sitio.nombre),
                    partes=[sitio.nombre])


def _huella(codigo, dominio, activo, clave=''):
    """No lleva lo observado (la versión ni las señales), así el hallazgo no se duplica entre escaneos."""
    return hashlib.sha256('|'.join((FUENTE, codigo, dominio, activo, clave)).encode('utf-8')).hexdigest()


def _hallazgo(candidato, dominio, host, ahora, url):
    """El candidato de soporte.py o nvd.py como Hallazgo del sitio, con su sitio como parte (#23)."""
    tipo = 'domain' if host == dominio else 'subdomain'
    evidencia = dict(candidato['evidencia'], url=url)
    return Hallazgo(candidato['codigo'], candidato['severidad'], host, candidato['titulo'], evidencia,
                    rubrica.calcular(candidato['codigo'], tipo, evidencia, ahora),
                    _huella(candidato['codigo'], dominio, host, candidato['clave']), clave=candidato['clave'],
                    partes=[host])


def _cuantos(n, singular, plural):
    return '%d %s' % (n, singular if n == 1 else plural)


def _lista(nombres, maximo=5):
    return ', '.join(nombres[:maximo]) + (' y %d más' % (len(nombres) - maximo) if len(nombres) > maximo else '')


# ---------------------------------------------------------------- punto de entrada

def _sin_cobertura(res, aviso):
    res.avisos.append(aviso)
    res.sin_cobertura = list(CODIGOS)
    return res


def recolectar(dominio, cliente=None, ahora=None, propios=()):
    """Tecnologías, versiones sin soporte y CVE de los sitios del dominio. `propios` no se usa."""
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


class _Sitio:
    """Lo que la corrida sabe de un sitio: su A, su visita, su análisis y si quedó revisado."""

    def __init__(self, nombre):
        self.nombre = nombre
        self.a = None            # {estado, ips, cnames} de su A, si se pidió
        self.web = None          # lo que va en atributos['web']
        self.borde = False       # False: no se escribe. None o un dict: borde.detectar()
        self.tecnologias = None  # las de huellas.analizar(), si el análisis terminó completo
        self.url = None          # la URL de la página que se analizó
        self.expuestas = []      # las cabeceras Server y X-Powered-By con versión, si el análisis terminó completo
        self.portada = []        # lo que portada.revisar() vio en su página: listado de directorio o depuración
        self.falta = None        # el motivo de MOTIVOS si quedó sin revisar
        self.saludo = None       # {'certificado': verify_code} o {'tls_viejo': True} si el saludo TLS falló así
        self.tls_visto = False   # True si se sabe cómo quedó su saludo TLS: terminó, falló por el certificado o la
        #                          versión, o el 443 no lo dio (rechazado, la página del 80, otro dominio)

    def sin_revisar(self, motivo):
        if self.falta is None:
            self.falta = motivo


def _elegir(nombres, ahora, cliente):
    """Los MAX_SITIOS nombres que se visitan cuando hay más: la raíz y, de los demás, MAX_SITIOS - 1 seguidos desde uno
    que avanza un bloque completo cada día. Así en días distintos quedan fuera nombres distintos y lo de ninguno se
    queda para siempre sin revisar ni cerrar. Al reproducir no hay día que valga: van primero los que la grabación
    trae."""
    raiz, resto = nombres[0], list(nombres[1:])
    if cliente.modo == 'reproducir':
        resto.sort(key=lambda n: not cliente.grabadora.archivo('a:' + n).exists())
    else:
        giro = ahora.toordinal() * (MAX_SITIOS - 1) % len(resto)
        resto = resto[giro:] + resto[:giro]
    return [raiz] + resto[:MAX_SITIOS - 1]


def _ubicar(sitios):
    """{ip: asn} de las IP de los A, con las bases locales pedidas una sola vez y solo si alguna IP es ubicable, y
    el aviso de base faltante, o None."""
    ips = sorted({ip for s in sitios for ip in ((s.a or {}).get('ips') or ())})
    if not any(geoip.ubicable(ip) for ip in ips):
        return {}, None
    bases = geoip.bases_por_omision()
    return {ip: geoip.ubicar(ip, bases)['asn'] for ip in ips}, geoip.aviso_sin_base(FUENTE, bases)


def _revisar(res, cliente, dominio, ahora):
    parcial, todos_los_nombres = [], True

    # 1. Nombres de Cert Spotter, más la raíz
    try:
        certs, completos = certspotter.certificados(cliente, dominio, max_paginas=PAGINAS_CT, intentos=INTENTOS_CT,
                                                    timeout=TIMEOUT_CT)
        ct_respondio = True
        if not completos:
            res.avisos.append('web: Cert Spotter no dio todas sus páginas, pueden faltar sitios del dominio')
            parcial.append('paginas' if not cliente.fallas and not cliente.raras_ct else 'ct')
            todos_los_nombres = False
    except FuenteNoResponde as e:
        certs, ct_respondio, todos_los_nombres = [], False, False
        res.avisos.append('%s. Solo se visitó la raíz' % e)
        parcial.append('ct')
    nombres = shodan._nombres(dominio, certs)
    comodin = any(n.strip().startswith('*.') for c in certs for n in (c.get('name_value') or '').split('\n'))
    if len(nombres) > MAX_SITIOS:
        res.avisos.append('web: se visitaron %d de %d nombres del dominio (MAX_SITIOS)' % (MAX_SITIOS, len(nombres)))
        nombres = _elegir(nombres, ahora, cliente)
        parcial.append('sitios')
        todos_los_nombres = False

    # 2. El A y la visita de cada nombre, sin tocar RESERVA_APIS
    sitios = {}          # host -> _Sitio, de los nombres y de los destinos de sus redirecciones
    fallas_dns, sin_tiempo = 0, []
    cliente.reserva = RESERVA_APIS
    try:
        for i, nombre in enumerate(nombres):
            sitio = sitios.setdefault(nombre, _Sitio(nombre))
            if sitio.web is not None:   # ya llegó como destino de otra redirección
                continue
            if cliente.restante() < MIN_RESTANTE:
                sin_tiempo = nombres[i:]
                break
            try:
                sitio.a = cliente.resolver_a(nombre)
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
            if sitio.a['estado'] != 'ok':
                sitio.web = {'estado': 'sin_a'}
                continue
            if not any(transporte.publica(ip) for ip in sitio.a['ips']):
                sitio.web = {'estado': 'no_publica'}
                continue
            try:
                host, url, visita, otro = _recorrer(cliente, dominio, nombre, sitios)
            except SinTiempo:
                sin_tiempo = nombres[i:]
                break
            except SinGrabacion:
                sitio.sin_revisar('grabacion')
                continue
            except FuenteNoResponde as e:   # una grabación que no se puede leer
                res.avisos.append(str(e))
                sitio.sin_revisar('grabacion')
                parcial.append('ilegible')
                continue
            _registrar(res, sitios, sitio, host, url, visita, otro, dominio)
    finally:
        cliente.reserva = 0
    sin_tiempo = [n for n in sin_tiempo if n not in sitios or (sitios[n].web is None and sitios[n].falta is None)]
    for nombre in sin_tiempo:   # un destino ya visitado por otra redirección no pierde lo que se vio
        sitios.setdefault(nombre, _Sitio(nombre)).sin_revisar('sin_tiempo')
    if sin_tiempo:
        res.avisos.append('web: se acabó el tiempo de la corrida antes de visitar %s'
                          % _cuantos(len(sin_tiempo), 'sitio', 'sitios'))
        parcial.append('tiempo')
    if not ct_respondio and fallas_dns == len(nombres):
        raise FuenteNoResponde('web: no respondieron Cert Spotter ni el DNS de %s' % dominio)
    if fallas_dns:
        res.avisos.append('web: el DNS no respondió al A de %s' % _cuantos(fallas_dns, 'nombre', 'nombres'))
        parcial.append('a')

    # 3. El borde de cada sitio visitado, con sus CNAME, sus IP, sus ASN y las cabeceras de su página
    asns, aviso_geo = _ubicar(sitios.values())
    if aviso_geo:
        res.avisos.append(aviso_geo)
    for sitio in sitios.values():
        if sitio.borde is False:
            continue
        a = sitio.a or {}
        cabeceras = sitio.borde if isinstance(sitio.borde, list) else None
        try:
            sitio.borde = borde.detectar(a.get('cnames') or (), a.get('ips') or (),
                                         [asns[ip] for ip in a.get('ips') or () if ip in asns], cabeceras)
        except Exception:   # un dato raro de un sitio no tumba la corrida: ese sitio queda sin revisar
            sitio.borde = False
            sitio.sin_revisar('borde')

    # 4. endoflife.date y la NVD de lo que soporte.py y nvd.py pueden revisar, y la versión en las cabeceras
    _soporte_y_cve(res, cliente, sitios, dominio, ahora, parcial)
    for host in sorted(sitios):
        if sitios[host].expuestas and sitios[host].tecnologias is not None:
            res.hallazgos.append(_version_expuesta(sitios[host], dominio, ahora))
        if sitios[host].saludo:
            res.hallazgos.append(_saludo_fallido(sitios[host], dominio, ahora))
        # Lo de la portada va aunque el sitio quede sin revisar (un 5xx con la página de depuración): se vio en la
        # página que llegó. Un sitio sin revisar no cierra lo que ya estaba abierto (paso 6).
        for candidato in sitios[host].portada:
            res.hallazgos.append(_de_portada(sitios[host], candidato, dominio, ahora))

    # 5. Activos
    for host in sorted(sitios, key=lambda h: (h != dominio, h)):
        sitio = sitios[host]
        if sitio.web is None and sitio.falta is None:
            continue
        atributos = {'web': dict(sitio.web or {}, fuente=FUENTE)}
        if sitio.falta:
            atributos['web']['sin_revisar'] = MOTIVOS[sitio.falta]
        if sitio.borde is not False:
            atributos['borde'] = sitio.borde
        if sitio.tecnologias is not None and sitio.falta is None:
            atributos['tecnologias'] = [{'nombre': t['nombre'], 'version': t['version'],
                                         'categorias': list(t['categorias'])} for t in sitio.tecnologias]
        res.activos.append(Activo('domain' if host == dominio else 'subdomain', host, atributos))

    # 6. Cobertura
    faltan = [h for h, s in sitios.items() if s.falta]
    hechos = [h for h, s in sitios.items() if not s.falta]
    if faltan:
        por_motivo = {}
        for h in faltan:
            por_motivo.setdefault(sitios[h].falta, []).append(h)
        for motivo, hosts in sorted(por_motivo.items()):
            if motivo not in ('reto', 'sin_tiempo'):   # el reto ya tiene su aviso, y el tiempo también
                res.avisos.append('web: %s sin revisar: %s (%s)'
                                  % (_cuantos(len(hosts), 'sitio', 'sitios'), MOTIVOS[motivo], _lista(sorted(hosts))))
    # Un nombre que solo se conoce por la redirección de otro sitio (www bajo un comodín) no está en ninguna de las dos
    # listas si ese sitio no llegó a responder: con sin_revisar el orquestador cerraría lo suyo sin visitarlo. En ese
    # caso, y solo si hay un comodín, no se pasa la lista de los que faltan y solo se cierra lo de los revisados.
    oculto = comodin and any(sitios[h].falta in OPACOS for h in faltan)
    lista = faltan if todos_los_nombres and not oculto else None
    revisados, sin_revisar, sin_cobertura = borde.cobertura(hechos, lista, list(CODIGOS))
    if sin_cobertura and res.hallazgos:
        # Ningún sitio quedó revisado completo, pero alguno dio hallazgos antes de que le faltara otra consulta: se
        # reportan y la corrida queda parcial, sin cerrar nada de lo que no se revisó.
        revisados, sin_revisar, sin_cobertura = [], (sorted(faltan) if lista is not None else None), []
    revisados, sin_revisar, sin_cobertura = _cobertura_tls(sitios, faltan, revisados, sin_revisar, sin_cobertura,
                                                           lista is not None)
    res.revisados, res.sin_revisar, res.sin_cobertura = revisados, sin_revisar, sin_cobertura
    if revisados is not None or sin_cobertura:
        res.avisos.append('%s, se revisaron %d de %d sitios' % (PARCIAL, len(hechos), len(sitios)))
    if cliente.modo == 'grabar' and cliente.degradada(parcial):
        res.avisos.insert(0, NO_SE_GRABO)
    else:
        cliente.terminar()
    return res


def _cobertura_tls(sitios, faltan, revisados, sin_revisar, sin_cobertura, con_lista):
    """La cobertura con las partes 'tls:<sitio>' de las dos reglas del saludo (RC-239). Si la corrida revisó todo, no
    cambia. Si no, van en revisados las de los sitios cuyo saludo se vio (tls_visto) o que quedaron revisados, y en
    sin_revisar, si la corrida sabe cuáles faltan, las de los que no. Si ningún sitio quedó revisado completo pero
    alguno dio su saludo, las dos reglas dejan de ir sin cobertura y solo se cierra lo de esos saludos: sin_revisar va
    en None, así nada de lo demás se cierra en una corrida que lo declara sin cobertura."""
    if revisados is None and not sin_cobertura:
        return revisados, sin_revisar, sin_cobertura
    vistos = sorted(PARTE_TLS + h for h, s in sitios.items() if s.tls_visto or not s.falta)
    if revisados is None:   # ningún sitio revisado completo y ningún hallazgo
        if not vistos:
            return revisados, sin_revisar, sin_cobertura
        revisados, sin_revisar = [], None
        sin_cobertura = [c for c in sin_cobertura if c not in CODIGOS_TLS]
    revisados = list(revisados) + vistos
    if sin_revisar is not None:
        sin_revisar = list(sin_revisar) + sorted(PARTE_TLS + h for h in faltan if not sitios[h].tls_visto)
    return revisados, sin_revisar, sin_cobertura


def _registrar(res, sitios, sitio, host, url, visita, otro, dominio):
    """Lo que dejó la visita de `sitio`, que terminó en `host` (él mismo o el destino de sus redirecciones)."""
    if host != sitio.nombre:   # redirigió dentro del dominio: lo que se vio es de `host`
        sitio.web = {'estado': 'redirige', 'redirige_a': host}
        sitio.borde = []       # el borde se calcula sin cabeceras, solo con su A
        sitio.tls_visto = True   # su saludo terminó: contestó con la redirección
        destino = sitios.setdefault(host, _Sitio(host))
        if destino.web is not None or destino.falta is not None:   # ya se visitó por su cuenta o por otro nombre
            return
        sitio = destino
    if visita.get('fuera'):
        sitio.web = {'estado': 'redirige', 'redirige_a_otro_dominio': otro}
        sitio.borde = []
        sitio.tls_visto = True
        return
    if visita.get('rechazada'):
        sitio.web = {'estado': 'sin_https'}
        sitio.tls_visto = True
        return
    if 'sin_respuesta' in visita:
        sitio.web = {'estado': 'sin_respuesta'}
        sitio.sin_revisar(visita['sin_respuesta'])
        if visita['sin_respuesta'] == 'certificado':
            sitio.saludo, sitio.url = {'certificado': visita.get('verify_code')}, _sin_consulta(url)
        elif visita['sin_respuesta'] == 'tls_viejo':
            sitio.saludo, sitio.url = {'tls_viejo': True}, _sin_consulta(url)
        sitio.tls_visto = sitio.saludo is not None
        return
    sitio.tls_visto = True   # dio una página: por HTTPS el saludo terminó, y por HTTP el 443 no la dio
    sitio.web = {'estado': 'visitado', 'url': _sin_consulta(url), 'estado_http': visita['estado']}
    if url.startswith('http://'):
        sitio.web['protocolo'] = 'http'   # el 443 no dio la página: se vio la del 80
    elif visita.get('tls'):
        sitio.web['tls'] = dict(visita['tls'])   # dato del activo, no hallazgo ni score (RC-239)
    sitio.borde = visita['cabeceras']   # borde.detectar() las usa en el paso 3
    sitio.url = _sin_consulta(url)
    try:
        analisis = huellas.analizar(visita['estado'], visita['cabeceras'], visita['cuerpo'], url=url)
    except Exception:   # una página rara no tumba la corrida: ese sitio queda sin revisar
        sitio.sin_revisar('huellas')
        return
    if analisis['reto']:
        res.avisos.append(borde.aviso(FUENTE, sitio.nombre, analisis['reto']))
        sitio.sin_revisar('reto')
        return
    try:   # antes del 5xx: la página de depuración suele llegar con un 500
        sitio.portada = portada.revisar(visita['estado'], visita['cuerpo'])
    except Exception:   # una página rara no tumba la corrida: ese sitio queda sin revisar
        sitio.sin_revisar('portada')
        return
    if _error_servidor(visita):   # la página de error no muestra lo que hay detrás
        sitio.sin_revisar('error_http')
        return
    if not analisis['completo']:
        sitio.sin_revisar('huellas')
        return
    sitio.tecnologias = analisis['tecnologias'] or []
    sitio.expuestas = _versiones(visita['cabeceras'])


def _soporte_y_cve(res, cliente, sitios, dominio, ahora, parcial):
    """outdated_software y known_vulnerability de las tecnologías de los sitios analizados completos."""
    con_tecnologias = [s for s in sitios.values() if s.tecnologias and not s.falta]
    productos, cpes = [], []
    for sitio in con_tecnologias:
        for t in sitio.tecnologias:
            if soporte.revisar(t, None, sitio.nombre, ahora)['estado'] == 'sin_dato':
                producto = soporte.PRODUCTOS[t['nombre']]
                if producto not in productos:
                    productos.append(producto)
            previa = nvd.revisar(t, None, sitio.nombre)
            if previa['estado'] == 'sin_dato' and previa['cpe'] not in cpes:
                cpes.append(previa['cpe'])
    for lista, tope, motivo, que in ((productos, MAX_PRODUCTOS, 'productos', 'productos en endoflife.date'),
                                     (cpes, MAX_CPE, 'cpe', 'CPE en la NVD')):
        if len(lista) > tope:
            res.avisos.append('web: se consultaron %d de %d %s (MAX_%s)' % (tope, len(lista), que,
                                                                           'PRODUCTOS' if motivo == 'productos' else 'CPE'))
            parcial.append(motivo)

    eol = _consultar_api(res, cliente, productos[:MAX_PRODUCTOS], parcial, PAUSA_EOL, 'endoflife.date',
                         lambda p: ('eol:' + p, soporte.url(p), None, False))
    respuestas_nvd = _consultar_api(res, cliente, cpes[:MAX_CPE], parcial, PAUSA_NVD, 'la NVD',
                                    lambda c: ('nvd:' + hashlib.sha256(c.encode('utf-8')).hexdigest()[:16] + ':'
                                               + c.split(':')[4], nvd.url(c), _reducir_nvd, True))

    cves = {}
    for sitio in con_tecnologias:
        candidatos, omitidas = [], []
        for t in sitio.tecnologias:
            producto = soporte.PRODUCTOS.get(t['nombre'])
            if soporte.revisar(t, None, sitio.nombre, ahora)['estado'] == 'sin_dato':
                if producto not in eol:
                    sitio.sin_revisar('tope' if producto not in productos[:MAX_PRODUCTOS] else 'eol')
                else:
                    revision = soporte.revisar(t, eol[producto], sitio.nombre, ahora)
                    # Respondió algo que no se lee (otra forma, un ciclo sin fin legible): sin revisar. Un 404 (no
                    # tiene el producto) o una respuesta legible sin ciclo para esta versión ('Apache/2') no: ahí no
                    # puede haber outdated_software y el sitio queda revisado.
                    if revision['estado'] == 'sin_dato' and eol[producto] is not None \
                            and (not soporte.ciclos(eol[producto]) or revision['ciclo'] is not None):
                        sitio.sin_revisar('eol')
                    if revision['hallazgo']:
                        candidatos.append(revision['hallazgo'])
            previa = nvd.revisar(t, None, sitio.nombre)
            if previa['estado'] == 'sin_dato':
                cpe = previa['cpe']
                if cpe not in respuestas_nvd:
                    sitio.sin_revisar('tope' if cpe not in cpes[:MAX_CPE] else 'nvd_falta')
                    continue
                revision = nvd.revisar(t, respuestas_nvd[cpe], sitio.nombre)
                if revision['estado'] == 'sin_dato' or not revision['completa']:
                    sitio.sin_revisar('nvd_falta')
                candidatos += revision['hallazgos']
                omitidas += [nvd.clave(c, cpe) for c in revision['omitidas']]
                for fila in revision['cves']:
                    cves.setdefault(fila['cve_id'], fila)
        claves = set()
        for candidato in candidatos:
            if (candidato['codigo'], candidato['clave']) in claves:
                continue
            claves.add((candidato['codigo'], candidato['clave']))
            res.hallazgos.append(_hallazgo(candidato, dominio, sitio.nombre, ahora, sitio.url))
        omitidos = [_huella('known_vulnerability', dominio, sitio.nombre, c) for c in dict.fromkeys(omitidas)
                    if ('known_vulnerability', c) not in claves]
        res.omitidos += [h for h in omitidos if h not in res.omitidos]
        if omitidas:
            res.avisos.append('web: %s trae más de %d CVE por tecnología, se omitieron %d'
                              % (sitio.nombre, nvd.MAX_CVE, len(omitidas)))
    res.cves = [cves[c] for c in sorted(cves)]


def _consultar_api(res, cliente, lista, parcial, pausa, nombre, armar):
    """{elemento: respuesta} de las consultas que llegaron, en orden y con `pausa` segundos entre una y otra. Un 429
    (o el 403 de la NVD) o el fin del tiempo cortan las que faltan."""
    respuestas, fallas, cortadas = {}, [], 0
    for i, elemento in enumerate(lista):
        consulta, url, reducir, limite_403 = armar(elemento)
        if url is None:
            continue
        if cliente.restante() < MIN_RESTANTE + (pausa if i else 0):
            cortadas = len(lista) - i
            break
        try:
            # La NVD (limite_403) no lleva pausa fija: cada intento espera su turno del ritmo de todo el proceso
            respuestas[elemento] = cliente.api(consulta, url, '%s (%s)' % (nombre, elemento),
                                               pausa=pausa if i and not limite_403 else 0, reducir=reducir,
                                               limite_403=limite_403, ritmo=limite_403)
        except LimiteAlcanzado as e:
            res.avisos.append('%s. No se consultaron %d más' % (e, len(lista) - i - 1))
            parcial.append('limite')
            break
        except SinTiempo:
            cortadas = len(lista) - i
            break
        except SinGrabacion:
            fallas.append(elemento)
            parcial.append('grabacion')
        except FuenteNoResponde as e:
            fallas.append(elemento)
            parcial.append('red')
            resto = len(lista) - i - 1
            if isinstance(e, RespuestaIlegible) or not resto:   # solo esa consulta
                res.avisos.append(str(e))
                continue
            res.avisos.append('%s. No se consultaron %d más' % (e, resto))   # caída: no se gasta el tiempo
            break
    if cortadas:
        res.avisos.append('web: se acabó el tiempo de la corrida antes de consultar %d en %s' % (cortadas, nombre))
        parcial.append('tiempo')
    return respuestas


# ---------------------------------------------------------------- línea de comandos

def resumen(res):
    lineas = ['%s · %s · %s · %d consultas' % (res.dominio, res.fuente, res.estado, res.consultas)]
    if res.error:
        lineas.append('error: ' + res.error)
    for a in res.activos:
        tecnologias = ', '.join('%s %s' % (t['nombre'], t['version'] or '') for t in a.atributos.get('tecnologias') or ())
        lineas.append('  %s %s: %s%s' % (a.tipo, a.valor, a.atributos['web'].get('estado'),
                                         ' · ' + tecnologias if tecnologias else ''))
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


def _main(argv=None):
    p = argparse.ArgumentParser(description='Visita web de la actividad 6 (sin --reproducir consulta en vivo)')
    p.add_argument('dominio')
    modo = p.add_mutually_exclusive_group()
    modo.add_argument('--grabar', action='store_true', help='consulta en vivo y graba las respuestas')
    modo.add_argument('--reproducir', action='store_true', help='usa solo lo grabado, sin red')
    args = p.parse_args(argv)
    dominio = args.dominio.strip().lower().rstrip('.')
    elegido = 'grabar' if args.grabar else 'reproducir' if args.reproducir else 'vivo'
    if elegido != 'reproducir' and not shodan._en_vivo_permitido(dominio):
        print('%s no está en DOMINIOS_EN_VIVO: solo se puede --reproducir' % dominio, file=sys.stderr)
        return 1
    res = contrato.ejecutar(sys.modules[__name__], dominio, elegido)
    print(resumen(res))
    return codigo_salida(res)


if __name__ == '__main__':
    sys.exit(_main())
