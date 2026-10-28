"""Registrador, fechas y vencimiento del dominio con RDAP, y WHOIS por el puerto 43 como respaldo (#15b, RC-166).

RDAP (RFC 9083) reemplaza a WHOIS: JSON por HTTPS, sin llave. Desde el 28 ene 2025 los gTLD ya no están obligados a
ofrecer WHOIS por el puerto 43, así que RDAP va primero. El servidor de cada TLD sale del bootstrap de IANA
(URL_BOOTSTRAP, RFC 9224): se busca el sufijo más largo del dominio que tenga servicio (para empresa.com.mx, primero
com.mx y después mx) y se usa su primera URL https. Después se pide <servidor>domain/<dominio>. Son dos consultas por
corrida, a IANA y al registro del TLD, y ninguna toca un servidor del dominio (carta, Anexo A, actividad 3).

Respaldo. WHOIS por el puerto 43 (RFC 3912) entra solo si el bootstrap no tiene un servidor RDAP https para el TLD (el
caso principal: .mx y .com.mx, que NIC México no ofrece por RDAP) o si RDAP no respondió, en el bootstrap o en el
registro, en vivo o al grabar. No entra con el 404 de RDAP ni cuando RDAP responde sin vencimiento o con una fecha rota:
es el mismo registro y diría lo mismo. Se pregunta a whois.iana.org por el TLD (la última etiqueta, 'mx') y se toma su
línea 'whois:', sin tabla fija de servidores. Si viene vacía, el TLD no tiene WHOIS. Después se pide el dominio a ese
servidor, el del registro del TLD (en Verisign con 'domain ' delante, PREFIJOS). Nunca se sigue 'Registrar WHOIS
Server' ni otra referencia a un registrador: su WHOIS sí trae al registrante. De la respuesta solo se leen las llaves
de CAMPOS_WHOIS (reducir_whois). Contactos, correos, teléfonos y direcciones no se leen ni se graban.

Devuelve un activo domain con:
- registrador (el 'fn' de la entidad con rol registrar, o 'Registrar' de WHOIS) y registrador_iana (su IANA Registrar ID),
- registrado, vence y ultimo_cambio (los eventos registration, expiration y last changed, en UTC),
- estado_registro (los status de RDAP, o los de EPP de WHOIS en la forma de RDAP), servidores_nombre (los NS que publica
  el registro) y dnssec,
- servidor_rdap y fuente_datos 'RDAP' cuando el registro respondió por RDAP con el dominio, o servidor_whois y
  fuente_datos 'WHOIS' cuando respondió por el puerto 43.
De las demás entidades (registrante, contactos administrativo y técnico, abuso) no se lee ni se graba nada: pueden ser
datos personales. Una entidad registrar que también tiene un rol de contacto (ROLES_DE_CONTACTO) tampoco cuenta. Un dato
que el registro no da sale 'No disponible' (NO_DISPONIBLE), no vacío. Si ni RDAP ni WHOIS responden, todos salen así.

domain_expiring_soon (media) sale sobre el activo domain si el vencimiento cae a menos de DIAS_POR_VENCER días de
`ahora`, como dice el texto de la regla (migración 003). Si la fecha ya pasó y el registro sigue publicado no sale,
porque la regla habla de lo que vence en los siguientes 30 días: queda un aviso con la fecha (_aviso_vencido). Un
vencimiento anterior o igual al registro, o de hace más de MAX_DIAS_VENCIDO días, es imposible y cuenta como fecha rota.

Cobertura. Si no se sabe el vencimiento (ni RDAP ni WHOIS respondieron, el TLD no tiene RDAP ni WHOIS, el registro no
conoce el dominio o no publica la fecha, o la publica rota o imposible), domain_expiring_soon va a sin_cobertura con un
aviso y el activo sale con 'No disponible'. La fuente queda succeeded y no failed, como pide RC-166: el escaneo termina
'partial' y no se lee como 0 hallazgos, pero el orquestador no la reintenta. La geolocalización y el ASN de las IP
(DB-IP Lite) no son de esta fuente: van en los activos ip de dns y shodan.
Reintentos: INTENTOS por consulta RDAP (esperas de 5 y 15 s) e INTENTOS_WHOIS por consulta WHOIS (ESPERAS_WHOIS),
nunca esperas más largas que lo que le queda a la corrida. Cada petición HTTP tiene un plazo absoluto,
min(TIMEOUT_HTTP, lo que queda), que cubre toda la lectura del cuerpo (_descargar, como shodan.py), sin cubrir
getaddrinfo. Un 429 o un 4xx, salvo el 408, no se reintentan. Una redirección que sale de https se corta (_SoloHttps).
Cada conversación por el puerto 43 tiene un plazo absoluto, min(TIMEOUT_WHOIS, lo que queda), que a diferencia de
_descargar sí cubre getaddrinfo (en un hilo aparte), el connect de cada dirección, el envío y cada recv (_conversar).
Mientras corre RDAP, restante() guarda RESERVA_WHOIS segundos de TIEMPO_CORRIDA para el respaldo.

Modos: 'vivo' consulta. 'grabar' además guarda en cirdan/recolectores/respuestas_grabadas/whois/<dominio>/ el bootstrap
reducido al servicio del dominio y la respuesta RDAP reducida a lo que se lee (reducir_rdap: sin contactos, solo con
los valores que pasan los filtros de leer_rdap y con un evento por acción), con la forma de RDAP. Si hubo respaldo,
guarda el servidor WHOIS que dio IANA (whois-iana:<tld>) y la respuesta WHOIS ya reducida (whois:<dominio>, de
reducir_whois), nunca el texto crudo. Todo va al final y solo si la corrida no tuvo ninguna falla: si RDAP falló y
WHOIS respondió, el resultado sale completo pero no se graba. El 404 del registro, un TLD sin servidor RDAP (con su
WHOIS, como .mx, o sin él) sí se graban: otra corrida daría lo mismo. Cualquier falla, o algo que no se pueda guardar
en UTF-8, deja intacta la grabación anterior, con el aviso NO_SE_GRABO al principio de los avisos. 'reproducir' solo
lee esa grabación y vuelve a pasarla por leer_rdap o leer_whois. Sin grabación del dominio, reproducir da el activo
con 'No disponible', domain_expiring_soon en sin_cobertura y un aviso, no failed. Una grabación de un TLD sin RDAP
hecha antes del respaldo (sin whois-iana) da lo mismo que entonces: 'No disponible' con su aviso.

    python -m cirdan.recolectores.rdap olmardo.com --reproducir
    python -m cirdan.recolectores.rdap olmardo.com --grabar
    python -m cirdan.recolectores.rdap olmardo.com --json

Como shodan.py, la línea de comandos rechaza vivo y --grabar si el dominio no está en DOMINIOS_EN_VIVO.
Código de salida: 0 si la corrida fue completa, 1 si queda en 'failed', 2 si la cobertura quedó parcial y 3 si
--grabar no escribió por una falla (NO_SE_GRABO): la grabación anterior sigue igual y hay que repetir --grabar más tarde.
"""
import argparse
import contextlib
import hashlib
import ipaddress
import json
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from cirdan.config import config
from cirdan.ml import caracteristicas as rubrica
from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import (NOMBRE_VALIDO, Activo, FuenteNoResponde, Grabadora, Hallazgo, Resultado,
                                          SinGrabacion, con_reintentos)

FUENTE = 'whois'             # data_sources.code de la semilla 001: RDAP es el WHOIS de hoy
CARPETA_GRABADAS = RAIZ_GRABADAS / 'whois'

# Código de regla -> severidad base. Existe en el catálogo de reglas (semilla 004).
CODIGOS = {'domain_expiring_soon': 'medium'}

URL_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json'
NOMBRE_RDAP = 'RDAP'         # atribución: va en los atributos y la evidencia
NOMBRE_WHOIS = 'WHOIS'       # atribución cuando el registro salió del puerto 43
IANA_WHOIS = 'whois.iana.org'   # da el servidor WHOIS de cada TLD (línea 'whois:'), sin tabla fija
PUERTO_WHOIS = 43
AGENTE = 'cirdan-osint/0.1 (+https://github.com/Kernel-Loco)'   # el mismo de crtsh.py
NO_DISPONIBLE = 'No disponible'

DIAS_POR_VENCER = 30         # vence en menos de esto = hallazgo (texto de la regla, migración 003)
MAX_DIAS_VENCIDO = 365       # un vencimiento de hace más de esto, o anterior al registro, es imposible: fecha rota
INTENTOS = 3                 # intentos por consulta dentro de una corrida (no es scan_source_runs.attempt)
ESPERAS = (5, 15)            # segundos entre intentos
TIMEOUT_HTTP = 15            # segundos por petición
TIEMPO_CORRIDA = 120         # segundos de toda la corrida: ninguna consulta empieza después
MAX_BYTES = 1024 * 1024      # tope de una respuesta HTTP. El bootstrap completo pesa unas decenas de KB
INTENTOS_WHOIS = 2           # intentos por consulta al puerto 43
ESPERAS_WHOIS = (5,)         # segundos entre intentos
TIMEOUT_WHOIS = 10           # segundos por conversación, de getaddrinfo al último recv
RESERVA_WHOIS = 30           # segundos de TIEMPO_CORRIDA que RDAP deja para el respaldo
MAX_BYTES_WHOIS = 64 * 1024  # tope de una respuesta WHOIS. La de whois.mx, con sus avisos, pesa unos 4 KB
MAX_DIRECCIONES = 2          # direcciones del servidor WHOIS que se prueban
# Prefijos NAT64 (RFC 6052 y RFC 8215): llevan una IPv4 en los últimos 32 bits, que también tiene que ser pública.
NAT64 = (ipaddress.ip_network('64:ff9b::/96'), ipaddress.ip_network('64:ff9b:1::/48'))
# Peor caso de una corrida para el límite diario (#13b): el bootstrap y el dominio por RDAP, y whois.iana.org y el
# servidor del TLD por el puerto 43, cada uno con sus intentos: 10. No hay semilla nueva: el daily_limit de 60 de la
# semilla 008 alcanza para 6 corridas en el peor caso. Una corrida normal gasta 2 (3 en .mx) y el orquestador ajusta
# la reserva a lo gastado.
MAX_CONSULTAS = 2 * INTENTOS + 2 * INTENTOS_WHOIS

# Lo que se guarda de una respuesta RDAP. Los topes cortan una respuesta rara, no una normal.
EVENTOS = {'registration': 'registrado', 'expiration': 'vence', 'last changed': 'ultimo_cambio'}
MAX_ESTADOS = 20
MAX_NS = 13
MAX_TEXTO = 200              # caracteres del nombre del registrador
ESTADO_VALIDO = re.compile(r'[a-z][a-z ]{0,59}')       # 'client transfer prohibited', 'active'
IANA_ID_VALIDO = re.compile(r'[0-9]{1,10}')
MAX_URL = 300
# Host de un servidor RDAP: como NOMBRE_VALIDO, pero el TLD también puede ser un IDN (xn--). Una IP no pasa.
HOST_VALIDO = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$')
# Roles de RDAP que pueden ser una persona: una entidad registrar que también tiene uno no se toma como registrador.
ROLES_DE_CONTACTO = {'registrant', 'administrative', 'technical', 'billing'}

# Lo que se lee de una respuesta WHOIS: llave (en minúsculas, antes del primer ':') -> campo. Una llave que no está
# aquí no se lee nunca: contactos, correos, teléfonos, direcciones, 'Registrar WHOIS Server', 'Registrar URL'.
CAMPOS_WHOIS = {'domain name': 'dominio', 'registrar': 'registrador', 'registrar iana id': 'registrador_iana',
                'creation date': 'registrado', 'created on': 'registrado',              # Verisign y whois.mx
                'registry expiry date': 'vence', 'expiration date': 'vence',
                'updated date': 'ultimo_cambio', 'last updated on': 'ultimo_cambio',
                'domain status': 'estado_registro', 'name server': 'servidores_nombre', 'dns': 'servidores_nombre',
                'dnssec': 'dnssec'}
DNSSEC_WHOIS = {'unsigned': False, 'signeddelegation': True, 'signed': True}
SOLO_FECHA = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')   # 'Expiration Date' de whois.mx: sin hora
# Textos con los que un registro dice que no conoce el dominio (Verisign, whois.mx y otros), solo sin 'Domain Name'.
NO_EXISTE_WHOIS = ('no match for', 'no_se_encontro_el_objeto', 'object_not_found', 'not found', 'no data found',
                   'no entries found')
PREFIJOS = {'whois.verisign-grs.com': 'domain '}   # sin 'domain', Verisign busca en todos los tipos de registro

# Avisos con texto fijo.
SIN_GRABACION_DOMINIO = 'whois: no hay grabación de RDAP de este dominio, no se revisó el registro'
SIN_RESPUESTA = 'whois: ni RDAP ni WHOIS por el puerto 43 dieron el registro del dominio, queda como No disponible'
NO_ENCONTRADO = 'whois: el registro del TLD no conoce este dominio (404 de RDAP)'
SIN_RDAP_TLD = 'el bootstrap de IANA no tiene un servidor RDAP https para el TLD'
CON_WHOIS = 'whois: el registro se pidió a WHOIS por el puerto 43 (%s) porque %s'          # servidor y razón
SIN_WHOIS = 'whois: IANA no publica un servidor WHOIS para el TLD de %s y %s, el registro queda como No disponible'
NO_ENCONTRADO_WHOIS = 'whois: el servidor WHOIS del TLD no conoce este dominio'
# Con %s el nombre de lo que respondió, NOMBRE_RDAP o NOMBRE_WHOIS.
SIN_VENCIMIENTO = 'whois: %s no publica la fecha de vencimiento de este dominio'
VENCIMIENTO_ROTO = 'whois: %s dio una fecha de vencimiento que no se puede leer'
VENCIMIENTO_IMPOSIBLE = ('whois: %s dio una fecha de vencimiento imposible (anterior o igual al registro, o de hace '
                         'más de un año) y se ignoró')
NO_SE_GRABO = ('whois: la corrida tuvo fallas (un 429, la red, el tope de tiempo o una respuesta que no se puede leer o '
               'guardar), no se grabó y se conserva la grabación anterior')


class LimiteAlcanzado(FuenteNoResponde):
    """La fuente respondió 429: llegó a su límite. No se reintenta en la corrida."""


class SinTiempo(FuenteNoResponde):
    """Se acabó TIEMPO_CORRIDA antes de la consulta, o el plazo de una petición o una conversación."""


class RespuestaIlegible(FuenteNoResponde):
    """La fuente respondió algo que no se puede leer, un 4xx, una redirección fuera de https o un servidor WHOIS sin
    IP pública."""


_NO_ENCONTRADO = object()    # el 404, dentro de _http
BLOQUE = 64 * 1024           # bytes que _descargar lee de una vez


# ---------------------------------------------------------------- consultas a la red

class _SoloHttps(urllib.request.HTTPRedirectHandler):
    """Sigue una redirección solo si se queda en https."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() != 'https':
            with contextlib.suppress(Exception):
                fp.close()
            raise RespuestaIlegible('whois: %s redirigió fuera de https' % urllib.parse.urlsplit(req.full_url).netloc)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_ABRIR = urllib.request.build_opener(_SoloHttps).open


def _descargar(url, timeout, cronometro=None):
    """El cuerpo de la respuesta, de a lo más MAX_BYTES. La única función que hace HTTP.

    `timeout` es el plazo absoluto de toda la petición: se lee por bloques y, si se pasa del plazo, lanza SinTiempo
    (como shodan._descargar). No cubre getaddrinfo. `cronometro` es time.monotonic por omisión."""
    cronometro = cronometro or time.monotonic
    plazo = cronometro() + timeout
    req = urllib.request.Request(url, headers={'User-Agent': AGENTE,
                                               'Accept': 'application/rdap+json, application/json'})
    partes, total = [], 0
    with _ABRIR(req, timeout=timeout) as r:
        leer = r.read1 if hasattr(r, 'read1') else r.read
        while True:
            if cronometro() > plazo:
                raise SinTiempo('whois: la respuesta tardó más de %s s' % timeout)
            parte = leer(min(BLOQUE, MAX_BYTES + 1 - total))
            if not parte:
                break
            partes.append(parte)
            total += len(parte)
            if total > MAX_BYTES:
                raise ValueError('respuesta de más de %d bytes' % MAX_BYTES)
    return b''.join(partes)


def _resolver(host, espera):
    """getaddrinfo de `host` en el puerto 43 dentro de `espera` segundos. getaddrinfo no tiene plazo: corre en un hilo
    daemon y se espera con join(espera). Si no terminó, lanza SinTiempo y el hilo sigue solo: la corrida no lo espera."""
    salida = {}

    def resolver():
        try:
            salida['direcciones'] = socket.getaddrinfo(host, PUERTO_WHOIS, type=socket.SOCK_STREAM)
        except OSError as e:
            salida['error'] = e
    hilo = threading.Thread(target=resolver, name='whois-getaddrinfo', daemon=True)
    hilo.start()
    hilo.join(espera)
    if hilo.is_alive():
        raise SinTiempo('whois: %s no resolvió en %s s' % (host, round(espera, 1)))
    if 'error' in salida:
        raise salida['error']
    return salida['direcciones']


def _publica(ip):
    """True si `ip` es una dirección pública: un servidor WHOIS que resuelve a 127.0.0.1, 10.x o 169.254.169.254 no se
    usa, así un DNS que miente no abre conexiones dentro de la red del contenedor. is_global da True en 64:ff9b::/96
    aunque por dentro sea 127.0.0.1 (64:ff9b::7f00:1), y en una red con NAT64 esa conexión llega a la IPv4: en los
    prefijos de NAT64 también se revisa la IPv4 de los últimos 32 bits. 6to4 (2002::/16) no se repite aquí: ipaddress
    ya lo da como no global en la versión de la imagen (2002:7f00:1::1 da False)."""
    try:
        direccion = ipaddress.ip_address(ip.split('%')[0])
    except ValueError:
        return False
    if direccion.version == 6 and any(direccion in red for red in NAT64) \
            and not ipaddress.IPv4Address(int(direccion) & 0xFFFFFFFF).is_global:
        return False
    return direccion.is_global


def _conversar(host, consulta, timeout, cronometro=None):
    """La respuesta de `host` por el puerto 43 a `consulta` seguida de CRLF (RFC 3912), de a lo más MAX_BYTES_WHOIS. La
    única función que abre sockets, como _descargar es la única que hace HTTP.

    `timeout` es el plazo absoluto de toda la conversación y, a diferencia de _descargar, sí cubre getaddrinfo
    (_resolver), el connect de cada dirección (a lo más MAX_DIRECCIONES), el envío y cada recv: antes de cada operación
    se vuelve a poner settimeout con lo que queda. El connect de cada dirección recibe a lo más lo que queda dividido
    entre las direcciones que faltan por probar (la última, todo lo que queda): así una primera dirección que descarta
    los SYN no se come el plazo y la segunda sí se prueba. Si no se puede crear el socket de una dirección (una familia
    que el kernel no tiene, como IPv6 apagado) o su connect falla, se pasa a la siguiente. Lanza SinTiempo si se pasa
    del plazo y ValueError si la respuesta pasa del tope. Un OSError (conexión rechazada o cortada) sale tal cual para
    que con_reintentos lo reintente. Todo socket que sí se creó se cierra siempre. `cronometro` es time.monotonic por
    omisión."""
    cronometro = cronometro or time.monotonic
    plazo = cronometro() + timeout

    def queda():
        segundos = plazo - cronometro()
        if segundos <= 0:
            raise SinTiempo('whois: %s tardó más de %s s' % (host, timeout))
        return segundos

    direcciones = [d for d in _resolver(host, queda()) if _publica(d[4][0])][:MAX_DIRECCIONES]
    if not direcciones:
        raise RespuestaIlegible('whois: %s no resuelve a una IP pública' % host)
    pedido = consulta.encode('ascii') + b'\r\n'
    ultimo = None
    for i, (familia, tipo, protocolo, _, destino) in enumerate(direcciones):
        try:
            s = socket.socket(familia, tipo, protocolo)
        except OSError as e:   # EAFNOSUPPORT: la siguiente dirección, que puede ser de otra familia
            ultimo = e
            continue
        try:
            s.settimeout(queda() / (len(direcciones) - i))   # las que faltan también tienen su parte del plazo
            try:
                s.connect(destino)
            except OSError as e:   # la siguiente dirección, con lo que queda del plazo
                ultimo = e
                continue
            s.settimeout(queda())
            s.sendall(pedido)
            partes, total = [], 0
            while True:
                s.settimeout(queda())
                parte = s.recv(min(BLOQUE, MAX_BYTES_WHOIS + 1 - total))
                if not parte:   # el servidor cerró: es el fin de la respuesta (RFC 3912)
                    return b''.join(partes)
                partes.append(parte)
                total += len(parte)
                if total > MAX_BYTES_WHOIS:
                    raise ValueError('respuesta de más de %d bytes' % MAX_BYTES_WHOIS)
        finally:
            s.close()
    raise ultimo


# ---------------------------------------------------------------- bootstrap de IANA

def _url_https(url):
    """La URL base de un servidor RDAP, terminada en '/', o None si no es https limpia: ASCII imprimible sin espacios,
    sin usuario ni contraseña ('@'), sin '\\', '?' ni '#' (aunque la consulta o el fragmento queden vacíos), y con un
    nombre de host (no una IP)."""
    if not isinstance(url, str) or len(url) > MAX_URL or not (url.isascii() and url.isprintable()) \
            or any(c in url for c in ' @\\?#'):
        return None
    try:
        partes = urllib.parse.urlsplit(url)
        partes.port   # lanza ValueError con un puerto roto
    except ValueError:
        return None
    if partes.scheme.lower() != 'https' or not partes.hostname or not HOST_VALIDO.fullmatch(partes.hostname) \
            or partes.query or partes.fragment:
        return None
    return url if url.endswith('/') else url + '/'


def _sufijos(dominio):
    """Los sufijos del dominio, del más largo al más corto, sin el dominio completo: empresa.com.mx da com.mx y mx."""
    etiquetas = dominio.split('.')
    return ['.'.join(etiquetas[i:]) for i in range(1, len(etiquetas))]


def servicio_de(bootstrap, dominio):
    """(sufijo, URL base) del servicio del bootstrap que cubre `dominio`, con el sufijo más largo que coincide (RFC
    9224, sección 4), o (None, None) si ningún servicio lo cubre o el que lo cubre no tiene una URL https. Lanza
    RespuestaIlegible si el bootstrap no tiene la forma de RFC 9224. Sirve igual con el completo y con el reducido."""
    if not isinstance(bootstrap, dict) or not isinstance(bootstrap.get('services'), list):
        raise RespuestaIlegible('whois: el bootstrap de IANA no tiene la forma de RFC 9224')
    por_sufijo = {}
    for servicio in bootstrap['services']:
        if not (isinstance(servicio, list) and len(servicio) == 2 and all(isinstance(p, list) for p in servicio)):
            continue
        urls = [u for u in map(_url_https, servicio[1]) if u]
        for sufijo in servicio[0]:
            if isinstance(sufijo, str):
                por_sufijo.setdefault(sufijo.strip().lower().rstrip('.'), urls)
    for sufijo in _sufijos(dominio):
        if sufijo in por_sufijo:
            urls = por_sufijo[sufijo]
            return (sufijo, urls[0]) if urls else (None, None)
    return None, None


def reducir_bootstrap(bootstrap, dominio):
    """El bootstrap con solo el servicio que cubre `dominio`, con la misma forma, para grabarlo."""
    sufijo, url = servicio_de(bootstrap, dominio)
    publicado = _fecha(bootstrap.get('publication'))   # en el formato de _iso: fromisoformat acepta cualquier separador
    return {'publication': _iso(publicado) if publicado else None,
            'services': [[[sufijo], [url]]] if sufijo else []}


# ---------------------------------------------------------------- respuesta RDAP

def _fecha(texto):
    """Un datetime en UTC, o None si `texto` no es una fecha ISO 8601. Sin zona se toma como UTC. Una fecha que se
    sale del calendario al pasarla a UTC (9999-12-31T23:59:59-05:00) también da None."""
    if not isinstance(texto, str) or not 10 <= len(texto) <= 40:
        return None
    try:
        d = datetime.fromisoformat(texto.strip().replace('Z', '+00:00').replace('z', '+00:00'))
        return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _iso(d):
    """Sin strftime: con un año menor que 1000, %Y no da cuatro dígitos en todas las plataformas."""
    return '%04d-%02d-%02dT%02d:%02d:%02dZ' % (d.year, d.month, d.day, d.hour, d.minute, d.second)


def _texto(texto):
    """Un texto corto de la fuente (el nombre del registrador): imprimible, con los espacios colapsados y de a lo más
    MAX_TEXTO caracteres, o None."""
    if not isinstance(texto, str):
        return None
    texto = ' '.join(texto.split())[:MAX_TEXTO].strip()
    return texto if texto and texto.isprintable() else None


def _limpio(texto, tope=200):
    """Un texto del servidor o de un error, listo para un aviso: sin caracteres de control ni surrogates sueltos, que
    la base no acepta (contrato._cabe_en_la_base)."""
    return ' '.join(''.join(c if c.isprintable() else ' ' for c in str(texto)).split())[:tope]


def _nombre(texto):
    """Un nombre de dominio o de NS en minúsculas y sin el punto final, o None si no es un nombre válido."""
    if not isinstance(texto, str) or len(texto) > 260:
        return None
    nombre = texto.strip().lower().rstrip('.')
    return nombre if NOMBRE_VALIDO.fullmatch(nombre) else None


def _lista(x):
    """`x` si es una lista y si no, una vacía: RDAP puede traer cualquier cosa en un campo."""
    return x if isinstance(x, list) else []


def _registrador(entidades):
    """La primera entidad de primer nivel con rol registrar y sin rol de contacto (ROLES_DE_CONTACTO), o None."""
    for e in _lista(entidades):
        roles = {r.strip().lower() for r in _lista(e.get('roles')) if isinstance(r, str)} if isinstance(e, dict) else set()
        if 'registrar' in roles and not roles & ROLES_DE_CONTACTO:
            return e
    return None


def _evento(e):
    """El campo de EVENTOS de un evento RDAP, o None si no es uno de los que se leen."""
    accion = e.get('eventAction') if isinstance(e, dict) else None
    return EVENTOS.get(accion) if isinstance(accion, str) else None


def _fechas(eventos):
    """({campo: datetime}, rotos) de los eventos RDAP. Si un evento viene más de una vez: el registro más viejo, y el
    vencimiento y el cambio más recientes. `rotos` son los campos que solo traen fechas que no se pueden leer."""
    fechas, rotos = {}, set()
    for e in _lista(eventos):
        campo = _evento(e)
        if not campo:
            continue
        d = _fecha(e.get('eventDate'))
        if d is None:
            rotos.add(campo)
            continue
        fechas[campo] = (min if campo == 'registrado' else max)(fechas.get(campo, d), d)
    return fechas, sorted(rotos - set(fechas))


def _fn(entidad):
    """El 'fn' (nombre) de la vCard de la entidad, o None."""
    vcard = entidad.get('vcardArray')
    if not (isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list)):
        return None
    for prop in vcard[1]:
        if isinstance(prop, list) and len(prop) == 4 and prop[0] == 'fn' and isinstance(prop[3], str):
            return _texto(prop[3])
    return None


def _iana_id(entidad):
    for p in _lista(entidad.get('publicIds')):
        if isinstance(p, dict) and p.get('type') == 'IANA Registrar ID' and isinstance(p.get('identifier'), str) \
                and IANA_ID_VALIDO.fullmatch(p['identifier'].strip()):
            return p['identifier'].strip()
    return None


def reducir_rdap(datos):
    """La respuesta RDAP con solo lo que lee leer_rdap y con la misma forma, para grabarla: leer_rdap da lo mismo con
    ella que con la original. Cada valor pasa el mismo filtro que en leer_rdap, así no se graba texto libre (que puede
    traer datos personales o no caber en UTF-8). Queda un evento por acción, con la fecha que elige leer_rdap en el
    formato de _iso, o null si la acción solo trae fechas que no se pueden leer (leer_rdap la sigue contando como
    rota). Del registrador solo quedan sus roles, su 'fn' y sus publicIds. Las demás entidades (contactos) no se
    graban."""
    if not isinstance(datos, dict):
        return datos
    if datos.get('errorCode') == 404:
        return {'errorCode': 404}
    reducido = {}
    if 'objectClassName' in datos:   # leer_rdap rechaza cualquiera que no sea 'domain' y toma su falta como 'domain'
        reducido['objectClassName'] = 'domain' if datos['objectClassName'] == 'domain' else 'otro'
    for k in ('ldhName', 'unicodeName'):
        if _nombre(datos.get(k)):
            reducido[k] = _nombre(datos[k])
    if isinstance(datos.get('events'), list):
        fechas, rotos = _fechas(datos['events'])
        reducido['events'] = [{'eventAction': accion, 'eventDate': _iso(fechas[campo]) if campo in fechas else None}
                              for accion, campo in EVENTOS.items() if campo in fechas or campo in rotos]
    if isinstance(datos.get('status'), list):
        reducido['status'] = sorted({s.strip().lower() for s in datos['status'] if isinstance(s, str)
                                     and ESTADO_VALIDO.fullmatch(s.strip().lower())})[:MAX_ESTADOS]
    if isinstance(datos.get('secureDNS'), dict) and isinstance(datos['secureDNS'].get('delegationSigned'), bool):
        reducido['secureDNS'] = {'delegationSigned': datos['secureDNS']['delegationSigned']}
    if isinstance(datos.get('nameservers'), list):
        ns = {_nombre(n.get('ldhName')) for n in datos['nameservers'] if isinstance(n, dict)} - {None}
        reducido['nameservers'] = [{'ldhName': n} for n in sorted(ns)[:MAX_NS]]
    registrador = _registrador(datos.get('entities'))
    if registrador:
        fn, iana = _fn(registrador), _iana_id(registrador)
        entidad = {'objectClassName': 'entity', 'roles': ['registrar']}
        if fn:
            entidad['vcardArray'] = ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', fn]]]
        if iana:
            entidad['publicIds'] = [{'type': 'IANA Registrar ID', 'identifier': iana}]
        reducido['entities'] = [entidad]
    return reducido


def leer_rdap(datos, dominio):
    """(atributos, rotos) de una respuesta RDAP de `dominio`. Lo que falta sale NO_DISPONIBLE. `rotos` dice qué datos
    venían pero no se pudieron leer. Lanza RespuestaIlegible si no es la respuesta de un dominio o es de otro."""
    if not isinstance(datos, dict) or datos.get('objectClassName', 'domain') != 'domain':
        raise RespuestaIlegible('whois: RDAP no respondió con un dominio')
    nombres = {n.strip().lower().rstrip('.') for n in (datos.get('ldhName'), datos.get('unicodeName')) if isinstance(n, str)}
    if dominio not in nombres:
        raise RespuestaIlegible('whois: RDAP respondió con otro dominio')
    atributos = {v: NO_DISPONIBLE for v in EVENTOS.values()}
    fechas, rotos = _fechas(datos.get('events'))
    for campo, d in fechas.items():
        atributos[campo] = _iso(d)

    registrador = _registrador(datos.get('entities'))
    atributos['registrador'] = (registrador and _fn(registrador)) or NO_DISPONIBLE
    atributos['registrador_iana'] = (registrador and _iana_id(registrador)) or NO_DISPONIBLE
    estados = {s.strip().lower() for s in _lista(datos.get('status')) if isinstance(s, str)}
    atributos['estado_registro'] = sorted(s for s in estados if ESTADO_VALIDO.fullmatch(s))[:MAX_ESTADOS] or NO_DISPONIBLE
    ns = {_nombre(n.get('ldhName')) for n in _lista(datos.get('nameservers')) if isinstance(n, dict)} - {None}
    atributos['servidores_nombre'] = sorted(ns)[:MAX_NS] or NO_DISPONIBLE
    firmado = datos['secureDNS'].get('delegationSigned') if isinstance(datos.get('secureDNS'), dict) else None
    atributos['dnssec'] = firmado if isinstance(firmado, bool) else NO_DISPONIBLE
    return atributos, rotos


# ---------------------------------------------------------------- respuesta WHOIS (puerto 43)

def _texto_whois(cuerpo):
    """Bytes a texto: RFC 3912 no declara juego de caracteres. UTF-8 estricto y, si falla, latin-1, que nunca falla. Lo
    que se lee después pasa por filtros ASCII o por _texto."""
    try:
        return cuerpo.decode('utf-8')
    except UnicodeDecodeError:
        return cuerpo.decode('latin-1')


def _campos(texto, llaves):
    """{llave: [valores]} de las líneas 'Llave: valor' cuya llave, en minúsculas y sin espacios de los lados, está en
    `llaves`. Se compara la llave exacta antes del primer ':', así 'Registrar WHOIS Server' no es 'Registrar' y las
    líneas de un contacto ('Name:', 'Email:', 'Phone:') nunca se leen. Las líneas se parten solo en '\\n' y se les quita
    el '\\r' final (RFC 3912): splitlines() también corta en U+2028, \\x85, \\x0b, \\x0c y \\x1c a \\x1e, y con eso lo que
    viene dentro del valor de un contacto ('Registrant Organization: X\\u2028Registrar: Y') se leería como otra línea."""
    campos = {}
    for linea in texto.split('\n'):
        llave, dos_puntos, valor = linea.rstrip('\r').partition(':')
        llave = llave.strip().lower()
        if dos_puntos and llave in llaves:
            campos.setdefault(llave, []).append(valor.strip())
    return campos


def servidor_whois_de(texto, tld):
    """El servidor WHOIS de `tld` en la respuesta de whois.iana.org (su línea 'whois:'), o None si IANA no publica uno
    ('whois:' vacía o ausente). Lanza RespuestaIlegible si no es la ficha del TLD (sin 'domain:' igual al TLD: un aviso
    de límite o un error no se toman como 'sin WHOIS') o si el servidor no pasa HOST_VALIDO. 'refer:' y los contactos
    del administrador del TLD no se leen."""
    campos = _campos(texto, {'domain', 'whois'})
    if tld not in {v.lower().rstrip('.') for v in campos.get('domain', [])}:
        raise RespuestaIlegible('whois: IANA no respondió con la ficha del TLD %s' % tld)
    valores = [v for v in campos.get('whois', []) if v]
    if not valores:
        return None
    host = valores[0].lower().rstrip('.')
    if not HOST_VALIDO.fullmatch(host):
        raise RespuestaIlegible('whois: IANA dio un servidor WHOIS que no es un nombre de host')
    return host


def _estado_epp(valor):
    """El primer token de 'Domain Status' (un código de EPP) en la forma de RDAP de RFC 8056: 'ok' es 'active' y
    'clientTransferProhibited' es 'client transfer prohibited'. Lo que sigue (la URL de ICANN) no se lee."""
    token = (valor.split() or [''])[0]
    if token.lower() == 'ok':
        return 'active'
    return re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', token).lower()


def _iana_id_whois(valor):
    return valor if IANA_ID_VALIDO.fullmatch(valor) else None


def _vence_whois(texto):
    """Como _fecha, pero un vencimiento que es solo fecha (AAAA-MM-DD, como 'Expiration Date' de whois.mx) es el final
    de ese día en UTC (23:59:59) y no las 00:00: el registro sigue vigente ese día, y con las 00:00 el dominio saldría
    vencido y domain_expiring_soon se cerraría antes de tiempo. Solo para 'vence' y solo en WHOIS: RDAP da la hora."""
    d = _fecha(texto)
    if d is not None and SOLO_FECHA.fullmatch(texto.strip()):
        return d.replace(hour=23, minute=59, second=59)
    return d


def reducir_whois(texto, dominio):
    """La respuesta WHOIS de `dominio` reducida a lo que lee leer_whois, para grabarla: {'dominio', y los campos de
    CAMPOS_WHOIS que vinieron}, cada valor con el mismo filtro que en RDAP (fechas con _fecha y _iso, salvo el
    vencimiento, que va con _vence_whois, NS con _nombre, estados con ESTADO_VALIDO, registrador con _texto, IANA ID con
    IANA_ID_VALIDO). Una fecha que viene pero no se puede leer queda en None (leer_whois la cuenta como rota). Si una
    fecha se repite, la misma regla que _fechas. {'no_encontrado': True} si no hay 'Domain Name' y el texto dice que el
    dominio no existe (NO_EXISTE_WHOIS). Lanza RespuestaIlegible si no hay 'Domain Name' ni ese texto, o si 'Domain Name' es otro dominio."""
    campos = {}
    for llave, valores in _campos(texto, CAMPOS_WHOIS).items():
        campos.setdefault(CAMPOS_WHOIS[llave], []).extend(valores)
    if 'dominio' not in campos:
        if any(t in texto.lower() for t in NO_EXISTE_WHOIS):
            return {'no_encontrado': True}
        raise RespuestaIlegible('whois: WHOIS no respondió con el registro de un dominio')
    if {_nombre(v) for v in campos['dominio']} != {dominio}:
        raise RespuestaIlegible('whois: WHOIS respondió con otro dominio')
    reducido = {'dominio': dominio}
    for campo in EVENTOS.values():
        if campo in campos:   # el vencimiento ya va grabado con su hora: leer_whois da lo mismo al reproducir
            fechas = [d for d in map(_vence_whois if campo == 'vence' else _fecha, campos[campo]) if d]
            reducido[campo] = _iso((min if campo == 'registrado' else max)(fechas)) if fechas else None
    for campo, filtro in (('registrador', _texto), ('registrador_iana', _iana_id_whois)):
        validos = [v for v in map(filtro, campos.get(campo, [])) if v]
        if validos:
            reducido[campo] = validos[0]
    if 'estado_registro' in campos:
        estados = {_estado_epp(v) for v in campos['estado_registro']}
        reducido['estado_registro'] = sorted(e for e in estados if ESTADO_VALIDO.fullmatch(e))[:MAX_ESTADOS]
    if 'servidores_nombre' in campos:   # whois.mx puede traer la IP después del nombre: solo el primer token
        ns = {_nombre(v.split()[0]) for v in campos['servidores_nombre'] if v.split()} - {None}
        reducido['servidores_nombre'] = sorted(ns)[:MAX_NS]
    firmas = [DNSSEC_WHOIS[v.split()[0].lower()] for v in campos.get('dnssec', [])
              if v.split() and v.split()[0].lower() in DNSSEC_WHOIS]
    if firmas:
        reducido['dnssec'] = firmas[0]
    return reducido


def leer_whois(datos, dominio):
    """(atributos, rotos) de una respuesta WHOIS ya reducida (reducir_whois), con la misma forma que leer_rdap. Vuelve
    a pasar cada valor por su filtro, así una grabación editada a mano no mete texto libre. Lo que falta sale
    NO_DISPONIBLE. Lanza RespuestaIlegible si no es la respuesta de `dominio`."""
    if not isinstance(datos, dict) or datos.get('dominio') != dominio:
        raise RespuestaIlegible('whois: WHOIS respondió con otro dominio')
    atributos, rotos = {v: NO_DISPONIBLE for v in EVENTOS.values()}, []
    for campo in EVENTOS.values():
        if campo in datos:
            d = _fecha(datos[campo])
            if d is None:
                rotos.append(campo)
            else:
                atributos[campo] = _iso(d)
    atributos['registrador'] = _texto(datos.get('registrador')) or NO_DISPONIBLE
    iana = datos.get('registrador_iana')
    atributos['registrador_iana'] = iana if isinstance(iana, str) and IANA_ID_VALIDO.fullmatch(iana) else NO_DISPONIBLE
    estados = {s for s in _lista(datos.get('estado_registro')) if isinstance(s, str) and ESTADO_VALIDO.fullmatch(s)}
    atributos['estado_registro'] = sorted(estados)[:MAX_ESTADOS] or NO_DISPONIBLE
    ns = {_nombre(n) for n in _lista(datos.get('servidores_nombre'))} - {None}
    atributos['servidores_nombre'] = sorted(ns)[:MAX_NS] or NO_DISPONIBLE
    atributos['dnssec'] = datos['dnssec'] if isinstance(datos.get('dnssec'), bool) else NO_DISPONIBLE
    return atributos, sorted(rotos)


# ---------------------------------------------------------------- cliente

class ClienteRdap:
    """Hace las dos consultas de RDAP (el bootstrap y el dominio) y, si hace falta, las dos del respaldo por el puerto
    43 (whois.iana.org y el servidor del TLD), con reintentos y, según el modo, graba o reproduce lo ya reducido con la
    Grabadora del contrato (#13).

    `descargar(url, timeout)` hace la consulta HTTP y `conversar(host, consulta, timeout)` la del puerto 43. Si no se
    pasan, se usan _descargar y _conversar, buscados en el módulo en cada consulta, así una prueba las puede cambiar con
    mock.patch.object. `cronometro` y `dormir` son time.monotonic y time.sleep por omisión. `consultas` suma cada
    intento de cada consulta, HTTP o TCP. `reserva` son los segundos de la corrida que RDAP deja para el respaldo:
    RESERVA_WHOIS mientras corre RDAP y 0 desde que pasa a WHOIS."""

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, descargar=None, nueva=False, reloj=None, cronometro=None,
                 dormir=None, conversar=None):
        self.modo = modo
        self.grabadora = Grabadora(carpeta, modo, nueva=nueva, reloj=reloj)
        self.descargar = descargar
        self.conversar = conversar
        self.cronometro = cronometro or time.monotonic
        self.dormir = dormir or time.sleep
        self.consultas = 0
        self.inicio = None
        self.reserva = RESERVA_WHOIS
        self.pendientes = []   # lo que se graba cuando la corrida termina
        self.fallas = 0        # consultas que fallaron en esta corrida, de cualquier tipo

    @property
    def leidas(self):
        """(archivo, fecha de grabación) de cada respuesta tomada del disco."""
        return self.grabadora.leidas

    def hay_grabacion(self):
        return any(self.grabadora.carpeta.glob('*.json'))

    def empezar(self):
        self.inicio = self.cronometro()

    def restante(self):
        """Segundos que le quedan a la corrida, sin la reserva del respaldo mientras corre RDAP: así RDAP nunca se come
        el tiempo de WHOIS. Al reproducir no hay consultas y no hay tope."""
        if self.modo == 'reproducir':
            return TIEMPO_CORRIDA
        if self.inicio is None:
            self.inicio = self.cronometro()
        return TIEMPO_CORRIDA - self.reserva - (self.cronometro() - self.inicio)

    def esperar(self, segundos):
        """El dormir de con_reintentos: nunca más largo que lo que le queda a la corrida."""
        self.dormir(max(0, min(segundos, self.restante())))

    def terminar(self):
        """La corrida terminó: graba todo lo pendiente. Si al grabar hubo una falla (RDAP no respondió aunque el
        respaldo sí), no graba nada y devuelve False. Primero revisa que todo se pueda guardar en UTF-8, porque el
        primer guardar() vacía la carpeta: si algo no se puede, no graba nada, conserva la grabación anterior y
        devuelve False."""
        pendientes, self.pendientes = self.pendientes, []
        if self.fallas and self.modo == 'grabar':
            return False
        try:
            for consulta, datos in pendientes:
                json.dumps({'consulta': consulta, 'datos': datos}, ensure_ascii=False).encode('utf-8')
        except (TypeError, ValueError):   # UnicodeEncodeError es un ValueError
            return False
        for consulta, datos in pendientes:
            self.grabadora.guardar(consulta, datos)
        return True

    def _grabar(self, consulta, datos):
        if self.modo == 'grabar':
            self.pendientes.append((consulta, datos))

    def _consultar(self, funcion):
        """Corre `funcion` y cuenta su falla (no la de la grabación) en `fallas`: con una, 'grabar' no escribe."""
        try:
            return funcion()
        except SinGrabacion:
            raise
        except FuenteNoResponde:
            self.fallas += 1
            raise

    def _http(self, url, que):
        """JSON de `url` con hasta INTENTOS intentos dentro del tiempo de la corrida. _NO_ENCONTRADO con un 404. Un 429
        lanza LimiteAlcanzado, y otro 4xx salvo el 408 (que se reintenta), un 200 vacío o 'null' o un JSON tan anidado
        que Python no lo puede leer, RespuestaIlegible, sin reintentar."""
        def intento():
            limite = min(TIMEOUT_HTTP, self.restante())
            if limite < 1:
                raise SinTiempo('whois: se acabó el tiempo de la corrida antes de consultar %s' % que)
            self.consultas += 1
            try:
                cuerpo = (self.descargar or _descargar)(url, limite)
            except SinTiempo:
                if self.restante() < 1:
                    raise SinTiempo('whois: se acabó el tiempo de la corrida mientras se leía %s' % que) from None
                raise TimeoutError('whois: %s tardó más de %s s en responder' % (que, limite)) from None
            except urllib.error.HTTPError as e:
                codigo, espera = e.code, (e.headers or {}).get('Retry-After')
                with contextlib.suppress(Exception):
                    e.close()
                if codigo == 404:
                    return _NO_ENCONTRADO
                if codigo == 429:
                    raise LimiteAlcanzado('whois: %s llegó a su límite de consultas (429, Retry-After %s s)'
                                          % (que, espera or '?')) from None
                if codigo < 500 and codigo != 408:
                    raise RespuestaIlegible('whois: %s respondió %d' % (que, codigo)) from None
                raise
            if not cuerpo or not cuerpo.strip():
                raise RespuestaIlegible('whois: %s respondió sin cuerpo' % que)
            try:
                datos = json.loads(cuerpo)
            except RecursionError:
                raise RespuestaIlegible('whois: %s respondió un JSON demasiado anidado' % que) from None
            if datos is None:
                raise RespuestaIlegible('whois: %s respondió null' % que)
            return datos
        intento.__name__ = 'whois: %s no respondió' % que
        return con_reintentos(intento, intentos=INTENTOS, esperas=ESPERAS, dormir=self.esperar)

    def bootstrap(self, dominio):
        """El bootstrap de IANA reducido al servicio que cubre `dominio` (reducir_bootstrap)."""
        del_disco, datos = self.grabadora.de_disco('bootstrap')
        if del_disco:
            servicio_de(datos, dominio)   # lanza RespuestaIlegible si la grabación está rota
            return datos

        def consulta():
            datos = self._http(URL_BOOTSTRAP, 'el bootstrap de IANA')
            if datos is _NO_ENCONTRADO:
                raise RespuestaIlegible('whois: el bootstrap de IANA respondió 404')
            return reducir_bootstrap(datos, dominio)
        datos = self._consultar(consulta)
        self._grabar('bootstrap', datos)
        return datos

    def registro(self, base, dominio):
        """La respuesta RDAP de `dominio` reducida (reducir_rdap), o {'errorCode': 404} si el registro no lo conoce."""
        clave = 'rdap:' + dominio
        del_disco, datos = self.grabadora.de_disco(clave)
        if del_disco:
            if not isinstance(datos, dict):
                raise FuenteNoResponde('whois: la grabación de %s no se puede leer' % clave)
            return datos

        def consulta():
            datos = self._http(base + 'domain/' + dominio, 'RDAP (%s)' % urllib.parse.urlsplit(base).hostname)
            if datos is _NO_ENCONTRADO:
                return {'errorCode': 404}
            if not isinstance(datos, dict):
                raise RespuestaIlegible('whois: RDAP respondió algo que no es un objeto')
            reducido = reducir_rdap(datos)
            leer_rdap(reducido, dominio)  # una respuesta de otro dominio o que no es un dominio no se graba
            return reducido
        datos = self._consultar(consulta)
        self._grabar(clave, datos)
        return datos

    def _tcp(self, host, consulta, que):
        """El texto de la respuesta de `host` por el puerto 43, con hasta INTENTOS_WHOIS intentos dentro del tiempo de
        la corrida. Una conexión rechazada o cortada, o una respuesta de más de MAX_BYTES_WHOIS, se reintentan. Una
        respuesta vacía lanza RespuestaIlegible sin reintentar: el servidor sí respondió."""
        def intento():
            limite = min(TIMEOUT_WHOIS, self.restante())
            if limite < 1:
                raise SinTiempo('whois: se acabó el tiempo de la corrida antes de consultar %s' % que)
            self.consultas += 1
            try:
                cuerpo = (self.conversar or _conversar)(host, consulta, limite)
            except SinTiempo:
                if self.restante() < 1:
                    raise SinTiempo('whois: se acabó el tiempo de la corrida mientras se leía %s' % que) from None
                raise TimeoutError('whois: %s tardó más de %s s en responder' % (que, limite)) from None
            if not cuerpo or not cuerpo.strip():
                raise RespuestaIlegible('whois: %s respondió sin texto' % que)
            return _texto_whois(cuerpo)
        intento.__name__ = 'whois: %s no respondió' % que
        return con_reintentos(intento, intentos=INTENTOS_WHOIS, esperas=ESPERAS_WHOIS, dormir=self.esperar)

    def servidor_whois(self, tld):
        """El servidor WHOIS de `tld` según whois.iana.org (servidor_whois_de), o None si IANA no publica uno."""
        clave = 'whois-iana:' + tld
        del_disco, datos = self.grabadora.de_disco(clave)
        if del_disco:
            host = datos.get('whois') if isinstance(datos, dict) else None
            if not isinstance(datos, dict) or 'whois' not in datos \
                    or not (host is None or isinstance(host, str) and HOST_VALIDO.fullmatch(host)):
                raise FuenteNoResponde('whois: la grabación de %s no se puede leer' % clave)
            return host

        def consulta():
            return servidor_whois_de(self._tcp(IANA_WHOIS, tld, 'el WHOIS de IANA'), tld)
        host = self._consultar(consulta)
        self._grabar(clave, {'whois': host})
        return host

    def whois(self, host, dominio):
        """La respuesta WHOIS de `dominio` en `host` reducida (reducir_whois), o {'no_encontrado': True}. Solo el
        servidor del registro del TLD: no se sigue ninguna referencia a un registrador."""
        clave = 'whois:' + dominio
        del_disco, datos = self.grabadora.de_disco(clave)
        if del_disco:
            if not isinstance(datos, dict):
                raise FuenteNoResponde('whois: la grabación de %s no se puede leer' % clave)
            return datos

        def consulta():
            texto = self._tcp(host, PREFIJOS.get(host, '') + dominio, 'WHOIS (%s)' % host)
            return reducir_whois(texto, dominio)   # una respuesta de otro dominio o sin registro no se graba
        datos = self._consultar(consulta)
        self._grabar(clave, datos)
        return datos


def carpeta_de(dominio):
    """Carpeta de la grabación de un dominio."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' consulta, 'reproducir' usa la grabación del dominio y 'grabar' empieza
    una grabación nueva."""
    return ClienteRdap(modo=modo, carpeta=carpeta_de(dominio), nueva=(modo == 'grabar'))


def _en_vivo_permitido(dominio):
    """Lo mismo que orquestador.en_vivo_permitido(), sin importar el orquestador (que importa los recolectores)."""
    permitidos = {d.strip().lower() for d in config('DOMINIOS_EN_VIVO', 'olmardo.com').split(',') if d.strip()}
    return '*' in permitidos or dominio in permitidos


# ---------------------------------------------------------------- activos y hallazgos

def _huella(codigo, dominio, activo, clave=''):
    """Lleva el día del vencimiento: si el dominio se renueva y vuelve a quedar por vencer, es otro hallazgo."""
    return hashlib.sha256('|'.join((FUENTE, codigo, dominio, activo, clave)).encode('utf-8')).hexdigest()


def _cuantos(n, singular, plural):
    return '%d %s' % (n, singular if n == 1 else plural)


def _no_disponible(dominio):
    """El activo domain cuando no se sabe nada del registro."""
    atributos = {v: NO_DISPONIBLE for v in EVENTOS.values()}
    atributos.update(registrador=NO_DISPONIBLE, registrador_iana=NO_DISPONIBLE, estado_registro=NO_DISPONIBLE,
                     servidores_nombre=NO_DISPONIBLE, dnssec=NO_DISPONIBLE)
    return Activo('domain', dominio, dict(atributos, fuente=FUENTE))


def hallazgo_vencimiento(dominio, vence, atributos, ahora):
    """domain_expiring_soon sobre el activo domain, o None si faltan DIAS_POR_VENCER días o más o si ya venció (eso es
    el aviso de _aviso_vencido). Los días se truncan, como en crtsh.py."""
    segundos = (vence - ahora).total_seconds()
    if not 0 <= segundos < DIAS_POR_VENCER * 86400:
        return None
    codigo = 'domain_expiring_soon'
    dias = int(segundos / 86400)
    if dias < 1:
        titulo = 'El registro de %s vence en menos de un día' % dominio
    else:
        titulo = 'El registro de %s vence en %s' % (dominio, _cuantos(dias, 'día', 'días'))
    servidor = 'servidor_whois' if 'servidor_whois' in atributos else 'servidor_rdap'
    evidencia = {'title': titulo, 'vence': _iso(vence), 'dias_para_vencer': dias,
                 'registrador': atributos['registrador'], 'estado_registro': atributos['estado_registro'],
                 'fuente_datos': atributos['fuente_datos'], servidor: atributos[servidor]}
    return Hallazgo(codigo, CODIGOS[codigo], dominio, titulo, evidencia,
                    rubrica.calcular(codigo, 'domain', evidencia, ahora),
                    _huella(codigo, dominio, dominio, vence.date().isoformat()))


def _aviso_vencido(dominio, vence, ahora, nombre=NOMBRE_RDAP):
    """El aviso de un registro que ya venció y sigue publicado. No es domain_expiring_soon: el texto de esa regla
    (migración 003) habla de lo que vence en los siguientes 30 días. `nombre` es lo que respondió (RDAP o WHOIS)."""
    dias = int((ahora - vence).total_seconds() / 86400)
    hace = 'hace menos de un día' if dias < 1 else 'hace %s' % _cuantos(dias, 'día', 'días')
    return ('whois: el registro de %s venció el %s (%s) y %s lo sigue publicando. No sale como domain_expiring_soon, '
            'que es para lo que vence en los siguientes %d días'
            % (dominio, vence.date().isoformat(), hace, nombre, DIAS_POR_VENCER))


def _sin_cobertura(res, dominio, aviso):
    res.activos.append(_no_disponible(dominio))
    res.avisos.append(aviso)
    res.sin_cobertura = list(CODIGOS)
    return res


def _motivo(error):
    """El texto de un error para ponerlo dentro de otro aviso, limpio (_limpio) y sin el 'whois: ' del principio."""
    texto = _limpio(error)
    return texto[len('whois: '):] if texto.startswith('whois: ') else texto


def _con_registro(res, dominio, ahora, atributos, rotos, origen):
    """El activo domain, los avisos de sus fechas y domain_expiring_soon con lo que dio RDAP o WHOIS. `origen` trae
    fuente_datos y el servidor que respondió (servidor_rdap o servidor_whois)."""
    nombre = origen['fuente_datos']
    vence, registrado = _fecha(atributos['vence']), _fecha(atributos['registrado'])
    imposible = vence is not None and (vence < ahora - timedelta(days=MAX_DIAS_VENCIDO)
                                       or (registrado is not None and vence <= registrado))
    if imposible:
        atributos['vence'] = NO_DISPONIBLE
    atributos.update(origen, fuente=FUENTE)
    res.activos.append(Activo('domain', dominio, atributos))
    if rotos:
        res.avisos.append('whois: %s dio fechas que no se pueden leer (%s) y se ignoraron' % (nombre, ', '.join(rotos)))
    if atributos['vence'] == NO_DISPONIBLE:
        res.avisos.append((VENCIMIENTO_IMPOSIBLE if imposible else VENCIMIENTO_ROTO if 'vence' in rotos
                           else SIN_VENCIMIENTO) % nombre)
        res.sin_cobertura = list(CODIGOS)
    elif vence < ahora:
        res.avisos.append(_aviso_vencido(dominio, vence, ahora, nombre))
    else:
        h = hallazgo_vencimiento(dominio, vence, atributos, ahora)
        if h:
            res.hallazgos.append(h)


# ---------------------------------------------------------------- punto de entrada

def recolectar(dominio, cliente=None, ahora=None, propios=()):
    """Registrador, fechas y vencimiento del dominio por RDAP, o por WHOIS como respaldo. `propios` no se usa."""
    dominio = dominio.strip().lower().rstrip('.')
    res = Resultado(dominio, FUENTE)
    if not NOMBRE_VALIDO.fullmatch(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res
    cliente = cliente or crear_cliente('vivo', dominio)
    if cliente.modo == 'reproducir' and not cliente.hay_grabacion():
        return _sin_cobertura(res, dominio, SIN_GRABACION_DOMINIO)
    try:
        cliente.empezar()
        _revisar(res, cliente, dominio, ahora or datetime.now(timezone.utc))
    finally:
        res.consultas = cliente.consultas
    return res


def _revisar(res, cliente, dominio, ahora):
    # Una falla de la red o del registro pasa al respaldo por el puerto 43 (_respaldo). Una grabación rota sí es
    # failed: la lanza el cliente al reproducir, fuera de este try, porque no es una falla de RDAP.
    try:
        bootstrap = cliente.bootstrap(dominio)
        sufijo, base = servicio_de(bootstrap, dominio)
        datos = cliente.registro(base, dominio) if base else None
    except SinGrabacion:
        raise
    except FuenteNoResponde as e:
        if cliente.modo == 'reproducir':
            raise
        return _respaldo(res, cliente, dominio, ahora, e)

    if not base:
        return _respaldo(res, cliente, dominio, ahora, None)
    if datos.get('errorCode') == 404:   # el registro respondió: WHOIS diría lo mismo
        _sin_cobertura(res, dominio, NO_ENCONTRADO)
    else:
        try:
            atributos, rotos = leer_rdap(datos, dominio)
        except RespuestaIlegible:
            if cliente.modo != 'reproducir':
                raise   # cliente.registro ya lo revisó: no llega aquí con una respuesta de la red
            raise FuenteNoResponde('whois: la grabación de rdap:%s no se puede leer' % dominio) from None
        _con_registro(res, dominio, ahora, atributos, rotos, {'fuente_datos': NOMBRE_RDAP, 'servidor_rdap': base})
    if not cliente.terminar():
        res.avisos.insert(0, NO_SE_GRABO)
    return res


def _respaldo(res, cliente, dominio, ahora, falla):
    """WHOIS por el puerto 43 cuando RDAP no sirve: el TLD no tiene servidor RDAP https en el bootstrap (`falla` es
    None, el caso de .mx y .com.mx) o RDAP no respondió (`falla` es su error). Si WHOIS tampoco responde, el activo sale
    'No disponible' con SIN_RESPUESTA y los dos motivos."""
    cliente.reserva = 0   # desde aquí corre con lo que RDAP dejó, RESERVA_WHOIS incluida
    tld = dominio.rsplit('.', 1)[1]
    razon = SIN_RDAP_TLD if falla is None else 'RDAP no respondió (%s)' % _motivo(falla)
    try:
        try:
            host = cliente.servidor_whois(tld)
        except SinGrabacion:
            # Una grabación de antes del respaldo: el bootstrap sin servicio y sin whois-iana. Da lo mismo que entonces.
            return _sin_cobertura(res, dominio, 'whois: %s de %s' % (SIN_RDAP_TLD, dominio))
        datos = cliente.whois(host, dominio) if host else None
    except SinGrabacion:
        raise
    except FuenteNoResponde as e:
        if cliente.modo == 'reproducir':
            raise
        _sin_cobertura(res, dominio, '%s (RDAP: %s. WHOIS: %s)'
                       % (SIN_RESPUESTA, SIN_RDAP_TLD if falla is None else _motivo(falla), _motivo(e)))
        if cliente.modo == 'grabar':
            res.avisos.insert(0, NO_SE_GRABO)
        return res

    if host is None:
        _sin_cobertura(res, dominio, SIN_WHOIS % (dominio, razon))
    elif datos.get('no_encontrado') is True:
        _sin_cobertura(res, dominio, CON_WHOIS % (host, razon))
        res.avisos.append(NO_ENCONTRADO_WHOIS)
    else:
        try:
            atributos, rotos = leer_whois(datos, dominio)
        except RespuestaIlegible:
            if cliente.modo != 'reproducir':
                raise   # cliente.whois ya lo revisó: no llega aquí con una respuesta de la red
            raise FuenteNoResponde('whois: la grabación de whois:%s no se puede leer' % dominio) from None
        res.avisos.append(CON_WHOIS % (host, razon))
        _con_registro(res, dominio, ahora, atributos, rotos, {'fuente_datos': NOMBRE_WHOIS, 'servidor_whois': host})
    if not cliente.terminar():
        res.avisos.insert(0, NO_SE_GRABO)
    return res


# ---------------------------------------------------------------- línea de comandos

SEVERIDAD_ES = {'critical': 'crítica', 'high': 'alta', 'medium': 'media', 'low': 'baja'}


def resumen(res):
    """Líneas para la terminal."""
    lineas = ['%s · %s · %s · %s' % (res.dominio, FUENTE, res.estado, _cuantos(res.consultas, 'consulta', 'consultas'))]
    if res.error:
        lineas.append('error: %s' % res.error)
    for a in res.activos:
        if a.tipo == 'domain':
            t = a.atributos
            lineas.append('Registro de %s · registrador %s · registrado %s · vence %s · último cambio %s'
                          % (a.valor, t['registrador'], t['registrado'], t['vence'], t['ultimo_cambio']))
    if res.hallazgos:
        lineas.append(_cuantos(len(res.hallazgos), 'hallazgo:', 'hallazgos:'))
        lineas += ['  [%s] %s' % (SEVERIDAD_ES.get(h.severidad, h.severidad), h.titulo) for h in res.hallazgos]
    elif res.estado == 'succeeded' and not res.sin_cobertura:
        lineas.append('Sin hallazgos.')
    if res.sin_cobertura:  # no es lo mismo que 0 hallazgos
        lineas.append('Cobertura parcial: no se revisó %s.' % ' ni '.join(res.sin_cobertura))
    lineas += ['aviso: %s' % a for a in res.avisos]
    return lineas


def codigo_salida(res):
    """0 si la corrida fue completa, 1 si el resultado queda en 'failed', 2 si la cobertura quedó parcial y 3 si
    --grabar no escribió por una falla (NO_SE_GRABO)."""
    if res.estado == 'failed':
        return 1
    if NO_SE_GRABO in res.avisos:
        return 3
    return 2 if res.sin_cobertura else 0


def _main(argv=None):
    # En Windows, cuando la salida no es la consola (Git Bash, una tubería), Python usa cp1252 y los acentos se rompen.
    if (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    p = argparse.ArgumentParser(description='Registrador, fechas y vencimiento del dominio por RDAP, con WHOIS por el '
                                            'puerto 43 como respaldo')
    p.add_argument('dominio')
    modo = p.add_mutually_exclusive_group()
    modo.add_argument('--grabar', action='store_true',
                      help='empieza una grabación nueva en cirdan/recolectores/respuestas_grabadas/whois/<dominio>/')
    modo.add_argument('--reproducir', action='store_true', help='usa solo la grabación, sin red')
    p.add_argument('--json', action='store_true', help='imprime el resultado completo en JSON')
    a = p.parse_args(argv)
    dominio = a.dominio.strip().lower().rstrip('.')
    if not NOMBRE_VALIDO.fullmatch(dominio):  # también evita que '..' o '/' saquen la carpeta de respuestas_grabadas
        p.error('dominio inválido: %s' % a.dominio)
    modo = 'grabar' if a.grabar else 'reproducir' if a.reproducir else 'vivo'
    if modo != 'reproducir' and not _en_vivo_permitido(dominio):
        p.error('%s no está en DOMINIOS_EN_VIVO: RDAP y WHOIS solo se consultan en vivo, o se graban, con la carta '
                'vigente del dominio. Usa --reproducir' % dominio)
    cliente = crear_cliente(modo, dominio)
    try:
        res = recolectar(dominio, cliente)
    except FuenteNoResponde as e:
        res = Resultado(dominio, FUENTE, estado='failed', consultas=cliente.consultas, error=str(e))
    if a.json:
        print(json.dumps(res.a_dict(), ensure_ascii=False, indent=1))
    else:
        print('\n'.join(resumen(res)))
    return codigo_salida(res)


if __name__ == '__main__':
    sys.exit(_main())
