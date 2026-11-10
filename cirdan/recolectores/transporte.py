"""HTTPS con un plazo absoluto por petición y sin redirecciones, para rdap.py y shodan.py (#15b, RC-166) y para el
TXT de verificación por DNS sobre HTTPS de orquestador/txt.py (#119, RC-236).

urllib solo pone un timeout a cada operación del socket: getaddrinfo no tiene, y el connect de cada dirección, el
handshake TLS, el envío y cada lectura de las cabeceras o del cuerpo tienen el timeout entero. Un servidor que contesta
de a poco estira así una petición mucho más que su timeout. Aquí `plazo` es un instante de `cronometro`
(time.monotonic por omisión) y cubre toda la petición, como rdap._conversar en el puerto 43:
- getaddrinfo corre en un hilo daemon y se espera solo lo que queda (resolver). Si no termina, el hilo sigue solo.
- el connect de cada dirección recibe lo que queda repartido entre las que faltan por probar (la última, todo lo que
  queda): una dirección que descarta los SYN no se come el plazo. Si no se puede crear el socket de una dirección (una
  familia que el kernel no tiene) o su connect falla, se pasa a la siguiente.
- el handshake TLS recibe lo que queda, porque CPython le da un solo plazo a todo el handshake.
- antes de cada lectura o escritura del socket TLS, en las cabeceras y en el cuerpo, se vuelve a poner settimeout con
  lo que queda (_SocketTls), y descargar() revisa el plazo antes de cada bloque.
Si se pasa del plazo, descargar() lanza PlazoVencido. El certificado se revisa como siempre
(ssl.create_default_context).

Una redirección (3xx) nunca se sigue: lanza Redirigida. Así cada petición llega solo al servidor que se pidió y es una
sola consulta, la que cuenta el cliente para el cupo (#13b), sin saltos que no cuentan. El bootstrap de IANA, los
registros RDAP, InternetDB y Cert Spotter responden sin redirigir. Si alguno redirige, el cliente lo toma como una
respuesta que no se puede leer. Tampoco se usan los proxies del entorno (HTTPS_PROXY y los demás): cada
petición va directa al servidor, porque el plazo no cubriría el CONNECT de un túnel.

Solo direcciones públicas (#18, RC-46, comentario 10283). _conectar se conecta solo a las direcciones globales de lo que
dio getaddrinfo (publica()), la misma lista a la que se conecta: un DNS que cambia entre una consulta anterior y la
conexión no lo salta. Si ninguna es global lanza NoPublica, que urllib entrega dentro de un URLError (su reason). Así
un nombre que apunta a 127.0.0.1, a la red interna (10.0.0.0/8 y las demás) o a 169.254.169.254 nunca recibe la
petición, ni en la visita web (visita.py) ni en las consultas a las fuentes.

visitar() es la petición de la visita web: da el estado, las cabeceras y hasta `tope` bytes del cuerpo de cualquier
respuesta, también un 4xx o un 5xx, y corta el cuerpo en vez de fallar. Una redirección tampoco se sigue: Redirigida
trae el destino (`destino`) y quien llama decide si lo visita.

retry_after() lee la cabecera Retry-After, para que un 5xx que la trae espere lo que pide antes de otro intento.
"""
import contextlib
import email.utils
import functools
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BLOQUE = 64 * 1024           # bytes que descargar lee de una vez
SEGUNDOS = re.compile(r'[0-9]{1,9}')
# Prefijos NAT64 (RFC 6052 y RFC 8215): llevan una IPv4 en los últimos 32 bits, que también tiene que ser pública.
NAT64 = (ipaddress.ip_network('64:ff9b::/96'), ipaddress.ip_network('64:ff9b:1::/48'))
IPV4_COMPATIBLE = ipaddress.ip_network('::/96')


class PlazoVencido(Exception):
    """La petición no terminó dentro de su plazo."""


class Redirigida(Exception):
    """El servidor respondió con una redirección, que no se sigue. `destino` es la URL absoluta a la que manda (la de
    urllib, ya unida con la de la petición), o None."""

    def __init__(self, codigo, host, destino=None):
        super().__init__('%s redirigió (%d) y no se siguen redirecciones' % (host, codigo))
        self.codigo, self.host, self.destino = codigo, host, destino


class NoPublica(OSError):
    """El nombre solo resolvió a direcciones que no son públicas: no se conecta a ninguna."""


def publica(ip):
    """True si `ip` es una dirección pública: un nombre que resuelve a 127.0.0.1, 10.x o 169.254.169.254 no se usa, así
    un DNS que miente no abre conexiones dentro de la red del contenedor ni de la VM. is_global da True en 64:ff9b::/96
    aunque por dentro sea 127.0.0.1 (64:ff9b::7f00:1), y en una red con NAT64 esa conexión llega a la IPv4: en los
    prefijos de NAT64 también se revisa la IPv4 de los últimos 32 bits. 6to4 (2002::/16) no se repite aquí: ipaddress
    ya lo da como no global en la versión de la imagen (2002:7f00:1::1 da False). Antes estaba en rdap.py
    (_publica)."""
    try:
        direccion = ipaddress.ip_address(str(ip).split('%')[0])
    except ValueError:
        return False
    if direccion.version == 6 and direccion in IPV4_COMPATIBLE and int(direccion) > 1:
        return False   # ::a.b.c.d (en desuso) puede llegar a la IPv4 y ipaddress la da como global
    if direccion.version == 6 and any(direccion in red for red in NAT64) \
            and not ipaddress.IPv4Address(int(direccion) & 0xFFFFFFFF).is_global:
        return False
    return direccion.is_global


def resolver(host, puerto, espera):
    """getaddrinfo de `host` dentro de `espera` segundos. getaddrinfo no tiene plazo: corre en un hilo daemon y se
    espera con join(espera). Si no terminó, lanza PlazoVencido y el hilo sigue solo: la corrida no lo espera."""
    salida = {}

    def resolver_():
        try:
            salida['direcciones'] = socket.getaddrinfo(host, puerto, type=socket.SOCK_STREAM)
        except OSError as e:
            salida['error'] = e
    hilo = threading.Thread(target=resolver_, name='https-getaddrinfo', daemon=True)
    hilo.start()
    hilo.join(espera)
    if hilo.is_alive():
        raise PlazoVencido('%s no resolvió en %s s' % (host, round(espera, 1)))
    if 'error' in salida:
        raise salida['error']
    return salida['direcciones']


class _SocketTls(ssl.SSLSocket):
    """El socket TLS de una petición: antes de cada lectura o escritura vuelve a poner settimeout con lo que queda del
    plazo (`queda`, que pone _Conexion después del handshake). recv, recv_into y sendall pasan por read y send."""
    queda = None

    def read(self, len=1024, buffer=None):
        if self.queda:
            self.settimeout(self.queda())
        return super().read(len, buffer)

    def send(self, data, flags=0):
        if self.queda:
            self.settimeout(self.queda())
        return super().send(data, flags)


@functools.lru_cache(maxsize=1)
def _contexto():
    """El contexto TLS por omisión (revisa el certificado y el nombre), con _SocketTls como clase de sus sockets."""
    contexto = ssl.create_default_context()
    contexto.sslsocket_class = _SocketTls
    return contexto


class _Conexion(http.client.HTTPSConnection):
    """Una conexión HTTPS en la que todo pasa dentro de `plazo`: getaddrinfo, el connect, el TLS y cada lectura o
    escritura. El `timeout` que pasa urllib no se usa."""

    def __init__(self, host, plazo, cronometro, familia=socket.AF_UNSPEC, **otros):
        super().__init__(host, **otros)
        self.plazo, self.cronometro, self.familia = plazo, cronometro, familia
        self._create_connection = self._conectar

    def queda(self):
        """Segundos que le quedan al plazo. Lanza PlazoVencido si ya no queda nada."""
        segundos = self.plazo - self.cronometro()
        if segundos <= 0:
            raise PlazoVencido('%s no terminó dentro de su plazo' % self.host)
        return segundos

    def _conectar(self, direccion, *_):
        """El socket conectado a la primera dirección pública de `direccion` (host, puerto) que responda, con
        settimeout en lo que queda para el handshake TLS. Las que no son públicas (publica()) se saltan sin crear su
        socket, y si no queda ninguna lanza NoPublica. Todo socket que falla se cierra. Con `familia` solo cuentan las
        direcciones de esa familia: la visita web pide AF_INET, así una AAAA que el DNS de la red arma con su propio
        prefijo de NAT64 (uno que publica() no puede conocer) nunca se usa para llegar a una IPv4 interna."""
        host, puerto = direccion
        todas = resolver(host, puerto, self.queda())
        if self.familia:
            todas = [d for d in todas if d[0] == self.familia]
        direcciones = [d for d in todas if publica(d[4][0])]
        if todas and not direcciones:
            raise NoPublica('%s resolvió solo a direcciones que no son públicas' % host)
        ultimo = OSError('%s no resolvió a ninguna dirección' % host)
        for i, (familia, tipo, protocolo, _, destino) in enumerate(direcciones):
            try:
                s = socket.socket(familia, tipo, protocolo)
            except OSError as e:   # EAFNOSUPPORT: la siguiente dirección, que puede ser de otra familia
                ultimo = e
                continue
            try:
                s.settimeout(self.queda() / (len(direcciones) - i))   # las que faltan también tienen su parte
                s.connect(destino)
                s.settimeout(self.queda())
            except OSError as e:   # la siguiente dirección, con lo que queda del plazo
                s.close()
                ultimo = e
                continue
            except BaseException:
                s.close()
                raise
            return s
        raise ultimo

    def connect(self):
        super().connect()
        self.sock.queda = self.queda


class _Https(urllib.request.HTTPSHandler):
    """Abre cada petición https con una _Conexion que tiene el plazo de la petición."""

    def __init__(self, plazo, cronometro, familia=socket.AF_UNSPEC):
        super().__init__(context=_contexto())
        self._conexion = functools.partial(_Conexion, plazo=plazo, cronometro=cronometro, familia=familia)

    def https_open(self, req):
        return self.do_open(self._conexion, req, context=self._context)


class _SinRedirecciones(urllib.request.HTTPRedirectHandler):
    """Ninguna redirección se sigue: lanza Redirigida."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        with contextlib.suppress(Exception):
            fp.close()
        raise Redirigida(code, urllib.parse.urlsplit(req.full_url).hostname, newurl)


def abrir(req, plazo, cronometro, familia=socket.AF_UNSPEC):
    """La respuesta a `req`, con _Https, _SinRedirecciones y sin proxies (un ProxyHandler vacío, que build_opener ya no
    agrega con los del entorno). Con `familia` la conexión solo va a direcciones de esa familia (_Conexion._conectar).
    Las pruebas la cambian por una respuesta simulada."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _SinRedirecciones,
                                       _Https(plazo, cronometro, familia)).open(req)


def descargar(req, plazo, tope, cronometro=None, tipo=None):
    """El cuerpo de la respuesta a `req`, que tiene que ser https, de a lo más `tope` bytes y todo antes de `plazo`.

    Lee por bloques (read1, una lectura del socket a la vez) y revisa el plazo antes de cada uno. Lanza PlazoVencido si
    se pasa, también cuando un timeout del socket llega con el plazo ya vencido, Redirigida con un 3xx y ValueError si
    la respuesta pasa de `tope` o si, con `tipo`, su Content-Type (sin parámetros) es otro. El HTTPError de un 4xx o un
    5xx y el OSError de la red salen tal cual."""
    cronometro = cronometro or time.monotonic
    if req.type != 'https':
        raise ValueError('solo se pide por https: %s' % req.full_url)
    partes, total = [], 0
    try:
        with abrir(req, plazo, cronometro) as r:
            if tipo is not None and r.headers.get_content_type() != tipo:
                raise ValueError('respuesta de tipo %s, no %s' % (r.headers.get_content_type(), tipo))
            leer = r.read1 if hasattr(r, 'read1') else r.read
            while True:
                if cronometro() > plazo:
                    raise PlazoVencido('%s no terminó dentro de su plazo' % req.host)
                parte = leer(min(BLOQUE, tope + 1 - total))
                if not parte:
                    break
                partes.append(parte)
                total += len(parte)
                if total > tope:
                    raise ValueError('respuesta de más de %d bytes' % tope)
    except urllib.error.HTTPError:
        raise
    except OSError:
        if cronometro() >= plazo:   # el timeout del socket era lo que quedaba del plazo
            raise PlazoVencido('%s no terminó dentro de su plazo' % req.host) from None
        raise
    return b''.join(partes)


def visitar(req, plazo, tope, cronometro=None):
    """(estado, cabeceras, cuerpo, cortado) de la respuesta a `req`, que tiene que ser https, todo antes de `plazo`:
    la visita web de la actividad 6 (visita.py). `cabeceras` es la lista de pares (nombre, valor) como llegaron, con
    las repetidas. Un 4xx o un 5xx es una respuesta como cualquier otra (un reto del WAF es un 403 o un 503). Del cuerpo
    se leen a lo más `tope` bytes y `cortado` dice si quedaba más: una página grande no es una falla.

    Lanza Redirigida con el destino si responde con una redirección que urllib sigue (301, 302, 303, 307 y 308 con
    Location), PlazoVencido si se pasa del plazo, también cuando un timeout del socket llega con el plazo ya vencido, y
    el OSError de la red tal cual: un URLError cuyo reason es NoPublica si el nombre solo resolvió a direcciones que no
    son públicas, o el de un certificado que no se pudo verificar.

    La conexión va solo por IPv4 (AF_INET), como el A con el que la visita decide si el nombre tiene sitio público: una
    red con NAT64 y un prefijo propio no puede llevarla a una IPv4 interna con una AAAA armada."""
    cronometro = cronometro or time.monotonic
    if req.type != 'https':
        raise ValueError('solo se pide por https: %s' % req.full_url)
    try:
        try:
            r = abrir(req, plazo, cronometro, socket.AF_INET)
        except urllib.error.HTTPError as e:   # la respuesta del sitio con su estado, que se analiza igual
            if e.fp is None:
                raise
            r = e
        with r:
            estado = r.getcode()
            cabeceras = list(r.headers.items()) if r.headers is not None else []
            leer = r.read1 if hasattr(r, 'read1') else r.read
            partes, total = [], 0
            while total <= tope:
                if cronometro() > plazo:
                    raise PlazoVencido('%s no terminó dentro de su plazo' % req.host)
                parte = leer(min(BLOQUE, tope + 1 - total))
                if not parte:
                    break
                partes.append(parte)
                total += len(parte)
    except (Redirigida, PlazoVencido):
        raise
    except OSError:
        if cronometro() >= plazo:   # el timeout del socket era lo que quedaba del plazo
            raise PlazoVencido('%s no terminó dentro de su plazo' % req.host) from None
        raise
    cuerpo = b''.join(partes)
    return estado, cabeceras, cuerpo[:tope], len(cuerpo) > tope


def retry_after(cabeceras, ahora=None):
    """Los segundos que pide esperar el Retry-After de `cabeceras` (RFC 9110, 10.2.3): un número de segundos o una
    fecha HTTP. La fecha se cuenta desde la cabecera Date de la misma respuesta o, si no viene, desde `ahora` (la hora
    UTC por omisión). None si no viene o no se puede leer. Nunca negativo."""
    valor = (cabeceras or {}).get('Retry-After')
    if not isinstance(valor, str):
        return None
    valor = valor.strip()
    if SEGUNDOS.fullmatch(valor):
        return int(valor)
    fecha = _fecha_http(valor)
    if fecha is None:
        return None
    base = _fecha_http((cabeceras or {}).get('Date')) or ahora or datetime.now(timezone.utc)
    return max(0, int((fecha - base).total_seconds() + 0.999))


def _fecha_http(valor):
    """La fecha HTTP `valor` en UTC, o None si no se puede leer."""
    if not isinstance(valor, str):
        return None
    try:
        fecha = email.utils.parsedate_to_datetime(valor)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    return fecha.replace(tzinfo=timezone.utc) if fecha.tzinfo is None else fecha
