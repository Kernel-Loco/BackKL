"""HTTPS con un plazo absoluto por petición y sin redirecciones, para rdap.py y shodan.py (#15b, RC-166).

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

retry_after() lee la cabecera Retry-After, para que un 5xx que la trae espere lo que pide antes de otro intento.
"""
import contextlib
import email.utils
import functools
import http.client
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


class PlazoVencido(Exception):
    """La petición no terminó dentro de su plazo."""


class Redirigida(Exception):
    """El servidor respondió con una redirección, que no se sigue."""

    def __init__(self, codigo, host):
        super().__init__('%s redirigió (%d) y no se siguen redirecciones' % (host, codigo))
        self.codigo, self.host = codigo, host


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

    def __init__(self, host, plazo, cronometro, **otros):
        super().__init__(host, **otros)
        self.plazo, self.cronometro = plazo, cronometro
        self._create_connection = self._conectar

    def queda(self):
        """Segundos que le quedan al plazo. Lanza PlazoVencido si ya no queda nada."""
        segundos = self.plazo - self.cronometro()
        if segundos <= 0:
            raise PlazoVencido('%s no terminó dentro de su plazo' % self.host)
        return segundos

    def _conectar(self, direccion, *_):
        """El socket conectado a la primera dirección de `direccion` (host, puerto) que responda, con settimeout en lo
        que queda para el handshake TLS. Todo socket que falla se cierra."""
        host, puerto = direccion
        direcciones = resolver(host, puerto, self.queda())
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

    def __init__(self, plazo, cronometro):
        super().__init__(context=_contexto())
        self._conexion = functools.partial(_Conexion, plazo=plazo, cronometro=cronometro)

    def https_open(self, req):
        return self.do_open(self._conexion, req, context=self._context)


class _SinRedirecciones(urllib.request.HTTPRedirectHandler):
    """Ninguna redirección se sigue: lanza Redirigida."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        with contextlib.suppress(Exception):
            fp.close()
        raise Redirigida(code, urllib.parse.urlsplit(req.full_url).hostname)


def abrir(req, plazo, cronometro):
    """La respuesta a `req`, con _Https, _SinRedirecciones y sin proxies (un ProxyHandler vacío, que build_opener ya no
    agrega con los del entorno). Las pruebas la cambian por una respuesta simulada."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _SinRedirecciones,
                                       _Https(plazo, cronometro)).open(req)


def descargar(req, plazo, tope, cronometro=None):
    """El cuerpo de la respuesta a `req`, que tiene que ser https, de a lo más `tope` bytes y todo antes de `plazo`.

    Lee por bloques (read1, una lectura del socket a la vez) y revisa el plazo antes de cada uno. Lanza PlazoVencido si
    se pasa, también cuando un timeout del socket llega con el plazo ya vencido, Redirigida con un 3xx y ValueError si
    la respuesta pasa de `tope`. El HTTPError de un 4xx o un 5xx y el OSError de la red salen tal cual."""
    cronometro = cronometro or time.monotonic
    if req.type != 'https':
        raise ValueError('solo se pide por https: %s' % req.full_url)
    partes, total = [], 0
    try:
        with abrir(req, plazo, cronometro) as r:
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
