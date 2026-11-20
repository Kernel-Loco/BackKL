"""Contraseñas con argon2id (OWASP ASVS V2.4). Nunca se guardan ni se registran en claro.

La huella argon2id (cadena PHC) se guarda cifrada con AES-256-GCM y una llave que vive fuera de la base (pepper,
RC-330): con un volcado de la base no se pueden probar contraseñas fuera de línea. El id del usuario va como dato
asociado, así que la huella de una cuenta copiada a otra no abre. Se cifra en vez de pasar la contraseña por un HMAC
antes de argon2id porque así la llave se puede rotar sin que nadie rehaga su contraseña (OWASP Password Storage Cheat
Sheet). Formato guardado: 'lt<versión>$' + base64 url-safe de nonce (12 bytes) + cifrado. La versión es la de la
llave que la cifró (RC-333): 'lt1$' la primera, 'lt2$' después de la primera rotación.

Una huella vieja sin cifrar ('$argon2id$...') todavía entra, y `needs_rehash` hace que el login la guarde cifrada en
ese mismo inicio de sesión (cirdan/auth/routes.py). Lo mismo pasa con una huella de la versión anterior mientras la
llave anterior esté puesta. El hash de relleno de las semillas y de demo.py tiene la forma sin cifrar pero no es
verificable, así que sigue sin abrir nada.

La llave sale de una de dos variables, nunca de las dos, como la del MFA (cirdan/auth/totp.py):
- `PASSWORD_HASH_KEY_VAULT_SECRET_URL`: en la VM, el secreto de Azure Key Vault que se lee con la identidad
  administrada (cirdan/auth/keyvault.py, docs/despliegue.md). Se lee una vez por proceso y queda solo en memoria.
- `PASSWORD_HASH_ENCRYPTION_KEY`: la llave misma, en el `.env` de desarrollo, del CI y del plan B.
Es otra llave que la del MFA, para no amarrar sus rotaciones. Se comparan los bytes de las dos: `_variables` cuando las
dos van en el .env y `comprobar_llave`, al arrancar la API, en todos los casos.

Rotar (RC-333, docs/despliegue.md): `PASSWORD_HASH_KEY_VERSION` sube en 1, la llave nueva va en las variables de
arriba y la de antes en `PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL` o `PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY`, con la
misma regla de una sola de las dos. Con ella puesta, una huella de la versión anterior entra y el login la vuelve a
cifrar con la actual. `python -m cirdan.auth.rotar_huellas` cifra con la actual las que falten sin pedir contraseñas.
La llave anterior no puede ser la actual ni la del MFA.

Contraseñas filtradas (RC-334): `revisar_nueva` junta la lista local de RC-281 y la API por rango de Pwned Passwords,
que solo recibe los 5 primeros caracteres hex del SHA-1 (k-anonimato). Se prende con `PWNED_PASSWORDS_ENABLED=true`.
"""
import base64
import binascii
import hashlib
import hmac
import http.client
import io
import logging
import os
import re
import ssl
import threading
import time
import urllib.parse
import uuid
from collections import namedtuple
from functools import cache
from pathlib import Path

from argon2 import PasswordHasher, profiles
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cirdan.auth import keyvault
from cirdan.config import config

log = logging.getLogger(__name__)

MIN_LENGTH = 12   # misma política que el portal (src/lib/validation.ts)
MAX_LENGTH = 128

VIEJA = '$argon2id$'
VARIABLE_URL = 'PASSWORD_HASH_KEY_VAULT_SECRET_URL'
VARIABLE_LLAVE = 'PASSWORD_HASH_ENCRYPTION_KEY'
VARIABLE_VERSION = 'PASSWORD_HASH_KEY_VERSION'
VARIABLE_URL_ANTERIOR = 'PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL'
VARIABLE_LLAVE_ANTERIOR = 'PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY'
MAX_VERSION = 9999
_VERSION = re.compile(r'[1-9][0-9]{0,3}')
_FORMATO = re.compile(r'lt([1-9][0-9]{0,3})\$')

# Fijos: t=3, m=64 MiB, p=4, los mismos que daba PasswordHasher() de argon2-cffi 25.1.0. Así una versión nueva de la
# librería no los cambia sin que nadie lo note (RFC 9106, segunda recomendación).
PARAMETROS = profiles.RFC_9106_LOW_MEMORY
_hasher = PasswordHasher.from_parameters(PARAMETROS)

# Relleno: con un correo que no existe se verifica contra una huella cifrada de esta contraseña, para que la respuesta
# tarde lo mismo que con una contraseña equivocada (descifrar y argon2id) y no se puedan adivinar correos.
_RELLENO = 'lowtide-relleno-que-nunca-coincide'
_ID_RELLENO = '00000000-0000-4000-8000-000000000000'

_llave_vault = None           # (url, llave) de la actual leída de Key Vault
_llave_vault_anterior = None  # lo mismo para la anterior
_relleno = None  # (llave, versión, huella cifrada del relleno)
_phc_relleno = None  # cadena PHC del relleno, sin cifrar: no depende de la llave
_candado = threading.Lock()

Variables = namedtuple('Variables', 'version url llave url_anterior llave_anterior')


def prefijo(version):
    """'lt1$' para la versión 1."""
    return 'lt%d$' % version


def version_de(huella):
    """La versión de la llave de una huella cifrada ('lt2$...' da 2), o None si no tiene esa forma."""
    m = _FORMATO.match(huella) if isinstance(huella, str) else None
    return int(m.group(1)) if m else None


def es_cifrada(huella):
    """True si la huella tiene la forma 'lt<versión>$', de cualquier versión."""
    return version_de(huella) is not None


def _decodificar(valor, origen):
    try:
        key = base64.urlsafe_b64decode(valor)
    except (binascii.Error, ValueError):
        key = b''
    if len(key) != 32:
        raise RuntimeError('%s debe ser de 32 bytes en base64 url-safe' % origen)
    return key


def _llave_del_mfa():
    """Los bytes de TOTP_ENCRYPTION_KEY, o None si no está o no se decodifica (de eso se queja cirdan/auth/totp.py)."""
    valor = config('TOTP_ENCRYPTION_KEY')
    try:
        return _decodificar(valor, 'TOTP_ENCRYPTION_KEY') if valor else None
    except RuntimeError:
        return None


def _secreto(url):
    """(bóveda, nombre) del secreto de una URL de Key Vault, sin la versión y en minúsculas, porque Key Vault no
    distingue mayúsculas en esos nombres. Dos versiones del mismo secreto son el mismo secreto."""
    try:
        partes = urllib.parse.urlsplit(url)
    except ValueError:
        return url, None
    return (partes.hostname or '').lower(), (partes.path.split('/')[2:3] or [''])[0].lower()


def _version():
    valor = (config(VARIABLE_VERSION) or '').strip() or '1'
    if not _VERSION.fullmatch(valor):
        raise RuntimeError('%s debe ser un número entero de 1 a %d' % (VARIABLE_VERSION, MAX_VERSION))
    return int(valor)


def _una(variable_url, variable_llave, obligatoria):
    """(url, None), (None, llave directa ya decodificada) o, si no es obligatoria y no viene ninguna, (None, None)."""
    url = config(variable_url)
    directa = config(variable_llave)
    if url and directa:
        raise RuntimeError('%s y %s están puestas: con Key Vault, quita %s del .env'
                           % (variable_url, variable_llave, variable_llave))
    if not url and not directa:
        if obligatoria:
            raise RuntimeError('Falta %s o %s: copia .env.example como .env y llena sus valores'
                               % (variable_llave, variable_url))
        return None, None
    if directa:
        return None, _decodificar(directa, variable_llave)
    return url, None


def _variables():
    """Las variables de las llaves ya revisadas, o RuntimeError. Vacía cuenta como sin poner. No usa la red."""
    version = _version()
    url, llave = _una(VARIABLE_URL, VARIABLE_LLAVE, True)
    url_ant, llave_ant = _una(VARIABLE_URL_ANTERIOR, VARIABLE_LLAVE_ANTERIOR, False)
    mfa = _llave_del_mfa()
    otra = config('TOTP_KEY_VAULT_SECRET_URL')
    if llave is not None and mfa is not None and hmac.compare_digest(llave, mfa):
        raise RuntimeError('%s debe ser otra llave que TOTP_ENCRYPTION_KEY' % VARIABLE_LLAVE)
    if url and otra and _secreto(url) == _secreto(otra):
        raise RuntimeError('%s debe ser otro secreto que TOTP_KEY_VAULT_SECRET_URL, no otra versión del mismo'
                           % VARIABLE_URL)
    if url_ant or llave_ant is not None:
        variable_ant = VARIABLE_URL_ANTERIOR if url_ant else VARIABLE_LLAVE_ANTERIOR
        if version == 1:
            raise RuntimeError('%s está puesta con %s en 1: la anterior es la de la versión %s menos 1, sube %s'
                               % (variable_ant, VARIABLE_VERSION, VARIABLE_VERSION, VARIABLE_VERSION))
        if llave_ant is not None:
            if llave is not None and hmac.compare_digest(llave_ant, llave):
                raise RuntimeError('%s es la misma llave que %s' % (VARIABLE_LLAVE_ANTERIOR, VARIABLE_LLAVE))
            if mfa is not None and hmac.compare_digest(llave_ant, mfa):
                raise RuntimeError('%s debe ser otra llave que TOTP_ENCRYPTION_KEY' % VARIABLE_LLAVE_ANTERIOR)
        else:
            if url and url_ant == url:
                raise RuntimeError('%s es la misma URL que %s' % (VARIABLE_URL_ANTERIOR, VARIABLE_URL))
            if otra and _secreto(url_ant) == _secreto(otra):
                raise RuntimeError('%s debe ser otro secreto que TOTP_KEY_VAULT_SECRET_URL, no otra versión del mismo'
                                   % VARIABLE_URL_ANTERIOR)
    return Variables(version, url, llave, url_ant, llave_ant)


def revisar_variables():
    """Sin red ni Key Vault: la versión, que venga una sola de las dos variables de cada llave y que las llaves
    directas sean de 32 bytes y distintas entre sí y de la del MFA. La usa el script de demo, que corre antes que la
    API, para que `docker compose up` falle con este mensaje en vez de dejar la API reiniciándose."""
    _variables()


def llave_en_key_vault():
    """True si la llave actual sale de Key Vault. Sin red: la usa el script de demo, que en la VM no llega a IMDS."""
    return _variables().url is not None


def version_actual():
    """La versión de la llave actual (`PASSWORD_HASH_KEY_VERSION`, 1 si no está). Sin red."""
    return _variables().version


def _de_key_vault(cache_nombre, url, variable):
    with _candado:
        guardada = globals()[cache_nombre]
        if guardada is None or guardada[0] != url:
            secreto = keyvault.leer_secreto(url, variable=variable)
            guardada = (url, _decodificar(secreto, 'El secreto de Key Vault de ' + variable))
            globals()[cache_nombre] = guardada
        return guardada[1]


def _key():
    v = _variables()
    if v.llave is not None:
        return v.llave
    return _de_key_vault('_llave_vault', v.url, VARIABLE_URL)


def _llave_anterior():
    """Los bytes de la llave anterior, o None si no está puesta."""
    v = _variables()
    if v.llave_anterior is not None:
        return v.llave_anterior
    if v.url_anterior:
        return _de_key_vault('_llave_vault_anterior', v.url_anterior, VARIABLE_URL_ANTERIOR)
    return None


def _llave_de(version):
    """La llave con la que se abre una huella de `version`: la actual, la anterior si está puesta y es la versión de
    antes, o None con cualquier otra."""
    actual = version_actual()
    if version == actual:
        return _key()
    if version == actual - 1:
        return _llave_anterior()
    return None


def _dato_asociado(user_id):
    """El id del usuario en su forma canónica: '...-ABC' y '...-abc' cifran igual. ValueError si no es un UUID."""
    return str(uuid.UUID(str(user_id))).encode()


def _cifrar(phc, user_id, key, version):
    nonce = os.urandom(12)
    blob = nonce + AESGCM(key).encrypt(nonce, phc.encode(), _dato_asociado(user_id))
    return prefijo(version) + base64.urlsafe_b64encode(blob).decode()


def _abrir(guardada, user_id, key, version):
    try:
        blob = base64.b64decode(guardada[len(prefijo(version)):], altchars=b'-_', validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(blob) < 12 + 16:
        return None
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], _dato_asociado(user_id)).decode()
    except (InvalidTag, ValueError):
        return None


def _descifrar(guardada, user_id):
    """La cadena PHC de una huella 'lt<versión>$', o None si no abre con la llave de su versión y este usuario, o si
    su versión no es la actual ni, con la anterior puesta, la de antes."""
    version = version_de(guardada)
    if version is None:
        return None
    key = _llave_de(version)
    if key is None:
        return None
    return _abrir(guardada, user_id, key, version)


def recifrar(guardada, user_id):
    """La huella de la versión anterior cifrada otra vez con la actual, con la misma cadena PHC (sin pedir la
    contraseña), o None si no es de la versión anterior, no está la llave anterior o no abre. Para
    cirdan/auth/rotar_huellas.py."""
    actual = version_actual()
    if version_de(guardada) != actual - 1:
        return None
    anterior = _llave_anterior()
    if anterior is None:
        return None
    phc = _abrir(guardada, user_id, anterior, actual - 1)
    if phc is None:
        return None
    return _cifrar(phc, user_id, _key(), actual)


def _relleno_phc():
    global _phc_relleno
    with _candado:
        if _phc_relleno is None:
            _phc_relleno = _hasher.hash(_RELLENO)
        return _phc_relleno


def _huella_relleno():
    global _relleno
    key = _key()
    version = version_actual()
    phc = _relleno_phc()
    with _candado:
        if _relleno is None or _relleno[0] != key or _relleno[1] != version:
            _relleno = (key, version, _cifrar(phc, _ID_RELLENO, key, version))
        return _relleno[2]


def comprobar_llave(llave_mfa=None):
    """Al arrancar la API: sin llave válida no arranca, en vez de fallar en el primer inicio de sesión. Con
    `llave_mfa`, los bytes que devuelve totp.comprobar_llave(), tampoco arranca si las dos son la misma, aunque una
    venga del .env y la otra de Key Vault. Con la llave anterior puesta, la lee y no arranca si es la actual o la del
    MFA (RC-333). También deja lista la huella de relleno, para que el primer correo inexistente no tarde un argon2id
    de más."""
    key = _key()
    en_vault = llave_en_key_vault()
    if llave_mfa is not None and hmac.compare_digest(key, llave_mfa):
        variable = VARIABLE_URL if en_vault else VARIABLE_LLAVE
        raise RuntimeError('%s da la misma llave que la del MFA: las huellas van con otra llave' % variable)
    anterior = _llave_anterior()
    if anterior is not None:
        variable = VARIABLE_URL_ANTERIOR if _variables().url_anterior else VARIABLE_LLAVE_ANTERIOR
        if hmac.compare_digest(anterior, key):
            raise RuntimeError('%s da la misma llave que la actual: pon ahí la de antes de rotar' % variable)
        if llave_mfa is not None and hmac.compare_digest(anterior, llave_mfa):
            raise RuntimeError('%s da la misma llave que la del MFA' % variable)
    _huella_relleno()


def hash_password(password, user_id):
    """Huella 'lt<versión actual>$' de `password` para el usuario `user_id`: argon2id y luego AES-256-GCM."""
    return _cifrar(_hasher.hash(password), user_id, _key(), version_actual())


def _verificar_phc(phc, password):
    try:
        return _hasher.verify(phc, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_password(password_hash, password, user_id):
    """True si `password` abre la huella guardada de `user_id`. Acepta la huella cifrada de la versión actual, la de
    la anterior si su llave está puesta y la vieja sin cifrar.

    Una huella que no abre (otra llave, otra versión, otro id, dañada o de otra forma) gasta igual un argon2id, el del
    relleno: así ese correo no responde más rápido que uno que no existe (punto 5 de RC-330 y punto 4 de RC-333)."""
    phc = None
    if isinstance(password_hash, str):
        if es_cifrada(password_hash):
            phc = _descifrar(password_hash, user_id)
        elif password_hash.startswith(VIEJA):
            phc = password_hash
    if phc is None:
        _verificar_phc(_relleno_phc(), password)
        return False
    return _verificar_phc(phc, password)


COMMON_FILE = Path(__file__).resolve().parent / 'datos' / 'contrasenas_comunes.txt'


@cache
def _common():
    """Las contraseñas comunes de COMMON_FILE (RC-281), en minúsculas. Una por línea, sin comentarios: una contraseña
    también puede empezar con '#'. La fuente y la licencia están en cirdan/auth/datos/README.md."""
    with COMMON_FILE.open(encoding='utf-8') as archivo:
        return frozenset(linea.rstrip('\r\n').casefold() for linea in archivo if linea.rstrip('\r\n'))


def is_common(password):
    """True si `password` está en la lista de contraseñas comunes, sin importar mayúsculas (RC-281, ASVS 5.0 nivel 1).
    Sin red. Es el respaldo de la revisión contra Pwned Passwords (`revisar_nueva`)."""
    return password.casefold() in _common()


# Pwned Passwords (RC-334): https://haveibeenpwned.com/API/v3#PwnedPasswords. Gratis, sin cuenta ni llave.
PWNED_VARIABLE = 'PWNED_PASSWORDS_ENABLED'
PWNED_HOST = 'api.pwnedpasswords.com'
PWNED_RUTA = '/range/'
PWNED_PLAZO = 2.0     # segundos: sin respuesta completa en ese tiempo, se sigue solo con la lista local
PWNED_TOPE = 1 << 20  # bytes: un rango con relleno trae unos 40 KB
PWNED_MIN_LINEAS = 800  # con relleno la API manda de 800 a 1000 líneas por rango
PWNED_EN_CURSO = 4    # consultas a la vez: con la API caída, una más no espera ni deja otro hilo colgado
_pwned_cupo = threading.BoundedSemaphore(PWNED_EN_CURSO)
_tls = ssl.create_default_context()
_RANGO = re.compile(r'([0-9A-Fa-f]{35}):([0-9]{1,12})')


def pwned_prendida():
    """True si `PWNED_PASSWORDS_ENABLED` es true. Apagada por omisión y en el CI. Prendida en la VM
    (docker-compose.despliegue.yml)."""
    return (config(PWNED_VARIABLE) or 'false').strip().lower() == 'true'


class SinRespuesta(Exception):
    """Pwned Passwords no respondió bien. El texto nunca lleva la contraseña ni su SHA-1."""


class _Lector(io.RawIOBase):
    """La lectura cruda del socket con `queda()` antes de cada recv: el tope total vale también para la línea de estado
    y los encabezados, que getresponse() lee con readline en varios recv."""

    def __init__(self, crudo, queda):
        super().__init__()
        self._crudo, self._queda = crudo, queda

    def readable(self):
        return True

    def readinto(self, b):
        self._queda()
        return self._crudo.readinto(b)

    def close(self):
        if not self.closed:
            self._crudo.close()
        super().close()


class _ConTope:
    """El socket de la conexión para getresponse(): makefile() da un lector con tope y lo demás va al socket."""

    def __init__(self, sock, queda):
        self._sock, self._queda = sock, queda

    def makefile(self, mode='rb', *args, **kw):
        # Con buffering=0 el socket da su SocketIO y cuenta la referencia como siempre: con 'Connection: close' el
        # socket se cierra cuando la respuesta termina, no antes.
        return io.BufferedReader(_Lector(self._sock.makefile(mode, buffering=0), self._queda))

    def __getattr__(self, nombre):
        return getattr(self._sock, nombre)


def _pedir_rango(cabeza):
    """El cuerpo de GET /range/<cabeza>, con relleno. Solo sale `cabeza`, los 5 primeros caracteres hex del SHA-1."""
    # Un tope de tiempo para todo desde antes de conectar: una respuesta que llega gota a gota, también en los
    # encabezados, no deja el hilo colgado ni su lugar en el cupo tomado. El DNS y el saludo TLS solo tienen el
    # timeout de cada operación, y filtrada() no los espera más de PWNED_PLAZO.
    fin = time.monotonic() + 2 * PWNED_PLAZO
    sock = None

    def queda():
        restante = fin - time.monotonic()
        if restante <= 0:
            raise SinRespuesta('respuesta de más de %.0f s' % (2 * PWNED_PLAZO))
        # El timeout del socket se reinicia con cada recv: se baja a lo que queda del tope. Con 'Connection: close'
        # o HTTP/1.0 el socket se cierra al leer el último byte (fileno -1) y settimeout daría OSError.
        if sock is not None and sock.fileno() != -1:
            sock.settimeout(min(PWNED_PLAZO, restante))

    conexion = http.client.HTTPSConnection(PWNED_HOST, timeout=PWNED_PLAZO, context=_tls)
    try:
        conexion.request('GET', PWNED_RUTA + cabeza, headers={
            'Add-Padding': 'true', 'User-Agent': 'LowTide', 'Accept': 'text/plain'})
        # Se guarda aquí: con 'Connection: close', getresponse() suelta conexion.sock y la respuesta sigue leyendo
        # del mismo socket.
        sock = getattr(conexion, 'sock', None)
        if sock is not None:
            conexion.sock = _ConTope(sock, queda)
        queda()
        respuesta = conexion.getresponse()
        if respuesta.status != 200:
            raise SinRespuesta('HTTP %d' % respuesta.status)
        partes, total = [], 0
        while True:
            queda()
            # read1 vuelve con lo que trae un solo recv. read(n) junta recv hasta llenar n bytes y no deja revisar el
            # tope entre uno y otro.
            parte = respuesta.read1(16384)
            if not parte:
                break
            total += len(parte)
            if total > PWNED_TOPE:
                raise SinRespuesta('respuesta de más de %d bytes' % PWNED_TOPE)
            partes.append(parte)
        # Con Content-Length, http.client no avisa si la conexión se cerró antes de tiempo: queda lo que faltaba.
        if respuesta.length:
            raise SinRespuesta('respuesta cortada')
        cuerpo = b''.join(partes).decode('ascii')
        # Con 'Add-Padding: true' la API manda siempre de 800 a 1000 líneas. Menos es una respuesta incompleta, que
        # podría no traer la línea de la contraseña.
        if len(cuerpo.splitlines()) < PWNED_MIN_LINEAS:
            raise SinRespuesta('respuesta de menos de %d líneas' % PWNED_MIN_LINEAS)
        return cuerpo
    finally:
        conexion.close()


def _sale_en(cuerpo, cola):
    """True si `cola` (los 35 caracteres hex que siguen del SHA-1) sale en el rango con un conteo mayor que 0. Las
    líneas de relleno traen 0 y no cuentan. SinRespuesta si una línea no tiene la forma SUFIJO:CONTEO."""
    sale = False
    for linea in cuerpo.splitlines():
        linea = linea.strip()
        if not linea:
            continue
        m = _RANGO.fullmatch(linea)
        if not m:
            raise SinRespuesta('línea del rango con otra forma')
        if int(m.group(2)) > 0 and hmac.compare_digest(m.group(1).upper(), cola):
            sale = True
    return sale


def filtrada(password):
    """True si `password` sale en Pwned Passwords, False si no y None si la API no respondió en PWNED_PLAZO
    segundos o respondió mal. Manda solo los 5 primeros caracteres hex del SHA-1 y compara el resto aquí. Ni la
    contraseña ni el SHA-1 completo salen de esta función ni van al log.

    El SHA-1 lo pide el protocolo de k-anonimato de la API (no guarda nada): no es la huella de la contraseña, que
    sigue siendo argon2id."""
    digest = hashlib.sha1(password.encode('utf-8'), usedforsecurity=False).hexdigest().upper()
    cabeza, cola = digest[:5], digest[5:]
    if not _pwned_cupo.acquire(blocking=False):
        log.warning('Pwned Passwords: ya hay %d consultas sin respuesta, se revisa solo con la lista local',
                    PWNED_EN_CURSO)
        return None
    resultado = {}

    def consultar():
        try:
            resultado['cuerpo'] = _pedir_rango(cabeza)
        except Exception as e:  # la causa va al log sin el texto, que podría traer la ruta
            resultado['error'] = type(e).__name__
        finally:
            _pwned_cupo.release()

    # En un hilo para que el plazo cuente todo, también el DNS, que no respeta el timeout del socket. Si se pasa, el
    # hilo termina solo con el timeout del socket y libera su lugar en el cupo.
    hilo = threading.Thread(target=consultar, name='pwned-passwords', daemon=True)
    hilo.start()
    hilo.join(PWNED_PLAZO)
    cuerpo = resultado.get('cuerpo')
    if cuerpo is None:
        log.warning('Pwned Passwords no respondió en %.0f s (%s): se revisa solo con la lista local',
                    PWNED_PLAZO, resultado.get('error', 'sin respuesta'))
        return None
    try:
        return _sale_en(cuerpo, cola)
    except SinRespuesta as e:
        log.warning('Pwned Passwords respondió con otra forma (%s): se revisa solo con la lista local', e)
        return None


Revision = namedtuple('Revision', 'problema sin_respuesta')


def revisar_nueva(password, permitir=None):
    """Revisa una contraseña nueva antes de guardarla: cambio de contraseña y, cuando existan, alta y restablecimiento
    (RC-227, RC-317 y la recuperación por correo).

    Devuelve Revision(problema, sin_respuesta). `problema` es 'comun' si está en la lista local (RC-281), 'filtrada'
    si sale en Pwned Passwords y None si se puede usar. `sin_respuesta` es True si la revisión de Pwned Passwords
    estaba prendida y la API no respondió: quien llama deja el evento en audit_log. Con la revisión apagada, o si ya
    es común, no se consulta la API. `permitir`, si viene, se llama justo antes de consultarla: con False no se
    consulta y se sigue como sin respuesta (el tope por usuario de routes.py)."""
    if is_common(password):
        return Revision('comun', False)
    if not pwned_prendida():
        return Revision(None, False)
    if permitir is not None and not permitir():
        return Revision(None, True)
    sale = filtrada(password)
    if sale is None:
        return Revision(None, True)
    return Revision('filtrada' if sale else None, False)


def burn_time(password):
    """Gasta el mismo tiempo que una verificación real (correo inexistente): descifrar y argon2id."""
    verify_password(_huella_relleno(), password, _ID_RELLENO)


def needs_rehash(password_hash, user_id):
    """True si hay que volver a guardar la huella: sin cifrar, de otra versión de la llave, que no abre o con otros
    parámetros de argon2id."""
    if version_de(password_hash) != version_actual():
        return True
    phc = _descifrar(password_hash, user_id)
    if phc is None:
        return True
    try:
        return _hasher.check_needs_rehash(phc)
    except InvalidHashError:
        return True
