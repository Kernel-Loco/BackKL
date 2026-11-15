"""Lectura de un secreto de Azure Key Vault con la identidad administrada de la VM (#49, RC-91).

Solo la usa la llave del MFA (`TOTP_KEY_VAULT_SECRET_URL`, ver `cirdan/auth/totp.py` y docs/despliegue.md). Pide un
token al servicio de metadatos de Azure (IMDS, 169.254.169.254, que solo responde dentro de la VM) y con él lee el
secreto por la API REST de Key Vault. Sin dependencias nuevas: urllib, sin proxy y sin seguir redirecciones, para que
el token no salga hacia otro servidor. Ningún mensaje de error lleva el token ni el valor del secreto, y los errores
salen sin el error de urllib encadenado ni el token en el traceback.
"""
import http.client
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

IMDS_TOKEN = ('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource='
              + urllib.parse.quote('https://vault.azure.net', safe=''))
API_VERSION = '7.4'
# Por intento: conectar, cada lectura del socket y el cuerpo completo. La resolución DNS del nombre de la bóveda no
# la limita: queda en manos del resolvedor del contenedor.
TIMEOUT = 5
# Toda la lectura, IMDS y Key Vault juntos. IMDS puede responder 410 hasta unos 70 s mientras se actualiza. El
# HEALTHCHECK del Dockerfile da más margen que esto (pruebas/test_despliegue.py lo revisa).
PLAZO = 90
# IMDS pide reintentar con 404 (la identidad aún no está lista al arrancar la VM), 410, 429 y 5xx. En la bóveda un 404
# es permanente (SecretNotFound: nombre o versión mal copiados) y sale en seco, sin gastar el plazo.
REINTENTAR = frozenset({404, 410, 429, 500, 502, 503, 504})
REINTENTAR_VAULT = REINTENTAR - {404}
ESPERAS = (1, 2, 4, 8, 16, 16, 16, 16)
MAXIMO = 64 * 1024  # bytes de una respuesta: un token o un secreto caben de sobra

# https://<bóveda>.vault.azure.net/secrets/<nombre>/<versión>, sin puerto, usuario, consulta ni fragmento. La versión
# es obligatoria: así cargar otro valor en la bóveda no cambia la llave que lee la API sin que alguien edite el .env.
# Nombre de bóveda: 3 a 24 letras, números o guiones. Nombre de secreto: 1 a 127 letras, números o guiones.
_RUTA = re.compile(r'/secrets/[0-9A-Za-z-]{1,127}/[0-9a-f]{32}')
_BOVEDA = re.compile(r'[a-z0-9-]{3,24}\.vault\.azure\.net')

# Puntos de tiempo, para que las pruebas los reemplacen sin tocar el módulo time de todo el proceso.
_reloj = time.monotonic
_dormir = time.sleep


class _SinRedireccion(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib responde con el HTTPError de la redirección


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SinRedireccion)


def _abrir(req, timeout):
    """Hace la petición y devuelve el JSON. Punto único de red, para que las pruebas lo reemplacen. El cuerpo se lee
    por partes y con `timeout` para todo, para que una respuesta que llega gota a gota no lo alargue."""
    fin = _reloj() + timeout
    partes, total = [], 0
    with _opener.open(req, timeout=timeout) as resp:
        while True:
            if _reloj() > fin:
                raise TimeoutError('respuesta lenta')
            parte = resp.read1(16384)
            if not parte:
                break
            total += len(parte)
            if total > MAXIMO:
                raise ValueError('respuesta demasiado grande')
            partes.append(parte)
    return json.loads(b''.join(partes).decode('utf-8'))


def validar_url(url):
    """La URL del secreto, o RuntimeError si no es de Key Vault. Se revisa antes de mandar el token."""
    error = RuntimeError('TOTP_KEY_VAULT_SECRET_URL debe ser https://<bóveda>.vault.azure.net/secrets/<nombre>/'
                         '<versión>')
    # urlsplit quita espacios y controles del principio y de en medio: aquí no se aceptan.
    if not isinstance(url, str) or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
        raise error
    try:
        partes = urllib.parse.urlsplit(url)
        puerto = partes.port
    except ValueError:
        raise error from None
    if (partes.scheme != 'https' or partes.username is not None or partes.password is not None
            or puerto is not None or partes.query or partes.fragment
            or not _BOVEDA.fullmatch(partes.hostname or '') or partes.netloc.lower() != partes.hostname
            or not _RUTA.fullmatch(partes.path)):
        raise error
    return url


def _con_reintentos(req, que, fin, reintentar):
    """El JSON de `req`, con reintentos hasta `fin` (de `_reloj`) para los códigos HTTP de `reintentar`. El
    RuntimeError sale fuera del `except`, sin el error de urllib en __context__."""
    fallo = 'no respondió a tiempo'
    for espera in (0,) + ESPERAS:
        if espera:
            if _reloj() + espera >= fin:
                break
            _dormir(espera)
        restante = fin - _reloj()
        if restante <= 0:
            break
        try:
            return _abrir(req, min(TIMEOUT, restante))
        except urllib.error.HTTPError as e:
            codigo = e.code
            e.close()
            fallo = 'respondió HTTP %s' % codigo
            if codigo not in reintentar:
                break
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as e:
            fallo = 'no respondió (%s)' % type(e).__name__
    raise RuntimeError('%s %s' % (que, fallo))


def leer_secreto(url):
    """Valor del secreto de Key Vault en `url` con la identidad administrada de la VM."""
    url = validar_url(url)
    fin = _reloj() + PLAZO
    req = urllib.request.Request(IMDS_TOKEN, headers={'Metadata': 'true'})
    token = _con_reintentos(req, 'La identidad administrada (IMDS)', fin, REINTENTAR)
    token = token.get('access_token') if isinstance(token, dict) else None
    if not isinstance(token, str) or not token:
        raise RuntimeError('La identidad administrada (IMDS) no devolvió un token')
    req = urllib.request.Request(url + '?api-version=' + API_VERSION)
    # Encabezado sin redirección: urllib no lo copia si alguna vez siguiera una.
    req.add_unredirected_header('Authorization', 'Bearer ' + token)
    del token
    try:
        datos = _con_reintentos(req, 'Key Vault', fin, REINTENTAR_VAULT)
    finally:
        # Los frames de un traceback guardan `req`: sin esto el token seguiría ahí.
        req.unredirected_hdrs.pop('Authorization', None)
    valor = datos.get('value') if isinstance(datos, dict) else None
    if not isinstance(valor, str) or not valor:
        raise RuntimeError('Key Vault no devolvió el valor del secreto')
    return valor
