"""Lectura de un secreto de Azure Key Vault con la identidad administrada de la VM (#49, RC-91).

Solo la usa la llave del MFA (`TOTP_KEY_VAULT_SECRET_URL`, ver `cirdan/auth/totp.py` y docs/despliegue.md). Pide un
token al servicio de metadatos de Azure (IMDS, 169.254.169.254, que solo responde dentro de la VM) y con él lee el
secreto por la API REST de Key Vault. Sin dependencias nuevas: urllib, sin proxy y sin seguir redirecciones, para que
el token no salga hacia otro servidor. Ningún mensaje de error lleva el token ni el valor del secreto.
"""
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

IMDS_TOKEN = ('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource='
              + urllib.parse.quote('https://vault.azure.net', safe=''))
API_VERSION = '7.4'
TIMEOUT = 5
# IMDS pide reintentar con 404 (la identidad aún no está lista al arrancar la VM), 410, 429 y 5xx.
REINTENTAR = {404, 410, 429, 500, 502, 503, 504}
ESPERAS = (1, 2, 4)

# https://<bóveda>.vault.azure.net/secrets/<nombre>[/<versión>], sin puerto, usuario, consulta ni fragmento.
# Nombre de bóveda: 3 a 24 letras, números o guiones. Nombre de secreto: 1 a 127 letras, números o guiones.
_RUTA = re.compile(r'/secrets/[0-9A-Za-z-]{1,127}(/[0-9a-f]{32})?')
_BOVEDA = re.compile(r'[a-z0-9-]{3,24}\.vault\.azure\.net')


class _SinRedireccion(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib responde con el HTTPError de la redirección


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SinRedireccion)


def _abrir(req):
    """Hace la petición y devuelve el JSON. Punto único de red, para que las pruebas lo reemplacen."""
    with _opener.open(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode('utf-8'))


def validar_url(url):
    """La URL del secreto, o RuntimeError si no es de Key Vault. Se revisa antes de mandar el token."""
    error = RuntimeError('TOTP_KEY_VAULT_SECRET_URL debe ser https://<bóveda>.vault.azure.net/secrets/<nombre>')
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


def _con_reintentos(req, que):
    for i, espera in enumerate((0,) + ESPERAS):
        time.sleep(espera)
        try:
            return _abrir(req)
        except urllib.error.HTTPError as e:
            codigo = e.code
            e.close()
            if codigo not in REINTENTAR or i == len(ESPERAS):
                raise RuntimeError('%s respondió HTTP %s' % (que, codigo)) from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            if i == len(ESPERAS):
                raise RuntimeError('%s no respondió (%s)' % (que, type(e).__name__)) from None


def leer_secreto(url):
    """Valor del secreto de Key Vault en `url` con la identidad administrada de la VM."""
    url = validar_url(url)
    req = urllib.request.Request(IMDS_TOKEN, headers={'Metadata': 'true'})
    token = _con_reintentos(req, 'La identidad administrada (IMDS)')
    token = token.get('access_token') if isinstance(token, dict) else None
    if not isinstance(token, str) or not token:
        raise RuntimeError('La identidad administrada (IMDS) no devolvió un token')
    req = urllib.request.Request(url + '?api-version=' + API_VERSION)
    # Encabezado sin redirección: urllib no lo copia si alguna vez siguiera una.
    req.add_unredirected_header('Authorization', 'Bearer ' + token)
    del token
    datos = _con_reintentos(req, 'Key Vault')
    valor = datos.get('value') if isinstance(datos, dict) else None
    if not isinstance(valor, str) or not valor:
        raise RuntimeError('Key Vault no devolvió el valor del secreto')
    return valor
