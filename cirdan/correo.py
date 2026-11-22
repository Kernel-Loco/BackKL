"""Envío del enlace para entrar por correo (#28, RC-63) con la API HTTPS de Resend (RC-170).

Sin SMTP ni puerto 25: las VM bloquean el 25 de salida, y Resend Free se usa por HTTPS. El remitente es
acceso@lowtidesec.com, con SPF, DKIM y DMARC en lowtidesec.com (docs/servicios_externos.md, fila Correo). La llave
de envío está limitada al dominio y va en `.env` como CORREO_API_KEY, nunca en el repo.

Plan B de RC-327 (decisión 7): si Resend no acepta el envío (429, 401, 403, 5xx o sin respuesta) o falta la llave, el
enlace no sale, la respuesta al portal es la misma y queda un aviso en el log con el motivo. Nunca con el correo, el
token ni el enlace. Sin reintentos ni segundo proveedor.

El correo solo lleva el enlace y cuánto dura. CORREO_API_URL existe solo para que las pruebas apunten a un servidor
simulado; en la VM queda la de Resend.
"""
import html
import json
import logging
import urllib.error
import urllib.request

from cirdan.config import config

log = logging.getLogger(__name__)

API_URL = 'https://api.resend.com/emails'
REMITENTE = 'LowTide <acceso@lowtidesec.com>'
PLAZO_SEGUNDOS = 10
ASUNTO = 'Tu enlace para entrar a LowTide'


class _SinRedireccion(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib responde con el HTTPError de la redirección: la llave no sigue a otro sitio


# Sin proxies del entorno ni redirecciones, como cirdan/auth/keyvault.py: la llave solo viaja a CORREO_API_URL.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SinRedireccion)


def _abrir(req):
    """Hace la petición y devuelve su código HTTP. Punto único de red, para que las pruebas lo reemplacen."""
    with _opener.open(req, timeout=PLAZO_SEGUNDOS) as resp:
        resp.read(65536)
        return resp.status


def cuerpo(enlace, minutos):
    """Asunto, texto y HTML del correo: solo el enlace y cuánto dura."""
    texto = ('Para entrar a LowTide, abre este enlace y pulsa "Entrar":\n\n%s\n\n'
             'El enlace vence en %d minutos y sirve una sola vez. Si no lo pediste, ignora este correo.\n'
             % (enlace, minutos))
    seguro = html.escape(enlace, quote=True)
    pagina = ('<p>Para entrar a LowTide, abre este enlace y pulsa <strong>Entrar</strong>:</p>'
              '<p><a href="%s">Entrar a LowTide</a></p>'
              '<p>El enlace vence en %d minutos y sirve una sola vez. Si no lo pediste, ignora este correo.</p>'
              % (seguro, minutos))
    return ASUNTO, texto, pagina


def enviar_enlace(destino, enlace, minutos):
    """Manda el correo con el enlace. Devuelve None si Resend lo aceptó, o el motivo del fallo: el código HTTP como
    texto ('429', '401', '403', '500'...), 'sin_respuesta' o 'sin_llave'. El aviso del log solo lleva ese motivo."""
    llave = config('CORREO_API_KEY')
    if not llave:
        log.warning('correo: no se envió el enlace, motivo=sin_llave (falta CORREO_API_KEY)')
        return 'sin_llave'
    asunto, texto, pagina = cuerpo(enlace, minutos)
    datos = json.dumps({'from': config('CORREO_REMITENTE') or REMITENTE, 'to': [destino], 'subject': asunto,
                        'text': texto, 'html': pagina}).encode()
    req = urllib.request.Request(config('CORREO_API_URL') or API_URL, data=datos, method='POST',
                                 headers={'Authorization': 'Bearer ' + llave, 'Content-Type': 'application/json',
                                          'User-Agent': 'lowtide-api'})
    try:
        estado = _abrir(req)
    except urllib.error.HTTPError as e:
        motivo = str(e.code)
        e.close()
    except Exception:  # sin conexión, plazo vencido, TLS: Resend no respondió
        motivo = 'sin_respuesta'
    else:
        if 200 <= estado < 300:
            return None
        motivo = str(estado)
    log.warning('correo: Resend no aceptó el enlace, motivo=%s', motivo)
    return motivo
