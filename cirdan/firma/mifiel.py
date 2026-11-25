"""Cliente mínimo de la API de Mifiel (RC-211, #26b) con urllib, sin el SDK (_plan de diseño, camino B).

Solo lo que usa el portal: crear el documento con un firmante, consultarlo, borrarlo mientras no esté firmado y bajar
el PDF firmado y el XML (la constancia NOM-151 va dentro del XML). Cada llamada la pide un Admin con un clic; no hay
consultas periódicas ni webhooks.

Modo (FIRMA_MODO): 'apagado' (por omisión), 'sandbox' o 'produccion'. Apagado, cliente() lanza Apagado y no se abre
ninguna conexión. Las llaves son MIFIEL_APP_ID y MIFIEL_APP_SECRET; las del sandbox y las de producción no se mezclan.

Autenticación HMAC-SHA1 con el esquema APIAuth del SDK oficial: la cadena 'MÉTODO,Content-Type,Content-MD5,ruta,fecha'
firmada con el secreto, en 'Authorization: APIAuth APP_ID:firma'. Content-MD5 es base64 del MD5 del cuerpo (de '' si
no hay cuerpo). Los vectores públicos del SDK están en pruebas/test_firma.py.

Toda petición va por transporte.descargar: solo https al 443, direcciones públicas, sin redirecciones, plazo absoluto
y tope de bytes. Los errores que salen de aquí traen un texto propio y corto: nunca la respuesta de Mifiel, que lleva
nombres, correos y enlaces, ni el secreto.

Sin fuente pública (se prueba en el sandbox antes de producción): cómo marca Mifiel un documento rechazado. La
especificación (docs.mifiel.com/es/api.json) deja 'state' como texto libre y solo nombra el evento signer_rejected de
los webhooks. Aquí cuenta como rechazado si 'state' del documento o de un firmante dice rejected o declined. Un
documento vencido Mifiel lo borra solo (descripción de DELETE en la especificación), así que un 404 cuenta como vencido,
igual que un expires_at ya pasado sin todas las firmas.
"""
import base64
import email.utils
import hashlib
import hmac
import http.client
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from cirdan.config import config
from cirdan.recolectores import transporte

BASES = {'sandbox': 'https://app-sandbox.mifiel.com/api/v1/', 'production': 'https://app.mifiel.com/api/v1/'}
MODOS = {'sandbox': 'sandbox', 'produccion': 'production'}
AGENTE = 'LowTide-firma/1.0'
PLAZO = 20                     # segundos por petición JSON
PLAZO_DESCARGA = 60            # segundos por archivo firmado
TOPE_JSON = 1024 * 1024
TOPE_ARCHIVO = 25 * 1024 * 1024
DIAS_PARA_FIRMAR = 7
RECHAZADO = frozenset({'rejected', 'declined'})


class FirmaError(Exception):
    """Mifiel no respondió o respondió algo que no se puede usar. El texto es propio y se puede mostrar."""


class Incierto(FirmaError):
    """La petición pudo llegar a Mifiel aunque no hubo respuesta útil: plazo vencido, conexión cortada, error 5xx o una
    respuesta que no se puede leer. Al crear, el documento pudo quedar hecho y la invitación mandada."""


class Apagado(FirmaError):
    """FIRMA_MODO está apagado o faltan las llaves."""


class NoEncontrado(FirmaError):
    """404: el documento no existe (Mifiel borra los vencidos)."""


class NoListo(FirmaError):
    """423: el archivo firmado todavía no se puede bajar."""


def entorno():
    """'sandbox', 'production' o None (apagado). Un valor desconocido cuenta como apagado."""
    return MODOS.get(config('FIRMA_MODO', 'apagado').strip().lower())


def firma_apiauth(secreto, metodo, content_type, content_md5, ruta, fecha):
    cadena = ','.join((metodo.upper(), content_type or '', content_md5, ruta, fecha))
    return base64.b64encode(hmac.new(secreto.encode('utf-8'), cadena.encode('utf-8'), hashlib.sha1).digest()).decode()


def encabezados(app_id, secreto, metodo, url, cuerpo=b'', content_type='', fecha=None):
    """Content-MD5, Date y Authorization de APIAuth. La ruta firmada es la de la URL con su query."""
    partes = urllib.parse.urlsplit(url)
    ruta = partes.path + ('?' + partes.query if partes.query else '')
    fecha = fecha or email.utils.formatdate(usegmt=True)
    md5 = base64.b64encode(hashlib.md5(cuerpo or b'', usedforsecurity=False).digest()).decode()
    firma = firma_apiauth(secreto, metodo, content_type, md5, ruta, fecha)
    salida = {'Content-MD5': md5, 'Date': fecha, 'Authorization': 'APIAuth %s:%s' % (app_id, firma)}
    if content_type:
        salida['Content-Type'] = content_type
    return salida


def multipart(campos, archivo):
    """(cuerpo, content_type). `campos` es una lista de pares de texto; `archivo` es (campo, nombre, bytes)."""
    frontera = 'lowtide' + secrets.token_hex(16)
    partes = []
    for nombre, valor in campos:
        partes.append(('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
                       % (frontera, nombre, valor)).encode('utf-8'))
    campo, nombre, datos = archivo
    partes.append(('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n'
                   'Content-Type: application/pdf\r\n\r\n' % (frontera, campo, nombre)).encode('utf-8'))
    partes.append(datos)
    partes.append(('\r\n--%s--\r\n' % frontera).encode('ascii'))
    return b''.join(partes), 'multipart/form-data; boundary=%s' % frontera


def _sin_saltos(texto):
    # Un nombre con CR o LF partiría el multipart. _datos_alta ya rechaza los nulos.
    return ' '.join(str(texto).split())


class Cliente:
    def __init__(self, environment, app_id, secreto, descargar=None, cronometro=None):
        if environment not in BASES:
            raise Apagado('Entorno de firma desconocido.')
        self.environment, self.base = environment, BASES[environment]
        self._app_id, self._secreto = app_id, secreto
        self._descargar = descargar or transporte.descargar
        self._cronometro = cronometro or time.monotonic

    def __repr__(self):
        return '<mifiel.Cliente %s>' % self.environment

    def _pedir(self, metodo, ruta, cuerpo=None, content_type='', tope=TOPE_JSON, plazo=PLAZO, tipo=None):
        url = self.base + ruta
        cabeceras = encabezados(self._app_id, self._secreto, metodo, url, cuerpo or b'', content_type)
        cabeceras.update({'User-Agent': AGENTE, 'Accept': '*/*' if tipo else 'application/json'})
        req = urllib.request.Request(url, data=cuerpo, headers=cabeceras, method=metodo)
        try:
            return self._descargar(req, self._cronometro() + plazo, tope, self._cronometro, tipo)
        except urllib.error.HTTPError as e:
            codigo = e.code
            e.close()
            if codigo == 404:
                raise NoEncontrado('Mifiel no encontró el documento.') from None
            if codigo == 423:
                raise NoListo('Mifiel todavía no entrega el archivo firmado.') from None
            if codigo in (401, 403):
                raise FirmaError('Mifiel rechazó las llaves de la API.') from None
            if codigo >= 500:
                raise Incierto('Mifiel respondió con error %d.' % codigo) from None
            raise FirmaError('Mifiel respondió con error %d.' % codigo) from None
        except transporte.PlazoVencido:
            raise Incierto('Mifiel no respondió a tiempo.') from None
        except transporte.Redirigida:
            raise FirmaError('Mifiel respondió con una redirección.') from None
        except ValueError:
            raise Incierto('La respuesta de Mifiel es demasiado grande o de otro tipo.') from None
        except (OSError, http.client.HTTPException):
            # IncompleteRead, BadStatusLine o LineTooLong no son OSError: sin esto saldrían como un 500 de la API.
            raise Incierto('No se pudo conectar con Mifiel.') from None

    def _json(self, *args, **kwargs):
        datos = self._pedir(*args, **kwargs)
        try:
            doc = json.loads(datos)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise Incierto('La respuesta de Mifiel no se puede leer.') from None
        if not isinstance(doc, dict):
            raise Incierto('La respuesta de Mifiel no se puede leer.')
        return doc

    def crear(self, pdf, nombre, correo, external_id, dias=DIAS_PARA_FIRMAR):
        """Crea el documento con un firmante y manda la invitación. Devuelve {'id', 'original_hash'}.

        Lanza Incierto si el documento pudo quedar creado en Mifiel sin que se sepa su id. Sube hasta 5 MB, así que
        usa el plazo de las descargas y no el de 20 s."""
        cuerpo, tipo = multipart(
            [('signatories[0][name]', _sin_saltos(nombre)), ('signatories[0][email]', _sin_saltos(correo)),
             ('send_invites', 'true'), ('days_to_expire', str(int(dias))), ('external_id', str(external_id))],
            ('file', 'carta_autorizacion.pdf', pdf))
        doc = self._json('POST', 'documents', cuerpo, tipo, plazo=PLAZO_DESCARGA)
        doc_id = doc.get('id')
        if not isinstance(doc_id, str) or not 1 <= len(doc_id) <= 100:
            raise Incierto('Mifiel no devolvió el id del documento.')
        original = doc.get('original_hash')
        return {'id': doc_id, 'original_hash': original if isinstance(original, str) else None}

    def consultar(self, doc_id):
        return self._json('GET', 'documents/%s' % urllib.parse.quote(doc_id, safe=''))

    def borrar(self, doc_id):
        """Borra un documento sin firmar. Un 404 cuenta como borrado."""
        try:
            self._pedir('DELETE', 'documents/%s' % urllib.parse.quote(doc_id, safe=''))
        except NoEncontrado:
            pass

    def pdf_firmado(self, doc_id):
        return self._pedir('GET', 'documents/%s/file_signed' % urllib.parse.quote(doc_id, safe=''),
                           tope=TOPE_ARCHIVO, plazo=PLAZO_DESCARGA, tipo='application/pdf')

    def xml(self, doc_id):
        return self._pedir('GET', 'documents/%s/xml' % urllib.parse.quote(doc_id, safe=''),
                           tope=TOPE_ARCHIVO, plazo=PLAZO_DESCARGA)


def cliente(environment=None, **kwargs):
    """El cliente del modo configurado. Lanza Apagado sin modo o sin llaves, antes de cualquier conexión."""
    actual = entorno()
    if actual is None:
        raise Apagado('La firma con Mifiel no está habilitada.')
    if environment is not None and environment != actual:
        raise Apagado('La solicitud es de otro entorno de Mifiel.')
    app_id, secreto = config('MIFIEL_APP_ID'), config('MIFIEL_APP_SECRET')
    if not app_id or not secreto:
        raise Apagado('Faltan las llaves de la API de Mifiel.')
    return Cliente(actual, app_id, secreto, **kwargs)


def _fecha(valor):
    if not isinstance(valor, str):
        return None
    try:
        fecha = datetime.fromisoformat(valor.replace('Z', '+00:00'))
    except ValueError:
        return None
    return fecha if fecha.tzinfo else fecha.replace(tzinfo=timezone.utc)


def _textos_de_estado(doc):
    estados = [doc.get('state')]
    for lista in ('signers', 'signatories'):
        for firmante in doc.get(lista) or ():
            if isinstance(firmante, dict):
                estados.append(firmante.get('state'))
    return {e.strip().lower() for e in estados if isinstance(e, str)}


def interpretar(doc, unsigned_sha256, ahora=None):
    """(estado, firmado_en, error) de un documento de Mifiel frente a la huella del PDF que se mandó.

    estado: 'signed' (todos firmaron y el original es el mismo PDF), 'rejected', 'expired' o 'sent'."""
    ahora = ahora or datetime.now(timezone.utc)
    if doc.get('signed_by_all') is True:
        original = doc.get('original_hash')
        if isinstance(original, str) and hmac.compare_digest(original.strip().lower(), unsigned_sha256.hex()):
            return 'signed', _fecha(doc.get('signed_at')), None
        return 'sent', None, 'Mifiel firmó un archivo distinto al que se mandó.'
    if _textos_de_estado(doc) & RECHAZADO:
        return 'rejected', None, None
    vence = _fecha(doc.get('expires_at'))
    if vence is not None and vence <= ahora:
        return 'expired', None, None
    return 'sent', None, None
