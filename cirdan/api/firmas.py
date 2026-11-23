"""Firma de la carta de autorización con Mifiel desde el portal (RC-211, #26b). Todo solo Admin.

Camino B, con la API de Mifiel (cirdan/firma/mifiel.py):
- POST /api/v1/signature-requests manda la carta a firmar. La fila nace en creating y se hace commit antes de llamar
  a Mifiel, fuera de la transacción. Luego pasa a sent o a failed con un UPDATE condicionado a creating.
- POST /api/v1/signature-requests/{id}/refresh consulta el documento, una llamada por clic y a lo más una cada 60 s.
  Con todas las firmas y el mismo original baja el PDF firmado y el XML y los guarda cifrados (cirdan/cartas.py, con
  el id de la solicitud en el AAD).
- POST /api/v1/signature-requests/{id}/cancel la cancela (y la borra en Mifiel si aún no está firmada). Si la firma
  está apagada o en otro entorno, la cancela aquí sin tocar Mifiel.
- POST /api/v1/signature-requests/{id}/accept: el Admin confirma la carta firmada escribiendo el dominio. Entonces
  nace la fila de domain_authorizations, y el dominio si no existía. La 031 exige que copie tal cual lo firmado y
  que venga de producción: una firma del sandbox no tiene validez legal.
Si Mifiel pudo recibir la carta sin que se sepa el id del documento (mifiel.Incierto), la solicitud se queda en
creating con el aviso en last_error y sigue ocupando el dominio: no se manda una segunda invitación hasta que el Admin
revise en la web de Mifiel y la cancele.
Camino A, sin la API: POST /api/v1/signature-uploads recibe el PDF firmado y el XML hechos en la web de Mifiel. La
validez del XML la revisa una persona en https://app.mifiel.com/verify-xml; aquí solo se revisa que esté bien formado.

La firma comparte con el alta (RC-59) los datos, el tope del PDF, el candado de la empresa y el interruptor
cartas.habilitado(). Con FIRMA_MODO apagado el camino B da 503 sin abrir ninguna conexión. La bitácora nunca lleva
nombre, correo ni la respuesta de Mifiel.
"""
import base64
import binascii
import json
import secrets
import uuid
import xml.parsers.expat

from fastapi import APIRouter, Depends, HTTPException, Request
from psycopg.errors import UniqueViolation
from starlette.concurrency import run_in_threadpool

from cirdan import cartas
from cirdan.api.v1 import (MAX_ALTA_BODY, MAX_CARTA, _choque_de_dominio, _datos_alta, _dominio_para_carta,
                           _respuesta_dominio, _revisar_empresa_y_carta)
from cirdan.auth.deps import Session, client_ip, require_roles
from cirdan.db import audit, transaction
from cirdan.firma import mifiel

router = APIRouter(prefix='/api/v1', tags=['portal'])

MAX_XML = 7 * 1024 * 1024
MAX_SUBIDA_BODY = (MAX_CARTA + 2) // 3 * 4 + (MAX_XML + 2) // 3 * 4 + 16384
ESPERA_CONSULTA = 60           # segundos entre dos consultas a Mifiel de la misma solicitud
CREANDO_VENCIDA = 5            # minutos en creating antes de darla por fallida
# Nombre, cargo y correo de quien firma solo salen mientras la solicitud sigue abierta y su carta no venció. Después
# están en bloqueo, como el correo de DOMAINS_SQL (RC-274, sección 5.6 de docs/politica_seguridad_privacidad.md).
_VISIBLE = "status IN ('creating', 'sent', 'signed') AND current_date <= valid_until"
COLUMNAS = ('id::text, fqdn::text, environment, status, '
            'CASE WHEN %(v)s THEN signer_name END AS signer_name, '
            'CASE WHEN %(v)s THEN signer_title END AS signer_title, '
            'CASE WHEN %(v)s THEN signer_email::text END AS signer_email, valid_from, '
            'valid_until, template_version, activities, provider_document_id, provider_signed_at, last_checked_at, '
            'last_error, created_at, updated_at, decided_at') % {'v': _VISIBLE}
NO_HABILITADA = 'El alta de dominios no está habilitada: falta configurar el almacenamiento y su respaldo.'
INCIERTO = ('Mifiel no confirmó si recibió la carta. Si al firmante le llegó la invitación, bórrala en la web de '
            'Mifiel. Luego cancela esta solicitud para mandar otra.')


def _solicitud(r):
    return {'id': r['id'], 'fqdn': r['fqdn'], 'provider': 'mifiel', 'environment': r['environment'],
            'status': r['status'], 'signer_name': r['signer_name'], 'signer_title': r['signer_title'],
            'signer_email': r['signer_email'], 'valid_from': r['valid_from'], 'valid_until': r['valid_until'],
            'template_version': r['template_version'], 'activities': r['activities'],
            'signed_at': r['provider_signed_at'], 'last_checked_at': r['last_checked_at'],
            'last_error': r['last_error'], 'created_at': r['created_at'], 'updated_at': r['updated_at'],
            'decided_at': r['decided_at']}


def _propia(session):
    if session.acting_elsewhere:
        raise HTTPException(403, 'La firma de la carta debe hacerla un administrador de la propia empresa.')


def _id(texto):
    try:
        return str(uuid.UUID(texto))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(404, 'Solicitud de firma no encontrada.') from None


def _leer(conn, request_id, bloquear=False):
    r = conn.execute('SELECT %s, (last_checked_at > now() - make_interval(secs => %%s)) AS reciente, '
                     '(created_at < now() - make_interval(mins => %%s)) AS creando_vencida '
                     'FROM signature_requests WHERE id = %%s%s' % (COLUMNAS, ' FOR UPDATE' if bloquear else ''),
                     (ESPERA_CONSULTA, CREANDO_VENCIDA, request_id)).fetchone()
    if not r:
        raise HTTPException(404, 'Solicitud de firma no encontrada.')
    return r


def _cliente(environment=None):
    try:
        return mifiel.cliente(environment)
    except mifiel.Apagado as e:
        if mifiel.entorno() is not None and environment is not None and environment != mifiel.entorno():
            raise HTTPException(409, 'La solicitud es de otro entorno de Mifiel que el configurado.') from None
        raise HTTPException(503, str(e)) from None


async def _cuerpo(request, tope, mensaje):
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > tope:
            raise HTTPException(413, mensaje)
        raw.extend(chunk)
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(422, 'El cuerpo de la solicitud no es válido.') from None


def _xml_bien_formado(datos):
    """True si es XML bien formado y sin DOCTYPE: sin DTD no hay entidades que expandir ni que ir a buscar."""
    parser = xml.parsers.expat.ParserCreate()

    def rechazar(*_):
        raise ValueError('DOCTYPE')
    parser.StartDoctypeDeclHandler = rechazar
    parser.EntityDeclHandler = rechazar
    try:
        parser.Parse(datos, True)
    except (xml.parsers.expat.ExpatError, ValueError):
        return False
    return True


def _actualizar(conn, request_id, de, sets, valores):
    """UPDATE condicionado al estado `de`. True si cambió la fila (otra petición no se adelantó)."""
    cur = conn.execute('UPDATE signature_requests SET %s WHERE id = %%s AND status = %%s' % ', '.join(sets),
                       (*valores, request_id, de))
    return cur.rowcount == 1


# ---------------------------------------------------------------- camino B

def _enviar(body, request, session):
    _propia(session)
    fqdn, name, title, email, start, end, pdf, version, activities = _datos_alta(body)
    cliente = _cliente()
    request_id = str(uuid.uuid4())
    with transaction(session.org_id) as conn:
        limit = _revisar_empresa_y_carta(conn, session, end)
        if conn.execute("SELECT 1 FROM signature_requests WHERE fqdn = %s AND status IN ('creating', 'sent', 'signed')",
                        (fqdn,)).fetchone():
            raise HTTPException(409, 'Ya hay una carta de ese dominio enviada a firmar. Cancélala antes de mandar otra.')
        existe = conn.execute("SELECT 1 FROM domains WHERE fqdn = %s AND status <> 'removed'", (fqdn,)).fetchone()
        if not existe:
            # Cada solicitud abierta de un dominio que todavía no existe aparta su lugar: si no, se firman cartas que
            # luego no caben al confirmar. El candado de _revisar_empresa_y_carta evita que dos envíos cuenten a la vez.
            count = conn.execute(
                "SELECT (SELECT count(*) FROM domains WHERE status <> 'removed') + "
                "(SELECT count(DISTINCT s.fqdn) FROM signature_requests s WHERE s.status IN ('creating', 'sent', "
                "'signed') AND NOT EXISTS (SELECT 1 FROM domains d WHERE d.fqdn = s.fqdn AND d.status <> 'removed')) "
                "AS total"
            ).fetchone()['total']
            if count >= limit:
                raise HTTPException(409, 'La organización alcanzó su límite de dominios.')
        key, digest = cartas.guardar(pdf, session.org_id, request_id)
        conn.execute(
            'INSERT INTO signature_requests (id, organization_id, provider, environment, fqdn, signer_name, '
            'signer_title, signer_email, valid_from, valid_until, template_version, activities, unsigned_document_key, '
            "unsigned_sha256, requested_by) VALUES (%s, %s, 'mifiel', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (request_id, session.org_id, cliente.environment, fqdn, name, title, email, start, end, version,
             activities, key, digest, session.user_id),
        )
        audit(conn, session.org_id, 'authorization.signature_requested', session.audit_user_id, client_ip(request),
              'signature_request', request_id, {'fqdn': fqdn, 'environment': cliente.environment},
              platform=session.audit_platform)

    # Fuera de la transacción: la fila ya existe en creating aunque Mifiel tarde o falle.
    error, incierto = None, False
    try:
        creado = cliente.crear(pdf, name, email, request_id)
    except mifiel.FirmaError as e:
        creado, error, incierto = None, str(e), isinstance(e, mifiel.Incierto)
    if creado and creado['original_hash'] and creado['original_hash'].strip().lower() != digest.hex():
        try:
            cliente.borrar(creado['id'])
        except mifiel.FirmaError:
            pass
        creado, error = None, 'Mifiel recibió un archivo distinto al que se mandó.'
    with transaction(session.org_id) as conn:
        if creado:
            if not _actualizar(conn, request_id, 'creating',
                               ("status = 'sent'", 'provider_document_id = %s', 'last_checked_at = now()'),
                               (creado['id'],)):
                try:
                    cliente.borrar(creado['id'])
                except mifiel.FirmaError:
                    pass
        elif incierto:
            # Pudo quedar creado en Mifiel con la invitación mandada: se queda abierta hasta que el Admin la cancele.
            _actualizar(conn, request_id, 'creating', ('last_error = %s', 'last_checked_at = now()'),
                        (('%s %s' % (error, INCIERTO))[:200],))
        else:
            _actualizar(conn, request_id, 'creating',
                        ("status = 'failed'", 'last_error = %s', 'last_checked_at = now()'), (error[:200],))
        r = _leer(conn, request_id)
    if incierto:
        raise HTTPException(502, '%s %s' % (error, INCIERTO))
    if error:
        raise HTTPException(502, 'No se pudo mandar la carta a Mifiel: %s' % error)
    return _solicitud(r)


@router.post('/signature-requests', status_code=201, summary='Manda la carta a firmar con Mifiel (solo Admin)')
async def create_signature_request(request: Request, session: Session = Depends(require_roles('admin'))):
    if not cartas.habilitado():
        raise HTTPException(409, NO_HABILITADA)
    body = await _cuerpo(request, MAX_ALTA_BODY, 'El PDF no puede superar 5 MB.')
    return await run_in_threadpool(_enviar, body, request, session)


@router.get('/signature-requests', summary='Cartas mandadas a firmar con Mifiel (solo Admin)')
def list_signature_requests(session: Session = Depends(require_roles('admin'))):
    _propia(session)
    with transaction(session.org_id) as conn:
        rows = conn.execute('SELECT %s FROM signature_requests ORDER BY created_at DESC LIMIT 100' % COLUMNAS).fetchall()
    items = [_solicitud(r) for r in rows]
    return {'items': items, 'total': len(items), 'mode': mifiel.entorno() or 'off'}


@router.post('/signature-requests/{request_id}/refresh', summary='Consulta en Mifiel el estado de la firma (solo Admin)')
def refresh_signature_request(request_id: str, request: Request, session: Session = Depends(require_roles('admin'))):
    _propia(session)
    request_id = _id(request_id)
    with transaction(session.org_id) as conn:
        r = _leer(conn, request_id)
        if r['status'] == 'creating' and r['creando_vencida'] and not r['last_error']:
            # No se sabe si llegó a Mifiel (la API pudo caerse a la mitad): no se da por fallida sola, porque eso
            # libera el dominio y el reintento mandaría una segunda invitación. Queda el aviso para el Admin.
            _actualizar(conn, request_id, 'creating', ('last_error = %s', 'last_checked_at = now()'), (INCIERTO,))
            r = _leer(conn, request_id)
    if r['status'] != 'sent' or r['reciente']:
        return _solicitud(r)

    cliente = _cliente(r['environment'])
    with transaction(session.org_id) as conn:
        sha = conn.execute('SELECT unsigned_sha256 FROM signature_requests WHERE id = %s',
                           (request_id,)).fetchone()['unsigned_sha256']
    estado, firmado_en, error, archivos = 'sent', None, None, None
    try:
        try:
            doc = cliente.consultar(r['provider_document_id'])
        except mifiel.NoEncontrado:
            # Mifiel borra solo un documento vencido. Un 404 de las descargas no cuenta: cae abajo como error.
            doc = None
        if doc is None:
            estado = 'expired'
        else:
            estado, firmado_en, error = mifiel.interpretar(doc, bytes(sha))
        if estado == 'signed':
            pdf = cliente.pdf_firmado(r['provider_document_id'])
            evidencia = cliente.xml(r['provider_document_id'])
            if not pdf.startswith(b'%PDF-') or not _xml_bien_formado(evidencia):
                estado, error = 'sent', 'Mifiel entregó archivos que no se pueden leer.'
            else:
                archivos = (cartas.guardar(pdf, session.org_id, request_id),
                            cartas.guardar(evidencia, session.org_id, request_id))
    except mifiel.FirmaError as e:
        estado, error = 'sent', str(e)
    if estado == 'signed' and archivos is None:
        estado = 'sent'

    with transaction(session.org_id) as conn:
        if estado == 'signed':
            (pdf_key, pdf_sha), (xml_key, xml_sha) = archivos
            if _actualizar(conn, request_id, 'sent',
                           ("status = 'signed'", 'signed_document_key = %s', 'signed_sha256 = %s', 'evidence_key = %s',
                            'evidence_sha256 = %s', 'provider_signed_at = %s', 'last_checked_at = now()',
                            'last_error = NULL'),
                           (pdf_key, pdf_sha, xml_key, xml_sha, firmado_en)):
                audit(conn, session.org_id, 'authorization.signature_signed', session.audit_user_id,
                      client_ip(request), 'signature_request', request_id, {'fqdn': r['fqdn']},
                      platform=session.audit_platform)
        else:
            _actualizar(conn, request_id, 'sent', ('status = %s', 'last_checked_at = now()', 'last_error = %s'),
                        (estado, error[:200] if error else None))
        return _solicitud(_leer(conn, request_id))


@router.post('/signature-requests/{request_id}/cancel', summary='Cancela una carta mandada a firmar (solo Admin)')
def cancel_signature_request(request_id: str, request: Request, session: Session = Depends(require_roles('admin'))):
    _propia(session)
    request_id = _id(request_id)
    with transaction(session.org_id) as conn:
        r = _leer(conn, request_id)
    if r['status'] == 'creating':
        # Sin id del documento no hay nada que borrar en Mifiel: queda failed con el aviso de revisarlo en su web.
        if not (r['last_error'] or r['creando_vencida']):
            raise HTTPException(409, 'La carta todavía se está mandando a Mifiel. Espera unos minutos y consulta su '
                                     'estado.')
        sets, valores = (("status = 'failed'", 'last_error = %s', 'last_checked_at = now()'),
                         ('Cancelada sin confirmar en Mifiel. Si llegó la invitación, bórrala en la web de Mifiel.',))
    elif r['status'] in ('sent', 'signed'):
        sets, valores = ("status = 'cancelled'", 'decided_by = %s', 'decided_at = now()'), (session.user_id,)
    else:
        raise HTTPException(409, 'Esta solicitud ya no se puede cancelar.')
    if r['status'] == 'sent':
        try:
            cliente = _cliente(r['environment'])
        except HTTPException:
            # Firma apagada, sin llaves o de otro entorno: se cancela aquí para liberar el dominio, sin tocar Mifiel.
            cliente = None
            sets, valores = sets + ('last_error = %s',), valores + (
                'Cancelada sin borrar en Mifiel: la firma está apagada o en otro entorno.',)
        if cliente is not None:
            try:
                cliente.borrar(r['provider_document_id'])
            except mifiel.FirmaError as e:
                raise HTTPException(502, 'No se pudo cancelar en Mifiel: %s' % e) from None
    with transaction(session.org_id) as conn:
        if not _actualizar(conn, request_id, r['status'], sets, valores):
            raise HTTPException(409, 'La solicitud cambió mientras se cancelaba. Consulta su estado otra vez.')
        audit(conn, session.org_id, 'authorization.signature_cancelled', session.audit_user_id, client_ip(request),
              'signature_request', request_id, {'fqdn': r['fqdn']}, platform=session.audit_platform)
        return _solicitud(_leer(conn, request_id))


def _aceptar(request_id, body, request, session):
    _propia(session)
    request_id = _id(request_id)
    if not isinstance(body, dict) or set(body) != {'confirm_fqdn'} or not isinstance(body['confirm_fqdn'], str):
        raise HTTPException(422, 'Escribe el dominio de la carta para confirmarla.')
    try:
        with transaction(session.org_id) as conn:
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s, 44))', (session.org_id,))
            r = _leer(conn, request_id, bloquear=True)
            if r['status'] != 'signed':
                raise HTTPException(409, 'Solo se confirma una carta ya firmada.')
            if r['environment'] != 'production':
                raise HTTPException(409, 'Una carta firmada en el sandbox de Mifiel no tiene validez legal y no se '
                                         'puede confirmar.')
            if body['confirm_fqdn'].strip().lower().removesuffix('.') != r['fqdn']:
                raise HTTPException(422, 'El dominio que escribiste no es el de la carta.')
            domain_id, _ = _dominio_para_carta(conn, session, request, r['fqdn'], r['valid_until'],
                                               secrets.token_hex(16), renovar=True)
            authorization_id = conn.execute(
                'INSERT INTO domain_authorizations (organization_id, domain_id, signer_name, signer_title, signer_email, '
                'signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by, template_version, '
                'activities, signature_request_id, signature_provider, evidence_key, evidence_sha256, signed_at) '
                'SELECT organization_id, %s, signer_name, signer_title, signer_email, signed_document_key, signed_sha256, '
                'valid_from, valid_until, %s, template_version, activities, id, provider, evidence_key, evidence_sha256, '
                'provider_signed_at FROM signature_requests WHERE id = %s RETURNING id::text',
                (domain_id, session.user_id, request_id),
            ).fetchone()['id']
            _actualizar(conn, request_id, 'signed', ("status = 'accepted'", 'decided_by = %s', 'decided_at = now()'),
                        (session.user_id,))
            audit(conn, session.org_id, 'authorization.uploaded', session.audit_user_id, client_ip(request),
                  'domain_authorization', authorization_id,
                  {'fqdn': r['fqdn'], 'valid_until': r['valid_until'].isoformat(), 'source': 'mifiel_api'},
                  platform=session.audit_platform)
            salida = _respuesta_dominio(conn, domain_id)
            salida['signature_request'] = _solicitud(_leer(conn, request_id))
    except UniqueViolation as error:
        choque = _choque_de_dominio(error)
        if choque:
            raise choque from None
        raise
    return salida


@router.post('/signature-requests/{request_id}/accept', summary='Confirma la carta firmada en Mifiel (solo Admin)')
async def accept_signature_request(request_id: str, request: Request,
                                   session: Session = Depends(require_roles('admin'))):
    if not cartas.habilitado():
        raise HTTPException(409, NO_HABILITADA)
    body = await _cuerpo(request, 64 * 1024, 'El cuerpo de la solicitud es demasiado grande.')
    return await run_in_threadpool(_aceptar, request_id, body, request, session)


# ---------------------------------------------------------------- camino A

def _subir(body, request, session):
    _propia(session)
    if not isinstance(body, dict) or not isinstance(body.get('xml_base64'), str):
        raise HTTPException(422, 'Adjunta el XML que entrega Mifiel.')
    body = dict(body)
    xml_b64 = body.pop('xml_base64')
    fqdn, name, title, email, start, end, pdf, version, activities = _datos_alta(body)
    try:
        evidencia = base64.b64decode(xml_b64, validate=True)
    except (ValueError, binascii.Error):
        raise HTTPException(422, 'No se pudo leer el XML.') from None
    if len(evidencia) > MAX_XML:
        raise HTTPException(413, 'El XML no puede superar 7 MB.')
    if not _xml_bien_formado(evidencia):
        raise HTTPException(422, 'El XML de Mifiel no es válido.')
    try:
        with transaction(session.org_id) as conn:
            domain_id, _ = _dominio_para_carta(conn, session, request, fqdn, end, secrets.token_hex(16), renovar=True)
            pdf_key, pdf_sha = cartas.guardar(pdf, session.org_id, domain_id)
            xml_key, xml_sha = cartas.guardar(evidencia, session.org_id, domain_id)
            authorization_id = conn.execute(
                'INSERT INTO domain_authorizations (organization_id, domain_id, signer_name, signer_title, signer_email, '
                'signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by, template_version, '
                "activities, signature_provider, evidence_key, evidence_sha256) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, "
                "%s, %s, %s, %s, 'mifiel', %s, %s) RETURNING id::text",
                (session.org_id, domain_id, name, title, email, pdf_key, pdf_sha, start, end, session.user_id, version,
                 activities, xml_key, xml_sha),
            ).fetchone()['id']
            audit(conn, session.org_id, 'authorization.uploaded', session.audit_user_id, client_ip(request),
                  'domain_authorization', authorization_id,
                  {'fqdn': fqdn, 'valid_until': end.isoformat(), 'source': 'mifiel_web'},
                  platform=session.audit_platform)
            return _respuesta_dominio(conn, domain_id)
    except UniqueViolation as error:
        choque = _choque_de_dominio(error)
        if choque:
            raise choque from None
        raise


@router.post('/signature-uploads', status_code=201,
             summary='Sube la carta firmada y el XML hechos en la web de Mifiel (solo Admin)')
async def upload_signed_letter(request: Request, session: Session = Depends(require_roles('admin'))):
    if not cartas.habilitado():
        raise HTTPException(409, NO_HABILITADA)
    body = await _cuerpo(request, MAX_SUBIDA_BODY, 'El PDF no puede superar 5 MB y el XML 7 MB.')
    return await run_in_threadpool(_subir, body, request, session)
