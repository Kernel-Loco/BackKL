"""Integración con Microsoft Teams (#65, RC-114): el Admin pega la URL del flujo de Workflows del canal.

La URL lleva su firma (`sig`), así que se guarda cifrada en `integrations.secret_enc` (cirdan/alertas) y nunca se
devuelve: la API solo muestra el host, si está encendida y la última entrega. Solo el Admin, con la sesión del portal.
Una empresa tiene a lo más una integración de Teams: poner otra URL reemplaza la anterior.
"""
import uuid

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from psycopg.types.json import Jsonb

from cirdan.alertas import outbox as alertas, tarjeta
from cirdan.auth.deps import Session, client_ip, require_roles
from cirdan.db import audit, transaction
from cirdan.recolectores import llaves

router = APIRouter(prefix='/api/v1/integrations/teams', tags=['integraciones'])
admin = require_roles('admin')

SIN_LLAVE = 'El servidor no tiene la llave para cifrar la URL del flujo (SOURCE_KEYS_ENCRYPTION_KEY).'
SIN_INTEGRACION = 'Tu empresa todavía no conecta un canal de Teams.'

ACTUAL_SQL = '''
SELECT i.id::text, i.endpoint AS host, i.enabled, i.updated_at,
       (SELECT jsonb_build_object('status', d.status, 'attempt', d.attempt, 'latency_ms', d.latency_ms,
                                  'delivered_at', d.delivered_at, 'last_error', d.last_error)
          FROM deliveries d WHERE d.integration_id = i.id ORDER BY d.created_at DESC LIMIT 1) AS last_delivery
  FROM integrations i
 WHERE i.kind = 'webhook' AND i.config->>'formato' = 'teams'
 ORDER BY i.created_at LIMIT 1
'''


def _vista(fila):
    if not fila:
        return {'configured': False, 'enabled': False, 'host': None, 'last_delivery': None}
    return {'configured': True, 'enabled': fila['enabled'], 'host': fila['host'], 'updated_at': fila['updated_at'],
            'last_delivery': fila['last_delivery']}


@router.get('', summary='La integración de Teams de la empresa, sin la URL (solo Admin)')
def get_teams(session: Session = Depends(admin)):
    with transaction(session.org_id) as conn:
        return _vista(conn.execute(ACTUAL_SQL).fetchone())


@router.put('', summary='Conecta o cambia el canal de Teams con la URL del flujo de Workflows (solo Admin)')
def put_teams(request: Request, payload: dict[str, object] = Body(...), session: Session = Depends(admin)):
    desconocidos = set(payload) - {'url', 'enabled'}
    if desconocidos:
        raise HTTPException(422, 'Campos desconocidos: %s' % ', '.join(sorted(desconocidos)))
    encendida = payload.get('enabled', True)
    if not isinstance(encendida, bool):
        raise HTTPException(422, 'enabled debe ser true o false.')
    try:
        host = tarjeta.validar_url(payload.get('url'))
    except tarjeta.UrlInvalida as error:
        raise HTTPException(422, str(error)) from error
    with transaction(session.org_id) as conn:
        actual = conn.execute(ACTUAL_SQL).fetchone()
        integracion = actual['id'] if actual else str(uuid.uuid4())
        try:
            secreto = alertas.cifrar_url(integracion, payload['url'])
        except llaves.LlaveIlegible:
            raise HTTPException(503, SIN_LLAVE) from None
        if actual:
            conn.execute('UPDATE integrations SET endpoint = %s, secret_enc = %s, secret_rotated_at = now(), '
                         'enabled = %s, updated_at = now() WHERE id = %s', (host, secreto, encendida, integracion))
        else:
            conn.execute("INSERT INTO integrations (id, organization_id, kind, name, endpoint, secret_enc, "
                         "secret_rotated_at, config, enabled) VALUES (%s, %s, 'webhook', 'Microsoft Teams', %s, %s, "
                         "now(), %s, %s)", (integracion, session.org_id, host, secreto,
                                            Jsonb({'formato': alertas.FORMATO}), encendida))
        # La bitácora lleva el host, nunca la URL: la firma abre el canal.
        audit(conn, session.org_id, 'integration.teams_set', session.audit_user_id, client_ip(request), None, None,
              {'integration_id': integracion, 'host': host, 'enabled': encendida, 'replaced': bool(actual)},
              platform=session.audit_platform)
        return _vista(conn.execute(ACTUAL_SQL).fetchone())


@router.delete('', status_code=204, summary='Desconecta el canal de Teams y borra la URL guardada (solo Admin)')
def delete_teams(request: Request, session: Session = Depends(admin)):
    with transaction(session.org_id) as conn:
        actual = conn.execute(ACTUAL_SQL).fetchone()
        if not actual:
            raise HTTPException(404, SIN_INTEGRACION)
        conn.execute('UPDATE integrations SET enabled = false, secret_enc = NULL, updated_at = now() WHERE id = %s',
                     (actual['id'],))
        audit(conn, session.org_id, 'integration.teams_removed', session.audit_user_id, client_ip(request), None, None,
              {'integration_id': actual['id'], 'host': actual['host']}, platform=session.audit_platform)
    return Response(status_code=204)


@router.post('/test', summary='Manda una tarjeta de prueba al canal de Teams (solo Admin)')
def test_teams(session: Session = Depends(admin)):
    with transaction(session.org_id) as conn:
        fila = conn.execute("SELECT id::text, secret_enc FROM integrations WHERE kind = 'webhook' AND enabled "
                            "AND secret_enc IS NOT NULL AND config->>'formato' = 'teams' LIMIT 1").fetchone()
    if not fila:
        raise HTTPException(404, SIN_INTEGRACION)
    try:
        url = alertas.descifrar_url(fila['id'], fila['secret_enc'])
        codigo = alertas.publicar(url, tarjeta.tarjeta('test', {}, alertas._portal()))
    except alertas.UrlIlegible:
        raise HTTPException(503, SIN_LLAVE) from None
    except OSError as error:
        return {'delivered': False, 'status': None, 'error': 'sin respuesta del flujo de Teams (%s)' % type(error).__name__}
    return {'delivered': 200 <= codigo < 300, 'status': codigo}
