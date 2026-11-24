"""Consola multiempresa del integrador (#66, RC-126): /api/v1/operator/organizations.

Una cuenta 'operator' de la empresa integradora ve las empresas cliente que le delegaron (tabla org_delegations,
migración 033) con su riesgo: el score más alto de sus dominios, y la lista sale ordenada por él.

Cómo se respeta RLS, que no cambia:
- La delegación se lee con app.current_org de la empresa integradora (la dueña de la fila).
- Los datos de cada empresa cliente se leen después, en su propia transacción, con app.current_org de esa empresa.
  Nunca hay dos empresas en una transacción, ninguna política mira a varias y ninguna función salta RLS.
- Una empresa que no está delegada, con la delegación revocada, que no existe o que está suspendida o cancelada
  responde 404 con el mismo texto: el operador no sabe si existe.
- Cada lectura de una empresa cliente queda en la bitácora de esa empresa, con actor 'operator' (no 'platform', que es
  el superadmin de RC-332), el id de la cuenta y la empresa integradora (comentario 10270, punto 1). La lectura y su
  registro van en la misma transacción: sin registro no hay datos.
- Antes de responder se vuelve a leer la delegación: si se revocó mientras se leía, la empresa no sale.

El superadmin de RC-332 (platform_admins, cirdan/api/plataforma.py) es otra cosa y no pasa por aquí.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from cirdan.auth import sessions
from cirdan.auth.deps import SESION_TERMINADA, Session, client_ip, current_session
from cirdan.db import audit, transaction
from cirdan.score import configuracion, criterio

router = APIRouter(prefix='/api/v1/operator', tags=['operador'])

ROL = 'operator'
SOLO_OPERADOR = 'Solo una cuenta de operador con MFA activo puede usar la consola del integrador.'
NO_ENCONTRADA = 'Organización no encontrada'
ACTIVAS = ('trial', 'active')

# La cuenta sigue siendo operator, activa, con TOTP activo y su empresa en trial o active. Se lee con RLS de su
# propia empresa: ninguna función SECURITY DEFINER.
CUENTA = ("SELECT u.role = %s AND u.mfa_enabled_at IS NOT NULL AND u.totp_secret_enc IS NOT NULL"
          "       AND o.status IN ('trial', 'active') AS ok"
          "  FROM users u JOIN organizations o ON o.id = u.organization_id"
          " WHERE u.id = %s AND u.is_active")

# Delegaciones vigentes de la empresa integradora. El WHERE repite lo que ya filtra RLS.
DELEGADAS = ("SELECT client_organization_id::text AS id FROM org_delegations"
             " WHERE organization_id = %s AND revoked_at IS NULL")

# Dentro de la empresa cliente, con su RLS: nombre, estado y el score vigente (el último) de cada dominio.
EMPRESA = "SELECT id::text, name, status FROM organizations WHERE id = %s"
DOMINIOS = """
SELECT d.id::text, d.fqdn::text, d.status, s.score, s.computed_at, s.band_medium_from, s.band_high_from,
       s.band_critical_from
  FROM domains d
  LEFT JOIN LATERAL (SELECT ds.score, ds.computed_at, rs.band_medium_from, rs.band_high_from, rs.band_critical_from
                       FROM domain_scores ds JOIN scoring_rule_sets rs ON rs.id = ds.rule_set_id
                      WHERE ds.domain_id = d.id ORDER BY ds.computed_at DESC LIMIT 1) s ON true
 WHERE d.status <> 'removed'
 ORDER BY s.score DESC NULLS LAST, d.fqdn
"""


def operator(request: Request) -> Session:
    """Sesión de una cuenta operator o 403. Mira el rol de la sesión y luego la base en cada llamada: si se le quitó el
    rol o el TOTP, se desactivó o se suspendió su empresa, la sesión se cierra ahí mismo y responde 401, para que no
    siga abierta hasta las 8 h. Una llave de API nunca llega aquí (solo cookie). Un superadmin trabajando en una
    empresa ajena tampoco: ahí su rol es admin."""
    session = current_session(request)
    if session.role != ROL or session.acting_elsewhere:
        raise HTTPException(403, SOLO_OPERADOR)
    with transaction(session.own_org_id) as conn:
        fila = conn.execute(CUENTA, (ROL, session.user_id)).fetchone()
    if not fila or not fila['ok']:
        sessions.delete(session.token)
        raise HTTPException(401, SESION_TERMINADA)
    return session


def _delegadas(session) -> set:
    with transaction(session.own_org_id) as conn:
        return {r['id'] for r in conn.execute(DELEGADAS, (session.own_org_id,)).fetchall()}


def _banda(fila):
    if fila['score'] is None:
        return None
    return criterio.banda(fila['score'], configuracion.cortes_de_fila(fila))


def _leer_cliente(session, cliente, ip, ruta, con_dominios):
    """Lee la empresa cliente con su propia RLS y deja el registro en su bitácora, en la misma transacción. None si no
    se ve o no está en trial o active (sin registro: no se leyó nada de ella)."""
    with transaction(cliente) as conn:
        org = conn.execute(EMPRESA, (cliente,)).fetchone()
        if not org or org['status'] not in ACTIVAS:
            return None
        dominios = conn.execute(DOMINIOS).fetchall()
        audit(conn, cliente, 'operator.client_data_read', ip=ip, entity_type='organization', entity_id=cliente,
              details={'route': ruta, 'via': 'delegation'},
              operator={'user_id': session.user_id, 'organization_id': session.own_org_id})
    # El riesgo de la empresa es el score más alto de sus dominios (DOMINIOS ya sale ordenado por score).
    top = next((d for d in dominios if d['score'] is not None), None)
    out = {'id': org['id'], 'name': org['name'], 'status': org['status'],
           'risk_score': top['score'] if top else None, 'risk_band': _banda(top) if top else None,
           'domains_count': len(dominios)}
    if con_dominios:
        out['domains'] = [{'id': d['id'], 'fqdn': d['fqdn'], 'status': d['status'], 'score': d['score'],
                           'band': _banda(d), 'computed_at': d['computed_at']} for d in dominios]
    return out


def _orden(item):
    # Más riesgo primero; las empresas sin score al final, luego por nombre y por id para que el orden sea fijo.
    return (item['risk_score'] is None, -(item['risk_score'] or 0), item['name'], item['id'])


@router.get('/organizations', summary='Empresas delegadas al integrador, ordenadas por su riesgo (solo operator)')
def list_organizations(request: Request, session: Session = Depends(operator)):
    ip = client_ip(request)
    items = []
    for cliente in sorted(_delegadas(session)):
        item = _leer_cliente(session, cliente, ip, '/api/v1/operator/organizations', False)
        if item:
            items.append(item)
    vigentes = _delegadas(session)  # una revocada mientras se leía ya no sale
    items = sorted((i for i in items if i['id'] in vigentes), key=_orden)
    return {'items': items, 'total': len(items)}


@router.get('/organizations/{organization_id}', summary='Una empresa delegada con sus dominios (solo operator)')
def get_organization(organization_id: str, request: Request, session: Session = Depends(operator)):
    try:
        cliente = str(uuid.UUID(organization_id))
    except ValueError:
        raise HTTPException(404, NO_ENCONTRADA)
    if cliente not in _delegadas(session):
        raise HTTPException(404, NO_ENCONTRADA)
    item = _leer_cliente(session, cliente, client_ip(request), '/api/v1/operator/organizations/{organization_id}',
                         True)
    if not item or cliente not in _delegadas(session):
        raise HTTPException(404, NO_ENCONTRADA)
    return item
