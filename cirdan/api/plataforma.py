"""Superadmin de la plataforma (RC-332): /api/v1/platform/organizations y /api/v1/platform/organization.

El superadmin (tabla platform_admins, migración 017) ve la lista de empresas y elige con cuál trabaja. La sesión cambia
de empresa activa y, en una ajena, el rol es Admin. Todo lo demás de la API sigue igual: cada transacción fija
app.current_org con una sola empresa y RLS hace el resto. No hay vistas que mezclen empresas.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from cirdan.auth import sessions
from cirdan.auth.deps import SESION_TERMINADA, Session, client_ip, current_session, is_platform_admin
from cirdan.db import audit, transaction

router = APIRouter(prefix='/api/v1/platform', tags=['plataforma'])

SOLO_SUPERADMIN = 'Solo el superadmin de la plataforma puede hacer esto.'
NO_ENCONTRADA = 'Organización no encontrada'
INACTIVA = 'La organización está suspendida o cancelada: no se puede trabajar en ella.'
ACTIVAS = ('trial', 'active')
ROL_AJENO = 'admin'  # rol del superadmin en una empresa que no es la suya


class OrganizacionIn(BaseModel):
    organization_id: str = Field(min_length=1, max_length=64)


def platform_admin(request: Request) -> Session:
    """Sesión de un superadmin o 403. Mira la bandera de la sesión y luego la base: si se le quitó el permiso
    después de iniciar sesión, ya no entra. Una llave de API nunca llega aquí (solo cookie)."""
    session = current_session(request)
    if not session.platform_admin or not is_platform_admin(session.user_id):
        raise HTTPException(403, SOLO_SUPERADMIN)
    return session


def _organizaciones(session):
    with transaction() as conn:
        return conn.execute('SELECT organization_id::text AS id, name, status FROM public.platform_organizations(%s)',
                            (session.user_id,)).fetchall()


@router.get('/organizations', summary='Todas las organizaciones, con la activa y la propia marcadas (solo superadmin)')
def list_organizations(session: Session = Depends(platform_admin)):
    items = [dict(o, active=o['id'] == session.org_id, home=o['id'] == session.own_org_id)
             for o in _organizaciones(session)]
    return {'items': items, 'total': len(items)}


@router.post('/organization', summary='Cambia la organización activa de la sesión (solo superadmin)')
def switch_organization(body: OrganizacionIn, request: Request, session: Session = Depends(platform_admin)):
    try:
        destino = str(uuid.UUID(body.organization_id))
    except ValueError:
        raise HTTPException(404, NO_ENCONTRADA)
    org = next((o for o in _organizaciones(session) if o['id'] == destino), None)
    if not org:
        raise HTTPException(404, NO_ENCONTRADA)
    if org['status'] not in ACTIVAS:
        raise HTTPException(409, INACTIVA)
    ip = client_ip(request)
    home = session.own_org_id
    with transaction(home) as conn:
        # En su empresa vuelve a su rol de la base, que pudo cambiar después de iniciar sesión.
        fila = conn.execute('SELECT role FROM users WHERE id = %s AND is_active', (session.user_id,)).fetchone()
        if not fila:
            sessions.delete(session.token)
            raise HTTPException(401, SESION_TERMINADA)
        rol = fila['role'] if destino == home else ROL_AJENO
        if destino != session.org_id:
            audit(conn, home, 'platform.organization_switched', session.user_id, ip, 'organization', destino,
                  {'from_organization_id': session.org_id, 'to_organization_id': destino, 'to_name': org['name']})
            if destino != home:
                # También en la bitácora de la empresa a la que entra, para que su Admin lo vea.
                with transaction(destino) as ajena:
                    audit(ajena, destino, 'platform.organization_entered', None, ip, 'organization', destino,
                          {'home_organization_id': home},
                          platform={'user_id': session.user_id, 'email': session.email})
    # La sesión cambia hasta que las dos bitácoras ya se guardaron: un cambio nunca queda sin registro. Si Valkey
    # falla aquí, queda el registro de un intento que no cambió nada.
    if not sessions.switch_org(session.token, destino, rol):
        raise HTTPException(401, SESION_TERMINADA)
    return {'organization_id': destino, 'organization_name': org['name'], 'role': rol, 'home': destino == home}
