"""Fuentes por cliente (#117, RC-235): listar las fuentes con su estado y apagar o encender una para la empresa.

Solo el Administrador y siempre con la sesión del portal. La empresa solo apaga: una fuente corre si está encendida en
data_sources (lo global, de la plataforma) y la empresa no la apagó (org_source_settings, migración 034). Una fuente
apagada en lo global (censys, subfinder) no se enciende para un cliente y responde 409. Las fuentes de inteligencia
(nvd, first_epss, cisa_kev) son de la plataforma: no se listan para cambiar y responden 422. Cada cambio queda en la
bitácora con source.disabled o source.enabled. Repetir el mismo estado no la repite.
Apagar una fuente baja la cobertura: el siguiente escaneo sale con partial_coverage y su score deja de ser comparable
con los anteriores (el portal lo avisa antes de cambiar).
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, StrictBool

from cirdan.auth.deps import Session, client_ip, require_roles
from cirdan.db import audit, transaction
from cirdan.recolectores import REGISTRO

router = APIRouter(prefix='/api/v1/sources', tags=['fuentes'])
admin = require_roles('admin')

FUENTE_PRUEBAS = 'ejemplo'   # solo para pruebas: no se lista ni se cambia
NO_ENCONTRADA = 'Fuente no encontrada'
DE_PLATAFORMA = 'Las fuentes de inteligencia son de la plataforma y no se apagan por empresa.'
APAGADA_GLOBAL = 'La fuente está apagada en la plataforma. Una empresa solo puede apagar fuentes, no encenderlas.'


class FuenteIn(BaseModel):
    enabled: StrictBool


LISTA_SQL = '''
SELECT d.id::text, d.code, d.kind, d.enabled AS global_enabled, o.enabled AS org_enabled, o.changed_at,
       u.email::text AS changed_by, (o.changed_by_platform IS NOT NULL) AS changed_by_platform
  FROM data_sources d
  LEFT JOIN org_source_settings o ON o.source_id = d.id
  LEFT JOIN users u ON u.id = o.changed_by
 WHERE d.code <> %s
'''


def _fila(f):
    osint = f['kind'] == 'osint'
    apagada = f['org_enabled'] is False
    return {
        'code': f['code'], 'kind': f['kind'], 'global_enabled': f['global_enabled'],
        # null: la empresa no la ha cambiado y sigue lo global.
        'org_enabled': f['org_enabled'],
        'effective_enabled': f['global_enabled'] and not apagada and (not osint or f['code'] in REGISTRO),
        # Toda osint se puede apagar, también una apagada hoy en lo global, para que no corra si la plataforma la
        # enciende. Volver a encender solo quita el apagado de la empresa.
        'can_change': osint,
        'changed_at': f['changed_at'],
        'changed_by': None if f['changed_by_platform'] else f['changed_by'],
        'changed_by_platform': bool(f['changed_by_platform']),
    }


@router.get('', summary='Fuentes con su estado global y el de la empresa (solo Admin)')
def list_sources(session: Session = Depends(admin)):
    with transaction(session.org_id) as conn:
        filas = conn.execute(LISTA_SQL + ' ORDER BY d.kind DESC, d.code', (FUENTE_PRUEBAS,)).fetchall()
    items = [_fila(f) for f in filas]
    return {'items': items, 'total': len(items)}


@router.put('/{code}', summary='Apaga o vuelve a encender una fuente OSINT para la empresa (solo Admin)')
def set_source(code: str, body: FuenteIn, request: Request, session: Session = Depends(admin)):
    with transaction(session.org_id) as conn:
        # Candado sobre la empresa: dos cambios a la vez de la misma fuente quedan en orden en la bitácora. NO KEY
        # UPDATE y no UPDATE, para no chocar con las FK hacia organizations (como llaves.py).
        conn.execute('SELECT 1 FROM organizations o FOR NO KEY UPDATE OF o').fetchone()
        fuente = conn.execute('SELECT id::text, code, kind, enabled FROM data_sources WHERE code = %s AND code <> %s',
                              (code, FUENTE_PRUEBAS)).fetchone()
        if not fuente:
            raise HTTPException(404, NO_ENCONTRADA)
        if fuente['kind'] != 'osint':
            raise HTTPException(422, DE_PLATAFORMA)
        actual = conn.execute('SELECT enabled FROM org_source_settings WHERE source_id = %s',
                              (fuente['id'],)).fetchone()
        antes = actual['enabled'] if actual else True
        # Volver a encender una que la empresa apagó vale aunque hoy esté apagada en lo global: solo quita su
        # apagado y sigue sin correr hasta que la plataforma la encienda. Encender una que la empresa no apagó y que
        # está apagada en lo global sería encenderla para el cliente: 409.
        if body.enabled and antes and not fuente['enabled']:
            raise HTTPException(409, APAGADA_GLOBAL)
        if antes != body.enabled:
            conn.execute(
                'INSERT INTO org_source_settings (organization_id, source_id, enabled, changed_by, '
                'changed_by_platform, changed_at) VALUES (%s, %s, %s, %s, %s, now()) '
                'ON CONFLICT (organization_id, source_id) DO UPDATE SET enabled = EXCLUDED.enabled, '
                'changed_by = EXCLUDED.changed_by, changed_by_platform = EXCLUDED.changed_by_platform, '
                'changed_at = EXCLUDED.changed_at',
                (session.org_id, fuente['id'], body.enabled, session.audit_user_id,
                 session.user_id if session.acting_elsewhere else None))
            audit(conn, session.org_id, 'source.enabled' if body.enabled else 'source.disabled', session.audit_user_id,
                  client_ip(request), 'data_source', fuente['id'], {'code': fuente['code'], 'enabled': body.enabled},
                  platform=session.audit_platform)
        fila = conn.execute(LISTA_SQL + ' AND d.id = %s', (FUENTE_PRUEBAS, fuente['id'])).fetchone()
    return _fila(fila)
