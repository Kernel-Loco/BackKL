"""Bitácora de la empresa y "verificar integridad" (#86, RC-130). La pantalla es #86b (RC-174), en FrontKL.

Solo el Administrador, con la cookie de sesión: una llave de API no entra (require_roles). Un superadmin en una
empresa ajena entra como admin de esa empresa (RC-332) y ve la de esa empresa. RLS deja ver solo la empresa de la
sesión. Verificar es una lectura y no escribe en la bitácora. El SQL está en cirdan/bitacora.py.
"""
from fastapi import APIRouter, Depends, Query, Response
from psycopg import IsolationLevel

from cirdan import bitacora
from cirdan.auth.deps import Session, require_roles
from cirdan.db import transaction

router = APIRouter(prefix='/api/v1', tags=['portal'])


@router.get('/audit-log', summary='Bitácora de la empresa, de la más nueva a la más vieja (solo Admin)')
def audit_log(response: Response,
              limit: int = Query(default=500, ge=1, le=1000), offset: int = Query(default=0, ge=0, le=1_000_000),
              session: Session = Depends(require_roles('admin'))):
    # El total y la página salen de la misma foto de la base, aunque se escriba en la bitácora a la vez.
    with transaction(session.org_id, isolation=IsolationLevel.REPEATABLE_READ) as conn:
        total = conn.execute(bitacora.TOTAL_SQL).fetchone()['total']
        filas = conn.execute(bitacora.LISTA_SQL, (limit, offset)).fetchall()
    response.headers['Cache-Control'] = 'no-store'
    return {'items': [bitacora.fila(r) for r in filas], 'total': total, 'limit': limit, 'offset': offset}


@router.get('/audit-log/verify', summary='Recalcula la cadena de hashes de la bitácora: íntegra o el primer eslabón roto '
                                         '(solo Admin)')
def audit_log_verify(response: Response, session: Session = Depends(require_roles('admin'))):
    with transaction(session.org_id) as conn:
        fila = conn.execute(bitacora.VERIFICAR_SQL).fetchone()
    response.headers['Cache-Control'] = 'no-store'
    return bitacora.resultado(fila)
