"""Endpoints de escaneos (#22): pedir un escaneo y consultar su estado.

Solo Analista y Administrador pueden pedir escaneos (el Gerente es de solo lectura). El
escaneo corre en un hilo aparte porque con los reintentos de una fuente puede tardar más de
media hora. En BackgroundTasks ocuparía uno de los hilos con los que el servidor atiende las
peticiones. Si la API se reinicia a mitad, el escaneo se da por caído (orquestador.abandonar_vencidos).
"""
import threading

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from cirdan import orquestador
from cirdan.auth.deps import Session, client_ip, current_session, require_roles
from cirdan.db import transaction

router = APIRouter(prefix='/api/v1', tags=['escaneos'])

SCAN_SQL = '''
SELECT s.id::text, d.fqdn::text AS domain, s.trigger_type AS trigger, s.status, s.queued_at, s.finished_at, s.stats
  FROM scans s JOIN domains d ON d.id = s.domain_id
 WHERE s.id = %s
'''
RUNS_SQL = '''
SELECT ds.code AS source, r.status, r.attempt, r.error, r.finished_at
  FROM scan_source_runs r JOIN data_sources ds ON ds.id = r.source_id
 WHERE r.scan_id = %s ORDER BY ds.code
'''


def _scan(conn, scan_id):
    scan = conn.execute(SCAN_SQL, (scan_id,)).fetchone()
    if scan:
        scan['sources'] = conn.execute(RUNS_SQL, (scan_id,)).fetchall()
    return scan


def _correr(org, scan_id, fqdn):
    try:
        orquestador.correr(org, scan_id, fqdn)
    except Exception as e:  # nunca dejar un escaneo en 'running' para siempre
        orquestador.marcar_fallido(org, scan_id, e)


@router.post('/domains/{fqdn}/scans', status_code=202, summary='Pide un escaneo (solo con autorización vigente y TXT verificado)')
def request_scan(fqdn: str, request: Request, session: Session = Depends(require_roles('analyst', 'admin'))):
    solicitud = orquestador.solicitar(session.org_id, fqdn, user_id=session.user_id, ip=client_ip(request))
    if not solicitud.aceptada:
        status = 404 if solicitud.motivos == ['domain_not_found'] else 409
        return JSONResponse({'accepted': False, 'detail': solicitud.detalle, 'reasons': solicitud.motivos}, status_code=status)
    threading.Thread(target=_correr, args=(session.org_id, solicitud.scan_id, solicitud.fqdn),
                     name='escaneo-' + solicitud.scan_id, daemon=True).start()
    with transaction(session.org_id) as conn:
        return {'accepted': True, 'scan': _scan(conn, solicitud.scan_id)}


@router.get('/scans/{scan_id}', summary='Estado de un escaneo y de cada fuente')
def get_scan(scan_id: str, session: Session = Depends(current_session)):
    try:
        with transaction(session.org_id) as conn:
            orquestador.abandonar_vencidos(conn, session.org_id, scan_id=scan_id)
            scan = _scan(conn, scan_id)
    except Exception:
        scan = None  # un id mal formado se responde igual que uno de otra empresa
    if not scan:
        raise HTTPException(404, 'Escaneo no encontrado')
    return scan
