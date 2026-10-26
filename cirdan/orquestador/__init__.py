"""Orquestador de escaneos v0 (#22, RC-51).

Solo escanea un dominio si tiene **autorización firmada vigente** y **registro TXT verificado
justo antes del escaneo**. Si falta algo, no escanea y dice por qué. El trigger de `scans` en la
base exige lo mismo, así que hay dos candados.

Dos pasos:
1. `solicitar()`: revisa el dominio y la autorización, consulta el TXT, guarda la evidencia en
   `dns_txt_verifications` (check_reason 'pre_scan') y, si todo cumple, crea la fila en `scans`.
2. `correr()`: ejecuta cada recolector con `contrato.ejecutar()` (#13) y llena `scan_source_runs`
   con `siguiente_estado()`. En vivo reintenta ahí mismo la fuente que falla. Guardar activos y
   hallazgos en la base es de #23.

Mientras corre, el escaneo marca que sigue vivo en `scans.updated_at`. Si la API se reinicia o se
corta a mitad, `abandonar_vencidos()` lo da por caído pasado ABANDONO, así no queda en 'running' para
siempre ni bloquea el siguiente escaneo del dominio.

    python -m cirdan.orquestador olmardo.com            (ver __main__.py)
"""
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.types.json import Jsonb

from cirdan.config import config
from cirdan.db import audit, transaction
from cirdan.orquestador import txt as dns_txt
from cirdan.recolectores import REGISTRO, cargar
from cirdan.recolectores.contrato import ejecutar, siguiente_estado

# Por qué no se escanea: los mismos códigos de scan_eligibility.reasons del contrato #21, más los
# que solo aparecen al pedir el escaneo.
MOTIVOS = {
    'domain_not_found': 'El dominio no está registrado en tu organización',
    'domain_paused': 'El dominio está en pausa',
    'domain_removed': 'El dominio fue eliminado',
    'authorization_missing': 'Falta la autorización firmada',
    'authorization_not_started': 'La autorización firmada todavía no entra en vigor',
    'authorization_expired': 'La autorización firmada venció',
    'authorization_revoked': 'La autorización firmada fue revocada',
    'txt_not_verified': 'Falta verificar el registro TXT',
    'scan_in_progress': 'Ya hay un escaneo en curso para este dominio',
    'live_scan_not_allowed': 'Este dominio es de la demo y no se consulta en vivo',
}
TXT_DETALLE = {
    'missing': 'no tiene registro TXT',
    'mismatch': 'su registro TXT no coincide con el esperado',
    'dns_error': 'el DNS no respondió',
}
FUENTE_PRUEBAS = 'ejemplo'  # recolector sin red; solo cuando una prueba lo pide

# Marca de vida del escaneo. Entre una marca y otra pasa a lo más una corrida de una fuente: crt.sh con sus
# 3 intentos y las 4 páginas de Cert Spotter con los suyos tardan unos 13 minutos en el peor caso.
LATIDO = 60                       # segundos entre marcas mientras se espera un reintento
ABANDONO = timedelta(minutes=30)  # sin marca en ese tiempo, el escaneo se da por caído
ERROR_ABANDONO = 'El escaneo se cortó: pasaron más de 30 minutos sin marca de vida'
ERROR_YA_NO_CORRE = 'El escaneo dejó de estar en curso antes de terminar esta fuente'


def dominios_en_vivo():
    """Dominios que se pueden consultar en vivo (DNS y fuentes). '*' = todos (producción)."""
    return {d.strip().lower() for d in config('DOMINIOS_EN_VIVO', 'olmardo.com').split(',') if d.strip()}


def en_vivo_permitido(fqdn):
    permitidos = dominios_en_vivo()
    return '*' in permitidos or fqdn.lower() in permitidos


@dataclass
class Solicitud:
    """Respuesta a «quiero escanear este dominio»."""
    fqdn: str
    aceptada: bool
    motivos: list = field(default_factory=list)
    detalle: str = ''
    scan_id: str | None = None
    domain_id: str | None = None
    txt: str | None = None  # resultado de la consulta TXT, si se hizo


@contextmanager
def _tx(org, conn):
    """La conexión de la prueba (que se deshace al final) o una transacción nueva."""
    if conn is not None:
        yield conn
    else:
        with transaction(org) as nueva:
            yield nueva


def _texto(motivos, txt_resultado=None):
    partes = [MOTIVOS[m] for m in motivos]
    if txt_resultado in TXT_DETALLE and 'txt_not_verified' in motivos:
        partes[motivos.index('txt_not_verified')] += ' (%s)' % TXT_DETALLE[txt_resultado]
    return 'No se puede escanear: ' + '; '.join(p[0].lower() + p[1:] for p in partes) + '.'


def _motivos_previos(conn, domain):
    """Lo que se revisa antes de consultar el DNS: estado del dominio y autorización vigente."""
    motivos = []
    if domain['status'] == 'paused':
        motivos.append('domain_paused')
    elif domain['status'] == 'removed':
        motivos.append('domain_removed')
    vigente = conn.execute(
        'SELECT id FROM domain_authorizations WHERE domain_id = %s AND revoked_at IS NULL '
        'AND current_date BETWEEN valid_from AND valid_until ORDER BY valid_until DESC LIMIT 1',
        (domain['id'],)).fetchone()
    if vigente:
        return motivos, vigente['id']
    ultima = conn.execute(
        'SELECT revoked_at, valid_from > current_date AS futura FROM domain_authorizations '
        'WHERE domain_id = %s ORDER BY valid_until DESC LIMIT 1', (domain['id'],)).fetchone()
    if not ultima:
        motivos.append('authorization_missing')
    elif ultima['revoked_at']:
        motivos.append('authorization_revoked')
    elif ultima['futura']:
        motivos.append('authorization_not_started')
    else:
        motivos.append('authorization_expired')
    return motivos, None


def _motivo_del_trigger(conn, authorization_id):
    """Por qué el trigger de scans rechazó el escaneo, leído de la base y no del texto del error.

    Sigue el orden del trigger: la autorización existe, no está revocada y está vigente; si todo eso
    cumple, lo que falló es la verificación TXT.
    """
    a = conn.execute(
        'SELECT revoked_at IS NOT NULL AS revocada, valid_from > current_date AS futura, '
        'valid_until < current_date AS vencida FROM domain_authorizations WHERE id = %s', (authorization_id,)).fetchone()
    if not a:
        return 'authorization_missing'
    if a['revocada']:
        return 'authorization_revoked'
    if a['futura']:
        return 'authorization_not_started'
    if a['vencida']:
        return 'authorization_expired'
    return 'txt_not_verified'


def _cerrar_corridas(conn, scan_ids, error):
    """Las fuentes de un escaneo que ya no corre no tendrán reintento: quedan en 'failed'."""
    conn.execute(
        "UPDATE scan_source_runs SET status = 'failed', next_retry_at = NULL, error = coalesce(error, %s), "
        "updated_at = now() WHERE scan_id = ANY(%s::uuid[]) AND status IN ('pending', 'running', 'retrying')",
        (error, list(scan_ids)))


def abandonar_vencidos(conn, org, domain_id=None, scan_id=None):
    """Da por caídos los escaneos activos sin marca de vida en ABANDONO y devuelve sus ids.

    Pasa si la API se reinició o se cortó a mitad de un escaneo. Sin esto, el escaneo quedaría en
    'running' para siempre y el índice único de scans rechazaría cada escaneo nuevo del dominio con
    scan_in_progress. Corre en la transacción de la organización, así que RLS limita lo que toca.
    """
    ids = [r['id'] for r in conn.execute(
        "UPDATE scans SET status = 'failed', finished_at = now(), updated_at = now(), "
        "stats = coalesce(stats, '{}'::jsonb) || %s "
        "WHERE status IN ('queued', 'running') AND updated_at < now() - %s "
        "AND (%s::uuid IS NULL OR domain_id = %s::uuid) AND (%s::uuid IS NULL OR id = %s::uuid) RETURNING id::text",
        (Jsonb({'error': ERROR_ABANDONO}), ABANDONO, domain_id, domain_id, scan_id, scan_id)).fetchall()]
    if ids:
        _cerrar_corridas(conn, ids, ERROR_ABANDONO)
        for i in ids:
            audit(conn, org, 'scan.abandoned', None, None, 'scan', i, {'error': ERROR_ABANDONO})
    return ids


def solicitar(org, fqdn, user_id=None, ip=None, trigger='on_demand', consultar=None, conn=None):
    """Revisa autorización y TXT y, si todo cumple, crea el escaneo. Nunca escanea sin los dos.

    `consultar` reemplaza la consulta DNS real (pruebas). Sin él, solo se consultan en vivo los
    dominios de DOMINIOS_EN_VIVO.
    """
    fqdn = fqdn.strip().lower().rstrip('.')
    with _tx(org, conn) as c:
        domain = c.execute('SELECT id::text, fqdn::text, status, txt_token FROM domains WHERE fqdn = %s', (fqdn,)).fetchone()
        if not domain:
            return Solicitud(fqdn, False, ['domain_not_found'], _texto(['domain_not_found']))

        motivos, authorization_id = _motivos_previos(c, domain)
        if not motivos and domain['status'] != 'verified':
            motivos.append('txt_not_verified')  # el alta (#26) todavía no verifica el TXT
        if not motivos and consultar is None and not en_vivo_permitido(fqdn):
            motivos.append('live_scan_not_allowed')

        txt_resultado = None
        verification_id = None
        if not motivos:
            consulta = (consultar or dns_txt.consultar_dns)(fqdn)
            txt_resultado = dns_txt.resultado(consulta, domain['txt_token'])
            verification_id = c.execute(
                'INSERT INTO dns_txt_verifications (organization_id, domain_id, check_reason, expected_value, '
                'observed_values, resolver_ip, result, checked_at) VALUES (%s, %s, %s, %s, %s, %s, %s, now()) '
                'RETURNING id::text',
                (org, domain['id'], 'pre_scan', dns_txt.esperado(domain['txt_token']),
                 list(consulta.valores) if consulta.valores else None, consulta.resolver_ip, txt_resultado)).fetchone()['id']
            if txt_resultado != 'match':
                motivos.append('txt_not_verified')

        # checked_at = now() (inicio de la transacción), igual que scans.queued_at: el trigger exige
        # que la verificación sea de la hora anterior al escaneo, y clock_timestamp() quedaría después.
        scan_id = None
        if not motivos:
            abandonar_vencidos(c, org, domain_id=domain['id'])  # uno caído no cuenta como escaneo en curso
            try:
                with c.transaction():  # punto de guardado: un choque no borra la evidencia del TXT
                    scan_id = c.execute(
                        'INSERT INTO scans (organization_id, domain_id, authorization_id, txt_verification_id, '
                        'trigger_type, requested_by, status) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id::text',
                        (org, domain['id'], authorization_id, verification_id, trigger, user_id, 'running')).fetchone()['id']
            except psycopg.errors.UniqueViolation:
                motivos.append('scan_in_progress')
            except psycopg.errors.CheckViolation as e:  # segundo candado: el trigger de scans dijo que no
                if e.diag.constraint_name:
                    raise  # un CHECK de la tabla, no el trigger: es un error del código
                motivos.append(_motivo_del_trigger(c, authorization_id))

        if motivos:
            detalle = _texto(motivos, txt_resultado)
            audit(c, org, 'scan.rejected', user_id, ip, 'domain', domain['id'],
                  {'fqdn': fqdn, 'reasons': motivos, 'txt': txt_resultado})
            return Solicitud(fqdn, False, motivos, detalle, domain_id=domain['id'], txt=txt_resultado)

        audit(c, org, 'scan.requested', user_id, ip, 'scan', scan_id, {'fqdn': fqdn, 'trigger': trigger})
        return Solicitud(fqdn, True, scan_id=scan_id, domain_id=domain['id'], txt=txt_resultado,
                         detalle='Escaneo de %s en curso.' % fqdn)


def fuentes_activas(conn):
    """Fuentes del escaneo normal: habilitadas en data_sources y con recolector registrado."""
    filas = conn.execute('SELECT code FROM data_sources WHERE enabled AND kind = %s ORDER BY code', ('osint',)).fetchall()
    return [f['code'] for f in filas if f['code'] in REGISTRO and f['code'] != FUENTE_PRUEBAS]


def _latido(org, scan_id, conn=None):
    """Marca que el escaneo sigue vivo. False si ya no está en 'running' (por ejemplo, lo dieron por caído)."""
    with _tx(org, conn) as c:
        return c.execute("UPDATE scans SET updated_at = now() WHERE id = %s AND status = 'running' RETURNING id",
                         (scan_id,)).fetchone() is not None


def _esperar(org, scan_id, segundos, conn, dormir):
    """Espera al reintento de una fuente sin perder la marca de vida. False si el escaneo ya no corre."""
    while segundos > 0:
        if not _latido(org, scan_id, conn):
            return False
        paso = min(LATIDO, segundos)
        dormir(paso)
        segundos -= paso
    return True


def _ya_no_corre(org, scan_id, conn, corridas):
    """El escaneo dejó de estar en 'running' a mitad: no se toca su estado, solo se cierran sus fuentes."""
    with _tx(org, conn) as c:
        _cerrar_corridas(c, [scan_id], ERROR_YA_NO_CORRE)
        scan = c.execute('SELECT status, stats FROM scans WHERE id = %s', (scan_id,)).fetchone()
    return {'scan_id': scan_id, 'status': scan['status'], 'stats': scan['stats'] or {}, 'sources': corridas}


def correr(org, scan_id, fqdn, fuentes=None, modo='vivo', ahora=None, conn=None, dormir=None):
    """Ejecuta los recolectores de un escaneo aceptado y deja el estado de cada fuente.

    Un recolector que falla no tumba el escaneo. En vivo, su fuente queda en 'retrying' y se vuelve a
    correr ahí mismo a 1, 5 y 25 minutos (siguiente_estado, #13). Mientras espera, el escaneo marca que
    sigue vivo y, si alguien lo dio por caído, deja de correr. Al reproducir o grabar no se reintenta: la
    respuesta sería la misma, o se volvería a vaciar la grabación, así que la fuente queda en 'failed'.
    Una fuente que no se recupera deja el escaneo 'partial'. También termina 'partial' si una fuente respondió
    pero dejó códigos en sin_cobertura (por ejemplo, crt.sh con el respaldo de Cert Spotter), así no
    se muestran como 0 hallazgos. crt.sh nunca busca dominios parecidos desde aquí, porque consulta
    variantes que pueden ser de terceros: lookalike_domain siempre queda en sin_cobertura. Devuelve un resumen.
    `dormir` reemplaza time.sleep (pruebas).
    """
    dormir = dormir or time.sleep
    fqdn = fqdn.strip().lower().rstrip('.')
    with _tx(org, conn) as c:
        fuentes = fuentes if fuentes is not None else fuentes_activas(c)
        catalogo = {f['code']: f for f in c.execute(
            'SELECT id::text, code, keep_raw_payload FROM data_sources WHERE code = ANY(%s)', (fuentes,)).fetchall()}
        propios = [r['fqdn'] for r in c.execute('SELECT fqdn::text FROM domains WHERE fqdn <> %s', (fqdn,)).fetchall()]

    if modo == 'vivo' and not en_vivo_permitido(fqdn):
        modo = 'reproducir'  # nunca consultar en vivo un dominio fuera de DOMINIOS_EN_VIVO

    reintenta = modo == 'vivo'
    corridas, activos, hallazgos = [], 0, 0
    for codigo in fuentes:
        intento = 0
        while True:
            if not _latido(org, scan_id, conn):
                return _ya_no_corre(org, scan_id, conn, corridas)
            res = ejecutar(cargar(codigo), fqdn, modo, ahora=ahora, propios=propios)
            momento = datetime.now(timezone.utc)
            status, attempt, next_retry_at = (siguiente_estado(res.estado, intento, momento) if reintenta
                                              else (res.estado, 0, None))
            resumen = {'activos': len(res.activos), 'hallazgos': len(res.hallazgos), 'consultas': res.consultas,
                       'avisos': res.avisos[:10], 'sin_cobertura': res.sin_cobertura}
            with _tx(org, conn) as c:  # una fila por fuente: cada reintento la actualiza
                c.execute(
                    'INSERT INTO scan_source_runs (organization_id, scan_id, source_id, status, attempt, next_retry_at, '
                    'raw_payload, error, finished_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now()) '
                    'ON CONFLICT (scan_id, source_id) DO UPDATE SET status = EXCLUDED.status, attempt = EXCLUDED.attempt, '
                    'next_retry_at = EXCLUDED.next_retry_at, raw_payload = EXCLUDED.raw_payload, error = EXCLUDED.error, '
                    'finished_at = EXCLUDED.finished_at, updated_at = now()',
                    (org, scan_id, catalogo[codigo]['id'], status, attempt, next_retry_at,
                     Jsonb(resumen) if catalogo[codigo]['keep_raw_payload'] else None, res.error or None))
            if status != 'retrying':
                break
            if not _esperar(org, scan_id, (next_retry_at - momento).total_seconds(), conn, dormir):
                return _ya_no_corre(org, scan_id, conn, corridas)
            intento = attempt
        corridas.append({'source': codigo, 'status': status, 'error': res.error or None,
                         'avisos_omitidos': max(0, len(res.avisos) - len(resumen['avisos'])), **resumen})
        if res.estado == 'succeeded':
            activos += len(res.activos)
            hallazgos += len(res.hallazgos)

    ok = sum(1 for r in corridas if r['status'] == 'succeeded')
    sin_cobertura = sorted({c for r in corridas if r['status'] == 'succeeded' for c in r['sin_cobertura']})
    estado = 'completed' if ok == len(corridas) and not sin_cobertura else 'failed' if ok == 0 else 'partial'
    stats = {'assets': activos, 'findings': hallazgos, 'sources_ok': ok, 'sources_failed': len(corridas) - ok}
    if sin_cobertura:
        stats['rules_without_coverage'] = sin_cobertura
    with _tx(org, conn) as c:
        cerrado = c.execute("UPDATE scans SET status = %s, finished_at = now(), stats = %s, updated_at = now() "
                            "WHERE id = %s AND status = 'running' RETURNING id", (estado, Jsonb(stats), scan_id)).fetchone()
        if cerrado:  # si lo dieron por caído entre la última fuente y aquí, se queda como está
            c.execute('UPDATE domains SET last_scan_at = now(), updated_at = now() WHERE fqdn = %s', (fqdn,))
            audit(c, org, 'scan.finished', None, None, 'scan', scan_id, {'fqdn': fqdn, 'status': estado, **stats})
    if not cerrado:
        return _ya_no_corre(org, scan_id, conn, corridas)
    return {'scan_id': scan_id, 'status': estado, 'stats': stats, 'sources': corridas}


def marcar_fallido(org, scan_id, error):
    """Si algo inesperado tumba el escaneo, no lo deja 'running' para siempre ni a sus fuentes esperando."""
    with transaction(org) as c:
        if c.execute("UPDATE scans SET status = 'failed', finished_at = now(), stats = %s, updated_at = now() "
                     "WHERE id = %s AND status = 'running' RETURNING id",
                     (Jsonb({'error': str(error)[:300]}), scan_id)).fetchone():
            _cerrar_corridas(c, [scan_id], str(error)[:300])
