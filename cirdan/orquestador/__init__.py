"""Orquestador de escaneos v0 (#22, RC-51).

Solo escanea un dominio si tiene **autorización firmada vigente** y **registro TXT verificado
justo antes del escaneo**. Si falta algo, no escanea y dice por qué. El trigger de `scans` en la
base exige lo mismo, así que hay dos candados.

Dos pasos:
1. `solicitar()`: revisa el dominio y la autorización, consulta el TXT, guarda la evidencia en
   `dns_txt_verifications` (check_reason 'pre_scan') y, si todo cumple, crea la fila en `scans`.
2. `correr()`: ejecuta cada recolector con `contrato.ejecutar()` (#13) y llena `scan_source_runs`
   con `siguiente_estado()`. En vivo reintenta ahí mismo la fuente que falla. Guarda activos y
   hallazgos de cada fuente que respondió (#31 y #23) y da por resuelto lo que esa fuente ya no encontró.

Cada fuente tiene un límite diario de consultas de toda la plataforma en `data_sources` (#13b, RC-184).
Antes de cada corrida que sale a la red, `correr()` reserva el máximo de la corrida y al terminar ajusta a lo
que de verdad gastó. Sin cupo, la fuente queda en 'failed' sin llamar al recolector.

Mientras corre, el escaneo marca que sigue vivo en `scans.updated_at`. Si la API se reinicia o se
corta a mitad, `abandonar_vencidos()` lo da por caído pasado ABANDONO, así no queda en 'running' para
siempre ni bloquea el siguiente escaneo del dominio. Un escaneo que ya no está en 'running' no vuelve a
escribir en sus fuentes.

    python -m cirdan.orquestador olmardo.com            (ver __main__.py)
"""
import ipaddress
import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.types.json import Jsonb

from cirdan import alcance_carta, db
from cirdan.config import config
from cirdan.db import audit, transaction
from cirdan.orquestador import txt as dns_txt
from cirdan.recolectores import REGISTRO, cargar, certspotter, turno
from cirdan.recolectores.contrato import COLUMNAS_CVES, CVE_VALIDA, Resultado, ejecutar, siguiente_estado
from cirdan.score import configuracion, motor

log = logging.getLogger(__name__)

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

# Marca de vida del escaneo. Una corrida de crt.sh puede tardar unos 15 minutos solo de HTTP: 865 s en el peor caso,
# con crt.sh arriba y lento (120 s de sus 2 búsquedas juntas, PLAZO_PRINCIPAL de crtsh.py, RC-218, 180 s de las 4
# páginas de Cert Spotter con 2 intentos de 20 s, 95 s de %marca% con 2 intentos de 45 s y 470 s de las 10 variantes,
# que es PRESUPUESTO_VARIANTES de crtsh.py, con 20 s en el primer intento y hasta 45 s en el segundo, o 45 s desde el primero
# si crt.sh viene lento: el presupuesto no cambia, #109, RC-226).
# Quedan 335 s antes de TOPE_CORRIDA, y el DNS de los nombres vencidos tiene PLAZO_DNS (300 s de crtsh.py, RC-288).
# Por eso, mientras corre una fuente, un hilo aparte marca vida cada LATIDO, hasta TOPE_CORRIDA: una corrida
# colgada para siempre deja de marcar y el escaneo se da por caído pasado ABANDONO.
LATIDO = 60                           # segundos entre marcas
TOPE_CORRIDA = timedelta(minutes=20)  # una corrida no marca vida más allá de esto
ABANDONO = timedelta(minutes=30)      # sin marca en ese tiempo, el escaneo se da por caído
ERROR_ABANDONO = 'El escaneo se cortó: pasaron más de 30 minutos sin marca de vida'
ACCION_HALLAZGO_RESUELTO = 'finding.resolved'
MOTIVO_SECRETO_ROTADO = 'secret_rotated'
ERROR_YA_NO_CORRE = 'El escaneo dejó de estar en curso antes de terminar esta fuente'

# Límite diario por fuente (#13b, RC-184): vive en data_sources (daily_limit, daily_used, daily_used_on) y solo
# lo mueven reserve_source_quota() y adjust_source_quota() de la migración 008, con el día en UTC. Se reserva
# MAX_CONSULTAS del recolector antes de cada corrida, también en cada reintento, porque las consultas reales
# solo se saben al final: así dos escaneos a la vez, o la API y la línea de comandos, no pasan el límite.
# Reproducir no sale a la red: no reserva ni ajusta.
MODOS_CON_CUPO = ('vivo', 'grabar')
# Una petición a la vez por host también entre escaneos (cirdan/recolectores/turno.py, comentario 10281.2 de RC-46):
# cada petición a un sitio del dominio toma antes un candado de PostgreSQL con la llave del host (_turno_host). Lo
# comparten la API y el programador, que usan la misma base. SEMILLA_TURNO separa estas llaves de las del alta de
# dominios (hashtextextended(fqdn, 59), migración 029).
SEMILLA_TURNO = 46
MIN_ESPERA_TURNO = 0.001  # segundos: con menos ya no se pide el turno
# La conexión del turno no tiene que quedar viva sin que nadie se entere: keepalives de los dos lados y tcp_user_timeout
# (ms) para datos sin confirmar. Si el cliente se cae, el servidor suelta el candado en unos 11 s y no en las 2 h que
# da Linux por omisión. Si la red o el servidor se caen, el cliente lo nota igual y la consulta falla (SinBase).
RED_TURNO = dict(keepalives=1, keepalives_idle=5, keepalives_interval=2, keepalives_count=3, tcp_user_timeout=10000,
                 options='-c tcp_keepalives_idle=5 -c tcp_keepalives_interval=2 -c tcp_keepalives_count=3 '
                         '-c tcp_user_timeout=10000')
# Códigos de HIBP cuyo hallazgo lleva su fila en breach_exposures (RC-54): nombre, fecha y clases de datos de la brecha.
BRECHAS = ('breach_exposure', 'breach_exposure_old', 'breach_exposure_no_passwords')
# Correos del dominio para el recolector que declara PIDE_CORREOS (HIBP, RC-54), de dos fuentes, cada una solo si la
# carta vigente del escaneo autoriza su actividad (alcance_carta, RC-59): sin la 4 no van los de GitHub y sin la 8 no
# van los de identidad, aunque los haya juntado una corrida con una carta anterior.
# 1. GitHub (#16): los de los hallazgos email_in_public_commits que siguen abiertos o con riesgo aceptado. Nunca uno ya
#    resuelto. assets.attributes se une entre fuentes, así que el correo sale del hallazgo y no de attributes.fuente.
# 2. Identidad (#20, RC-56): los activos email del dominio que vio alguna corrida de identity que respondió
#    ('succeeded') desde su última corrida completa (scan_source_runs.coverage = 'complete': revisó todas sus partes),
#    esa incluida. El orquestador marca cada correo que da identity con el escaneo que lo vio (_marcar_identidad):
#    attributes.identidad_scan en todo modo e identidad_scan_vivo solo en vivo y al grabar. Solo identity cambia esas
#    llaves: que HIBP o GitHub suban last_seen_at no revive un correo. Así un correo que la última corrida completa ya
#    no vio no entra, y una corrida parcial o sin cobertura (el sitio caído) no saca los que no pudo revisar. Sin
#    ninguna corrida completa cuentan todas las que respondieron. En un escaneo en vivo no cuentan las corridas en modo
#    reproducir (scan_source_runs.mode), que pueden traer una grabación vieja, y se lee identidad_scan_vivo, que una
#    corrida en reproducir no pisa. Lo guardado antes de la migración 032 no tiene
#    marca y espera a que identity lo vuelva a ver. Los correos personales (servicios gratuitos) nunca son activos,
#    solo su HMAC (identidad.py), así que nunca se consultan. Como HIBP corre después de identity (fuentes_activas),
#    entran los de este mismo escaneo si identity respondió.
# Nunca un correo con un hallazgo marcado como falso positivo sobre un activo email con ese valor, de cualquier dominio
# de la organización: el hallazgo de GitHub no lleva el dominio en la huella y el upsert lo mueve al dominio que lo vio
# al último. Hoy solo GitHub da hallazgos sobre el activo email: un correo que solo vio identity no tiene cómo
# excluirse así (sus hallazgos y los de HIBP cuelgan del dominio). Solo los del dominio del escaneo (assets.domain_id),
# y hibp._correos_validos vuelve a revisar que sean del dominio o de un subdominio. RLS deja solo los de la organización
# del escaneo, y la consulta también la fija.
# Van primero los que HIBP no ha consultado nunca y luego los que hace más que no consulta (attributes.hibp_consultado),
# así el tope de hibp.MAX_CORREOS rota entre escaneos y no deja siempre fuera a los mismos. `total` es cuántos había
# antes del tope, para el aviso de los que sobran.
_IDENTITY_RESPONDIO = (
    "SELECT {r}.scan_id, {r}.finished_at FROM scan_source_runs {r} JOIN scans {s} ON {s}.id = {r}.scan_id "
    "JOIN data_sources {d} ON {d}.id = {r}.source_id WHERE {s}.domain_id = %(dominio)s AND {d}.code = 'identity' "
    "AND {r}.status = 'succeeded' AND (%(reproducir)s OR {r}.mode IS DISTINCT FROM 'reproducir')")
CORREOS_SQL = (
    "SELECT correo, count(*) OVER () AS total FROM ("
    "SELECT lower(a.value) AS correo FROM findings f "
    "JOIN assets a ON a.id = f.asset_id JOIN scoring_rules r ON r.id = f.rule_id "
    "WHERE %(con_github)s AND f.domain_id = %(dominio)s AND r.code = 'email_in_public_commits' "
    "AND a.asset_type = 'email' AND f.status IN ('open', 'accepted_risk') "
    "UNION "
    "SELECT lower(a.value) FROM assets a "
    "WHERE %(con_identidad)s AND a.domain_id = %(dominio)s AND a.asset_type = 'email' "
    "AND a.attributes->>(CASE WHEN %(reproducir)s THEN 'identidad_scan' ELSE 'identidad_scan_vivo' END) IN ("
    "SELECT v.scan_id::text FROM (" + _IDENTITY_RESPONDIO.format(r='r', s='s', d='d') + ") v "
    "WHERE v.finished_at >= COALESCE((SELECT max(u.finished_at) FROM (" + _IDENTITY_RESPONDIO.format(
        r='r2', s='s2', d='d2') + " AND r2.coverage = 'complete') u), '-infinity'))"
    ") c WHERE NOT EXISTS (SELECT 1 FROM findings f JOIN assets a ON a.id = f.asset_id "
    "WHERE a.organization_id = (SELECT organization_id FROM domains WHERE id = %(dominio)s) "
    "AND a.asset_type = 'email' AND lower(a.value) = c.correo AND f.status = 'false_positive') "
    "ORDER BY (SELECT max(x.attributes->>'hibp_consultado') FROM assets x WHERE x.domain_id = %(dominio)s "
    "AND x.asset_type = 'email' AND lower(x.value) = c.correo) NULLS FIRST, correo LIMIT %(tope)s")
MAX_CORREOS = 200   # el recolector consulta menos (hibp.MAX_CORREOS) y avisa de los que sobran
SIN_CUPO = 'Sin cupo diario: %s no tiene cupo para una corrida completa hoy (día UTC).'

# Costo medido del escaneo (#52, RC-87): se guarda en scans.stats para el costo interno, pero GET /api/v1/scans y
# GET /api/v1/scans/{id} no lo entregan al portal ni a las llaves de API. Las demás llaves de stats salen igual.
STATS_INTERNAS = frozenset({'queries', 'queries_by_source', 'seconds_by_source', 'duration_seconds'})


def stats_publicas(stats):
    """scans.stats sin las llaves de STATS_INTERNAS. Un stats en NULL se queda en None."""
    if stats is None:
        return None
    return {k: v for k, v in stats.items() if k not in STATS_INTERNAS}

# Los hallazgos de una empresa se guardan de una fuente a la vez (RC-55). Dos dominios de la misma empresa pueden dar
# la misma huella (un repo de GitHub declarado en los dos, el certificado de un subdominio) y escanearse a la vez:
# así el segundo ve lo que insertó el primero y no lo cuenta otra vez como nuevo. Es la forma de dos llaves de
# pg_advisory_xact_lock, que no choca con la de una llave del trigger de audit_log.
CANDADO_HALLAZGOS = 'cirdan.findings'


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


def solicitar(org, fqdn, user_id=None, ip=None, trigger='on_demand', consultar=None, conn=None, platform=None):
    """Revisa autorización y TXT y, si todo cumple, crea el escaneo. Nunca escanea sin los dos.

    `platform` es el superadmin que lo pide desde una empresa ajena (RC-332), con user_id None: va a la bitácora
    con actor 'platform' y el escaneo queda sin requested_by.

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
                 dns_txt.guardables(consulta.valores) if consulta.valores else None, consulta.resolver_ip, txt_resultado)).fetchone()['id']
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
                  {'fqdn': fqdn, 'reasons': motivos, 'txt': txt_resultado}, platform=platform)
            return Solicitud(fqdn, False, motivos, detalle, domain_id=domain['id'], txt=txt_resultado)

        audit(c, org, 'scan.requested', user_id, ip, 'scan', scan_id, {'fqdn': fqdn, 'trigger': trigger},
              platform=platform)
        return Solicitud(fqdn, True, scan_id=scan_id, domain_id=domain['id'], txt=txt_resultado,
                         detalle='Escaneo de %s en curso.' % fqdn)


def fuentes_activas(conn):
    """Fuentes del escaneo normal: habilitadas en data_sources y con recolector registrado, en orden de code.

    Las que piden correos (PIDE_CORREOS, HIBP, RC-54) van al final, en orden de code entre ellas, para que lean los
    correos que github e identity guardaron en este mismo escaneo (CORREOS_SQL). Las demás no cambian de orden. Una
    fuente cuyo módulo no se puede importar se queda en su lugar y falla en su turno, como antes: no tumba el escaneo
    antes de que corran las demás."""
    filas = conn.execute('SELECT code FROM data_sources WHERE enabled AND kind = %s ORDER BY code', ('osint',)).fetchall()
    codigos = [f['code'] for f in filas if f['code'] in REGISTRO and f['code'] != FUENTE_PRUEBAS]
    return sorted(codigos, key=_pide_correos)


def _pide_correos(codigo):
    try:
        modulo = cargar(codigo)
    except Exception:   # nunca el texto: lo deja el bucle de correr() cuando le toque
        return False
    return getattr(modulo, 'PIDE_CORREOS', False) is True


def _latido(org, scan_id, conn=None):
    """Marca que el escaneo sigue vivo. False si ya no está en 'running' (por ejemplo, lo dieron por caído)."""
    with _tx(org, conn) as c:
        return c.execute("UPDATE scans SET updated_at = now() WHERE id = %s AND status = 'running' RETURNING id",
                         (scan_id,)).fetchone() is not None


# Las partes de un hallazgo guardado, como arreglo jsonb (#23). Lo guardado antes de evidence.partes las tiene en otra
# llave: el secreto de GitHub su repo en 'repo', el puerto de Shodan su IP en 'ip' (la CVE, con '/cve'), y el correo
# sus repos en 'repos', que sirven solo si no se cortaron en MAX_REPOS_ACTIVO (5) de github.py. La vigencia de un
# certificado de ct_logs la arma con 'host' y 'vence', como _parte de crtsh.py (RC-55).
# Hallazgos de ct_logs que se cierran por fecha en toda corrida de la fuente que respondió, aunque sea parcial (RC-55 y
# RC-218): (código, campo de la evidencia, días). Se cierra si el campo es anterior a la hora del escaneo menos esos
# días. cert_new_issuer deja de ser reciente a los crtsh.VENTANA_EMISOR_DIAS de emitido o al vencer, y
# cert_internal_name cuenta hasta crtsh.VENTANA_VENCIDOS_DIAS después de vencer su certificado más reciente.
CIERRE_POR_FECHA = (('cert_expiring_soon', 'vence', 0), ('cert_new_issuer', 'vence', 0),
                    ('cert_new_issuer', 'emitido', 90), ('cert_internal_name', 'vence', 365))

PARTES = ('''COALESCE(evidence->'partes', '''
          '''CASE WHEN jsonb_typeof(evidence->'repo') = 'string' THEN jsonb_build_array(evidence->'repo') END, '''
          '''CASE WHEN jsonb_typeof(evidence->'ip') = 'string' THEN '''
          '''jsonb_build_array(evidence->>'ip' || CASE WHEN evidence ? 'cve' THEN '/cve' ELSE '' END) END, '''
          '''CASE WHEN jsonb_typeof(evidence->'repos') = 'array' THEN CASE WHEN jsonb_array_length(evidence->'repos') '''
          '''< 5 THEN evidence->'repos' END END, '''
          '''CASE WHEN evidence->>'origen' IN ('crtsh', 'certspotter') AND jsonb_typeof(evidence->'host') = 'string' '''
          '''AND jsonb_typeof(evidence->'vence') = 'string' '''
          '''THEN jsonb_build_array((evidence->>'host') || '@' || (evidence->>'vence')) END, '[]'::jsonb)''')


def _cve_de(hallazgo):
    """La CVE de un hallazgo (su evidencia 'cve', como la ponen Shodan y la visita web), o None si no trae una con la
    forma del CHECK de cves.cve_id."""
    cve = hallazgo.evidencia.get('cve') if isinstance(hallazgo.evidencia, dict) else None
    return cve if isinstance(cve, str) and CVE_VALIDA.fullmatch(cve) else None


def _guardar_resultado(conn, org, scan_id, domain_id, source_id, resultado, reglas, ahora=None):
    """Guarda activos y hallazgos de una fuente que respondió. Devuelve dos conjuntos de id de hallazgos: los que
    abrió (insertó o reabrió) y los que dio por resueltos. `ahora` es la hora del escaneo (la de correr), y sin ella
    la de este momento."""
    # org pasa por uuid para que la llave sea la misma aunque la línea de comandos la reciba en mayúsculas.
    conn.execute('SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s::uuid::text))', (CANDADO_HALLAZGOS, org))
    atributos_raiz = {}
    for activo in resultado.activos:
        if activo.tipo == 'domain' and activo.valor == resultado.dominio:
            atributos_raiz.update(activo.atributos)
    raiz = conn.execute(
        "INSERT INTO assets (organization_id, domain_id, asset_type, value, attributes, first_seen_at, last_seen_at) "
        "VALUES (%s, %s, 'domain', %s, %s, now(), now()) "
        "ON CONFLICT (domain_id, asset_type, value) DO UPDATE SET "
        "attributes = assets.attributes || EXCLUDED.attributes, "
        "last_seen_at = GREATEST(assets.last_seen_at, EXCLUDED.last_seen_at), updated_at = now() "
        "RETURNING id::text", (org, domain_id, resultado.dominio, Jsonb(atributos_raiz))).fetchone()['id']
    activos = {resultado.dominio: raiz}

    for activo in resultado.activos:
        if activo.tipo == 'domain' and activo.valor == resultado.dominio:
            continue
        atributos = activo.atributos
        parent_id = activos.get(atributos.get('parent'), raiz)
        ip_value = None
        if activo.tipo == 'ip':
            ip_value = str(ipaddress.ip_address(activo.valor))
        elif isinstance(atributos.get('ip_address'), str):
            try:
                ip_value = str(ipaddress.ip_address(atributos['ip_address']))
            except ValueError:
                pass
        asset_id = conn.execute(
            'INSERT INTO assets (organization_id, domain_id, parent_asset_id, asset_type, value, ip_address, '
            'attributes, first_seen_at, last_seen_at) VALUES (%s, %s, %s, %s, %s, %s, %s, now(), now()) '
            'ON CONFLICT (domain_id, asset_type, value) DO UPDATE SET '
            'parent_asset_id = COALESCE(assets.parent_asset_id, EXCLUDED.parent_asset_id), '
            'ip_address = COALESCE(assets.ip_address, EXCLUDED.ip_address), '
            'attributes = assets.attributes || EXCLUDED.attributes, '
            'last_seen_at = GREATEST(assets.last_seen_at, EXCLUDED.last_seen_at), updated_at = now() '
            'RETURNING id::text',
            (org, domain_id, parent_id, activo.tipo, activo.valor, ip_value, Jsonb(atributos)),
        ).fetchone()['id']
        activos[activo.valor] = asset_id

    # El estado de antes dice si el hallazgo es nuevo o se reabre. FOR NO KEY UPDATE lo deja fijo hasta el commit, como
    # el upsert, sin chocar con el FOR KEY SHARE de la llave foránea cuando otro escaneo guarda sus score_contributions.
    # Con la cobertura parcial, lo abierto conserva las partes que esta corrida no revisó y que siguen ahí: un correo
    # que esta vez salió solo en el repo A sigue también en el B que no se clonó, y no se cierra mientras B no se revise.
    # Lo guardado antes sin partes que se puedan saber (un correo con 5 repos o más) puede seguir en cualquier parte que
    # no se revisó: lleva las de sin_revisar o, si no se saben, queda sin partes y espera a una corrida completa. Las
    # partes se leen por organización, como el upsert, que mueve a este dominio un correo de GitHub guardado en otro
    # dominio de la misma empresa: su huella no lleva el dominio (#23)
    huellas = [bytes.fromhex(h.huella) for h in resultado.hallazgos]
    previos, previas = {}, {}
    for f in conn.execute(
            'SELECT fingerprint, status, {p} AS partes FROM findings WHERE organization_id = %s '
            'AND fingerprint = ANY(%s::bytea[]) ORDER BY fingerprint FOR NO KEY UPDATE'.format(p=PARTES),
            (org, huellas)).fetchall():
        previos[bytes(f['fingerprint'])] = f['status']
        if resultado.revisados is not None and f['status'] == 'open':
            previas[bytes(f['fingerprint']).hex()] = f['partes']
    abiertos = set()

    # Las CVE van a la tabla global cves antes que los hallazgos que las nombran (llave foránea de findings.cve_id). Las
    # filas de la NVD que trae el recolector (Resultado.cves, la visita web) entran completas y las demás, como las que
    # Shodan deduce, entran como stub. Nunca se actualiza una que ya está: eso es del cargador diario de inteligencia
    # (#69, RC-127), que llena el CVSS de los stubs, y cirdan_app no tiene UPDATE en cves (migraciones 001 y 014, #18).
    # Como shodan corre antes que web (fuentes_activas va por code), una CVE que los dos ven queda como stub hasta el
    # cargador: la API toma entonces el CVSS de la evidencia del hallazgo (cirdan/api/v1.py).
    for fila in resultado.cves:
        columnas = [c for c in COLUMNAS_CVES if c in fila]
        conn.execute(
            'INSERT INTO cves ({c}) VALUES ({v}) ON CONFLICT (cve_id) DO NOTHING'.format(
                c=', '.join(columnas), v=', '.join(['%s'] * len(columnas))),
            [fila[c] for c in columnas])
    con_fila = {f['cve_id'] for f in resultado.cves}
    for cve in sorted({_cve_de(h) for h in resultado.hallazgos} - con_fila - {None}):
        conn.execute('INSERT INTO cves (cve_id) VALUES (%s) ON CONFLICT (cve_id) DO NOTHING', (cve,))

    for hallazgo in resultado.hallazgos:
        regla = reglas.get(hallazgo.codigo)
        if not regla:
            raise ValueError('hallazgo sin regla activa: %s' % hallazgo.codigo)
        evidencia = dict(hallazgo.evidencia)
        if isinstance(hallazgo.caracteristicas, dict):  # las del reto quedan guardadas para la API y el ML (#23)
            evidencia['caracteristicas'] = hallazgo.caracteristicas
        if hallazgo.partes:  # para no cerrarlo en un escaneo que no revisó sus repos o su IP (#23)
            previa = previas.get(bytes.fromhex(hallazgo.huella).hex())
            if previa == [] and resultado.sin_revisar is None:  # se guardó antes sin partes que se puedan saber
                evidencia['partes'] = []
            else:  # con [] y sin_revisar, puede seguir en cualquiera de las partes que no se revisaron
                evidencia['partes'] = hallazgo.partes + [
                    p for p in (resultado.sin_revisar if previa == [] else previa or []) if p not in resultado.revisados
                    and p not in hallazgo.partes and (resultado.sin_revisar is None or p in resultado.sin_revisar)]
        asset_id = activos.get(hallazgo.activo)
        if not asset_id:  # un activo que la fuente no dio no tumba el escaneo: el hallazgo cuelga del dominio
            log.warning('%s: hallazgo %s sin su activo %s, va en el dominio', resultado.fuente, hallazgo.codigo,
                        hallazgo.activo)
            evidencia['activo_no_encontrado'] = hallazgo.activo
            asset_id = raiz
        huella = bytes.fromhex(hallazgo.huella)
        finding = conn.execute(
            'INSERT INTO findings (organization_id, domain_id, asset_id, rule_id, source_id, fingerprint, severity, '
            "status, evidence, cve_id, detected_at, last_scan_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, 'open', %s, %s, now(), %s) "
            'ON CONFLICT (organization_id, fingerprint) DO UPDATE SET '
            'domain_id = EXCLUDED.domain_id, asset_id = EXCLUDED.asset_id, rule_id = EXCLUDED.rule_id, '
            'source_id = EXCLUDED.source_id, severity = EXCLUDED.severity, evidence = EXCLUDED.evidence, '
            'cve_id = EXCLUDED.cve_id, '
            'status = CASE WHEN findings.status = %s AND NOT ('
            'EXISTS (SELECT 1 FROM scoring_rules r JOIN audit_log al '
            'ON al.organization_id = findings.organization_id '
            'WHERE r.id = findings.rule_id AND r.code = %s AND al.entity_type = %s '
            'AND al.entity_id = findings.id AND al.actor_user_id IS NOT NULL AND al.action = %s '
            'AND al.details->>%s = %s '
            'AND al.occurred_at >= findings.resolved_at '
            'AND COALESCE(NULLIF(EXCLUDED.evidence->>%s, %s)::timestamptz <= al.occurred_at, TRUE)'
            ')) THEN %s ELSE findings.status END, '
            'resolved_at = CASE WHEN findings.status = %s THEN CASE WHEN EXISTS ('
            'SELECT 1 FROM scoring_rules r JOIN audit_log al '
            'ON al.organization_id = findings.organization_id '
            'WHERE r.id = findings.rule_id AND r.code = %s AND al.entity_type = %s '
            'AND al.entity_id = findings.id AND al.actor_user_id IS NOT NULL AND al.action = %s '
            'AND al.details->>%s = %s '
            'AND al.occurred_at >= findings.resolved_at '
            'AND COALESCE(NULLIF(EXCLUDED.evidence->>%s, %s)::timestamptz <= al.occurred_at, TRUE)'
            ') THEN findings.resolved_at ELSE NULL END ELSE findings.resolved_at END, '
            'last_scan_id = EXCLUDED.last_scan_id, updated_at = now() RETURNING id::text, status',
            (org, domain_id, asset_id, regla['id'], source_id, huella, hallazgo.severidad,
             Jsonb(evidencia), _cve_de(hallazgo), scan_id, 'resolved', 'secret_in_public_repo', 'finding',
             ACCION_HALLAZGO_RESUELTO, 'reason', MOTIVO_SECRETO_ROTADO, 'ultima_vez', '', 'open', 'resolved',
             'secret_in_public_repo', 'finding', ACCION_HALLAZGO_RESUELTO, 'reason', MOTIVO_SECRETO_ROTADO,
             'ultima_vez', ''),
        ).fetchone()
        finding_id = finding['id']
        if previos.get(huella) in (None, 'resolved') and finding['status'] == 'open':
            # Un secreto rotado sigue resuelto si no volvió a aparecer después de la declaración.
            abiertos.add(finding_id)
        if hallazgo.codigo in BRECHAS and isinstance(evidencia.get('breach_name'), str):
            # La brecha del hallazgo para la API y el reporte (v1.py, LEFT JOIN breach_exposures). Solo el hecho:
            # nombre, fecha y clases de datos, nunca contraseñas ni la descripción de la brecha.
            clases = evidencia.get('data_classes')
            clases = [x for x in clases if isinstance(x, str)] if isinstance(clases, list) else []
            fecha = evidencia.get('breach_date') if isinstance(evidencia.get('breach_date'), str) else None
            conn.execute(
                'INSERT INTO breach_exposures (finding_id, organization_id, breach_name, breach_date, data_classes) '
                'VALUES (%s, %s, %s, %s::date, %s::text[]) ON CONFLICT (finding_id) DO UPDATE SET '
                'breach_name = EXCLUDED.breach_name, breach_date = EXCLUDED.breach_date, '
                'data_classes = EXCLUDED.data_classes',
                (finding_id, org, evidencia['breach_name'], fecha, clases))

    # Lo abierto de esta fuente que ya no salió se arregló (#23). No se toca lo que siguió ahí sin reportarse por un
    # tope (omitidos), ni lo que el cliente marcó como riesgo aceptado o falso positivo. Si la fuente revisó todo
    # (revisados es None), tampoco los códigos que no pudo revisar (sin_cobertura). Si revisó solo una parte, deciden
    # las partes, porque una parte revisada se revisó para todos los códigos: solo se cierra lo que trae partes y todas
    # se revisaron. Si además dio sin_revisar, se cierra lo que trae partes y ninguna está ahí: así se cierra lo de un
    # repo borrado o de una IP que ya no resuelve. Lo que no trae partes espera a una corrida completa.
    # Un certificado por vencer cuyo vencimiento ya pasó se cierra en toda corrida de su fuente que respondió, aunque no
    # lo haya visto: ya no está por vencer, y si la fuente siempre queda parcial (crt.sh solo con la búsqueda por nombre,
    # o más certificados de los que caben en las páginas de Cert Spotter) nunca llegaría la corrida completa que lo
    # cierra (RC-55). Igual los de higiene que crt.sh ya no daría por fecha (CIERRE_POR_FECHA, RC-218). Las fechas de la
    # evidencia son isoformat en UTC
    # (crtsh._fecha): se comparan como texto con la hora del corte en el mismo formato, así una fecha rota no lo cierra
    # ni tumba la transacción.
    cortes = [((ahora or datetime.now(timezone.utc)) - timedelta(days=dias)).astimezone(timezone.utc).isoformat()
              for _, _, dias in CIERRE_POR_FECHA]
    cerrados = {f['id'] for f in conn.execute(
        "UPDATE findings SET status = 'resolved', resolved_at = now(), last_scan_id = %(scan)s, updated_at = now() "
        "WHERE domain_id = %(dominio)s AND source_id = %(fuente)s AND status = 'open' "
        'AND fingerprint <> ALL(%(huellas)s::bytea[]) '
        'AND (((%(revisados)s::text[] IS NOT NULL '
        'OR rule_id NOT IN (SELECT id FROM scoring_rules WHERE code = ANY(%(sin_cobertura)s::text[]))) '
        'AND (%(revisados)s::text[] IS NULL OR (jsonb_array_length({p}) > 0 AND CASE '
        'WHEN %(sin_revisar)s::text[] IS NULL THEN {p} <@ to_jsonb(%(revisados)s::text[]) '
        'ELSE NOT ({p} ?| %(sin_revisar)s::text[]) END))) '
        'OR EXISTS (SELECT 1 FROM unnest(%(codigos)s::text[], %(campos)s::text[], %(cortes)s::text[]) '
        'AS c(codigo, campo, corte) JOIN scoring_rules r ON r.code = c.codigo WHERE r.id = findings.rule_id '
        "AND jsonb_typeof(evidence->c.campo) = 'string' "
        "AND evidence->>c.campo ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}T\\d{{2}}:\\d{{2}}:\\d{{2}}(\\.\\d{{1,6}})?\\+00:00$' "
        "AND (evidence->>c.campo) COLLATE \"C\" < c.corte)) RETURNING id::text".format(p=PARTES),
        {'scan': scan_id, 'dominio': domain_id, 'fuente': source_id,
         'huellas': huellas + [bytes.fromhex(h) for h in resultado.omitidos],
         'sin_cobertura': list(resultado.sin_cobertura), 'revisados': resultado.revisados,
         'sin_revisar': resultado.sin_revisar, 'codigos': [c for c, _, _ in CIERRE_POR_FECHA],
         'campos': [c for _, c, _ in CIERRE_POR_FECHA], 'cortes': cortes},
    ).fetchall()}
    return abiertos, cerrados


def _preparar_score(conn, domain_id, scan_id):
    """Hallazgos puntuables y predicciones del modelo. No depende de los pesos, así que corre antes de tomar el
    candado de pesos y no hace esperar al PUT ni a los cierres de otros escaneos de la organización (RC-62)."""
    filas = conn.execute(
        'SELECT f.id::text AS id, r.code AS rule_code, f.severity, f.status, f.evidence, '
        'a.asset_type, a.first_seen_at AS asset_first_seen, f.detected_at, sc.queued_at AS scan_at, '
        "f.evidence->'caracteristicas' AS caracteristicas "
        'FROM findings f JOIN scoring_rules r ON r.id = f.rule_id '
        'JOIN assets a ON a.id = f.asset_id LEFT JOIN scans sc ON sc.id = f.last_scan_id '
        'WHERE f.domain_id = %s AND f.status = ANY(%s) ORDER BY f.id',
        (domain_id, list(motor.ESTADOS_PUNTUABLES)),
    ).fetchall()
    metodo, model_version, fallback_reason, predicciones = 'rules', None, 'artefacto_ml_no_disponible', None
    explicaciones_ml, version_explicacion = None, None
    try:
        from cirdan.ml import inferencia

        bundle = inferencia.cargar_modelo()
        version_explicacion = bundle['version']
        if not bundle.get('metrics', {}).get('integrable', False):
            fallback_reason = 'macro_f1_no_supera_reglas'
            try:
                explicaciones_ml = inferencia.predecir(bundle, filas)
            except Exception as error:
                log.warning('No se pudo generar SHAP para el escaneo %s: %s', scan_id, type(error).__name__)
        else:
            predicciones = inferencia.predecir(bundle, filas)
            explicaciones_ml = predicciones
            metodo, model_version, fallback_reason = 'ml', bundle['version'], None
    except FileNotFoundError as error:
        fallback_reason = 'artefacto_ml_no_disponible'
        log.warning('El score del escaneo %s usará reglas: %s', scan_id, type(error).__name__)
    except Exception as error:
        fallback_reason = 'inferencia_ml_no_disponible'
        log.warning('El score del escaneo %s usará reglas: %s', scan_id, type(error).__name__)
    return {'filas': filas, 'metodo': metodo, 'model_version': model_version, 'fallback_reason': fallback_reason,
            'predicciones': predicciones, 'explicaciones_ml': explicaciones_ml,
            'version_explicacion': version_explicacion}


def _guardar_score(conn, org, domain_id, scan_id, rule_set_id, reglas, pesos, parcial, preparado=None):
    p = preparado or _preparar_score(conn, domain_id, scan_id)
    filas, predicciones, explicaciones_ml = p['filas'], p['predicciones'], p['explicaciones_ml']
    metodo, model_version, fallback_reason = p['metodo'], p['model_version'], p['fallback_reason']
    version_explicacion = p['version_explicacion']
    hallazgos_score = []
    for hallazgo in filas:
        copia = dict(hallazgo)
        if predicciones is not None and copia['id'] in predicciones:
            copia['severity'] = predicciones[copia['id']]['severity']
        hallazgos_score.append(copia)
    # Los cortes de bandas del juego con que se guarda el score: mueven el piso y la banda (RC-237).
    calculo = motor.calcular(hallazgos_score, reglas, pesos, configuracion.cortes_del_juego(conn, rule_set_id))
    if explicaciones_ml is not None:
        for aporte in calculo['contributions']:
            prediccion = explicaciones_ml.get(aporte['finding_id'])
            if prediccion:
                aporte['factors']['model_prediction'] = prediccion['model_prediction']
                aporte['factors']['confidence'] = prediccion['confidence']
                aporte['factors']['shap'] = prediccion['shap']
                aporte['factors']['explanation_model_version'] = version_explicacion
    score_id = conn.execute(
        'INSERT INTO domain_scores (organization_id, domain_id, scan_id, rule_set_id, score, category_scores, '
        'reason, method, model_version, model_fallback_reason, partial_coverage, computed_at) '
        # clock_timestamp() y no now(): se guarda después de tomar el candado de pesos, así que un rules_change del
        # PUT que corrió antes queda con hora menor y uno que corre después con hora mayor (RC-62).
        "VALUES (%s, %s, %s, %s, %s, %s, 'scan', %s, %s, %s, %s, clock_timestamp()) "
        'RETURNING id::text',
        (org, domain_id, scan_id, rule_set_id, calculo['score'], Jsonb(calculo['category_scores']), metodo,
         model_version, fallback_reason, parcial),
    ).fetchone()['id']
    for aporte in calculo['contributions']:
        conn.execute(
            'INSERT INTO score_contributions (organization_id, score_id, finding_id, rule_id, penalty, severity, factors) '
            'VALUES (%s, %s, %s, %s, %s, %s, %s)',
            (org, score_id, aporte['finding_id'], aporte['rule_id'], aporte['penalty'], aporte['severity'],
             Jsonb(aporte['factors'])),
        )
    return calculo


def _candado_de(modo, conn):
    """El candado de turno.con_candado() para una corrida: _turno_host en vivo y al grabar, que salen a los sitios.
    Al reproducir no sale nada, y con la conexión de una prueba tampoco va, como _latiendo: todo va en su transacción."""
    return _turno_host if conn is None and modo in MODOS_CON_CUPO else None


@contextmanager
def _turno_host(host, espera):
    """El turno de `host` para una petición de un sitio (turno.con_candado): un candado de sesión de PostgreSQL en una
    conexión propia, que se cierra al terminar la petición. Cerrarla suelta el candado, también si la petición lanzó.
    Si otro escaneo tiene el host más de `espera` segundos, contando lo que tardó en conectar (lock_timeout), lanza
    turno.SinTurno y la petición no sale. Si la base no conecta o falla al pedir el candado, lanza turno.SinBase: no
    es falta de tiempo, la fuente queda en 'failed' y se reintenta. Con RED_TURNO, una red o un servidor que se caen
    también dan SinBase, y un cliente que se cae suelta el candado en unos segundos. Una base que acepta la conexión
    pero no contesta, como un contenedor en pausa, no tiene plazo aquí, igual que el latido y las transacciones del
    escaneo.
    Si la sesión del candado se cae a media petición (la base se reinicia o alguien termina su backend), el servidor
    lo suelta y otro escaneo puede pedir al mismo host antes de que termine esa petición. Es la excepción que anota la
    sección 9 de la carta. El candado no lee tablas: va sin empresa."""
    if espera < MIN_ESPERA_TURNO:
        raise turno.SinTurno('no quedó tiempo para esperar el turno de %s' % host)
    inicio = time.monotonic()
    try:
        conn = psycopg.connect(db.DSN, autocommit=True, connect_timeout=max(2, min(10, int(espera))), **RED_TURNO)
    except psycopg.Error as e:
        raise turno.SinBase('la base no respondió al pedir el turno de %s (%s)' % (host, type(e).__name__)) from None
    try:
        queda = espera - (time.monotonic() - inicio)   # el connect ya se comió parte de la espera
        if queda < MIN_ESPERA_TURNO:
            raise turno.SinTurno('no quedó tiempo para esperar el turno de %s' % host)
        try:
            conn.execute("SELECT set_config('lock_timeout', %s, false)", ('%dms' % max(1, int(queda * 1000)),))
            conn.execute('SELECT pg_advisory_lock(hashtextextended(%s, %s))', (host, SEMILLA_TURNO))
        except psycopg.errors.LockNotAvailable:
            raise turno.SinTurno('otro escaneo tuvo el turno de %s más tiempo del que le quedaba a la corrida'
                                 % host) from None
        except psycopg.Error as e:
            raise turno.SinBase('la base falló al tomar el turno de %s (%s)' % (host, type(e).__name__)) from None
        yield
    finally:
        conn.close()


@contextmanager
def _latiendo(org, scan_id, conn):
    """Marca vida cada LATIDO en un hilo aparte mientras corre una fuente, hasta TOPE_CORRIDA.

    Con la conexión de una prueba no hace falta: todo va en una transacción y now() no avanza.
    """
    if conn is not None:
        yield
        return
    alto = threading.Event()

    def latir():
        for _ in range(int(TOPE_CORRIDA.total_seconds() // LATIDO)):
            if alto.wait(LATIDO):
                return
            try:
                if not _latido(org, scan_id):
                    return  # lo dieron por caído: el hilo principal lo verá al terminar la corrida
            except Exception as e:  # la base no respondió esta vez: se intenta en la siguiente marca
                log.warning('No se pudo marcar vida del escaneo %s: %s', scan_id, e)
    hilo = threading.Thread(target=latir, name='latido-' + str(scan_id), daemon=True)
    hilo.start()
    try:
        yield
    finally:
        alto.set()


def _esperar(org, scan_id, segundos, conn, dormir):
    """Espera al reintento de una fuente sin perder la marca de vida. False si el escaneo ya no corre."""
    while segundos > 0:
        if not _latido(org, scan_id, conn):
            return False
        paso = min(LATIDO, segundos)
        dormir(paso)
        segundos -= paso
    return True


def _reservar(org, codigo, consultas, conn):
    """Reserva `consultas` del cupo de hoy de la fuente en una transacción corta propia, antes de salir a la red.

    Devuelve el día (UTC) de la reserva, o None si no cabe en el límite: entonces no se reservó nada.
    """
    with _tx(org, conn) as c:
        return c.execute('SELECT public.reserve_source_quota(%s, %s) AS dia', (codigo, consultas)).fetchone()['dia']


def _ajustar(org, codigo, dia, delta, conn):
    """Devuelve lo reservado de más (delta negativo) o suma lo gastado de más. Si ya cambió el día, no hace nada."""
    with _tx(org, conn) as c:
        c.execute('SELECT public.adjust_source_quota(%s, %s, %s)', (codigo, dia, delta))


def _ya_no_corre(org, scan_id, conn, corridas):
    """El escaneo dejó de estar en 'running' a mitad: no se toca su estado, solo se cierran sus fuentes."""
    with _tx(org, conn) as c:
        _cerrar_corridas(c, [scan_id], ERROR_YA_NO_CORRE)
        scan = c.execute('SELECT status, stats FROM scans WHERE id = %s', (scan_id,)).fetchone()
    return {'scan_id': scan_id, 'status': scan['status'], 'stats': scan['stats'] or {}, 'sources': corridas}


def cobertura(res, modulo):
    """scan_source_runs.coverage de una corrida (migración 032): qué partes revisó la fuente, no qué códigos.

    'complete' si respondió y revisó todas sus partes (revisados es None), aunque algún código quede en sin_cobertura,
    por ejemplo por falta de llave. 'partial' si revisó solo algunas (revisados, aunque sea vacío). 'none' si todos
    sus códigos quedaron sin cobertura: no revisó nada. None si no respondió."""
    if res.estado != 'succeeded':
        return None
    if res.revisados is not None:
        return 'partial'
    codigos = set(getattr(modulo, 'CODIGOS', None) or ())
    return 'none' if codigos and codigos <= set(res.sin_cobertura) else 'complete'


def _marcar_identidad(res, codigo, scan_id, modo):
    """Pone el escaneo en attributes.identidad_scan de cada correo que dio identity y, en vivo o al grabar, también en
    identidad_scan_vivo (CORREOS_SQL, RC-54). El upsert de assets une attributes con ||: solo identity escribe esas
    llaves, y una corrida en reproducir no pisa la marca de la última en vivo."""
    if codigo != 'identity' or res.estado != 'succeeded':
        return
    marca = {'identidad_scan': str(scan_id)}
    if modo != 'reproducir':
        marca['identidad_scan_vivo'] = str(scan_id)
    for activo in res.activos:
        if (activo.tipo == 'email' and isinstance(activo.atributos, dict)
                and isinstance(activo.atributos.get('identidad'), dict)):
            activo.atributos = {**activo.atributos, **marca}


def _extras(org, modulo, codigo, domain_id, modo, actividades, conn=None):
    """Las opciones que el orquestador arma para el recolector que las pide (RC-54), para contrato.ejecutar(extras=).

    PIDE_CORREOS: `correos`, los de CORREOS_SQL con las ramas que autorizan las `actividades` de la carta del escaneo,
    y `correos_total`, cuántos había antes del tope de MAX_CORREOS (0 si no hay ninguno). PIDE_LLAVE: `llave`, la de
    data_sources.api_key_enc descifrada (cirdan/recolectores/llaves.py), solo en vivo y al grabar: al reproducir no
    hace falta y no se lee. Si la llave no se puede leer (falta la migración 032, falta SOURCE_KEYS_ENCRYPTION_KEY o
    no abre), va None y la fuente queda sin cobertura por falta de llave. El log nunca lleva la llave ni el valor
    cifrado. Un error de la base aquí no tumba el escaneo: cada lectura va en su propio punto de guardado."""
    extras = {}
    if getattr(modulo, 'PIDE_CORREOS', False) is True:
        try:
            with _tx(org, conn) as c, c.transaction():
                filas = c.execute(CORREOS_SQL, {
                    'dominio': domain_id, 'tope': MAX_CORREOS, 'reproducir': modo == 'reproducir',
                    'con_github': alcance_carta.autorizada('github', actividades),
                    'con_identidad': alcance_carta.autorizada('identity', actividades)}).fetchall()
            extras['correos'] = [f['correo'] for f in filas]
            extras['correos_total'] = filas[0]['total'] if filas else 0
        except psycopg.Error as e:
            log.warning('%s: no se pudieron leer los correos del dominio (%s)', codigo, type(e).__name__)
            extras['correos'], extras['correos_total'] = [], 0
    if getattr(modulo, 'PIDE_LLAVE', False) is True and modo in MODOS_CON_CUPO:
        from cirdan.recolectores import llaves   # pide cryptography: solo se carga si una fuente lo necesita
        try:
            with _tx(org, conn) as c, c.transaction():
                extras['llave'] = llaves.leer(c, codigo)
        except (psycopg.Error, llaves.LlaveIlegible) as e:
            log.warning('%s: no se pudo leer la llave de la fuente (%s)', codigo,
                        e if isinstance(e, llaves.LlaveIlegible) else type(e).__name__)
            extras['llave'] = None
    return extras


@certspotter.un_escaneo()  # cada llamada abre el suyo y lo cierra al volver, también con una excepción
def correr(org, scan_id, fqdn, fuentes=None, modo='vivo', ahora=None, conn=None, dormir=None):
    """Ejecuta los recolectores de un escaneo aceptado y deja el estado de cada fuente.

    Cada página de Cert Spotter sale a la red una sola vez en el escaneo: la primera fuente que la pide la consulta y
    las demás reusan lo que recibió, un 429 o una falla incluidos (certspotter.un_escaneo, RC-326). Lo reusado no
    cuenta en sus consultas ni en su cupo diario. Un reintento a 1, 5 o 25 minutos vuelve a pedir lo que falló, salvo
    un 429 (certspotter.nuevo_intento).

    Un recolector que falla no tumba el escaneo. En vivo, su fuente queda en 'retrying' y se vuelve a
    correr ahí mismo a 1, 5 y 25 minutos (siguiente_estado, #13). Mientras corre o espera, el escaneo marca
    que sigue vivo y, si alguien lo dio por caído, deja de correr. Al reproducir no se reintenta, porque la
    respuesta grabada sería la misma, ni al grabar, porque cada intento volvería a vaciar la grabación: la
    fuente queda en 'failed'. Las consultas de la fila suman las de todos sus intentos y los errores de los
    intentos anteriores quedan en sus avisos.
    En vivo y al grabar, antes de cada corrida (también de cada reintento) reserva en data_sources el máximo de
    consultas del recolector (MAX_CONSULTAS) y al terminar ajusta a las que gastó. Si la fuente ya no tiene cupo
    hoy (día UTC), queda en 'failed' sin llamar al recolector y sin reintento, porque esperar 1, 5 o 25 minutos no
    devuelve un cupo diario. Si algo lanza entre la reserva y el ajuste, lo reservado se queda: es lo conservador.
    Al reproducir no reserva ni ajusta: las demos no gastan cupo ni se bloquean.
    Una fuente que no se recupera deja el escaneo 'partial' si otra respondió, o 'failed' si ninguna respondió.
    También termina 'partial' si una fuente respondió
    pero dejó códigos en sin_cobertura (por ejemplo, crt.sh con el respaldo de Cert Spotter), así no
    se muestran como 0 hallazgos, o si revisó solo una parte de lo suyo (revisados, en stats.sources_partial).
    crt.sh busca dominios parecidos en cada escaneo, solo en los registros de certificados (#109, RC-226): si
    ninguna de esas búsquedas responde, si no responde la de %marca% o si el dominio no tiene marca (un subdominio,
    un sufijo que crtsh.py no conoce o un hosting), lookalike_domain queda en sin_cobertura, nunca en 0. Si solo
    falta la respuesta de alguna variante, ct_logs da revisados y va en stats.sources_partial. Devuelve
    un resumen.
    En stats, assets cuenta los (tipo, valor) distintos de las fuentes que respondieron: un subdominio que dan
    ct_logs y subfinder cuenta una vez. En assets van una sola vez, con sus atributos unidos.
    new_findings cuenta los hallazgos que el escaneo dejó abiertos y antes no lo estaban: los que insertó y los que
    reabrió porque estaban en 'resolved'. No cuenta los que ya estaban abiertos ni los que el cliente marcó como
    riesgo aceptado o falso positivo, que no cambian. resolved_findings cuenta los que pasó a 'resolved' porque su
    fuente respondió y ya no los dio: nunca los de una fuente caída ni lo que _guardar_resultado deja abierto
    (omitidos, sin_cobertura de una fuente que revisó todo y, en una corrida parcial, lo que no trae partes o trae
    una sin revisar, salvo un cert_expiring_soon ya vencido). Un hallazgo que una fuente resuelve y otra reabre en
    el mismo escaneo quedó como estaba y no cuenta en ninguno. Los conteos solo se guardan al cerrar: lo que
    guardaron las fuentes de un escaneo que se cae o lo dan por caído no se cuenta.
    queries, queries_by_source, seconds_by_source y duration_seconds dan el costo medido del escaneo (#52, RC-87).
    `dormir` reemplaza time.sleep (pruebas).
    """
    dormir = dormir or time.sleep
    inicio = time.monotonic()
    fqdn = fqdn.strip().lower().rstrip('.')
    with _tx(org, conn) as c:
        fuentes = fuentes if fuentes is not None else fuentes_activas(c)
        catalogo = {f['code']: f for f in c.execute(
            'SELECT id::text, code, keep_raw_payload FROM data_sources WHERE code = ANY(%s)', (fuentes,)).fetchall()}
        # Solo los dominios vigentes de la organización cuentan como propios (#109, RC-226). Uno dado de baja
        # ('removed') puede ser hoy de un tercero, y uno sin verificar ('pending_verification') no probó ser suyo:
        # darlo de alta no debe esconder ni resolver un dominio parecido.
        propios = [r['fqdn'] for r in c.execute(
            "SELECT fqdn::text FROM domains WHERE fqdn <> %s AND status IN ('verified', 'paused')", (fqdn,)).fetchall()]
        domain = c.execute('SELECT id::text FROM domains WHERE fqdn = %s', (fqdn,)).fetchone()
        if not domain:
            raise ValueError('dominio no encontrado para el escaneo: %s' % fqdn)
        rule_set = configuracion.juego_activo(c, org)
        if not rule_set:
            raise RuntimeError('no hay un juego de reglas activo')
        reglas = configuracion.reglas_del_juego(c, rule_set['id'])
        pesos = configuracion.pesos_del_juego(rule_set)
        # Alcance de la carta con la que se aceptó el escaneo (RC-59). Sin carta o sin alcance no corre ninguna fuente.
        alcance = c.execute('SELECT a.activities FROM scans s JOIN domain_authorizations a ON a.id = s.authorization_id '
                            'WHERE s.id = %s', (scan_id,)).fetchone()
        actividades = alcance['activities'] if alcance else None

    if modo == 'vivo' and not en_vivo_permitido(fqdn):
        modo = 'reproducir'  # nunca consultar en vivo un dominio fuera de DOMINIOS_EN_VIVO

    reintenta = modo == 'vivo'
    con_cupo = modo in MODOS_CON_CUPO
    corridas, activos, hallazgos = [], set(), 0
    nuevos, resueltos = set(), set()  # id de los hallazgos que este escaneo abrió y los que resolvió
    tiempos = {}  # segundos de cada fuente con todos sus intentos, sin las esperas entre reintentos
    for codigo in fuentes:
        intento, gastadas, previos, segundos = 0, 0, [], 0.0
        modulo = cargar(codigo)
        permitida = alcance_carta.autorizada(codigo, actividades)
        while True:
            if not _latido(org, scan_id, conn):
                return _ya_no_corre(org, scan_id, conn, corridas)
            reservadas, dia = 0, None
            if con_cupo and permitida:
                reservadas = getattr(modulo, 'MAX_CONSULTAS')
                dia = _reservar(org, codigo, reservadas, conn)
            if not permitida:  # la carta no la autoriza: ni cupo, ni recolector, ni reintento; sus reglas sin cobertura
                aviso = alcance_carta.NO_AUTORIZADA % (codigo, alcance_carta.ACTIVIDAD_DE_FUENTE.get(codigo, '?'))
                res = Resultado(fqdn, codigo, estado='failed', error=aviso, avisos=[aviso],
                                sin_cobertura=sorted(set(getattr(modulo, 'CODIGOS', {})) & set(reglas)))
                status, attempt, next_retry_at = 'failed', intento, None
            elif con_cupo and dia is None:  # sin cupo: ni se llama al recolector ni se reintenta
                res = Resultado(fqdn, codigo, estado='failed', error=SIN_CUPO % codigo, avisos=[SIN_CUPO % codigo])
                status, attempt, next_retry_at = 'failed', intento, None
            else:
                arranque = time.monotonic()
                with _latiendo(org, scan_id, conn), turno.con_candado(_candado_de(modo, conn)):
                    extras = _extras(org, modulo, codigo, domain['id'], modo, actividades, conn)
                    res = ejecutar(modulo, fqdn, modo, ahora=ahora, propios=propios, codigos=reglas, extras=extras)
                _marcar_identidad(res, codigo, scan_id, modo)
                segundos += time.monotonic() - arranque
                if dia is not None and res.consultas != reservadas:
                    _ajustar(org, codigo, dia, res.consultas - reservadas, conn)
                momento = datetime.now(timezone.utc)
                status, attempt, next_retry_at = (siguiente_estado(res.estado, intento, momento) if reintenta
                                                  else (res.estado, 0, None))
            gastadas += res.consultas
            avisos = previos + res.avisos
            resumen = {'activos': len(res.activos), 'hallazgos': len(res.hallazgos), 'consultas': gastadas,
                       'avisos': avisos[:10], 'sin_cobertura': res.sin_cobertura, 'sin_llave': res.sin_llave,
                       'cobertura_parcial': res.estado == 'succeeded' and res.revisados is not None}
            # La marca de vida y la fila van en una transacción: si lo dieron por caído mientras la fuente corría,
            # no se escribe encima de la fila que ya se cerró, y nadie lo puede dar por caído en medio.
            cambios = None
            with _tx(org, conn) as c:  # una fila por fuente: cada reintento la actualiza
                vivo = _latido(org, scan_id, c)
                if vivo:
                    c.execute(
                        'INSERT INTO scan_source_runs (organization_id, scan_id, source_id, status, attempt, next_retry_at, '
                        'raw_payload, error, finished_at, coverage, mode) '
                        'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now(), %s, %s) '
                        'ON CONFLICT (scan_id, source_id) DO UPDATE SET status = EXCLUDED.status, attempt = EXCLUDED.attempt, '
                        'next_retry_at = EXCLUDED.next_retry_at, raw_payload = EXCLUDED.raw_payload, error = EXCLUDED.error, '
                        'finished_at = EXCLUDED.finished_at, coverage = EXCLUDED.coverage, mode = EXCLUDED.mode, '
                        'updated_at = now()',
                        (org, scan_id, catalogo[codigo]['id'], status, attempt, next_retry_at,
                         Jsonb(resumen) if catalogo[codigo]['keep_raw_payload'] else None, res.error or None,
                         cobertura(res, modulo), modo))
                    if res.estado == 'succeeded':
                        cambios = _guardar_resultado(c, org, scan_id, domain['id'], catalogo[codigo]['id'], res, reglas,
                                                     ahora)
            if not vivo:
                return _ya_no_corre(org, scan_id, conn, corridas)
            if cambios:
                # Lo que una fuente resuelve y otra reabre en este escaneo (o al revés) no cuenta. Hoy dos fuentes no
                # dan la misma huella y no pasa, pero el conteo no depende de eso.
                abiertos, cerrados = cambios
                resueltos |= cerrados - nuevos
                nuevos -= cerrados
                nuevos |= abiertos - resueltos
                resueltos -= abiertos
            if status != 'retrying':
                break
            previos.append('Intento %d: %s' % (attempt, (res.error or '')[:300]))
            if not _esperar(org, scan_id, (next_retry_at - momento).total_seconds(), conn, dormir):
                return _ya_no_corre(org, scan_id, conn, corridas)
            certspotter.nuevo_intento()  # el reintento vuelve a pedir lo que falló en Cert Spotter, salvo un 429
            intento = attempt
        corridas.append({'source': codigo, 'status': status, 'error': res.error or None, 'no_autorizada': not permitida,
                         'avisos_omitidos': max(0, len(avisos) - len(resumen['avisos'])), **resumen})
        tiempos[codigo] = segundos
        if res.estado == 'succeeded':
            activos.update((a.tipo, a.valor) for a in res.activos)  # un subdominio que dan dos fuentes cuenta una vez
            hallazgos += len(res.hallazgos)

    ok = sum(1 for r in corridas if r['status'] == 'succeeded')
    sin_cobertura = sorted({c for r in corridas if r['status'] == 'succeeded' or r['no_autorizada']
                            for c in r['sin_cobertura']})
    no_autorizadas = [r['source'] for r in corridas if r['no_autorizada']]
    a_medias = [r['source'] for r in corridas if r['status'] == 'succeeded' and r['cobertura_parcial']]
    completo = ok == len(corridas) and not sin_cobertura and not a_medias
    estado = 'completed' if completo else 'failed' if ok == 0 else 'partial'
    stats = {'assets': len(activos), 'findings': hallazgos, 'new_findings': len(nuevos),
             'resolved_findings': len(resueltos), 'sources_ok': ok, 'sources_failed': len(corridas) - ok}
    if sin_cobertura:
        stats['rules_without_coverage'] = sin_cobertura
    # De esas, las que faltaron por no tener la llave de la fuente (HIBP, RC-54). Su fuente no guarda raw_payload
    # (keep_raw_payload false), así que coverage_gaps de la API las lee de aquí para dar 'no_api_key'.
    sin_llave = sorted({c for r in corridas if r['status'] == 'succeeded' for c in r['sin_llave']})
    if sin_llave:
        stats['rules_without_key'] = sin_llave
    if a_medias:
        stats['sources_partial'] = a_medias
    if no_autorizadas:
        stats['sources_unauthorized'] = no_autorizadas
    # Costo medido del escaneo (#52, RC-87): consultas de cada fuente con todos sus intentos, también las de una
    # fuente que falló, y segundos. seconds_by_source suma lo que tardó el recolector en cada intento, sin las
    # esperas entre reintentos. duration_seconds va del inicio de correr() hasta antes del score y sí las incluye.
    stats['queries'] = sum(r['consultas'] for r in corridas)
    stats['queries_by_source'] = {r['source']: r['consultas'] for r in corridas}
    stats['seconds_by_source'] = {codigo: round(s, 3) for codigo, s in tiempos.items()}
    stats['duration_seconds'] = round(time.monotonic() - inicio, 3)
    with _tx(org, conn) as c:
        # El modelo corre antes de bloquear la fila del escaneo y de tomar el candado de pesos (RC-62). Si ya lo
        # dieron por caído no se calcula de balde: el UPDATE de abajo sigue siendo el que decide.
        sigue = c.execute("SELECT 1 FROM scans WHERE id = %s AND status = 'running'", (scan_id,)).fetchone()
        preparado = _preparar_score(c, domain['id'], scan_id) if sigue else None
        # clock_timestamp(): el cierre lleva la hora de después del modelo, no la del inicio de la transacción.
        cerrado = sigue and c.execute(
            "UPDATE scans SET status = %s, finished_at = clock_timestamp(), stats = %s, updated_at = clock_timestamp() "
            "WHERE id = %s AND status = 'running' RETURNING id", (estado, Jsonb(stats), scan_id)).fetchone()
        if cerrado:  # si lo dieron por caído entre la última fuente y aquí, se queda como está
            c.execute('UPDATE domains SET last_scan_at = clock_timestamp(), updated_at = clock_timestamp() '
                      'WHERE fqdn = %s', (fqdn,))
            # Si cambiaron los pesos mientras corría (PUT /scoring/weights), el score sale con el juego activo de
            # ahora, no con el del inicio. El candado es el del PUT: si el PUT va primero, aquí ya se ve su juego, y
            # si va después, su recálculo ve este score y lo copia con los pesos nuevos (RC-62). Los dos guardan con
            # clock_timestamp(), tomado ya con el candado, para que el orden de computed_at sea el del candado.
            configuracion.bloquear_pesos(c, org)
            vigente = configuracion.juego_activo(c, org)
            if vigente and vigente['id'] != rule_set['id']:
                rule_set = vigente
                reglas = configuracion.reglas_del_juego(c, rule_set['id'])
                pesos = configuracion.pesos_del_juego(rule_set)
            _guardar_score(c, org, domain['id'], scan_id, rule_set['id'], reglas, pesos, estado != 'completed',
                           preparado)
            audit(c, org, 'scan.finished', None, None, 'scan', scan_id, {'fqdn': fqdn, 'status': estado, **stats})
    if not cerrado:
        return _ya_no_corre(org, scan_id, conn, corridas)
    return {'scan_id': scan_id, 'status': estado, 'stats': stats, 'sources': corridas}


def marcar_fallido(org, scan_id, error):
    """Si algo inesperado tumba el escaneo, no lo deja 'running' para siempre ni a sus fuentes esperando."""
    texto = (str(error) or type(error).__name__)[:300]  # Ctrl+C (KeyboardInterrupt) no trae texto
    with transaction(org) as c:
        c.execute("UPDATE scans SET status = 'failed', finished_at = now(), stats = %s, updated_at = now() "
                  "WHERE id = %s AND status = 'running'", (Jsonb({'error': texto}), scan_id))
        # también si ya no estaba en 'running' (lo dieron por caído antes): ninguna fuente se queda esperando
        _cerrar_corridas(c, [scan_id], texto)
