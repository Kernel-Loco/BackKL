"""Límites del plan en la capa de servicio (db/cirdan_esquema.dbml, 'Planes en la capa de servicio').

Hoy solo existe la acción 'on_demand_scan' (RC-297): los escaneos que se piden a mano, desde el portal, una llave de API
o `python -m cirdan.orquestador`. Los programados de RC-52 (trigger 'scheduled') no pasan por aquí. max_domains y
api_and_siem siguen fuera.

El cupo diario de cada fuente es uno para toda la plataforma (data_sources.daily_limit, migración 008). Para que una sola
empresa no gaste más de la mitad del cupo de ct_logs, whois ni shodan, el tope sale de la mitad de cada cupo entre lo
que reserva una corrida (MAX_CONSULTAS de su recolector), con los cupos de las semillas 014, 008 y 018:

    ct_logs  400 / 2 = 200,  200 / 36  = 5
    whois     60 / 2 =  30,   30 / 10  = 3
    shodan  2140 / 2 = 1070, 1070 / 214 = 5

El menor es whois: 3 escaneos a mano por empresa y día UTC (decisión 2 de Ernesto, 24 nov). Cada reintento de una
fuente reserva otra vez su MAX_CONSULTAS, así que en un escaneo a mano estas 3 fuentes solo se reintentan si el intento
fallido no gastó nada (orquestador.correr, SIN_REINTENTO, elegido por Ernesto el 25 nov): cada escaneo a mano gasta a lo
más un MAX_CONSULTAS de cada una y la cuenta vale también con reintentos. Dividir entre los 4 intentos dejaría whois
en 30 / 40 = 0. Las pruebas de test_planes.py revisan que TOPE_EMPRESA siga cuadrando si cambia un recolector.

Con plans.on_demand_scans = false (Starter y Business, también Grupo Olmardo y LowTide), cada dominio tiene además 1
escaneo a mano por día UTC. Con true (Enterprise), el mismo dominio se puede volver a pedir tras ENFRIAMIENTO (decisión
1 de Ernesto, opción b). El enfriamiento vale para los dos planes.

Todo se cuenta desde `scans`, sin migración: los de trigger 'on_demand' o 'api' de la empresa, en cualquier estado,
porque uno que falló también gastó cupo. Antes de contar toma un candado de transacción por empresa: dos peticiones
en paralelo de la misma empresa esperan una a la otra y la segunda ya ve el escaneo que la primera insertó.
"""
import math
from dataclasses import dataclass
from datetime import timedelta

TOPE_EMPRESA = 3                    # escaneos a mano por empresa y día UTC
TOPE_DOMINIO_SIN_PLAN = 1           # por dominio y día UTC con on_demand_scans = false
ENFRIAMIENTO = timedelta(hours=6)   # entre dos escaneos a mano del mismo dominio, el de RC-216
A_MANO = ['on_demand', 'api']       # trigger_type que cuentan; 'scheduled' (RC-52) no
FUENTES_DEL_TOPE = ('ct_logs', 'whois', 'shodan')
CANDADO = 'cirdan.on_demand_scan'   # dos llaves de pg_advisory_xact_lock, como CANDADO_HALLAZGOS del orquestador

MOTIVOS = {
    'on_demand_daily_limit': 'Tu organización ya pidió %d escaneos a mano hoy, el tope por día (UTC)' % TOPE_EMPRESA,
    'on_demand_domain_daily_limit': 'Tu plan permite %d escaneo a mano por dominio al día (UTC)' % TOPE_DOMINIO_SIN_PLAN,
    'on_demand_cooldown': 'Este dominio ya se escaneó a mano en las últimas %d horas' % (ENFRIAMIENTO.seconds // 3600),
}

CONTEO_SQL = '''
SELECT p.on_demand_scans,
       (SELECT count(*) FROM scans s
         WHERE s.organization_id = %(org)s AND s.trigger_type = ANY(%(a_mano)s) AND s.queued_at >= dia.inicio) AS empresa_hoy,
       (SELECT count(*) FROM scans s
         WHERE s.domain_id = %(dominio)s AND s.trigger_type = ANY(%(a_mano)s) AND s.queued_at >= dia.inicio) AS dominio_hoy,
       (SELECT max(s.queued_at) FROM scans s
         WHERE s.domain_id = %(dominio)s AND s.trigger_type = ANY(%(a_mano)s)) AS ultimo,
       now() AS ahora,
       dia.inicio + interval '1 day' AS manana
  FROM organizations o JOIN plans p ON p.id = o.plan_id,
       LATERAL (SELECT date_trunc('day', now(), 'UTC') AS inicio) dia
 WHERE o.id = %(org)s
'''


@dataclass
class Limite:
    """Por qué no se puede pedir el escaneo y en cuántos segundos se podría (Retry-After)."""
    motivos: list
    retry_after: int


def _segundos(hasta, ahora):
    return max(1, math.ceil((hasta - ahora).total_seconds()))


def _candado(conn, org):
    """Candado de la empresa hasta el final de la transacción (pg_advisory_xact_lock con dos llaves)."""
    conn.execute('SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s::uuid::text))', (CANDADO, org))


def tomar_candado(conn, org):
    """El candado de la empresa antes de cualquier otro de la transacción, sobre todo el de la cadena de audit_log.

    orquestador.solicitar() lo toma antes de _en_curso(), que puede escribir scan.abandoned. check_plan_limits lo vuelve a
    pedir y PostgreSQL lo apila en la misma transacción sin esperar."""
    _candado(conn, org)


def check_plan_limits(org, action, conn, domain_id=None):
    """None si el plan deja hacer `action`, o un Limite. Corre dentro de la transacción de la empresa (RLS).

    Para 'on_demand_scan' toma el candado de la empresa, que dura hasta el final de la transacción: quien llama
    inserta el escaneo en esa misma transacción, así que la cuenta de la siguiente petición ya lo incluye."""
    if action != 'on_demand_scan':
        raise ValueError('check_plan_limits: acción desconocida %r' % action)
    _candado(conn, org)
    f = conn.execute(CONTEO_SQL, {'org': org, 'dominio': domain_id, 'a_mano': A_MANO}).fetchone()
    if f is None:  # sin fila de la empresa: RLS o una empresa que no existe; no se escanea
        raise RuntimeError('check_plan_limits: no se encontró el plan de la empresa')
    hasta = []  # (motivo, momento desde el que se puede)
    if f['empresa_hoy'] >= TOPE_EMPRESA:
        hasta.append(('on_demand_daily_limit', f['manana']))
    if not f['on_demand_scans'] and f['dominio_hoy'] >= TOPE_DOMINIO_SIN_PLAN:
        hasta.append(('on_demand_domain_daily_limit', f['manana']))
    if f['ultimo'] is not None and f['ultimo'] + ENFRIAMIENTO > f['ahora']:
        hasta.append(('on_demand_cooldown', f['ultimo'] + ENFRIAMIENTO))
    if not hasta:
        return None
    return Limite([m for m, _ in hasta], max(_segundos(h, f['ahora']) for _, h in hasta))
