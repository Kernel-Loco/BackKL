"""Alertas en vivo a Microsoft Teams con outbox (#65, RC-114).

1. **Outbox.** La alerta se crea en la misma transacción que lo que la causa, así que no se pierde ni se manda de un
   cambio que no se guardó:
   - `finding.created`: un hallazgo crítico que el escaneo abre o reabre (orquestador, `_guardar_resultado`).
   - `score.above_threshold`: un score que llega al umbral de la empresa (`organizations.alert_score_threshold`,
     `criterio.dispara_alerta()`) cuando el anterior del dominio estaba abajo o no había. Así no se repite en cada
     escaneo mientras siga arriba (orquestador, `_guardar_score`).
   Por cada integración de Teams encendida de la empresa queda una fila `pending` en `deliveries`.
2. **Entrega.** `despachar(org)` manda las pendientes de la empresa con la tarjeta adaptable (tarjeta.py) al flujo de
   Workflows. Cada intento queda en `deliveries`: `attempt`, `response_status`, `last_error`, `next_attempt_at` y, al
   entregar, `delivered_at`, del que la base saca `latency_ms` (meta: menos de 60 s). Reintenta a los 10 s, 1 min,
   5 min y 30 min; al quinto fallo queda `dead`. El orquestador la lanza en un hilo al cerrar el escaneo, con la
   empresa ya conocida, sin saltar RLS. `python -m cirdan.alertas <empresa>` reintenta a mano.
3. **La URL del flujo** lleva su firma: va cifrada con AES-256-GCM en `integrations.secret_enc` con
   SOURCE_KEYS_ENCRYPTION_KEY (la misma llave que cifra las de las fuentes, RC-54) y el id de la integración como dato
   asociado. En `endpoint` solo va el host. Nunca se escribe en un log, la bitácora ni una respuesta.
"""
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg.types.json import Jsonb

from cirdan.alertas import tarjeta
from cirdan.config import config
from cirdan.recolectores import llaves
from cirdan.score import criterio

log = logging.getLogger('cirdan.alertas')

VERSION = 1
AAD = 'integrations.secret_enc:%s'
FORMATO = 'teams'
LOTE = 20
TIEMPO = 10   # segundos por intento de entrega
INTEGRACIONES_SQL = ("SELECT id FROM integrations WHERE kind = 'webhook' AND enabled AND secret_enc IS NOT NULL "
                     "AND config->>'formato' = %s")


class UrlIlegible(Exception):
    """La URL guardada no abre: falta la llave de cifrado, es otra o el valor está roto. Nunca trae la URL."""


def cifrar_url(integracion_id, url):
    nonce = os.urandom(12)
    cifrado = AESGCM(llaves._llave_de_cifrado()).encrypt(nonce, url.strip().encode(), (AAD % integracion_id).encode())
    return bytes([VERSION]) + nonce + cifrado


def descifrar_url(integracion_id, blob):
    blob = bytes(blob) if not isinstance(blob, memoryview) else blob.tobytes()
    if len(blob) < 1 + 12 + 16 or blob[0] != VERSION:
        raise UrlIlegible('la URL guardada de la integración no tiene la forma de la versión %d' % VERSION)
    try:
        return AESGCM(llaves._llave_de_cifrado()).decrypt(blob[1:13], blob[13:],
                                                          (AAD % integracion_id).encode()).decode()
    except (InvalidTag, UnicodeDecodeError, llaves.LlaveIlegible):
        raise UrlIlegible('la URL guardada de la integración no abre con %s' % llaves.VARIABLE) from None


# ------------------------------------------------------------------ outbox (en la transacción de quien llama)

def _encolar(conn, org, alerta_id, detectada):
    """Una entrega pendiente por integración de Teams encendida. Devuelve cuántas."""
    integraciones = [f['id'] for f in conn.execute(INTEGRACIONES_SQL, (FORMATO,)).fetchall()]
    for integracion in integraciones:
        conn.execute(
            "INSERT INTO deliveries (organization_id, integration_id, alert_id, status, message_id, detected_at) "
            "VALUES (%s, %s, %s, 'pending', %s, %s) ON CONFLICT (integration_id, alert_id) DO NOTHING",
            (org, integracion, alerta_id, str(uuid.uuid4()), detectada))
    return len(integraciones)


def encolar_hallazgos(conn, org, domain_id, finding_ids):
    """Alertas finding.created de los hallazgos críticos abiertos o reabiertos entre `finding_ids`. Devuelve sus ids."""
    if not finding_ids:
        return []
    filas = conn.execute(
        "SELECT f.id::text, f.severity, f.evidence->>'title' AS title, r.code AS rule_code, d.fqdn::text AS domain, "
        "clock_timestamp() AS ahora FROM findings f JOIN scoring_rules r ON r.id = f.rule_id "
        "JOIN domains d ON d.id = f.domain_id "
        "WHERE f.id = ANY(%s::uuid[]) AND f.domain_id = %s AND f.status = 'open' AND f.severity = 'critical'",
        (list(finding_ids), domain_id)).fetchall()
    creadas = []
    for f in filas:
        payload = {'domain': f['domain'], 'finding_id': f['id'], 'title': tarjeta.sin_correos(f['title']),
                   'severity': f['severity'], 'rule_code': f['rule_code'], 'detected_at': f['ahora'].isoformat()}
        alerta = conn.execute(
            "INSERT INTO alerts (organization_id, domain_id, event_type, finding_id, severity, payload, detected_at) "
            "VALUES (%s, %s, 'finding.created', %s, %s, %s, %s) RETURNING id::text",
            (org, domain_id, f['id'], f['severity'], Jsonb(payload), f['ahora'])).fetchone()['id']
        _encolar(conn, org, alerta, f['ahora'])
        creadas.append(alerta)
    return creadas


def encolar_score(conn, org, domain_id, score_id, score):
    """Alerta score.above_threshold si `score` llega al umbral y el score anterior del dominio estaba abajo o no
    había. Devuelve su id o None."""
    umbral = conn.execute('SELECT alert_score_threshold AS t FROM organizations WHERE id = %s', (org,)).fetchone()
    umbral = umbral['t'] if umbral and umbral['t'] is not None else criterio.UMBRAL_ALERTA
    if not criterio.dispara_alerta(score, umbral):
        return None
    anterior = conn.execute(
        'SELECT score FROM domain_scores WHERE domain_id = %s AND id <> %s ORDER BY computed_at DESC LIMIT 1',
        (domain_id, score_id)).fetchone()
    if anterior and criterio.dispara_alerta(anterior['score'], umbral):
        return None   # ya estaba arriba: la alerta salió cuando cruzó
    fila = conn.execute('SELECT d.fqdn::text AS domain, s.computed_at FROM domain_scores s '
                        'JOIN domains d ON d.id = s.domain_id WHERE s.id = %s', (score_id,)).fetchone()
    if not fila:   # el score no es de esta empresa o no existe: sin alerta, y el escaneo no se cae por ella
        return None
    payload = {'domain': fila['domain'], 'score': score, 'threshold': umbral,
               'previous_score': anterior['score'] if anterior else None, 'computed_at': fila['computed_at'].isoformat()}
    severidad = 'critical' if score >= criterio.CORTES_PLANTILLA['critical'] else 'high'
    alerta = conn.execute(
        "INSERT INTO alerts (organization_id, domain_id, event_type, score_id, severity, payload, detected_at) "
        "VALUES (%s, %s, 'score.above_threshold', %s, %s, %s, %s) RETURNING id::text",
        (org, domain_id, score_id, severidad, Jsonb(payload), fila['computed_at'])).fetchone()['id']
    _encolar(conn, org, alerta, fila['computed_at'])
    return alerta


# ------------------------------------------------------------------ entrega

def publicar(url, mensaje, tiempo=TIEMPO):
    """POST del mensaje al flujo. Devuelve el código HTTP. Sin redirecciones: el flujo responde 2xx directo."""
    class SinRedirecciones(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    peticion = urllib.request.Request(url, data=json.dumps(mensaje).encode(), method='POST',
                                      headers={'Content-Type': 'application/json', 'User-Agent': 'lowtide-alertas'})
    try:
        with urllib.request.build_opener(SinRedirecciones).open(peticion, timeout=tiempo) as respuesta:  # nosec B310
            return respuesta.status
    except urllib.error.HTTPError as error:
        return error.code


def _portal():
    try:
        from cirdan.config import origenes_permitidos
        return (config('PORTAL_URL') or origenes_permitidos()[0]).rstrip('/')
    except Exception:   # sin enlace no se cae la entrega
        return None


PENDIENTES_SQL = '''
SELECT d.id::text, d.attempt, d.integration_id::text, i.secret_enc, a.event_type, a.payload
  FROM deliveries d JOIN alerts a ON a.id = d.alert_id JOIN integrations i ON i.id = d.integration_id
 WHERE d.status IN ('pending', 'retrying') AND (d.next_attempt_at IS NULL OR d.next_attempt_at <= now())
   AND i.enabled
 ORDER BY d.detected_at, d.id
 LIMIT 1
 FOR UPDATE OF d SKIP LOCKED
'''


def _entregar_una(conn, enviar, portal):
    """Toma una entrega vencida (con candado, otro despachador la salta) y la intenta. False si no había."""
    d = conn.execute(PENDIENTES_SQL).fetchone()
    if not d:
        return False
    intento = d['attempt'] + 1
    codigo, error = None, None
    try:
        url = descifrar_url(d['integration_id'], d['secret_enc'])
        codigo = enviar(url, tarjeta.tarjeta(d['event_type'], d['payload'] or {}, portal))
        if not 200 <= codigo < 300:
            error = 'el flujo de Teams respondió HTTP %d' % codigo
    except UrlIlegible as e:
        error = str(e)
    except (urllib.error.URLError, OSError, ValueError) as e:
        error = 'sin respuesta del flujo de Teams (%s)' % type(e).__name__
    if error is None:
        conn.execute("UPDATE deliveries SET status = 'delivered', attempt = %s, response_status = %s, last_error = NULL, "
                     'delivered_at = clock_timestamp(), next_attempt_at = NULL, updated_at = now() WHERE id = %s',
                     (intento, codigo, d['id']))
    else:
        espera = tarjeta.espera(intento)
        conn.execute("UPDATE deliveries SET status = %s, attempt = %s, response_status = %s, last_error = %s, "
                     "next_attempt_at = CASE WHEN %s::int IS NULL THEN NULL ELSE now() + make_interval(secs => %s) END, "
                     'updated_at = now() WHERE id = %s',
                     ('dead' if espera is None else 'retrying', intento, codigo, error, espera, espera or 0, d['id']))
        log.warning('entrega %s de alertas: intento %d falló: %s', d['id'], intento, error)
    return True


def despachar(org, enviar=publicar, conn=None, maximo=LOTE):
    """Manda las entregas vencidas de la empresa, cada una en su transacción (o en savepoints de `conn` en pruebas).
    Devuelve cuántas intentó."""
    from cirdan.db import transaction   # solo al despachar: la tarjeta y el cifrado se prueban sin base
    portal = _portal()
    intentadas = 0
    while intentadas < maximo:
        if conn is not None:
            with conn.transaction():
                hubo = _entregar_una(conn, enviar, portal)
        else:
            with transaction(org) as c:
                hubo = _entregar_una(c, enviar, portal)
        if not hubo:
            break
        intentadas += 1
    return intentadas


def siguiente_espera(org, conn=None):
    """Segundos hasta la próxima entrega por reintentar de la empresa, o None si no queda ninguna."""
    from cirdan.db import transaction
    sql = ("SELECT extract(epoch FROM min(next_attempt_at) - now()) AS s FROM deliveries "
           "WHERE status = 'retrying'")
    if conn is not None:
        fila = conn.execute(sql).fetchone()
    else:
        with transaction(org) as c:
            fila = c.execute(sql).fetchone()
    return None if fila['s'] is None else max(0.0, float(fila['s']))


def despachar_en_segundo_plano(org, enviar=publicar, limite=3600):
    """Hilo que despacha ya y sigue con los reintentos de la empresa hasta `limite` segundos. Lo lanza el orquestador
    al cerrar el escaneo. Si el proceso se reinicia, la siguiente corrida (o `python -m cirdan.alertas`) retoma las
    pendientes: están en la base."""
    def trabajar():
        fin = time.monotonic() + limite
        try:
            while True:
                despachar(org, enviar)
                espera = siguiente_espera(org)
                if espera is None or time.monotonic() + espera > fin:
                    return
                time.sleep(espera + 1)
        except Exception:
            log.exception('falló el despacho de alertas de la empresa %s', org)
    hilo = threading.Thread(target=trabajar, name='alertas-%s' % org, daemon=True)
    hilo.start()
    return hilo
