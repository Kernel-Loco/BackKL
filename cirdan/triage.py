"""Ciclo de remediación con triage (#80, RC-133): validación del cambio de estado de un hallazgo, las acciones de la
bitácora y las métricas de remediación por dominio. Sin base ni red: la API (cirdan/api/v1.py) hace las consultas.

Un hallazgo se marca falso positivo, riesgo aceptado (con fecha de revisión) o resuelto, o se reabre. Quién, cuándo,
el motivo y la fecha de revisión quedan en `audit_log` (la bitácora con cadena de hash), no en columnas nuevas de
`findings`. Así el orquestador, que ya lee la bitácora para no reabrir un secreto rotado (#80, PR 271), y el reporte
leen lo mismo.

- Un falso positivo sale del score (el motor solo cuenta `open` y `accepted_risk`) y se recalcula el score del dominio.
  Queda como etiqueta para reentrenar el clasificador (#34): `findings.status = 'false_positive'` con su evento.
- Un riesgo aceptado sigue en el score, pero sale del plan de acción hasta su fecha de revisión. Ese día vuelve al plan.
- Un hallazgo resuelto que el siguiente escaneo vuelve a ver se reabre (orquestador) y cuenta como no remediado.
"""
from datetime import date, datetime, timedelta, timezone

ESTADOS = ('open', 'resolved', 'accepted_risk', 'false_positive')
# Cada estado nuevo deja su acción en la bitácora. 'finding.resolved' es la misma que lee el orquestador
# (orquestador.ACCION_HALLAZGO_RESUELTO) para no reabrir un secreto rotado.
ACCIONES = {
    'resolved': 'finding.resolved',
    'false_positive': 'finding.false_positive',
    'accepted_risk': 'finding.accepted_risk',
    'open': 'finding.reopened',
}
MOTIVOS_RESUELTO = ('fixed', 'secret_rotated')
REGLA_SECRETO = 'secret_in_public_repo'
MOTIVO_SECRETO_ROTADO = 'secret_rotated'
REVISION_MAXIMA_DIAS = 365
NOTA_MAXIMA = 500


def _texto(valor, campo, maximo):
    if valor is None:
        return None
    if not isinstance(valor, str):
        raise ValueError('%s debe ser texto' % campo)
    limpio = ''.join(c for c in valor if c.isprintable() or c == ' ').strip()
    if len(limpio) > maximo:
        raise ValueError('%s admite hasta %d caracteres' % (campo, maximo))
    return limpio or None


def validar(payload, regla, hoy=None):
    """El cambio que pide el cliente, validado. ValueError con un mensaje para el 422 si algo no cuadra.

    `status`: uno de ESTADOS. `reason`: solo con 'resolved', 'fixed' (por omisión) o 'secret_rotated', y este solo en
    la regla de secretos. `review_date` (AAAA-MM-DD): obligatoria con 'accepted_risk', de mañana a un año, y no va con
    los demás. `note`: texto libre opcional, hasta 500 caracteres.
    """
    if not isinstance(payload, dict):
        raise ValueError('el cuerpo debe ser un objeto JSON')
    desconocidos = set(payload) - {'status', 'reason', 'review_date', 'note'}
    if desconocidos:
        raise ValueError('campos desconocidos: %s' % ', '.join(sorted(desconocidos)))
    estado = payload.get('status')
    if estado not in ESTADOS:
        raise ValueError('status debe ser uno de: %s' % ', '.join(ESTADOS))
    hoy = hoy or datetime.now(timezone.utc).date()

    motivo = _texto(payload.get('reason'), 'reason', 40)
    if estado == 'resolved':
        motivo = motivo or 'fixed'
        if motivo not in MOTIVOS_RESUELTO:
            raise ValueError('reason debe ser uno de: %s' % ', '.join(MOTIVOS_RESUELTO))
        if motivo == MOTIVO_SECRETO_ROTADO and regla != REGLA_SECRETO:
            raise ValueError("'secret_rotated' solo aplica a secretos en repositorios públicos")
    elif motivo is not None:
        raise ValueError('reason solo va con status resolved')

    revision = payload.get('review_date')
    if estado == 'accepted_risk':
        if not isinstance(revision, str):
            raise ValueError('review_date (AAAA-MM-DD) es obligatoria para aceptar el riesgo')
        try:
            revision = date.fromisoformat(revision)
        except ValueError:
            raise ValueError('review_date debe ser una fecha AAAA-MM-DD') from None
        if not hoy < revision <= hoy + timedelta(days=REVISION_MAXIMA_DIAS):
            raise ValueError('review_date debe estar entre mañana y un año a partir de hoy')
    elif revision is not None:
        raise ValueError('review_date solo va con status accepted_risk')

    return {'status': estado, 'reason': motivo, 'review_date': revision,
            'note': _texto(payload.get('note'), 'note', NOTA_MAXIMA)}


def detalles(anterior, cambio):
    """Los details del evento de la bitácora: el antes, el después y lo que dijo el cliente. Sin datos del hallazgo."""
    datos = {'from': anterior, 'to': cambio['status']}
    if cambio['reason']:
        datos['reason'] = cambio['reason']
    if cambio['review_date']:
        datos['review_date'] = cambio['review_date'].isoformat()
    if cambio['note']:
        datos['note'] = cambio['note']
    return datos


def revision_vencida(estado, revision, hoy=None):
    """Un riesgo aceptado cuya fecha de revisión ya llegó (o que no la tiene) vuelve al plan de acción."""
    if estado != 'accepted_risk':
        return False
    if revision is None:
        return True
    if isinstance(revision, str):
        try:
            revision = date.fromisoformat(revision)
        except ValueError:
            return True
    return revision <= (hoy or datetime.now(timezone.utc).date())


def metricas(filas):
    """Métricas de remediación de un dominio a partir de sus hallazgos (status, detected_at, resolved_at).

    `closed_pct`: resueltos entre todos los hallazgos que no son falso positivo, en porcentaje con un decimal. Un
    hallazgo que el escaneo reabrió vuelve a 'open' sin `resolved_at`, así que cuenta como no remediado.
    `mean_time_to_remediate_days`: promedio en días, con un decimal, de detected_at a resolved_at de los resueltos.
    """
    por_estado = dict.fromkeys(ESTADOS, 0)
    dias = []
    for fila in filas:
        por_estado[fila['status']] = por_estado.get(fila['status'], 0) + 1
        if fila['status'] == 'resolved' and fila['resolved_at'] and fila['detected_at']:
            dias.append(max((fila['resolved_at'] - fila['detected_at']).total_seconds(), 0) / 86400)
    reales = sum(por_estado.values()) - por_estado['false_positive']
    return {
        'total': sum(por_estado.values()),
        'by_status': por_estado,
        'closed': por_estado['resolved'],
        'closed_pct': round(100 * por_estado['resolved'] / reales, 1) if reales else None,
        'mean_time_to_remediate_days': round(sum(dias) / len(dias), 1) if dias else None,
        'remediated_count': len(dias),
    }
