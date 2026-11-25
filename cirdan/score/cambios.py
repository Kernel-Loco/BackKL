"""Resumen de cambios entre los escaneos que aparecen en el histórico."""
from datetime import timedelta

SEMANA = timedelta(days=7)
# Si ningún escaneo anterior terminó dentro de la semana, el crecimiento se mide contra el más reciente de antes, solo
# si tiene 14 días o menos. Así un programador semanal que se corre unos minutos sigue midiendo la semana, y un
# escaneo de hace un mes no cuenta como 'en la semana' (Ernesto, 23 nov, RC-73).
TOPE_RESPALDO = timedelta(days=14)


def _sirve_de_base(escaneo):
    return escaneo.get('scan_status') != 'failed' and bool((escaneo['stats'] or {}).get('assets'))


def base_de_la_semana(actual, anteriores):
    """El escaneo contra el que se mide el crecimiento de la semana, o None.

    Es el más viejo de los que terminaron en los 7 días antes de actual, así varios escaneos de la semana con menos
    de 20 % cada uno suman. Si no hay ninguno, el más reciente que terminó antes, con 14 días o menos. Solo sirve de
    base un escaneo que no falló y que contó activos: uno 'failed' guarda 0 activos y dejaría la semana sin
    crecimiento. Uno 'partial' sí cuenta, como en el contrato (completado o parcial)."""
    fin = actual['finished_at']
    if not fin:
        return None
    con_fecha = [e for e in anteriores if e['finished_at'] and e['finished_at'] <= fin and _sirve_de_base(e)]
    en_la_semana = [e for e in con_fecha if fin - e['finished_at'] <= SEMANA]
    if en_la_semana:
        return min(en_la_semana, key=lambda e: e['finished_at'])
    respaldo = [e for e in con_fecha if fin - e['finished_at'] <= TOPE_RESPALDO]
    return max(respaldo, key=lambda e: e['finished_at']) if respaldo else None


def resumen_semanal(actual, anteriores):
    """Resume activos y hallazgos nuevos y el crecimiento de activos en la semana.

    anteriores son los escaneos del histórico que van antes de actual. previous_scan_id, previous_scan_at y
    assets_before son los de la base de la semana (base_de_la_semana). Sin base, previous_scan_id y previous_scan_at
    son los del escaneo anterior más reciente, como referencia, y assets_before y assets_growth_percent van en None."""
    stats = actual['stats'] or {}
    nuevos_activos = actual['new_assets'] or 0
    nuevos_hallazgos = stats.get('new_findings') or 0
    activos_actuales = stats.get('assets')

    crecimiento = None
    activos_anteriores = None
    base = base_de_la_semana(actual, anteriores)
    if base:
        referencia = base
        activos_anteriores = base['stats']['assets']
        if activos_actuales is not None:
            crecimiento = (activos_actuales - activos_anteriores) * 100 / activos_anteriores
    else:
        referencia = anteriores[-1] if anteriores else None

    alertas = {
        'new_asset': nuevos_activos > 0,
        'new_finding': nuevos_hallazgos > 0,
        # Se compara antes de redondear: 20.001 % sí supera 20 %.
        'assets_growth_over_20_percent': crecimiento is not None and crecimiento > 20,
    }
    if not any(alertas.values()):
        return None

    return {
        'previous_scan_id': referencia['scan_id'] if referencia else None,
        'previous_scan_at': referencia['finished_at'] if referencia else None,
        'assets_before': activos_anteriores,
        'assets_now': activos_actuales,
        'new_assets': nuevos_activos,
        'assets_growth_percent': round(crecimiento, 2) if crecimiento is not None else None,
        'new_findings': nuevos_hallazgos,
        'alerts': alertas,
    }
