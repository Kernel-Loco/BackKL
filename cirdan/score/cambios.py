"""Resumen de cambios entre los escaneos que aparecen en el histórico."""
from datetime import timedelta


def resumen_semanal(actual, anterior):
    """Resume activos y hallazgos nuevos y el crecimiento semanal de activos."""
    stats = actual['stats'] or {}
    nuevos_activos = actual['new_assets'] or 0
    nuevos_hallazgos = stats.get('new_findings') or 0
    activos_actuales = stats.get('assets')

    crecimiento = None
    activos_anteriores = None
    anterior_id = anterior['scan_id'] if anterior else None
    anterior_fecha = anterior['finished_at'] if anterior else None

    if anterior and anterior_fecha and actual['finished_at'] and activos_actuales is not None:
        intervalo = actual['finished_at'] - anterior_fecha
        activos_anteriores = (anterior['stats'] or {}).get('assets')
        if timedelta(0) <= intervalo <= timedelta(days=7) and activos_anteriores:
            crecimiento = round((activos_actuales - activos_anteriores) * 100 / activos_anteriores, 2)

    alertas = {
        'new_asset': nuevos_activos > 0,
        'new_finding': nuevos_hallazgos > 0,
        'assets_growth_over_20_percent': crecimiento is not None and crecimiento > 20,
    }
    if not any(alertas.values()):
        return None

    return {
        'previous_scan_id': anterior_id,
        'previous_scan_at': anterior_fecha,
        'assets_before': activos_anteriores,
        'assets_now': activos_actuales,
        'new_assets': nuevos_activos,
        'assets_growth_percent': crecimiento,
        'new_findings': nuevos_hallazgos,
        'alerts': alertas,
    }
