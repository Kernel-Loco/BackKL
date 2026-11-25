"""Alcance de la carta de autorización (#26, RC-59, propuesta 10251).

La carta autoriza las actividades de su Anexo A (docs/plantilla_carta_autorizacion.md) y lo que no describe no está
autorizado. domain_authorizations guarda la versión de la plantilla y las actividades que firmó la empresa
(migración 029), y el orquestador solo corre las fuentes cuya actividad está en la carta vigente.

Una fuente también puede usar los registros públicos de certificados y el DNS público para saber qué nombres revisar,
como lo dice cada actividad del Anexo A. Eso no cuenta como otra actividad.
"""

# versión de la plantilla -> actividades de su Anexo A. La 1 tiene las actividades 1 a 11 (sin cambios desde el
# 18 oct 2026). Una versión nueva se suma aquí y en el CHECK domain_authorizations_plantilla_valida de la base.
PLANTILLAS = {1: frozenset(range(1, 12))}
PLANTILLA_VIGENTE = 1

# data_sources.code -> actividad del Anexo A que hace. 'ejemplo' es solo para pruebas y no consulta nada.
ACTIVIDAD_DE_FUENTE = {
    'ct_logs': 1, 'subfinder': 1, 'dns': 2, 'whois': 3, 'github': 4, 'shodan': 5, 'censys': 5, 'web': 6,
    'hibp': 7, 'identity': 8, 'api_docs': 9,
}
FUENTE_PRUEBAS = 'ejemplo'

NO_AUTORIZADA = 'Fuente %s no autorizada por la carta (actividad %s del Anexo A).'


def actividades_validas(version, actividades):
    """Las actividades sin repetir y ordenadas si `version` es una plantilla conocida y todas son suyas; si no, None."""
    if isinstance(version, bool) or not isinstance(version, int) or version not in PLANTILLAS:
        return None
    if not isinstance(actividades, list) or not actividades:
        return None
    if any(isinstance(a, bool) or not isinstance(a, int) for a in actividades):
        return None
    if len(set(actividades)) != len(actividades) or not set(actividades) <= PLANTILLAS[version]:
        return None
    return sorted(actividades)


def autorizada(fuente, actividades):
    """True si la carta (sus `actividades`, o None si no tiene alcance) autoriza la fuente. Una fuente sin actividad
    conocida no se autoriza nunca, salvo la de pruebas."""
    if fuente == FUENTE_PRUEBAS:
        return True
    actividad = ACTIVIDAD_DE_FUENTE.get(fuente)
    return actividad is not None and actividades is not None and actividad in actividades
