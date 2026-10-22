"""Características del reto para el ML (#33 a #36): tipo, antigüedad, exposición y sensibilidad.

Salen de la evidencia del hallazgo con una sola rúbrica, la de sensibilidad(), para que el lote de #33 y los
hallazgos reales usen los mismos valores. Hoy la API (cirdan/api/v1.py:26-27) y crt.sh (crtsh.py:390, 398 y 435)
todavía ponen la sensibilidad fija por código. Que adopten calcular() va en otra tarjeta, antes de #36.

Rúbrica de sensibilidad, según lo que expone el hallazgo:
- alta: credenciales, acceso remoto a un sistema o datos personales.
- media: un servicio, el correo o información interna sin acceso directo.
- baja: solo información pública o un activo sin uso.
"""
from datetime import date, datetime

# Código de regla -> tipo, con los mismos nombres que cirdan/api/v1.py:20-25
TIPO = {
    'breach_exposure': 'correos_en_brecha', 'cert_expired': 'certificado_vencido',
    'cert_expiring_soon': 'certificado_por_vencer', 'outdated_software': 'software_desactualizado',
    'exposed_rdp': 'servicio_expuesto', 'dmarc_missing': 'dmarc_faltante', 'spf_missing': 'spf_faltante',
    'lookalike_domain': 'dominio_parecido',
}
EXPOSICION_DIRECTA = {'outdated_software', 'exposed_rdp'}     # v1.py:26
ACTIVOS_DIRECTOS = ('ip', 'service')                          # v1.py:80

# De qué fecha de la evidencia cuenta la antigüedad. Los demás códigos cuentan desde primera_vez.
DESDE = {
    'breach_exposure': 'breach_date',          # la brecha (v1.py:69-70)
    'cert_expired': 'not_after',               # el vencimiento (v1.py:71-72)
    'cert_expiring_soon': 'not_before',        # la emisión (crtsh.py:397)
    'lookalike_domain': 'primer_certificado',  # el primer certificado del parecido (crtsh.py:434)
}

# Clases de datos de HIBP que cuentan como credenciales o datos personales. Correos, nombres y usuarios no.
DATOS_SENSIBLES = {'Passwords', 'Password hints', 'Phone numbers', 'Physical addresses', 'Dates of birth',
                   'Government issued IDs', 'Credit cards'}
# Para qué sirve el host, según #18 (cabeceras y huellas) o el nombre del host
USO = {
    'inicio_de_sesion': 'alta',  # pide usuario y contraseña
    'api': 'media',
    'correo': 'media',
    'servidor': 'media',         # una aplicación de la empresa sin inicio de sesión a la vista
    'sitio_publico': 'baja',     # sitio informativo, sin formularios ni inicio de sesión
    'sin_contenido': 'baja',     # resuelve pero no muestra nada
}
PALABRAS_SOSPECHOSAS = ('login', 'acceso', 'pago', 'cuenta', 'verifica', 'seguridad')
DIAS_SIN_VER = 180   # un servicio que no se ve desde hace más de esto ya no da acceso confirmado


def _dia(valor):
    if isinstance(valor, datetime):
        return valor.date()
    if isinstance(valor, date):
        return valor
    return date.fromisoformat(str(valor)[:10])


def antiguedad_dias(codigo, evidencia, referencia):
    """Días desde que empezó la exposición hasta `referencia` (el día del escaneo). 0 si la evidencia no trae la fecha."""
    desde = (evidencia or {}).get(DESDE.get(codigo, 'primera_vez'))
    if not desde:
        return 0
    return max(0, (_dia(referencia) - _dia(desde)).days)


def exposicion(codigo, tipo_activo):
    """directa si el activo responde en internet (un servicio o un panel), publica si es un dato público."""
    return 'directa' if codigo in EXPOSICION_DIRECTA or tipo_activo in ACTIVOS_DIRECTOS else 'publica'


def sensibilidad(codigo, evidencia, referencia):
    """La rúbrica de sensibilidad (alta, media o baja) según lo que la evidencia dice que expone el hallazgo."""
    e = evidencia or {}
    if codigo == 'breach_exposure':
        return 'alta' if DATOS_SENSIBLES & set(e.get('data_classes') or ()) else 'media'
    if codigo == 'exposed_rdp':
        ultima = e.get('ultima_vez')
        sin_ver = ultima and (_dia(referencia) - _dia(ultima)).days > DIAS_SIN_VER
        return 'media' if sin_ver else 'alta'
    if codigo in ('dmarc_missing', 'spf_missing'):
        if not e.get('mx'):
            return 'baja'        # el dominio no recibe correo
        if codigo == 'spf_missing' and e.get('dmarc') == 'p=reject':
            return 'baja'        # el DMARC ya rechaza el correo suplantado
        return 'media'
    if codigo == 'lookalike_domain':
        nombres = [e.get('dominio_parecido') or ''] + list(e.get('nombres') or ())
        return 'alta' if any(p in n for n in nombres for p in PALABRAS_SOSPECHOSAS) else 'baja'
    return USO.get(e.get('uso'), 'media')   # outdated_software, cert_expired, cert_expiring_soon y códigos nuevos


def calcular(codigo, tipo_activo, evidencia, referencia):
    """Las 4 características del reto, con las claves y valores del contrato de plugin (#13)."""
    return {
        'tipo': TIPO.get(codigo, codigo),
        'antiguedad_dias': antiguedad_dias(codigo, evidencia, referencia),
        'exposicion': exposicion(codigo, tipo_activo),
        'sensibilidad': sensibilidad(codigo, evidencia, referencia),
    }
