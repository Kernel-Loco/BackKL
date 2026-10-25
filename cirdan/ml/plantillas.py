"""Plantillas del lote semisintético del ML (#33, RC-65).

Una plantilla es un código de regla con una variante de contexto. Son 3 por código, 24 en total. Cada una arma la
evidencia de un hallazgo con datos que un recolector da hoy o va a dar: crt.sh (#14), DNS con MX (#15), Shodan (#17),
versiones (#18) y HIBP (#19). La clase esperada solo sirve para balancear el lote. Nunca es la etiqueta.

Todo es ficticio y se puede publicar: dominios bajo .example (RFC 2606), IP de documentación (RFC 5737), brechas
DemoBreach, productos de demostración y CVE del año 2099. Lo que se repite entre filas no se contradice: una empresa
tiene un solo perfil de correo, una brecha una sola fecha, una versión un solo fin de soporte y un host un solo
hallazgo de certificado.
"""
import ipaddress
import re
from dataclasses import dataclass
from datetime import date, timedelta
from functools import partial
from typing import Callable

from cirdan.ml.caracteristicas import SPF_NULO
from cirdan.recolectores import crtsh

REFERENCIA = date(2026, 10, 20)   # día del escaneo de todo el lote

# Código -> (categoría, severidad base). Las 7 reglas de db/semillas/001_datos_demo.sql:36-42 y cert_expiring_soon,
# que emite cirdan/recolectores/crtsh.py:79 y que #30 agregó al catálogo en db/semillas/004_reglas_recolectores.sql.
# Los certificados van a infrastructure (db/cirdan_esquema.dbml:223). Si #31 cambia una severidad base, se cambia
# aquí, se regenera el lote y se recalcula clase_reglas. pruebas/test_dataset_ml.py revisa que coincida con la
# semilla 001 y con crtsh.py, y pruebas/test_catalogo_reglas.py que crtsh.py coincida con el catálogo.
REGLAS = {
    'breach_exposure': ('data_leaks', 'critical'),
    'cert_expired': ('infrastructure', 'high'),
    'outdated_software': ('infrastructure', 'high'),
    'exposed_rdp': ('infrastructure', 'high'),
    'dmarc_missing': ('configuration', 'medium'),
    'spf_missing': ('configuration', 'low'),
    'lookalike_domain': ('digital_identity', 'medium'),
    'cert_expiring_soon': ('infrastructure', crtsh.CODIGOS['cert_expiring_soon']),
}
FUENTE = {
    'breach_exposure': 'hibp', 'outdated_software': 'shodan', 'exposed_rdp': 'shodan', 'dmarc_missing': 'dns',
    'spf_missing': 'dns', 'cert_expired': 'ct_logs', 'cert_expiring_soon': 'ct_logs', 'lookalike_domain': 'ct_logs',
}
CLASES = ('alta', 'media', 'baja')
# Severidad de las reglas -> clase del modelo: crítica y alta cuentan como alta (docs/criterio_criticidad.md:48)
CLASE_DE_SEVERIDAD = {'critical': 'alta', 'high': 'alta', 'medium': 'media', 'low': 'baja'}

# ---------------------------------------------------------------- empresas ficticias

# Perfil de correo de cada empresa -> cuántas hay. Así un mismo dominio no dice en una fila que tiene MX y en otra que no.
# sin_mx_spf_nulo: sin MX, con SPF que no autoriza a nadie (v=spf1 -all) y sin DMARC.
# sin_mx_reject: sin MX ni SPF, con DMARC p=reject.
# mx_spf: MX y SPF, sin DMARC. mx_sin_spf: MX, sin SPF ni DMARC. mx_reject: MX y DMARC p=reject, sin SPF.
PERFILES = {'sin_mx_spf_nulo': 20, 'sin_mx_reject': 28, 'mx_spf': 16, 'mx_sin_spf': 28, 'mx_reject': 28}
CON_MX = ('mx_spf', 'mx_sin_spf', 'mx_reject')
SIN_DMARC = ('sin_mx_spf_nulo', 'mx_spf', 'mx_sin_spf')   # los subdominios de las demás heredan su p=reject
CON_REJECT = ('sin_mx_reject', 'mx_reject')
_INICIOS = ('nor', 'tec', 'bri', 'cor', 'dun', 'fon', 'gar', 'lir', 'men', 'olv', 'pra', 'quin', 'riv', 'sol', 'tar',
            'ves', 'zan', 'cal', 'bel', 'tor')
_MEDIOS = ('a', 'e', 'i', 'o', 'ar', 'en', 'is', 'or')
_FINALES = ('mira', 'vella', 'tivia', 'beno', 'dara', 'rino', 'deva', 'tora', 'meca', 'vento', 'sela', 'quiro')
# Que ningún nombre parezca una clase, una severidad o un dominio parecido sospechoso
_PROHIBIDO = re.compile(r'alt[ao]|baj[ao]|medi[ao]|crit|low|high|sever|login|acceso|pago|cuenta|verifica|seguridad')


@dataclass(frozen=True)
class Empresa:
    dominio: str
    perfil: str


def empresas(rng):
    """Las empresas del lote, con nombres inventados bajo .com.example y su perfil de correo."""
    nombres = sorted({i + m + f for i in _INICIOS for m in _MEDIOS for f in _FINALES if not _PROHIBIDO.search(i + m + f)})
    elegidos = rng.sample(nombres, sum(PERFILES.values()))
    perfiles = [p for p, n in PERFILES.items() for _ in range(n)]
    return [Empresa('%s.com.example' % n, p) for n, p in zip(elegidos, perfiles)]


class Contexto:
    """Lo que una plantilla usa para armar una fila: el azar del lote, las empresas, las IP libres y los hosts que ya
    tienen un hallazgo de certificado."""

    def __init__(self, rng, lista):
        self.rng = rng
        self.lista = lista
        self._ips = [str(ip) for red in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')
                     for ip in ipaddress.ip_network(red).hosts()]
        rng.shuffle(self._ips)
        self._usadas = set()
        self.con_certificado = set()

    def nueva_plantilla(self):
        self._usadas = set()

    def empresa(self, *perfiles):
        """Una empresa con alguno de `perfiles` (cualquiera si no se pasan), sin repetir dentro de la plantilla mientras
        alcancen."""
        candidatas = [e for e in self.lista if not perfiles or e.perfil in perfiles]
        libres = [e for e in candidatas if e.dominio not in self._usadas]
        e = self.rng.choice(libres or candidatas)
        self._usadas.add(e.dominio)
        return e

    def ip(self):
        """Una IP de documentación (RFC 5737) que ninguna otra fila del lote usa."""
        return self._ips.pop()


def _hace(dias):
    return (REFERENCIA - timedelta(days=dias)).isoformat()


# ---------------------------------------------------------------- cómo se arma cada código
# Cada función devuelve la empresa, el activo, su tipo, la evidencia y los datos de la CVE si tiene.

# Brechas ficticias: (nombre, fecha, clases de datos de HIBP). Cada una sale igual en todas sus filas.
BRECHAS_RECIENTES = (   # con contraseñas, de hace menos de 6 meses
    ('DemoBreach-Boletos', '2026-09-28', ('Email addresses', 'Passwords', 'Phone numbers')),
    ('DemoBreach-Foro', '2026-09-14', ('Email addresses', 'Passwords', 'Usernames')),
    ('DemoBreach-Tienda', '2026-08-02', ('Email addresses', 'Names', 'Passwords')),
    ('DemoBreach-Recetas', '2026-07-11', ('Email addresses', 'Passwords')),
    ('DemoBreach-Viajes', '2026-06-18', ('Email addresses', 'Passwords', 'Usernames')),
    ('DemoBreach-Gimnasio', '2026-05-07', ('Email addresses', 'Names', 'Passwords')),
)
BRECHAS_VIEJAS = (      # con contraseñas, de hace más de 3 años
    ('DemoBreach-Citas', '2023-05-04', ('Email addresses', 'Passwords', 'Phone numbers')),
    ('DemoBreach-Mudanzas', '2022-08-30', ('Email addresses', 'Names', 'Passwords')),
    ('DemoBreach-Fotos', '2022-01-19', ('Email addresses', 'Passwords')),
    ('DemoBreach-Juegos', '2021-03-09', ('Email addresses', 'Passwords', 'Usernames')),
    ('DemoBreach-Musica', '2020-06-15', ('Email addresses', 'Passwords', 'Usernames')),
    ('DemoBreach-Cupones', '2019-11-22', ('Email addresses', 'Passwords')),
)
BRECHAS_SIN_CONTRASENAS = (   # solo correos, nombres o usuarios, de 2 meses a 4 años
    ('DemoBreach-Concursos', '2026-08-21', ('Email addresses', 'Names', 'Usernames')),
    ('DemoBreach-Catalogo', '2026-03-02', ('Email addresses',)),
    ('DemoBreach-Encuestas', '2025-02-12', ('Email addresses',)),
    ('DemoBreach-Webinars', '2024-07-29', ('Email addresses', 'Names')),
    ('DemoBreach-Boletin', '2023-11-03', ('Email addresses', 'Names')),
    ('DemoBreach-Eventos', '2022-12-06', ('Email addresses', 'Names', 'Usernames')),
)


def brecha(ctx, brechas):
    """Correos de una empresa con MX en una de `brechas`."""
    r, e = ctx.rng, ctx.empresa(*CON_MX)
    nombre, fecha, clases = r.choice(brechas)
    evidencia = {'emails_exposed': r.randint(2, 60), 'breach_name': nombre, 'breach_date': fecha,
                 'data_classes': list(clases)}
    return {'empresa': e, 'asset': e.dominio, 'asset_type': 'domain', 'evidence': evidencia, 'cve': None}


# Productos ficticios: versión -> (fin de soporte o None si sigue con soporte, CVE como (id, CVSS, EPSS, KEV)).
# Cada versión sale con la misma fecha y las mismas CVE en todas sus filas.
VERSIONES = {
    'PanelDemo': {
        '2.1': ('2024-05-01', (('CVE-2099-10231', 9.8, 0.974, True), ('CVE-2099-11872', 8.8, 0.412, True))),
        '2.3': ('2024-11-15', (('CVE-2099-12045', 9.1, 0.633, True), ('CVE-2099-13390', 8.1, 0.027, True))),
        '2.4': ('2025-06-30', (('CVE-2099-14417', 9.8, 0.215, True), ('CVE-2099-15102', 8.6, 0.058, True))),
        '3.0': ('2026-03-31', (('CVE-2099-16583', 8.8, 0.891, True), ('CVE-2099-17220', 8.1, 0.094, True))),
    },
    'ServidorDemo': {
        '9.2': (None, (('CVE-2099-20114', 6.5, 0.214, False), ('CVE-2099-21876', 4.3, 0.002, False))),
        '9.4': (None, (('CVE-2099-22931', 5.3, 0.018, False), ('CVE-2099-23408', 6.1, 0.296, False))),
        '10.1': (None, (('CVE-2099-24750', 4.0, 0.001, False), ('CVE-2099-25663', 5.9, 0.087, False))),
    },
    'libreria-demo.js': {
        '1.4': ('2021-06-30', ()),
        '1.7': ('2022-12-31', ()),
        '1.9': ('2024-08-31', ()),
    },
}


def software(ctx, hosts, uso, producto):
    r, e = ctx.rng, ctx.empresa()
    host = '%s.%s' % (r.choice(hosts), e.dominio)
    version = r.choice(sorted(VERSIONES[producto]))
    fin, cves = VERSIONES[producto][version]
    evidencia = {'port': 443, 'producto': producto, 'version': version, 'fin_de_soporte': fin, 'uso': uso,
                 'primera_vez': _hace(r.randint(5, 300))}
    datos_cve = None
    if cves:
        cve_id, cvss, epss, kev = r.choice(cves)
        datos_cve = {'cve_id': cve_id, 'cvss': cvss, 'epss': epss, 'in_kev': kev}
    return {'empresa': e, 'asset': host, 'asset_type': 'subdomain', 'evidence': evidencia, 'cve': datos_cve}


EQUIPOS_PRODUCCION = ('SRV-PROD-01', 'SRV-PROD-03', 'ERP-PROD-02', 'DB-PROD-01', 'APP-PROD-05')
EQUIPOS_PRUEBAS = ('PRUEBAS-07', 'QA-02', 'TEST-WIN-04', 'DEV-03', 'LAB-01')


def rdp(ctx, equipos, primera, ultima):
    """`primera` y `ultima`: rangos de hace cuántos días se vio el servicio por primera y por última vez."""
    r, e = ctx.rng, ctx.empresa()
    ip = ctx.ip()
    vista = r.randint(*primera)
    evidencia = {'ip': ip, 'port': 3389, 'host': e.dominio, 'equipo': r.choice(equipos), 'primera_vez': _hace(vista),
                 'ultima_vez': _hace(min(vista, r.randint(*ultima)))}
    return {'empresa': e, 'asset': '%s:3389/tcp' % ip, 'asset_type': 'service', 'evidence': evidencia, 'cve': None}


HOSTS_ACCESO = ('login', 'acceso', 'portal', 'clientes')
HOSTS_API = ('api', 'ws', 'api-movil')
HOSTS_CORREO = ('smtp', 'imap', 'correo')
HOSTS_SIN_CONTENIDO = ('old', 'eventos2020', 'promo2019', 'staging-viejo', 'beta')
HOSTS_SECUNDARIOS = ('blog', 'eventos', 'docs', 'ayuda', 'promo')
API_O_CORREO = (('api', HOSTS_API), ('correo', HOSTS_CORREO))
EMISORES = ('Autoridad Demo R3', 'Autoridad Demo R4', 'CA Ejemplo TLS')


def certificado(ctx, codigo, usos, vidas, dias):
    """`usos`: pares (uso, hosts) posibles. `vidas`: días de vigencia posibles del certificado. `dias`: rango de días
    vencido (cert_expired) o para vencer (cert_expiring_soon). Un host tiene un solo hallazgo de certificado en todo
    el lote, así no sale vencido en una fila y por vencer en otra."""
    r = ctx.rng
    host = None
    while host is None or host in ctx.con_certificado:
        uso, hosts = r.choice(usos)
        e = ctx.empresa(*(CON_MX if uso == 'correo' else ()))
        host = '%s.%s' % (r.choice(hosts), e.dominio)
    ctx.con_certificado.add(host)
    d = r.randint(*dias)
    vence = REFERENCIA + timedelta(days=-d if codigo == 'cert_expired' else d)
    emitido = vence - timedelta(days=r.choice(vidas))
    evidencia = {'host': host, 'not_before': emitido.isoformat(), 'not_after': vence.isoformat(),
                 'emisor': r.choice(EMISORES), 'uso': uso}
    if codigo == 'cert_expired':
        evidencia.update(dias_vencido=d, resuelve=True)
    else:
        evidencia['dias_para_vencer'] = d
    return {'empresa': e, 'asset': host, 'asset_type': 'subdomain', 'evidence': evidencia, 'cve': None}


SUBDOMINIOS_CAMPANAS = ('boletin', 'campanas', 'promociones', 'noticias')
PROVEEDOR_ENVIOS = 'envios.correo-demo.example'
SPF_DE_PERFIL = {'mx_spf': 'v=spf1 mx include:%s -all' % PROVEEDOR_ENVIOS, 'sin_mx_spf_nulo': SPF_NULO}


def dmarc(ctx, perfiles, primera, campanas=False):
    """Falta DMARC en el dominio o, con `campanas`, en un subdominio que manda correo por un proveedor de envíos."""
    r, e = ctx.rng, ctx.empresa(*perfiles)
    if campanas:
        nombre = '%s.%s' % (r.choice(SUBDOMINIOS_CAMPANAS), e.dominio)
        mx, spf = ['mx.' + PROVEEDOR_ENVIOS], 'v=spf1 include:%s -all' % PROVEEDOR_ENVIOS
    else:
        nombre = e.dominio
        mx = ['mx1.' + nombre] if e.perfil in CON_MX else []
        spf = SPF_DE_PERFIL.get(e.perfil)
    evidencia = {'record': '_dmarc.' + nombre, 'observed': 'NXDOMAIN', 'mx': mx, 'spf': spf,
                 'primera_vez': _hace(r.randint(*primera))}
    return {'empresa': e, 'asset': nombre, 'asset_type': 'subdomain' if campanas else 'domain', 'evidence': evidencia,
            'cve': None}


def spf(ctx, perfil, primera):
    r, e = ctx.rng, ctx.empresa(perfil)
    evidencia = {'record': e.dominio, 'observed': 'sin TXT v=spf1',
                 'mx': ['mx1.' + e.dominio] if perfil in CON_MX else [],
                 'dmarc': 'p=reject' if perfil in CON_REJECT else None, 'primera_vez': _hace(r.randint(*primera))}
    return {'empresa': e, 'asset': e.dominio, 'asset_type': 'domain', 'evidence': evidencia, 'cve': None}


PALABRAS_PARECIDO = ('login', 'pagos', 'acceso', 'cuenta')
OTROS_TLD = ('net', 'org', 'info')


def variantes_de_crtsh(marca):
    """Las variantes de marca.com que crt.sh consulta con --con-parecidos (crtsh.candidatos_parecidos), en orden."""
    return crtsh.candidatos_parecidos(marca + '.com', crtsh.MAX_CANDIDATOS)


def parecido(ctx, tipo, primero, certificados, vencido=None):
    """Dominio parecido con certificado. `primero`: rango de hace cuántos días salió su primer certificado.
    `vencido`: rango de hace cuántos días venció el último (None si sigue vigente). crt.sh lo sigue reportando hasta
    90 días después (crtsh.VENTANA_PARECIDOS_DIAS). Los errores tipográficos y los otros TLD salen de las variantes que
    crt.sh consulta, con .example al final."""
    r, e = ctx.rng, ctx.empresa()
    marca = e.dominio.split('.')[0]
    if tipo == 'contiene_marca':
        dominio = '%s-%s.com.example' % (marca, r.choice(PALABRAS_PARECIDO))
    else:
        variantes = [v.split('.', 1) for v in variantes_de_crtsh(marca)]
        if tipo == 'otro_tld':
            opciones = ['%s.%s' % (n, s) for n, s in variantes if n == marca and s in OTROS_TLD]
        else:   # error_tipografico: los homoglifos de crtsh.HOMOGLIFOS
            opciones = ['%s.%s' % (n, s) for n, s in variantes if n != marca and s == 'com']
        dominio = r.choice(opciones) + '.example'
    edad = r.randint(*primero)
    if vencido:
        vence = REFERENCIA - timedelta(days=r.randint(*vencido))
    else:
        vence = REFERENCIA + timedelta(days=90 - edad if edad < 90 else r.randint(10, 85))
    evidencia = {'dominio_parecido': dominio, 'tipo_parecido': tipo, 'nombres': [dominio, 'www.' + dominio],
                 'certificados': r.randint(*certificados), 'primer_certificado': _hace(edad),
                 'vence': vence.isoformat(), 'emisor': r.choice(EMISORES)}
    return {'empresa': e, 'asset': e.dominio, 'asset_type': 'domain', 'evidence': evidencia, 'cve': None}


# ---------------------------------------------------------------- títulos

def titulo(codigo, asset, e):
    """Título en español como el de cada recolector. Los de crt.sh son los de crtsh.py:385, 393 y 427."""
    if codigo == 'breach_exposure':
        n = e['emails_exposed']
        return ('%d correos de la empresa aparecen' % n if n > 1 else '1 correo de la empresa aparece') + \
            ' en una brecha de datos pública'
    if codigo == 'outdated_software':
        return '%s usa %s %s, una versión desactualizada' % (asset, e['producto'], e['version'])
    if codigo == 'exposed_rdp':
        return 'El puerto 3389 (RDP) se vio abierto en %s' % e['ip']   # la evidencia dice cuándo
    if codigo == 'cert_expired':
        return 'Certificado vencido en %s' % asset
    if codigo == 'cert_expiring_soon':
        d = e['dias_para_vencer']
        return 'El certificado de %s vence en %d %s' % (asset, d, 'día' if d == 1 else 'días')
    if codigo == 'dmarc_missing':
        return 'Falta el registro DMARC en %s' % asset
    if codigo == 'spf_missing':
        return 'Falta el registro SPF en %s' % asset
    if codigo == 'lookalike_domain':
        return 'Dominio parecido con certificado: %s' % e['dominio_parecido']
    raise ValueError('código sin título: %s' % codigo)


# ---------------------------------------------------------------- las 24 plantillas

@dataclass(frozen=True)
class Plantilla:
    id: str
    codigo: str
    clase_esperada: str   # solo para balancear el lote, nunca es la etiqueta
    filas: int
    prueba: bool          # va al set de prueba. Es una propuesta que se confirma en #34
    descripcion: str
    armar: Callable


_P = Plantilla
PLANTILLAS = (
    _P('brecha_contrasenas_reciente', 'breach_exposure', 'alta', 24, False,
       'Brecha con contraseñas de hace menos de 6 meses', partial(brecha, brechas=BRECHAS_RECIENTES)),
    _P('brecha_contrasenas_vieja', 'breach_exposure', 'alta', 24, True,
       'Brecha con contraseñas de hace más de 3 años', partial(brecha, brechas=BRECHAS_VIEJAS)),
    _P('brecha_solo_correos', 'breach_exposure', 'media', 13, False,
       'Brecha solo con correos, nombres o usuarios, de 2 meses a 4 años',
       partial(brecha, brechas=BRECHAS_SIN_CONTRASENAS)),
    _P('software_panel_kev', 'outdated_software', 'alta', 24, False,
       'Panel de acceso sin soporte con una CVE en KEV, EPSS de 0.027 a 0.974',
       partial(software, hosts=('admin', 'panel', 'acceso'), uso='inicio_de_sesion', producto='PanelDemo')),
    _P('software_servidor_con_soporte', 'outdated_software', 'media', 13, True,
       'Aplicación con soporte y una CVE con CVSS de 4.0 a 6.5, EPSS de 0.001 a 0.296',
       partial(software, hosts=('app', 'tienda', 'reservas'), uso='servidor', producto='ServidorDemo')),
    _P('software_libreria_sitio_estatico', 'outdated_software', 'baja', 16, False,
       'Librería sin soporte en un sitio informativo, sin CVE',
       partial(software, hosts=('www', 'blog', 'landing'), uso='sitio_publico', producto='libreria-demo.js')),
    _P('rdp_produccion', 'exposed_rdp', 'alta', 24, False,
       'RDP de un servidor de producción, visto por primera vez hace 2 a 400 días',
       partial(rdp, equipos=EQUIPOS_PRODUCCION, primera=(2, 400), ultima=(0, 3))),
    _P('rdp_pruebas', 'exposed_rdp', 'alta', 23, True,
       'RDP de un equipo de pruebas', partial(rdp, equipos=EQUIPOS_PRUEBAS, primera=(10, 300), ultima=(0, 5))),
    _P('rdp_sin_ver_6_meses', 'exposed_rdp', 'media', 13, False,
       'RDP que no se ve desde hace más de 6 meses',
       partial(rdp, equipos=EQUIPOS_PRODUCCION + EQUIPOS_PRUEBAS, primera=(300, 900), ultima=(190, 290))),
    _P('vencido_sitio_de_acceso', 'cert_expired', 'alta', 23, False,
       'Sitio de inicio de sesión con el certificado vencido hace menos de 30 días',
       partial(certificado, codigo='cert_expired', usos=(('inicio_de_sesion', HOSTS_ACCESO),), vidas=(90,),
               dias=(3, 29))),
    _P('vencido_api_o_correo', 'cert_expired', 'media', 13, True,
       'API o correo con el certificado vencido hace 5 a 200 días',
       partial(certificado, codigo='cert_expired', usos=API_O_CORREO, vidas=(90, 365), dias=(5, 200))),
    _P('vencido_sin_contenido', 'cert_expired', 'baja', 16, False,
       'Subdominio que resuelve sin contenido, con el certificado vencido hace más de 6 meses',
       partial(certificado, codigo='cert_expired', usos=(('sin_contenido', HOSTS_SIN_CONTENIDO),), vidas=(90, 365),
               dias=(185, 360))),
    _P('por_vencer_sitio_principal', 'cert_expiring_soon', 'media', 13, False,
       'Sitio principal con certificado de 90 días y menos de 7 para vencer',
       partial(certificado, codigo='cert_expiring_soon', usos=(('sitio_publico', ('www',)),), vidas=(90,),
               dias=(1, 6))),
    _P('por_vencer_api_o_correo', 'cert_expiring_soon', 'media', 13, True,
       'API o correo con certificado de 90 días y 8 a 20 para vencer',
       partial(certificado, codigo='cert_expiring_soon', usos=API_O_CORREO, vidas=(90,), dias=(8, 20))),
    _P('por_vencer_sitio_secundario', 'cert_expiring_soon', 'baja', 16, False,
       'Sitio secundario con certificado de un año y 20 a 29 días para vencer',
       partial(certificado, codigo='cert_expiring_soon', usos=(('sitio_publico', HOSTS_SECUNDARIOS),), vidas=(365,),
               dias=(20, 29))),
    _P('dmarc_con_mx', 'dmarc_missing', 'media', 13, False,
       'Dominio con MX y SPF que manda correo, visto por primera vez hace 1 a 500 días',
       partial(dmarc, perfiles=('mx_spf',), primera=(1, 500))),
    _P('dmarc_sin_mx', 'dmarc_missing', 'baja', 16, False,
       'Dominio sin MX, con un SPF que no autoriza a nadie a enviar (v=spf1 -all)',
       partial(dmarc, perfiles=('sin_mx_spf_nulo',), primera=(5, 300))),
    _P('dmarc_subdominio_campanas', 'dmarc_missing', 'media', 13, True,
       'Subdominio de campañas con MX de un proveedor de envíos',
       partial(dmarc, perfiles=SIN_DMARC, primera=(5, 300), campanas=True)),
    _P('spf_sin_mx', 'spf_missing', 'baja', 24, False,
       'Dominio sin MX, con DMARC p=reject', partial(spf, perfil='sin_mx_reject', primera=(5, 300))),
    _P('spf_con_mx_y_dmarc_reject', 'spf_missing', 'baja', 24, True,
       'Dominio con MX y DMARC p=reject', partial(spf, perfil='mx_reject', primera=(5, 300))),
    _P('spf_con_mx_sin_dmarc', 'spf_missing', 'media', 24, False,
       'Dominio con MX y sin DMARC, visto por primera vez hace 1 a 400 días',
       partial(spf, perfil='mx_sin_spf', primera=(1, 400))),
    _P('parecido_reciente_login_o_pago', 'lookalike_domain', 'media', 13, False,
       'Parecido con la marca y login, pagos, acceso o cuenta, con su primer certificado de hace menos de 30 días',
       partial(parecido, tipo='contiene_marca', primero=(2, 29), certificados=(1, 3))),
    _P('parecido_viejo', 'lookalike_domain', 'baja', 15, False,
       'Error tipográfico con certificados desde hace más de un año, el último vencido hace 20 a 85 días',
       partial(parecido, tipo='error_tipografico', primero=(400, 1500), certificados=(4, 15), vencido=(20, 85))),
    _P('parecido_otro_tld', 'lookalike_domain', 'baja', 15, True,
       'La marca con otro TLD, sin nombres sospechosos, primer certificado de hace 10 a 800 días',
       partial(parecido, tipo='otro_tld', primero=(10, 800), certificados=(1, 8))),
)
POR_ID = {p.id: p for p in PLANTILLAS}
