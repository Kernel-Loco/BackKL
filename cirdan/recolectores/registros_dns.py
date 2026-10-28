"""Recolector de registros DNS con SPF y DMARC (#15, RC-48).

Consulta al resolvedor público, sin tocar los servidores del dominio, los registros A, AAAA, MX, NS y TXT del
dominio autorizado y el TXT de _dmarc.<dominio>, y devuelve:
- activos: el dominio con todo su DNS en los atributos 'dns', un activo ip por cada A y AAAA, y un activo
  subdomain por cada MX y NS que está dentro del dominio. Un MX o NS de un tercero, como los de Cloudflare, solo
  queda en los atributos 'dns' del dominio, porque el filtro de alcance lo descartaría. No hay un tipo de activo
  para un registro DNS, así que MX, NS y TXT viven en esos atributos, como en la semilla de acme-demo.mx.
  Cada activo ip lleva su país, ASN y proveedor de la base local de DB-IP Lite (geoip.ubicar, #15b, RC-166), con
  fuente_geo y base_geo, y 'cdn' si su ASN es de un CDN o un proxy inverso (geoip.cdn_por_asn). Eso no consulta la
  red ni se graba: al reproducir sale de la base del momento. Sin la base, esos datos quedan 'No disponible' con un
  aviso (geoip.aviso_sin_base), una vez por corrida y solo si hubo alguna IP ubicable. La fuente no falla por eso.
- hallazgos de configuración: spf_missing, spf_allow_all, dmarc_missing y dmarc_policy_none.
Hasta que #23 (RC-55) guarde activos y hallazgos, nada de esto se escribe en assets ni en findings: activos y
hallazgos quedan en el Resultado, y scan_source_runs solo guarda sus conteos, avisos y sin_cobertura.

Reglas de SPF, sobre los TXT de la raíz que empiezan con v=spf1 (RFC 7208, 4.5: sin distinguir mayúsculas, sin recortar
el texto y seguido de un espacio o del fin, así que con un espacio antes o un tabulador después no es SPF):
- ninguno, o más de uno: spf_missing, porque con dos ninguno vale.
- +all o all sin calificador: spf_allow_all.
- ?all, o sin all ni redirect=: spf_missing, porque el resultado por omisión es neutral (RFC 7208, 4.7).
- redirect= sin all: ningún hallazgo y un aviso, porque no se sigue el redirect.
- -all o ~all: nada.
Reglas de DMARC, sobre los TXT de _dmarc.<dominio> que empiezan con la versión de RFC 7489, 6.4: la v sin distinguir
mayúsculas, espacios o tabuladores opcionales alrededor del igual, DMARC1 exacto en mayúsculas y después punto y coma,
espacio, tabulador o el fin. Un v=dmarc1 en minúsculas no es DMARC: cuenta como otro TXT. Los nombres de etiqueta (p, sp,
rua) y los valores de política no distinguen mayúsculas.
- ninguno, o más de uno: dmarc_missing.
- p=none: dmarc_policy_none. p=quarantine o p=reject: nada.
- p ausente, p no válido o sp no válido (RFC 7489, 6.6.3 paso 6): si rua trae al menos un URI con esquema (esquema:resto en
  alguna de sus partes separadas por coma), el receptor lo toma como p=none y es dmarc_policy_none. Si no, lo ignora y es
  dmarc_missing.
sp=none y pct menor a 100 no generan hallazgo, porque no están en el catálogo de reglas (#30).

Una falla del DNS no es un «no hay». NXDOMAIN y NoAnswer quieren decir que no hay registro y cuentan para los
hallazgos. Un tiempo agotado, un SERVFAIL u otra falla (ConsultaFallida) deja ese tipo sin saber: se avisa, y si es
el TXT de la raíz o el de _dmarc sus códigos quedan en sin_cobertura y no sale ningún hallazgo de ese registro. Si
fallan las 6 consultas, la fuente se cae con FuenteNoResponde para que el orquestador la reintente. Si la raíz no
existe (NXDOMAIN), no hay activos ni hallazgos, solo un aviso, y los 4 códigos quedan en sin_cobertura.

Solo se consulta el dominio raíz y _dmarc.<dominio>, con consultas DNS normales a 1.1.1.1 y 8.8.8.8 (carta de
autorización, Anexo A, actividad 2). Sin transferencias de zona, sin preguntar a los servidores autoritativos y sin
adivinar nombres. Los subdominios de otras fuentes no se resuelven: eso necesita pasar datos entre fuentes (#23).

Ni la evidencia ni las grabaciones guardan tokens: de un TXT que no sea SPF ni DMARC solo se guarda su prefijo (lo
anterior al primer '=', u 'otro' si no tiene) y cuántos hay, nunca su valor, tampoco el de cirdan-verification.

Modos: 'vivo' consulta el DNS, 'grabar' además guarda cada respuesta ya limpia en
cirdan/recolectores/respuestas_grabadas/dns/<dominio>/ y 'reproducir' solo lee esas respuestas, sin red (pruebas y
respaldo de las demos). dnspython se importa solo al consultar de verdad (_consultar), así el módulo carga y se
prueba en una PC que no lo tiene.

    python -m cirdan.recolectores.registros_dns olmardo.com
    python -m cirdan.recolectores.registros_dns olmardo.com --grabar
    python -m cirdan.recolectores.registros_dns olmardo.com --reproducir
    python -m cirdan.recolectores.registros_dns olmardo.com --json

olmardo.com es el dominio de prueba del equipo. Solo se consulta en vivo un dominio con carta de autorización
vigente, nunca uno de terceros, y --grabar solo con el dominio de prueba. Código de salida: 0 bien, 1 si el
resultado queda en 'failed', 2 si quedan avisos.
"""
import argparse
import hashlib
import ipaddress
import json
import re
import sys
import time
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path

from cirdan.ml import caracteristicas as rubrica
from cirdan.recolectores import geoip
from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import (NOMBRE_VALIDO, SIN_GRABACION, Activo, FuenteNoResponde, Grabadora,
                                          Hallazgo, Resultado, SinGrabacion, con_reintentos, nombre_archivo)

FUENTE = 'dns'
CARPETA_GRABADAS = RAIZ_GRABADAS / 'dns'

RESOLVEDORES = ('1.1.1.1', '8.8.8.8')   # públicos y fijos, como orquestador/txt.py. Nunca el DNS del sistema
TIMEOUT_S = 5.0                         # tiempo total de una consulta, con sus dos resolvedores
INTENTOS = 3                            # intentos por consulta dentro de una corrida (no es scan_source_runs.attempt)
ESPERAS = (5, 15)                       # segundos entre intentos
DMARC = '_dmarc.'                       # prefijo del nombre donde se publica el DMARC
# (tipo, prefijo del nombre). Cada corrida hace estas 6 consultas y ninguna más
CONSULTAS = (('A', ''), ('AAAA', ''), ('MX', ''), ('NS', ''), ('TXT', ''), ('TXT', DMARC))
MAX_CONSULTAS = len(CONSULTAS) * INTENTOS   # peor caso de una corrida, con todos los reintentos. Resultado.consultas no lo pasa
ESTADOS = ('ok', 'vacio', 'nxdomain')       # ok: hay registros. vacio: el nombre existe sin ese tipo. nxdomain: no existe
POLITICAS = ('none', 'quarantine', 'reject')

# Código de regla -> severidad base. Los cuatro deben existir en el catálogo de reglas (#30).
CODIGOS = {'spf_missing': 'low', 'spf_allow_all': 'medium', 'dmarc_missing': 'medium', 'dmarc_policy_none': 'medium'}
MX_SIN_SABER = ('(no se supo)',)           # solo para la rúbrica del ML: un MX que no se supo nunca baja la sensibilidad
SIN_COBERTURA_SPF = ('spf_missing', 'spf_allow_all')
SIN_COBERTURA_DMARC = ('dmarc_missing', 'dmarc_policy_none')
# El título del hallazgo es propio, no el de la regla (docs/contrato_api_v1.md), con la forma '<hecho> en <dominio>' de crt.sh,
# en lenguaje simple y sin siglas (docs/contrato_plugin.md) y con el vocabulario del catálogo (003_textos_reglas.sql).
TITULOS = {
    'spf_missing': 'Sin lista válida de servidores de correo en %s',
    'spf_allow_all': 'La lista de servidores de correo de %s acepta a cualquiera',
    'dmarc_missing': 'Sin regla contra correos falsos en %s',
    'dmarc_policy_none': 'La regla contra correos falsos de %s solo observa',
}

ES_SPF = re.compile(r'v=spf1( |\Z)', re.IGNORECASE)   # RFC 7208, 4.5: sobre el texto sin recortar, seguido de un espacio o del fin
ES_DMARC = re.compile(r'[vV][ \t]*=[ \t]*DMARC1(?=[ \t;]|\Z)')   # RFC 7489, 6.4: v sin distinguir mayúsculas, DMARC1 exacto
URI_RUA = re.compile(r'[A-Za-z][A-Za-z0-9+.-]*:.+')   # esquema:resto, una parte de rua separada por comas
TERMINO_ALL = re.compile(r'([+\-~?]?)all')
PREFIJO_VALIDO = re.compile(r'[A-Za-z][A-Za-z0-9._-]{0,47}')   # lo que puede ser el nombre de un TXT, no un valor
CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')               # Postgres no acepta el nulo y el resto no es de un registro

# Solo para lo que se imprime: los datos conservan los códigos de la base (medium, low).
SEVERIDAD_ES = {'critical': 'crítica', 'high': 'alta', 'medium': 'media', 'low': 'baja'}
EXPOSICION_ES = {'publica': 'pública', 'directa': 'directa'}
CODIGO_ES = {'spf_missing': 'SPF válido', 'spf_allow_all': 'SPF que no acepta a todos',
             'dmarc_missing': 'DMARC válido', 'dmarc_policy_none': 'política DMARC'}
MESES = ('ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic')

Veredicto = namedtuple('Veredicto', 'codigo observado aviso')   # codigo None: ningún hallazgo


class ConsultaFallida(Exception):
    """El DNS no dio respuesta (tiempo agotado, SERVFAIL, ningún servidor contestó): no se sabe si el registro existe."""


# ---------------------------------------------------------------- consulta al DNS

def _valor(tipo, r):
    """El valor de un registro de dnspython. Los TXT llegan unidos: las cadenas partidas de un TXT largo van sin separador."""
    if tipo in ('A', 'AAAA'):
        return r.address
    if tipo == 'MX':
        return r.preference, r.exchange.to_text()
    if tipo == 'NS':
        return r.target.to_text()
    return b''.join(r.strings).decode('ascii', 'replace')


def _consultar(nombre, tipo):
    """La única función que usa dnspython y habla con el resolvedor.

    Devuelve ('ok', valores), ('vacio', []) si el nombre existe pero no tiene registros de ese tipo (NoAnswer) o
    ('nxdomain', []) si el nombre no existe. Cualquier otra falla de DNS lanza ConsultaFallida. dnspython se importa
    aquí y no al cargar el módulo, porque la PC de desarrollo no lo tiene (está en requirements.txt y en la imagen)."""
    import dns.exception
    import dns.resolver
    resolvedor = dns.resolver.Resolver(configure=False)   # nunca el DNS del sistema ni del contenedor
    resolvedor.nameservers = list(RESOLVEDORES)
    resolvedor.lifetime = TIMEOUT_S
    try:
        respuesta = resolvedor.resolve(nombre, tipo)
    except dns.resolver.NXDOMAIN:
        return 'nxdomain', []
    except dns.resolver.NoAnswer:
        return 'vacio', []
    except dns.exception.DNSException as e:
        raise ConsultaFallida('%s: %s' % (type(e).__name__, e)) from None
    return 'ok', [_valor(tipo, r) for r in respuesta]


# ---------------------------------------------------------------- limpieza de lo que se guarda

def _host(texto):
    """El nombre de un MX o NS en minúsculas y sin el punto final. La raíz (el MX nulo, RFC 7505) es '.'."""
    host = str(texto).strip().lower().rstrip('.')
    return host or '.'


def _prefijo(texto):
    """Lo anterior al primer '=' de un TXT, u 'otro'. Un valor que termina en '=' (relleno de base64) o que no parece el nombre
    de un registro es 'otro': nunca se guarda un token por llamarse prefijo."""
    clave, igual, resto = texto.partition('=')
    return clave if igual and resto.strip('=') and PREFIJO_VALIDO.fullmatch(clave) else 'otro'


def _limpiar_txt(valores, es_registro):
    """{'registros': los TXT completos que son SPF (o DMARC), 'otros': {prefijo: cuántos}}. Del resto no se guarda nada más."""
    registros, otros = [], {}
    for valor in valores:
        texto = CONTROL.sub('�', str(valor))   # sin recortar: SPF y DMARC se reconocen por el texto tal como llegó
        if es_registro.match(texto):
            registros.append(texto.strip())
        else:
            prefijo = _prefijo(texto.strip())
            otros[prefijo] = otros.get(prefijo, 0) + 1
    return {'registros': sorted(registros), 'otros': dict(sorted(otros.items()))}


def _limpiar(tipo, nombre, valores):
    """Lo que se analiza y se graba de una respuesta: ordenado, sin repetidos, sin tokens y listo para JSON."""
    if tipo in ('A', 'AAAA'):
        version, direcciones = (4 if tipo == 'A' else 6), set()
        for valor in valores:
            try:
                direccion = ipaddress.ip_address(str(valor).strip())
            except ValueError:
                continue
            if direccion.version == version:
                direcciones.add(direccion)
        return [str(d) for d in sorted(direcciones)]
    if tipo == 'MX':
        return [{'prioridad': p, 'host': h} for p, h in sorted({(int(p), _host(h)) for p, h in valores})]
    if tipo == 'NS':
        return sorted({_host(v) for v in valores})
    return _limpiar_txt(valores, ES_DMARC if nombre.startswith(DMARC) else ES_SPF)


# ---------------------------------------------------------------- cliente, grabación y reproducción

def _nombre_grabado(consulta):
    """a_acme.mx.json, aaaa_acme.mx.json, mx_..., ns_..., txt_acme.mx.json y dmarc_acme.mx.json para txt:_dmarc.acme.mx.
    El _dmarc lleva su propio nombre, así no se confunde con el TXT de la raíz."""
    tipo, _, nombre = consulta.lower().partition(':')
    if tipo == 'txt' and nombre.startswith(DMARC):
        return nombre_archivo('dmarc:' + nombre[len(DMARC):])
    return nombre_archivo(consulta)


def _texto(x):
    return isinstance(x, str)


def _ip(x, version):
    try:
        return _texto(x) and ipaddress.ip_address(x).version == version
    except ValueError:
        return False


def _entero(x):
    return isinstance(x, int) and not isinstance(x, bool)


def _forma_valida(tipo, valores):
    """True si `valores` tiene la forma que graba el cliente para ese tipo (la que deja _limpiar)."""
    if tipo == 'TXT':
        return (isinstance(valores, dict) and isinstance(valores.get('registros'), list)
                and all(map(_texto, valores['registros'])) and isinstance(valores.get('otros'), dict)
                and all(_texto(k) and _entero(n) and n >= 0 for k, n in valores['otros'].items()))
    if not isinstance(valores, list):
        return False
    if tipo == 'MX':
        return all(isinstance(m, dict) and _texto(m.get('host')) and _entero(m.get('prioridad')) for m in valores)
    if tipo in ('A', 'AAAA'):
        return all(_ip(x, 4 if tipo == 'A' else 6) for x in valores)
    return all(map(_texto, valores))   # NS: una lista de textos


def _leer_grabado(tipo, datos):
    """(estado, valores) de una respuesta grabada. Lanza ValueError si el archivo no tiene la forma que graba el cliente. El
    que consulta la toma como una respuesta que no se supo, nunca como «no hay»."""
    if not isinstance(datos, dict) or datos.get('estado') not in ESTADOS or not _forma_valida(tipo, datos.get('valores')):
        raise ValueError('forma inesperada')
    return datos['estado'], datos['valores']


class ClienteDns:
    """Hace las consultas con reintentos y, según el modo, graba o reproduce las respuestas ya limpias con la Grabadora del
    contrato (#13)."""

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, resolver=None, dormir=None, reloj=None, nueva=False):
        """`resolver(nombre, tipo)` hace la consulta y devuelve lo mismo que _consultar. Si no se pasa, se usa _consultar,
        buscado en el módulo en cada consulta, así una prueba lo puede cambiar con mock.patch.object.
        `nueva` (solo al grabar) vacía la carpeta y escribe la marca de inicio con la primera respuesta que se supo: si
        ninguna llega, la grabación anterior queda intacta."""
        self.modo, self.carpeta = modo, Path(carpeta)
        self.grabadora = Grabadora(carpeta, modo, nueva=nueva, reloj=reloj, nombre=_nombre_grabado)
        self.resolver = resolver
        self.dormir = dormir or time.sleep
        self.consultas = 0      # cada intento de cada consulta, hasta MAX_CONSULTAS

    @property
    def leidas(self):
        """(archivo, fecha de grabación) de cada respuesta tomada del disco."""
        return self.grabadora.leidas

    def consultar(self, nombre, tipo):
        """(estado, valores) ya limpios. Lanza FuenteNoResponde si el DNS no respondió después de los intentos, y SinGrabacion
        (que es una) si al reproducir la grabación no trae esa consulta. Solo se graba lo que se supo: una consulta que
        falló no se graba, y una respuesta vieja de ella no pasa por la de hoy."""
        consulta = '%s:%s' % (tipo.lower(), nombre)
        try:
            del_disco, datos = self.grabadora.de_disco(consulta)
            if del_disco:
                return _leer_grabado(tipo, datos)
        except SinGrabacion:
            raise
        except (ValueError, KeyError, TypeError, AttributeError, OSError, RecursionError) as e:   # un archivo roto no tumba la fuente
            raise FuenteNoResponde('la grabación de %s no se puede leer (%s: %s)' % (consulta, type(e).__name__, e)) from None

        def intento():
            self.consultas += 1
            return (self.resolver or _consultar)(nombre, tipo)
        intento.__name__ = 'El DNS no respondió a %s de %s' % (tipo, nombre)
        try:
            estado, crudo = con_reintentos(intento, intentos=INTENTOS, esperas=ESPERAS, errores=(ConsultaFallida,),
                                           dormir=self.dormir)
        except FuenteNoResponde:
            self.grabadora.descartar(consulta)
            raise
        valores = _limpiar(tipo, nombre, crudo)
        self.grabadora.guardar(consulta, {'estado': estado, 'valores': valores})   # fuera del try: un error del disco no es del DNS
        return estado, valores


# ---------------------------------------------------------------- reglas de SPF y DMARC

def analizar_spf(registros):
    """Veredicto sobre los TXT v=spf1 de la raíz (decisión de cada caso en el docstring del módulo)."""
    if not registros:
        return Veredicto('spf_missing', 'sin TXT v=spf1', None)
    if len(registros) > 1:
        return Veredicto('spf_missing', 'hay %d registros v=spf1 y con más de uno ninguno vale' % len(registros), None)
    terminos = registros[0].lower().split()[1:]
    calificador = next((m.group(1) for m in map(TERMINO_ALL.fullmatch, terminos) if m), None)
    if calificador is None:
        if any(t.startswith('redirect=') for t in terminos):
            return Veredicto(None, 'usa redirect= y no tiene all', 'El SPF usa redirect= y no se evaluó adónde apunta')
        return Veredicto('spf_missing', 'sin all ni redirect=, el resultado por omisión es neutral', None)
    if calificador in ('', '+'):
        return Veredicto('spf_allow_all', 'usa +all' if calificador else 'usa all sin calificador', None)
    if calificador == '?':
        return Veredicto('spf_missing', 'termina en ?all, el resultado es neutral', None)
    return Veredicto(None, 'termina en %sall' % calificador, None)


def _etiquetas_dmarc(registro):
    """Las etiquetas de un registro DMARC en minúsculas. Si una se repite vale la primera."""
    etiquetas = {}
    for parte in registro.split(';'):
        clave, igual, valor = parte.partition('=')
        clave = clave.strip().lower()
        if igual and clave and clave not in etiquetas:
            etiquetas[clave] = valor.strip().lower()
    return etiquetas


def _tiene_uri(rua):
    """True si alguna parte de rua (separadas por coma) tiene la forma esquema:resto."""
    return any(URI_RUA.fullmatch(parte.strip()) for parte in rua.split(','))


def _politica(registro):
    """(política, observado) de un solo registro DMARC. La política es la que aplica un receptor: 'none', 'quarantine' o
    'reject', o None si lo ignora. Con un p ausente o no válido, o un sp no válido, RFC 7489 6.6.3 paso 6 dice que el
    receptor lo toma como p=none si rua trae al menos un URI con esquema, y si no lo ignora."""
    etiquetas = _etiquetas_dmarc(registro)
    p, sp = etiquetas.get('p'), etiquetas.get('sp')
    if p in POLITICAS and (sp is None or sp in POLITICAS):
        return p, 'p=' + p
    motivo = 'sin p' if p is None else 'p no válido' if p not in POLITICAS else 'sp no válido'
    if _tiene_uri(etiquetas.get('rua', '')):
        return 'none', '%s y con rua, se toma como p=none' % motivo
    return None, '%s y sin rua con URI, el receptor lo ignora' % motivo


def politica_dmarc(registros):
    """'p=reject' (o p=none, p=quarantine) si hay un solo DMARC que un receptor aplica, y None si no."""
    if len(registros) == 1:
        politica, _ = _politica(registros[0])
        if politica:
            return 'p=' + politica
    return None


def analizar_dmarc(registros, estado='ok'):
    """Veredicto sobre los TXT v=DMARC1 de _dmarc.<dominio>. `estado` solo cambia el texto de lo observado cuando no hay ninguno."""
    if not registros:
        return Veredicto('dmarc_missing', 'NXDOMAIN' if estado == 'nxdomain' else 'sin TXT v=DMARC1', None)
    if len(registros) > 1:
        return Veredicto('dmarc_missing', 'hay %d registros v=DMARC1 y con más de uno se ignoran' % len(registros), None)
    politica, observado = _politica(registros[0])
    if politica is None:
        return Veredicto('dmarc_missing', observado, None)
    return Veredicto('dmarc_policy_none' if politica == 'none' else None, observado, None)


# ---------------------------------------------------------------- activos y hallazgos

def _huella(*partes):
    """No lleva lo observado, así el hallazgo no se duplica entre escaneos aunque el registro cambie."""
    return hashlib.sha256('|'.join((FUENTE,) + partes).encode('utf-8')).hexdigest()


def _normalizado(registro):
    return ' '.join(registro.split()).lower()


def _activos_ip(dominio, raiz):
    """(activos, aviso): un activo ip por cada A y AAAA de la raíz, con su ubicación (geoip.ubicar) y 'cdn' si su ASN es
    de un CDN, y el aviso de base faltante o None. `host` es el dominio, para el filtro de alcance. Las bases se piden
    una sola vez por corrida, y solo si alguna IP es ubicable: con solo 10.0.0.1 no se buscaría nada y el aviso de base
    faltante no diría nada cierto. Las demás igual llevan sus atributos de geo, con 'No disponible' (geoip.ubicar no
    pide las bases para una IP que no es ubicable)."""
    ips = [(tipo.lower(), ip) for tipo in ('A', 'AAAA') for ip in raiz.get(tipo, (None, []))[1]]
    bases = geoip.bases_por_omision() if any(geoip.ubicable(ip) for _, ip in ips) else None
    activos = []
    for origen, ip in ips:
        atributos = dict({'host': dominio, 'fuente': FUENTE, 'origen': origen}, **geoip.ubicar(ip, bases))
        cdn = geoip.cdn_por_asn(atributos['asn'])
        if cdn:
            atributos['cdn'] = cdn
        activos.append(Activo('ip', ip, atributos))
    return activos, None if bases is None else geoip.aviso_sin_base(FUENTE, bases)


def _activos_subdominio(dominio, mx, ns):
    """Un activo subdomain por cada host de MX o NS que está dentro del dominio. El de un tercero y el dominio mismo no son
    activos: quedan en los atributos 'dns'. Si un host es MX y NS, es un solo activo con los dos orígenes."""
    hosts = {}
    for origen, host, prioridad in [('mx', m['host'], m['prioridad']) for m in mx] + [('ns', h, None) for h in ns]:
        if not host.endswith('.' + dominio) or not NOMBRE_VALIDO.fullmatch(host):
            continue
        atributos = hosts.setdefault(host, {'fuente': FUENTE, 'origen': origen, 'origenes': []})
        if origen not in atributos['origenes']:
            atributos['origenes'].append(origen)
        if prioridad is not None:
            atributos['prioridad'] = min(prioridad, atributos.get('prioridad', prioridad))
    return [Activo('subdomain', host, atributos) for host, atributos in sorted(hosts.items())]


def _hallazgo(codigo, dominio, nombre, registros, veredicto, contexto, ahora):
    """El hallazgo de un código sobre el activo domain. La evidencia trae lo que lee la rúbrica del ML
    (cirdan/ml/caracteristicas.py): mx, spf y dmarc. `registro` es el SPF o DMARC observado, o None."""
    titulo = TITULOS[codigo] % dominio
    evidencia = {'title': titulo, 'consulta': nombre, 'registro': registros[0] if len(registros) == 1 else None,
                 'registros': list(registros), 'observado': veredicto.observado, **contexto}
    # La evidencia dice mx None si no se supo, pero la rúbrica da 'baja' solo con la certeza de que no hay MX: sin saberlo
    # se calcula como si hubiera correo, que es lo conservador.
    para_rubrica = evidencia if evidencia['mx'] is not None else {**evidencia, 'mx': list(MX_SIN_SABER)}
    return Hallazgo(codigo, CODIGOS[codigo], dominio, titulo, evidencia,
                    rubrica.calcular(codigo, 'domain', para_rubrica, ahora), _huella(codigo, dominio))


# ---------------------------------------------------------------- punto de entrada

def recolectar(dominio, cliente=None, ahora=None, propios=()):
    """Recolecta los registros DNS de `dominio` y revisa su SPF y su DMARC.

    Hace las 6 consultas de CONSULTAS. Lanza FuenteNoResponde (o SinGrabacion, al reproducir sin grabación) si ninguna
    respondió, para que contrato.ejecutar() deje la fuente en 'failed' y el orquestador la reintente."""
    dominio = dominio.strip().lower().rstrip('.')
    cliente = cliente or ClienteDns()
    ahora = ahora or datetime.now(timezone.utc)
    res = Resultado(dominio, FUENTE)
    if not NOMBRE_VALIDO.fullmatch(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res

    respuestas, fallas = {}, []
    for tipo, prefijo in CONSULTAS:
        try:
            respuestas[(tipo, prefijo)] = cliente.consultar(prefijo + dominio, tipo)
        except FuenteNoResponde as e:
            fallas.append(e)
    res.consultas = cliente.consultas
    if len(fallas) == len(CONSULTAS):
        if all(isinstance(e, SinGrabacion) for e in fallas):
            raise fallas[0]
        raise FuenteNoResponde('el DNS no respondió a ninguna consulta de %s. %s' % (dominio, ' '.join(str(e) for e in fallas)))
    res.avisos += [str(e) for e in fallas]

    raiz = {tipo: respuestas[(tipo, '')] for tipo, prefijo in CONSULTAS if prefijo == '' and (tipo, '') in respuestas}
    if raiz and all(estado == 'nxdomain' for estado, _ in raiz.values()):
        res.avisos.append('%s no existe en el DNS (NXDOMAIN). No se revisaron sus registros, su SPF ni su DMARC' % dominio)
        res.sin_cobertura = list(CODIGOS)
        return res

    # Los atributos 'dns' del dominio solo traen los tipos que se supieron. Una lista vacía quiere decir que no hay.
    dns = {clave: raiz[tipo][1] for tipo, clave in (('A', 'a'), ('AAAA', 'aaaa'), ('MX', 'mx'), ('NS', 'ns')) if tipo in raiz}
    txt_raiz, txt_dmarc = respuestas.get(('TXT', '')), respuestas.get(('TXT', DMARC))
    if txt_raiz:
        dns['spf'], dns['txt_otros'] = txt_raiz[1]['registros'], txt_raiz[1]['otros']
    if txt_dmarc:
        dns['dmarc'] = txt_dmarc[1]['registros']
    activos_ip, aviso_geo = _activos_ip(dominio, raiz)
    if aviso_geo:
        res.avisos.append(aviso_geo)
    res.activos = [Activo('domain', dominio, {'dns': dns})] + activos_ip + \
        _activos_subdominio(dominio, dns.get('mx', []), dns.get('ns', []))

    # Contexto de la rúbrica: los MX que reciben correo (el MX nulo '.' no), el único SPF y la política del único DMARC.
    contexto = {'mx': [m['host'] for m in dns['mx'] if m['host'] != '.'] if 'mx' in dns else None,
                'spf': _normalizado(dns['spf'][0]) if len(dns.get('spf', [])) == 1 else None,
                'dmarc': politica_dmarc(dns['dmarc']) if 'dmarc' in dns else None}
    if txt_raiz:
        veredicto = analizar_spf(dns['spf'])
        if veredicto.aviso:
            res.avisos.append(veredicto.aviso)
        if veredicto.codigo:
            res.hallazgos.append(_hallazgo(veredicto.codigo, dominio, dominio, dns['spf'], veredicto, contexto, ahora))
    else:
        res.sin_cobertura += SIN_COBERTURA_SPF
    if txt_dmarc:
        veredicto = analizar_dmarc(dns['dmarc'], txt_dmarc[0])
        if veredicto.codigo:
            res.hallazgos.append(_hallazgo(veredicto.codigo, dominio, DMARC + dominio, dns['dmarc'], veredicto, contexto, ahora))
    else:
        res.sin_cobertura += SIN_COBERTURA_DMARC
    return res


# ---------------------------------------------------------------- salida para personas

def _dia(fecha):
    return '%d %s %d' % (fecha.day, MESES[fecha.month - 1], fecha.year)


def _zona(fecha):
    """'UTC' o el desfase de una fecha con zona, como 'UTC-06:00'. Dentro del contenedor de la API la hora local es UTC."""
    z = fecha.strftime('%z')
    return 'UTC' if z in ('', '+0000') else 'UTC%s:%s' % (z[:3], z[3:5])


def _cuantos(n, singular, plural):
    return '%d %s' % (n, singular if n == 1 else plural)


def resumen(res, cliente=None, maximo_activos=20):
    """Líneas en español para leer el resultado en una terminal o en una demo."""
    cabecera = '%s · DNS público (%s) · %s' % (res.dominio, ' y '.join(RESOLVEDORES), res.estado)
    leidas = cliente.leidas if cliente else []
    if cliente and cliente.modo == 'reproducir':
        if leidas:
            grabado = min(f for _, f in leidas).astimezone()
            cabecera += ' · sin red, respuestas grabadas el %s a las %s (%s)' % (
                _dia(grabado), grabado.strftime('%H:%M'), _zona(grabado))
        else:
            cabecera += ' · sin red'
    else:
        cabecera += ' · %s' % _cuantos(res.consultas, 'consulta', 'consultas')
        if leidas:
            cabecera += ' y %s de la grabación' % _cuantos(len(leidas), 'respuesta', 'respuestas')
    lineas = [cabecera]
    if res.error:
        lineas.append('error: %s' % res.error)

    if res.activos:
        lineas.append(_cuantos(len(res.activos), 'activo:', 'activos:'))
        for a in res.activos[:maximo_activos]:
            if a.tipo == 'domain':
                dns = a.atributos.get('dns', {})
                conteo = ['%s %s' % (nombre.upper(), len(dns[clave])) for nombre, clave in (
                    ('A', 'a'), ('AAAA', 'aaaa'), ('MX', 'mx'), ('NS', 'ns'), ('SPF', 'spf'), ('DMARC', 'dmarc')) if clave in dns]
                lineas.append('  %s · %s' % (a.valor, ' · '.join(conteo)))
            else:
                lineas.append('  %s · %s · %s' % (a.valor, a.tipo, a.atributos.get('origen', '')))
        if len(res.activos) > maximo_activos:
            lineas.append('  y %d más (--json para verlos todos)' % (len(res.activos) - maximo_activos))

    if res.hallazgos:
        lineas.append(_cuantos(len(res.hallazgos), 'hallazgo:', 'hallazgos:'))
        for h in res.hallazgos:
            c = h.caracteristicas
            lineas.append('  [%s] %s' % (SEVERIDAD_ES.get(h.severidad, h.severidad), h.titulo))
            lineas.append('      tipo: %s · antigüedad: %s · exposición: %s · sensibilidad: %s' % (
                c['tipo'].replace('_', ' '), _cuantos(c['antiguedad_dias'], 'día', 'días'),
                EXPOSICION_ES.get(c['exposicion'], c['exposicion']), c['sensibilidad']))
            lineas.append('      observado: %s' % h.evidencia['observado'])
    elif res.estado == 'succeeded':
        lineas.append('Sin hallazgos.')
    if res.sin_cobertura:  # no es lo mismo que 0 hallazgos
        nombres = ['%s (%s)' % (CODIGO_ES.get(c, c), c) for c in res.sin_cobertura]
        lineas.append('Cobertura parcial: no se revisaron %s.' % (
            nombres[0] if len(nombres) == 1 else ', '.join(nombres[:-1]) + ' ni ' + nombres[-1]))

    faltan = [a[len(SIN_GRABACION):] for a in res.avisos if a.startswith(SIN_GRABACION)]
    if faltan:
        uno = len(faltan) == 1
        lineas.append('%s %s: %s. Se vuelve a grabar con --grabar.' % (
            'Falta' if uno else 'Faltan', _cuantos(len(faltan), 'respuesta grabada', 'respuestas grabadas'), ', '.join(faltan)))
    lineas += ['aviso: %s' % a for a in res.avisos if not a.startswith(SIN_GRABACION)]
    return lineas


def carpeta_de(dominio):
    """Carpeta de las respuestas grabadas de un dominio (la usan el CLI y el plugin)."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' consulta el DNS, 'reproducir' usa la grabación del dominio y 'grabar'
    empieza una grabación nueva, igual que --grabar."""
    return ClienteDns(modo=modo, carpeta=carpeta_de(dominio), nueva=(modo == 'grabar'))


def codigo_salida(res):
    """0 bien, 1 si el resultado queda en 'failed', 2 si quedan avisos (cada código sin cobertura trae el suyo)."""
    return 1 if res.estado == 'failed' else 2 if res.avisos else 0


def _main(argv=None):
    # En Windows, cuando la salida no es la consola (Git Bash, una tubería), Python usa cp1252 y los acentos se rompen.
    if (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    p = argparse.ArgumentParser(description='Registros A, AAAA, MX, NS y TXT de un dominio, con su SPF y su DMARC, desde el DNS público')
    p.add_argument('dominio')
    modo = p.add_mutually_exclusive_group()
    modo.add_argument('--grabar', action='store_true',
                      help='empieza una grabación nueva en cirdan/recolectores/respuestas_grabadas/dns/<dominio>/')
    modo.add_argument('--reproducir', action='store_true', help='usa solo las respuestas grabadas, sin red')
    p.add_argument('--json', action='store_true', help='imprime el resultado completo en JSON')
    a = p.parse_args(argv)
    dominio = a.dominio.strip().lower().rstrip('.')
    if not NOMBRE_VALIDO.fullmatch(dominio):  # también evita que '..' o '/' saquen la carpeta de respuestas_grabadas
        p.error('dominio inválido: %s' % a.dominio)
    cliente = ClienteDns(modo='grabar' if a.grabar else 'reproducir' if a.reproducir else 'vivo',
                         carpeta=carpeta_de(dominio), nueva=a.grabar)
    try:
        res = recolectar(dominio, cliente)
    except FuenteNoResponde as e:
        res = Resultado(dominio, FUENTE, estado='failed', consultas=cliente.consultas, error=str(e))
    if a.json:
        print(json.dumps(res.a_dict(), ensure_ascii=False, indent=1))
    else:
        print('\n'.join(resumen(res, cliente)))
    return codigo_salida(res)


if __name__ == '__main__':
    sys.exit(_main())
