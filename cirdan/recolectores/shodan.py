"""Servicios expuestos y vulnerabilidades conocidas con Shodan InternetDB (#17, RC-49).

InternetDB (https://internetdb.shodan.io/<ip>) da, sin llave, lo que Shodan ya vio de una IP: puertos abiertos,
CPE, tags, nombres y CVE. Nunca se le pide a Shodan que escanee nada y no se toca ningún servidor del dominio. El
contrato (#13) solo pasa el dominio, así que el recolector arma su lista de IP en tres pasos, todos con fuentes que la
carta ya autoriza (Anexo A, actividades 1, 2 y 5):
1. Nombres: los del dominio en los certificados vigentes de Cert Spotter (certspotter.certificados(), sin cambiarlo),
   sin el '*.' de los comodines, más la raíz. Nunca se adivina un nombre. Hasta MAX_NOMBRES con la raíz.
2. IP: un A de cada nombre con 1.1.1.1 y 8.8.8.8, nunca con el DNS del sistema. Sin AAAA: InternetDB es solo IPv4.
3. Servicios: GET a InternetDB por cada IP pública que no sea de un CDN, hasta MAX_IPS, con PAUSA_INTERNETDB entre una
   y otra.
Los nombres que dan otras fuentes no se usan: eso necesita pasar datos entre fuentes (#23).

CDN (politica_uso_etico.md, punto 5: de una IP de CDN solo se registra que existe). Solo se consultan las IPv4 globales
que no son multicast, reservadas ni de 192.88.99.0/24 (consultable). No se consultan las de los rangos IPv4 de
Cloudflare (RANGOS_CLOUDFLARE) ni las que llegan por una cadena CNAME en la que cualquier nombre, intermedio o final,
termina en un sufijo de SUFIJOS_CDN (CDN y bordes compartidos conocidos). La cadena sale de la misma respuesta del A,
sin consultas extra (_cadena_cname). Quedan como activo ip con su marca y sin consulta. Si aun así InternetDB trae el
tag 'cdn', sus datos se descartan con un aviso. Un CDN distinto, sin CNAME a la vista, no se detecta hasta #15b
(RC-166).

Devuelve:
- un activo ip por IP, con 'hosts' (los nombres que resuelven a ella) e 'internetdb' con puertos, tags, CPE, cuántos
  CVE y los nombres del dominio, o 'sin_datos' con un 404. Solo las IP que InternetDB sí respondió llevan fuente_datos
  'Shodan InternetDB' (atribución),
- un activo service por puerto, '<ip>:<puerto>/<protocolo>', con 'parent' e 'ip_address' = su IP (RC-60 los lee),
- un hallazgo por puerto sobre su activo service, según la familia del puerto:
  - 3389: exposed_rdp (alta).
  - 22, 23, 5900, 5901, 5985 y 5986: exposed_remote_admin (alta).
  - 21, 139, 445, 548, 873 y 2049: exposed_file_sharing (alta).
  - 1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211 y 27017: exposed_database (alta).
  - 80 y 443, y los de correo (25, 110, 143, 465, 587, 993 y 995): activo service sin hallazgo.
  - los industriales (102, 502, 789, 1911, 2404, 4911, 9600, 20000, 44818 y 47808): exposed_service con
    puerto_industrial en la evidencia. exposed_ot_device necesita la API de host de Shodan.
  - cualquier otro, como 8080 o 50000: exposed_service (baja).
- known_vulnerability (media) sobre el activo ip, uno por CVE con la CVE como clave, hasta MAX_CVE por IP (las más
  recientes por año y número, y un aviso con cuántas se omitieron). Cada CVE se normaliza a 'CVE-<año>-<número>' sin
  ceros de más antes de quitar repetidas. Son CVE que Shodan deduce de la versión (deducida_por_version), con las CPE
  de esa IP. KEV y EPSS son de #69 (RC-127).
Los tags solo van a los atributos. 'honeypot' descarta los hallazgos y servicios de esa IP con un aviso. Los nombres de
InternetDB que no son del dominio no se guardan, solo se cuentan (hostnames_ajenos). Si una IP los trae, puede ser un
dato de quien tuvo la IP antes: la evidencia lleva posible_dato_de_otro_dueno y queda un aviso. Sin nombres ajenos esa
marca no sale, aunque el dato sea de otro dueño: InternetDB no da fechas ni nombres que lo digan.

Sin llave de Shodan (#8, RC-40) no hay API de host ni fechas: exposed_iot_device, exposed_ot_device y outdated_software
(SIN_LLAVE) van siempre a sin_cobertura. InternetDB tampoco dice cuándo vio cada puerto ni si es tcp o udp: la
evidencia lleva vigencia 'sin_fecha', fuente_sin_fecha y nota_vigencia (NOTA_SIN_FECHA: el dato puede ser viejo o de
quien tuvo la IP antes), el protocolo es tcp salvo PUERTOS_UDP, y el activo service lleva protocolo_supuesto.

Cobertura. Si algo quedó sin revisar (Cert Spotter caído o con 429, nombres o IP cortados por MAX_NOMBRES o MAX_IPS, un
A fallido, una IP sin respuesta, una respuesta 200 de InternetDB sin 'ports' o con campos que no se pueden leer, el 429
de InternetDB o el tope de tiempo), los códigos de CODIGOS sin hallazgos también van a sin_cobertura. Uno con
hallazgos no puede ir ahí (validar() lo rechaza) y solo queda el aviso. Si no queda ninguna IP que consultar y todo
respondió, la fuente queda succeeded con 0 hallazgos y un aviso. Si Cert Spotter y todos los A fallaron, o todas las IP
fallaron por la red, FuenteNoResponde, para que el orquestador la reintente.
Reintentos: 3 intentos por A y por IP (esperas de 5 y 15 s, nunca más largas que lo que le queda a la corrida) y 2 por
página de Cert Spotter. El lifetime del A es min(TIMEOUT_DNS, lo que queda). Cada petición HTTP tiene un plazo
absoluto, min(TIMEOUT_HTTP o TIMEOUT_CT, lo que queda), que cubre toda la lectura del cuerpo (_descargar lee por bloques
y corta al pasarse). Ese plazo no cubre la búsqueda del nombre del servidor (getaddrinfo), que no tiene timeout en
urllib. Solo el 404 de InternetDB es 'sin datos'. Un 200 vacío o 'null' no se puede leer. Un 429 de InternetDB o de
Cert Spotter no se reintenta: otro intento solo gastaría cupo.

Modos: 'vivo' consulta. 'grabar' además guarda lo ya limpio en cirdan/recolectores/respuestas_grabadas/shodan/<dominio>/
(las páginas de Cert Spotter reducidas a lo que lee certspotter.certificado(), cada A con estado, IP y su cadena CNAME,
y cada IP de InternetDB limpia o 'sin_datos'), todo al final y solo si la corrida no tuvo ninguna falla. Los únicos
recortes que no impiden grabar son los topes deterministas (TOPES: PAGINAS_CT, MAX_NOMBRES y MAX_IPS, más el de MAX_CVE,
que no deja la cobertura parcial), porque otra corrida los repetiría igual. Cualquier falla (un 429, la red, un A sin
respuesta, el tope de tiempo, una respuesta que no se puede leer, un 4xx, una página o una emisión de Cert Spotter rota
o campos rotos de InternetDB) deja intacta la grabación anterior, como github.py con SIN_CUOTA, con el aviso NO_SE_GRABO
al principio de los avisos. Una grabación fallida tampoco la toca. 'reproducir' solo lee esa grabación. Sin grabación
del dominio, reproducir da los 9 códigos en sin_cobertura y un aviso, no failed, para que la demo no muestre la fuente
caída. dnspython se importa solo al consultar de verdad (_resolver_a), como registros_dns.py.

    python -m cirdan.recolectores.shodan olmardo.com --reproducir
    python -m cirdan.recolectores.shodan olmardo.com --grabar
    python -m cirdan.recolectores.shodan olmardo.com --json

Como github.py, la línea de comandos rechaza vivo y --grabar si el dominio no está en DOMINIOS_EN_VIVO.
Código de salida: 0 si la corrida fue completa (el aviso fijo LIMITES y los códigos de SIN_LLAVE no cuentan), 1 si
queda en 'failed', 2 si la cobertura quedó parcial y 3 si --grabar no escribió por una falla (NO_SE_GRABO): la
grabación anterior sigue igual y hay que repetir --grabar más tarde. Si la falla deja la fuente en failed (por
ejemplo, todas las IP caídas) sale 1, y la grabación anterior también sigue igual.
"""
import argparse
import contextlib
import hashlib
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cirdan.config import config
from cirdan.ml import caracteristicas as rubrica
from cirdan.recolectores import certspotter
from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import (NOMBRE_VALIDO, Activo, FuenteNoResponde, Grabadora, Hallazgo, Resultado,
                                          SinGrabacion, con_reintentos, en_alcance_nombre)

FUENTE = 'shodan'
CARPETA_GRABADAS = RAIZ_GRABADAS / 'shodan'

# Código de regla -> severidad base. Los seis existen en el catálogo de reglas (semillas 001 y 004).
CODIGOS = {'exposed_rdp': 'high', 'exposed_remote_admin': 'high', 'exposed_file_sharing': 'high',
           'exposed_database': 'high', 'exposed_service': 'low', 'known_vulnerability': 'medium'}
# Sin la llave de Shodan (#8) no se pueden revisar: van siempre a sin_cobertura y no entran en CODIGOS.
SIN_LLAVE = ('exposed_iot_device', 'exposed_ot_device', 'outdated_software')

URL_INTERNETDB = 'https://internetdb.shodan.io/'
NOMBRE_INTERNETDB = 'Shodan InternetDB'          # atribución: va en los atributos y la evidencia
AGENTE = 'cirdan-osint/0.1 (+https://github.com/Kernel-Loco)'   # el mismo de crtsh.py
ORIGEN = 'cert_spotter_a'                        # de dónde salió la IP: un nombre de Cert Spotter y su A
RESOLVEDORES = ('1.1.1.1', '8.8.8.8')            # públicos y fijos, como registros_dns.py. Nunca el DNS del sistema

PAGINAS_CT = 2               # páginas de Cert Spotter: casi siempre la página y la vacía que cierra
INTENTOS_CT = 2              # intentos por página, como certspotter.COMPLEMENTO
TIMEOUT_CT = 20              # segundos por página
MAX_NOMBRES = 10             # nombres que se resuelven, con la raíz
MAX_IPS = 10                 # IP que se consultan en InternetDB
MAX_CVE = 25                 # known_vulnerability por IP. Los demás se cuentan en un aviso
INTENTOS = 3                 # intentos por A y por IP dentro de una corrida (no es scan_source_runs.attempt)
ESPERAS = (5, 15)            # segundos entre intentos
TIMEOUT_DNS = 5.0            # tiempo total de un A, con sus dos resolvedores
TIMEOUT_HTTP = 10            # segundos por petición a InternetDB
PAUSA_INTERNETDB = 1         # segundos entre una IP y la siguiente
TIEMPO_CORRIDA = 360         # segundos de toda la corrida, como github.py: ninguna consulta empieza después
MIN_RESTANTE = 5             # con menos segundos que esto ya no se empieza otro nombre ni otra IP
MAX_BYTES = 1024 * 1024      # tope de una respuesta HTTP
# Peor caso de una corrida para el límite diario (#13b): cada intento de cada petición HTTP o DNS.
MAX_CONSULTAS = PAGINAS_CT * INTENTOS_CT + MAX_NOMBRES * INTENTOS + MAX_IPS * INTENTOS

# Puertos por familia. Las listas no se cruzan (pruebas/test_shodan.py lo revisa).
PUERTOS = {
    'exposed_rdp': (3389,),
    'exposed_remote_admin': (22, 23, 5900, 5901, 5985, 5986),
    'exposed_file_sharing': (21, 139, 445, 548, 873, 2049),
    'exposed_database': (1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211, 27017),
}
PUERTOS_WEB = (80, 443)
PUERTOS_CORREO = (25, 110, 143, 465, 587, 993, 995)   # exposed_service habla de 'entradas distintas de sitios web y correo'
PUERTOS_INDUSTRIALES = (102, 502, 789, 1911, 2404, 4911, 9600, 20000, 44818, 47808)
PUERTOS_UDP = (123, 161, 500, 1900, 5353, 5683, 47808)  # solo tienen sentido en udp. Los demás se suponen tcp

# Rangos IPv4 publicados de Cloudflare, verificados contra cloudflare.com/ips-v4 el 27 oct 2026. Cambian poco, pero
# cambian: la fecha dice cuándo se revisaron por última vez.
RANGOS_CLOUDFLARE = tuple(ipaddress.ip_network(r) for r in (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'))
# Sufijo de cualquier nombre de la cadena CNAME, intermedio o final -> CDN o borde compartido. Una IP que llega por una
# cadena con uno de estos no se consulta. Sufijos públicos conocidos, sin verificar en vivo, hasta #15b.
SUFIJOS_CDN = {'cdn.cloudflare.net': 'cloudflare', 'cloudfront.net': 'cloudfront', 'akamaiedge.net': 'akamai',
               'edgekey.net': 'akamai', 'edgesuite.net': 'akamai', 'akamai.net': 'akamai', 'akamaized.net': 'akamai',
               'fastly.net': 'fastly', 'azureedge.net': 'azure_cdn', 'azurefd.net': 'azure_front_door',
               't-msedge.net': 'azure_front_door', 'b-cdn.net': 'bunny', 'incapdns.net': 'imperva',
               'vercel-dns.com': 'vercel', 'netlify.app': 'netlify', 'netlify.com': 'netlify',
               'myshopify.com': 'shopify', 'github.io': 'github_pages', 'herokudns.com': 'heroku'}
# Bordes con un número en el nombre, que no caben en un sufijo fijo: Vercel también da CNAME como
# <hash>.vercel-dns-017.com. Sin verificar en vivo, hasta #15b.
CDN_NUMERADOS = ((re.compile(r'(?:[a-z0-9_-]+\.)*vercel-dns-[0-9]{1,4}\.com'), 'vercel'),)
MAX_SALTOS_CNAME = 16        # nombres de una cadena CNAME que se siguen y se graban
# Lo que nunca se manda a InternetDB aunque ipaddress diga is_global: el relay 6to4 (RFC 7526).
RED_6TO4 = ipaddress.ip_network('192.88.99.0/24')

# Solo dígitos ASCII y a lo más 19 en el número: uno enorme no llega a int() (que desde Python 3.11 lanza ValueError
# con más de 4300 dígitos) y la entrada cuenta como rota.
CVE_VALIDO = re.compile(r'CVE-([0-9]{4})-([0-9]{4,19})')
CPE_VALIDO = re.compile(r'cpe:(?:/|2\.3:)[aho](?::[!-9;-~]*){0,12}')   # CPE 2.2 (cpe:/) y 2.3 (cpe:2.3:), ASCII visible
TAG_VALIDO = re.compile(r'[a-z0-9][a-z0-9_.-]{0,31}')
MAX_CPE = 200                # caracteres de una CPE
ESTADOS_A = ('ok', 'vacio', 'nxdomain')
CAMPOS = ('ports', 'tags', 'cpes', 'vulns', 'hostnames')   # los de una respuesta de InternetDB que se leen

# Avisos con texto fijo.
SIN_GRABACION_DOMINIO = 'shodan: no hay grabación de Shodan de este dominio, no se revisó InternetDB'
LIMITES = ('shodan: solo IPv4 y sin la llave de Shodan (#8): exposed_iot_device, exposed_ot_device y outdated_software '
           'quedan sin cobertura, y un CDN que no sea Cloudflare ni llegue por un CNAME conocido no se detecta hasta #15b')
SIN_IP = 'shodan: ninguna IP pública del dominio fuera de un CDN, no hubo nada que consultar en InternetDB'
PARCIAL = 'shodan: cobertura parcial'
NO_SE_GRABO = ('shodan: la corrida tuvo fallas (un 429, la red, el tope de tiempo o una respuesta que no se puede leer), '
               'no se grabó y se conserva la grabación anterior')
NOTA_SIN_FECHA = ('InternetDB no dice cuándo vio este dato: puede ser viejo o de quien tuvo la IP antes que el dominio')

TITULOS = {
    'exposed_rdp': 'Shodan vio abierto el escritorio remoto (puerto %d) en %s',
    'exposed_remote_admin': 'Shodan vio abierta una entrada de administración remota (puerto %d) en %s',
    'exposed_file_sharing': 'Shodan vio abierto un servicio para compartir archivos (puerto %d) en %s',
    'exposed_database': 'Shodan vio abierta una base de datos (puerto %d) en %s',
    'exposed_service': 'Shodan vio abierto el puerto %d en %s',
}
TITULO_CVE = 'Vulnerabilidad conocida %s por la versión que Shodan vio en %s'


class LimiteAlcanzado(FuenteNoResponde):
    """La fuente respondió 429: llegó a su límite. No se reintenta en la corrida."""


class SinTiempo(FuenteNoResponde):
    """Se acabó TIEMPO_CORRIDA antes de la consulta."""


class RespuestaIlegible(FuenteNoResponde):
    """La fuente respondió algo que no se puede leer, o un 4xx. Otro intento daría lo mismo."""


class ConsultaFallida(Exception):
    """El DNS no dio respuesta (tiempo agotado, SERVFAIL, ningún servidor contestó): no se sabe la IP."""


FALLAS = {'limite': LimiteAlcanzado, 'tiempo': SinTiempo, 'ilegible': RespuestaIlegible, 'error': FuenteNoResponde}
# Recortes deterministas de la cobertura: otra corrida los repetiría igual, así que no impiden grabar. Cualquier otra
# razón de cobertura parcial es una falla y 'grabar' no escribe (ClienteShodan.degradada).
TOPES = ('paginas', 'nombres', 'ips')
_NO_ENCONTRADO = object()    # el 404, dentro de _http
BLOQUE = 64 * 1024           # bytes que _descargar lee de una vez


# ---------------------------------------------------------------- consultas a la red

def _descargar(url, timeout, cronometro=None):
    """El cuerpo de la respuesta, de a lo más MAX_BYTES. La única función que hace HTTP.

    `timeout` es el plazo absoluto de toda la petición, no solo de cada operación de socket: se lee por bloques (read1,
    una lectura del socket a la vez) y, si se pasa del plazo, lanza SinTiempo. Así un servidor que manda el cuerpo de a
    poco no estira la corrida. No cubre getaddrinfo. `cronometro` es time.monotonic por omisión."""
    cronometro = cronometro or time.monotonic
    plazo = cronometro() + timeout
    req = urllib.request.Request(url, headers={'User-Agent': AGENTE, 'Accept': 'application/json'})
    partes, total = [], 0
    with urllib.request.urlopen(req, timeout=timeout) as r:
        leer = r.read1 if hasattr(r, 'read1') else r.read
        while True:
            if cronometro() > plazo:
                raise SinTiempo('shodan: la respuesta tardó más de %s s' % timeout)
            parte = leer(min(BLOQUE, MAX_BYTES + 1 - total))
            if not parte:
                break
            partes.append(parte)
            total += len(parte)
            if total > MAX_BYTES:
                raise ValueError('respuesta de más de %d bytes' % MAX_BYTES)
    return b''.join(partes)


def _cadena_cname(respuesta, nombre):
    """Los nombres de destino de la cadena CNAME de `nombre`, en orden: cada intermedio y el final, sin `nombre`.

    Salen de la sección de respuesta del mensaje que dnspython ya recibió (respuesta.response.answer), así que no hay
    consultas extra, y se completan con respuesta.canonical_name, el último. Sigue a lo más MAX_SALTOS_CNAME nombres y
    se detiene en un ciclo. Solo lee rdtype, name y target, así una prueba la puede llamar con objetos simulados."""
    destinos = {}
    for rrset in getattr(getattr(respuesta, 'response', None), 'answer', None) or ():
        if int(rrset.rdtype) != 5:    # dns.rdatatype.CNAME
            continue
        for rr in rrset:
            destinos[str(rrset.name).lower().rstrip('.')] = str(rr.target).lower().rstrip('.')
    inicio = nombre.lower().rstrip('.')
    cadena, actual = [], inicio
    while actual in destinos and len(cadena) < MAX_SALTOS_CNAME:
        actual = destinos[actual]
        if actual == inicio or actual in cadena:
            break
        cadena.append(actual)
    final = str(respuesta.canonical_name).lower().rstrip('.')
    if final != inicio and final not in cadena and len(cadena) < MAX_SALTOS_CNAME:
        cadena.append(final)
    return cadena


def _resolver_a(nombre, lifetime=TIMEOUT_DNS):
    """La única función que usa dnspython y habla con el resolvedor. Pregunta el A de `nombre` a 1.1.1.1 y 8.8.8.8.

    Devuelve (estado, ips, cadena): ('ok', IP, los nombres de la cadena CNAME, [] sin CNAME), ('vacio', [], []) si el
    nombre existe sin A (NoAnswer) o ('nxdomain', [], []). La cadena sale de la misma respuesta, sin consultas extra
    (_cadena_cname). `lifetime` es el tiempo total del A con sus dos resolvedores. Otra falla de DNS lanza
    ConsultaFallida. dnspython se importa aquí, como en registros_dns.py, porque la PC de desarrollo no lo tiene (está
    en requirements.txt y en la imagen)."""
    import dns.exception
    import dns.resolver
    resolvedor = dns.resolver.Resolver(configure=False)   # nunca el DNS del sistema ni del contenedor
    resolvedor.nameservers = list(RESOLVEDORES)
    resolvedor.lifetime = lifetime
    try:
        respuesta = resolvedor.resolve(nombre, 'A')
    except dns.resolver.NXDOMAIN:
        return 'nxdomain', [], []
    except dns.resolver.NoAnswer:
        return 'vacio', [], []
    except dns.exception.DNSException as e:
        raise ConsultaFallida('%s: %s' % (type(e).__name__, e)) from None
    return 'ok', [r.address for r in respuesta], _cadena_cname(respuesta, nombre)


# ---------------------------------------------------------------- limpieza de lo que se graba

def _entero(x):
    return isinstance(x, int) and not isinstance(x, bool)


def _nombre(x):
    """Un nombre en minúsculas y sin punto final, o None si no es válido."""
    if not isinstance(x, str):
        return None
    x = x.strip().lower().rstrip('.')
    return x if NOMBRE_VALIDO.fullmatch(x) else None


def _ipv4(x):
    try:
        return isinstance(x, str) and ipaddress.ip_address(x.strip()).version == 4
    except ValueError:
        return False


def limpiar_a(estado, ips, cnames):
    """{estado, ips, cnames} de un A, como se graba: solo IPv4 válidas, ordenadas y sin repetir, y los nombres válidos
    de la cadena CNAME en su orden, sin repetir y hasta MAX_SALTOS_CNAME. `cnames` puede ser una lista, un solo nombre
    o None. ValueError si no tiene esa forma (una grabación rota, o un resolvedor que devuelve otra cosa)."""
    if estado not in ESTADOS_A or not isinstance(ips, (list, tuple)):
        raise ValueError('forma inesperada')
    if cnames is None or isinstance(cnames, str):
        cnames = [cnames] if cnames else []
    if not isinstance(cnames, (list, tuple)):
        raise ValueError('forma inesperada')
    limpias = sorted({ipaddress.ip_address(ip.strip()) for ip in ips if _ipv4(ip)})
    cadena = []
    for c in map(_nombre, cnames):
        if c and c not in cadena:
            cadena.append(c)
    return {'estado': estado, 'ips': [str(ip) for ip in limpias] if estado == 'ok' else [],
            'cnames': cadena[:MAX_SALTOS_CNAME] if estado == 'ok' else []}


def reducir_pagina(pagina):
    """Una página de Cert Spotter con solo lo que lee certspotter.certificado(): sin huellas ni llaves públicas."""
    reducida = []
    for e in pagina:
        if not isinstance(e, dict):
            continue
        emisor = e.get('issuer')
        emisor = emisor.get('name') or emisor.get('friendly_name') if isinstance(emisor, dict) else emisor
        reducida.append({'id': e.get('id'), 'dns_names': e.get('dns_names'), 'not_before': e.get('not_before'),
                         'not_after': e.get('not_after'), 'revoked': e.get('revoked') is True,
                         'issuer': {'name': emisor if isinstance(emisor, str) else ''}})
    return reducida


def _cve(v):
    """'CVE-<año>-<número>' con el número sin ceros de más (mínimo 4 dígitos), o None si no es una CVE válida.
    Así 'cve-2014-00160' y 'CVE-2014-0160' son la misma."""
    m = CVE_VALIDO.fullmatch(v.strip().upper()) if isinstance(v, str) else None
    return 'CVE-%s-%04d' % (m.group(1), int(m.group(2))) if m else None


def limpiar_internetdb(datos, dominio):
    """Lo que se usa y se graba de una respuesta de InternetDB, o None si no es un objeto.

    {'cdn': True} si trae el tag 'cdn': de esa IP no se guarda nada más. {'sin_datos': True} es el 404. Si no,
    {ports, tags, cpes, vulns, hostnames, hostnames_ajenos, rotos}: solo puertos de 1 a 65535, tags, CPE (2.2 o 2.3) y
    CVE con forma válida (normalizadas con _cve, de la más reciente a la más vieja), y solo los nombres del dominio. Los
    demás nombres solo se cuentan. 'rotos' lista los campos que traían algo que no se pudo leer y se ignoró, y 'ports'
    si la respuesta no lo traía. Lee igual la respuesta de InternetDB y lo que ya grabó, así una
    grabación cambiada a mano no mete otra cosa."""
    if not isinstance(datos, dict):
        return None
    if datos.get('sin_datos') is True:
        return {'sin_datos': True}
    rotos = {c for c in (datos.get('rotos') or ()) if c in CAMPOS} if isinstance(datos.get('rotos'), list) else set()

    def lista(campo):
        valor = datos.get(campo, [])
        if not isinstance(valor, list):
            rotos.add(campo)
            return []
        return valor

    tags = sorted({t for t in lista('tags') if isinstance(t, str) and TAG_VALIDO.fullmatch(t)})
    if len(tags) != len(set(map(str, lista('tags')))):
        rotos.add('tags')
    if datos.get('cdn') is True or 'cdn' in tags:
        return {'cdn': True}
    puertos = sorted({p for p in lista('ports') if _entero(p) and 1 <= p <= 65535})
    if len(puertos) != len({p if _entero(p) else repr(p) for p in lista('ports')}):
        rotos.add('ports')
    cpes = sorted({c for c in lista('cpes') if isinstance(c, str) and len(c) <= MAX_CPE and CPE_VALIDO.fullmatch(c)})
    if len(cpes) != len(set(map(repr, lista('cpes')))):
        rotos.add('cpes')
    if 'ports' not in datos:   # un 200 sin 'ports' no dice qué puertos vio: no es 'ninguno'
        rotos.add('ports')
    cves = [_cve(v) for v in lista('vulns')]
    vulns = sorted(set(filter(None, cves)), key=lambda v: tuple(int(n) for n in v.split('-')[1:]), reverse=True)
    if None in cves:
        rotos.add('vulns')
    del_dominio, ajenos = set(), 0
    for h in lista('hostnames'):
        nombre = _nombre(h)
        if nombre and en_alcance_nombre(nombre, dominio):
            del_dominio.add(nombre)
        else:
            ajenos += 1
    previos = datos.get('hostnames_ajenos', 0)
    ajenos += previos if _entero(previos) and previos > 0 else 0
    return {'ports': puertos, 'tags': tags, 'cpes': cpes, 'vulns': vulns, 'hostnames': sorted(del_dominio),
            'hostnames_ajenos': ajenos, 'rotos': sorted(rotos)}


# ---------------------------------------------------------------- cliente, grabación y reproducción

class ClienteShodan:
    """Hace las consultas (Cert Spotter, el A y InternetDB) con reintentos y, según el modo, graba o reproduce lo ya
    limpio con la Grabadora del contrato (#13).

    `descargar(url, timeout)` y `resolver(nombre, lifetime)` hacen la consulta. Si no se pasan, se usan _descargar y
    _resolver_a, buscados en el módulo en cada consulta, así una prueba los puede cambiar con mock.patch.object.
    `cronometro` y `dormir` son time.monotonic y time.sleep por omisión. `consultas` suma cada intento de cada petición HTTP o DNS."""

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, descargar=None, resolver=None, nueva=False, reloj=None,
                 cronometro=None, dormir=None):
        self.modo = modo
        self.grabadora = Grabadora(carpeta, modo, nueva=nueva, reloj=reloj)
        self.descargar, self.resolver = descargar, resolver
        self.cronometro = cronometro or time.monotonic
        self.dormir = dormir or time.sleep
        self.consultas = 0
        self.inicio = None
        self.pendientes = []   # lo que se graba cuando la corrida termina
        self.fallas = 0        # consultas que fallaron en esta corrida, de cualquier tipo
        self.raras_ct = 0      # emisiones de Cert Spotter que no se pueden leer (certspotter.legible)

    @property
    def leidas(self):
        """(archivo, fecha de grabación) de cada respuesta tomada del disco."""
        return self.grabadora.leidas

    def hay_grabacion(self):
        return any(Path(self.grabadora.carpeta).glob('*.json'))

    def empezar(self):
        self.inicio = self.cronometro()

    def restante(self):
        """Segundos que le quedan a la corrida. Al reproducir no hay consultas y no hay tope."""
        if self.modo == 'reproducir':
            return TIEMPO_CORRIDA
        if self.inicio is None:
            self.inicio = self.cronometro()
        return TIEMPO_CORRIDA - (self.cronometro() - self.inicio)

    def esperar(self, segundos):
        """El dormir de con_reintentos: nunca más largo que lo que le queda a la corrida."""
        self.dormir(max(0, min(segundos, self.restante())))

    def degradada(self, parcial=()):
        """True si la corrida tuvo alguna falla: una consulta que falló, de cualquier tipo, o una razón de cobertura
        parcial (`parcial`, de _revisar) que no es un tope determinista de TOPES. Con eso 'grabar' no escribe."""
        return bool(self.fallas) or bool(set(parcial) - set(TOPES))

    def terminar(self):
        """La corrida terminó: graba todo lo pendiente. Una corrida que falla no llega aquí y no toca la grabación."""
        for consulta, datos in self.pendientes:
            self.grabadora.guardar(consulta, datos)
        self.pendientes = []

    def _grabar(self, consulta, datos):
        if self.modo == 'grabar':
            self.pendientes.append((consulta, datos))

    def _de_disco(self, consulta):
        """(True, datos) si sale de la grabación. Una corrida con fallas ya no se graba, pero una grabación de antes o
        editada a mano puede traer una falla: se lanza otra vez, con su clase y su texto, y no se lee como datos."""
        del_disco, datos = self.grabadora.de_disco(consulta)
        if del_disco and isinstance(datos, dict) and 'falla' in datos:
            raise FALLAS.get(datos.get('tipo'), FuenteNoResponde)(str(datos['falla'])[:300])
        return del_disco, datos

    def _consultar(self, consulta, funcion):
        """Corre `funcion` y cuenta su falla (no la de la grabación) en `fallas`: con una, 'grabar' no escribe."""
        try:
            return funcion()
        except SinGrabacion:
            raise
        except FuenteNoResponde:
            self.fallas += 1
            raise

    def _http(self, url, intentos, timeout, que, sin_reintento=()):
        """JSON de `url` con hasta `intentos` intentos dentro del tiempo de la corrida. None solo con un 404. Un 429
        lanza LimiteAlcanzado, y otro 4xx o un 200 vacío o 'null' RespuestaIlegible, sin reintentar."""
        def intento():
            limite = min(timeout, self.restante())
            if limite < 1:
                raise SinTiempo('shodan: se acabó el tiempo de la corrida antes de consultar %s' % que)
            self.consultas += 1
            try:
                cuerpo = (self.descargar or _descargar)(url, limite)
            except SinTiempo:
                # La respuesta se pasó de su plazo. Si con eso se acabó la corrida, es el corte por tiempo. Si no, es
                # una respuesta lenta y cuenta como una falla de red, que con_reintentos reintenta.
                if self.restante() < 1:
                    raise SinTiempo('shodan: se acabó el tiempo de la corrida mientras se leía %s' % que) from None
                raise TimeoutError('shodan: %s tardó más de %s s en responder' % (que, limite)) from None
            except urllib.error.HTTPError as e:
                codigo, espera = e.code, (e.headers or {}).get('Retry-After')
                with contextlib.suppress(Exception):
                    e.close()
                if codigo == 404:
                    return _NO_ENCONTRADO
                if codigo == 429:
                    raise LimiteAlcanzado('shodan: %s llegó a su límite de consultas (429, Retry-After %s s)'
                                          % (que, espera or '?')) from None
                if codigo in sin_reintento or (codigo < 500 and codigo != 408):
                    raise RespuestaIlegible('shodan: %s respondió %d' % (que, codigo)) from None
                raise
            if not cuerpo or not cuerpo.strip():
                raise RespuestaIlegible('shodan: %s respondió sin cuerpo' % que)
            datos = json.loads(cuerpo)
            if datos is None:
                raise RespuestaIlegible('shodan: %s respondió null' % que)
            return datos
        intento.__name__ = 'shodan: %s no respondió' % que
        datos = con_reintentos(intento, intentos=intentos, esperas=ESPERAS, dormir=self.esperar)
        return None if datos is _NO_ENCONTRADO else datos

    def pedir(self, consulta, url, fuente=certspotter.NOMBRE, intentos=INTENTOS_CT, timeout=None, pausa=0,
              sin_reintento=(), texto=None, valida=None):
        """La lista JSON de `url`, con la misma firma de ClienteCrtsh.pedir, así certspotter.certificados() la usa sin
        cambios. Se graba la página reducida (reducir_pagina). Una respuesta que no es lista, o con la que `valida`
        da False, cuenta como una que no llegó y no se reintenta."""
        del_disco, datos = self._de_disco(consulta)
        if del_disco:
            if not isinstance(datos, list):
                raise FuenteNoResponde('shodan: la grabación de %s no se puede leer' % consulta)
        else:
            que = '%s (%s)' % (fuente, texto or consulta)

            def pagina():
                if pausa:
                    self.dormir(pausa)
                datos = self._http(url, intentos, timeout or TIMEOUT_CT, que, sin_reintento)
                if not isinstance(datos, list) or (valida and not valida(datos)):
                    raise RespuestaIlegible('shodan: %s respondió algo que no se puede leer' % que)
                return reducir_pagina(datos)
            datos = self._consultar(consulta, pagina)
            self._grabar(consulta, datos)
        # Una emisión que certificados() salta deja la lista incompleta: es una falla, no el tope de páginas
        self.raras_ct += sum(1 for e in datos if not certspotter.legible(e))
        return datos

    def resolver_a(self, nombre):
        """{estado, ips, cnames} del A de `nombre`. Lanza FuenteNoResponde si el DNS no respondió en INTENTOS intentos.
        El lifetime de cada intento es min(TIMEOUT_DNS, lo que le queda a la corrida)."""
        consulta = 'a:' + nombre
        del_disco, datos = self._de_disco(consulta)
        if del_disco:
            try:
                return limpiar_a(datos['estado'], datos['ips'], datos.get('cnames', datos.get('cname')))
            except (ValueError, KeyError, TypeError, AttributeError):
                raise FuenteNoResponde('shodan: la grabación de %s no se puede leer' % consulta) from None

        def intento():
            limite = min(TIMEOUT_DNS, self.restante())
            if limite < 1:
                raise SinTiempo('shodan: se acabó el tiempo de la corrida antes de resolver %s' % nombre)
            self.consultas += 1
            return limpiar_a(*(self.resolver or _resolver_a)(nombre, limite))
        intento.__name__ = 'shodan: el DNS no respondió al A de %s' % nombre

        datos = self._consultar(consulta, lambda: con_reintentos(intento, intentos=INTENTOS, esperas=ESPERAS,
                                                                 errores=(ConsultaFallida,), dormir=self.esperar))
        self._grabar(consulta, datos)
        return datos

    def internetdb(self, ip, dominio, pausa=0):
        """Lo que InternetDB sabe de `ip`, ya limpio (limpiar_internetdb). Un 404 es {'sin_datos': True}. Una respuesta
        que no es un objeto lanza RespuestaIlegible, sin reintento."""
        consulta = 'internetdb:' + ip
        del_disco, datos = self._de_disco(consulta)
        if del_disco:
            limpio = limpiar_internetdb(datos, dominio)
            if limpio is None:
                raise FuenteNoResponde('shodan: la grabación de %s no se puede leer' % consulta)
            return limpio
        que = 'InternetDB (%s)' % ip

        def consulta_ip():
            if pausa:
                self.dormir(pausa)
            crudo = self._http(URL_INTERNETDB + ip, INTENTOS, TIMEOUT_HTTP, que)
            limpio = {'sin_datos': True} if crudo is None else limpiar_internetdb(crudo, dominio)
            if limpio is None:
                raise RespuestaIlegible('shodan: %s respondió algo que no es un objeto' % que)
            return limpio
        limpio = self._consultar(consulta, consulta_ip)
        self._grabar(consulta, limpio)
        return limpio


def carpeta_de(dominio):
    """Carpeta de la grabación de un dominio."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' consulta, 'reproducir' usa la grabación del dominio y 'grabar' empieza
    una grabación nueva."""
    return ClienteShodan(modo=modo, carpeta=carpeta_de(dominio), nueva=(modo == 'grabar'))


def _en_vivo_permitido(dominio):
    """Lo mismo que orquestador.en_vivo_permitido(), sin importar el orquestador (que importa los recolectores)."""
    permitidos = {d.strip().lower() for d in config('DOMINIOS_EN_VIVO', 'olmardo.com').split(',') if d.strip()}
    return '*' in permitidos or dominio in permitidos


# ---------------------------------------------------------------- reglas

def codigo_de_puerto(puerto):
    """El código de un puerto, o None para los de sitios web y correo, que dan servicio sin hallazgo."""
    for codigo, puertos in PUERTOS.items():
        if puerto in puertos:
            return codigo
    if puerto in PUERTOS_WEB or puerto in PUERTOS_CORREO:
        return None
    return 'exposed_service'


def protocolo(puerto):
    return 'udp' if puerto in PUERTOS_UDP else 'tcp'


def consultable(ip):
    """True si la IP se puede mandar a InternetDB: IPv4 global, no multicast, no reservada y fuera de 192.88.99.0/24.
    ipaddress da is_global True para multicast (224.0.0.0/4, con 233.252.0.0/24 de documentación) y para el relay
    6to4, así que no basta."""
    d = ipaddress.ip_address(ip)
    return d.version == 4 and d.is_global and not d.is_multicast and not d.is_reserved and d not in RED_6TO4


def cdn_de(ip, cnames=()):
    """El CDN de una IP: 'cloudflare' por sus rangos, el del sufijo de cualquier nombre de su cadena CNAME (intermedio o
    final, con SUFIJOS_CDN o CDN_NUMERADOS), o None. `cnames` es un nombre o una lista de nombres."""
    direccion = ipaddress.ip_address(ip)
    if any(direccion in red for red in RANGOS_CLOUDFLARE):
        return 'cloudflare'
    if isinstance(cnames, str):
        cnames = (cnames,)
    for cname in sorted(c for c in cnames or () if c):
        for sufijo, cdn in SUFIJOS_CDN.items():
            if cname == sufijo or cname.endswith('.' + sufijo):
                return cdn
        for patron, cdn in CDN_NUMERADOS:
            if patron.fullmatch(cname):
                return cdn
    return None


# ---------------------------------------------------------------- activos y hallazgos

def _huella(codigo, dominio, activo, clave=''):
    """No lleva lo observado (tags, CPE ni nombres), así el hallazgo no se duplica entre escaneos."""
    return hashlib.sha256('|'.join((FUENTE, codigo, dominio, activo, clave)).encode('utf-8')).hexdigest()


def _cuantos(n, singular, plural):
    return '%d %s' % (n, singular if n == 1 else plural)


def _donde(hosts):
    """El primer nombre de la IP y cuántos más tiene, para el título."""
    return hosts[0] if len(hosts) == 1 else '%s y %s' % (hosts[0], _cuantos(len(hosts) - 1, 'nombre más', 'nombres más'))


def _evidencia(titulo, ip, hosts, datos):
    """Lo común de la evidencia: InternetDB no da fechas, así que el dato puede ser viejo."""
    evidencia = {'title': titulo, 'ip': ip, 'hosts': hosts, 'tags': datos['tags'], 'fuente_datos': NOMBRE_INTERNETDB,
                 'vigencia': 'sin_fecha', 'fuente_sin_fecha': True, 'nota_vigencia': NOTA_SIN_FECHA}
    if datos['hostnames_ajenos']:
        evidencia['posible_dato_de_otro_dueno'] = True
    return evidencia


def hallazgo_puerto(codigo, dominio, servicio, ip, puerto, hosts, datos, ahora):
    """Un hallazgo de puerto sobre su activo service. Las características salen de la rúbrica (caracteristicas.py)."""
    titulo = TITULOS[codigo] % (puerto, _donde(hosts))
    evidencia = dict(_evidencia(titulo, ip, hosts, datos), puerto=puerto, protocolo=protocolo(puerto),
                     protocolo_supuesto=True)
    if puerto in PUERTOS_INDUSTRIALES:
        evidencia['puerto_industrial'] = True
    return Hallazgo(codigo, CODIGOS[codigo], servicio, titulo, evidencia,
                    rubrica.calcular(codigo, 'service', evidencia, ahora), _huella(codigo, dominio, servicio))


def hallazgo_cve(dominio, ip, cve, hosts, datos, ahora):
    """known_vulnerability sobre el activo ip, con la CVE como clave. Shodan la deduce de la versión."""
    codigo = 'known_vulnerability'
    titulo = TITULO_CVE % (cve, _donde(hosts))
    evidencia = dict(_evidencia(titulo, ip, hosts, datos), cve=cve, cpes=datos['cpes'], deducida_por_version=True)
    return Hallazgo(codigo, CODIGOS[codigo], ip, titulo, evidencia, rubrica.calcular(codigo, 'ip', evidencia, ahora),
                    _huella(codigo, dominio, ip, cve), clave=cve)


def _sin_cobertura(res, aviso):
    res.avisos.append(aviso)
    res.sin_cobertura = list(CODIGOS) + list(SIN_LLAVE)
    return res


# ---------------------------------------------------------------- punto de entrada

def recolectar(dominio, cliente=None, ahora=None, propios=()):
    """Servicios y CVE que Shodan ya vio en las IP públicas del dominio. `propios` no se usa."""
    dominio = dominio.strip().lower().rstrip('.')
    res = Resultado(dominio, FUENTE)
    if not NOMBRE_VALIDO.fullmatch(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res
    cliente = cliente or crear_cliente('vivo', dominio)
    if cliente.modo == 'reproducir' and not cliente.hay_grabacion():
        return _sin_cobertura(res, SIN_GRABACION_DOMINIO)
    try:
        cliente.empezar()
        _revisar(res, cliente, dominio, ahora or datetime.now(timezone.utc))
    finally:
        res.consultas = cliente.consultas
    return res


def _nombres(dominio, certs):
    """La raíz y después, por nombre, los del dominio en los certificados, sin el '*.' de los comodines."""
    nombres = set()
    for cert in certs:
        for n in (cert.get('name_value') or '').split('\n'):
            n = n.strip().lower()
            n = _nombre(n[2:] if n.startswith('*.') else n)
            if n and n != dominio and en_alcance_nombre(n, dominio):
                nombres.add(n)
    return [dominio] + sorted(nombres)


def _revisar(res, cliente, dominio, ahora):
    parcial = []    # por qué la cobertura quedó parcial

    # 1. Nombres de Cert Spotter, más la raíz
    try:
        certs, completos = certspotter.certificados(cliente, dominio, max_paginas=PAGINAS_CT, intentos=INTENTOS_CT,
                                                    timeout=TIMEOUT_CT)
        ct_respondio = True
        if not completos:
            res.avisos.append('shodan: Cert Spotter no dio todas sus páginas, pueden faltar nombres del dominio')
            # Sin fallas ni emisiones ilegibles, solo se cortó en PAGINAS_CT: un tope determinista
            parcial.append('paginas' if not cliente.fallas and not cliente.raras_ct else 'ct')
    except FuenteNoResponde as e:
        certs, ct_respondio = [], False
        res.avisos.append('%s. Solo se revisó la raíz' % e)
        parcial.append('ct')
    nombres = _nombres(dominio, certs)
    if len(nombres) > MAX_NOMBRES:
        res.avisos.append('shodan: se resolvieron %d de %d nombres del dominio (MAX_NOMBRES)' % (MAX_NOMBRES, len(nombres)))
        nombres = nombres[:MAX_NOMBRES]
        parcial.append('nombres')

    # 2. Un A por nombre
    por_ip, cnames, fallas_a, sin_tiempo = {}, {}, 0, 0
    for i, nombre in enumerate(nombres):
        if cliente.restante() < MIN_RESTANTE:
            sin_tiempo = len(nombres) - i
            break
        try:
            a = cliente.resolver_a(nombre)
        except SinTiempo:
            sin_tiempo = len(nombres) - i
            break
        except FuenteNoResponde as e:
            fallas_a += 1
            res.avisos.append(str(e))
            continue
        for ip in a['ips']:
            por_ip.setdefault(ip, set()).add(nombre)
            cnames.setdefault(ip, set()).update(a['cnames'])
    if sin_tiempo:
        res.avisos.append('shodan: se acabó el tiempo de la corrida antes de resolver %s'
                          % _cuantos(sin_tiempo, 'nombre', 'nombres'))
        parcial.append('tiempo')
    if not ct_respondio and fallas_a == len(nombres):
        raise FuenteNoResponde('shodan: no respondieron Cert Spotter ni el DNS de %s' % dominio)
    if fallas_a:
        parcial.append('a')

    # 3. Qué IP se consultan: públicas (consultable) y fuera de un CDN en toda su cadena CNAME
    ips = sorted(por_ip, key=ipaddress.ip_address)
    marcas, consultar = {}, []
    for ip in ips:
        if not consultable(ip):
            marcas[ip] = {'no_publica': True}
            continue
        cdn = cdn_de(ip, cnames.get(ip, ()))
        if cdn:
            marcas[ip] = {'cdn': cdn}
        else:
            consultar.append(ip)
    if len(consultar) > MAX_IPS:
        res.avisos.append('shodan: se consultaron %d de %d IP en InternetDB (MAX_IPS)' % (MAX_IPS, len(consultar)))
        for ip in consultar[MAX_IPS:]:
            marcas[ip] = {'internetdb': 'sin_consultar'}
        consultar = consultar[:MAX_IPS]
        parcial.append('ips')

    # 4. InternetDB por IP
    datos, fallas_red, sin_tiempo = {}, 0, 0
    for i, ip in enumerate(consultar):
        if cliente.restante() < MIN_RESTANTE:
            sin_tiempo = len(consultar) - i
            break
        try:
            datos[ip] = cliente.internetdb(ip, dominio, pausa=PAUSA_INTERNETDB if i else 0)
        except LimiteAlcanzado as e:
            res.avisos.append('%s. No se consultaron %s' % (e, _cuantos(len(consultar) - i, 'IP', 'IP')))
            parcial.append('limite')
            break
        except SinTiempo:
            sin_tiempo = len(consultar) - i
            break
        except SinGrabacion as e:
            res.avisos.append('shodan: %s' % e)
            parcial.append('grabacion')
        except RespuestaIlegible as e:
            res.avisos.append(str(e))
            parcial.append('ilegible')
        except FuenteNoResponde as e:
            fallas_red += 1
            res.avisos.append(str(e))
            parcial.append('red')
    if sin_tiempo:
        res.avisos.append('shodan: se acabó el tiempo de la corrida antes de consultar %s en InternetDB'
                          % _cuantos(sin_tiempo, 'IP', 'IP'))
        parcial.append('tiempo')
    if consultar and fallas_red == len(consultar):
        raise FuenteNoResponde('shodan: InternetDB no respondió por ninguna IP de %s' % dominio)
    if not consultar and not parcial:
        res.avisos.append(SIN_IP)

    # 5. Activos y hallazgos
    for ip in ips:
        hosts = sorted(por_ip[ip])
        atributos = {'hosts': hosts, 'fuente': FUENTE, 'origen': ORIGEN}
        atributos.update(marcas.get(ip, {}))
        d = datos.get(ip)
        if ip in marcas:
            atributos.setdefault('internetdb', 'no_consultada')
            res.activos.append(Activo('ip', ip, atributos))
            continue
        if d is None:
            atributos['internetdb'] = 'sin_respuesta'
            res.activos.append(Activo('ip', ip, atributos))
            continue
        atributos['fuente_datos'] = NOMBRE_INTERNETDB   # solo en las IP que InternetDB sí respondió
        if d.get('sin_datos'):
            atributos['internetdb'] = 'sin_datos'
            res.activos.append(Activo('ip', ip, atributos))
            continue
        if d.get('cdn'):
            atributos.update(cdn='internetdb', internetdb='descartada_cdn')
            res.activos.append(Activo('ip', ip, atributos))
            res.avisos.append('shodan: InternetDB marca %s como CDN, se descartaron sus datos' % ip)
            continue
        atributos['internetdb'] = {'puertos': d['ports'], 'tags': d['tags'], 'cpes': d['cpes'], 'vulns': len(d['vulns']),
                                   'hostnames': d['hostnames'], 'hostnames_ajenos': d['hostnames_ajenos']}
        res.activos.append(Activo('ip', ip, atributos))
        if d['rotos']:   # lo que no se pudo leer no es 'nada abierto': esa IP queda revisada a medias
            res.avisos.append('shodan: InternetDB dio en %s datos que no se pueden leer (%s) y se ignoraron'
                              % (ip, ', '.join(d['rotos'])))
            parcial.append('ilegible')
        if d['hostnames_ajenos']:
            res.avisos.append('shodan: InternetDB trae en %s %s de otro dominio: sus datos pueden ser de quien tuvo la '
                              'IP antes' % (ip, _cuantos(d['hostnames_ajenos'], 'nombre', 'nombres')))
        if 'honeypot' in d['tags']:
            res.avisos.append('shodan: InternetDB marca %s como honeypot, no se sacan hallazgos de esa IP' % ip)
            continue
        for puerto in d['ports']:
            servicio = '%s:%d/%s' % (ip, puerto, protocolo(puerto))
            res.activos.append(Activo('service', servicio, {
                'hosts': hosts, 'fuente': FUENTE, 'parent': ip, 'ip_address': ip, 'puerto': puerto,
                'protocolo': protocolo(puerto), 'protocolo_supuesto': True, 'fuente_datos': NOMBRE_INTERNETDB}))
            codigo = codigo_de_puerto(puerto)
            if codigo:
                res.hallazgos.append(hallazgo_puerto(codigo, dominio, servicio, ip, puerto, hosts, d, ahora))
        # d['vulns'] va de la más reciente a la más vieja: se reportan las MAX_CVE más recientes
        res.hallazgos += [hallazgo_cve(dominio, ip, cve, hosts, d, ahora) for cve in d['vulns'][:MAX_CVE]]
        if len(d['vulns']) > MAX_CVE:
            res.avisos.append('shodan: %s trae %d CVE, se reportan las %d más recientes y se omitieron %d'
                              % (ip, len(d['vulns']), MAX_CVE, len(d['vulns']) - MAX_CVE))

    # 6. Cobertura
    res.avisos.append(LIMITES)
    res.sin_cobertura = list(SIN_LLAVE)
    if parcial:
        con_hallazgos = {h.codigo for h in res.hallazgos}
        res.sin_cobertura = [c for c in CODIGOS if c not in con_hallazgos] + list(SIN_LLAVE)
        res.avisos.append('%s, se revisaron %d de %d IP del dominio en InternetDB'
                          % (PARCIAL, len(datos), len(consultar) + sum(1 for m in marcas.values() if m.get('internetdb'))))
    # Una corrida con fallas no pisa una grabación completa (como github.py con SIN_CUOTA). El aviso va primero, para
    # que entre en los 10 que guarda el orquestador
    if cliente.modo == 'grabar' and cliente.degradada(parcial):
        res.avisos.insert(0, NO_SE_GRABO)
    else:
        cliente.terminar()
    return res


# ---------------------------------------------------------------- línea de comandos

SEVERIDAD_ES = {'critical': 'crítica', 'high': 'alta', 'medium': 'media', 'low': 'baja'}


def resumen(res):
    """Líneas para la terminal."""
    lineas = ['%s · %s · %s · %s' % (res.dominio, FUENTE, res.estado, _cuantos(res.consultas, 'consulta', 'consultas'))]
    if res.error:
        lineas.append('error: %s' % res.error)
    for a in res.activos:
        if a.tipo == 'ip':
            i = a.atributos.get('internetdb')
            estado = ('puertos %s' % (', '.join(map(str, i['puertos'])) or 'ninguno')) if isinstance(i, dict) else i
            marca = ' · CDN %s' % a.atributos['cdn'] if a.atributos.get('cdn') else ''
            lineas.append('IP %s (%s) · %s%s' % (a.valor, ', '.join(a.atributos['hosts']), estado, marca))
    if res.hallazgos:
        lineas.append(_cuantos(len(res.hallazgos), 'hallazgo:', 'hallazgos:'))
        lineas += ['  [%s] %s' % (SEVERIDAD_ES.get(h.severidad, h.severidad), h.titulo) for h in res.hallazgos]
    elif res.estado == 'succeeded':
        lineas.append('Sin hallazgos.')
    if res.sin_cobertura:  # no es lo mismo que 0 hallazgos
        lineas.append('Cobertura parcial: no se revisaron %s.' % ' ni '.join(res.sin_cobertura))
    lineas += ['aviso: %s' % a for a in res.avisos]
    return lineas


def codigo_salida(res):
    """0 si la corrida fue completa, 1 si el resultado queda en 'failed', 2 si la cobertura quedó parcial y 3 si
    --grabar no escribió por una falla (NO_SE_GRABO). El aviso fijo LIMITES y los códigos de SIN_LLAVE, que salen en
    toda corrida, no cuentan."""
    if res.estado == 'failed':
        return 1
    if NO_SE_GRABO in res.avisos:
        return 3
    parcial = set(res.sin_cobertura) - set(SIN_LLAVE) or any(a.startswith(PARCIAL) for a in res.avisos)
    return 2 if parcial else 0


def _main(argv=None):
    # En Windows, cuando la salida no es la consola (Git Bash, una tubería), Python usa cp1252 y los acentos se rompen.
    if (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    p = argparse.ArgumentParser(description='Servicios y CVE que Shodan InternetDB ya vio en las IP públicas del dominio')
    p.add_argument('dominio')
    modo = p.add_mutually_exclusive_group()
    modo.add_argument('--grabar', action='store_true',
                      help='empieza una grabación nueva en cirdan/recolectores/respuestas_grabadas/shodan/<dominio>/')
    modo.add_argument('--reproducir', action='store_true', help='usa solo la grabación, sin red')
    p.add_argument('--json', action='store_true', help='imprime el resultado completo en JSON')
    a = p.parse_args(argv)
    dominio = a.dominio.strip().lower().rstrip('.')
    if not NOMBRE_VALIDO.fullmatch(dominio):  # también evita que '..' o '/' saquen la carpeta de respuestas_grabadas
        p.error('dominio inválido: %s' % a.dominio)
    modo = 'grabar' if a.grabar else 'reproducir' if a.reproducir else 'vivo'
    if modo != 'reproducir' and not _en_vivo_permitido(dominio):
        p.error('%s no está en DOMINIOS_EN_VIVO: Shodan solo se consulta en vivo, o se graba, con la carta vigente del '
                'dominio. Usa --reproducir' % dominio)
    cliente = crear_cliente(modo, dominio)
    try:
        res = recolectar(dominio, cliente)
    except FuenteNoResponde as e:
        res = Resultado(dominio, FUENTE, estado='failed', consultas=cliente.consultas, error=str(e))
    if a.json:
        print(json.dumps(res.a_dict(), ensure_ascii=False, indent=1))
    else:
        print('\n'.join(resumen(res)))
    return codigo_salida(res)


if __name__ == '__main__':
    sys.exit(_main())
