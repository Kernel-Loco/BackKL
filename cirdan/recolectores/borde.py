"""CDN o WAF delante de un sitio, y respuestas de reto o bloqueo del WAF, sin red (#18, RC-46).

No es un recolector (no está en REGISTRO ni tiene MAX_CONSULTAS): son funciones puras para la visita web normal de la
actividad 6 del Anexo A, que las llama por cada sitio con lo que ya tiene. No hace ninguna petición ni consulta DNS.

Señales, todas pasivas y de datos que ya se tienen:
- cname: un nombre de la cadena CNAME del sitio, intermedio o final, termina en un sufijo de shodan.SUFIJOS_CDN o calza
  con shodan.CDN_NUMERADOS. La cadena sale de la misma respuesta DNS del A (shodan._cadena_cname).
- rangos: la IP está en los rangos IPv4 publicados de Cloudflare (shodan.RANGOS_CLOUDFLARE). Una IPv6 de Cloudflare
  sale por el ASN.
- asn: el ASN de la IP, de la base local de DB-IP Lite (geoip.ubicar), está en geoip.CDN_POR_ASN. Un ASN mixto de nube
  y CDN (Amazon, Microsoft, Google) no cuenta: ahí el CDN sale por el CNAME o por las cabeceras.
- cabeceras: la respuesta de la visita web trae una cabecera propia del borde (FIRMAS). Solo se guarda el nombre de la
  cabecera, nunca su valor: cf-ray o x-sucuri-id identifican la petición. De una cookie, solo la parte fija de su
  nombre que calzó con la firma (por ejemplo incap_ses_), nunca lo que pone el servidor.
Solo cuentan los de PROVEEDORES, que son CDN o proxy inverso con WAF. Un CNAME a un hosting de shodan.SUFIJOS_CDN
(shopify, github_pages, heroku) no marca nada. Si el ASN o las cabeceras del mismo sitio son de un CDN, ese CDN sí sale,
porque es el que está delante (un hosting que sirve por Fastly o por Cloudflare).

Qué se guarda. detectar() da el dato del activo del sitio, que la visita web pone en atributos['borde']
(assets.attributes) del domain o subdomain, por ejemplo {'texto': 'Protegido por Cloudflare', ...}. Nunca es un
hallazgo ni entra al score: no tiene código de regla. Que no se vea un CDN o WAF no prueba que no lo haya:
detectar() da None, que quiere decir 'no se vio', nunca 'no hay', y el portal no muestra nada. La visita guarda
'borde': None en ese caso para que un sitio que dejó su CDN no siga marcado (el orquestador une los atributos con ||,
que no borra llaves). Si la visita a un sitio falló, no escribe 'borde' y se queda lo último que se vio.

Reto o bloqueo. reto() dice si la respuesta es un reto o un bloqueo del WAF y no la página del sitio:
- con cualquier estado, también un 429, una cabecera que lo declara (RETO_POR_CABECERA, por ejemplo cf-mitigated:
  challenge). El motivo es esa cabecera y aviso() lo llama reto o bloqueo.
- un 429 sin cabecera de reto, siempre: es un límite de peticiones y nunca trae la página del sitio, con o sin marca.
  No dice que sea un WAF: aviso() lo llama límite de peticiones y solo nombra al proveedor si una marca dice de quién
  es. Las cabeceras del CDN vienen en toda respuesta que pasa por él, también en un 429 del propio sitio.
- un 403 o un 503 solo con una marca de página de reto o bloqueo en el cuerpo (MARCAS). Sin marca es la respuesta del
  sitio, que se analiza como cualquier otra. Las marcas son de las páginas de cada proveedor: un captcha genérico
  (reCAPTCHA, hCaptcha, Turnstile) no cuenta, porque puede ser un formulario del propio sitio, ni un script que el CDN
  o la aplicación ponen en cualquier página (el de /cdn-cgi/challenge-platform/ de Cloudflare, el de
  /_Incapsula_Resource de Imperva o el SDK AwsWafIntegration de AWS WAF).
Las tecnologías de un sitio con reto quedan sin cobertura, nunca 0 tecnologías, como la cobertura parcial de #23.
cobertura() lo pasa a revisados, sin_revisar y sin_cobertura del Resultado, y aviso() da el texto. El reto también trae
las cabeceras del borde, así que detectar() lo marca igual. No se reintenta para saltar el reto.

Las cabeceras pueden ser un dict, un http.client.HTTPMessage o una lista de pares. Un generador se gasta en la primera
llamada, así que a detectar() y a reto() se les pasa la misma lista. Nombres, patrones y cuerpo se comparan solo en
ASCII (re.ASCII, str.isascii y minúsculas solo de A a Z): con re.IGNORECASE o str.lower(), 'ſ' calzaría con 's',
'İ' con 'i' y 'K' (U+212A) con 'k'.

FIRMAS, RETO_POR_CABECERA y MARCAS son señales públicas conocidas, sin verificar en vivo, como shodan.SUFIJOS_CDN. Se
revisan con la primera grabación de la visita web. Las pruebas usan respuestas armadas a mano en
pruebas/fixtures/borde/, no grabadas de ningún dominio.
"""
import ipaddress
import re

from cirdan.recolectores import geoip, shodan
from cirdan.recolectores.contrato import NOMBRE_VALIDO

# Código -> nombre visible. Los códigos son los de shodan.SUFIJOS_CDN y geoip.CDN_POR_ASN cuando coinciden.
PROVEEDORES = {'akamai': 'Akamai', 'aws_waf': 'AWS WAF', 'azure_cdn': 'Azure CDN',
               'azure_front_door': 'Azure Front Door', 'bunny': 'Bunny', 'cloudflare': 'Cloudflare',
               'cloudfront': 'Amazon CloudFront', 'edgio': 'Edgio', 'fastly': 'Fastly', 'imperva': 'Imperva',
               'netlify': 'Netlify', 'sucuri': 'Sucuri', 'vercel': 'Vercel'}
SENALES = ('asn', 'cabeceras', 'cname', 'rangos')
TEXTO = 'Protegido por %s'

# Una cookie con ese nombre: al inicio del valor o después de ', ', por si el cliente juntó varias Set-Cookie en una
# (como el dict de cabeceras de requests). El grupo 1 es la parte fija del nombre, lo único que se guarda.
_COOKIE = r'(?:^|,\s*)%s='
# Cabecera -> [(proveedor, patrón del valor o None)]. Con None basta que venga la cabecera. El patrón se busca al inicio
# del valor, sin distinguir mayúsculas. En 'set-cookie' se busca en todo el valor (_COOKIE).
FIRMAS = {
    'cf-ray': [('cloudflare', None)],
    'cf-cache-status': [('cloudflare', None)],
    'cf-mitigated': [('cloudflare', None)],
    'x-sucuri-id': [('sucuri', None)],
    'x-sucuri-cache': [('sucuri', None)],
    'x-sucuri-block': [('sucuri', None)],
    'x-iinfo': [('imperva', None)],
    'x-cdn': [('imperva', r'(incapsula|imperva)\b')],
    'akamai-grn': [('akamai', None)],
    'akamai-cache-status': [('akamai', None)],
    'x-akamai-transformed': [('akamai', None)],
    'x-akamai-request-id': [('akamai', None)],
    'x-fastly-request-id': [('fastly', None)],
    'fastly-debug-digest': [('fastly', None)],
    'x-amz-cf-id': [('cloudfront', None)],
    'x-amz-cf-pop': [('cloudfront', None)],
    'via': [('cloudfront', r'.*\(cloudfront\)')],
    'x-amzn-waf-action': [('aws_waf', None)],
    'x-azure-ref': [('azure_front_door', None)],
    'x-vercel-id': [('vercel', None)],
    'x-vercel-cache': [('vercel', None)],
    'x-vercel-mitigated': [('vercel', None)],
    'x-nf-request-id': [('netlify', None)],
    'cdn-pullzone': [('bunny', None)],
    'server': [('cloudflare', r'cloudflare\b'), ('akamai', r'akamai(ghost|netstorage)\b'),
               ('sucuri', r'sucuri/cloudproxy\b'), ('vercel', r'vercel\b'), ('netlify', r'netlify\b'),
               ('bunny', r'bunnycdn\b'), ('cloudfront', r'cloudfront\b')],
    'set-cookie': [('cloudflare', _COOKIE % r'(__cf_bm|cf_clearance|__cflb)'),
                   ('imperva', _COOKIE % r'(incap_ses_|visid_incap_|nlbi_)[0-9a-z_]*'),
                   ('sucuri', _COOKIE % r'(sucuri_cloudproxy_)[0-9a-z_]*'), ('akamai', _COOKIE % r'(ak_bmsc)'),
                   ('aws_waf', _COOKIE % r'(aws-waf-token)')],
}
# Cabecera -> (proveedor, patrón del valor): con cualquier estado, la respuesta es un reto o un bloqueo.
RETO_POR_CABECERA = {'cf-mitigated': ('cloudflare', r'challenge\b'),
                     'x-amzn-waf-action': ('aws_waf', r'(captcha|challenge|block)\b'),
                     'x-vercel-mitigated': ('vercel', r'(challenge|deny)\b'),
                     'x-sucuri-block': ('sucuri', r'.')}
# Marcas de la página de reto o bloqueo de cada proveedor, en minúsculas, para un 403, un 429 o un 503. Solo texto de
# esa página: no un script que también va en las páginas normales del sitio.
MARCAS = (('cloudflare', '<title>just a moment...</title>'), ('cloudflare', 'attention required! | cloudflare'),
          ('cloudflare', 'cf-error-details'), ('sucuri', 'sucuri website firewall'),
          ('imperva', 'incapsula incident id'), ('akamai', 'reference&#32;&#35;'),
          ('cloudfront', 'generated by cloudfront (cloudfront)'), ('vercel', 'vercel security checkpoint'))
ESTADOS_CON_MARCA = (403, 503)
LIMITE = 429
MOTIVO_PAGINA = 'página de reto o bloqueo'
MOTIVO_LIMITE = 'límite de peticiones'
MAX_CUERPO = 64 * 1024       # caracteres del cuerpo que se revisan, como el bloque de transporte.descargar
MAX_VALOR = 8 * 1024         # caracteres del valor de una cabecera que se comparan con su patrón (no se guardan)
MAX_COOKIES = 64 * 1024      # lo mismo en set-cookie, pero entre todas las de la respuesta: el tope de una línea en
                             # http.client. Por cada Set-Cookie, 99 de 64 KiB tomaban más de 1 s
MAX_CNAMES = shodan.MAX_SALTOS_CNAME
MAX_IPS = 64                 # IP y ASN que se miran: de más solo se pierde una señal

_FIRMAS = {c: [(p, re.compile(v, re.I | re.A) if v else None) for p, v in f] for c, f in FIRMAS.items()}
_RETOS = {c: (p, re.compile(v, re.I | re.A)) for c, (p, v) in RETO_POR_CABECERA.items()}
_MINUSCULAS = {c: c + 32 for c in range(ord('A'), ord('Z') + 1)}   # para str.translate: solo de A a Z
# Valores sueltos que no se recorren: una red de ipaddress se recorrería dirección por dirección.
_UNO = (str, bytes, int, ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)


def _varios(x, tope=None):
    """Una lista con lo que llegó: None da [], un solo texto, número, IP o red da [x] y cualquier otra cosa que no se
    pueda recorrer (iter() lanza TypeError) da []. Un error al recorrerla, como el TypeError de map(int, ['1', None]),
    sí sale: con [] se perdería lo ya leído y la visita lo tomaría por un negativo (sin reto, sin borde), cuando el
    sitio debe quedar sin cobertura. Con `tope` se leen exactamente esos, ni uno más: un generador como red.hosts()
    no se recorre entero."""
    if x is None:
        return []
    if isinstance(x, _UNO):
        return [x]
    try:
        iterador = iter(x)
    except TypeError:
        return []
    salida = []
    try:
        while tope is None or len(salida) < tope:
            salida.append(next(iterador))
    except StopIteration:
        pass
    return salida


def _pares(cabeceras):
    """[(nombre en minúsculas, valor)] de un dict, un http.client.HTTPMessage (que repite set-cookie) o una lista de
    pares. Lo que no es texto, o un nombre que no es ASCII, se salta. Cada valor se corta a MAX_VALOR, y los de
    set-cookie, entre todos, a MAX_COOKIES: lo que pase de ahí llega vacío."""
    if cabeceras is None:
        return []
    pares = _varios(cabeceras.items() if hasattr(cabeceras, 'items') else cabeceras)
    salida = []
    resto = MAX_COOKIES   # de toda la respuesta, no de cada Set-Cookie
    for par in pares:
        if not isinstance(par, (list, tuple)) or len(par) != 2:
            continue
        nombre, valor = par
        if isinstance(nombre, str) and isinstance(valor, str) and nombre.isascii():
            nombre = nombre.strip().lower()
            if nombre == 'set-cookie':
                valor = valor.strip()[:resto]
                resto -= len(valor)
            else:
                valor = valor.strip()[:MAX_VALOR]
            salida.append((nombre, valor))
    return salida


def por_cabeceras(cabeceras):
    """{proveedor: [nombres de cabecera]} con las firmas de FIRMAS. Una cookie va como 'set-cookie:<parte fija de su
    nombre>', que sale de la firma y no del servidor. Se ven todas las cookies de los primeros MAX_COOKIES caracteres
    de todas las Set-Cookie de la respuesta, también si llegan juntadas con ', ', y de cada una de las demás cabeceras
    se miran MAX_VALOR."""
    vistos = {}
    for nombre, valor in _pares(cabeceras):
        for proveedor, patron in _FIRMAS.get(nombre, ()):
            if nombre == 'set-cookie':
                etiquetas = ['set-cookie:' + c.group(1).lower() for c in patron.finditer(valor)]
            else:
                etiquetas = [nombre] if patron is None or patron.match(valor) else []
            for etiqueta in etiquetas:
                nombres = vistos.setdefault(proveedor, [])
                if etiqueta not in nombres:
                    nombres.append(etiqueta)
    return {p: sorted(n) for p, n in vistos.items()}


def _limpio(nombre):
    """Un nombre DNS en minúsculas y sin el punto final, o '' si no lo es. Es el de contrato.NOMBRE_VALIDO: al menos
    dos etiquetas, las de antes de la última de 1 a 63 letras ASCII, dígitos o guion, sin guion al inicio ni al
    final, y la última de 2 a 63 letras ASCII, sin dígitos ni guion ('a.b' y 'tienda.acme-demo.123' dan ''), con
    hasta 253 caracteres sin el punto final (un IDN va en punycode). Un espacio, un NUL, una URL, un puerto, una sola
    etiqueta o dos puntos al final dan ''."""
    if not isinstance(nombre, str):
        return ''
    nombre = nombre.translate(_MINUSCULAS)
    nombre = nombre[:-1] if nombre.endswith('.') else nombre
    return nombre if NOMBRE_VALIDO.fullmatch(nombre) else ''


def por_cname(cnames):
    """{proveedor: [nombres de la cadena CNAME]} con los sufijos de shodan. Solo los de PROVEEDORES."""
    vistos = {}
    for cname in sorted({_limpio(c) for c in _varios(cnames, MAX_CNAMES)} - {''}):
        cdn = next((c for s, c in shodan.SUFIJOS_CDN.items() if cname == s or cname.endswith('.' + s)), None) or \
            next((c for patron, c in shodan.CDN_NUMERADOS if patron.fullmatch(cname)), None)
        if cdn in PROVEEDORES:
            vistos.setdefault(cdn, []).append(cname)
    return vistos


def por_rangos(ips):
    """{'cloudflare': [IP]} si alguna IP está en los rangos IPv4 publicados de Cloudflare. Una IP inválida se salta."""
    dentro = []
    for ip in _varios(ips, MAX_IPS):
        try:
            direccion = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            continue
        if any(direccion in red for red in shodan.RANGOS_CLOUDFLARE) and str(direccion) not in dentro:
            dentro.append(str(direccion))
    return {'cloudflare': sorted(dentro)} if dentro else {}


def por_asn(asns):
    """{proveedor: [ASN]} con geoip.CDN_POR_ASN. 'No disponible' y lo que no es un ASN se saltan."""
    vistos = {}
    for asn in _varios(asns, MAX_IPS):
        cdn = geoip.cdn_por_asn(asn)
        if cdn in PROVEEDORES and asn not in vistos.get(cdn, []):
            vistos.setdefault(cdn, []).append(asn)
    return {p: sorted(a) for p, a in vistos.items()}


def _lista(nombres):
    return nombres[0] if len(nombres) == 1 else '%s y %s' % (', '.join(nombres[:-1]), nombres[-1])


def detectar(cnames=(), ips=(), asns=(), cabeceras=None):
    """El dato del activo del sitio: qué CDN o WAF tiene delante y por qué señales, o None si no se vio ninguno (que no
    quiere decir que no haya). `cnames` es la cadena CNAME del sitio, `ips` sus IP, `asns` el ASN de cada una (de
    geoip.ubicar) y `cabeceras` las de la respuesta de la visita web, si hubo.

    {'texto': 'Protegido por Cloudflare', 'proveedores': [{'codigo', 'nombre', 'senales', y por cada señal lo que la
    dio: 'cabeceras' (nombres), 'cnames', 'ips' (de los rangos) y 'asns'}]}. Primero el proveedor con más señales."""
    por_senal = {'asn': por_asn(asns), 'cabeceras': por_cabeceras(cabeceras), 'cname': por_cname(cnames),
                 'rangos': por_rangos(ips)}
    campo = {'asn': 'asns', 'cabeceras': 'cabeceras', 'cname': 'cnames', 'rangos': 'ips'}
    proveedores = {}
    for senal in SENALES:
        for codigo, valores in por_senal[senal].items():
            p = proveedores.setdefault(codigo, {'codigo': codigo, 'nombre': PROVEEDORES[codigo], 'senales': []})
            p['senales'].append(senal)
            p[campo[senal]] = valores
    if not proveedores:
        return None
    orden = sorted(proveedores.values(), key=lambda p: (-len(p['senales']), p['codigo']))
    return {'texto': TEXTO % _lista([p['nombre'] for p in orden]), 'proveedores': orden}


def _texto(cuerpo):
    """Los primeros MAX_CUERPO caracteres del cuerpo, con minúsculas solo de A a Z (str.lower() pasaría 'K' a 'k').
    Bytes se leen como UTF-8 y lo ilegible se cambia."""
    if isinstance(cuerpo, (bytes, bytearray)):
        cuerpo = bytes(cuerpo[:MAX_CUERPO * 4]).decode('utf-8', errors='replace')
    return cuerpo[:MAX_CUERPO].translate(_MINUSCULAS) if isinstance(cuerpo, str) else ''


def reto(estado, cabeceras=None, cuerpo=None):
    """{'proveedor', 'estado', 'motivo'} si la respuesta es un reto o un bloqueo del WAF y no la página del sitio, o
    None. 'proveedor' es un código de PROVEEDORES o None si no se sabe de quién es. Las reglas, en el encabezado."""
    if isinstance(estado, bool) or not isinstance(estado, int):
        return None
    for nombre, valor in _pares(cabeceras):   # con cualquier estado, también un 429
        if nombre in _RETOS and _RETOS[nombre][1].match(valor):
            return {'proveedor': _RETOS[nombre][0], 'estado': estado, 'motivo': 'cabecera ' + nombre}
    if estado not in ESTADOS_CON_MARCA + (LIMITE,):
        return None
    texto = _texto(cuerpo)
    proveedor = next((p for p, m in MARCAS if m in texto), None)
    if estado == LIMITE:   # siempre límite de peticiones, y de quién solo si lo dijo una marca
        return {'proveedor': proveedor, 'estado': estado, 'motivo': MOTIVO_LIMITE}
    return {'proveedor': proveedor, 'estado': estado, 'motivo': MOTIVO_PAGINA} if proveedor else None


def aviso(fuente, host, datos):
    """El aviso de un sitio con reto o bloqueo (lo que dio reto()), para Resultado.avisos de `fuente`. Un 429 sin
    cabecera de reto sale como límite de peticiones. Solo nombra al proveedor si reto() lo supo, y nunca dice WAF si no
    se sabe de quién es."""
    datos = datos if isinstance(datos, dict) else {}
    proveedor = datos.get('proveedor')
    quien = PROVEEDORES.get(proveedor) if isinstance(proveedor, str) else None
    estado, motivo = datos.get('estado'), datos.get('motivo')
    de = ' de %s' % quien if quien else ''
    if motivo == MOTIVO_LIMITE:
        que, detalle = 'un límite de peticiones' + de, (estado,)
    else:
        que, detalle = 'un reto o bloqueo' + de, (estado, motivo)
    detalle = ', '.join(str(d) for d in detalle if d is not None)
    return '%s: %s respondió con %s%s: sus tecnologías quedan sin cobertura, no 0' % (
        fuente, host, que, ' (%s)' % detalle if detalle else '')


def _sitios(x):
    """({nombre limpio: [formas distintas como llegaron]}, si algo no se pudo leer como nombre). Un texto es un
    sitio."""
    if x is None:
        return {}, False
    if isinstance(x, str):
        x = [x]
    if not isinstance(x, (list, tuple, set, frozenset)):
        return {}, True
    sitios = {}
    for s in x:
        if _limpio(s) and s not in sitios.get(_limpio(s), []):
            sitios.setdefault(_limpio(s), []).append(s)
    return sitios, any(not _limpio(s) for s in x)


def _formas(sitios):
    """Cada sitio en todas las formas en que llegó, en la de _limpio() y en esa con el punto final, sin repetir."""
    return [f for k in sorted(sitios) for f in dict.fromkeys(sitios[k] + [k, k + '.'])]


def cobertura(revisados, sin_revisar, codigos):
    """(revisados, sin_revisar, sin_cobertura) del Resultado de la visita web, con los sitios (sus nombres) como partes
    (#23). Un sitio con reto, o que no se pudo visitar, va en sin_revisar, y si también está en revisados gana
    sin_revisar, con las formas en que llegó de los dos lados. Los nombres se comparan en minúsculas y sin el punto
    final, y solo cuentan los nombres DNS (_limpio). En revisados, lo que no es un nombre se salta. En sin_revisar
    no: si algo no se puede leer, no se sabe qué sitio quedó sin revisar y ninguno cuenta como revisado. `codigos`
    son los de la fuente, y sin ninguno lanza ValueError. En revisados y en sin_revisar cada sitio sale en todas las
    formas en que llegó, en la de _limpio() y en esa con el punto final (_formas). El orquestador compara las partes
    tal cual: un hallazgo con su sitio en una de esas formas calza, y en la forma de _limpio() calza siempre. Uno
    guardado en otra corrida con otras mayúsculas no calza: si su sitio va en sin_revisar se cierra sin revisarlo, y
    con sin_revisar None se queda abierto aunque se haya revisado.
    - sin_revisar vacío: (None, None, []), revisó todo. Es lo único que lo dice.
    - sin_revisar None, que no sabe cuáles quedaron sin revisar (contrato.Resultado): con revisados,
      (revisados, None, []), una corrida parcial en la que el orquestador cierra solo lo de revisados. Sin revisados,
      (None, None, codigos).
    - ninguno revisado: (None, None, codigos), todos los códigos sin cobertura y ningún hallazgo de ellos.
    - si no, cobertura parcial: los sitios de cada lado y cada hallazgo lleva su sitio en partes."""
    codigos = list(dict.fromkeys(c for c in _varios(codigos) if isinstance(c, str) and c))
    if not codigos:
        raise ValueError('cobertura() necesita los códigos de regla de la fuente')
    falta, ilegible = _sitios(sin_revisar)
    if ilegible:
        return None, None, codigos
    llegaron = _sitios(revisados)[0]
    hechos = {k: s for k, s in llegaron.items() if k not in falta}
    # Un sitio que también llegó en revisados, con otra forma, lleva esa forma en sin_revisar: un hallazgo con su
    # sitio así escrito no se cierra sin revisarse.
    falta = {k: s + [f for f in llegaron.get(k, []) if f not in s] for k, s in falta.items()}
    if sin_revisar is None:
        return (_formas(hechos), None, []) if hechos else (None, None, codigos)
    if not falta:
        return None, None, []
    if not hechos:
        return None, None, codigos
    return _formas(hechos), _formas(falta), []
