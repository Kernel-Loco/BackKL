"""Recolector de Certificate Transparency con crt.sh (#14).

Lee los logs públicos de Certificate Transparency, sin tocar los servidores del
dominio, y devuelve:
- los subdominios del dominio autorizado (activos),
- certificados vencidos de nombres que todavía resuelven en DNS, o que vencen en menos de 30 días
  cuando les queda menos de un tercio de su vida (hallazgos),
- dominios parecidos que ya tienen un certificado emitido (hallazgos).

La búsqueda de dominios parecidos (#109, RC-226) consulta en crt.sh %marca% y hasta 10 variantes del dominio, las
de candidatos_parecidos(), que pueden ser de terceros. ErnestoDL aprobó esa lista el 10 nov 2026 y está en
docs/contrato_plugin.md. Solo se buscan en los registros de certificados: nunca se resuelve el DNS de un dominio
parecido ni se le hace ninguna petición, y Cert Spotter no los busca. El orquestador (#22) la pide en cada
escaneo, porque contrato.ejecutar() pasa EN_ESCANEO, y la terminal también, salvo con --sin-parecidos.
recolectar() la deja apagada por defecto para quien lo llame directo. Si no se buscan, o si ninguna búsqueda
responde, lookalike_domain queda en sin_cobertura: cobertura parcial, nunca 0 parecidos. --con-parecidos se sigue
aceptando y hace lo mismo que no ponerlo. Tampoco se buscan, con un aviso, si el dominio no es su propio dominio
registrable (_marca). La terminal no recibe los otros dominios de la empresa y no los excluye: uno propio puede salir
como parecido. En un escaneo el orquestador sí pasa los dominios verificados o en pausa de la organización.

Modos: 'vivo' consulta crt.sh; 'grabar' además guarda cada respuesta en
cirdan/recolectores/respuestas_grabadas/crtsh/<dominio>/; 'reproducir' solo lee esas respuestas, sin red
(pruebas y respaldo de las demos). Cada corrida también consulta Cert Spotter (#14b,
certspotter.py). Si crt.sh responde, Cert Spotter suma los certificados vigentes que crt.sh no trae, sin
contar dos veces el mismo, y si Cert Spotter no responde queda lo de crt.sh con un aviso. Si crt.sh no
responde después de los reintentos, los subdominios y certificados vigentes salen solo de Cert Spotter,
sin vencidos ni dominios parecidos: esos dos códigos quedan en sin_cobertura. Si Cert Spotter tampoco
responde, el resultado queda en 'failed' y no trae activos ni hallazgos.

Cobertura (#23, RC-55). Cada hallazgo de vigencia lleva como parte el nombre con el vencimiento de su
certificado (_parte) y uno de dominio parecido, el dominio parecido. Si pueden faltar certificados (se usó
la búsqueda por nombre, o Cert Spotter no respondió, no estaba grabado o no dio todas sus páginas),
revisados lleva las partes de todos los certificados que llegaron y sin_revisar queda en None: así el
orquestador no cierra lo de un certificado que esta corrida no vio. En el respaldo no van los ya
vencidos, porque cert_expired queda en sin_cobertura.

Grabación dañada (RC-46). Al reproducir, un archivo vacío, cortado o ilegible (una respuesta de crt.sh, una
página de Cert Spotter, un falla_ o un dns_) no es que la fuente no respondiera. El resultado trae lo que sí
se pudo leer, revisados queda en [] para que el orquestador no cierre nada en ese escaneo, y el primer aviso
nombra los archivos dañados (DANADA). La única excepción al cierre es la de siempre: un por vencer cuya fecha
ya pasó se cierra en toda corrida de la fuente (RC-55, orquestador). Nunca queda 'failed' ni completo: si no se
pudo leer nada, sale sin activos, con los tres códigos en sin_cobertura. Si el dañado es el dns_ de un nombre,
no se sabe si resolvía y su certificado vencido no se reporta en esa corrida (DNS_DANADO).

    python -m cirdan.recolectores.crtsh olmardo.com
    python -m cirdan.recolectores.crtsh olmardo.com --sin-parecidos     (sin la búsqueda de dominios parecidos)
    python -m cirdan.recolectores.crtsh olmardo.com --grabar
    python -m cirdan.recolectores.crtsh olmardo.com --grabar --completar
    python -m cirdan.recolectores.crtsh olmardo.com --reproducir

olmardo.com es el dominio de prueba del equipo. Solo se consulta en vivo un dominio
con carta de autorización vigente, nunca uno de terceros, y --grabar solo con el
dominio de prueba.

--grabar empieza con la carpeta del dominio vacía. --completar solo consulta
lo que aún no se grabó desde ese inicio, para terminar una grabación que
crt.sh dejó a medias. Las páginas de Cert Spotter se graban en la misma carpeta. Si se grabó el
respaldo de Cert Spotter, también se graba que crt.sh no respondió, así --reproducir lo repite igual,
y --completar vuelve a probar crt.sh sin repetir la consulta a Cert Spotter. Si crt.sh ya responde,
sus certificados se unen a los de Cert Spotter grabados y la grabación deja de ser respaldo. Código de
salida: 0 bien, 1 si el resultado queda en 'failed', 2 si quedan avisos (grabación incompleta o dañada,
variantes sin respuesta, Cert Spotter sin responder o respaldo de Cert Spotter). Con el respaldo de
Cert Spotter el código 2 es lo esperado.
"""
import argparse
import hashlib
import http.client
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cirdan.recolectores import certspotter, contrato
from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import (MARCA, NOMBRE_VALIDO, SIN_GRABACION, Activo, FuenteNoResponde,  # noqa: F401
                                          Grabadora, Hallazgo, Resultado, SinGrabacion, nombre_archivo)

FUENTE = 'ct_logs'
URL = 'https://crt.sh/'
AGENTE = contrato.AGENTE   # uno solo para todas las fuentes (contrato.py)
CARPETA_GRABADAS = RAIZ_GRABADAS / 'crtsh'

DIAS_POR_VENCER = 30         # vence en menos de esto = hallazgo...
FRACCION_POR_VENCER = 3      # ...y le queda menos de 1/3 de su vida (los de vida corta se renuevan solos)
VENTANA_VENCIDOS_DIAS = 365  # vencido hace más de esto ya no es hallazgo; el subdominio queda como activo
VENTANA_PARECIDOS_DIAS = 90  # un dominio parecido cuenta si tiene un certificado vigente o vencido hace menos de esto
MAX_CANDIDATOS = 10          # variantes que se consultan al buscar parecidos (política de uso ético, 1.5)
INTENTOS_PARECIDOS = 2       # intentos HTTP de %marca% y de cada variante
FALLAS_SEGUIDAS = 3          # si tantas variantes seguidas fallan, crt.sh está saturado y se dejan las demás
INTENTOS = 3                 # intentos HTTP por consulta dentro de una corrida (no es scan_source_runs.attempt)
ESPERAS = (5, 15)            # segundos entre intentos; crt.sh suele recuperarse en segundos
PAUSA_PARECIDOS = 2          # segundos entre consultas de variantes, para no saturar crt.sh
FALLA = 'falla:'             # consulta que graba que crt.sh no respondió y se usó Cert Spotter
ORIGEN = 'crtsh'             # de dónde salió el certificado, en atributos y evidencia (el otro es Cert Spotter)

# Código de regla -> severidad base. Los tres deben existir en el catálogo de reglas (#30).
CODIGOS = {'cert_expired': 'high', 'cert_expiring_soon': 'medium', 'lookalike_domain': 'medium'}

# Lo que ejecutar() le pasa a recolectar() en cada escaneo, además de dominio, cliente, ahora y propios (#109, RC-226).
EN_ESCANEO = {'parecidos': True}

# Máximo de consultas HTTP de una corrida de un escaneo, lo que reserva el límite diario (#13b). Con crt.sh caído es el
# respaldo, sin parecidos: las dos búsquedas de crt.sh fallan con todos sus INTENTOS (2 x 3) y Cert Spotter da
# MAX_PAGINAS páginas con todos sus intentos cada una (4 x 3), 18. El peor caso es con crt.sh arriba: sus dos búsquedas
# (2 x 3), el complemento de Cert Spotter con 2 intentos por página (4 x 2) y los parecidos, %marca% y MAX_CANDIDATOS
# variantes con INTENTOS_PARECIDOS cada una (11 x 2), 36 en total.
MAX_CONSULTAS = max(2 * INTENTOS + certspotter.MAX_PAGINAS * INTENTOS,
                    2 * INTENTOS + certspotter.MAX_PAGINAS * certspotter.COMPLEMENTO['intentos']
                    + (1 + MAX_CANDIDATOS) * INTENTOS_PARECIDOS)

# Sufijos de dos niveles más comunes para sacar el dominio registrable sin descargar la lista pública de sufijos.
SUFIJOS_DOBLES = {'com.mx', 'org.mx', 'net.mx', 'edu.mx', 'gob.mx', 'com.br', 'com.ar', 'com.co', 'com.pe', 'com.es',
                  'co.uk', 'org.uk', 'com.au', 'co.jp'}
TLD_PRINCIPALES = ('com', 'mx', 'com.mx', 'net')
TLD_SECUNDARIOS = ('org', 'co', 'io', 'info', 'online', 'site')
HOMOGLIFOS = {'o': '0', 'l': '1', 'i': 'l', 'm': 'rn', 'w': 'vv', 'e': '3', 'a': '4', 's': '5'}

# Solo para lo que se imprime: los datos conservan los códigos de la base (high, medium...).
SEVERIDAD_ES = {'critical': 'crítica', 'high': 'alta', 'medium': 'media', 'low': 'baja'}
CODIGO_ES = {'cert_expired': 'certificados vencidos', 'cert_expiring_soon': 'certificados por vencer',
             'lookalike_domain': 'dominios parecidos'}
EXPOSICION_ES = {'publica': 'pública', 'privada': 'privada'}
MESES = ('ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic')


CrtshNoResponde = FuenteNoResponde  # el contrato (#13) define las excepciones de todas las fuentes

# Avisos de una grabación con archivos dañados (RC-46). DANADA va primero, para que no lo corte el tope de avisos.
DANADA = ('La grabación tiene %s (%s). Se muestra lo que sí se pudo leer, pueden faltar subdominios y certificados, y '
          'en este escaneo no se marca nada como resuelto, salvo un certificado por vencer cuya fecha ya pasó')
DNS_DANADO = object()        # lo que da el DNS de un nombre cuyo dns_ grabado está dañado: su vencido no se reporta
MAX_DANADOS = 5              # archivos dañados que nombra el aviso. De los demás dice cuántos son
SIN_LEER = 'No se pudo leer ningún certificado de la grabación de este dominio'
SIN_MARCA = ('No se buscaron dominios parecidos de %s: solo se buscan cuando el dominio autorizado es su propio '
             'dominio registrable, con un sufijo que Cirdan conoce')
POR_NOMBRE_DANADA = ('No se pudo leer la grabación de %%.%s. Se usó la búsqueda por nombre y pueden faltar '
                     'subdominios')


class GrabacionDanada(FuenteNoResponde):
    """Un archivo de la grabación vacío, cortado o ilegible. Hereda de FuenteNoResponde para que la corrida siga con
    lo demás, pero no es que la fuente no respondiera: los avisos no lo dicen así y la corrida no cierra nada, salvo
    el por vencer cuya fecha ya pasó (DANADA)."""

    def __init__(self, archivo):
        super().__init__('El archivo %s de la grabación está dañado (vacío, cortado o ilegible)' % archivo)
        self.archivo = archivo


# ---------------------------------------------------------------- consulta a crt.sh

def _descargar(url, timeout):
    req = urllib.request.Request(url, headers={'User-Agent': AGENTE, 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _nombre_grabado(consulta):
    """subdominios_acme.mx.json para %.acme.mx, contiene_acme.json para %acme% y acme.com.json para acme.com.
    La falla grabada de una consulta lleva falla_ antes del mismo nombre."""
    c = consulta.lower()
    if c.startswith(FALLA):
        return 'falla_' + _nombre_grabado(c[len(FALLA):])
    if c.startswith('%.'):
        c = 'subdominios_' + c[2:]
    elif c.startswith('%') and c.endswith('%'):
        c = 'contiene_' + c.strip('%')
    return nombre_archivo(c)


def _archivo_grabado(consulta, carpeta):
    return Path(carpeta) / _nombre_grabado(consulta)


class ClienteCrtsh:
    """Hace las consultas con reintentos y, según el modo, graba o reproduce las respuestas con la Grabadora del
    contrato (#13)."""

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, transporte=None, dormir=None, timeout=45,
                 completar=False, desde=None, reloj=None, nueva=False, resolver=None):
        """`completar` (solo al grabar) reutiliza lo grabado desde `desde`, el inicio de la grabación en curso,
        y vuelve a consultar lo demás, incluidas las respuestas de grabaciones anteriores.
        `nueva` (solo al grabar) vacía la carpeta y escribe la marca de inicio con la primera respuesta válida de
        crt.sh o Cert Spotter: si ninguno responde, la grabación anterior queda intacta.
        `resolver(nombre)` dice si un nombre resuelve en DNS (True, False o None si no se pudo saber). Si no se pasa,
        se usa el del transporte cuando lo trae (el simulado de las pruebas) o la consulta DNS del sistema."""
        self.modo, self.carpeta, self.timeout = modo, Path(carpeta), timeout
        self.grabadora = Grabadora(carpeta, modo, completar=completar, desde=desde, nueva=nueva, reloj=reloj,
                                   nombre=_nombre_grabado)
        self.transporte = transporte or _descargar
        self.resolver = resolver or getattr(self.transporte, 'resolver', None) or _resolver_dns
        self.dormir = dormir or time.sleep
        self.consultas = 0
        self.danados = []          # archivos de la grabación que no se pudieron leer, sin repetir (RC-46)
        self._dns_funciona = {}    # nombre de control -> si el DNS responde, una vez por corrida

    @property
    def leidas(self):
        """(archivo, fecha de grabación) de cada respuesta tomada del disco."""
        return self.grabadora.leidas

    def _de_disco(self, consulta):
        """de_disco de la Grabadora. Un archivo que no se puede leer (solo pasa al reproducir: con --completar se
        consulta otra vez) se anota en `danados` y lanza GrabacionDanada con su nombre."""
        try:
            return self.grabadora.de_disco(consulta)
        except ValueError:
            archivo = _nombre_grabado(consulta)
            if archivo not in self.danados:
                self.danados.append(archivo)
            raise GrabacionDanada(archivo) from None

    def resuelve(self, nombre, control=None):
        """True si el nombre resuelve en DNS, False si no existe y None si no se pudo saber. La respuesta se graba y se
        reproduce como las de crt.sh (dns_<nombre>.json), así --reproducir no consulta el DNS.

        Un «no existe» solo se cree si el nombre de `control` (el dominio autorizado) sí resuelve: sin servidor DNS
        alcanzable, Windows y macOS dan el mismo código que un nombre que no existe. Si el control falla, es None y no
        se graba. Con el archivo de la grabación dañado también es None, y queda anotado en `danados`."""
        consulta = 'dns:' + nombre
        try:
            del_disco, datos = self._de_disco(consulta)
        except GrabacionDanada:
            return None
        if del_disco:
            return datos
        valor = self.resolver(nombre)
        if valor is False and control:
            if control not in self._dns_funciona:
                self._dns_funciona[control] = self.resolver(control) is True
            if not self._dns_funciona[control]:
                valor = None
        if valor is not None:
            self.grabadora.guardar(consulta, valor)
        return valor

    def consultar(self, consulta, intentos=INTENTOS, timeout=None, pausa=0, **extra):
        """Una consulta a crt.sh. `pausa`: segundos de espera antes de consultar, no aplica si la respuesta sale del disco.

        Al reproducir, si la grabación dice que crt.sh no respondió a esta consulta, lanza CrtshNoResponde con el mismo
        error, así el respaldo de Cert Spotter se repite igual que en vivo. Si el archivo de la respuesta o el de su
        falla está dañado, lanza GrabacionDanada."""
        url = URL + '?' + urllib.parse.urlencode(dict(q=consulta, output='json', **extra))
        try:
            datos = self.pedir(consulta, url, 'crt.sh', intentos, timeout, pausa)
        except SinGrabacion as falta:
            try:
                _, error = self._de_disco(FALLA + consulta)
            except SinGrabacion:
                raise falta from None
            raise CrtshNoResponde(error) from None
        return datos

    def grabar_falla(self, consulta, error=None):
        """Graba que crt.sh no respondió a `consulta`. Se llama cuando Cert Spotter ya respondió: si tampoco responde,
        no se graba nada y la grabación anterior queda intacta. Sin `error` borra la falla grabada, porque crt.sh ya
        respondió (por ejemplo con --completar)."""
        if error is None:
            self.grabadora.descartar(FALLA + consulta)
        elif not isinstance(error, (SinGrabacion, GrabacionDanada)):
            self.grabadora.guardar(FALLA + consulta, str(error))

    def pedir(self, consulta, url, fuente='crt.sh', intentos=INTENTOS, timeout=None, pausa=0, sin_reintento=(),
              texto=None, valida=None):
        """La lista JSON de `url` con reintentos. Sale del disco si la grabación la trae y, al grabar, se guarda.
        Lo usan crt.sh y su respaldo Cert Spotter (certspotter.py). Un código HTTP de `sin_reintento` corta los
        intentos, por ejemplo el 429 de Cert Spotter. `texto` se muestra en el error en lugar de `consulta`. Una
        respuesta con la que `valida(datos)` da False cuenta como una que no llegó, no se graba y no se reintenta.
        Un archivo de la grabación vacío, cortado o ilegible lanza GrabacionDanada (_de_disco)."""
        del_disco, datos = self._de_disco(consulta)
        if del_disco:
            return datos
        if pausa:
            self.dormir(pausa)
        ultimo, hechos = '', 0
        for n in range(intentos):
            self.consultas += 1
            hechos += 1
            try:
                cuerpo = self.transporte(url, timeout or self.timeout)
                datos = json.loads(cuerpo or b'[]')
                if not isinstance(datos, list):
                    raise ValueError('respuesta inesperada')
                if valida and not valida(datos):
                    ultimo = 'ValueError: respuesta que no se puede leer'
                    break  # la fuente sí respondió y otro intento daría lo mismo
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
                ultimo = '%s: %s' % (type(e).__name__, e)
                if isinstance(e, urllib.error.HTTPError) and e.code in sin_reintento:
                    if e.code == 429:
                        ultimo = 'llegó a su límite de consultas, Retry-After %s s' % (
                            (e.headers or {}).get('Retry-After') or '?')
                    break  # otro intento solo gastaría cupo
                if isinstance(e, urllib.error.HTTPError) and e.code < 500 and e.code not in (408, 429):
                    break  # la fuente sí respondió y otro intento daría lo mismo
                if n < intentos - 1:
                    self.dormir(ESPERAS[min(n, len(ESPERAS) - 1)])
                continue
            self.grabadora.guardar(consulta, datos)  # fuera del try: un error del disco no es una falla de la fuente
            return datos
        self.grabadora.descartar(consulta)  # una respuesta de una grabación anterior no debe pasar por la de hoy
        raise CrtshNoResponde('%s no respondió a %s después de %d %s (%s)' % (
            fuente, texto or consulta, hechos, 'intento' if hechos == 1 else 'intentos', ultimo))


# ---------------------------------------------------------------- utilidades

NO_EXISTE = {socket.EAI_NONAME, getattr(socket, 'EAI_NODATA', socket.EAI_NONAME), 11001, 11004}  # NXDOMAIN o sin datos


def _resolver_dns(nombre):
    """True si el nombre resuelve (A, AAAA o un CNAME que llega a una), False si no existe y None si no se pudo saber.
    Es la misma consulta de DNS que hace cualquier navegador, sin tocar los servidores del dominio."""
    try:
        socket.getaddrinfo(nombre, None, proto=socket.IPPROTO_TCP)
        return True
    except socket.gaierror as e:
        return False if e.errno in NO_EXISTE else None
    except (OSError, UnicodeError):
        return None


def _con_fechas(certs):
    """Los certificados con una vigencia que se puede leer. Uno con fechas raras se salta y no tumba la corrida."""
    return [c for c in certs if isinstance(c, dict) and _se_lee(c.get('not_before')) and _se_lee(c.get('not_after'))]


def _se_lee(texto):
    try:
        _fecha(texto)
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _fecha(texto):
    d = datetime.fromisoformat(texto.replace('Z', ''))
    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)


def registrable(nombre):
    """Dominio registrable aproximado: acme.com.mx para www.acme.com.mx, acme.mx para api.acme.mx."""
    partes = nombre.split('.')
    if len(partes) >= 3 and '.'.join(partes[-2:]) in SUFIJOS_DOBLES:
        return '.'.join(partes[-3:])
    return '.'.join(partes[-2:])


def _marca(dominio):
    """La etiqueta que se busca como marca, o None si no se puede saber cuál es. registrable() solo conoce
    SUFIJOS_DOBLES: de acme.com.gt saca com.gt, con la etiqueta 'com', y sus variantes (com.com, com.mx) no se parecen
    al dominio autorizado. Por eso solo hay marca cuando el dominio autorizado es su propio dominio registrable.
    Tampoco la hay en un subdominio (api.acme.mx) ni en un sufijo solo (com.mx)."""
    if dominio in SUFIJOS_DOBLES or '.' not in dominio or registrable(dominio) != dominio:
        return None
    return dominio.split('.', 1)[0]


def _nombres(cert):
    """Nombres válidos del certificado, sin repetir, en minúsculas y con la marca de comodín aparte."""
    nombres = {}
    for crudo in (cert.get('name_value') or '').split('\n') + [cert.get('common_name') or '']:
        n = crudo.strip().lower().rstrip('.')
        comodin = n.startswith('*.')
        if comodin:
            n = n[2:]
        if n and NOMBRE_VALIDO.match(n):
            nombres[n] = nombres.get(n, False) or comodin
    return sorted(nombres.items())


def _huella(*partes):
    return hashlib.sha256('|'.join((FUENTE,) + partes).encode('utf-8')).hexdigest()


def _origen(cert):
    """De dónde salió el certificado, para los atributos y la evidencia: crt.sh con su id y su número de serie, o Cert
    Spotter con su id y su sha256."""
    if cert.get('origen') == certspotter.ORIGEN:
        return {'origen': certspotter.ORIGEN, 'certspotter_id': cert.get('id'), 'sha256': cert.get('cert_sha256', '')}
    return {'origen': ORIGEN, 'crtsh_id': cert.get('id'), 'serie': cert.get('serial_number', '')}


def _serie(cert):
    """Lo que distingue al certificado en la huella: su vigencia. crt.sh y Cert Spotter la dan igual (Cert Spotter no da
    el número de serie), así el mismo certificado no se duplica en findings cuando cambia la fuente."""
    return '%s/%s' % (_fecha(cert['not_before']).isoformat(), _fecha(cert['not_after']).isoformat())


def _del_dominio(nombre, dominio):
    return nombre == dominio or nombre.endswith('.' + dominio)


def _parte(nombre, cert):
    """La parte de un hallazgo de vigencia (#23): el nombre con el vencimiento de su certificado, el mismo texto que
    'host' y 'vence' de la evidencia. Así el orquestador la saca también de lo guardado antes de evidence.partes."""
    return '%s@%s' % (nombre, _fecha(cert['not_after']).isoformat())


def _revisados(dominio, certs, ahora, respaldo=False, sin_revocaciones=False):
    """Las partes que revisó una corrida a la que pueden faltarle certificados (#23, RC-55): cada nombre del dominio con
    el vencimiento de cada certificado que llegó. Con `respaldo` (solo Cert Spotter) no van los que ya vencieron:
    cert_expired queda sin cobertura, así que su hallazgo no se revisó aunque llegue el certificado.
    Con `sin_revocaciones` (el complemento de Cert Spotter no respondió, y es el que dice qué certificado de crt.sh está
    revocado) tampoco van los nombres cuyo hallazgo depende de una revocación: los de más de una vigencia, porque una
    renovación revocada no cuenta como la reciente, y los ya vencidos con un comodín vigente en su padre, porque un
    comodín revocado no los cubre."""
    por_nombre, comodines = {}, set()
    for c in certs:
        for n, comodin in _nombres(c):
            if _del_dominio(n, dominio):
                por_nombre.setdefault(n, []).append(c)
                if comodin and _fecha(c['not_before']) <= ahora < _fecha(c['not_after']):
                    comodines.add(n)
    dudosos = {n for n, cs in por_nombre.items()
               if len({_serie(c) for c in cs}) > 1 or (n != dominio and n.split('.', 1)[1] in comodines
                                                        and max(_fecha(c['not_after']) for c in cs) < ahora)}
    return sorted({_parte(n, c) for n, cs in por_nombre.items() if not (sin_revocaciones and n in dudosos)
                   for c in cs if not respaldo or _fecha(c['not_after']) >= ahora})


def _unir(certs, otros, dominio):
    """Los certificados de `certs` (crt.sh) más los de `otros` (Cert Spotter) que no están en `certs`. El mismo
    certificado tiene en las dos fuentes la misma vigencia y los mismos nombres del dominio, aunque cada una le dé su
    propio id: queda el de crt.sh, con la marca de revocado de Cert Spotter, que crt.sh no da."""
    def clave(c):
        return _serie(c), tuple(n for n in _nombres(c) if _del_dominio(n[0], dominio))
    revocados = {clave(c) for c in otros if c.get('revocado')} - {clave(c) for c in otros if not c.get('revocado')}
    vistos = {clave(c) for c in certs}
    return ([dict(c, revocado=True) if clave(c) in revocados else c for c in certs] +
            [c for c in otros if clave(c) not in vistos])


def candidatos_parecidos(dominio, maximo=MAX_CANDIDATOS):
    """Variantes de un dominio, en orden de probabilidad: TLD más comunes, sin guion, homoglifos, otros TLD,
    letras omitidas, letras cambiadas de lugar y letras repetidas. Nunca incluye el dominio original ni da más de
    MAX_CANDIDATOS, aunque `maximo` pida más: es el tope de la política de uso ético y el que cuenta MAX_CONSULTAS.
    Sin marca (_marca) no hay variantes: de acme.com.gt saldrían com.com o com.mx, que no se le parecen."""
    etiqueta = _marca(dominio)
    if etiqueta is None:
        return []
    base, sufijo = dominio, dominio.split('.', 1)[1]
    vistos, salida = {base}, []

    def agregar(nombre):
        if nombre not in vistos and NOMBRE_VALIDO.match(nombre):
            vistos.add(nombre)
            salida.append(nombre)

    for tld in TLD_PRINCIPALES:
        agregar('%s.%s' % (etiqueta, tld))
    if '-' in etiqueta:
        agregar('%s.%s' % (etiqueta.replace('-', ''), sufijo))
    for letra, parecida in HOMOGLIFOS.items():
        if letra in etiqueta:
            agregar('%s.%s' % (etiqueta.replace(letra, parecida, 1), sufijo))
    for tld in TLD_SECUNDARIOS:
        agregar('%s.%s' % (etiqueta, tld))
    if len(etiqueta) >= 5:
        for i in range(len(etiqueta)):
            agregar('%s.%s' % (etiqueta[:i] + etiqueta[i + 1:], sufijo))
        for i in range(len(etiqueta) - 1):
            agregar('%s.%s' % (etiqueta[:i] + etiqueta[i + 1] + etiqueta[i] + etiqueta[i + 2:], sufijo))
        for i in range(len(etiqueta)):
            agregar('%s.%s' % (etiqueta[:i + 1] + etiqueta[i] + etiqueta[i + 1:], sufijo))
    return salida[:max(0, min(maximo, MAX_CANDIDATOS))]


# ---------------------------------------------------------------- análisis

def _subdominios(dominio, certs, ahora, resuelve=None, anticipar=False):
    """Agrupa los certificados por nombre dentro del dominio y genera activos y hallazgos de vigencia.

    Un certificado vencido solo es hallazgo si el nombre todavía resuelve en DNS (`resuelve(nombre)` no es False) y no
    lo cubre un certificado comodín vigente de su dominio padre. Si no, el sitio ya no existe o usa el comodín, y el
    nombre queda solo como activo. Sin `resuelve` se da por hecho que resuelve. Un comodín vencido (*.nombre) siempre
    cuenta: no lo cubre el comodín del padre y su DNS no es el del nombre base.
    Si `resuelve(nombre)` da DNS_DANADO (el dns_ grabado de ese nombre está dañado, RC-46), no se sabe si resolvía y
    su vencido tampoco se reporta: el nombre queda solo como activo, sin el atributo resuelve.
    Con `anticipar` (al grabar) también consulta el DNS de los nombres que todavía no vencen o que un comodín cubre, así
    una reproducción de días después tiene las respuestas que necesite.
    """
    por_nombre, comodines = {}, set()
    vistos = set()
    for c in certs:
        if (c.get('origen'), c.get('id')) in vistos:  # crt.sh y Cert Spotter numeran por separado
            continue
        vistos.add((c.get('origen'), c.get('id')))
        vigente = _fecha(c['not_before']) <= ahora < _fecha(c['not_after']) and not c.get('revocado')
        for nombre, comodin in _nombres(c):
            if not _del_dominio(nombre, dominio):
                continue
            g = por_nombre.setdefault(nombre, {'certs': [], 'comodin': False})
            g['certs'].append(c)
            g['comodin'] |= comodin
            if comodin and vigente:
                comodines.add(nombre)  # *.nombre está cubierto hoy

    activos, hallazgos = [], []
    for nombre in sorted(por_nombre):
        g = por_nombre[nombre]
        reciente = max(g['certs'], key=lambda c: (not c.get('revocado'), _fecha(c['not_after'])))  # revocado, al final
        vence = _fecha(reciente['not_after'])
        primero = min(_fecha(c['not_before']) for c in g['certs'])
        dias = (vence - ahora).total_seconds() / 86400
        origen = _origen(reciente)
        activos.append(Activo('domain' if nombre == dominio else 'subdomain', nombre, {
            'comodin': g['comodin'], 'certificados': len(g['certs']), 'primer_certificado': primero.isoformat(),
            'vence': vence.isoformat(), 'emisor': reciente.get('issuer_name', ''), 'fuente': FUENTE, **origen}))
        evidencia = {'host': nombre, 'vence': vence.isoformat(), 'emisor': reciente.get('issuer_name', ''), **origen,
                     'comodin': g['comodin']}
        exacto = nombre in {n.strip().lower().rstrip('.') for n in
                            (reciente.get('name_value') or '').split('\n') + [reciente.get('common_name') or '']}
        padre = nombre.split('.', 1)[1] if nombre != dominio else ''
        cubierto = exacto and padre in comodines  # un *.padre vigente no cubre a un comodín *.nombre
        dns = None
        if resuelve and exacto and -dias <= VENTANA_VENCIDOS_DIAS and (anticipar or (dias < 0 and not cubierto)):
            dns = resuelve(nombre)
        if dias < 0 and -dias <= VENTANA_VENCIDOS_DIAS:
            if cubierto:
                activos[-1].atributos['cubierto_por_comodin'] = padre
                continue
            if dns is False:
                activos[-1].atributos['resuelve'] = False
                continue
            if dns is DNS_DANADO:  # no se sabe si resolvía: abrir su vencido podría ser falso (RC-46)
                continue
            titulo = 'Certificado vencido en %s' % nombre
            hallazgos.append(Hallazgo(
                'cert_expired', CODIGOS['cert_expired'], nombre, titulo,
                dict(evidencia, title=titulo, dias_vencido=int(-dias)),
                {'tipo': 'certificado_vencido', 'antiguedad_dias': int(-dias), 'exposicion': 'publica',
                 'sensibilidad': 'media'},
                _huella('cert_expired', nombre, _serie(reciente)), partes=[_parte(nombre, reciente)]))
        elif 0 <= dias < DIAS_POR_VENCER and dias * 86400 < (vence - _fecha(reciente['not_before'])).total_seconds() / FRACCION_POR_VENCER:
            titulo = ('El certificado de %s vence en menos de un día' % nombre if dias < 1 else
                      'El certificado de %s vence en %s' % (nombre, _cuantos(int(dias), 'día', 'días')))
            hallazgos.append(Hallazgo(
                'cert_expiring_soon', CODIGOS['cert_expiring_soon'], nombre, titulo,
                dict(evidencia, title=titulo, dias_para_vencer=int(dias)),
                {'tipo': 'certificado_por_vencer', 'antiguedad_dias': max(0, (ahora - _fecha(reciente['not_before'])).days),
                 'exposicion': 'publica', 'sensibilidad': 'baja'},
                _huella('cert_expiring_soon', nombre, _serie(reciente)), partes=[_parte(nombre, reciente)]))
    return activos, hallazgos


def _parecidos(dominio, certs_por_tipo, propios, ahora):
    """Un hallazgo por dominio registrable parecido con certificados recientes. `certs_por_tipo` trae
    (tipo, certificados, filtro): el filtro deja solo los nombres que se parecen, porque un mismo
    certificado puede cubrir dominios ajenos (por ejemplo los compartidos de una CDN)."""
    grupos = {}
    for tipo, certs, filtro in certs_por_tipo:
        for c in certs:
            for nombre, _ in _nombres(c):
                reg = registrable(nombre)
                if reg in propios or nombre in propios or not filtro(nombre):
                    continue
                g = grupos.setdefault(reg, {'tipo': tipo, 'nombres': set(), 'certs': {}})
                g['nombres'].add(nombre)
                g['certs'][c.get('id')] = c

    hallazgos = []
    limite = ahora - timedelta(days=VENTANA_PARECIDOS_DIAS)
    for reg in sorted(grupos):
        g = grupos[reg]
        certs = list(g['certs'].values())
        reciente = max(certs, key=lambda c: _fecha(c['not_after']))
        if _fecha(reciente['not_after']) < limite:
            continue
        primero = min(_fecha(c['not_before']) for c in certs)
        titulo = 'Dominio parecido con certificado: %s' % reg
        hallazgos.append(Hallazgo(
            'lookalike_domain', CODIGOS['lookalike_domain'], dominio, titulo,
            {'title': titulo, 'dominio_parecido': reg, 'tipo_parecido': g['tipo'],
             'nombres': sorted(g['nombres'])[:10], 'certificados': len(certs),
             'primer_certificado': primero.isoformat(), 'vence': _fecha(reciente['not_after']).isoformat(),
             'emisor': reciente.get('issuer_name', ''), 'origen': ORIGEN, 'crtsh_id': reciente.get('id')},
            {'tipo': 'dominio_parecido', 'antiguedad_dias': max(0, (ahora - primero).days), 'exposicion': 'publica',
             'sensibilidad': 'alta'},
            _huella('lookalike_domain', dominio, reg), clave=reg, partes=[reg]))
    return hallazgos


# ---------------------------------------------------------------- punto de entrada

def recolectar(dominio, cliente=None, ahora=None, propios=(), parecidos=False, max_candidatos=MAX_CANDIDATOS):
    """Recolecta subdominios y vigencia de certificados de `dominio`, y sus dominios parecidos si `parecidos`.

    `parecidos` consulta en crt.sh %marca% y las variantes de candidatos_parecidos(), que pueden ser de terceros, y
    solo ahí: nunca resuelve su DNS ni les hace peticiones. Aquí va apagado por defecto. Lo prenden los escaneos
    (EN_ESCANEO) y la terminal. Sin esa búsqueda, o si ninguna responde, lookalike_domain queda en sin_cobertura.
    Tampoco se busca nada, y queda igual con un aviso, si el dominio no es su propio dominio registrable (un
    subdominio, o un sufijo de dos niveles que no está en SUFIJOS_DOBLES, como acme.com.gt): sus variantes serían de
    otra marca (_marca). De lo que trae %marca% solo cuenta el nombre con la marca en su dominio registrable.
    `propios` son los otros dominios de la misma empresa, que nunca cuentan como parecidos.
    """
    dominio = dominio.strip().lower().rstrip('.')
    cliente = cliente or ClienteCrtsh()
    ahora = ahora or datetime.now(timezone.utc)
    res = Resultado(dominio, FUENTE)
    if not NOMBRE_VALIDO.match(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res

    # Subdominios: primero la consulta por comodín; si crt.sh no la resuelve, la búsqueda por nombre.
    certs, fallas, consultas = None, [], (('%.' + dominio, {'deduplicate': 'Y'}), (dominio, {}))
    for consulta, extra in consultas:
        try:
            certs = _con_fechas(cliente.consultar(consulta, **extra))
            break
        except CrtshNoResponde as e:
            fallas.append((consulta, e))
    respaldo = certs is None
    completo = not fallas  # sin la búsqueda por nombre ni Cert Spotter a medias llegaron todos los certificados
    sin_revocaciones = False  # el complemento no respondió: no se sabe qué certificado de crt.sh se revocó

    def danados():  # archivos de la grabación que no se pudieron leer hasta ahora (RC-46)
        return list(getattr(cliente, 'danados', ()))
    antes = danados()  # los de crt.sh: si Cert Spotter suma otro, sus páginas no faltan porque no las diera
    if respaldo:  # crt.sh no respondió a ninguna: los certificados vigentes salen de Cert Spotter (#14b)
        try:
            certs, completos = certspotter.certificados(cliente, dominio)
        except FuenteNoResponde as e:
            res.consultas = cliente.consultas
            if danados():  # no hay nada que mostrar, pero por un archivo dañado: ni failed ni completo
                res.avisos += [str(x) for x in [f for _, f in fallas] + [e] if not isinstance(x, GrabacionDanada)]
                res.avisos.append(SIN_LEER)
                res.sin_cobertura = list(CODIGOS)
                return _danada(res, danados())
            res.estado, res.error = 'failed', '%s. %s' % (fallas[-1][1], e)
            return res
        certs = _con_fechas(certs)
        for consulta, e in fallas:  # Cert Spotter ya respondió: grabar la falla no borra la grabación anterior
            cliente.grabar_falla(consulta, e)
        res.avisos += [str(e) for _, e in fallas if not isinstance(e, GrabacionDanada)]
        res.avisos.append(certspotter.AVISO_DANADA if any(isinstance(e, GrabacionDanada) for _, e in fallas)
                          else certspotter.AVISO)
        if not completos and danados() == antes:
            res.avisos.append(certspotter.INCOMPLETO)
        res.sin_cobertura = list(certspotter.SIN_COBERTURA)
        completo = completos  # vencidos y parecidos ya van en sin_cobertura
    else:
        fallidas = dict(fallas)
        for consulta, _ in consultas:  # la falla de hoy se graba (--reproducir repite el aviso) y una vieja se borra
            cliente.grabar_falla(consulta, fallidas.get(consulta))
        if fallas:  # se usó la búsqueda por nombre, que puede no traer todos los subdominios
            falla_comodin = fallas[0][1]
            res.avisos.append(str(falla_comodin) if isinstance(falla_comodin, SinGrabacion) else
                              POR_NOMBRE_DANADA % dominio if isinstance(falla_comodin, GrabacionDanada) else
                              'crt.sh no respondió a %%.%s. Se usó la búsqueda por nombre y pueden faltar subdominios'
                              % dominio)
        try:  # crt.sh no siempre lee todos los logs: Cert Spotter suma los certificados vigentes que le falten (#14b)
            de_cert_spotter, completos = certspotter.certificados(cliente, dominio, **certspotter.COMPLEMENTO)
        except SinGrabacion as e:  # grabación de antes de que #14 consultara siempre Cert Spotter
            res.avisos.append(str(e))
            completo, sin_revocaciones = False, True
        except FuenteNoResponde as e:
            res.avisos.append('%s. %s' % (e, certspotter.SIN_COMPLEMENTO))
            completo, sin_revocaciones = False, True
        else:
            certs = _unir(certs, _con_fechas(de_cert_spotter), dominio)
            if not completos:
                if danados() == antes:  # una página dañada de la grabación no es que Cert Spotter no la diera
                    res.avisos.append(certspotter.INCOMPLETO)
                completo = False  # las revocaciones de las páginas que faltan quedan como residual (README)
    res.consultas = cliente.consultas
    desconocidos = []

    def resuelve(nombre):
        try:
            valor = cliente.resuelve(nombre, control=dominio)
        except SinGrabacion:  # la grabación no trae ese DNS (por ejemplo, es de antes de que crt.sh lo consultara)
            valor = None
        if valor is None and _nombre_grabado('dns:' + nombre) in danados():
            return DNS_DANADO  # su dns_ está dañado: ya lo nombra el aviso DANADA y su vencido no se reporta
        if valor is None:
            desconocidos.append(nombre)
        return valor
    res.activos, res.hallazgos = _subdominios(dominio, certs, ahora, resuelve,
                                              anticipar=getattr(cliente, 'modo', 'vivo') == 'grabar')
    # Un código sin cobertura no trae hallazgos: al reproducir el respaldo meses después, ya vencieron.
    res.hallazgos = [h for h in res.hallazgos if h.codigo not in res.sin_cobertura]
    if not completo:  # pueden faltar certificados: el orquestador solo cierra lo de los que llegaron (#23, RC-55)
        res.revisados = _revisados(dominio, certs, ahora, respaldo, sin_revocaciones)
    vencidos = {h.activo for h in res.hallazgos if h.codigo == 'cert_expired'}
    res.avisos += ['No se pudo comprobar en DNS si %s resuelve. Se reporta su certificado vencido.' % n
                   for n in desconocidos if n in vencidos]

    # Dominios parecidos (#109, RC-226): solo se buscan en crt.sh. Nunca se resuelve su DNS ni se les pide nada.
    respondidas = 0        # búsquedas de parecidos que sí respondieron
    sin_marca = False      # %marca% no respondió: no se sabe qué parecidos por contenido hay
    etiqueta = _marca(dominio) if parecidos and not respaldo else None
    if parecidos and not respaldo and etiqueta is None:  # ninguna consulta: no hay de qué buscar parecidos
        res.avisos.append(SIN_MARCA % dominio)
    if etiqueta is not None:  # con crt.sh caído no se buscan: lookalike_domain queda en sin_cobertura
        propios_set = {registrable(dominio)} | {registrable(p.lower()) for p in propios} | {p.lower() for p in propios}
        por_tipo, sin_respuesta = [], []
        if len(etiqueta) >= 5:  # con etiquetas cortas la búsqueda por contenido trae demasiado ruido
            # Solo cuenta el nombre con la marca en su dominio registrable: olmardo.github.io no es un parecido de
            # github.io. Tampoco cuenta la marca puesta como subdominio de otro dominio (acme.mx.otro.net).
            try:
                por_tipo.append(('contiene_marca',
                                 _con_fechas(cliente.consultar('%' + etiqueta + '%', intentos=INTENTOS_PARECIDOS)),
                                 lambda n, e=etiqueta: e in registrable(n)))
                respondidas += 1
            except CrtshNoResponde as e:
                res.avisos.append(str(e))
                sin_marca = True
        candidatos = [c for c in candidatos_parecidos(dominio, max_candidatos) if c not in propios_set]
        seguidas = 0
        for i, candidato in enumerate(candidatos):
            if seguidas >= FALLAS_SEGUIDAS:
                res.avisos.append('crt.sh saturado: se omitieron %d variantes (%s)' % (
                    len(candidatos) - i, ', '.join(candidatos[i:])))
                sin_respuesta += candidatos[i:]
                break
            try:
                encontrados = cliente.consultar(candidato, intentos=INTENTOS_PARECIDOS, timeout=20,
                                                pausa=PAUSA_PARECIDOS)
                seguidas = 0
                respondidas += 1
            except SinGrabacion as e:  # falta en la grabación: no cuenta como saturación de crt.sh
                res.avisos.append(str(e))
                sin_respuesta.append(candidato)
                continue
            except CrtshNoResponde as e:
                res.avisos.append(str(e))
                sin_respuesta.append(candidato)
                seguidas += 1
                continue
            tipo = 'otro_tld' if candidato.split('.', 1)[0] == etiqueta else 'error_tipografico'
            por_tipo.append((tipo, _con_fechas(encontrados), lambda n, k=candidato: registrable(n) == k))
        if respondidas and not sin_marca:
            res.hallazgos += _parecidos(dominio, por_tipo, propios_set, ahora)
            # Una variante que no respondió no es que ya no tenga certificado: su huella va en omitidos y el orquestador
            # no cierra el parecido que un escaneo anterior dejó abierto, ni guarda uno que nunca se reportó (#23).
            dadas = {h.huella for h in res.hallazgos}
            res.omitidos += [h for h in (_huella('lookalike_domain', dominio, c) for c in sin_respuesta)
                             if h not in dadas and h not in res.omitidos]
    # Sin búsquedas, sin ninguna respuesta o sin la de %marca% no es lo mismo que 0 parecidos: cobertura parcial, sin
    # hallazgos de este código en la corrida, y el orquestador no cierra los que ya estaban abiertos.
    if (not respondidas or sin_marca) and 'lookalike_domain' not in res.sin_cobertura:
        res.sin_cobertura.append('lookalike_domain')
    res.consultas = cliente.consultas
    return _danada(res, danados()) if danados() else res


def _danada(res, archivos):
    """El resultado de una corrida con archivos dañados en la grabación (RC-46): no se sabe qué dejó de verse, así que
    revisados queda en [] y el orquestador no cierra nada de esta fuente en ese escaneo (con None lo daría por completo
    y cerraría lo que no salió). Queda la excepción de RC-55, que no depende de revisados: un por vencer cuya fecha ya
    pasó se cierra en toda corrida, y el aviso lo dice. El aviso que nombra los archivos va primero."""
    res.revisados, res.sin_revisar = [], None
    nombres = ', '.join(archivos[:MAX_DANADOS])
    if len(archivos) > MAX_DANADOS:
        nombres += ' y %d más' % (len(archivos) - MAX_DANADOS)
    res.avisos.insert(0, DANADA % (_cuantos(len(archivos), 'archivo dañado', 'archivos dañados'), nombres))
    return res


# ---------------------------------------------------------------- salida para personas

def _dia(fecha):
    d = _fecha(fecha) if isinstance(fecha, str) else fecha
    return '%d %s %d' % (d.day, MESES[d.month - 1], d.year)


def _zona(fecha):
    """'UTC' o el desfase de una fecha con zona, como 'UTC-06:00'. Dentro del contenedor de la API la hora local es UTC."""
    z = fecha.strftime('%z')
    return 'UTC' if z in ('', '+0000') else 'UTC%s:%s' % (z[:3], z[3:5])


def _cuantos(n, singular, plural):
    return '%d %s' % (n, singular if n == 1 else plural)


def resumen(res, cliente=None, maximo_activos=20):
    """Líneas en español para leer el resultado en una terminal o en una demo."""
    if certspotter.AVISO in res.avisos:
        origen = 'Cert Spotter (crt.sh no respondió)'
    elif certspotter.AVISO_DANADA in res.avisos:
        origen = 'Cert Spotter (la grabación de crt.sh está dañada)'
    elif SIN_LEER in res.avisos:
        origen = 'grabación dañada'
    elif res.estado != 'succeeded' or any(a.endswith(certspotter.SIN_COMPLEMENTO) or
                                          a.startswith(SIN_GRABACION + certspotter.PREFIJO) for a in res.avisos):
        origen = 'crt.sh'
    else:
        origen = 'crt.sh y Cert Spotter'
    cabecera = '%s · %s · %s' % (res.dominio, origen, res.estado)
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
        # La cabecera usa la hora local y las fechas de vencimiento van en UTC, como en los certificados.
        lineas.append(_cuantos(len(res.activos), 'activo', 'activos') + ', con su vencimiento en UTC:')
        for a in res.activos[:maximo_activos]:
            linea = '  %s · vence %s' % (a.valor, _dia(a.atributos['vence']))
            lineas.append(linea + (' · comodín' if a.atributos.get('comodin') else ''))
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
    elif res.estado == 'succeeded':
        lineas.append('Sin hallazgos.')
    if res.sin_cobertura:  # no es lo mismo que 0 hallazgos
        nombres = ['%s (%s)' % (CODIGO_ES.get(c, c), c) for c in res.sin_cobertura]
        lineas.append('Cobertura parcial: no se revisaron %s.' % (
            nombres[0] if len(nombres) == 1 else ', '.join(nombres[:-1]) + ' ni ' + nombres[-1]))

    faltan = [a[len(SIN_GRABACION):] for a in res.avisos if a.startswith(SIN_GRABACION)]
    if faltan:
        uno = len(faltan) == 1
        lineas.append('%s %s: %s. Se %s con --grabar --completar.' % (
            'Falta' if uno else 'Faltan', _cuantos(len(faltan), 'respuesta grabada', 'respuestas grabadas'),
            ', '.join(faltan), 'completa' if uno else 'completan'))
    lineas += ['aviso: %s' % a for a in res.avisos if not a.startswith(SIN_GRABACION)]
    return lineas


def carpeta_de(dominio):
    """Carpeta de las respuestas grabadas de un dominio (la usan el CLI y el plugin)."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' consulta crt.sh, 'reproducir' usa la grabación del dominio y
    'grabar' empieza una grabación nueva, igual que --grabar."""
    return ClienteCrtsh(modo=modo, carpeta=carpeta_de(dominio), nueva=(modo == 'grabar'))


def _main(argv=None):
    # En Windows, cuando la salida no es la consola (Git Bash, una tubería), Python usa cp1252 y los acentos se rompen.
    if (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    p = argparse.ArgumentParser(
        description='Subdominios, certificados y dominios parecidos desde crt.sh',
        epilog='La terminal no sabe qué otros dominios son de la empresa y no los excluye: uno propio, como la versión '
               '.mx del mismo nombre, puede salir como dominio parecido. En un escaneo el orquestador sí los excluye.')
    p.add_argument('dominio')
    p.add_argument('--grabar', action='store_true',
                   help='empieza una grabación nueva en cirdan/recolectores/respuestas_grabadas/crtsh/<dominio>/')
    p.add_argument('--completar', action='store_true', help='con --grabar, solo consulta lo que aún no está grabado')
    p.add_argument('--reproducir', action='store_true', help='usa solo las respuestas grabadas, sin red')
    buscar = p.add_mutually_exclusive_group()
    buscar.add_argument('--con-parecidos', action='store_true',
                        help='busca dominios parecidos: consulta en crt.sh %%marca%% y las variantes de '
                             'candidatos_parecidos(), solo en los certificados. Ya es lo predeterminado y se acepta '
                             'igual que antes')
    buscar.add_argument('--sin-parecidos', action='store_true',
                        help='no busca dominios parecidos: lookalike_domain queda sin cobertura')
    p.add_argument('--json', action='store_true', help='imprime el resultado completo en JSON')
    a = p.parse_args(argv)
    if a.completar and not a.grabar:
        p.error('--completar va junto con --grabar')
    if a.grabar and a.reproducir:
        p.error('--grabar y --reproducir no van juntos')
    modo = 'grabar' if a.grabar else 'reproducir' if a.reproducir else 'vivo'
    dominio = a.dominio.strip().lower().rstrip('.')
    if not NOMBRE_VALIDO.match(dominio):  # también evita que '..' o '/' saquen la carpeta de respuestas_grabadas
        p.error('dominio inválido: %s' % a.dominio)
    # Cada dominio graba en su carpeta. --grabar la vacía y marca el inicio en cuanto crt.sh o Cert Spotter
    # responde, así lo que no se grabe hoy aparece como faltante y nunca se mezcla con días anteriores. Si ninguno
    # responde, la grabación anterior queda intacta. --completar solo reutiliza lo grabado desde esa marca.
    carpeta = carpeta_de(dominio)
    marca = carpeta / MARCA
    desde = None
    if a.completar:
        if not marca.exists():
            p.error('--completar continúa una grabación de este dominio, primero corre --grabar')
        desde = Grabadora.inicio(carpeta)
        if _archivo_grabado(FALLA + dominio, carpeta).exists():  # solo se graba si se usó Cert Spotter
            print('aviso: esta grabación es el respaldo de Cert Spotter. Si crt.sh responde, sus certificados se unen a '
                  'los de Cert Spotter y la grabación deja de ser respaldo. Las páginas de Cert Spotter se quedan como '
                  'se grabaron: para tener las de hoy, corre --grabar sin --completar.', file=sys.stderr)
    cliente = ClienteCrtsh(modo=modo, carpeta=carpeta, completar=a.completar, desde=desde,
                           nueva=a.grabar and not a.completar)
    res = recolectar(dominio, cliente, parecidos=not a.sin_parecidos)
    if a.json:
        print(json.dumps(res.a_dict(), ensure_ascii=False, indent=1))
    else:
        print('\n'.join(resumen(res, cliente)))
    if a.grabar and any(x.endswith(certspotter.SIN_COMPLEMENTO) or x == certspotter.INCOMPLETO for x in res.avisos):
        print('aviso: Cert Spotter no quedó grabado completo y pueden faltar sus certificados. Si fue un 429 o un error '
              'de red, repite con --grabar --completar cuando vuelva a responder (con 429, después de su Retry-After).',
              file=sys.stderr)
    return codigo_salida(res)


def codigo_salida(res):
    """0 bien, 1 si el resultado queda en 'failed', 2 si quedan avisos."""
    return 1 if res.estado == 'failed' else 2 if res.avisos else 0


if __name__ == '__main__':
    sys.exit(_main())
