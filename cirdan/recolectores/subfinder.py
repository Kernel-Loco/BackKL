"""Subdominios pasivos del índice público de Common Crawl (#14b, RC-184), en la fuente subfinder.

La fuente se llama subfinder porque nació para correr el binario de ProjectDiscovery con sus fuentes pasivas. El 15 nov,
de sus 20 fuentes solo commoncrawl pasó la revisión de términos (decisión 6 de docs/servicios_externos.md), y el
commoncrawl de subfinder 2.17.0 revisa un solo índice por año de los últimos 5, en orden al azar, y deja de buscar en el
primer 404 'No Captures found'. Con eso un dominio chico casi nunca daba nombres, y una corrida vacía no se distinguía
de una que no buscó en todos los años. Desde el 15 nov este recolector ya no corre el binario: pide el CDX de Common
Crawl directo, con transporte.py (TLS verificado, sin redirecciones, solo direcciones públicas y el puerto 443). La fila
de data_sources, la carpeta de grabaciones y los activos siguen iguales. El binario sigue en la imagen sin usarse.

Qué pide, sin tocar los servidores del dominio:
- collinfo.json, la lista de índices de Common Crawl, y de ahí toma los INDICES más recientes (unos 12 son un año),
- el CDX de cada uno con url=*.<dominio>, solo el campo url y a lo más LIMITE_FILAS capturas, con PAUSA segundos entre
  petición y petición, porque Common Crawl pide bajar el ritmo y bloquea la IP 24 h si no (https://commoncrawl.org/faq).
  La pausa y el turno (Ritmo) son de todo el proceso: dos escaneos a la vez en la API no le pegan más rápido.
De cada captura solo se guarda el nombre del host, nunca la URL.

Un 404 con 'No Captures found' es un índice sin capturas del dominio y no corta la búsqueda: se revisan todos. Un
índice cuyo CDX da 500, 502 o 504 o no termina en TIMEOUT_PETICION (el 16 nov CC-MAIN-2026-43 dio 504 dos veces en una
hora) se salta y se sigue con los demás: el resultado lleva el aviso SALTADOS con cuáles y por qué, revisados con los
que sí se revisaron y sin_revisar con los saltados, así el escaneo termina 'partial' (stats.sources_partial), como
ct_logs cuando falta una variante de dominios parecidos. Si no se revisó ninguno, FuenteNoResponde. Cualquier otra
respuesta (un 503 o un 429, que son la señal de Common Crawl de bajar el ritmo, un 404 sin ese texto, una red caída, una
redirección, una respuesta de más de MAX_BYTES_CDX, un 200 sin ninguna captura legible o cualquier falla de
collinfo.json) deja la corrida en FuenteNoResponde, sin grabar. Así una corrida que termina dice qué índices revisó
completos, y 0 nombres en ellos es un resultado de verdad: se graba, con el aviso SIN_CAPTURAS si ninguno tenía
capturas. Toda la corrida tiene MAX_SEGUNDOS, y cada petición a lo más TIMEOUT_PETICION. Una corrida con índices
saltados también se graba (con su aviso) y reemplaza la grabación anterior del dominio, como cualquier --grabar.

Modos: 'vivo' consulta; 'grabar' además guarda el resultado ya leído (líneas, avisos e índices) en
cirdan/recolectores/respuestas_grabadas/subfinder/<dominio>/ con la Grabadora del contrato (#13); 'reproducir' solo lee
esa grabación. Sin grabación del dominio, reproducir sale succeeded con el aviso SIN_GRABACION_DOMINIO y sin activos,
como github.py: no es una fuente caída y el escaneo de una demo no queda partial por eso. Un archivo de la grabación
que no se puede leer sí es FuenteNoResponde. No tiene línea de comandos propia. En la imagen, el usuario cirdan es dueño
de respuestas_grabadas/subfinder/ y de nada más (Dockerfile), así que puede grabar dentro del contenedor.

Consultas del límite diario (#13b): peticiones HTTP, como en las demás fuentes. MAX_CONSULTAS es collinfo.json más un
CDX por índice, sin reintentos dentro de la corrida (el orquestador la reintenta a 1, 5 y 25 minutos).
`consultas` cuenta las que sí se hicieron, y 0 al reproducir.
"""
import http.client
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from cirdan.recolectores import transporte
from cirdan.recolectores.contrato import AGENTE
from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import (NOMBRE_VALIDO, Activo, FuenteNoResponde, Grabadora, Resultado, SinGrabacion,
                                          en_alcance_nombre)

FUENTE = 'subfinder'
CARPETA_GRABADAS = RAIZ_GRABADAS / 'subfinder'

# Solo activos: ningún código de regla (pruebas/test_catalogo_reglas.py acepta el dict vacío).
CODIGOS = {}

# La única fuente que pasó la regla de la decisión 6 de docs/servicios_externos.md (sus términos publicados permiten el
# uso automático y mostrar sus datos a terceros). Va en 'origen' de cada activo.
ORIGEN = 'commoncrawl'
COLLINFO = 'https://index.commoncrawl.org/collinfo.json'
CDX = 'https://index.commoncrawl.org/%s-index?'   # el id del índice, que antes pasa por ID_INDICE
ID_INDICE = re.compile(r'CC-MAIN-[0-9]{4}-[0-9]{2}')
INDICES = 12                 # los índices más recientes que se revisan: unos 12 son un año
LIMITE_FILAS = 5000          # capturas por índice (limit del CDX). Si llega, el aviso RECORTADO
PAUSA = 1.0                  # segundos entre petición y petición
TIMEOUT_PETICION = 30        # segundos de cada petición, de getaddrinfo al último bloque (transporte.descargar)
MAX_SEGUNDOS = 300           # segundos de toda la corrida, pausas incluidas
MAX_BYTES_COLLINFO = 1 << 20
MAX_BYTES_CDX = 4 << 20      # 5000 capturas de solo la URL caben con holgura
MAX_CONSULTAS = 1 + INDICES  # collinfo.json más un CDX por índice: peticiones HTTP de una corrida (#13b)
CONSULTA = 'subfinder:'      # consulta de la grabadora: subfinder_<dominio>.json
SIN_CAPTURAS = 'subfinder: Common Crawl no tiene capturas de este dominio en sus últimos %d índices'
SIN_GRABACION_DOMINIO = 'subfinder: no hay grabación de Common Crawl de este dominio, no se revisó Common Crawl'
RECORTADO = 'subfinder: %s al tope de %d capturas, la lista puede estar incompleta'
SALTADOS = 'subfinder: Common Crawl no respondió en %s, se revisaron los demás índices'
SALTABLES = (500, 502, 504)   # el servidor de ese índice falló o no contestó a tiempo: se salta (no 503 ni 429)
NO_CAPTURAS = b'No Captures found'   # el cuerpo del 404 del CDX cuando el índice no tiene capturas del dominio
NOMBRE_FUENTE = re.compile(r'[a-z0-9_-]{1,40}')
FALLAS = (OSError, ValueError, http.client.HTTPException, transporte.PlazoVencido, transporte.Redirigida)


class SinCapturas(Exception):
    """El 404 'No Captures found' del CDX: el índice no tiene capturas del dominio."""


def _saltable(error):
    """Un 500, 502 o 504 o el plazo de la petición vencido: una falla de ese índice, no la señal de bajar el ritmo
    (503 o 429) ni una respuesta rara."""
    return isinstance(error, transporte.PlazoVencido) or (isinstance(error, urllib.error.HTTPError) and
                                                           error.code in SALTABLES)


class Ritmo:
    """Una petición a la vez a Common Crawl en todo el proceso y PAUSA entre el fin de una y el inicio de la siguiente,
    aunque sean de corridas distintas: la API corre cada escaneo en su propio hilo (cirdan/api/escaneos.py). Entre
    procesos no se coordina: la línea de comandos que corre a la vez que la API lleva su propio ritmo."""

    def __init__(self):
        self.candado = threading.Lock()
        self.ultima = None   # cuándo terminó la última petición, en el cronómetro del cliente (time.monotonic)


RITMO = Ritmo()   # el de todos los clientes del proceso


def _descargar(url, plazo, tope, cronometro):
    """El cuerpo de la respuesta a `url`, de a lo más `tope` bytes y todo antes de `plazo` (un instante de
    `cronometro`). La única función que hace HTTP. Lanza SinCapturas con el 404 'No Captures found'. Cualquier otra
    falla sale como la da transporte.descargar (HTTPError, OSError, PlazoVencido, Redirigida o ValueError)."""
    req = urllib.request.Request(url, headers={'User-Agent': AGENTE})
    try:
        return transporte.descargar(req, plazo, tope, cronometro)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            try:
                cuerpo = e.read(4096) or b''
            except (OSError, ValueError, http.client.HTTPException):
                cuerpo = b''
            if NO_CAPTURAS in cuerpo:
                raise SinCapturas() from None
        raise


def url_cdx(indice, dominio):
    """La consulta del CDX de un índice para el dominio y sus subdominios, solo con la URL de cada captura."""
    return CDX % indice + urllib.parse.urlencode({'url': '*.' + dominio, 'output': 'json', 'fl': 'url',
                                                  'limit': LIMITE_FILAS})


def indices(cuerpo):
    """Los ids de los INDICES índices más recientes de collinfo.json, del más nuevo al más viejo. Solo los que tienen
    la forma CC-MAIN-AAAA-SS: la URL del CDX se arma aquí, nunca se toma de la respuesta."""
    try:
        lista = json.loads(cuerpo.decode('utf-8', 'replace'))
    except ValueError:
        raise FuenteNoResponde('subfinder: collinfo.json de Common Crawl no es JSON') from None
    if not isinstance(lista, list):
        raise FuenteNoResponde('subfinder: collinfo.json de Common Crawl no es una lista')
    ids = {c['id'] for c in lista if isinstance(c, dict) and isinstance(c.get('id'), str) and
           ID_INDICE.fullmatch(c['id'])}
    if not ids:
        raise FuenteNoResponde('subfinder: collinfo.json de Common Crawl no trae ningún índice')
    return sorted(ids, reverse=True)[:INDICES]


def hosts(cuerpo):
    """(hosts, filas, raras) de una respuesta del CDX: un JSON por línea con su 'url'. Solo el nombre del host."""
    nombres, filas, raras = set(), 0, 0
    for texto in cuerpo.decode('utf-8', 'replace').splitlines():
        texto = texto.strip()
        if not texto:
            continue
        filas += 1
        try:
            captura = json.loads(texto)
            host = urllib.parse.urlsplit(captura['url']).hostname if isinstance(captura, dict) else None
        except (ValueError, KeyError, TypeError, AttributeError):
            host = None
        if isinstance(host, str) and host:
            nombres.add(host)
        else:
            raras += 1
    return nombres, filas, raras


def _motivo(error):
    """Un texto corto de la falla, sin el cuerpo ni la URL de la respuesta."""
    if isinstance(error, urllib.error.HTTPError):
        return 'HTTP %s' % error.code
    return type(error).__name__


def _cuantos(n, singular, plural):
    return '%d %s' % (n, singular if n == 1 else plural)


class ClienteSubfinder:
    """Pide el CDX de Common Crawl y, según el modo, graba o reproduce el resultado ya leído con la Grabadora (#13).

    `descargar(url, plazo, tope, cronometro)`, `cronometro`, `dormir` y `ritmo` se inyectan en las pruebas. Por
    omisión son _descargar, time.monotonic, time.sleep y RITMO. `reloj` es el de la Grabadora (fecha de grabación).
    `consultas` suma cada petición HTTP que sí se hizo."""

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, descargar=None, nueva=False, reloj=None,
                 cronometro=None, dormir=None, ritmo=None):
        self.modo = modo
        self.grabadora = Grabadora(carpeta, modo, nueva=nueva, reloj=reloj)
        self.descargar = descargar or _descargar
        self.cronometro = cronometro or time.monotonic
        self.dormir = dormir or time.sleep
        self.ritmo = ritmo or RITMO
        self.consultas = 0

    @property
    def leidas(self):
        """(archivo, fecha de grabación) de cada respuesta tomada del disco."""
        return self.grabadora.leidas

    def _pedir(self, url, tope, fin, que):
        """El cuerpo de una petición, con lo que quede de la corrida como plazo. `que` nombra la petición en el error.
        Espera su turno en `ritmo` (a lo más hasta `fin`) y, si la última petición del proceso terminó hace menos de
        PAUSA, lo que falte para completarla."""
        sin_tiempo = FuenteNoResponde('subfinder: Common Crawl no terminó en %d s (faltó %s)' % (MAX_SEGUNDOS, que))
        if not self.ritmo.candado.acquire(timeout=max(0.0, fin - self.cronometro())):
            raise sin_tiempo
        try:
            if self.ritmo.ultima is not None:
                falta = self.ritmo.ultima + PAUSA - self.cronometro()
                if falta > 0:
                    self.dormir(min(falta, PAUSA))
            ahora = self.cronometro()
            if ahora >= fin:
                raise sin_tiempo
            self.consultas += 1
            try:
                return self.descargar(url, min(ahora + TIMEOUT_PETICION, fin), tope, self.cronometro)
            except FALLAS as e:
                error = FuenteNoResponde('subfinder: Common Crawl no respondió en %s (%s)' % (que, _motivo(e)))
                error.motivo, error.saltable = _motivo(e), _saltable(e)   # _consultar decide si salta el índice
                raise error from None
            finally:
                self.ritmo.ultima = self.cronometro()
        finally:
            self.ritmo.candado.release()

    def _consultar(self, dominio):
        fin = self.cronometro() + MAX_SEGUNDOS
        try:
            ids = indices(self._pedir(COLLINFO, MAX_BYTES_COLLINFO, fin, 'collinfo.json'))
        except SinCapturas:
            raise FuenteNoResponde('subfinder: Common Crawl no respondió en collinfo.json (HTTP 404)') from None
        nombres, recortados, raras, con_capturas, revisados, saltados = set(), [], 0, 0, [], []
        for indice in ids:
            try:
                cuerpo = self._pedir(url_cdx(indice, dominio), MAX_BYTES_CDX, fin, indice)
            except SinCapturas:
                revisados.append(indice)
                continue
            except FuenteNoResponde as e:
                # Sin tiempo no se salta: ese índice faltó porque la corrida no terminó.
                if not getattr(e, 'saltable', False) or self.cronometro() >= fin:
                    raise
                saltados.append('%s (%s)' % (indice, e.motivo))
                continue
            encontrados, filas, malas = hosts(cuerpo)
            if malas == filas:   # un 200 vacío o sin ninguna captura legible: no se sabe qué hay, no se graba
                raise FuenteNoResponde('subfinder: Common Crawl no dio ninguna captura legible en %s' % indice)
            con_capturas += 1
            revisados.append(indice)
            nombres |= encontrados
            raras += malas
            if filas >= LIMITE_FILAS:
                recortados.append(indice)
        if not revisados:
            raise FuenteNoResponde('subfinder: Common Crawl no respondió en ninguno de sus %d índices (%s)' % (
                len(ids), ', '.join(saltados)))
        avisos = []
        if saltados:
            avisos.append(SALTADOS % ', '.join(saltados))
        if not con_capturas:
            avisos.append(SIN_CAPTURAS % len(revisados))
        if recortados:
            avisos.append(RECORTADO % ('el índice %s llegó' % recortados[0] if len(recortados) == 1 else
                                       '%d índices llegaron' % len(recortados), LIMITE_FILAS))
        if raras:
            avisos.append('subfinder: se %s %s del CDX que no se %s leer' % (
                'saltó' if raras == 1 else 'saltaron', _cuantos(raras, 'captura', 'capturas'),
                'pudo' if raras == 1 else 'pudieron'))
        lineas = [{'host': h, 'input': dominio, 'sources': [ORIGEN]} for h in sorted(nombres)]
        datos = {'lineas': lineas, 'avisos': avisos, 'indices': ids}
        if saltados:
            datos['revisados'] = revisados
        return datos

    def enumerar(self, dominio):
        """{'lineas', 'avisos', 'indices'} de Common Crawl para el dominio, más 'revisados' si se saltó algún índice.
        Sale del disco al reproducir (SinGrabacion si no hay grabación) y se graba al grabar. Si la corrida queda en
        FuenteNoResponde no se graba nada, así la grabación anterior queda intacta. Un índice saltado no la deja así."""
        consulta = CONSULTA + dominio
        del_disco, datos = self.grabadora.de_disco(consulta)
        if del_disco:
            if not (isinstance(datos, dict) and isinstance(datos.get('lineas'), list) and
                    isinstance(datos.get('avisos'), list) and _revisados_validos(datos)):
                raise FuenteNoResponde('la grabación de subfinder de %s no se puede leer' % dominio)
            return datos
        datos = self._consultar(dominio)
        self.grabadora.guardar(consulta, datos)
        return datos


def _revisados_validos(datos):
    """'revisados' de una grabación: falta, o es una parte sin repetir de sus 'indices', con al menos uno."""
    if 'revisados' not in datos:
        return True
    rev, ids = datos['revisados'], datos.get('indices')
    return (isinstance(rev, list) and isinstance(ids, list) and rev and len(set(map(str, rev))) == len(rev) and
            all(isinstance(i, str) and ID_INDICE.fullmatch(i) and i in ids for i in rev) and
            all(isinstance(i, str) and ID_INDICE.fullmatch(i) for i in ids) and len(rev) < len(ids))


def _normalizar(nombre):
    nombre = nombre.strip().lower().rstrip('.')
    while nombre.startswith('*.'):
        nombre = nombre[2:]
    return nombre


def subdominios(dominio, lineas):
    """(activos, fuera, invalidos): un Activo 'subdomain' por nombre, sin repetir y con las fuentes juntas.

    Cada nombre va en minúsculas, sin punto final y sin '*.' delante. El propio dominio no sale como subdominio.
    `fuera` y `invalidos` cuentan los nombres que se descartaron por no ser del dominio o por no pasar la validación
    de nombres del contrato."""
    origen, fuera, invalidos = {}, set(), set()
    for linea in lineas:
        if not isinstance(linea, dict) or not isinstance(linea.get('host'), str):
            continue
        nombre = _normalizar(linea['host'])
        if nombre == dominio:
            continue
        if not NOMBRE_VALIDO.fullmatch(nombre):
            invalidos.add(nombre)
            continue
        if not en_alcance_nombre(nombre, dominio):
            fuera.add(nombre)
            continue
        fuentes = linea.get('sources') if isinstance(linea.get('sources'), list) else []
        origen.setdefault(nombre, set()).update(f for f in fuentes if isinstance(f, str) and NOMBRE_FUENTE.fullmatch(f))
    activos = [Activo('subdomain', n, {'fuente': FUENTE, 'origen': sorted(origen[n])}) for n in sorted(origen)]
    return activos, len(fuera), len(invalidos)


def carpeta_de(dominio):
    """Carpeta de la grabación de un dominio."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' consulta Common Crawl, 'reproducir' usa la grabación del dominio y
    'grabar' empieza una grabación nueva."""
    return ClienteSubfinder(modo=modo, carpeta=carpeta_de(dominio), nueva=(modo == 'grabar'))


def recolectar(dominio, cliente=None, ahora=None, propios=()):
    """Subdominios de `dominio` según el índice de Common Crawl. `ahora` y `propios` no se usan: Common Crawl no da
    fechas de los nombres ni busca dominios parecidos."""
    dominio = dominio.strip().lower().rstrip('.')
    res = Resultado(dominio, FUENTE)
    if not NOMBRE_VALIDO.fullmatch(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res
    cliente = cliente or crear_cliente('vivo', dominio)
    try:
        datos = cliente.enumerar(dominio)
    except SinGrabacion:  # reproducir sin grabación del dominio: no se revisó, no es una caída
        res.avisos.append(SIN_GRABACION_DOMINIO)
        return res
    finally:
        res.consultas = cliente.consultas
    res.avisos += [a for a in datos['avisos'] if isinstance(a, str)]
    if 'revisados' in datos:   # se saltó algún índice: el escaneo termina 'partial' (contrato, #23)
        res.revisados = list(datos['revisados'])
        res.sin_revisar = [i for i in datos['indices'] if i not in datos['revisados']]
    res.activos, fuera, invalidos = subdominios(dominio, datos['lineas'])
    if fuera:  # cuántos, no cuáles: pueden ser de terceros
        res.avisos.append('subfinder: %s fuera del dominio' % _descartados(fuera))
    if invalidos:
        res.avisos.append('subfinder: %s que no %s' % (_descartados(invalidos), 'es un nombre de dominio válido'
                                                         if invalidos == 1 else 'son nombres de dominio válidos'))
    return res


def _descartados(n):
    return 'se descartó 1 nombre' if n == 1 else 'se descartaron %d nombres' % n
