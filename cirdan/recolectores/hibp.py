"""Recolector de correos del dominio en brechas públicas con Have I Been Pwned, API v3 (#19, RC-54).

Solo consulta el dominio autorizado y los correos de ese dominio, con la llave de la plataforma (plan Core 1, cifrada
en data_sources.api_key_enc, cirdan/recolectores/llaves.py). HIBP nunca da contraseñas: da el alias del correo y el
nombre de la brecha, y de cada brecha su fecha y qué clases de datos se filtraron. Aquí solo se guarda ese hecho.
Nunca la descripción de la brecha, su número de cuentas, el logo ni nada más.

1. GET /breacheddomain/{dominio}: alias -> nombres de brecha de todo el dominio. Pide que el dominio esté verificado
   en el panel de HIBP. 404 es que ningún correo del dominio sale en una brecha: corrida completa, sin hallazgos.
   403 es dominio sin verificar o sin acceso: se pasa al paso 2.
2. Si dio 403: GET /breachedaccount/{correo}?truncateResponse=false, uno por uno, con los correos que el orquestador
   pasa en `correos` (PIDE_CORREOS, orquestador.CORREOS_SQL): los de email_in_public_commits de GitHub (#16) y los
   del dominio que vio identidad (#20, RC-56) desde su última corrida completa, cada rama solo si la carta autoriza
   su actividad. Hasta MAX_CORREOS, en el orden que los da el orquestador: primero los que nunca se consultaron y
   luego los que hace más que no se consultan (attributes.hibp_consultado, que se pone a cada correo consultado),
   así el tope rota entre escaneos. El aviso de los que sobran cuenta sobre `correos_total`. 404 es sin brechas.
   Esta búsqueda ve solo esos correos y no todo el dominio: la corrida siempre es parcial (revisados con los correos
   revisados) y nunca cierra un hallazgo de la búsqueda por dominio.
3. Con el paso 1, GET /breach/{nombre} (sin llave) da fecha y clases de datos de cada brecha, una vez por nombre, hasta
   MAX_BRECHAS. Una brecha sin sus datos queda sin revisar (revisados con las que sí).

Un hallazgo por brecha, en el dominio, con su clave en el nombre de la brecha y la huella de (fuente, dominio, nombre),
así el mismo hallazgo pasa de breach_exposure a breach_exposure_old al cumplir un año sin duplicarse. El código sale de
las clases de datos y de la fecha (los textos de la migración 003):
- breach_exposure: con contraseñas, preguntas de seguridad u otros datos de acceso (DATOS_DE_ACCESO) y menos de un año
  de la brecha al detectarla. Sin fecha cuenta como reciente.
- breach_exposure_old: con datos de acceso y más de un año.
- breach_exposure_no_passwords: sin datos de acceso.
Los correos van como activos email y en la evidencia (emails, emails_exposed). La evidencia lleva la atribución que
pide la licencia CC BY 4.0 de HIBP (ATRIBUCION).

Brechas que no cuentan: las fabricadas (IsFabricated), las listas de spam (IsSpamList) y las retiradas (IsRetired). Las
sensibles (IsSensitive, un sitio de salud, religión o citas) tampoco se ligan a un correo: su nombre puede revelar un
dato sensible de la persona y eso espera la revisión legal (docs/politica_seguridad_privacidad.md, sección 5.3, punto
5). Solo se cuentan en un aviso, sin nombre ni correo.

Sin llave, o con la llave rechazada (401), no consulta nada y la corrida es 'succeeded' con los 3 códigos en
sin_cobertura y sin_llave: 'Sin cobertura de HIBP', nunca 0. No es 'failed', porque un reintento a 1, 5 y 25 minutos
no trae la llave y atrasaría el escaneo. Sin correos que consultar (403 y ninguno de GitHub ni de identidad), igual
pero sin sin_llave.

Ritmo: 10 consultas por minuto con llave (Core 1, data_sources.rate_limit_per_min), así que hay PAUSA segundos entre
una y otra. Un 429 espera su Retry-After y lo vuelve a intentar dentro del tope de la corrida. Si pide más de
MAX_ESPERA, no se reintenta: la consulta queda sin respuesta.
Ninguna consulta empieza después de TIEMPO_CORRIDA. La llave va solo en la cabecera hibp-api-key: nunca en la URL, la
grabación, un aviso ni un error. Las peticiones van por transporte.descargar: sin redirecciones ni proxies.

Al grabar se guarda solo lo reducido de cada respuesta (limpiar_*), en respuestas_grabadas/hibp/<dominio>/, que no va
en git ni en la imagen (.dockerignore). Cada correo y cada alias quedan solo con las brechas que cuentan: las sensibles
y las descartadas no se graban ligadas a un correo. Un 401 o un 429 no se graban. Al reproducir no se usa la llave.
"""
import hashlib
import http.client
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone

from cirdan.exportar import ATRIBUCION_HIBP
from cirdan.ml import caracteristicas as rubrica
from cirdan.recolectores import contrato, transporte
from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import (Activo, FuenteNoResponde, Grabadora, Hallazgo, Resultado, SinGrabacion,
                                          en_alcance_nombre)

FUENTE = 'hibp'
CARPETA_GRABADAS = RAIZ_GRABADAS / 'hibp'

# Código de regla -> severidad base de su regla (semillas 001 y 004).
# pruebas/test_catalogo_reglas.py revisa que coincida.
CODIGOS = {'breach_exposure': 'critical', 'breach_exposure_old': 'high', 'breach_exposure_no_passwords': 'medium'}
SIN_LLAVE = tuple(CODIGOS)      # todo HIBP pide la llave
PIDE_CORREOS = True             # el orquestador pasa `correos`: los de GitHub (#16) e identidad (#20) del dominio
PIDE_LLAVE = True               # el orquestador pasa `llave` en vivo y al grabar (llaves.leer)

URL = 'https://haveibeenpwned.com/api/v3/'
SITIO = 'https://haveibeenpwned.com'
ATRIBUCION = ATRIBUCION_HIBP
AGENTE = contrato.AGENTE

CONSULTA_DOMINIO = 'dominio'
MAX_CORREOS = 25        # correos que se consultan uno por uno. Core 1 da hasta 25 correos con brechas por dominio
MAX_BRECHAS = 40        # brechas del dominio cuyos datos se piden
MAX_ALIAS = 500         # alias que se leen de la búsqueda por dominio
MAX_CORREOS_EVIDENCIA = 50
MAX_CLASES = 40         # clases de datos por brecha
MAX_TEXTO = 120         # caracteres del nombre y el título de una brecha
INTENTOS = 3            # intentos por consulta, con los 429
ESPERAS = (5, 15)       # segundos entre intentos tras una falla de red o un 5xx
PAUSA = 6.0             # segundos entre consultas con llave: 10 por minuto
PAUSA_SIN_LLAVE = 1.5   # segundos entre consultas de /breach, que no lleva llave
MAX_ESPERA = 60         # lo más que se espera un Retry-After
TIEMPO_CORRIDA = 360    # segundos de toda la corrida: ninguna consulta empieza después
TIMEOUT = 15            # segundos por petición
MAX_BYTES = 2 * 1024 * 1024
DIAS_RECIENTE = 365

# Toda consulta de una corrida, con sus intentos: 1 por dominio, los correos o las brechas (nunca las dos), y lo que
# reserva el límite diario (#13b).
MAX_CONSULTAS = (1 + max(MAX_CORREOS, MAX_BRECHAS)) * INTENTOS

# Clases de datos de HIBP que dan acceso a una cuenta (los nombres que usa HIBP en DataClasses)
DATOS_DE_ACCESO = frozenset({
    'Passwords', 'Password hints', 'Historical passwords', 'Security questions and answers', 'Auth tokens', 'PINs',
    'Encrypted keys', 'Private keys', 'Session tokens',
})

SIN_LLAVE_AVISO = 'Sin cobertura de HIBP: falta la llave de la API'
LLAVE_RECHAZADA = 'Sin cobertura de HIBP: la API rechazó la llave (401)'
SIN_CORREOS = ('Sin cobertura de HIBP: el dominio no está verificado en HIBP (403) y no hay correos del dominio que '
               'consultar uno por uno')
SIN_GRABACION_DOMINIO = 'Sin cobertura de HIBP: no hay grabación de HIBP de este dominio'
POR_CORREO = ('hibp: el dominio no está verificado en HIBP (403): se consultaron uno por uno %d de %d correos de '
              'GitHub y de identidad, no todo el dominio')
SOBRAN_CORREOS = 'hibp: %d correos quedaron sin consultar por el tope de %d'
SOBRAN_BRECHAS = 'hibp: %d brechas quedaron sin revisar por el tope de %d'
SIN_DATOS_BRECHA = 'hibp: %d brechas sin sus datos (fecha y clases), quedan sin revisar'
CORREO_SIN_RESPUESTA = 'hibp: %d correos sin respuesta, quedan sin revisar'
SENSIBLES = ('hibp: %d brechas sensibles no se ligan a ningún correo hasta la revisión legal (política de privacidad, '
             'sección 5.3, punto 5)')
DESCARTADAS = 'hibp: %d brechas fabricadas, de spam o retiradas no cuentan'

# Una llave de API: solo ASCII visible, sin espacios ni saltos de línea, que irían a la cabecera (y a un error de
# http.client con su valor). La de HIBP es de 32 caracteres hexadecimales.
LLAVE_VALIDA = re.compile(r'^[!-~]{16,256}$')
LLAVE_MAL_FORMADA = 'Sin cobertura de HIBP: la llave guardada no tiene la forma de una llave de API'
ALIAS_VALIDO = re.compile(r'^[a-z0-9!#$%&\'*+/=?^_`{|}~.-]{1,64}$')
FECHA_VALIDA = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}')


class SinTiempo(FuenteNoResponde):
    """Ya no queda tiempo de la corrida para otra consulta."""


class LlaveRechazada(Exception):
    """La API respondió 401: la llave no sirve. No se reintenta."""


# ---------------------------------------------------------------- limpieza de respuestas

def _texto(x, maximo=MAX_TEXTO):
    if not isinstance(x, str):
        return None
    x = ''.join(c for c in x if c >= ' ' and c != '\x7f').strip()
    return x[:maximo] if x and contrato._cabe_en_la_base(x) else None


def _fecha(x):
    """'AAAA-MM-DD' de una fecha válida de HIBP, o None."""
    if not isinstance(x, str) or not FECHA_VALIDA.match(x):
        return None
    try:
        return date.fromisoformat(x[:10]).isoformat()
    except ValueError:
        return None


def limpiar_brecha(b):
    """Lo que se usa de un modelo de brecha de HIBP, o None si no trae nombre. Nunca Description, PwnCount ni logo."""
    if not isinstance(b, dict):
        return None
    nombre = _texto(b.get('Name'))
    if not nombre:
        return None
    clases = b.get('DataClasses') if isinstance(b.get('DataClasses'), list) else []
    clases = sorted({c for c in (_texto(x, 60) for x in clases) if c})[:MAX_CLASES]
    return {'Name': nombre, 'Title': _texto(b.get('Title')) or nombre, 'BreachDate': _fecha(b.get('BreachDate')),
            'DataClasses': clases, **{k: b.get(k) is True for k in ('IsVerified', 'IsFabricated', 'IsSensitive',
                                                                     'IsRetired', 'IsSpamList', 'IsMalware')}}


def _alias(x):
    x = x.strip().lower() if isinstance(x, str) else ''
    return x if ALIAS_VALIDO.fullmatch(x) and not x.startswith('.') and not x.endswith('.') else None


def limpiar_dominio(datos):
    """{alias: [nombres]} de /breacheddomain, con alias válidos y nombres sin repetir, hasta MAX_ALIAS."""
    if not isinstance(datos, dict):
        raise ValueError('breacheddomain no devolvió un objeto')
    limpio = {}
    for alias in sorted(datos, key=str)[:MAX_ALIAS]:
        a, nombres = _alias(alias), datos[alias]
        if a and isinstance(nombres, list):
            limpio.setdefault(a, set()).update(n for n in (_texto(x) for x in nombres) if n)
    return {a: sorted(n) for a, n in limpio.items() if n}


def limpiar_cuenta(datos):
    """Las brechas de /breachedaccount con truncateResponse=false, limpias."""
    if not isinstance(datos, list):
        raise ValueError('breachedaccount no devolvió una lista')
    return [b for b in (limpiar_brecha(x) for x in datos) if b]


def cuenta_al_disco(brechas):
    """Lo que se graba de un correo: solo las brechas que cuentan. Una sensible nunca queda ligada a un correo en el
    disco (sección 5.3, punto 5), y una descartada no se usa."""
    return [b for b in brechas if cuenta(b) == 'cuenta']


# ---------------------------------------------------------------- cliente

def _tapar(texto, llave):
    texto = str(texto)
    return texto.replace(llave, '***') if llave else texto


def _descargar(url, cabeceras, timeout=TIMEOUT):
    """(código HTTP, Retry-After en segundos o None, cuerpo) con transporte.descargar (RC-304): solo https, sin los
    proxies del entorno, a lo más MAX_BYTES y todo dentro de `timeout`. Una redirección no se sigue, así que la llave
    nunca sale hacia otro host: da FuenteNoResponde, sin reintento, igual que una respuesta de más de MAX_BYTES. Lanza
    OSError o PlazoVencido si no hay respuesta."""
    peticion = urllib.request.Request(url, headers=cabeceras, method='GET')
    try:
        return 200, None, transporte.descargar(peticion, time.monotonic() + timeout, MAX_BYTES)
    except transporte.Redirigida as e:
        raise FuenteNoResponde('hibp: %s' % e) from None
    except ValueError as e:
        raise FuenteNoResponde('hibp: %s' % e) from None
    except urllib.error.HTTPError as e:
        espera = transporte.retry_after(e.headers)   # segundos o fecha HTTP (RFC 9110, 10.2.3)
        e.close()
        return e.code, espera, b''


class ClienteHibp:
    """Consultas a la API v3 con su ritmo, sus reintentos y la grabación. `descargar`, `dormir` y `reloj` se
    reemplazan en las pruebas: nunca salen a la red."""

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, descargar=None, dormir=None, reloj=None, nueva=False,
                 llave=None):
        self.modo = modo
        self.grabadora = Grabadora(carpeta, modo, nueva=nueva, sobre=True)
        self.descargar = descargar or _descargar
        self.dormir = dormir or time.sleep
        self.reloj = reloj or time.monotonic
        self.llave = llave
        self.consultas = 0
        self.inicio = None
        self.ultima = None          # momento de la última consulta con llave
        self.grabo_fallas = False   # al grabar, alguna consulta falló y no quedó grabada
        self.no_antes = None        # con un Retry-After de más de MAX_ESPERA, ninguna consulta con llave antes de esto

    def empezar(self):
        self.inicio = self.reloj()

    def restante(self):
        return TIEMPO_CORRIDA - (self.reloj() - (self.inicio if self.inicio is not None else self.reloj()))

    def esperar(self, segundos):
        """Duerme si cabe en la corrida. False si no cabe."""
        if segundos <= 0:
            return True
        if segundos >= self.restante():
            return False
        self.dormir(segundos)
        return True

    def _espaciar(self):
        if self.ultima is not None:
            falta = PAUSA - (self.reloj() - self.ultima)
            if falta > 0 and not self.esperar(falta):
                raise SinTiempo('hibp: sin tiempo para otra consulta')

    def pedir(self, consulta, ruta, limpiar, con_llave=True, al_disco=None):
        """{'estado': 200 o 404 o 403, 'datos': lo limpio} de una consulta, del disco o de la API.
        Lanza LlaveRechazada con 401, SinGrabacion al reproducir si falta, y FuenteNoResponde si no hubo respuesta.
        Con `al_disco`, un 200 se graba con al_disco(datos), o no se graba aquí si devuelve None."""
        del_disco, datos = self.grabadora.de_disco(consulta)
        if del_disco:
            if not isinstance(datos, dict) or datos.get('estado') not in (200, 403, 404):
                raise ValueError('la grabación de %s no tiene la forma de hibp' % consulta)
            return datos
        cabeceras = {'user-agent': AGENTE, 'accept': 'application/json'}
        if con_llave:
            cabeceras['hibp-api-key'] = self.llave or ''
        ultimo = None
        for n in range(INTENTOS):
            if self.restante() <= 0:
                raise SinTiempo('hibp: sin tiempo para otra consulta')
            if con_llave:
                if self.no_antes is not None and self.reloj() < self.no_antes:
                    raise SinTiempo('hibp: HIBP pidió esperar más de %d s (429)' % MAX_ESPERA)
                self._espaciar()
            self.consultas += 1
            try:
                if con_llave:
                    self.ultima = self.reloj()
                codigo, espera, cuerpo = self.descargar(URL + ruta, cabeceras, min(TIMEOUT, self.restante()))
            except (OSError, ValueError, http.client.HTTPException, transporte.PlazoVencido) as e:
                ultimo = _tapar('%s: %s' % (type(e).__name__, e), self.llave)
                if n < INTENTOS - 1 and not self.esperar(ESPERAS[min(n, len(ESPERAS) - 1)]):
                    break
                continue
            if codigo == 200:
                if len(cuerpo) > MAX_BYTES:
                    raise FuenteNoResponde('hibp: la respuesta de %s pasa de %d bytes' % (consulta, MAX_BYTES))
                try:
                    respuesta = {'estado': 200, 'datos': limpiar(json.loads(cuerpo.decode('utf-8')))}
                except (ValueError, UnicodeDecodeError):
                    raise FuenteNoResponde('hibp: la respuesta de %s no se puede leer' % consulta) from None
                para_disco = respuesta['datos'] if al_disco is None else al_disco(respuesta['datos'])
                if para_disco is not None:
                    self.grabadora.guardar(consulta, {'estado': 200, 'datos': para_disco})
                return respuesta
            if codigo in (403, 404):
                respuesta = {'estado': codigo, 'datos': None}
                self.grabadora.guardar(consulta, respuesta)
                return respuesta
            if codigo == 401:
                raise LlaveRechazada()
            if codigo == 429:
                ultimo = 'HTTP 429'
                if espera is not None and espera > MAX_ESPERA:   # volver antes de lo que pide solo da otro 429
                    ultimo = 'HTTP 429, Retry-After %d s' % espera
                    if con_llave:   # tampoco el correo siguiente: la llave es la misma
                        self.no_antes = self.reloj() + espera
                    break
                if n < INTENTOS - 1 and not self.esperar(max(espera or PAUSA, 1)):
                    break
                continue
            if codigo >= 500:
                ultimo = 'HTTP %d' % codigo
                if n < INTENTOS - 1 and not self.esperar(ESPERAS[min(n, len(ESPERAS) - 1)]):
                    break
                continue
            raise FuenteNoResponde('hibp: %s respondió HTTP %d' % (consulta, codigo))   # 400 y otros 4xx
        self.grabadora.descartar(consulta)
        self.grabo_fallas = self.modo == 'grabar'
        raise FuenteNoResponde('hibp: %s sin respuesta después de los intentos (%s)' % (consulta, ultimo))


def carpeta_de(dominio):
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Su cliente para el modo. La llave no la lee: llega en recolectar(llave=...) desde el orquestador."""
    return ClienteHibp(modo, carpeta_de(dominio), nueva=(modo == 'grabar'))


# ---------------------------------------------------------------- hallazgos

def _consulta(tipo, valor):
    """Nombre de la consulta en la grabación: el correo y la brecha van como huella, no en el nombre del archivo."""
    return '%s-%s' % (tipo, hashlib.sha256(valor.encode('utf-8')).hexdigest()[:32])


def huella(dominio, nombre):
    return hashlib.sha256(('%s|brecha|%s|%s' % (FUENTE, dominio, nombre)).encode('utf-8')).hexdigest()


def codigo_de(brecha, ahora):
    """El código de regla de una brecha según sus clases de datos y su fecha."""
    if not DATOS_DE_ACCESO & set(brecha['DataClasses']):
        return 'breach_exposure_no_passwords'
    fecha = brecha['BreachDate']
    if fecha and (ahora.date() - date.fromisoformat(fecha)).days > DIAS_RECIENTE:
        return 'breach_exposure_old'
    return 'breach_exposure'


def cuenta(brecha):
    """'descartada', 'sensible' o 'cuenta'."""
    if brecha['IsFabricated'] or brecha['IsSpamList'] or brecha['IsRetired']:
        return 'descartada'
    if brecha['IsSensitive']:
        return 'sensible'
    return 'cuenta'


def hallazgo(dominio, brecha, correos, ahora, busqueda, partes):
    codigo = codigo_de(brecha, ahora)
    correos = sorted(correos)
    titulo = 'Correos de %s en la brecha %s' % (dominio, brecha['Title'])
    evidencia = {
        'title': titulo, 'breach_name': brecha['Name'], 'breach_title': brecha['Title'],
        'breach_date': brecha['BreachDate'], 'data_classes': brecha['DataClasses'],
        'access_data': sorted(DATOS_DE_ACCESO & set(brecha['DataClasses'])),
        'emails': correos[:MAX_CORREOS_EVIDENCIA], 'emails_exposed': len(correos),
        'verified': brecha['IsVerified'], 'search': busqueda,
        'attribution': ATRIBUCION, 'source_url': SITIO,
    }
    return Hallazgo(codigo, CODIGOS[codigo], dominio, titulo, evidencia,
                    rubrica.calcular(codigo, 'domain', evidencia, ahora), huella(dominio, brecha['Name']),
                    clave=brecha['Name'], partes=sorted(partes))


def _sin_cobertura(res, aviso, por_llave):
    res.sin_cobertura = list(CODIGOS)
    res.sin_llave = list(CODIGOS) if por_llave else []
    res.avisos.append(aviso)
    return res


def _correos_validos(dominio, correos):
    vistos = {}   # en el orden que da el orquestador (primero los que hace más que no se consultan), sin repetir
    for c in correos or ():
        if not isinstance(c, str) or '@' not in c:
            continue
        c = c.strip().lower()
        alias, _, nombre = c.rpartition('@')
        if _alias(alias) and en_alcance_nombre(nombre, dominio) and contrato.NOMBRE_VALIDO.fullmatch(nombre):
            vistos.setdefault(c, None)
    return list(vistos)


def _armar(res, dominio, por_brecha, brechas, ahora, busqueda, parte_de):
    """Activos y hallazgos de {nombre: correos} con los datos de cada brecha. Devuelve los conteos de descartadas y
    sensibles."""
    descartadas = sensibles = 0
    correos_vistos = set()
    for nombre in sorted(por_brecha):
        b = brechas.get(nombre)
        if b is None:
            continue
        que = cuenta(b)
        if que == 'descartada':
            descartadas += 1
            continue
        if que == 'sensible':
            sensibles += 1
            continue
        correos = por_brecha[nombre]
        correos_vistos.update(correos)
        res.hallazgos.append(hallazgo(dominio, b, correos, ahora, busqueda, parte_de(nombre, correos)))
    res.activos += [Activo('email', c, {'fuente': FUENTE}) for c in sorted(correos_vistos)]
    if descartadas:
        res.avisos.append(DESCARTADAS % descartadas)
    if sensibles:
        res.avisos.append(SENSIBLES % sensibles)


def _por_dominio(cliente, res, dominio, alias, ahora):
    por_brecha = {}
    for a, nombres in alias.items():
        for n in nombres:
            por_brecha.setdefault(n, set()).add('%s@%s' % (a, dominio))
    nombres = sorted(por_brecha)
    brechas, sin_datos = {}, []
    for i, nombre in enumerate(nombres[:MAX_BRECHAS]):
        if i and not cliente.esperar(PAUSA_SIN_LLAVE):
            sin_datos += nombres[i:MAX_BRECHAS]
            break
        try:
            r = cliente.pedir(_consulta('brecha', nombre), 'breach/' + urllib.parse.quote(nombre, safe=''),
                              limpiar_brecha, con_llave=False)
        except (FuenteNoResponde, ValueError):
            sin_datos.append(nombre)
            continue
        if r['estado'] == 200 and r['datos'] and r['datos']['Name'] == nombre:
            brechas[nombre] = r['datos']
        else:
            sin_datos.append(nombre)
    sobran = nombres[MAX_BRECHAS:]
    if cliente.modo == 'grabar' and (sobran or sin_datos):
        # Corrida parcial: el dominio no se graba, así reproducirla nunca da una corrida completa que daría por
        # resueltos los hallazgos de las brechas que quedaron fuera. Si es la primera respuesta de la grabación
        # (Grabadora.nueva), la carpeta no se vacía y queda la grabación anterior, como con cualquier grabación fallida
        cliente.grabadora.descartar(CONSULTA_DOMINIO)
    elif cliente.modo == 'grabar':
        # El dominio se graba aquí, ya con los datos de cada brecha: cada alias solo con las brechas que cuentan. Las
        # sensibles, las descartadas y las que quedaron sin datos no se ligan a ningún correo en el disco (sección 5.3,
        # punto 5). Al reproducir, sus avisos no salen.
        si = {n for n, b in brechas.items() if cuenta(b) == 'cuenta'}
        cliente.grabadora.guardar(CONSULTA_DOMINIO, {'estado': 200, 'datos': {
            a: [n for n in ns if n in si] for a, ns in sorted(alias.items()) if any(n in si for n in ns)}})
    _armar(res, dominio, por_brecha, brechas, ahora, 'domain', lambda n, _c: ['brecha:' + n])
    if sobran:
        res.avisos.append(SOBRAN_BRECHAS % (len(sobran), MAX_BRECHAS))
    if sin_datos:
        res.avisos.append(SIN_DATOS_BRECHA % len(sin_datos))
    if sobran or sin_datos:
        res.revisados = ['brecha:' + n for n in sorted(brechas)]
        for h in res.hallazgos:
            h.partes = ['brecha:' + h.clave]


def _por_correo(cliente, res, dominio, correos, ahora, total=None):
    if not correos:
        return _sin_cobertura(res, SIN_CORREOS, por_llave=False)
    revisados, sin_respuesta, por_brecha, brechas = [], 0, {}, {}
    for correo in correos[:MAX_CORREOS]:
        try:
            r = cliente.pedir(_consulta('correo', correo),
                              'breachedaccount/%s?truncateResponse=false' % urllib.parse.quote(correo, safe=''),
                              limpiar_cuenta, al_disco=cuenta_al_disco)
        except SinTiempo:
            break
        except (FuenteNoResponde, ValueError):
            sin_respuesta += 1
            continue
        if r['estado'] == 403:   # el plan no deja consultar correos: se toma como falla de esa consulta
            sin_respuesta += 1
            continue
        revisados.append(correo)
        for b in (r['datos'] or []) if r['estado'] == 200 else []:
            por_brecha.setdefault(b['Name'], set()).add(correo)
            brechas.setdefault(b['Name'], b)
    _armar(res, dominio, por_brecha, brechas, ahora, 'emails', lambda _n, c: ['correo:' + x for x in c])
    # Solo los correos de GitHub y de identidad, no todo el dominio: siempre parcial, y sin sin_revisar para no cerrar
    # lo que la búsqueda por dominio encontró en correos que aquí no se consultan.
    res.revisados = ['correo:' + c for c in revisados]
    # Cada correo consultado lleva la hora en attributes.hibp_consultado: el orquestador pone primero los que hace más
    # que no se consultan, así el tope rota entre escaneos (CORREOS_SQL).
    consultado = ahora.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    propios = {a.valor: a for a in res.activos if a.tipo == 'email'}
    for c in revisados:
        if c in propios:
            propios[c].atributos = {**propios[c].atributos, 'hibp_consultado': consultado}
        else:
            res.activos.append(Activo('email', c, {'hibp_consultado': consultado}))
    # total: los que había antes de los topes del orquestador (orquestador.MAX_CORREOS) y de aquí
    total = max(len(correos), total if isinstance(total, int) and not isinstance(total, bool) else 0)
    res.avisos.insert(0, POR_CORREO % (len(revisados), total))
    if total > MAX_CORREOS:
        res.avisos.append(SOBRAN_CORREOS % (total - MAX_CORREOS, MAX_CORREOS))
    sin_consultar = len(correos[:MAX_CORREOS]) - len(revisados) - sin_respuesta
    if sin_respuesta or sin_consultar:
        res.avisos.append(CORREO_SIN_RESPUESTA % (sin_respuesta + sin_consultar))
    if not revisados:   # ningún correo respondió: nada revisado, sin cobertura
        res.hallazgos, res.activos, res.revisados = [], [], None
        return _sin_cobertura(res, 'Sin cobertura de HIBP: ningún correo del dominio respondió', por_llave=False)
    return res


def recolectar(dominio, cliente=None, ahora=None, propios=(), correos=(), llave=None, correos_total=None):
    dominio = dominio.strip().lower().rstrip('.')
    ahora = ahora or datetime.now(timezone.utc)
    cliente = cliente or crear_cliente('vivo', dominio)
    res = Resultado(dominio, FUENTE)
    if cliente.modo != 'reproducir':
        llave = (llave or cliente.llave or '').strip()
        if not llave:
            return _sin_cobertura(res, SIN_LLAVE_AVISO, por_llave=True)
        if not LLAVE_VALIDA.fullmatch(llave):
            return _sin_cobertura(res, LLAVE_MAL_FORMADA, por_llave=True)
        cliente.llave = llave
    cliente.empezar()
    try:
        try:
            r = cliente.pedir(CONSULTA_DOMINIO, 'breacheddomain/' + urllib.parse.quote(dominio, safe=''),
                              limpiar_dominio, al_disco=lambda _d: None)   # 200: lo graba _por_dominio
        except SinGrabacion:
            return _sin_cobertura(res, SIN_GRABACION_DOMINIO, por_llave=False)
        if r['estado'] == 404:
            pass                                  # ningún correo del dominio en una brecha: completo, sin hallazgos
        elif r['estado'] == 200:
            _por_dominio(cliente, res, dominio, r['datos'] or {}, ahora)
        else:                                     # 403: dominio sin verificar o sin acceso
            _por_correo(cliente, res, dominio, _correos_validos(dominio, correos), ahora, correos_total)
    except LlaveRechazada:
        res = Resultado(dominio, FUENTE, consultas=cliente.consultas)
        return _sin_cobertura(res, LLAVE_RECHAZADA, por_llave=True)
    finally:
        res.consultas = cliente.consultas
    return res
