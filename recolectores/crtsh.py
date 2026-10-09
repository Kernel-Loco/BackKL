"""Recolector de Certificate Transparency con crt.sh (#14).

Lee los logs públicos de Certificate Transparency, sin tocar los servidores del
dominio, y devuelve:
- los subdominios del dominio autorizado (activos),
- certificados vencidos o que vencen en menos de 30 días (hallazgos),
- dominios parecidos que ya tienen un certificado emitido (hallazgos).

Modos: 'vivo' consulta crt.sh; 'grabar' además guarda cada respuesta en
respuestas_grabadas/crtsh/<dominio>/; 'reproducir' solo lee esas respuestas, sin red
(pruebas y respaldo de las demos). Si crt.sh no responde después de los
reintentos, el resultado queda en 'failed' y no trae activos ni hallazgos.

    python -m recolectores.crtsh acme-demo.mx
    python -m recolectores.crtsh acme-demo.mx --grabar
    python -m recolectores.crtsh acme-demo.mx --grabar --completar
    python -m recolectores.crtsh acme-demo.mx --reproducir

--grabar empieza con la carpeta del dominio vacía. --completar solo consulta
lo que aún no se grabó desde ese inicio, para terminar una grabación que
crt.sh dejó a medias. Código de salida: 0 bien, 1 si el
resultado queda en 'failed', 2 si quedan avisos (grabación incompleta o
variantes sin respuesta).
"""
import argparse
import hashlib
import http.client
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

FUENTE = 'ct_logs'
URL = 'https://crt.sh/'
AGENTE = 'cirdan-osint/0.1 (+https://github.com/Kernel-Loco)'
CARPETA_GRABADAS = Path(__file__).resolve().parent.parent / 'respuestas_grabadas' / 'crtsh'

DIAS_POR_VENCER = 30         # vence en menos de esto = hallazgo
VENTANA_VENCIDOS_DIAS = 365  # vencido hace más de esto ya no es hallazgo; el subdominio queda como activo
VENTANA_PARECIDOS_DIAS = 90  # un dominio parecido cuenta si tiene un certificado vigente o vencido hace menos de esto
MAX_CANDIDATOS = 10          # variantes que se consultan por escaneo
FALLAS_SEGUIDAS = 3          # si tantas variantes seguidas fallan, crt.sh está saturado y se dejan las demás
INTENTOS = 3                 # scan_source_runs.attempt va de 0 a 3
ESPERAS = (5, 15)            # segundos entre intentos; crt.sh suele recuperarse en segundos
PAUSA_PARECIDOS = 2          # segundos entre consultas de variantes, para no saturar crt.sh

# Código de regla -> severidad base. Los tres deben existir en el catálogo de reglas (#30).
CODIGOS = {'cert_expired': 'high', 'cert_expiring_soon': 'medium', 'lookalike_domain': 'medium'}

# Sufijos de dos niveles más comunes para sacar el dominio registrable sin descargar la lista pública de sufijos.
SUFIJOS_DOBLES = {'com.mx', 'org.mx', 'net.mx', 'edu.mx', 'gob.mx', 'com.br', 'com.ar', 'com.co', 'com.pe', 'com.es',
                  'co.uk', 'org.uk', 'com.au', 'co.jp'}
TLD_PRINCIPALES = ('com', 'mx', 'com.mx', 'net')
TLD_SECUNDARIOS = ('org', 'co', 'io', 'info', 'online', 'site')
HOMOGLIFOS = {'o': '0', 'l': '1', 'i': 'l', 'm': 'rn', 'w': 'vv', 'e': '3', 'a': '4', 's': '5'}
NOMBRE_VALIDO = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
SIN_GRABACION = 'no hay respuesta grabada para '
MARCA = '.grabacion'  # inicio de la grabación en curso, dentro de la carpeta del dominio

# Solo para lo que se imprime: los datos conservan los códigos de la base (high, medium...).
SEVERIDAD_ES = {'critical': 'crítica', 'high': 'alta', 'medium': 'media', 'low': 'baja'}
EXPOSICION_ES = {'publica': 'pública', 'privada': 'privada'}
MESES = ('ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic')


class CrtshNoResponde(Exception):
    """crt.sh no respondió con un JSON válido después de todos los intentos."""


class SinGrabacion(CrtshNoResponde):
    """En modo reproducir no hay respuesta grabada para la consulta. No es una falla de crt.sh."""


@dataclass
class Activo:
    tipo: str                      # 'domain' o 'subdomain'
    valor: str
    atributos: dict = field(default_factory=dict)


@dataclass
class Hallazgo:
    codigo: str                    # código de la regla (scoring_rules.code)
    severidad: str
    activo: str                    # valor del activo al que pertenece
    titulo: str
    evidencia: dict
    caracteristicas: dict          # tipo, antiguedad_dias, exposicion y sensibilidad (características del reto)
    huella: str                    # sha256 estable para no duplicar el hallazgo entre escaneos


@dataclass
class Resultado:
    dominio: str
    fuente: str = FUENTE
    estado: str = 'succeeded'      # 'succeeded' o 'failed', como scan_source_runs.status
    consultas: int = 0             # peticiones HTTP hechas a crt.sh, contando reintentos
    error: str = ''
    avisos: list = field(default_factory=list)
    activos: list = field(default_factory=list)
    hallazgos: list = field(default_factory=list)

    def a_dict(self):
        return asdict(self)


# ---------------------------------------------------------------- consulta a crt.sh

def _descargar(url, timeout):
    req = urllib.request.Request(url, headers={'User-Agent': AGENTE, 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _archivo_grabado(consulta, carpeta):
    """subdominios_acme.mx.json para %.acme.mx, contiene_acme.json para %acme% y acme.com.json para acme.com."""
    c = consulta.lower()
    if c.startswith('%.'):
        c = 'subdominios_' + c[2:]
    elif c.startswith('%') and c.endswith('%'):
        c = 'contiene_' + c.strip('%')
    return Path(carpeta) / ('%s.json' % (re.sub(r'[^a-z0-9.-]+', '_', c).strip('_.') or 'vacio'))


class ClienteCrtsh:
    """Hace las consultas con reintentos y, según el modo, graba o reproduce las respuestas."""

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, transporte=None, dormir=None, timeout=45,
                 completar=False, desde=None, reloj=None, nueva=False):
        """`completar` (solo al grabar) reutiliza lo grabado desde `desde`, el inicio de la grabación en curso,
        y vuelve a consultar lo demás, incluidas las respuestas de grabaciones anteriores.
        `nueva` (solo al grabar) vacía la carpeta y escribe la marca de inicio con la primera respuesta válida de
        crt.sh: si crt.sh no responde, la grabación anterior queda intacta."""
        assert modo in ('vivo', 'grabar', 'reproducir'), modo
        assert not completar or modo == 'grabar', 'completar solo aplica al grabar'
        self.modo, self.carpeta, self.timeout, self.completar, self.desde = modo, Path(carpeta), timeout, completar, desde
        self.transporte = transporte or _descargar
        self.dormir = dormir or time.sleep
        self.reloj = reloj or (lambda: datetime.now(timezone.utc))
        self.nueva = nueva and modo == 'grabar'
        self.consultas = 0
        self.leidas = []           # (archivo, fecha de grabación) de cada respuesta tomada del disco

    @staticmethod
    def _abrir(archivo):
        """(datos, fecha de grabación). La fecha va dentro del archivo porque git y las copias cambian la del sistema;
        los archivos del formato anterior (solo la lista) usan la fecha del sistema."""
        contenido = json.loads(archivo.read_text(encoding='utf-8') or '[]')
        if isinstance(contenido, dict) and 'datos' in contenido:
            return contenido['datos'], _fecha(contenido['grabado'])
        return contenido, datetime.fromtimestamp(archivo.stat().st_mtime, timezone.utc)

    def _leer(self, archivo):
        datos, fecha = self._abrir(archivo)
        self.leidas.append((archivo.name, fecha))
        return datos

    def consultar(self, consulta, intentos=INTENTOS, timeout=None, pausa=0, **extra):
        """`pausa`: segundos de espera antes de consultar crt.sh; no aplica si la respuesta sale del disco."""
        archivo = _archivo_grabado(consulta, self.carpeta)
        if self.modo == 'reproducir':
            if not archivo.exists():
                raise SinGrabacion(SIN_GRABACION + consulta)
            return self._leer(archivo)
        if self.completar and archivo.exists():
            datos, fecha = self._abrir(archivo)
            if self.desde is None or fecha >= self.desde:
                self.leidas.append((archivo.name, fecha))
                return datos
        if pausa:
            self.dormir(pausa)
        url = URL + '?' + urllib.parse.urlencode(dict(q=consulta, output='json', **extra))
        ultimo = ''
        for n in range(intentos):
            self.consultas += 1
            try:
                cuerpo = self.transporte(url, timeout or self.timeout)
                datos = json.loads(cuerpo or b'[]')
                if not isinstance(datos, list):
                    raise ValueError('respuesta inesperada')
                if self.modo == 'grabar':
                    self.carpeta.mkdir(parents=True, exist_ok=True)
                    if self.nueva:  # crt.sh ya respondió: hasta aquí no se toca la grabación anterior
                        self.nueva = False
                        for viejo in self.carpeta.glob('*.json'):
                            viejo.unlink()
                        (self.carpeta / MARCA).write_text(self.reloj().isoformat(), encoding='utf-8')
                    archivo.write_text(json.dumps({'grabado': self.reloj().isoformat(), 'consulta': consulta,
                                                   'datos': datos}, ensure_ascii=False), encoding='utf-8')
                return datos
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
                ultimo = '%s: %s' % (type(e).__name__, e)
                if n < intentos - 1:
                    self.dormir(ESPERAS[min(n, len(ESPERAS) - 1)])
        if self.modo == 'grabar' and not self.nueva and archivo.exists():
            archivo.unlink()  # una respuesta de una grabación anterior no debe pasar por la de hoy
        raise CrtshNoResponde('crt.sh no respondió a %s después de %d intentos (%s)' % (consulta, intentos, ultimo))


# ---------------------------------------------------------------- utilidades

def _con_fechas(certs):
    return [c for c in certs if isinstance(c, dict) and c.get('not_before') and c.get('not_after')]


def _fecha(texto):
    d = datetime.fromisoformat(texto.replace('Z', ''))
    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d


def registrable(nombre):
    """Dominio registrable aproximado: acme.com.mx para www.acme.com.mx, acme.mx para api.acme.mx."""
    partes = nombre.split('.')
    if len(partes) >= 3 and '.'.join(partes[-2:]) in SUFIJOS_DOBLES:
        return '.'.join(partes[-3:])
    return '.'.join(partes[-2:])


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


def candidatos_parecidos(dominio, maximo=MAX_CANDIDATOS):
    """Variantes de un dominio, en orden de probabilidad: TLD más comunes, sin guion, homoglifos, otros TLD,
    letras omitidas, letras cambiadas de lugar y letras repetidas. Nunca incluye el dominio original."""
    base = registrable(dominio)
    etiqueta, sufijo = base.split('.', 1)
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
    return salida[:maximo]


# ---------------------------------------------------------------- análisis

def _subdominios(dominio, certs, ahora):
    """Agrupa los certificados por nombre dentro del dominio y genera activos y hallazgos de vigencia."""
    por_nombre = {}
    vistos = set()
    for c in certs:
        if c.get('id') in vistos:
            continue
        vistos.add(c.get('id'))
        for nombre, comodin in _nombres(c):
            if nombre != dominio and not nombre.endswith('.' + dominio):
                continue
            g = por_nombre.setdefault(nombre, {'certs': [], 'comodin': False})
            g['certs'].append(c)
            g['comodin'] |= comodin

    activos, hallazgos = [], []
    for nombre in sorted(por_nombre):
        g = por_nombre[nombre]
        reciente = max(g['certs'], key=lambda c: _fecha(c['not_after']))
        vence = _fecha(reciente['not_after'])
        primero = min(_fecha(c['not_before']) for c in g['certs'])
        dias = (vence - ahora).total_seconds() / 86400
        activos.append(Activo('domain' if nombre == dominio else 'subdomain', nombre, {
            'comodin': g['comodin'], 'certificados': len(g['certs']), 'primer_certificado': primero.isoformat(),
            'vence': vence.isoformat(), 'emisor': reciente.get('issuer_name', ''), 'fuente': FUENTE}))
        evidencia = {'host': nombre, 'vence': vence.isoformat(), 'emisor': reciente.get('issuer_name', ''),
                     'serie': reciente.get('serial_number', ''), 'crtsh_id': reciente.get('id'),
                     'comodin': g['comodin']}
        if dias < 0 and -dias <= VENTANA_VENCIDOS_DIAS:
            titulo = 'Certificado vencido en %s' % nombre
            hallazgos.append(Hallazgo(
                'cert_expired', CODIGOS['cert_expired'], nombre, titulo,
                dict(evidencia, title=titulo, dias_vencido=int(-dias)),
                {'tipo': 'certificado_vencido', 'antiguedad_dias': int(-dias), 'exposicion': 'publica',
                 'sensibilidad': 'media'},
                _huella('cert_expired', nombre, str(reciente.get('serial_number', '')))))
        elif 0 <= dias < DIAS_POR_VENCER:
            titulo = 'El certificado de %s vence en %d días' % (nombre, int(dias))
            hallazgos.append(Hallazgo(
                'cert_expiring_soon', CODIGOS['cert_expiring_soon'], nombre, titulo,
                dict(evidencia, title=titulo, dias_para_vencer=int(dias)),
                {'tipo': 'certificado_por_vencer', 'antiguedad_dias': int((ahora - _fecha(reciente['not_before'])).days),
                 'exposicion': 'publica', 'sensibilidad': 'baja'},
                _huella('cert_expiring_soon', nombre, str(reciente.get('serial_number', '')))))
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
             'emisor': reciente.get('issuer_name', ''), 'crtsh_id': reciente.get('id')},
            {'tipo': 'dominio_parecido', 'antiguedad_dias': int((ahora - primero).days), 'exposicion': 'publica',
             'sensibilidad': 'alta'},
            _huella('lookalike_domain', dominio, reg)))
    return hallazgos


# ---------------------------------------------------------------- punto de entrada

def recolectar(dominio, cliente=None, ahora=None, propios=(), parecidos=True, max_candidatos=MAX_CANDIDATOS):
    """Recolecta subdominios, vigencia de certificados y dominios parecidos de `dominio`.

    `propios` son los otros dominios de la misma empresa, que nunca cuentan como parecidos.
    """
    dominio = dominio.strip().lower().rstrip('.')
    cliente = cliente or ClienteCrtsh()
    ahora = ahora or datetime.now(timezone.utc)
    res = Resultado(dominio)
    if not NOMBRE_VALIDO.match(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res

    # Subdominios: primero la consulta por comodín; si crt.sh no la resuelve, la búsqueda por nombre.
    certs, falla_comodin = None, None
    for consulta, extra in (('%.' + dominio, {'deduplicate': 'Y'}), (dominio, {})):
        try:
            certs = _con_fechas(cliente.consultar(consulta, **extra))
            break
        except CrtshNoResponde as e:
            res.error = str(e)
            falla_comodin = falla_comodin or e
    res.consultas = cliente.consultas
    if certs is None:
        res.estado = 'failed'
        return res
    res.error = ''
    if falla_comodin:  # se usó la búsqueda por nombre, que puede no traer todos los subdominios
        res.avisos.append(str(falla_comodin) if isinstance(falla_comodin, SinGrabacion) else
                          'crt.sh no respondió a %%.%s. Se usó la búsqueda por nombre y pueden faltar subdominios'
                          % dominio)
    res.activos, res.hallazgos = _subdominios(dominio, certs, ahora)

    if parecidos:
        propios_set = {registrable(dominio)} | {registrable(p.lower()) for p in propios} | {p.lower() for p in propios}
        etiqueta = registrable(dominio).split('.', 1)[0]
        por_tipo = []
        if len(etiqueta) >= 5:  # con etiquetas cortas la búsqueda por contenido trae demasiado ruido
            try:
                por_tipo.append(('contiene_marca', _con_fechas(cliente.consultar('%' + etiqueta + '%', intentos=2)),
                                 lambda n, e=etiqueta: e in n))
            except CrtshNoResponde as e:
                res.avisos.append(str(e))
        candidatos = [c for c in candidatos_parecidos(dominio, max_candidatos) if c not in propios_set]
        seguidas = 0
        for i, candidato in enumerate(candidatos):
            if seguidas >= FALLAS_SEGUIDAS:
                res.avisos.append('crt.sh saturado: se omitieron %d variantes (%s)' % (
                    len(candidatos) - i, ', '.join(candidatos[i:])))
                break
            try:
                encontrados = cliente.consultar(candidato, intentos=2, timeout=20, pausa=PAUSA_PARECIDOS)
                seguidas = 0
            except SinGrabacion as e:  # falta en la grabación: no cuenta como saturación de crt.sh
                res.avisos.append(str(e))
                continue
            except CrtshNoResponde as e:
                res.avisos.append(str(e))
                seguidas += 1
                continue
            tipo = 'otro_tld' if candidato.split('.', 1)[0] == etiqueta else 'error_tipografico'
            por_tipo.append((tipo, _con_fechas(encontrados), lambda n, k=candidato: registrable(n) == k))
        res.hallazgos += _parecidos(dominio, por_tipo, propios_set, ahora)
    res.consultas = cliente.consultas
    return res


# ---------------------------------------------------------------- salida para personas

def _dia(fecha):
    d = _fecha(fecha) if isinstance(fecha, str) else fecha
    return '%d %s %d' % (d.day, MESES[d.month - 1], d.year)


def _cuantos(n, singular, plural):
    return '%d %s' % (n, singular if n == 1 else plural)


def resumen(res, cliente=None, maximo_activos=20):
    """Líneas en español para leer el resultado en una terminal o en una demo."""
    cabecera = '%s · crt.sh · %s' % (res.dominio, res.estado)
    leidas = cliente.leidas if cliente else []
    if cliente and cliente.modo == 'reproducir':
        if leidas:
            grabado = min(f for _, f in leidas).astimezone()
            cabecera += ' · sin red, respuestas grabadas el %s a las %s' % (_dia(grabado), grabado.strftime('%H:%M'))
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


def _main(argv=None):
    # En Windows, cuando la salida no es la consola (Git Bash, una tubería), Python usa cp1252 y los acentos se rompen.
    if (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    p = argparse.ArgumentParser(description='Subdominios, certificados y dominios parecidos desde crt.sh')
    p.add_argument('dominio')
    p.add_argument('--grabar', action='store_true',
                   help='empieza una grabación nueva en respuestas_grabadas/crtsh/<dominio>/')
    p.add_argument('--completar', action='store_true', help='con --grabar, solo consulta lo que aún no está grabado')
    p.add_argument('--reproducir', action='store_true', help='usa solo las respuestas grabadas, sin red')
    p.add_argument('--sin-parecidos', action='store_true')
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
    # Cada dominio graba en su carpeta. --grabar la vacía y marca el inicio en cuanto crt.sh responde, así lo que no
    # se grabe hoy aparece como faltante y nunca se mezcla con días anteriores; si crt.sh no responde, la grabación
    # anterior queda intacta. --completar solo reutiliza lo grabado desde esa marca.
    carpeta = carpeta_de(dominio)
    marca = carpeta / MARCA
    desde = None
    if a.completar:
        if not marca.exists():
            p.error('--completar continúa una grabación de este dominio, primero corre --grabar')
        desde = _fecha(marca.read_text(encoding='utf-8').strip())
    cliente = ClienteCrtsh(modo=modo, carpeta=carpeta, completar=a.completar, desde=desde,
                           nueva=a.grabar and not a.completar)
    res = recolectar(dominio, cliente, parecidos=not a.sin_parecidos)
    if a.json:
        print(json.dumps(res.a_dict(), ensure_ascii=False, indent=1))
    else:
        print('\n'.join(resumen(res, cliente)))
    return codigo_salida(res)


def codigo_salida(res):
    """0 bien, 1 si el resultado queda en 'failed', 2 si quedan avisos."""
    return 1 if res.estado == 'failed' else 2 if res.avisos else 0


if __name__ == '__main__':
    sys.exit(_main())
