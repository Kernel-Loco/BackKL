"""Identidad pasiva (#20, RC-56): correos del dominio, perfiles públicos y usuarios de GitHub.

Qué revisa, todo de fuentes públicas y sin sesión:
- El sitio: la portada de cada nombre del dominio (los de Cert Spotter más la raíz, hasta MAX_SITIOS), con la misma
  visita que visita.py (mismo transporte, solo IP públicas, redirecciones solo dentro del dominio). De cada página
  salen los correos que trae y los enlaces a perfiles públicos (GitHub, GitLab, LinkedIn, X, Facebook, Instagram,
  YouTube y TikTok).
- Los certificados: los correos (emailAddress del sujeto y rfc822Name del subjectAltName) del certificado que el sitio
  presenta en el mismo saludo TLS de esa visita. No hay otra consulta.
- Los commits de la organización: la organización de GitHub declarada (github.declarada), su lista de repos y una
  página de commits de hasta MAX_REPOS_API repos, por la API sin token. De cada commit solo el correo del autor y el de
  quien lo subió, y el login ligado a cada uno.
- Los perfiles de GitHub enlazados desde el sitio: su correo público (GET /users/<login>), hasta MAX_PERFILES_API. Las
  demás redes nunca se consultan: el enlace basta para el activo.

Nunca entra a cuentas ni navega con sesión: ninguna petición lleva cookies, Authorization ni token.

Activos:
- email: cada correo del dominio o de un subdominio, con atributos['identidad'] = {origenes, donde}. Va en su propia
  llave porque el orquestador une los atributos de un activo sin mezclar las llaves de dentro, y github.py ya pone
  los suyos ('fuente', 'repos') en el mismo correo.
- profile: la URL https canónica de cada perfil, con 'hosts' (el sitio que lo enlaza o el host del correo del commit,
  nombres del dominio para el filtro de alcance) y atributos['identidad'] = {red, usuario, origenes}. Un usuario de
  GitHub con un commit firmado con un correo del dominio es un profile de GitHub.

Hallazgos, sobre el activo del dominio:
- personal_email_exposed (medio): un correo de un servicio gratuito (GRATUITOS) en el sitio, en el certificado, en los
  commits de la organización o en un perfil de GitHub enlazado. La evidencia lo lleva enmascarado (primera letra,
  '***' y el servicio) y dice dónde salió, nunca el correo completo. Su clave y su huella llevan un sha256 del correo
  con el dominio, así el mismo correo no se duplica entre escaneos.
- email_pattern_exposed (medio): al menos MIN_PATRON correos del dominio de personas distintas con el mismo formato
  (FORMATOS) en el mismo host. Un buzón con una palabra de GENERICOS no cuenta (docs/hallazgos_esperados.md:85). La
  evidencia dice el formato y cuántos, sin los correos, que ya son activos.

Partes (#23): cada sitio por su nombre, 'github:<org>/<repo>' por los commits de un repo y 'github:perfil:<login>' por
un perfil de GitHub. Un sitio que no se pudo leer completo (reto, 5xx, sin respuesta, página cortada) o lo de GitHub
que no se pudo pedir deja la corrida parcial: revisados lleva lo que sí se revisó y sin_revisar va en None, así el
orquestador solo cierra lo que salió de partes revisadas.

La grabación guarda solo lo ya reducido (los correos del dominio, los personales enmascarados y los perfiles), nunca el
cuerpo de una página ni un correo de terceros.

Uso:
  python -m cirdan.recolectores.identidad --reproducir olmardo.com
"""
import argparse
import hashlib
import html
import html.parser
import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone

from cirdan.ml import caracteristicas as rubrica
from cirdan.recolectores import borde, certspotter, github, shodan, transporte, visita
from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import (NOMBRE_VALIDO, Activo, FuenteNoResponde, Hallazgo, Resultado, SinGrabacion,
                                          en_alcance_nombre)
from cirdan.recolectores.shodan import LimiteAlcanzado, RespuestaIlegible, SinTiempo

FUENTE = 'identity'
CARPETA_GRABADAS = RAIZ_GRABADAS / 'identity'
CODIGOS = {'personal_email_exposed': 'medium', 'email_pattern_exposed': 'medium'}
PREFIJO = 'identity: '

MAX_SITIOS = visita.MAX_SITIOS             # nombres que se visitan, con la raíz
MAX_REDIRECCIONES = visita.MAX_REDIRECCIONES
TIEMPO_CORRIDA = 300                       # segundos de toda la corrida: ninguna consulta empieza después
RESERVA_GITHUB = 60                        # segundos que las visitas no tocan, para la API de GitHub
MIN_RESTANTE = 5                           # con menos segundos que esto ya no se empieza otro sitio ni otra consulta
MAX_REPOS_API = 5                          # repos de la organización de los que se lee una página de commits
MAX_PERFILES_API = 3                       # perfiles de GitHub enlazados desde el sitio cuyo correo público se lee
POR_PAGINA = 100                           # una sola página de repos y de commits
INTENTOS_API = github.INTENTOS             # intentos por petición a la API de GitHub
TIMEOUT_API = 20                           # segundos por petición a la API de GitHub
MAX_POR_PAGINA = 200                       # correos o perfiles que se guardan de una página, del sitio o de la API
MAX_DONDE = 5                              # lugares que se nombran en la evidencia o en el activo
MAX_TEXTO = 2 * 1024 * 1024                # caracteres del cuerpo que se leen
MIN_PATRON = 3                             # correos de personas distintas con el mismo formato (hallazgos_esperados:85)

# Peor caso de una corrida para el límite diario (#13b): las páginas de Cert Spotter, el A y la visita de cada nombre
# con sus redirecciones, como visita.py, más la lista de repos, una página de commits por repo y un perfil por login.
# La petición por http del 80 solo va cuando el https se rechazó o no conectó: no siguió redirecciones (visita.py).
MAX_CONSULTAS = (visita.PAGINAS_CT * visita.INTENTOS_CT + MAX_SITIOS * shodan.INTENTOS
                 + MAX_SITIOS * (1 + MAX_REDIRECCIONES) + INTENTOS_API * (1 + MAX_REPOS_API + MAX_PERFILES_API))

# Topes deterministas: lo que dejan fuera no impide grabar.
TOPES = ('paginas', 'sitios', 'repos', 'commits', 'perfiles')

# Servicios gratuitos de correo: un correo de uno de estos ligado a la empresa queda fuera de sus controles. Lista fija,
# sin consultas. Un correo de cualquier otro dominio (un proveedor, otra empresa) no se guarda.
GRATUITOS = frozenset({
    'gmail.com', 'googlemail.com', 'hotmail.com', 'hotmail.es', 'outlook.com', 'outlook.es', 'live.com',
    'live.com.mx', 'msn.com', 'yahoo.com', 'yahoo.com.mx', 'yahoo.es', 'icloud.com', 'me.com', 'mac.com', 'aol.com',
    'protonmail.com', 'proton.me', 'pm.me', 'gmx.com', 'gmx.net', 'mail.com', 'yandex.com', 'zoho.com',
    'prodigy.net.mx'})

# Palabras de buzones de un área o de un sistema, no de una persona: no cuentan para el patrón de correos
GENERICOS = frozenset({
    'admin', 'administracion', 'abuse', 'alertas', 'atencion', 'auditoria', 'billing', 'careers', 'ceo', 'cliente',
    'clientes', 'cobranza', 'compras', 'contact', 'contacto', 'correo', 'cumplimiento', 'dev', 'devops', 'direccion',
    'dpo', 'empleo', 'equipo', 'facturacion', 'finanzas', 'gerencia', 'hello', 'help', 'hola', 'hostmaster', 'humanos',
    'info', 'informes', 'it', 'jobs', 'legal', 'mail', 'marketing', 'news', 'newsletter', 'no', 'noreply',
    'notificaciones', 'notifications', 'office', 'oficina', 'pagos', 'postmaster', 'prensa', 'privacidad', 'privacy',
    'recursos', 'reply', 'reservas', 'rh', 'root', 'sales', 'security', 'seguridad', 'servicio', 'servicios',
    'sistemas', 'soporte', 'support', 'team', 'ti', 'ventas', 'web', 'webmaster'})

# Formatos de un buzón con el nombre de una persona, en orden: el primero que calza
FORMATOS = (('nombre.apellido', re.compile(r'[a-z]{2,30}\.[a-z]{2,30}')),
            ('nombre_apellido', re.compile(r'[a-z]{2,30}_[a-z]{2,30}')),
            ('nombre-apellido', re.compile(r'[a-z]{2,30}-[a-z]{2,30}')),
            ('inicial.apellido', re.compile(r'[a-z]\.[a-z]{2,30}')),
            ('nombre.inicial', re.compile(r'[a-z]{2,30}\.[a-z]')))

# Un correo en el texto: el usuario no puede venir pegado a otro carácter de usuario, así una cadena larga no da
# pedazos. Cuantificadores con tope: sin retroceso que crezca con el cuerpo.
_CORREO = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})@((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)"
                     r"{1,8}[A-Za-z]{2,63})(?![A-Za-z0-9-])", re.A)
_HUELLA = re.compile(r'[0-9a-f]{64}')
_ENMASCARADO = re.compile(r'[a-z0-9]\*\*\*@[a-z0-9.-]{3,40}')
ORIGENES = ('sitio', 'certificado', 'commits', 'perfil')
TAGS_ENLACE = ('a', 'link', 'area')

# Redes de los perfiles: host -> red. Un host de LinkedIn de un país (mx.linkedin.com) también es LinkedIn.
REDES = {'github.com': 'github', 'www.github.com': 'github', 'gitlab.com': 'gitlab', 'www.gitlab.com': 'gitlab',
         'linkedin.com': 'linkedin', 'x.com': 'x', 'www.x.com': 'x', 'twitter.com': 'x', 'www.twitter.com': 'x',
         'mobile.twitter.com': 'x', 'facebook.com': 'facebook', 'www.facebook.com': 'facebook',
         'm.facebook.com': 'facebook', 'instagram.com': 'instagram', 'www.instagram.com': 'instagram',
         'youtube.com': 'youtube', 'www.youtube.com': 'youtube', 'm.youtube.com': 'youtube', 'tiktok.com': 'tiktok',
         'www.tiktok.com': 'tiktok'}
# Primeras rutas que no son un perfil (páginas del servicio, botones de compartir)
RESERVADAS = {
    'github': {'about', 'apps', 'collections', 'contact', 'customer-stories', 'enterprise', 'events', 'explore',
               'features', 'home', 'join', 'login', 'marketplace', 'new', 'notifications', 'organizations', 'pricing',
               'readme', 'search', 'security', 'settings', 'site', 'sponsors', 'team', 'topics', 'trending', 'pulls',
               'issues', 'codespaces', 'signup', 'logout', 'password_reset'},
    'gitlab': {'explore', 'help', 'users', 'dashboard', 'search', 'admin', 'projects', 'groups', 'api', '-'},
    'x': {'home', 'share', 'intent', 'i', 'search', 'hashtag', 'explore', 'settings', 'login', 'signup', 'tos',
          'privacy', 'messages', 'notifications', 'compose'},
    'facebook': {'sharer', 'sharer.php', 'share', 'share.php', 'dialog', 'plugins', 'login', 'login.php',
                 'profile.php', 'pages', 'groups', 'events', 'watch', 'help', 'policies', 'privacy', 'tr', 'home.php',
                 'photo.php', 'story.php', 'permalink.php', 'hashtag', 'business', 'ads', 'marketplace', 'gaming'},
    'instagram': {'p', 'reel', 'reels', 'explore', 'accounts', 'stories', 'tv', 'about', 'developer', 'legal',
                  'direct', 'web'},
}
_USUARIO_RED = {'github': github.ORG_VALIDA, 'gitlab': re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}'),
                'x': re.compile(r'[A-Za-z0-9_]{1,15}'), 'facebook': re.compile(r'[A-Za-z0-9.]{1,50}'),
                'instagram': re.compile(r'[A-Za-z0-9_.]{1,30}'), 'tiktok': re.compile(r'[A-Za-z0-9_.]{1,24}'),
                'linkedin': re.compile(r'[A-Za-z0-9_-][A-Za-z0-9_.%-]{0,99}'),
                'youtube': re.compile(r'[A-Za-z0-9_.-]{1,100}')}
TIPOS_LINKEDIN = ('company', 'in', 'school', 'showcase')
TIPOS_YOUTUBE = ('c', 'channel', 'user')

# Motivos de un sitio sin revisar: los de visita.py más el de una página que pasó del tope de bytes
MOTIVOS = dict(visita.MOTIVOS, cortado='su página pasó del tope de bytes y no se leyó completa',
               pagina='su página no se pudo leer')
FALLAS_DE_RED = visita.FALLAS_DE_RED

SIN_GRABACION_DOMINIO = PREFIJO + 'no hay grabación de identidad de este dominio, no se revisó'
SIN_DECLARACION = PREFIJO + 'el dominio no tiene organización de GitHub declarada, no se revisaron sus commits'
DECLARO_NINGUNA = PREFIJO + 'la empresa declaró que no tiene organización de GitHub, no se revisaron commits'
DECLARADA_INVALIDA = PREFIJO + 'la organización de GitHub declarada no es un nombre válido, no se revisaron commits'
NO_EXISTE = PREFIJO + 'la organización de GitHub declarada no existe, no se revisaron commits'
SIN_CUOTA = PREFIJO + 'GitHub no dio permiso o se acabó su cuota por hora (403 o 429)'
PARCIAL = PREFIJO + 'cobertura parcial'
NO_SE_GRABO = (PREFIJO + 'la corrida tuvo fallas (la red, el tiempo, la cuota de GitHub o una respuesta que no se puede '
               'leer): no se grabó, queda la grabación anterior')


class _Vacio(Exception):
    """GitHub respondió 409 a los commits: el repo está vacío."""


# ---------------------------------------------------------------- peticiones

def _visitar(url, timeout):
    """La visita de visita._visitar a `url`, con los correos del certificado del mismo saludo y sin limpiar:
    ClienteIdentidad.limpiar la reduce antes de leerla y de grabarla. La única función que pide a un sitio: las pruebas
    la cambian con mock.patch.object."""
    return visita._visitar(url, timeout, saludo={'correos': None}, limpiar=False)


def _descargar(url, timeout):
    """El cuerpo de una respuesta de la API de GitHub, con github._descargar (sin token, sin redirecciones, solo IP
    públicas en el 443). La única función que pide a GitHub: las pruebas la cambian con mock.patch.object. Una
    respuesta de más de github.MAX_BYTES o una redirección dan RespuestaIlegible, y una que tarda de más SinTiempo, que
    _http reintenta como una falla de red mientras le quede tiempo a la corrida."""
    try:
        return github._descargar(url, timeout)
    except transporte.PlazoVencido:
        raise SinTiempo(PREFIJO + 'GitHub tardó más de %s s' % timeout) from None
    except transporte.Redirigida:
        raise RespuestaIlegible(PREFIJO + 'GitHub respondió con una redirección') from None
    except ValueError as e:
        raise RespuestaIlegible(PREFIJO + 'GitHub dio una respuesta que no se puede leer (%s)' % type(e).__name__) \
            from None


class ClienteIdentidad(visita.ClienteWeb):
    """El cliente de la visita web (Cert Spotter, el A y la visita de cada sitio, con sus reintentos, el tiempo de la
    corrida y la grabación) con la API de GitHub (api). Cada visita se reduce (limpiar) a los correos y perfiles antes
    de leerla y de grabarla. `visitar(url, timeout)` pide a un sitio: si no se pasa, _visitar, buscada en el módulo en
    cada consulta. GitHub va por _descargar, salvo que el cliente traiga `descargar` (las pruebas), que también hace las
    veces de Cert Spotter."""
    PREFIJO = PREFIJO
    TIEMPO_CORRIDA = TIEMPO_CORRIDA
    TOPES = TOPES

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, dominio='', visitar=None, **otros):
        super().__init__(modo=modo, carpeta=carpeta, visitar=visitar or (lambda url, timeout: _visitar(url, timeout)),
                         **otros)
        self.dominio = dominio

    def limpiar(self, datos):
        """La visita como se lee y se graba: una página queda en {estado, cortado, reto, identidad}, sin cabeceras ni
        cuerpo. Una redirección, un 443 cerrado o una falla quedan con su forma de visita.limpiar_visita. Lo ya
        reducido (de la grabación) se valida otra vez. ValueError si no tiene ninguna de esas formas."""
        if isinstance(datos, dict) and 'identidad' in datos:
            return _reducida(datos, self.dominio)
        limpia = visita.limpiar_visita(datos)
        if 'estado' not in limpia:
            return limpia
        tls = datos.get('tls')
        return _reducir(limpia, tls.get('correos') if isinstance(tls, dict) else None, self.dominio)

    def github(self, consulta, ruta, que, reducir):
        """El JSON de https://api.github.com<ruta> ya reducido (`reducir`), o {'no_existe': True} con un 404 y
        {'vacio': True} con un 409. Lanza github.CuotaAgotada con un 403 o un 429, SinGrabacion al reproducir sin ella y
        FuenteNoResponde si no respondió en INTENTOS_API intentos o si la grabación no se puede leer."""
        try:
            del_disco, datos = self._de_disco(consulta)
            if del_disco:
                return datos if _especial(datos) else reducir(datos)
        except (ValueError, KeyError, TypeError, AttributeError):
            raise FuenteNoResponde(self.PREFIJO + 'la grabación de %s no se puede leer' % que) from None
        url = github.API + ruta

        def pedir():
            try:
                crudo = self._http(url, INTENTOS_API, TIMEOUT_API, que,
                                   peticion=lambda u, t: _descargar(u, t))
            except LimiteAlcanzado:
                raise github.CuotaAgotada() from None
            except RespuestaIlegible as e:
                if getattr(e, 'codigo', None) == 403:
                    raise github.CuotaAgotada() from None
                if getattr(e, 'codigo', None) == 409:
                    return {'vacio': True}
                raise
            if crudo is None:
                return {'no_existe': True}
            try:
                return reducir(crudo)
            except (ValueError, KeyError, TypeError, AttributeError):
                raise RespuestaIlegible(self.PREFIJO + '%s respondió algo que no se puede leer' % que) from None
        datos = self._consultar(consulta, pedir)
        self._grabar(consulta, datos)
        return datos


def _especial(datos):
    return datos in ({'no_existe': True}, {'vacio': True})


def carpeta_de(dominio):
    """Carpeta de la grabación de un dominio."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' consulta, 'reproducir' usa la grabación del dominio y 'grabar' empieza
    una grabación nueva."""
    dominio = dominio.strip().lower().rstrip('.')
    return ClienteIdentidad(modo=modo, carpeta=carpeta_de(dominio), dominio=dominio, nueva=(modo == 'grabar'))


# ---------------------------------------------------------------- correos

def _masca(usuario, servicio):
    return '%s***@%s' % (usuario[0], servicio)


def _clave(correo, dominio):
    """La clave estable de un correo personal: un sha256 con el dominio, nunca el correo."""
    return hashlib.sha256(('correo|%s|%s' % (dominio, correo)).encode('utf-8')).hexdigest()


def _clasificar(correo, dominio):
    """('dominio', correo) si es del dominio o de un subdominio, ('personal', {huella, correo, servicio}) si es de un
    servicio gratuito, o None: el de cualquier otro dominio no se guarda. Todo en minúsculas."""
    if not isinstance(correo, str) or len(correo) > 320:
        return None
    correo = correo.strip().lower()
    usuario, arroba, host = correo.rpartition('@')
    if not arroba or not github.USUARIO_VALIDO.fullmatch(usuario) or not NOMBRE_VALIDO.fullmatch(host):
        return None
    if en_alcance_nombre(host, dominio):
        return ('dominio', correo) if github.correo_valido(correo, dominio) else None
    if host in GRATUITOS and usuario[0].isalnum():
        return 'personal', {'huella': _clave(correo, dominio), 'correo': _masca(usuario, host), 'servicio': host}
    return None


def _correos_del_texto(texto, dominio):
    """(correos del dominio, personales) de un texto: tal cual, con las entidades HTML resueltas y con los %XX de un
    mailto: resueltos. Sin repetir, en el orden en que salen, hasta MAX_POR_PAGINA de cada uno."""
    propios, personales = [], {}
    vistos = set()
    base = html.unescape(texto[:MAX_TEXTO])
    for t in (base, urllib.parse.unquote(base)):
        for m in _CORREO.finditer(t):
            correo = (m.group(1) + '@' + m.group(2)).lower()
            if correo in vistos:
                continue
            vistos.add(correo)
            tipo = _clasificar(correo, dominio)
            if tipo is None:
                continue
            if tipo[0] == 'dominio' and len(propios) < MAX_POR_PAGINA:
                propios.append(tipo[1])
            elif tipo[0] == 'personal' and len(personales) < MAX_POR_PAGINA:
                personales.setdefault(tipo[1]['huella'], tipo[1])
    return propios, list(personales.values())


def _correos_sueltos(correos, dominio):
    """(correos del dominio, personales) de una lista de correos (los del certificado)."""
    propios, personales = [], {}
    for c in list(correos or ())[:MAX_POR_PAGINA]:
        tipo = _clasificar(c, dominio)
        if tipo and tipo[0] == 'dominio' and tipo[1] not in propios:
            propios.append(tipo[1])
        elif tipo and tipo[0] == 'personal':
            personales.setdefault(tipo[1]['huella'], tipo[1])
    return propios, list(personales.values())


def _personal_valido(p):
    return (isinstance(p, dict) and set(p) == {'huella', 'correo', 'servicio'} and isinstance(p['huella'], str)
            and bool(_HUELLA.fullmatch(p['huella'])) and p['servicio'] in GRATUITOS
            and isinstance(p['correo'], str) and bool(_ENMASCARADO.fullmatch(p['correo']))
            and p['correo'].endswith('@' + p['servicio']))


# ---------------------------------------------------------------- perfiles

class _Enlaces(html.parser.HTMLParser):
    """Los href de <a>, <link> y <area> de una página, hasta MAX_POR_PAGINA * 10."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag in TAGS_ENLACE and len(self.hrefs) < MAX_POR_PAGINA * 10:
            for nombre, valor in attrs:
                if nombre == 'href' and isinstance(valor, str) and valor.strip():
                    self.hrefs.append(valor.strip())

    handle_startendtag = handle_starttag


def perfil(href):
    """{red, usuario, url} del perfil público de un enlace, con la URL https canónica, o None si el enlace no es un
    perfil de REDES (una página del servicio, un botón de compartir, otro sitio)."""
    if not isinstance(href, str) or len(href) > visita.MAX_URL or '\\' in href:
        return None
    texto = href.strip()
    if texto.startswith('//'):
        texto = 'https:' + texto
    try:
        partes = urllib.parse.urlsplit(texto)
        puerto = partes.port
    except ValueError:
        return None
    if partes.scheme.lower() not in ('http', 'https') or partes.username is not None or puerto not in (None, 80, 443):
        return None
    host = (partes.hostname or '').lower().rstrip('.')
    red = REDES.get(host) or ('linkedin' if host.endswith('.linkedin.com') else None)
    if red is None:
        return None
    segmentos = [urllib.parse.unquote(s) for s in partes.path.split('/') if s]
    if not segmentos:
        return None
    primero = segmentos[0]
    if red == 'linkedin':
        if len(segmentos) < 2 or primero.lower() not in TIPOS_LINKEDIN:
            return None
        tipo, usuario = primero.lower(), segmentos[1].lower()
        if not _USUARIO_RED[red].fullmatch(usuario):
            return None
        return {'red': red, 'usuario': usuario, 'url': 'https://www.linkedin.com/%s/%s' % (tipo, _ruta(usuario))}
    if red == 'youtube':
        if primero.startswith('@'):
            usuario = primero[1:].lower()
            ok = _USUARIO_RED[red].fullmatch(usuario)
            return {'red': red, 'usuario': '@' + usuario, 'url': 'https://www.youtube.com/@%s' % usuario} if ok else None
        if len(segmentos) < 2 or primero not in TIPOS_YOUTUBE or not _USUARIO_RED[red].fullmatch(segmentos[1]):
            return None
        usuario = segmentos[1] if primero == 'channel' else segmentos[1].lower()   # el id de un canal distingue mayúsculas
        return {'red': red, 'usuario': '%s/%s' % (primero, usuario),
                'url': 'https://www.youtube.com/%s/%s' % (primero, usuario)}
    if red == 'tiktok':
        usuario = primero[1:].lower() if primero.startswith('@') else ''
        if not usuario or not _USUARIO_RED[red].fullmatch(usuario):
            return None
        return {'red': red, 'usuario': '@' + usuario, 'url': 'https://www.tiktok.com/@%s' % usuario}
    if red == 'github' and primero.lower() == 'orgs' and len(segmentos) >= 2:
        primero = segmentos[1]
    usuario = primero.lower()
    if usuario in RESERVADAS.get(red, ()) or not _USUARIO_RED[red].fullmatch(usuario):
        return None
    if red == 'x' and partes.path.lower().startswith(('/intent', '/share')):
        return None
    canonico = {'github': 'https://github.com/%s', 'gitlab': 'https://gitlab.com/%s', 'x': 'https://x.com/%s',
                'facebook': 'https://www.facebook.com/%s', 'instagram': 'https://www.instagram.com/%s'}[red]
    return {'red': red, 'usuario': usuario, 'url': canonico % usuario}


def _ruta(texto):
    return urllib.parse.quote(texto, safe="-._~%")


def _perfiles_del_html(cuerpo):
    """Los perfiles (perfil()) de los enlaces de una página, sin repetir, hasta MAX_POR_PAGINA. Un HTML que el
    parser no puede leer da los que alcanzó a ver."""
    lector = _Enlaces()
    try:
        lector.feed(cuerpo[:MAX_TEXTO])
        lector.close()
    except Exception:   # un HTML raro no tumba la corrida: quedan los enlaces que ya se leyeron
        pass
    vistos, salida = set(), []
    for href in lector.hrefs:
        p = perfil(href)
        if p and p['url'] not in vistos and len(salida) < MAX_POR_PAGINA:
            vistos.add(p['url'])
            salida.append(p)
    return salida


def _perfil_valido(p):
    return (isinstance(p, dict) and set(p) == {'red', 'usuario', 'url'} and isinstance(p.get('url'), str)
            and perfil(p['url']) == p)


# ---------------------------------------------------------------- páginas

def _reducir(limpia, correos_cert, dominio):
    """{estado, cortado, reto, identidad} de una página ya limpia (visita.limpiar_visita) y los correos del certificado
    de su saludo. El reto (borde.reto) dice que la página no es la del sitio: no se lee."""
    reto = _reto(borde.reto(limpia['estado'], limpia['cabeceras'], limpia['cuerpo']))
    salida = {'estado': limpia['estado'], 'cortado': limpia['cortado'], 'reto': reto}
    cert_propios, cert_personales = _correos_sueltos(correos_cert if isinstance(correos_cert, list) else (), dominio)
    if reto:
        propios, personales, perfiles = [], [], []
    else:
        propios, personales = _correos_del_texto(limpia['cuerpo'], dominio)
        perfiles = _perfiles_del_html(limpia['cuerpo'])
    salida['identidad'] = {'correos': propios, 'personales': personales, 'perfiles': perfiles,
                           'correos_cert': cert_propios, 'personales_cert': cert_personales}
    return salida


def _reto(datos):
    if not isinstance(datos, dict):
        return None
    proveedor = datos.get('proveedor')
    return {'proveedor': proveedor if proveedor in borde.PROVEEDORES else None,
            'estado': datos.get('estado') if shodan._entero(datos.get('estado')) else None,
            'motivo': datos.get('motivo') if datos.get('motivo') in (borde.MOTIVO_PAGINA, borde.MOTIVO_LIMITE) else None}


def _reducida(datos, dominio):
    """Una página ya reducida (de la grabación), validada: ValueError si algo no tiene su forma."""
    estado, ident = datos.get('estado'), datos.get('identidad')
    if not shodan._entero(estado) or not isinstance(ident, dict) or set(datos) != {'estado', 'cortado', 'reto',
                                                                                   'identidad'}:
        raise ValueError('forma inesperada')
    reto = datos['reto']
    if reto is not None and _reto(reto) != reto:
        raise ValueError('forma inesperada')
    if set(ident) != {'correos', 'personales', 'perfiles', 'correos_cert', 'personales_cert'}:
        raise ValueError('forma inesperada')
    for llave in ('correos', 'correos_cert'):
        lista = ident[llave]
        if not isinstance(lista, list) or len(lista) > MAX_POR_PAGINA or not all(
                isinstance(c, str) and _clasificar(c, dominio) == ('dominio', c) for c in lista):
            raise ValueError('forma inesperada')
    for llave in ('personales', 'personales_cert'):
        lista = ident[llave]
        if not isinstance(lista, list) or len(lista) > MAX_POR_PAGINA or not all(_personal_valido(p) for p in lista):
            raise ValueError('forma inesperada')
    if not isinstance(ident['perfiles'], list) or len(ident['perfiles']) > MAX_POR_PAGINA or not all(
            _perfil_valido(p) for p in ident['perfiles']):
        raise ValueError('forma inesperada')
    return {'estado': estado, 'cortado': datos['cortado'] is True, 'reto': reto,
            'identidad': {k: [dict(x) if isinstance(x, dict) else x for x in v] for k, v in ident.items()}}


# ---------------------------------------------------------------- GitHub

def _repos(datos):
    """La lista de repos (github.repos_limpios) con solo nombre, fork, deshabilitado, privado y último push."""
    return [{k: r[k] for k in ('nombre', 'fork', 'deshabilitado', 'privado', 'subido')}
            for r in github.repos_limpios(datos)]


def _elegir_repos(repos):
    """(los repos de los que se leen commits, cuántos quedaron fuera por el tope). Ni forks, ni deshabilitados, ni
    privados, ni con nombre inválido. Hasta MAX_REPOS_API por último push, del más reciente."""
    candidatos = [r for r in repos if r['nombre'] and not (r['fork'] or r['deshabilitado'] or r['privado'])]
    candidatos.sort(key=lambda r: (r['subido'], r['nombre']), reverse=True)
    return candidatos[:MAX_REPOS_API], max(0, len(candidatos) - MAX_REPOS_API)


def _commits(datos, dominio):
    """{n, correos: [{correo, login, fecha}], personales: [{huella, correo, servicio, fecha}]} de una página de
    commits de la API (o de su forma ya reducida). De cada commit solo los correos del autor y de quien lo subió, y el
    login ligado a cada uno. Un correo de otro dominio, o uno de noreply de GitHub, no se guarda. La fecha es la más
    vieja con ese correo."""
    if isinstance(datos, dict) and set(datos) == {'n', 'correos', 'personales'}:
        return _commits_reducidos(datos, dominio)
    if not isinstance(datos, list):
        raise ValueError('forma inesperada')
    propios, personales = {}, {}
    for c in datos:
        if not isinstance(c, dict) or not isinstance(c.get('commit'), dict):
            continue
        for quien in ('author', 'committer'):
            firma = c['commit'].get(quien)
            cuenta = c.get(quien)
            if not isinstance(firma, dict):
                continue
            tipo = _clasificar(firma.get('email'), dominio)
            fecha = github._fecha(firma.get('date')) or ''
            login = cuenta.get('login') if isinstance(cuenta, dict) else None
            login = login if isinstance(login, str) and github.ORG_VALIDA.fullmatch(login) else None
            if tipo and tipo[0] == 'dominio' and (tipo[1] in propios or len(propios) < MAX_POR_PAGINA):
                previo = propios.setdefault(tipo[1], {'correo': tipo[1], 'login': login, 'fecha': fecha})
                previo['login'] = previo['login'] or login
                previo['fecha'] = min(x for x in (previo['fecha'], fecha) if x) if previo['fecha'] or fecha else ''
            elif tipo and tipo[0] == 'personal' and (tipo[1]['huella'] in personales or
                                                     len(personales) < MAX_POR_PAGINA):
                previo = personales.setdefault(tipo[1]['huella'], dict(tipo[1], fecha=fecha))
                previo['fecha'] = min(x for x in (previo['fecha'], fecha) if x) if previo['fecha'] or fecha else ''
    return {'n': len(datos), 'correos': list(propios.values()), 'personales': list(personales.values())}


def _commits_reducidos(datos, dominio):
    n = datos['n']
    if not shodan._entero(n) or n < 0 or not isinstance(datos['correos'], list) or not isinstance(
            datos['personales'], list):
        raise ValueError('forma inesperada')
    for c in datos['correos']:
        if not (isinstance(c, dict) and set(c) == {'correo', 'login', 'fecha'}
                and _clasificar(c['correo'], dominio) == ('dominio', c['correo'])
                and (c['login'] is None or (isinstance(c['login'], str) and github.ORG_VALIDA.fullmatch(c['login'])))
                and isinstance(c['fecha'], str) and (c['fecha'] == '' or github._fecha(c['fecha']) == c['fecha'])):
            raise ValueError('forma inesperada')
    for p in datos['personales']:
        if not (isinstance(p, dict) and isinstance(p.get('fecha'), str)
                and _personal_valido({k: v for k, v in p.items() if k != 'fecha'})
                and (p['fecha'] == '' or github._fecha(p['fecha']) == p['fecha'])):
            raise ValueError('forma inesperada')
    return {'n': n, 'correos': [dict(c) for c in datos['correos']], 'personales': [dict(p) for p in datos['personales']]}


def _usuario(datos, dominio):
    """{login, correo, personal} del perfil de un usuario u organización de GitHub (o de su forma ya reducida): el
    correo público solo si es del dominio, y el personal enmascarado si es de un servicio gratuito."""
    if not isinstance(datos, dict) or not isinstance(datos.get('login'), str) or not github.ORG_VALIDA.fullmatch(
            datos['login']):
        raise ValueError('forma inesperada')
    if set(datos) == {'login', 'correo', 'personal'}:
        if datos['correo'] is not None and _clasificar(datos['correo'], dominio) != ('dominio', datos['correo']):
            raise ValueError('forma inesperada')
        if datos['personal'] is not None and not _personal_valido(datos['personal']):
            raise ValueError('forma inesperada')
        return {'login': datos['login'], 'correo': datos['correo'],
                'personal': dict(datos['personal']) if datos['personal'] else None}
    tipo = _clasificar(datos.get('email'), dominio)
    return {'login': datos['login'], 'correo': tipo[1] if tipo and tipo[0] == 'dominio' else None,
            'personal': tipo[1] if tipo and tipo[0] == 'personal' else None}


# ---------------------------------------------------------------- lo que se junta

class _Junta:
    """Lo que salió en la corrida: correos del dominio, personales y perfiles, con dónde y de qué parte salió cada uno."""

    def __init__(self):
        self.correos = {}     # correo -> {origenes, donde, partes}
        self.personales = {}  # huella -> {correo, servicio, origenes, donde, partes, primera_vez}
        self.perfiles = {}    # url -> {red, usuario, origenes, hosts, partes}

    def correo(self, correo, origen, donde, parte):
        d = self.correos.setdefault(correo, {'origenes': set(), 'donde': [], 'partes': set()})
        self._anotar(d, origen, donde, parte)

    def personal(self, p, origen, donde, parte, fecha=''):
        d = self.personales.setdefault(p['huella'], {'correo': p['correo'], 'servicio': p['servicio'],
                                                     'origenes': set(), 'donde': [], 'partes': set(),
                                                     'primera_vez': ''})
        self._anotar(d, origen, donde, parte)
        if fecha and (not d['primera_vez'] or fecha < d['primera_vez']):
            d['primera_vez'] = fecha

    def perfil(self, p, origen, host, parte):
        d = self.perfiles.setdefault(p['url'], {'red': p['red'], 'usuario': p['usuario'], 'origenes': set(),
                                                'hosts': [], 'donde': [], 'partes': set()})
        self._anotar(d, origen, host, parte)
        if host not in d['hosts']:
            d['hosts'].append(host)

    @staticmethod
    def _anotar(d, origen, donde, parte):
        d['origenes'].add(origen)
        d['partes'].add(parte)
        if donde not in d['donde']:
            d['donde'].append(donde)


class _Sitio:
    def __init__(self, nombre):
        self.nombre = nombre
        self.visto = False   # se sabe qué tiene: dio su página, redirigió, no tiene A, no es pública o no tiene https
        self.falta = None    # el motivo de MOTIVOS si quedó sin revisar
        self.pagina = None   # la página reducida, si dio una

    def sin_revisar(self, motivo):
        if self.falta is None:
            self.falta = motivo


# ---------------------------------------------------------------- punto de entrada

def _sin_cobertura(res, aviso):
    res.avisos.append(aviso)
    res.sin_cobertura = list(CODIGOS)
    return res


def recolectar(dominio, cliente=None, ahora=None, propios=()):
    """Correos, perfiles y usuarios de GitHub del dominio. `propios` no se usa."""
    dominio = dominio.strip().lower().rstrip('.')
    res = Resultado(dominio, FUENTE)
    if not NOMBRE_VALIDO.fullmatch(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res
    cliente = cliente or crear_cliente('vivo', dominio)
    cliente.dominio = dominio
    if cliente.modo == 'reproducir' and not cliente.hay_grabacion():
        return _sin_cobertura(res, SIN_GRABACION_DOMINIO)
    try:
        cliente.empezar()
        _revisar(res, cliente, dominio, ahora or datetime.now(timezone.utc))
    except FuenteNoResponde:
        raise
    except Exception as e:   # nunca el texto de la excepción: puede traer un correo o un pedazo de la fuente
        raise FuenteNoResponde(PREFIJO + 'falla inesperada (%s)' % type(e).__name__) from None
    finally:
        res.consultas = cliente.consultas
    return res


def _revisar(res, cliente, dominio, ahora):
    parcial, junta = [], _Junta()
    sitios, todos_los_nombres, ct_respondio, fallas_dns, n_nombres = _sitios(res, cliente, dominio, ahora, parcial)
    for host in sorted(sitios):
        _leer_sitio(res, sitios[host], junta)
    gh = _github(res, cliente, dominio, junta, parcial)
    if not ct_respondio and fallas_dns == n_nombres and not gh['respondio']:
        raise FuenteNoResponde(PREFIJO + 'no respondieron Cert Spotter, el DNS de %s ni GitHub' % dominio)

    for correo in sorted(junta.correos):
        d = junta.correos[correo]
        res.activos.append(Activo('email', correo, {'identidad': {'origenes': sorted(d['origenes']),
                                                                  'donde': d['donde'][:MAX_DONDE]}}))
    for url in sorted(junta.perfiles):
        d = junta.perfiles[url]
        res.activos.append(Activo('profile', url, {'hosts': sorted(d['hosts']),
                                                   'identidad': {'red': d['red'], 'usuario': d['usuario'],
                                                                 'origenes': sorted(d['origenes'])}}))
    for huella in sorted(junta.personales):
        res.hallazgos.append(_personal(junta.personales[huella], huella, dominio, ahora))
    res.hallazgos += _patrones(junta, dominio, ahora)

    # Cobertura
    faltan = sorted(h for h, s in sitios.items() if s.falta) + gh['faltan']
    hechos = sorted(h for h, s in sitios.items() if not s.falta) + gh['hechos']
    por_motivo = {}
    for h, s in sitios.items():
        if s.falta and s.falta not in ('reto', 'sin_tiempo'):
            por_motivo.setdefault(s.falta, []).append(h)
    for motivo, hosts in sorted(por_motivo.items()):
        res.avisos.append(PREFIJO + '%s sin revisar: %s (%s)' % (visita._cuantos(len(hosts), 'sitio', 'sitios'),
                                                                 MOTIVOS[motivo], visita._lista(sorted(hosts))))
    completo = not faltan and todos_los_nombres and gh['completo']
    if not completo:
        if hechos or res.hallazgos:
            res.revisados = hechos
        else:
            res.sin_cobertura = list(CODIGOS)
        res.avisos.append('%s, se revisaron %d de %d sitios' % (PARCIAL, len([h for h in hechos if ':' not in h]),
                                                                len(sitios)))
    if cliente.modo == 'grabar' and cliente.degradada(parcial):
        res.avisos.insert(0, NO_SE_GRABO)
    else:
        cliente.terminar()
    return res


def _sitios(res, cliente, dominio, ahora, parcial):
    """({host: _Sitio}, todos_los_nombres, ct_respondio, fallas_dns, cuántos nombres) de la visita a la portada de
    cada nombre."""
    todos_los_nombres = True
    try:
        certs, completos = certspotter.certificados(cliente, dominio, max_paginas=visita.PAGINAS_CT,
                                                    intentos=visita.INTENTOS_CT, timeout=visita.TIMEOUT_CT)
        ct_respondio = True
        if not completos:
            res.avisos.append(PREFIJO + 'Cert Spotter no dio todas sus páginas, pueden faltar sitios del dominio')
            parcial.append('paginas' if not cliente.fallas and not cliente.raras_ct else 'ct')
            todos_los_nombres = False
    except FuenteNoResponde as e:
        certs, ct_respondio, todos_los_nombres = [], False, False
        res.avisos.append('%s. Solo se visitó la raíz' % e)
        parcial.append('ct')
    nombres = shodan._nombres(dominio, certs)
    if len(nombres) > MAX_SITIOS:
        res.avisos.append(PREFIJO + 'se visitaron %d de %d nombres del dominio (MAX_SITIOS)' % (MAX_SITIOS,
                                                                                               len(nombres)))
        nombres = visita._elegir(nombres, ahora, cliente)
        parcial.append('sitios')
        todos_los_nombres = False

    sitios, fallas_dns, sin_tiempo = {}, 0, []
    cliente.reserva = RESERVA_GITHUB
    try:
        for i, nombre in enumerate(nombres):
            sitio = sitios.setdefault(nombre, _Sitio(nombre))
            if sitio.visto or sitio.falta:   # ya llegó como destino de otra redirección
                continue
            if cliente.restante() < MIN_RESTANTE:
                sin_tiempo = nombres[i:]
                break
            try:
                a = cliente.resolver_a(nombre)
            except SinTiempo:
                sin_tiempo = nombres[i:]
                break
            except SinGrabacion:
                sitio.sin_revisar('grabacion')
                continue
            except FuenteNoResponde:
                fallas_dns += 1
                sitio.sin_revisar('dns')
                continue
            if a['estado'] != 'ok' or not any(transporte.publica(ip) for ip in a['ips']):
                sitio.visto = True   # sin A o solo con IP privadas: no tiene sitio público que leer
                continue
            try:
                host, url, vista, _ = visita._recorrer(cliente, dominio, nombre, sitios)
            except SinTiempo:
                sin_tiempo = nombres[i:]
                break
            except SinGrabacion:
                sitio.sin_revisar('grabacion')
                continue
            except FuenteNoResponde as e:   # una grabación que no se puede leer
                res.avisos.append(str(e))
                sitio.sin_revisar('grabacion')
                parcial.append('ilegible')
                continue
            _registrar(sitios, sitio, host, vista)
    finally:
        cliente.reserva = 0
    sin_tiempo = [n for n in sin_tiempo if n not in sitios or not (sitios[n].visto or sitios[n].falta)]
    for nombre in sin_tiempo:
        sitios.setdefault(nombre, _Sitio(nombre)).sin_revisar('sin_tiempo')
    if sin_tiempo:
        res.avisos.append(PREFIJO + 'se acabó el tiempo de la corrida antes de visitar %s'
                          % visita._cuantos(len(sin_tiempo), 'sitio', 'sitios'))
        parcial.append('tiempo')
    if fallas_dns:
        res.avisos.append(PREFIJO + 'el DNS no respondió al A de %s' % visita._cuantos(fallas_dns, 'nombre', 'nombres'))
        parcial.append('a')
    return sitios, todos_los_nombres, ct_respondio, fallas_dns, len(nombres)


def _registrar(sitios, sitio, host, vista):
    """Lo que dejó la visita de `sitio`, que terminó en `host` (él mismo o el destino de sus redirecciones)."""
    if host != sitio.nombre:   # redirigió dentro del dominio: lo que se vio es de `host`
        sitio.visto = True
        destino = sitios.setdefault(host, _Sitio(host))
        if destino.visto or destino.falta or vista.get('ya_visitado'):
            return
        sitio = destino
    if vista.get('fuera') or vista.get('rechazada') or vista.get('ya_visitado'):
        sitio.visto = True   # manda a otro dominio o no tiene https ni http: no hay página del dominio que leer
        return
    if 'sin_respuesta' in vista:
        sitio.sin_revisar(vista['sin_respuesta'])
        return
    if 'identidad' not in vista:   # una página que limpiar() no redujo: no se lee
        sitio.sin_revisar('pagina')
        return
    sitio.pagina = vista
    if vista['reto']:
        sitio.sin_revisar('reto')
    elif visita._error_servidor(vista):
        sitio.sin_revisar('error_http')
    elif vista['cortado']:
        sitio.sin_revisar('cortado')
    else:
        sitio.visto = True


def _leer_sitio(res, sitio, junta):
    """Los correos y perfiles de la página de `sitio`. Lo de una página con reto no se lee. Lo de un 5xx o una página
    cortada sí: se vio en la página que llegó, aunque el sitio quede sin revisar."""
    pagina = sitio.pagina
    if pagina is None:
        return
    if pagina['reto']:
        res.avisos.append(PREFIJO + 'el sitio %s respondió con un reto o bloqueo (%s): sus correos y perfiles quedan '
                          'sin cobertura, no 0' % (sitio.nombre, pagina['reto'].get('motivo') or 'sin motivo'))
    ident = pagina['identidad']
    donde = 'sitio %s' % sitio.nombre
    for correo in ident['correos']:
        junta.correo(correo, 'sitio', donde, sitio.nombre)
    for p in ident['personales']:
        junta.personal(p, 'sitio', donde, sitio.nombre)
    for p in ident['perfiles']:
        junta.perfil(p, 'sitio', sitio.nombre, sitio.nombre)
    donde = 'certificado de %s' % sitio.nombre
    for correo in ident['correos_cert']:
        junta.correo(correo, 'certificado', donde, sitio.nombre)
    for p in ident['personales_cert']:
        junta.personal(p, 'certificado', donde, sitio.nombre)


def _github(res, cliente, dominio, junta, parcial):
    """Los commits de la organización declarada y el correo público de los perfiles de GitHub enlazados desde el
    sitio. {respondio, completo, hechos, faltan}: las partes 'github:...' revisadas y las que faltaron."""
    estado = {'respondio': False, 'completo': True, 'hechos': [], 'faltan': []}
    org = github.declarada(dominio)
    aviso = (SIN_DECLARACION if org is None else DECLARO_NINGUNA if org == github.NINGUNA else
             DECLARADA_INVALIDA if not github.ORG_VALIDA.fullmatch(org) else None)
    perfiles = sorted({d['usuario'] for d in junta.perfiles.values() if d['red'] == 'github'})
    if aviso:
        res.avisos.append(aviso)
        org = None
    cuota = False

    def falta(parte, motivo):
        estado['faltan'].append(parte)
        estado['completo'] = False
        parcial.append(motivo)

    if org:
        parte_org = 'github:%s' % org.lower()
        try:
            repos = cliente.github('gh:repos:%s' % org.lower(), '/orgs/%s/repos?per_page=%d&sort=pushed' % (
                org, POR_PAGINA), 'la lista de repos de %s' % org, _repos)
            estado['respondio'] = True
        except SinGrabacion:
            repos = None
            falta(parte_org, 'grabacion')
        except github.CuotaAgotada:
            repos, cuota = None, True
            falta(parte_org, 'cuota')
        except (SinTiempo, FuenteNoResponde) as e:
            repos = None
            res.avisos.append(str(e))
            falta(parte_org, 'github')
        if isinstance(repos, dict) and repos.get('no_existe'):
            res.avisos.append(NO_EXISTE)
            repos = []
        if isinstance(repos, list):
            if len(repos) >= POR_PAGINA:
                res.avisos.append(PREFIJO + 'GitHub dio %d repos de %s en una página: pueden faltar' % (len(repos), org))
                estado['completo'] = False
                parcial.append('repos')
            elegidos, sobran = _elegir_repos(repos)
            if sobran:
                res.avisos.append(PREFIJO + 'se leyeron los commits de %d de %d repos de %s (MAX_REPOS_API)'
                                  % (len(elegidos), len(elegidos) + sobran, org))
                estado['completo'] = False
                parcial.append('repos')
            for r in elegidos:
                parte = 'github:%s/%s' % (org.lower(), r['nombre'])
                if cuota or cliente.restante() < MIN_RESTANTE:
                    falta(parte, 'cuota' if cuota else 'tiempo')
                    continue
                try:
                    commits = cliente.github('gh:commits:%s/%s' % (org.lower(), r['nombre']),
                                             '/repos/%s/%s/commits?per_page=%d' % (org, urllib.parse.quote(
                                                 r['nombre'], safe='._-'), POR_PAGINA),
                                             'los commits de %s/%s' % (org, r['nombre']),
                                             lambda d: _commits(d, dominio))
                except SinGrabacion:
                    falta(parte, 'grabacion')
                    continue
                except github.CuotaAgotada:
                    cuota = True
                    falta(parte, 'cuota')
                    continue
                except (SinTiempo, FuenteNoResponde) as e:
                    res.avisos.append(str(e))
                    falta(parte, 'github')
                    continue
                if _especial(commits):   # un repo vacío (409) o que ya no está (404): no tiene commits
                    estado['hechos'].append(parte)
                    continue
                if commits['n'] >= POR_PAGINA:
                    # Solo la página más reciente: los commits de antes no se leen. Lo de este repo no se cierra
                    res.avisos.append(PREFIJO + 'de %s/%s se leyó una sola página de commits' % (org, r['nombre']))
                    estado['completo'] = False
                    parcial.append('commits')
                    estado['faltan'].append(parte)
                else:
                    estado['hechos'].append(parte)
                donde = 'commits de %s/%s' % (org.lower(), r['nombre'])
                for c in commits['correos']:
                    junta.correo(c['correo'], 'commits', donde, parte)
                    if c['login']:
                        host = c['correo'].rsplit('@', 1)[1]
                        junta.perfil({'red': 'github', 'usuario': c['login'].lower(),
                                      'url': 'https://github.com/%s' % c['login'].lower()}, 'commits', host, parte)
                for p in commits['personales']:
                    junta.personal({k: p[k] for k in ('huella', 'correo', 'servicio')}, 'commits', donde, parte,
                                   p['fecha'])
            if repos is not None and not cuota:
                estado['hechos'].append(parte_org)

    # El correo público de los perfiles de GitHub enlazados desde el sitio
    if len(perfiles) > MAX_PERFILES_API:
        res.avisos.append(PREFIJO + 'se leyó el correo público de %d de %d perfiles de GitHub (MAX_PERFILES_API)'
                          % (MAX_PERFILES_API, len(perfiles)))
        estado['completo'] = False
        parcial.append('perfiles')
    for login in perfiles[:MAX_PERFILES_API]:
        parte = 'github:perfil:%s' % login
        if cuota or cliente.restante() < MIN_RESTANTE:
            falta(parte, 'cuota' if cuota else 'tiempo')
            continue
        try:
            usuario = cliente.github('gh:usuario:%s' % login, '/users/%s' % login, 'el perfil de %s' % login,
                                     lambda d: _usuario(d, dominio))
            estado['respondio'] = True
        except SinGrabacion:
            falta(parte, 'grabacion')
            continue
        except github.CuotaAgotada:
            cuota = True
            falta(parte, 'cuota')
            continue
        except (SinTiempo, FuenteNoResponde) as e:
            res.avisos.append(str(e))
            falta(parte, 'github')
            continue
        estado['hechos'].append(parte)
        if _especial(usuario):
            continue
        donde = 'perfil https://github.com/%s' % login
        if usuario['correo']:
            junta.correo(usuario['correo'], 'perfil', donde, parte)
        if usuario['personal']:
            junta.personal(usuario['personal'], 'perfil', donde, parte)
    if cuota:
        res.avisos.append(SIN_CUOTA)
    return estado


# ---------------------------------------------------------------- hallazgos

def _huella(codigo, dominio, clave):
    """No lleva lo observado (dónde salió), así el hallazgo no se duplica entre escaneos."""
    return hashlib.sha256('|'.join((FUENTE, codigo, dominio, dominio, clave)).encode('utf-8')).hexdigest()


def _personal(d, huella_correo, dominio, ahora):
    """personal_email_exposed de un correo de un servicio gratuito, con el correo enmascarado."""
    codigo = 'personal_email_exposed'
    titulo = 'Un correo de %s aparece ligado a %s' % (d['servicio'], dominio)
    evidencia = {'title': titulo, 'correo': d['correo'], 'servicio': d['servicio'],
                 'origenes': sorted(d['origenes']), 'donde': d['donde'][:MAX_DONDE]}
    if d['primera_vez']:
        evidencia['primera_vez'] = d['primera_vez']
    return Hallazgo(codigo, CODIGOS[codigo], dominio, titulo, evidencia,
                    rubrica.calcular(codigo, 'domain', evidencia, ahora), _huella(codigo, dominio, huella_correo),
                    clave=huella_correo, partes=sorted(d['partes']))


def formato(correo):
    """El formato de FORMATOS de un buzón con el nombre de una persona, o None (un buzón genérico u otro formato)."""
    usuario = correo.rsplit('@', 1)[0]
    if any(t in GENERICOS for t in re.split(r'[._-]', usuario)):
        return None
    return next((nombre for nombre, patron in FORMATOS if patron.fullmatch(usuario)), None)


def _patrones(junta, dominio, ahora):
    """email_pattern_exposed por formato y host con al menos MIN_PATRON buzones de personas distintas."""
    grupos = {}
    for correo, d in junta.correos.items():
        f = formato(correo)
        if f:
            grupos.setdefault((f, correo.rsplit('@', 1)[1]), []).append(d)
    codigo, hallazgos = 'email_pattern_exposed', []
    for (f, host), lista in sorted(grupos.items()):
        if len(lista) < MIN_PATRON:
            continue
        titulo = 'Los correos de %s siguen el formato %s' % (host, f)
        evidencia = {'title': titulo, 'formato': f, 'host': host, 'correos_con_el_formato': len(lista),
                     'ejemplo': '%s@%s' % (f, host),
                     'origenes': sorted(set().union(*(d['origenes'] for d in lista)))}
        hallazgos.append(Hallazgo(codigo, CODIGOS[codigo], dominio, titulo, evidencia,
                                  rubrica.calcular(codigo, 'domain', evidencia, ahora),
                                  _huella(codigo, dominio, '%s@%s' % (f, host)), clave='%s@%s' % (f, host),
                                  partes=sorted(set().union(*(d['partes'] for d in lista)))))
    return hallazgos


# ---------------------------------------------------------------- consola

def resumen(res):
    lineas = ['%s %s: %s, %d consultas' % (FUENTE, res.dominio, res.estado, res.consultas)]
    if res.error:
        lineas.append('  error: %s' % res.error)
    for a in res.activos:
        lineas.append('  activo %s %s' % (a.tipo, a.valor))
    for h in res.hallazgos:
        lineas.append('  %s [%s] %s' % (h.codigo, h.severidad, h.titulo))
    for a in res.avisos:
        lineas.append('  aviso: %s' % a)
    if res.sin_cobertura:
        lineas.append('  sin cobertura: %s' % ', '.join(res.sin_cobertura))
    return lineas


def codigo_salida(res):
    return 0 if res.estado == 'succeeded' and not res.sin_cobertura and res.revisados is None else 1


def _main(argv=None):
    p = argparse.ArgumentParser(description='Identidad pasiva (#20): correos, perfiles y usuarios de GitHub del '
                                            'dominio (sin --reproducir consulta en vivo)')
    p.add_argument('dominio')
    modo = p.add_mutually_exclusive_group()
    modo.add_argument('--grabar', action='store_true',
                      help='empieza una grabación nueva en cirdan/recolectores/respuestas_grabadas/identity/<dominio>/')
    modo.add_argument('--reproducir', action='store_true', help='usa solo la grabación, sin red')
    p.add_argument('--json', action='store_true', help='imprime el resultado completo en JSON')
    a = p.parse_args(argv)
    dominio = a.dominio.strip().lower().rstrip('.')
    if not NOMBRE_VALIDO.fullmatch(dominio):   # también evita que '..' o '/' saquen la carpeta de respuestas_grabadas
        p.error('dominio inválido: %s' % a.dominio)
    modo = 'grabar' if a.grabar else 'reproducir' if a.reproducir else 'vivo'
    if modo != 'reproducir' and not github._en_vivo_permitido(dominio):
        p.error('%s no está en DOMINIOS_EN_VIVO: solo se consulta en vivo, o se graba, con la carta vigente del '
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
