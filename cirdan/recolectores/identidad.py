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
  '***' y el servicio, sin la letra si el usuario es corto) y dice dónde salió, nunca el correo completo. Su clave y
  su huella llevan un HMAC-SHA256 (llave IDENTITY_HMAC_KEY) del buzón normalizado con el dominio, así el mismo correo
  no se duplica entre escaneos y la huella no se revierte probando nombres. Sin la llave no se guarda ningún correo
  personal y la regla queda sin cobertura.
- email_pattern_exposed (medio): al menos MIN_PATRON correos del dominio de personas distintas con el mismo formato
  (FORMATOS) en el mismo host. Un buzón con una palabra de GENERICOS no cuenta (docs/hallazgos_esperados.md:85). La
  evidencia dice el formato y cuántos, sin los correos, que ya son activos.

Partes (#23): cada sitio por su nombre, 'github:<org>/<repo>' por los commits de un repo y 'github:perfil:<login>' por
un perfil de GitHub. Un sitio que no se pudo leer completo (reto, 5xx, sin respuesta, página cortada o con más correos
o enlaces de los que caben) o lo de GitHub que no se pudo pedir deja la corrida parcial: revisados lleva lo que sí se
revisó. Si se sabe qué partes existen (Cert Spotter completo y la lista de repos entera), sin_revisar lleva las que no
se revisaron, también las que MAX_SITIOS, MAX_REPOS_API o MAX_PERFILES_API dejaron fuera, y el orquestador cierra lo
demás. Si no se sabe, sin_revisar va en None y solo se cierra lo que salió de partes revisadas. Un correo personal del
perfil de GitHub enlazado lleva también como partes los sitios que lo enlazan. Lo leído en el destino de una redirección
que no es un nombre de Cert Spotter (uno de un comodín) lleva también como partes los nombres que redirigen ahí: si el
origen queda sin revisar, el destino no se visita y no está en sin_revisar, así no se cierra lo suyo (alcance1).

La grabación guarda solo lo ya reducido (los correos del dominio, los personales enmascarados y los perfiles, y de una
redirección su destino sin correos ni valores sensibles en la consulta y los correos de su certificado), nunca el
cuerpo de una página ni un correo de terceros.

Uso:
  python -m cirdan.recolectores.identidad --reproducir olmardo.com
"""
import argparse
import hashlib
import hmac
import html
import html.parser
import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone

from cirdan.config import config
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
# Llave del HMAC de la huella de un correo personal (a1 de la revisión de RC-56). Sin llave, un sha256 del correo con el
# dominio, que se conoce, se revierte probando nombres. Sin ella no se guarda ningún correo personal: la regla queda sin
# cobertura. Cambiarla cambia las huellas, y los hallazgos abiertos se cierran y se abren otra vez.
LLAVE = 'IDENTITY_HMAC_KEY'
MIN_LLAVE = 32                             # caracteres de la llave, como mínimo

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
# pedazos. Cuantificadores con tope: sin retroceso que crezca con el cuerpo. El host tampoco puede seguir con otra
# etiqueta ('.xn--p1ai', '.x1'): sin eso el retroceso lo cortaba en un nombre del dominio que no es el del correo.
_CORREO = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})@((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)"
                     r"{1,8}(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59}))(?![A-Za-z0-9-]|\.[A-Za-z0-9])", re.A)
# La última etiqueta del host que es una palabra con mayúscula inicial ('ti@acme.com.Gracias'): el correo cerró la frase
# sin espacio. Sin cortarla, el host quedaba acme.com.gracias y el correo del dominio se perdía (R6 de RC-56).
_PALABRA = re.compile(r'[A-Z][a-z]{1,62}')
_HUELLA = re.compile(r'[0-9a-f]{64}')
_ENMASCARADO = re.compile(r'(?:[a-z0-9])?\*\*\*@[a-z0-9.-]{3,40}')
MIN_USUARIO_MASCARA = 4                    # con un usuario más corto la máscara no lleva su primera letra
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
               'issues', 'codespaces', 'signup', 'logout', 'password_reset', 'users', 'orgs', 'dashboard',
               'solutions', 'resources', 'copilot', 'why-github', 'premium-support', 'mobile', 'blog', 'partners',
               'education', 'nonprofit', 'git-guides', 'github', 'stars', 'watching', 'gist', 'discussions',
               'actions', 'packages', 'ai', 'customer', 'case-studies', 'newsroom', 'careers'},
    'gitlab': {'explore', 'help', 'users', 'dashboard', 'search', 'admin', 'projects', 'groups', 'api', '-'},
    'x': {'home', 'share', 'intent', 'i', 'search', 'hashtag', 'explore', 'settings', 'login', 'signup', 'tos',
          'privacy', 'messages', 'notifications', 'compose'},
    'facebook': {'sharer', 'sharer.php', 'share', 'share.php', 'dialog', 'plugins', 'login', 'login.php',
                 'profile.php', 'pages', 'groups', 'events', 'watch', 'help', 'policies', 'privacy', 'tr', 'home.php',
                 'photo.php', 'story.php', 'permalink.php', 'hashtag', 'business', 'ads', 'marketplace', 'gaming',
                 'people'},
    'instagram': {'p', 'reel', 'reels', 'explore', 'accounts', 'stories', 'tv', 'about', 'developer', 'legal',
                  'direct', 'web'},
}
_USUARIO_RED = {'github': github.ORG_VALIDA, 'gitlab': re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}'),
                'x': re.compile(r'[A-Za-z0-9_]{1,15}'), 'facebook': re.compile(r'[A-Za-z0-9.]{1,50}'),
                'instagram': re.compile(r'[A-Za-z0-9_.]{1,30}'), 'tiktok': re.compile(r'[A-Za-z0-9_.]{1,24}'),
                'linkedin': re.compile(r'[\w-][\w.%-]{0,99}'),   # con acentos: jos%C3%A9-p es josé-p
                'youtube': re.compile(r'[A-Za-z0-9_.-]{1,100}')}
TIPOS_LINKEDIN = ('company', 'in', 'school', 'showcase')
TIPOS_YOUTUBE = ('c', 'channel', 'user')

# Motivos de un sitio sin revisar: los de visita.py más el de una página que pasó del tope de bytes
MOTIVOS = dict(visita.MOTIVOS, cortado='su página pasó del tope de bytes, de correos o de enlaces y no se leyó completa',
               pagina='su página no se pudo leer')
FALLAS_DE_RED = visita.FALLAS_DE_RED

SIN_GRABACION_DOMINIO = PREFIJO + 'no hay grabación de identidad de este dominio, no se revisó'
SIN_DECLARACION = PREFIJO + 'el dominio no tiene organización de GitHub declarada, no se revisaron sus commits'
DECLARO_NINGUNA = PREFIJO + 'la empresa declaró que no tiene organización de GitHub, no se revisaron commits'
DECLARADA_INVALIDA = PREFIJO + 'la organización de GitHub declarada no es un nombre válido, no se revisaron commits'
NO_EXISTE = PREFIJO + 'la organización de GitHub declarada no existe, no se revisaron commits'
SIN_CUOTA = PREFIJO + 'GitHub no dio permiso o se acabó su cuota por hora (403 o 429)'
PARCIAL = PREFIJO + 'cobertura parcial'
SIN_LLAVE = (PREFIJO + 'falta %s (o tiene menos de %d caracteres): no se guardó ningún correo personal y '
             'personal_email_exposed queda sin cobertura' % (LLAVE, MIN_LLAVE))
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
        self.certs = {}   # url -> {correos_cert, personales_cert} de una visita que contestó con una redirección

    def sitio(self, url, contar=True, **otros):
        """visita.ClienteWeb.sitio, y anota los correos del certificado de una redirección (b2)."""
        datos = super().sitio(url, contar=contar, **otros)
        if isinstance(datos, dict) and 'cert' in datos:
            self.certs[url] = datos['cert']
        return datos

    def limpiar(self, datos):
        """La visita como se lee y se graba: una página queda en {estado, cortado, reto, identidad}, sin cabeceras ni
        cuerpo. Una redirección, un 443 cerrado o una falla quedan con su forma de visita.limpiar_visita. Lo ya
        reducido (de la grabación) se valida otra vez. ValueError si no tiene ninguna de esas formas."""
        if isinstance(datos, dict) and 'identidad' in datos:
            return _reducida(datos, self.dominio)
        if isinstance(datos, dict) and 'redirige' in datos:
            if datos['redirige'] is not None and not isinstance(datos['redirige'], str):
                raise ValueError('forma inesperada')
            # Sin la consulta del destino (a4) y con los correos del certificado del saludo que la dio (b2)
            limpia = visita.limpiar_visita(dict(datos, redirige=_destino_sin_datos(datos['redirige'])))
            cert = _cert_de_redireccion(datos, self.dominio)
            if cert is not None:
                limpia['cert'] = cert
            return limpia
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
    """El correo enmascarado: su primera letra, '***' y el servicio. Con un usuario de menos de MIN_USUARIO_MASCARA
    caracteres la primera letra dejaría casi todo el correo a la vista: solo '***' y el servicio."""
    return '%s***@%s' % (usuario[0] if len(usuario) >= MIN_USUARIO_MASCARA else '', servicio)


def _llave():
    """La llave del HMAC (LLAVE) en bytes, o None si falta o es corta."""
    valor = (config(LLAVE) or '').strip()
    return valor.encode('utf-8') if len(valor) >= MIN_LLAVE else None


# Servicios que son el mismo buzón con otro nombre, y los que no distinguen los puntos del usuario
MISMO_SERVICIO = {'googlemail.com': 'gmail.com'}
SIN_PUNTOS = frozenset({'gmail.com'})


def _normal(usuario, servicio):
    """El buzón de un correo personal para su huella: sin la '+etiqueta', con googlemail.com como gmail.com y, en
    Gmail, sin los puntos del usuario. Así juan.perez+x@gmail.com y juanperez@googlemail.com dan la misma huella."""
    usuario = usuario.split('+', 1)[0] or usuario
    servicio = MISMO_SERVICIO.get(servicio, servicio)
    if servicio in SIN_PUNTOS:
        usuario = usuario.replace('.', '') or usuario
    return '%s@%s' % (usuario, servicio)


def _clave(correo, dominio, llave):
    """La clave estable de un correo personal: un HMAC-SHA256 con la llave (LLAVE) del buzón normalizado (_normal) y
    el dominio, nunca el correo. Sin la llave no se puede rehacer probando nombres."""
    usuario, _, servicio = correo.rpartition('@')
    mensaje = 'correo|%s|%s' % (dominio, _normal(usuario, servicio))
    return hmac.new(llave, mensaje.encode('utf-8'), hashlib.sha256).hexdigest()


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
    llave = _llave() if host in GRATUITOS and usuario[0].isalnum() else None
    if llave:   # sin llave no se guarda (SIN_LLAVE)
        return 'personal', {'huella': _clave(correo, dominio, llave), 'correo': _masca(usuario, host), 'servicio': host}
    return None


def _correos_del_texto(texto, dominio):
    """(correos del dominio, personales, lleno) de un texto: tal cual, con las entidades HTML resueltas y con los %XX
    de un mailto: resueltos. Sin repetir, en el orden en que salen, hasta MAX_POR_PAGINA de cada uno. `lleno` dice que
    alguno pasó del tope (o el texto de MAX_TEXTO) y quedaron correos sin guardar."""
    propios, personales = [], {}
    vistos, lleno = set(), len(texto) > MAX_TEXTO
    base = html.unescape(texto[:MAX_TEXTO])
    for t in (base, urllib.parse.unquote(base)):
        for m in _CORREO.finditer(t):
            correo = (m.group(1) + '@' + m.group(2)).lower()
            tipo = _clasificar(correo, dominio)
            corto, _, ultima = m.group(2).rpartition('.')
            if tipo is None and '.' in corto and _PALABRA.fullmatch(ultima):
                correo = (m.group(1) + '@' + corto).lower()
                tipo = _clasificar(correo, dominio)
            if correo in vistos:
                continue
            vistos.add(correo)
            if tipo is None:
                continue
            if tipo[0] == 'dominio':
                if len(propios) < MAX_POR_PAGINA:
                    propios.append(tipo[1])
                else:
                    lleno = True
            elif tipo[1]['huella'] not in personales:
                if len(personales) < MAX_POR_PAGINA:
                    personales[tipo[1]['huella']] = tipo[1]
                else:
                    lleno = True
    return propios, list(personales.values()), lleno


def _correos_sueltos(correos, dominio):
    """(correos del dominio, personales, lleno) de una lista de correos (los del certificado), hasta MAX_POR_PAGINA."""
    propios, personales = [], {}
    correos = list(correos or ())
    for c in correos[:MAX_POR_PAGINA]:
        tipo = _clasificar(c, dominio)
        if tipo and tipo[0] == 'dominio' and tipo[1] not in propios:
            propios.append(tipo[1])
        elif tipo and tipo[0] == 'personal':
            personales.setdefault(tipo[1]['huella'], tipo[1])
    return propios, list(personales.values()), len(correos) > MAX_POR_PAGINA


def _personal_valido(p):
    return (isinstance(p, dict) and set(p) == {'huella', 'correo', 'servicio'} and isinstance(p['huella'], str)
            and bool(_HUELLA.fullmatch(p['huella'])) and p['servicio'] in GRATUITOS
            and isinstance(p['correo'], str) and bool(_ENMASCARADO.fullmatch(p['correo']))
            and p['correo'].endswith('@' + p['servicio']))


# ---------------------------------------------------------------- perfiles

class _Enlaces(html.parser.HTMLParser):
    """Los href de <a>, <link> y <area> de una página, hasta MAX_POR_PAGINA * 10. `lleno` dice que hubo más."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs, self.lleno = [], False

    def handle_starttag(self, tag, attrs):
        if tag in TAGS_ENLACE:
            for nombre, valor in attrs:
                if nombre == 'href' and isinstance(valor, str) and valor.strip():
                    if len(self.hrefs) < MAX_POR_PAGINA * 10:
                        self.hrefs.append(valor.strip())
                    else:
                        self.lleno = True

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
    if red == 'github':
        # Solo github.com/<login> o github.com/orgs/<org>: github.com/<dueño>/<repo> es un repo, muchas veces de un
        # tercero (una biblioteca que el sitio cita), no el perfil de la empresa.
        if primero.lower() == 'orgs' and len(segmentos) in (2, 3) and segmentos[2:] in ([], ['people'],
                                                                                         ['repositories']):
            primero = segmentos[1]
        elif len(segmentos) != 1:
            return None
    usuario = primero.lower()
    if usuario in RESERVADAS.get(red, ()) or not _USUARIO_RED[red].fullmatch(usuario):
        return None
    if red == 'x' and partes.path.lower().startswith(('/intent', '/share')):
        return None
    canonico = {'github': 'https://github.com/%s', 'gitlab': 'https://gitlab.com/%s', 'x': 'https://x.com/%s',
                'facebook': 'https://www.facebook.com/%s', 'instagram': 'https://www.instagram.com/%s'}[red]
    return {'red': red, 'usuario': usuario, 'url': canonico % usuario}


def _ruta(texto):
    """El usuario ya decodificado como segmento de URL: perfil(perfil(x)['url']) da lo mismo que perfil(x), también
    con un '%' o una letra con acento en el usuario."""
    return urllib.parse.quote(texto, safe="-._~")


def _perfiles_del_html(cuerpo):
    """(perfiles, lleno): los perfiles (perfil()) de los enlaces de una página, sin repetir, hasta MAX_POR_PAGINA, y
    si quedaron enlaces o perfiles sin leer por un tope. Un HTML que el parser no puede leer da los que alcanzó a ver."""
    lector = _Enlaces()
    try:
        lector.feed(cuerpo[:MAX_TEXTO])
        lector.close()
    except Exception:   # un HTML raro no tumba la corrida: quedan los enlaces que ya se leyeron
        pass
    vistos, salida, lleno = set(), [], lector.lleno
    for href in lector.hrefs:
        p = perfil(href)
        if p and p['url'] not in vistos:
            if len(salida) < MAX_POR_PAGINA:
                vistos.add(p['url'])
                salida.append(p)
            else:
                lleno = True
    return salida, lleno


def _perfil_valido(p):
    return (isinstance(p, dict) and set(p) == {'red', 'usuario', 'url'} and isinstance(p.get('url'), str)
            and perfil(p['url']) == p)


# ---------------------------------------------------------------- páginas

def _reducir(limpia, correos_cert, dominio):
    """{estado, cortado, reto, identidad} de una página ya limpia (visita.limpiar_visita) y los correos del certificado
    de su saludo. El reto (borde.reto) dice que la página no es la del sitio: no se lee."""
    reto = _reto(borde.reto(limpia['estado'], limpia['cabeceras'], limpia['cuerpo']))
    cert_propios, cert_personales, lleno = _correos_sueltos(correos_cert if isinstance(correos_cert, list) else (),
                                                            dominio)
    if reto:
        propios, personales, perfiles = [], [], []
    else:
        propios, personales, lleno_texto = _correos_del_texto(limpia['cuerpo'], dominio)
        perfiles, lleno_enlaces = _perfiles_del_html(limpia['cuerpo'])
        lleno = lleno or lleno_texto or lleno_enlaces
    # Una página con más correos o enlaces de los que caben queda como cortada: no se leyó completa
    salida = {'estado': limpia['estado'], 'cortado': limpia['cortado'] or lleno, 'reto': reto}
    salida['identidad'] = {'correos': propios, 'personales': personales, 'perfiles': perfiles,
                           'correos_cert': cert_propios, 'personales_cert': cert_personales}
    return salida


def _cert_de_redireccion(datos, dominio):
    """{correos_cert, personales_cert} del certificado que presentó un sitio que contestó con una redirección (b2 de
    la revisión de RC-56), de su saludo (tls.correos, en vivo) o ya reducido (cert, de la grabación). None si no hubo
    saludo con correos, como en una grabación de antes o una redirección por http."""
    if 'cert' in datos:
        cert = datos['cert']
        if not isinstance(cert, dict) or set(cert) != {'correos_cert', 'personales_cert'}:
            raise ValueError('forma inesperada')
        _validar_correos(cert['correos_cert'], dominio)
        _validar_personales(cert['personales_cert'])
        return {k: [dict(x) if isinstance(x, dict) else x for x in v] for k, v in cert.items()}
    tls = datos.get('tls')
    correos = tls.get('correos') if isinstance(tls, dict) else None
    if not isinstance(correos, list):
        return None
    propios, personales, _ = _correos_sueltos(correos, dominio)
    return {'correos_cert': propios, 'personales_cert': personales}


# Parámetros de la consulta de una redirección cuyo valor no se lee ni se graba: puede ser un correo o una credencial
SENSIBLES = frozenset({'login_hint', 'email', 'mail', 'correo', 'user', 'username', 'usuario', 'token', 'code',
                       'state', 'nonce', 'ticket', 'sid', 'key', 'apikey', 'api_key', 'sig', 'signature', 'otp',
                       'samlrequest', 'samlresponse', 'relaystate'})
PEDAZOS_SENSIBLES = ('token', 'secret', 'password', 'passwd', 'session', 'auth')


def _sin_correos(texto, segura):
    """`texto` tal cual, o, si trae un correo (también con %XX una o dos veces, como '%2540'), decodificado, sin los
    correos y codificado otra vez con `segura` (sin '%': aplicarlo dos veces da lo mismo, R4 de RC-56)."""
    doble = urllib.parse.unquote(urllib.parse.unquote(texto))
    if not _CORREO.search(doble):
        return texto
    return urllib.parse.quote(_CORREO.sub('_', doble), safe=segura)


def _consulta_sin_datos(consulta):
    """La consulta de una redirección con sus parámetros en el mismo orden, sin correos y sin el valor de los
    parámetros de SENSIBLES o con un pedazo de PEDAZOS_SENSIBLES en el nombre (R2 de RC-56)."""
    if not consulta:
        return ''
    pares = []
    for par in consulta.split('&'):
        nombre, igual, valor = par.partition('=')
        llano = urllib.parse.unquote_plus(nombre).strip().lower()
        if llano in SENSIBLES or any(p in llano for p in PEDAZOS_SENSIBLES):
            valor = ''
        pares.append(_sin_correos(nombre, "/:!$'()*+,-._~") + igual + _sin_correos(valor, "/:!$'()*+,-._~?"))
    return '&'.join(pares)


def _destino_sin_datos(destino):
    """El destino de una redirección como se lee y se graba (a4): sin usuario, sin fragmento ni ';parámetros', y sin
    correos en la ruta. La consulta se queda, sin correos ni valores sensibles (_consulta_sin_datos): sin ella, una
    portada que redirige a /?lang=es volvía a / hasta MAX_REDIRECCIONES (R2). La ruta va tal cual si no trae un correo
    (R4). El destino que no se puede leer queda en None, que _recorrer trata como ilegible."""
    if not isinstance(destino, str):
        return None
    try:
        partes = urllib.parse.urlsplit(destino.strip())
        partes.port
    except ValueError:
        return None
    ruta = _sin_correos(partes.path.split(';', 1)[0], "/:!$&'()*+,=-._~")
    return urllib.parse.urlunsplit((partes.scheme, partes.netloc.rpartition('@')[2], ruta,
                                    _consulta_sin_datos(partes.query), ''))


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
        _validar_correos(ident[llave], dominio)
    for llave in ('personales', 'personales_cert'):
        _validar_personales(ident[llave])
    if not isinstance(ident['perfiles'], list) or len(ident['perfiles']) > MAX_POR_PAGINA or not all(
            _perfil_valido(p) for p in ident['perfiles']):
        raise ValueError('forma inesperada')
    return {'estado': estado, 'cortado': datos['cortado'] is True, 'reto': reto,
            'identidad': {k: [dict(x) if isinstance(x, dict) else x for x in v] for k, v in ident.items()}}


def _validar_correos(lista, dominio):
    if not isinstance(lista, list) or len(lista) > MAX_POR_PAGINA or not all(
            isinstance(c, str) and _clasificar(c, dominio) == ('dominio', c) for c in lista):
        raise ValueError('forma inesperada')


def _validar_personales(lista):
    if not isinstance(lista, list) or len(lista) > MAX_POR_PAGINA or not all(_personal_valido(p) for p in lista):
        raise ValueError('forma inesperada')


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


def _fuera_del_tope(repos, elegidos):
    """Los repos que se leerían y MAX_REPOS_API dejó fuera (para sin_revisar)."""
    nombres = {r['nombre'] for r in elegidos}
    return [r for r in repos if r['nombre'] and not (r['fork'] or r['deshabilitado'] or r['privado'])
            and r['nombre'] not in nombres]


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

    def correo(self, correo, origen, donde, parte, otras=()):
        d = self.correos.setdefault(correo, {'origenes': set(), 'donde': [], 'partes': set()})
        self._anotar(d, origen, donde, parte)
        d['partes'].update(otras)

    def personal(self, p, origen, donde, parte, fecha='', otras=()):
        """`otras` son partes de las que también depende (los sitios que enlazan el perfil donde salió, o los que
        redirigen al sitio donde salió)."""
        d = self.personales.setdefault(p['huella'], {'correo': p['correo'], 'servicio': p['servicio'],
                                                     'origenes': set(), 'donde': [], 'partes': set(),
                                                     'primera_vez': ''})
        self._anotar(d, origen, donde, parte)
        d['partes'].update(otras)
        if fecha and (not d['primera_vez'] or fecha < d['primera_vez']):
            d['primera_vez'] = fecha

    def perfil(self, p, origen, host, parte, otras=()):
        d = self.perfiles.setdefault(p['url'], {'red': p['red'], 'usuario': p['usuario'], 'origenes': set(),
                                                'hosts': [], 'donde': [], 'partes': set()})
        self._anotar(d, origen, host, parte)
        d['partes'].update(otras)
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
        self.cert = None     # {correos_cert, personales_cert} del certificado de su redirección, si redirigió
        self.origenes = set()   # alcance1: los nombres de Cert Spotter que redirigen aquí, si este no es uno de ellos

    @property
    def web(self):
        """Lo que visita._recorrer mira para no visitar otra vez un sitio (b1 de la revisión de RC-56): algo si ya se
        sabe qué tiene, None si no."""
        return {} if self.visto else None

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
    sin_llave = cliente.modo != 'reproducir' and _llave() is None
    if sin_llave:   # sin llave no se guarda ningún correo personal: tampoco se graba, queda la grabación anterior
        res.avisos.append(SIN_LLAVE)
        parcial.append('llave')
    (sitios, todos_los_nombres, ct_respondio, fallas_dns, n_nombres, cortados,
     ct_completo) = _sitios(res, cliente, dominio, ahora, parcial)
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
            # b4: si se sabe qué partes tiene el dominio (Cert Spotter completo y la lista de repos entera), van en
            # sin_revisar las que existen y no se revisaron, así se cierra lo de un repo borrado o de un perfil que el
            # sitio ya no enlaza. Si no se sabe, None: solo se cierra lo que salió de partes revisadas.
            if ct_completo and gh['enumerado']:
                res.sin_revisar = sorted(set(faltan + cortados + gh['sobran']) - set(hechos))
            if sin_llave:
                # R1: con revisados el orquestador cierra por partes sin mirar sin_cobertura, y cerraría los
                # personal_email_exposed abiertos de las partes revisadas aunque sigan ahí. Sin partes revisadas no
                # se cierra nada: lo demás espera a una corrida con la llave o completa.
                res.revisados, res.sin_revisar = [], None
        else:
            res.sin_cobertura = list(CODIGOS)
        res.avisos.append('%s, se revisaron %d de %d sitios' % (PARCIAL, len([h for h in hechos if ':' not in h]),
                                                                len(sitios)))
    if sin_llave:
        if 'personal_email_exposed' not in res.sin_cobertura:
            res.sin_cobertura = list(res.sin_cobertura) + ['personal_email_exposed']
        res.sin_llave = ['personal_email_exposed']   # R5: el portal lo muestra como falta de llave (RC-229)
    if cliente.modo == 'grabar' and cliente.degradada(parcial):
        res.avisos.insert(0, NO_SE_GRABO)
    else:
        cliente.terminar()
    return res


def _sitios(res, cliente, dominio, ahora, parcial):
    """({host: _Sitio}, todos_los_nombres, ct_respondio, fallas_dns, cuántos nombres, cortados, ct_completo) de la
    visita a la portada de cada nombre. cortados son los nombres que MAX_SITIOS dejó fuera, y ct_completo dice que
    Cert Spotter dio todas sus páginas: con eso se sabe qué sitios tiene el dominio."""
    todos_los_nombres, ct_completo, cortados = True, True, []
    try:
        certs, completos = certspotter.certificados(cliente, dominio, max_paginas=visita.PAGINAS_CT,
                                                    intentos=visita.INTENTOS_CT, timeout=visita.TIMEOUT_CT)
        ct_respondio = True
        if not completos:
            res.avisos.append(PREFIJO + 'Cert Spotter no dio todas sus páginas, pueden faltar sitios del dominio')
            parcial.append('paginas' if not cliente.fallas and not cliente.raras_ct else 'ct')
            todos_los_nombres = ct_completo = False
    except FuenteNoResponde as e:
        certs, ct_respondio, todos_los_nombres, ct_completo = [], False, False, False
        res.avisos.append('%s. Solo se visitó la raíz' % e)
        parcial.append('ct')
    nombres = shodan._nombres(dominio, certs)
    conocidos = set(nombres)   # los que tienen su propia parte en sin_revisar si no se visitan (alcance1)
    if len(nombres) > MAX_SITIOS:
        res.avisos.append(PREFIJO + 'se visitaron %d de %d nombres del dominio (MAX_SITIOS)' % (MAX_SITIOS,
                                                                                               len(nombres)))
        elegidos = visita._elegir(nombres, ahora, cliente)
        cortados = sorted(set(nombres) - set(elegidos))
        nombres = elegidos
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
                saltos = []
                host, url, vista, _ = visita._recorrer(cliente, dominio, nombre, sitios, saltos)
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
            sitio.cert = cliente.certs.get('https://%s/' % nombre)   # si su primera respuesta fue una redirección
            final = _registrar(sitios, sitio, host, vista, conocidos, saltos)
            if final is not None and final is not sitio and final.cert is None:
                # R3: el destino (a -> z -> otro dominio) queda visto con los correos del certificado de su saludo
                final.cert = cliente.certs.get(url)
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
    return sitios, todos_los_nombres, ct_respondio, fallas_dns, len(nombres), cortados, ct_completo


def _registrar(sitios, sitio, host, vista, conocidos, saltos=()):
    """Lo que dejó la visita de `sitio`, que terminó en `host` (él mismo o el destino de sus redirecciones). Devuelve
    el _Sitio al que quedó lo visto, o None si el destino ya se conocía. `conocidos` son los nombres de Cert Spotter:
    un destino que no es uno de ellos anota como orígenes a `sitio` y a los hosts intermedios de la cadena (`saltos`),
    también si ya se conocía (alcance1): si uno de ellos queda sin revisar, el destino no se visita."""
    if host != sitio.nombre:   # redirigió dentro del dominio: lo que se vio es de `host`
        sitio.visto = True
        destino = sitios.setdefault(host, _Sitio(host))
        if host not in conocidos:
            destino.origenes.add(sitio.nombre)
            destino.origenes.update(s for s in saltos if s and s != host)
        if destino.visto or destino.falta or vista.get('ya_visitado'):
            return None
        sitio = destino
    if vista.get('fuera') or vista.get('rechazada') or vista.get('ya_visitado'):
        sitio.visto = True   # manda a otro dominio o no tiene https ni http: no hay página del dominio que leer
    elif 'sin_respuesta' in vista:
        sitio.sin_revisar(vista['sin_respuesta'])
    elif 'identidad' not in vista:   # una página que limpiar() no redujo: no se lee
        sitio.sin_revisar('pagina')
    else:
        sitio.pagina = vista
        if vista['reto']:
            sitio.sin_revisar('reto')
        elif visita._error_servidor(vista):
            sitio.sin_revisar('error_http')
        elif vista['cortado']:
            sitio.sin_revisar('cortado')
        else:
            sitio.visto = True
    return sitio


def _leer_sitio(res, sitio, junta):
    """Los correos y perfiles de la página de `sitio`. Lo de una página con reto no se lee. Lo de un 5xx o una página
    cortada sí: se vio en la página que llegó, aunque el sitio quede sin revisar. Lo de un destino que no es nombre de
    Cert Spotter lleva también como partes los nombres que redirigen a él (alcance1)."""
    otras = sorted(sitio.origenes)
    donde = 'certificado de %s' % sitio.nombre
    for correo in (sitio.cert or {}).get('correos_cert', ()):
        junta.correo(correo, 'certificado', donde, sitio.nombre, otras)
    for p in (sitio.cert or {}).get('personales_cert', ()):
        junta.personal(p, 'certificado', donde, sitio.nombre, otras=otras)
    pagina = sitio.pagina
    if pagina is None:
        return
    if pagina['reto']:
        res.avisos.append(PREFIJO + 'el sitio %s respondió con un reto o bloqueo (%s): sus correos y perfiles quedan '
                          'sin cobertura, no 0' % (sitio.nombre, pagina['reto'].get('motivo') or 'sin motivo'))
    ident = pagina['identidad']
    donde = 'sitio %s' % sitio.nombre
    for correo in ident['correos']:
        junta.correo(correo, 'sitio', donde, sitio.nombre, otras)
    for p in ident['personales']:
        junta.personal(p, 'sitio', donde, sitio.nombre, otras=otras)
    for p in ident['perfiles']:
        junta.perfil(p, 'sitio', sitio.nombre, sitio.nombre, otras)
    donde = 'certificado de %s' % sitio.nombre
    for correo in ident['correos_cert']:
        junta.correo(correo, 'certificado', donde, sitio.nombre, otras)
    for p in ident['personales_cert']:
        junta.personal(p, 'certificado', donde, sitio.nombre, otras=otras)


def _github(res, cliente, dominio, junta, parcial):
    """Los commits de la organización declarada y el correo público de los perfiles de GitHub enlazados desde el
    sitio. {respondio, completo, hechos, faltan}: las partes 'github:...' revisadas y las que faltaron."""
    # enumerado: se sabe qué partes github:... existen (sin org, o con su lista de repos entera). sobran: las que
    # existen y los topes dejaron fuera, para sin_revisar.
    estado = {'respondio': False, 'completo': True, 'hechos': [], 'faltan': [], 'enumerado': True, 'sobran': []}
    org = github.declarada(dominio)
    aviso = (SIN_DECLARACION if org is None else DECLARO_NINGUNA if org == github.NINGUNA else
             DECLARADA_INVALIDA if not github.ORG_VALIDA.fullmatch(org) else None)
    # login -> los sitios que lo enlazan: un correo de su perfil también depende de que el sitio lo siga enlazando
    sitios_de = {}
    for d in junta.perfiles.values():
        if d['red'] == 'github':
            sitios_de.setdefault(d['usuario'], set()).update(d['partes'])
    perfiles = sorted(sitios_de)
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
        if repos is None:
            estado['enumerado'] = False
        if isinstance(repos, dict) and repos.get('no_existe'):
            res.avisos.append(NO_EXISTE)
            repos = []
        if isinstance(repos, list):
            if len(repos) >= POR_PAGINA:
                res.avisos.append(PREFIJO + 'GitHub dio %d repos de %s en una página: pueden faltar' % (len(repos), org))
                estado['completo'] = estado['enumerado'] = False
                parcial.append('repos')
            elegidos, sobran = _elegir_repos(repos)
            estado['sobran'] += ['github:%s/%s' % (org.lower(), r['nombre']) for r in _fuera_del_tope(repos, elegidos)]
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
                    # Con 12 hex del nombre: 'a_b' y 'a__b' (o 'web' y 'web_') no comparten archivo (c2)
                    commits = cliente.github('gh:commits:%s/%s:%s' % (org.lower(), r['nombre'], hashlib.sha256(
                                                 r['nombre'].encode('utf-8')).hexdigest()[:12]),
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
        estado['sobran'] += ['github:perfil:%s' % login for login in perfiles[MAX_PERFILES_API:]]
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
            junta.personal(usuario['personal'], 'perfil', donde, parte, otras=sitios_de[login])
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
