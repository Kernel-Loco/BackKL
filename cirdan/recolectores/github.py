"""Secretos, correos y organización pública en GitHub (#16, RC-50).

Revisa los repositorios públicos de la organización de GitHub que la empresa declaró como suya y devuelve:
- secret_in_public_repo (crítico, sobre el activo domain): una clave de acceso en la versión actual o en el historial
  de un repo. La busca gitleaks 8.21.2 con gitleaks_cirdan.toml: sus reglas de omisión más una para los tokens falsos
  CIRDAN_FAKE_ de la siembra y de las pruebas. Un secreto que ya solo vive en el historial también es crítico.
- email_in_public_commits (bajo, sobre un activo email por correo): un correo del dominio, o de un subdominio, como
  autor o como quien subió un commit.
- el activo domain con atributos['github']: la organización, si su perfil enlaza al dominio, si GitHub la verificó y
  qué repos se revisaron y cuántos se saltaron.

Organización declarada. Solo se revisa la organización que la empresa declara controlar, que hace de campo
'Organización de GitHub de la empresa' de la carta. Hasta la tabla de #64 la declaración vive en la variable
ORGS_GITHUB_DECLARADAS, con pares dominio=org separados por comas (por omisión olmardo.com=olmardo), y es de toda la
plataforma, no de cada carta. Sin declaración, con 'ninguna' o con un nombre inválido no se consulta nada: la fuente
queda succeeded, con sus 2 códigos en sin_cobertura y un aviso, así el portal dice 'sin cobertura' y no 0. Deducir la
organización del nombre del dominio (GET /orgs/<etiqueta>) va apagado: la política de uso ético prohíbe adivinar
nombres de recursos.

Qué consulta, y nada más:
- GET /orgs/<org> y una página de GET /orgs/<org>/repos (hasta 100, por pushed_at), sin token y con 3 intentos cada una.
- git clone --bare --no-tags por https de hasta MAX_REPOS repos que no sean fork ni deshabilitados, de hasta MAX_KB_REPO
  cada uno, por pushed_at descendente. Los archivados entran, y los de tamaño 0 también: GitHub calcula 'size' cada hora
  y un repo recién creado sale con 0 aunque ya tenga commits.
- Lo demás es local, sobre el clon: gitleaks git con --redact, que salta los archivos de más de MAX_MB_ARCHIVO MB, y git
  log para los correos.

Sin secretos ni datos personales de más:
- gitleaks corre con --redact y su reporte se lee por lista blanca: RuleID, File y Date. Nunca Secret, Match, Author,
  Email ni Message. Si un hallazgo trae Secret o Match sin redactar, la corrida se descarta: queda sin cobertura con un
  aviso fijo, sin grabar nada, y no se reintenta, porque daría lo mismo.
- La huella es el sha256 de código, repo, ruta y regla: no depende del valor del secreto, que no se usa, no se guarda ni
  sale del proceso. Si llega sin redactar, solo se lee para comprobarlo y la corrida se descarta.
- De git log solo salen los correos del autor y de quien subió cada commit, en minúsculas. Los nombres nunca. Los que no
  son del dominio (noreply, gmail, parecidos) y los del dominio con forma inválida se descartan y solo se cuentan en un
  aviso, sin sus valores. El título del hallazgo no lleva el correo, que ya es su activo.
- Ni stderr ni el texto de una excepción llegan al resultado: scan_source_runs.error se guarda aunque keep_raw_payload
  sea false. Toda falla sale como FuenteNoResponde con un texto fijo (paso, repo y código de salida).
- El clon, el reporte y la salida de git log viven en una carpeta temporal cirdan-github-* que no puede pasar de
  MAX_DISCO mientras corre git o gitleaks y que se borra al terminar. Si la API muere a medias, o si el sistema no deja
  borrarla, se queda, así que cada corrida en vivo o al grabar empieza borrando las que tengan más de una hora.

Límites de una corrida: MAX_REPOS repos, MAX_KB_REPO por repo, MAX_DISCO de disco, TIMEOUT_CLON s por clon,
TIMEOUT_GITLEAKS s por gitleaks, TIMEOUT_LOG s por git log y TIEMPO_CORRIDA s en total, también para la API. Un repo
que no se revisó por un límite o una falla deja un aviso de cobertura parcial. Si así un código quedó sin hallazgos,
va a sin_cobertura. Si ya trae hallazgos no puede ir ahí (validar() lo rechaza y la fuente quedaría failed): queda el
aviso y revisados lleva los repos que sí se revisaron ('org/repo'). Cada secreto lleva su repo como parte y cada
correo los repos donde salió, así el orquestador no cierra el secreto de un repo que no se clonó. Si no hubo más
páginas de repos y todos los que se revisarían tienen nombre válido, sin_revisar lleva los públicos que no se
revisaron, sin forks ni deshabilitados, que una corrida completa tampoco revisa. Así se cierra lo de un repo que ya
no está, como uno borrado o que se hizo privado (#23). Si no se pudo revisar ningún repo,
la fuente no respondió. Sin git o gitleaks instalados tampoco responde, y se sabe antes de consultar la API.

Cuota de GitHub sin token: 60 consultas por hora por IP. Un 403 o 429 no se reintenta en la corrida ni la deja failed,
porque el orquestador la reintentaría a 1, 5 y 25 minutos reservando MAX_CONSULTAS cada vez: queda succeeded con sus 2
códigos en sin_cobertura y un aviso. Un clon no gasta esa cuota, pero cuenta como consulta del límite diario (#13b).

Modos: 'vivo' consulta GitHub; 'grabar' además guarda lo ya limpio en
cirdan/recolectores/respuestas_grabadas/github/<dominio>/ (perfil y lista de repos filtrados y, por repo, los secretos
reducidos y los correos ya filtrados), nunca el clon ni el reporte, y solo si la corrida terminó, así una grabación
fallida deja intacta la anterior; 'reproducir' solo lee esa grabación. Sin grabación del dominio, reproducir da
sin_cobertura y un aviso, no failed, para que la demo no muestre la fuente caída.

    python -m cirdan.recolectores.github olmardo.com --reproducir
    python -m cirdan.recolectores.github olmardo.com --grabar

A diferencia de crt.sh, la línea de comandos rechaza vivo y --grabar si el dominio no está en DOMINIOS_EN_VIVO.
Código de salida: 0 bien, 1 si queda en 'failed', 2 si quedan avisos.
"""
import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cirdan.config import config
from cirdan.ml import caracteristicas as rubrica
from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import (NOMBRE_VALIDO, Activo, FuenteNoResponde, Grabadora, Hallazgo, Resultado,
                                          SinGrabacion, con_reintentos, en_alcance_nombre, fecha_iso, nombre_archivo)

FUENTE = 'github'
CARPETA_GRABADAS = RAIZ_GRABADAS / 'github'
REGLAS = Path(__file__).resolve().parent / 'gitleaks_cirdan.toml'

# Código de regla -> severidad base. Los dos existen en el catálogo de reglas (semilla 004).
CODIGOS = {'secret_in_public_repo': 'critical', 'email_in_public_commits': 'low'}
TIPOS = {'secret_in_public_repo': 'secreto_en_repositorio', 'email_in_public_commits': 'correo_en_commits'}

DECLARADAS = 'ORGS_GITHUB_DECLARADAS'          # dominio=org,dominio=org
DECLARADAS_OMISION = 'olmardo.com=olmardo'
NINGUNA = 'ninguna'                            # la empresa declaró que no tiene organización en GitHub

API = 'https://api.github.com'
CLON = 'https://github.com/%s/%s.git'
AGENTE = 'cirdan-osint/0.1 (+https://github.com/Kernel-Loco)'   # el mismo de crtsh.py
VERSION_API = '2022-11-28'
TIMEOUT_HTTP = 30                # segundos por petición a la API
INTENTOS = 3                     # intentos por petición a la API dentro de una corrida
MAX_BYTES = 5 * 1024 * 1024      # tope de una respuesta de la API
POR_PAGINA = 100                 # se lee una sola página de repos
MAX_REPOS = 10                   # repos que se clonan por corrida
MAX_KB_REPO = 100 * 1024         # 100 MB, en KB como 'size' de la API
TIMEOUT_CLON = 120               # segundos por clon
TIMEOUT_GITLEAKS = 120           # segundos por gitleaks
TIMEOUT_LOG = 60                 # segundos por git log
TIEMPO_CORRIDA = 360             # segundos de toda la corrida: ningún paso empieza ni sigue después
MIN_RESTANTE = 5                 # con menos segundos que esto ya no se empieza otro repo
# Peor caso de una corrida para el límite diario (#13b): perfil y página de repos con sus 3 intentos y un clon por repo.
MAX_CONSULTAS = INTENTOS * 2 + MAX_REPOS
PREFIJO_TEMPORAL = 'cirdan-github-'
VIEJA_S = 3600                   # una carpeta temporal con más de una hora es de una corrida que ya no corre
MAX_REPORTE = 50 * 1024 * 1024   # tope del reporte de gitleaks
MAX_LOG = 20 * 1024 * 1024       # tope de la salida de git log
MAX_DISCO = 300 * 1024 * 1024    # tope de la carpeta temporal mientras corre git o gitleaks
MAX_MB_ARCHIVO = 100             # gitleaks salta los archivos de más de esto (--max-target-megabytes)
VIGILAR_S = 1                    # cada cuánto se revisan el tiempo y el disco de un proceso
MAX_RUTA = 300
MAX_REPOS_ACTIVO = 5             # repos que se nombran en un activo email
REDACTADO = 'REDACTED'           # lo que pone gitleaks --redact en Secret y dentro de Match

# Opciones de git en cada llamada: sin hooks, solo https, revisa los objetos al recibirlos y nunca pide credenciales.
OPCIONES_GIT = ('-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
                '-c', 'transfer.fsckObjects=true', '-c', 'credential.helper=')
FORMATO_LOG = '--format=%ae%x00%ce%x00%ct'      # correo del autor, de quien subió el commit y fecha (epoch)

ORG_VALIDA = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}')        # sin '-' inicial, '/' ni '.'
REPO_VALIDO = re.compile(r'[A-Za-z0-9._][A-Za-z0-9._-]{0,99}')   # sin '-' inicial ni '/'. '..' se rechaza aparte
REGLA_VALIDA = re.compile(r'[a-z0-9][a-z0-9_-]{0,79}')
USUARIO_VALIDO = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}")
EPOCH = re.compile(r'[0-9]{1,12}')
CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f]')

# Avisos con texto fijo: nunca llevan valores de la fuente.
SIN_DECLARACION = 'github: el dominio no tiene organización de GitHub declarada, no se revisó GitHub'
DECLARO_NINGUNA = 'github: la empresa declaró que no tiene organización de GitHub, no se revisó GitHub'
DECLARADA_INVALIDA = 'github: la organización declarada no es un nombre válido de GitHub, no se revisó GitHub'
NO_EXISTE = 'github: la organización declarada no existe en GitHub'
RENOMBRADA = 'github: la organización declarada cambió de nombre en GitHub, hay que actualizar la declaración'
SIN_CUOTA = 'github: GitHub no dio permiso o se acabó su cuota por hora (403 o 429), no se revisó GitHub'
SIN_GRABACION_DOMINIO = 'github: no hay grabación de GitHub de este dominio, no se revisó GitHub'
SIN_REDACTAR = 'github: gitleaks entregó un hallazgo sin redactar y se descartó la corrida'
SALTADOS = {'fork': 'fork', 'deshabilitado': 'deshabilitado', 'grande': 'de más de 100 MB o sin tamaño',
            'nombre_invalido': 'con nombre inválido', 'sobra': 'más allá de los %d más recientes' % MAX_REPOS}
PARCIALES = ('grande', 'nombre_invalido', 'sobra')   # saltados que sí son cobertura parcial


class NoExiste(Exception):
    """GitHub respondió 404."""


class CuotaAgotada(Exception):
    """GitHub respondió 403 o 429: sin permiso o sin cuota por hora. No se reintenta en la corrida."""


class Renombrada(Exception):
    """El perfil que devolvió GitHub es de otra organización: la declarada cambió de nombre."""


class FallaRepo(FuenteNoResponde):
    """Un repo no se pudo revisar. La corrida sigue con los demás y queda con cobertura parcial."""


# ---------------------------------------------------------------- organización declarada

def declarada(dominio):
    """La organización de GitHub declarada para el dominio en ORGS_GITHUB_DECLARADAS: su nombre, NINGUNA o None."""
    for par in (config(DECLARADAS, DECLARADAS_OMISION) or '').split(','):
        nombre, igual, org = par.partition('=')
        if igual and nombre.strip().lower().rstrip('.') == dominio:
            org = org.strip()
            return NINGUNA if org.lower() == NINGUNA else org
    return None


def _en_vivo_permitido(dominio):
    """Lo mismo que orquestador.en_vivo_permitido(), sin importar el orquestador (que importa los recolectores)."""
    permitidos = {d.strip().lower() for d in config('DOMINIOS_EN_VIVO', 'olmardo.com').split(',') if d.strip()}
    return '*' in permitidos or dominio in permitidos


# ---------------------------------------------------------------- limpieza de lo que da GitHub

def _texto(valor):
    """Un texto que se puede grabar en UTF-8 y en la base: sin surrogates sueltos ni caracteres de control."""
    return CONTROL.sub('?', valor.encode('utf-8', 'replace').decode('utf-8'))


def _ruta(valor):
    return _texto(valor)[:MAX_RUTA] if isinstance(valor, str) and valor else '(sin ruta)'


def _fecha(valor):
    """La fecha en ISO 8601 con zona, o None si no es una fecha."""
    if not isinstance(valor, str):
        return None
    try:
        return fecha_iso(valor).isoformat()
    except (ValueError, TypeError):
        return None


def _primera(a, b):
    return min(x for x in (a, b) if x) if a or b else None


def _repo_valido(nombre):
    return (isinstance(nombre, str) and bool(REPO_VALIDO.fullmatch(nombre)) and '..' not in nombre
            and bool(nombre.strip('.')))


def _del_dominio(host, dominio):
    return isinstance(host, str) and bool(host) and en_alcance_nombre(host, dominio)


def _blog_del_dominio(blog, dominio):
    """El sitio del perfil está en el dominio. El host sale de urllib.parse, no de comparar el texto."""
    if not isinstance(blog, str) or not blog.strip():
        return False
    texto = blog.strip() if '://' in blog else 'https://' + blog.strip()
    if '\\' in texto:  # urlsplit no corta en '\\' y un navegador sí: 'https://otro.com\\@dominio' abre otro.com
        return False
    try:
        return _del_dominio(urllib.parse.urlsplit(texto).hostname, dominio)
    except ValueError:
        return False


def _correo_del_dominio(correo, dominio):
    """El correo del perfil tiene una sola '@', algo antes de ella y un host del dominio."""
    if not isinstance(correo, str):
        return False
    usuario, arroba, host = correo.strip().rpartition('@')
    return bool(arroba and usuario and '@' not in usuario) and _del_dominio(host, dominio)


def correo_valido(correo, dominio):
    """Un correo en minúsculas, del dominio o de un subdominio, que también cumple la regla de correos del contrato."""
    usuario, arroba, host = correo.rpartition('@')
    return bool(arroba and USUARIO_VALIDO.fullmatch(usuario) and NOMBRE_VALIDO.fullmatch(host)
                and en_alcance_nombre(host, dominio))


def perfil_limpio(datos, org, dominio):
    """Del perfil de la organización solo lo que se usa: nombre, verificada, si enlaza al dominio y cuántos repos."""
    if not isinstance(datos, dict) or not isinstance(datos.get('login'), str):
        raise FuenteNoResponde('github: el perfil de la organización no se puede leer')
    if datos['login'].lower() != org.lower() or not ORG_VALIDA.fullmatch(datos['login']):
        raise Renombrada()
    repos = datos.get('public_repos')
    return {'login': datos['login'], 'verificada': datos.get('is_verified') is True,
            'blog_del_dominio': _blog_del_dominio(datos.get('blog'), dominio),
            'correo_del_dominio': _correo_del_dominio(datos.get('email'), dominio),
            'repos_publicos': repos if type(repos) is int and repos >= 0 else None}


def _perfil_grabado(datos, org):
    if not (isinstance(datos, dict) and isinstance(datos.get('login'), str) and ORG_VALIDA.fullmatch(datos['login'])
            and datos['login'].lower() == org.lower()):
        raise FuenteNoResponde('github: la grabación del perfil no se puede leer')
    repos = datos.get('repos_publicos')
    return {'login': datos['login'], 'verificada': datos.get('verificada') is True,
            'blog_del_dominio': datos.get('blog_del_dominio') is True,
            'correo_del_dominio': datos.get('correo_del_dominio') is True,
            'repos_publicos': repos if type(repos) is int and repos >= 0 else None}


def repos_limpios(datos):
    """De la página de repos solo nombre, fork, deshabilitado, archivado, privado, tamaño en KB y último push. Un nombre
    inválido se guarda vacío, así nunca llega a una línea de comandos ni a la grabación."""
    if not isinstance(datos, list):
        raise FuenteNoResponde('github: la lista de repos no se puede leer')
    repos = []
    for r in datos:
        if not isinstance(r, dict):
            continue
        kb, subido = r.get('size', r.get('kb')), r.get('pushed_at', r.get('subido'))
        repos.append({'nombre': r.get('name', r.get('nombre')) if _repo_valido(r.get('name', r.get('nombre'))) else '',
                      'fork': r.get('fork') is True,
                      'deshabilitado': (r.get('disabled') if 'disabled' in r else r.get('deshabilitado')) is True,
                      'archivado': (r.get('archived') if 'archived' in r else r.get('archivado')) is True,
                      'privado': (r.get('private') if 'private' in r else r.get('privado')) is True,
                      'kb': kb if type(kb) is int and kb >= 0 else None,
                      'subido': _fecha(subido) or ''})
    return repos


def elegir(repos):
    """(los repos que se clonan, cuántos se saltaron por motivo). Hasta MAX_REPOS por último push, del más reciente."""
    saltados = dict.fromkeys(SALTADOS, 0)
    candidatos = []
    for r in repos:
        if r['privado']:  # sin token no deberían llegar. No se revisan ni se cuentan como públicos
            continue
        motivo = ('fork' if r['fork'] else 'deshabilitado' if r['deshabilitado'] else
                  'nombre_invalido' if not r['nombre'] else
                  'grande' if r['kb'] is None or r['kb'] > MAX_KB_REPO else None)
        if motivo:
            saltados[motivo] += 1
        else:
            candidatos.append(r)
    candidatos.sort(key=lambda r: (r['subido'], r['nombre']), reverse=True)
    saltados['sobra'] = max(0, len(candidatos) - MAX_REPOS)
    return candidatos[:MAX_REPOS], saltados


# ---------------------------------------------------------------- lo que dan gitleaks y git log

class SecretoSinRedactar(FuenteNoResponde):
    """gitleaks entregó Secret o Match sin redactar. Descarta la corrida: nada de ella se guarda ni se graba, y queda
    sin cobertura y no failed, porque reintentarla volvería a dar lo mismo."""

    def __init__(self):
        super().__init__(SIN_REDACTAR)


def leer_reporte(texto):
    """[{regla, ruta, primera_vez}] del reporte JSON de gitleaks: uno por ruta y regla, con la fecha más vieja.

    Solo lee RuleID, File y Date. Secret y Match solo se miran para comprobar que vienen redactados. Lanza
    SecretoSinRedactar si no, y ValueError si el reporte no tiene la forma de gitleaks."""
    datos = json.loads(texto)
    if not isinstance(datos, list):
        raise ValueError('el reporte no es una lista')
    vistos = {}
    for f in datos:
        if not isinstance(f, dict):
            raise ValueError('un hallazgo del reporte no es un objeto')
        coincide = f.get('Match', '')
        if f.get('Secret') != REDACTADO or not isinstance(coincide, str) or (coincide and REDACTADO not in coincide):
            raise SecretoSinRedactar()
        regla = f.get('RuleID') if isinstance(f.get('RuleID'), str) and REGLA_VALIDA.fullmatch(f['RuleID']) else 'desconocida'
        llave = (_ruta(f.get('File')), regla)
        vistos[llave] = _primera(vistos.get(llave), _fecha(f.get('Date')))
    return [{'regla': regla, 'ruta': ruta, 'primera_vez': fecha} for (ruta, regla), fecha in sorted(vistos.items())]


def leer_correos(texto, dominio):
    """([{correo, commits, primera_vez}], ajenos, invalidos) de la salida de git log con FORMATO_LOG.

    Solo quedan los correos del dominio o de un subdominio que pasan correo_valido(). ajenos e invalidos cuentan los
    demás correos distintos, sin guardarlos."""
    commits, primera, ajenos, invalidos = {}, {}, set(), set()
    # split('\n') y no splitlines(): git deja \x1c-\x1e, \x85 o U+2028 dentro de un correo y splitlines() también corta
    # ahí, así que la cola de un correo inválido saldría como uno válido.
    for linea in (texto or '').split('\n'):
        partes = linea.split('\x00')
        if len(partes) != 3:
            continue
        cuando = partes[2].strip()
        cuando = (datetime.fromtimestamp(int(cuando), timezone.utc).isoformat()
                  if EPOCH.fullmatch(cuando) and int(cuando) < 253402300800 else None)
        # Solo espacios y tabuladores: strip() también quitaría de las puntas \x0b, \x1c-\x1f, \x85 o U+2028, y un
        # correo armado con ellos saldría como válido.
        for correo in {p.strip(' \t').lower() for p in partes[:2]} - {''}:
            if '@' not in correo or not en_alcance_nombre(correo.rpartition('@')[2], dominio):
                ajenos.add(correo)
            elif not correo_valido(correo, dominio):
                invalidos.add(correo)
            else:
                commits[correo] = commits.get(correo, 0) + 1
                primera[correo] = _primera(primera.get(correo), cuando)
    correos = [{'correo': c, 'commits': commits[c], 'primera_vez': primera[c]} for c in sorted(commits)]
    return correos, len(ajenos), len(invalidos)


def revision_valida(datos, dominio):
    """Lo de un repo (de revisar() o de la grabación) revisado otra vez, así vivo y reproducir dan lo mismo y una
    grabación cambiada a mano no mete otra cosa."""
    if not (isinstance(datos, dict) and isinstance(datos.get('secretos'), list) and isinstance(datos.get('correos'), list)):
        raise FallaRepo('github: la grabación de un repo no se puede leer')
    secretos = {}
    for s in datos['secretos']:
        if isinstance(s, dict) and isinstance(s.get('regla'), str) and REGLA_VALIDA.fullmatch(s['regla']):
            llave = (_ruta(s.get('ruta')), s['regla'])
            secretos[llave] = _primera(secretos.get(llave), _fecha(s.get('primera_vez')))
    correos = {}
    for c in datos['correos']:
        if (isinstance(c, dict) and isinstance(c.get('correo'), str) and correo_valido(c['correo'], dominio)
                and type(c.get('commits')) is int and c['commits'] > 0):
            x = correos.setdefault(c['correo'], {'correo': c['correo'], 'commits': 0, 'primera_vez': None})
            x['commits'] += c['commits']
            x['primera_vez'] = _primera(x['primera_vez'], _fecha(c.get('primera_vez')))

    def conteo(n):
        return n if type(n) is int and n >= 0 else 0
    return {'secretos': [{'regla': regla, 'ruta': ruta, 'primera_vez': f} for (ruta, regla), f in sorted(secretos.items())],
            'correos': [correos[c] for c in sorted(correos)],
            'ajenos': conteo(datos.get('ajenos')), 'invalidos': conteo(datos.get('invalidos'))}


# ---------------------------------------------------------------- procesos y HTTP

def _binario(nombre):
    """Ruta de un programa en el PATH, o None si no está instalado."""
    return shutil.which(nombre)


class MuyGrande(Exception):
    """La carpeta temporal pasó de su tope mientras corría un proceso."""


def _matar(proceso):
    """Mata el proceso con sus hijos (git clone deja otros, como git-remote-https): en Linux con todo su grupo y en
    Windows con taskkill /T, para que ninguno siga escribiendo en la carpeta temporal."""
    try:
        if os.name == 'posix':
            os.killpg(proceso.pid, signal.SIGKILL)
            return
        try:
            subprocess.run(['taskkill', '/T', '/F', '/PID', str(proceso.pid)], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        except (OSError, subprocess.SubprocessError):
            pass
        proceso.kill()
    except OSError:
        pass


def _peso(carpeta):
    """Bytes de los archivos bajo la carpeta, sin seguir enlaces."""
    total = 0
    for raiz, _, archivos in os.walk(carpeta):
        for nombre in archivos:
            try:
                total += os.lstat(os.path.join(raiz, nombre)).st_size
            except OSError:
                pass
    return total


def _ejecutar(comando, timeout, env, cwd, salida=None, disco=None):
    """Corre un proceso sin shell ni entrada y sin leer su stderr, que puede traer URLs o pedazos del repo. Su stdout va
    al archivo `salida`, nunca a la memoria de la API, o se tira. Cada VIGILAR_S revisa el tiempo y, con `disco`, que la
    carpeta `cwd` no pase de esos bytes: si se pasa lanza TimeoutExpired o MuyGrande y lo mata con sus hijos. En Linux va
    en su propio grupo de procesos para matarlo completo."""
    fin = time.monotonic() + timeout
    with open(salida, 'xb') if salida else contextlib.nullcontext(subprocess.DEVNULL) as destino:
        opciones = {'stdin': subprocess.DEVNULL, 'stdout': destino, 'stderr': subprocess.DEVNULL, 'env': env, 'cwd': cwd}
        if os.name == 'posix':
            opciones['start_new_session'] = True
        with subprocess.Popen(comando, **opciones) as proceso:
            try:
                while True:
                    try:
                        proceso.wait(timeout=max(0, min(VIGILAR_S, fin - time.monotonic())))
                    except subprocess.TimeoutExpired:
                        if time.monotonic() >= fin:
                            raise subprocess.TimeoutExpired(comando, timeout) from None
                    if disco is not None and _peso(cwd) > disco:
                        raise MuyGrande()
                    if proceso.returncode is not None:
                        break
            except BaseException:
                _matar(proceso)
                raise
    return subprocess.CompletedProcess(comando, proceso.returncode, None, None)


def _entorno(casa):
    """Entorno limpio para git y gitleaks: nada de la API, sin configuración global ni del sistema y sin preguntar. En
    Windows también SYSTEMROOT, sin la que git no puede abrir conexiones."""
    env = {'PATH': os.environ.get('PATH', os.defpath), 'HOME': casa, 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0', 'GIT_LFS_SKIP_SMUDGE': '1'}
    if os.name == 'nt':
        env['SYSTEMROOT'] = os.environ.get('SYSTEMROOT', r'C:\Windows')
    return env


def _descargar(url, timeout):
    """El cuerpo de la respuesta. `timeout` vale para cada operación del socket y también para toda la respuesta, así
    una que llega gota a gota se corta igual."""
    fin = time.monotonic() + timeout
    req = urllib.request.Request(url, headers={'User-Agent': AGENTE, 'Accept': 'application/vnd.github+json',
                                               'X-GitHub-Api-Version': VERSION_API})
    partes, total = [], 0
    with urllib.request.urlopen(req, timeout=timeout) as r:
        while True:
            if time.monotonic() > fin:
                raise TimeoutError('la respuesta no terminó en %s s' % timeout)
            trozo = r.read1(64 * 1024)
            if not trozo:
                break
            partes.append(trozo)
            total += len(trozo)
            if total > MAX_BYTES:
                raise ValueError('respuesta de más de %d bytes' % MAX_BYTES)
    return b''.join(partes)


def _archivo(consulta):
    """Nombre del archivo grabado: el legible del contrato más 12 de su sha256, así dos repos que solo difieren en
    caracteres que nombre_archivo() cambia por '_' no comparten archivo."""
    return '%s-%s.json' % (nombre_archivo(consulta)[:-len('.json')][:100],
                           hashlib.sha256(consulta.encode('utf-8')).hexdigest()[:12])


def _borrar(carpeta):
    """rmtree sin lanzar errores. En Windows git deja los .pack y .idx en solo lectura y rmtree no los borra, así que
    a lo que no pudo borrar le quita ese modo y lo intenta otra vez."""
    if os.name != 'nt':
        shutil.rmtree(carpeta, ignore_errors=True)
        return

    def solo_lectura(funcion, ruta, _error):
        if funcion in (os.unlink, os.remove, os.rmdir):
            with contextlib.suppress(OSError):
                # Un enlace duro no se toca: el chmod también cambiaría el archivo de fuera de la carpeta.
                if os.lstat(ruta).st_nlink == 1:
                    os.chmod(ruta, stat.S_IWRITE)
                    funcion(ruta)

    with contextlib.suppress(OSError):
        if sys.version_info >= (3, 12):
            shutil.rmtree(carpeta, onexc=solo_lectura)
        else:
            shutil.rmtree(carpeta, onerror=solo_lectura)


def limpiar_viejas(raiz=None, vieja=VIEJA_S):
    """Borra las carpetas cirdan-github-* de más de `vieja` segundos: las dejó una corrida que se cortó sin su finally.
    Las de una corrida en curso son más nuevas y no se tocan."""
    limite = time.time() - vieja
    for carpeta in Path(raiz or tempfile.gettempdir()).glob(PREFIJO_TEMPORAL + '*'):
        try:
            if carpeta.is_dir() and not carpeta.is_symlink() and carpeta.stat().st_mtime < limite:
                _borrar(carpeta)
        except OSError:
            pass


class ClienteGitHub:
    """Consulta la API, clona y revisa cada repo y, según el modo, graba o reproduce lo ya limpio con la Grabadora del
    contrato (#13).

    `descargar(url, timeout)`, `ejecutar(comando, timeout, env, cwd, salida, disco)`, `git`, `gitleaks`, `cronometro`, `dormir` y
    `temporal` se inyectan en las pruebas. Por omisión son urllib, _ejecutar, los del PATH, time.monotonic, time.sleep y
    la carpeta temporal del sistema. `consultas` suma cada intento a la API y cada clon."""

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, descargar=None, ejecutar=None, git=None, gitleaks=None,
                 nueva=False, reloj=None, cronometro=None, dormir=None, temporal=None):
        self.modo = modo
        self.grabadora = Grabadora(carpeta, modo, nueva=nueva, reloj=reloj, nombre=_archivo)
        self.descargar = descargar or _descargar
        self.ejecutar = ejecutar or _ejecutar
        self.git, self.gitleaks = git, gitleaks
        self.cronometro = cronometro or time.monotonic
        self.dormir = dormir or time.sleep
        self.temporal = temporal
        self.consultas = 0
        self.inicio = None
        self.pendientes = []   # lo que se graba cuando la corrida termina

    @property
    def leidas(self):
        """(archivo, fecha de grabación) de cada respuesta tomada del disco."""
        return self.grabadora.leidas

    def empezar(self):
        self.inicio = self.cronometro()
        if self.modo != 'reproducir':
            self._programas()   # antes de gastar consultas: sin git o gitleaks no se puede revisar nada
            limpiar_viejas(self.temporal)

    def restante(self):
        """Segundos que le quedan a la corrida. Al reproducir no corre ningún proceso y no hay tope."""
        if self.modo == 'reproducir':
            return TIEMPO_CORRIDA
        if self.inicio is None:
            self.inicio = self.cronometro()
        return TIEMPO_CORRIDA - (self.cronometro() - self.inicio)

    def _de_disco(self, consulta):
        return self.grabadora.de_disco(consulta)

    def _grabar(self, consulta, datos):
        if self.modo == 'grabar':
            self.pendientes.append((consulta, datos))

    def terminar(self):
        """La corrida terminó: graba todo lo pendiente. Una corrida que falla no llega aquí y no toca la grabación."""
        for consulta, datos in self.pendientes:
            self.grabadora.guardar(consulta, datos)
        self.pendientes = []

    def _api(self, ruta, paso):
        """JSON de la API de GitHub con hasta INTENTOS intentos, dentro del tiempo de la corrida. Un 404 lanza NoExiste
        y un 403 o 429 CuotaAgotada, sin reintentar. Lo demás sale como FuenteNoResponde con texto fijo."""
        url = API + ruta

        def consulta():
            limite = min(TIMEOUT_HTTP, self.restante())
            if limite < 1:
                raise FuenteNoResponde('github: se acabó el tiempo de la corrida antes de consultar la API (%s)' % paso)
            self.consultas += 1
            try:
                return json.loads(self.descargar(url, limite))
            except urllib.error.HTTPError as e:
                codigo = e.code
                e.close()
                if codigo == 404:
                    raise NoExiste() from None
                if codigo in (403, 429):
                    raise CuotaAgotada() from None
                if codigo < 500 and codigo != 408:
                    raise FuenteNoResponde('github: la API de GitHub respondió %d (%s)' % (codigo, paso)) from None
                raise
        consulta.__name__ = paso
        try:
            return con_reintentos(consulta, intentos=INTENTOS, dormir=self.dormir)
        except (NoExiste, CuotaAgotada):
            raise
        except FuenteNoResponde as e:
            if str(e).startswith('github: '):
                raise
            raise FuenteNoResponde('github: la API de GitHub no respondió (%s)' % paso) from None

    def perfil(self, org, dominio):
        consulta = 'perfil:' + org
        del_disco, datos = self._de_disco(consulta)
        if del_disco:
            return _perfil_grabado(datos, org)
        datos = perfil_limpio(self._api('/orgs/' + org, 'perfil'), org, dominio)
        self._grabar(consulta, datos)
        return datos

    def repos(self, org):
        consulta = 'repos:' + org
        del_disco, datos = self._de_disco(consulta)
        if not del_disco:
            datos = repos_limpios(self._api('/orgs/%s/repos?type=public&sort=pushed&direction=desc&per_page=%d'
                                            % (org, POR_PAGINA), 'repos'))
            self._grabar(consulta, datos)
        return repos_limpios(datos)

    def revisar(self, org, repo, dominio):
        """{secretos, correos, ajenos, invalidos} de un repo: lo clona, corre gitleaks y lee los correos de git log."""
        consulta = 'repo:%s/%s' % (org, repo)
        del_disco, datos = self._de_disco(consulta)
        if del_disco:
            return revision_valida(datos, dominio)
        datos = revision_valida(self._revisar_en_vivo(org, repo, dominio), dominio)
        self._grabar(consulta, datos)
        return datos

    def _correr(self, comando, casa, tope, paso, org, repo, salida=None):
        restante = min(tope, self.restante())
        if restante < 1:
            raise FallaRepo('github: se acabó el tiempo de la corrida al %s %s/%s' % (paso, org, repo))
        try:
            hecho = self.ejecutar(comando, timeout=restante, env=_entorno(casa), cwd=casa, salida=salida, disco=MAX_DISCO)
        except subprocess.TimeoutExpired:
            raise FallaRepo('github: no se terminó de %s %s/%s en %d s' % (paso, org, repo, restante)) from None
        except MuyGrande:
            raise FallaRepo('github: se pasó de %d MB al %s %s/%s' % (MAX_DISCO // 2 ** 20, paso, org, repo)) from None
        except OSError as e:
            raise FallaRepo('github: no se pudo %s %s/%s (%s)' % (paso, org, repo, type(e).__name__)) from None
        if hecho.returncode != 0:
            raise FallaRepo('github: no se pudo %s %s/%s (código %s)' % (paso, org, repo, hecho.returncode))

    def _programas(self):
        git, gitleaks = self.git or _binario('git'), self.gitleaks or _binario('gitleaks')
        if not git or not gitleaks:
            raise FuenteNoResponde('github: git o gitleaks no está instalado')
        return git, gitleaks

    def _revisar_en_vivo(self, org, repo, dominio):
        git, _ = self._programas()
        # Si no se puede borrar (en Windows, un archivo que algo dejó abierto), no tapa la falla del repo: la borra una
        # corrida de después con limpiar_viejas().
        with tempfile.TemporaryDirectory(prefix=PREFIJO_TEMPORAL, dir=self.temporal, ignore_cleanup_errors=True) as casa:
            destino = os.path.join(casa, 'repo.git')
            self.consultas += 1
            self._correr([git, *OPCIONES_GIT, 'clone', '--bare', '--no-tags', '--quiet', '--', CLON % (org, repo),
                          destino], casa, TIMEOUT_CLON, 'clonar', org, repo)
            return self.analizar(destino, casa, org, repo, dominio)

    def analizar(self, destino, casa, org, repo, dominio):
        """{secretos, correos, ajenos, invalidos} de un clon bare que ya está en disco, sin red: gitleaks y git log.
        En un clon bare no hay árbol de trabajo, así que el repo no puede traer un .gitleaksignore que gitleaks lea."""
        git, gitleaks = self._programas()
        reporte = os.path.join(casa, 'reporte.json')
        self._correr([gitleaks, 'git', destino, '--config', str(REGLAS), '--log-opts=--all', '--redact', '--no-banner',
                      '--log-level', 'error', '--report-format', 'json', '--report-path', reporte, '--exit-code', '0',
                      '--max-target-megabytes', str(MAX_MB_ARCHIVO)],
                     casa, TIMEOUT_GITLEAKS, 'revisar con gitleaks', org, repo)
        try:
            if os.path.getsize(reporte) > MAX_REPORTE:
                raise ValueError('reporte demasiado grande')
            with open(reporte, encoding='utf-8', errors='replace') as f:
                secretos = leer_reporte(f.read())
        except (OSError, ValueError, RecursionError):
            raise FallaRepo('github: no se pudo leer el reporte de gitleaks de %s/%s' % (org, repo)) from None
        log = os.path.join(casa, 'log.txt')
        self._correr([git, *OPCIONES_GIT, '-C', destino, 'log', '--all', FORMATO_LOG], casa, TIMEOUT_LOG,
                     'leer los commits de', org, repo, salida=log)
        try:
            demasiado = os.path.getsize(log) > MAX_LOG
            texto = None if demasiado else Path(log).read_bytes().decode('utf-8', 'replace')
        except OSError:
            raise FallaRepo('github: no se pudieron leer los commits de %s/%s' % (org, repo)) from None
        if demasiado:
            raise FallaRepo('github: los commits de %s/%s pasan de %d MB' % (org, repo, MAX_LOG // 2 ** 20))
        correos, ajenos, invalidos = leer_correos(texto, dominio)
        return {'secretos': secretos, 'correos': correos, 'ajenos': ajenos, 'invalidos': invalidos}


def carpeta_de(dominio):
    """Carpeta de la grabación de un dominio."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' consulta GitHub, 'reproducir' usa la grabación del dominio y 'grabar'
    empieza una grabación nueva."""
    return ClienteGitHub(modo=modo, carpeta=carpeta_de(dominio), nueva=(modo == 'grabar'))


# ---------------------------------------------------------------- activos y hallazgos

def _huella(*partes):
    """No lleva el valor del secreto ni el commit, así el hallazgo no se duplica entre escaneos."""
    return hashlib.sha256('\0'.join(partes).encode('utf-8')).hexdigest()


def _caracteristicas(codigo, tipo_activo, evidencia, ahora, sensibilidad):
    return {'tipo': TIPOS[codigo], 'antiguedad_dias': rubrica.antiguedad_dias(codigo, evidencia, ahora),
            'exposicion': rubrica.exposicion(codigo, tipo_activo), 'sensibilidad': sensibilidad}


def hallazgo_secreto(dominio, repo, secreto, ahora):
    """secret_in_public_repo sobre el dominio. La evidencia lleva repo, ruta, tipo (la regla de gitleaks) y huella,
    nunca el valor ni el commit. La sensibilidad es alta: es una credencial (rúbrica de caracteristicas.py)."""
    codigo = 'secret_in_public_repo'
    titulo = 'Clave de acceso publicada en GitHub: %s, archivo %s' % (repo, secreto['ruta'])
    huella = _huella(codigo, repo, secreto['ruta'], secreto['regla'])
    evidencia = {'title': titulo, 'repo': repo, 'ruta': secreto['ruta'], 'tipo': secreto['regla'], 'huella': huella,
                 'primera_vez': secreto['primera_vez']}
    return Hallazgo(codigo, CODIGOS[codigo], dominio, titulo, evidencia,
                    _caracteristicas(codigo, 'domain', evidencia, ahora, 'alta'), huella,
                    clave='%s:%s:%s' % (repo, secreto['ruta'], secreto['regla']), partes=[repo])


def hallazgo_correo(correo, datos, ahora, partes=None):
    """email_in_public_commits sobre el activo email. La sensibilidad sale de la rúbrica (media: el correo). El título
    no lleva el correo, que ya es el activo: el título puede salir de la plataforma (politica_uso_etico.md). `partes`
    son todos los repos donde salió, sin el corte de MAX_REPOS_ACTIVO que tiene datos['repos'] (#23)."""
    codigo = 'email_in_public_commits'
    titulo = 'Correo de la empresa en los cambios publicados en GitHub'
    evidencia = {'title': titulo, 'repos': datos['repos'], 'commits': datos['commits'],
                 'primera_vez': datos['primera_vez']}
    return Hallazgo(codigo, CODIGOS[codigo], correo, titulo, evidencia,
                    _caracteristicas(codigo, 'email', evidencia, ahora, rubrica.sensibilidad(codigo, evidencia, ahora)),
                    _huella(codigo, correo), partes=list(datos['repos'] if partes is None else partes))


def _cuantos(n, singular, plural):
    return '%d %s' % (n, singular if n == 1 else plural)


def _sin_cobertura(res, aviso):
    res.avisos.append(aviso)
    res.sin_cobertura = list(CODIGOS)
    return res


# ---------------------------------------------------------------- punto de entrada

def recolectar(dominio, cliente=None, ahora=None, propios=()):
    """Secretos y correos del dominio en los repos públicos de su organización de GitHub declarada. `propios` no se
    usa: GitHub no busca dominios parecidos."""
    dominio = dominio.strip().lower().rstrip('.')
    res = Resultado(dominio, FUENTE)
    if not NOMBRE_VALIDO.fullmatch(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res
    org = declarada(dominio)
    if org is None:
        return _sin_cobertura(res, SIN_DECLARACION)
    if org == NINGUNA:
        return _sin_cobertura(res, DECLARO_NINGUNA)
    if not ORG_VALIDA.fullmatch(org):
        return _sin_cobertura(res, DECLARADA_INVALIDA)
    cliente = cliente or crear_cliente('vivo', dominio)
    try:
        cliente.empezar()
        _revisar(res, cliente, org, dominio, ahora or datetime.now(timezone.utc))
    except FuenteNoResponde:
        raise
    except Exception as e:  # nunca el texto de la excepción: puede traer pedazos de la fuente
        raise FuenteNoResponde('github: falla inesperada al revisar GitHub (%s)' % type(e).__name__) from None
    finally:
        res.consultas = cliente.consultas
    return res


def _revisar(res, cliente, org, dominio, ahora):
    try:
        perfil = cliente.perfil(org, dominio)
        repos = cliente.repos(perfil['login'])
    except SinGrabacion:
        return _sin_cobertura(res, SIN_GRABACION_DOMINIO)
    except NoExiste:
        return _sin_cobertura(res, NO_EXISTE)
    except Renombrada:
        return _sin_cobertura(res, RENOMBRADA)
    except CuotaAgotada:
        return _sin_cobertura(res, SIN_CUOTA)
    login = perfil['login']
    elegidos, saltados = elegir(repos)

    revisados, fallas, sin_grabacion, sin_tiempo = [], [], 0, 0
    for i, r in enumerate(elegidos):
        if cliente.restante() < MIN_RESTANTE:
            sin_tiempo = len(elegidos) - i
            break
        try:
            revisados.append((r['nombre'], cliente.revisar(login, r['nombre'], dominio)))
        except SinGrabacion:
            sin_grabacion += 1
        except SecretoSinRedactar:   # nada de la corrida se usa ni se graba
            return _sin_cobertura(res, SIN_REDACTAR)
        except FallaRepo as e:
            fallas.append(str(e))
    if elegidos and not revisados:
        if cliente.modo == 'reproducir':
            return _sin_cobertura(res, SIN_GRABACION_DOMINIO)
        raise FuenteNoResponde('github: no se pudo revisar ningún repo de %s' % login)

    revisados_nombres = [nombre for nombre, _ in revisados]
    res.activos.append(Activo('domain', res.dominio, {'fuente': FUENTE, 'github': {
        'organizacion': login, 'nivel': 'declarada', 'verificada': perfil['verificada'],
        'blog_del_dominio': perfil['blog_del_dominio'], 'correo_del_dominio': perfil['correo_del_dominio'],
        'repos_revisados': revisados_nombres, 'repos_saltados': {k: v for k, v in saltados.items() if v}}}))

    correos, ajenos, invalidos = {}, 0, 0
    for nombre, datos in revisados:
        repo = '%s/%s' % (login, nombre)
        res.hallazgos += [hallazgo_secreto(res.dominio, repo, s, ahora) for s in datos['secretos']]
        ajenos += datos['ajenos']
        invalidos += datos['invalidos']
        for c in datos['correos']:
            x = correos.setdefault(c['correo'], {'repos': [], 'commits': 0, 'primera_vez': None})
            x['repos'].append(repo)
            x['commits'] += c['commits']
            x['primera_vez'] = _primera(x['primera_vez'], c['primera_vez'])
    for correo in sorted(correos):
        datos = dict(correos[correo], repos=correos[correo]['repos'][:MAX_REPOS_ACTIVO])
        res.activos.append(Activo('email', correo, {'fuente': FUENTE, **datos}))
        res.hallazgos.append(hallazgo_correo(correo, datos, ahora, partes=correos[correo]['repos']))

    for motivo, n in saltados.items():
        if n:
            res.avisos.append('github: se %s %s %s' % ('saltó' if n == 1 else 'saltaron', _cuantos(n, 'repo', 'repos'),
                                                     SALTADOS[motivo]))
    res.avisos += fallas
    if sin_grabacion:
        res.avisos.append('github: falta la grabación de %s' % _cuantos(sin_grabacion, 'repo', 'repos'))
    if sin_tiempo:
        res.avisos.append('github: se acabó el tiempo de la corrida antes de revisar %s'
                          % _cuantos(sin_tiempo, 'repo', 'repos'))
    # Cada repo cuenta sus correos distintos: la grabación no guarda los descartados, así que no se pueden juntar.
    if ajenos:
        res.avisos.append('github: se %s %s que no %s del dominio, contando cada repo aparte' % (
            'descartó' if ajenos == 1 else 'descartaron', _cuantos(ajenos, 'correo', 'correos'), 'es' if ajenos == 1 else 'son'))
    if invalidos:
        res.avisos.append('github: se %s %s del dominio con forma inválida, contando cada repo aparte' % (
            'descartó' if invalidos == 1 else 'descartaron', _cuantos(invalidos, 'correo', 'correos')))

    total = len(elegidos) + sum(saltados[m] for m in PARCIALES)
    mas_paginas = len(repos) >= POR_PAGINA and (perfil['repos_publicos'] is None or perfil['repos_publicos'] > len(repos))
    if len(revisados) < total or mas_paginas:
        res.avisos.append('github: cobertura parcial, se revisaron %d de %s repos' % (
            len(revisados), ('%d o más' % total) if mas_paginas else total))
        con_hallazgos = {h.codigo for h in res.hallazgos}
        res.sin_cobertura = [c for c in CODIGOS if c not in con_hallazgos]
        res.revisados = ['%s/%s' % (login, nombre) for nombre in revisados_nombres]
        # sin forks ni deshabilitados, que una corrida completa tampoco revisa: lo que salió de ellos se cierra igual
        revisables = [r for r in repos if not r['privado'] and not r['fork'] and not r['deshabilitado']]
        if not mas_paginas and all(r['nombre'] for r in revisables):  # se conocen todos los que se revisarían
            res.sin_revisar = [x for x in dict.fromkeys('%s/%s' % (login, r['nombre']) for r in revisables)
                               if x not in res.revisados]
    cliente.terminar()
    return res


# ---------------------------------------------------------------- línea de comandos

SEVERIDAD_ES = {'critical': 'crítica', 'high': 'alta', 'medium': 'media', 'low': 'baja'}


def resumen(res):
    """Líneas para la terminal. No hay valores de secretos que mostrar: el resultado no los trae."""
    lineas = ['%s · %s · %s · %s' % (res.dominio, FUENTE, res.estado, _cuantos(res.consultas, 'consulta', 'consultas'))]
    if res.error:
        lineas.append('error: %s' % res.error)
    for a in res.activos:
        if a.tipo == 'domain':
            g = a.atributos['github']
            lineas.append('organización %s · %s · verificada: %s · repos revisados: %d' % (
                g['organizacion'], g['nivel'], 'sí' if g['verificada'] else 'no', len(g['repos_revisados'])))
    if res.hallazgos:
        lineas.append(_cuantos(len(res.hallazgos), 'hallazgo:', 'hallazgos:'))
        lineas += ['  [%s] %s' % (SEVERIDAD_ES.get(h.severidad, h.severidad),
                                  h.titulo if h.activo == res.dominio else '%s: %s' % (h.titulo, h.activo))
                   for h in res.hallazgos]
    elif res.estado == 'succeeded' and not res.sin_cobertura:
        lineas.append('Sin hallazgos.')
    if res.sin_cobertura:  # no es lo mismo que 0 hallazgos
        lineas.append('Cobertura parcial: no se revisaron %s.' % ' ni '.join(res.sin_cobertura))
    lineas += ['aviso: %s' % a for a in res.avisos]
    return lineas


def codigo_salida(res):
    """0 bien, 1 si el resultado queda en 'failed', 2 si quedan avisos."""
    return 1 if res.estado == 'failed' else 2 if res.avisos else 0


def _main(argv=None):
    # En Windows, cuando la salida no es la consola (Git Bash, una tubería), Python usa cp1252 y los acentos se rompen.
    if (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    p = argparse.ArgumentParser(description='Secretos y correos del dominio en los repos públicos de su organización de '
                                            'GitHub declarada (ORGS_GITHUB_DECLARADAS)')
    p.add_argument('dominio')
    modo = p.add_mutually_exclusive_group()
    modo.add_argument('--grabar', action='store_true',
                      help='empieza una grabación nueva en cirdan/recolectores/respuestas_grabadas/github/<dominio>/')
    modo.add_argument('--reproducir', action='store_true', help='usa solo la grabación, sin red')
    p.add_argument('--json', action='store_true', help='imprime el resultado completo en JSON')
    a = p.parse_args(argv)
    dominio = a.dominio.strip().lower().rstrip('.')
    if not NOMBRE_VALIDO.fullmatch(dominio):  # también evita que '..' o '/' saquen la carpeta de respuestas_grabadas
        p.error('dominio inválido: %s' % a.dominio)
    modo = 'grabar' if a.grabar else 'reproducir' if a.reproducir else 'vivo'
    if modo != 'reproducir' and not _en_vivo_permitido(dominio):
        p.error('%s no está en DOMINIOS_EN_VIVO: GitHub solo se consulta en vivo, o se graba, con la carta vigente del '
                'dominio. Usa --reproducir' % dominio)
    if os.name == 'posix':  # cerrar la terminal o un kill también matan a git y gitleaks y borran la carpeta temporal
        for senal in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(senal, lambda numero, _: sys.exit(128 + numero))
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
