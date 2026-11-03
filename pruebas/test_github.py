"""Pruebas del recolector de GitHub (#16, RC-50), sin red: la API, git y gitleaks simulados con salidas de la misma
forma que las reales (gitleaks 8.21.2 con --redact y git log con FORMATO_LOG). La clase Integracion corre git y gitleaks
reales sobre un repo local, también sin red, y solo dentro del contenedor.

    python -m unittest -v pruebas/test_github.py

El token falso se genera en cada corrida ('CIRDAN_FAKE_' más 32 hexadecimales): nunca vive en un archivo del repo.
"""
import hashlib
import io
import json
import logging
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
import urllib.error
import urllib.parse
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_github.py
from pruebas.test_catalogo_reglas import POR_CODIGO  # noqa: E402
from pruebas.test_crtsh import AHORA  # noqa: E402
from pruebas.test_subfinder import Cronometro  # noqa: E402
from cirdan.recolectores import REGISTRO, cargar, contrato, github, gitleaks_reglas  # noqa: E402
from cirdan.recolectores.contrato import FuenteNoResponde  # noqa: E402

TOKEN = 'CIRDAN_FAKE_' + secrets.token_hex(16)
OTRO_TOKEN = 'CIRDAN_FAKE_' + secrets.token_hex(16)
DOMINIO, ORG = 'acme-demo.mx', 'acme-demo'
DECLARADA = 'olmardo.com=olmardo,acme-demo.mx=acme-demo'
BINARIOS = {'git': '/usr/bin/git', 'gitleaks': '/usr/local/bin/gitleaks'}
RAIZ = Path(__file__).resolve().parents[1]
SEMILLA = RAIZ / 'db' / 'semillas' / '006_github.sql'
CODIGOS = list(github.CODIGOS)


def repo(nombre, subido='2026-10-10T10:00:00Z', kb=50, **cambios):
    """Un repo de GET /orgs/<org>/repos, con campos que el recolector no guarda."""
    base = {'name': nombre, 'full_name': '%s/%s' % (ORG, nombre), 'fork': False, 'disabled': False, 'archived': False,
            'private': False, 'size': kb, 'pushed_at': subido, 'description': 'Lo hizo Juana Pérez',
            'owner': {'login': ORG, 'email': 'juana@gmail.com'}, 'html_url': 'https://github.com/%s/%s' % (ORG, nombre)}
    base.update(cambios)
    return base


PERFIL = {'login': ORG, 'name': 'Acme Demo', 'is_verified': False, 'blog': 'www.acme-demo.mx',
          'email': 'contacto@acme-demo.mx', 'public_repos': 3, 'description': 'Organización de Juana Pérez'}
REPOS = [repo('api', '2026-10-10T10:00:00Z'), repo('sitio', '2026-10-12T10:00:00Z'),
         repo('copia', '2026-10-14T10:00:00Z', fork=True)]


def hallazgo_gitleaks(regla='cirdan-fake-token', archivo='config/.env', fecha='2026-09-01T12:00:00Z', **cambios):
    """Un hallazgo del reporte JSON de gitleaks 8.21.2 con --redact, con todos sus campos."""
    base = {'RuleID': regla, 'Description': 'Token falso de LowTide', 'StartLine': 3, 'EndLine': 3, 'StartColumn': 7,
            'EndColumn': 50, 'Match': 'TOKEN=REDACTED', 'Secret': 'REDACTED', 'File': archivo, 'SymlinkFile': '',
            'Commit': 'c0ffee' * 6 + 'abcd', 'Entropy': 4.5, 'Author': 'Juana Pérez', 'Email': 'juana@gmail.com',
            'Date': fecha, 'Message': 'sube la configuración', 'Tags': [],
            'Fingerprint': 'c0ffee:%s:%s:3' % (archivo, regla)}
    base.update(cambios)
    return base


def commit(autor, quien, cuando):
    """Una línea de git log con FORMATO_LOG: correo del autor, de quien subió el commit y fecha en epoch."""
    return '%s\x00%s\x00%d' % (autor, quien, cuando)


EPOCA = int(datetime(2026, 9, 1, 12, tzinfo=timezone.utc).timestamp())
LOG = '\n'.join([
    commit('Dev@Acme-Demo.mx', 'noreply@github.com', EPOCA),         # del dominio en mayúsculas, subido desde la web
    commit('ana@ti.acme-demo.mx', 'ana@ti.acme-demo.mx', EPOCA + 86400),   # de un subdominio
    commit('x@gmail.com', 'x@gmail.com', EPOCA),
    commit('y@acme-dem0.mx', 'y@acme-dem0.mx', EPOCA),                # dominio parecido
    commit('a@b@acme-demo.mx', 'ana@ti_x.acme-demo.mx', EPOCA),       # del dominio, con forma inválida
    commit('dev@acme-demo.mx', 'dev@acme-demo.mx', EPOCA - 86400),
]) + '\n'


class ApiSimulada:
    """Hace las veces de github._descargar: responde por ruta y anota cada URL. `fallas` da, por ruta, lo que lanzan los
    primeros intentos: un código HTTP (con el token en el mensaje y el cuerpo) o una excepción."""

    def __init__(self, perfil=None, repos=None, fallas=None):
        self.respuestas = {'/orgs/' + ORG: PERFIL if perfil is None else perfil,
                           '/orgs/%s/repos' % ORG: REPOS if repos is None else repos}
        self.fallas = {ruta: list(lista) for ruta, lista in (fallas or {}).items()}
        self.urls = []

    def __call__(self, url, timeout):
        self.urls.append(url)
        ruta = urllib.parse.urlsplit(url).path
        if self.fallas.get(ruta):
            falla = self.fallas[ruta].pop(0)
            if isinstance(falla, int):
                raise urllib.error.HTTPError(url, falla, 'falla con ' + TOKEN, {}, io.BytesIO(TOKEN.encode()))
            raise falla
        if ruta not in self.respuestas:
            raise urllib.error.HTTPError(url, 404, 'Not Found', {}, io.BytesIO(b''))
        datos = self.respuestas[ruta]
        return datos if isinstance(datos, bytes) else json.dumps(datos).encode('utf-8')


def sin_api(url, timeout):
    raise AssertionError('no debe consultar GitHub: %s' % url)


class ProcesosSimulados:
    """Hace las veces de github._ejecutar: git clone, gitleaks git y los dos git log, el de los entornos de Python y el
    de los correos, que escriben su salida en `salida`. Anota cada llamada, si su carpeta existía y qué archivos ya
    había en ella (restos). `reporte` (lista o texto) y `log` son de todos los repos, salvo los que den `reportes` y
    `logs` por repo, y `entornos` también. `fallas` da, por (paso, repo), un código de salida o una excepción, y el paso
    que falla deja su salida a medias, como un proceso cortado."""

    def __init__(self, reporte=None, log=None, reportes=None, logs=None, fallas=None, entornos=''):
        self.reporte = [hallazgo_gitleaks()] if reporte is None else reporte
        self.log = LOG if log is None else log
        self.entornos = entornos
        self.reportes, self.logs, self.fallas = reportes or {}, logs or {}, fallas or {}
        self.llamadas = []
        self.repo = None

    def __call__(self, comando, timeout, env, cwd, salida=None, disco=None):
        comando = list(comando)
        paso = ('clone' if 'clone' in comando else 'entornos' if '--name-only' in comando
                else 'log' if 'log' in comando else 'gitleaks')
        if paso == 'clone':
            self.repo = comando[comando.index('--') + 1].rsplit('/', 1)[1][:-len('.git')]
        casa = os.path.isdir(cwd)
        self.llamadas.append(SimpleNamespace(paso=paso, repo=self.repo, comando=comando, timeout=timeout, env=dict(env),
                                             cwd=cwd, salida=salida, disco=disco, casa=casa,
                                             restos=sorted(os.listdir(cwd)) if casa else None))
        falla = self.fallas.get((paso, self.repo))
        if falla is not None and salida:
            with open(salida, 'x', encoding='utf-8', newline='') as f:
                f.write('x\0' * 10)
        if isinstance(falla, BaseException):
            raise falla
        if falla is not None:
            return subprocess.CompletedProcess(comando, falla, None, None)
        if paso == 'gitleaks':
            reporte = self.reportes.get(self.repo, self.reporte)
            with open(comando[comando.index('--report-path') + 1], 'w', encoding='utf-8') as f:
                f.write(reporte if isinstance(reporte, str) else json.dumps(reporte))
        if paso in ('log', 'entornos'):
            with open(salida, 'x', encoding='utf-8', newline='') as f:
                f.write(self.logs.get(self.repo, self.log) if paso == 'log' else self.entornos)
        return subprocess.CompletedProcess(comando, 0, None, None)

    def de(self, paso):
        return [ll for ll in self.llamadas if ll.paso == paso]


def sin_procesos(comando, **opciones):
    raise AssertionError('no debe correr procesos: %s' % comando)


def cliente(api=None, procesos=None, modo='vivo', carpeta=None, nueva=False, cronometro=None, temporal=None, git=True):
    return github.ClienteGitHub(modo=modo, carpeta=carpeta or github.carpeta_de(DOMINIO), descargar=api or ApiSimulada(),
                                ejecutar=procesos or ProcesosSimulados(), git=BINARIOS['git'] if git else None,
                                gitleaks=BINARIOS['gitleaks'], nueva=nueva, cronometro=cronometro,
                                dormir=lambda s: None, temporal=temporal)


def recolectar(api=None, procesos=None, declaradas=DECLARADA, **kw):
    """(resultado, cliente). La carpeta temporal es una propia, que se revisa al final: debe quedar vacía."""
    with tempfile.TemporaryDirectory() as t, mock.patch.dict(os.environ, {github.DECLARADAS: declaradas}):
        c = cliente(api, procesos, temporal=kw.pop('temporal', t), **kw)
        try:
            return github.recolectar(DOMINIO, c, AHORA), c
        finally:
            assert not list(Path(t).glob(github.PREFIJO_TEMPORAL + '*')), 'quedó una carpeta temporal'


def por_ejecutar(api=None, procesos=None, modo='vivo', carpeta=None, declaradas=DECLARADA):
    """Por contrato.ejecutar(), como lo llama el orquestador."""
    with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {github.DECLARADAS: declaradas}), \
            mock.patch.object(github, 'CARPETA_GRABADAS', Path(carpeta or d)), \
            mock.patch.object(github, '_descargar', api or ApiSimulada()), \
            mock.patch.object(github, '_ejecutar', procesos or ProcesosSimulados()), \
            mock.patch.object(github, '_binario', lambda nombre: BINARIOS[nombre]), \
            mock.patch.object(github.time, 'sleep', lambda s: None):
        return contrato.ejecutar(cargar('github'), DOMINIO, modo=modo, ahora=AHORA)


def huella(*partes):
    return hashlib.sha256('\0'.join(partes).encode('utf-8')).hexdigest()


class Registro(logging.Handler):
    """Junta todo lo que se registra en el logger raíz, con el texto de sus excepciones."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.textos = []

    def emit(self, registro):
        self.textos.append(self.format(registro))


class SinFuga(unittest.TestCase):
    """D9: el valor del token no aparece en el resultado, los avisos, el error, la grabación ni los logs."""

    def setUp(self):
        self.registro = Registro()
        raiz = logging.getLogger()
        self.nivel = raiz.level
        raiz.addHandler(self.registro)
        raiz.setLevel(logging.DEBUG)

    def tearDown(self):
        logging.getLogger().removeHandler(self.registro)
        logging.getLogger().setLevel(self.nivel)
        self.assertNotIn(TOKEN, '\n'.join(self.registro.textos))

    def sin_token(self, res):
        texto = json.dumps(res.a_dict(), ensure_ascii=False)
        self.assertNotIn(TOKEN, texto)
        self.assertNotIn(TOKEN[len('CIRDAN_FAKE_'):], texto)

    def test_1_un_reporte_sin_redactar_descarta_la_corrida_sin_dejarla_failed(self):
        """Sin cobertura y no failed: el orquestador reintentaría y gitleaks volvería a escribir el valor en disco."""
        with self.assertRaises(github.SecretoSinRedactar) as e:
            github.leer_reporte(json.dumps([hallazgo_gitleaks(Secret=TOKEN, Match='TOKEN=' + TOKEN)]))
        self.assertEqual(str(e.exception), github.SIN_REDACTAR)
        procesos = ProcesosSimulados(reporte=[hallazgo_gitleaks(Secret=TOKEN, Match='TOKEN=' + TOKEN)])
        res = por_ejecutar(procesos=procesos)
        self.assertEqual((res.estado, res.error, res.activos, res.hallazgos), ('succeeded', '', [], []))
        self.assertEqual((res.sin_cobertura, res.avisos), (CODIGOS, [github.SIN_REDACTAR]))
        self.assertEqual(len(procesos.de('clone')), 1)   # el primer repo sin redactar corta la corrida
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        self.sin_token(res)

    def test_2_un_match_sin_redactar_tambien_descarta(self):
        for reporte in ([hallazgo_gitleaks(Match='TOKEN=' + TOKEN)], [hallazgo_gitleaks(Match=TOKEN[:20])],
                        [hallazgo_gitleaks(Secret='')]):
            with self.subTest(reporte=reporte[0]['Match'][:6]):
                res, _ = recolectar(procesos=ProcesosSimulados(reporte=reporte))
                self.assertEqual((res.estado, res.hallazgos, res.avisos), ('succeeded', [], [github.SIN_REDACTAR]))
                self.sin_token(res)

    def test_3_ni_stderr_ni_el_texto_de_una_excepcion_llegan_al_resultado(self):
        fallas = {('clone', 'sitio'): subprocess.TimeoutExpired(['git'], 120, output=TOKEN.encode(), stderr=TOKEN.encode()),
                  ('gitleaks', 'api'): OSError(TOKEN)}
        res = por_ejecutar(procesos=ProcesosSimulados(fallas=fallas))
        self.assertEqual(res.estado, 'failed')
        self.assertEqual(res.error, 'FuenteNoResponde: github: no se pudo revisar ningún repo de acme-demo')
        self.sin_token(res)
        fallas = {('clone', 'sitio'): subprocess.TimeoutExpired(['git'], 120, output=TOKEN.encode(), stderr=TOKEN.encode())}
        res = por_ejecutar(procesos=ProcesosSimulados(fallas=fallas))
        self.assertEqual(res.estado, 'succeeded')
        self.assertIn('github: no se terminó de clonar acme-demo/sitio en 120 s', res.avisos)
        self.sin_token(res)
        res = por_ejecutar(procesos=ProcesosSimulados(fallas={('gitleaks', 'api'): OSError(TOKEN)}))
        self.assertIn('github: no se pudo revisar con gitleaks acme-demo/api (OSError)', res.avisos)
        self.sin_token(res)

    def test_4_las_fallas_de_la_api_salen_con_texto_fijo(self):
        for fallas, error in (({'/orgs/acme-demo': [502, 502, 502]}, 'github: la API de GitHub no respondió (perfil)'),
                              ({'/orgs/acme-demo': [401]}, 'github: la API de GitHub respondió 401 (perfil)'),
                              ({'/orgs/acme-demo/repos': [ValueError(TOKEN)] * 3},
                               'github: la API de GitHub no respondió (repos)'),
                              ({'/orgs/acme-demo': [RuntimeError(TOKEN)]},
                               'github: falla inesperada al revisar GitHub (RuntimeError)')):
            with self.subTest(error=error):
                res = por_ejecutar(api=ApiSimulada(fallas=fallas))
                self.assertEqual((res.estado, res.error), ('failed', 'FuenteNoResponde: ' + error))
                self.sin_token(res)

    def test_5_la_grabacion_no_guarda_valores_nombres_ni_campos_de_mas(self):
        with tempfile.TemporaryDirectory() as d:
            res, _ = recolectar(modo='grabar', carpeta=Path(d), nueva=True)
            self.assertEqual(res.estado, 'succeeded')
            grabado = '\n'.join(p.read_text(encoding='utf-8') for p in Path(d).glob('*.json'))
        for prohibido in (TOKEN, 'Juana', 'gmail', 'noreply', 'acme-dem0', 'ti_x', 'Secret', 'Match', 'Author', 'Message',
                          'Commit', 'c0ffee', 'description', 'html_url', 'Acme Demo', 'contacto@'):
            self.assertNotIn(prohibido, grabado)


class Declaracion(unittest.TestCase):
    """D1: solo la organización declarada en ORGS_GITHUB_DECLARADAS."""

    def test_1_sin_declaracion_no_consulta_y_queda_sin_cobertura(self):
        for declaradas, aviso in (('olmardo.com=olmardo', github.SIN_DECLARACION), ('', github.SIN_DECLARACION),
                                  ('acme-demo.mx=ninguna', github.DECLARO_NINGUNA),
                                  ('acme-demo.mx=NINGUNA', github.DECLARO_NINGUNA),
                                  ('acme-demo.mx=-acme', github.DECLARADA_INVALIDA),
                                  ('acme-demo.mx=acme/../otra', github.DECLARADA_INVALIDA),
                                  ('acme-demo.mx=acme.demo', github.DECLARADA_INVALIDA),
                                  ('acme-demo.mx=' + 'a' * 40, github.DECLARADA_INVALIDA)):
            with self.subTest(declaradas=declaradas):
                res, c = recolectar(sin_api, sin_procesos, declaradas=declaradas)
                self.assertEqual((res.estado, res.consultas, res.activos, res.hallazgos), ('succeeded', 0, [], []))
                self.assertEqual((res.sin_cobertura, res.avisos), (CODIGOS, [aviso]))
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_2_lee_varios_pares_sin_importar_mayusculas_ni_espacios(self):
        with mock.patch.dict(os.environ, {github.DECLARADAS: ' olmardo.com=olmardo , ACME-DEMO.MX.= Acme-Demo ,x'}):
            self.assertEqual((github.declarada('acme-demo.mx'), github.declarada('olmardo.com'),
                              github.declarada('beta.mx')), ('Acme-Demo', 'olmardo', None))
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(github, 'config', lambda n, d=None: d):
            self.assertEqual(github.declarada('olmardo.com'), 'olmardo')   # la omisión, como en docker-compose.yml

    def test_3_la_declarada_da_el_activo_domain_con_su_organizacion(self):
        api = ApiSimulada()
        res, c = recolectar(api)
        self.assertEqual(api.urls, ['https://api.github.com/orgs/acme-demo',
                                    'https://api.github.com/orgs/acme-demo/repos?type=public&sort=pushed&direction=desc'
                                    '&per_page=100'])
        dominio = [a for a in res.activos if a.tipo == 'domain']
        self.assertEqual(len(dominio), 1)
        self.assertEqual(dominio[0].valor, DOMINIO)
        self.assertEqual(dominio[0].atributos, {'fuente': 'github', 'github': {
            'organizacion': 'acme-demo', 'nivel': 'declarada', 'verificada': False, 'blog_del_dominio': True,
            'correo_del_dominio': True, 'repos_revisados': ['sitio', 'api'], 'repos_saltados': {'fork': 1}}})
        self.assertEqual(res.consultas, 4)   # perfil, repos y 2 clones
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_4_el_blog_cuenta_solo_si_su_host_es_del_dominio(self):
        for blog, esperado in (('https://www.acme-demo.mx/inicio', True), ('acme-demo.mx', True),
                               ('HTTP://WWW.ACME-DEMO.MX', True), ('https://acme-demo.mx.otro.com', False),
                               ('https://acme-demo.mx@otro.com', False), ('https://notacme-demo.mx', False),
                               ('https://otro.com/acme-demo.mx', False), ('https://[::1', False), ('', False),
                               ('https://otro.com\\@acme-demo.mx', False), ('otro.com\\@www.acme-demo.mx/x', False),
                               (None, False)):
            with self.subTest(blog=blog):
                self.assertIs(github._blog_del_dominio(blog, DOMINIO), esperado)

    def test_4b_el_correo_del_perfil_cuenta_solo_con_una_arroba_y_host_del_dominio(self):
        for correo, esperado in (('contacto@acme-demo.mx', True), (' Contacto@TI.Acme-Demo.mx ', True),
                                 ('acme-demo.mx', False), ('@acme-demo.mx', False), ('a@b@acme-demo.mx', False),
                                 ('contacto@otro.mx', False), ('contacto@acme-demo.mx.otro.mx', False), (None, False)):
            with self.subTest(correo=correo):
                self.assertIs(github._correo_del_dominio(correo, DOMINIO), esperado)
        perfil = github.perfil_limpio(dict(PERFIL, email='acme-demo.mx'), ORG, DOMINIO)
        self.assertIs(perfil['correo_del_dominio'], False)

    def test_5_una_organizacion_que_cambio_de_nombre_queda_sin_cobertura(self):
        res, _ = recolectar(ApiSimulada(perfil=dict(PERFIL, login='otra-org')), sin_procesos)
        self.assertEqual((res.estado, res.sin_cobertura, res.avisos), ('succeeded', CODIGOS, [github.RENOMBRADA]))

    def test_6_una_organizacion_que_no_existe_queda_sin_cobertura(self):
        res, c = recolectar(ApiSimulada(fallas={'/orgs/acme-demo': [404]}), sin_procesos)
        self.assertEqual((res.estado, res.sin_cobertura, res.avisos, res.consultas),
                         ('succeeded', CODIGOS, [github.NO_EXISTE], 1))


class Secretos(unittest.TestCase):
    """D3 y D5: un hallazgo por repo, ruta y regla, sin valor ni commit."""

    def test_1_un_hallazgo_por_repo_ruta_y_regla_con_la_fecha_mas_vieja(self):
        reporte = [hallazgo_gitleaks(fecha='2026-09-20T00:00:00Z'),
                   hallazgo_gitleaks(fecha='2026-09-01T12:00:00Z', Commit='b' * 40),
                   hallazgo_gitleaks('generic-api-key', 'app.py', '2026-10-01T00:00:00Z')]
        res, _ = recolectar(procesos=ProcesosSimulados(reportes={'sitio': reporte, 'api': []}))
        secretos = [h for h in res.hallazgos if h.codigo == 'secret_in_public_repo']
        self.assertEqual([(h.activo, h.clave) for h in secretos], [
            (DOMINIO, 'acme-demo/sitio:app.py:generic-api-key'), (DOMINIO, 'acme-demo/sitio:config/.env:cirdan-fake-token')])
        h = secretos[1]
        self.assertEqual(h.severidad, 'critical')
        self.assertEqual(h.titulo, 'Clave de acceso publicada en GitHub: acme-demo/sitio, archivo config/.env')
        self.assertEqual(h.evidencia, {'title': h.titulo, 'repo': 'acme-demo/sitio', 'ruta': 'config/.env',
                                       'tipo': 'cirdan-fake-token', 'huella': h.huella,
                                       'primera_vez': '2026-09-01T12:00:00+00:00'})
        self.assertEqual(h.caracteristicas, {'tipo': 'secreto_en_repositorio', 'antiguedad_dias': 44,
                                             'exposicion': 'publica', 'sensibilidad': 'alta'})
        self.assertEqual(h.huella, huella('secret_in_public_repo', 'acme-demo/sitio', 'config/.env', 'cirdan-fake-token'))

    def test_2_la_huella_no_depende_del_valor_ni_del_commit(self):
        uno, _ = recolectar(procesos=ProcesosSimulados(
            reporte=[hallazgo_gitleaks(Commit='a' * 40, StartLine=1, Entropy=3.1)]))
        otro, _ = recolectar(procesos=ProcesosSimulados(
            reporte=[hallazgo_gitleaks(Commit='b' * 40, StartLine=9, Entropy=4.9, Fingerprint='otro')]))
        self.assertEqual([h.huella for h in uno.hallazgos], [h.huella for h in otro.hallazgos])

    def test_3_regla_desconocida_y_ruta_con_controles_se_limpian(self):
        reporte = [hallazgo_gitleaks('Regla Con Espacios', 'a\nb\x00c' + 'x' * 400)]
        res, _ = recolectar(procesos=ProcesosSimulados(reportes={'sitio': reporte, 'api': []}, log=''))
        (h,) = res.hallazgos
        self.assertEqual(h.evidencia['tipo'], 'desconocida')
        self.assertEqual(h.evidencia['ruta'], ('a?b?c' + 'x' * 400)[:300])
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_4b_las_marcas_dan_la_carpeta_del_entorno_y_solo_lo_que_instalo_se_descarta(self):
        """Con pyvenv.cfg solo site-packages, y con conda también la biblioteca estándar (lib/<python>/, con lib en
        minúsculas, o Lib/) y los paquetes de pkgs/ con la forma <nombre>-<versión>-<build>. Una marca en la raíz no
        esconde lib/ ni pkgs/ del cliente, y lo que esté en una carpeta etc/ se revisa siempre."""
        texto = ('pyvenv.cfg\0a/.venv/pyvenv.cfg\0env/conda-meta/history\0env/pyvenv.cfg\0notpyvenv.cfg\0'
                 'x/conda-meta/history.bak\0')
        entornos = github.leer_entornos(texto)
        self.assertEqual(entornos, {'': {'pyvenv.cfg'}, 'a/.venv': {'pyvenv.cfg'},
                                    'env': {'conda-meta/history', 'pyvenv.cfg'}})
        descartadas = ('Lib/site-packages/x.py', 'lib/python3.12/site-packages/p/k.pem', 'site-packages/p/k.pem',
                       'a/.venv/LIB/site-packages/w.py', 'a/.venv/lib64/pypy3.10/site-packages/w.py',
                       'env/Lib/test/keycert.pem', 'env/lib/python3.13t/test/k.pem', 'env/lib/pypy3.10/test/k.pem',
                       'env/pkgs/openssl-3.0.13-h2466b09_1/info/test/k.pem',
                       'env/pkgs/python-3.12.1-h1d929f7_1_cpython/Lib/test/k.pem', 'env/pkgs/tzdata-2024a-0/k.pem')
        revisadas = ('pyvenv.cfg', 'app/lib/z.py', 'lib/config.js', 'pkgs/infra/creds.yml', 'Library/k.pem',
                     'lib/python3.12/ajustes.py', 'lib/node/site-packages/k.pem', 'a/.venv/bin/activate',
                     'a/lib/site-packages/v.py', 'env/lib/R/etc/Renviron.site', 'env/Lib/R/etc/Renviron.site',
                     'env/lib/libssl/k.pem', 'env/LIB/test/k.pem', 'env/Library/ssl/k.pem',
                     'env/etc/conda/activate.d/e.sh', 'lib/site-packages/p/etc/k.pem', 'lib',
                     'env/lib64/python3.12/test/k.pem', 'env/LIB/python3.12/test/k.pem', 'env/pkgs/api/.env',
                     'env/pkgs/infra-2-prod/k.pem', 'env/pkgs/api-v2-final/k.pem', 'env/pkgs/k.pem')
        secretos = [{'regla': 'r', 'ruta': ruta, 'primera_vez': None} for ruta in descartadas + revisadas]
        self.assertEqual([s['ruta'] for s in github.fuera_de_entornos(secretos, entornos)], list(revisadas))
        self.assertEqual(github.fuera_de_entornos(secretos, {}), secretos)

    def test_4c_una_marca_de_conda_en_la_raiz_solo_descarta_site_packages(self):
        """Un conda-meta/history en la raíz, aunque sea de una rama ya fusionada, no esconde pkgs/, Lib/ ni lib/ del
        cliente: en la raíz solo se descarta site-packages, sea cual sea la marca."""
        entornos = github.leer_entornos('conda-meta/history\0')
        self.assertEqual(entornos, {'': {'conda-meta/history'}})
        descartadas = ('site-packages/p/k.pem', 'Lib/site-packages/p/k.pem', 'lib/python3.12/site-packages/p/k.pem')
        revisadas = ('pkgs/api/.env', 'pkgs/openssl-3.0.13-h2466b09_1/info/test/k.pem', 'Lib/config.py',
                     'Lib/test/k.pem', 'lib/python3.12/ajustes.py', 'conda-meta/history')
        secretos = [{'regla': 'r', 'ruta': ruta, 'primera_vez': None} for ruta in descartadas + revisadas]
        self.assertEqual([s['ruta'] for s in github.fuera_de_entornos(secretos, entornos)], list(revisadas))

    def test_4_un_reporte_ilegible_es_falla_de_ese_repo(self):
        res, _ = recolectar(procesos=ProcesosSimulados(reportes={'sitio': 'esto no es json'}))
        self.assertEqual(res.estado, 'succeeded')
        self.assertIn('github: no se pudo leer el reporte de gitleaks de acme-demo/sitio', res.avisos)
        self.assertIn('github: cobertura parcial, se revisaron 1 de 2 repos', res.avisos)
        with self.assertRaises(FuenteNoResponde):
            recolectar(procesos=ProcesosSimulados(reportes={'sitio': '{"no": "lista"}', 'api': '[1, 2]'}))


class Correos(unittest.TestCase):
    """D4: solo correos del dominio o subdominios, validados. Los demás solo se cuentan."""

    def test_1_quedan_los_del_dominio_y_de_sus_subdominios(self):
        res = por_ejecutar()
        self.assertEqual(res.estado, 'succeeded', res.error)
        correos = [a for a in res.activos if a.tipo == 'email']
        self.assertEqual([a.valor for a in correos], ['ana@ti.acme-demo.mx', 'dev@acme-demo.mx'])
        self.assertEqual(correos[1].atributos, {'fuente': 'github', 'repos': ['acme-demo/sitio', 'acme-demo/api'],
                                                'commits': 4, 'primera_vez': '2026-08-31T12:00:00+00:00'})
        self.assertIn('github: se descartaron 6 correos que no son del dominio, contando cada repo aparte', res.avisos)
        self.assertIn('github: se descartaron 4 correos del dominio con forma inválida, contando cada repo aparte',
                      res.avisos)

    def test_2_un_hallazgo_bajo_por_correo_sin_nombres(self):
        res, _ = recolectar()
        correos = [h for h in res.hallazgos if h.codigo == 'email_in_public_commits']
        self.assertEqual([h.activo for h in correos], ['ana@ti.acme-demo.mx', 'dev@acme-demo.mx'])
        h = correos[1]
        self.assertEqual(h.severidad, 'low')
        self.assertEqual(h.titulo, 'Correo de la empresa en los cambios publicados en GitHub')   # sin el correo
        self.assertEqual(set(h.evidencia), {'title', 'repos', 'commits', 'primera_vez'})
        self.assertNotIn('@', json.dumps(h.evidencia))
        self.assertIn('  [baja] Correo de la empresa en los cambios publicados en GitHub: dev@acme-demo.mx',
                      github.resumen(res))
        self.assertEqual(h.caracteristicas, {'tipo': 'correo_en_commits', 'antiguedad_dias': 45,
                                             'exposicion': 'publica', 'sensibilidad': 'media'})
        self.assertEqual(h.huella, huella('email_in_public_commits', 'dev@acme-demo.mx'))

    def test_3_leer_correos_no_guarda_los_descartados(self):
        correos, ajenos, invalidos = github.leer_correos(LOG + 'basura sin separadores\n\x00\x00\n', DOMINIO)
        self.assertEqual([(c['correo'], c['commits']) for c in correos], [('ana@ti.acme-demo.mx', 1), ('dev@acme-demo.mx', 2)])
        self.assertEqual((ajenos, invalidos), (3, 2))

    def test_3b_un_separador_raro_dentro_del_correo_no_parte_la_linea(self):
        raros = '\n'.join(commit('x%sdirector@acme-demo.mx' % c, 'dev@acme-demo.mx', EPOCA)
                          for c in ('\x1e', '\x1c', '\x85', '\u2028', '\r', '\x0b'))
        correos, ajenos, invalidos = github.leer_correos(raros + '\n', DOMINIO)
        self.assertEqual([(c['correo'], c['commits']) for c in correos], [('dev@acme-demo.mx', 6)])
        self.assertEqual((ajenos, invalidos), (0, 6))

    def test_3c_un_separador_raro_en_las_puntas_no_se_quita(self):
        raros = ('\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\x1f', '\x85', '\u2028', '\u2029')
        texto = '\n'.join([commit('%sdirector@acme-demo.mx' % c, 'dev@acme-demo.mx', EPOCA) for c in raros]
                          + [commit('director@acme-demo.mx%s' % c, 'dev@acme-demo.mx', EPOCA) for c in raros]
                          + [commit(' ana@acme-demo.mx\t', 'dev@acme-demo.mx', EPOCA)])
        correos, ajenos, invalidos = github.leer_correos(texto + '\n', DOMINIO)
        self.assertEqual([(c['correo'], c['commits']) for c in correos],
                         [('ana@acme-demo.mx', 1), ('dev@acme-demo.mx', 2 * len(raros) + 1)])
        self.assertEqual(ajenos + invalidos, 2 * len(raros))

    def test_4_los_repos_del_activo_email_van_hasta_cinco(self):
        repos = [repo('r%d' % i, '2026-10-%02dT00:00:00Z' % (i + 1)) for i in range(8)]
        res, _ = recolectar(ApiSimulada(perfil=dict(PERFIL, public_repos=8), repos=repos))
        (dev,) = [a for a in res.activos if a.valor == 'dev@acme-demo.mx']
        self.assertEqual(len(dev.atributos['repos']), github.MAX_REPOS_ACTIVO)
        self.assertEqual(dev.atributos['commits'], 16)


class Procesos(unittest.TestCase):
    """D2: argumentos, entorno, nombres y límites."""

    def test_1_git_clona_bare_con_opciones_seguras_y_la_url_despues_de_doble_guion(self):
        procesos = ProcesosSimulados()
        with mock.patch.dict(os.environ, {'CIRDAN_APP_PASSWORD': 'no-debe-pasar'}):
            recolectar(procesos=procesos)
        clon = procesos.de('clone')[0]
        casa = clon.cwd
        self.assertEqual(clon.comando, [BINARIOS['git'], '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
                                        '-c', 'protocol.https.allow=always', '-c', 'transfer.fsckObjects=true',
                                        '-c', 'credential.helper=', 'clone', '--bare', '--no-tags', '--quiet', '--',
                                        'https://github.com/acme-demo/sitio.git', os.path.join(casa, 'repo.git')])
        fuga = procesos.de('gitleaks')[0].comando
        self.assertEqual(fuga[:3], [BINARIOS['gitleaks'], 'git', os.path.join(casa, 'repo.git')])
        for opcion in (['--config', str(github.REGLAS)], ['--log-opts=--all --no-renames'], ['--ignore-gitleaks-allow'],
                       ['--redact'], ['--exit-code', '0'], ['--report-format', 'json']):
            self.assertTrue(any(fuga[i:i + len(opcion)] == opcion for i in range(len(fuga))), opcion)
        self.assertEqual(fuga[-2:], ['--max-target-megabytes', '100'])
        log = procesos.de('log')[0]
        self.assertEqual(log.comando, [BINARIOS['git'], *github.OPCIONES_GIT, '-C', os.path.join(casa, 'repo.git'),
                                       'log', '--all', '--format=%ae%x00%ce%x00%ct'])
        entornos = procesos.de('entornos')[0]
        self.assertEqual(entornos.comando, [BINARIOS['git'], *github.OPCIONES_GIT, '-C', os.path.join(casa, 'repo.git'),
                                            'log', '--all', '--full-history', '--no-renames', '--format=',
                                            '--name-only', '-z', '--', ':(glob)**/pyvenv.cfg',
                                            ':(glob)**/conda-meta/history'])
        self.assertEqual(entornos.timeout, github.TIMEOUT_ENTORNOS)
        salidas = {'log': 'log.txt', 'entornos': 'entornos.txt'}
        entorno = {'PATH': os.environ.get('PATH', os.defpath), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                   'GIT_TERMINAL_PROMPT': '0', 'GIT_LFS_SKIP_SMUDGE': '1'}
        if os.name == 'nt':
            entorno['SYSTEMROOT'] = os.environ.get('SYSTEMROOT', r'C:\Windows')
        for ll in procesos.llamadas:
            self.assertEqual(ll.env, dict(entorno, HOME=ll.cwd))
            self.assertTrue(ll.casa)
            self.assertTrue(os.path.basename(ll.cwd).startswith(github.PREFIJO_TEMPORAL))
            self.assertEqual(ll.salida, os.path.join(ll.cwd, salidas[ll.paso]) if ll.paso in salidas else None)
            self.assertEqual(ll.disco, github.MAX_DISCO)

    def test_2_nombres_de_repo_peligrosos_no_llegan_a_la_linea_de_comandos(self):
        malos = ['-x', '..', '.', '...', 'a/b', 'ok..x', 'a b', '-', 'x' * 101, None, 7]
        procesos = ProcesosSimulados(reporte=[], log='')
        res, _ = recolectar(ApiSimulada(repos=[repo(n) for n in malos] + [repo('bueno')]), procesos)
        self.assertEqual([ll.repo for ll in procesos.de('clone')], ['bueno'])
        self.assertIn('github: se saltaron 11 repos con nombre inválido', res.avisos)
        self.assertIn('github: cobertura parcial, se revisaron 1 de 12 repos', res.avisos)
        self.assertEqual(res.sin_cobertura, CODIGOS)
        for valido in ('.github', '_privado', 'a.b-c_d', 'x' * 100):
            self.assertTrue(github._repo_valido(valido), valido)

    def test_3_fork_deshabilitado_y_grande_se_saltan_con_aviso_y_archivado_y_vacio_entran(self):
        """El de tamaño 0 entra: GitHub calcula 'size' cada hora y un repo recién creado sale con 0."""
        repos = [repo('fork', fork=True), repo('apagado', disabled=True), repo('vacio', kb=0),
                 repo('grande', kb=github.MAX_KB_REPO + 1), repo('sin-tamano', kb=None), repo('viejo', archived=True),
                 repo('privado', private=True)]
        procesos = ProcesosSimulados()
        res, _ = recolectar(ApiSimulada(repos=repos), procesos)
        self.assertEqual([ll.repo for ll in procesos.de('clone')], ['viejo', 'vacio'])
        self.assertEqual([a for a in res.avisos if 'saltó' in a or 'saltaron' in a], [
            'github: se saltó 1 repo fork', 'github: se saltó 1 repo deshabilitado',
            'github: se saltaron 2 repos de más de 100 MB o sin tamaño'])
        self.assertIn('github: cobertura parcial, se revisaron 2 de 4 repos', res.avisos)
        self.assertEqual(res.sin_revisar, ['acme-demo/grande', 'acme-demo/sin-tamano'])   # sin el fork ni el apagado
        self.assertEqual(res.sin_cobertura, [])   # los dos códigos trajeron hallazgos: solo queda el aviso
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_4_hasta_diez_repos_por_ultimo_push(self):
        repos = [repo('r%02d' % i, '2026-10-%02dT00:00:00Z' % (i + 1)) for i in range(13)]
        procesos = ProcesosSimulados()
        res, _ = recolectar(ApiSimulada(perfil=dict(PERFIL, public_repos=13), repos=repos), procesos)
        self.assertEqual([ll.repo for ll in procesos.de('clone')], ['r%02d' % i for i in range(12, 2, -1)])
        self.assertIn('github: se saltaron 3 repos más allá de los 10 más recientes', res.avisos)
        self.assertIn('github: cobertura parcial, se revisaron 10 de 13 repos', res.avisos)
        self.assertEqual(res.sin_cobertura, [])
        self.assertFalse({h.codigo for h in res.hallazgos} & set(res.sin_cobertura))

    def test_5_sin_hallazgos_y_con_cobertura_parcial_los_dos_codigos_van_a_sin_cobertura(self):
        repos = [repo('r%02d' % i, '2026-10-%02dT00:00:00Z' % (i + 1)) for i in range(13)]
        res, _ = recolectar(ApiSimulada(repos=repos), ProcesosSimulados(reporte=[], log=''))
        self.assertEqual((res.hallazgos, res.sin_cobertura), ([], CODIGOS))
        res, _ = recolectar(ApiSimulada(repos=repos), ProcesosSimulados(log=''))
        self.assertEqual(res.sin_cobertura, ['email_in_public_commits'])
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_6_una_pagina_llena_con_mas_repos_es_cobertura_parcial(self):
        repos = [repo('r%03d' % i, fork=True) for i in range(github.POR_PAGINA)]
        res, _ = recolectar(ApiSimulada(perfil=dict(PERFIL, public_repos=150), repos=repos), sin_procesos)
        self.assertIn('github: cobertura parcial, se revisaron 0 de 0 o más repos', res.avisos)
        self.assertEqual(res.sin_cobertura, CODIGOS)

    def test_7_un_repo_que_falla_deja_aviso_y_si_fallan_todos_la_fuente_no_responde(self):
        res, _ = recolectar(procesos=ProcesosSimulados(fallas={('clone', 'api'): 128}))
        self.assertIn('github: no se pudo clonar acme-demo/api (código 128)', res.avisos)
        self.assertIn('github: cobertura parcial, se revisaron 1 de 2 repos', res.avisos)
        with self.assertRaises(FuenteNoResponde) as e:
            recolectar(procesos=ProcesosSimulados(fallas={('clone', 'api'): 128, ('log', 'sitio'): 1}))
        self.assertEqual(str(e.exception), 'github: no se pudo revisar ningún repo de acme-demo')

    def test_7b_con_cobertura_parcial_revisados_y_sin_revisar_llevan_los_repos(self):
        """#23: cada secreto lleva su repo como parte y cada correo todos los repos donde salió. Con la cobertura parcial,
        revisados lleva los repos que sí se revisaron y, si la lista de repos vino completa, sin_revisar los públicos que
        no, sin el fork, que una corrida completa tampoco revisa: así el orquestador no cierra el secreto de un repo que
        no se clonó y sí el de uno que ya no está. Con todo revisado, los dos quedan en None."""
        reportes = {'api': [hallazgo_gitleaks(archivo='config/.env')], 'sitio': [hallazgo_gitleaks(archivo='web/.env')]}
        completo, _ = recolectar(procesos=ProcesosSimulados(reportes=reportes))
        self.assertEqual((completo.revisados, completo.sin_revisar), (None, None))
        self.assertEqual({h.evidencia['ruta']: h.partes for h in completo.hallazgos if h.codigo == 'secret_in_public_repo'},
                         {'config/.env': ['acme-demo/api'], 'web/.env': ['acme-demo/sitio']})
        correos = [h for h in completo.hallazgos if h.codigo == 'email_in_public_commits']
        self.assertTrue(correos)
        self.assertEqual({tuple(sorted(h.partes)) for h in correos}, {('acme-demo/api', 'acme-demo/sitio')})
        fallas = {'clon que se pasa de su tiempo': {('clone', 'api'): subprocess.TimeoutExpired(['git'], 120)},
                  'gitleaks que falla': {('gitleaks', 'api'): 1}}
        for caso, falla in fallas.items():
            with self.subTest(caso=caso):
                res, _ = recolectar(procesos=ProcesosSimulados(reportes=reportes, fallas=falla))
                self.assertEqual(res.revisados, ['acme-demo/sitio'])
                self.assertEqual(res.sin_revisar, ['acme-demo/api'])   # copia es un fork
                self.assertEqual([h.partes for h in res.hallazgos if h.codigo == 'secret_in_public_repo'],
                                 [['acme-demo/sitio']])
                self.assertEqual({tuple(h.partes) for h in res.hallazgos if h.codigo == 'email_in_public_commits'},
                                 {('acme-demo/sitio',)})
                self.assertEqual(res.sin_cobertura, [])   # el código trae hallazgos: solo las partes protegen al de api
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        repos = [repo('r%02d' % i, '2026-10-%02dT00:00:00Z' % (i + 1)) for i in range(13)]
        res, _ = recolectar(ApiSimulada(perfil=dict(PERFIL, public_repos=13), repos=repos), ProcesosSimulados())
        self.assertEqual(res.revisados, ['acme-demo/r%02d' % i for i in range(12, 2, -1)])   # los 10 del tope
        self.assertEqual(res.sin_revisar, ['acme-demo/r%02d' % i for i in range(3)])
        correo = next(h for h in res.hallazgos if h.codigo == 'email_in_public_commits')
        self.assertEqual(len(correo.evidencia['repos']), github.MAX_REPOS_ACTIVO)
        self.assertEqual(sorted(correo.partes), sorted(res.revisados))   # las partes no se cortan
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_7c_sin_la_lista_completa_de_repos_sin_revisar_queda_en_none(self):
        """#23: con más páginas de repos o un nombre que no se puede usar no se sabe cuáles son todos: sin_revisar no
        dice nada y el orquestador solo cierra lo de los repos revisados. Un fork o un deshabilitado con nombre
        inválido no importa, porque tampoco se revisaría."""
        mas = [repo('r%03d' % i, fork=i > 0) for i in range(github.POR_PAGINA)]
        res, _ = recolectar(ApiSimulada(perfil=dict(PERFIL, public_repos=150), repos=mas), ProcesosSimulados())
        self.assertEqual((res.revisados, res.sin_revisar), (['acme-demo/r000'], None))
        for cambios, sin_revisar in (({}, None), ({'fork': True}, ['acme-demo/api']),
                                     ({'disabled': True}, ['acme-demo/api'])):
            raro = REPOS + [repo('../fuera', '2026-10-01T10:00:00Z', **cambios)]
            res, _ = recolectar(ApiSimulada(repos=raro), ProcesosSimulados(fallas={('clone', 'api'): 128}))
            self.assertEqual((res.revisados, res.sin_revisar), (['acme-demo/sitio'], sin_revisar), cambios)

    def test_8_el_tiempo_de_la_corrida_recorta_cada_paso_y_corta_los_repos(self):
        repos = [repo('a', '2026-10-03T00:00:00Z'), repo('b', '2026-10-02T00:00:00Z'), repo('c', '2026-10-01T00:00:00Z')]
        procesos = ProcesosSimulados()   # con un hallazgo: clon, gitleaks, entornos y git log
        res, _ = recolectar(ApiSimulada(repos=repos), procesos, cronometro=Cronometro(32))
        self.assertEqual([ll.repo for ll in procesos.de('clone')], ['a', 'b'])
        self.assertEqual([(ll.paso, ll.timeout) for ll in procesos.llamadas],
                         [('clone', 120), ('gitleaks', 120), ('entornos', 30), ('log', 60),
                          ('clone', 72), ('gitleaks', 40), ('entornos', 8)])
        self.assertIn('github: se acabó el tiempo de la corrida al leer los commits de acme-demo/b', res.avisos)
        self.assertIn('github: se acabó el tiempo de la corrida antes de revisar 1 repo', res.avisos)
        self.assertIn('github: cobertura parcial, se revisaron 1 de 3 repos', res.avisos)

    def test_8b_el_tiempo_de_la_corrida_tambien_corta_la_api(self):
        api = ApiSimulada()
        with self.assertRaises(FuenteNoResponde) as e:
            recolectar(api, sin_procesos, cronometro=Cronometro(200))
        self.assertEqual(str(e.exception), 'github: se acabó el tiempo de la corrida antes de consultar la API (repos)')
        self.assertEqual(len(api.urls), 1)

    def test_9_sin_git_o_gitleaks_la_fuente_no_responde_antes_de_consultar(self):
        with mock.patch.object(github, '_binario', lambda nombre: None), self.assertRaises(FuenteNoResponde) as e:
            recolectar(sin_api, sin_procesos, git=False)
        self.assertEqual(str(e.exception), 'github: git o gitleaks no está instalado')
        with mock.patch.object(github, '_binario', lambda nombre: None):
            res, _ = recolectar(sin_api, sin_procesos, git=False, declaradas='acme-demo.mx=ninguna')
        self.assertEqual(res.avisos, [github.DECLARO_NINGUNA])   # sin organización no hacen falta

    def test_10_git_log_que_pasa_de_su_tope_es_falla_de_ese_repo(self):
        with mock.patch.object(github, 'MAX_LOG', len(LOG) - 1):
            res, _ = recolectar(procesos=ProcesosSimulados(logs={'sitio': LOG, 'api': ''}))
        self.assertIn('github: los commits de acme-demo/sitio pasan de 0 MB', res.avisos)
        self.assertIn('github: cobertura parcial, se revisaron 1 de 2 repos', res.avisos)
        self.assertEqual([a.valor for a in res.activos if a.tipo == 'email'], [])

    def test_11_un_proceso_que_llena_el_disco_es_falla_de_ese_repo(self):
        res, _ = recolectar(procesos=ProcesosSimulados(fallas={('clone', 'sitio'): github.MuyGrande()}))
        self.assertIn('github: se pasó de 300 MB al clonar acme-demo/sitio', res.avisos)
        self.assertIn('github: cobertura parcial, se revisaron 1 de 2 repos', res.avisos)

    def test_12_los_paquetes_de_un_entorno_con_marca_se_descartan_y_lo_demas_se_revisa(self):
        """pyvenv.cfg (venv, virtualenv, uv y PyPy) o conda-meta/history (conda) marcan un entorno instalado: se
        descarta su site-packages, sea cual sea su forma, y con conda también la biblioteca estándar y los paquetes de
        pkgs/. Se revisa lo demás, como bin/activate, Library/, etc/ o la lib/ de un venv, y con las dos marcas en la
        raíz, lib/, Lib/ y pkgs/ del cliente."""
        rutas = {'herramientas/pypy/lib/pypy3.10/site-packages/tornado/test/test.key': False,
                 'py313t/lib/python3.13t/site-packages/paquete/prueba.pem': False,
                 'lib/python3.12/site-packages/paquete/prueba.pem': False,
                 'conda/Lib/test/keycert.pem': False, 'conda/pkgs/openssl-3.0.13-h2466b09_1/info/test/clave.pem': False,
                 'conda/Library/ssl/clave.pem': True, 'conda/Lib/R/etc/Renviron.site': True,
                 'py313t/bin/activate': True, 'conda/etc/conda/activate.d/env_vars.sh': True,
                 'conda/Scripts/activate.bat': True, 'herramientas/lib/claves.py': True, '.env/lib/produccion.sh': True,
                 'lib/config.js': True, 'pkgs/infra/creds.yml': True, 'Lib/ajustes.py': True, 'conda/pkgs/api/.env': True}
        marcas = ('pyvenv.cfg\0conda-meta/history\0herramientas/pypy/pyvenv.cfg\0py313t/pyvenv.cfg\0.env/pyvenv.cfg\0'
                  'conda/conda-meta/history\0')
        procesos = ProcesosSimulados(reporte=[hallazgo_gitleaks(archivo=ruta) for ruta in rutas], entornos=marcas)
        res, _ = recolectar(procesos=procesos)
        self.assertEqual({h.evidencia['ruta'] for h in res.hallazgos if h.codigo == 'secret_in_public_repo'},
                         {ruta for ruta, revisada in rutas.items() if revisada})
        self.assertEqual([ll.repo for ll in procesos.de('entornos')], ['sitio', 'api'])

    def test_13_sin_hallazgos_no_busca_entornos_y_si_la_busqueda_falla_quedan_todos_los_secretos_con_aviso(self):
        """Mejor un crítico falso de un paquete que perder un secreto: falle por código, por tiempo, por disco o por
        tamaño, el repo cuenta como revisado, no se descarta nada y queda un aviso con la causa. El aviso también va
        en la evidencia de cada secreto del repo, porque el resumen de la corrida no se guarda (keep_raw_payload). La
        salida de la búsqueda se borra, así no le quita el disco al git log de los correos."""
        procesos = ProcesosSimulados(reporte=[])
        recolectar(procesos=procesos)
        self.assertEqual(procesos.de('entornos'), [])
        paquete = 'venv2/lib/python3.12/site-packages/p/k.pem'
        casos = [({('entornos', 'sitio'): 1}, '', None,
                  {'sitio': 'github: no se pudo buscar entornos de Python en acme-demo/sitio (código 1)'}),
                 ({('entornos', 'sitio'): subprocess.TimeoutExpired('git', 30)}, '', None,
                  {'sitio': 'github: no se terminó de buscar entornos de Python en acme-demo/sitio en 30 s'}),
                 ({('entornos', 'sitio'): github.MuyGrande()}, '', None,
                  {'sitio': 'github: se pasó de 300 MB al buscar entornos de Python en acme-demo/sitio'}),
                 ({}, 'x\0' * 2000, len(LOG.encode('utf-8')),
                  {r: 'github: los entornos de Python de acme-demo/%s pasan de 0 MB' % r for r in ('sitio', 'api')})]
        for fallas, relleno, tope, causas in casos:
            procesos = ProcesosSimulados(reporte=[hallazgo_gitleaks(archivo=paquete)], fallas=fallas,
                                         entornos=relleno + 'venv2/pyvenv.cfg\0')
            with mock.patch.object(github, 'MAX_LOG', tope or github.MAX_LOG):
                res, _ = recolectar(procesos=procesos)
            avisos = {'acme-demo/' + r: github.SIN_ENTORNOS % causa for r, causa in causas.items()}
            self.assertEqual([(h.evidencia['repo'], h.evidencia['ruta'], h.evidencia.get('aviso'))
                              for h in res.hallazgos if h.codigo == 'secret_in_public_repo'],
                             [(r, paquete, aviso) for r, aviso in avisos.items()])
            self.assertEqual([a for a in res.avisos if 'entornos' in a], list(avisos.values()))
            self.assertEqual([a for a in res.avisos if 'cobertura parcial' in a], [])
            self.assertEqual((res.revisados, res.sin_revisar), (None, None))
            self.assertEqual([ll.restos for ll in procesos.de('log')], [['reporte.json']] * 2)
            self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        self.assertNotIn('sin_entornos', github.revision_valida({'secretos': [], 'correos': [], 'sin_entornos': 'x'},
                                                                DOMINIO))

    def test_13b_si_el_tiempo_de_la_corrida_se_acaba_en_la_busqueda_el_repo_queda_como_falla(self):
        """Lo que la búsqueda cortada deja sin tiempo es el git log de los correos: el repo no cuenta como revisado,
        sale en sin_revisar y no da sus secretos ni un aviso de entornos."""
        repos = [repo('a', '2026-10-03T00:00:00Z'), repo('b', '2026-10-02T00:00:00Z'), repo('c', '2026-10-01T00:00:00Z')]
        procesos = ProcesosSimulados(fallas={('entornos', 'b'): subprocess.TimeoutExpired('git', 8)})
        res, _ = recolectar(ApiSimulada(repos=repos), procesos, cronometro=Cronometro(32))
        self.assertEqual([(ll.paso, ll.repo, ll.timeout) for ll in procesos.llamadas][-2:],
                         [('gitleaks', 'b', 40), ('entornos', 'b', 8)])
        self.assertIn('github: se acabó el tiempo de la corrida al leer los commits de acme-demo/b', res.avisos)
        self.assertEqual([a for a in res.avisos if 'entornos' in a], [])
        self.assertEqual([h.partes for h in res.hallazgos if h.codigo == 'secret_in_public_repo'], [['acme-demo/a']])
        self.assertEqual((res.revisados, res.sin_revisar), (['acme-demo/a'], ['acme-demo/b', 'acme-demo/c']))


class Cuota(unittest.TestCase):
    """D6: 403 y 429 no se reintentan ni dejan la fuente fallida."""

    def test_1_403_o_429_queda_sin_cobertura_sin_reintentar(self):
        for ruta, codigo, consultas in (('/orgs/acme-demo', 403, 1), ('/orgs/acme-demo', 429, 1),
                                        ('/orgs/acme-demo/repos', 429, 2)):
            with self.subTest(ruta=ruta, codigo=codigo):
                res = por_ejecutar(api=ApiSimulada(fallas={ruta: [codigo]}), procesos=sin_procesos)
                self.assertEqual((res.estado, res.sin_cobertura, res.avisos, res.consultas),
                                 ('succeeded', CODIGOS, [github.SIN_CUOTA], consultas))

    def test_2_un_5xx_se_reintenta_dentro_de_la_corrida(self):
        api = ApiSimulada(fallas={'/orgs/acme-demo': [502, 503]})
        res, c = recolectar(api)
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.consultas, 3 + 1 + 2)

    def test_2b_una_respuesta_que_llega_gota_a_gota_se_corta_y_una_grande_tambien(self):
        class Gotero:
            def __init__(self, espera, trozo):
                self.espera, self.trozo = espera, trozo

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read1(self, n):
                time.sleep(self.espera)
                return self.trozo

        with mock.patch.object(github.urllib.request, 'urlopen', lambda req, timeout: Gotero(0.2, b'x')):
            inicio = time.monotonic()
            with self.assertRaises(TimeoutError):
                github._descargar('https://api.github.com/orgs/acme-demo', 1)
            self.assertLess(time.monotonic() - inicio, 5)
        with mock.patch.object(github.urllib.request, 'urlopen', lambda req, timeout: Gotero(0, b'x' * 1024)), \
                mock.patch.object(github, 'MAX_BYTES', 4000), self.assertRaises(ValueError):
            github._descargar('https://api.github.com/orgs/acme-demo', 30)

    def test_3_el_peor_caso_cabe_en_max_consultas(self):
        self.assertEqual(github.MAX_CONSULTAS, 16)
        repos = [repo('r%02d' % i, '2026-10-%02dT00:00:00Z' % (i + 1)) for i in range(13)]
        api = ApiSimulada(perfil=dict(PERFIL, public_repos=13), repos=repos,
                          fallas={'/orgs/acme-demo': [502, 502], '/orgs/acme-demo/repos': [502, 502]})
        res = por_ejecutar(api=api)
        self.assertEqual((res.estado, res.consultas), ('succeeded', github.MAX_CONSULTAS))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])


class GrabarYReproducir(unittest.TestCase):
    """D8: se graba lo ya limpio y solo si la corrida terminó."""

    def test_1_graba_y_reproduce_lo_mismo_sin_red_ni_procesos(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            grabado, _ = recolectar(modo='grabar', carpeta=carpeta, nueva=True)
            self.assertIsNotNone(contrato.Grabadora.inicio(carpeta))
            self.assertEqual(len(list(carpeta.glob('*.json'))), 4)   # perfil, repos y 2 repos revisados
            otra, c = recolectar(sin_api, sin_procesos, modo='reproducir', carpeta=carpeta)
        self.assertEqual((otra.estado, otra.consultas), ('succeeded', 0))
        self.assertEqual((otra.activos, otra.hallazgos, otra.avisos, otra.sin_cobertura, otra.revisados, otra.sin_revisar),
                         (grabado.activos, grabado.hallazgos, grabado.avisos, grabado.sin_cobertura, grabado.revisados,
                          grabado.sin_revisar))
        self.assertEqual(len(c.leidas), 4)

    def test_2_una_grabacion_fallida_deja_intacta_la_anterior(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d)
            (carpeta / 'viejo.json').write_text('[]', encoding='utf-8')
            res, _ = recolectar(procesos=ProcesosSimulados(reporte=[hallazgo_gitleaks(Secret=TOKEN)]), modo='grabar',
                                carpeta=carpeta, nueva=True)
            self.assertEqual(res.avisos, [github.SIN_REDACTAR])
            self.assertEqual(sorted(p.name for p in carpeta.iterdir()), ['viejo.json'])
            with self.assertRaises(FuenteNoResponde):
                recolectar(procesos=ProcesosSimulados(fallas={('clone', 'sitio'): 1, ('clone', 'api'): 1}),
                           modo='grabar', carpeta=carpeta, nueva=True)
            self.assertEqual(sorted(p.name for p in carpeta.iterdir()), ['viejo.json'])

    def test_3_reproducir_sin_grabacion_queda_sin_cobertura(self):
        with tempfile.TemporaryDirectory() as d:
            res = por_ejecutar(sin_api, sin_procesos, modo='reproducir', carpeta=d)
        self.assertEqual((res.estado, res.sin_cobertura, res.avisos), ('succeeded', CODIGOS, [github.SIN_GRABACION_DOMINIO]))

    def test_4_reproducir_con_un_repo_sin_grabar_es_cobertura_parcial(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d)
            recolectar(modo='grabar', carpeta=carpeta, nueva=True)
            github.ClienteGitHub(modo='grabar', carpeta=carpeta).grabadora.archivo('repo:acme-demo/api').unlink()
            res, _ = recolectar(sin_api, sin_procesos, modo='reproducir', carpeta=carpeta)
        self.assertIn('github: falta la grabación de 1 repo', res.avisos)
        self.assertIn('github: cobertura parcial, se revisaron 1 de 2 repos', res.avisos)
        self.assertEqual((res.revisados, res.sin_revisar), (['acme-demo/sitio'], ['acme-demo/api']))

    def test_5_una_grabacion_cambiada_a_mano_no_mete_otra_cosa(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d)
            recolectar(modo='grabar', carpeta=carpeta, nueva=True)
            archivo = github.ClienteGitHub(modo='grabar', carpeta=carpeta).grabadora.archivo('repo:acme-demo/sitio')
            contenido = json.loads(archivo.read_text(encoding='utf-8'))
            contenido['datos']['correos'].append({'correo': 'x@gmail.com', 'commits': 1, 'primera_vez': None})
            contenido['datos']['correos'].append({'correo': 'z@acme-demo.mx', 'commits': -3, 'primera_vez': None})
            contenido['datos']['secretos'].append({'regla': 'Regla Mala', 'ruta': 'x', 'primera_vez': None, 'valor': TOKEN})
            archivo.write_text(json.dumps(contenido), encoding='utf-8')
            res, _ = recolectar(sin_api, sin_procesos, modo='reproducir', carpeta=carpeta)
        self.assertNotIn('x@gmail.com', [a.valor for a in res.activos])
        self.assertNotIn('z@acme-demo.mx', [a.valor for a in res.activos])
        self.assertNotIn(TOKEN, json.dumps(res.a_dict()))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_5b_al_grabar_una_busqueda_de_entornos_que_falla_es_falla_del_repo(self):
        """Grabado sin filtrar, cada demo mostraría los críticos falsos de sus paquetes hasta volver a grabar: ese repo no
        se graba, la corrida queda con cobertura parcial y al reproducir falta su grabación. La grabación nunca trae el
        aviso de entornos, así que una cambiada a mano tampoco lo mete en la evidencia."""
        paquete = 'venv2/lib/python3.12/site-packages/p/k.pem'
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d)
            procesos = ProcesosSimulados(reporte=[hallazgo_gitleaks(archivo=paquete)], entornos='venv2/pyvenv.cfg\0',
                                         fallas={('entornos', 'sitio'): subprocess.TimeoutExpired('git', 30)})
            grabado, _ = recolectar(procesos=procesos, modo='grabar', carpeta=carpeta, nueva=True)
            self.assertIn('github: no se terminó de buscar entornos de Python en acme-demo/sitio en 30 s', grabado.avisos)
            self.assertIn('github: cobertura parcial, se revisaron 1 de 2 repos', grabado.avisos)
            self.assertEqual([a for a in grabado.avisos if 'sin descartar' in a], [])
            grabadora = github.ClienteGitHub(modo='grabar', carpeta=carpeta).grabadora
            self.assertFalse(grabadora.archivo('repo:acme-demo/sitio').exists())
            otra, _ = recolectar(sin_api, sin_procesos, modo='reproducir', carpeta=carpeta)
            self.assertIn('github: falta la grabación de 1 repo', otra.avisos)
            self.assertEqual((otra.revisados, otra.sin_revisar), (['acme-demo/api'], ['acme-demo/sitio']))
            archivo = grabadora.archivo('repo:acme-demo/api')
            contenido = json.loads(archivo.read_text(encoding='utf-8'))
            contenido['datos']['secretos'].append({'regla': 'cirdan-fake-token', 'ruta': 'x/.env', 'primera_vez': None})
            contenido['datos']['sin_entornos'] = 'github: ' + TOKEN
            archivo.write_text(json.dumps(contenido), encoding='utf-8')
            otra, _ = recolectar(sin_api, sin_procesos, modo='reproducir', carpeta=carpeta)
        (secreto,) = [h for h in otra.hallazgos if h.codigo == 'secret_in_public_repo']
        self.assertNotIn('aviso', secreto.evidencia)
        self.assertNotIn(TOKEN, json.dumps(otra.a_dict()))

    def test_6_dos_repos_parecidos_no_comparten_archivo(self):
        self.assertNotEqual(github._archivo('repo:acme-demo/a.b'), github._archivo('repo:acme-demo/a_b'))
        self.assertNotEqual(github._archivo('repo:acme-demo/A'), github._archivo('repo:acme-demo/a'))
        self.assertTrue(github._archivo('repo:acme-demo/' + 'x' * 100).endswith('.json'))


class Temporales(unittest.TestCase):
    """D7: la carpeta del clon y del reporte se borra, y las de corridas cortadas también."""

    def test_1_la_carpeta_se_borra_al_terminar_y_al_abortar(self):
        with tempfile.TemporaryDirectory() as t:
            for procesos in (ProcesosSimulados(), ProcesosSimulados(reporte=[hallazgo_gitleaks(Secret=TOKEN)])):
                try:
                    recolectar(procesos=procesos, temporal=t)
                except FuenteNoResponde:
                    pass
                self.assertTrue(all(ll.casa for ll in procesos.llamadas))
                self.assertEqual(list(Path(t).iterdir()), [])

    def test_2_cada_corrida_en_vivo_borra_las_carpetas_viejas_y_no_las_nuevas(self):
        with tempfile.TemporaryDirectory() as t:
            vieja, nueva, ajena = (Path(t) / n for n in ('cirdan-github-vieja', 'cirdan-github-nueva', 'otra-vieja'))
            for carpeta in (vieja, nueva, ajena):
                carpeta.mkdir()
                (carpeta / 'repo.git').mkdir()
            hace_dos_horas = time.time() - 2 * 3600
            os.utime(vieja, (hace_dos_horas, hace_dos_horas))
            os.utime(ajena, (hace_dos_horas, hace_dos_horas))
            recolectar(temporal=t)
            self.assertEqual(sorted(p.name for p in Path(t).iterdir()), ['cirdan-github-nueva', 'otra-vieja'])

    def test_3_ejecutar_no_lee_stderr_y_solo_guarda_stdout_en_su_archivo(self):
        programa = 'import sys; print(%r); print(%r, file=sys.stderr)' % ('salida', TOKEN)
        with tempfile.TemporaryDirectory() as t:
            env = github._entorno(t)
            sin_salida = github._ejecutar([sys.executable, '-c', programa], timeout=30, env=env, cwd=t)
            self.assertEqual(os.listdir(t), [])
            archivo = os.path.join(t, 'salida.txt')
            con_salida = github._ejecutar([sys.executable, '-c', programa], timeout=30, env=env, cwd=t, salida=archivo)
            self.assertEqual(Path(archivo).read_text(encoding='utf-8').strip(), 'salida')
        for hecho in (sin_salida, con_salida):
            self.assertEqual((hecho.returncode, hecho.stdout, hecho.stderr), (0, None, None))

    def test_4_ejecutar_mata_el_proceso_que_se_pasa_del_tiempo(self):
        with tempfile.TemporaryDirectory() as t:
            env = github._entorno(t)
            inicio = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                github._ejecutar([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=0.5, env=env, cwd=t)
            self.assertLess(time.monotonic() - inicio, 10)

    def test_5_ejecutar_mata_el_proceso_que_llena_la_carpeta(self):
        programa = "import time; open('grande', 'wb').write(b'0' * 2000000); time.sleep(30)"
        with tempfile.TemporaryDirectory() as t:
            inicio = time.monotonic()
            with self.assertRaises(github.MuyGrande):
                github._ejecutar([sys.executable, '-c', programa], timeout=30, env=github._entorno(t), cwd=t,
                                 disco=1000000)
            self.assertLess(time.monotonic() - inicio, 10)
            self.assertGreaterEqual(github._peso(t), 2000000)

    def test_6_en_windows_el_entorno_lleva_systemroot(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual('SYSTEMROOT' in github._entorno(t), os.name == 'nt')

    def test_7_una_carpeta_vieja_se_borra_aunque_git_deje_archivos_de_solo_lectura(self):
        with tempfile.TemporaryDirectory() as t:
            vieja = Path(t) / 'cirdan-github-vieja'
            paquetes = vieja / 'repo.git' / 'objects' / 'pack'
            paquetes.mkdir(parents=True)
            for nombre in ('pack-1.pack', 'pack-1.idx'):
                (paquetes / nombre).write_bytes(b'x')
                os.chmod(paquetes / nombre, stat.S_IREAD)
            hace_dos_horas = time.time() - 2 * 3600
            os.utime(vieja, (hace_dos_horas, hace_dos_horas))
            github.limpiar_viejas(t)
            self.assertEqual(list(Path(t).iterdir()), [])


class Contrato(unittest.TestCase):

    def test_1_registrado_y_con_los_codigos_del_catalogo(self):
        self.assertEqual(REGISTRO['github'], 'cirdan.recolectores.github')
        for codigo, severidad in github.CODIGOS.items():
            self.assertEqual(severidad, POR_CODIGO[codigo][5], codigo)

    def test_2_por_ejecutar_cumple_el_contrato(self):
        res = por_ejecutar()
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        self.assertLessEqual(res.consultas, github.MAX_CONSULTAS)
        self.assertEqual(sorted({h.codigo for h in res.hallazgos}), sorted(CODIGOS))

    def test_3_las_reglas_de_gitleaks_traen_las_de_omision_sin_herencia_y_la_propia(self):
        """Que sea igual a lo que genera gitleaks_reglas.py con el gitleaks de la imagen lo prueba Integracion."""
        texto = github.REGLAS.read_text(encoding='utf-8-sig')  # gitleaks acepta el BOM
        self.assertNotIn(TOKEN, texto)
        # Solo estas claves: con [extend] la allowlist de omisión se sumaría a esta, y gitleaks lee la config con
        # viper, que no distingue mayúsculas, así que [AllowList] o [Extend] también contarían. En la allowlist, paths
        # y regexes se unen con 'OR': nada de LowTide, que saltaría lo mismo en los repos de los clientes (PR 81)
        reglas = tomllib.loads(texto)
        self.assertEqual(sorted(reglas), ['allowlist', 'rules', 'title'])
        self.assertEqual(sorted(reglas['allowlist']), ['description', 'paths', 'regexes', 'stopwords'])
        self.assertNotIn('cirdan', json.dumps(reglas['allowlist']).lower())
        rutas = reglas['allowlist']['paths']
        self.assertEqual(len(rutas), len(set(rutas)))
        self.assertEqual(set(rutas), {nueva for nueva in gitleaks_reglas.CAMBIOS.values() if nueva}
                         | set(gitleaks_reglas.CONSERVADAS))
        # Las 195 de omisión de 8.21.2 y la propia, cada una con su id
        self.assertEqual(len(reglas['rules']), 196)
        self.assertEqual(len({regla['id'] for regla in reglas['rules']}), 196)
        self.assertEqual(reglas['rules'][-1], tomllib.loads(gitleaks_reglas.REGLA_PROPIA)['rules'][0])

    def test_4_la_imagen_pide_buildkit_y_no_fija_targetarch(self):
        """El builder clásico ignora ADD --checksum: la primera etapa lo detiene con --chmod antes de bajar nada, y
        BuildKit la salta porque ninguna otra la usa. Un ARG TARGETARCH con valor le ganaría a la plataforma que pone
        BuildKit (PR 79)."""
        # Como Docker: primero se quitan los comentarios y las líneas vacías, y después se juntan las que terminan en \
        lineas = [l for l in (RAIZ / 'Dockerfile').read_text(encoding='utf-8-sig').splitlines()
                  if l.strip() and not l.lstrip().startswith('#')]
        instrucciones = [l.strip() for l in re.sub(r'\\[ \t]*\n', ' ', '\n'.join(lineas)).splitlines()]
        self.assertEqual(instrucciones[:2], ['FROM scratch AS pide-buildkit', 'COPY --chmod=0644 requirements.txt /'])
        self.assertEqual([l for l in instrucciones if 'pide-buildkit' in l], ['FROM scratch AS pide-buildkit'])
        for linea in instrucciones:
            if re.match(r'(?i)ARG\s', linea):
                self.assertFalse([a for a in linea.split()[1:] if a.startswith('TARGETARCH=')], linea)


class LineaDeComandos(unittest.TestCase):

    def correr(self, *argv, en_vivo='olmardo.com', carpeta=None):
        salida = io.StringIO()
        with tempfile.TemporaryDirectory() as d, redirect_stdout(salida), \
                mock.patch.dict(os.environ, {'DOMINIOS_EN_VIVO': en_vivo, github.DECLARADAS: DECLARADA}), \
                mock.patch.object(github, 'CARPETA_GRABADAS', Path(carpeta or d)), \
                mock.patch.object(github, '_descargar', sin_api), mock.patch.object(github, '_ejecutar', sin_procesos):
            codigo = github._main(list(argv))
        return codigo, salida.getvalue()

    def test_1_fuera_de_dominios_en_vivo_rechaza_vivo_y_grabar(self):
        for argv in (['acme-demo.mx'], ['acme-demo.mx', '--grabar'], ['../x', '--reproducir']):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as e, \
                    mock.patch('sys.stderr', io.StringIO()):
                self.correr(*argv)
            self.assertEqual(e.exception.code, 2)

    def test_2_reproducir_sin_grabacion_avisa_y_sale_con_2(self):
        codigo, salida = self.correr('acme-demo.mx', '--reproducir')
        self.assertEqual(codigo, 2)
        self.assertIn('Cobertura parcial: no se revisaron secret_in_public_repo ni email_in_public_commits.', salida)
        self.assertIn('aviso: ' + github.SIN_GRABACION_DOMINIO, salida)


def fila_de_la_semilla(code):
    """{columna: valor} de la fila `code` en el INSERT INTO data_sources de la semilla 006, sin comentarios."""
    from pruebas import test_subfinder
    with mock.patch.object(test_subfinder, 'SEMILLA', SEMILLA):
        return test_subfinder.fila_de_la_semilla(code)


class Semilla(unittest.TestCase):
    """Lectura estática de db/semillas/006_github.sql, sin base."""

    def test_1_github_va_encendida_sin_respuesta_cruda_y_con_25_corridas_por_dia(self):
        fila = fila_de_la_semilla('github')
        self.assertIsNotNone(fila, 'la semilla 006 no trae la fila de github en su INSERT INTO data_sources')
        self.assertEqual((fila['kind'], fila['enabled'].lower(), fila['keep_raw_payload'].lower()),
                         ("'osint'", 'true', 'false'))
        self.assertEqual(int(fila['daily_limit']), 25 * github.MAX_CONSULTAS)
        self.assertIn("SET client_encoding = 'UTF8';", SEMILLA.read_text(encoding='utf-8'))


class Reglas(unittest.TestCase):
    """gitleaks_reglas.generar sobre una config por omisión de juguete con la forma de la de 8.21.2."""

    LICENCIA = 'MIT License\n\nCopyright (c) 2019 Zachary Rice\n'

    def omision(self, rutas):
        return ('# auto-generada\n\ntitle = "gitleaks config"\n\n[allowlist]\ndescription = "global allow lists"\n'
                "regexes = [\n    '''^x$''',\n]\npaths = [\n%s]\nstopwords = [\n    \"abc\",\n]\n\n"
                "[[rules]]\nid = \"uno\"\nregex = '''uno[0-9]{8}'''\n\n[rules.allowlist]\npaths = [\n    '''gitleaks\\.toml''',\n]\n"
                % ''.join("    '''%s''',\n" % ruta for ruta in rutas))

    def test_1_quita_o_ancla_las_rutas_de_cambios_y_deja_las_demas_y_las_de_cada_regla(self):
        texto = gitleaks_reglas.generar(self.omision([*gitleaks_reglas.CAMBIOS, '(^|/)node_modules/.*?$']),
                                        self.LICENCIA, '8.21.2')
        self.assertTrue(texto.startswith('# Reglas de gitleaks 8.21.2 '))
        self.assertIn('\n# Copyright (c) 2019 Zachary Rice\n', texto)
        reglas = tomllib.loads(texto)
        self.assertEqual(reglas['title'], 'LowTide: reglas de omisión de gitleaks y tokens falsos CIRDAN_FAKE_')
        self.assertEqual(reglas['allowlist']['paths'],
                         [nueva for nueva in gitleaks_reglas.CAMBIOS.values() if nueva] + ['(^|/)node_modules/.*?$'])
        self.assertEqual((reglas['allowlist']['regexes'], reglas['allowlist']['stopwords']), (['^x$'], ['abc']))
        self.assertEqual([regla['id'] for regla in reglas['rules']], ['uno', 'cirdan-fake-token'])
        self.assertEqual(reglas['rules'][0]['allowlist'], {'paths': [r'gitleaks\.toml']})  # la de cada regla no cambia

    def test_2_falla_si_una_ruta_de_cambios_ya_no_viene_en_la_version_de_gitleaks(self):
        with self.assertRaisesRegex(ValueError, 'ya no vienen'):
            gitleaks_reglas.generar(self.omision(list(gitleaks_reglas.CAMBIOS)[1:]), self.LICENCIA, '8.21.2')

    def test_3_falla_si_la_version_de_gitleaks_trae_una_ruta_sin_revisar(self):
        with self.assertRaisesRegex(ValueError, 'sin revisar'):
            gitleaks_reglas.generar(self.omision([*gitleaks_reglas.CAMBIOS, r'(^|/)composer\.lock$']), self.LICENCIA,
                                    '8.21.2')


@unittest.skipUnless(os.environ.get('INTEGRACION_GITHUB') == '1'
                     or (os.name == 'posix' and shutil.which('git') and shutil.which('gitleaks')),
                     'pide git y gitleaks: corre dentro del contenedor')
class Integracion(unittest.TestCase):
    """git y gitleaks 8.21.2 reales sobre un repo local, sin red. Dentro del contenedor, desde la raíz de BackKL, con
    db/ y docs/ montados porque este archivo importa test_catalogo_reglas, que los lee:
        docker compose run --rm -v "$(pwd -W)/pruebas:/app/pruebas:ro" -v "$(pwd -W)/db:/app/db:ro" \\
            -v "$(pwd -W)/docs:/app/docs:ro" api python -m unittest pruebas.test_github.Integracion
    Con INTEGRACION_GITHUB=1, como en el CI, falla en vez de saltarse si no hay git o gitleaks.
    """

    def armar(self, d, extra=(), permitida=None, renombrar=None, marcas=(), rama=()):
        """Un clon bare de un repo con un token que solo queda en el historial y otro en la versión actual. Cada ruta
        de `extra` lleva TOKEN en un último commit, y `permitida` lo lleva con un comentario gitleaks:allow. Con
        `renombrar` = (de, a), otro commit mueve el archivo de una ruta a la otra sin cambiarlo. Las rutas de `marcas`
        van en el último commit sin token, como marcas de entornos de Python. Una rama agrega las rutas de `rama` (las
        marcas sin token y las demás con TOKEN), otro commit las quita, se fusiona con --no-ff y se borra."""
        fuente, casa = os.path.join(d, 'fuente'), os.path.join(d, 'casa')
        os.mkdir(fuente)
        os.mkdir(casa)
        env = {'PATH': os.environ['PATH'], 'HOME': d, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
               'GIT_AUTHOR_NAME': 'Dev', 'GIT_AUTHOR_EMAIL': 'dev@acme-demo.mx',
               'GIT_COMMITTER_NAME': 'Dev', 'GIT_COMMITTER_EMAIL': 'Dev@Acme-Demo.mx'}

        def git(*args, cwd=fuente):
            subprocess.run(['git', *args], cwd=cwd, env=env, check=True, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        git('init', '-q')
        Path(fuente, 'viejo.txt').write_text('TOKEN=%s\n' % TOKEN, encoding='utf-8')
        git('add', 'viejo.txt')
        git('commit', '-q', '-m', 'uno')
        git('rm', '-q', 'viejo.txt')
        git('commit', '-q', '-m', 'dos')
        os.mkdir(os.path.join(fuente, 'config'))
        Path(fuente, 'config', '.env').write_text('OTRO=%s\n' % OTRO_TOKEN, encoding='utf-8')
        git('add', '-f', 'config/.env')
        git('commit', '-q', '-m', 'tres')
        for ruta in extra:
            os.makedirs(os.path.join(fuente, os.path.dirname(ruta)), exist_ok=True)
            Path(fuente, ruta).write_text('TOKEN=%s\n' % TOKEN, encoding='utf-8')
            git('add', '-f', ruta)
        if permitida:
            os.makedirs(os.path.join(fuente, os.path.dirname(permitida)), exist_ok=True)
            Path(fuente, permitida).write_text('TOKEN = "%s"  # gitleaks:allow\n' % TOKEN, encoding='utf-8')
            git('add', '-f', permitida)
        for ruta in marcas:
            os.makedirs(os.path.join(fuente, os.path.dirname(ruta)), exist_ok=True)
            Path(fuente, ruta).write_text('home = /usr/bin\n', encoding='utf-8')
            git('add', '-f', ruta)
        if extra or permitida or marcas:
            git('commit', '-q', '-m', 'cuatro')
        if renombrar:
            os.makedirs(os.path.join(fuente, os.path.dirname(renombrar[1])), exist_ok=True)
            git('mv', '-f', *renombrar)
            git('commit', '-q', '-m', 'cinco')
        if rama:
            git('checkout', '-q', '-b', 'entorno')
            for ruta in rama:
                os.makedirs(os.path.join(fuente, os.path.dirname(ruta)), exist_ok=True)
                marca = ruta.endswith(github.MARCAS_ENTORNO)
                Path(fuente, ruta).write_text('home = /usr/bin\n' if marca else 'TOKEN=%s\n' % TOKEN, encoding='utf-8')
                git('add', '-f', ruta)
            git('commit', '-q', '-m', 'seis')
            git('rm', '-q', *rama)
            git('commit', '-q', '-m', 'siete')
            git('checkout', '-q', '-')
            git('merge', '-q', '--no-ff', '-m', 'ocho', 'entorno')
            git('branch', '-q', '-D', 'entorno')
        destino = os.path.join(casa, 'repo.git')
        git('clone', '--bare', '--quiet', fuente, destino, cwd=d)
        return destino, casa

    def test_1_la_regla_propia_halla_el_token_en_el_historial_y_en_la_version_actual(self):
        with tempfile.TemporaryDirectory() as d:
            destino, casa = self.armar(d)
            datos = github.ClienteGitHub(temporal=d).analizar(destino, casa, ORG, 'sitio', DOMINIO)
        self.assertEqual([(s['ruta'], s['regla']) for s in datos['secretos']],
                         [('config/.env', 'cirdan-fake-token'), ('viejo.txt', 'cirdan-fake-token')])
        self.assertEqual([(c['correo'], c['commits']) for c in datos['correos']], [('dev@acme-demo.mx', 3)])
        texto = json.dumps(datos)
        self.assertNotIn(TOKEN, texto)
        self.assertNotIn(OTRO_TOKEN, texto)

    def test_2_las_reglas_de_omision_solas_no_lo_hallan(self):
        with tempfile.TemporaryDirectory() as d:
            destino, casa = self.armar(d)
            reporte = os.path.join(casa, 'omision.json')
            subprocess.run(['gitleaks', 'git', destino, '--log-opts=--all', '--redact', '--no-banner', '--log-level',
                            'error', '--report-format', 'json', '--report-path', reporte, '--exit-code', '0'],
                           cwd=casa, env=github._entorno(casa), check=True, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(json.loads(Path(reporte).read_text(encoding='utf-8')), [])

    def test_3_tambien_lo_halla_en_pruebas_y_en_respuestas_grabadas_de_un_cliente(self):
        """Una [allowlist] con esas rutas y la regex CIRDAN_FAKE_ apagaba los cuatro: gitleaks une las dos con 'OR'
        (PR 81)."""
        extra = ('pruebas/conf.py', 'cirdan/recolectores/respuestas_grabadas/github/sitio.json')
        with tempfile.TemporaryDirectory() as d:
            destino, casa = self.armar(d, extra)
            datos = github.ClienteGitHub(temporal=d).analizar(destino, casa, ORG, 'sitio', DOMINIO)
        self.assertEqual([(s['ruta'], s['regla']) for s in datos['secretos']],
                         [(ruta, 'cirdan-fake-token') for ruta in sorted(extra + ('config/.env', 'viejo.txt'))])
        texto = json.dumps(datos)
        self.assertNotIn(TOKEN, texto)
        self.assertNotIn(OTRO_TOKEN, texto)

    def test_4_ni_un_gitleaks_allow_ni_la_allowlist_de_omision_le_esconden_un_secreto(self):
        """Sin --ignore-gitleaks-allow el comentario salta la línea, y la allowlist de 8.21.2 salta los lock files,
        lo que lleve gitleaks.toml en la ruta y lo que termine en doc, bin o v2 aunque no sea extensión. Siguen
        saltadas las dependencias que instala un gestor de paquetes y go.sum (gitleaks_reglas.py)."""
        revisadas = ('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', '.gitleaks.toml',
                     'deploy/gitleaks.toml/claves.env', 'docs/guia.adoc', 'api/v2', 'scripts/bin',
                     'infra/prodenv/lib/ajustes.py', '.env/lib/produccion.sh')
        saltadas = ('node_modules/paquete/index.js', 'go.sum', 'venv/lib/python3.12/site-packages/ajustes.py',
                    '.venv/Lib/site-packages/ajustes.py', '.venv/lib/pypy3.10/site-packages/ajustes.py',
                    'venv/lib/python3.13t/site-packages/ajustes.py')
        with tempfile.TemporaryDirectory() as d:
            destino, casa = self.armar(d, revisadas + saltadas, permitida='app/ajustes.py')
            datos = github.ClienteGitHub(temporal=d).analizar(destino, casa, ORG, 'sitio', DOMINIO)
        self.assertEqual([(s['ruta'], s['regla']) for s in datos['secretos']],
                         [(ruta, 'cirdan-fake-token')
                          for ruta in sorted(revisadas + ('app/ajustes.py', 'config/.env', 'viejo.txt'))])
        self.assertNotIn(TOKEN, json.dumps(datos))

    def test_5_gitleaks_cirdan_toml_es_el_que_genera_gitleaks_reglas_con_el_gitleaks_de_la_imagen(self):
        if not os.path.exists(gitleaks_reglas.LICENCIA) and os.environ.get('INTEGRACION_GITHUB') != '1':
            self.skipTest('pide el gitleaks de la imagen, con su licencia')
        binario = shutil.which('gitleaks')
        with open(gitleaks_reglas.LICENCIA, encoding='utf-8') as f:
            licencia = f.read()
        omision, version = gitleaks_reglas.omision(binario), gitleaks_reglas.version(binario)
        self.assertEqual(len(tomllib.loads(omision)['rules']), 195)
        esperado = gitleaks_reglas.generar(omision, licencia, version)
        self.assertTrue(github.REGLAS.read_text(encoding='utf-8') == esperado,
                        'gitleaks_cirdan.toml no es el que sale del gitleaks de la imagen: vuelve a generarlo como '
                        'dice cirdan/recolectores/gitleaks_reglas.py')

    def test_6_un_secreto_que_entra_en_una_ruta_que_se_salta_se_halla_al_renombrarlo(self):
        """Sin --no-renames, git log solo dice 'rename from' y 'rename to', sin el contenido."""
        with tempfile.TemporaryDirectory() as d:
            destino, casa = self.armar(d, ('node_modules/paquete/.env',),
                                       renombrar=('node_modules/paquete/.env', 'config/claves.env'))
            datos = github.ClienteGitHub(temporal=d).analizar(destino, casa, ORG, 'sitio', DOMINIO)
        self.assertEqual([s['ruta'] for s in datos['secretos']], ['config/.env', 'config/claves.env', 'viejo.txt'])

    def test_7_con_marca_se_descarta_lo_que_instalo_el_entorno_con_cualquier_python_y_nada_mas(self):
        """Fuera de una carpeta venv, ninguna ruta de gitleaks_cirdan.toml salta PyPy (lib/pypy3.10/), Python sin GIL
        (lib/python3.13t/) ni conda (Lib/ o lib/python3.13t/ con la biblioteca estándar, y los paquetes de pkgs/): los
        descarta github.py por la marca. Lo demás del entorno se revisa, y una marca en la raíz, aunque sea de conda, no
        esconde la lib/, la Lib/ ni los pkgs/ del cliente. lib/python3.12/ no sirve aquí: la salta gitleaks_cirdan.toml
        en cualquier carpeta."""
        marcas = ('pyvenv.cfg', 'conda-meta/history', 'herramientas/pypy/pyvenv.cfg', 'py313t/pyvenv.cfg',
                  '.env/pyvenv.cfg', 'conda/conda-meta/history', 'miniconda/conda-meta/history')
        descartadas = ('lib/python3.13t/site-packages/paquete/prueba.py',
                       'herramientas/pypy/lib/pypy3.10/site-packages/tornado/test/prueba.py',
                       'py313t/lib/python3.13t/site-packages/paquete/prueba.py', 'conda/Lib/test/claves.py',
                       'miniconda/lib/python3.13t/test/claves.py',
                       'miniconda/pkgs/openssl-3.0.13-h2466b09_1/info/test/claves.py')
        revisadas = ('lib/claves.rb', 'pkgs/infra/creds.yml', 'pkgs/api/.env', 'Lib/ajustes.rb', '.env/lib/produccion.sh',
                     'herramientas/lib/claves.py', 'py313t/bin/activate', 'conda/etc/conda/activate.d/env_vars.sh',
                     'conda/Scripts/activate.bat', 'conda/Lib/R/etc/Renviron.site', 'conda/Library/ssl/claves.py',
                     'miniconda/lib/R/etc/Renviron.site', 'miniconda/pkgs/api/.env')
        with tempfile.TemporaryDirectory() as d:
            destino, casa = self.armar(d, descartadas + revisadas, marcas=marcas)
            datos = github.ClienteGitHub(temporal=d).analizar(destino, casa, ORG, 'sitio', DOMINIO)
        self.assertEqual([s['ruta'] for s in datos['secretos']], sorted(revisadas + ('config/.env', 'viejo.txt')))

    def test_8_cuenta_la_marca_de_una_rama_ya_fusionada_y_borrada(self):
        """Sin --full-history, git log con rutas sigue solo al primer padre de un merge que no cambió nada, así que no
        ve la marca de la rama que agregó un entorno y lo quitó, y su site-packages daría un crítico falso."""
        rama = ('venv2/pyvenv.cfg', 'venv2/lib/python3.13t/site-packages/paquete/prueba.py', 'venv2/bin/activate')
        with tempfile.TemporaryDirectory() as d:
            destino, casa = self.armar(d, rama=rama)
            datos = github.ClienteGitHub(temporal=d).analizar(destino, casa, ORG, 'sitio', DOMINIO)
        self.assertEqual([s['ruta'] for s in datos['secretos']], ['config/.env', 'venv2/bin/activate', 'viejo.txt'])


if __name__ == '__main__':
    unittest.main()
