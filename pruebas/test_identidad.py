"""Pruebas sin red de la identidad pasiva (cirdan/recolectores/identidad.py, #20, RC-56).

Los sitios se simulan con ClienteIdentidad(visitar=...), Cert Spotter y la API de GitHub con
ClienteIdentidad(descargar=...) y el A con el ResolvedorSimulado de test_shodan. Los correos personales de los fixtures
(pruebas/fixtures/identidad/) llevan el prefijo CIRDAN_FAKE_: ninguno es de una persona. Nada sale a la red.

Cada punto del Hecho cuando de RC-56 tiene su prueba:
1. Del sitio, de los commits y de los certificados salen los correos del dominio, los perfiles enlazados y los usuarios
   de GitHub con correo del dominio: Identidad.test_1, test_2 y test_3.
2. Cada uno es un activo: los mismos, más Base.test_4 (el tipo profile en el contrato y en la migración 028).
3. personal_email_exposed y email_pattern_exposed: Identidad.test_4 y test_5.
4. El correo y el perfil sembrados por #10b en reservas.olmardo.com: Identidad.test_6.
5. Nunca entra a cuentas ni navega con sesión: Identidad.test_7.

Uso, desde la raíz del repo:
  python -m unittest pruebas/test_identidad.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))  # también corre como python pruebas/test_identidad.py
from pruebas import test_subfinder  # noqa: E402
from pruebas.test_shodan import ResolvedorSimulado, a, error_http, paginas  # noqa: E402
from cirdan.recolectores import REGISTRO, cargar, contrato, github, identidad, transporte, visita  # noqa: E402
from cirdan.recolectores.contrato import Activo, FuenteNoResponde, Resultado  # noqa: E402

DOMINIO = 'acme-demo.mx'
IP = '104.21.48.10'
IP_RESERVAS = '20.150.10.20'
AHORA = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
FIXTURES = RAIZ / 'pruebas' / 'fixtures' / 'identidad'
SEMILLA = RAIZ / 'db' / 'semillas' / '026_identidad.sql'
MIGRACION = RAIZ / 'db' / 'migraciones' / '028_tipo_activo_perfil.sql'
DECLARADA = 'acme-demo.mx=acme-demo'
LLAVE_FALSA = 'CIRDAN_FAKE_llave_del_hmac_de_identidad'   # IDENTITY_HMAC_KEY de las pruebas, no es de ningún despliegue
_CON_LLAVE = mock.patch.dict(os.environ, {identidad.LLAVE: LLAVE_FALSA})


def setUpModule():
    _CON_LLAVE.start()


def tearDownModule():
    _CON_LLAVE.stop()


def fixture(nombre):
    texto = (FIXTURES / nombre).read_text(encoding='utf-8')
    return json.loads(texto) if nombre.endswith('.json') else texto


def pagina(archivo=None, estado=200, tls=None, cuerpo=None, cabeceras=None):
    """Una visita como la da visita._visitar(limpiar=False): estado, cabeceras, cuerpo, cortado y el saludo TLS."""
    visita_ = {'estado': estado, 'cabeceras': cabeceras or [['Content-Type', 'text/html; charset=utf-8']],
               'cuerpo': fixture(archivo) if archivo else (cuerpo or '<html><body>hola</body></html>'),
               'cortado': False}
    if tls is not None:
        visita_['tls'] = dict({'version': 'TLSv1.3', 'cifrado': 'TLS_AES_256_GCM_SHA384'}, **tls)
    return visita_


def github_acme(**cambios):
    """La API de GitHub de la organización acme-demo: dos repos (más un fork), los commits de sitio, vacio sin
    commits (409) y el perfil de la organización con su correo público."""
    rutas = {'/orgs/acme-demo/repos': fixture('repos_acme.json'),
             '/repos/acme-demo/sitio/commits': fixture('commits_sitio.json'),
             '/repos/acme-demo/vacio/commits': 409,
             '/users/acme-demo': fixture('usuario_acme.json')}
    rutas.update(cambios)
    return rutas


class Red:
    """Hace las veces de descargar(url, timeout) del cliente: Cert Spotter da `ct` en orden y la API de GitHub responde
    por ruta (un entero es un error HTTP y una ruta que no está es un 404). Anota cada URL."""

    def __init__(self, ct=None, github_=None):
        self.ct = [[]] if ct is None else list(ct)
        self.github = github_acme() if github_ is None else github_
        self.urls = []

    def __call__(self, url, timeout):
        self.urls.append(url)
        partes = urlsplit(url)
        if partes.hostname == 'api.certspotter.com':
            respuesta = self.ct.pop(0) if self.ct else []
        elif partes.hostname == 'api.github.com':
            respuesta = self.github.get(partes.path, 404)
        else:
            raise AssertionError('consulta inesperada: %s' % url)
        if isinstance(respuesta, int):
            raise error_http(url, respuesta)
        return json.dumps(respuesta).encode()

    def de_github(self):
        return [u for u in self.urls if urlsplit(u).hostname == 'api.github.com']


class Sitios:
    """Hace las veces de identidad._visitar(url, timeout): `paginas_` da la visita de cada URL. Una URL que no está es
    un puerto cerrado."""

    def __init__(self, paginas_):
        self.paginas, self.urls = paginas_, []

    def __call__(self, url, timeout):
        self.urls.append(url)
        return self.paginas.get(url, {'rechazada': True})


def correr(sitios, red=None, zona=None, modo='vivo', carpeta=None, dominio=DOMINIO, declaradas=DECLARADA):
    red = Red() if red is None else red
    cliente = identidad.ClienteIdentidad(
        modo=modo, carpeta=carpeta or identidad.carpeta_de(dominio), dominio=dominio, visitar=Sitios(sitios),
        descargar=red, resolver=ResolvedorSimulado({dominio: a(IP)} if zona is None else zona),
        cronometro=lambda: 0.0, dormir=lambda s: None, nueva=(modo == 'grabar'))
    with mock.patch.dict(os.environ, {github.DECLARADAS: declaradas}):
        res = identidad.recolectar(dominio, cliente, ahora=AHORA)
    return res, cliente, red


def de_tipo(res, tipo):
    return {x.valor: x for x in res.activos if x.tipo == tipo}


def hallazgos(res, codigo):
    return [h for h in res.hallazgos if h.codigo == codigo]


ACME = {'https://acme-demo.mx/': pagina('acme.html', tls={'correos': ['webmaster@acme-demo.mx',
                                                                      'CIRDAN_FAKE_cert@yahoo.com',
                                                                      'pki@autoridad-externa.com']})}


class Identidad(unittest.TestCase):

    def test_1_del_sitio_salen_los_correos_del_dominio_y_los_perfiles_enlazados(self):
        res, _, _ = correr(ACME)
        self.assertEqual(res.estado, 'succeeded')
        correos = de_tipo(res, 'email')
        for correo in ('ventas@acme-demo.mx', 'ana.lopez@acme-demo.mx', 'beto.ruiz@acme-demo.mx',
                       'carla.diaz@acme-demo.mx'):   # la última viene con entidades HTML (&#46; y &#64;)
            self.assertIn(correo, correos)
            self.assertEqual(correos[correo].atributos['identidad'], {'origenes': ['sitio'],
                                                                      'donde': ['sitio acme-demo.mx']})
        # El correo de un proveedor no es del dominio ni de un servicio gratuito: no se guarda. Un nombre de imagen
        # con @ tampoco es un correo del dominio
        textos = json.dumps(contrato.Resultado.a_dict(res)).lower()
        for fuera in ('proveedor-externo', 'logo@2x', 'autoridad-externa'):
            self.assertNotIn(fuera, textos)
        perfiles = de_tipo(res, 'profile')
        esperados = {'https://www.linkedin.com/company/acme-demo': ('linkedin', 'acme-demo'),
                     'https://x.com/acmedemomx': ('x', 'acmedemomx'),
                     'https://github.com/acme-demo': ('github', 'acme-demo'),
                     'https://www.instagram.com/acme.demo': ('instagram', 'acme.demo')}
        for url, (red, usuario) in esperados.items():
            self.assertIn(url, perfiles)
            self.assertEqual(perfiles[url].atributos['hosts'], [DOMINIO])
            self.assertEqual((perfiles[url].atributos['identidad']['red'],
                              perfiles[url].atributos['identidad']['usuario']), (red, usuario))
        # Los botones de compartir no son perfiles
        self.assertFalse(any('sharer' in u or 'intent' in u for u in perfiles))
        self.assertEqual(contrato.validar(res, set(identidad.CODIGOS)), [])
        self.assertEqual(len(contrato.filtrar_alcance(res).activos), len(res.activos))

    def test_2_del_certificado_salen_sus_correos(self):
        res, _, _ = correr(ACME)
        correo = de_tipo(res, 'email')['webmaster@acme-demo.mx']
        self.assertEqual(correo.atributos['identidad'], {'origenes': ['certificado'],
                                                         'donde': ['certificado de acme-demo.mx']})
        personal = [h for h in hallazgos(res, 'personal_email_exposed') if 'certificado' in h.evidencia['origenes']]
        self.assertEqual([h.evidencia['correo'] for h in personal], ['c***@yahoo.com'])
        self.assertEqual(personal[0].partes, [DOMINIO])

    def test_3_de_los_commits_salen_correos_y_usuarios_de_github_con_correo_del_dominio(self):
        res, _, red = correr(ACME)
        correo = de_tipo(res, 'email')['dora.paz@acme-demo.mx']
        self.assertEqual(correo.atributos['identidad'], {'origenes': ['commits'],
                                                         'donde': ['commits de acme-demo/sitio']})
        usuario = de_tipo(res, 'profile')['https://github.com/dorapaz-acme']
        self.assertEqual(usuario.atributos, {'hosts': [DOMINIO], 'identidad': {
            'red': 'github', 'usuario': 'dorapaz-acme', 'origenes': ['commits']}})
        # El login de quien solo firmó con un correo personal o de otro dominio no es un activo
        self.assertNotIn('https://github.com/becario-fake', de_tipo(res, 'profile'))
        self.assertNotIn('https://github.com/web-flow', de_tipo(res, 'profile'))
        # Sin el fork, y vacio (409) cuenta como revisado sin commits
        rutas = [urlsplit(u).path for u in red.de_github()]
        self.assertEqual(rutas, ['/orgs/acme-demo/repos', '/repos/acme-demo/sitio/commits',
                                 '/repos/acme-demo/vacio/commits', '/users/acme-demo'])
        self.assertIsNone(res.revisados)
        self.assertEqual(res.sin_cobertura, [])

    def test_4_un_correo_personal_da_hallazgo_enmascarado(self):
        res, _, _ = correr(ACME)
        lista = hallazgos(res, 'personal_email_exposed')
        self.assertEqual(sorted(h.evidencia['correo'] for h in lista),
                         ['c***@gmail.com', 'c***@gmail.com', 'c***@hotmail.com', 'c***@yahoo.com'])
        # Los dos de gmail.com (el mailto del sitio y el del perfil de la organización) se enmascaran igual, pero son
        # correos distintos: cada uno con su hallazgo, su clave y sus partes
        self.assertEqual(len({h.clave for h in lista}), 4)
        del_sitio = [h for h in lista if 'sitio' in h.evidencia['origenes']]
        self.assertEqual(len(del_sitio), 1)
        self.assertEqual(del_sitio[0].evidencia['donde'], ['sitio acme-demo.mx'])
        becario, = [h for h in lista if h.evidencia['servicio'] == 'hotmail.com']
        self.assertEqual((becario.activo, becario.severidad, becario.partes, becario.evidencia['primera_vez']),
                         (DOMINIO, 'medium', ['github:acme-demo/sitio'], '2026-10-01T09:00:00+00:00'))
        self.assertEqual(becario.caracteristicas['sensibilidad'], 'media')
        perfil_org = [h for h in lista if 'perfil' in h.evidencia['origenes']]
        # Lleva también el sitio que enlaza el perfil: si deja de enlazarlo, se cierra (b4)
        self.assertEqual([h.partes for h in perfil_org], [[DOMINIO, 'github:perfil:acme-demo']])
        # Nunca el correo completo: ni en la evidencia, ni en la clave, ni en la huella, ni en los activos
        textos = json.dumps(res.a_dict()).lower()
        self.assertNotIn('cirdan_fake_', textos)
        for h in lista:
            self.assertEqual(len(h.clave), 64)
            self.assertNotIn('@', h.titulo)
        # La misma huella en otro escaneo
        otra, _, _ = correr(ACME)
        self.assertEqual(sorted(h.huella for h in otra.hallazgos), sorted(h.huella for h in res.hallazgos))

    def test_5_el_patron_de_correos_pide_tres_personas_con_el_mismo_formato(self):
        res, _, _ = correr(ACME)
        patron = hallazgos(res, 'email_pattern_exposed')
        self.assertEqual(len(patron), 1)
        e = patron[0].evidencia
        self.assertEqual((e['formato'], e['host'], e['correos_con_el_formato'], e['ejemplo']),
                         ('nombre.apellido', DOMINIO, 4, 'nombre.apellido@acme-demo.mx'))
        self.assertEqual(sorted(patron[0].partes), [DOMINIO, 'github:acme-demo/sitio'])
        self.assertNotIn('ana.lopez', json.dumps(e))   # los correos ya son activos, no van en la evidencia
        # Con dos personas no alcanza, y los buzones genéricos no cuentan aunque sigan el formato
        cuerpo = ('<p>ana.lopez@acme-demo.mx beto.ruiz@acme-demo.mx ventas.norte@acme-demo.mx soporte.ti@acme-demo.mx '
                  'contacto@acme-demo.mx</p>')
        res, _, _ = correr({'https://acme-demo.mx/': pagina(cuerpo=cuerpo)}, red=Red(github_={}))
        self.assertEqual(hallazgos(res, 'email_pattern_exposed'), [])
        self.assertEqual(identidad.formato('j.perez@acme-demo.mx'), 'inicial.apellido')
        self.assertEqual(identidad.formato('juan_perez@acme-demo.mx'), 'nombre_apellido')
        self.assertIsNone(identidad.formato('rh.mexico@acme-demo.mx'))
        self.assertIsNone(identidad.formato('jperez@acme-demo.mx'))

    def test_6_en_el_dominio_de_prueba_salen_el_correo_y_el_perfil_sembrados(self):
        """docs/hallazgos_esperados.md filas 14 y 15: reservas.olmardo.com (solo el 80) muestra contacto@olmardo.com y
        enlaza a github.com/olmardo. Ninguno da hallazgo: es un buzón del dominio y la página de la organización."""
        dominio, reservas = 'olmardo.com', 'reservas.olmardo.com'
        zona = {dominio: a(IP), reservas: a(IP_RESERVAS)}
        sitios = {'https://olmardo.com/': pagina(cuerpo='<html><body>Grupo Olmardo</body></html>'),
                  'http://%s/' % reservas: pagina('reservas.html',
                                                  cabeceras=[['Server', 'nginx/1.24.0 (Ubuntu)'],
                                                             ['Content-Type', 'text/html; charset=utf-8']])}
        api = {'/orgs/olmardo/repos': [{'name': 'sitio-reservas', 'fork': False, 'disabled': False, 'private': False,
                                        'size': 20, 'pushed_at': '2026-10-23T10:00:00Z'}],
               '/repos/olmardo/sitio-reservas/commits': [
                   {'commit': {'author': {'email': 'ti@olmardo.com', 'date': '2026-10-23T10:00:00Z'},
                               'committer': {'email': 'ti@olmardo.com', 'date': '2026-10-23T10:00:00Z'}},
                    'author': None, 'committer': None}],
               '/users/olmardo': {'login': 'olmardo', 'type': 'Organization', 'email': None}}
        res, _, red = correr(sitios, red=Red(ct=paginas(reservas), github_=api), zona=zona, dominio=dominio,
                             declaradas='olmardo.com=olmardo')
        self.assertEqual(res.estado, 'succeeded')
        self.assertIn('contacto@olmardo.com', de_tipo(res, 'email'))
        self.assertEqual(de_tipo(res, 'email')['contacto@olmardo.com'].atributos['identidad']['donde'],
                         ['sitio reservas.olmardo.com'])
        perfil = de_tipo(res, 'profile')['https://github.com/olmardo']
        self.assertEqual(perfil.atributos['hosts'], [reservas])
        self.assertIn('ti@olmardo.com', de_tipo(res, 'email'))
        self.assertEqual(res.hallazgos, [])
        self.assertIsNone(res.revisados)
        self.assertIn('https://api.github.com/users/olmardo', red.urls)
        self.assertEqual(contrato.validar(res, set(identidad.CODIGOS)), [])

    def test_7_nunca_entra_a_cuentas_ni_navega_con_sesion(self):
        """Las peticiones reales que arman _visitar y _descargar (con el transporte cambiado): GET sin Cookie, sin
        Authorization y sin token en la URL, y el opener de transporte.py no guarda cookies."""
        pedidas = []

        def visitar(req, plazo, tope, cronometro):
            pedidas.append(req)
            req.saludo.update(version='TLSv1.3', cifrado='TLS_AES_256_GCM_SHA384', correos=[])
            return 200, [['Content-Type', 'text/html']], fixture('acme.html').encode('utf-8'), False

        api = github_acme()

        def descargar(req, plazo, tope, cronometro):
            pedidas.append(req)
            partes = urlsplit(req.full_url)
            if partes.hostname == 'api.certspotter.com':
                return b'[]'
            respuesta = api.get(partes.path, 404)
            if isinstance(respuesta, int):
                raise error_http(req.full_url, respuesta)
            return json.dumps(respuesta).encode()
        cliente = identidad.ClienteIdentidad(modo='vivo', carpeta=identidad.carpeta_de(DOMINIO), dominio=DOMINIO,
                                             resolver=ResolvedorSimulado({DOMINIO: a(IP)}), cronometro=lambda: 0.0,
                                             dormir=lambda s: None)
        with mock.patch.object(transporte, 'visitar', visitar), mock.patch.object(transporte, 'descargar', descargar), \
                mock.patch.dict(os.environ, {github.DECLARADAS: DECLARADA}):
            res = identidad.recolectar(DOMINIO, cliente, ahora=AHORA)
        self.assertEqual(res.estado, 'succeeded')
        self.assertIn('https://acme-demo.mx/', [r.full_url for r in pedidas])
        self.assertIn('https://api.github.com/users/acme-demo', [r.full_url for r in pedidas])
        for req in pedidas:
            cabeceras = {k.lower() for k, _ in req.header_items()}
            self.assertEqual(req.get_method(), 'GET', req.full_url)
            self.assertFalse(cabeceras & {'cookie', 'authorization', 'proxy-authorization'}, req.full_url)
            self.assertNotRegex(urlsplit(req.full_url).query.lower(), r'token|secret|key=|password', req.full_url)
            self.assertIsNone(req.data, req.full_url)
        fuente = Path(transporte.__file__).read_text(encoding='utf-8')
        self.assertNotIn('HTTPCookieProcessor', fuente)
        self.assertNotIn('CookieJar', fuente)

    def test_8_graba_solo_lo_reducido_y_reproduce_lo_mismo(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            res, _, _ = correr(ACME, modo='grabar', carpeta=carpeta)
            self.assertNotIn(identidad.NO_SE_GRABO, res.avisos)
            archivos = sorted(carpeta.glob('*.json'))
            self.assertTrue(archivos)
            texto = '\n'.join(p.read_text(encoding='utf-8') for p in archivos).lower()
            for nunca in ('cirdan_fake_', '<html', '"cuerpo"', '"cabeceras"', 'proveedor-externo', 'otra-empresa',
                          'noreply', 'autoridad-externa', '"name"', 'dora paz'):
                self.assertNotIn(nunca, texto)
            otra, cliente, _ = correr({}, red=Red(ct=[], github_={}), modo='reproducir', carpeta=carpeta)
            self.assertEqual(cliente.consultas, 0)
            self.assertEqual((otra.activos, otra.hallazgos, otra.revisados), (res.activos, res.hallazgos, None))

    def test_9_un_reto_deja_el_sitio_sin_revisar_y_no_cierra_lo_suyo(self):
        www = 'www.acme-demo.mx'
        zona = {DOMINIO: a(IP), www: a(IP)}
        sitios = dict(ACME)
        sitios['https://%s/' % www] = pagina('acme.html', estado=429)
        res, _, _ = correr(sitios, red=Red(ct=paginas(www)), zona=zona)
        self.assertEqual(sorted(res.revisados), sorted([DOMINIO, 'github:acme-demo', 'github:acme-demo/sitio',
                                                'github:acme-demo/vacio', 'github:perfil:acme-demo']))
        # Cert Spotter dio todas sus páginas: se sabe qué sitios hay y www va en sin_revisar (b4)
        self.assertEqual(res.sin_revisar, [www])
        self.assertTrue(any('www.acme-demo.mx respondió con un reto' in x for x in res.avisos))
        self.assertTrue(any(x.startswith(identidad.PARCIAL) for x in res.avisos))
        for perfil in de_tipo(res, 'profile').values():
            self.assertNotIn(www, perfil.atributos['hosts'])
        self.assertEqual(contrato.validar(res, set(identidad.CODIGOS)), [])

    def test_10_sin_cuota_de_github_no_cierra_lo_de_github_ni_graba(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            res, _, red = correr(ACME, red=Red(github_=github_acme(**{'/orgs/acme-demo/repos': 403})), modo='grabar',
                                 carpeta=carpeta)
            self.assertEqual(res.avisos[0], identidad.NO_SE_GRABO)
            self.assertIn(identidad.SIN_CUOTA, res.avisos)
            self.assertEqual(res.revisados, [DOMINIO])
            # Con la cuota acabada no se pide nada más a GitHub, tampoco el perfil enlazado
            self.assertEqual([urlsplit(u).path for u in red.de_github()], ['/orgs/acme-demo/repos'])
            self.assertFalse(list(carpeta.glob('*.json')))
            self.assertEqual(contrato.validar(res, set(identidad.CODIGOS)), [])

    def test_11_sin_organizacion_declarada_no_lee_commits(self):
        res, _, red = correr(ACME, declaradas='otro.mx=otro')
        self.assertIn(identidad.SIN_DECLARACION, res.avisos)
        self.assertEqual([urlsplit(u).path for u in red.de_github()], ['/users/acme-demo'])
        self.assertNotIn('dora.paz@acme-demo.mx', de_tipo(res, 'email'))
        self.assertIsNone(res.revisados)

    def test_12_una_pagina_llena_de_commits_no_cierra_lo_de_ese_repo(self):
        llena = fixture('commits_sitio.json') * 34   # 102 commits: la página trae 100 o más
        res, _, _ = correr(ACME, red=Red(github_=github_acme(**{'/repos/acme-demo/sitio/commits': llena})))
        self.assertNotIn('github:acme-demo/sitio', res.revisados)
        self.assertIn('github:acme-demo/vacio', res.revisados)
        self.assertTrue(any('una sola página de commits' in x for x in res.avisos))

    def test_13_reproducir_sin_grabacion_queda_sin_cobertura(self):
        with tempfile.TemporaryDirectory() as d:
            res, _, _ = correr({}, modo='reproducir', carpeta=Path(d) / DOMINIO)
        self.assertEqual((res.estado, res.sin_cobertura, res.avisos),
                         ('succeeded', list(identidad.CODIGOS), [identidad.SIN_GRABACION_DOMINIO]))

    def test_14_si_nada_responde_la_fuente_no_responde(self):
        red = Red(ct=[500] * 10, github_={})
        with self.assertRaises(FuenteNoResponde):
            correr(ACME, red=red, zona={DOMINIO: 'falla'}, declaradas='otro.mx=otro')
        # Con GitHub respondiendo, lo de GitHub sí cuenta
        res, _, _ = correr(ACME, red=Red(ct=[500] * 10), zona={DOMINIO: 'falla'})
        self.assertIn('github:acme-demo/sitio', res.revisados)
        self.assertNotIn(DOMINIO, res.revisados)

    def test_15_una_grabacion_alterada_no_se_lee(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            correr(ACME, modo='grabar', carpeta=carpeta)
            sitio = next(p for p in carpeta.glob('sitio_*.json'))
            sobre = json.loads(sitio.read_text(encoding='utf-8'))
            sobre['datos']['identidad']['personales'] = [{'huella': '0' * 64, 'correo': 'alguien@gmail.com',
                                                         'servicio': 'gmail.com'}]
            sitio.write_text(json.dumps(sobre), encoding='utf-8')
            res, _, _ = correr({}, red=Red(ct=[], github_={}), modo='reproducir', carpeta=carpeta)
        self.assertNotIn(DOMINIO, res.revisados)
        self.assertTrue(any('no se puede leer' in x for x in res.avisos))
        self.assertNotIn('alguien@gmail.com', json.dumps(res.a_dict()))


class Extraccion(unittest.TestCase):

    def test_1_perfiles_canonicos(self):
        casos = {
            'https://github.com/Olmardo': 'https://github.com/olmardo',
            'https://github.com/orgs/olmardo/people': 'https://github.com/olmardo',
            'http://www.github.com/olmardo/': 'https://github.com/olmardo',
            'https://mx.linkedin.com/company/Grupo-Olmardo': 'https://www.linkedin.com/company/grupo-olmardo',
            'https://www.linkedin.com/in/ana-lopez-123/': 'https://www.linkedin.com/in/ana-lopez-123',
            'https://twitter.com/GrupoOlmardo': 'https://x.com/grupoolmardo',
            'https://www.youtube.com/@GrupoOlmardo': 'https://www.youtube.com/@grupoolmardo',
            'https://www.youtube.com/channel/UCabcDEF123': 'https://www.youtube.com/channel/UCabcDEF123',
            'https://www.tiktok.com/@grupo.olmardo?lang=es': 'https://www.tiktok.com/@grupo.olmardo',
            'https://gitlab.com/olmardo': 'https://gitlab.com/olmardo',
            '//www.facebook.com/GrupoOlmardo': 'https://www.facebook.com/grupoolmardo',
        }
        for href, url in casos.items():
            self.assertEqual((identidad.perfil(href) or {}).get('url'), url, href)
        for href in ('https://github.com/login', 'https://github.com/', 'https://www.facebook.com/sharer/sharer.php',
                     'https://twitter.com/intent/tweet', 'https://www.linkedin.com/shareArticle?url=x',
                     'https://www.instagram.com/p/abc123/', 'https://otro.com/olmardo', 'mailto:ti@olmardo.com',
                     'javascript:alert(1)', 'https://user:clave@github.com/olmardo', 'https://github.com:8443/olmardo',
                     'https://github.com.evil.com/olmardo', 'https://evilgithub.com/olmardo',
                     'https://github.com\\@evil.com/olmardo', 'https://www.tiktok.com/olmardo', '/contacto',
                     # b3: un repo (muchas veces de un tercero) y las páginas del servicio no son perfiles
                     'https://github.com/olmardo/sitio-reservas', 'https://github.com/axios/axios',
                     'https://github.com/users/foo/projects/1', 'https://github.com/orgs/', 'https://github.com/dashboard',
                     # b7: /people/<nombre>/<id> de Facebook no es un usuario 'people'
                     'https://www.facebook.com/people/Grupo-Olmardo/100064'):
            self.assertIsNone(identidad.perfil(href), href)
        for href in casos:   # la URL canónica da el mismo perfil: así se valida al reproducir
            p = identidad.perfil(href)
            self.assertEqual(identidad.perfil(p['url']), p, href)
            self.assertIsNotNone(contrato._host_de_url(p['url']), href)

    def test_2_correos_del_texto(self):
        texto = ('<a href="mailto:Ti%40olmardo.com">x</a> contacto&#64;olmardo.com otro@reservas.olmardo.com '
                 'CIRDAN_FAKE_ana@Gmail.com cobros@proveedor.mx olmardo.com@gmail.co '
                 + 'a' * 70 + '@olmardo.com x@olmardo.comercial')
        propios, personales, lleno = identidad._correos_del_texto(texto, 'olmardo.com')
        self.assertEqual(propios, ['contacto@olmardo.com', 'otro@reservas.olmardo.com', 'ti@olmardo.com'])
        self.assertEqual([(p['correo'], p['servicio']) for p in personales], [('c***@gmail.com', 'gmail.com')])
        self.assertFalse(lleno)
        llave = LLAVE_FALSA.encode()
        self.assertEqual(personales[0]['huella'], identidad._clave('cirdan_fake_ana@gmail.com', 'olmardo.com', llave))
        # La misma persona en otro dominio da otra clave: no se liga entre empresas
        self.assertNotEqual(identidad._clave('cirdan_fake_ana@gmail.com', 'otro.mx', llave), personales[0]['huella'])

    def test_3_una_pagina_enorme_o_rara_no_tumba_la_lectura(self):
        raro = '<a href="https://github.com/olmardo">' + '<' * 50000 + '<a href=' + '"' * 1000
        perfiles, _ = identidad._perfiles_del_html(raro)
        self.assertEqual([p['url'] for p in perfiles], ['https://github.com/olmardo'])
        enorme = 'x' * (identidad.MAX_TEXTO + 10) + ' ti@olmardo.com'
        # Lo que pasó de MAX_TEXTO no se leyó: la página cuenta como cortada (b8)
        self.assertEqual(identidad._correos_del_texto(enorme, 'olmardo.com'), ([], [], True))

    def test_4_correos_del_certificado(self):
        cert = {'subject': ((('commonName', 'olmardo.com'),), (('emailAddress', 'ti@olmardo.com'),)),
                'subjectAltName': (('DNS', 'olmardo.com'), ('email', 'pki@olmardo.com'), ('email', 'ti@olmardo.com'))}
        self.assertEqual(transporte.correos_del_certificado(cert), ['ti@olmardo.com', 'pki@olmardo.com'])
        self.assertEqual(transporte.correos_del_certificado({}), [])
        self.assertEqual(transporte.correos_del_certificado({'subject': 7}), [])

    def test_5_la_visita_trae_los_correos_del_saludo_sin_limpiar(self):
        def visitar(req, plazo, tope, cronometro):
            self.assertEqual(req.saludo, {'correos': None})
            req.saludo.update(version='TLSv1.3', cifrado='TLS_AES_256_GCM_SHA384', correos=['ti@olmardo.com'])
            return 200, [['Content-Type', 'text/html']], b'<html></html>', False
        with mock.patch.object(transporte, 'visitar', visitar):
            crudo = identidad._visitar('https://olmardo.com/', 5)
            self.assertEqual(crudo['tls']['correos'], ['ti@olmardo.com'])

        # La visita de web no cambia: sin saludo extra y limpia (c4)
        def visitar_web(req, plazo, tope, cronometro):
            self.assertEqual(req.saludo, {})
            req.saludo.update(version='TLSv1.3', cifrado='TLS_AES_256_GCM_SHA384')
            return 200, [['Content-Type', 'text/html']], b'<html></html>', False
        with mock.patch.object(transporte, 'visitar', visitar_web):
            self.assertEqual(visita._visitar('https://olmardo.com/', 5)['tls'],
                             {'version': 'TLSv1.3', 'cifrado': 'TLS_AES_256_GCM_SHA384'})


class Revision(unittest.TestCase):
    """Los arreglos de la revisión de riesgo de RC-56 (ronda 1), cada uno con el id de su hallazgo."""

    def test_1_sin_llave_no_guarda_correos_personales_ni_graba(self):
        """a1: sin IDENTITY_HMAC_KEY (o corta) no hay huella que no se pueda revertir: no se guarda ningún correo
        personal, la regla queda sin cobertura y la corrida no se graba."""
        for valor in ('', 'CIRDAN_FAKE_corta'):
            with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {identidad.LLAVE: valor}):
                carpeta = Path(d) / DOMINIO
                res, _, _ = correr(ACME, modo='grabar', carpeta=carpeta)
                self.assertEqual(hallazgos(res, 'personal_email_exposed'), [])
                self.assertIn(identidad.SIN_LLAVE, res.avisos)
                self.assertIn('personal_email_exposed', res.sin_cobertura)
                self.assertEqual(res.sin_llave, ['personal_email_exposed'])   # R5
                self.assertEqual(res.avisos[0], identidad.NO_SE_GRABO)
                self.assertFalse(list(carpeta.glob('*.json')))
                self.assertTrue(hallazgos(res, 'email_pattern_exposed'))   # lo demás sí sale
                self.assertEqual(contrato.validar(res, set(identidad.CODIGOS)), [])

    def test_2_la_huella_es_un_hmac_del_buzon_normalizado(self):
        """a1 y a3: con otra llave cambia, sin la llave no es el sha256 del correo, y las formas del mismo buzón de
        Gmail (+etiqueta, puntos, googlemail.com) dan la misma."""
        import hashlib
        llave = LLAVE_FALSA.encode()
        huella = identidad._clave('juanperez@gmail.com', DOMINIO, llave)
        self.assertNotEqual(huella, identidad._clave('juanperez@gmail.com', DOMINIO, b'x' * 32))
        self.assertNotEqual(huella, hashlib.sha256(('correo|%s|juanperez@gmail.com' % DOMINIO).encode()).hexdigest())
        for igual in ('juan.perez@gmail.com', 'juan.perez+trabajo@gmail.com', 'juanperez@googlemail.com'):
            self.assertEqual(identidad._clave(igual, DOMINIO, llave), huella, igual)
        # En otro servicio los puntos sí cuentan
        self.assertNotEqual(identidad._clave('juan.perez@outlook.com', DOMINIO, llave),
                            identidad._clave('juanperez@outlook.com', DOMINIO, llave))
        cuerpo = '<p>CIRDAN_FAKE_ju.an@gmail.com y cirdan_fake_juan+x@googlemail.com</p>'
        res, _, _ = correr({'https://acme-demo.mx/': pagina(cuerpo=cuerpo)}, red=Red(github_={}))
        self.assertEqual(len(hallazgos(res, 'personal_email_exposed')), 1)

    def test_3_la_mascara_de_un_usuario_corto_no_lleva_su_letra(self):
        """a2: 'a***@outlook.com' de a@outlook.com era el correo entero."""
        for usuario, mascara in (('a', '***@outlook.com'), ('jp', '***@outlook.com'), ('ana', '***@outlook.com'),
                                 ('anab', 'a***@outlook.com')):
            tipo, p = identidad._clasificar('%s@outlook.com' % usuario, DOMINIO)
            self.assertEqual((tipo, p['correo']), ('personal', mascara), usuario)
            self.assertTrue(identidad._personal_valido(p), usuario)

    def test_4_una_redireccion_no_tumba_la_corrida_ni_graba_su_consulta(self):
        """b1: www que redirige a la raíz ya visitada no tumba la corrida. a4: el destino se graba sin su consulta.
        b2: los correos del certificado de www salen, con www como parte, y www queda revisado."""
        www = 'www.acme-demo.mx'
        sitios = dict(ACME)
        sitios['https://%s/' % www] = {
            'redirige': 'https://acme-demo.mx/?login_hint=CIRDAN_FAKE_hint@gmail.com#x', 'codigo': 301,
            'tls': {'version': 'TLSv1.3', 'cifrado': 'TLS_AES_256_GCM_SHA384',
                    'correos': ['CIRDAN_FAKE_viejo@gmail.com', 'pki@acme-demo.mx']}}
        zona = {DOMINIO: a(IP), www: a(IP)}
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            res, _, _ = correr(sitios, red=Red(ct=paginas(www)), zona=zona, modo='grabar', carpeta=carpeta)
            self.assertEqual(res.estado, 'succeeded')
            self.assertIsNone(res.revisados)   # www quedó revisado: redirigió y se leyó su certificado
            self.assertEqual(de_tipo(res, 'email')['pki@acme-demo.mx'].atributos['identidad']['donde'],
                             ['certificado de %s' % www])
            viejo = [h for h in hallazgos(res, 'personal_email_exposed') if h.partes == [www]]
            self.assertEqual([h.evidencia['donde'] for h in viejo], [['certificado de %s' % www]])
            texto = '\n'.join(p.read_text(encoding='utf-8') for p in carpeta.glob('*.json')).lower()
            for nunca in ('login_hint=c', 'cirdan_fake_', '#x'):
                self.assertNotIn(nunca, texto)
            otra, cliente, _ = correr({}, red=Red(ct=[], github_={}), zona=zona, modo='reproducir', carpeta=carpeta)
            self.assertEqual(cliente.consultas, 0)
            self.assertEqual((otra.activos, otra.hallazgos, otra.revisados), (res.activos, res.hallazgos, None))

    def test_5_el_destino_de_una_redireccion_se_lee_sin_datos(self):
        """a4: sin usuario, fragmento, ';parámetros' ni correos en la ruta. R2: la consulta se queda sin correos ni
        valores sensibles. R4: una ruta sin correo va tal cual ('%2541' no pasa a '%41') y un correo codificado dos
        veces ('%2540') también se quita. Dos veces da lo mismo."""
        casos = {'https://u:p@acme-demo.mx/a;jsessionid=1?ref=x@gmail.com#f': 'https://acme-demo.mx/a?ref=_',
                 'https://acme-demo.mx/u/juan.perez@gmail.com/': 'https://acme-demo.mx/u/_/',
                 'https://acme-demo.mx': 'https://acme-demo.mx',
                 'https://acme-demo.mx/a%2541': 'https://acme-demo.mx/a%2541',
                 'https://acme-demo.mx/u/juan%2540gmail.com': 'https://acme-demo.mx/u/_',
                 'https://acme-demo.mx/?lang=es': 'https://acme-demo.mx/?lang=es',
                 'https://acme-demo.mx/sso?login_hint=ana%40gmail.com&token=abc&Session_Id=9&next=%2Fa&code':
                     'https://acme-demo.mx/sso?login_hint=&token=&Session_Id=&next=%2Fa&code',
                 'https://acme-demo.mx/?ref=ana%2540gmail.com&x=1': 'https://acme-demo.mx/?ref=_&x=1'}
        for destino, esperado in casos.items():
            self.assertEqual(identidad._destino_sin_datos(destino), esperado, destino)
            self.assertEqual(identidad._destino_sin_datos(esperado), esperado, destino)
        self.assertIsNone(identidad._destino_sin_datos('https://[::1/'))
        cliente = identidad.ClienteIdentidad(dominio=DOMINIO)
        with self.assertRaises(ValueError):
            cliente.limpiar({'redirige': 7})
        with self.assertRaises(ValueError):   # una grabación con un correo personal sin enmascarar
            cliente.limpiar({'redirige': None, 'codigo': 301, 'cert': {
                'correos_cert': [], 'personales_cert': [{'huella': '0' * 64, 'correo': 'ana@gmail.com',
                                                         'servicio': 'gmail.com'}]}})

    def test_6_con_las_partes_sabidas_van_en_sin_revisar_las_que_no_se_revisaron(self):
        """b4: con Cert Spotter completo y la lista de repos entera, sin_revisar lleva los repos que MAX_REPOS_API dejó
        fuera y los perfiles que dejó MAX_PERFILES_API. Si Cert Spotter no respondió, None."""
        repos = [{'name': 'r%d' % i, 'fork': False, 'disabled': False, 'private': False, 'size': 1,
                  'pushed_at': '2026-10-%02dT10:00:00Z' % (i + 1)} for i in range(identidad.MAX_REPOS_API + 2)]
        enlaces = ''.join('<a href="https://github.com/acme-p%d">p</a>' % i
                          for i in range(identidad.MAX_PERFILES_API + 1))
        sitios = {'https://acme-demo.mx/': pagina(cuerpo='<html>%s</html>' % enlaces)}
        res, _, _ = correr(sitios, red=Red(github_={'/orgs/acme-demo/repos': repos}))
        self.assertEqual(res.sin_revisar, ['github:acme-demo/r0', 'github:acme-demo/r1',
                                           'github:perfil:acme-p%d' % identidad.MAX_PERFILES_API])
        self.assertIn('github:acme-demo/r6', res.revisados)
        self.assertEqual(contrato.validar(res, set(identidad.CODIGOS)), [])
        res, _, _ = correr(sitios, red=Red(ct=[500] * 10, github_={'/orgs/acme-demo/repos': repos}))
        self.assertIsNone(res.sin_revisar)
        # Sin la lista de repos tampoco se sabe qué partes hay
        res, _, _ = correr(sitios, red=Red(github_={'/orgs/acme-demo/repos': 500}))
        self.assertIsNone(res.sin_revisar)

    def test_7_una_pagina_con_mas_correos_de_los_que_caben_queda_cortada(self):
        """b8: lo que pasó del tope no se leyó, así que el sitio no queda revisado y no cierra lo suyo."""
        cuerpo = ' '.join('p%d@acme-demo.mx' % i for i in range(identidad.MAX_POR_PAGINA + 1))
        res, _, _ = correr({'https://acme-demo.mx/': pagina(cuerpo=cuerpo)}, red=Red(github_={}))
        self.assertNotIn(DOMINIO, res.revisados)
        self.assertTrue(any('tope de bytes, de correos o de enlaces' in x for x in res.avisos), res.avisos)
        enlaces = ''.join('<a href="https://x.com/p%d">x</a>' % i for i in range(identidad.MAX_POR_PAGINA + 1))
        self.assertTrue(identidad._perfiles_del_html(enlaces)[1])

    def test_8_un_correo_con_otra_etiqueta_detras_no_es_del_dominio(self):
        """b5: juan.perez@acme-demo.mx.xn--p1ai no es un correo de acme-demo.mx."""
        propios, _, _ = identidad._correos_del_texto('juan.perez@acme-demo.mx.xn--p1ai luis@acme-demo.mx.x1 '
                                                     'ana@acme-demo.mx. beto@ACME-demo.mx', DOMINIO)
        self.assertEqual(propios, ['ana@acme-demo.mx', 'beto@acme-demo.mx'])

    def test_9_linkedin_con_acentos_o_por_ciento_da_lo_mismo_al_reproducir(self):
        """b6"""
        for href, url in (('https://www.linkedin.com/in/jos%C3%A9-p', 'https://www.linkedin.com/in/jos%C3%A9-p'),
                          ('https://www.linkedin.com/in/a%2541', 'https://www.linkedin.com/in/a%2541')):
            p = identidad.perfil(href)
            self.assertEqual(p['url'], url, href)
            self.assertTrue(identidad._perfil_valido(p), href)

    def test_10_repos_con_nombres_parecidos_no_comparten_archivo(self):
        """c2: 'a_b' y 'a__b' (o 'web' y 'web_') daban el mismo archivo de la grabación."""
        repos = [{'name': n, 'fork': False, 'disabled': False, 'private': False, 'size': 1,
                  'pushed_at': '2026-10-01T10:00:00Z'} for n in ('a_b', 'a__b', 'web', 'web_')]
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            correr(ACME, red=Red(github_={'/orgs/acme-demo/repos': repos}), modo='grabar', carpeta=carpeta)
            self.assertEqual(len(list(carpeta.glob('gh_commits_*.json'))), 4)

    def test_11_el_peor_caso_no_pasa_de_max_consultas(self):
        """c5: Cert Spotter con un reintento por página, MAX_SITIOS nombres con el A al último intento, cada sitio con
        todas sus redirecciones, GitHub con más repos y perfiles de los topes y cada petición con todos sus intentos."""
        nombres = ['s%d.acme-demo.mx' % i for i in range(identidad.MAX_SITIOS - 1)]
        pagina_ct, vacia = paginas(*nombres)
        zona = {n: ['falla'] * (identidad.shodan.INTENTOS - 1) + [a(IP)] for n in [DOMINIO] + nombres}
        enlaces = ''.join('<a href="https://github.com/acme-p%d">p</a>' % i
                          for i in range(identidad.MAX_PERFILES_API + 2))
        sitios = {}
        for n in [DOMINIO] + nombres:
            for salto in range(identidad.MAX_REDIRECCIONES + 1):
                sitios['https://%s/%s' % (n, 'p%d' % salto if salto else '')] = {
                    'redirige': 'https://%s/p%d' % (n, salto + 1), 'codigo': 302}
        sitios['https://%s/' % DOMINIO] = pagina(cuerpo=enlaces)
        repos = [{'name': 'r%d' % i, 'fork': False, 'disabled': False, 'private': False, 'size': 1,
                  'pushed_at': '2026-10-%02dT10:00:00Z' % (i + 1)} for i in range(identidad.MAX_REPOS_API + 2)]
        api = {'/orgs/acme-demo/repos': repos}
        api.update({'/repos/acme-demo/r%d/commits' % i: 500 for i in range(len(repos))})
        api.update({'/users/acme-p%d' % i: 500 for i in range(identidad.MAX_PERFILES_API + 2)})
        res, cliente, _ = correr(sitios, red=Red(ct=[500, pagina_ct, 500, vacia], github_=api), zona=zona)
        self.assertGreater(res.consultas, identidad.MAX_CONSULTAS // 2)
        self.assertLessEqual(res.consultas, identidad.MAX_CONSULTAS)


class Ronda2(unittest.TestCase):
    """Las regresiones que encontró la ronda 2 de la revisión de RC-56, cada una con su id (R1 a R7)."""

    def test_1_sin_llave_una_corrida_parcial_no_cierra_correos_personales(self):
        """R1: con más de MAX_REPOS_API repos la corrida es parcial. Con revisados, el orquestador cierra por partes sin
        mirar sin_cobertura: sin llave, revisados va vacío y sin_revisar en None, así no se cierra ningún correo
        personal abierto. Con la llave, la misma corrida sí da sus partes."""
        repos = [{'name': 'r%d' % i, 'fork': False, 'disabled': False, 'private': False, 'size': 1,
                  'pushed_at': '2026-10-%02dT10:00:00Z' % (i + 1)} for i in range(identidad.MAX_REPOS_API + 2)]
        red = lambda: Red(github_={'/orgs/acme-demo/repos': repos})   # noqa: E731
        con_llave, _, _ = correr(ACME, red=red())
        self.assertIn(DOMINIO, con_llave.revisados)
        self.assertIsNotNone(con_llave.sin_revisar)
        with mock.patch.dict(os.environ, {identidad.LLAVE: ''}):
            res, _, _ = correr(ACME, red=red())
        self.assertEqual(res.revisados, [])
        self.assertIsNone(res.sin_revisar)
        self.assertIn('personal_email_exposed', res.sin_cobertura)
        self.assertEqual(res.sin_llave, ['personal_email_exposed'])   # R5
        self.assertEqual(hallazgos(res, 'personal_email_exposed'), [])
        self.assertTrue(hallazgos(res, 'email_pattern_exposed'))
        self.assertEqual(contrato.validar(res, set(identidad.CODIGOS)), [])

    def test_2_una_portada_que_redirige_a_su_consulta_se_lee(self):
        """R2: / que manda a /?lang=es volvía a / hasta MAX_REDIRECCIONES y la raíz quedaba sin revisar."""
        sitios = {'https://acme-demo.mx/': {'redirige': 'https://acme-demo.mx/?lang=es', 'codigo': 302},
                  'https://acme-demo.mx/?lang=es': pagina('acme.html')}
        res, _, _ = correr(sitios, red=Red(github_={}))
        self.assertIsNone(res.revisados)
        self.assertTrue(de_tipo(res, 'email'))
        self.assertFalse(any('redirecciones' in x for x in res.avisos), res.avisos)

    def test_3_el_destino_que_sale_del_dominio_trae_su_certificado(self):
        """R3: en acme-demo.mx -> tienda -> otro dominio, tienda quedaba visto sin los correos de su certificado."""
        tienda = 'tienda.acme-demo.mx'
        sitios = {'https://acme-demo.mx/': {'redirige': 'https://%s/' % tienda, 'codigo': 301},
                  'https://%s/' % tienda: {'redirige': 'https://otra-empresa.com/', 'codigo': 302, 'tls': {
                      'version': 'TLSv1.3', 'cifrado': 'TLS_AES_256_GCM_SHA384',
                      'correos': ['CIRDAN_FAKE_tienda@gmail.com', 'pki@acme-demo.mx']}}}
        zona = {DOMINIO: a(IP), tienda: a(IP)}
        res, _, _ = correr(sitios, red=Red(ct=paginas(tienda), github_={}), zona=zona)
        self.assertEqual(de_tipo(res, 'email')['pki@acme-demo.mx'].atributos['identidad']['donde'],
                         ['certificado de %s' % tienda])
        personal = hallazgos(res, 'personal_email_exposed')
        self.assertEqual([(h.partes, h.evidencia['donde']) for h in personal],
                         [([tienda], ['certificado de %s' % tienda])])

    def test_4_la_grabacion_de_un_destino_con_por_ciento_reproduce_lo_mismo(self):
        """R4: '/a%2541' se grababa como '/a%41' y al reproducir salía '/aA'. Y '/u/juan%2540gmail.com' grababa el
        correo codificado."""
        cliente = identidad.ClienteIdentidad(dominio=DOMINIO)
        for destino, esperado in (('https://acme-demo.mx/a%2541', 'https://acme-demo.mx/a%2541'),
                                  ('https://acme-demo.mx/u/CIRDAN_FAKE_j%2540gmail.com', 'https://acme-demo.mx/u/_')):
            limpia = cliente.limpiar({'redirige': destino, 'codigo': 301})
            self.assertEqual(limpia['redirige'], esperado)
            self.assertEqual(cliente.limpiar(json.loads(json.dumps(limpia)))['redirige'], esperado)

    def test_5_un_correo_que_cierra_la_frase_sin_espacio_sale(self):
        """R6: 'ti@acme-demo.mx.Gracias' daba el host acme-demo.mx.gracias y el correo se perdía. Solo se corta una
        palabra con mayúscula inicial: '.RU' o '.x1' detrás siguen sin ser del dominio."""
        texto = ('ti.lopez@acme-demo.mx.Gracias, CIRDAN_FAKE_juan@gmail.com.Saludos, luis@acme-demo.mx.RU '
                 'ana@acme-demo.mx.x1 beto@acme-demo.mx.Mx.Gracias')
        propios, personales, _ = identidad._correos_del_texto(texto, DOMINIO)
        self.assertEqual(propios, ['ti.lopez@acme-demo.mx'])
        self.assertEqual([p['correo'] for p in personales], ['c***@gmail.com'])

    def test_6_la_documentacion_dice_lo_que_hace(self):
        """R7: sin_revisar también lleva los perfiles, al reproducir sin llave sale lo grabado, la consulta de una
        redirección se queda sin datos y cambiar la llave cierra los abiertos (no los reabre)."""
        doc = (RAIZ / 'docs' / 'contrato_plugin.md').read_text(encoding='utf-8')
        parrafo = next(p for p in doc.split('\n') if p.startswith('El recolector de identidad pasiva'))
        for frase in ('`github:perfil:<login>`', 'Al reproducir no hace falta la llave', '`sin_llave`',
                      '`revisados` vacío', 'con su consulta sin correos'):
            self.assertIn(frase, parrafo)
        self.assertNotIn('sin usuario, consulta,', parrafo)
        env = (RAIZ / '.env.example').read_text(encoding='utf-8')
        self.assertNotIn('se reabren', env)
        self.assertIn('abiertos se\n# cierran', env)



class Ronda4(unittest.TestCase):
    """El alto de la pasada amplia de la ronda 3 de RC-56 (alcance1)."""

    def test_1_lo_del_destino_de_una_redireccion_no_se_cierra_si_su_origen_queda_sin_revisar(self):
        """alcance1: acme-demo.mx manda a www, que no es nombre de Cert Spotter (sale de un comodín), y la página de
        www trae un correo personal. Si en la corrida siguiente la raíz da 503, www no se visita y no está en
        sin_revisar: el hallazgo tiene que llevar también a la raíz como parte, o el orquestador lo cierra con
        NOT(partes ?| sin_revisar) aunque el correo siga en www. Si www sí es nombre de Cert Spotter, tiene su propia
        parte en sin_revisar y no depende de la raíz."""
        www = 'www.acme-demo.mx'
        cuerpo = '<html><body>Escribe a CIRDAN_FAKE_ana@gmail.com o a ti@acme-demo.mx</body></html>'
        redirige = {'https://acme-demo.mx/': {'redirige': 'https://%s/' % www, 'codigo': 301},
                    'https://%s/' % www: pagina(cuerpo=cuerpo)}
        primera, _, _ = correr(redirige, red=Red(github_={}))
        personal = hallazgos(primera, 'personal_email_exposed')
        self.assertEqual([h.partes for h in personal], [sorted([DOMINIO, www])])

        caida = {'https://acme-demo.mx/': pagina(estado=503)}
        segunda, _, _ = correr(caida, red=Red(github_={}))
        self.assertEqual(segunda.sin_revisar, [DOMINIO])
        self.assertEqual(hallazgos(segunda, 'personal_email_exposed'), [])
        # el orquestador cierra lo que trae partes y ninguna está en sin_revisar
        self.assertTrue(set(personal[0].partes) & set(segunda.sin_revisar))

        zona = {DOMINIO: a(IP), www: a(IP)}
        de_ct, _, _ = correr(redirige, red=Red(ct=paginas(www), github_={}), zona=zona)
        self.assertEqual([h.partes for h in hallazgos(de_ct, 'personal_email_exposed')], [[www]])

    def test_2_en_una_cadena_lo_del_destino_depende_tambien_del_salto_intermedio(self):
        """alcance1, cadena: acme-demo.mx -> tienda -> www, ninguno de los dos en Cert Spotter. Si en la corrida
        siguiente tienda da 503, sin_revisar queda en [tienda] y la raíz sí se revisó: lo de www tiene que llevar a
        tienda como parte, o se cierra aunque el correo siga en www."""
        www, tienda = 'www.acme-demo.mx', 'tienda.acme-demo.mx'
        cuerpo = '<html><body>Escribe a CIRDAN_FAKE_ana@gmail.com</body></html>'
        cadena = {'https://acme-demo.mx/': {'redirige': 'https://%s/' % tienda, 'codigo': 301},
                  'https://%s/' % tienda: {'redirige': 'https://%s/' % www, 'codigo': 302},
                  'https://%s/' % www: pagina(cuerpo=cuerpo)}
        primera, _, _ = correr(cadena, red=Red(github_={}))
        personal = hallazgos(primera, 'personal_email_exposed')
        self.assertEqual([h.partes for h in personal], [sorted([DOMINIO, tienda, www])])

        caida = {'https://acme-demo.mx/': {'redirige': 'https://%s/' % tienda, 'codigo': 301},
                 'https://%s/' % tienda: pagina(estado=503)}
        segunda, _, _ = correr(caida, red=Red(github_={}))
        self.assertEqual(segunda.sin_revisar, [tienda])
        self.assertTrue(set(personal[0].partes) & set(segunda.sin_revisar))

class Base(unittest.TestCase):
    """Lectura estática de la semilla y la migración 028, del registro y del .gitignore, sin base."""

    def test_1_semilla_identity_encendida_con_10_corridas_por_dia(self):
        with mock.patch.object(test_subfinder, 'SEMILLA', SEMILLA):
            fila = test_subfinder.fila_de_la_semilla('identity')
        self.assertIsNotNone(fila, 'la semilla 026 no trae la fila de identity')
        self.assertEqual((fila['kind'], fila['enabled'].lower(), fila['keep_raw_payload'].lower()),
                         ("'osint'", 'true', 'false'))
        self.assertEqual(int(fila['daily_limit']), 10 * identidad.MAX_CONSULTAS)
        texto = SEMILLA.read_text(encoding='utf-8')
        self.assertIn("SET client_encoding = 'UTF8';", texto)
        self.assertIn('ON CONFLICT (code) DO NOTHING', texto)
        self.assertIn('la migración 028, que va ANTES que esta', texto)
        otras = [p.name for p in SEMILLA.parent.glob('*.sql') if p != SEMILLA
                 and fila['id'].strip("'") in p.read_text(encoding='utf-8')]
        self.assertEqual(otras, [])
        leeme = (RAIZ / 'db' / 'README.md').read_text(encoding='utf-8')
        m028, s_identidad = '< db/migraciones/%s' % MIGRACION.name, '< db/semillas/%s' % SEMILLA.name
        self.assertEqual((leeme.count(m028), leeme.count(s_identidad)), (2, 2))
        ordenes = [linea.split('< db/')[1].strip() for linea in leeme.splitlines() if m028 in linea or s_identidad in linea]
        self.assertEqual(ordenes, ['migraciones/' + MIGRACION.name, 'semillas/' + SEMILLA.name] * 2)

    def test_2_migracion_agrega_profile_sin_quitar_tipos(self):
        texto = MIGRACION.read_text(encoding='utf-8')
        self.assertIn("CHECK (asset_type IN ('domain','subdomain','ip','service','certificate','email','api_doc',"
                      "'profile'));", texto)
        self.assertIn("SET client_encoding = 'UTF8';", texto)
        self.assertIn("SET LOCAL lock_timeout = '5s';", texto)
        numeros = sorted(int(p.name[:3]) for p in MIGRACION.parent.glob('[0-9][0-9][0-9]_*.sql'))
        self.assertEqual(numeros, list(range(1, len(numeros) + 1)))
        self.assertEqual(contrato.TIPOS_ACTIVO, ('domain', 'subdomain', 'ip', 'service', 'certificate', 'email',
                                                 'api_doc', 'profile'))

    def test_3_las_grabaciones_de_identity_no_van_al_repo(self):
        self.assertEqual(identidad.CARPETA_GRABADAS, contrato.CARPETA_GRABADAS / 'identity')
        self.assertTrue((identidad.CARPETA_GRABADAS / '.gitkeep').exists())
        reglas = RAIZ / '.gitignore'
        if not reglas.exists() or not shutil.which('git'):
            self.skipTest('sin .gitignore o sin git, por ejemplo dentro del contenedor')
        with tempfile.TemporaryDirectory() as d:
            repo, vacio = Path(d) / 'repo', Path(d) / 'sin_exclusiones'
            vacio.write_text('', encoding='utf-8')
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            (repo / '.git' / 'info').mkdir(exist_ok=True)
            (repo / '.git' / 'info' / 'exclude').write_text('', encoding='utf-8')
            (repo / '.gitignore').write_bytes(reglas.read_bytes())

            def ignorado(ruta):
                r = subprocess.run(['git', '-c', 'core.excludesFile=' + vacio.as_posix(), 'check-ignore', '-q',
                                    '--no-index', 'cirdan/recolectores/respuestas_grabadas/' + ruta], cwd=repo)
                self.assertIn(r.returncode, (0, 1), ruta)
                return r.returncode == 0
            for ruta in ('identity/olmardo.com/sitio_reservas.olmardo.com_0123456789abcdef.json',
                         'identity/olmardo.com/.grabacion', 'identity/olmardo.com/gh_commits_olmardo_sitio.json'):
                self.assertTrue(ignorado(ruta), ruta)
            self.assertFalse(ignorado('identity/.gitkeep'))

    def test_4_registro_y_contrato_del_perfil(self):
        self.assertEqual(REGISTRO['identity'], 'cirdan.recolectores.identidad')
        self.assertIs(cargar('identity'), identidad)
        self.assertEqual(identidad.FUENTE, 'identity')
        res = Resultado(DOMINIO, 'identity')
        res.activos = [Activo('profile', 'https://github.com/acme-demo', {'hosts': [DOMINIO]})]
        self.assertEqual(contrato.validar(res), [])
        for malo in ('http://github.com/acme-demo', 'https://github.com/acme-demo?tab=repos', 'github.com/acme-demo',
                     'https://u@github.com/acme-demo'):
            res.activos = [Activo('profile', malo, {'hosts': [DOMINIO]})]
            self.assertTrue(contrato.validar(res), malo)
        # Sin hosts del dominio no pasa el filtro de alcance
        res.activos = [Activo('profile', 'https://github.com/acme-demo', {'hosts': ['otro.mx']})]
        self.assertEqual(contrato.filtrar_alcance(res).activos, [])

    def test_5_maximo_de_consultas(self):
        self.assertEqual(identidad.MAX_CONSULTAS, 171)
        self.assertFalse(getattr(identidad, 'EN_ESCANEO', None))


if __name__ == '__main__':
    unittest.main()
