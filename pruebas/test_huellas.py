"""Pruebas de las tecnologías web por huellas, la versión sin soporte y las CVE por CPE (#18, RC-46), sin red.

    python -m unittest -v pruebas/test_huellas.py

Las respuestas de pruebas/fixtures/huellas/ están armadas a mano: las páginas con señales públicas de cada tecnología,
las de endoflife.date con la forma de su API v1 o de la de antes y la de la NVD con la de su API 2.0. No son
grabaciones de ningún dominio ni consultas a esas API: ciclos, fechas y CVE son de ejemplo y las cookies llevan
CIRDAN_FAKE_. Las de reto o bloqueo son las de pruebas/fixtures/borde/.

Con HUELLAS_TARBALL=<ruta de wappalyzer-6.10.54.tgz>, la prueba 5 vuelve a generar huellas_wappalyzer.json desde el
tarball de npm y lo compara con el del repo. Sin la variable se salta (el tarball no va en el repo).
"""
import hashlib
import http.client
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import time
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))  # también corre como python pruebas/test_huellas.py
from cirdan.ml import caracteristicas as rubrica  # noqa: E402
from cirdan.recolectores import REGISTRO, borde, huellas, nvd, shodan, soporte  # noqa: E402
from cirdan.recolectores.contrato import Activo, Hallazgo, Resultado, validar  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'huellas'
FIXTURES_BORDE = Path(__file__).resolve().parent / 'fixtures' / 'borde'
SITIO = 'www.acme-demo.mx'
HOY = date(2026, 11, 6)
# Tecnología -> lo que hace que su CPE no sea una cadena de CPE 2.3 en Wappalyzer 6.10.54.
CPE_INVALIDOS = {'Angular': ':*:*:*:*:*:*:*:*:*', 'Erlang': 'erlang%2fotp', 'Weblication': 'cms_core_&_grid'}


def fixture(nombre, carpeta=FIXTURES):
    return json.loads((carpeta / (nombre + '.json')).read_text(encoding='utf-8'))


def analizar(nombre, carpeta=FIXTURES, **otros):
    r = fixture(nombre, carpeta)
    return huellas.analizar(r['estado'], r['cabeceras'], r['cuerpo'], **otros)


def por_nombre(resultado):
    return {t['nombre']: t for t in resultado['tecnologias']}


def tecnologia(nombre, version, distribucion=None, confianza=100, implicada_por=None, cpe=None):
    datos = huellas.cargar()['tecnologias'][nombre]
    return {'nombre': nombre, 'version': version, 'categorias': [huellas.CATEGORIAS[c] for c in datos['cats']],
            'cpe': cpe or datos['cpe'], 'confianza': confianza, 'senales': ['headers:server'],
            'distribucion': distribucion, 'implicada_por': implicada_por}


def cookies_de(valor):
    """[(nombre, valor)] de cada cookie de una Set-Cookie, también juntadas con ', ', sin usar huellas._cookies: un
    pedazo después de una coma cuenta si antes de su primer ';' trae un '=' (el resto de un Expires no lo trae)."""
    salida = []
    for pedazo in valor.split(','):
        nombre, igual, resto = pedazo.split(';', 1)[0].strip().partition('=')
        if igual and nombre:
            salida.append((nombre, resto))
    return salida


_SESION = re.compile(r'(?:Set-Cookie|PHPSESSID|session)[^"]*?=([^;" ]+)', re.I)


def valores_de_sesion(texto):
    """Lo que va después de 'Set-Cookie', 'PHPSESSID' o 'session' y un '=' en cualquier parte del texto de un fixture,
    también en el cuerpo (como un enlace a '/?PHPSESSID=...'), salvo '/' y 'http'."""
    return [v for v in _SESION.findall(texto) if v not in ('/', 'http')]


def severidades_del_catalogo():
    from pruebas.test_catalogo_reglas import JUEGO_V1, leer_reglas
    reglas, _ = leer_reglas()
    return {code: sev for _, _, juego, code, _, sev, _, _ in reglas if juego == JUEGO_V1}


def como_hallazgo(candidato, ahora):
    """El candidato de soporte.py o nvd.py como contrato.Hallazgo, como lo hará la visita web."""
    huella = hashlib.sha256('|'.join(('web', candidato['codigo'], SITIO, candidato['clave'])).encode()).hexdigest()
    return Hallazgo(candidato['codigo'], candidato['severidad'], SITIO, candidato['titulo'], candidato['evidencia'],
                    rubrica.calcular(candidato['codigo'], 'subdomain', candidato['evidencia'], ahora), huella,
                    clave=candidato['clave'])


class Datos(unittest.TestCase):
    def setUp(self):
        self.archivo = json.loads(huellas.ARCHIVO.read_text(encoding='utf-8'))

    def test_1_procedencia_mit_de_npm(self):
        p = self.archivo['procedencia']
        self.assertEqual((p['nombre'], p['version'], p['licencia'], p['autor']),
                         ('wappalyzer', '6.10.54', 'MIT', 'Wappalyzer'))
        self.assertEqual(p['tarball'], 'https://registry.npmjs.org/wappalyzer/-/wappalyzer-6.10.54.tgz')
        # La integridad del registro de npm (dist.integrity y dist.shasum), revisada el 5 nov contra el tarball.
        self.assertEqual(p['integridad'], 'sha512-P9VSYXSL6hiExangdWwipDlmMEdpdPqeHuv4QqsUTVxhuj4ua1YrE4xL7ENxs9b2wk9'
                                          'JeIzFR+ZqTmrlSYSEgw==')
        self.assertEqual((p['shasum'], p['bytes']), ('de8e0f0386f66bc6ce858408de9faa477f304c5e', 337360))
        self.assertEqual((p['tecnologias_en_paquete'], p['categorias_en_paquete']), (3588, 108))
        self.assertEqual({k: v for k, v in p.items() if k in huellas.PAQUETE}, huellas.PAQUETE)

    def test_2_cuantas_quedan(self):
        f, t = self.archivo['filtro'], self.archivo['tecnologias']
        self.assertEqual(f['tecnologias'], len(t))
        self.assertEqual(len(t), 553)
        self.assertEqual(f['con_cpe'], sum(1 for x in t.values() if 'cpe' in x))
        self.assertEqual(f['con_cpe'], 136)
        self.assertEqual(f['patrones_descartados'], [])
        self.assertEqual(f['categorias'], {str(c): n for c, n in huellas.CATEGORIAS.items()})

    def test_3_solo_categorias_y_campos_del_hecho_cuando(self):
        permitidos = {'cats', 'cpe'} | set(huellas.CAMPOS) | set(huellas.RELACIONES)
        for nombre, t in self.archivo['tecnologias'].items():
            self.assertLessEqual(set(t), permitidos, nombre)
            self.assertTrue(t['cats'] and set(t['cats']) <= set(huellas.CATEGORIAS), nombre)
        usados = {c for t in self.archivo['tecnologias'].values() for c in t}
        for fuera in ('js', 'dom', 'xhr', 'dns', 'css', 'robots', 'url', 'text', 'certIssuer', 'icon', 'description',
                      'website', 'pricing'):
            self.assertNotIn(fuera, usados)

    def test_4_relaciones_solo_a_lo_que_queda_y_todo_compila(self):
        t = self.archivo['tecnologias']
        for nombre, x in t.items():
            for campo in ('implies', 'excludes', 'requires'):
                for otra in x.get(campo, []):
                    self.assertIn(otra.split('\\;')[0], t, '%s %s %s' % (nombre, campo, otra))
            for c in x.get('requiresCategory', []):
                self.assertIn(int(c), huellas.CATEGORIAS, nombre)
            if 'cpe' in x and nombre not in CPE_INVALIDOS:
                self.assertEqual(nvd.cpe_con_version(x['cpe'], '1.0.0').split(':')[5], '1.0.0', nombre)
        # Los CPE de Wappalyzer 6.10.54 que no son una cadena de CPE 2.3: nvd.py no los arregla ni los consulta.
        self.assertEqual({n for n, x in t.items() if 'cpe' in x and nvd.cpe_con_version(x['cpe'], '1.0.0') is None},
                         set(CPE_INVALIDOS))
        for nombre, por_que in CPE_INVALIDOS.items():
            self.assertIn(por_que, t[nombre]['cpe'], nombre)
        self.assertEqual(t['Angular']['cpe'].count(':'), 13)
        # El de GLPI termina en un espacio: nvd.py lo quita y lo consulta.
        self.assertTrue(t['GLPI']['cpe'].endswith(' '))
        self.assertEqual(nvd.cpe_con_version(t['GLPI']['cpe'], '10.0.7'),
                         'cpe:2.3:a:glpi-project:glpi:10.0.7:*:*:*:*:*:*:*')
        cargado = huellas.cargar()
        self.assertEqual(len(cargado['tecnologias']), len(t))
        self.assertEqual(sum(len(p) for x in cargado['tecnologias'].values() for p in x['patrones'].values()), 870)

    def test_5_igual_al_que_sale_del_tarball(self):
        ruta = os.environ.get('HUELLAS_TARBALL')
        if not ruta:
            self.skipTest('sin HUELLAS_TARBALL: el tarball de npm no va en el repo')
        self.assertEqual(huellas.serializar(huellas.generar(ruta)), huellas.ARCHIVO.read_text(encoding='utf-8'))

    def test_6_otro_tarball_no_sirve(self):
        with tempfile.TemporaryDirectory() as carpeta:
            ruta = Path(carpeta) / 'wappalyzer-6.10.54.tgz'
            with tarfile.open(ruta, 'w:gz') as tar:
                datos = json.dumps({'name': 'wappalyzer', 'version': '6.10.54', 'license': 'MIT',
                                    'author': 'Wappalyzer'}).encode()
                info = tarfile.TarInfo('package/package.json')
                info.size = len(datos)
                tar.addfile(info, io.BytesIO(datos))
            with self.assertRaisesRegex(ValueError, 'no es el de wappalyzer 6.10.54'):
                huellas.generar(ruta)

    def test_7_filtrar_quita_lo_que_no_queda(self):
        categorias = {str(c): {'name': n} for c, n in huellas.CATEGORIAS.items()}
        tecnologias = {
            'Sitio': {'cats': [1, 6], 'headers': {'X-Sitio': ''},
                      'implies':['Base', 'Fuera', 'Lenguaje\\;confidence:50'],
                      'js': {'sitio': ''}, 'icon': 'x.svg', 'cpe': 'cpe:2.3:a:x:sitio:*:*:*:*:*:*:*:*'},
            'Lenguaje': {'cats': [27]},                                      # sin patrones, pero implicado
            'Suelto': {'cats': [27]},                                        # sin patrones ni quién lo implique
            'Fuera': {'cats': [6], 'headers': {'X-Fuera': ''}},              # otra categoría
            'Base': {'cats': [10], 'html': 'base'},
            'Plugin': {'cats': [1], 'html': 'plugin', 'requires': 'Fuera'},  # requiere algo que no queda
            'Malo': {'cats': [59], 'html': ['(?<=a+)b', 'bien']},            # lookbehind de largo variable
            'SoloJs': {'cats': [59], 'js': {'x': ''}},
        }
        salida, descartados = huellas.filtrar(tecnologias, categorias)
        self.assertEqual(sorted(salida), ['Lenguaje', 'Malo', 'Sitio'])
        self.assertEqual(salida['Sitio'], {'cats': [1], 'cpe': 'cpe:2.3:a:x:sitio:*:*:*:*:*:*:*:*',
                                           'headers': {'X-Sitio': ''},
                                           'implies': ['Lenguaje\\;confidence:50']})
        self.assertEqual(salida['Malo']['html'], ['bien'])
        self.assertEqual([(d['tecnologia'], d['patron']) for d in descartados], [('Malo', '(?<=a+)b')])
        with self.assertRaisesRegex(ValueError, 'categories.json'):
            huellas.filtrar(tecnologias, {})

    def test_8_notice_y_readme(self):
        aviso = ' '.join((RAIZ / 'NOTICE').read_text(encoding='utf-8').split())
        for texto in ('Wappalyzer 6.10.54', 'https://registry.npmjs.org/wappalyzer/-/wappalyzer-6.10.54.tgz',
                      'cirdan/recolectores/huellas_wappalyzer.json', 'Permission is hereby granted, free of charge',
                      'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND',
                      'This product uses the NVD API but is not endorsed or certified by the NVD.'):
            self.assertIn(texto, aviso)
        fila = [linea for linea in (RAIZ / 'README.md').read_text(encoding='utf-8').splitlines()
                if linea.startswith('| `LICENSE`, `NOTICE` |')]
        self.assertEqual(len(fila), 1)
        self.assertIn('Wappalyzer', fila[0])

    def test_9_no_son_recolectores(self):
        for modulo in (huellas, soporte, nvd):
            self.assertNotIn(modulo.__name__.rsplit('.', 1)[1], REGISTRO)
            self.assertFalse(hasattr(modulo, 'recolectar'), modulo.__name__)
            self.assertFalse(hasattr(modulo, 'MAX_CONSULTAS'), modulo.__name__)


class Regex(unittest.TestCase):
    def test_1_cuantificadores_con_tope(self):
        self.assertEqual(huellas._regex('a+b*').pattern, 'a{1,250}b{0,250}')
        self.assertEqual(huellas._regex(r'a\+[+*]c').pattern, r'a\+[+*]c')
        self.assertEqual(huellas._regex(r'[\]+]x+').pattern, r'[\]+]x{1,250}')
        self.assertEqual(huellas._regex('([\\d.]{2,})?x{3}').pattern, '([\\d.]{2,250})?x{3}')
        self.assertEqual(huellas._regex('(?<v>[\\d.]+)').pattern, '(?P<v>[\\d.]{1,250})')
        self.assertEqual(huellas._regex('(?<=a)b(?<!c)').pattern, '(?<=a)b(?<!c)')
        self.assertIsNone(huellas._regex('^a+$').search('a' * 251))

    def test_2_sin_mayusculas_y_solo_ascii(self):
        self.assertTrue(huellas._regex('^nginx').search('NGINX/1.0'))
        self.assertFalse(huellas._regex('^s').search('ſ'))       # ſ no es s
        self.assertFalse(huellas._regex('^k').search('K'))  # el signo de Kelvin no es k
        self.assertFalse(huellas._regex('^\\d').search('١'))     # un dígito árabe no es \d

    def test_3_version_y_confianza(self):
        regex, version, confianza = huellas._patron('nginx(?:/([\\d.]+))?\\;version:\\1\\;confidence:50')
        self.assertEqual((version, confianza), ('\\1', 50))
        self.assertEqual(huellas.resolver_version(version, regex, 'nginx/1.24.0 (Ubuntu)'), '1.24.0')
        self.assertEqual(huellas.resolver_version(version, regex, 'nginx'), '')
        regex, version, _ = huellas._patron('ver(\\d)?\\;version:\\1?con:sin')
        self.assertEqual(huellas.resolver_version(version, regex, 'ver7'), 'con')
        self.assertEqual(huellas.resolver_version(version, regex, 'ver'), 'sin')
        regex, version, _ = huellas._patron('v=([\\d.]+)\\;version:\\1')
        self.assertEqual(huellas.resolver_version(version, regex, 'v=12345678901'), '')   # más de 10: no se usa
        self.assertEqual(huellas._patron('x\\;confidence:mucho')[2], 100)


class Motor(unittest.TestCase):
    def test_1_servidor_lenguaje_cms_y_libreria(self):
        r = analizar('ubuntu_nginx_wordpress_200')
        self.assertTrue(r['completo'])
        self.assertIsNone(r['reto'])
        t = por_nombre(r)
        self.assertEqual({n: (x['version'], x['distribucion']) for n, x in t.items()},
                         {'Nginx': ('1.24.0', 'Ubuntu'), 'C': (None, None), 'PHP': ('8.1.2', 'Ubuntu'),
                          'WordPress': ('5.8.1', None), 'jQuery': ('3.5.1', None)})
        self.assertEqual(t['WordPress']['categorias'], ['CMS'])
        self.assertEqual(t['WordPress']['senales'], ['headers:link', 'html', 'meta:generator'])
        self.assertEqual(t['PHP']['senales'], ['cookies:phpsessid', 'headers:x-powered-by'])
        self.assertEqual(t['C']['implicada_por'], 'Nginx')
        self.assertEqual(t['Nginx']['cpe'], 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*')

    def test_2_nunca_guarda_valores_de_cookies_ni_del_html(self):
        for nombre in ('ubuntu_nginx_wordpress_200', 'cloudflare_laravel_200', 'iis_aspnet_200'):
            texto = json.dumps(analizar(nombre))
            self.assertNotIn('CIRDAN_FAKE', texto, nombre)
            self.assertNotIn('acme-demo', texto, nombre)

    def test_3_lo_del_cdn_no_es_del_sitio(self):
        r = analizar('cloudflare_laravel_200')
        self.assertEqual(r['del_borde'], ['cf-ray', 'server', 'set-cookie:__cf_bm'])
        t = por_nombre(r)
        self.assertEqual(sorted(t), ['Laravel', 'PHP', 'Vue.js'])
        self.assertEqual((t['Laravel']['senales'], t['Vue.js']['version']), (['cookies:laravel_session'], '2.6.14'))
        e = huellas.entradas(fixture('cloudflare_laravel_200')['cabeceras'])
        self.assertNotIn('server', e['headers'])
        self.assertEqual(sorted(e['cookies']), ['laravel_session'])
        # El Expires con coma no parte la cookie: la línea llega entera, con lo que va después de la coma.
        self.assertEqual(e['headers']['set-cookie'], ['laravel_session=CIRDAN_FAKE_laravel; expires=Thu, '
                                                      '05-Nov-2026 20:00:00 GMT; Max-Age=7200; path=/; httponly'])
        # Si el CDN no reescribe server, la de origen sí cuenta.
        self.assertIn('Nginx', por_nombre(huellas.analizar(200, {'Server': 'nginx/1.20.1', 'CF-RAY': 'x'})))
        self.assertEqual(huellas.analizar(200, {'Server': 'cloudflare'})['tecnologias'], [])

    def test_4_reto_o_bloqueo_sin_cobertura_nunca_0(self):
        for nombre in ('cloudflare_reto_403', 'cloudflare_reto_503', 'akamai_bloqueo_403', 'limite_429',
                       'aws_waf_reto_202'):
            r = analizar(nombre, FIXTURES_BORDE)
            self.assertIsNone(r['tecnologias'], nombre)
            self.assertFalse(r['completo'], nombre)
            self.assertTrue(borde.aviso('web', SITIO, r['reto']).endswith('sus tecnologías quedan sin cobertura, no 0'))
        r = analizar('origen_403', FIXTURES_BORDE)   # un 403 del sitio se analiza como cualquier otra respuesta
        self.assertIsNone(r['reto'])
        self.assertIsInstance(r['tecnologias'], list)

    def test_5_distribucion_por_la_misma_respuesta(self):
        t = por_nombre(analizar('centos_apache_php_200'))
        self.assertEqual((t['Apache HTTP Server']['version'], t['Apache HTTP Server']['distribucion']),
                         ('2.4.6', 'CentOS'))
        self.assertEqual((t['PHP']['version'], t['PHP']['distribucion']), ('5.4.16', 'CentOS'))
        casos = {'nginx/1.22.1': None, 'nginx/1.24.0 (Ubuntu)': 'Ubuntu', 'Apache/2.4.62 (Debian)': 'Debian',
                 'PHP/8.2.7-1~deb12u1': 'Debian', 'PHP/7.4.33-1+deb11u5': 'Debian',
                 'Apache/2.4.37 (Red Hat Enterprise Linux)': 'Red Hat', 'Apache/2.4.58 (Unix)': None,
                 'PHP/7.4.33-1.el7.remi': 'Enterprise Linux', 'nginx/1.20.1 (Amazon Linux)': 'Amazon Linux',
                 'Microsoft-IIS/10.0': None, 'Apache/2.4.41 (Win64)': None, None: None}
        for valor, esperado in casos.items():
            self.assertEqual(huellas.distribucion(valor), esperado, valor)

    def test_5b_la_version_del_html_no_es_de_la_distribucion(self):
        t = por_nombre(huellas.analizar(200, {'Server': 'nginx/1.24.0 (Ubuntu)'},
                                        '<meta name="generator" content="WordPress 5.8.1">'))
        self.assertEqual(t['WordPress']['distribucion'], None)
        self.assertEqual(t['Nginx']['distribucion'], 'Ubuntu')

    def test_6_scripts_meta_y_cabeceras(self):
        t = por_nombre(analizar('nginx_drupal_200'))
        self.assertEqual({n: x['version'] for n, x in t.items()},
                         {'Nginx': '1.18.0', 'C': None, 'Drupal': '7', 'PHP': None, 'jQuery': '1.12.4'})
        self.assertEqual(t['Drupal']['senales'], ['headers:expires', 'headers:x-generator', 'scripts'])
        self.assertIsNone(t['Nginx']['distribucion'])
        t = por_nombre(analizar('iis_aspnet_200'))
        self.assertEqual((t['IIS']['version'], t['Microsoft ASP.NET']['version']), ('10.0', '4.0.30319'))
        self.assertIn('html', t['Microsoft ASP.NET']['senales'])
        self.assertIn('cookies:asp.net_sessionid', t['Microsoft ASP.NET']['senales'])
        # scripts aparte que ya tenga la visita
        t = por_nombre(huellas.analizar(200, None, '<html></html>', scripts=['x = {drupal_internal__nid: 1}']))
        self.assertEqual(t['Drupal']['senales'], ['scripts'])

    def test_7_excludes_implies_y_requires(self):
        t = por_nombre(huellas.analizar(200, None, '<script src="/js/lodash.min.js"></script>'
                                                   '<script src="/js/underscore.min.js?ver=1.13.1"></script>'))
        self.assertEqual(sorted(t), ['Lodash'])   # la primera que salió excluye a la otra, como en Wappalyzer
        t = por_nombre(huellas.analizar(200, None, '<script src="/js/underscore.min.js?ver=1.13.1"></script>'))
        self.assertEqual(t['Underscore.js']['version'], '1.13.1')
        t = por_nombre(huellas.analizar(200, None, '<script src="https://cdn.mgpanel.org/x.js"></script>'))
        self.assertEqual(t, {})           # MGPanel requiere PHP
        t = por_nombre(huellas.analizar(200, {'Set-Cookie': 'laravel_session=CIRDAN_FAKE_x'},
                                        '<script src="https://cdn.mgpanel.org/x.js"></script>'))
        self.assertEqual(sorted(t), ['Laravel', 'MGPanel', 'PHP'])   # PHP implicado por Laravel cuenta
        self.assertEqual(t['PHP']['implicada_por'], 'Laravel')

    def test_8_formas_de_las_cabeceras_y_del_cuerpo(self):
        mensaje = http.client.parse_headers(io.BytesIO(b'Server: nginx/1.25.3\r\n'
                                                       b'Set-Cookie: PHPSESSID=CIRDAN_FAKE_a\r\n'
                                                       b'Set-Cookie: otra=CIRDAN_FAKE_b\r\n\r\n'))
        for cabeceras in ({'Server': 'nginx/1.25.3'}, [('server', 'nginx/1.25.3')], mensaje,
                          (p for p in [('Server', 'nginx/1.25.3')])):
            self.assertEqual(por_nombre(huellas.analizar(200, cabeceras))['Nginx']['version'], '1.25.3')
        self.assertIn('PHP', por_nombre(huellas.analizar(200, mensaje)))
        for raro in (None, 'texto', 7, [('Server', None)], [(None, 'nginx')], [('Sérver', 'nginx')]):
            self.assertEqual(huellas.analizar(200, raro)['tecnologias'], [], raro)
        cuerpo = '<meta name="generator" content="WordPress 6.1">'.encode()
        self.assertEqual(por_nombre(huellas.analizar(200, None, cuerpo))['WordPress']['version'], '6.1')
        self.assertEqual(huellas.analizar(200, None, b'\xff\xfe<html>')['tecnologias'], [])
        self.assertEqual(huellas.analizar('200', None, None)['tecnologias'], [])

    def test_9_tope_de_tiempo_deja_incompleto(self):
        pasos = iter(range(1000000))
        r = analizar('ubuntu_nginx_wordpress_200', reloj=lambda: next(pasos) * 0.01)
        self.assertFalse(r['completo'])
        self.assertIsInstance(r['tecnologias'], list)

    def test_10_topes_de_lo_que_se_lee(self):
        html = '<script src="/a.js"></script>' * (huellas.MAX_SCRIPTS + 50) + '<script>' + 'x' * 100000 + '</script>'
        e = huellas.entradas(None, html + 'x' * huellas.MAX_HTML)
        self.assertEqual(len(e['scriptSrc']), huellas.MAX_SCRIPTS)
        self.assertEqual(len(e['html']), huellas.MAX_HTML)
        self.assertLessEqual(max(map(len, e['scripts'])), huellas.MAX_SCRIPT)
        e = huellas.entradas(None, '<script src="/%s.js"></script><meta name="x" content="%s">' % ('a' * 3000,
                                                                                                    'b' * 3000))
        self.assertEqual((len(e['scriptSrc'][0]), len(e['meta']['x'][0])), (huellas.MAX_SRC, huellas.MAX_SRC))
        # Una etiqueta sin '>' en MAX_ETIQUETA caracteres no se lee, y lo que sigue sí.
        e = huellas.entradas(None, '<script src="/%s.js"></script><script src="/b.js"></script>' % ('a' * 5000))
        self.assertEqual(e['scriptSrc'], ['/b.js'])
        e = huellas.entradas(None, '<!-- <meta name="generator" content="Joomla"> --><META NAME=Generator '
                                   "CONTENT='WordPress 6.1 &amp; m&aacute;s'><script>var a = '</scripts>';</script >")
        self.assertEqual((e['meta'], e['scripts']), ({'generator': ['WordPress 6.1 & más']}, ["var a = '</scripts>';"]))
        e = huellas.entradas(None, None, scripts=['y' * 100000] * 10)
        self.assertLessEqual(sum(map(len, e['scripts'])), huellas.MAX_TEXTO_SCRIPTS)

    def test_11_respuestas_armadas_para_trabar_las_regex(self):
        bases = ('a', '<', ' ', '"', '.', '1.', '/', '-', '<link rel="stylesheet" ', '<script src="',
                 '<meta name="generator" content="', '<div id="wrapper_r" class="', '<a href="/x/y-z.js?v=1.2" ')
        peor = 0
        for base in bases:
            texto = (base * (huellas.MAX_HTML // len(base) + 1))[:huellas.MAX_HTML]
            cabeceras = [('Server', (base * 9000)[:9000]), ('X-Powered-By', 'php/' + (base * 9000)[:9000]),
                         ('Set-Cookie', 'a=' + (base * 70000)[:70000])]
            for url in (None, 'https://' + SITIO + '/'):   # con url, cada src se compara resuelto y crudo
                inicio = time.monotonic()
                r = huellas.analizar(200, cabeceras, texto, scripts=[texto[:huellas.MAX_SCRIPT]] * 4, url=url)
                peor = max(peor, time.monotonic() - inicio)
                self.assertIsInstance(r['tecnologias'], list, (base, url))
        self.assertLess(peor, huellas.TOPE_SEGUNDOS + 1.0)

    def test_12_muchas_cabeceras_iguales(self):
        # http.client deja pasar 100 cabeceras y borde._pares corta cada una a 8 KiB. Con el patrón de Liferay
        # ('[a-z\s]+([\d.]+)') cada valor de tabuladores cuesta unos 0.05 s: 99 tomaban 5 s. Cada valor lleva un
        # carácter menos que MAX_VALOR: uno de MAX_VALOR no se lee (test_23).
        cabeceras = [('Liferay-Portal', '-' + '\t' * (huellas.MAX_VALOR - 3) + '-')] * 99
        inicio = time.monotonic()
        r = huellas.analizar(200, cabeceras)
        self.assertLess(time.monotonic() - inicio, huellas.TOPE_SEGUNDOS + 0.5)
        self.assertFalse(r['completo'])
        # MAX_CABECERAS es de toda la respuesta, sin contar las Set-Cookie.
        e = huellas.entradas(cabeceras + [('Set-Cookie', 'PHPSESSID=CIRDAN_FAKE_a')])
        self.assertLessEqual(sum(map(len, e['headers']['liferay-portal'])), huellas.MAX_CABECERAS)
        self.assertEqual((e['recortes'], sorted(e['cookies'])), (['MAX_CABECERAS'], ['phpsessid']))
        self.assertEqual(huellas.entradas([('Server', 'nginx/1.24.0')] * 3)['recortes'], [])

    def test_13_el_reloj_se_revisa_entre_un_valor_y_el_siguiente(self):
        # Una regex que tarda 2 s en cada valor: con el tope de 3 s, el tercer valor ya no se revisa.
        ahora, revisados = [0.0], []

        class Lenta:
            def search(self, valor):
                revisados.append(valor)
                ahora[0] += 2.0

        datos = {'tecnologias': {'Lenta': {'cats': [22], 'cpe': None, 'implies': [], 'excludes': [], 'requires': [],
                                           'requiresCategory': [],
                                           'patrones': {'headers': [('x-lenta', Lenta(), '', 100)]}}}}
        r = huellas.analizar(200, [('X-Lenta', 'a'), ('X-Lenta', 'b'), ('X-Lenta', 'c')], datos=datos,
                             reloj=lambda: ahora[0])
        self.assertEqual((revisados, r['completo']), (['a', 'b'], False))
        # El src resuelto y el crudo son dos valores: con una regex de 4 s, el crudo ya no se revisa.

        class MasLenta:
            def search(self, valor):
                revisados.append(valor)
                ahora[0] += 4.0

        ahora[0], revisados[:] = 0.0, []
        datos['tecnologias']['Lenta']['patrones'] = {'scriptSrc': [(None, MasLenta(), '', 100)]}
        r = huellas.analizar(200, None, '<script src="/a.js"></script>', datos=datos, reloj=lambda: ahora[0],
                             url='https://' + SITIO + '/')
        self.assertEqual((revisados, r['completo']), (['https://www.acme-demo.mx/a.js'], False))

    def test_14_la_marca_de_la_otra_cabecera(self):
        # PHP sale solo de X-Powered-By, sin marca, y hereda la de Server: la distribución empaqueta los dos.
        t = por_nombre(huellas.analizar(200, [('Server', 'Apache/2.4.6 (CentOS)'), ('X-Powered-By', 'PHP/5.4.16')]))
        self.assertEqual(t['PHP']['senales'], ['headers:x-powered-by'])
        self.assertEqual((t['PHP']['version'], t['PHP']['distribucion']), ('5.4.16', 'CentOS'))
        self.assertEqual(soporte.revisar(t['PHP'], fixture('eol_php'), SITIO, HOY)['estado'], 'distribucion')
        # Un framework detrás del servidor de la distribución no la hereda: Ubuntu no parcha Next.js.
        t = por_nombre(huellas.analizar(200, [('Server', 'nginx/1.18.0 (Ubuntu)'),
                                              ('X-Powered-By', 'Next.js 12.3.4')]))
        self.assertEqual((t['Next.js']['version'], t['Next.js']['distribucion']), ('12.3.4', None))
        self.assertEqual(t['Nginx']['distribucion'], 'Ubuntu')
        # El PPA de deb.sury.org sigue la versión oficial: ni marca propia ni heredada. La cabecera sí dice que el
        # servidor es Ubuntu (test_17).
        sury = 'PHP/8.1.27-1+ubuntu22.04.1+deb.sury.org+1'
        self.assertEqual(huellas.distribucion(sury), 'Ubuntu')
        for server in ('nginx/1.18.0', 'Apache/2.4.52 (Ubuntu)'):
            t = por_nombre(huellas.analizar(200, [('Server', server), ('X-Powered-By', sury)]))
            self.assertEqual((t['PHP']['version'], t['PHP']['distribucion']), ('8.1.27', None), server)
        self.assertEqual(huellas.distribucion('Apache/2.4.52 (Ubuntu) ' + sury), 'Ubuntu')

    def test_15_lo_que_no_se_lee_va_en_recortes(self):
        # Un generator después de MAX_HTML no se ve, y el recorte queda dicho. Una página normal llega a MAX_HTML:
        # sigue completa (test_20).
        cuerpo = 'x' * (huellas.MAX_HTML + 6000) + '<meta name="generator" content="WordPress 5.8.1">'
        r = huellas.analizar(200, None, cuerpo)
        self.assertEqual((r['tecnologias'], r['completo'], r['recortes']), ([], True, ['MAX_HTML']))
        self.assertEqual(huellas.entradas(None, cuerpo)['recortes'], ['MAX_HTML'])
        self.assertEqual(huellas.entradas(None, cuerpo.encode())['recortes'], ['MAX_HTML'])
        # Igual con un src después de MAX_SCRIPTS.
        cuerpo = '<script src="/a.js"></script>' * 250 + '<script src="https://code.jquery.com/jquery-3.5.1.min.js">'
        r = huellas.analizar(200, None, cuerpo)
        self.assertEqual((r['tecnologias'], r['completo'], r['recortes']), ([], True, ['MAX_SCRIPTS']))
        self.assertEqual(huellas.entradas(None, cuerpo)['recortes'], ['MAX_SCRIPTS'])
        self.assertEqual(huellas.entradas(None, '<meta name="a" content="b">' * 201)['recortes'], ['MAX_SCRIPTS'])
        self.assertEqual(huellas.entradas(None, None, scripts=['x = 1'] * 201)['recortes'], ['MAX_SCRIPTS'])
        # Y con el texto de los scripts después de MAX_TEXTO_SCRIPTS, del HTML o aparte.
        self.assertEqual(huellas.entradas(None, None, scripts=['y' * 100000] * 10)['recortes'],
                         ['MAX_SCRIPT', 'MAX_TEXTO_SCRIPTS'])
        html = '<script>%s</script>' % ('y' * 60000)
        self.assertEqual(huellas.entradas(None, html, scripts=['z' * 64000] * 4)['recortes'], ['MAX_TEXTO_SCRIPTS'])
        self.assertEqual(huellas.entradas(None, html, scripts=['z' * 64000] * 3)['recortes'], [])
        # _recortar_html corta una página armada de '<' y la deja incompleta, y no corta una normal.
        armada = '<' * huellas.MAX_HTML
        corto, recortado = huellas._recortar_html(armada)
        self.assertTrue(recortado)
        self.assertLess(len(corto), len(armada) // 10)
        self.assertEqual(huellas.entradas(None, armada)['recortes'], ['MAX_COSTO_HTML'])
        self.assertFalse(huellas.analizar(200, None, armada)['completo'])
        pagina = fixture('ubuntu_nginx_wordpress_200')['cuerpo']
        self.assertEqual(huellas._recortar_html(pagina), (pagina, False))
        self.assertEqual(huellas.entradas(None, pagina)['recortes'], [])

    def test_16_src_relativo_con_la_url_de_la_pagina(self):
        # El scriptSrc de GLPI empieza con '//': Wappalyzer lo compara con el src ya resuelto del DOM.
        cuerpo = '<script src="/glpi/js/common.min.js?v=10.0.7"></script>'
        self.assertNotIn('GLPI', por_nombre(huellas.analizar(200, None, cuerpo)))
        t = por_nombre(huellas.analizar(200, None, cuerpo, url='https://' + SITIO + '/front/central.php'))
        self.assertEqual((t['GLPI']['version'], t['GLPI']['senales']), ('10.0.7', ['scriptSrc']))
        e = huellas.entradas(None, cuerpo, url='https://' + SITIO + '/')
        self.assertEqual(e['scriptSrc'], ['https://www.acme-demo.mx/glpi/js/common.min.js?v=10.0.7'])
        # Sin URL, o con una que urljoin no puede leer, el src queda como vino.
        for url in (None, '', 7, 'http://[x/'):
            self.assertEqual(huellas.entradas(None, cuerpo, url=url)['scriptSrc'],
                             ['/glpi/js/common.min.js?v=10.0.7'], url)

    def test_17_la_marca_es_la_del_pedazo_de_cada_producto(self):
        sury = 'PHP/8.1.27-1+ubuntu22.04.1+deb.sury.org+1'
        # La cabecera de Surý dice que el servidor es Ubuntu: Apache sin marca (ServerTokens Min) la hereda, y PHP,
        # que sigue la versión oficial, no. Sin la herencia, la NVD daría CVE que Ubuntu ya parchó en Apache.
        separadas = [('Server', 'Apache/2.4.52'), ('X-Powered-By', sury)]
        # En una sola cabecera (mod_php con ServerTokens Full), el '(Ubuntu)' es de Apache y no de PHP.
        juntas = [('Server', 'Apache/2.4.52 (Ubuntu) ' + sury)]
        for cabeceras in (separadas, juntas):
            t = por_nombre(huellas.analizar(200, cabeceras))
            apache = t['Apache HTTP Server']
            self.assertEqual((apache['version'], apache['distribucion']), ('2.4.52', 'Ubuntu'), cabeceras)
            self.assertEqual((t['PHP']['version'], t['PHP']['distribucion']), ('8.1.27', None), cabeceras)
            self.assertEqual(nvd.revisar(apache, fixture('nvd_nginx_1.18.0'), SITIO)['estado'], 'distribucion')
        # Tampoco pasa a otro producto sin marca que no hereda: el '(Ubuntu)' es de nginx, no de Werkzeug (Flask).
        t = por_nombre(huellas.analizar(200, [('Server', 'nginx/1.18.0 (Ubuntu) Werkzeug/2.0.2')]))
        self.assertEqual((t['Flask']['version'], t['Flask']['distribucion']), ('2.0.2', None))
        self.assertEqual(t['Nginx']['distribucion'], 'Ubuntu')
        # El pedazo es el producto que calzó con los comentarios que le siguen.
        valor = 'Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16'
        self.assertEqual(huellas._pedazo(valor, 0, 12), 'Apache/2.4.6 (CentOS)')
        self.assertEqual(huellas._pedazo(valor, valor.index('PHP'), len(valor)), 'PHP/5.4.16')
        self.assertEqual(huellas._pedazo('Next.js 12.3.4', 0, 14), 'Next.js 12.3.4')
        self.assertEqual(huellas._pedazo('nginx/1.20.1 (Amazon Linux)', 0, 0), 'nginx/1.20.1 (Amazon Linux)')

    def test_18_un_valor_que_no_cabe_en_max_cabeceras_se_salta_entero(self):
        # Antes de Server quedan 9 caracteres: 'nginx/1.24.0' no se lee, ni cortado a 'nginx/1.2' (otra versión).
        relleno = [('Content-Security-Policy', 'a' * (huellas.MAX_VALOR - 1))] * 7 + [
            ('Content-Security-Policy', 'a' * (huellas.MAX_CABECERAS - 7 * (huellas.MAX_VALOR - 1) - 9))]
        cabeceras = relleno + [('Server', 'nginx/1.24.0'), ('X-Powered-By', 'PHP/8.1')]
        e = huellas.entradas(cabeceras)
        self.assertNotIn('server', e['headers'])
        self.assertEqual(e['headers']['x-powered-by'], ['PHP/8.1'])   # lo que sí cabe entero se lee
        self.assertIn('MAX_CABECERAS', e['recortes'])
        r = huellas.analizar(200, cabeceras)
        self.assertNotIn('Nginx', por_nombre(r))
        self.assertFalse(r['completo'])

    def test_19_el_src_se_compara_como_vino_y_resuelto(self):
        # Los patrones de TYPO3 ('^/?typo3(?:conf|temp)/') y React ('^react\b.*\.js') esperan el src relativo.
        url = 'https://' + SITIO + '/inicio/'
        cuerpo = '<script src="/typo3temp/assets/js/main.js"></script><script src="react.production.min.js"></script>'
        t = por_nombre(huellas.analizar(200, None, cuerpo, url=url))
        self.assertEqual((t['TYPO3 CMS']['senales'], t['React']['senales']), (['scriptSrc'], ['scriptSrc']))
        t = por_nombre(huellas.analizar(200, None, '<script src="typo3conf/ext/x/y.js"></script>', url=url))
        self.assertIn('TYPO3 CMS', t)
        e = huellas.entradas(None, cuerpo, url=url)
        self.assertEqual(e['scriptSrc_crudo'], ['/typo3temp/assets/js/main.js', 'react.production.min.js'])
        self.assertEqual(e['scriptSrc'], ['https://www.acme-demo.mx/typo3temp/assets/js/main.js',
                                          'https://www.acme-demo.mx/inicio/react.production.min.js'])
        # Un patrón que calza con las dos formas da una sola detección: la confianza no se suma dos veces.
        datos = {'tecnologias': {'Prueba': {'cats': [59], 'cpe': None, 'implies': [], 'excludes': [], 'requires': [],
                                            'requiresCategory': [], 'patrones': {
                                                'scriptSrc': [(None,) + huellas._patron('lib\\.js\\;confidence:50')]}}}}
        r = huellas.analizar(200, None, '<script src="/js/lib.js"></script>', datos=datos, url=url)
        self.assertEqual([(x['confianza'], x['senales']) for x in r['tecnologias']], [(50, ['scriptSrc'])])

    def test_20_completo_solo_con_el_tiempo_y_dejan_incompleto(self):
        # Una página normal, con un script en línea y cuatro de 64 KiB de la visita, pasa de MAX_TEXTO_SCRIPTS y
        # sigue completa: si no, sus hallazgos nunca se cerrarían.
        r = huellas.analizar(200, {'Server': 'nginx/1.24.0'}, '<script>var a = 1;</script>',
                             scripts=['z' * huellas.MAX_SCRIPT] * 4)
        self.assertEqual((r['completo'], r['recortes']), (True, ['MAX_TEXTO_SCRIPTS']))
        self.assertIn('Nginx', por_nombre(r))
        # MAX_CABECERAS, MAX_COSTO_HTML y MAX_VALOR (test_23) sí la dejan incompleta, y el tope de tiempo también
        # (test_9).
        r = huellas.analizar(200, [('X-Relleno', 'a' * (huellas.MAX_VALOR - 1))] * 9)
        self.assertEqual((r['completo'], r['recortes']), (False, ['MAX_CABECERAS']))
        r = huellas.analizar(200, None, '<' * huellas.MAX_HTML)
        self.assertEqual((r['completo'], r['recortes']), (False, ['MAX_COSTO_HTML']))
        self.assertEqual(huellas.DEJAN_INCOMPLETO, ('MAX_CABECERAS', 'MAX_COSTO_HTML', 'MAX_VALOR'))

    def test_21_cada_tope_que_corta_va_en_recortes(self):
        def recortes(cabeceras=None, cuerpo=None, scripts=()):
            return huellas.entradas(cabeceras, cuerpo, scripts)['recortes']
        # Una etiqueta sin '>' en MAX_ETIQUETA caracteres: el generator no se lee.
        cuerpo = '<meta name="generator" content="WordPress 5.8.1" data-x="%s">' % ('a' * 5000)
        r = huellas.analizar(200, None, cuerpo)
        self.assertEqual((r['tecnologias'], r['completo'], r['recortes']), ([], True, ['MAX_ETIQUETA']))
        # 201 scripts en línea.
        self.assertEqual(recortes(cuerpo='<script>x = 1</script>' * 201), ['MAX_SCRIPTS'])
        # Un bundle con el banner de Ember después de MAX_SCRIPT, en línea o aparte.
        banner = '/** @overview Ember - JavaScript Application Framework @version 3.28.0 */'
        self.assertIn('Ember.js', por_nombre(huellas.analizar(200, None, '<script>x;%s</script>' % banner)))
        bundle = 'x' * (huellas.MAX_SCRIPT + 100) + banner
        r = huellas.analizar(200, None, '<script>%s</script>' % bundle)
        self.assertEqual((r['tecnologias'], r['completo'], r['recortes']), ([], True, ['MAX_SCRIPT']))
        self.assertEqual(recortes(scripts=[bundle]), ['MAX_SCRIPT'])
        # Un src o un content de <meta> de más de MAX_SRC.
        self.assertEqual(recortes(cuerpo='<script src="/%s.js"></script>' % ('a' * 3000)), ['MAX_SRC'])
        self.assertEqual(recortes(cuerpo='<meta name="x" content="%s">' % ('b' * 3000)), ['MAX_SRC'])
        # Un src corto que resuelto contra una url larga pasa de MAX_SRC.
        url = 'https://' + SITIO + '/' + 'd/' * huellas.MAX_SRC
        e = huellas.entradas(None, '<script src="lib.js"></script>', url=url)
        self.assertEqual((e['scriptSrc_crudo'], len(e['scriptSrc'][0]), e['recortes']),
                         (['lib.js'], huellas.MAX_SRC, ['MAX_SRC']))
        r = huellas.analizar(200, None, '<script src="lib.js"></script>', url=url)
        self.assertEqual((r['completo'], r['recortes']), (True, ['MAX_SRC']))
        # Una cabecera cortada a MAX_VALOR, una Set-Cookie de más de MAX_VALOR y Set-Cookie cortadas a MAX_COOKIES.
        # MAX_VALOR deja el análisis incompleto (test_23) y MAX_COOKIES no.
        for cabeceras in ([('X-Largo', 'a' * 9000)], [('Set-Cookie', 'a=CIRDAN_FAKE_' + 'b' * 9000)]):
            self.assertEqual(recortes(cabeceras=cabeceras), ['MAX_VALOR'])
            r = huellas.analizar(200, cabeceras)
            self.assertEqual((r['completo'], r['recortes']), (False, ['MAX_VALOR']))
        cookies = [('Set-Cookie', 'c%d=CIRDAN_FAKE_%s' % (i, 'd' * 7000)) for i in range(10)]
        self.assertEqual(recortes(cabeceras=cookies), ['MAX_COOKIES'])
        r = huellas.analizar(200, cookies)
        self.assertEqual((r['completo'], r['recortes']), (True, ['MAX_COOKIES']))
        # Un cuerpo en bytes de más de 1 MiB (MAX_HTML * 4) cuyo texto cabe en MAX_HTML: lo que sigue no se lee.
        cuerpo = ('\U0001F600' * huellas.MAX_HTML).encode() + b'<meta name="generator" content="WordPress 5.8.1">'
        r = huellas.analizar(200, None, cuerpo)
        self.assertEqual((r['tecnologias'], r['completo'], r['recortes']), ([], True, ['MAX_HTML']))
        # Una página normal no llega a ninguno.
        pagina = fixture('ubuntu_nginx_wordpress_200')
        self.assertEqual(recortes(pagina['cabeceras'], pagina['cuerpo']), [])

    def test_22_no_hereda_quien_ya_dice_su_origen(self):
        sury = 'PHP/8.1.27-1+ubuntu22.04.1+deb.sury.org+1'
        # Un Apache compilado aparte ('(Unix)', '(Win64)') no es el de Ubuntu: sin distribución, sus CVE cuentan.
        for server in ('Apache/2.4.58 (Unix) OpenSSL/3.0.2', 'Apache/2.4.41 (Win64)', 'Apache/2.4.41 (Win32)'):
            t = por_nombre(huellas.analizar(200, [('Server', server), ('X-Powered-By', sury)]))
            apache = t['Apache HTTP Server']
            self.assertEqual(apache['distribucion'], None, server)
            self.assertNotEqual(nvd.revisar(apache, fixture('nvd_nginx_1.18.0'), SITIO)['estado'], 'distribucion')
        # Tampoco junto a un PHP con la marca de Ubuntu.
        t = por_nombre(huellas.analizar(200, [('Server', 'Apache/2.4.58 (Unix)'),
                                              ('X-Powered-By', 'PHP/7.4.3-4ubuntu2.19')]))
        self.assertEqual((t['Apache HTTP Server']['distribucion'], t['PHP']['distribucion']), (None, 'Ubuntu'))
        # Ni un producto que la distribución no empaqueta con esa cabecera.
        for server, nombre, version in (('openresty/1.21.4.1', 'OpenResty', '1.21.4.1'),
                                        ('Jetty(9.4.44.v20210927)', 'Jetty', '9.4.44')):
            t = por_nombre(huellas.analizar(200, [('Server', server), ('X-Powered-By', sury)]))
            self.assertEqual((t[nombre]['version'], t[nombre]['distribucion']), (version, None), server)
        self.assertEqual(huellas.NO_HEREDAN, ('Jetty', 'OpenResty'))
        # Sin comentario sí hereda (test_17).
        t = por_nombre(huellas.analizar(200, [('Server', 'Apache/2.4.52'), ('X-Powered-By', sury)]))
        self.assertEqual(t['Apache HTTP Server']['distribucion'], 'Ubuntu')

    def test_23_un_valor_cortado_por_max_valor_no_se_lee(self):
        # borde._pares corta Server a MAX_VALOR, y 'nginx/1.24.0' llega como 'nginx/1.2', que es otra versión.
        cabeceras = [('Server', 'a' * 8182 + ' nginx/1.24.0'), ('X-Powered-By', 'PHP/8.1')]
        self.assertTrue(borde._pares(cabeceras)[0][1].endswith(' nginx/1.2'))   # borde.py sigue igual
        e = huellas.entradas(cabeceras)
        self.assertEqual((sorted(e['headers']), e['recortes']), (['x-powered-by'], ['MAX_VALOR']))
        r = huellas.analizar(200, cabeceras)
        self.assertNotIn('Nginx', por_nombre(r))
        self.assertIn('PHP', por_nombre(r))   # lo demás sí se lee
        self.assertEqual((r['completo'], r['recortes']), (False, ['MAX_VALOR']))
        # Con un carácter menos que MAX_VALOR llega entero y se lee.
        r = huellas.analizar(200, [('Server', 'a' * (huellas.MAX_VALOR - 14) + ' nginx/1.24.0')])
        self.assertEqual((por_nombre(r)['Nginx']['version'], r['completo'], r['recortes']), ('1.24.0', True, []))
        # Una Set-Cookie de más de MAX_VALOR tampoco se lee cortada, ni su nombre.
        e = huellas.entradas([('Set-Cookie', 'laravel_session=CIRDAN_FAKE_' + 'b' * 9000)])
        self.assertEqual((e['cookies'], e['headers'], e['recortes']), ({}, {}, ['MAX_VALOR']))

    def test_24_la_version_de_un_plugin_no_es_la_de_jquery(self):
        # El patrón '/(\d+\.\d+\.\d+)/jquery[/.-][^u]' de Wappalyzer calza con la ruta de cdnjs de un plugin: la
        # versión es la del plugin. jQuery sigue saliendo (el plugin lo necesita), sin esa versión.
        cdnjs = 'https://cdnjs.cloudflare.com/ajax/libs/'
        validate = cdnjs + 'jquery-validate/1.19.5/jquery.validate.min.js'
        mousewheel = cdnjs + 'jquery-mousewheel/3.1.13/jquery.mousewheel.js'
        propio = 'https://code.jquery.com/jquery-3.7.1.min.js'
        casos = {(validate,): None, (validate, propio): '3.7.1', (propio, validate): '3.7.1',
                 (cdnjs + 'jquery-migrate/3.4.1/jquery-migrate.min.js',): None,
                 ('/js/jquery-migrate-3.4.1.min.js',): None,
                 (cdnjs + 'jquery.mask/1.14.16/jquery.mask.min.js',): None,
                 (cdnjs + 'jquery-easing/1.4.1/jquery.easing.min.js',): None,
                 # El de mousewheel tapaba un jQuery 2.2.4 real (3.1.13 es más larga).
                 (mousewheel, 'https://code.jquery.com/jquery-2.2.4.min.js'): '2.2.4', (mousewheel,): None,
                 # Los archivos de jQuery sí dan su versión.
                 (cdnjs + 'jquery/3.7.1/jquery.min.js',): '3.7.1',
                 (cdnjs + 'jquery/3.7.1/jquery.slim.min.js',): '3.7.1',
                 ('/3.6.0/jquery.js',): '3.6.0', ('/js/jquery-1.12.4.min.js?v=2',): '1.12.4'}
        for srcs, esperada in casos.items():
            cuerpo = ''.join('<script src="%s"></script>' % s for s in srcs)
            t = por_nombre(huellas.analizar(200, None, cuerpo, url='https://' + SITIO + '/'))
            self.assertEqual((t['jQuery']['version'], t['jQuery']['confianza']), (esperada, 100), srcs)
            if esperada is None:   # sin versión no hay hallazgo ni consulta
                self.assertEqual(soporte.revisar(t['jQuery'], fixture('eol_jquery'), SITIO, HOY)['estado'],
                                 'sin_version', srcs)
                self.assertEqual(nvd.revisar(t['jQuery'], fixture('nvd_nginx_1.18.0'), SITIO)['estado'],
                                 'sin_version', srcs)
        for src, nombre, propio in (('https://code.jquery.com/jquery-3.7.1.slim.min.js?x=1#y', 'jQuery', True),
                                    (validate, 'jQuery', False), ('jquery-migrate-3.4.1.min.js', 'jQuery', False),
                                    ('/js/JQuery.Min.JS', 'jQuery', True),
                                    ('/js/vue-2.6.14.runtime.min.js', 'Vue.js', True),
                                    ('/lib/angular-1.0.0.js', 'AngularJS', True),
                                    ('/lib/angular-1.0.0-rc.1.js', 'AngularJS', False),
                                    ('/textAngular-1.5.16.min.js', 'AngularJS', False), ('/jquery/', 'jQuery', False)):
            self.assertIs(huellas._es_propio(nombre, src), propio, src)
        self.assertEqual(huellas._archivo('https://code.jquery.com/jquery-3.7.1.slim.min.js?x=1#y'),
                         'jquery-3.7.1.slim.min')
        # Lo mismo con React, Vue.js y AngularJS: un archivo de otro nombre con el suyo adentro no da su versión.
        for src, nombre in (('/js/preact-10.5.13.min.js', 'React'), ('/js/bootstrap-vue-2.21.2.min.js', 'Vue.js'),
                            ('/js/textAngular-1.5.16.min.js', 'AngularJS')):
            t = por_nombre(huellas.analizar(200, None, '<script src="%s"></script>' % src))
            self.assertIsNone(t[nombre]['version'], src)
        for src, nombre, version in (('/js/react-16.14.0.min.js', 'React', '16.14.0'),
                                     ('/js/vue-2.6.14.min.js', 'Vue.js', '2.6.14'),
                                     ('/js/angular-1.8.2.min.js', 'AngularJS', '1.8.2')):
            t = por_nombre(huellas.analizar(200, None, '<script src="%s"></script>' % src))
            self.assertEqual(t[nombre]['version'], version, src)
        # Una tecnología fuera de ARCHIVOS_PROPIOS sigue con la versión de cualquier src (GLPI, test_16).
        self.assertNotIn('GLPI', huellas.ARCHIVOS_PROPIOS)

    def test_25_gana_la_version_de_la_senal_mas_directa(self):
        cabecera = ('x-prueba',) + huellas._patron('v([\\d.]+)\\;version:\\1')
        html = (None,) + huellas._patron('prueba-([\\d.]+)\\;version:\\1')
        datos = {'tecnologias': {'Prueba': {'cats': [1], 'cpe': None, 'implies': [], 'excludes': [], 'requires': [],
                                            'requiresCategory': [],
                                            'patrones': {'headers': [cabecera], 'html': [html]}}}}

        def version(cabeceras, html=None):
            return por_nombre(huellas.analizar(200, cabeceras, html, datos=datos))['Prueba']['version']
        # La cabecera gana aunque la del html sea más larga (antes ganaba la más larga).
        self.assertEqual(version([('X-Prueba', 'v2.0.1')], '<p>prueba-10.0.12</p>'), '2.0.1')
        # Una de una señal menos directa solo cuenta si alarga la elegida.
        self.assertEqual(version([('X-Prueba', 'v2.0')], '<p>prueba-2.0.1</p>'), '2.0.1')
        self.assertEqual(version([('X-Prueba', 'v2.0')], '<p>prueba-2.01</p>'), '2.0')
        self.assertEqual(version(None, '<p>prueba-2.0.1</p>'), '2.0.1')
        # Dos de la misma señal que no concuerdan: sin versión. Si una alarga a la otra, la más larga.
        self.assertIsNone(version([('X-Prueba', 'v2.0.1'), ('X-Prueba', 'v3.1.4')]))
        self.assertEqual(version([('X-Prueba', 'v2.0'), ('X-Prueba', 'v2.0.1')]), '2.0.1')
        # Dos archivos de jQuery con versiones distintas en la misma página: no se sabe cuál usa.
        t = por_nombre(huellas.analizar(200, None, '<script src="https://code.jquery.com/jquery-1.12.4.min.js">'
                                                   '</script><script src="/js/jquery-3.7.1.min.js"></script>'))
        self.assertIsNone(t['jQuery']['version'])

    def test_26_muchas_versiones_no_pasan_del_tope(self):
        # Una Set-Cookie de menos de 64 KiB con 4000 ci_csrf_token juntadas con ',' (http.client la deja pasar) da
        # 4000 veces el '2+' de CodeIgniter. Compararlas de dos en dos, después del reloj, tomaba casi 5 s.
        crudo = 'Set-Cookie: %s\r\n\r\n' % ','.join(['ci_csrf_token=a'] * 4000)
        mensaje = http.client.parse_headers(io.BytesIO(crudo.encode('latin-1')))
        inicio = time.monotonic()
        r = huellas.analizar(200, mensaje, '<p>hola</p>')
        self.assertLess(time.monotonic() - inicio, huellas.TOPE_SEGUNDOS)
        self.assertEqual((por_nombre(r)['CodeIgniter']['version'], r['completo']), ('2+', True))
        # Con más de MAX_VERSIONES distintas sale sin versión, aunque concuerden. Las repetidas cuentan una vez y
        # queda la primera.
        cadena = ['1' + '.0' * i for i in range(huellas.MAX_VERSIONES + 1)]
        candidatas = [(0, v, 'headers', 'x-prueba', 'v' + v, (0, 0)) for v in cadena]
        self.assertIsNone(huellas._elegir_version(candidatas))
        self.assertEqual(huellas._elegir_version(candidatas[:huellas.MAX_VERSIONES])[1], cadena[-2])
        repetidas = [(0, '2.0.1', 'headers', 'x-prueba', 'v2.0.1-%d' % i, (0, 0)) for i in range(5000)]
        self.assertEqual(huellas._elegir_version(repetidas)[4], 'v2.0.1-0')
        self.assertEqual(huellas._elegir_version(repetidas + [(2, '2.0.1.4', 'html', None, '', (0, 0))])[1],
                         '2.0.1.4')
        # MAX_VERSIONES cuenta versiones distintas, no pares (señal, versión): 5 versiones en 9 pares no son muchas.
        pares = [(0, '2.0', 'headers', 'server', 'x/2.0', (0, 5))]
        pares += [(d, '1.%d' % i, 'scriptSrc' if d == 1 else 'html', None, 'v', (0, 1)) for d in (1, 2)
                  for i in range(1, 5)]
        self.assertEqual(huellas._elegir_version(pares)[1], '2.0')
        cadena = [(d, '4' + '.0' * i, 'html', None, '', (0, 0)) for d in (0, 2) for i in range(5)]
        self.assertEqual(huellas._elegir_version(cadena)[1], '4.0.0.0.0')   # 10 pares, 5 versiones

    def test_27_archivos_de_jquery_con_huella_de_cache_y_sufijos(self):
        # Nombres reales: huella de caché de Django y Rails, ';jsessionid=' de JSP y sufijos de compilación.
        casos = {'jQuery': (('https://code.jquery.com/jquery-3.7.1.min.js', '3.7.1'),
                            ('/static/js/jquery-3.6.0.min.5e3a1b2c4d6f.js', '3.6.0'),
                            ('/static/js/jquery-3.6.0.min.0e3a1b2c4d6f.js', '3.6.0'),
                            ('/assets/jquery-3.6.0.min-8f14e45fceea167a5a36dedd4bea2543.js', '3.6.0'),
                            ('/js/jquery-1.12.4.min.js;jsessionid=CIRDAN_FAKE_X', '1.12.4'),
                            ('/js/jquery-1.12.4.js;jsessionid=CIRDAN_FAKE_X?v=1', '1.12.4'),
                            ('/js/jquery-3.5.1.custom.min.js', '3.5.1'), ('/js/jquery-1.11.3-min.js', '1.11.3'),
                            ('/js/jquery-1.8.3_min.js', None), ('/js/jquery-3.6.0.min.js.gz', None),
                            ('/vendor/jquery-3.7.1/jquery.min.js', '3.7.1'),
                            ('/ajax/libs/jquery/3.7.1/jquery.min.js', '3.7.1'),
                            ('/ajax/libs/jquery/3.7.1/jquery.slim.min.js', '3.7.1'),
                            ('https://ajax.aspnetcdn.com/ajax/jQuery/jquery-3.7.1.min.js', '3.7.1'),
                            ('/js/jquery-3.4.1.min.js%3Fv%3D1', None), ('/js/jQuery-3.4.1.MIN.JS', '3.4.1'),
                            ('/js/jquery-3.4.1.min.cjs', '3.4.1'), ('/js/jquery-3.4.1.min.js/', None),
                            ('/lib/jquery/3.4.1/jquery.js?ver=3.4.1', '3.4.1'),
                            ('/js/jquery-2.2.4.min.js?ver=2.2.4#x', '2.2.4'), ('/js/jquery-3.6.0.bundle.js', None),
                            ('/js/jquery-3.6.0.dev.js', None), ('/js/jquery-3.6.0.slim.js', '3.6.0'),
                            ('/js/jquery-3.6.0-patched.min.js', None),
                            ('/static/jquery-3.6.0.min.js?1699999999', '3.6.0'), ('/js/jquery-3.0.0-rc1.js', None),
                            ('/js/jquery-3.0.0-beta1.js', None), ('/js/jquery-3.0.0.min.map.js', None)),
                 'AngularJS': (('/js/angular-1.8.2.min.js', '1.8.2'), ('/js/angular-1.8.2.min.abcdef12.js', '1.8.2'),
                               ('/1.8.2/angular.min.js', '1.8.2'), ('/js/angular-1.8.2.custom.js', '1.8.2')),
                 'React': (('/js/react-15.6.1.min.js', '15.6.1'), ('/15.6.1/react.min.js', '15.6.1'),
                           ('/js/react-16.14.0.production.min.js', '16.14.0'),
                           ('/js/react-with-addons-15.6.1.min.js', '15.6.1')),
                 'Vue.js': (('/js/vue-2.6.14.min.js', '2.6.14'), ('/2.6.14/vue.min.js', '2.6.14'),
                            ('/js/vue-3.2.47.global.prod.js', '3.2.47'), ('/js/vue-2.6.14.runtime.min.js', '2.6.14'),
                            ('/js/vue-2.6.14.common.js', '2.6.14'), ('/js/vue-2.7.14.esm.browser.min.js', '2.7.14'),
                            ('/js/vue.2.6.14.js', '2.6.14'))}
        for nombre, srcs in casos.items():
            for src, version in srcs:
                t = por_nombre(huellas.analizar(200, None, '<script src="%s"></script>' % src))
                self.assertEqual(t[nombre]['version'], version, src)
        # react-dom no es React.
        self.assertNotIn('React', por_nombre(huellas.analizar(200, None, '<script src="/js/react-dom-16.14.0.min.js">'
                                                                         '</script>')))
        # Lo que la forma decidida deja fuera: un sufijo que no es de compilación (-patched, .dev, .bundle, .map) o
        # una extensión que no es .js, .mjs ni .cjs.
        for src in ('/js/jquery-3.6.0-patched.min.js', '/js/jquery-3.6.0.dev.js', '/js/jquery-3.6.0.bundle.js',
                    '/js/jquery-3.0.0.min.map.js', '/js/jquery-3.6.0.min.js.gz'):
            self.assertFalse(huellas._es_propio('jQuery', src), src)
        # Cada sufijo de compilación, también sin versión en el nombre, solo en el alias que lo publica: los de Vue.js
        # en un archivo de jQuery son de un plugin, y 'slim' o 'pack' en uno de Vue.js no son suyos.
        de_vue, de_jquery = ('browser', 'common', 'global', 'runtime', 'esm', 'cjs'), ('slim', 'pack')
        for sufijo in ('min', 'production', 'development', 'prod', 'umd', 'self') + de_vue + de_jquery:
            for nombre, alias, suyos in (('Vue.js', 'vue', de_vue), ('jQuery', 'jquery', de_jquery)):
                propio = sufijo not in de_vue + de_jquery or sufijo in suyos
                src = '/2.6.14/%s.%s.min.js;x=1' % (alias, sufijo.upper())
                self.assertIs(huellas._es_propio(nombre, src), propio, src)
                src = '/js/%s-2.6.14.%s.js' % (alias, sufijo)   # el patrón de Vue.js no calza con el de arriba
                version = por_nombre(huellas.analizar(200, None, '<script src="%s"></script>' % src))[nombre]
                self.assertEqual(version['version'], '2.6.14' if propio else None, src)
        self.assertEqual(huellas.SUFIJOS_DEL_ALIAS, {'vue': de_vue, 'jquery': de_jquery})

    def test_28_el_archivo_propio_calza_entero(self):
        # Plugins y archivos que empiezan con el nombre de la librería: no son suyos y no dan su versión.
        for nombre, src in (('jQuery', '/js/jquery-1.12.4-plugin.js'), ('jQuery', '/js/jquery-1.12.4-ui.min.js'),
                            ('AngularJS', '/js/angular-1.8.2-route.min.js'), ('React', '/js/react-16.14.0-dom.min.js'),
                            ('Vue.js', '/js/vue-2.6.14-compat.min.js'), ('jQuery', '/js/jquery-1.12.4-wp.js'),
                            ('Vue.js', '/js/vue-3d-model.umd.js'), ('AngularJS', '/js/angular-2-local-storage.js'),
                            ('jQuery', '/ajax/libs/jquery.3d/3.0.1/jquery.3d.min.js'),
                            ('jQuery', '/ajax/libs/jquery.3dflipbook/1.2.3/jquery.3dflipbook.min.js'),
                            ('jQuery', '/static/2.1.0/jquery.custom.js'),
                            ('jQuery', '/static/3.1.0/jquery.custom.min.js'),
                            ('jQuery', '/1.12.4/jquery' + '.min' * 60 + '.js'),
                            # Plugins con un sufijo que solo publica Vue.js.
                            ('jQuery', '/ajax/libs/jquery-browser/0.1.0/jquery.browser.min.js'),
                            ('jQuery', '/ajax/libs/jquery-browser-plugin/0.1.0/jquery-browser.min.js'),
                            ('jQuery', '/static/2.1.0/jquery.common.js'),
                            ('jQuery', '/ajax/libs/jquery-global/1.0.0/jquery.global.js'),
                            # Una versión con prerelease no es la del archivo propio: ni 4.0.0 ni 3.0.0.
                            ('jQuery', 'https://code.jquery.com/jquery-4.0.0-beta.2.js'),
                            ('jQuery', 'https://code.jquery.com/jquery-3.0.0-rc1.js'),
                            ('jQuery', 'https://code.jquery.com/jquery-3.0.0-alpha1.js'),
                            ('AngularJS', '/js/angular-1.2.0-rc.3.min.js'),
                            # Tras el corte de mod_pagespeed no se quita otra extensión: 'jquery.cjs' no es propio.
                            ('jQuery', '/ajax/libs/jquery-cjs/2.0.1/jquery.cjs.js.pagespeed.jm.X.js'),
                            ('jQuery', '/static/2.1.0/jquery.js.js.pagespeed.jm.X.js')):
            self.assertFalse(huellas._es_propio(nombre, src), src)
            t = por_nombre(huellas.analizar(200, None, '<script src="%s"></script>' % src))
            self.assertIsNone(t.get(nombre, {}).get('version'), src)
        # El plugin con sufijo de Vue.js ya no tapa el jQuery real de la página.
        plugin = '/ajax/libs/jquery-browser/0.1.0/jquery.browser.min.js'
        t = por_nombre(huellas.analizar(200, None, '<script src="%s"></script><script src="/js/jquery-3.7.1.min.js">'
                                                   '</script>' % plugin))
        self.assertEqual(t['jQuery']['version'], '3.7.1')
        # Un ';' en una carpeta no corta el nombre, y la huella de caché puede empezar con letra. Los .pack de jQuery
        # 1.0 a 1.2.6 y los nombres de mod_pagespeed ('.js.pagespeed.jm.' y '.js.pagespeed.ce.') también son suyos.
        for src, version in (('/app;x=1/js/jquery-1.12.4.min.js', '1.12.4'),
                             ('/static/vendor/jquery/3.6.0/jquery.min.e3a1b2c4d6f5.js', '3.6.0'),
                             ('/assets/jquery-3.6.0.min.self-8f14e45f.js', '3.6.0'),
                             ('/js/jquery-1.2.6.pack.js', '1.2.6'),
                             ('/js/jquery-1.7.2.min.js.pagespeed.jm.6CdKpKE3dq.js', '1.7.2'),
                             ('/wp-includes/js/jquery-1.12.4.min.js.pagespeed.ce.Xn4Q1u2b0c.js', '1.12.4'),
                             ('/ajax/libs/jquery/3.6.0/jquery.min.js.pagespeed.jm.Q1w2E3r4T5.js', '3.6.0')):
            self.assertTrue(huellas._es_propio('jQuery', src), src)
            t = por_nombre(huellas.analizar(200, None, '<script src="%s"></script>' % src))
            self.assertEqual(t['jQuery']['version'], version, src)
        self.assertEqual(huellas._archivo('/js/JQuery-1.7.2.min.js.pagespeed.jm.X.js'), 'jquery-1.7.2.min')
        # MAX_ARCHIVO se mide sin la extensión: 200 caracteres más '.js' sí se comparan, 201 no.
        self.assertEqual(huellas._archivo('/js/' + 'a' * huellas.MAX_ARCHIVO + '.js'), 'a' * huellas.MAX_ARCHIVO)
        self.assertIsNone(huellas._archivo('/js/' + 'a' * (huellas.MAX_ARCHIVO + 1)))
        # Tampoco cuenta la cola de mod_pagespeed.
        cola = '.js.pagespeed.jm.' + 'X' * 40 + '.js'
        self.assertEqual(huellas._archivo('/js/' + 'a' * huellas.MAX_ARCHIVO + cola), 'a' * huellas.MAX_ARCHIVO)
        self.assertIsNone(huellas._archivo('/js/' + 'a' * (huellas.MAX_ARCHIVO + 1) + cola))
        self.assertEqual(huellas._archivo('/js/jquery.cjs.js.pagespeed.jm.X.js'), 'jquery.cjs')
        largo = '/1.2.3/jquery-1.2.3' + '.min' * ((huellas.MAX_ARCHIVO - 12) // 4) + '.js'
        self.assertEqual(len(huellas._archivo(largo)), huellas.MAX_ARCHIVO)
        self.assertEqual(por_nombre(huellas.analizar(200, None, '<script src="%s"></script>' % largo))['jQuery']
                         ['version'], '1.2.3')
        # El plugin ya no tapa la versión real de la página, ni sale con la suya.
        vue = {'schema_version': '1.0.0', 'result': {'name': 'vue', 'releases': [
            {'name': '3', 'isEol': False, 'eolFrom': None, 'latest': {'name': '3.4.0'}},
            {'name': '2', 'isEol': True, 'eolFrom': '2023-12-31', 'latest': {'name': '2.7.16'}}]}}
        for nombre, srcs, version in (
                ('Vue.js', ('https://cdnjs.cloudflare.com/ajax/libs/vue/2.6.14/vue.min.js',
                            'https://unpkg.com/vue-3d-model@1.4.1/dist/vue-3d-model.umd.js'), '2.6.14'),
                ('Vue.js', ('/js/vue-2.6.14.min.js', '/js/vue-3d-model.min.js'), '2.6.14'),
                ('Vue.js', ('/js/vue-3d-model.min.js',), None),
                ('jQuery', ('https://code.jquery.com/jquery-2.2.4.min.js', '/static/2.1.0/jquery.custom.js'), '2.2.4'),
                ('jQuery', ('https://code.jquery.com/jquery-1.12.4.min.js',
                            '/ajax/libs/jquery.3d/3.0.1/jquery.3d.min.js'), '1.12.4'),
                ('jQuery', ('/static/3.1.0/jquery.custom.js',), None),
                ('AngularJS', ('/ajax/libs/angular.js/1.8.2/angular.min.js', '/js/angular-2-local-storage.js'),
                 '1.8.2')):
            cuerpo = ''.join('<script src="%s"></script>' % x for x in srcs)
            t = por_nombre(huellas.analizar(200, None, cuerpo))[nombre]
            self.assertEqual(t['version'], version, srcs)
            if nombre == 'Vue.js' and version is None:
                self.assertEqual(soporte.revisar(t, vue, SITIO, HOY)['estado'], 'sin_version', srcs)

    def test_29_la_version_de_un_src_no_sale_de_una_huella_de_cache(self):
        # El patrón de Vue.js o AngularJS saca '2', '8' o '3' de los dígitos de la huella: no es una versión.
        for nombre, src in (('Vue.js', '/static/js/vue.8f14e45fceea.js'), ('Vue.js', '/static/js/vue.2b14e45fceea.js'),
                            ('Vue.js', '/js/vue-2b14e45f.js'),
                            ('Vue.js', '/assets/vue-0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071.js'),
                            ('AngularJS', '/static/js/angular.8f14e45fceea.js'),
                            ('AngularJS', '/assets/angular-3f2a1b9c4d5e.js')):
            t = por_nombre(huellas.analizar(200, None, '<script src="%s"></script>' % src))[nombre]
            self.assertIsNone(t['version'], src)
        t = por_nombre(huellas.analizar(200, None, '<script src="/static/js/vue.3b14e45fceea.js"></script>'
                                                   '<script src="/js/vue-2.6.14.min.js"></script>'))
        self.assertEqual(t['Vue.js']['version'], '2.6.14')
        def en(src, version):   # el lugar de la última aparición, como el de un grupo del patrón
            inicio = src.rindex(version)
            return inicio, inicio + len(version)
        self.assertFalse(huellas._version_del_src_cuenta('Vue.js', '/js/vue.2b14e45f.js', en('vue.2b', '2')))
        self.assertTrue(huellas._version_del_src_cuenta('Vue.js', '/js/vue-2.6.14.min.js', (8, 14)))
        self.assertFalse(huellas._version_del_src_cuenta('Vue.js', '/js/vue-2.6.14.min.js', None))
        for src, cuenta in (('/js/common.min.js?v=10.0.7', True), ('/js/common.min.js?v=10.0.71', False),
                            ('/js/common.min.js?v=110.0.7', False), ('/js/common.min.js?v=a10.0.7', False)):
            self.assertIs(huellas._version_del_src_cuenta('GLPI', src, en(src[:src.index('10.0.7') + 6], '10.0.7')),
                          cuenta, src)
        # Se mira donde calzó el grupo del patrón, no en todo el src: un 'v2' o un '?v=2' en otra parte de la ruta, en
        # el host o en la URL de la página no vuelven versión el '2' de la huella de caché.
        for url, src in ((None, '/static/v2/js/vue.2b14e45fceea.js'), (None, '/assets-v2/js/vue.2b14e45fceea.js'),
                         (None, '/js/vue.2b14e45fceea.js?v=2'), (None, '/js/vue.2b14e45fceea.js?v2'),
                         ('https://v2.acme-demo.mx/', 'js/vue.2b14e45fceea.js'),
                         ('https://www.acme-demo.mx/v2/inicio', 'static/vue.2b14e45fceea.js')):
            t = por_nombre(huellas.analizar(200, None, '<script src="%s"></script>' % src, url=url))['Vue.js']
            self.assertIsNone(t['version'], (url, src))
            self.assertEqual(soporte.revisar(t, fixture('eol_jquery'), SITIO, HOY)['estado'], 'sin_version', src)
        # Una 'v' pegada delante solo vale después de '-', '@', '_' o '.': la de una carpeta del sitio no.
        for src, nombre, version in (('https://s3.amazonaws.com/builds.handlebarsjs.com/handlebars-v4.7.7.js',
                                      'Handlebars', '4.7.7'),
                                     ('/js/handlebars.runtime-v4.7.7.min.js', 'Handlebars', '4.7.7'),
                                     ('/js/handlebars-V1.3.0.min.js', 'Handlebars', '1.3.0'),
                                     ('https://cdn.jsdelivr.net/gh/foo/hogan@v3.0.2/hogan.min.js', 'Hogan.js', '3.0.2'),
                                     ('/static/v1.10.0/jquery-ui.min.js', 'jQuery UI', None),
                                     ('/build/v1.0.2/dojo/dojo.js', 'Dojo', None),
                                     ('https://polyfill.io/v3/polyfill.min.js?features=default', 'Polyfill', None)):
            t = por_nombre(huellas.analizar(200, None, '<script src="%s"></script>' % src))
            self.assertEqual(t[nombre]['version'], version, src)
        for texto, lugar, suelta in (('-v4.7.7', (2, 7), True), ('@v4.7.7/', (2, 7), True), ('_V4.7.7', (2, 7), True),
                                     ('.v4.7.7', (2, 7), True), ('/v4.7.7/', (2, 7), False), ('v4.7.7', (1, 6), False),
                                     ('dev4.7.7', (3, 8), False), ('-vv4.7.7', (3, 8), False),
                                     ('-v4.7.71', (2, 7), False), ('4.7.7', (0, 5), True), ('/4.7.7', (1, 6), True),
                                     ('a4.7.7', (1, 6), False), ('4.7.7a', (0, 5), False), ('4.7.7', None, False)):
            self.assertIs(huellas._suelta(texto, lugar), suelta, (texto, lugar))
        # El lugar es el del grupo que nombra la plantilla, en su orden ('\\1?\\1:\\2' de Modernizr), o None.
        m = re.search(r'(?:x(\d))?-(\d)', '9-5')
        self.assertEqual((huellas._lugar('\\1?\\1:\\2', m, '5'), huellas._lugar('\\1', m, '5')), ((2, 3), None))
        m = re.search(r'x(\d)?-(\d)', 'x9-5')
        self.assertEqual(huellas._lugar('\\1?\\1:\\2', m, '9'), (1, 2))
        self.assertEqual(huellas._lugar('\\1?\\1:\\2', re.search(r'(\d)-(\d)', '5-5'), '5'), (0, 1))
        self.assertIsNone(huellas._lugar('', m, '9'))

    def test_30_lo_que_corre_despues_del_reloj_no_crece_con_la_respuesta(self):
        # Se mide solo lo que corre después de la última vez que el análisis mira el reloj (las versiones, _es_propio
        # y _version_del_src_cuenta), que no tiene tope de tiempo. Lo de antes ya lo cubre TOPE_SEGUNDOS. El tope de
        # 0.3 s deja margen: aquí toma unos 0.03 s, compilar una regex por detección tomaba 0.7 s con el segundo html
        # y buscar la versión en todo el src, 0.6 s con el tercero.
        ultima = [0.0]

        def reloj():
            ultima[0] = time.monotonic()
            return ultima[0]
        # 126 src de 2 KiB que calzan con los patrones de las cuatro y cuyo archivo es 'jquery' con muchos '.min'.
        cola = '?a=/jquery-1.2.3.js&b=angular-1.js&c=/1/angular.js&d=react-1.2.js&e=/1/react.js&f=vue-1.js&g=/1/vue.js'
        src = '/1.2.3/jquery' + '.min' * ((huellas.MAX_SRC - len(cola) - 24) // 4) + 'x.js' + cola + '&h='
        cuantos = min(huellas.MAX_SCRIPTS, (huellas.MAX_HTML - 100) // (len(src) + 25))
        html = ''.join('<script src="%s%d"></script>' % (src, i) for i in range(cuantos))
        r = huellas.analizar(200, None, html, reloj=reloj)
        self.assertLess(time.monotonic() - ultima[0], 0.3)
        self.assertTrue(r['completo'])
        self.assertEqual({n: t['version'] for n, t in por_nombre(r).items() if n in huellas.ARCHIVOS_PROPIOS},
                         dict.fromkeys(huellas.ARCHIVOS_PROPIOS))
        # Src que calzan con unos 50 patrones de scriptSrc cada uno, con versiones distintas: unas 9000 versiones que
        # revisar después del reloj.
        trozos = ('unpkg.com/aos@{v}/dist/aos.js', '/axios@{v}/axios.min.js', '/clientjs@{v}/', 'clipboard-{v}.js',
                  'darkmode-js@{v}/lib/darkmode-js.min.js', '{v}/dojo/dojo.js', 'jquery.fancybox.js?v={v}',
                  'fingerprintjs2@{v}/', 'flickity/{v}/flickity.min.js', '/@glidejs/glide@{v}', '@{v}/glider.min.js',
                  'handlebars-v{v}.js', 'hogan-.{v}.js', '{v}/hogan.min.js', 'howler@{v}/dist/howler.min.js',
                  '/htmx.org@{v}', 'cdn.jsdelivr.net/npm/intersection-observer@{v}', '{v}/jsrender.min.js',
                  '{v}/jsviews.js', 'koken.js?{v}', '@{v}/list.js', '/{v}/mobx.js?', 'photoswipe/{v}/photoswipe.min.js',
                  'polyfill.io/v{v}', 'prototype-{v}.js', 'quicklink@{v}/dist/quicklink.js',
                  '/react-redux@{v}/react-redux.js', '/react-router@{v}/react-router.js', '/redux@{v}/redux.js',
                  '/{v}/slick.js', '/npm/sweetalert2@{v}', '/npm/swiffy-slider@{v}/', '/{v}/min/tiny-slider.js',
                  '/tippy.js@{v}', 'xregexp-{v}.js', '/{v}/xregexp.js', '//unpkg.com/hyperscript.org@{v}',
                  '@tarekraafat/autocomplete.js@{v}/', '/{v}/crypto-js.js', 'decimal-{v}.js', '/{v}/decimal.js',
                  '/fullPage.js/{v}/', 'jquery-modal/{v}/jquery.modal.min.js', 'jquery-ui-{v}.js', '{v}/jquery-ui.js',
                  '/{v}/libphonenumber.js', 'web-vitals@{v}/dist/web-vitals.js', 'jquery-migrate-{v}.js',
                  'angular-{v}.js', 'react-{v}.js', 'vue-{v}.js', '/jquery-{v}.js')
        srcs = ['/'.join(['/x%d' % i] + [f.format(v='%d.%d.7' % (i + 1, j + 1)) for j, f in enumerate(trozos)])
                for i in range(huellas.MAX_SCRIPTS)]
        cuantos = min(huellas.MAX_SCRIPTS, (huellas.MAX_HTML - 100) // (len(srcs[-1]) + 25))
        html = ''.join('<script src="%s"></script>' % s for s in srcs[:cuantos])
        r = huellas.analizar(200, None, html, reloj=reloj)
        self.assertLess(time.monotonic() - ultima[0], 0.3)
        self.assertEqual((r['completo'], cuantos, len(srcs[-1]) < huellas.MAX_SRC), (True, 186, True))
        self.assertIsNone(por_nombre(r)['Handlebars']['version'])   # más de MAX_VERSIONES distintas
        # Las mismas, todas con la versión '1', detrás de 'v1' repetido 500 veces: revisar cada aparición de la
        # versión en todo el src tomaba 0.6 s después del reloj. Ahora se miran solo las orillas del grupo.
        cola = '/'.join(f.format(v='1') for f in trozos)
        srcs = [('/x%d%s/%s' % (i, 'v1' * 500, cola))[:huellas.MAX_SRC] for i in range(huellas.MAX_SCRIPTS)]
        cuantos = min(huellas.MAX_SCRIPTS, (huellas.MAX_HTML - 100) // (len(srcs[-1]) + 25))
        r = huellas.analizar(200, None, ''.join('<script src="%s"></script>' % s for s in srcs[:cuantos]), reloj=reloj)
        self.assertLess(time.monotonic() - ultima[0], 0.3)
        self.assertEqual((r['completo'], cuantos, por_nombre(r)['Handlebars']['version']), (True, 128, '1'))


class Soporte(unittest.TestCase):
    def test_1_version_sin_soporte(self):
        r = soporte.revisar(tecnologia('Nginx', '1.18.0'), fixture('eol_nginx'), SITIO, HOY)
        self.assertEqual((r['estado'], r['producto'], r['ciclo']), ('sin_soporte', 'nginx', '1.18'))
        h = r['hallazgo']
        self.assertEqual((h['codigo'], h['severidad'], h['clave']), ('outdated_software', 'high', 'nginx'))
        self.assertEqual(h['titulo'], 'Versión sin soporte: Nginx 1.18.0 en www.acme-demo.mx')
        self.assertEqual((h['evidencia']['fin_de_soporte'], h['evidencia']['ultima_del_ciclo']),
                         ('2021-04-20', '1.18.0'))
        self.assertEqual(h['evidencia']['url_fuente'], 'https://endoflife.date/api/v1/products/nginx/')

    def test_2_nunca_la_version_de_una_distribucion(self):
        t = por_nombre(analizar('ubuntu_nginx_wordpress_200'))
        for nombre, producto in (('Nginx', 'eol_nginx'), ('PHP', 'eol_php')):
            r = soporte.revisar(t[nombre], fixture(producto), SITIO, HOY)
            self.assertEqual((r['estado'], r['hallazgo']), ('distribucion', None), nombre)
        t = por_nombre(analizar('centos_apache_php_200'))
        self.assertEqual(soporte.revisar(t['PHP'], fixture('eol_php'), SITIO, HOY)['estado'], 'distribucion')

    def test_3_con_soporte_y_el_dia_del_fin(self):
        self.assertEqual(soporte.revisar(tecnologia('Nginx', '1.27.1'), fixture('eol_nginx'), SITIO, HOY)['estado'],
                         'con_soporte')
        # 1.26 termina el 7 nov: el 6 sigue con soporte y el 7 ya no.
        self.assertEqual(soporte.revisar(tecnologia('Nginx', '1.26.2'), fixture('eol_nginx'), SITIO, HOY)['estado'],
                         'con_soporte')
        r = soporte.revisar(tecnologia('Nginx', '1.26.2'), fixture('eol_nginx'), SITIO,
                            datetime(2026, 11, 7, tzinfo=timezone.utc))
        self.assertEqual(r['estado'], 'sin_soporte')

    def test_4_api_de_antes_y_ciclo_mas_largo(self):
        r = soporte.revisar(tecnologia('PHP', '7.4.33'), fixture('eol_php'), SITIO, HOY)
        self.assertEqual((r['estado'], r['ciclo'], r['hallazgo']['evidencia']['fin_de_soporte']),
                         ('sin_soporte', '7.4', '2022-11-28'))
        self.assertEqual(soporte.revisar(tecnologia('PHP', '8.3.1'), fixture('eol_php'), SITIO, HOY)['estado'],
                         'con_soporte')
        drupal = fixture('eol_drupal')
        self.assertEqual(soporte.revisar(tecnologia('Drupal', '10.2.3'), drupal, SITIO, HOY)['ciclo'], '10.2')
        self.assertEqual(soporte.revisar(tecnologia('Drupal', '10.3.1'), drupal, SITIO, HOY)['estado'], 'con_soporte')
        self.assertEqual(soporte.revisar(tecnologia('Drupal', '7'), drupal, SITIO, HOY)['estado'], 'sin_soporte')
        r = soporte.revisar(tecnologia('jQuery', '1.12.4'), fixture('eol_jquery'), SITIO, HOY)
        self.assertEqual((r['estado'], r['hallazgo']['evidencia']['fin_de_soporte']), ('sin_soporte', None))

    def test_5_sin_dato_nunca_con_soporte(self):
        for respuesta in (None, {}, [], {'result': {}}, {'result': {'releases': 'x'}}, 'texto', [{'cycle': 'abc'}]):
            self.assertEqual(soporte.revisar(tecnologia('Nginx', '1.18.0'), respuesta, SITIO, HOY)['estado'],
                             'sin_dato', respuesta)
        for version in ('1.2', '2.0.1', '1'):   # 1.2 no es 1.24 y 1 no alcanza a 1.1
            self.assertEqual(soporte.revisar(tecnologia('Nginx', version), fixture('eol_nginx'), SITIO, HOY)['estado'],
                             'sin_dato', version)

    def test_6_sin_producto_ni_version(self):
        self.assertEqual(soporte.revisar(tecnologia('Laravel', '9.0'), [], SITIO, HOY)['estado'], 'sin_producto')
        for t in (tecnologia('Nginx', None), tecnologia('Nginx', 'v1.18'), tecnologia('Nginx', '1.18.0', confianza=50),
                  tecnologia('Nginx', '1.18.0', implicada_por='Otra')):
            self.assertEqual(soporte.revisar(t, fixture('eol_nginx'), SITIO, HOY)['estado'], 'sin_version', t)
        self.assertEqual(soporte.revisar(None, None, SITIO, HOY)['estado'], 'sin_producto')

    def test_7_productos_que_existen_en_las_huellas(self):
        datos = huellas.cargar()['tecnologias']
        for nombre, producto in soporte.PRODUCTOS.items():
            self.assertIn(nombre, datos)
            self.assertTrue(soporte.url(producto))
        self.assertIsNone(soporte.url('../x'))
        self.assertIsNone(soporte.url(None))

    def test_8_el_hallazgo_cumple_el_contrato_y_el_catalogo(self):
        self.assertEqual(soporte.CODIGOS, {c: severidades_del_catalogo()[c] for c in soporte.CODIGOS})
        r = soporte.revisar(tecnologia('Nginx', '1.18.0'), fixture('eol_nginx'), SITIO, HOY)
        res = Resultado('acme-demo.mx', 'web', activos=[Activo('subdomain', SITIO)],
                        hallazgos=[como_hallazgo(r['hallazgo'], datetime(2026, 11, 6, tzinfo=timezone.utc))])
        self.assertEqual(validar(res, codigos=list(soporte.CODIGOS) + list(nvd.CODIGOS)), [])


    def test_9_un_ciclo_con_eol_ilegible_es_sin_dato(self):
        # Si el ciclo que calza con la versión no trae un fin legible, no se cae a un ciclo más corto que sí lo trae.
        v1 = {'result': {'releases': [{'name': '10.2', 'isEol': None, 'eolFrom': '2024-12-11T00:00:00Z'},
                                      {'name': '10', 'isEol': False, 'eolFrom': None}]}}
        antes = [{'cycle': '10.2', 'eol': None}, {'cycle': '10', 'eol': False}]
        for respuesta in (v1, antes):
            r = soporte.revisar(tecnologia('Drupal', '10.2.3'), respuesta, SITIO, HOY)
            self.assertEqual((r['estado'], r['ciclo'], r['hallazgo']), ('sin_dato', '10.2', None), respuesta)
            # Una versión de otro ciclo sí usa el que se lee.
            r = soporte.revisar(tecnologia('Drupal', '10.3.1'), respuesta, SITIO, HOY)
            self.assertEqual((r['estado'], r['ciclo']), ('con_soporte', '10'), respuesta)

    def test_10_la_version_necesita_las_partes_de_su_ciclo(self):
        def revisar(cabeceras, nombre, respuesta):
            return soporte.revisar(por_nombre(huellas.analizar(200, cabeceras))[nombre], respuesta, SITIO, HOY)
        # 'Drupal 7' cae en el ciclo 7: Drupal 7 sin soporte es un hallazgo correcto.
        r = revisar([('X-Generator', 'Drupal 7 (https://www.drupal.org)')], 'Drupal', fixture('eol_drupal'))
        self.assertEqual((r['estado'], r['ciclo']), ('sin_soporte', '7'))
        # 'Drupal 10' no dice si es 10.2 o 10.3, aunque haya un ciclo 10.
        r = revisar([('X-Generator', 'Drupal 10 (https://www.drupal.org)')], 'Drupal', fixture('eol_drupal'))
        self.assertEqual((r['estado'], r['ciclo'], r['hallazgo']), ('sin_dato', None, None))
        apache = [{'cycle': '2.4', 'eol': False}, {'cycle': '2.2', 'eol': '2017-07-11'}]
        self.assertEqual(revisar([('Server', 'Apache/2.4')], 'Apache HTTP Server', apache)['estado'], 'con_soporte')
        self.assertEqual(revisar([('Server', 'Apache/2')], 'Apache HTTP Server', apache)['estado'], 'sin_dato')
        self.assertEqual(revisar([('X-Powered-By', 'PHP/7')], 'PHP', fixture('eol_php'))['estado'], 'sin_dato')
        self.assertEqual(revisar([('Server', 'nginx/1')], 'Nginx', fixture('eol_nginx'))['estado'], 'sin_dato')
        lista = [{'ciclo': '10.2', 'eol': False}, {'ciclo': '10', 'eol': False}, {'ciclo': '7', 'eol': True}]
        self.assertIsNone(soporte.ciclo_de('10', lista))
        self.assertEqual([soporte.ciclo_de(v, lista)['ciclo'] for v in ('10.2.3', '10.3.1', '7', '7.98')],
                         ['10.2', '10', '7', '7'])

    def test_11_origen_sin_confirmar_en_la_evidencia(self):
        # nginx/1.18.0 sin marca (Debian 11 lo manda así): sí da hallazgos, con el aviso en la evidencia.
        t = por_nombre(analizar('nginx_drupal_200'))
        self.assertEqual((t['Nginx']['version'], t['Nginx']['distribucion'], t['Nginx']['origen_sin_confirmar']),
                         ('1.18.0', None, True))
        r = soporte.revisar(t['Nginx'], fixture('eol_nginx'), SITIO, HOY)
        self.assertEqual((r['estado'], r['hallazgo']['evidencia']['origen_sin_confirmar']), ('sin_soporte', True))
        r = nvd.revisar(t['Nginx'], fixture('nvd_nginx_1.18.0'), SITIO)
        self.assertEqual(r['estado'], 'con_cve')
        self.assertEqual({h['evidencia']['origen_sin_confirmar'] for h in r['hallazgos']}, {True})
        # Drupal no lo empaqueta la distribución con esa cabecera.
        self.assertFalse(t['Drupal']['origen_sin_confirmar'])
        r = soporte.revisar(t['Drupal'], fixture('eol_drupal'), SITIO, HOY)
        self.assertEqual((r['estado'], r['hallazgo']['evidencia']['origen_sin_confirmar']), ('sin_soporte', False))
        # Con la marca sigue saliendo 'distribucion', sin hallazgos.
        t = por_nombre(huellas.analizar(200, [('Server', 'nginx/1.18.0 (Ubuntu)')]))
        self.assertEqual(soporte.revisar(t['Nginx'], fixture('eol_nginx'), SITIO, HOY)['estado'], 'distribucion')
        self.assertEqual(nvd.revisar(t['Nginx'], fixture('nvd_nginx_1.18.0'), SITIO)['estado'], 'distribucion')
        self.assertFalse(t['Nginx']['origen_sin_confirmar'])
        # El PHP de deb.sury.org sigue la versión oficial, y el Apache con '(Unix)' no es de la lista.
        t = por_nombre(huellas.analizar(200, [('Server', 'Apache/2.4.58 (Unix)'),
                                              ('X-Powered-By', 'PHP/8.1.27-1+ubuntu22.04.1+deb.sury.org+1')]))
        self.assertEqual((t['PHP']['origen_sin_confirmar'], t['Apache HTTP Server']['origen_sin_confirmar']),
                         (False, False))
        r = nvd.revisar(t['PHP'], fixture('nvd_nginx_1.18.0'), SITIO)
        self.assertEqual({h['evidencia']['origen_sin_confirmar'] for h in r['hallazgos']}, {False})
        # PHP de RHEL ('PHP/7.4.33', sin sufijo) junto a un nginx sin marca.
        t = por_nombre(huellas.analizar(200, [('Server', 'nginx/1.20.1'), ('X-Powered-By', 'PHP/7.4.33')]))
        self.assertEqual((t['PHP']['origen_sin_confirmar'], t['Nginx']['origen_sin_confirmar']), (True, True))
        # Una tecnología armada a mano sin la llave: por el nombre.
        self.assertTrue(huellas.origen_sin_confirmar(tecnologia('Nginx', '1.18.0')))
        self.assertFalse(huellas.origen_sin_confirmar(tecnologia('Nginx', '1.18.0', distribucion='Debian')))
        self.assertFalse(huellas.origen_sin_confirmar(tecnologia('Drupal', '7.98')))
        self.assertEqual(huellas.EMPAQUETAN_SIN_MARCA, ('Nginx', 'PHP', 'Perl', 'Python'))
        # El nombre armado a mano se compara sin distinguir mayúsculas.
        for nombre in ('nginx', 'NGINX', 'php'):
            t = dict(tecnologia('Nginx', '1.18.0'), nombre=nombre)
            self.assertTrue(huellas.origen_sin_confirmar(t), nombre)
            r = nvd.revisar(t, fixture('nvd_nginx_1.18.0'), SITIO)
            self.assertEqual({h['evidencia']['origen_sin_confirmar'] for h in r['hallazgos']}, {True}, nombre)
            self.assertFalse(huellas.origen_sin_confirmar(dict(t, distribucion='Debian')), nombre)
        self.assertFalse(huellas.origen_sin_confirmar(dict(tecnologia('Nginx', '1.18.0'), nombre=None)))


class Nvd(unittest.TestCase):
    def test_1_cpe_con_version(self):
        cpe = 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*'
        self.assertEqual(nvd.cpe_con_version(cpe, '1.18.0'), 'cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*')
        self.assertEqual(nvd.cpe_con_version(cpe, '2.4.0-Beta'), 'cpe:2.3:a:nginx:nginx:2.4.0-beta:*:*:*:*:*:*:*')
        for version in ('', None, 'v1.0.0', ' 1.0.0'):
            self.assertIsNone(nvd.cpe_con_version(cpe, version), version)
        # Versiones de 3 partes, que con_precision sí acepta: las rechaza _VERSION.
        for version in ('1.0.0 (Ubuntu)', '1.0.0:0', '1.0.0*', '1.0.0/x', '1.0.0?', '1.0.0\\-1', '1.0.0+1',
                        '1.0.0~rc1', '1.0.0%2f', '1.0.0ñ', '1.0.0\n', '1.0.0' + '1' * 40):
            self.assertTrue(nvd.con_precision(cpe, version), version)
            self.assertIsNone(nvd.cpe_con_version(cpe, version), version)
        for malo in ('cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*', 'cpe:/a:nginx:nginx', 'cpe:2.3:a:nginx', None,
                     'cpe:2.3:a:x\\:y:nginx:*:*:*:*:*:*:*:*'):
            self.assertIsNone(nvd.cpe_con_version(malo, '1.0.0'), malo)
        self.assertEqual(nvd.url('cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'),
                         'https://services.nvd.nist.gov/rest/json/cves/2.0'
                         '?cpeName=cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*&isVulnerable&noRejected')
        for malo in (None, 1, b'cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'):   # sin CPE con versión, sin URL
            self.assertIsNone(nvd.url(malo), malo)
        # Solo cadenas de CPE 2.3: un espacio adentro, un signo sin escapar o algo que no es ASCII no pasan.
        for malo in ('cpe:2.3:a:glpi project:glpi:*:*:*:*:*:*:*:*',
                     'cpe:2.3:a:weblication:cms_core_&_grid:*:*:*:*:*:*:*:*',
                     'cpe:2.3:a:erlang:erlang%2fotp:*:*:*:*:*:*:*:*', 'cpe:2.3:a:x:y z:*:*:*:*:*:*:*:*',
                     'cpe:2.3:a:x:ñandú:*:*:*:*:*:*:*:*', 'cpe:2.3:a:x::*:*:*:*:*:*:*:*',
                     'cpe:2.3:a:x:a*b:*:*:*:*:*:*:*:*'):
            self.assertIsNone(nvd.cpe_con_version(malo, '1.0.0'), malo)
        self.assertEqual(nvd.cpe_con_version('cpe:2.3:a:weblication:cms_core_\\&_grid:*:*:*:*:*:*:*:*', '5.3.1'),
                         'cpe:2.3:a:weblication:cms_core_\\&_grid:5.3.1:*:*:*:*:*:*:*')
        self.assertEqual(nvd.cpe_con_version('cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*', '26.1.2'),
                         'cpe:2.3:a:erlang:erlang\\/otp:26.1.2:*:*:*:*:*:*:*')
        # Sin precisión (con_precision) no hay CPE con versión, así que url() nunca se arma para 'nginx/1'.
        drupal = 'cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*'
        for c, version in ((cpe, '1'), (cpe, '1.18'), (cpe, '2.4-beta'), (drupal, '7'), (drupal, '10.2')):
            self.assertIsNone(nvd.cpe_con_version(c, version), version)
        self.assertEqual(nvd.cpe_con_version(drupal, '7.98'), 'cpe:2.3:a:drupal:drupal:7.98:*:*:*:*:*:*:*')

    def test_2_una_cve_por_hallazgo(self):
        r = nvd.revisar(tecnologia('Nginx', '1.18.0'), fixture('nvd_nginx_1.18.0'), SITIO)
        self.assertEqual((r['estado'], r['completa'], r['omitidas']), ('con_cve', True, []))
        self.assertEqual([h['clave'] for h in r['hallazgos']],
                         ['CVE-2099-0102|nginx:nginx', 'CVE-2099-0101|nginx:nginx', 'CVE-2098-12345|nginx:nginx'])
        self.assertEqual([h['evidencia']['cve'] for h in r['hallazgos']],
                         ['CVE-2099-0102', 'CVE-2099-0101', 'CVE-2098-12345'])
        h = r['hallazgos'][1]
        self.assertEqual((h['codigo'], h['severidad']), ('known_vulnerability', 'medium'))
        self.assertEqual(h['titulo'], 'Vulnerabilidad conocida CVE-2099-0101 por la versión de Nginx 1.18.0 en '
                                      'www.acme-demo.mx')
        self.assertEqual((h['evidencia']['cvss'], h['evidencia']['cvss_metrica']), (7.5, 'cvssMetricV31'))
        self.assertTrue(h['evidencia']['deducida_por_version'])
        filas = {f['cve_id']: f for f in r['cves']}
        self.assertEqual(filas['CVE-2099-0101']['description'], 'Fake test vulnerability, written by hand.')
        self.assertEqual(filas['CVE-2099-0101']['cvss_vector'], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')
        self.assertEqual(filas['CVE-2099-0102']['cvss_base_score'], 5.0)
        self.assertEqual(r['hallazgos'][0]['evidencia']['cvss_metrica'], 'cvssMetricV2')
        self.assertEqual((filas['CVE-2098-12345']['cvss_base_score'], filas['CVE-2098-12345']['published_at']),
                         (None, None))   # un puntaje de 11 y una fecha que no es fecha no pasan
        self.assertNotIn('CVE-2098-0103', filas)   # rechazada
        for f in r['cves']:
            self.assertRegex(f['cve_id'], r'^CVE-[0-9]{4}-[0-9]{4,}$')   # el CHECK de cves.cve_id

    def test_2b_filas_con_solo_columnas_de_cves_y_fecha_con_zona(self):
        # Las columnas de CREATE TABLE cves en la migración 001: un INSERT con las llaves de la fila no falla.
        sql = (RAIZ / 'db' / 'migraciones' / '001_esquema_inicial.sql').read_text(encoding='utf-8')
        tabla = re.search(r'CREATE TABLE cves \((.*?)\n\);', sql, re.S).group(1)
        columnas = {linea.split()[0] for linea in tabla.strip().splitlines()}
        self.assertLessEqual(set(nvd.COLUMNAS_CVES), columnas)
        r = nvd.revisar(tecnologia('Nginx', '1.18.0'), fixture('nvd_nginx_1.18.0'), SITIO)
        for f in r['cves']:
            self.assertEqual(tuple(f), nvd.COLUMNAS_CVES, f['cve_id'])
        # La NVD da la hora en UTC sin zona: la fila lleva '+00:00' para que timestamptz no la lea en hora de México.
        publicada = {f['cve_id']: f['published_at'] for f in r['cves']}
        self.assertEqual(publicada['CVE-2099-0101'], '2099-01-02T10:00:00.000+00:00')
        self.assertEqual(datetime.fromisoformat(publicada['CVE-2099-0102']),
                         datetime(2099, 1, 3, 10, tzinfo=timezone.utc))
        # Si ya trae zona, se respeta.
        for fecha in ('2099-01-02T10:00:00Z', '2099-01-02T10:00:00.5-06:00'):
            leidas = nvd.leer({'totalResults': 1, 'vulnerabilities': [{'cve': {'id': 'CVE-2099-0001',
                                                                               'published': fecha}}]})
            self.assertEqual(leidas['cves'][0]['published_at'], fecha)
        for mala in ('2099-01-02T10:00:00+0600', '2099-01-02 10:00:00', '2099-01-02T10:00:00+06:00x'):
            leidas = nvd.leer({'totalResults': 1, 'vulnerabilities': [{'cve': {'id': 'CVE-2099-0001',
                                                                               'published': mala}}]})
            self.assertIsNone(leidas['cves'][0]['published_at'], mala)

    def test_2c_published_at_solo_con_una_fecha_y_hora_valida(self):
        # Postgres rechazaría la fila en cves.published_at, y con ella todo el lote.
        def publicada(fecha):
            leidas = nvd.leer({'totalResults': 1, 'vulnerabilities': [{'cve': {'id': 'CVE-2099-0001',
                                                                               'published': fecha}}]})
            return leidas['cves'][0]['published_at']
        for mala in ('2021-06-01T10:00:00+99:99', '2021-02-30T25:61:00', '2021-02-30T10:00:00',
                     '2021-06-01T10:00:60', '2021-06-01T10:00:00+14:01', '2021-06-01T10:00:00-15:00',
                     '2021-06-01T10:00:00+05:99', '0000-01-01T00:00:00'):
            self.assertIsNone(publicada(mala), mala)
        for buena, esperada in (('2021-06-01T10:00:00+14:00', '2021-06-01T10:00:00+14:00'),
                                ('2021-06-01T10:00:00.25-14:00', '2021-06-01T10:00:00.25-14:00'),
                                ('2024-02-29T23:59:59', '2024-02-29T23:59:59+00:00')):
            self.assertEqual(publicada(buena), esperada)
            self.assertIsNotNone(datetime.fromisoformat(esperada).utcoffset())

    def test_3_nunca_la_version_de_una_distribucion(self):
        t = por_nombre(analizar('ubuntu_nginx_wordpress_200'))['Nginx']
        r = nvd.revisar(t, fixture('nvd_nginx_1.18.0'), SITIO)
        self.assertEqual((r['estado'], r['hallazgos'], r['cpe']),
                         ('distribucion', [], 'cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*'))

    def test_4_tope_y_respuesta_incompleta(self):
        respuesta = {'startIndex': 0, 'totalResults': 40, 'resultsPerPage': 30,
                     'vulnerabilities': [{'cve': {'id': 'CVE-2099-%04d' % (1000 + i)}} for i in range(30)]}
        r = nvd.revisar(tecnologia('Nginx', '1.18.0'), respuesta, SITIO)
        self.assertEqual(len(r['hallazgos']), nvd.MAX_CVE)
        self.assertEqual(r['hallazgos'][0]['clave'], 'CVE-2099-1029|nginx:nginx')
        self.assertEqual(r['omitidas'], ['CVE-2099-%04d' % (1000 + i) for i in range(4, -1, -1)])
        self.assertFalse(r['completa'])

    def test_5_sin_dato_y_sin_cve(self):
        for respuesta in (None, [], {}, {'vulnerabilities': 'x'}, 'texto'):
            self.assertEqual(nvd.revisar(tecnologia('Nginx', '1.18.0'), respuesta, SITIO)['estado'], 'sin_dato')
        r = nvd.revisar(tecnologia('Nginx', '1.18.0'), {'totalResults': 0, 'startIndex': 0, 'vulnerabilities': []},
                        SITIO)
        self.assertEqual((r['estado'], r['completa']), ('sin_cve', True))
        # Sin CVE de una respuesta incompleta o con entradas que no se pudieron leer: no se sabe, nunca 0 CVE.
        ilegibles = [{'cve': {'id': 'CVE-2021-23017-x'}}, {'sin': 'cve'}, 7]
        for respuesta in ({'totalResults': 40, 'startIndex': 0, 'vulnerabilities': []},
                          {'totalResults': 3, 'startIndex': 0, 'vulnerabilities': ilegibles},
                          {'totalResults': 0, 'startIndex': 5, 'vulnerabilities': []},
                          {'vulnerabilities': []}):
            r = nvd.revisar(tecnologia('Nginx', '1.18.0'), respuesta, SITIO)
            self.assertEqual((r['estado'], r['completa'], r['hallazgos']), ('sin_dato', False, []), respuesta)
        # Con CVE sigue 'con_cve', y 'completa' dice que se tiró algo.
        respuesta = {'totalResults': 4, 'startIndex': 0,
                     'vulnerabilities': ilegibles + [{'cve': {'id': 'CVE-2099-0101'}}]}
        r = nvd.revisar(tecnologia('Nginx', '1.18.0'), respuesta, SITIO)
        self.assertEqual((r['estado'], r['completa'], [h['clave'] for h in r['hallazgos']]),
                         ('con_cve', False, ['CVE-2099-0101|nginx:nginx']))
        self.assertEqual(nvd.leer(respuesta)['descartadas'], 3)
        # Una rechazada no es ilegible: la respuesta sigue completa.
        r = nvd.revisar(tecnologia('Nginx', '1.18.0'), {'totalResults': 1, 'startIndex': 0, 'vulnerabilities': [
            {'cve': {'id': 'CVE-2099-0101', 'vulnStatus': 'Rejected'}}]}, SITIO)
        self.assertEqual((r['estado'], r['completa']), ('sin_cve', True))
        for t in (tecnologia('Nginx', None), tecnologia('Nginx', '1.18.0', confianza=75),
                  tecnologia('Nginx', '1.18.0', implicada_por='X'), tecnologia('Vue.js', '2.6.14')):
            self.assertEqual(nvd.revisar(t, fixture('nvd_nginx_1.18.0'), SITIO)['estado'], 'sin_version', t['nombre'])

    def test_6_cumple_el_contrato_y_el_catalogo(self):
        self.assertEqual(nvd.CODIGOS, {c: severidades_del_catalogo()[c] for c in nvd.CODIGOS})
        self.assertEqual(nvd.CODIGOS['known_vulnerability'], shodan.CODIGOS['known_vulnerability'])
        r = nvd.revisar(tecnologia('Nginx', '1.18.0'), fixture('nvd_nginx_1.18.0'), SITIO)
        ahora = datetime(2026, 11, 6, tzinfo=timezone.utc)
        res = Resultado('acme-demo.mx', 'web', activos=[Activo('subdomain', SITIO)],
                        hallazgos=[como_hallazgo(h, ahora) for h in r['hallazgos']])
        self.assertEqual(validar(res, codigos=list(soporte.CODIGOS) + list(nvd.CODIGOS)), [])
        self.assertEqual(len({h.huella for h in res.hallazgos}), len(res.hallazgos))

    def test_7_la_misma_cve_en_dos_tecnologias_del_sitio(self):
        # Drupal y el jQuery que trae con la misma CVE: dos hallazgos que no chocan en contrato.validar.
        cuerpo = ('<meta name="generator" content="Drupal 7.98 (https://www.drupal.org)">'
                  '<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>')
        t = por_nombre(huellas.analizar(200, None, cuerpo))
        respuesta = {'totalResults': 1, 'startIndex': 0, 'vulnerabilities': [
            {'cve': {'id': 'CVE-2020-11022', 'published': '2020-04-29T22:15:11.903'}}]}
        ahora = datetime(2026, 11, 9, tzinfo=timezone.utc)
        hallazgos, filas = [], []
        for nombre in ('Drupal', 'jQuery'):
            r = nvd.revisar(t[nombre], respuesta, SITIO)
            self.assertEqual(r['estado'], 'con_cve', nombre)
            hallazgos += [como_hallazgo(h, ahora) for h in r['hallazgos']]
            filas += r['cves']
        res = Resultado('acme-demo.mx', 'web', activos=[Activo('subdomain', SITIO)], hallazgos=hallazgos)
        self.assertEqual(validar(res, codigos=list(soporte.CODIGOS) + list(nvd.CODIGOS)), [])
        self.assertEqual([h.clave for h in hallazgos], ['CVE-2020-11022|drupal:drupal', 'CVE-2020-11022|jquery:jquery'])
        # Las filas de cves sí se repiten: la visita las une por cve_id.
        self.assertEqual([f['cve_id'] for f in filas], ['CVE-2020-11022', 'CVE-2020-11022'])
        # La clave no lleva la versión: es la misma entre corridas.
        otra = nvd.revisar(tecnologia('jQuery', '3.4.0'), respuesta, SITIO)
        self.assertEqual(otra['hallazgos'][0]['clave'], 'CVE-2020-11022|jquery:jquery')
        self.assertEqual(nvd.clave('CVE-2021-23017', 'cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'),
                         'CVE-2021-23017|nginx:nginx')

    def test_8_solo_versiones_con_precision(self):
        respuesta = {'totalResults': 1, 'startIndex': 0, 'vulnerabilities': [{'cve': {'id': 'CVE-2018-7600'}}]}

        def revisar(cabeceras, nombre, cuerpo=None):
            return nvd.revisar(por_nombre(huellas.analizar(200, cabeceras, cuerpo))[nombre], respuesta, SITIO)
        for cabeceras, nombre in (([('X-Generator', 'Drupal 7 (https://www.drupal.org)')], 'Drupal'),
                                  ([('X-Generator', 'Drupal 10.2 (https://www.drupal.org)')], 'Drupal'),
                                  ([('Server', 'Apache/2.4')], 'Apache HTTP Server'),
                                  ([('X-Powered-By', 'PHP/7')], 'PHP'), ([('Server', 'nginx/1')], 'Nginx'),
                                  ([('Server', 'nginx/1.18')], 'Nginx')):
            r = revisar(cabeceras, nombre)
            self.assertEqual((r['estado'], r['cpe'], r['hallazgos']), ('sin_version', None, []), cabeceras)
        # Los de DOS_PARTES sí se consultan con 2 partes, y con 3 o más se consulta todo.
        for cabeceras, nombre, cuerpo in (
                ([('X-Generator', 'Drupal 7.98 (https://www.drupal.org)')], 'Drupal', None),
                (None, 'WordPress', '<meta name="generator" content="WordPress 6.4">'),
                ([('Server', 'Microsoft-IIS/10.0')], 'IIS', None),
                ([('Server', 'Apache/2.4.58')], 'Apache HTTP Server', None),
                ([('Server', 'nginx/1.18.0')], 'Nginx', None),
                ([('X-AspNet-Version', '4.0.30319')], 'Microsoft ASP.NET', None)):
            self.assertEqual(revisar(cabeceras, nombre, cuerpo)['estado'], 'con_cve', (cabeceras, cuerpo))
        self.assertEqual(revisar(None, 'WordPress', '<meta name="generator" content="WordPress 6">')['estado'],
                         'sin_version')
        cpe = 'cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*'
        self.assertEqual([nvd.con_precision(cpe, v) for v in ('7.98', '6.38', '10.2', '10.2.3', '7', None)],
                         [True, True, False, True, False, False])
        self.assertTrue(nvd.con_precision('cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*', '2.4.0-beta'))
        self.assertFalse(nvd.con_precision('cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*', '2.4-beta'))

    def test_9_productos_de_dos_partes(self):
        # Sus patrones del JSON dan 2 partes en el formato normal: 'Quick.Cms v6.7', 'prototype-1.7.js',
        # 'X-Lift-Version: 2.6', 'GlassFish Server Open Source Edition 4.1' y 'HP-iLO-Server/1.30'.
        respuesta = {'totalResults': 1, 'startIndex': 0, 'vulnerabilities': [{'cve': {'id': 'CVE-2018-7600'}}]}
        for cabeceras, cuerpo, nombre, version in (
                (None, '<meta name="generator" content="Quick.Cms v6.7">', 'Quick.CMS', '6.7'),
                (None, '<script src="/js/prototype-1.7.js"></script>', 'Prototype', '1.7'),
                ([('X-Lift-Version', '2.6')], None, 'Lift', '2.6'),
                ([('Server', 'GlassFish Server Open Source Edition 4.1')], None, 'GlassFish', '4.1'),
                ([('Server', 'HP-iLO-Server/1.30')], None, 'HP iLO', '1.30')):
            t = por_nombre(huellas.analizar(200, cabeceras, cuerpo))[nombre]
            self.assertEqual((t['version'], t['confianza']), (version, 100), nombre)
            self.assertTrue(nvd.con_precision(t['cpe'], version), nombre)
            self.assertEqual(nvd.revisar(t, respuesta, SITIO)['estado'], 'con_cve', nombre)
            self.assertFalse(nvd.con_precision(t['cpe'], version.split('.')[0]), nombre)
        t = por_nombre(huellas.analizar(200, None, '<meta name="generator" content="Quick.Cms v6">'))['Quick.CMS']
        self.assertEqual(nvd.revisar(t, respuesta, SITIO)['estado'], 'sin_version')


class Textos(unittest.TestCase):
    def test_1_sin_valores_reales_en_los_fixtures(self):
        revisadas = []
        for archivo in sorted(FIXTURES.glob('*.json')) + sorted(FIXTURES_BORDE.glob('*.json')):
            datos = json.loads(archivo.read_text(encoding='utf-8'))
            if archivo.parent == FIXTURES:   # las de endoflife.date de antes son una lista con la nota en la primera
                nota = datos[0] if isinstance(datos, list) else datos
                self.assertIn('a mano', nota['_nota'], archivo.name)
            for nombre, valor in datos.get('cabeceras', []) if isinstance(datos, dict) else ():
                if nombre.lower() != 'set-cookie':
                    continue
                for cookie in cookies_de(valor):
                    revisadas.append(cookie)
                    self.assertTrue(cookie[1].startswith('CIRDAN_FAKE_'), (archivo.name, cookie))
            # Además, sobre todo el texto del fixture: un valor de sesión real en el cuerpo tampoco pasa.
            for valor in valores_de_sesion(json.dumps(datos)):
                self.assertTrue(valor.startswith('CIRDAN_FAKE_'), (archivo.name, valor))
        # Todas las cookies de los fixtures, también las que llegan juntadas con ', '.
        self.assertGreaterEqual({n for n, _ in revisadas}, {'PHPSESSID', 'ASP.NET_SessionId', '__cf_bm',
                                                            'laravel_session'})

    def test_2_la_revision_de_cookies_ve_cada_una(self):
        juntas = 'a=CIRDAN_FAKE_a; expires=Thu, 05-Nov-2026 20:00:00 GMT; path=/, XSRF-TOKEN=real; path=/'
        self.assertEqual(cookies_de(juntas), [('a', 'CIRDAN_FAKE_a'), ('XSRF-TOKEN', 'real')])
        self.assertEqual(cookies_de('ASP.NET_SessionId=abc123; HttpOnly'), [('ASP.NET_SessionId', 'abc123')])

    def test_3_la_revision_del_texto_ve_el_cuerpo(self):
        cuerpo = json.dumps({'cuerpo': '<p>PHPSESSID=abc123real; path=/</p>', 'cabeceras': [
            ['Set-Cookie', 'laravel_session=CIRDAN_FAKE_x; path=/']]})
        self.assertEqual(valores_de_sesion(cuerpo), ['abc123real', 'CIRDAN_FAKE_x'])
        self.assertEqual(valores_de_sesion(json.dumps({'a': 'phpsessid=Real1; ASP.NET_SessionId=Real2'})),
                         ['Real1', 'Real2'])


if __name__ == '__main__':
    unittest.main()
