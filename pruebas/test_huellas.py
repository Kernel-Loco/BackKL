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
            if 'cpe' in x and nombre != 'Angular':
                self.assertEqual(nvd.cpe_con_version(x['cpe'], '1.0').split(':')[5], '1.0', nombre)
        # El de Angular trae 14 partes en Wappalyzer 6.10.54: nvd.py no lo arregla ni lo consulta.
        self.assertEqual(t['Angular']['cpe'].count(':'), 13)
        self.assertIsNone(nvd.cpe_con_version(t['Angular']['cpe'], '17.0.1'))
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
        self.assertEqual(sorted(e['cookies']), ['laravel_session'])   # el Expires con coma no parte la cookie
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
            inicio = time.monotonic()
            r = huellas.analizar(200, cabeceras, texto, scripts=[texto[:huellas.MAX_SCRIPT]] * 4)
            peor = max(peor, time.monotonic() - inicio)
            self.assertIsInstance(r['tecnologias'], list, base)
        self.assertLess(peor, huellas.TOPE_SEGUNDOS + 1.0)


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


class Nvd(unittest.TestCase):
    def test_1_cpe_con_version(self):
        cpe = 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*'
        self.assertEqual(nvd.cpe_con_version(cpe, '1.18.0'), 'cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*')
        self.assertEqual(nvd.cpe_con_version(cpe, '2.4.0-Beta'), 'cpe:2.3:a:nginx:nginx:2.4.0-beta:*:*:*:*:*:*:*')
        for version in ('', None, 'v1', '1.0 (Ubuntu)', '1:0', '1*', '1.0/x', '1' * 40):
            self.assertIsNone(nvd.cpe_con_version(cpe, version), version)
        for malo in ('cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*', 'cpe:/a:nginx:nginx', 'cpe:2.3:a:nginx', None,
                     'cpe:2.3:a:x\\:y:nginx:*:*:*:*:*:*:*:*'):
            self.assertIsNone(nvd.cpe_con_version(malo, '1.0'), malo)
        self.assertEqual(nvd.url('cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'),
                         'https://services.nvd.nist.gov/rest/json/cves/2.0'
                         '?cpeName=cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*&isVulnerable&noRejected')

    def test_2_una_cve_por_hallazgo(self):
        r = nvd.revisar(tecnologia('Nginx', '1.18.0'), fixture('nvd_nginx_1.18.0'), SITIO)
        self.assertEqual((r['estado'], r['completa'], r['omitidas']), ('con_cve', True, []))
        self.assertEqual([h['clave'] for h in r['hallazgos']], ['CVE-2099-0102', 'CVE-2099-0101', 'CVE-2098-12345'])
        h = r['hallazgos'][1]
        self.assertEqual((h['codigo'], h['severidad']), ('known_vulnerability', 'medium'))
        self.assertEqual(h['titulo'], 'Vulnerabilidad conocida CVE-2099-0101 por la versión de Nginx 1.18.0 en '
                                      'www.acme-demo.mx')
        self.assertEqual((h['evidencia']['cvss'], h['evidencia']['cvss_metrica']), (7.5, 'cvssMetricV31'))
        self.assertTrue(h['evidencia']['deducida_por_version'])
        filas = {f['cve_id']: f for f in r['cves']}
        self.assertEqual(filas['CVE-2099-0101']['description'], 'Fake test vulnerability, written by hand.')
        self.assertEqual(filas['CVE-2099-0101']['cvss_vector'], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')
        self.assertEqual((filas['CVE-2099-0102']['cvss_base_score'], filas['CVE-2099-0102']['cvss_metrica']),
                         (5.0, 'cvssMetricV2'))
        self.assertEqual((filas['CVE-2098-12345']['cvss_base_score'], filas['CVE-2098-12345']['published_at']),
                         (None, None))   # un puntaje de 11 y una fecha que no es fecha no pasan
        self.assertNotIn('CVE-2098-0103', filas)   # rechazada
        for f in r['cves']:
            self.assertRegex(f['cve_id'], r'^CVE-[0-9]{4}-[0-9]{4,}$')   # el CHECK de cves.cve_id

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
        self.assertEqual(r['hallazgos'][0]['clave'], 'CVE-2099-1029')
        self.assertEqual(r['omitidas'], ['CVE-2099-%04d' % (1000 + i) for i in range(4, -1, -1)])
        self.assertFalse(r['completa'])

    def test_5_sin_dato_y_sin_cve(self):
        for respuesta in (None, [], {}, {'vulnerabilities': 'x'}, 'texto'):
            self.assertEqual(nvd.revisar(tecnologia('Nginx', '1.18.0'), respuesta, SITIO)['estado'], 'sin_dato')
        r = nvd.revisar(tecnologia('Nginx', '1.18.0'), {'totalResults': 0, 'startIndex': 0, 'vulnerabilities': []},
                        SITIO)
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


class Textos(unittest.TestCase):
    def test_1_sin_valores_reales_en_los_fixtures(self):
        for archivo in sorted(FIXTURES.glob('*.json')):
            datos = json.loads(archivo.read_text(encoding='utf-8'))
            texto = json.dumps(datos)
            self.assertIn('_nota', texto, archivo.name)
            self.assertIn('a mano', texto, archivo.name)
            for cookie in re.findall(r'(?:Set-Cookie|PHPSESSID|session)[^"]*?=([^;" ]+)', texto):
                if cookie not in ('/', 'http'):
                    self.assertTrue(cookie.startswith('CIRDAN_FAKE_'), (archivo.name, cookie))


if __name__ == '__main__':
    unittest.main()
