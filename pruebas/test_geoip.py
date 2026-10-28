"""Pruebas de la geolocalización con DB-IP Lite (#15b, RC-166), sin red y sin maxminddb: las bases son lectores falsos
con .get, como el que da maxminddb.open_database.

    python -m unittest -v pruebas/test_geoip.py

Los registros tienen la forma de las bases de DB-IP (country.iso_code, autonomous_system_number y
autonomous_system_organization), pero son inventados: no dicen dónde está de verdad ninguna IP. No hay prueba con una
.mmdb real: maxminddb no está en la PC y no se puede armar una sin una dependencia nueva.
"""
import ast
import importlib.util
import io
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_geoip.py
from cirdan.recolectores import REGISTRO, geoip, rdap, shodan  # noqa: E402

RAIZ = Path(__file__).resolve().parents[1]
NO = geoip.NO_DISPONIBLE
IP_V4, IP_V6 = '40.65.94.253', '2606:4700:4700::1111'
NOMBRES = ['dbip-asn-lite-2026-10', 'dbip-country-lite-2026-10']


class LectorFalso:
    """Lo mínimo de un maxminddb.Reader: .get(ip) da el registro o None. Anota cada IP que se le pide."""

    def __init__(self, registros=None, error=None):
        self.registros, self.error, self.pedidas = registros or {}, error, []

    def get(self, ip):
        self.pedidas.append(ip)
        if self.error:
            raise self.error
        return self.registros.get(ip)


def bases(asn=None, pais=None, nombres=NOMBRES, problema=None):
    return SimpleNamespace(asn=asn, pais=pais, nombres=list(nombres), problema=problema)


def registro_asn(numero=8075, organizacion='Microsoft Corporation'):
    return {'autonomous_system_number': numero, 'autonomous_system_organization': organizacion}


def registro_pais(codigo='US'):
    return {'continent': {'code': 'NA'}, 'country': {'iso_code': codigo, 'names': {'es': 'Estados Unidos'}}}


def carpeta_con(d, *archivos, nombre='geo'):
    carpeta = Path(d) / nombre
    carpeta.mkdir()
    for nombre in archivos:
        (carpeta / nombre).write_bytes(b'')
    return carpeta


class Ubicar(unittest.TestCase):

    def test_1_pais_asn_y_proveedor_de_una_ip_con_las_dos_bases(self):
        asn = LectorFalso({IP_V4: registro_asn(), IP_V6: registro_asn(13335, 'Cloudflare, Inc.')})
        pais = LectorFalso({IP_V4: registro_pais('US'), IP_V6: registro_pais('AU')})
        b = bases(asn, pais)
        self.assertEqual(geoip.ubicar(IP_V4, b), {'pais': 'US', 'asn': 8075, 'proveedor': 'Microsoft Corporation',
                                                   'fuente_geo': 'DB-IP Lite', 'base_geo': NOMBRES})
        dato = geoip.ubicar(' %s ' % IP_V6, b)   # IPv6 también, y sin los espacios de alrededor
        self.assertEqual((dato['pais'], dato['asn'], dato['proveedor']), ('AU', 13335, 'Cloudflare, Inc.'))
        self.assertEqual(asn.pedidas, [IP_V4, IP_V6])
        self.assertIsNot(dato['base_geo'], b.nombres)   # una copia: un activo no comparte la lista con otro

    def test_2_una_ip_que_no_es_global_no_se_busca(self):
        asn, pais = LectorFalso(), LectorFalso()
        for ip in ('10.0.0.1', '192.168.1.10', '127.0.0.1', '203.0.113.7', '100.64.0.1', '224.0.0.1', '::1',
                   'fe80::1', '2001:db8::1', '', 'no-es-ip', None):
            self.assertEqual(geoip.ubicar(ip, bases(asn, pais)),
                             {'pais': NO, 'asn': NO, 'proveedor': NO, 'fuente_geo': NO, 'base_geo': NO}, ip)
        self.assertEqual((asn.pedidas, pais.pedidas), ([], []))

    def test_3_lo_que_no_tiene_forma_sale_no_disponible(self):
        raros = {'1.0.0.1': ({'country': {'iso_code': 'usa'}}, registro_asn(0, '\x00\x1b\t ​\r\n')),
                 '1.0.0.2': ({'country': {'iso_code': 'mx'}}, registro_asn('13335', 42)),
                 '1.0.0.3': ({'country': 'MX'}, registro_asn(True, None)),
                 '1.0.0.4': ({'country': {'iso_code': 52}}, registro_asn(4294967296, '')),
                 '1.0.0.5': ([], ['no', 'es', 'dict'])}
        b = bases(LectorFalso({ip: a for ip, (_, a) in raros.items()}), LectorFalso({ip: p for ip, (p, _) in raros.items()}))
        for ip in raros:
            dato = geoip.ubicar(ip, b)
            self.assertEqual((dato['pais'], dato['asn'], dato['proveedor']), (NO, NO, NO), ip)
        # una IP que la base no conoce (None) también
        self.assertEqual(geoip.ubicar('1.0.0.9', b)['pais'], NO)
        # el ASN más alto sí vale
        self.assertEqual(geoip.ubicar('1.0.0.1', bases(LectorFalso({'1.0.0.1': registro_asn(4294967295)})))['asn'],
                         4294967295)

    def test_4_el_proveedor_sale_imprimible_colapsado_y_con_tope(self):
        def proveedor(texto):
            return geoip.ubicar(IP_V4, bases(LectorFalso({IP_V4: registro_asn(64500, texto)})))['proveedor']
        self.assertEqual(proveedor('  Proveedor\x00 de\r\nprueba\x1b[0m​  S.A.  '), 'Proveedor de prueba [0m S.A.')
        self.assertEqual(proveedor('Telefónica México'), 'Telefónica México')
        largo = proveedor('x' * 199 + ' ' + 'y' * 300)
        self.assertEqual((len(largo), largo), (199, 'x' * 199))   # sin el espacio que quedó al final del corte
        self.assertEqual(len(proveedor('z' * 500)), geoip.MAX_TEXTO)

    def test_5_una_base_que_lanza_al_leer_cuenta_como_sin_dato(self):
        rota = LectorFalso(error=ValueError('registro dañado'))
        b = bases(rota, LectorFalso({IP_V4: registro_pais('MX')}))
        dato = geoip.ubicar(IP_V4, b)
        self.assertEqual((dato['pais'], dato['asn'], dato['proveedor']), ('MX', NO, NO))
        self.assertEqual(rota.pedidas, [IP_V4])
        b = bases(LectorFalso(error=RuntimeError('mmap')), LectorFalso(error=OSError('disco')))
        self.assertEqual(geoip.ubicar(IP_V4, b)['pais'], NO)

    def test_6_sin_bases_todo_sale_no_disponible_y_base_geo_tambien(self):
        dato = geoip.ubicar(IP_V4, bases(nombres=[], problema='falta todo'))
        self.assertEqual(dato, {'pais': NO, 'asn': NO, 'proveedor': NO, 'fuente_geo': NO, 'base_geo': NO})
        # con una sola base, base_geo dice solo esa
        dato = geoip.ubicar(IP_V4, bases(asn=LectorFalso({IP_V4: registro_asn()}), nombres=NOMBRES[:1]))
        self.assertEqual((dato['asn'], dato['pais'], dato['base_geo']), (8075, NO, NOMBRES[:1]))

    def test_7_sin_bases_toma_las_de_bases_por_omision(self):
        b = bases(LectorFalso({IP_V4: registro_asn()}), LectorFalso({IP_V4: registro_pais()}))
        with mock.patch.object(geoip, 'bases_por_omision', return_value=b):
            self.assertEqual(geoip.ubicar(IP_V4)['asn'], 8075)

    def test_8_no_disponible_es_el_mismo_texto_de_rdap_y_geoip_no_es_un_recolector(self):
        self.assertEqual(geoip.NO_DISPONIBLE, rdap.NO_DISPONIBLE)
        self.assertNotIn('cirdan.recolectores.geoip', REGISTRO.values())
        self.assertFalse(hasattr(geoip, 'MAX_CONSULTAS'))
        self.assertEqual(geoip.CARPETA, RAIZ / 'datos' / 'geo')

    def test_20_fuente_geo_solo_si_la_ip_se_busco_en_una_base_que_abrio(self):
        """datos-H4: solo se atribuye a DB-IP lo que salió de una base suya. Una IP que no es global, o una corrida sin
        ninguna base, da 'No disponible' en fuente_geo y base_geo. Una IP que no es global ni pide las bases."""
        con_una = bases(asn=LectorFalso({IP_V4: registro_asn()}), nombres=NOMBRES[:1])
        dato = geoip.ubicar(IP_V4, con_una)
        self.assertEqual((dato['fuente_geo'], dato['base_geo']), ('DB-IP Lite', NOMBRES[:1]))
        dato = geoip.ubicar('1.0.0.9', con_una)   # la base no la conoce, pero sí se buscó en ella
        self.assertEqual((dato['asn'], dato['fuente_geo']), (NO, 'DB-IP Lite'))
        for ip, b in (('10.0.0.1', con_una), (IP_V4, bases(nombres=[], problema='falta'))):
            dato = geoip.ubicar(ip, b)
            self.assertEqual((dato['fuente_geo'], dato['base_geo']), (NO, NO), ip)
        with mock.patch.object(geoip, 'bases_por_omision', side_effect=AssertionError('no debía pedir las bases')):
            self.assertEqual(geoip.ubicar('192.168.1.10')['fuente_geo'], NO)


class AbrirBases(unittest.TestCase):
    """Bases: qué archivo se elige, la caché por ruta y lo que pasa sin archivos, sin maxminddb o con una base rota."""

    def setUp(self):
        cache = mock.patch.object(geoip, '_LECTORES', {})   # cada prueba con la caché vacía
        cache.start()
        self.addCleanup(cache.stop)

    def abrir_falso(self):
        abiertas = []

        def abrir(ruta):
            abiertas.append(ruta.name)
            return LectorFalso({IP_V4: registro_asn()}), None
        return abiertas, mock.patch.object(geoip.Bases, '_abrir', staticmethod(abrir))

    def test_9_toma_la_base_mas_nueva_por_nombre(self):
        abiertas, parche = self.abrir_falso()
        with tempfile.TemporaryDirectory() as d, parche:
            carpeta = carpeta_con(d, 'dbip-asn-lite-2026-09.mmdb', 'dbip-asn-lite-2026-10.mmdb',
                                  'dbip-asn-lite-2026-11.mmdb.gz', 'dbip-asn-lite-viejo.mmdb', 'dbip-asn-lite-2026-1.mmdb',
                                  'dbip-country-lite-2025-12.mmdb', 'dbip-country-lite-2026-10.mmdb',
                                  'dbip-city-lite-2026-12.mmdb', '.gitkeep')
            b = geoip.Bases(carpeta)
        self.assertEqual(abiertas, ['dbip-asn-lite-2026-10.mmdb', 'dbip-country-lite-2026-10.mmdb'])
        self.assertEqual((b.nombres, b.problema), (NOMBRES, None))
        self.assertIsNotNone(b.asn)
        self.assertIsNotNone(b.pais)

    def test_10_cada_ruta_se_abre_una_sola_vez(self):
        abiertas, parche = self.abrir_falso()
        with tempfile.TemporaryDirectory() as d, parche:
            carpeta = carpeta_con(d, 'dbip-asn-lite-2026-10.mmdb', 'dbip-country-lite-2026-10.mmdb')
            primera, segunda = geoip.Bases(carpeta), geoip.Bases(carpeta)
            self.assertEqual(len(abiertas), 2)
            self.assertIs(primera.asn, segunda.asn)
            otra = Path(d) / 'otra'
            otra.mkdir()
            (otra / 'dbip-asn-lite-2026-10.mmdb').write_bytes(b'')
            geoip.Bases(otra)   # el mismo nombre en otra carpeta es otra ruta
            self.assertEqual(len(abiertas), 3)

    def test_11_sin_archivos_los_lectores_quedan_en_none_con_el_problema(self):
        with tempfile.TemporaryDirectory() as d:
            for carpeta in (carpeta_con(d, '.gitkeep'), Path(d) / 'no_existe'):
                b = geoip.Bases(carpeta)
                self.assertEqual((b.asn, b.pais, b.nombres), (None, None, []))
                self.assertEqual(b.problema, 'falta dbip-asn-lite-AAAA-MM.mmdb en datos/geo; '
                                             'falta dbip-country-lite-AAAA-MM.mmdb en datos/geo')
            abiertas, parche = self.abrir_falso()
            with parche:
                b = geoip.Bases(carpeta_con(d, 'dbip-country-lite-2026-10.mmdb', nombre='solo_pais'))
            self.assertEqual((b.asn, b.nombres), (None, NOMBRES[1:]))
            self.assertEqual(b.problema, 'falta dbip-asn-lite-AAAA-MM.mmdb en datos/geo')

    def test_12_sin_maxminddb_o_con_una_base_rota_no_lanza_y_tampoco_se_reintenta(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = carpeta_con(d, 'dbip-asn-lite-2026-10.mmdb', 'dbip-country-lite-2026-10.mmdb')
            with mock.patch.dict(sys.modules, {'maxminddb': None}):   # import maxminddb lanza ImportError
                b = geoip.Bases(carpeta)
            self.assertEqual((b.asn, b.pais, b.nombres), (None, None, []))
            self.assertEqual(b.problema, 'maxminddb no está instalado')   # una vez, aunque falte para las dos
            self.assertEqual(geoip.ubicar(IP_V4, b)['pais'], NO)

            geoip._LECTORES.clear()
            falso = SimpleNamespace(open_database=mock.Mock(side_effect=ValueError('no es MMDB')))
            with mock.patch.dict(sys.modules, {'maxminddb': falso}):
                b = geoip.Bases(carpeta)
                geoip.Bases(carpeta)
            self.assertEqual(b.problema, 'no se pudo abrir dbip-asn-lite-2026-10.mmdb (ValueError); '
                                         'no se pudo abrir dbip-country-lite-2026-10.mmdb (ValueError)')
            self.assertEqual(falso.open_database.call_count, 2)   # la falla también queda en la caché
            self.assertEqual(falso.open_database.call_args_list[0].args, (str(carpeta / 'dbip-asn-lite-2026-10.mmdb'),))

    def test_13_el_modulo_carga_sin_maxminddb(self):
        arbol = ast.parse((RAIZ / 'cirdan' / 'recolectores' / 'geoip.py').read_text(encoding='utf-8'))
        for nodo in arbol.body:  # ni import maxminddb ni from maxminddb... al cargar el módulo
            nombres = [a.name for a in nodo.names] if isinstance(nodo, ast.Import) else \
                [nodo.module or ''] if isinstance(nodo, ast.ImportFrom) else []
            self.assertFalse([n for n in nombres if n.split('.')[0] == 'maxminddb'], ast.dump(nodo))
        spec = importlib.util.spec_from_file_location('geoip_sin_maxminddb', geoip.__file__)
        copia = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {'maxminddb': None}):
            spec.loader.exec_module(copia)
            self.assertEqual(copia.FUENTE_GEO, 'DB-IP Lite')

    def test_14_bases_por_omision_es_la_misma_y_mira_carpeta(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(geoip, '_POR_OMISION', []), \
                mock.patch.object(geoip, 'CARPETA', carpeta_con(d, '.gitkeep')):
            b = geoip.bases_por_omision()
            self.assertIs(geoip.bases_por_omision(), b)
            self.assertEqual(b.carpeta, geoip.CARPETA)
            self.assertIn('falta dbip-asn-lite', b.problema)


class CdnYAviso(unittest.TestCase):

    def test_15_cdn_por_asn_solo_con_asn_de_cdn(self):
        esperados = {13335: 'cloudflare', 54113: 'fastly', 20940: 'akamai', 16625: 'akamai', 19551: 'imperva',
                     30148: 'sucuri', 200325: 'bunny', 22822: 'edgio'}
        for asn, cdn in esperados.items():
            self.assertEqual(geoip.cdn_por_asn(asn), cdn, asn)
        # nubes mixtas, CDN77 (también servidores dedicados), Edgecast (ahora con nube) y lo que no es un ASN
        for asn in (16509, 8075, 15169, 60068, 15133, 64500, 0, '13335', True, None, NO):
            self.assertIsNone(geoip.cdn_por_asn(asn), asn)
        self.assertFalse({16509, 8075, 15169} & set(geoip.CDN_POR_ASN))
        # los nombres son los de shodan cuando el CDN también está ahí
        de_shodan = set(shodan.SUFIJOS_CDN.values())
        self.assertEqual(set(geoip.CDN_POR_ASN.values()) - de_shodan, {'sucuri', 'edgio'})

    def test_16_aviso_sin_base(self):
        self.assertEqual(geoip.aviso_sin_base('shodan', bases(problema='maxminddb no está instalado')),
                         'shodan: sin la base local de DB-IP Lite (maxminddb no está instalado), el país, el ASN y el '
                         'proveedor de las IP quedan como No disponible')
        self.assertIsNone(geoip.aviso_sin_base('dns', bases()))

    def test_17_linea_de_comandos(self):
        b = bases(LectorFalso({IP_V4: registro_asn(13335, 'Cloudflare, Inc.')}), LectorFalso({IP_V4: registro_pais()}))
        salida = io.StringIO()
        with mock.patch.object(geoip, 'bases_por_omision', return_value=b), redirect_stdout(salida):
            codigo = geoip._main([IP_V4, '10.0.0.1'])
        lineas = salida.getvalue().splitlines()
        self.assertEqual(codigo, 0)
        self.assertEqual(lineas[0], IP_V4 + ' {"pais": "US", "asn": 13335, "proveedor": "Cloudflare, Inc.", '
                                            '"fuente_geo": "DB-IP Lite", "base_geo": ["dbip-asn-lite-2026-10", '
                                            '"dbip-country-lite-2026-10"], "cdn": "cloudflare"}')
        self.assertIn('"pais": "No disponible"', lineas[1])
        salida = io.StringIO()
        with mock.patch.object(geoip, 'bases_por_omision', return_value=bases(nombres=[], problema='falta')), \
                redirect_stdout(salida):
            self.assertEqual(geoip._main([IP_V4]), 1)
        self.assertTrue(salida.getvalue().startswith('geoip: sin la base local de DB-IP Lite (falta)'))

    def test_21_el_aviso_nombra_solo_lo_que_falto(self):
        """geo-G4: con la base de ASN abierta el ASN y el proveedor sí salen, y con la de países el país también."""
        lector = LectorFalso()
        sin_pais = bases(asn=lector, nombres=NOMBRES[:1], problema='falta dbip-country-lite-AAAA-MM.mmdb en datos/geo')
        self.assertEqual(geoip.aviso_sin_base('dns', sin_pais),
                         'dns: sin la base local de DB-IP Lite (falta dbip-country-lite-AAAA-MM.mmdb en datos/geo), el país '
                         'de las IP queda como No disponible')
        sin_asn = bases(pais=lector, nombres=NOMBRES[1:], problema='falta dbip-asn-lite-AAAA-MM.mmdb en datos/geo')
        self.assertEqual(geoip.aviso_sin_base('dns', sin_asn),
                         'dns: sin la base local de DB-IP Lite (falta dbip-asn-lite-AAAA-MM.mmdb en datos/geo), el ASN y '
                         'el proveedor de las IP quedan como No disponible')
        self.assertIn('el país, el ASN y el proveedor', geoip.aviso_sin_base('dns', bases(nombres=[], problema='falta')))

    def test_22_lo_que_agrega_la_fuente_va_en_el_mismo_aviso_solo_sin_la_base_de_asn(self):
        """geo-G1: shodan agrega que no pudo descartar los CDN por ASN, en el mismo aviso y solo si falta esa base."""
        extra = 'no se descartaron los CDN por ASN'
        sin_asn = bases(pais=LectorFalso(), nombres=NOMBRES[1:], problema='falta asn')
        self.assertEqual(geoip.aviso_sin_base('shodan', sin_asn, sin_asn=extra),
                         geoip.aviso_sin_base('shodan', sin_asn) + ', y ' + extra)
        self.assertEqual(geoip.aviso_sin_base('shodan', bases(nombres=[], problema='falta'), sin_asn=extra)[-len(extra):],
                         extra)
        sin_pais = bases(asn=LectorFalso(), nombres=NOMBRES[:1], problema='falta país')
        self.assertEqual(geoip.aviso_sin_base('shodan', sin_pais, sin_asn=extra), geoip.aviso_sin_base('shodan', sin_pais))
        self.assertIsNone(geoip.aviso_sin_base('shodan', bases(), sin_asn=extra))


class Empaque(unittest.TestCase):

    def test_18_las_bases_no_van_al_repo(self):
        """17 MB que cambian cada mes no entran a git. Solo .gitkeep, para que COPY datos/geo/ no falle en un clon."""
        self.assertTrue((geoip.CARPETA / '.gitkeep').exists())
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
                                    '--no-index', ruta], cwd=repo)
                self.assertIn(r.returncode, (0, 1), ruta)  # 128: git no pudo revisarlo
                return r.returncode == 0
            for ruta in ('datos/geo/dbip-asn-lite-2026-10.mmdb', 'datos/geo/dbip-country-lite-2026-10.mmdb',
                         'datos/geo/dbip-asn-lite-2026-10.mmdb.gz', 'datos/geo/otra/base.mmdb'):
                self.assertTrue(ignorado(ruta), ruta)
            for ruta in ('datos/geo/.gitkeep', 'datos/ml/rc65/dataset.csv', 'cirdan/recolectores/geoip.py'):
                self.assertFalse(ignorado(ruta), ruta)

    def test_19_la_imagen_copia_las_bases_antes_del_codigo_y_trae_maxminddb(self):
        lineas = [l.strip() for l in (RAIZ / 'Dockerfile').read_text(encoding='utf-8').splitlines()]
        self.assertLess(lineas.index('COPY datos/geo/ datos/geo/'), lineas.index('COPY cirdan/ cirdan/'))
        excluidos = [l.strip().strip('/') for l in (RAIZ / '.dockerignore').read_text(encoding='utf-8').splitlines()]
        self.assertFalse({'datos', 'datos/geo', 'datos/*'} & set(excluidos))   # qué entra de datos/geo: test_23
        self.assertIn('maxminddb==3.2.0', (RAIZ / 'requirements.txt').read_text(encoding='utf-8').splitlines())
        aviso = (RAIZ / 'NOTICE').read_text(encoding='utf-8')
        self.assertIn('IP Geolocation by DB-IP', aviso)
        self.assertIn('IP to ASN Lite e IP to Country Lite', aviso)

    def test_23_de_datos_geo_solo_entran_a_la_imagen_gitkeep_y_las_dos_bases(self):
        """geo-G7: COPY datos/geo/ copiaría todo. .dockerignore deja fuera los .gz, City Lite y lo demás, y solo deja
        .gitkeep y los .mmdb con el nombre de las dos bases. Los meses viejos sí entran: se borran a mano (README).
        Las reglas se evalúan como Docker: la última que coincide con la ruta o con una carpeta de arriba gana."""
        reglas = []
        for linea in (RAIZ / '.dockerignore').read_text(encoding='utf-8').splitlines():
            linea = linea.strip()
            if linea and not linea.startswith('#'):
                negada = linea.startswith('!')
                reglas.append((negada, patron_dockerignore(linea.lstrip('!').strip().strip('/'))))

        def excluido(ruta):
            partes = ruta.split('/')
            arriba = ['/'.join(partes[:i]) for i in range(1, len(partes) + 1)]
            fuera = False
            for negada, patron in reglas:
                if any(patron.fullmatch(p) for p in arriba):
                    fuera = not negada
            return fuera
        for ruta in ('datos/geo/.gitkeep', 'datos/geo/dbip-asn-lite-2026-10.mmdb', 'datos/geo/dbip-country-lite-2026-10.mmdb',
                     'datos/geo/dbip-asn-lite-2026-09.mmdb', 'cirdan/recolectores/geoip.py', 'requirements.txt'):
            self.assertFalse(excluido(ruta), ruta)
        for ruta in ('datos/geo/dbip-asn-lite-2026-10.mmdb.gz', 'datos/geo/dbip-country-lite-2026-10.mmdb.gz',
                     'datos/geo/dbip-city-lite-2026-10.mmdb', 'datos/geo/notas.txt', 'datos/geo/otra/dbip-asn-lite-2026-10.mmdb',
                     'pruebas/test_geoip.py', '.env'):
            self.assertTrue(excluido(ruta), ruta)


def patron_dockerignore(patron):
    """Un patrón de .dockerignore como expresión regular: * y ? no cruzan '/', y **/ es cero o más carpetas."""
    regex, i = '', 0
    while i < len(patron):
        if patron.startswith('**/', i):
            regex, i = regex + '(?:.*/)?', i + 3
        elif patron.startswith('**', i):
            regex, i = regex + '.*', i + 2
        elif patron[i] == '*':
            regex, i = regex + '[^/]*', i + 1
        elif patron[i] == '?':
            regex, i = regex + '[^/]', i + 1
        else:
            regex, i = regex + re.escape(patron[i]), i + 1
    return re.compile(regex)


if __name__ == '__main__':
    unittest.main()
