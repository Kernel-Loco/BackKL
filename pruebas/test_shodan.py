"""Pruebas del recolector de Shodan InternetDB (#17, RC-49), sin red ni DNS real: Cert Spotter e InternetDB con un
transporte HTTP simulado y el A con un resolvedor simulado. Las respuestas de 20.69.154.199 y 40.65.94.253 son las que
InternetDB dio el 27 oct 2026 (_plan/rc49/en_vivo_27oct/), copiadas tal cual.

    python -m unittest -v pruebas/test_shodan.py

Las IP de prueba son las de las VM del equipo y otras globales: las de documentación (192.0.2.0/24) no son globales y el
recolector no las consulta.
"""
import io
import ipaddress
import json
import os
import re
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_shodan.py
from pruebas.test_catalogo_reglas import POR_CODIGO  # noqa: E402
from pruebas.test_certspotter import emision  # noqa: E402
from pruebas.test_crtsh import AHORA  # noqa: E402
from pruebas.test_subfinder import Cronometro  # noqa: E402
from pruebas.test_geoip import NOMBRES, LectorFalso, bases, registro_asn, registro_pais  # noqa: E402
from cirdan.recolectores import REGISTRO, cargar, contrato, geoip, shodan  # noqa: E402
from cirdan.recolectores.contrato import FuenteNoResponde  # noqa: E402

SEMILLA = Path(__file__).resolve().parents[1] / 'db' / 'semillas' / '007_shodan.sql'
DOMINIO = 'olmardo.com'
CAMARA, RESERVAS = '20.69.154.199', '40.65.94.253'   # camaras.olmardo.com y reservas.olmardo.com (siembra #10)
CLOUDFLARE = '104.21.48.10'                            # dentro de 104.16.0.0/13
# InternetDB el 27 oct 2026 a las 18:55 (Monterrey): lo que vio Shodan de quien tuvo antes la IP de la VM de cámaras,
# y nada de la de reservas.
REAL_CAMARA = (b'{"cpes":["cpe:/a:openbsd:openssh:8.9p1","cpe:/o:canonical:ubuntu_linux"],"hostnames":[],'
               b'"ip":"20.69.154.199","ports":[50000],"tags":["cloud"],"vulns":[]}')
REAL_404 = b'{"detail":"No information available"}'
# Lo que se espera cuando Shodan vea la VM sembrada: solo el 8080 con la página de la cámara.
CAMARA_8080 = {'cpes': [], 'hostnames': ['camaras.olmardo.com'], 'ip': CAMARA, 'ports': [8080], 'tags': [], 'vulns': []}
NO = geoip.NO_DISPONIBLE
CLAVES_GEO = ('pais', 'asn', 'proveedor', 'fuente_geo', 'base_geo')


def setUpModule():
    """Ninguna prueba depende de que la PC tenga o no la base de DB-IP en datos/geo: bases_por_omision da unas Bases
    falsas sin lectores y sin problema, así todo sale 'No disponible', sin aviso y sin CDN por ASN. La clase Geo pone
    las suyas."""
    parche = mock.patch.object(geoip, 'bases_por_omision', return_value=bases())
    parche.start()
    unittest.addModuleCleanup(parche.stop)


def internetdb(ip, ports=(), tags=(), cpes=(), vulns=(), hostnames=()):
    """Una respuesta 200 de InternetDB con la forma real."""
    return {'cpes': list(cpes), 'hostnames': list(hostnames), 'ip': ip, 'ports': list(ports), 'tags': list(tags),
            'vulns': list(vulns)}


def paginas(*nombres, id_=9101):
    """Las páginas de Cert Spotter con un certificado vigente por nombre, más la vacía que cierra."""
    return [[emision(str(id_ + i), [n], '2026-09-20T00:00:00Z', '2026-12-19T00:00:00Z') for i, n in enumerate(nombres)], []]


def error_http(url, codigo, espera=None):
    return urllib.error.HTTPError(url, codigo, 'falla %d' % codigo, {'Retry-After': espera} if espera else {},
                                  io.BytesIO(b''))


class HttpSimulado:
    """Hace las veces de shodan._descargar(url, timeout).

    Cert Spotter (la URL lleva parámetros) responde `ct` en orden, una respuesta por intento: una lista es la página y un
    entero es un error HTTP con ese código. Si se acaban, responde la página vacía. InternetDB responde por IP (el último
    tramo de la URL): un dict es el JSON, bytes van tal cual, un entero es un error HTTP y una lista da una respuesta por
    intento (la última se repite). Una IP que no está da 404 con el cuerpo real."""

    def __init__(self, ct=None, ips=None):
        self.ct = [[]] if ct is None else list(ct)
        self.ips = ips or {}
        self.urls, self.por_ip = [], {}

    def __call__(self, url, timeout):
        self.urls.append(url)
        if '?' in url:
            respuesta = self.ct.pop(0) if self.ct else []
        else:
            ip = url.rsplit('/', 1)[1]
            self.por_ip[ip] = self.por_ip.get(ip, 0) + 1
            respuesta = self.ips.get(ip, 404)
            if isinstance(respuesta, list):
                respuesta = respuesta[min(self.por_ip[ip], len(respuesta)) - 1]
        if isinstance(respuesta, int):
            raise error_http(url, respuesta, '60' if respuesta == 429 else None)
        return respuesta if isinstance(respuesta, bytes) else json.dumps(respuesta).encode()

    def consultadas(self):
        """IP que llegaron a InternetDB."""
        return set(self.por_ip)


class ResolvedorSimulado:
    """Hace las veces de shodan._resolver_a(nombre, lifetime). `zona` da por nombre (estado, ips, cadena CNAME),
    'falla' (el DNS no respondió) o una lista con una de esas por intento (la última se repite). Un nombre que no está
    es nxdomain. Guarda el lifetime de cada consulta en `lifetimes`."""

    def __init__(self, zona):
        self.zona, self.nombres, self.lifetimes = zona, [], []

    def __call__(self, nombre, lifetime=shodan.TIMEOUT_DNS):
        self.nombres.append(nombre)
        self.lifetimes.append(lifetime)
        respuesta = self.zona.get(nombre, ('nxdomain', [], []))
        if isinstance(respuesta, list):
            respuesta = respuesta[min(self.nombres.count(nombre), len(respuesta)) - 1]
        if respuesta == 'falla':
            raise shodan.ConsultaFallida('Timeout: ningún servidor respondió')
        return respuesta


def a(*ips, cname=None):
    """Un A que responde. `cname` es un nombre o la cadena CNAME completa, del primer destino al último."""
    return ('ok', list(ips), [cname] if isinstance(cname, str) else list(cname or ()))


def zona_olmardo(**extra):
    """La raíz detrás de Cloudflare, camaras en su VM y reservas y eventos en la de reservas."""
    zona = {DOMINIO: a(CLOUDFLARE), 'camaras.olmardo.com': a(CAMARA), 'reservas.olmardo.com': a(RESERVAS),
            'eventos.olmardo.com': a(RESERVAS)}
    zona.update(extra)
    return zona


def ct_olmardo():
    return paginas('camaras.olmardo.com', 'eventos.olmardo.com', 'reservas.olmardo.com', '*.olmardo.com')


def recolectar(http, dns, modo='vivo', carpeta=None, nueva=False, cronometro=None, dominio=DOMINIO):
    cliente = shodan.ClienteShodan(modo=modo, carpeta=carpeta or shodan.carpeta_de(dominio), descargar=http,
                                   resolver=dns, nueva=nueva, cronometro=cronometro or Cronometro(0),
                                   dormir=lambda s: None)
    return shodan.recolectar(dominio, cliente, ahora=AHORA)


def activo(res, valor):
    return next(a for a in res.activos if a.valor == valor)


def codigos_sin(res):
    """Lo que debe quedar en sin_cobertura con la cobertura parcial: los códigos sin hallazgos y los de sin llave."""
    con = {h.codigo for h in res.hallazgos}
    return [c for c in shodan.CODIGOS if c not in con] + list(shodan.SIN_LLAVE)


class Shodan(unittest.TestCase):

    def test_1_cumple_el_contrato_y_ejecutar_lo_deja_succeeded(self):
        self.assertEqual(REGISTRO['shodan'], 'cirdan.recolectores.shodan')
        http = HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080})
        res = recolectar(http, ResolvedorSimulado(zona_olmardo()))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        with tempfile.TemporaryDirectory() as d, mock.patch.object(shodan, 'CARPETA_GRABADAS', Path(d)), \
                mock.patch.object(shodan, '_descargar', HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080})), \
                mock.patch.object(shodan, '_resolver_a', ResolvedorSimulado(zona_olmardo())), \
                mock.patch.object(shodan.time, 'sleep', lambda s: None):
            otra = contrato.ejecutar(cargar('shodan'), DOMINIO, modo='vivo', ahora=AHORA, codigos=set(POR_CODIGO))
        self.assertEqual(otra.estado, 'succeeded', otra.error)
        self.assertEqual((otra.activos, otra.hallazgos), (res.activos, res.hallazgos))

    def test_2_el_8080_da_exposed_service_en_camaras(self):
        """Hecho cuando de RC-49: la VM sembrada con el 8080 da exposed_service baja sobre su servicio."""
        res = recolectar(HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080}), ResolvedorSimulado(zona_olmardo()))
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        [h] = res.hallazgos
        self.assertEqual((h.codigo, h.severidad, h.activo), ('exposed_service', 'low', '20.69.154.199:8080/tcp'))
        self.assertEqual(h.evidencia['hosts'], ['camaras.olmardo.com'])
        self.assertEqual(h.titulo, 'Shodan vio abierto el puerto 8080 en camaras.olmardo.com')
        self.assertEqual((h.evidencia['vigencia'], h.evidencia['fuente_sin_fecha']), ('sin_fecha', True))
        self.assertNotIn('posible_dato_de_otro_dueno', h.evidencia)
        servicio = activo(res, '20.69.154.199:8080/tcp')
        self.assertEqual((servicio.tipo, servicio.atributos['parent'], servicio.atributos['ip_address']),
                         ('service', CAMARA, CAMARA))
        ip = activo(res, CAMARA)
        self.assertEqual((ip.atributos['origen'], ip.atributos['fuente_datos']), ('cert_spotter_a', 'Shodan InternetDB'))
        self.assertEqual(ip.atributos['internetdb']['puertos'], [8080])
        self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))
        self.assertIn(shodan.LIMITES, res.avisos)

    def test_3_web_y_correo_dan_servicio_sin_hallazgo(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[80, 443, 25, 587])})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(res.hallazgos, [])
        self.assertEqual(sorted(a.valor for a in res.activos if a.tipo == 'service'),
                         sorted('%s:%d/tcp' % (CAMARA, p) for p in (80, 443, 25, 587)))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_4_un_puerto_por_familia_da_su_codigo(self):
        """502 (Modbus) da exposed_service con puerto_industrial: exposed_ot_device necesita la API de host (#8)."""
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[3389, 22, 445, 5432, 502])})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        por_puerto = {h.evidencia['puerto']: h for h in res.hallazgos}
        self.assertEqual({p: h.codigo for p, h in por_puerto.items()},
                         {3389: 'exposed_rdp', 22: 'exposed_remote_admin', 445: 'exposed_file_sharing',
                          5432: 'exposed_database', 502: 'exposed_service'})
        self.assertTrue(por_puerto[502].evidencia['puerto_industrial'])
        self.assertNotIn('puerto_industrial', por_puerto[22].evidencia)
        self.assertNotIn('exposed_ot_device', {h.codigo for h in res.hallazgos})
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_5_listas_de_puertos_disjuntas(self):
        listas = list(shodan.PUERTOS.values()) + [shodan.PUERTOS_WEB, shodan.PUERTOS_CORREO, shodan.PUERTOS_INDUSTRIALES]
        todos = [p for lista in listas for p in lista]
        self.assertEqual(len(todos), len(set(todos)))
        for puerto in shodan.PUERTOS_WEB + shodan.PUERTOS_CORREO:
            self.assertIsNone(shodan.codigo_de_puerto(puerto), puerto)
        for codigo, puertos in shodan.PUERTOS.items():
            for puerto in puertos:
                self.assertEqual(shodan.codigo_de_puerto(puerto), codigo, puerto)
        for puerto in shodan.PUERTOS_INDUSTRIALES + (8080, 50000):
            self.assertEqual(shodan.codigo_de_puerto(puerto), 'exposed_service', puerto)

    def test_6_vulns_da_un_known_vulnerability_por_cve_hasta_25(self):
        """tiempos-5: con más de 25 se reportan las 25 más recientes (año y número de mayor a menor) y el aviso dice
        cuántas se omitieron."""
        cves = ['CVE-2023-%d' % (1000 + i) for i in range(30)]
        cpes = ['cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*']
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, cpes=cpes, vulns=cves[15:] + cves[:15])})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        vulns = [h for h in res.hallazgos if h.codigo == 'known_vulnerability']
        recientes = list(reversed(cves))[:shodan.MAX_CVE]
        self.assertEqual([h.clave for h in vulns], recientes)
        self.assertEqual({(h.activo, h.severidad) for h in vulns}, {(CAMARA, 'medium')})
        self.assertEqual(len({h.huella for h in vulns}), shodan.MAX_CVE)
        self.assertEqual((vulns[0].evidencia['cve'], vulns[0].evidencia['cpes'], vulns[0].evidencia['deducida_por_version']),
                         ('CVE-2023-1029', cpes, True))
        self.assertEqual(activo(res, CAMARA).atributos['internetdb']['vulns'], 30)
        self.assertIn('shodan: %s trae 30 CVE, se reportan las 25 más recientes y se omitieron 5' % CAMARA, res.avisos)
        viejas = recolectar(HttpSimulado(ips={CAMARA: internetdb(CAMARA, vulns=['CVE-2007-4752'] + cves[:25])}),
                            ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertNotIn('CVE-2007-4752', [h.clave for h in viejas.hallazgos])
        self.assertIn('CVE-2023-1024', [h.clave for h in viejas.hallazgos])
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_7_ip_de_cloudflare_y_privada_no_se_consultan(self):
        http = HttpSimulado(paginas('interno.olmardo.com'), {CLOUDFLARE: CAMARA_8080, '10.0.0.5': CAMARA_8080})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CLOUDFLARE), 'interno.olmardo.com': a('10.0.0.5')}))
        self.assertEqual(http.consultadas(), set())
        self.assertEqual(activo(res, CLOUDFLARE).atributos['cdn'], 'cloudflare')
        self.assertTrue(activo(res, '10.0.0.5').atributos['no_publica'])
        self.assertEqual({a.atributos['internetdb'] for a in res.activos}, {'no_consultada'})
        self.assertEqual((res.estado, res.hallazgos, res.sin_cobertura), ('succeeded', [], list(shodan.SIN_LLAVE)))
        self.assertIn(shodan.SIN_IP, res.avisos)
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_8_cname_de_cdn_no_se_consulta_y_el_tag_cdn_descarta(self):
        nube, marcada = '52.84.17.10', '23.45.67.89'
        zona = {DOMINIO: a(marcada), 'www.olmardo.com': a(nube, cname='d111abc.cloudfront.net')}
        http = HttpSimulado(paginas('www.olmardo.com'), {nube: CAMARA_8080,
                                                          marcada: internetdb(marcada, ports=[8080], tags=['cdn'])})
        res = recolectar(http, ResolvedorSimulado(zona))
        self.assertEqual(http.consultadas(), {marcada})
        self.assertEqual(activo(res, nube).atributos['cdn'], 'cloudfront')
        self.assertEqual((activo(res, marcada).atributos['cdn'], activo(res, marcada).atributos['internetdb']),
                         ('internetdb', 'descartada_cdn'))
        self.assertEqual(res.hallazgos, [])
        self.assertEqual([a.tipo for a in res.activos], ['ip', 'ip'])
        self.assertIn('shodan: InternetDB marca %s como CDN, se descartaron sus datos' % marcada, res.avisos)

    def test_9_un_404_da_sin_datos_sin_reintentos(self):
        """El 404 real de 40.65.94.253 del 27 oct."""
        http = HttpSimulado(ips={RESERVAS: [404]})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(RESERVAS)}))
        self.assertEqual(http.por_ip, {RESERVAS: 1})
        self.assertEqual(activo(res, RESERVAS).atributos['internetdb'], 'sin_datos')
        self.assertEqual((res.estado, res.hallazgos, res.sin_cobertura), ('succeeded', [], list(shodan.SIN_LLAVE)))
        self.assertEqual(res.consultas, 3)   # Cert Spotter, el A y InternetDB

    def test_10_dos_nombres_con_la_misma_ip_comparten_activo(self):
        res = recolectar(HttpSimulado(ct_olmardo(), {RESERVAS: internetdb(RESERVAS, ports=[8443])}),
                         ResolvedorSimulado(zona_olmardo()))
        ips = [a for a in res.activos if a.valor == RESERVAS]
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0].atributos['hosts'], ['eventos.olmardo.com', 'reservas.olmardo.com'])
        [h] = [h for h in res.hallazgos if h.evidencia['ip'] == RESERVAS]
        self.assertEqual(h.titulo, 'Shodan vio abierto el puerto 8443 en eventos.olmardo.com y 1 nombre más')

    def test_11_hostnames_ajenos_solo_se_cuentan(self):
        respuesta = internetdb(CAMARA, ports=[8080],
                               hostnames=['Camaras.olmardo.com.', 'ajenoxyz.otro-cliente.com', 'ajenoxyz.example'])
        res = recolectar(HttpSimulado(ips={CAMARA: respuesta}), ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        datos = activo(res, CAMARA).atributos['internetdb']
        self.assertEqual((datos['hostnames'], datos['hostnames_ajenos']), (['camaras.olmardo.com'], 2))
        self.assertNotIn('ajenoxyz', json.dumps(res.a_dict()))
        self.assertTrue(res.hallazgos[0].evidencia['posible_dato_de_otro_dueno'])
        self.assertIn('shodan: InternetDB trae en %s 2 nombres de otro dominio: sus datos pueden ser de quien tuvo '
                      'la IP antes' % CAMARA, res.avisos)

    def test_12_reproducir_sin_grabacion(self):
        http = HttpSimulado()
        with tempfile.TemporaryDirectory() as d:
            res = recolectar(http, ResolvedorSimulado({}), modo='reproducir', carpeta=Path(d) / DOMINIO)
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.sin_cobertura, list(shodan.CODIGOS) + list(shodan.SIN_LLAVE))
        self.assertEqual(len(res.sin_cobertura), 9)
        self.assertEqual((res.avisos, res.consultas, http.urls), ([shodan.SIN_GRABACION_DOMINIO], 0, []))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_13_grabacion_con_fallas_no_toca_la_anterior_y_la_completa_reproduce_lo_mismo(self):
        """re-contrato-1: solo se graba una corrida sin fallas. La primera es completa (reservas da 404, que no es
        falla). Una segunda con un 403 de reservas no escribe nada, y una que termina en FuenteNoResponde tampoco."""
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            ips = {CAMARA: CAMARA_8080, RESERVAS: 404}
            res = recolectar(HttpSimulado(ct_olmardo(), ips), ResolvedorSimulado(zona_olmardo()), modo='grabar',
                             carpeta=carpeta, nueva=True)
            archivos = {p.name: p.read_bytes() for p in carpeta.iterdir()}
            self.assertIn('certspotter_olmardo.com.json', archivos)
            self.assertIn('a_camaras.olmardo.com.json', archivos)
            self.assertIn('internetdb_20.69.154.199.json', archivos)
            grabada = json.loads(archivos['internetdb_20.69.154.199.json'])['datos']
            self.assertEqual(grabada['ports'], [8080])
            self.assertNotIn('ip', grabada)
            self.assertEqual(json.loads(archivos['internetdb_40.65.94.253.json'])['datos'], {'sin_datos': True})
            self.assertNotIn(shodan.NO_SE_GRABO, res.avisos)
            self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))
            con_403 = recolectar(HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080, RESERVAS: 403}),
                                 ResolvedorSimulado(zona_olmardo()), modo='grabar', carpeta=carpeta, nueva=True)
            self.assertEqual(con_403.avisos[0], shodan.NO_SE_GRABO)
            self.assertEqual({p.name: p.read_bytes() for p in carpeta.iterdir()}, archivos)
            caido = {DOMINIO: 'falla', 'camaras.olmardo.com': 'falla'}
            with self.assertRaises(FuenteNoResponde):
                recolectar(HttpSimulado([500, 500]), ResolvedorSimulado(caido), modo='grabar', carpeta=carpeta,
                           nueva=True)
            self.assertEqual({p.name: p.read_bytes() for p in carpeta.iterdir()}, archivos)
            http = HttpSimulado()
            otra = recolectar(http, ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
        self.assertEqual(http.urls, [])
        self.assertEqual((otra.activos, otra.hallazgos, otra.sin_cobertura, otra.avisos),
                         (res.activos, res.hallazgos, res.sin_cobertura, res.avisos))
        self.assertEqual(activo(otra, RESERVAS).atributos['internetdb'], 'sin_datos')

    def test_14_el_peor_caso_gasta_justo_max_consultas(self):
        """Dos páginas llenas de Cert Spotter al segundo intento, MAX_NOMBRES nombres que resuelven al tercero y
        MAX_IPS IP que responden al tercero."""
        nombres = ['n%02d.olmardo.com' % i for i in range(12)]
        ct = [500, paginas(*nombres[:6])[0], 500, paginas(*nombres[6:], id_=9201)[0]]
        zona = {DOMINIO: ['falla', 'falla', a('20.69.154.10')]}
        zona.update({n: ['falla', 'falla', a('20.69.154.%d' % (11 + i))] for i, n in enumerate(nombres)})
        ips = {'20.69.154.%d' % (10 + i): [500, 500, internetdb('', ports=[8080])] for i in range(13)}
        http, dns = HttpSimulado(ct, ips), ResolvedorSimulado(zona)
        res = recolectar(http, dns)
        self.assertEqual(shodan.MAX_CONSULTAS, 64)
        self.assertEqual((res.consultas, len(http.urls) + len(dns.nombres)), (shodan.MAX_CONSULTAS, shodan.MAX_CONSULTAS))
        self.assertEqual(len(http.consultadas()), shodan.MAX_IPS)
        self.assertEqual(res.sin_cobertura, codigos_sin(res))

    def test_15_los_cortes_dejan_en_sin_cobertura_solo_los_codigos_sin_hallazgos(self):
        con_dos = internetdb(CAMARA, ports=[8080, 3389])
        nombres = ['n%02d.olmardo.com' % i for i in range(12)]
        casos = {
            'MAX_NOMBRES': (HttpSimulado(paginas(*nombres), {CAMARA: con_dos}),
                            ResolvedorSimulado({DOMINIO: a(CAMARA)}), Cronometro(0),
                            'shodan: se resolvieron 10 de 13 nombres del dominio (MAX_NOMBRES)'),
            'MAX_IPS': (HttpSimulado(ips={CAMARA: con_dos}),
                        ResolvedorSimulado({DOMINIO: a(CAMARA, *('20.69.155.%d' % i for i in range(1, 11)))}),
                        Cronometro(0), 'shodan: se consultaron 10 de 11 IP en InternetDB (MAX_IPS)'),
            'tiempo': (HttpSimulado(paginas(*nombres), {CAMARA: con_dos}),
                       ResolvedorSimulado(dict({DOMINIO: a(CAMARA)}, **{n: a('20.69.156.%d' % i) for i, n in enumerate(nombres)})),
                       Cronometro(10), 'shodan: se acabó el tiempo de la corrida antes de consultar'),
        }
        for caso, (http, dns, cronometro, aviso) in casos.items():
            with self.subTest(caso=caso):
                res = recolectar(http, dns, cronometro=cronometro)
                self.assertEqual(res.estado, 'succeeded')
                self.assertEqual({h.codigo for h in res.hallazgos}, {'exposed_service', 'exposed_rdp'})
                self.assertEqual(res.sin_cobertura, codigos_sin(res))
                self.assertNotIn('exposed_service', res.sin_cobertura)
                self.assertTrue(any(x.startswith(aviso) for x in res.avisos), res.avisos)
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_16_cert_spotter_caido_sigue_con_la_raiz_y_todo_caido_es_fuente_no_responde(self):
        http = HttpSimulado([500, 500], {CAMARA: CAMARA_8080})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual([h.codigo for h in res.hallazgos], ['exposed_service'])
        self.assertEqual(res.sin_cobertura, codigos_sin(res))
        self.assertTrue(any(x.endswith('Solo se revisó la raíz') for x in res.avisos), res.avisos)
        with self.assertRaises(FuenteNoResponde):
            recolectar(HttpSimulado([500, 500]), ResolvedorSimulado({DOMINIO: 'falla'}))
        with self.assertRaises(FuenteNoResponde):   # todas las IP sin respuesta por la red
            recolectar(HttpSimulado(ips={CAMARA: 503}), ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        with tempfile.TemporaryDirectory() as d, mock.patch.object(shodan, 'CARPETA_GRABADAS', Path(d)), \
                mock.patch.object(shodan, '_descargar', HttpSimulado([500, 500])), \
                mock.patch.object(shodan, '_resolver_a', ResolvedorSimulado({DOMINIO: 'falla'})), \
                mock.patch.object(shodan.time, 'sleep', lambda s: None):
            caida = contrato.ejecutar(cargar('shodan'), DOMINIO, modo='vivo', ahora=AHORA)
        self.assertEqual(caida.estado, 'failed')
        self.assertEqual(caida.consultas, 2 + 3)

    def test_17_puertos_udp_salen_con_udp_y_protocolo_supuesto(self):
        res = recolectar(HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[161, 47808, 8080])}),
                         ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        servicios = {a.valor: a.atributos for a in res.activos if a.tipo == 'service'}
        self.assertEqual(sorted(servicios), ['20.69.154.199:161/udp', '20.69.154.199:47808/udp', '20.69.154.199:8080/tcp'])
        self.assertTrue(all(s['protocolo_supuesto'] for s in servicios.values()))
        bacnet = next(h for h in res.hallazgos if h.evidencia['puerto'] == 47808)
        self.assertEqual((bacnet.evidencia['protocolo'], bacnet.evidencia['puerto_industrial']), ('udp', True))

    def test_18_la_huella_no_cambia_con_lo_mismo_observado(self):
        uno = recolectar(HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[8080], vulns=['CVE-2024-6387'])}),
                         ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        otro = recolectar(HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[8080], vulns=['CVE-2024-6387'],
                                                               tags=['cloud'], cpes=['cpe:/a:nginx:nginx'])}),
                          ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual([h.huella for h in uno.hallazgos], [h.huella for h in otro.hallazgos])
        self.assertEqual(len({h.huella for h in uno.hallazgos}), 2)

    def test_19_cada_hallazgo_sale_con_su_severidad_del_catalogo(self):
        for codigo, severidad in shodan.CODIGOS.items():
            self.assertEqual(POR_CODIGO[codigo][5], severidad, codigo)
        for codigo in shodan.SIN_LLAVE:
            self.assertIn(codigo, POR_CODIGO)
            self.assertNotIn(codigo, shodan.CODIGOS)
        res = recolectar(HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[3389, 22, 445, 5432, 8080],
                                                              vulns=['CVE-2024-6387'])}),
                         ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual({h.codigo for h in res.hallazgos}, set(shodan.CODIGOS))
        for h in res.hallazgos:
            self.assertEqual(h.severidad, shodan.CODIGOS[h.codigo], h.codigo)

    def test_20_429_de_internetdb_corta_las_ip_que_faltan(self):
        otra, ultima = '20.69.154.200', '20.69.154.201'
        http = HttpSimulado(ips={CAMARA: CAMARA_8080, otra: 429, ultima: CAMARA_8080})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA, otra, ultima)}))
        self.assertEqual(http.por_ip, {CAMARA: 1, otra: 1})
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.sin_cobertura, codigos_sin(res))
        self.assertIn('shodan: InternetDB (%s) llegó a su límite de consultas (429, Retry-After 60 s). No se consultaron '
                      '2 IP' % otra, res.avisos)
        self.assertEqual(activo(res, ultima).atributos['internetdb'], 'sin_respuesta')

    def test_21_429_de_cert_spotter_sigue_con_la_raiz(self):
        http = HttpSimulado([429], {CAMARA: CAMARA_8080})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(len([u for u in http.urls if '?' in u]), 1)
        self.assertEqual([h.codigo for h in res.hallazgos], ['exposed_service'])
        self.assertEqual(res.sin_cobertura, codigos_sin(res))
        self.assertIn('exposed_rdp', res.sin_cobertura)

    def test_22_respuestas_rotas_de_internetdb_se_ignoran_con_aviso(self):
        rota, lista, texto = '20.69.154.210', '20.69.154.211', '20.69.154.212'
        ips = {CAMARA: {'ports': [8080, 70000, 0, True, '22'], 'vulns': ['CVE-2024-6387', 'nada'],
                        'cpes': ['cpe:/a:nginx:nginx', 'no es cpe'], 'tags': 'cloud', 'hostnames': []},
               rota: {'ports': 'muchos', 'vulns': None},
               lista: b'[1, 2]', texto: b'esto no es JSON'}
        http = HttpSimulado(ips=ips)
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA, rota, lista, texto)}))
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(sorted(h.codigo for h in res.hallazgos), ['exposed_service', 'known_vulnerability'])
        self.assertEqual(activo(res, CAMARA).atributos['internetdb']['cpes'], ['cpe:/a:nginx:nginx'])
        self.assertIn('shodan: InternetDB dio en %s datos que no se pueden leer (cpes, ports, tags, vulns) y se ignoraron'
                      % CAMARA, res.avisos)
        self.assertIn('shodan: InternetDB dio en %s datos que no se pueden leer (ports, vulns) y se ignoraron' % rota,
                      res.avisos)
        self.assertEqual(http.por_ip[lista], 1)   # un JSON que no es objeto no se reintenta
        self.assertEqual(http.por_ip[texto], shodan.INTENTOS)
        self.assertEqual(activo(res, lista).atributos['internetdb'], 'sin_respuesta')
        self.assertEqual(res.sin_cobertura, codigos_sin(res))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_23_honeypot_descarta_los_hallazgos_de_la_ip(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[22, 3389], tags=['honeypot'], vulns=['CVE-2024-6387'])})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual((res.hallazgos, [a.tipo for a in res.activos]), ([], ['ip']))
        self.assertEqual(activo(res, CAMARA).atributos['internetdb']['tags'], ['honeypot'])
        self.assertIn('shodan: InternetDB marca %s como honeypot, no se sacan hallazgos de esa IP' % CAMARA, res.avisos)

    def test_24_las_respuestas_reales_del_27_oct(self):
        """InternetDB todavía trae el 50000 de quien tuvo antes la IP de la VM de cámaras, y nada de la de reservas."""
        http = HttpSimulado(ct_olmardo(), {CAMARA: REAL_CAMARA, RESERVAS: [404]})
        res = recolectar(http, ResolvedorSimulado(zona_olmardo()))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        [h] = res.hallazgos
        self.assertEqual((h.codigo, h.activo), ('exposed_service', '20.69.154.199:50000/tcp'))
        self.assertEqual((h.evidencia['vigencia'], h.evidencia['fuente_sin_fecha'], h.evidencia['tags']),
                         ('sin_fecha', True, ['cloud']))
        datos = activo(res, CAMARA).atributos['internetdb']
        self.assertEqual(datos['cpes'], ['cpe:/a:openbsd:openssh:8.9p1', 'cpe:/o:canonical:ubuntu_linux'])
        self.assertEqual((datos['tags'], datos['vulns'], datos['hostnames']), (['cloud'], 0, []))
        self.assertEqual(activo(res, RESERVAS).atributos['internetdb'], 'sin_datos')
        self.assertEqual(activo(res, CLOUDFLARE).atributos['cdn'], 'cloudflare')
        self.assertEqual(http.consultadas(), {CAMARA, RESERVAS})
        self.assertNotIn('posible_dato_de_otro_dueno', h.evidencia)   # sin nombres en InternetDB no hay marca
        self.assertEqual(h.evidencia['nota_vigencia'], shodan.NOTA_SIN_FECHA)
        self.assertEqual(shodan.codigo_salida(res), 0)
        self.assertEqual(json.loads(REAL_404), {'detail': 'No information available'})

    def test_25_rangos_de_cloudflare_y_cpe(self):
        self.assertEqual(len(shodan.RANGOS_CLOUDFLARE), 15)
        self.assertTrue(all(r.version == 4 and r.is_global for r in shodan.RANGOS_CLOUDFLARE))
        self.assertEqual(shodan.cdn_de(CLOUDFLARE, None), 'cloudflare')
        self.assertEqual(shodan.cdn_de('131.0.72.1', None), 'cloudflare')
        self.assertIsNone(shodan.cdn_de(CAMARA, None))
        self.assertEqual(shodan.cdn_de(CAMARA, 'lowtide.azureedge.net'), 'azure_cdn')
        self.assertIsNone(shodan.cdn_de(CAMARA, 'noazureedge.net'))
        for cpe in ('cpe:/a:openbsd:openssh:8.9p1', 'cpe:/o:canonical:ubuntu_linux', 'cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'):
            self.assertTrue(shodan.CPE_VALIDO.fullmatch(cpe), cpe)
        for cpe in ('cpe:/x:algo', 'openssh 8.9', 'cpe:/a:con espacio'):
            self.assertIsNone(shodan.CPE_VALIDO.fullmatch(cpe), cpe)
        self.assertTrue(ipaddress.ip_address(CAMARA).is_global and ipaddress.ip_address(RESERVAS).is_global)

    def test_26_linea_de_comandos(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(shodan, 'CARPETA_GRABADAS', Path(d)), \
                mock.patch.dict(os.environ, {'DOMINIOS_EN_VIVO': 'olmardo.com'}):
            for argv in (['acme-demo.mx'], ['acme-demo.mx', '--grabar'], ['../x', '--reproducir'],
                         ['olmardo.com', '--grabar', '--reproducir']):
                with self.subTest(argv=argv), self.assertRaises(SystemExit) as e, redirect_stdout(io.StringIO()), \
                        mock.patch('sys.stderr', io.StringIO()):
                    shodan._main(argv)
                self.assertEqual(e.exception.code, 2)
            salida = io.StringIO()
            with redirect_stdout(salida):
                codigo = shodan._main(['acme-demo.mx', '--reproducir'])
        self.assertEqual(codigo, 2)
        self.assertIn('aviso: ' + shodan.SIN_GRABACION_DOMINIO, salida.getvalue())

    def test_27_la_grabacion_de_un_dominio_sin_ip_guarda_algo(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            res = recolectar(HttpSimulado(), ResolvedorSimulado({}), modo='grabar', carpeta=carpeta, nueva=True)
            self.assertIn(shodan.SIN_IP, res.avisos)
            self.assertTrue(list(carpeta.glob('*.json')))
            otra = recolectar(HttpSimulado(), ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
        self.assertEqual((otra.estado, otra.sin_cobertura, otra.avisos), (res.estado, res.sin_cobertura, res.avisos))


class RRset(list):
    """Un RRset de la sección de respuesta como lo lee _cadena_cname: rdtype, name y cada registro con target."""

    def __init__(self, rdtype, nombre, *destinos):
        super().__init__(mock.Mock(target=d + '.') for d in destinos)
        self.rdtype, self.name = rdtype, nombre + '.'


def respuesta_dns(canonical, *rrsets):
    return mock.Mock(canonical_name=canonical + '.', response=mock.Mock(answer=list(rrsets)))


class Arreglos(unittest.TestCase):
    """Los arreglos de la revisión de RC-49 (_plan/rc49/revision.md), uno por hallazgo."""

    def test_28_cadena_cname_con_el_intermedio_de_cdn_no_se_consulta(self):
        """etica-1: la cadena tiene 3 saltos y solo el primer destino es de un CDN (azurefd.net). El nombre final no está
        en SUFIJOS_CDN, y aun así la IP no llega a InternetDB."""
        nube = '13.107.246.40'
        cadena = ['lowtide.azurefd.net', 'star-azurefd-prod.trafficmanager.net', 'borde-final.ejemplo-cdn.net']
        self.assertIsNone(shodan.cdn_de(nube, cadena[-1]))
        zona = {DOMINIO: a(CAMARA), 'www.olmardo.com': a(nube, cname=cadena)}
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            http = HttpSimulado(paginas('www.olmardo.com'), {CAMARA: CAMARA_8080, nube: CAMARA_8080})
            res = recolectar(http, ResolvedorSimulado(zona), modo='grabar', carpeta=carpeta, nueva=True)
            self.assertEqual(http.consultadas(), {CAMARA})
            self.assertEqual(activo(res, nube).atributos['cdn'], 'azure_front_door')
            grabado = json.loads((carpeta / 'a_www.olmardo.com.json').read_text(encoding='utf-8'))['datos']
            self.assertEqual(grabado['cnames'], cadena)
            otra = recolectar(HttpSimulado(), ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
        self.assertEqual((otra.activos, otra.hallazgos), (res.activos, res.hallazgos))

    def test_29_la_cadena_sale_de_la_seccion_de_respuesta_con_cada_salto(self):
        """etica-1: _cadena_cname sigue los CNAME de la respuesta (aunque vengan en otro orden) y suma canonical_name."""
        CNAME, A = 5, 1
        resp = respuesta_dns('borde-final.ejemplo-cdn.net',
                             RRset(CNAME, 'star-azurefd-prod.trafficmanager.net', 'borde-final.ejemplo-cdn.net'),
                             RRset(CNAME, 'www.olmardo.com', 'lowtide.azurefd.net'),
                             RRset(CNAME, 'lowtide.azurefd.net', 'star-azurefd-prod.trafficmanager.net'),
                             RRset(A, 'borde-final.ejemplo-cdn.net'))
        self.assertEqual(shodan._cadena_cname(resp, 'WWW.olmardo.com.'),
                         ['lowtide.azurefd.net', 'star-azurefd-prod.trafficmanager.net', 'borde-final.ejemplo-cdn.net'])
        self.assertEqual(shodan._cadena_cname(respuesta_dns('www.olmardo.com', RRset(A, 'www.olmardo.com')),
                                              'www.olmardo.com'), [])
        ciclo = respuesta_dns('a.ejemplo.net', RRset(CNAME, 'x.olmardo.com', 'a.ejemplo.net'),
                              RRset(CNAME, 'a.ejemplo.net', 'x.olmardo.com'))
        self.assertEqual(shodan._cadena_cname(ciclo, 'x.olmardo.com'), ['a.ejemplo.net'])
        self.assertEqual(shodan.limpiar_a('ok', [CAMARA], ['B.ejemplo.net.', 'b.ejemplo.net', 'no valido!'])['cnames'],
                         ['b.ejemplo.net'])
        self.assertEqual(shodan.limpiar_a('ok', [CAMARA], 'viejo.cloudfront.net')['cnames'], ['viejo.cloudfront.net'])

    def test_30_bordes_compartidos_conocidos(self):
        """etica-4 y re-etica-1: las redes de borde compartidas comunes se tratan como CDN, también los sitios viejos de
        Netlify (netlify.com) y los CNAME numerados de Vercel (vercel-dns-NNN.com). trafficmanager.net no, porque solo
        dirige."""
        for cname, cdn in (('shops.myshopify.com', 'shopify'), ('cname.vercel-dns.com', 'vercel'),
                           ('lowtide.netlify.app', 'netlify'), ('kernel-loco.github.io', 'github_pages'),
                           ('x.herokudns.com', 'heroku'), ('a1.akamaized.net', 'akamai'), ('e1.edgesuite.net', 'akamai'),
                           ('x.incapdns.net', 'imperva'), ('shed.dual-low.t-msedge.net', 'azure_front_door'),
                           ('sitio.netlify.com', 'netlify'), ('1a2b3c.vercel-dns-017.com', 'vercel'),
                           ('vercel-dns-0.com', 'vercel'), ('a.b.vercel-dns-123.com', 'vercel')):
            self.assertEqual(shodan.cdn_de(CAMARA, cname), cdn, cname)
        for cname in ('star-azurefd-prod.trafficmanager.net', 'novercel-dns-017.com', 'x.vercel-dns-abc.com',
                      'x.vercel-dns-12345.com', 'x.vercel-dns-017.com.mx', 'minetlify.com'):
            self.assertIsNone(shodan.cdn_de(CAMARA, cname), cname)
        self.assertNotIn('trafficmanager.net', shodan.SUFIJOS_CDN)
        zona = {DOMINIO: a(CAMARA), 'app.olmardo.com': a(RESERVAS, cname='1a2b3c.vercel-dns-017.com')}
        http = HttpSimulado(paginas('app.olmardo.com'), {CAMARA: CAMARA_8080, RESERVAS: CAMARA_8080})
        res = recolectar(http, ResolvedorSimulado(zona))
        self.assertEqual(http.consultadas(), {CAMARA})
        self.assertEqual(activo(res, RESERVAS).atributos['cdn'], 'vercel')

    def test_31_grabar_con_cualquier_falla_no_pisa_la_grabacion_completa(self):
        """contrato-1 y re-contrato-1: la segunda grabación tiene una falla, de cualquier tipo (429, 403, una página o
        una emisión de Cert Spotter rota, la red, un 200 vacío o campos rotos de InternetDB, un A sin respuesta), y la
        primera queda intacta. NO_SE_GRABO va primero en los avisos (re-contrato-3) y el código de salida es 3
        (re-contrato-2). --reproducir sigue dando el hallazgo de la cámara."""
        rota = {'id': '9999', 'dns_names': ['x.olmardo.com'], 'not_before': 'no es fecha', 'not_after': None,
                'issuer': {'name': 'R3'}}
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            buena = recolectar(HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080}), ResolvedorSimulado(zona_olmardo()),
                               modo='grabar', carpeta=carpeta, nueva=True)
            self.assertNotIn(shodan.NO_SE_GRABO, buena.avisos)
            self.assertEqual(shodan.codigo_salida(buena), 0)
            archivos = {p.name: p.read_bytes() for p in carpeta.iterdir()}
            casos = {
                '429 de Cert Spotter': (HttpSimulado([429], {CAMARA: CAMARA_8080}), zona_olmardo()),
                '403 de Cert Spotter': (HttpSimulado([403], {CAMARA: CAMARA_8080}), zona_olmardo()),
                'página de Cert Spotter rota': (HttpSimulado([[rota]], {CAMARA: CAMARA_8080}), zona_olmardo()),
                'emisión ilegible de Cert Spotter': (HttpSimulado([ct_olmardo()[0] + [rota], []], {CAMARA: CAMARA_8080}),
                                                     zona_olmardo()),
                'segunda página de Cert Spotter caída': (HttpSimulado([ct_olmardo()[0], 500, 500], {CAMARA: CAMARA_8080}),
                                                         zona_olmardo()),
                '429 de InternetDB': (HttpSimulado(ct_olmardo(), {CAMARA: 429}), zona_olmardo()),
                'red de InternetDB': (HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080, RESERVAS: 503}), zona_olmardo()),
                '200 vacío de InternetDB': (HttpSimulado(ct_olmardo(), {CAMARA: b'', RESERVAS: b''}), zona_olmardo()),
                'campos rotos de InternetDB': (HttpSimulado(ct_olmardo(), {CAMARA: {'ports': 'muchos'}}), zona_olmardo()),
                'A sin respuesta': (HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080}),
                                    zona_olmardo(**{'eventos.olmardo.com': 'falla'})),
            }
            for caso, (http, zona) in casos.items():
                with self.subTest(caso=caso):
                    res = recolectar(http, ResolvedorSimulado(zona), modo='grabar', carpeta=carpeta, nueva=True)
                    self.assertEqual(res.estado, 'succeeded')
                    self.assertEqual(res.avisos[0], shodan.NO_SE_GRABO)
                    self.assertEqual(shodan.codigo_salida(res), 3)
                    self.assertEqual({p.name: p.read_bytes() for p in carpeta.iterdir()}, archivos)
            otra = recolectar(HttpSimulado(), ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
        self.assertEqual((otra.activos, otra.hallazgos), (buena.activos, buena.hallazgos))
        self.assertEqual([h.activo for h in otra.hallazgos], ['20.69.154.199:8080/tcp'])

    def test_32_un_200_vacio_o_null_no_es_sin_datos(self):
        """contrato-3: solo el 404 da 'sin_datos'. Un 200 sin cuerpo o con 'null' no se puede leer, no se reintenta y
        deja la cobertura parcial."""
        for cuerpo in (b'', b'  ', b'null'):
            with self.subTest(cuerpo=cuerpo):
                http = HttpSimulado(ips={CAMARA: cuerpo})
                res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                self.assertEqual(http.por_ip, {CAMARA: 1})
                self.assertEqual(activo(res, CAMARA).atributos['internetdb'], 'sin_respuesta')
                self.assertEqual(res.sin_cobertura, codigos_sin(res))
                self.assertTrue(any(x.startswith('shodan: InternetDB (%s) respondió' % CAMARA) for x in res.avisos))
        res = recolectar(HttpSimulado(ips={CAMARA: 404}), ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(activo(res, CAMARA).atributos['internetdb'], 'sin_datos')

    def test_33_el_codigo_de_salida_no_cuenta_el_aviso_fijo(self):
        """contrato-4: 0 con una corrida completa aunque lleve LIMITES, 2 solo con cobertura parcial y 1 si falla."""
        completa = recolectar(HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080}), ResolvedorSimulado(zona_olmardo()))
        self.assertIn(shodan.LIMITES, completa.avisos)
        self.assertEqual(shodan.codigo_salida(completa), 0)
        parcial = recolectar(HttpSimulado([429], {CAMARA: CAMARA_8080}), ResolvedorSimulado(zona_olmardo()))
        self.assertEqual(shodan.codigo_salida(parcial), 2)
        self.assertEqual(shodan.codigo_salida(contrato.Resultado(DOMINIO, 'shodan', estado='failed')), 1)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(shodan, 'CARPETA_GRABADAS', Path(d)):
            recolectar(HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080}), ResolvedorSimulado(zona_olmardo()),
                       modo='grabar', carpeta=Path(d) / DOMINIO, nueva=True)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(shodan._main([DOMINIO, '--reproducir']), 0)

    def test_34_el_corte_por_tiempo_no_se_graba_y_deja_la_anterior(self):
        """contrato-5 y re-contrato-4: el corte por tiempo es una falla, así que --grabar no escribe nada. Primero se
        graba una corrida completa. Después cada A tarda 100 s, el corte de MIN_RESTANTE llega en el quinto nombre y
        la corrida avisa los 3 nombres que no resolvió, pone NO_SE_GRABO primero, sale con 3 y no toca la grabación
        anterior, que --reproducir sigue dando completa. Ninguna falla 'tiempo' llega al disco."""
        nombres = ['n%02d.olmardo.com' % i for i in range(6)]
        zona = dict({DOMINIO: a(CAMARA)}, **{n: a('20.69.157.%d' % i) for i, n in enumerate(nombres)})
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            completa = recolectar(HttpSimulado(paginas(*nombres), {CAMARA: CAMARA_8080}), ResolvedorSimulado(zona),
                                  modo='grabar', carpeta=carpeta, nueva=True)
            self.assertNotIn(shodan.NO_SE_GRABO, completa.avisos)
            archivos = {p.name: p.read_bytes() for p in carpeta.iterdir()}
            dns = ResolvedorSimulado(zona)
            cliente = shodan.ClienteShodan(modo='grabar', carpeta=carpeta, descargar=HttpSimulado(paginas(*nombres)),
                                           resolver=dns, nueva=True, cronometro=lambda: 1000 + 100 * len(dns.nombres),
                                           dormir=lambda s: None)
            res = shodan.recolectar(DOMINIO, cliente, ahora=AHORA)
            self.assertIn('shodan: se acabó el tiempo de la corrida antes de resolver 3 nombres', res.avisos)
            self.assertEqual(res.avisos[0], shodan.NO_SE_GRABO)
            self.assertEqual(shodan.codigo_salida(res), 3)
            self.assertEqual({p.name: p.read_bytes() for p in carpeta.iterdir()}, archivos)
            self.assertFalse(any(b'"tiempo"' in x for x in archivos.values()))
            http = HttpSimulado()
            otra = recolectar(http, ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
        self.assertEqual(http.urls, [])
        self.assertEqual((otra.activos, otra.hallazgos, otra.avisos), (completa.activos, completa.hallazgos, completa.avisos))

    def test_35_multicast_reservadas_y_6to4_no_se_consultan(self):
        """etica-2: ipaddress da is_global True para multicast y 192.88.99.0/24, pero no se mandan a InternetDB."""
        raras = ('224.0.0.1', '233.252.0.1', '192.88.99.1', '239.255.255.250')
        for ip in raras:
            self.assertFalse(shodan.consultable(ip), ip)
        self.assertTrue(shodan.consultable(CAMARA))
        http = HttpSimulado(ips={ip: CAMARA_8080 for ip in raras})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(*raras)}))
        self.assertEqual(http.consultadas(), set())
        self.assertTrue(all(activo(res, ip).atributos['no_publica'] for ip in raras))
        self.assertIn(shodan.SIN_IP, res.avisos)

    def test_36_fuente_datos_solo_en_las_ip_que_respondio_internetdb(self):
        """etica-5: CDN, no pública, sin respuesta y sin consultar no llevan fuente_datos. Las que respondieron sí."""
        caida, sin_datos = '20.69.154.150', '20.69.154.151'
        zona = {DOMINIO: a(CLOUDFLARE, '10.0.0.5', CAMARA, caida, sin_datos)}
        res = recolectar(HttpSimulado(ips={CAMARA: CAMARA_8080, caida: 503, sin_datos: 404}), ResolvedorSimulado(zona))
        for ip in (CLOUDFLARE, '10.0.0.5', caida):
            self.assertNotIn('fuente_datos', activo(res, ip).atributos, ip)
        for ip in (CAMARA, sin_datos):
            self.assertEqual(activo(res, ip).atributos['fuente_datos'], 'Shodan InternetDB', ip)
        cortada = recolectar(HttpSimulado(ips={CAMARA: CAMARA_8080}),
                             ResolvedorSimulado({DOMINIO: a(CAMARA, *('20.69.155.%d' % i for i in range(1, 11)))}))
        self.assertEqual(activo(cortada, '20.69.155.10').atributos['internetdb'], 'sin_consultar')
        self.assertNotIn('fuente_datos', activo(cortada, '20.69.155.10').atributos)

    def test_37_dato_sin_nombres_no_lleva_la_marca_y_explica_la_vigencia(self):
        """etica-3: la respuesta real de 20.69.154.199 no trae nombres, así que no lleva posible_dato_de_otro_dueno,
        pero su evidencia explica que InternetDB no fecha el dato y que puede ser de otro dueño."""
        res = recolectar(HttpSimulado(ips={CAMARA: REAL_CAMARA}), ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        [h] = res.hallazgos
        self.assertNotIn('posible_dato_de_otro_dueno', h.evidencia)
        self.assertEqual((h.evidencia['vigencia'], h.evidencia['nota_vigencia']), ('sin_fecha', shodan.NOTA_SIN_FECHA))
        self.assertIn('quien tuvo la IP antes', shodan.NOTA_SIN_FECHA)

    def test_38_un_200_sin_ports_o_con_campos_rotos_deja_la_ip_parcial(self):
        """tiempos-2: con una sola IP, un 200 con {}, con {'detail': ...} o con 'ports' roto no es 'nada abierto'."""
        for cuerpo in ({}, json.loads(REAL_404), {'ports': 'muchos', 'vulns': None}):
            with self.subTest(cuerpo=cuerpo):
                res = recolectar(HttpSimulado(ips={CAMARA: cuerpo}), ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                self.assertEqual((res.estado, res.hallazgos), ('succeeded', []))
                self.assertEqual(res.sin_cobertura, list(shodan.CODIGOS) + list(shodan.SIN_LLAVE))
                self.assertTrue(any(x.startswith('shodan: InternetDB dio en %s datos que no se pueden leer (' % CAMARA)
                                    and 'ports' in x for x in res.avisos), res.avisos)
                self.assertEqual(shodan.codigo_salida(res), 2)

    def test_39_el_tiempo_de_la_corrida_acota_el_lifetime_y_las_esperas(self):
        """tiempos-3: con 3 s restantes el A usa lifetime 3, y una espera de 15 s duerme solo lo que queda."""
        reloj = {'t': 0.0}
        dormidas = []

        def dormir(s):
            dormidas.append(s)
            reloj['t'] += s
        dns = ResolvedorSimulado({DOMINIO: ['falla', a(CAMARA)]})
        cliente = shodan.ClienteShodan(resolver=dns, cronometro=lambda: reloj['t'], dormir=dormir)
        cliente.empezar()
        reloj['t'] = shodan.TIEMPO_CORRIDA - 8
        cliente.esperar(15)
        self.assertEqual(dormidas, [8])
        reloj['t'] = shodan.TIEMPO_CORRIDA - 9   # falla con lifetime 5, duerme 5 y al segundo intento quedan 4
        self.assertEqual(cliente.resolver_a(DOMINIO)['ips'], [CAMARA])
        self.assertEqual(dns.lifetimes, [shodan.TIMEOUT_DNS, 4])
        reloj['t'] = shodan.TIEMPO_CORRIDA - 3
        dns2 = ResolvedorSimulado({'x.olmardo.com': 'falla'})
        cliente.resolver = dns2
        dormidas.clear()
        with self.assertRaises(shodan.SinTiempo):
            cliente.resolver_a('x.olmardo.com')
        self.assertEqual(dns2.lifetimes, [3])
        self.assertEqual(dormidas, [3])   # la espera de 5 s se acota a los 3 que quedaban, y el siguiente es SinTiempo

    def test_40_las_cve_se_normalizan_antes_de_quitar_repetidas(self):
        """tiempos-6: CVE-2014-0160 escrita con ceros de más o en minúsculas es la misma: un solo hallazgo.
        re-tiempos-1: un número de más de 19 dígitos, o con dígitos que no son ASCII, no llega a int() y cuenta como
        roto, así la corrida no se cae con ValueError y 'vulns' deja la cobertura parcial."""
        self.assertEqual(shodan._cve('cve-2014-00160'), 'CVE-2014-0160')
        self.assertEqual(shodan._cve('CVE-2021-44228'), 'CVE-2021-44228')
        self.assertEqual(shodan._cve('CVE-2014-000000160'), 'CVE-2014-0160')
        self.assertIsNone(shodan._cve('CVE-14-0160'))
        self.assertEqual(shodan._cve('CVE-2024-' + '9' * 19), 'CVE-2024-' + '9' * 19)
        enorme = 'CVE-2024-' + '1' * 5000
        for rara in (enorme, 'CVE-2024-' + '1' * 20, 'CVE-٢٠٢٤-6387', 'CVE-2024-٦٣٨٧'):
            self.assertIsNone(shodan._cve(rara), rara[:40])
        vulns = ['CVE-2014-0160', 'cve-2014-00160', 'CVE-2014-000160', 'CVE-2024-6387']
        res = recolectar(HttpSimulado(ips={CAMARA: internetdb(CAMARA, vulns=vulns)}), ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual([h.clave for h in res.hallazgos], ['CVE-2024-6387', 'CVE-2014-0160'])
        self.assertEqual(activo(res, CAMARA).atributos['internetdb']['vulns'], 2)
        self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))   # no hay campos rotos
        rota = recolectar(HttpSimulado(ips={CAMARA: internetdb(CAMARA, vulns=['CVE-2024-6387', enorme])}),
                          ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(rota.estado, 'succeeded')
        self.assertEqual([h.clave for h in rota.hallazgos], ['CVE-2024-6387'])
        self.assertIn('shodan: InternetDB dio en %s datos que no se pueden leer (vulns) y se ignoraron' % CAMARA,
                      rota.avisos)
        self.assertEqual(rota.sin_cobertura, codigos_sin(rota))

    def test_41_los_topes_deterministas_si_se_graban(self):
        """re-contrato-1: los únicos recortes que no impiden grabar son los topes deterministas: PAGINAS_CT (dos páginas
        llenas, sin la vacía que cierra), MAX_NOMBRES, MAX_IPS y MAX_CVE. La corrida queda parcial (código 2), se graba
        y --reproducir da lo mismo."""
        nombres = ['n%02d.olmardo.com' % i for i in range(12)]
        ct = [paginas(*nombres[:6])[0], paginas(*nombres[6:], id_=9201)[0]]
        zona = {DOMINIO: a(CAMARA, *('20.69.155.%d' % i for i in range(1, 11)))}
        cves = ['CVE-2024-%04d' % (1000 + i) for i in range(30)]
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            http = HttpSimulado(ct, {CAMARA: internetdb(CAMARA, ports=[8080], vulns=cves)})
            res = recolectar(http, ResolvedorSimulado(zona), modo='grabar', carpeta=carpeta, nueva=True)
            self.assertEqual(len([u for u in http.urls if '?' in u]), shodan.PAGINAS_CT)
            self.assertNotIn(shodan.NO_SE_GRABO, res.avisos)
            for aviso in ('shodan: Cert Spotter no dio todas sus páginas', 'shodan: se resolvieron 10 de 13 nombres',
                          'shodan: se consultaron 10 de 11 IP', 'shodan: %s trae 30 CVE' % CAMARA):
                self.assertTrue(any(x.startswith(aviso) for x in res.avisos), aviso)
            self.assertEqual(shodan.codigo_salida(res), 2)
            self.assertTrue(list(carpeta.glob('internetdb_*.json')))
            otra = recolectar(HttpSimulado(), ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
        self.assertEqual((otra.activos, otra.hallazgos, otra.sin_cobertura, otra.avisos),
                         (res.activos, res.hallazgos, res.sin_cobertura, res.avisos))

    def test_42_sin_grabar_el_cli_sale_con_3_y_el_aviso_entra_en_los_10_del_orquestador(self):
        """re-contrato-2 y re-contrato-3: python -m cirdan.recolectores.shodan --grabar sale con 3 si no escribió, y
        con 0 si grabó una corrida completa. Con 8 A caídos hay más de 10 avisos y NO_SE_GRABO sigue en avisos[:10],
        lo que guarda el orquestador en raw_payload."""
        with tempfile.TemporaryDirectory() as d, mock.patch.object(shodan, 'CARPETA_GRABADAS', Path(d)), \
                mock.patch.dict(os.environ, {'DOMINIOS_EN_VIVO': DOMINIO}), \
                mock.patch.object(shodan.time, 'sleep', lambda s: None), \
                mock.patch.object(shodan, '_resolver_a', ResolvedorSimulado(zona_olmardo())):
            with mock.patch.object(shodan, '_descargar', HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080})), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(shodan._main([DOMINIO, '--grabar']), 0)
            archivos = {p.name: p.read_bytes() for p in (Path(d) / DOMINIO).iterdir()}
            salida = io.StringIO()
            with mock.patch.object(shodan, '_descargar', HttpSimulado([429], {CAMARA: CAMARA_8080})), \
                    redirect_stdout(salida):
                self.assertEqual(shodan._main([DOMINIO, '--grabar']), 3)
            self.assertIn('aviso: ' + shodan.NO_SE_GRABO, salida.getvalue())
            self.assertEqual({p.name: p.read_bytes() for p in (Path(d) / DOMINIO).iterdir()}, archivos)
        nombres = ['n%d.olmardo.com' % i for i in range(8)]
        zona = dict({DOMINIO: a(CAMARA)}, **{n: 'falla' for n in nombres})
        with tempfile.TemporaryDirectory() as d:
            res = recolectar(HttpSimulado(paginas(*nombres), {CAMARA: CAMARA_8080}), ResolvedorSimulado(zona),
                             modo='grabar', carpeta=Path(d) / DOMINIO, nueva=True)
        self.assertGreater(len(res.avisos), 10)
        self.assertEqual(res.avisos[0], shodan.NO_SE_GRABO)
        self.assertIn(shodan.NO_SE_GRABO, res.avisos[:10])

    def test_43_una_respuesta_http_lenta_no_pasa_de_su_plazo(self):
        """re-tiempos-2: _descargar tiene un plazo absoluto para toda la petición. Un servidor que manda un byte cada
        5 s (reloj simulado, sin red ni dormir) se corta con SinTiempo al pasar los 10 s, aunque cada lectura del
        socket llegue antes de su timeout. En el cliente, si aún queda corrida eso es una falla de red que se reintenta,
        y si ya no queda es el corte por tiempo."""
        reloj = {'t': 0.0}

        class Lenta:
            def __init__(self, partes, paso):
                self.partes, self.paso, self.lecturas = list(partes), paso, 0

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read1(self, n):
                self.lecturas += 1
                reloj['t'] += self.paso
                return self.partes.pop(0)[:n] if self.partes else b''

        lenta = Lenta([b'{'] * 100, 5)
        with mock.patch.object(shodan.urllib.request, 'urlopen', lambda req, timeout: lenta):
            with self.assertRaises(shodan.SinTiempo):
                shodan._descargar(shodan.URL_INTERNETDB + CAMARA, 10, cronometro=lambda: reloj['t'])
        self.assertEqual(lenta.lecturas, 3)    # a los 15 s ya no lee otra parte
        reloj['t'] = 0.0
        rapida = Lenta([b'{"ports":', b' [8080]}'], 1)
        with mock.patch.object(shodan.urllib.request, 'urlopen', lambda req, timeout: rapida):
            self.assertEqual(shodan._descargar(shodan.URL_INTERNETDB + CAMARA, 10, cronometro=lambda: reloj['t']),
                             b'{"ports": [8080]}')
        enorme = Lenta([b'x' * shodan.BLOQUE] * 20, 0)
        with mock.patch.object(shodan.urllib.request, 'urlopen', lambda req, timeout: enorme), \
                self.assertRaises(ValueError):
            shodan._descargar(shodan.URL_INTERNETDB + CAMARA, 10, cronometro=lambda: 0)

        def tarda(url, timeout):
            reloj['t'] += timeout
            raise shodan.SinTiempo('shodan: la respuesta tardó más de %s s' % timeout)
        reloj['t'] = 0.0
        cliente = shodan.ClienteShodan(descargar=tarda, cronometro=lambda: reloj['t'], dormir=lambda s: None)
        cliente.empezar()
        with self.assertRaises(FuenteNoResponde) as e:
            cliente.internetdb(CAMARA, DOMINIO)
        self.assertNotIsInstance(e.exception, shodan.SinTiempo)
        self.assertIn('TimeoutError', str(e.exception))
        self.assertEqual((cliente.consultas, cliente.fallas), (shodan.INTENTOS, 1))
        reloj['t'] = shodan.TIEMPO_CORRIDA - 6
        with self.assertRaises(shodan.SinTiempo):
            cliente.internetdb(RESERVAS, DOMINIO)
        self.assertEqual(cliente.consultas, shodan.INTENTOS + 1)


class Geo(unittest.TestCase):
    """País, ASN y proveedor de DB-IP Lite en los activos ip, y el CDN por ASN antes de InternetDB (#15b, RC-166). Los
    lectores son falsos: los registros tienen la forma de DB-IP pero son inventados."""

    FASTLY, AMAZON = '151.101.1.10', '3.33.152.147'

    def con_bases(self, b):
        """Cambia las Bases de esta prueba y devuelve el mock, para contar cuántas veces se pidieron."""
        parche = mock.patch.object(geoip, 'bases_por_omision', return_value=b)
        self.addCleanup(parche.stop)
        return parche.start()

    def bases_llenas(self):
        asn = LectorFalso({CAMARA: registro_asn(8075, 'Microsoft Corporation'),
                           RESERVAS: registro_asn(8075, 'Microsoft Corporation'),
                           self.FASTLY: registro_asn(54113, 'Fastly, Inc.'),
                           self.AMAZON: registro_asn(16509, 'Amazon.com, Inc.'),
                           CLOUDFLARE: registro_asn(13335, 'Cloudflare, Inc.')})
        pais = LectorFalso({ip: registro_pais('US') for ip in (CAMARA, RESERVAS, self.FASTLY, self.AMAZON, CLOUDFLARE)})
        return bases(asn, pais)

    def test_44_cada_activo_ip_lleva_pais_asn_y_proveedor(self):
        pedidas = self.con_bases(self.bases_llenas())
        http = HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080})
        res = recolectar(http, ResolvedorSimulado(zona_olmardo()))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        camara = activo(res, CAMARA).atributos
        self.assertEqual({k: camara[k] for k in CLAVES_GEO}, {'pais': 'US', 'asn': 8075, 'proveedor': 'Microsoft Corporation',
                                                              'fuente_geo': 'DB-IP Lite', 'base_geo': NOMBRES})
        self.assertNotIn('cdn', camara)
        self.assertEqual(camara['internetdb']['puertos'], [8080])
        # la IP de Cloudflare sale por sus rangos, como antes, y también lleva su ubicación
        self.assertEqual({k: activo(res, CLOUDFLARE).atributos[k] for k in ('cdn', 'asn', 'internetdb')},
                         {'cdn': 'cloudflare', 'asn': 13335, 'internetdb': 'no_consultada'})
        self.assertEqual(activo(res, RESERVAS).atributos['proveedor'], 'Microsoft Corporation')
        self.assertEqual(pedidas.call_count, 1)   # una vez por corrida, no una por IP
        self.assertFalse([x for x in res.avisos if 'DB-IP' in x and x != shodan.LIMITES])

    def test_45_una_ip_de_un_asn_de_cdn_sin_cname_no_se_consulta_y_las_de_nube_mixta_si(self):
        """Fastly (54113) sin CNAME a la vista no llega a InternetDB. Microsoft (8075) y Amazon (16509) son nubes mixtas:
        sus IP sí se consultan, y su CDN solo sale por el CNAME."""
        self.con_bases(self.bases_llenas())
        zona = {DOMINIO: a(CAMARA), 'www.olmardo.com': a(self.FASTLY), 'tienda.olmardo.com': a(self.AMAZON)}
        http = HttpSimulado(paginas('www.olmardo.com', 'tienda.olmardo.com'),
                            {CAMARA: CAMARA_8080, self.FASTLY: CAMARA_8080, self.AMAZON: 404})
        res = recolectar(http, ResolvedorSimulado(zona))
        self.assertEqual(http.consultadas(), {CAMARA, self.AMAZON})
        self.assertNotIn(self.FASTLY, http.por_ip)
        fastly = activo(res, self.FASTLY).atributos
        self.assertEqual({k: fastly[k] for k in ('cdn', 'internetdb', 'asn', 'proveedor')},
                         {'cdn': 'fastly', 'internetdb': 'no_consultada', 'asn': 54113, 'proveedor': 'Fastly, Inc.'})
        self.assertNotIn('fuente_datos', fastly)
        self.assertNotIn('cdn', activo(res, CAMARA).atributos)
        self.assertEqual(activo(res, self.AMAZON).atributos['internetdb'], 'sin_datos')
        self.assertEqual([h.activo for h in res.hallazgos], ['20.69.154.199:8080/tcp'])
        self.assertEqual(res.consultas, 2 + 3 + 2)   # dos páginas de Cert Spotter, tres A y dos IP: Fastly no gastó
        self.assertEqual((res.estado, res.sin_cobertura), ('succeeded', list(shodan.SIN_LLAVE)))

    def test_46_sin_base_no_disponible_con_un_solo_aviso_y_sin_ip_ningun_aviso(self):
        sin_base = bases(nombres=[], problema='maxminddb no está instalado')
        pedidas = self.con_bases(sin_base)
        res = recolectar(HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080}), ResolvedorSimulado(zona_olmardo()))
        ips = [a.atributos for a in res.activos if a.tipo == 'ip']
        self.assertEqual(len(ips), 3)
        for atributos in ips:
            self.assertEqual({k: atributos[k] for k in CLAVES_GEO},
                             {'pais': NO, 'asn': NO, 'proveedor': NO, 'fuente_geo': NO, 'base_geo': NO})
        aviso = geoip.aviso_sin_base('shodan', sin_base, sin_asn=shodan.SIN_CDN_POR_ASN)
        self.assertEqual(res.avisos.count(aviso), 1)
        self.assertTrue(aviso.startswith('shodan: sin la base local de DB-IP Lite (maxminddb no está instalado)'))
        self.assertEqual((res.estado, res.sin_cobertura), ('succeeded', list(shodan.SIN_LLAVE)))
        self.assertEqual(shodan.codigo_salida(res), 0)   # no deja la cobertura parcial
        pedidas.reset_mock()
        vacio = recolectar(HttpSimulado(), ResolvedorSimulado({}))
        self.assertFalse([x for x in vacio.avisos if 'DB-IP' in x and x != shodan.LIMITES], vacio.avisos)
        self.assertEqual(pedidas.call_count, 0)

    def test_47_la_ubicacion_no_se_graba_y_reproducir_da_lo_mismo_salvo_la_ubicacion(self):
        """Grabado con la base y reproducido con ella da lo mismo. Reproducido sin la base, todo es lo de antes salvo lo
        nuevo de geoip y el aviso: la ubicación es de la base del momento, no de la grabación."""
        self.con_bases(self.bases_llenas())
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            vivo = recolectar(HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080, RESERVAS: 404}),
                              ResolvedorSimulado(zona_olmardo()), modo='grabar', carpeta=carpeta, nueva=True)
            self.assertNotIn(shodan.NO_SE_GRABO, vivo.avisos)
            for archivo in carpeta.glob('*.json'):
                texto = archivo.read_text(encoding='utf-8')
                for clave in ('DB-IP', 'pais', 'proveedor', 'Microsoft'):
                    self.assertNotIn(clave, texto, archivo.name)
            con_base = recolectar(HttpSimulado(), ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
            sin_base = bases(nombres=[], problema='falta dbip-asn-lite-AAAA-MM.mmdb en datos/geo')
            with mock.patch.object(geoip, 'bases_por_omision', return_value=sin_base):
                http = HttpSimulado()
                otra = recolectar(http, ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
        self.assertEqual(http.urls, [])
        self.assertEqual((con_base.activos, con_base.hallazgos, con_base.sin_cobertura, con_base.avisos),
                         (vivo.activos, vivo.hallazgos, vivo.sin_cobertura, vivo.avisos))

        def sin_geo(res):
            return [(a.tipo, a.valor, {k: v for k, v in a.atributos.items() if k not in CLAVES_GEO}) for a in res.activos]
        self.assertEqual(sin_geo(otra), sin_geo(vivo))
        self.assertEqual((otra.hallazgos, otra.sin_cobertura), (vivo.hallazgos, vivo.sin_cobertura))
        self.assertEqual(sorted(otra.avisos),
                         sorted(vivo.avisos + [geoip.aviso_sin_base('shodan', sin_base, sin_asn=shodan.SIN_CDN_POR_ASN)]))
        self.assertEqual((activo(otra, CAMARA).atributos['asn'], activo(vivo, CAMARA).atributos['asn']), (NO, 8075))

    def test_48_el_aviso_de_limites_ya_no_deja_el_cdn_para_15b(self):
        """geo-G2: LIMITES no dice que solo se escapan los CDN de una nube mixta. También los que no están en
        CDN_POR_ASN (CDN77, Edgecast u otros) y todos cuando falta la base."""
        self.assertNotIn('#15b', shodan.LIMITES)
        for texto in ('CNAME conocido', 'geoip.CDN_POR_ASN', 'nubes mixtas', 'otros fuera de la lista',
                      'sin la base de DB-IP'):
            self.assertIn(texto, shodan.LIMITES)
        self.assertEqual(shodan.MAX_CONSULTAS, 64)   # la ubicación es local: no suma consultas

    def test_49_sin_la_base_de_asn_el_cdn_por_asn_se_consulta_y_el_aviso_lo_dice(self):
        """geo-G1: sin la base de ASN, Fastly sin CNAME sí llega a InternetDB (la conducta no cambia), y el único aviso
        de base faltante dice que esas IP no se pudieron descartar. Si falta solo la de países, el filtro sí corre y el
        aviso no lo menciona."""
        llenas = self.bases_llenas()
        zona = {DOMINIO: a(CAMARA), 'www.olmardo.com': a(self.FASTLY)}
        sin_asn = bases(pais=llenas.pais, nombres=NOMBRES[1:], problema='falta dbip-asn-lite-AAAA-MM.mmdb en datos/geo')
        self.con_bases(sin_asn)
        http = HttpSimulado(paginas('www.olmardo.com'), {CAMARA: CAMARA_8080, self.FASTLY: 404})
        res = recolectar(http, ResolvedorSimulado(zona))
        self.assertEqual(http.consultadas(), {CAMARA, self.FASTLY})
        geo = [x for x in res.avisos if 'DB-IP Lite (' in x]
        self.assertEqual(geo, ['shodan: sin la base local de DB-IP Lite (falta dbip-asn-lite-AAAA-MM.mmdb en datos/geo), '
                               'el ASN y el proveedor de las IP quedan como No disponible, y ' + shodan.SIN_CDN_POR_ASN])
        self.assertNotIn('cdn', activo(res, self.FASTLY).atributos)
        sin_pais = bases(asn=llenas.asn, nombres=NOMBRES[:1], problema='falta dbip-country-lite-AAAA-MM.mmdb en datos/geo')
        self.con_bases(sin_pais)
        http = HttpSimulado(paginas('www.olmardo.com'), {CAMARA: CAMARA_8080})
        res = recolectar(http, ResolvedorSimulado(zona))
        self.assertEqual(http.consultadas(), {CAMARA})
        self.assertEqual([x for x in res.avisos if 'DB-IP Lite (' in x],
                         ['shodan: sin la base local de DB-IP Lite (falta dbip-country-lite-AAAA-MM.mmdb en datos/geo), '
                          'el país de las IP queda como No disponible'])

    def test_50_con_solo_ip_que_no_se_ubican_no_se_piden_las_bases_ni_hay_aviso(self):
        """geo-G5: con solo IP privadas no se busca nada en la base, así que tampoco sale el aviso de base faltante. Las
        IP igual llevan sus atributos de geo con 'No disponible'."""
        pedidas = self.con_bases(bases(nombres=[], problema='maxminddb no está instalado'))
        res = recolectar(HttpSimulado(paginas('intranet.olmardo.com')),
                         ResolvedorSimulado({DOMINIO: a('10.0.0.1'), 'intranet.olmardo.com': a('192.168.1.10')}))
        self.assertEqual(pedidas.call_count, 0)
        self.assertFalse([x for x in res.avisos if 'DB-IP Lite (' in x], res.avisos)
        for ip in ('10.0.0.1', '192.168.1.10'):
            atributos = activo(res, ip).atributos
            self.assertEqual({k: atributos[k] for k in CLAVES_GEO}, dict.fromkeys(CLAVES_GEO, NO))
            self.assertEqual(atributos['no_publica'], True)

    def test_51_reproducir_con_otra_base_deja_sin_grabacion_la_ip_que_era_cdn_por_asn(self):
        """geo-G3: grabado con una base que marca a Fastly como CDN por ASN, su IP no se consulta ni se graba. Si se
        reproduce con una base que ya no trae ese ASN, la IP se pide a la grabación, no está y la corrida queda parcial
        por 'grabacion', con su aviso y sin red. Es lo que dice docs/contrato_plugin.md: la grabación no cambia."""
        self.con_bases(self.bases_llenas())
        zona = {DOMINIO: a(CAMARA), 'www.olmardo.com': a(self.FASTLY)}
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            vivo = recolectar(HttpSimulado(paginas('www.olmardo.com'), {CAMARA: CAMARA_8080}), ResolvedorSimulado(zona),
                              modo='grabar', carpeta=carpeta, nueva=True)
            self.assertNotIn(shodan.NO_SE_GRABO, vivo.avisos)
            self.assertEqual(activo(vivo, self.FASTLY).atributos['cdn'], 'fastly')
            self.assertFalse((carpeta / ('internetdb_%s.json' % self.FASTLY)).exists())
            otra_base = bases(LectorFalso({CAMARA: registro_asn(8075, 'Microsoft Corporation')}),
                              LectorFalso({CAMARA: registro_pais('US')}))
            self.con_bases(otra_base)
            http = HttpSimulado()
            otra = recolectar(http, ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
        self.assertEqual(http.urls, [])
        self.assertIn('shodan: %sinternetdb:%s' % (contrato.SIN_GRABACION, self.FASTLY), otra.avisos)
        fastly = activo(otra, self.FASTLY).atributos
        self.assertEqual((fastly['internetdb'], 'cdn' in fastly), ('sin_respuesta', False))
        self.assertEqual(otra.hallazgos, vivo.hallazgos)   # lo de la cámara sí estaba grabado
        self.assertEqual(otra.sin_cobertura, codigos_sin(otra))
        self.assertEqual((otra.estado, shodan.codigo_salida(otra)), ('succeeded', 2))


class Semilla(unittest.TestCase):
    """base-3: lectura estática de db/semillas/007_shodan.sql, sin base."""

    def test_1_shodan_tiene_10_corridas_por_dia_y_client_encoding_antes_de_begin(self):
        texto = SEMILLA.read_text(encoding='utf-8')
        sin_comentarios = '\n'.join(linea.split('--')[0] for linea in texto.splitlines())
        [limite] = re.findall(r"UPDATE\s+data_sources\s+SET\s+daily_limit\s*=\s*(\d+)\s+WHERE\s+code\s*=\s*'shodan'",
                              sin_comentarios)
        self.assertEqual(int(limite), 10 * shodan.MAX_CONSULTAS)
        self.assertIn("SET client_encoding = 'UTF8';", sin_comentarios)
        self.assertLess(sin_comentarios.index("SET client_encoding = 'UTF8';"), sin_comentarios.index('BEGIN;'))
        self.assertIn('AND daily_limit IS NULL', sin_comentarios)


if __name__ == '__main__':
    unittest.main()
