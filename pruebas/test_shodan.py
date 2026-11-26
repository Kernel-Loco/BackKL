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
from pruebas.test_catalogo_reglas import FILA_TEXTO, POR_CODIGO  # noqa: E402
from pruebas.test_certspotter import emision  # noqa: E402
from pruebas.test_crtsh import AHORA  # noqa: E402
from pruebas.test_subfinder import Cronometro  # noqa: E402
from pruebas.test_geoip import NOMBRES, LectorFalso, bases, registro_asn, registro_pais  # noqa: E402
from cirdan.recolectores import REGISTRO, cargar, contrato, geoip, rangos_cdn, shodan  # noqa: E402
from cirdan.recolectores.contrato import FuenteNoResponde  # noqa: E402
from cirdan.score import plan as plan_accion  # noqa: E402

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
ETQ = shodan.PARTE_ETIQUETAS
CLAVES_GEO = ('pais', 'asn', 'proveedor', 'fuente_geo', 'base_geo')


ASN_DOC = 64500   # ASN de documentación (RFC 5398): no es de ningún CDN


class AsnDeTodas(LectorFalso):
    """Una base de ASN falsa que da ASN_DOC a toda IP: sin un ASN conocido la IP no se consulta (RC-49, H11)."""

    def get(self, ip):
        self.pedidas.append(ip)
        return registro_asn(ASN_DOC, 'Ejemplo de documentacion')


def bases_por_defecto():
    return bases(asn=AsnDeTodas(), nombres=NOMBRES[:1])


def setUpModule():
    """Ninguna prueba depende de que la PC tenga o no la base de DB-IP en datos/geo: bases_por_omision da unas Bases
    falsas sin problema, con un ASN que no es de CDN para toda IP y sin país, así no hay aviso ni CDN por ASN y toda IP
    pública se puede consultar. La clase Geo pone las suyas."""
    parche = mock.patch.object(geoip, 'bases_por_omision', return_value=bases_por_defecto())
    parche.start()
    unittest.addModuleCleanup(parche.stop)
    sin_llave()


def sin_llave():
    """RC-337: ninguna prueba toma la SHODAN_API_KEY del entorno o del .env de la PC. Sin esto, una PC con la llave en su
    .env mandaría la API de host al simulado. Las pruebas de la llave la ponen con su propio parche."""
    parche = mock.patch.object(shodan, '_llave_de_config', return_value='')
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

    def __init__(self, ct=None, ips=None, hosts=None):
        self.ct = [[]] if ct is None else list(ct)
        self.ips = ips or {}
        self.hosts = hosts or {}
        self.urls, self.por_ip, self.por_host = [], {}, {}

    def __call__(self, url, timeout):
        self.urls.append(url)
        if url.startswith('https://api.shodan.io/'):
            # La API de host (RC-337) responde por IP como InternetDB, con `hosts`. Una excepción se lanza tal cual
            ip = url.split('?', 1)[0].rsplit('/', 1)[1]
            self.por_host[ip] = self.por_host.get(ip, 0) + 1
            respuesta = self.hosts.get(ip, 404)
            if isinstance(respuesta, list):
                respuesta = respuesta[min(self.por_host[ip], len(respuesta)) - 1]
            if isinstance(respuesta, BaseException):
                raise respuesta
        elif '?' in url:
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

    def de_host(self):
        """URL que llegaron a la API de Shodan."""
        return [u for u in self.urls if u.startswith('https://api.shodan.io/')]


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
    return [c for c in shodan.CODIGOS_PUERTOS if c not in con] + [c for c in shodan.SIN_LLAVE if c not in con]


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
        self.assertEqual(res.sin_llave, list(shodan.SIN_LLAVE))   # sin la API de host faltan por la llave (RC-229)

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
        nube, marcada = '3.80.0.10', '23.45.67.89'   # una IP de Amazon fuera de los rangos de CloudFront: sale por el CNAME
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
        self.assertEqual(res.sin_cobertura, list(shodan.CODIGOS))
        self.assertEqual(len(res.sin_cobertura), 11)   # 11 con exposed_ai_service (RC-262)
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
        self.assertEqual((otra.activos, otra.hallazgos, otra.sin_cobertura, otra.avisos, otra.revisados, otra.sin_revisar,
                          otra.omitidos),
                         (res.activos, res.hallazgos, res.sin_cobertura, res.avisos, res.revisados, res.sin_revisar, res.omitidos))
        self.assertEqual(activo(otra, RESERVAS).atributos['internetdb'], 'sin_datos')

    def test_14_el_peor_caso_gasta_justo_max_consultas(self):
        """Dos páginas llenas de Cert Spotter al segundo intento, MAX_NOMBRES nombres que resuelven al tercero y
        MAX_IPS IP que responden al tercero."""
        nombres = ['n%02d.olmardo.com' % i for i in range(shodan.MAX_NOMBRES + 1)]
        mitad = len(nombres) // 2
        ct = [500, paginas(*nombres[:mitad])[0], 500, paginas(*nombres[mitad:], id_=9201)[0]]
        zona = {DOMINIO: ['falla', 'falla', a('20.69.154.10')]}
        zona.update({n: ['falla', 'falla', a('20.69.154.%d' % (11 + i))] for i, n in enumerate(nombres)})
        ips = {'20.69.154.%d' % (10 + i): [500, 500, internetdb('', ports=[8080])] for i in range(len(nombres) + 1)}
        http, dns = HttpSimulado(ct, ips), ResolvedorSimulado(zona)
        res = recolectar(http, dns)
        self.assertEqual(shodan.MAX_CONSULTAS, 214)   # 184 de antes más MAX_IPS IP en la API de host (RC-337)
        self.assertEqual(len(dns.nombres), shodan.MAX_NOMBRES * shodan.INTENTOS)
        sin_host = shodan.MAX_CONSULTAS - shodan.MAX_IPS * shodan.INTENTOS   # sin la llave no corre la API de host
        self.assertEqual((res.consultas, len(http.urls) + len(dns.nombres)), (sin_host, sin_host))
        self.assertEqual(len(http.consultadas()), shodan.MAX_IPS)
        self.assertEqual(res.sin_cobertura, codigos_sin(res))

    def test_15_los_cortes_dejan_en_sin_cobertura_solo_los_codigos_sin_hallazgos(self):
        con_dos = internetdb(CAMARA, ports=[8080, 3389])
        nombres = ['n%02d.olmardo.com' % i for i in range(shodan.MAX_NOMBRES + 2)]
        casos = {
            'MAX_NOMBRES': (HttpSimulado(paginas(*nombres), {CAMARA: con_dos}),
                            ResolvedorSimulado({DOMINIO: a(CAMARA)}), Cronometro(0),
                            'shodan: se resolvieron %d de %d nombres del dominio (MAX_NOMBRES)'
                            % (shodan.MAX_NOMBRES, shodan.MAX_NOMBRES + 3)),
            'MAX_IPS': (HttpSimulado(ips={CAMARA: con_dos}),
                        ResolvedorSimulado({DOMINIO: a(CAMARA, *('20.69.155.%d' % i for i in range(1, 11)))}),
                        Cronometro(0), 'shodan: se consultaron 10 de 11 IP en InternetDB (MAX_IPS)'),
            'tiempo': (HttpSimulado(paginas(*nombres[:12]), {CAMARA: con_dos}),
                       ResolvedorSimulado(dict({DOMINIO: a(CAMARA)},
                                               **{n: a('20.69.156.%d' % i) for i, n in enumerate(nombres[:12])})),
                       Cronometro(10), 'shodan: el tiempo de la corrida cortó'),
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
        for codigo in shodan.SIN_LLAVE:   # RC-220: ya los emite, con su severidad del catálogo
            self.assertIn(codigo, POR_CODIGO)
            self.assertEqual(shodan.CODIGOS[codigo], POR_CODIGO[codigo][5], codigo)
        res = recolectar(HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[3389, 22, 445, 5432, 2375, 11434, 8080],
                                                              vulns=['CVE-2024-6387'])}),
                         ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual({h.codigo for h in res.hallazgos}, set(shodan.CODIGOS_PUERTOS))
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
        nube = '20.69.154.10'   # de Microsoft, fuera de los rangos de Front Door: sale por la cadena
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
        graba una corrida completa. Después cada A tarda 100 s, el corte de MIN_RESTANTE con RESERVA_INTERNETDB llega en
        el cuarto nombre y la corrida avisa los 4 nombres que no resolvió, pone NO_SE_GRABO primero, sale con 3 y no toca la grabación
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
            self.assertIn('shodan: se acabó el tiempo de la corrida antes de resolver 4 nombres', res.avisos)
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
                self.assertEqual(res.sin_cobertura, list(shodan.CODIGOS))
                self.assertTrue(any(x.startswith('shodan: InternetDB dio en %s datos que no se pueden leer (' % CAMARA)
                                    and 'ports' in x for x in res.avisos), res.avisos)
                self.assertEqual(shodan.codigo_salida(res), 2)

    def test_39_el_tiempo_de_la_corrida_acota_el_lifetime_y_las_esperas(self):
        """tiempos-3: con 3 s restantes el A usa lifetime 3. RC-166, 14: una espera después de la cual no quedaría
        MIN_INTENTO más HOLGURA no se duerme, ni vale si el sueño se pasó, y sale el error del último intento, no un
        SinTiempo que lo tape."""
        reloj = {'t': 0.0}
        dormidas = []

        def dormir(s):
            dormidas.append(s)
            reloj['t'] += s
        dns = ResolvedorSimulado({DOMINIO: ['falla', a(CAMARA)]})
        cliente = shodan.ClienteShodan(resolver=dns, cronometro=lambda: reloj['t'], dormir=dormir)
        cliente.empezar()
        reloj['t'] = shodan.TIEMPO_CORRIDA - 8
        self.assertIs(cliente.esperar(15), False)
        self.assertIs(cliente.esperar(7), False)     # quedaría 1, menos que MIN_INTENTO más HOLGURA
        self.assertIs(cliente.esperar(6.5), True)
        self.assertEqual(dormidas, [6.5])
        reloj['t'] = shodan.TIEMPO_CORRIDA - 8       # un sueño que se pasa 0.2 s: antes quedan 1.15 y después 0.95
        with mock.patch.object(cliente, 'dormir', lambda s: dormir(s + 0.2)):
            self.assertIs(cliente.esperar(6.85), False)
        self.assertEqual(dormidas, [6.5, 6.85 + 0.2])
        reloj['t'] = shodan.TIEMPO_CORRIDA - 9   # falla con lifetime 5, duerme 5 y al segundo intento quedan 4
        self.assertEqual(cliente.resolver_a(DOMINIO)['ips'], [CAMARA])
        self.assertEqual(dns.lifetimes, [shodan.TIMEOUT_DNS, 4])
        reloj['t'] = shodan.TIEMPO_CORRIDA - 3
        dns2 = ResolvedorSimulado({'x.olmardo.com': 'falla'})
        cliente.resolver = dns2
        dormidas.clear()
        with self.assertRaises(FuenteNoResponde) as e:
            cliente.resolver_a('x.olmardo.com')
        self.assertNotIsInstance(e.exception, shodan.SinTiempo)
        self.assertEqual(str(e.exception), 'shodan: el DNS no respondió al A de x.olmardo.com después de 1 intento,'
                                           ' sin tiempo para otro (ConsultaFallida: Timeout: ningún servidor'
                                           ' respondió)')
        self.assertEqual((dns2.lifetimes, dormidas), ([3], []))   # ni la espera de 5 s ni un intento de menos de 1 s

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
        nombres = ['n%02d.olmardo.com' % i for i in range(shodan.MAX_NOMBRES + 2)]
        mitad = len(nombres) // 2
        ct = [paginas(*nombres[:mitad])[0], paginas(*nombres[mitad:], id_=9201)[0]]
        zona = {DOMINIO: a(CAMARA, *('20.69.155.%d' % i for i in range(1, 11)))}
        cves = ['CVE-2024-%04d' % (1000 + i) for i in range(30)]
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            http = HttpSimulado(ct, {CAMARA: internetdb(CAMARA, ports=[8080], vulns=cves)})
            res = recolectar(http, ResolvedorSimulado(zona), modo='grabar', carpeta=carpeta, nueva=True)
            self.assertEqual(len([u for u in http.urls if '?' in u]), shodan.PAGINAS_CT)
            self.assertNotIn(shodan.NO_SE_GRABO, res.avisos)
            for aviso in ('shodan: Cert Spotter no dio todas sus páginas',
                          'shodan: se resolvieron %d de %d nombres' % (shodan.MAX_NOMBRES, shodan.MAX_NOMBRES + 3),
                          'shodan: se consultaron 10 de 11 IP', 'shodan: %s trae 30 CVE' % CAMARA):
                self.assertTrue(any(x.startswith(aviso) for x in res.avisos), aviso)
            self.assertEqual(shodan.codigo_salida(res), 2)
            self.assertEqual(len(res.omitidos), 5)   # las 5 CVE que MAX_CVE dejó fuera
            self.assertTrue(list(carpeta.glob('internetdb_*.json')))
            otra = recolectar(HttpSimulado(), ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
        self.assertEqual((otra.activos, otra.hallazgos, otra.sin_cobertura, otra.avisos, otra.revisados, otra.sin_revisar,
                          otra.omitidos),
                         (res.activos, res.hallazgos, res.sin_cobertura, res.avisos, res.revisados, res.sin_revisar, res.omitidos))

    def test_42_sin_grabar_el_cli_sale_con_3_y_el_aviso_entra_en_los_10_del_orquestador(self):
        """re-contrato-2 y re-contrato-3: python -m cirdan.recolectores.shodan --grabar sale con 3 si no escribió, y
        con 0 si grabó una corrida completa. Con 9 IP que no responden en InternetDB hay más de 10 avisos y NO_SE_GRABO
        sigue en avisos[:10], lo que guarda el orquestador en raw_payload. Los A caídos ya van en un solo aviso."""
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
        caidas = ['20.69.155.%d' % i for i in range(1, 11)]
        zona = {DOMINIO: a(CAMARA, *caidas)}
        with tempfile.TemporaryDirectory() as d:
            res = recolectar(HttpSimulado(ips=dict({CAMARA: CAMARA_8080}, **{ip: 503 for ip in caidas})),
                             ResolvedorSimulado(zona), modo='grabar', carpeta=Path(d) / DOMINIO, nueva=True)
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
        with mock.patch.object(shodan.transporte, 'abrir', lambda req, plazo, cronometro: lenta):
            with self.assertRaises(shodan.SinTiempo):
                shodan._descargar(shodan.URL_INTERNETDB + CAMARA, 10, cronometro=lambda: reloj['t'])
        self.assertEqual(lenta.lecturas, 3)    # a los 15 s ya no lee otra parte
        reloj['t'] = 0.0
        rapida = Lenta([b'{"ports":', b' [8080]}'], 1)
        with mock.patch.object(shodan.transporte, 'abrir', lambda req, plazo, cronometro: rapida):
            self.assertEqual(shodan._descargar(shodan.URL_INTERNETDB + CAMARA, 10, cronometro=lambda: reloj['t']),
                             b'{"ports": [8080]}')
        enorme = Lenta([b'x' * shodan.transporte.BLOQUE] * 20, 0)
        with mock.patch.object(shodan.transporte, 'abrir', lambda req, plazo, cronometro: enorme), \
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


    def test_43b_con_cobertura_parcial_revisados_lleva_las_partes_revisadas_completas(self):
        """#23: cada puerto lleva su IP como parte y cada CVE su IP con '/cve'. Con la cobertura parcial, revisados
        lleva las partes que InternetDB respondió sin campos rotos (también un 404) y las que una corrida completa
        tampoco consulta (CDN). No van la IP que no respondió, los puertos de una IP con 'ports' roto ni las cortadas
        por MAX_IPS. Si se conocen todos los nombres, sin_revisar lleva las demás partes de sus IP. Con todo revisado,
        los dos quedan en None."""
        rota, sin_datos = '20.69.155.1', '20.69.155.2'
        zona = {DOMINIO: a(CLOUDFLARE), 'camaras.olmardo.com': a(CAMARA), 'reservas.olmardo.com': a(RESERVAS),
                'eventos.olmardo.com': a(rota), 'www.olmardo.com': a(sin_datos)}
        nombres = paginas('camaras.olmardo.com', 'eventos.olmardo.com', 'reservas.olmardo.com', 'www.olmardo.com')
        con_rdp = internetdb(CAMARA, ports=[3389], vulns=['CVE-2024-0001'])
        completo = recolectar(HttpSimulado(nombres, {CAMARA: con_rdp, RESERVAS: internetdb(RESERVAS, ports=[3389])}),
                              ResolvedorSimulado({k: v for k, v in zona.items() if v != a(rota)}))
        self.assertEqual((completo.revisados, completo.sin_revisar), (None, None))
        self.assertEqual({(h.codigo, tuple(h.partes)) for h in completo.hallazgos},
                         {('exposed_rdp', (CAMARA,)), ('known_vulnerability', (CAMARA + '/cve',)),
                          ('exposed_rdp', (RESERVAS,))})
        http = HttpSimulado(nombres, {CAMARA: con_rdp, RESERVAS: 503, rota: {'ports': 'muchos'}})
        res = recolectar(http, ResolvedorSimulado(zona))
        self.assertTrue(any(x.startswith(shodan.PARCIAL) for x in res.avisos), res.avisos)
        self.assertCountEqual(res.revisados, [CAMARA, CAMARA + '/cve', rota + '/cve', sin_datos, sin_datos + '/cve',
                                              CLOUDFLARE, CLOUDFLARE + '/cve', CLOUDFLARE + ETQ])
        # sin la llave, la parte de etiquetas de las IP consultadas nunca queda revisada (RC-220)
        self.assertCountEqual(res.sin_revisar, [RESERVAS, RESERVAS + '/cve', rota] +
                              [ip + ETQ for ip in (CAMARA, RESERVAS, rota, sin_datos)])
        self.assertEqual({(h.codigo, tuple(h.partes)) for h in res.hallazgos},
                         {('exposed_rdp', (CAMARA,)), ('known_vulnerability', (CAMARA + '/cve',))})
        self.assertNotIn('exposed_rdp', res.sin_cobertura)   # el código trae hallazgos: solo las partes protegen a RESERVAS
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        muchas = ['20.69.157.%d' % i for i in range(1, shodan.MAX_IPS + 2)]
        res = recolectar(HttpSimulado(ips={muchas[0]: internetdb(muchas[0], ports=[3389])}),
                         ResolvedorSimulado({DOMINIO: a(*muchas)}))
        self.assertEqual(res.revisados, [p for ip in muchas[:shodan.MAX_IPS] for p in (ip, ip + '/cve')])
        # la última quedó fuera por MAX_IPS. Sin la llave, la parte de etiquetas de ninguna queda revisada
        self.assertEqual(res.sin_revisar, [ip + ETQ for ip in muchas[:shodan.MAX_IPS]] +
                         [muchas[-1], muchas[-1] + '/cve', muchas[-1] + ETQ])
        res = recolectar(HttpSimulado([503] * shodan.INTENTOS_CT, {CAMARA: internetdb(CAMARA, ports=[3389])}),
                         ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        # sin Cert Spotter no se saben todas las IP del dominio: solo se cierra lo de las revisadas
        self.assertEqual((res.revisados, res.sin_revisar), ([CAMARA, CAMARA + '/cve'], None))

    def test_43d_con_mas_de_10_nombres_se_saben_todas_las_ip(self):
        """RC-55: 12 nombres ya no cortan los nombres. Con todo respondido la corrida es completa, y si una IP no responde,
        sin_revisar lleva sus partes: así el orquestador cierra lo de una IP que ya no es del dominio. Solo si los nombres
        pasan de MAX_NOMBRES no se saben todas las IP y sin_revisar queda en None."""
        nombres = ['n%02d.olmardo.com' % i for i in range(12)]
        zona = dict({DOMINIO: a(CAMARA)}, **{n: a(RESERVAS if i % 2 else CAMARA) for i, n in enumerate(nombres)})
        con_rdp = {CAMARA: internetdb(CAMARA, ports=[3389]), RESERVAS: internetdb(RESERVAS, ports=[3389])}
        res = recolectar(HttpSimulado(paginas(*nombres), con_rdp), ResolvedorSimulado(zona))
        self.assertEqual((res.revisados, res.sin_revisar), (None, None))
        self.assertEqual(shodan.codigo_salida(res), 0)
        res = recolectar(HttpSimulado(paginas(*nombres), dict(con_rdp, **{RESERVAS: 503})), ResolvedorSimulado(zona))
        self.assertEqual((res.revisados, res.sin_revisar),
                         ([CAMARA, CAMARA + '/cve'], [CAMARA + ETQ, RESERVAS, RESERVAS + '/cve', RESERVAS + ETQ]))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        muchos = ['m%03d.olmardo.com' % i for i in range(shodan.MAX_NOMBRES)]   # con la raíz pasan de MAX_NOMBRES
        res = recolectar(HttpSimulado(paginas(*muchos), {CAMARA: internetdb(CAMARA, ports=[3389])}),
                         ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertTrue(any(x.startswith('shodan: se resolvieron %d de %d nombres' % (shodan.MAX_NOMBRES,
                                                                                       shodan.MAX_NOMBRES + 1))
                            for x in res.avisos), res.avisos)
        self.assertEqual((res.revisados, res.sin_revisar), ([CAMARA, CAMARA + '/cve'], None))

    def test_43e_los_a_que_no_responden_dejan_tiempo_para_internetdb(self):
        """shodan-1 (RC-55): 11 nombres con el DNS caído, que van antes de 30 que sí resuelven, tardan 35 s cada uno.
        Sin RESERVA_INTERNETDB se comían los 360 s y no se consultaba ninguna IP. Ahora los A se cortan a tiempo, la
        IP de la raíz se consulta, la corrida queda parcial y el aviso del tiempo cabe en los 10 que guarda el
        orquestador porque los A fallidos van en uno solo."""
        reloj = {'t': 0.0}
        rotos = ['a%02d.olmardo.com' % i for i in range(11)]
        buenos = ['b%02d.olmardo.com' % i for i in range(30)]
        zona = dict({DOMINIO: a(CAMARA)}, **{n: 'falla' for n in rotos},
                    **{n: a('20.69.160.%d' % (i + 1)) for i, n in enumerate(buenos)})

        class Lento(ResolvedorSimulado):
            def __call__(self, nombre, lifetime=shodan.TIMEOUT_DNS):
                try:
                    return super().__call__(nombre, lifetime)
                except shodan.ConsultaFallida:
                    reloj['t'] += lifetime
                    raise

        def dormir(s):
            reloj['t'] += s
        http = HttpSimulado(paginas(*rotos, *buenos), {CAMARA: internetdb(CAMARA, ports=[3389])})
        cliente = shodan.ClienteShodan(carpeta=shodan.carpeta_de(DOMINIO), descargar=http, resolver=Lento(zona),
                                       cronometro=lambda: reloj['t'], dormir=dormir)
        res = shodan.recolectar(DOMINIO, cliente, ahora=AHORA)
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(http.consultadas(), {CAMARA})
        self.assertEqual([h.codigo for h in res.hallazgos], ['exposed_rdp'])
        self.assertLessEqual(reloj['t'], shodan.TIEMPO_CORRIDA - shodan.RESERVA_INTERNETDB)
        self.assertEqual((res.revisados, res.sin_revisar), ([CAMARA, CAMARA + '/cve'], None))
        tiempo = [i for i, x in enumerate(res.avisos) if x.startswith('shodan: se acabó el tiempo de la corrida antes '
                                                                       'de resolver')]
        self.assertEqual(len(tiempo), 1, res.avisos)
        self.assertLess(tiempo[0], 10, res.avisos)
        # 7 A de 35 s caben en los 250 s. El octavo empieza con 5 s, falla su único intento y cuenta como A fallido
        # aunque no quedara tiempo para otro (RC-166), y el aviso lo dice
        [fallidos] = [x for x in res.avisos if 'no respondió al A' in x]
        self.assertTrue(fallidos.startswith('shodan: el DNS no respondió al A de 8 nombres (1 sin tiempo para otro '
                                            'intento): a00.olmardo.com, '), fallidos)
        self.assertTrue(fallidos.endswith(' y 3 más'), fallidos)
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_43f_la_ip_de_la_raiz_va_antes_del_corte_de_max_ips(self):
        """shodan-2 (RC-55): con la raíz en 52.10.0.5 y 15 subdominios en 20.69.x, el orden por dirección dejaba la raíz
        fuera de MAX_IPS en cada escaneo. Ahora sus IP van primero y su RDP se ve."""
        raiz = '52.10.0.5'
        subs = ['s%02d.olmardo.com' % i for i in range(15)]
        zona = dict({DOMINIO: a(raiz)}, **{n: a('20.69.%d.10' % (140 + i)) for i, n in enumerate(subs)})
        http = HttpSimulado(paginas(*subs), {raiz: internetdb(raiz, ports=[3389])})
        res = recolectar(http, ResolvedorSimulado(zona))
        self.assertIn(raiz, http.consultadas())
        self.assertEqual(len(http.consultadas()), shodan.MAX_IPS)
        self.assertEqual([h.codigo for h in res.hallazgos], ['exposed_rdp'])
        self.assertTrue(any(x.startswith('shodan: se consultaron 10 de 16 IP en InternetDB') for x in res.avisos),
                        res.avisos)
        fuera = sorted((x.valor for x in res.activos if x.atributos.get('internetdb') == 'sin_consultar'),
                       key=ipaddress.ip_address)
        self.assertEqual(fuera, ['20.69.%d.10' % (140 + i) for i in range(9, 15)])

    def test_43g_una_grabacion_con_el_tope_viejo_de_nombres_da_un_solo_aviso(self):
        """shodan-5 (RC-55): una grabación hecha con MAX_NOMBRES en 10 no trae los A de los demás nombres. Al reproducir
        van en un aviso que dice por qué, no en uno por nombre como si el DNS no hubiera respondido, y la corrida queda
        parcial por la grabación."""
        nombres = ['n%02d.olmardo.com' % i for i in range(12)]
        zona = dict({DOMINIO: a(CAMARA)}, **{n: a(RESERVAS) for n in nombres})
        ips = {CAMARA: internetdb(CAMARA, ports=[3389]), RESERVAS: internetdb(RESERVAS, ports=[8080])}
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(shodan, 'MAX_NOMBRES', 10):
                vieja = recolectar(HttpSimulado(paginas(*nombres), ips), ResolvedorSimulado(zona), modo='grabar',
                                   carpeta=Path(d) / DOMINIO, nueva=True)
            self.assertNotIn(shodan.NO_SE_GRABO, vieja.avisos)
            http = HttpSimulado()
            res = recolectar(http, ResolvedorSimulado({}), modo='reproducir', carpeta=Path(d) / DOMINIO)
        self.assertEqual(http.urls, [])
        self.assertEqual(res.estado, 'succeeded')
        self.assertFalse([x for x in res.avisos if 'no respondió al A' in x], res.avisos)
        self.assertIn('shodan: la grabación no trae el A de 3 nombres, se grabó con otro tope de nombres: '
                      'n09.olmardo.com, n10.olmardo.com, n11.olmardo.com', res.avisos)
        self.assertIsNone(res.sin_revisar)
        self.assertEqual(sorted(res.revisados), sorted([CAMARA, CAMARA + '/cve', RESERVAS, RESERVAS + '/cve']))
        self.assertEqual({h.codigo for h in res.hallazgos}, {'exposed_rdp', 'exposed_service'})

    def test_43c_el_tope_de_cve_y_los_campos_que_no_deciden_hallazgos(self):
        """#23: una IP con más de MAX_CVE CVE reporta las más recientes y pone la huella de las demás en omitidos,
        que siguen ahí: el orquestador no cierra las que se reportaron antes y la corrida no queda parcial. 'cpes' o
        'hostnames' rotos no quitan nada de revisados: no deciden ningún hallazgo. 'vulns' roto solo quita las CVE y
        'tags' roto quita las dos partes."""
        vulns = ['CVE-2024-%04d' % i for i in range(1, shodan.MAX_CVE + 2)]
        res = recolectar(HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[3389], vulns=vulns)}),
                         ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual((res.revisados, res.sin_revisar), (None, None))
        datos = {'tags': [], 'hostnames_ajenos': 0, 'cpes': []}
        vieja = shodan.hallazgo_cve(DOMINIO, CAMARA, 'CVE-2024-0001', [DOMINIO], datos, AHORA).huella
        self.assertEqual(res.omitidos, [vieja])   # la más vieja quedó fuera del tope
        self.assertNotIn(vieja, [h.huella for h in res.hallazgos])
        self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))
        self.assertFalse(any(x.startswith(shodan.PARCIAL) for x in res.avisos), res.avisos)
        self.assertEqual(shodan.codigo_salida(res), 0)
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        rotos = {'cpes': ({'cpes': 'x'}, [CAMARA, CAMARA + '/cve']),
                 'hostnames': ({'hostnames': 'x'}, [CAMARA, CAMARA + '/cve']),
                 'vulns': ({'vulns': ['nada']}, [CAMARA]), 'tags': ({'tags': 'x'}, []),
                 'ports': ({'ports': 'x'}, [CAMARA + '/cve'])}
        for campo, (cambio, esperado) in rotos.items():
            with self.subTest(campo=campo):
                res = recolectar(HttpSimulado(ips={CAMARA: dict(internetdb(CAMARA, ports=[3389]), **cambio)}),
                                 ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                self.assertEqual(res.revisados, esperado)
                self.assertEqual(res.sin_revisar, [p for p in (CAMARA, CAMARA + '/cve', CAMARA + ETQ) if p not in esperado])

    def test_52_un_5xx_con_retry_after_espera_lo_que_pide(self):
        """RC-166, 15: el Retry-After de un 5xx alarga la espera antes del siguiente intento, hasta MAX_ESPERA aunque
        pida más: un valor genérico como 30 o 3600 no quita los reintentos. Si todos fallan, sale el error de
        con_reintentos con los intentos que se hicieron, que cuenta como la falla de red de la IP, y no SinTiempo."""
        for valor in ('12', '15', '16', '40', '3600'):
            with self.subTest(valor=valor):
                pedidas, dormidas = [], []

                def descargar(url, timeout, valor=valor, pedidas=pedidas):
                    pedidas.append(url)
                    if len(pedidas) == 1:
                        raise error_http(url, 503, valor)
                    return REAL_CAMARA
                cliente = shodan.ClienteShodan(descargar=descargar, cronometro=Cronometro(0), dormir=dormidas.append)
                cliente.empezar()
                self.assertEqual(cliente.internetdb(CAMARA, DOMINIO)['ports'], [50000])
                self.assertEqual((dormidas, cliente.consultas), ([min(int(valor), shodan.MAX_ESPERA)], 2))
        dormidas = []

        def caido(url, timeout):
            raise error_http(url, 503, '3600')
        cliente = shodan.ClienteShodan(descargar=caido, cronometro=Cronometro(0), dormir=dormidas.append)
        cliente.empezar()
        with self.assertRaises(FuenteNoResponde) as e:
            cliente.internetdb(CAMARA, DOMINIO)
        self.assertNotIsInstance(e.exception, shodan.SinTiempo)
        self.assertEqual(str(e.exception), 'shodan: InternetDB (%s) no respondió después de 3 intentos (HTTPError: '
                                           'HTTP Error 503: falla 503)' % CAMARA)
        self.assertEqual((dormidas, cliente.consultas), ([15, 15], 3))

    def test_53_ninguna_redireccion_se_sigue_y_el_plazo_es_sin_tiempo(self):
        """RC-166, 6 y 7: _descargar usa transporte.descargar. Una redirección no se puede leer y no se reintenta, el
        plazo vencido del transporte es SinTiempo y solo se pide por https."""
        def redirige(req, plazo, cronometro):
            raise shodan.transporte.Redirigida(302, 'internetdb.shodan.io')

        def vence(req, plazo, cronometro):
            raise shodan.transporte.PlazoVencido('internetdb.shodan.io no terminó dentro de su plazo')

        def sin_red(req, plazo, cronometro):
            raise AssertionError('se consultó la red: %s' % req.full_url)
        with mock.patch.object(shodan.transporte, 'abrir', redirige):
            with self.assertRaises(shodan.RespuestaIlegible) as e:
                shodan._descargar(shodan.URL_INTERNETDB + CAMARA, 10)
            self.assertEqual(str(e.exception),
                             'shodan: internetdb.shodan.io redirigió (302) y no se siguen redirecciones')
            cliente = shodan.ClienteShodan(cronometro=Cronometro(0), dormir=lambda s: None)
            cliente.empezar()
            with self.assertRaises(shodan.RespuestaIlegible):
                cliente.internetdb(CAMARA, DOMINIO)
            self.assertEqual(cliente.consultas, 1)
        with mock.patch.object(shodan.transporte, 'abrir', vence), self.assertRaises(shodan.SinTiempo) as e:
            shodan._descargar(shodan.URL_INTERNETDB + CAMARA, 10)
        self.assertEqual(str(e.exception), 'shodan: la respuesta tardó más de 10 s')
        with mock.patch.object(shodan.transporte, 'abrir', sin_red), self.assertRaises(ValueError):
            shodan._descargar('http://internetdb.shodan.io/' + CAMARA, 10)

    def test_54_sin_tiempo_para_otro_intento_la_ip_cuenta_como_falla_de_red(self):
        """RC-166, 14: una IP cuyo siguiente intento ya no cabe en la corrida queda como falla de red con su error, no
        como SinTiempo, que antes lo tapaba. El reloj avanza de verdad: el 503 de la IP `lenta` llega con 4.5 s
        restantes, la espera de 5 s no cabe y la IP siguiente ya no empieza (MIN_RESTANTE). Si otra IP respondió, la
        fuente queda succeeded con el aviso. Si ninguna respondió, aunque el tiempo cortara las demás, o si la única IP
        consultable falló, la fuente falla con FuenteNoResponde para que el orquestador la reintente."""
        reloj = {'t': 0.0}

        class Tarda(HttpSimulado):   # la consulta a InternetDB de `lenta` deja a la corrida con 4.5 s
            lenta = CAMARA

            def __call__(self, url, timeout):
                if '?' not in url and url.rsplit('/', 1)[1] == self.lenta and self.lenta not in self.por_ip:
                    reloj['t'] = shodan.TIEMPO_CORRIDA - 4.5
                return super().__call__(url, timeout)
        # Otra IP respondió: queda succeeded con el aviso de la que no
        http = Tarda(ct_olmardo(), {CAMARA: CAMARA_8080, RESERVAS: 503})
        http.lenta = RESERVAS
        res = recolectar(http, ResolvedorSimulado(zona_olmardo()), cronometro=lambda: reloj['t'])
        self.assertEqual((http.por_ip, res.estado), ({CAMARA: 1, RESERVAS: 1}, 'succeeded'))
        self.assertIn('shodan: InternetDB (%s) no respondió después de 1 intento, sin tiempo para otro (HTTPError: '
                      'HTTP Error 503: falla 503)' % RESERVAS, res.avisos)
        self.assertIn(RESERVAS, res.sin_revisar)
        # CAMARA respondió, `segunda` falló por la red y el tiempo cortó RESERVAS: queda succeeded con sus hallazgos
        reloj['t'] = 0.0
        segunda = '20.69.155.10'   # entre CAMARA y RESERVAS: las IP se consultan en orden
        http = Tarda(paginas('camaras.olmardo.com', 'api.olmardo.com', 'reservas.olmardo.com'),
                     {CAMARA: CAMARA_8080, segunda: 503, RESERVAS: 503})
        http.lenta = segunda
        res = recolectar(http, ResolvedorSimulado(zona_olmardo(**{'api.olmardo.com': a(segunda)})),
                         cronometro=lambda: reloj['t'])
        self.assertEqual((http.por_ip, res.estado), ({CAMARA: 1, segunda: 1}, 'succeeded'))
        self.assertIn('exposed_service', {h.codigo for h in res.hallazgos})
        self.assertIn('shodan: el tiempo de la corrida cortó 1 IP en InternetDB, sin consultar o con la lectura a '
                      'medias', res.avisos)
        self.assertTrue({segunda, RESERVAS} <= set(res.sin_revisar), res.sin_revisar)
        # Ninguna respondió: la primera falló por la red y el tiempo cortó la otra (RC-166, delta-tiempos-1)
        reloj['t'] = 0.0
        http = Tarda(ct_olmardo(), {CAMARA: 503, RESERVAS: 503})
        with self.assertRaises(FuenteNoResponde) as e:
            recolectar(http, ResolvedorSimulado(zona_olmardo()), cronometro=lambda: reloj['t'])
        self.assertEqual((http.por_ip, str(e.exception)),
                         ({CAMARA: 1}, 'shodan: InternetDB no respondió por ninguna IP de olmardo.com (por la red: '
                                       '1, cortadas por el tiempo: 1)'))
        # Sin una falla de red, el tiempo que corta todas las IP deja la fuente succeeded con el aviso

        class SinPlazo(HttpSimulado):   # la lectura de la primera IP agota la corrida: SinTiempo, no falla de red
            def __call__(self, url, timeout):
                if '?' not in url:
                    self.por_ip[url.rsplit('/', 1)[1]] = 1
                    reloj['t'] = shodan.TIEMPO_CORRIDA - 0.5
                    raise shodan.SinTiempo('shodan: la respuesta tardó más de %d s' % timeout)
                return super().__call__(url, timeout)
        reloj['t'] = 0.0
        http = SinPlazo(ct_olmardo())
        res = recolectar(http, ResolvedorSimulado(zona_olmardo()), cronometro=lambda: reloj['t'])
        self.assertEqual((http.por_ip, res.estado), ({CAMARA: 1}, 'succeeded'))
        self.assertIn('shodan: el tiempo de la corrida cortó 2 IP en InternetDB, sin consultar o con la lectura a '
                      'medias', res.avisos)
        self.assertTrue({CAMARA, RESERVAS} <= set(res.sin_revisar), res.sin_revisar)
        # Una sola IP consultable: su falla de red es la de todas
        reloj['t'] = 0.0
        http = Tarda(paginas('camaras.olmardo.com'), {CAMARA: 503})
        with self.assertRaises(FuenteNoResponde) as e:
            recolectar(http, ResolvedorSimulado({DOMINIO: a(CLOUDFLARE), 'camaras.olmardo.com': a(CAMARA)}),
                       cronometro=lambda: reloj['t'])
        self.assertEqual((http.por_ip, str(e.exception)),
                         ({CAMARA: 1}, 'shodan: InternetDB no respondió por ninguna IP de olmardo.com'))

    def test_55_el_aviso_de_los_a_dice_cuantos_quedaron_sin_tiempo_para_otro_intento(self):
        """RC-166, buscador de la unión con dev, 1: el aviso único de los A fallidos tiraba el ', sin tiempo para otro'
        de cada error. Con la raíz bien y a00 a a07 con el DNS caído (35 s cada uno), a07 es el último nombre y empieza
        con 5 s antes de RESERVA_INTERNETDB: falla su único intento, cuenta como A fallido y no queda otro aviso del
        tiempo. Ahora el aviso de los A lo dice, sin cambiar estado ni cobertura. Con todos sus intentos no dice nada
        del tiempo, y un solo A fallido sale con su error tal cual."""
        reloj = {'t': 0.0}

        class Lento(ResolvedorSimulado):
            def __call__(self, nombre, lifetime=shodan.TIMEOUT_DNS):
                try:
                    return super().__call__(nombre, lifetime)
                except shodan.ConsultaFallida:
                    reloj['t'] += lifetime
                    raise

        class Tarda(HttpSimulado):   # Cert Spotter deja a la corrida en `desde`
            desde = 0.0

            def __call__(self, url, timeout):
                if '?' in url:
                    reloj['t'] = self.desde
                return super().__call__(url, timeout)

        def dormir(s):
            reloj['t'] += s

        def correr(rotos, desde=0.0):
            reloj['t'] = 0.0
            http = Tarda(paginas(*rotos), {CAMARA: internetdb(CAMARA, ports=[3389])})
            http.desde = desde
            cliente = shodan.ClienteShodan(carpeta=shodan.carpeta_de(DOMINIO), descargar=http,
                                           resolver=Lento(dict({DOMINIO: a(CAMARA)}, **{n: 'falla' for n in rotos})),
                                           cronometro=lambda: reloj['t'], dormir=dormir)
            return shodan.recolectar(DOMINIO, cliente, ahora=AHORA)
        res = correr(['a%02d.olmardo.com' % i for i in range(8)])
        self.assertEqual(reloj['t'], shodan.TIEMPO_CORRIDA - shodan.RESERVA_INTERNETDB)
        self.assertEqual((res.estado, [h.codigo for h in res.hallazgos]), ('succeeded', ['exposed_rdp']))
        self.assertEqual((res.revisados, res.sin_revisar), ([CAMARA, CAMARA + '/cve'], None))
        self.assertIn('shodan: el DNS no respondió al A de 8 nombres (1 sin tiempo para otro intento): a00.olmardo.com,'
                      ' a01.olmardo.com, a02.olmardo.com, a03.olmardo.com, a04.olmardo.com y 3 más', res.avisos)
        self.assertFalse([x for x in res.avisos if 'se acabó el tiempo' in x], res.avisos)
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        # Con sus 3 intentos el aviso no habla del tiempo
        res = correr(['a00.olmardo.com', 'a01.olmardo.com'])
        self.assertIn('shodan: el DNS no respondió al A de 2 nombres: a00.olmardo.com, a01.olmardo.com', res.avisos)
        # Un solo A fallido, con 5 s: su error ya lo dice
        res = correr(['a00.olmardo.com'], desde=shodan.TIEMPO_CORRIDA - shodan.RESERVA_INTERNETDB - 5)
        self.assertIn('shodan: el DNS no respondió al A de a00.olmardo.com después de 1 intento, sin tiempo para otro '
                      '(ConsultaFallida: Timeout: ningún servidor respondió)', res.avisos)
        # con_reintentos marca el error con sin_tiempo solo si dormir devolvió False

        def falla():
            raise OSError('conexión cortada')
        for dormir_, sin_tiempo in ((lambda s: False, True), (lambda s: None, False)):
            with self.assertRaises(FuenteNoResponde) as e:
                contrato.con_reintentos(falla, dormir=dormir_)
            self.assertIs(e.exception.sin_tiempo, sin_tiempo)

    def test_56_en_los_a_la_espera_descuenta_la_reserva_de_internetdb(self):
        """RC-166, buscador de la unión con dev, 2: README.md decía 'ni un segundo' y ni él ni el docstring decían que
        en los A esperar() mira restante(), que descuenta RESERVA_INTERNETDB, y pide MIN_INTENTO más HOLGURA: un A que
        falla con 115 s por delante no espera los 5 s ni se reintenta, y uno con 117 s sí. Fuera de los A esa espera
        cabe."""
        self.assertEqual((shodan.MIN_INTENTO + shodan.HOLGURA, shodan.RESERVA_INTERNETDB), (1.1, 110))   # README.md
        reloj = {'t': 0.0}
        dormidas = []

        def dormir(s):
            dormidas.append(s)
            reloj['t'] += s
        dns = ResolvedorSimulado({'x.olmardo.com': 'falla', 'y.olmardo.com': ['falla', a(CAMARA)]})
        cliente = shodan.ClienteShodan(resolver=dns, cronometro=lambda: reloj['t'], dormir=dormir)
        cliente.empezar()
        cliente.reserva = shodan.RESERVA_INTERNETDB
        reloj['t'] = shodan.TIEMPO_CORRIDA - 115
        with self.assertRaises(FuenteNoResponde) as e:
            cliente.resolver_a('x.olmardo.com')
        self.assertIn('x.olmardo.com después de 1 intento, sin tiempo para otro', str(e.exception))
        self.assertEqual((dns.lifetimes, dormidas), ([shodan.TIMEOUT_DNS], []))
        reloj['t'] = shodan.TIEMPO_CORRIDA - 117
        self.assertEqual(cliente.resolver_a('y.olmardo.com')['ips'], [CAMARA])
        self.assertEqual((dns.lifetimes, dormidas), ([shodan.TIMEOUT_DNS] * 2 + [2], [5]))
        cliente.reserva = 0
        reloj['t'] = shodan.TIEMPO_CORRIDA - 115
        self.assertIs(cliente.esperar(5), True)

    def test_un_archivo_vacio_o_sin_sobre_de_la_grabacion_no_se_lee_como_sin_datos(self):
        """c3-1 (RC-46): un archivo de 0 bytes (una escritura que se cortó) se leía como [] y la corrida reproducida
        salía completa, con revisados None, así que el orquestador cerraba lo que no salió. Ahora es una consulta
        que no llegó, igual que un archivo sin su sobre {grabado, datos}."""
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            recolectar(HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080, RESERVAS: 404}),
                       ResolvedorSimulado(zona_olmardo()), modo='grabar', carpeta=carpeta, nueva=True)
            archivos = sorted(carpeta.glob('*.json'))
            self.assertGreaterEqual(len(archivos), 3)
            completa = recolectar(HttpSimulado(), ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
            self.assertEqual((completa.estado, completa.revisados, completa.sin_cobertura),
                             ('succeeded', None, list(shodan.SIN_LLAVE)))
            for archivo in archivos:
                bueno = archivo.read_text(encoding='utf-8')
                for roto in ('', '[]', '{}'):
                    with self.subTest(archivo=archivo.name, roto=roto):
                        archivo.write_text(roto, encoding='utf-8')
                        try:
                            res = recolectar(HttpSimulado(), ResolvedorSimulado({}), modo='reproducir',
                                             carpeta=carpeta)
                        except contrato.FuenteNoResponde:
                            continue
                        self.assertFalse(res.estado == 'succeeded' and res.revisados is None
                                         and res.sin_cobertura == completa.sin_cobertura, 'quedó como completa')
                archivo.write_text(bueno, encoding='utf-8')


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
        """Sin ninguna base, nada sale de DB-IP y ninguna IP pública va a InternetDB (RC-49, H11): la cobertura queda
        parcial y el único aviso de la base lo dice, sin repetirlo con SIN_ASN."""
        sin_base = bases(nombres=[], problema='maxminddb no está instalado')
        pedidas = self.con_bases(sin_base)
        http = HttpSimulado(ct_olmardo(), {CAMARA: CAMARA_8080})
        res = recolectar(http, ResolvedorSimulado(zona_olmardo()))
        self.assertEqual(http.consultadas(), set())
        ips = [a.atributos for a in res.activos if a.tipo == 'ip']
        self.assertEqual(len(ips), 3)
        for atributos in ips:
            self.assertEqual({k: atributos[k] for k in CLAVES_GEO},
                             {'pais': NO, 'asn': NO, 'proveedor': NO, 'fuente_geo': NO, 'base_geo': NO})
            self.assertNotIn('fuente_datos', atributos)
        self.assertEqual([activo(res, ip).atributos['internetdb'] for ip in (CAMARA, RESERVAS)], ['sin_asn'] * 2)
        self.assertEqual(activo(res, CLOUDFLARE).atributos['cdn'], 'cloudflare')   # por sus rangos, sin la base
        aviso = geoip.aviso_sin_base('shodan', sin_base, sin_asn=shodan.SIN_CDN_POR_ASN)
        self.assertEqual(res.avisos.count(aviso), 1)
        self.assertTrue(aviso.startswith('shodan: sin la base local de DB-IP Lite (maxminddb no está instalado)'))
        self.assertTrue(aviso.endswith(shodan.SIN_CDN_POR_ASN))
        self.assertFalse([x for x in res.avisos if 'sin ASN en la base' in x], res.avisos)
        self.assertEqual((res.estado, res.hallazgos, res.sin_cobertura), ('succeeded', [], codigos_sin(res)))
        self.assertEqual(shodan.codigo_salida(res), 2)   # cobertura parcial: no cierra los hallazgos de antes
        self.assertEqual(res.revisados, [CLOUDFLARE, CLOUDFLARE + shodan.PARTE_CVE, CLOUDFLARE + ETQ])   # la de CDN cuenta revisada
        self.assertEqual(sorted(res.sin_revisar), sorted(ip + p for ip in (CAMARA, RESERVAS) for p in ('', shodan.PARTE_CVE, ETQ)))
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
        self.assertEqual((con_base.activos, con_base.hallazgos, con_base.sin_cobertura, con_base.avisos,
                          con_base.revisados, con_base.sin_revisar, con_base.omitidos),
                         (vivo.activos, vivo.hallazgos, vivo.sin_cobertura, vivo.avisos, vivo.revisados, vivo.sin_revisar,
                          vivo.omitidos))

        # Sin la base de ASN la grabación no basta: las IP sin ASN no se piden a InternetDB ni a la grabación (RC-49,
        # H11), quedan sin revisar y la corrida, parcial.
        self.assertEqual({ip: activo(otra, ip).atributos['internetdb'] for ip in (CAMARA, RESERVAS)},
                         {CAMARA: 'sin_asn', RESERVAS: 'sin_asn'})
        self.assertEqual((otra.hallazgos, otra.sin_cobertura, otra.revisados),
                         ([], codigos_sin(otra), [CLOUDFLARE, CLOUDFLARE + shodan.PARTE_CVE, CLOUDFLARE + ETQ]))
        self.assertEqual(sorted(otra.sin_revisar), sorted(ip + p for ip in (CAMARA, RESERVAS) for p in ('', shodan.PARTE_CVE, ETQ)))
        self.assertIn(geoip.aviso_sin_base('shodan', sin_base, sin_asn=shodan.SIN_CDN_POR_ASN), otra.avisos)
        self.assertFalse([x for x in otra.avisos if 'no hay respuesta grabada' in x], otra.avisos)
        self.assertEqual((activo(otra, CAMARA).atributos['asn'], activo(vivo, CAMARA).atributos['asn']), (NO, 8075))

    def test_48_el_aviso_de_limites_ya_no_deja_el_cdn_para_15b(self):
        """geo-G2: LIMITES no dice que solo se escapan los CDN de una nube mixta. También los que no están en
        CDN_POR_ASN (CDN77, Edgecast u otros). Sin la base ya no se escapa ninguno: no se consulta nada (RC-49, H11)."""
        self.assertNotIn('#15b', shodan.LIMITES)
        for texto in ('CNAME conocido', 'geoip.CDN_POR_ASN', 'nubes mixtas', 'otros fuera de la lista',
                      'CloudFront, Azure Front Door y los bordes de Google del ' + shodan.RANGOS_CDN_FECHA,
                      'Cloud CDN en un balanceador de Google Cloud'):
            self.assertIn(texto, shodan.LIMITES)
        self.assertNotIn('sin la base', shodan.LIMITES)
        self.assertEqual(shodan.MAX_CONSULTAS, 214)   # la ubicación es local: no suma consultas

    def test_49_sin_la_base_de_asn_ninguna_ip_va_a_internetdb_y_el_aviso_lo_dice(self):
        """geo-G1 y H11 de la auditoría del 12 nov (RC-49): sin la base de ASN, Fastly sin CNAME no llega a InternetDB,
        ni la VM, porque no se puede descartar que sean de un CDN. El único aviso de base faltante lo dice. Si falta
        solo la de países, el filtro sí corre y el aviso no lo menciona."""
        llenas = self.bases_llenas()
        zona = {DOMINIO: a(CAMARA), 'www.olmardo.com': a(self.FASTLY)}
        sin_asn = bases(pais=llenas.pais, nombres=NOMBRES[1:], problema='falta dbip-asn-lite-AAAA-MM.mmdb en datos/geo')
        self.con_bases(sin_asn)
        http = HttpSimulado(paginas('www.olmardo.com'), {CAMARA: CAMARA_8080, self.FASTLY: 404})
        res = recolectar(http, ResolvedorSimulado(zona))
        self.assertEqual(http.consultadas(), set())
        self.assertEqual({ip: activo(res, ip).atributos['internetdb'] for ip in (CAMARA, self.FASTLY)},
                         {CAMARA: 'sin_asn', self.FASTLY: 'sin_asn'})
        self.assertEqual((res.hallazgos, shodan.codigo_salida(res)), ([], 2))
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
        reproduce con una base que le da otro ASN que no es de CDN, la IP se pide a la grabación, no está y la corrida
        queda parcial por 'grabacion', con su aviso y sin red. Es lo que dice docs/contrato_plugin.md: la grabación no
        cambia. Con una base que no trae su ASN, ni se pide (RC-49, H11)."""
        self.con_bases(self.bases_llenas())
        zona = {DOMINIO: a(CAMARA), 'www.olmardo.com': a(self.FASTLY)}
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            vivo = recolectar(HttpSimulado(paginas('www.olmardo.com'), {CAMARA: CAMARA_8080}), ResolvedorSimulado(zona),
                              modo='grabar', carpeta=carpeta, nueva=True)
            self.assertNotIn(shodan.NO_SE_GRABO, vivo.avisos)
            self.assertEqual(activo(vivo, self.FASTLY).atributos['cdn'], 'fastly')
            self.assertFalse((carpeta / ('internetdb_%s.json' % self.FASTLY)).exists())
            otra_base = bases(LectorFalso({CAMARA: registro_asn(8075, 'Microsoft Corporation'),
                                           self.FASTLY: registro_asn(ASN_DOC, 'Ejemplo de documentacion')}),
                              LectorFalso({CAMARA: registro_pais('US')}))
            self.con_bases(otra_base)
            http = HttpSimulado()
            otra = recolectar(http, ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
            self.con_bases(bases(LectorFalso({CAMARA: registro_asn(8075, 'Microsoft Corporation')}),
                                 LectorFalso({CAMARA: registro_pais('US')})))
            sin_fastly = recolectar(http, ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
        self.assertEqual(http.urls, [])
        self.assertIn('shodan: %sinternetdb:%s' % (contrato.SIN_GRABACION, self.FASTLY), otra.avisos)
        fastly = activo(otra, self.FASTLY).atributos
        self.assertEqual((fastly['internetdb'], 'cdn' in fastly), ('sin_respuesta', False))
        self.assertEqual(otra.hallazgos, vivo.hallazgos)   # lo de la cámara sí estaba grabado
        self.assertEqual(otra.sin_cobertura, codigos_sin(otra))
        self.assertEqual((otra.estado, shodan.codigo_salida(otra)), ('succeeded', 2))
        self.assertEqual(activo(sin_fastly, self.FASTLY).atributos['internetdb'], 'sin_asn')
        self.assertFalse([x for x in sin_fastly.avisos if 'no hay respuesta grabada' in x], sin_fastly.avisos)
        self.assertIn(shodan.SIN_ASN % ('1 IP', self.FASTLY), sin_fastly.avisos)
        self.assertEqual((sin_fastly.hallazgos, shodan.codigo_salida(sin_fastly)), (vivo.hallazgos, 2))


    def test_52_una_ip_que_la_base_no_trae_no_va_a_internetdb_ni_pisa_la_grabacion(self):
        """H11 de la auditoría del 12 nov (RC-49): con la base de ASN abierta, la IP que la base no trae no se consulta,
        porque no se puede descartar que sea de un CDN. La otra sí. Su aviso las cuenta, la cobertura queda parcial con
        esa IP sin revisar (no se cierran sus hallazgos de antes) y --grabar no pisa la grabación anterior."""
        llenas = self.bases_llenas()
        self.con_bases(bases(LectorFalso({CAMARA: registro_asn(8075, 'Microsoft Corporation')}), llenas.pais))
        zona = {DOMINIO: a(CAMARA), 'www.olmardo.com': a(self.AMAZON)}
        http = HttpSimulado(paginas('www.olmardo.com'), {CAMARA: CAMARA_8080, self.AMAZON: 404})
        res = recolectar(http, ResolvedorSimulado(zona))
        self.assertEqual(http.consultadas(), {CAMARA})
        self.assertEqual(activo(res, self.AMAZON).atributos['internetdb'], 'sin_asn')
        self.assertIn(shodan.SIN_ASN % ('1 IP', self.AMAZON), res.avisos)
        self.assertEqual([h.activo for h in res.hallazgos], ['20.69.154.199:8080/tcp'])
        self.assertEqual(sorted(res.sin_revisar), sorted([CAMARA + ETQ, self.AMAZON, self.AMAZON + shodan.PARTE_CVE,
                                                          self.AMAZON + ETQ]))
        self.assertEqual((res.estado, shodan.codigo_salida(res)), ('succeeded', 2))
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            self.con_bases(llenas)
            completa = recolectar(HttpSimulado(paginas('www.olmardo.com'), {CAMARA: CAMARA_8080, self.AMAZON: 404}),
                                  ResolvedorSimulado(zona), modo='grabar', carpeta=carpeta, nueva=True)
            self.assertNotIn(shodan.NO_SE_GRABO, completa.avisos)
            antes = {f.name: f.read_bytes() for f in carpeta.glob('*.json')}
            self.assertIn('internetdb_%s.json' % self.AMAZON, antes)
            self.con_bases(bases(LectorFalso({CAMARA: registro_asn(8075, 'Microsoft Corporation')}), llenas.pais))
            otra = recolectar(HttpSimulado(paginas('www.olmardo.com'), {CAMARA: CAMARA_8080}),
                              ResolvedorSimulado(zona), modo='grabar', carpeta=carpeta)
            self.assertEqual(otra.avisos[0], shodan.NO_SE_GRABO)
            self.assertEqual({f.name: f.read_bytes() for f in carpeta.glob('*.json')}, antes)
        self.assertEqual(shodan.codigo_salida(otra), 3)

    def test_53_las_ip_de_los_rangos_de_cdn_de_las_nubes_no_van_a_internetdb(self):
        """H11 de la auditoría del 12 nov (RC-49): una IP de CloudFront, de Azure Front Door o de un borde de Google, sin
        CNAME a la vista y con un ASN mixto que geoip.CDN_POR_ASN no lista, no se consulta. Una VM de Amazon, una de
        Google Cloud y la de camaras (Microsoft, AS8075) sí."""
        cloudfront, front_door, google = '52.84.17.10', '13.107.246.40', '142.250.0.10'
        ec2, gce = '3.80.0.10', '34.123.45.67'
        zona = {DOMINIO: a(CAMARA), 'cf.olmardo.com': a(cloudfront), 'fd.olmardo.com': a(front_door),
                'g.olmardo.com': a(google), 'ec2.olmardo.com': a(ec2), 'gce.olmardo.com': a(gce)}
        respuestas = {ip: 404 for ip in (cloudfront, front_door, google, ec2, gce)}
        respuestas[CAMARA] = CAMARA_8080
        http = HttpSimulado(paginas(*sorted(n for n in zona if n != DOMINIO)), respuestas)
        res = recolectar(http, ResolvedorSimulado(zona))
        self.assertEqual(http.consultadas(), {CAMARA, ec2, gce})
        self.assertEqual({ip: activo(res, ip).atributos.get('cdn') for ip in (cloudfront, front_door, google, ec2, gce)},
                         {cloudfront: 'cloudfront', front_door: 'azure_front_door', google: 'google', ec2: None,
                          gce: None})
        self.assertEqual((res.estado, shodan.codigo_salida(res)), ('succeeded', 0))
        for ip in (CAMARA, RESERVAS, ec2, gce, '199.36.158.100'):
            self.assertIsNone(shodan.cdn_de(ip), ip)
        self.assertEqual({cdn for _, cdn in shodan.RANGOS_CDN}, {'cloudfront', 'azure_front_door', 'google'})
        self.assertTrue(all(r.version == 4 and r.is_global for r, _ in shodan.RANGOS_CDN))

    def test_54_rangos_cdn_arma_el_json_sin_red_y_el_del_repo_tiene_su_forma(self):
        """H11 (RC-49): rangos_cdn.armar toma solo CLOUDFRONT de Amazon, solo AzureFrontDoor.Frontend de Azure y goog.json
        menos cloud.json de Google, sin IPv6 ni redes que no son globales. rangos_cdn.json es lo que escribe main()."""
        aws = {'syncToken': '1', 'createDate': 'x', 'prefixes': [
            {'ip_prefix': '52.84.0.0/16', 'service': 'CLOUDFRONT'}, {'ip_prefix': '52.85.0.0/16', 'service': 'CLOUDFRONT'},
            {'ip_prefix': '3.80.0.0/12', 'service': 'EC2'}]}
        azure = {'changeNumber': 2, 'cloud': 'Public', 'values': [
            {'name': 'AzureFrontDoor.Frontend', 'properties': {'changeNumber': 3, 'addressPrefixes': [
                '13.107.246.0/24', '2620:1ec:bdf::/48', '10.0.0.0/8']}},
            {'name': 'AzureCloud', 'properties': {'changeNumber': 4, 'addressPrefixes': ['20.69.154.0/24']}}]}
        goog = {'syncToken': '5', 'creationTime': 'y', 'prefixes': [
            {'ipv4Prefix': '8.8.8.0/24'}, {'ipv4Prefix': '34.0.0.0/15'}, {'ipv6Prefix': '2001:4860::/32'}]}
        cloud = {'syncToken': '5', 'prefixes': [{'ipv4Prefix': '34.0.0.0/16', 'service': 'Google Cloud'}]}
        armado = rangos_cdn.armar(aws, azure, goog, cloud, '2026-11-12')
        self.assertEqual(armado['rangos'], {'cloudfront': ['52.84.0.0/15'], 'azure_front_door': ['13.107.246.0/24'],
                                            'google': ['8.8.8.0/24', '34.1.0.0/16']})
        self.assertEqual(armado['procedencia']['descargado'], '2026-11-12')
        with self.assertRaises(ValueError):
            rangos_cdn.armar(aws, {'changeNumber': 2, 'cloud': 'Public', 'values': azure['values'][1:]}, goog, cloud, 'f')
        with self.assertRaises(ValueError):
            rangos_cdn.armar(aws, azure, goog, {'syncToken': '5', 'prefixes': goog['prefixes']}, 'f')   # Google sin rangos
        archivo = Path(rangos_cdn.__file__).with_name('rangos_cdn.json')
        texto = archivo.read_text(encoding='utf-8')
        leido = json.loads(texto)
        self.assertEqual(texto, json.dumps(leido, ensure_ascii=False, indent=1, sort_keys=True) + '\n')
        self.assertEqual(leido['procedencia']['descargado'], shodan.RANGOS_CDN_FECHA)
        self.assertRegex(shodan.RANGOS_CDN_FECHA, r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$')
        for cdn, redes in leido['rangos'].items():
            unidas = [str(r) for r in ipaddress.collapse_addresses(ipaddress.ip_network(x) for x in redes)]
            self.assertEqual(redes, unidas, cdn)


LLAVE = 'CIRDAN_FAKE_' + 'k7Qm2Xv9Lp4Rt8Wz3Nb6'   # falsa, con la forma de LLAVE_VALIDA (AGENTS.md regla 7)
LEER_LLAVE = shodan._llave_de_config               # la de verdad, antes de que setUpModule la cambie (sin_llave)


def banner(puerto, protocolo='tcp', producto=None, version=None, visto='2026-11-10T12:34:56.123456', tags=()):
    """Un servicio de la API de host con la forma real: con el banner, el HTML y los nombres que nunca se guardan."""
    return {'port': puerto, 'transport': protocolo, 'product': producto, 'version': version, 'timestamp': visto,
            'tags': list(tags), 'data': 'banner completo de prueba', 'http': {'html': '<html>prueba</html>'},
            'hostnames': ['interno.ejemplo.test'], 'location': {'city': 'Ciudad de prueba'}}


def respuesta_host(ip, tags=(), servicios=None):
    """Una respuesta 200 de GET /shodan/host/<ip> con la forma real. Sin `servicios`, uno en el 502."""
    servicios = [banner(502, producto='Modbus', tags=tags)] if servicios is None else servicios
    return {'ip_str': ip, 'tags': list(tags), 'ports': sorted({s['port'] for s in servicios}), 'data': servicios,
            'hostnames': ['interno.olmardo.com'], 'org': 'Organizacion de prueba'}


def con_llave(http, dns, llave=LLAVE, modo='vivo', carpeta=None, nueva=False, cronometro=None):
    """Como recolectar(), con la llave de la API de host en el cliente (la que crear_cliente toma de SHODAN_API_KEY)."""
    cliente = shodan.ClienteShodan(modo=modo, carpeta=carpeta or shodan.carpeta_de(DOMINIO), descargar=http,
                                   resolver=dns, nueva=nueva, cronometro=cronometro or Cronometro(0),
                                   dormir=lambda s: None, llave=llave)
    return shodan.recolectar(DOMINIO, cliente, ahora=AHORA)


def url_host(ip):
    return shodan.URL_HOST + ip + '?key=' + LLAVE


def todo(res):
    """Todo el resultado como texto: activos, hallazgos con su evidencia, avisos, error y cobertura."""
    return json.dumps(res.a_dict(), default=str, ensure_ascii=False)


class EtiquetasInternetDB(unittest.TestCase):
    """RC-220: sin la llave, las etiquetas de InternetDB dan exposed_ot_device, exposed_iot_device y outdated_software,
    sin fecha. Sin la API de host la parte '<ip>/etiquetas' nunca queda revisada."""

    def test_1_cada_etiqueta_da_su_codigo_con_la_evidencia_de_internetdb(self):
        for etiqueta, codigo in shodan.ETIQUETAS.items():
            with self.subTest(etiqueta=etiqueta):
                http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, tags=[etiqueta])})
                res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                self.assertEqual(res.estado, 'succeeded')
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
                [h] = res.hallazgos
                self.assertEqual((h.codigo, h.severidad, h.activo, h.partes),
                                 (codigo, shodan.CODIGOS[codigo], CAMARA, [CAMARA + ETQ]))
                self.assertEqual(h.severidad, POR_CODIGO[codigo][5])
                self.assertEqual((h.evidencia['fuente_datos'], h.evidencia['etiquetas'], h.evidencia['vigencia'],
                                  h.evidencia['fuente_sin_fecha']), ('Shodan InternetDB', [etiqueta], 'sin_fecha', True))
                self.assertNotIn('servicios', h.evidencia)
                self.assertEqual(res.sin_cobertura, [c for c in shodan.SIN_LLAVE if c != codigo])
                self.assertEqual(res.revisados, [CAMARA, CAMARA + shodan.PARTE_CVE])
                self.assertEqual(res.sin_revisar, [CAMARA + ETQ])
                self.assertIn(shodan.LIMITES, res.avisos)
                self.assertEqual(http.de_host(), [])

    def test_2_eol_product_y_eol_os_dan_un_solo_outdated_software(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, tags=['eol-product', 'eol-os', 'iot'])})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        por_codigo = {h.codigo: h for h in res.hallazgos}
        self.assertEqual(sorted(por_codigo), ['exposed_iot_device', 'outdated_software'])
        self.assertEqual(por_codigo['outdated_software'].evidencia['etiquetas'], ['eol-os', 'eol-product'])
        self.assertEqual(por_codigo['outdated_software'].titulo,
                         'Shodan marca software sin soporte del fabricante (eol-os, eol-product) en olmardo.com')
        self.assertEqual(res.sin_cobertura, ['exposed_ot_device'])
        self.assertEqual(res.sin_revisar, [CAMARA + ETQ])

    def test_3_una_ip_sin_etiquetas_deja_los_tres_codigos_sin_cobertura(self):
        res = recolectar(HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[8080])}),
                         ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual([h.codigo for h in res.hallazgos], ['exposed_service'])
        self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))
        self.assertEqual((res.revisados, res.sin_revisar), (None, None))

    def test_4_honeypot_con_ics_y_etiquetas_desconocidas_no_dan_hallazgos(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, tags=['honeypot', 'ics']),
                                 RESERVAS: internetdb(RESERVAS, tags=['cloud', 'vpn', 'starlink'])})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA, RESERVAS)}))
        self.assertEqual(res.hallazgos, [])
        self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))
        self.assertIn('shodan: InternetDB marca %s como honeypot, no se sacan hallazgos de esa IP' % CAMARA, res.avisos)
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])


class ApiDeHost(unittest.TestCase):
    """RC-337: con la llave, GET /shodan/host/<ip> por cada IP que va a InternetDB. Nunca /shodan/scan ni la búsqueda, y
    la llave solo va en la URL que se manda: nunca en la grabación, los avisos, el error, la evidencia ni los activos."""

    def solo_host(self, http):
        """Toda URL de la API de Shodan es la de host, con la llave al final, y ninguna de scan ni de búsqueda."""
        for u in http.de_host():
            self.assertTrue(u.startswith(shodan.URL_HOST), u)
            self.assertTrue(u.endswith('?key=' + LLAVE), u)
            self.assertNotIn('/scan', u)
            self.assertNotIn('search', u)

    def test_1_cada_etiqueta_da_su_codigo_con_servicios_y_fecha(self):
        for etiqueta, codigo in shodan.ETIQUETAS.items():
            with self.subTest(etiqueta=etiqueta):
                servicios = [banner(502, producto='Modbus', tags=[etiqueta]),
                             banner(443, producto='nginx', version='1.18', visto='2026-11-01T00:00:00.000000')]
                http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[443])},
                                    hosts={CAMARA: respuesta_host(CAMARA, [etiqueta], servicios)})
                res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                self.assertEqual(res.estado, 'succeeded')
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
                self.assertEqual(http.de_host(), [url_host(CAMARA)])
                self.solo_host(http)
                [h] = res.hallazgos
                self.assertEqual((h.codigo, h.severidad, h.activo, h.partes),
                                 (codigo, shodan.CODIGOS[codigo], CAMARA, [CAMARA + ETQ]))
                self.assertEqual(h.evidencia['fuente_datos'], 'Shodan')
                self.assertEqual(h.evidencia['servicios'], [{'puerto': 502, 'protocolo': 'tcp', 'producto': 'Modbus',
                                                             'version': None, 'visto': '2026-11-10T12:34:56Z'}])
                self.assertEqual((h.evidencia['vigencia'], h.evidencia['ultima_vez'], h.evidencia['etiquetas']),
                                 ('con_fecha', '2026-11-10T12:34:56Z', [etiqueta]))
                self.assertEqual(activo(res, CAMARA).atributos['shodan_host'], {'tags': [etiqueta], 'puertos': [443, 502]})
                # Revisada completa en la única IP: los tres códigos tienen cobertura y no hay partes
                self.assertEqual((res.sin_cobertura, res.revisados, res.sin_revisar), ([], None, None))
                self.assertIn(shodan.LIMITES_CON_LLAVE, res.avisos)
                self.assertNotIn(shodan.LIMITES, res.avisos)
                texto = todo(res)
                for nunca in ('banner completo', '<html>', 'interno.ejemplo.test', 'Ciudad de prueba', LLAVE):
                    self.assertNotIn(nunca, texto)

    def test_2_una_ip_sin_etiquetas_queda_revisada(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA)}, hosts={CAMARA: respuesta_host(CAMARA)})
        res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(res.hallazgos, [])
        self.assertEqual((res.sin_cobertura, res.revisados, res.sin_revisar), ([], None, None))
        self.assertFalse(any(x.startswith('shodan: la API de host respondió completa') for x in res.avisos))

    def test_3_un_404_deja_las_etiquetas_sin_cobertura(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA)})   # la API de host da 404 a toda IP que no está
        res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(http.por_host, {CAMARA: 1})   # un 404 no se reintenta
        self.assertEqual(activo(res, CAMARA).atributos['shodan_host'], 'sin_datos')
        self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))
        self.assertIn(shodan.ETIQUETAS_PARCIAL % (0, 1), res.avisos)
        self.assertEqual(res.sin_llave, [])   # con la llave lo que falta es cobertura parcial, no la llave (RC-229)
        # Con una etiqueta de InternetDB sale su hallazgo, sin fecha, y la parte de etiquetas queda sin revisar
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, tags=['iot'])})
        res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        [h] = res.hallazgos
        self.assertEqual((h.codigo, h.evidencia['fuente_datos']), ('exposed_iot_device', 'Shodan InternetDB'))
        self.assertEqual(res.sin_cobertura, ['exposed_ot_device', 'outdated_software'])
        self.assertEqual((res.revisados, res.sin_revisar), ([CAMARA, CAMARA + shodan.PARTE_CVE], [CAMARA + ETQ]))

    def test_4_un_503_o_un_timeout_no_tumban_la_fuente_ni_lo_de_internetdb(self):
        for caso, respuesta in (('503', [503, 503, 503]), ('timeout', TimeoutError('lento'))):
            with self.subTest(caso=caso):
                http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[3389])}, hosts={CAMARA: respuesta})
                res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                self.assertEqual(res.estado, 'succeeded')
                self.assertEqual(http.por_host, {CAMARA: shodan.INTENTOS})
                self.assertEqual([h.codigo for h in res.hallazgos], ['exposed_rdp'])
                self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))   # exposed_rdp y los de puertos, completos
                self.assertIn(shodan.ETIQUETAS_PARCIAL % (0, 1), res.avisos)
                self.assertTrue(any(x.startswith('shodan: la API de host (%s) no respondió después de 3 intentos' % CAMARA)
                                    for x in res.avisos), res.avisos)
                self.assertNotIn(LLAVE, todo(res))

    def test_5_401_o_403_dicen_que_rechazo_la_llave_y_cortan_las_demas(self):
        for codigo in (401, 403):
            with self.subTest(codigo=codigo):
                http = HttpSimulado(ips={CAMARA: internetdb(CAMARA), RESERVAS: internetdb(RESERVAS)},
                                    hosts={CAMARA: codigo, RESERVAS: respuesta_host(RESERVAS, ['iot'])})
                res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA, RESERVAS)}))
                self.assertEqual(http.de_host(), [url_host(CAMARA)])
                self.assertIn(shodan.LLAVE_RECHAZADA % (codigo, '2 IP'), res.avisos)
                self.assertEqual(res.hallazgos, [])
                self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))
                self.assertIn(shodan.ETIQUETAS_PARCIAL % (0, 2), res.avisos)
                self.assertNotIn(LLAVE, todo(res))

    def test_6_un_429_corta_las_ip_que_faltan(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA), RESERVAS: internetdb(RESERVAS)}, hosts={CAMARA: 429})
        res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA, RESERVAS)}))
        self.assertEqual(http.de_host(), [url_host(CAMARA)])
        [aviso] = [x for x in res.avisos if '429' in x]
        self.assertTrue(aviso.startswith('shodan: la API de host (%s) llegó a su límite de consultas (429' % CAMARA))
        self.assertTrue(aviso.endswith('. No se consultaron 2 IP'), aviso)
        self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))
        self.assertIn(shodan.ETIQUETAS_PARCIAL % (0, 2), res.avisos)

    def test_7_honeypot_solo_en_la_api_de_host_descarta_la_ip(self):
        aviso = 'shodan: la API de host marca %s como honeypot, no se sacan hallazgos de esa IP' % CAMARA
        for caso, en_idb in (('con InternetDB', internetdb(CAMARA, ports=[3389], vulns=['CVE-2024-6387'])),
                             ('InternetDB 404', 404)):
            with self.subTest(caso=caso):
                http = HttpSimulado(ips={CAMARA: en_idb}, hosts={CAMARA: respuesta_host(CAMARA, ['honeypot', 'ics'])})
                res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                self.assertEqual((res.hallazgos, [x.tipo for x in res.activos]), ([], ['ip']))
                self.assertEqual(res.avisos.count(aviso), 1)
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_8_sin_llave_o_con_una_mal_formada_no_hay_url_de_host_ni_su_valor_en_el_aviso(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA)}, hosts={CAMARA: respuesta_host(CAMARA, ['iot'])})
        res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}), llave='')
        self.assertEqual(http.de_host(), [])
        self.assertIn(shodan.LIMITES, res.avisos)
        self.assertNotIn(shodan.LLAVE_MAL, res.avisos)
        for mala in ('CIRDAN_FAKE_corta', LLAVE + '&x=1', 'CIRDAN FAKE k7Qm2Xv9Lp4Rt8Wz3Nb6', LLAVE + '/../scan'):
            with self.subTest(mala=mala):
                http = HttpSimulado(ips={CAMARA: internetdb(CAMARA)}, hosts={CAMARA: respuesta_host(CAMARA, ['iot'])})
                res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}), llave=mala)
                self.assertEqual(http.de_host(), [])
                self.assertIn(shodan.LLAVE_MAL, res.avisos)
                self.assertIn(shodan.LIMITES, res.avisos)
                self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))
                self.assertNotIn(mala, todo(res))

    def test_9_la_llave_nunca_sale_en_la_grabacion_los_avisos_el_error_la_evidencia_ni_los_activos(self):
        dns = {DOMINIO: a(CAMARA, RESERVAS)}
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            http = HttpSimulado(ips={CAMARA: internetdb(CAMARA), RESERVAS: internetdb(RESERVAS)},
                                hosts={CAMARA: respuesta_host(CAMARA, ['iot'])})
            res = con_llave(http, ResolvedorSimulado(dns), modo='grabar', carpeta=carpeta, nueva=True)
            self.assertNotIn(shodan.NO_SE_GRABO, res.avisos)
            archivos = {p.name: p.read_bytes() for p in carpeta.iterdir()}
            self.assertIn('host_20.69.154.199.json', archivos)
            self.assertEqual(json.loads(archivos['host_40.65.94.253.json'])['datos'], {'sin_datos': True})
            grabada = json.loads(archivos['host_20.69.154.199.json'])['datos']
            self.assertEqual(sorted(grabada), ['hostnames_ajenos', 'rotos', 'servicios', 'tags'])   # solo cuenta
            self.assertEqual(sorted(grabada['servicios'][0]), ['producto', 'protocolo', 'puerto', 'tags', 'version', 'visto'])
            for nombre, contenido in archivos.items():
                for nunca in (LLAVE.encode(), b'key=', b'banner completo', b'interno.olmardo.com'):
                    self.assertNotIn(nunca, contenido, nombre)
            self.assertNotIn(LLAVE, todo(res))
        # Una URLError cuyo texto trae la URL con la llave (se reintenta) y un KeyError(url) inesperado
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA), RESERVAS: internetdb(RESERVAS)},
                            hosts={CAMARA: urllib.error.URLError('sin red hacia ' + url_host(CAMARA)),
                                   RESERVAS: KeyError(url_host(RESERVAS))})
        res = con_llave(http, ResolvedorSimulado(dns))
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(http.por_host, {CAMARA: shodan.INTENTOS, RESERVAS: 1})
        self.assertNotIn(LLAVE, todo(res))
        self.assertTrue(any('key=' + shodan.LLAVE_TAPADA in x for x in res.avisos), res.avisos)
        self.assertIn('shodan: la API de host (%s) falló (KeyError)' % RESERVAS, res.avisos)
        # Lo mismo por contrato.ejecutar, con la llave de SHODAN_API_KEY: ni el error ni scan_source_runs la llevan
        with tempfile.TemporaryDirectory() as d, mock.patch.object(shodan, 'CARPETA_GRABADAS', Path(d)), \
                mock.patch.object(shodan, '_llave_de_config', return_value=LLAVE), \
                mock.patch.object(shodan, '_descargar', HttpSimulado(
                    ips={CAMARA: internetdb(CAMARA)},
                    hosts={CAMARA: urllib.error.URLError('sin red hacia ' + url_host(CAMARA))})), \
                mock.patch.object(shodan, '_resolver_a', ResolvedorSimulado({DOMINIO: a(CAMARA)})), \
                mock.patch.object(shodan.time, 'sleep', lambda s: None):
            otra = contrato.ejecutar(cargar('shodan'), DOMINIO, modo='vivo', ahora=AHORA, codigos=set(POR_CODIGO))
        self.assertEqual(otra.estado, 'succeeded', otra.error)
        self.assertNotIn(LLAVE, todo(otra))
        # Un FuenteNoResponde que sale de la corrida con la llave en su texto sale tapado, y un aviso también
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA)})
        falla = FuenteNoResponde('shodan: falló ' + url_host(CAMARA))
        with mock.patch.object(shodan, '_revisar', side_effect=falla), self.assertRaises(FuenteNoResponde) as cm:
            con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertNotIn(LLAVE, str(cm.exception))
        self.assertIn('key=' + shodan.LLAVE_TAPADA, str(cm.exception))

        def con_aviso(res, cliente, dominio, ahora):
            res.avisos.append('shodan: un aviso con %s dentro' % LLAVE)
        with mock.patch.object(shodan, '_revisar', con_aviso):
            res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(res.avisos, ['shodan: un aviso con %s dentro' % shodan.LLAVE_TAPADA])

    def test_10_reproducir_con_y_sin_grabaciones_de_la_api_de_host(self):
        dns = {DOMINIO: a(CAMARA, RESERVAS)}
        for caso, llave_al_grabar in (('con host_*.json', LLAVE), ('sin host_*.json', '')):
            with self.subTest(caso=caso), tempfile.TemporaryDirectory() as d:
                carpeta = Path(d) / DOMINIO
                http = HttpSimulado(ips={CAMARA: internetdb(CAMARA), RESERVAS: internetdb(RESERVAS)},
                                    hosts={CAMARA: respuesta_host(CAMARA, ['iot']), RESERVAS: respuesta_host(RESERVAS)})
                grabada = con_llave(http, ResolvedorSimulado(dns), llave=llave_al_grabar, modo='grabar',
                                    carpeta=carpeta, nueva=True)
                self.assertEqual(any(carpeta.glob('host_*.json')), bool(llave_al_grabar))
                otro = HttpSimulado()
                repetida = con_llave(otro, ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)   # con LLAVE
                self.assertEqual(otro.urls, [])
                self.assertEqual((repetida.activos, repetida.hallazgos, repetida.sin_cobertura, repetida.avisos,
                                  repetida.revisados, repetida.sin_revisar),
                                 (grabada.activos, grabada.hallazgos, grabada.sin_cobertura, grabada.avisos,
                                  grabada.revisados, grabada.sin_revisar))
                if llave_al_grabar:
                    self.assertEqual([h.codigo for h in repetida.hallazgos], ['exposed_iot_device'])
                    self.assertEqual(repetida.sin_cobertura, [])
                    self.assertIn(shodan.LIMITES_CON_LLAVE, repetida.avisos)
                else:
                    self.assertEqual(repetida.hallazgos, [])
                    self.assertEqual(repetida.sin_cobertura, list(shodan.SIN_LLAVE))
                    self.assertIn(shodan.LIMITES, repetida.avisos)

    def test_11_el_peor_caso_con_la_llave_gasta_justo_max_consultas(self):
        """test_14 con la API de host: cada una de las MAX_IPS IP responde al tercer intento."""
        nombres = ['n%02d.olmardo.com' % i for i in range(shodan.MAX_NOMBRES + 1)]
        mitad = len(nombres) // 2
        ct = [500, paginas(*nombres[:mitad])[0], 500, paginas(*nombres[mitad:], id_=9201)[0]]
        zona = {DOMINIO: ['falla', 'falla', a('20.69.154.10')]}
        zona.update({n: ['falla', 'falla', a('20.69.154.%d' % (11 + i))] for i, n in enumerate(nombres)})
        todas = ['20.69.154.%d' % (10 + i) for i in range(len(nombres) + 1)]
        ips = {ip: [500, 500, internetdb('', ports=[8080])] for ip in todas}
        hosts = {ip: [500, 500, respuesta_host(ip)] for ip in todas}
        http, dns = HttpSimulado(ct, ips, hosts), ResolvedorSimulado(zona)
        res = con_llave(http, dns)
        self.assertEqual(shodan.MAX_CONSULTAS, 214)
        self.assertEqual((res.consultas, len(http.urls) + len(dns.nombres)), (shodan.MAX_CONSULTAS, shodan.MAX_CONSULTAS))
        self.assertEqual(len(http.de_host()), shodan.MAX_IPS * shodan.INTENTOS)
        self.assertEqual(set(http.por_host), http.consultadas())
        self.solo_host(http)

    def test_12_la_unica_ruta_de_la_api_de_shodan_es_la_de_host(self):
        fuente = Path(shodan.__file__).read_text(encoding='utf-8')
        self.assertEqual(re.findall(r"api\.shodan\.io[^'\"\s]*", fuente), ['api.shodan.io/shodan/host/'])
        self.assertTrue(shodan.URL_HOST.endswith('/shodan/host/'))

    def test_13_crear_cliente_lee_la_llave_en_vivo_y_al_grabar_pero_no_al_reproducir(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(shodan, 'CARPETA_GRABADAS', Path(d)), \
                mock.patch.object(shodan, '_llave_de_config', return_value=LLAVE) as leer:
            self.assertEqual(shodan.crear_cliente('vivo', DOMINIO).llave, LLAVE)
            self.assertEqual(shodan.crear_cliente('grabar', DOMINIO).llave, LLAVE)
            self.assertEqual(leer.call_count, 2)
            self.assertEqual(shodan.crear_cliente('reproducir', DOMINIO).llave, '')
            self.assertEqual(leer.call_count, 2)
            self.assertEqual(shodan.ClienteShodan(modo='reproducir', carpeta=Path(d), llave=LLAVE).llave, '')
        # La de verdad (setUpModule la cambia por sin_llave): SHODAN_API_KEY sin espacios, o '' sin ella
        for puesta, esperada in (('  %s\n' % LLAVE, LLAVE), ('', ''), (None, '')):
            with self.subTest(puesta=puesta), mock.patch.object(shodan, 'config', lambda nombre, omision: puesta):
                self.assertEqual(LEER_LLAVE(), esperada)

    def sin_llave_en_la_cadena(self, error):
        """Ni el error ni los que guarda detrás (__cause__ y __context__) llevan la llave: ni en su texto, ni en sus
        argumentos, ni en la URL de un HTTPError (llave-1)."""
        vistos = []
        while error is not None and all(error is not v for v in vistos):
            vistos.append(error)
            for texto in (str(error), repr(error.args), str(getattr(error, 'url', '') or '')):
                self.assertNotIn(LLAVE, texto, type(error).__name__)
            error = error.__cause__ or error.__context__
        return vistos

    def test_14_ningun_error_de_la_api_de_host_guarda_la_llave_detras(self):
        """llave-1: el error tapado se lanza fuera del except, así su __context__ no guarda el HTTPError con la URL ni el
        KeyError(url) con la llave."""
        for caso, respuesta in (('401', 401), ('KeyError', KeyError(url_host(CAMARA))), ('503', [503, 503, 503])):
            with self.subTest(caso=caso), tempfile.TemporaryDirectory() as d:
                cliente = shodan.ClienteShodan(modo='vivo', carpeta=Path(d),
                                               descargar=HttpSimulado(hosts={CAMARA: respuesta}),
                                               cronometro=Cronometro(0), dormir=lambda s: None, llave=LLAVE)
                with self.assertRaises(FuenteNoResponde) as cm:
                    cliente.host(CAMARA, DOMINIO)
                self.assertEqual(self.sin_llave_en_la_cadena(cm.exception), [cm.exception])
        # Lo mismo con un FuenteNoResponde que sale de la corrida y trae detrás un error con la llave
        def con_detras(res, cliente, dominio, ahora):
            try:
                raise KeyError(url_host(CAMARA))
            except KeyError:
                raise FuenteNoResponde('shodan: falló ' + url_host(CAMARA))
        with mock.patch.object(shodan, '_revisar', con_detras), self.assertRaises(FuenteNoResponde) as cm:
            con_llave(HttpSimulado(), ResolvedorSimulado({}))
        self.assertEqual(self.sin_llave_en_la_cadena(cm.exception), [cm.exception])
        self.assertIn('key=' + shodan.LLAVE_TAPADA, str(cm.exception))

    def test_15_una_llave_mal_formada_no_estropea_los_avisos_ni_el_error(self):
        """llave-2: con SHODAN_API_KEY=0 no se consulta la API de host y no se tapa nada: los avisos y el error quedan
        igual que sin llave, más el aviso LLAVE_MAL."""
        ip = '20.69.154.10'
        for mala in ('0', '1', 'shodan'):
            with self.subTest(mala=mala):
                vistos = {}
                for llave in ('', mala):
                    http = HttpSimulado(ips={ip: internetdb(ip, ports=[8080], hostnames=['otro.ejemplo.test'])})
                    vistos[llave] = con_llave(http, ResolvedorSimulado({DOMINIO: a(ip)}), llave=llave)
                    self.assertEqual(http.de_host(), [])
                self.assertEqual([x for x in vistos[mala].avisos if x != shodan.LLAVE_MAL], vistos[''].avisos)
                self.assertTrue(any(ip in x for x in vistos[mala].avisos), vistos[mala].avisos)
                self.assertNotIn(shodan.LLAVE_TAPADA, todo(vistos[mala]))
                errores = {}
                for llave in ('', mala):
                    http = HttpSimulado(ips={ip: [503, 503, 503]})
                    with self.assertRaises(FuenteNoResponde) as cm:
                        con_llave(http, ResolvedorSimulado({DOMINIO: a(ip)}), llave=llave)
                    errores[llave] = str(cm.exception)
                self.assertEqual(errores[mala], errores[''])
                self.assertNotIn(shodan.LLAVE_TAPADA, errores[mala])

    def grabar_y_luego(self, segunda):
        """Graba una corrida completa con la llave (con host_*.json) y después corre `segunda(carpeta)`, que graba otra
        vez. Devuelve (archivos de la primera, resultado de la segunda, archivos después)."""
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            http = HttpSimulado(ips={CAMARA: internetdb(CAMARA), RESERVAS: internetdb(RESERVAS)},
                                hosts={CAMARA: respuesta_host(CAMARA, ['iot']), RESERVAS: respuesta_host(RESERVAS)})
            primera = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA, RESERVAS)}), modo='grabar', carpeta=carpeta,
                                nueva=True)
            self.assertNotIn(shodan.NO_SE_GRABO, primera.avisos)
            antes = {p.name: p.read_bytes() for p in carpeta.iterdir()}
            self.assertIn('host_%s.json' % CAMARA, antes)
            res = segunda(carpeta)
            return antes, res, {p.name: p.read_bytes() for p in carpeta.iterdir()}

    def test_16_el_tope_de_tiempo_antes_de_la_api_de_host_no_pisa_la_grabacion(self):
        """cobertura-1: InternetDB responde por las 2 IP, pero deja la corrida a 3 s del final y la API de host se corta
        antes de pedir nada. Es una falla: NO_SE_GRABO primero, código de salida 3 y la grabación anterior intacta."""
        def segunda(carpeta):
            reloj = [1000.0]
            http = HttpSimulado(ips={CAMARA: internetdb(CAMARA), RESERVAS: internetdb(RESERVAS)})

            def lenta(url, timeout):
                respuesta = http(url, timeout)
                if url.startswith(shodan.URL_INTERNETDB) and sum(http.por_ip.values()) == 2:
                    reloj[0] = 1000.0 + shodan.TIEMPO_CORRIDA - 3
                return respuesta
            cliente = shodan.ClienteShodan(modo='grabar', carpeta=carpeta, descargar=lenta,
                                           resolver=ResolvedorSimulado({DOMINIO: a(CAMARA, RESERVAS)}), nueva=True,
                                           cronometro=lambda: reloj[0], dormir=lambda s: None, llave=LLAVE)
            res = shodan.recolectar(DOMINIO, cliente, ahora=AHORA)
            self.assertEqual(http.de_host(), [])
            return res
        antes, res, despues = self.grabar_y_luego(segunda)
        self.assertIn('shodan: el tiempo de la corrida cortó 2 IP en la API de host', res.avisos)
        self.assertEqual(res.avisos[0], shodan.NO_SE_GRABO)
        self.assertEqual(shodan.codigo_salida(res), 3)
        self.assertEqual(despues, antes)

    def test_17_una_respuesta_de_host_con_rotos_no_pisa_la_grabacion(self):
        """cobertura-3: un banner sin 'transport' o unos tags que no son lista dejan 'rotos' en la respuesta de host. Es
        una falla, como los campos rotos de InternetDB: --grabar no escribe."""
        sin_transporte = banner(502, producto='Modbus')
        del sin_transporte['transport']
        tags_rotos = dict(respuesta_host(CAMARA), tags='iot')
        for caso, respuesta in (('data', respuesta_host(CAMARA, servicios=[sin_transporte])), ('tags', tags_rotos)):
            with self.subTest(caso=caso):
                def segunda(carpeta):
                    http = HttpSimulado(ips={CAMARA: internetdb(CAMARA), RESERVAS: internetdb(RESERVAS)},
                                        hosts={CAMARA: respuesta, RESERVAS: respuesta_host(RESERVAS)})
                    return con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA, RESERVAS)}), modo='grabar',
                                     carpeta=carpeta, nueva=True)
                antes, res, despues = self.grabar_y_luego(segunda)
                self.assertEqual(res.avisos[0], shodan.NO_SE_GRABO)
                self.assertEqual(despues, antes)
                self.assertNotIn(CAMARA + ETQ, res.revisados or [])

    def test_18_una_ip_revisada_completa_cierra_sus_etiquetas_sin_depender_de_otra(self):
        """cobertura-2: la API de host responde completa por CAMARA, sin etiquetas, y da 503 por RESERVAS. Ninguna IP trae
        hallazgos de etiqueta, y aun así CAMARA/etiquetas va en revisados y RESERVAS/etiquetas en sin_revisar."""
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA), RESERVAS: internetdb(RESERVAS)},
                            hosts={CAMARA: respuesta_host(CAMARA), RESERVAS: [503, 503, 503]})
        res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA, RESERVAS)}))
        self.assertEqual(res.hallazgos, [])
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))
        self.assertIn(CAMARA + ETQ, res.revisados)
        self.assertNotIn(RESERVAS + ETQ, res.revisados)
        for ip in (CAMARA, RESERVAS):
            self.assertIn(ip, res.revisados)
            self.assertIn(ip + shodan.PARTE_CVE, res.revisados)
        self.assertEqual(res.sin_revisar, [RESERVAS + ETQ])
        self.assertIn(shodan.ETIQUETAS_PARCIAL % (1, 2), res.avisos)
        # Solo faltan las etiquetas de RESERVAS: es la cobertura de SIN_LLAVE y la línea de comandos sale con 0
        self.assertEqual(shodan.codigo_salida(res), 0)

    def test_19_las_etiquetas_que_solo_trae_internetdb_van_aparte_y_sin_fecha(self):
        """cobertura-4: InternetDB trae 'eol-os' y la API de host solo 'eol-product'. El outdated_software lleva la
        evidencia de la API de host, con fecha, y 'eol-os' en etiquetas_internetdb con su nota de vigencia."""
        servicios = [banner(443, producto='nginx', tags=['eol-product']),
                     banner(22, producto='OpenSSH', visto='2026-11-12T00:00:00.000000')]
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, tags=['eol-os'])},
                            hosts={CAMARA: respuesta_host(CAMARA, ['eol-product'], servicios)})
        res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        [h] = res.hallazgos
        self.assertEqual((h.codigo, h.evidencia['etiquetas'], h.evidencia['fuente_datos']),
                         ('outdated_software', ['eol-os', 'eol-product'], 'Shodan'))
        self.assertEqual((h.evidencia['etiquetas_internetdb'], h.evidencia['nota_vigencia']),
                         (['eol-os'], shodan.NOTA_SIN_FECHA))
        self.assertEqual([s['puerto'] for s in h.evidencia['servicios']], [443])   # solo el que lleva 'eol-product'
        self.assertEqual(h.evidencia['ultima_vez'], '2026-11-10T12:34:56Z')
        # Con la misma etiqueta en las dos no hay etiquetas_internetdb
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, tags=['eol-product'])},
                            hosts={CAMARA: respuesta_host(CAMARA, ['eol-product'], servicios)})
        [h] = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)})).hallazgos
        self.assertNotIn('etiquetas_internetdb', h.evidencia)
        self.assertNotIn('nota_vigencia', h.evidencia)

    def test_20_una_respuesta_de_host_de_mas_de_8_mb_no_se_reintenta(self):
        """tiempos-5: el ValueError del tope de bytes de transporte.descargar daría lo mismo otra vez. Es
        RespuestaIlegible: un solo intento, un aviso sin la llave y la IP sin revisar en sus etiquetas."""
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA)})
        pedidas = []

        def descargar(url, timeout, cronometro=None, tope=shodan.MAX_BYTES):
            if url.startswith(shodan.URL_HOST):
                pedidas.append((url, tope))
                raise ValueError('respuesta de más de %d bytes en %s' % (tope, url))
            return http(url, timeout)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(shodan, '_descargar', descargar):
            cliente = shodan.ClienteShodan(modo='vivo', carpeta=Path(d),
                                           resolver=ResolvedorSimulado({DOMINIO: a(CAMARA)}),
                                           cronometro=Cronometro(0), dormir=lambda s: None, llave=LLAVE)
            res = shodan.recolectar(DOMINIO, cliente, ahora=AHORA)
        self.assertEqual(pedidas, [(url_host(CAMARA), shodan.MAX_BYTES_HOST)])
        self.assertEqual(res.estado, 'succeeded')
        self.assertTrue(any('la API de host (%s) dio una respuesta que no se puede leer' % CAMARA in x
                            for x in res.avisos), res.avisos)
        self.assertNotIn(LLAVE, todo(res))
        self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))
        self.assertEqual(cliente.fallas, 1)

    def test_21_cada_aviso_de_una_respuesta_ilegible_de_host_nombra_su_ip(self):
        """Con 2 IP que dan el ValueError de transporte.descargar salen 2 avisos distintos, cada uno con su IP, sin la
        llave ni el texto del ValueError."""
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA), RESERVAS: internetdb(RESERVAS)})

        def descargar(url, timeout, cronometro=None, tope=shodan.MAX_BYTES):
            if url.startswith(shodan.URL_HOST):
                raise ValueError('respuesta de más de %d bytes en %s' % (tope, url))
            return http(url, timeout)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(shodan, '_descargar', descargar):
            cliente = shodan.ClienteShodan(modo='vivo', carpeta=Path(d),
                                           resolver=ResolvedorSimulado({DOMINIO: a(CAMARA, RESERVAS)}),
                                           cronometro=Cronometro(0), dormir=lambda s: None, llave=LLAVE)
            res = shodan.recolectar(DOMINIO, cliente, ahora=AHORA)
        avisos = [x for x in res.avisos if 'dio una respuesta que no se puede leer' in x]
        self.assertEqual(len(set(avisos)), 2, res.avisos)
        for ip in (CAMARA, RESERVAS):
            self.assertEqual(len([x for x in avisos if 'la API de host (%s)' % ip in x]), 1, avisos)
        self.assertNotIn(LLAVE, todo(res))
        self.assertFalse(any('respuesta de más de' in x for x in res.avisos), res.avisos)


    def test_22_el_tag_cdn_de_la_api_de_host_descarta_la_ip(self):
        """llave-1: la API de host marca la IP como CDN y InternetDB no. Como el tag cdn de InternetDB, de esa IP solo
        queda que existe: ni puertos, ni CVE, ni etiquetas, ni productos (docs/politica_uso_etico.md, sección 2, punto
        5). Vale igual si InternetDB dio 404, y la grabación guarda solo la marca."""
        self.assertEqual(shodan.limpiar_host({'cdn': True}, DOMINIO), {'cdn': True})
        servicios = [banner(443, producto='nginx', version='1.0', tags=['eol-product'])]
        for respuesta, internetdb_esperado in ((internetdb(CAMARA, ports=[8080], vulns=['CVE-2024-6387']),
                                                'descartada_cdn'), (404, 'sin_datos')):
            with self.subTest(internetdb=internetdb_esperado), tempfile.TemporaryDirectory() as d:
                http = HttpSimulado(ips={CAMARA: respuesta},
                                    hosts={CAMARA: respuesta_host(CAMARA, ['cdn', 'eol-product'], servicios)})
                res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}), modo='grabar',
                                carpeta=Path(d) / DOMINIO, nueva=True)
                self.assertEqual(res.hallazgos, [])
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
                atributos = activo(res, CAMARA).atributos
                self.assertEqual((atributos['cdn'], atributos['shodan_host'], atributos['internetdb']),
                                 ('shodan_host', 'descartada_cdn', internetdb_esperado))
                self.assertFalse([x for x in res.activos if x.tipo == 'service'])
                self.assertIn('shodan: la API de host marca %s como CDN, se descartaron sus datos' % CAMARA, res.avisos)
                self.assertNotIn('nginx', todo(res))
                self.assertEqual((res.sin_cobertura, res.revisados), ([], None))
                self.assertEqual(shodan.codigo_salida(res), 0)
                grabada = json.loads((Path(d) / DOMINIO / ('host_%s.json' % CAMARA)).read_bytes())['datos']
                self.assertEqual(grabada, {'cdn': True})

    def test_23_los_nombres_ajenos_de_la_api_de_host_marcan_un_posible_dato_de_otro_dueno(self):
        """llave-2: InternetDB no trae nombres (o dio 404) y la API de host trae hostnames y domains de otra empresa.
        El hallazgo lleva posible_dato_de_otro_dueno y sale un aviso, sin guardar los nombres. Con solo nombres del
        dominio no sale la marca."""
        for respuesta in (internetdb(CAMARA), 404):
            with self.subTest(internetdb=respuesta if respuesta == 404 else 200):
                ajena = dict(respuesta_host(CAMARA, ['ics']), hostnames=['scada.otraempresa.test', 'camaras.olmardo.com'],
                             domains=['otraempresa.test', 'olmardo.com'])
                http = HttpSimulado(ips={CAMARA: respuesta}, hosts={CAMARA: ajena})
                res = con_llave(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                [h] = res.hallazgos
                self.assertEqual((h.codigo, h.evidencia.get('posible_dato_de_otro_dueno')), ('exposed_ot_device', True))
                self.assertIn('shodan: la API de host trae en %s 2 nombres de otro dominio: sus datos pueden ser de quien '
                              'tuvo la IP antes' % CAMARA, res.avisos)
                self.assertNotIn('otraempresa', todo(res))
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        propia = dict(respuesta_host(CAMARA, ['ics']), hostnames=['camaras.olmardo.com'], domains=['olmardo.com'])
        res = con_llave(HttpSimulado(ips={CAMARA: internetdb(CAMARA)}, hosts={CAMARA: propia}),
                        ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        [h] = res.hallazgos
        self.assertNotIn('posible_dato_de_otro_dueno', h.evidencia)
        self.assertFalse(any('de otro dominio' in x for x in res.avisos), res.avisos)

class Contenedores(unittest.TestCase):
    """RC-224: los puertos de Docker, etcd, Kubernetes y kubelet que ve InternetDB dan exposed_container_api (alta). Solo
    sale de la misma consulta pasiva a InternetDB: nunca se conecta al servicio, así que no sabe si pide autenticación."""

    PUERTOS = {2375: 'Docker', 2376: 'Docker', 2379: 'etcd', 2380: 'etcd', 6443: 'Kubernetes', 10250: 'kubelet',
               10255: 'kubelet'}
    MIGRACION = Path(__file__).resolve().parents[1] / 'db' / 'migraciones' / '019_texto_contenedores_internetdb.sql'
    PERMITE = re.compile(r'\bpermite\b', re.IGNORECASE)

    def test_1_la_familia_tiene_los_7_puertos_alta_en_infrastructure(self):
        self.assertEqual(shodan.PUERTOS['exposed_container_api'], (2375, 2376, 2379, 2380, 6443, 10250, 10255))
        self.assertEqual(shodan.SERVICIO_CONTENEDORES, self.PUERTOS)
        self.assertEqual(shodan.CODIGOS['exposed_container_api'], 'high')
        self.assertIn('exposed_container_api', shodan.CODIGOS_PUERTOS)
        self.assertEqual((POR_CODIGO['exposed_container_api'][4], POR_CODIGO['exposed_container_api'][5]),
                         ('infrastructure', 'high'))
        otras = [p for c, lista in shodan.PUERTOS.items() if c != 'exposed_container_api' for p in lista]
        otras += list(shodan.PUERTOS_WEB + shodan.PUERTOS_CORREO + shodan.PUERTOS_INDUSTRIALES + shodan.PUERTOS_UDP)
        self.assertEqual(set(self.PUERTOS) & set(otras), set())

    def test_2_cada_puerto_da_su_hallazgo_con_el_servicio_probable_y_la_nota(self):
        for puerto, servicio in self.PUERTOS.items():
            with self.subTest(puerto=puerto):
                http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[puerto])})
                res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
                [h] = res.hallazgos
                e = h.evidencia
                self.assertEqual((h.codigo, h.severidad, h.activo), ('exposed_container_api', 'high',
                                                                     '%s:%d/tcp' % (CAMARA, puerto)))
                self.assertEqual((e['ip'], e['puerto'], e['servicio_probable'], e['servicio_supuesto'],
                                  e['autenticacion']), (CAMARA, puerto, servicio, True, 'desconocida'))
                self.assertEqual(e['nota_autenticacion'], shodan.NOTA_CONTENEDORES)
                self.assertEqual((e['vigencia'], e['nota_vigencia']), ('sin_fecha', shodan.NOTA_SIN_FECHA))
                self.assertEqual(h.titulo, 'Shodan vio abierto el puerto %d, que suele ser de %s, en %s'
                                 % (puerto, servicio, DOMINIO))
                self.assertEqual(h.titulo, e['title'])
                self.assertEqual(http.consultadas(), {CAMARA})   # solo InternetDB, nunca el servicio

    def test_3_la_nota_dice_que_no_se_sabe_si_pide_autenticacion_ni_cuando_lo_vio(self):
        nota = shodan.NOTA_CONTENEDORES
        self.assertIn('no dice si el servicio pide autenticación', nota)
        self.assertIn('ni cuándo lo vio', nota)
        self.assertIn('puede permitir', nota)
        self.assertIsNone(self.PERMITE.search(nota))

    def test_4_el_texto_de_la_regla_dice_puede_permitir_y_nunca_permite(self):
        sql = self.MIGRACION.read_text(encoding='utf-8')
        [fila] = [f for f in FILA_TEXTO.findall(sql) if f[0] == 'exposed_container_api']
        texto = ' '.join(fila[1:])
        self.assertIn('puede permitir', texto)
        self.assertIsNone(self.PERMITE.search(texto))
        titulos = [shodan.TITULOS['exposed_container_api'] % (p, s, DOMINIO) for p, s in self.PUERTOS.items()]
        self.assertEqual([t for t in titulos if self.PERMITE.search(t)], [])

    def test_5_una_ip_honeypot_con_2375_no_da_hallazgos(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[2375], tags=['honeypot'])})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual((res.hallazgos, [x.tipo for x in res.activos]), ([], ['ip']))
        self.assertIn('shodan: InternetDB marca %s como honeypot, no se sacan hallazgos de esa IP' % CAMARA, res.avisos)
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_6_una_ip_sin_ninguno_de_esos_puertos_no_da_el_codigo(self):
        for puertos in ([], [22, 80, 443, 8080, 2377, 6444, 10251]):
            with self.subTest(puertos=puertos):
                http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=puertos)})
                res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                self.assertNotIn('exposed_container_api', {h.codigo for h in res.hallazgos})
                self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))   # revisado completo: no va a sin_cobertura
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_7_cae_en_el_tipo_por_omision_de_caracteristicas(self):
        """Sin entrada en TIPO el tipo es el código, la exposición es directa por el activo service y la sensibilidad
        media, como cualquier código nuevo (cirdan/ml/caracteristicas.py)."""
        from cirdan.ml import caracteristicas
        self.assertNotIn('exposed_container_api', caracteristicas.TIPO)
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[6443])})
        [h] = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)})).hallazgos
        self.assertEqual(caracteristicas.calcular(h.codigo, 'service', h.evidencia, AHORA),
                         {'tipo': 'exposed_container_api', 'antiguedad_dias': 0, 'exposicion': 'directa',
                          'sensibilidad': 'media'})


class ServiciosIA(unittest.TestCase):
    """RC-262: los puertos por omisión de Ollama, LM Studio, Gradio, ComfyUI, Ray Dashboard, Qdrant y Milvus que ve
    InternetDB dan exposed_ai_service (alta). Solo sale de la misma consulta pasiva a InternetDB: nunca se conecta al
    servicio, así que no sabe si pide autenticación ni qué responde. Respuestas de InternetDB armadas a mano."""

    PUERTOS = {11434: 'Ollama', 1234: 'LM Studio', 7860: 'Gradio', 8188: 'ComfyUI', 8265: 'Ray Dashboard',
               6333: 'Qdrant', 6334: 'Qdrant', 19530: 'Milvus'}
    # Los usan muchos servicios: 3000 a 8888 siguen en exposed_service, y el 80 y el 443 son de la web sin hallazgo
    GENERICOS = (80, 443, 3000, 5000, 8000, 8080, 8888)
    DOCUMENTACION = {11434: 'docs.ollama.com', 1234: 'lmstudio.ai', 7860: 'www.gradio.app', 8188: 'docs.comfy.org',
                     8265: 'docs.ray.io', 6333: 'qdrant.tech', 6334: 'qdrant.tech', 19530: 'milvus.io'}
    MIGRACION = Path(__file__).resolve().parents[1] / 'db' / 'migraciones' / '023_texto_ia_internetdb.sql'
    PERMITE = re.compile(r'\bpermite\b', re.IGNORECASE)

    def test_1_la_familia_tiene_los_8_puertos_alta_en_infrastructure_sin_cruzarse(self):
        self.assertEqual(shodan.PUERTOS['exposed_ai_service'], (11434, 1234, 7860, 8188, 8265, 6333, 6334, 19530))
        self.assertEqual(shodan.SERVICIO_IA, self.PUERTOS)
        self.assertEqual(shodan.CODIGOS['exposed_ai_service'], 'high')
        self.assertIn('exposed_ai_service', shodan.CODIGOS_PUERTOS)
        self.assertEqual((POR_CODIGO['exposed_ai_service'][4], POR_CODIGO['exposed_ai_service'][5]),
                         ('infrastructure', 'high'))
        otras = [p for c, lista in shodan.PUERTOS.items() if c != 'exposed_ai_service' for p in lista]
        otras += list(shodan.PUERTOS_WEB + shodan.PUERTOS_CORREO + shodan.PUERTOS_INDUSTRIALES + shodan.PUERTOS_UDP)
        self.assertEqual(set(self.PUERTOS) & set(otras), set())
        self.assertEqual(set(self.PUERTOS) & set(self.GENERICOS), set())
        for codigo, lista in shodan.PUERTOS.items():
            with self.subTest(codigo=codigo):
                self.assertEqual(set(lista) & set(self.GENERICOS), set())

    def test_2_cada_puerto_lleva_el_enlace_a_la_documentacion_oficial_en_su_comentario(self):
        fuente = Path(shodan.__file__).read_text(encoding='utf-8')
        [bloque] = re.findall(r"'exposed_ai_service': \(\n(.*?)\n    \),", fuente, re.DOTALL)
        trozos = re.split(r'^\s+(\d+),\s+#', bloque, flags=re.MULTILINE)[1:]
        enlaces = dict(zip((int(p) for p in trozos[0::2]), trozos[1::2]))
        self.assertEqual(list(enlaces), list(shodan.PUERTOS['exposed_ai_service']))
        for puerto, comentario in enlaces.items():
            with self.subTest(puerto=puerto):
                self.assertIn(self.PUERTOS[puerto], comentario)
                self.assertIn(str(puerto), comentario)
                self.assertIn('https://%s/' % self.DOCUMENTACION[puerto], comentario)

    def test_3_cada_puerto_da_su_hallazgo_con_el_producto_probable_y_la_nota(self):
        for puerto, producto in self.PUERTOS.items():
            with self.subTest(puerto=puerto):
                http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[puerto])})
                res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
                [h] = res.hallazgos
                e = h.evidencia
                self.assertEqual((h.codigo, h.severidad, h.activo), ('exposed_ai_service', 'high',
                                                                     '%s:%d/tcp' % (CAMARA, puerto)))
                self.assertEqual((e['ip'], e['puerto'], e['servicio_probable'], e['servicio_supuesto'],
                                  e['autenticacion']), (CAMARA, puerto, producto, True, 'desconocida'))
                self.assertEqual(e['nota_autenticacion'], shodan.NOTA_IA)
                self.assertEqual((e['vigencia'], e['nota_vigencia']), ('sin_fecha', shodan.NOTA_SIN_FECHA))
                self.assertEqual(e['fuente_datos'], 'Shodan InternetDB')
                self.assertEqual(h.titulo, 'Shodan vio abierto el puerto %d, que suele ser de %s, en %s'
                                 % (puerto, producto, DOMINIO))
                self.assertEqual(h.titulo, e['title'])
                self.assertEqual(http.consultadas(), {CAMARA})   # solo InternetDB, nunca el servicio

    def test_4_una_ip_con_11434_y_otros_puertos_da_cada_uno_en_su_familia(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[22, 443, 8080, 11434, 6333, 2375, 5432])})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        por_puerto = {h.evidencia['puerto']: h.codigo for h in res.hallazgos}
        self.assertEqual(por_puerto, {22: 'exposed_remote_admin', 8080: 'exposed_service', 11434: 'exposed_ai_service',
                                      6333: 'exposed_ai_service', 2375: 'exposed_container_api',
                                      5432: 'exposed_database'})
        ia = {h.evidencia['puerto']: h.evidencia['servicio_probable'] for h in res.hallazgos
              if h.codigo == 'exposed_ai_service'}
        self.assertEqual(ia, {11434: 'Ollama', 6333: 'Qdrant'})
        [docker] = [h for h in res.hallazgos if h.codigo == 'exposed_container_api']
        self.assertEqual(docker.evidencia['nota_autenticacion'], shodan.NOTA_CONTENEDORES)
        self.assertNotIn('servicio_probable', [k for h in res.hallazgos if h.codigo == 'exposed_service'
                                               for k in h.evidencia])
        self.assertEqual(http.consultadas(), {CAMARA})

    def test_5_una_ip_sin_ninguno_de_esos_puertos_no_da_el_codigo(self):
        for puertos in ([], list(self.GENERICOS), [22, 1235, 7861, 8187, 11435, 19531, 6335]):
            with self.subTest(puertos=puertos):
                http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=puertos)})
                res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
                self.assertNotIn('exposed_ai_service', {h.codigo for h in res.hallazgos})
                self.assertEqual(res.sin_cobertura, list(shodan.SIN_LLAVE))   # revisado completo: no va a sin_cobertura
                self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=list(self.GENERICOS))})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual(set(self.GENERICOS) & set(shodan.PUERTOS_WEB), {80, 443})
        self.assertEqual({h.evidencia['puerto']: h.codigo for h in res.hallazgos},
                         {p: 'exposed_service' for p in (3000, 5000, 8000, 8080, 8888)})

    def test_6_la_nota_y_el_texto_dicen_puede_permitir_y_nunca_permite(self):
        nota = shodan.NOTA_IA
        self.assertIn('no dice si el servicio pide autenticación, qué responde', nota)
        self.assertIn('ni cuándo lo vio', nota)
        self.assertIn('puede permitir', nota)
        self.assertIsNone(self.PERMITE.search(nota))
        sql = self.MIGRACION.read_text(encoding='utf-8')
        [fila] = [f for f in FILA_TEXTO.findall(sql) if f[0] == 'exposed_ai_service']
        texto = ' '.join(fila[1:])
        self.assertIn('puede permitir', texto)
        self.assertIsNone(self.PERMITE.search(texto))
        titulos = [shodan.TITULOS['exposed_ai_service'] % (p, s, DOMINIO) for p, s in self.PUERTOS.items()]
        self.assertEqual([t for t in titulos if self.PERMITE.search(t)], [])

    def test_7_una_ip_honeypot_con_11434_no_da_hallazgos(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[11434], tags=['honeypot'])})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        self.assertEqual((res.hallazgos, [x.tipo for x in res.activos]), ([], ['ip']))
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_8_reproducir_no_usa_red(self):
        """Lo grabado de una corrida con 11434 se repite igual con --reproducir y sin red."""
        with tempfile.TemporaryDirectory() as tmp:
            carpeta = Path(tmp) / DOMINIO
            http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[11434, 8265])})
            grabada = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}), modo='grabar', carpeta=carpeta,
                                 nueva=True)
            self.assertNotIn(shodan.NO_SE_GRABO, grabada.avisos)
            sin_red = HttpSimulado()
            repetida = recolectar(sin_red, ResolvedorSimulado({}), modo='reproducir', carpeta=carpeta)
        self.assertEqual(sin_red.urls, [])
        self.assertEqual((repetida.hallazgos, repetida.sin_cobertura), (grabada.hallazgos, grabada.sin_cobertura))
        self.assertEqual({(h.codigo, h.evidencia['puerto'], h.evidencia['servicio_probable']) for h in repetida.hallazgos},
                         {('exposed_ai_service', 11434, 'Ollama'), ('exposed_ai_service', 8265, 'Ray Dashboard')})

    def test_9_cae_en_el_tipo_por_omision_de_caracteristicas(self):
        """Sin entrada en TIPO el tipo es el código, la exposición es directa por el activo service y la sensibilidad
        media, como cualquier código nuevo (cirdan/ml/caracteristicas.py)."""
        from cirdan.ml import caracteristicas
        self.assertNotIn('exposed_ai_service', caracteristicas.TIPO)
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[11434])})
        [h] = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)})).hallazgos
        self.assertEqual(h.caracteristicas,
                         {'tipo': 'exposed_ai_service', 'antiguedad_dias': 0, 'exposicion': 'directa',
                          'sensibilidad': 'media'})


class Semilla(unittest.TestCase):
    """base-3: lectura estática de db/semillas/007_shodan.sql, 011_shodan_nombres.sql y 018_shodan_host.sql, sin base."""

    @staticmethod
    def limite_y_texto(semilla):
        texto = semilla.read_text(encoding='utf-8')
        sin_comentarios = '\n'.join(linea.split('--')[0] for linea in texto.splitlines())
        [limite] = re.findall(r"UPDATE\s+data_sources\s+SET\s+daily_limit\s*=\s*(\d+)\s+WHERE\s+code\s*=\s*'shodan'",
                              sin_comentarios)
        return int(limite), sin_comentarios

    def test_1_shodan_tiene_10_corridas_por_dia_y_client_encoding_antes_de_begin(self):
        limite, sin_comentarios = self.limite_y_texto(SEMILLA)
        self.assertEqual(limite, 640)   # 10 corridas de 64, con MAX_NOMBRES en 10. La 011 lo sube
        self.assertIn("SET client_encoding = 'UTF8';", sin_comentarios)
        self.assertLess(sin_comentarios.index("SET client_encoding = 'UTF8';"), sin_comentarios.index('BEGIN;'))
        self.assertIn('AND daily_limit IS NULL', sin_comentarios)

    def test_2_la_011_sube_el_limite_a_10_corridas_del_tope_nuevo_sin_pisar_uno_puesto_a_mano(self):
        """RC-55: MAX_NOMBRES pasó a 50. La 011 deja otra vez 10 corridas del peor caso y solo cambia la fila si no tiene
        límite o si tiene el 640 de la 007. shodan-3: uno puesto a mano menor que una corrida da un WARNING."""
        limite, sin_comentarios = self.limite_y_texto(SEMILLA.with_name('011_shodan_nombres.sql'))
        self.assertEqual(limite, 1840)   # 10 corridas de 184, el tope de entonces. La 018 lo sube
        self.assertLess(sin_comentarios.index("SET client_encoding = 'UTF8';"), sin_comentarios.index('BEGIN;'))
        self.assertRegex(sin_comentarios, r"AND\s+\(daily_limit\s+IS\s+NULL\s+OR\s+daily_limit\s*=\s*640\)")
        self.assertRegex(sin_comentarios, r"code\s*=\s*'shodan'\s+AND\s+daily_limit\s*<\s*184\)")
        self.assertIn("RAISE WARNING 'shodan tiene un límite diario menor que 184", sin_comentarios)

    def test_3_la_018_sube_el_limite_a_10_corridas_con_la_api_de_host(self):
        """RC-337: la API de host suma MAX_IPS consultas con sus intentos. La 018 deja otra vez 10 corridas del peor
        caso y solo cambia la fila si no tiene límite o si tiene el 1840 de la 011. Uno menor que una corrida da un
        WARNING. Es la última semilla de shodan: su límite es el que vale con el MAX_CONSULTAS de hoy."""
        limite, sin_comentarios = self.limite_y_texto(SEMILLA.with_name('018_shodan_host.sql'))
        self.assertEqual(limite, 10 * shodan.MAX_CONSULTAS)
        self.assertLess(sin_comentarios.index("SET client_encoding = 'UTF8';"), sin_comentarios.index('BEGIN;'))
        self.assertRegex(sin_comentarios, r"AND\s+\(daily_limit\s+IS\s+NULL\s+OR\s+daily_limit\s*=\s*1840\)")
        self.assertRegex(sin_comentarios, r"code\s*=\s*'shodan'\s+AND\s+daily_limit\s*<\s*%d\)" % shodan.MAX_CONSULTAS)
        self.assertIn("RAISE WARNING 'shodan tiene un límite diario menor que %d" % shodan.MAX_CONSULTAS, sin_comentarios)
        self.assertEqual(sorted(p.name for p in SEMILLA.parent.glob('*shodan*.sql')),
                         ['007_shodan.sql', '011_shodan_nombres.sql', '018_shodan_host.sql'])


class AmenazaReal(unittest.TestCase):
    """RC-127 (#69): una respuesta grabada de InternetDB con una CVE que está en CISA KEV (Log4Shell) y otra que no.
    Los datos de KEV y EPSS son los que el cargador diario deja en cves; aquí van fijos, sin red. Nunca se levanta ni
    se consulta un servicio vulnerable real (retro-10)."""

    KEV, OTRA = 'CVE-2021-44228', 'CVE-2023-1001'
    INTEL = {KEV: {'in_kev': True, 'epss': 0.94358}, OTRA: {'in_kev': False, 'epss': 0.00043}}
    REGLAS = {
        'known_vulnerability': {'id': 'r1', 'category': 'infrastructure', 'weight': 1.0, 'max_penalty': 25,
                                'recommendation': 'Actualiza el software.'},
        'secret_in_public_repo': {'id': 'r2', 'category': 'data_leaks', 'weight': 1.0, 'max_penalty': 40,
                                  'recommendation': 'Revoca la credencial.'},
    }
    PESOS = {'infrastructure': 0.30, 'digital_identity': 0.20, 'configuration': 0.20, 'data_leaks': 0.30}

    def hallazgos(self):
        http = HttpSimulado(ips={CAMARA: internetdb(CAMARA, ports=[8983], vulns=[self.OTRA, self.KEV])})
        res = recolectar(http, ResolvedorSimulado({DOMINIO: a(CAMARA)}))
        vulns = [h for h in res.hallazgos if h.codigo == 'known_vulnerability']
        self.assertEqual(sorted(h.clave for h in vulns), [self.KEV, self.OTRA])
        filas = [{'id': h.clave, 'rule_code': h.codigo, 'severity': h.severidad, 'status': 'open', 'asset_id': h.activo,
                  'asset_type': 'ip', 'asset_value': h.activo, 'cve_id': h.clave, **self.INTEL[h.clave]} for h in vulns]
        # Un secreto crítico baja más el score solo: sin KEV encabezaría el plan
        filas.append({'id': 's1', 'rule_code': 'secret_in_public_repo', 'severity': 'critical', 'status': 'open',
                      'asset_id': 'repo', 'asset_type': 'repository', 'asset_value': 'olmardo/sitio'})
        return filas

    def test_1_la_accion_con_kev_encabeza_el_plan_y_lleva_el_aviso(self):
        filas = self.hallazgos()
        for agrupar in plan_accion.AGRUPACIONES:
            with self.subTest(agrupar=agrupar):
                resultado = plan_accion.construir_plan(DOMINIO, filas, self.REGLAS, self.PESOS, agrupar=agrupar)
                primera = resultado['actions'][0]
                self.assertTrue(primera['in_kev'])
                self.assertIn(self.KEV, primera['cve_ids'])
                self.assertEqual(primera['threat_note'], plan_accion.AVISO_KEV)
                self.assertEqual(primera['epss_max'], 0.94358)
                self.assertTrue(all(not accion['in_kev'] and accion['threat_note'] is None
                                    for accion in resultado['actions'][1:]))
                # La acumulada sigue el orden nuevo: la última deja el mismo score de resolver todo que sin KEV
                sin_kev = plan_accion.construir_plan(DOMINIO, [dict(f, in_kev=False) for f in filas], self.REGLAS,
                                                     self.PESOS, agrupar=agrupar)
                self.assertEqual(resultado['actions'][-1]['score_after_acumulado'],
                                 sin_kev['actions'][-1]['score_after_acumulado'])

    def test_2_sin_kev_el_orden_es_el_de_siempre(self):
        filas = [dict(f, in_kev=False) for f in self.hallazgos()]
        resultado = plan_accion.construir_plan(DOMINIO, filas, self.REGLAS, self.PESOS)
        self.assertEqual(resultado['actions'][0]['id'], 'secret_in_public_repo')
        self.assertFalse(any(accion['in_kev'] for accion in resultado['actions']))


if __name__ == '__main__':
    unittest.main()
