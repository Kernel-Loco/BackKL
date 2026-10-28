"""Pruebas del recolector de RDAP (#15b, RC-166), sin red: el bootstrap de IANA y el registro con un transporte HTTP
simulado.

    python -m unittest -v pruebas/test_rdap.py

Las respuestas tienen la forma de RDAP (RFC 9083) y del bootstrap (RFC 9224), pero son simuladas. Las fechas de
olmardo.com son las de la semilla 002 y de docs/hallazgos_esperados.md, fila 7. El registrador, los contactos y los
servidores de .mx y de los TLD zz y yy son inventados: no dicen qué TLD tiene RDAP de verdad.
"""
import io
import json
import os
import re
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_rdap.py
from pruebas.test_catalogo_reglas import POR_CODIGO  # noqa: E402
from pruebas.test_crtsh import AHORA  # noqa: E402
from pruebas.test_shodan import error_http  # noqa: E402
from pruebas.test_subfinder import Cronometro  # noqa: E402
from cirdan.recolectores import REGISTRO, cargar, contrato, rdap  # noqa: E402
from cirdan.recolectores.contrato import FuenteNoResponde  # noqa: E402

SEMILLA = Path(__file__).resolve().parents[1] / 'db' / 'semillas' / '008_whois.sql'
DOMINIO = 'olmardo.com'
VERISIGN = 'https://rdap.verisign.com/com/v1/'
REGISTRADO, VENCE, CAMBIO = '2026-10-14T00:38:02Z', '2027-10-14T00:38:02Z', '2026-10-14T00:40:11Z'
NO = rdap.NO_DISPONIBLE
BOOTSTRAP = {
    'version': '1.0', 'publication': '2026-10-20T19:00:01Z', 'description': 'RDAP bootstrap file for DNS',
    'services': [
        [['com', 'net'], [VERISIGN]],
        [['mx'], ['https://rdap.mx.example/']],
        [['zz'], ['http://solo-http.example/']],                                      # sin https
        [['yy'], ['http://rdap.yy.example/', 'https://rdap.yy.example/v1']],          # https en segundo lugar y sin '/'
        'roto', [['ww']], [[1, 'vv'], ['https://rdap.vv.example/']],                  # entradas que no se leen
    ]}
# Datos personales inventados de un registrante: nada de esto puede quedar en la grabación ni en el resultado.
PERSONALES = ('Persona Registrante', 'registrante@olmardo.com', '+52.8180000000', 'Calle Falsa 123', 'abuso@registrador.example')


def vcard(*props):
    return ['vcard', [['version', {}, 'text', '4.0']] + [list(p) for p in props]]


def respuesta(dominio=DOMINIO, vence=VENCE, registrado=REGISTRADO, cambio=CAMBIO, eventos=None, **extra):
    """Una respuesta 200 de RDAP con la forma de la de Verisign. `vence`, `registrado` o `cambio` en None quitan el
    evento. `eventos` reemplaza la lista entera."""
    if eventos is None:
        eventos = [{'eventAction': a, 'eventDate': f} for a, f in
                   (('registration', registrado), ('expiration', vence), ('last changed', cambio)) if f]
        eventos.append({'eventAction': 'last update of RDAP database', 'eventDate': '2026-10-15T11:58:00Z'})
    datos = {
        'objectClassName': 'domain', 'handle': '3012345678_DOMAIN_COM-VRSN', 'ldhName': dominio.upper(),
        'links': [{'value': VERISIGN + 'domain/' + dominio, 'rel': 'self', 'href': VERISIGN + 'domain/' + dominio}],
        'status': ['client transfer prohibited', 'client delete prohibited'],
        'entities': [{
            'objectClassName': 'entity', 'handle': '9999', 'roles': ['registrar'],
            'publicIds': [{'type': 'IANA Registrar ID', 'identifier': '9999'}],
            'vcardArray': vcard(['fn', {}, 'text', 'Registrador de Prueba, Inc.']),
            'entities': [{'objectClassName': 'entity', 'roles': ['abuse'],
                          'vcardArray': vcard(['fn', {}, 'text', ''], ['email', {}, 'text', 'abuso@registrador.example'],
                                              ['tel', {'type': 'voice'}, 'uri', 'tel:+52.8180000000'])}]}],
        'events': eventos,
        'secureDNS': {'delegationSigned': False},
        'nameservers': [{'objectClassName': 'nameserver', 'ldhName': 'ADA.NS.CLOUDFLARE.COM'},
                        {'objectClassName': 'nameserver', 'ldhName': 'BOB.NS.CLOUDFLARE.COM'}],
        'rdapConformance': ['rdap_level_0', 'icann_rdap_technical_implementation_guide_1'],
        'notices': [{'title': 'Terms of Use', 'description': ['Service subject to Terms of Use.']}],
    }
    datos.update(extra)
    return datos


def registrante():
    """Una entidad de registrante con datos personales, como la que puede traer un registro sin redacción."""
    return {'objectClassName': 'entity', 'roles': ['registrant'],
            'vcardArray': vcard(['fn', {}, 'text', 'Persona Registrante'],
                                ['email', {}, 'text', 'registrante@olmardo.com'],
                                ['tel', {}, 'uri', 'tel:+52.8180000000'],
                                ['adr', {}, 'text', ['', '', 'Calle Falsa 123', 'Monterrey', 'NL', '64000', 'MX']])}


class HttpSimulado:
    """Hace las veces de rdap._descargar(url, timeout). El bootstrap responde `bootstrap` y cada dominio lo que diga
    `dominios` (el último tramo de la URL): un dict es el JSON, bytes van tal cual, un entero es un error HTTP, una
    excepción se lanza y una lista da una respuesta por intento (la última se repite). Un dominio que no está da 404."""

    def __init__(self, bootstrap=None, dominios=None):
        self.bootstrap = BOOTSTRAP if bootstrap is None else bootstrap
        self.dominios = {DOMINIO: respuesta()} if dominios is None else dominios
        self.urls = []

    def __call__(self, url, timeout):
        self.urls.append(url)
        if url == rdap.URL_BOOTSTRAP:
            r = self.bootstrap
        else:
            r = self.dominios.get(url.rsplit('/domain/', 1)[1], 404)
        if isinstance(r, list):
            r = r[min(self.urls.count(url), len(r)) - 1]
        if isinstance(r, Exception):
            raise r
        if isinstance(r, int):
            raise error_http(url, r, '60' if r == 429 else None)
        return r if isinstance(r, bytes) else json.dumps(r).encode()


class SinRed:
    """Un transporte que falla la prueba si alguien lo llama."""

    def __call__(self, url, timeout):
        raise AssertionError('se consultó la red: %s' % url)


def recolectar(http, modo='vivo', carpeta=None, nueva=False, cronometro=None, dominio=DOMINIO, dormir=None, ahora=AHORA):
    cliente = rdap.ClienteRdap(modo=modo, carpeta=carpeta or rdap.carpeta_de(dominio), descargar=http, nueva=nueva,
                               cronometro=cronometro or Cronometro(0), dormir=dormir or (lambda s: None))
    return rdap.recolectar(dominio, cliente, ahora=ahora)


def con_vencimiento(delta, ahora=AHORA, **extra):
    """Una respuesta de olmardo.com que vence `delta` después de `ahora`."""
    return HttpSimulado(dominios={DOMINIO: respuesta(vence=(ahora + delta).strftime('%Y-%m-%dT%H:%M:%SZ'), **extra)})


def el_dominio(res):
    [a] = [a for a in res.activos if a.tipo == 'domain']
    return a


class Rdap(unittest.TestCase):

    def test_1_cumple_el_contrato_y_ejecutar_lo_deja_succeeded(self):
        self.assertEqual(REGISTRO['whois'], 'cirdan.recolectores.rdap')
        self.assertEqual((rdap.FUENTE, rdap.CODIGOS), ('whois', {'domain_expiring_soon': 'medium'}))
        http = HttpSimulado()
        res = recolectar(http)
        self.assertEqual(contrato.validar(res, POR_CODIGO), [])
        self.assertEqual((res.estado, res.hallazgos, res.sin_cobertura, res.consultas), ('succeeded', [], [], 2))
        self.assertEqual(http.urls, [rdap.URL_BOOTSTRAP, VERISIGN + 'domain/olmardo.com'])
        self.assertEqual(el_dominio(res).atributos, {
            'fuente': 'whois', 'fuente_datos': 'RDAP', 'servidor_rdap': VERISIGN,
            'registrador': 'Registrador de Prueba, Inc.', 'registrador_iana': '9999',
            'registrado': REGISTRADO, 'vence': VENCE, 'ultimo_cambio': CAMBIO,
            'estado_registro': ['client delete prohibited', 'client transfer prohibited'],
            'servidores_nombre': ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'], 'dnssec': False})
        self.assertEqual(res.avisos, [rdap.PENDIENTE])
        self.assertEqual(rdap.codigo_salida(res), 0)
        json.dumps(res.a_dict())   # el resultado se puede guardar como JSON
        with mock.patch.object(rdap, '_descargar', HttpSimulado()), mock.patch.object(rdap.time, 'sleep', lambda s: None):
            otra = contrato.ejecutar(cargar('whois'), DOMINIO, modo='vivo', ahora=AHORA)
        self.assertEqual((otra.estado, otra.activos), ('succeeded', res.activos))

    def test_2_domain_expiring_soon_a_menos_de_30_dias(self):
        res = recolectar(con_vencimiento(timedelta(days=12, hours=3)))
        self.assertEqual(contrato.validar(res, POR_CODIGO), [])
        [h] = res.hallazgos
        self.assertEqual((h.codigo, h.severidad, h.activo, h.titulo),
                         ('domain_expiring_soon', 'medium', DOMINIO, 'El registro de olmardo.com vence en 12 días'))
        self.assertEqual(h.evidencia, {
            'title': h.titulo, 'vence': '2026-10-27T15:00:00Z', 'dias_para_vencer': 12,
            'registrador': 'Registrador de Prueba, Inc.',
            'estado_registro': ['client delete prohibited', 'client transfer prohibited'],
            'fuente_datos': 'RDAP', 'servidor_rdap': VERISIGN})
        self.assertEqual(h.caracteristicas, {'tipo': 'domain_expiring_soon', 'antiguedad_dias': 0,
                                             'exposicion': 'publica', 'sensibilidad': 'media'})
        self.assertEqual(res.sin_cobertura, [])
        casos = {timedelta(days=30): None, timedelta(days=30, seconds=-1): 'vence en 29 días',
                 timedelta(days=1, seconds=1): 'vence en 1 día', timedelta(hours=23): 'vence en menos de un día',
                 timedelta(0): 'vence en menos de un día', timedelta(days=3, hours=12): 'vence en 3 días'}
        for delta, titulo in casos.items():
            with self.subTest(delta=delta):
                res = recolectar(con_vencimiento(delta))
                self.assertEqual(contrato.validar(res, POR_CODIGO), [])
                self.assertEqual([h.titulo for h in res.hallazgos],
                                 ['El registro de olmardo.com ' + titulo] if titulo else [])
        # Los días se truncan, como en crtsh.py: 3.5 días son 3 (round daría 4)
        self.assertEqual(recolectar(con_vencimiento(timedelta(days=3, hours=12))).hallazgos[0].evidencia['dias_para_vencer'], 3)

    def test_3_la_huella_es_estable_y_cambia_con_otro_vencimiento(self):
        a = recolectar(con_vencimiento(timedelta(days=10))).hallazgos[0]
        b = recolectar(con_vencimiento(timedelta(days=10)), ahora=AHORA + timedelta(days=2)).hallazgos[0]
        c = recolectar(con_vencimiento(timedelta(days=11))).hallazgos[0]
        self.assertRegex(a.huella, r'^[0-9a-f]{64}$')
        self.assertEqual(a.huella, b.huella)       # otro escaneo, mismo vencimiento: el mismo hallazgo
        self.assertNotEqual(a.huella, c.huella)    # se renovó y vuelve a vencer: otro hallazgo

    def test_4_rdap_sin_respuesta_da_no_disponible_y_sin_cobertura(self):
        datos_no = {'registrador': NO, 'registrador_iana': NO, 'registrado': NO, 'vence': NO, 'ultimo_cambio': NO,
                    'estado_registro': NO, 'servidores_nombre': NO, 'dnssec': NO, 'fuente': 'whois'}
        casos = {
            '503 del registro': (HttpSimulado(dominios={DOMINIO: 503}), 4, [5, 15]),
            'sin red al bootstrap': (HttpSimulado(bootstrap=[urllib.error.URLError('sin red')]), 3, [5, 15]),
            '429 del registro': (HttpSimulado(dominios={DOMINIO: 429}), 2, []),
            '403 del registro': (HttpSimulado(dominios={DOMINIO: 403}), 2, []),
            '408 del registro, que sí se reintenta': (HttpSimulado(dominios={DOMINIO: 408}), 4, [5, 15]),
            'cuerpo null': (HttpSimulado(dominios={DOMINIO: b'null'}), 2, []),
            'cuerpo vacío': (HttpSimulado(dominios={DOMINIO: b'  '}), 2, []),
            'no es JSON': (HttpSimulado(dominios={DOMINIO: b'<html>'}), 4, [5, 15]),
            'otro dominio': (HttpSimulado(dominios={DOMINIO: respuesta(ldhName='OTRO.COM')}), 2, []),
            'no es un dominio': (HttpSimulado(dominios={DOMINIO: respuesta(objectClassName='entity')}), 2, []),
            'bootstrap sin services': (HttpSimulado(bootstrap={'version': '1.0'}), 1, []),
            'bootstrap 404': (HttpSimulado(bootstrap=404), 1, []),
        }
        for caso, (http, consultas, esperas) in casos.items():
            with self.subTest(caso=caso):
                dormidas = []
                res = recolectar(http, dormir=dormidas.append)
                self.assertEqual(contrato.validar(res, POR_CODIGO), [])
                self.assertEqual((res.estado, res.hallazgos, res.sin_cobertura), ('succeeded', [], ['domain_expiring_soon']))
                self.assertEqual(el_dominio(res).atributos, datos_no)
                self.assertTrue(res.avisos[0].startswith(rdap.SIN_RESPUESTA), res.avisos)
                self.assertEqual((res.consultas, dormidas), (consultas, esperas))
                self.assertEqual(rdap.codigo_salida(res), 2)
        res = recolectar(HttpSimulado(dominios={DOMINIO: 429}))
        self.assertIn('429', res.avisos[0])

    def test_5_404_y_tld_sin_rdap_https(self):
        res = recolectar(HttpSimulado(dominios={}))
        self.assertEqual((res.estado, res.sin_cobertura, res.consultas), ('succeeded', ['domain_expiring_soon'], 2))
        self.assertIn(rdap.NO_ENCONTRADO, res.avisos)
        self.assertEqual(el_dominio(res).atributos['vence'], NO)
        for dominio in ('ejemplo.zz', 'ejemplo.qq'):   # zz solo tiene http y qq no está en el bootstrap
            with self.subTest(dominio=dominio):
                http = HttpSimulado(dominios={dominio: respuesta(dominio)})
                res = recolectar(http, dominio=dominio)
                self.assertEqual(contrato.validar(res, POR_CODIGO), [])
                self.assertEqual((res.sin_cobertura, http.urls), (['domain_expiring_soon'], [rdap.URL_BOOTSTRAP]))
                self.assertIn('no tiene un servidor RDAP https', res.avisos[0])
                self.assertEqual(el_dominio(res).atributos['registrador'], NO)

    def test_6_el_bootstrap_da_el_sufijo_mas_largo_y_solo_https(self):
        con_mx = dict(BOOTSTRAP, services=BOOTSTRAP['services'] + [[['com.mx'], ['https://rdap.com-mx.example']]])
        self.assertEqual(rdap.servicio_de(con_mx, 'empresa.com.mx'), ('com.mx', 'https://rdap.com-mx.example/'))
        self.assertEqual(rdap.servicio_de(con_mx, 'empresa.mx'), ('mx', 'https://rdap.mx.example/'))
        self.assertEqual(rdap.servicio_de(BOOTSTRAP, 'olmardo.com'), ('com', VERISIGN))
        self.assertEqual(rdap.servicio_de(BOOTSTRAP, 'algo.yy'), ('yy', 'https://rdap.yy.example/v1/'))
        self.assertEqual(rdap.servicio_de(BOOTSTRAP, 'algo.zz'), (None, None))
        self.assertEqual(rdap.servicio_de(BOOTSTRAP, 'algo.vv'), ('vv', 'https://rdap.vv.example/'))
        self.assertEqual(rdap.servicio_de({'services': [[['COM.'], [VERISIGN]]]}, 'olmardo.com'), ('com', VERISIGN))
        for url in ('https://usuario@rdap.example/', 'https://rdap.example/?q=1', 'https://rdap.example/#x', 'ftp://rdap.example/',
                    'https:///sin-host', 'https://rdap.example:99999/', 'https://' + 'a' * 300 + '.example/', 7):
            self.assertIsNone(rdap._url_https(url), url)
        for roto in (None, [], {'services': 'com'}, {'services': None}):
            with self.assertRaises(rdap.RespuestaIlegible):
                rdap.servicio_de(roto, 'olmardo.com')
        reducido = rdap.reducir_bootstrap(BOOTSTRAP, 'olmardo.com')
        self.assertEqual(reducido, {'publication': '2026-10-20T19:00:01Z', 'services': [[['com'], [VERISIGN]]]})
        self.assertEqual(rdap.servicio_de(reducido, 'olmardo.com'), ('com', VERISIGN))
        self.assertEqual(rdap.reducir_bootstrap(BOOTSTRAP, 'algo.zz')['services'], [])

    def test_7_no_guarda_contactos_ni_datos_personales(self):
        datos = respuesta()
        datos['entities'].append(registrante())
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            res = recolectar(HttpSimulado(dominios={DOMINIO: datos}), modo='grabar', carpeta=carpeta, nueva=True)
            grabado = ''.join(p.read_text(encoding='utf-8') for p in carpeta.glob('*.json'))
        resultado = json.dumps(res.a_dict(), ensure_ascii=False)
        for dato in PERSONALES:
            self.assertNotIn(dato, grabado)
            self.assertNotIn(dato, resultado)
        reducido = rdap.reducir_rdap(datos)
        self.assertEqual(reducido['entities'], [{
            'objectClassName': 'entity', 'roles': ['registrar'],
            'vcardArray': vcard(['fn', {}, 'text', 'Registrador de Prueba, Inc.']),
            'publicIds': [{'type': 'IANA Registrar ID', 'identifier': '9999'}]}])
        self.assertNotIn('notices', reducido)
        self.assertEqual(rdap.leer_rdap(reducido, DOMINIO), rdap.leer_rdap(datos, DOMINIO))   # reducir no cambia lo leído
        # Sin registrador, o con uno sin nombre ni IANA ID, sale No disponible
        sin = respuesta(entities=[registrante()])
        atributos, _ = rdap.leer_rdap(sin, DOMINIO)
        self.assertEqual((atributos['registrador'], atributos['registrador_iana']), (NO, NO))
        self.assertNotIn('entities', rdap.reducir_rdap(sin))

    def test_8_fechas_rotas_ausentes_o_repetidas(self):
        res = recolectar(HttpSimulado(dominios={DOMINIO: respuesta(vence=None)}))
        self.assertEqual((res.sin_cobertura, el_dominio(res).atributos['vence']), (['domain_expiring_soon'], NO))
        self.assertIn(rdap.SIN_VENCIMIENTO, res.avisos)
        self.assertEqual(el_dominio(res).atributos['registrado'], REGISTRADO)
        res = recolectar(HttpSimulado(dominios={DOMINIO: respuesta(vence='mañana')}))
        self.assertEqual(res.sin_cobertura, ['domain_expiring_soon'])
        self.assertIn(rdap.VENCIMIENTO_ROTO, res.avisos)
        self.assertIn('whois: RDAP dio fechas que no se pueden leer (vence) y se ignoraron', res.avisos)
        eventos = [{'eventAction': 'expiration', 'eventDate': '2026-10-20T00:00:00Z'},
                   {'eventAction': 'expiration', 'eventDate': '2027-10-13T18:38:02-06:00'},   # la más reciente, en UTC
                   {'eventAction': 'expiration', 'eventDate': 12},
                   {'eventAction': 'registration', 'eventDate': '2026-10-14T00:38:02.123456Z'},
                   {'eventAction': 'registration', 'eventDate': '2026-10-15'},
                   {'eventAction': 'last changed', 'eventDate': '2026-10-14T00:40:11'},       # sin zona: UTC
                   'roto', {'eventAction': 'transfer', 'eventDate': '2026-10-16T00:00:00Z'}]
        res = recolectar(HttpSimulado(dominios={DOMINIO: respuesta(eventos=eventos)}))
        t = el_dominio(res).atributos
        self.assertEqual((t['vence'], t['registrado'], t['ultimo_cambio']), (VENCE, '2026-10-14T00:38:02Z', CAMBIO))
        self.assertEqual((res.hallazgos, res.sin_cobertura), ([], []))
        self.assertEqual(res.avisos, [rdap.PENDIENTE])   # una fecha rota con otra buena del mismo evento no avisa
        datos = respuesta(status=['active', 'ACTIVE', 'con_guion_bajo', 7, 'x' * 80], nameservers=[{'ldhName': 'NS1.'},
                          {'ldhName': 'ns1.olmardo.com.'}, 'roto'], secureDNS={'delegationSigned': 'si'})
        t, _ = rdap.leer_rdap(datos, DOMINIO)
        self.assertEqual((t['estado_registro'], t['servidores_nombre'], t['dnssec']), (['active'], ['ns1.olmardo.com'], NO))

    def test_9_graba_al_final_y_reproduce_sin_red(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            carpeta.mkdir()
            (carpeta / 'viejo.json').write_text('[]', encoding='utf-8')
            res = recolectar(con_vencimiento(timedelta(days=5)), modo='grabar', carpeta=carpeta, nueva=True)
            self.assertEqual(sorted(p.name for p in carpeta.glob('*.json')), ['bootstrap.json', 'rdap_olmardo.com.json'])
            self.assertIsNotNone(contrato.Grabadora.inicio(carpeta))
            bootstrap = json.loads((carpeta / 'bootstrap.json').read_text(encoding='utf-8'))['datos']
            self.assertEqual(bootstrap['services'], [[['com'], [VERISIGN]]])
            otra = recolectar(SinRed(), modo='reproducir', carpeta=carpeta)
        self.assertEqual(len(res.hallazgos), 1)
        self.assertEqual((otra.estado, otra.activos, otra.hallazgos, otra.sin_cobertura, otra.avisos, otra.consultas),
                         (res.estado, res.activos, res.hallazgos, res.sin_cobertura, res.avisos, 0))

    def test_10_el_404_y_el_tld_sin_rdap_tambien_se_graban(self):
        for dominio, dominios in ((DOMINIO, {}), ('ejemplo.zz', {})):
            with self.subTest(dominio=dominio), tempfile.TemporaryDirectory() as d:
                carpeta = Path(d) / dominio
                res = recolectar(HttpSimulado(dominios=dominios), modo='grabar', carpeta=carpeta, nueva=True, dominio=dominio)
                self.assertNotIn(rdap.NO_SE_GRABO, res.avisos)
                otra = recolectar(SinRed(), modo='reproducir', carpeta=carpeta, dominio=dominio)
                self.assertEqual((otra.activos, otra.sin_cobertura, otra.avisos), (res.activos, res.sin_cobertura, res.avisos))

    def test_11_una_corrida_con_fallas_no_pisa_la_grabacion(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            recolectar(HttpSimulado(), modo='grabar', carpeta=carpeta, nueva=True)
            antes = {p.name: p.read_bytes() for p in carpeta.iterdir()}
            for http in (HttpSimulado(dominios={DOMINIO: 503}), HttpSimulado(dominios={DOMINIO: 429}),
                         HttpSimulado(bootstrap=urllib.error.URLError('sin red'))):
                res = recolectar(http, modo='grabar', carpeta=carpeta, nueva=True)
                self.assertEqual(res.avisos[0], rdap.NO_SE_GRABO)
                self.assertEqual(rdap.codigo_salida(res), 3)
                self.assertEqual({p.name: p.read_bytes() for p in carpeta.iterdir()}, antes)

    def test_12_reproducir_sin_grabacion_o_con_una_rota(self):
        with tempfile.TemporaryDirectory() as d:
            res = recolectar(SinRed(), modo='reproducir', carpeta=Path(d) / DOMINIO)
            self.assertEqual((res.estado, res.consultas, res.sin_cobertura), ('succeeded', 0, ['domain_expiring_soon']))
            self.assertEqual(res.avisos, [rdap.SIN_GRABACION_DOMINIO, rdap.PENDIENTE])
            self.assertEqual(el_dominio(res).atributos['vence'], NO)
            self.assertEqual(rdap.codigo_salida(res), 2)
            # Una grabación rota (editada a mano o de otra versión) es failed, no 'No disponible': no es una falla de RDAP
            bueno = rdap.reducir_bootstrap(BOOTSTRAP, DOMINIO)
            rotas = {'bootstrap sin services': ({'version': '1.0'}, respuesta()),
                     'registro que no es objeto': (bueno, ['no es un objeto']),
                     'registro de otro dominio': (bueno, respuesta(ldhName='OTRO.COM')),
                     'registro que no es dominio': (bueno, {'objectClassName': 'entity', 'ldhName': DOMINIO})}
            for caso, (bootstrap, registro) in rotas.items():
                with self.subTest(caso=caso):
                    raiz = Path(d) / caso.replace(' ', '_')
                    grabadora = contrato.Grabadora(raiz / DOMINIO, 'grabar')
                    grabadora.guardar('bootstrap', bootstrap)
                    grabadora.guardar('rdap:' + DOMINIO, registro)
                    with self.assertRaises(FuenteNoResponde):
                        recolectar(SinRed(), modo='reproducir', carpeta=raiz / DOMINIO)
                    with mock.patch.object(rdap, 'CARPETA_GRABADAS', raiz):
                        fallida = contrato.ejecutar(cargar('whois'), DOMINIO, modo='reproducir', ahora=AHORA)
                    self.assertEqual((fallida.estado, fallida.activos), ('failed', []))

    def test_13_la_redireccion_fuera_de_https_se_corta(self):
        req = urllib.request.Request(VERISIGN + 'domain/olmardo.com')
        manejador = rdap._SoloHttps()
        with self.assertRaises(rdap.RespuestaIlegible):
            manejador.redirect_request(req, io.BytesIO(), 302, 'Found', {}, 'http://rdap.verisign.com/x')
        nueva = manejador.redirect_request(req, io.BytesIO(), 302, 'Found', {}, 'https://rdap.verisign.com/com/v2/x')
        self.assertEqual(nueva.full_url, 'https://rdap.verisign.com/com/v2/x')
        self.assertIn(rdap._SoloHttps, [type(h) for h in rdap._ABRIR.__self__.handlers])

    def test_14_descargar_tiene_plazo_absoluto_tope_y_cabeceras(self):
        class Respuesta:
            def __init__(self, partes):
                self.partes = list(partes)

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read1(self, n):
                return self.partes.pop(0)[:n] if self.partes else b''

        pedidas = []

        def abrir(partes):
            def f(req, timeout):
                pedidas.append((req, timeout))
                return Respuesta(partes)
            return f
        with mock.patch.object(rdap, '_ABRIR', abrir([b'{"a":', b'1}'])):
            self.assertEqual(rdap._descargar(rdap.URL_BOOTSTRAP, 15, Cronometro(1)), b'{"a":1}')
        req, timeout = pedidas[0]
        self.assertEqual((req.get_header('User-agent'), timeout), (rdap.AGENTE, 15))
        self.assertIn('application/rdap+json', req.get_header('Accept'))
        with mock.patch.object(rdap, '_ABRIR', abrir([b'{', b'"a"', b':1}'])), self.assertRaises(rdap.SinTiempo):
            rdap._descargar(rdap.URL_BOOTSTRAP, 10, Cronometro(6))
        with mock.patch.object(rdap, '_ABRIR', abrir([b'x' * rdap.BLOQUE] * 17)), self.assertRaises(ValueError):
            rdap._descargar(rdap.URL_BOOTSTRAP, 10, Cronometro(0))

    def test_15_el_tope_de_tiempo_corta_la_corrida(self):
        res = recolectar(HttpSimulado(), cronometro=Cronometro(200))
        self.assertEqual((res.consultas, res.sin_cobertura), (0, ['domain_expiring_soon']))
        self.assertIn('se acabó el tiempo de la corrida', res.avisos[0])
        # Una respuesta lenta que no acaba la corrida es una falla de red y se reintenta
        lenta = HttpSimulado(dominios={DOMINIO: [rdap.SinTiempo('lenta'), respuesta()]})
        res = recolectar(lenta)
        self.assertEqual((res.consultas, res.sin_cobertura, el_dominio(res).atributos['vence']), (3, [], VENCE))

    def test_16_semilla_008_y_maximo_de_consultas(self):
        self.assertEqual(rdap.MAX_CONSULTAS, 6)
        texto = SEMILLA.read_text(encoding='utf-8')
        sin_comentarios = '\n'.join(linea.split('--')[0] for linea in texto.splitlines())
        [limite] = re.findall(r"UPDATE\s+data_sources\s+SET\s+daily_limit\s*=\s*(\d+)\s+WHERE\s+code\s*=\s*'whois'",
                              sin_comentarios)
        self.assertEqual(int(limite), 10 * rdap.MAX_CONSULTAS)
        self.assertIn("SET client_encoding = 'UTF8';", sin_comentarios)
        self.assertLess(sin_comentarios.index("SET client_encoding = 'UTF8';"), sin_comentarios.index('BEGIN;'))
        self.assertIn('AND daily_limit IS NULL', sin_comentarios)
        self.assertLessEqual(set(rdap.CODIGOS), set(POR_CODIGO))   # la severidad la revisa test_catalogo_reglas

    def test_17_linea_de_comandos(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(rdap, 'CARPETA_GRABADAS', Path(d)), \
                mock.patch.dict(os.environ, {'DOMINIOS_EN_VIVO': 'olmardo.com'}):
            for argv in (['acme-demo.mx'], ['acme-demo.mx', '--grabar'], ['../x', '--reproducir'],
                         ['olmardo.com', '--grabar', '--reproducir']):
                with self.subTest(argv=argv), self.assertRaises(SystemExit) as e, redirect_stdout(io.StringIO()), \
                        mock.patch('sys.stderr', io.StringIO()):
                    rdap._main(argv)
                self.assertEqual(e.exception.code, 2)
            salida = io.StringIO()
            with redirect_stdout(salida):
                codigo = rdap._main(['acme-demo.mx', '--reproducir'])
            self.assertEqual(codigo, 2)
            self.assertIn('aviso: ' + rdap.SIN_GRABACION_DOMINIO, salida.getvalue())
            self.assertIn('Registro de acme-demo.mx · registrador No disponible', salida.getvalue())
            # _main usa la hora real: el vencimiento va contra ella, no contra AHORA
            por_vencer = con_vencimiento(timedelta(days=12), ahora=datetime.now(timezone.utc))
            with mock.patch.object(rdap, '_descargar', por_vencer), redirect_stdout(io.StringIO()) as s:
                self.assertEqual(rdap._main([DOMINIO, '--json']), 0)
            self.assertEqual(json.loads(s.getvalue())['hallazgos'][0]['codigo'], 'domain_expiring_soon')

    def test_18_un_registro_vencido_da_aviso_y_una_fecha_imposible_es_rota(self):
        antes = '2020-03-01T00:00:00Z'   # un registro viejo: el vencimiento de abajo no es anterior a él
        res = recolectar(con_vencimiento(timedelta(days=-2, hours=-12), registrado=antes))
        self.assertEqual(contrato.validar(res, POR_CODIGO), [])
        self.assertEqual((res.estado, res.hallazgos, res.sin_cobertura), ('succeeded', [], []))
        self.assertEqual(el_dominio(res).atributos['vence'], '2026-10-13T00:00:00Z')
        self.assertIn('whois: el registro de olmardo.com venció el 2026-10-13 (hace 2 días) y RDAP lo sigue publicando. '
                      'No sale como domain_expiring_soon, que es para lo que vence en los siguientes 30 días', res.avisos)
        self.assertEqual(rdap.codigo_salida(res), 0)
        res = recolectar(con_vencimiento(timedelta(hours=-1), registrado=antes))
        self.assertTrue(any('(hace menos de un día)' in a for a in res.avisos), res.avisos)
        self.assertIsNone(rdap.hallazgo_vencimiento(DOMINIO, AHORA - timedelta(seconds=1), {}, AHORA))
        imposibles = {'de 1970': con_vencimiento(datetime(1970, 1, 1, tzinfo=timezone.utc) - AHORA, registrado='1960-01-01'),
                      'de hace más de un año': con_vencimiento(timedelta(days=-366), registrado=antes),
                      'anterior al registro': con_vencimiento(timedelta(days=-2), registrado='2026-10-14T12:00:00Z'),
                      'igual al registro': con_vencimiento(timedelta(days=5), registrado='2026-10-20T12:00:00Z')}
        for caso, http in imposibles.items():
            with self.subTest(caso=caso):
                res = recolectar(http)
                self.assertEqual(contrato.validar(res, POR_CODIGO), [])
                self.assertEqual((res.estado, res.hallazgos, res.sin_cobertura), ('succeeded', [], ['domain_expiring_soon']))
                self.assertEqual(el_dominio(res).atributos['vence'], NO)
                self.assertIn(rdap.VENCIMIENTO_IMPOSIBLE, res.avisos)
                self.assertEqual(rdap.codigo_salida(res), 2)

    def test_19_una_respuesta_rara_no_deja_la_fuente_en_failed(self):
        def ejecutar(http):
            with mock.patch.object(rdap, '_descargar', http), mock.patch.object(rdap.time, 'sleep', lambda s: None):
                return contrato.ejecutar(cargar('whois'), DOMINIO, modo='vivo', ahora=AHORA)
        # eventAction que no es texto: se ignora el evento
        eventos = [{'eventAction': ['expiration'], 'eventDate': '2026-10-20T00:00:00Z'},
                   {'eventAction': {'a': 1}, 'eventDate': '2026-10-20T00:00:00Z'},
                   {'eventAction': 'expiration', 'eventDate': VENCE}]
        res = ejecutar(HttpSimulado(dominios={DOMINIO: respuesta(eventos=eventos)}))
        self.assertEqual((res.estado, res.sin_cobertura, el_dominio(res).atributos['vence']), ('succeeded', [], VENCE))
        # Fechas que se salen del calendario al pasarlas a UTC
        res = ejecutar(HttpSimulado(dominios={DOMINIO: respuesta(vence='9999-12-31T23:59:59-05:00')}))
        self.assertEqual((res.estado, res.sin_cobertura), ('succeeded', ['domain_expiring_soon']))
        self.assertIn(rdap.VENCIMIENTO_ROTO, res.avisos)
        res = ejecutar(HttpSimulado(dominios={DOMINIO: respuesta(registrado='0001-01-01T00:00:00+01:00')}))
        self.assertEqual((res.estado, el_dominio(res).atributos['registrado'], el_dominio(res).atributos['vence']),
                         ('succeeded', NO, VENCE))
        self.assertEqual(rdap._iso(datetime(1, 1, 1, 4, tzinfo=timezone.utc)), '0001-01-01T04:00:00Z')
        # Un JSON muy anidado no se reintenta y da No disponible
        res = ejecutar(HttpSimulado(dominios={DOMINIO: b'[' * 200000 + b']' * 200000}))
        self.assertEqual((res.estado, res.consultas, res.sin_cobertura), ('succeeded', 2, ['domain_expiring_soon']))
        self.assertIn('demasiado anidado', res.avisos[0])
        # Texto del servidor con un carácter nulo o un surrogate: no llega a los avisos
        url = VERISIGN + 'domain/' + DOMINIO
        for error in (urllib.error.HTTPError(url, 503, 'Servicio\x00 roto \udc80', {}, None),
                      urllib.error.HTTPError(url, 429, 'Too Many', {'Retry-After': '6\x000'}, None)):
            with self.subTest(codigo=error.code):
                res = ejecutar(HttpSimulado(dominios={DOMINIO: error}))
                self.assertEqual((res.estado, res.sin_cobertura), ('succeeded', ['domain_expiring_soon']))
                self.assertTrue(res.avisos[0].startswith(rdap.SIN_RESPUESTA), res.avisos)
                self.assertTrue(all(contrato._cabe_en_la_base(a) and a.isprintable() for a in res.avisos), res.avisos)

    def test_20_la_url_del_bootstrap_no_lleva_credenciales_espacios_ni_ip(self):
        for url in ('https://:clave@rdap.example/', 'https://usuario:clave@rdap.example/', 'https://rdap.example/v1\\x/',
                    'https://rdap.example/v 1/', 'https://rdap.example/\tv1/', 'https://rdap.example/?',
                    'https://rdap.example/#', 'https://192.168.0.10/', 'https://[::1]/', 'https://10.0.0.1:8443/rdap/',
                    'https://rdap.exámple/', 'https://rdap.example/\udc80/'):
            with self.subTest(url=url):
                self.assertIsNone(rdap._url_https(url))
                bootstrap = {'services': [[['com'], [url]]]}
                self.assertEqual(rdap.servicio_de(bootstrap, DOMINIO), (None, None))
        self.assertEqual(rdap._url_https('https://rdap.verisign.com/com/v1'), VERISIGN)
        self.assertEqual(rdap._url_https('https://rdap.nic.mx:443/'), 'https://rdap.nic.mx:443/')
        self.assertEqual(rdap._url_https('https://rdap.nic.xn--p1ai/'), 'https://rdap.nic.xn--p1ai/')   # TLD IDN

    def test_21_una_entidad_registrar_con_rol_de_contacto_no_es_el_registrador(self):
        persona = {'objectClassName': 'entity', 'roles': ['registrar', 'registrant'],
                   'vcardArray': vcard(['fn', {}, 'text', 'Persona Registrante'])}
        sola = respuesta(entities=[persona])
        self.assertEqual(rdap.leer_rdap(sola, DOMINIO)[0]['registrador'], NO)
        self.assertNotIn('entities', rdap.reducir_rdap(sola))
        for rol in ('administrative', 'technical', 'billing', ' Registrant '):
            otra = dict(persona, roles=['registrar', rol])
            self.assertEqual(rdap.leer_rdap(respuesta(entities=[otra]), DOMINIO)[0]['registrador'], NO, rol)
        # Si después viene el registrador de verdad, se toma ese
        con = respuesta()
        con['entities'].insert(0, persona)
        self.assertEqual(rdap.leer_rdap(con, DOMINIO)[0]['registrador'], 'Registrador de Prueba, Inc.')
        # Roles raros no rompen nada
        rara = dict(con['entities'][1], roles=['registrar', ['x'], {'a': 1}])
        self.assertEqual(rdap.leer_rdap(respuesta(entities=[rara]), DOMINIO)[0]['registrador'], 'Registrador de Prueba, Inc.')

    def test_22_la_grabacion_solo_lleva_valores_filtrados_y_un_surrogate_no_la_borra(self):
        texto = 'Persona Registrante registrante@olmardo.com ' + 'x' * 5000
        datos = respuesta(status=['active', texto], secureDNS={'delegationSigned': texto}, unicodeName=texto + '\udc80',
                          nameservers=[{'ldhName': 'ns1.olmardo.com'}, {'ldhName': texto}, {'ldhName': 'NS2.OLMARDO.COM.'}],
                          eventos=[{'eventAction': 'last changed', 'eventDate': texto}]
                          + [{'eventAction': 'registration', 'eventDate': REGISTRADO}] * 100
                          # fromisoformat acepta cualquier separador, también un surrogate: se graba en el formato de _iso
                          + [{'eventAction': 'expiration', 'eventDate': '2027-10-14\udc8000:38:02Z'}])
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            res = recolectar(HttpSimulado(dominios={DOMINIO: datos}), modo='grabar', carpeta=carpeta, nueva=True)
            grabado = (carpeta / 'rdap_olmardo.com.json').read_text(encoding='utf-8')
            otra = recolectar(SinRed(), modo='reproducir', carpeta=carpeta)
        self.assertEqual(res.avisos[0], rdap.PENDIENTE)   # se grabó
        self.assertNotIn('Persona', grabado)
        self.assertNotIn('registrante@', grabado)
        self.assertLess(len(grabado), 2000)
        reducido = json.loads(grabado)['datos']
        self.assertEqual(reducido['events'], [{'eventAction': 'registration', 'eventDate': REGISTRADO},
                                              {'eventAction': 'expiration', 'eventDate': VENCE},
                                              {'eventAction': 'last changed', 'eventDate': None}])   # la rota sigue contando
        self.assertEqual(el_dominio(res).atributos['vence'], VENCE)
        self.assertEqual(reducido['status'], ['active'])
        self.assertNotIn('secureDNS', reducido)
        self.assertNotIn('unicodeName', reducido)
        self.assertEqual(reducido['nameservers'], [{'ldhName': 'ns1.olmardo.com'}, {'ldhName': 'ns2.olmardo.com'}])
        self.assertEqual(rdap.leer_rdap(reducido, DOMINIO), rdap.leer_rdap(datos, DOMINIO))   # reducir no cambia lo leído
        self.assertEqual((otra.activos, otra.hallazgos, otra.avisos), (res.activos, res.hallazgos, res.avisos))
        # Más casos donde leer_rdap tiene que dar lo mismo con la respuesta reducida
        for raro in (respuesta(objectClassName=None), respuesta(objectClassName=7)):
            with self.assertRaises(rdap.RespuestaIlegible):
                rdap.leer_rdap(rdap.reducir_rdap(raro), DOMINIO)
        nombre_largo = respuesta()
        nombre_largo['entities'][0]['vcardArray'] = vcard(['fn', {}, 'text', 'A' * 199 + ' B'])
        self.assertEqual(rdap.leer_rdap(rdap.reducir_rdap(nombre_largo), DOMINIO), rdap.leer_rdap(nombre_largo, DOMINIO))
        publicado = rdap.reducir_bootstrap(dict(BOOTSTRAP, publication='2026-10-20\udc8019:00:01Z'), DOMINIO)['publication']
        self.assertEqual(publicado, '2026-10-20T19:00:01Z')
        # Si algo no se puede guardar en UTF-8, no se graba nada y la grabación anterior queda igual
        original = rdap.reducir_rdap
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            recolectar(HttpSimulado(), modo='grabar', carpeta=carpeta, nueva=True)
            antes = {p.name: p.read_bytes() for p in carpeta.iterdir()}
            with mock.patch.object(rdap, 'reducir_rdap', lambda x: dict(original(x), nota='\udc80')):
                res = recolectar(con_vencimiento(timedelta(days=5)), modo='grabar', carpeta=carpeta, nueva=True)
            self.assertEqual({p.name: p.read_bytes() for p in carpeta.iterdir()}, antes)
        self.assertEqual((res.avisos[0], rdap.codigo_salida(res), len(res.hallazgos)), (rdap.NO_SE_GRABO, 3, 1))

    def test_23_esperar_no_pasa_del_tiempo_que_queda_y_una_lectura_que_lo_acaba(self):
        reloj, dormidas = [1000.0], []
        cliente = rdap.ClienteRdap(descargar=SinRed(), cronometro=lambda: reloj[0], dormir=dormidas.append)
        cliente.empezar()
        reloj[0] += rdap.TIEMPO_CORRIDA - 3
        cliente.esperar(15)
        reloj[0] += 10
        cliente.esperar(5)
        self.assertEqual(dormidas, [3, 0])

        def lenta(url, timeout):
            if url == rdap.URL_BOOTSTRAP:
                return json.dumps(BOOTSTRAP).encode()
            reloj[0] += rdap.TIEMPO_CORRIDA   # la lectura se come lo que queda de la corrida
            raise rdap.SinTiempo('lenta')
        reloj[0] = 1000.0
        cliente = rdap.ClienteRdap(descargar=lenta, cronometro=lambda: reloj[0], dormir=lambda s: None)
        res = rdap.recolectar(DOMINIO, cliente, ahora=AHORA)
        self.assertEqual((res.estado, res.consultas, res.sin_cobertura), ('succeeded', 2, ['domain_expiring_soon']))
        self.assertIn('se acabó el tiempo de la corrida mientras se leía RDAP (rdap.verisign.com)', res.avisos[0])


if __name__ == '__main__':
    unittest.main()
