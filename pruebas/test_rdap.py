"""Pruebas del recolector de RDAP y su respaldo por WHOIS (#15b, RC-166), sin red: el bootstrap de IANA y el registro
con un transporte HTTP simulado, y el puerto 43 con una conversación simulada (WhoisSimulado). Ninguna prueba abre un
socket: el _conversar de verdad solo corre con un módulo socket falso.

    python -m unittest -v pruebas/test_rdap.py

Las respuestas tienen la forma de RDAP (RFC 9083), del bootstrap (RFC 9224) y de WHOIS de whois.iana.org, whois.mx y
Verisign (_plan/rc166/estudio/whois43.md), pero son simuladas. Las fechas de olmardo.com son las de la semilla 002 y de
docs/hallazgos_esperados.md, fila 7. El registrador, los contactos y los servidores de .mx y de los TLD zz y yy son
inventados: no dicen qué TLD tiene RDAP de verdad.
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
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
    """Un transporte (HTTP o puerto 43) que falla la prueba si alguien lo llama."""

    def __call__(self, destino, *_):
        raise AssertionError('se consultó la red: %s' % destino)


CONVERSAR = rdap._conversar   # el de verdad: la clase Rdap lo cambia por SinRed en cada prueba
MX = 'acme-demo.com.mx'
SIN_MX = dict(BOOTSTRAP, services=[s for s in BOOTSTRAP['services'] if s != [['mx'], ['https://rdap.mx.example/']]])
# Fichas de whois.iana.org de un TLD, con los contactos inventados del administrador del TLD (no se leen).
IANA_MX = ('% IANA WHOIS server\r\n\r\ndomain:       MX\r\n\r\norganisation: Registro Falso\r\naddress:      Calle Falsa 123'
           '\r\ncontact:      administrative\r\nname:         Persona Administradora Falsa\r\nphone:        +52.8180000002'
           '\r\n\r\nnserver:      A.NS.EXAMPLE 1.2.3.4\r\nwhois:        whois.mx\r\n\r\nstatus:       ACTIVE\r\n')
IANA_COM = IANA_MX.replace('MX\r\n', 'COM\r\n').replace('whois.mx', 'whois.verisign-grs.com')
IANA_SIN_WHOIS = IANA_MX.replace('MX\r\n', 'ZZ\r\n').replace('whois.mx', '')
# Datos personales inventados de los contactos de WHOIS: nada de esto puede quedar en la grabación ni en el resultado.
CONTACTOS = ('Persona Registrante Falsa', 'Persona Administrativa Falsa', 'Persona Administradora Falsa', 'Ciudad Falsa',
             'Estado Falso', 'Pais Falso', 'Calle Falsa 123', 'CIRDAN_FAKE_correo', '+52.818000000')
# Respuesta de whois.mx con la forma del estudio (sección 4.1): contactos, NS con IP y avisos con '%'.
WHOIS_MX = '''Domain Name:       acme-demo.com.mx

Created On:        2019-05-12
Expiration Date:   2026-11-05
Last Updated On:   2025-11-01
Registrar:         Registrador de Prueba MX
URL:               registrador-mx.example

Registrant:
   Name:           Persona Registrante Falsa
   City:           Ciudad Falsa
   State:          Estado Falso
   Country:        Pais Falso
   Email:          CIRDAN_FAKE_correo_registrante
   Phone:          +52.8180000003
   Address:        Calle Falsa 123

Administrative Contact:
   Name:           Persona Administrativa Falsa
   City:           Ciudad Falsa
   Email:          CIRDAN_FAKE_correo_admin

Technical Contact:
   Name:           Persona Administrativa Falsa

Billing Contact:
   Name:           Persona Administrativa Falsa

Name Servers:
   DNS:            ns1.acme-demo.com.mx 1.2.3.4
   DNS:            NS2.ACME-DEMO.COM.MX

DNSSEC DS Records:


% NOTICE: The expiration date displayed in this record is the date the
% registrar's sponsorship of the domain name registration in the registry is
% currently set to expire.
'''.replace('\n', '\r\n')
# Respuesta de Verisign (sección 4.2): 'thin', sin registrante, con la referencia al WHOIS del registrador.
WHOIS_VERISIGN = '''   Domain Name: OLMARDO.COM
   Registry Domain ID: 3012345678_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.registrador.example
   Registrar URL: registrador.example
   Updated Date: 2026-10-14T00:40:11Z
   Creation Date: 2026-10-14T00:38:02Z
   Registry Expiry Date: 2027-10-14T00:38:02Z
   Registrar: Registrador de Prueba, Inc.
   Registrar IANA ID: 9999
   Registrar Abuse Contact Email: CIRDAN_FAKE_correo_abuso
   Registrar Abuse Contact Phone: +52.8180000004
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: ADA.NS.CLOUDFLARE.COM
   Name Server: BOB.NS.CLOUDFLARE.COM
   DNSSEC: unsigned
>>> Last update of whois database: 2026-10-15T11:58:00Z <<<
'''.replace('\n', '\r\n')


class WhoisSimulado:
    """Hace las veces de rdap._conversar(host, consulta, timeout). `respuestas` es {(host, consulta): respuesta}: texto
    (va en UTF-8) o bytes tal cual, una excepción se lanza y una lista da una respuesta por intento (la última se
    repite). Lo que no está se rechaza como una conexión caída (ConnectionRefusedError), que se reintenta."""

    def __init__(self, respuestas=None):
        self.respuestas = respuestas or {}
        self.pedidas, self.plazos = [], []

    def __call__(self, host, consulta, timeout):
        self.pedidas.append((host, consulta))
        self.plazos.append(timeout)
        r = self.respuestas.get((host, consulta), ConnectionRefusedError('conexión rechazada'))
        if isinstance(r, list):
            r = r[min(self.pedidas.count((host, consulta)), len(r)) - 1]
        if isinstance(r, Exception):
            raise r
        return r.encode('utf-8') if isinstance(r, str) else r


def whois_mx(respuesta_mx=WHOIS_MX, iana=IANA_MX):
    return WhoisSimulado({(rdap.IANA_WHOIS, 'mx'): iana, ('whois.mx', MX): respuesta_mx})


def whois_com(respuesta_com=WHOIS_VERISIGN):
    return WhoisSimulado({(rdap.IANA_WHOIS, 'com'): IANA_COM,
                          ('whois.verisign-grs.com', 'domain ' + DOMINIO): respuesta_com})


def recolectar(http, modo='vivo', carpeta=None, nueva=False, cronometro=None, dominio=DOMINIO, dormir=None, ahora=AHORA,
               whois=None):
    """`whois` es el puerto 43. Por omisión rechaza toda conexión: si RDAP falla, fallan los dos."""
    cliente = rdap.ClienteRdap(modo=modo, carpeta=carpeta or rdap.carpeta_de(dominio), descargar=http, nueva=nueva,
                               cronometro=cronometro or Cronometro(0), dormir=dormir or (lambda s: None),
                               conversar=WhoisSimulado() if whois is None else whois)
    return rdap.recolectar(dominio, cliente, ahora=ahora)


def con_vencimiento(delta, ahora=AHORA, **extra):
    """Una respuesta de olmardo.com que vence `delta` después de `ahora`."""
    return HttpSimulado(dominios={DOMINIO: respuesta(vence=(ahora + delta).strftime('%Y-%m-%dT%H:%M:%SZ'), **extra)})


def el_dominio(res):
    [a] = [a for a in res.activos if a.tipo == 'domain']
    return a


class Socket:
    """Un socket falso de Red. Con `red.reloj`, un connect a una dirección de `red.colgadas` gasta todo su timeout,
    como un servidor que descarta los SYN, y lanza TimeoutError."""

    def __init__(self, red, familia, tipo, protocolo):
        self.red, self.cerrado, self.plazos, self.enviado = red, False, [], b''
        red.sockets.append(self)

    def settimeout(self, segundos):
        self.plazos.append(segundos)

    def connect(self, destino):
        if destino[0] in self.red.colgadas:
            self.red.reloj[0] += self.plazos[-1]
            raise TimeoutError('timed out')
        if destino[0] in self.red.caidas:
            raise ConnectionRefusedError('rechazada')

    def sendall(self, datos):
        self.enviado += datos

    def recv(self, n):
        return self.red.partes.pop(0)[:n] if self.red.partes else b''

    def close(self):
        self.cerrado = True


class Red:
    """Un módulo socket falso: getaddrinfo da `ips` (familia 10 si es IPv6, 2 si no) y cada socket lee `partes`.
    socket() de una familia de `sin_familia` lanza OSError, como AF_INET6 en un kernel sin IPv6."""
    SOCK_STREAM = 1

    def __init__(self, ips, partes=(), caidas=(), resolver=None, colgadas=(), reloj=None, sin_familia=()):
        self.ips, self.partes, self.caidas, self.sockets, self.resolver = ips, list(partes), caidas, [], resolver
        self.colgadas, self.reloj, self.sin_familia = colgadas, reloj, sin_familia
        self.pedidas = []

    def getaddrinfo(self, host, puerto, type=None):
        self.pedidas.append((host, puerto, type))
        if self.resolver:
            self.resolver()
        return [(10 if ':' in ip else 2, 1, 6, '', (ip, puerto)) for ip in self.ips]

    def socket(self, familia, tipo, protocolo):
        if familia in self.sin_familia:
            raise OSError(97, 'Address family not supported by protocol')
        return Socket(self, familia, tipo, protocolo)


class Rdap(unittest.TestCase):

    def setUp(self):
        # Ninguna prueba abre un socket: si alguien llega al _conversar del módulo sin cambiarlo, la prueba falla.
        guardia = mock.patch.object(rdap, '_conversar', SinRed())
        guardia.start()
        self.addCleanup(guardia.stop)

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
        self.assertEqual(res.avisos, [])
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
                dormidas, whois = [], WhoisSimulado()   # el puerto 43 tampoco responde
                res = recolectar(http, dormir=dormidas.append, whois=whois)
                self.assertEqual(contrato.validar(res, POR_CODIGO), [])
                self.assertEqual((res.estado, res.hallazgos, res.sin_cobertura), ('succeeded', [], ['domain_expiring_soon']))
                self.assertEqual(el_dominio(res).atributos, datos_no)
                self.assertTrue(res.avisos[0].startswith(rdap.SIN_RESPUESTA + ' (RDAP: '), res.avisos)
                self.assertIn('. WHOIS: el WHOIS de IANA no respondió después de 2 intentos (ConnectionRefusedError',
                              res.avisos[0])
                # Lo de RDAP y después los 2 intentos a whois.iana.org, con su espera de 5 s
                self.assertEqual(whois.pedidas, [(rdap.IANA_WHOIS, 'com')] * rdap.INTENTOS_WHOIS)
                self.assertEqual((res.consultas, dormidas), (consultas + 2, esperas + [5]))
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
        self.assertIn(rdap.SIN_VENCIMIENTO % 'RDAP', res.avisos)
        self.assertEqual(el_dominio(res).atributos['registrado'], REGISTRADO)
        res = recolectar(HttpSimulado(dominios={DOMINIO: respuesta(vence='mañana')}))
        self.assertEqual(res.sin_cobertura, ['domain_expiring_soon'])
        self.assertIn(rdap.VENCIMIENTO_ROTO % 'RDAP', res.avisos)
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
        self.assertEqual(res.avisos, [])   # una fecha rota con otra buena del mismo evento no avisa
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

    def test_10_el_404_y_el_tld_sin_rdap_ni_whois_tambien_se_graban(self):
        sin_whois = WhoisSimulado({(rdap.IANA_WHOIS, 'zz'): IANA_SIN_WHOIS})
        for dominio, archivos in ((DOMINIO, ['bootstrap.json', 'rdap_olmardo.com.json']),
                                  ('ejemplo.zz', ['bootstrap.json', 'whois-iana_zz.json'])):
            with self.subTest(dominio=dominio), tempfile.TemporaryDirectory() as d:
                carpeta = Path(d) / dominio
                res = recolectar(HttpSimulado(dominios={}), modo='grabar', carpeta=carpeta, nueva=True, dominio=dominio,
                                 whois=sin_whois)
                self.assertNotIn(rdap.NO_SE_GRABO, res.avisos)
                self.assertEqual(sorted(p.name for p in carpeta.glob('*.json')), archivos)
                otra = recolectar(SinRed(), modo='reproducir', carpeta=carpeta, dominio=dominio, whois=SinRed())
                self.assertEqual((otra.activos, otra.sin_cobertura, otra.avisos), (res.activos, res.sin_cobertura, res.avisos))
        self.assertEqual(sin_whois.pedidas, [(rdap.IANA_WHOIS, 'zz')])   # el 404 de RDAP no pasa a WHOIS

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
            self.assertEqual(res.avisos, [rdap.SIN_GRABACION_DOMINIO])
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
        # RDAP (bootstrap y dominio) y el respaldo (whois.iana.org y el servidor del TLD), cada uno con sus intentos
        self.assertEqual(rdap.MAX_CONSULTAS, 2 * rdap.INTENTOS + 2 * rdap.INTENTOS_WHOIS)
        self.assertEqual(rdap.MAX_CONSULTAS, 10)
        texto = SEMILLA.read_text(encoding='utf-8')
        sin_comentarios = '\n'.join(linea.split('--')[0] for linea in texto.splitlines())
        [limite] = re.findall(r"UPDATE\s+data_sources\s+SET\s+daily_limit\s*=\s*(\d+)\s+WHERE\s+code\s*=\s*'whois'",
                              sin_comentarios)
        self.assertGreaterEqual(int(limite) // rdap.MAX_CONSULTAS, 6)   # al menos 6 corridas en el peor caso
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
                self.assertIn(rdap.VENCIMIENTO_IMPOSIBLE % 'RDAP', res.avisos)
                self.assertEqual(rdap.codigo_salida(res), 2)

    def test_19_una_respuesta_rara_no_deja_la_fuente_en_failed(self):
        def ejecutar(http):
            with mock.patch.object(rdap, '_descargar', http), mock.patch.object(rdap.time, 'sleep', lambda s: None), \
                    mock.patch.object(rdap, '_conversar', WhoisSimulado()):   # el puerto 43 tampoco responde
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
        self.assertIn(rdap.VENCIMIENTO_ROTO % 'RDAP', res.avisos)
        res = ejecutar(HttpSimulado(dominios={DOMINIO: respuesta(registrado='0001-01-01T00:00:00+01:00')}))
        self.assertEqual((res.estado, el_dominio(res).atributos['registrado'], el_dominio(res).atributos['vence']),
                         ('succeeded', NO, VENCE))
        self.assertEqual(rdap._iso(datetime(1, 1, 1, 4, tzinfo=timezone.utc)), '0001-01-01T04:00:00Z')
        # Un JSON muy anidado no se reintenta y da No disponible
        res = ejecutar(HttpSimulado(dominios={DOMINIO: b'[' * 200000 + b']' * 200000}))
        self.assertEqual((res.estado, res.consultas, res.sin_cobertura), ('succeeded', 2 + 2, ['domain_expiring_soon']))
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
        self.assertNotIn(rdap.NO_SE_GRABO, res.avisos)   # se grabó
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
        reloj[0] += rdap.TIEMPO_CORRIDA - rdap.RESERVA_WHOIS - 3   # mientras corre RDAP, la reserva no cuenta
        cliente.esperar(15)
        reloj[0] += 10
        cliente.esperar(5)
        cliente.reserva = 0                                          # al pasar a WHOIS queda la reserva: 30 - 7 s
        self.assertEqual(cliente.restante(), rdap.RESERVA_WHOIS - 7)
        cliente.esperar(5)
        self.assertEqual(dormidas, [3, 0, 5])

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

    def test_24_las_grabaciones_de_whois_no_van_al_repo(self):
        """Igual que las de dns: un git add no sube el registro de una empresa a un repo público. Revisa solo el .gitignore."""
        self.assertEqual(rdap.CARPETA_GRABADAS, contrato.CARPETA_GRABADAS / 'whois')
        self.assertTrue((rdap.CARPETA_GRABADAS / '.gitkeep').exists())
        reglas = Path(__file__).resolve().parents[1] / '.gitignore'
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
                self.assertIn(r.returncode, (0, 1), ruta)  # 128: git no pudo revisarlo
                return r.returncode == 0
            for ruta in ('whois/olmardo.com/bootstrap.json', 'whois/olmardo.com/rdap_olmardo.com.json',
                         'whois/olmardo.com/.grabacion', 'whois/acme-demo.com.mx/whois-iana_mx.json',
                         'whois/acme-demo.com.mx/whois_acme-demo.com.mx.json'):
                self.assertTrue(ignorado(ruta), ruta)
            for ruta in ('whois/.gitkeep', 'dns/.gitkeep', 'ejemplo/acme-demo.mx/resultado.json'):
                self.assertFalse(ignorado(ruta), ruta)


    # ------------------------------------------------------------ respaldo por WHOIS (puerto 43)

    def test_25_com_mx_sin_rdap_sale_de_whois_mx_sin_contactos(self):
        http, whois = HttpSimulado(bootstrap=SIN_MX, dominios={}), whois_mx()
        res = recolectar(http, dominio=MX, whois=whois)
        self.assertEqual(contrato.validar(res, POR_CODIGO), [])
        self.assertEqual(http.urls, [rdap.URL_BOOTSTRAP])
        self.assertEqual(whois.pedidas, [(rdap.IANA_WHOIS, 'mx'), ('whois.mx', MX)])
        self.assertEqual((res.estado, res.sin_cobertura, res.consultas), ('succeeded', [], 3))
        self.assertEqual(el_dominio(res).atributos, {
            'fuente': 'whois', 'fuente_datos': 'WHOIS', 'servidor_whois': 'whois.mx',
            'registrador': 'Registrador de Prueba MX', 'registrador_iana': NO,
            'registrado': '2019-05-12T00:00:00Z', 'vence': '2026-11-05T23:59:59Z', 'ultimo_cambio': '2025-11-01T00:00:00Z',
            'estado_registro': NO, 'servidores_nombre': ['ns1.acme-demo.com.mx', 'ns2.acme-demo.com.mx'], 'dnssec': NO})
        self.assertEqual(res.avisos, [rdap.CON_WHOIS % ('whois.mx', rdap.SIN_RDAP_TLD)])
        # domain_expiring_soon desde WHOIS: la evidencia dice de dónde salió el dato. La 'Expiration Date' de whois.mx
        # es solo fecha y vale hasta el final de ese día (23:59:59Z): de AHORA al 5 nov a esa hora son 21 días
        [h] = res.hallazgos
        self.assertEqual((h.codigo, h.titulo), ('domain_expiring_soon', 'El registro de acme-demo.com.mx vence en 21 días'))
        self.assertEqual(h.evidencia, {
            'title': h.titulo, 'vence': '2026-11-05T23:59:59Z', 'dias_para_vencer': 21,
            'registrador': 'Registrador de Prueba MX', 'estado_registro': NO,
            'fuente_datos': 'WHOIS', 'servidor_whois': 'whois.mx'})
        self.assertEqual(rdap.codigo_salida(res), 0)
        resultado = json.dumps(res.a_dict(), ensure_ascii=False)
        for dato in CONTACTOS:
            self.assertNotIn(dato, resultado)
        # Al grabar quedan el bootstrap reducido, el servidor de IANA y la respuesta reducida, y se reproduce sin red
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / MX
            grabada = recolectar(HttpSimulado(bootstrap=SIN_MX, dominios={}), modo='grabar', carpeta=carpeta, nueva=True,
                                 dominio=MX, whois=whois_mx())
            self.assertEqual(sorted(p.name for p in carpeta.glob('*.json')),
                             ['bootstrap.json', 'whois-iana_mx.json', 'whois_acme-demo.com.mx.json'])
            leido = {p.name: json.loads(p.read_text(encoding='utf-8'))['datos'] for p in carpeta.glob('*.json')}
            grabado = ''.join(p.read_text(encoding='utf-8') for p in carpeta.glob('*.json'))
            otra = recolectar(SinRed(), modo='reproducir', carpeta=carpeta, dominio=MX, whois=SinRed())
        for dato in CONTACTOS + ('registrador-mx.example', 'NOTICE'):
            self.assertNotIn(dato, grabado)
        self.assertEqual(leido['bootstrap.json']['services'], [])
        self.assertEqual(leido['whois-iana_mx.json'], {'whois': 'whois.mx'})
        self.assertEqual(leido['whois_acme-demo.com.mx.json'], {
            'dominio': MX, 'registrado': '2019-05-12T00:00:00Z', 'vence': '2026-11-05T23:59:59Z',
            'ultimo_cambio': '2025-11-01T00:00:00Z', 'registrador': 'Registrador de Prueba MX',
            'servidores_nombre': ['ns1.acme-demo.com.mx', 'ns2.acme-demo.com.mx']})
        self.assertEqual((grabada.activos, grabada.hallazgos, grabada.avisos), (res.activos, res.hallazgos, res.avisos))
        self.assertEqual((otra.activos, otra.hallazgos, otra.avisos, otra.consultas),
                         (res.activos, res.hallazgos, res.avisos, 0))

    def test_26_com_con_rdap_caido_sale_de_verisign_y_no_se_graba(self):
        whois = whois_com()
        res = recolectar(HttpSimulado(dominios={DOMINIO: 503}), whois=whois)
        self.assertEqual(contrato.validar(res, POR_CODIGO), [])
        # Solo el servidor del registro: 'Registrar WHOIS Server' no se sigue
        self.assertEqual(whois.pedidas, [(rdap.IANA_WHOIS, 'com'), ('whois.verisign-grs.com', 'domain olmardo.com')])
        self.assertEqual((res.estado, res.hallazgos, res.sin_cobertura, res.consultas), ('succeeded', [], [], 1 + 3 + 2))
        self.assertEqual(el_dominio(res).atributos, {
            'fuente': 'whois', 'fuente_datos': 'WHOIS', 'servidor_whois': 'whois.verisign-grs.com',
            'registrador': 'Registrador de Prueba, Inc.', 'registrador_iana': '9999',
            'registrado': REGISTRADO, 'vence': VENCE, 'ultimo_cambio': CAMBIO,
            'estado_registro': ['client delete prohibited', 'client transfer prohibited'],
            'servidores_nombre': ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'], 'dnssec': False})
        [aviso] = res.avisos
        self.assertTrue(aviso.startswith(rdap.CON_WHOIS % ('whois.verisign-grs.com', 'RDAP no respondió (RDAP (')), aviso)
        self.assertIn('HTTPError', aviso)
        self.assertEqual(rdap.codigo_salida(res), 0)
        resultado = json.dumps(res.a_dict(), ensure_ascii=False)
        for dato in CONTACTOS + ('whois.registrador.example',):
            self.assertNotIn(dato, resultado)
        # Al grabar, una falla de RDAP con el respaldo bueno no graba: la grabación anterior queda igual
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            recolectar(HttpSimulado(), modo='grabar', carpeta=carpeta, nueva=True)
            antes = {p.name: p.read_bytes() for p in carpeta.iterdir()}
            grabada = recolectar(HttpSimulado(dominios={DOMINIO: 503}), modo='grabar', carpeta=carpeta, nueva=True,
                                 whois=whois_com())
            self.assertEqual({p.name: p.read_bytes() for p in carpeta.iterdir()}, antes)
        self.assertEqual((grabada.avisos[0], grabada.avisos[1:], grabada.activos), (rdap.NO_SE_GRABO, [aviso], res.activos))
        self.assertEqual(rdap.codigo_salida(grabada), 3)
        # El 404 de RDAP y una respuesta sin vencimiento no pasan a WHOIS (la guardia de setUp falla si alguien llama)
        self.assertIn(rdap.NO_ENCONTRADO, recolectar(HttpSimulado(dominios={}), whois=SinRed()).avisos)
        sin_fecha = recolectar(HttpSimulado(dominios={DOMINIO: respuesta(vence=None)}), whois=SinRed())
        self.assertEqual(sin_fecha.avisos, [rdap.SIN_VENCIMIENTO % 'RDAP'])

    def test_27_tld_sin_whois_y_dominio_que_whois_no_conoce(self):
        sin_whois = WhoisSimulado({(rdap.IANA_WHOIS, 'mx'): IANA_SIN_WHOIS.replace('ZZ\r\n', 'MX\r\n')})
        res = recolectar(HttpSimulado(bootstrap=SIN_MX), dominio=MX, whois=sin_whois)
        self.assertEqual(contrato.validar(res, POR_CODIGO), [])
        self.assertEqual((res.estado, res.sin_cobertura, res.consultas), ('succeeded', ['domain_expiring_soon'], 2))
        self.assertEqual(res.avisos, [rdap.SIN_WHOIS % (MX, rdap.SIN_RDAP_TLD)])
        self.assertEqual(el_dominio(res).atributos['vence'], NO)
        self.assertEqual(sin_whois.pedidas, [(rdap.IANA_WHOIS, 'mx')])
        no_existe = {'Verisign': 'No match for "OLMARDO.COM".\r\n>>> Last update of whois database: 2026-10-15 <<<\r\n',
                     'whois.mx': 'No_Se_Encontro_El_Objeto/Object_Not_Found\r\n&PARAMETROS VALIDOS\r\n'}
        for caso, texto in no_existe.items():
            with self.subTest(caso=caso):
                res = recolectar(HttpSimulado(dominios={DOMINIO: 503}), whois=whois_com(texto))
                self.assertEqual((res.estado, res.sin_cobertura, res.consultas),
                                 ('succeeded', ['domain_expiring_soon'], 1 + 3 + 2))
                self.assertEqual(res.avisos[1], rdap.NO_ENCONTRADO_WHOIS)
                self.assertEqual(el_dominio(res).atributos['registrador'], NO)
        self.assertEqual(rdap.reducir_whois(no_existe['whois.mx'], MX), {'no_encontrado': True})

    def test_28_respuestas_whois_que_no_se_pueden_leer(self):
        raras = {
            'de otro dominio': (WHOIS_VERISIGN.replace('OLMARDO.COM', 'OTRO.COM'), 'WHOIS respondió con otro dominio'),
            'con dos dominios': (WHOIS_VERISIGN + '   Domain Name: OTRO.COM\r\n', 'WHOIS respondió con otro dominio'),
            'sin campos': ('Servicio en mantenimiento, intente más tarde\r\n', 'no respondió con el registro de un dominio'),
            'vacía': ('  \r\n', 'respondió sin texto'),
        }
        for caso, (texto, motivo) in raras.items():
            with self.subTest(caso=caso):
                whois = whois_com(texto)
                res = recolectar(HttpSimulado(dominios={DOMINIO: 503}), whois=whois)
                self.assertEqual(contrato.validar(res, POR_CODIGO), [])
                self.assertEqual((res.estado, res.sin_cobertura), ('succeeded', ['domain_expiring_soon']))
                self.assertTrue(res.avisos[0].startswith(rdap.SIN_RESPUESTA), res.avisos)
                self.assertIn(motivo, res.avisos[0])
                self.assertEqual(len(whois.pedidas), 2)   # no se reintenta: el servidor sí respondió
                self.assertEqual(el_dominio(res).atributos['registrador'], NO)
        # Una ficha de IANA rota o con un servidor que no es un nombre de host tampoco se usa
        for caso, ficha in {'sin ficha': '% This query returned 0 objects.\r\n',
                            'servidor con IP': IANA_COM.replace('whois.verisign-grs.com', '192.0.2.43'),
                            'servidor con puerto': IANA_COM.replace('whois.verisign-grs.com', 'whois.example:4343')}.items():
            with self.subTest(caso=caso):
                whois = WhoisSimulado({(rdap.IANA_WHOIS, 'com'): ficha})
                res = recolectar(HttpSimulado(dominios={DOMINIO: 503}), whois=whois)
                self.assertTrue(res.avisos[0].startswith(rdap.SIN_RESPUESTA), res.avisos)
                self.assertEqual(whois.pedidas, [(rdap.IANA_WHOIS, 'com')])
        # Fallan los dos: un solo aviso con los dos motivos y, al grabar, NO_SE_GRABO
        res = recolectar(HttpSimulado(dominios={DOMINIO: 503}), whois=WhoisSimulado({(rdap.IANA_WHOIS, 'com'): IANA_COM}))
        self.assertTrue(res.avisos[0].startswith(rdap.SIN_RESPUESTA + ' (RDAP: RDAP (rdap.verisign.com) no respondió'))
        self.assertIn('. WHOIS: WHOIS (whois.verisign-grs.com) no respondió después de 2 intentos', res.avisos[0])
        self.assertEqual((res.consultas, rdap.codigo_salida(res)), (1 + 3 + 1 + 2, 2))
        with tempfile.TemporaryDirectory() as d:
            res = recolectar(HttpSimulado(dominios={DOMINIO: 503}), modo='grabar', carpeta=Path(d) / DOMINIO, nueva=True)
            self.assertEqual(list(Path(d).iterdir()), [])
        self.assertEqual((res.avisos[0], rdap.codigo_salida(res)), (rdap.NO_SE_GRABO, 3))

    def test_29_lectura_de_whois_campos_codificacion_y_estados(self):
        # Latin-1 cuando no es UTF-8 válido, y UTF-8 cuando sí
        texto = WHOIS_MX.replace('Registrador de Prueba MX', 'Compañía Registradora')
        for cuerpo in (texto.encode('latin-1'), texto.encode('utf-8')):
            with self.subTest(cuerpo=cuerpo[200:230]):
                res = recolectar(HttpSimulado(bootstrap=SIN_MX), dominio=MX,
                                 whois=whois_mx(respuesta_mx=cuerpo))
                self.assertEqual(el_dominio(res).atributos['registrador'], 'Compañía Registradora')
        self.assertEqual([rdap._estado_epp(v) for v in ('ok', 'OK', 'clientTransferProhibited https://icann.org/epp#x',
                                                        'redemptionPeriod', 'pendingDelete', 'serverHold', 'inactive')],
                         ['active', 'active', 'client transfer prohibited', 'redemption period', 'pending delete',
                          'server hold', 'inactive'])
        # Fechas repetidas como en _fechas, una rota que cuenta como rota, y DNSSEC firmado
        raro = ('Domain Name: OLMARDO.COM\nCreation Date: 2026-10-15T00:00:00Z\nCreation Date: ' + REGISTRADO
                + '\nRegistry Expiry Date: 2026-10-20T00:00:00Z\nRegistry Expiry Date: ' + VENCE
                + '\nUpdated Date: ayer\nDNSSEC: signedDelegation\nDomain Status: con_guion_bajo\n'
                + 'Registrar: \x00\nRegistrar IANA ID: 12a\nName Server: \nName Server: ns1.olmardo.com. 1.2.3.4\n'
                + 'Registrant Name: Persona Registrante Falsa\nRegistrant Email: CIRDAN_FAKE_correo\n')
        reducido = rdap.reducir_whois(raro, DOMINIO)
        self.assertEqual(reducido, {'dominio': DOMINIO, 'registrado': REGISTRADO, 'vence': VENCE, 'ultimo_cambio': None,
                                    'estado_registro': [], 'servidores_nombre': ['ns1.olmardo.com'], 'dnssec': True})
        atributos, rotos = rdap.leer_whois(reducido, DOMINIO)
        self.assertEqual((atributos['ultimo_cambio'], atributos['estado_registro'], atributos['registrador'],
                          atributos['registrador_iana'], rotos), (NO, NO, NO, NO, ['ultimo_cambio']))
        res = recolectar(HttpSimulado(dominios={DOMINIO: 503}), whois=whois_com(raro))
        self.assertIn('whois: WHOIS dio fechas que no se pueden leer (ultimo_cambio) y se ignoraron', res.avisos)
        # leer_whois vuelve a filtrar lo grabado: un valor editado a mano no pasa
        editado = dict(reducido, registrador='x' * 500, estado_registro=['active', 'Con Mayúsculas', 7],
                       servidores_nombre=['NS1.OLMARDO.COM', 'no es un nombre'], dnssec='si', registrador_iana='9999')
        atributos, _ = rdap.leer_whois(editado, DOMINIO)
        self.assertEqual((len(atributos['registrador']), atributos['estado_registro'], atributos['servidores_nombre'],
                          atributos['dnssec'], atributos['registrador_iana']),
                         (rdap.MAX_TEXTO, ['active'], ['ns1.olmardo.com'], NO, '9999'))
        for roto in ({'dominio': 'otro.com'}, ['no es un objeto'], {'no_encontrado': True}):
            with self.assertRaises(rdap.RespuestaIlegible):
                rdap.leer_whois(roto, DOMINIO)
        # Ficha de IANA: solo 'whois:', vacía es None
        self.assertEqual(rdap.servidor_whois_de(IANA_MX, 'mx'), 'whois.mx')
        self.assertIsNone(rdap.servidor_whois_de(IANA_SIN_WHOIS, 'zz'))
        self.assertIsNone(rdap.servidor_whois_de('domain: ZZ\n', 'zz'))
        with self.assertRaises(rdap.RespuestaIlegible):
            rdap.servidor_whois_de(IANA_MX, 'com')

    def test_30_reproducir_grabaciones_viejas_o_rotas_del_respaldo(self):
        with tempfile.TemporaryDirectory() as d:
            # De antes del respaldo: bootstrap sin servicio y sin whois-iana. Da lo de entonces y no falla
            vieja = Path(d) / 'vieja' / MX
            contrato.Grabadora(vieja, 'grabar').guardar('bootstrap', rdap.reducir_bootstrap(SIN_MX, MX))
            res = recolectar(SinRed(), modo='reproducir', carpeta=vieja, dominio=MX, whois=SinRed())
            self.assertEqual((res.estado, res.sin_cobertura, res.consultas), ('succeeded', ['domain_expiring_soon'], 0))
            self.assertEqual(res.avisos, ['whois: el bootstrap de IANA no tiene un servidor RDAP https para el TLD de '
                                          'acme-demo.com.mx'])
            self.assertEqual(el_dominio(res).atributos['vence'], NO)
            # Con whois-iana pero sin la respuesta, o con una rota, es failed: no es una falla de WHOIS
            rotas = {'sin la respuesta': ({'whois': 'whois.mx'}, None),
                     'whois-iana roto': ({'whois': '10.0.0.1'}, {'dominio': MX}),
                     'whois-iana sin la llave': ({}, {'dominio': MX}),
                     'respuesta de otro dominio': ({'whois': 'whois.mx'}, {'dominio': 'otro.com.mx'}),
                     'respuesta que no es objeto': ({'whois': 'whois.mx'}, ['no es un objeto'])}
            for caso, (iana, respuesta_whois) in rotas.items():
                with self.subTest(caso=caso):
                    raiz = Path(d) / caso.replace(' ', '_')
                    grabadora = contrato.Grabadora(raiz / MX, 'grabar')
                    grabadora.guardar('bootstrap', rdap.reducir_bootstrap(SIN_MX, MX))
                    grabadora.guardar('whois-iana:mx', iana)
                    if respuesta_whois is not None:
                        grabadora.guardar('whois:' + MX, respuesta_whois)
                    with self.assertRaises(FuenteNoResponde):
                        recolectar(SinRed(), modo='reproducir', carpeta=raiz / MX, dominio=MX, whois=SinRed())
                    with mock.patch.object(rdap, 'CARPETA_GRABADAS', raiz):
                        fallida = contrato.ejecutar(cargar('whois'), MX, modo='reproducir', ahora=AHORA)
                    self.assertEqual((fallida.estado, fallida.activos), ('failed', []))

    def test_31_la_reserva_deja_tiempo_al_respaldo(self):
        reloj = [1000.0]

        def lenta(url, timeout):
            self.assertLessEqual(timeout, rdap.TIEMPO_CORRIDA - rdap.RESERVA_WHOIS)
            reloj[0] += rdap.TIEMPO_CORRIDA - rdap.RESERVA_WHOIS   # RDAP se come toda su parte
            raise rdap.SinTiempo('lenta')
        whois = whois_com()
        cliente = rdap.ClienteRdap(descargar=lenta, conversar=whois, cronometro=lambda: reloj[0], dormir=lambda s: None)
        res = rdap.recolectar(DOMINIO, cliente, ahora=AHORA)
        self.assertEqual((res.consultas, res.sin_cobertura, el_dominio(res).atributos['fuente_datos']), (3, [], 'WHOIS'))
        self.assertIn('se acabó el tiempo de la corrida mientras se leía el bootstrap de IANA', res.avisos[0])
        self.assertEqual(whois.plazos, [rdap.TIMEOUT_WHOIS, rdap.TIMEOUT_WHOIS])   # WHOIS tuvo su reserva entera
        # Si una lectura de RDAP se come toda la corrida, no se abre ninguna conexión al puerto 43
        reloj[0] = 1000.0

        def eterna(url, timeout):
            reloj[0] += rdap.TIEMPO_CORRIDA
            raise rdap.SinTiempo('eterna')
        cliente = rdap.ClienteRdap(descargar=eterna, conversar=SinRed(), cronometro=lambda: reloj[0], dormir=lambda s: None)
        res = rdap.recolectar(DOMINIO, cliente, ahora=AHORA)
        self.assertEqual((res.consultas, res.sin_cobertura), (1, ['domain_expiring_soon']))
        self.assertIn('WHOIS: se acabó el tiempo de la corrida antes de consultar el WHOIS de IANA', res.avisos[0])

    def test_32_conversar_tiene_plazo_absoluto_tope_y_cierra_el_socket(self):
        # Normal: manda la consulta con CRLF, junta todo hasta que el servidor cierra y cierra el socket
        red = Red(['1.2.3.4'], [b'Domain Name: ', b'olmardo.com\r\n'])
        with mock.patch.object(rdap, 'socket', red):
            self.assertEqual(CONVERSAR('whois.mx', MX, 10, Cronometro(1)), b'Domain Name: olmardo.com\r\n')
        [s] = red.sockets
        self.assertEqual((s.enviado, s.cerrado, red.pedidas), (MX.encode() + b'\r\n', True, [('whois.mx', 43, 1)]))
        self.assertEqual(s.plazos, [8, 7, 6, 5, 4])   # se recalcula antes de connect, sendall y cada recv
        # Un servidor que manda de a poco no pasa del plazo absoluto, y el socket se cierra
        red = Red(['1.2.3.4'], [b'x'] * 100)
        with mock.patch.object(rdap, 'socket', red), self.assertRaises(rdap.SinTiempo):
            CONVERSAR('whois.mx', MX, 10, Cronometro(1))
        self.assertTrue(red.sockets[0].cerrado)
        # Más de MAX_BYTES_WHOIS: ValueError, y el socket se cierra
        red = Red(['1.2.3.4'], [b'x' * rdap.BLOQUE] * 3)
        with mock.patch.object(rdap, 'socket', red), self.assertRaises(ValueError):
            CONVERSAR('whois.mx', MX, 10, Cronometro(0))
        self.assertTrue(red.sockets[0].cerrado)
        # La primera dirección rechaza: la segunda con lo que queda. Nunca más de MAX_DIRECCIONES
        red = Red(['1.2.3.4', '5.6.7.8', '9.9.9.10'], [b'ok'], caidas={'1.2.3.4'})
        with mock.patch.object(rdap, 'socket', red):
            self.assertEqual(CONVERSAR('whois.mx', MX, 10, Cronometro(0)), b'ok')
        self.assertEqual([s.cerrado for s in red.sockets], [True, True])
        red = Red(['1.2.3.4', '5.6.7.8', '9.9.9.10'], caidas={'1.2.3.4', '5.6.7.8', '9.9.9.10'})
        with mock.patch.object(rdap, 'socket', red), self.assertRaises(ConnectionRefusedError):
            CONVERSAR('whois.mx', MX, 10, Cronometro(0))
        self.assertEqual(len(red.sockets), rdap.MAX_DIRECCIONES)
        # Un nombre que resuelve a IP privadas o de la nube no abre ningún socket
        red = Red(['127.0.0.1', '10.0.0.1', '169.254.169.254', 'fe80::1%eth0'])
        with mock.patch.object(rdap, 'socket', red), self.assertRaises(rdap.RespuestaIlegible):
            CONVERSAR('whois.mx', MX, 10, Cronometro(0))
        self.assertEqual(red.sockets, [])
        # El plazo también cubre getaddrinfo, que se queda colgado en su hilo
        suelta = threading.Event()
        red = Red(['1.2.3.4'], resolver=lambda: suelta.wait(30))
        try:
            inicio = time.monotonic()
            with mock.patch.object(rdap, 'socket', red), self.assertRaises(rdap.SinTiempo):
                CONVERSAR('whois.mx', MX, 0.2)
            self.assertLess(time.monotonic() - inicio, 5)
            self.assertEqual(red.sockets, [])
        finally:
            suelta.set()

    def test_33_conversar_reparte_el_plazo_y_salta_la_familia_que_no_hay(self):
        # La primera dirección descarta los SYN: su connect gasta solo su parte y la segunda se prueba con el resto
        reloj = [1000.0]
        red = Red(['2600::1', '1.2.3.4'], [b'ok'], colgadas={'2600::1'}, reloj=reloj)
        with mock.patch.object(rdap, 'socket', red):
            self.assertEqual(CONVERSAR('whois.mx', MX, 10, lambda: reloj[0]), b'ok')
        primera, segunda = red.sockets
        self.assertEqual((primera.plazos, segunda.plazos[0]), ([5], 5))
        self.assertEqual([s.cerrado for s in red.sockets], [True, True])
        # La última recibe todo lo que queda: si la primera rechaza de inmediato, la segunda tiene el plazo entero
        red = Red(['1.2.3.4', '5.6.7.8', '9.9.9.10'], [b'ok'], caidas={'1.2.3.4'})
        with mock.patch.object(rdap, 'socket', red):
            self.assertEqual(CONVERSAR('whois.mx', MX, 10, Cronometro(0)), b'ok')
        self.assertEqual([s.plazos[0] for s in red.sockets], [5, 10])
        # Las dos colgadas: TimeoutError (se reintenta) sin pasar del plazo de la conversación
        reloj = [1000.0]
        red = Red(['2600::1', '1.2.3.4'], colgadas={'2600::1', '1.2.3.4'}, reloj=reloj)
        with mock.patch.object(rdap, 'socket', red), self.assertRaises(TimeoutError):
            CONVERSAR('whois.mx', MX, 10, lambda: reloj[0])
        self.assertEqual(reloj[0], 1010)
        # Sin IPv6 en el kernel, socket(AF_INET6) falla: se pasa a la IPv4 y solo se cierra el socket que sí se creó
        red = Red(['2600::1', '1.2.3.4'], [b'ok'], sin_familia={10})
        with mock.patch.object(rdap, 'socket', red):
            self.assertEqual(CONVERSAR('whois.mx', MX, 10, Cronometro(0)), b'ok')
        [s] = red.sockets
        self.assertEqual((s.plazos[0], s.cerrado), (10, True))
        red = Red(['2600::1', '2600::2'], sin_familia={10})
        with mock.patch.object(rdap, 'socket', red), self.assertRaises(OSError):
            CONVERSAR('whois.mx', MX, 10, Cronometro(0))
        self.assertEqual(red.sockets, [])

    def test_34_un_valor_de_contacto_no_se_lee_como_otra_linea(self):
        # Sin la línea 'Registrar' del registro, lo que venga dentro de un contacto sería el registrador (validos[0])
        sin_registrador = WHOIS_MX.replace('Registrar:         Registrador de Prueba MX\r\n', '')
        tras_dominio = 'Domain Name:       acme-demo.com.mx\r\n'
        casos = {
            'U+2028 en la organización': (sin_registrador.replace(tras_dominio, tras_dominio + 'Registrant Organization: '
                                          'Persona Registrante Falsa Registrar: Persona Registrante Falsa, tel '
                                          '+52.8180000005\r\n')).encode('utf-8'),
            '\\x85 en la calle, leído como latin-1': (sin_registrador.replace(tras_dominio, tras_dominio
                                                      + 'Registrant Street: Calle Falsa 123 \x85Registrar: Persona '
                                                      'Registrante Falsa\r\n')).encode('latin-1'),
        }
        for caso, cuerpo in casos.items():
            with self.subTest(caso=caso):
                self.assertNotIn('registrador', rdap.reducir_whois(rdap._texto_whois(cuerpo), MX))
                with tempfile.TemporaryDirectory() as d:
                    carpeta = Path(d) / MX
                    res = recolectar(HttpSimulado(bootstrap=SIN_MX, dominios={}), modo='grabar', carpeta=carpeta,
                                     nueva=True, dominio=MX, whois=whois_mx(respuesta_mx=cuerpo))
                    grabado = ''.join(p.read_text(encoding='utf-8') for p in carpeta.glob('*.json'))
                self.assertEqual(el_dominio(res).atributos['registrador'], NO)
                resultado = json.dumps(res.a_dict(), ensure_ascii=False)
                for dato in CONTACTOS + ('8180000005',):
                    self.assertNotIn(dato, resultado)
                    self.assertNotIn(dato, grabado)
        # Ningún otro separador de splitlines() parte la línea; el CRLF de RFC 3912 sí, sin dejar el '\r'
        for separador in ('\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\x85', ' ', ' '):
            with self.subTest(separador=repr(separador)):
                texto = ('Domain Name: OLMARDO.COM\r\nRegistrant Organization: Persona Registrante Falsa' + separador
                         + 'Registrar: Persona Registrante Falsa\r\nName Server: ADA.NS.CLOUDFLARE.COM\r\n')
                self.assertEqual(rdap.reducir_whois(texto, DOMINIO),
                                 {'dominio': DOMINIO, 'servidores_nombre': ['ada.ns.cloudflare.com']})

    def test_35_nat64_hacia_una_ipv4_interna_no_es_publica(self):
        for ip in ('64:ff9b::7f00:1', '64:ff9b::a9fe:a9fe', '64:ff9b::a00:1', '64:ff9b::c0a8:101',
                   '64:ff9b:1::7f00:1', '2002:7f00:1::1', '::ffff:127.0.0.1'):
            with self.subTest(ip=ip):
                self.assertFalse(rdap._publica(ip))
        # NAT64 hacia una IPv4 pública sigue sirviendo
        self.assertTrue(rdap._publica('64:ff9b::102:304'))
        self.assertTrue(rdap._publica('2600::1'))
        red = Red(['64:ff9b::7f00:1', '64:ff9b::a9fe:a9fe'])
        with mock.patch.object(rdap, 'socket', red), self.assertRaises(rdap.RespuestaIlegible):
            CONVERSAR('whois.mx', MX, 10, Cronometro(0))
        self.assertEqual(red.sockets, [])

    def test_36_un_vencimiento_de_whois_sin_hora_vale_todo_ese_dia(self):
        # El 5 nov a las 01:00Z (4 nov en Monterrey) el registro de whois.mx ('Expiration Date: 2026-11-05') sigue vigente
        borde = datetime(2026, 11, 5, 1, 0, tzinfo=timezone.utc)
        res = recolectar(HttpSimulado(bootstrap=SIN_MX, dominios={}), dominio=MX, whois=whois_mx(), ahora=borde)
        self.assertEqual(res.avisos, [rdap.CON_WHOIS % ('whois.mx', rdap.SIN_RDAP_TLD)])
        self.assertEqual(el_dominio(res).atributos['vence'], '2026-11-05T23:59:59Z')
        [h] = res.hallazgos
        self.assertEqual((h.codigo, h.titulo), ('domain_expiring_soon',
                                                'El registro de acme-demo.com.mx vence en menos de un día'))
        # Se graba ya con la hora y al reproducir da lo mismo
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / MX
            recolectar(HttpSimulado(bootstrap=SIN_MX, dominios={}), modo='grabar', carpeta=carpeta, nueva=True,
                       dominio=MX, whois=whois_mx(), ahora=borde)
            grabada = json.loads((carpeta / 'whois_acme-demo.com.mx.json').read_text(encoding='utf-8'))['datos']
            otra = recolectar(SinRed(), modo='reproducir', carpeta=carpeta, dominio=MX, whois=SinRed(), ahora=borde)
        self.assertEqual(grabada['vence'], '2026-11-05T23:59:59Z')
        self.assertEqual((otra.activos, otra.hallazgos, otra.avisos), (res.activos, res.hallazgos, res.avisos))
        # Ya el 6 nov venció
        res = recolectar(HttpSimulado(bootstrap=SIN_MX, dominios={}), dominio=MX, whois=whois_mx(),
                         ahora=datetime(2026, 11, 6, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(res.hallazgos, [])
        self.assertIn('venció el 2026-11-05 (hace menos de un día)', res.avisos[1])
        # Solo 'vence' y solo sin hora: con hora queda igual, el registro sin hora sigue a las 00:00 y RDAP no cambia
        reducido = rdap.reducir_whois('Domain Name: OLMARDO.COM\nCreation Date: 2019-05-12\n'
                                      'Registry Expiry Date: 2026-11-05T00:00:00Z\n', DOMINIO)
        self.assertEqual((reducido['registrado'], reducido['vence']), ('2019-05-12T00:00:00Z', '2026-11-05T00:00:00Z'))
        atributos, _ = rdap.leer_rdap(respuesta(vence='2026-11-05'), DOMINIO)
        self.assertEqual(atributos['vence'], '2026-11-05T00:00:00Z')


if __name__ == '__main__':
    unittest.main()
