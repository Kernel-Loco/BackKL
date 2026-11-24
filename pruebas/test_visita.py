"""Pruebas sin red de la visita web de la actividad 6 (cirdan/recolectores/visita.py, #18, RC-46).

Los sitios se simulan con ClienteWeb(visitar=...), Cert Spotter, endoflife.date y la NVD con ClienteWeb(descargar=...)
y el A con el ResolvedorSimulado de test_shodan. Las conexiones de transporte.py se prueban con resolver y socket
cambiados: nada sale a la red.

Uso, desde la raíz del repo:
  python -m unittest pruebas/test_visita.py
"""
import contextlib
import email.message
import importlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))  # también corre como python pruebas/test_visita.py
from pruebas import test_rdap, test_subfinder  # noqa: E402
from pruebas.test_geoip import bases as bases_geo  # noqa: E402
from pruebas.test_huellas import FIXTURES_BORDE, fixture  # noqa: E402
from pruebas.test_shodan import ResolvedorSimulado, a, error_http, paginas  # noqa: E402
from cirdan.recolectores import REGISTRO, contrato, portada, rdap, shodan, transporte, visita  # noqa: E402

DOMINIO = 'acme-demo.mx'
WWW = 'www.acme-demo.mx'
IP = '104.21.48.10'
AHORA = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
COOKIE = 'CIRDAN_FAKE_cookie_de_sesion_1234'
SEMILLA = RAIZ / 'db' / 'semillas' / '012_visita_web.sql'
MIGRACION = RAIZ / 'db' / 'migraciones' / '014_cves_desde_recolectores.sql'
CVES_NGINX = ['CVE-2098-12345', 'CVE-2099-0101', 'CVE-2099-0102']


def pagina_nginx(estado=200):
    """nginx 1.18.0 sin marca de distribución, con una cookie de sesión que nunca se guarda."""
    return {'estado': estado, 'cabeceras': [['Server', 'nginx/1.18.0'], ['Content-Type', 'text/html; charset=utf-8'],
                                            ['Set-Cookie', 'PHPSESSID=%s; Path=/; HttpOnly' % COOKIE]],
            'cuerpo': '<html><head><title>Acme</title></head><body>hola</body></html>'}


class Apis:
    """Hace las veces de _descargar_api(url, timeout): Cert Spotter da `ct` en orden, endoflife.date y la NVD dan lo
    de `eol` y `nvd` (un entero es un error HTTP)."""

    def __init__(self, ct=None, eol=None, nvd=None):
        self.ct = [[]] if ct is None else list(ct)
        self.eol = fixture('eol_nginx') if eol is None else eol
        self.nvd = fixture('nvd_nginx_1.18.0') if nvd is None else nvd
        self.urls = []

    def __call__(self, url, timeout):
        self.urls.append(url)
        servidor = urlsplit(url).hostname   # el nombre exacto del servidor, no un trozo de la URL
        if servidor == 'api.certspotter.com':
            respuesta = self.ct.pop(0) if self.ct else []
        elif servidor == 'endoflife.date':
            respuesta = self.eol
        elif servidor == 'services.nvd.nist.gov':
            respuesta = self.nvd
        else:
            raise AssertionError('consulta inesperada: %s' % url)
        if isinstance(respuesta, int):
            raise error_http(url, respuesta)
        return json.dumps(respuesta).encode()


class Sitios:
    """Hace las veces de _visitar(url, timeout): `paginas` da la respuesta de cada URL (ya en la forma de
    limpiar_visita). Una URL que no está es un 443 cerrado."""

    def __init__(self, paginas_):
        self.paginas, self.urls = paginas_, []

    def __call__(self, url, timeout):
        self.urls.append(url)
        return self.paginas.get(url, {'rechazada': True})


def correr(sitios, zona=None, apis=None, modo='vivo', carpeta=None, ahora=None):
    dormidas = []
    cliente = visita.ClienteWeb(modo=modo, carpeta=carpeta or visita.carpeta_de(DOMINIO), visitar=Sitios(sitios),
                                descargar=apis or Apis(), resolver=ResolvedorSimulado({DOMINIO: a(IP)} if zona is None else zona),
                                cronometro=lambda: 0.0, dormir=dormidas.append, nueva=(modo == 'grabar'))
    with mock.patch.object(visita.geoip, 'bases_por_omision', return_value=bases_geo()):   # sin datos/geo
        res = visita.recolectar(DOMINIO, cliente, ahora=ahora or AHORA)
    return res, cliente, dormidas


def activo(res, valor):
    return next(x for x in res.activos if x.valor == valor)


class Visita(unittest.TestCase):
    def test_1_redireccion_dentro_del_dominio_huellas_soporte_y_cve(self):
        """La raíz manda a www, que tiene nginx 1.18.0: un outdated_software y tres known_vulnerability en www."""
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            res, cliente, dormidas = correr(
                {'https://%s/' % DOMINIO: {'redirige': 'https://%s/' % WWW, 'codigo': 301},
                 'https://%s/' % WWW: pagina_nginx()},
                zona={DOMINIO: a(IP), WWW: a(IP)}, apis=Apis(ct=paginas(WWW)), modo='grabar', carpeta=carpeta)
            grabado = ''.join(p.read_text(encoding='utf-8') for p in carpeta.glob('*.json'))
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(contrato.validar(res, codigos=set(visita.CODIGOS)), [])
        self.assertEqual(sorted(h.codigo for h in res.hallazgos),
                         ['known_vulnerability'] * 3 + ['outdated_software', 'server_version_disclosed'])
        self.assertEqual({(h.activo, tuple(h.partes)) for h in res.hallazgos}, {(WWW, (WWW,))})
        self.assertTrue(all(h.evidencia['url'] == 'https://%s/' % WWW for h in res.hallazgos))
        self.assertEqual([f['cve_id'] for f in res.cves], CVES_NGINX)
        self.assertEqual(sorted(h.evidencia['cve'] for h in res.hallazgos if h.codigo == 'known_vulnerability'),
                         CVES_NGINX)
        # Todo revisado: nada parcial
        self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura), (None, None, []))
        self.assertEqual(activo(res, DOMINIO).atributos['web']['redirige_a'], WWW)
        web = activo(res, WWW).atributos
        self.assertEqual((web['web']['estado'], web['web']['estado_http']), ('visitado', 200))
        self.assertIn({'nombre': 'Nginx', 'version': '1.18.0', 'categorias': mock.ANY}, web['tecnologias'])
        # Ritmo fijo: una pausa antes de la segunda petición a un sitio, ninguna antes de la primera
        self.assertEqual(cliente.visitar.urls, ['https://%s/' % DOMINIO, 'https://%s/' % WWW])
        self.assertEqual(dormidas, [1])   # PAUSA_SITIO, literal para que la prueba vea si cambia
        self.assertLessEqual(res.consultas, visita.MAX_CONSULTAS)
        # El valor de la cookie no queda en la grabación ni en lo que se guarda; el nombre sí
        self.assertTrue(grabado)
        self.assertNotIn(COOKIE, grabado)
        self.assertIn('PHPSESSID=', grabado)
        self.assertNotIn(COOKIE, json.dumps([x.atributos for x in res.activos]))
        self.assertNotIn(COOKIE, json.dumps([h.evidencia for h in res.hallazgos]))

    def test_2_redirecciones_que_no_se_siguen(self):
        raiz = 'https://%s/' % DOMINIO
        casos = (
            ('http', {raiz: {'redirige': 'http://%s/' % DOMINIO, 'codigo': 301}}, 'no_https'),
            ('otro puerto', {raiz: {'redirige': 'https://%s:8443/' % DOMINIO, 'codigo': 302}}, 'no_https'),
            ('ilegible', {raiz: {'redirige': None, 'codigo': 302}}, 'ilegible'),
            ('más de 3', {raiz: {'redirige': raiz + 'a', 'codigo': 302},
                          raiz + 'a': {'redirige': raiz + 'b', 'codigo': 302},
                          raiz + 'b': {'redirige': raiz + 'c', 'codigo': 302},
                          raiz + 'c': {'redirige': raiz + 'd', 'codigo': 302}}, 'redirecciones'),
        )
        for nombre, sitios, motivo in casos:
            with self.subTest(nombre):
                res, cliente, _ = correr(sitios)
                self.assertEqual(res.estado, 'succeeded', res.error)
                self.assertEqual(res.sin_cobertura, list(visita.CODIGOS))
                self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS[motivo])
                self.assertNotIn('tecnologias', activo(res, DOMINIO).atributos)
                self.assertLessEqual(len(cliente.visitar.urls), 1 + visita.MAX_REDIRECCIONES)
                self.assertTrue(all(u.startswith('https://%s/' % DOMINIO) for u in cliente.visitar.urls))

    def test_3_a_otro_dominio_no_se_sigue_y_cuenta_como_revisado(self):
        res, cliente, _ = correr({'https://%s/' % DOMINIO: {'redirige': 'https://www.otra-empresa.com/', 'codigo': 301}})
        self.assertEqual(cliente.visitar.urls, ['https://%s/' % DOMINIO])
        self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura, res.hallazgos), (None, None, [], []))
        self.assertEqual(activo(res, DOMINIO).atributos['web'],
                         {'estado': 'redirige', 'redirige_a_otro_dominio': 'www.otra-empresa.com', 'fuente': 'web'})

    def test_4_reto_del_waf_queda_sin_revisar(self):
        reto = fixture('cloudflare_reto_403', FIXTURES_BORDE)
        res, _, _ = correr({'https://%s/' % DOMINIO: visita.limpiar_visita(
            {k: reto[k] for k in ('estado', 'cabeceras', 'cuerpo')})})
        # el saludo sí terminó: las dos reglas TLS quedan revisadas con su parte (RC-239)
        self.assertEqual(res.sin_cobertura, [c for c in visita.CODIGOS if c not in visita.CODIGOS_TLS])
        self.assertEqual((res.revisados, res.sin_revisar), (['tls:' + DOMINIO], None))
        self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['reto'])
        self.assertNotIn('tecnologias', activo(res, DOMINIO).atributos)
        self.assertEqual(res.hallazgos, [])

    def test_5_sin_a_o_solo_ip_internas_no_se_visita(self):
        for nombre, zona, estado in (('nxdomain', {}, 'sin_a'),
                                     ('interna', {DOMINIO: a('10.0.0.5', '192.168.1.10')}, 'no_publica'),
                                     ('nat64 de una interna', {DOMINIO: a('64:ff9b::a00:5')}, 'no_publica')):
            with self.subTest(nombre):
                res, cliente, _ = correr({'https://%s/' % DOMINIO: pagina_nginx()}, zona=zona)
                self.assertEqual(cliente.visitar.urls, [])
                self.assertEqual(activo(res, DOMINIO).atributos['web']['estado'], estado)
                self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura), (None, None, []))

    def test_6_la_nvd_con_403_corta_y_no_se_graba(self):
        with tempfile.TemporaryDirectory() as d:
            res, _, _ = correr({'https://%s/' % DOMINIO: pagina_nginx()}, apis=Apis(nvd=403), modo='grabar',
                               carpeta=Path(d) / DOMINIO)
            self.assertEqual(list((Path(d) / DOMINIO).glob('*.json')), [])
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertIn(visita.NO_SE_GRABO, res.avisos)
        # lo de endoflife.date y las cabeceras sí llegó
        self.assertEqual([h.codigo for h in res.hallazgos], ['outdated_software', 'server_version_disclosed'])
        self.assertEqual(res.cves, [])
        self.assertEqual(res.revisados, ['tls:' + DOMINIO])
        self.assertIn(DOMINIO, res.sin_revisar)
        self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['nvd_falta'])
        self.assertTrue(any('403' in x for x in res.avisos), res.avisos)

    def test_7_sitio_que_no_responde_es_una_falla_de_la_corrida(self):
        with tempfile.TemporaryDirectory() as d:
            res, cliente, _ = correr({'https://%s/' % DOMINIO: {'sin_respuesta': 'tiempo'}}, modo='grabar',
                                     carpeta=Path(d) / DOMINIO)
        self.assertEqual(cliente.fallas, 1)
        self.assertIn(visita.NO_SE_GRABO, res.avisos)
        self.assertEqual(res.sin_cobertura, list(visita.CODIGOS))


class Peticion(unittest.TestCase):
    """_visitar y transporte.visitar con abrir() simulado."""

    class Respuesta:
        def __init__(self, estado, cabeceras, cuerpo):
            self.estado, self.cuerpo = estado, cuerpo
            self.headers = email.message.Message()
            for k, v in cabeceras:
                self.headers[k] = v

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def getcode(self):
            return self.estado

        def read(self, n=-1):
            parte, self.cuerpo = (self.cuerpo, b'') if n < 0 else (self.cuerpo[:n], self.cuerpo[n:])
            return parte

    def test_1_user_agent_de_la_carta_y_cookies_sin_valor(self):
        pedidas = []

        def abrir(req, plazo, cronometro, *familia):
            pedidas.append(req)
            self.assertEqual(familia, (socket.AF_INET,))   # la visita va solo por IPv4, como su A
            return self.Respuesta(200, [('Server', 'nginx'), ('Set-Cookie', 'a=%s; Path=/' % COOKIE),
                                        ('Set-Cookie', 'b=2')], 'ñ'.encode('latin-1'))
        with mock.patch.object(transporte, 'abrir', abrir):
            r = visita._visitar('https://%s/' % DOMINIO, 5)
        self.assertEqual(pedidas[0].get_header('User-agent'), contrato.AGENTE)
        self.assertEqual(pedidas[0].get_method(), 'GET')
        self.assertEqual(r['estado'], 200)
        self.assertEqual([v for k, v in r['cabeceras'] if k == 'Set-Cookie'], ['a=', 'b='])
        self.assertNotIn(COOKIE, json.dumps(r))
        for modulo in ('crtsh', 'github', 'shodan', 'rdap', 'visita'):
            self.assertEqual(importlib.import_module('cirdan.recolectores.' + modulo).AGENTE, contrato.AGENTE, modulo)

    def test_1b_user_agent_con_la_version_del_build_y_la_pagina_de_lowtide(self):
        # Comentario 10281 punto 1: la versión real del build y una liga a la página que dice qué es LowTide y a quién
        # escribir. La consulta del TXT (orquestador/txt.py) usa la misma constante y no tiene copia propia.
        # El orquestador pide la base al importarse: txt.py se revisa por su texto (test_txt.py prueba la petición).
        from cirdan import version
        self.assertEqual(contrato.AGENTE, 'lowtide-osint/%s (+https://lowtidesec.com/seguridad)' % version.VERSION)
        self.assertRegex(version.VERSION, r'^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-rc)?$')
        raiz = Path(__file__).resolve().parent.parent
        txt = (raiz / 'cirdan' / 'orquestador' / 'txt.py').read_text(encoding='utf-8')
        self.assertNotIn('AGENTE =', txt)
        self.assertNotIn('lowtide-osint', txt)
        self.assertIn("'User-Agent': contrato.AGENTE", txt)
        self.assertIn('version=VERSION,', (raiz / 'cirdan' / 'api' / 'main.py').read_text(encoding='utf-8'))

    def test_1c_la_seccion_9_de_la_carta_trae_el_user_agent_y_el_ritmo(self):
        # Comentario 10281 puntos 1 y 2: el User-Agent y el ritmo de las actividades 6, 8 y 9 se escriben en la sección
        # 9. Los números salen de las constantes: si cambian aquí, la carta tiene que cambiar.
        from cirdan.recolectores import api_docs, identidad
        raiz = Path(__file__).resolve().parent.parent
        carta = (raiz / 'docs' / 'plantilla_carta_autorizacion.md').read_text(encoding='utf-8')
        seccion = carta.split('## 9. ', 1)[1].split('\n## ', 1)[0]
        self.assertIn('`lowtide-osint/<versión> (+%s)`' % contrato.PAGINA, seccion)
        self.assertIn('(hoy `%s`)' % contrato.AGENTE, seccion)
        self.assertIn('(actividades 6, 8 y 9). LowTide hace una petición a la vez por host, también entre análisis '
                      'distintos que corran al mismo tiempo', seccion)
        self.assertEqual((visita.PAUSA_SITIO, api_docs.PAUSA_RUTA), (1, 1))
        self.assertEqual(seccion.count('una pausa de 1 segundo antes de cada petición, salvo la primera de la '
                                       'corrida'), 3)
        # Actividad 6 (web) y actividad 8 (identity, que visita con visita._recorrer): mismos nombres y redirecciones.
        self.assertEqual((identidad.MAX_SITIOS, identidad.MAX_REDIRECCIONES), (visita.MAX_SITIOS, visita.MAX_REDIRECCIONES))
        self.assertEqual(seccion.count('hasta %d nombres del dominio contando la raíz, y por cada nombre hasta %d '
                                       'redirecciones dentro del dominio' % (visita.MAX_SITIOS, visita.MAX_REDIRECCIONES)), 2)
        por_corrida = visita.MAX_SITIOS * (1 + visita.MAX_REDIRECCIONES)
        self.assertEqual(seccion.count('El tope es de %d peticiones a los sitios del dominio por corrida' % por_corrida), 2)
        self.assertEqual(api_docs.MAX_SITIOS, visita.MAX_SITIOS)
        self.assertIn('sus %d rutas fijas de documentación' % len(api_docs.RUTAS), seccion)
        rutas = api_docs.MAX_SITIOS * len(api_docs.RUTAS)
        self.assertIn('El tope es de %d peticiones a los sitios del dominio por corrida' % rutas, seccion)
        # Cada fuente que falla entera se vuelve a correr a 1, 5 y 25 minutos (contrato.siguiente_estado): el tope por
        # análisis es el de una corrida por el número de corridas (RC-46, H3 de la revisión).
        corridas = contrato.MAX_INTENTO + 1
        esperas = [int(e.total_seconds() // 60) for e in contrato.ESPERAS_REINTENTO]
        self.assertEqual((corridas, esperas), (4, [1, 5, 25]))
        self.assertIn('la vuelve a correr hasta %d veces, a los 1, 5 y 25 minutos' % contrato.MAX_INTENTO, seccion)
        self.assertIn('el tope por análisis es de %d peticiones en la actividad 6, %d en la 8 y %d en la 9'
                      % (corridas * por_corrida, corridas * por_corrida, corridas * rutas), seccion)
        # El 80 solo cuando el 443 no conectó (visita._recorrer y _http), sin seguir sus redirecciones.
        self.assertIn('pide una vez http://<nombre>/ en el puerto 80 y no sigue sus redirecciones', seccion)
        self.assertNotIn('no reintenta', seccion)
        self.assertNotIn('github.com/Kernel-Loco', carta)

    def test_2_un_403_es_una_respuesta_y_el_cuerpo_se_corta(self):
        def abrir(req, plazo, cronometro, *_):
            raise urllib.error.HTTPError(req.full_url, 403, 'Forbidden', email.message.Message(),
                                         __import__('io').BytesIO(b'x' * (visita.MAX_BYTES_SITIO + 10)))
        with mock.patch.object(transporte, 'abrir', abrir):
            r = visita._visitar('https://%s/' % DOMINIO, 5)
        self.assertEqual((r['estado'], r['cortado'], len(r['cuerpo'])), (403, True, visita.MAX_BYTES_SITIO))

    def test_2b_un_500_con_pagina_de_depuracion_se_lee_con_el_mismo_tope(self):
        """Punto 3 de RC-228: el cuerpo del HTTPError de un 500 se lee con el tope de una 200 y portada.py lo ve."""
        werkzeug = pagina_portada('werkzeug_500')['cuerpo'].encode('utf-8')
        for cuerpo, cortado in ((werkzeug, False), (werkzeug + b' ' * visita.MAX_BYTES_SITIO, True)):
            with self.subTest(cortado=cortado):
                def abrir(req, plazo, cronometro, *_):
                    raise urllib.error.HTTPError(req.full_url, 500, 'Internal Server Error',
                                                 email.message.Message(), __import__('io').BytesIO(cuerpo))
                with mock.patch.object(transporte, 'abrir', abrir):
                    r = visita._visitar('https://%s/' % DOMINIO, 5)
                self.assertEqual((r['estado'], r['cortado']), (500, cortado))
                self.assertLessEqual(len(r['cuerpo']), visita.MAX_BYTES_SITIO)
                self.assertEqual([v['firma'] for v in portada.revisar(r['estado'], r['cuerpo'])], ['werkzeug'])

    def test_3_motivos_de_lo_que_no_termino(self):
        casos = ((urllib.error.URLError(transporte.NoPublica('x')), {'sin_respuesta': 'no_publica'}),
                 (urllib.error.URLError(ssl.SSLCertVerificationError('x')),
                  {'sin_respuesta': 'certificado', 'verify_code': None}),
                 (urllib.error.URLError(ConnectionRefusedError()), {'rechazada': True}),
                 (urllib.error.URLError(OSError('x')), {'sin_respuesta': 'red'}),
                 (urllib.error.URLError(ssl.SSLError(1, '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]')),
                  {'sin_respuesta': 'tls'}),
                 (ssl.SSLError(1, '[SSL: UNSUPPORTED_PROTOCOL]'), {'sin_respuesta': 'tls'}),
                 (urllib.error.URLError(ssl.SSLEOFError(8, 'EOF occurred in violation of protocol')),
                  {'sin_respuesta': 'red'}),
                 (transporte.PlazoVencido('x'), {'sin_respuesta': 'tiempo'}),
                 (transporte.SinConexion('x'), {'sin_respuesta': 'tiempo', 'al_conectar': True}),
                 (transporte.Redirigida(302, DOMINIO, 'https://%s/x' % WWW),
                  {'redirige': 'https://%s/x' % WWW, 'codigo': 302}))
        for error, esperado in casos:
            with self.subTest(type(error).__name__), mock.patch.object(
                    transporte, 'abrir', mock.Mock(side_effect=error)):
                self.assertEqual(visita._visitar('https://%s/' % DOMINIO, 5), esperado)

    def test_4_siguiente_arma_la_url_dentro_del_dominio(self):
        self.assertEqual(visita._siguiente('https://WWW.Acme-Demo.mx:443/a b?x=ñ#f', DOMINIO),
                         ('https://www.acme-demo.mx/a%20b?x=%C3%B1', None))
        self.assertEqual(visita._siguiente('https://usuario@www.acme-demo.mx/', DOMINIO),
                         ('https://www.acme-demo.mx/', None))
        self.assertEqual(visita._siguiente('https://acme-demo.mx.evil.com/', DOMINIO), (None, None))
        self.assertEqual(visita._siguiente('https://%s/' % DOMINIO + 'a' * visita.MAX_URL, DOMINIO),
                         (None, 'ilegible'))

    def test_5_limpiar_visita_rechaza_formas_raras(self):
        for malo in (None, [], {'estado': '200', 'cabeceras': [], 'cuerpo': ''},
                     {'estado': 200, 'cabeceras': [['a']], 'cuerpo': ''}, {'sin_respuesta': 'otro'},
                     {'redirige': 3}):
            with self.subTest(malo), self.assertRaises(ValueError):
                visita.limpiar_visita(malo)


class Conectar(unittest.TestCase):
    """transporte._Conexion._conectar: solo se conecta a las direcciones públicas de la lista que revisó."""

    class Socket:
        conectadas = []

        def __init__(self, *_):
            pass

        def settimeout(self, _):
            pass

        def connect(self, destino):
            self.conectadas.append(destino[0])

        def close(self):
            pass

    def conectar(self, direcciones, **otros):
        self.Socket.conectadas = []
        conexion = transporte._Conexion(WWW, plazo=time.monotonic() + 30, cronometro=time.monotonic, **otros)
        info = [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443))
                for ip in direcciones]
        with mock.patch.object(transporte, 'resolver', lambda host, puerto, espera: info), \
                mock.patch.object(transporte.socket, 'socket', self.Socket):
            return conexion._conectar((WWW, 443))

    def test_1_solo_internas_lanza_no_publica(self):
        for ips in (['10.0.0.5'], ['127.0.0.1', '169.254.169.254'], ['64:ff9b::a00:5'], ['::1'], ['100.64.0.1']):
            with self.subTest(ips), self.assertRaises(transporte.NoPublica):
                self.conectar(ips)
            self.assertEqual(self.Socket.conectadas, [])

    def test_2_mezcla_se_conecta_solo_a_la_publica(self):
        self.conectar(['10.0.0.5', IP, '192.168.0.1'])
        self.assertEqual(self.Socket.conectadas, [IP])

    def test_3_no_publica_es_un_oserror_y_rdap_usa_la_misma(self):
        self.assertTrue(issubclass(transporte.NoPublica, OSError))
        self.assertIs(rdap._publica, transporte.publica)
        self.assertIs(rdap.NAT64, transporte.NAT64)
        self.assertTrue(transporte.publica(IP))
        self.assertFalse(transporte.publica('64:ff9b::7f00:1'))

    def test_4_con_familia_ipv4_una_aaaa_de_nat64_propio_no_se_usa(self):
        """Un prefijo de NAT64 propio de la red (aquí 2a00:1450:64::/96 con 10.0.0.5 dentro) se ve como una IPv6
        pública: publica() no lo puede saber. Con familia=AF_INET, que es lo que pide la visita, no se usa."""
        nat64 = '2a00:1450:64::a00:5'
        self.assertTrue(transporte.publica(nat64))
        self.conectar([nat64, IP], familia=socket.AF_INET)
        self.assertEqual(self.Socket.conectadas, [IP])
        with self.assertRaises(OSError):
            self.conectar([nat64], familia=socket.AF_INET)
        self.assertEqual(self.Socket.conectadas, [])
        with self.assertRaises(transporte.NoPublica):   # de las IPv4, ninguna pública
            self.conectar([nat64, '10.0.0.5'], familia=socket.AF_INET)
        self.conectar([nat64, IP])   # sin familia, como las fuentes que piden a un servidor fijo. RDAP pide AF_INET
        self.assertEqual(self.Socket.conectadas, [nat64])

    def test_5_ninguna_direccion_interna_abre_un_socket(self):
        """Las de #181 (RC-299), una por una: loopback, redes privadas, metadatos de la nube, CGNAT, NAT64 hacia el
        loopback y una IPv4 mapeada en IPv6. 1.0.0.1, la del TXT por DoH (orquestador/txt.py), sí pasa."""
        for ip in ('127.0.0.1', '::1', '10.0.0.1', '172.16.0.1', '192.168.0.1', '169.254.169.254', '100.64.0.1',
                   '64:ff9b::7f00:1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '0.0.0.0', 'fec0::1',
                   '::ffff:0:7f00:1', '::ffff:0:a9fe:a9fe'):
            with self.subTest(ip), self.assertRaises(transporte.NoPublica):
                self.conectar([ip])
            self.assertEqual(self.Socket.conectadas, [], ip)
        self.conectar(['1.0.0.1'])
        self.assertEqual(self.Socket.conectadas, ['1.0.0.1'])

    def test_6_un_puerto_fuera_de_la_lista_no_resuelve_ni_abre_un_socket(self):
        self.assertEqual(transporte.PUERTOS, frozenset({443}))
        self.assertTrue(issubclass(transporte.PuertoNoPermitido, OSError))
        self.Socket.conectadas = []
        resueltos = []
        with mock.patch.object(transporte, 'resolver', lambda *a: resueltos.append(a) or []), \
                mock.patch.object(transporte.socket, 'socket', self.Socket):
            for puerto in (80, 6379, 5432, 8443, 0, None):
                conexion = transporte._Conexion(WWW, plazo=time.monotonic() + 30, cronometro=time.monotonic)
                with self.subTest(puerto), self.assertRaises(transporte.PuertoNoPermitido):
                    conexion._conectar((WWW, puerto))
            # Por las dos entradas, con la URL completa: urllib entrega el error como la razón de un URLError
            for pedir in (lambda r: transporte.descargar(r, time.monotonic() + 30, 1000),
                          lambda r: transporte.visitar(r, time.monotonic() + 30, 1000)):
                for url in ('https://%s:6379/' % WWW, 'https://%s:80/' % WWW):
                    with self.subTest(url), self.assertRaises(urllib.error.URLError) as error:
                        pedir(urllib.request.Request(url))
                    self.assertIsInstance(error.exception.reason, transporte.PuertoNoPermitido)
        self.assertEqual((resueltos, self.Socket.conectadas), ([], []))


def pagina_reservas():
    """Como reservas.olmardo.com (hallazgos_esperados.md, fila 12): solo el 80, con Server y versión."""
    return {'estado': 200, 'cabeceras': [['Server', 'nginx/1.24.0 (Ubuntu)'],
                                         ['Content-Type', 'text/html; charset=utf-8']],
            'cuerpo': '<html><head><title>Reservas (sitio de pruebas)</title></head><body>pruebas</body></html>'}


class Http(unittest.TestCase):
    """El 80 por http cuando el 443 no da la página (RC-46, RC-165), y server_version_disclosed (HX1)."""
    RAIZ_HTTPS, RAIZ_HTTP = 'https://%s/' % DOMINIO, 'http://%s/' % DOMINIO
    NO_CONECTA = dict(sin_respuesta='tiempo', al_conectar=True)   # transporte.SinConexion

    def test_1_443_cerrado_o_sin_conectar_y_pagina_en_el_80(self):
        for nombre, https in (('rechazada', {'rechazada': True}), ('no conecta', self.NO_CONECTA)):
            with self.subTest(nombre), tempfile.TemporaryDirectory() as d:
                res, cliente, _ = correr({self.RAIZ_HTTPS: https, self.RAIZ_HTTP: pagina_reservas()},
                                         apis=Apis(eol=404, nvd={'totalResults': 0, 'vulnerabilities': []}),
                                         modo='grabar', carpeta=Path(d) / DOMINIO)
                self.assertEqual(cliente.visitar.urls, [self.RAIZ_HTTPS, self.RAIZ_HTTP])
                self.assertEqual(res.estado, 'succeeded', res.error)
                self.assertEqual(contrato.validar(res, codigos=set(visita.CODIGOS)), [])
                web = activo(res, DOMINIO).atributos
                self.assertEqual(web['web'], {'estado': 'visitado', 'url': self.RAIZ_HTTP, 'estado_http': 200,
                                              'protocolo': 'http', 'fuente': 'web'})
                self.assertIn('Nginx', [x['nombre'] for x in web['tecnologias']])
                self.assertEqual([h.codigo for h in res.hallazgos], ['server_version_disclosed'])
                h = res.hallazgos[0]
                self.assertEqual((h.activo, h.partes, h.severidad), (DOMINIO, [DOMINIO], 'low'))
                self.assertEqual(h.evidencia['cabeceras'], [{'cabecera': 'Server', 'valor': 'nginx/1.24.0 (Ubuntu)'}])
                self.assertEqual(h.evidencia['url'], self.RAIZ_HTTP)
                # El 80 dio la página: la falla del 443 no es de la corrida y la grabación se escribe
                self.assertEqual(cliente.fallas, 0)
                self.assertNotIn(visita.NO_SE_GRABO, res.avisos)
                self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura), (None, None, []))

    def test_2_sin_pagina_en_el_80_queda_lo_del_443(self):
        for nombre, https, http, estado, fallas in (
                ('los dos cerrados', {'rechazada': True}, {'rechazada': True}, 'sin_https', 0),
                ('80 redirige al 443', {'rechazada': True}, {'redirige': self.RAIZ_HTTPS, 'codigo': 301},
                 'sin_https', 0),
                ('443 rechazado y 80 que no conecta', {'rechazada': True}, self.NO_CONECTA, 'sin_https', 0),
                ('443 que no conecta y 80 cerrado', self.NO_CONECTA, {'rechazada': True}, 'sin_respuesta', 1),
                ('ninguno conecta', self.NO_CONECTA, self.NO_CONECTA, 'sin_respuesta', 1)):
            with self.subTest(nombre):
                res, cliente, _ = correr({self.RAIZ_HTTPS: https, self.RAIZ_HTTP: http})
                # La redirección del 80 no se sigue: solo esas dos peticiones
                self.assertEqual(cliente.visitar.urls, [self.RAIZ_HTTPS, self.RAIZ_HTTP])
                self.assertEqual(activo(res, DOMINIO).atributos['web']['estado'], estado)
                self.assertEqual(cliente.fallas, fallas)
                self.assertEqual(res.hallazgos, [])

    def test_3_el_80_solo_se_prueba_en_el_primer_salto(self):
        """Un https que contesta (aunque sea con un error) o una redirección a un 443 cerrado no piden el 80."""
        www = 'https://%s/' % WWW
        res, cliente, _ = correr({self.RAIZ_HTTPS: {'redirige': www, 'codigo': 301}, www: {'sin_respuesta': 'tiempo'}},
                                 zona={DOMINIO: a(IP), WWW: a(IP)})
        self.assertEqual(cliente.visitar.urls, [self.RAIZ_HTTPS, www])
        self.assertEqual(cliente.fallas, 1)
        res, cliente, _ = correr({self.RAIZ_HTTPS: dict(pagina_nginx(), estado=502)})
        self.assertEqual(cliente.visitar.urls, [self.RAIZ_HTTPS])

    def test_4_una_grabacion_de_antes_sin_el_80_queda_como_estaba(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            _, grabo, _ = correr({self.RAIZ_HTTPS: {'rechazada': True}}, modo='grabar', carpeta=carpeta)
            clave_80 = 'sitio:%s:%s' % (DOMINIO, visita.hashlib.sha256(self.RAIZ_HTTP.encode()).hexdigest()[:16])
            grabo.grabadora.archivo(clave_80).unlink()   # como una grabación de antes de RC-46, sin el 80
            res, cliente, _ = correr({}, zona={}, modo='reproducir', carpeta=carpeta)
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(activo(res, DOMINIO).atributos['web']['estado'], 'sin_https')
        self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura), (None, None, []))

    def test_5_server_sin_version_no_da_hallazgo(self):
        for cabeceras in ([['Server', 'nginx']], [['Server', 'cloudflare'], ['X-Powered-By', 'Express']], []):
            with self.subTest(cabeceras):
                pagina = dict(pagina_reservas(), cabeceras=cabeceras + [['Content-Type', 'text/html']])
                res, _, _ = correr({self.RAIZ_HTTPS: pagina}, apis=Apis(eol=404, nvd={'totalResults': 0,
                                                                                      'vulnerabilities': []}))
                self.assertNotIn('server_version_disclosed', [h.codigo for h in res.hallazgos])
                self.assertEqual(res.sin_cobertura, [])

    def test_6_versiones_de_las_cabeceras(self):
        largo = 'Apache/2.4.58 (Unix) ' + 'x' * 400
        self.assertEqual(visita._versiones([['server', 'nginx/1.24.0 (Ubuntu)'], ['X-Powered-By', 'PHP/8.1.2'],
                                            ['Server', 'nginx/1.24.0 (Ubuntu)'], ['Via', '1.1 varnish/6.0'],
                                            ['X-Powered-By', 'ASP.NET'], ['Server', largo]]),
                         [{'cabecera': 'server', 'valor': 'nginx/1.24.0 (Ubuntu)'},
                          {'cabecera': 'X-Powered-By', 'valor': 'PHP/8.1.2'},
                          {'cabecera': 'Server', 'valor': 'nginx/1.24.0 (Ubuntu)'},
                          {'cabecera': 'Server', 'valor': largo[:visita.MAX_VALOR_CABECERA]}])
        # La huella no lleva el valor: otra versión es el mismo hallazgo
        uno, _, _ = correr({self.RAIZ_HTTPS: pagina_reservas()}, apis=Apis(eol=404, nvd={'totalResults': 0,
                                                                                         'vulnerabilities': []}))
        otra = dict(pagina_reservas(), cabeceras=[['Server', 'nginx/1.26.2'], ['Content-Type', 'text/html']])
        dos, _, _ = correr({self.RAIZ_HTTPS: otra}, apis=Apis(eol=404, nvd={'totalResults': 0, 'vulnerabilities': []}))
        huella = lambda r: [h.huella for h in r.hallazgos if h.codigo == 'server_version_disclosed']
        self.assertEqual(huella(uno), huella(dos))
        self.assertEqual(len(huella(uno)), 1)

    def test_7_el_80_solo_por_http_y_solo_en_visitar(self):
        """transporte: http solo al 80 (PUERTOS_HTTP) y solo en visitar(); https al 80 y http a otro puerto no
        resuelven ni abren un socket. descargar() (las API) sigue solo con https."""
        self.assertEqual(transporte.PUERTOS_HTTP, frozenset({80}))
        resueltos, abiertos = [], []
        with mock.patch.object(transporte, 'resolver', lambda *a: resueltos.append(a) or []), \
                mock.patch.object(transporte.socket, 'socket', lambda *a: abiertos.append(a)), \
                mock.patch.object(transporte._ConexionHttp, 'clase_socket', lambda *a: abiertos.append(a)):
            for url in ('http://%s:8080/' % WWW, 'http://%s:443/' % WWW, 'http://%s:6379/' % WWW,
                        'https://%s:80/' % WWW):
                with self.subTest(url), self.assertRaises(urllib.error.URLError) as error:
                    transporte.visitar(urllib.request.Request(url), time.monotonic() + 30, 1000)
                self.assertIsInstance(error.exception.reason, transporte.PuertoNoPermitido)
            with self.assertRaises(ValueError):
                transporte.descargar(urllib.request.Request('http://%s/' % WWW), time.monotonic() + 30, 1000)
        self.assertEqual((resueltos, abiertos), ([], []))

    def test_8_el_80_tampoco_se_conecta_a_ip_internas(self):
        conectadas = []

        class Socket(Conectar.Socket):
            def connect(self, destino):
                conectadas.append(destino[0])
        for ips, lanza in ((['10.0.0.5', '169.254.169.254'], True), (['127.0.0.1', IP], False)):
            conectadas.clear()
            conexion = transporte._ConexionHttp(WWW, plazo=time.monotonic() + 30, cronometro=time.monotonic,
                                               familia=socket.AF_INET)
            info = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 80)) for ip in ips]
            with self.subTest(ips), mock.patch.object(transporte, 'resolver', lambda host, puerto, espera: info), \
                    mock.patch.object(transporte._ConexionHttp, 'clase_socket', Socket):
                if lanza:
                    with self.assertRaises(transporte.NoPublica):
                        conexion._conectar((WWW, 80))
                else:
                    conexion._conectar((WWW, 80))
            self.assertEqual(conectadas, [] if lanza else [IP])

    def test_9_una_falla_pasajera_del_443_no_prueba_el_80(self):
        """Un 443 que conectó y no terminó, o una falla de la red, es una falla de la corrida aunque el 80 tenga una
        página: la grabación no se escribe y el sitio no cambia por el del 80 (conexiones-1, tiempos_y_datos-2)."""
        for nombre, https in (('tiempo', {'sin_respuesta': 'tiempo'}), ('red', {'sin_respuesta': 'red'})):
            with self.subTest(nombre), tempfile.TemporaryDirectory() as d:
                res, cliente, _ = correr({self.RAIZ_HTTPS: https, self.RAIZ_HTTP: pagina_reservas()},
                                         modo='grabar', carpeta=Path(d) / DOMINIO)
                self.assertEqual(cliente.visitar.urls, [self.RAIZ_HTTPS])
                self.assertEqual(cliente.fallas, 1)
                self.assertIn(visita.NO_SE_GRABO, res.avisos)
                self.assertEqual(activo(res, DOMINIO).atributos['web']['estado'], 'sin_respuesta')
                self.assertEqual(res.hallazgos, [])

    def test_10_443_rechazado_y_80_con_falla_pasajera(self):
        """Con el 443 cerrado, un 80 que conectó y no terminó (o una falla de la red) no prueba que no haya sitio: es
        una falla y el sitio queda sin revisar, no 'sin_https' (tiempos_y_datos-1)."""
        for nombre, http in (('tiempo', {'sin_respuesta': 'tiempo'}), ('red', {'sin_respuesta': 'red'})):
            with self.subTest(nombre), tempfile.TemporaryDirectory() as d:
                res, cliente, _ = correr({self.RAIZ_HTTPS: {'rechazada': True}, self.RAIZ_HTTP: http},
                                         modo='grabar', carpeta=Path(d) / DOMINIO)
                self.assertEqual(cliente.visitar.urls, [self.RAIZ_HTTPS, self.RAIZ_HTTP])
                self.assertEqual(cliente.fallas, 1)
                self.assertIn(visita.NO_SE_GRABO, res.avisos)
                web = activo(res, DOMINIO).atributos['web']
                self.assertEqual(web['estado'], 'sin_respuesta')
                self.assertNotEqual(web['estado'], 'sin_https')

    def test_11_sin_tiempo_para_el_80_deja_lo_del_443(self):
        """Si a la corrida ya no le alcanza para el 80, queda 'sin_https' del 443, que ya se sabía, sin cobertura
        parcial por tiempo (conexiones-2)."""
        original = visita.ClienteWeb.sitio

        def sitio(cliente, url, *args, **kw):
            if url.startswith('http://'):
                raise visita.SinTiempo('web: se acabó el tiempo de la corrida antes de visitar %s' % url)
            return original(cliente, url, *args, **kw)
        with mock.patch.object(visita.ClienteWeb, 'sitio', sitio):
            res, cliente, _ = correr({self.RAIZ_HTTPS: {'rechazada': True}})
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(activo(res, DOMINIO).atributos['web']['estado'], 'sin_https')
        self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura), (None, None, []))
        self.assertEqual(cliente.fallas, 0)

    def test_12_el_80_tiene_su_propio_plazo(self):
        """La petición al 80 usa TIMEOUT_HTTP, y 20 sitios con el 443 y el 80 sin conectar caben en la corrida con
        100 s de sobra para Cert Spotter y las A (tiempos_y_datos-3)."""
        plazos = []

        class ConPlazos(Sitios):
            def __call__(self, url, timeout):
                plazos.append(timeout)
                return super().__call__(url, timeout)
        cliente = visita.ClienteWeb(modo='vivo', carpeta=visita.carpeta_de(DOMINIO), cronometro=lambda: 0.0,
                                    dormir=lambda _: None,
                                    descargar=Apis(), resolver=ResolvedorSimulado({DOMINIO: a(IP)}),
                                    visitar=ConPlazos({self.RAIZ_HTTPS: self.NO_CONECTA,
                                                       self.RAIZ_HTTP: pagina_reservas()}))
        _, url, pagina, _ = visita._recorrer(cliente, DOMINIO, DOMINIO)
        self.assertEqual((url, pagina['estado']), (self.RAIZ_HTTP, 200))
        self.assertEqual(plazos, [visita.TIMEOUT_SITIO, visita.TIMEOUT_HTTP])
        peor = 2 * visita.PAUSA_SITIO + visita.TIMEOUT_SITIO + visita.TIMEOUT_HTTP
        self.assertLessEqual(visita.MAX_SITIOS * peor, visita.TIEMPO_CORRIDA - visita.RESERVA_APIS - 100)

    def test_13_sin_conexion_solo_si_ninguna_ip_conecto_a_tiempo(self):
        """transporte: SinConexion cuando cada dirección agotó su plazo al conectar (un puerto que descarta los
        paquetes). Un rechazo en alguna dirección es un rechazo. _visitar lo guarda con al_conectar."""
        def conectar(errores):
            fallas = iter(errores)

            class Socket(Conectar.Socket):
                def connect(self, destino):
                    raise next(fallas)
            conexion = transporte._Conexion(WWW, plazo=time.monotonic() + 30, cronometro=time.monotonic)
            info = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('104.21.48.%d' % i, 443)) for i in range(len(errores))]
            with mock.patch.object(transporte, 'resolver', lambda host, puerto, espera: info), \
                    mock.patch.object(transporte.socket, 'socket', Socket):
                return conexion._conectar((WWW, 443))
        for errores in ([TimeoutError()], [socket.timeout(), TimeoutError()]):
            with self.subTest(errores), self.assertRaises(transporte.SinConexion) as e:
                conectar(errores)
            self.assertIsInstance(e.exception, transporte.PlazoVencido)
        for errores in ([ConnectionRefusedError()], [TimeoutError(), ConnectionRefusedError()],
                        [ConnectionRefusedError(), TimeoutError()], [OSError('red')]):
            with self.subTest(errores), self.assertRaises(OSError) as e:
                conectar(errores)
            self.assertNotIsInstance(e.exception, transporte.SinConexion)
        # La grabación conserva al_conectar solo con tiempo y en True
        self.assertEqual(visita.limpiar_visita(self.NO_CONECTA), self.NO_CONECTA)
        self.assertEqual(visita.limpiar_visita({'sin_respuesta': 'red', 'al_conectar': True}), {'sin_respuesta': 'red'})
        self.assertEqual(visita.limpiar_visita({'sin_respuesta': 'tiempo', 'al_conectar': 'si'}),
                         {'sin_respuesta': 'tiempo'})

    def test_14_cabeceras_con_tope_en_la_grabacion(self):
        """limpiar_visita guarda a lo más MAX_PARES cabeceras de borde.MAX_VALOR + 1 caracteres: borde y huellas no
        leen más, así el análisis no cambia y la grabación no crece a megas (conexiones-4)."""
        corta = 'nginx/1.24.0 (Ubuntu)'
        pagina = dict(pagina_reservas(), cabeceras=[['Server', corta]] + [['X-Relleno-%d' % i, 'x' * 70000]
                                                                         for i in range(150)])
        limpia = visita.limpiar_visita(pagina)
        self.assertEqual(len(limpia['cabeceras']), visita.MAX_PARES)
        self.assertEqual(limpia['cabeceras'][0], ['Server', corta])
        self.assertTrue(all(len(v) == visita.borde.MAX_VALOR + 1 for _, v in limpia['cabeceras'][1:]))
        self.assertEqual(visita.MAX_LARGO_CABECERA, visita.borde.MAX_VALOR + 1)
        # Lo que huellas lee de una cabecera recortada es lo mismo que de la entera: nada de más de MAX_VALOR
        valor = 'Apache/2.4.58 ' + 'y' * 70000
        entera = dict(pagina_reservas(), cabeceras=[['Server', valor]])
        self.assertEqual(visita.limpiar_visita(entera)['cabeceras'][0][1], valor[:visita.borde.MAX_VALOR + 1])

    def test_15_el_socket_plano_acota_cada_lectura_por_el_plazo(self):
        """_SocketPlano: un 80 que manda las cabeceras de a un byte no estira la visita más allá de su plazo
        (conexiones-3). Sin red: socket.socketpair()."""
        import threading

        cliente_sock, servidor_sock = socket.socketpair()

        class Plano(transporte._SocketPlano):
            def setsockopt(self, *_):   # http.client pide TCP_NODELAY, que AF_UNIX no tiene
                pass
        plano = Plano(fileno=cliente_sock.detach())
        alto = threading.Event()

        def goteo():
            try:
                servidor_sock.recv(65536)
                servidor_sock.sendall(b'HTTP/1.1 200 OK\r\nX-Lento: ')
                for _ in range(80):   # 4 s de goteo si nadie corta
                    if alto.wait(0.05):
                        break
                    servidor_sock.sendall(b'a')
            except OSError:
                pass
            finally:
                servidor_sock.close()
        hilo = threading.Thread(target=goteo, daemon=True)
        hilo.start()
        inicio = time.monotonic()
        try:
            with mock.patch.object(transporte._ConexionHttp, '_conectar', lambda self, *a: plano), \
                    self.assertRaises(transporte.PlazoVencido):
                transporte.visitar(urllib.request.Request('http://%s/' % WWW), time.monotonic() + 0.5, 1000)
        finally:
            alto.set()
            plano.close()
            hilo.join(5)
        self.assertLess(time.monotonic() - inicio, 2.0)


class Contrato(unittest.TestCase):
    def resultado(self, cves):
        return contrato.Resultado(DOMINIO, 'web', cves=cves)

    def test_1_cves_validas(self):
        bien = [{'cve_id': 'CVE-2099-0101', 'description': 'x', 'cvss_base_score': 7.5,
                 'cvss_vector': 'CVSS:3.1/AV:N', 'published_at': '2099-01-01T00:00:00+00:00'},
                {'cve_id': 'CVE-2099-0102'}]
        self.assertEqual(contrato._errores_cves(bien), [])

    def test_2_cves_que_tumbarian_la_base(self):
        casos = {'no es lista': 'CVE-2099-0101', 'fila no dict': ['CVE-2099-0101'],
                 'id malo': [{'cve_id': 'CVE-99-1'}], 'id con basura': [{'cve_id': 'CVE-2099-0101 '}],
                 'repetida': [{'cve_id': 'CVE-2099-0101'}, {'cve_id': 'CVE-2099-0101'}],
                 'columna de más': [{'cve_id': 'CVE-2099-0101', 'in_kev': True}],
                 'puntaje 11': [{'cve_id': 'CVE-2099-0101', 'cvss_base_score': 11}],
                 'puntaje bool': [{'cve_id': 'CVE-2099-0101', 'cvss_base_score': True}],
                 'puntaje texto': [{'cve_id': 'CVE-2099-0101', 'cvss_base_score': '7.5'}],
                 'descripción no texto': [{'cve_id': 'CVE-2099-0101', 'description': 3}],
                 'fecha sin zona': [{'cve_id': 'CVE-2099-0101', 'published_at': '2099-01-01T00:00:00'}],
                 'fecha mala': [{'cve_id': 'CVE-2099-0101', 'published_at': 'ayer'}]}
        for nombre, cves in casos.items():
            with self.subTest(nombre):
                self.assertTrue(contrato._errores_cves(cves), nombre)
                self.assertTrue(contrato.validar(self.resultado(cves)), nombre)

    def test_3_registro_y_maximo(self):
        self.assertEqual(REGISTRO['web'], 'cirdan.recolectores.visita')
        self.assertEqual(visita.MAX_CONSULTAS, 2 * 2 + 20 * 3 + 20 * 4 + 10 * 2 + 10 * 2)
        self.assertEqual(visita.MAX_CONSULTAS, 184)
        self.assertEqual(set(visita.CODIGOS), {'outdated_software', 'known_vulnerability', 'server_version_disclosed',
                                               'directory_listing', 'debug_page_exposed',
                                               'tls_certificate_invalid', 'tls_legacy_only'})


class Base(unittest.TestCase):
    """Lectura estática de la semilla 012 y la migración 014, sin base."""

    def test_1_semilla_web_encendida_con_10_corridas_por_dia(self):
        with mock.patch.object(test_subfinder, 'SEMILLA', SEMILLA):
            fila = test_subfinder.fila_de_la_semilla('web')
        self.assertIsNotNone(fila, 'la semilla 012 no trae la fila de web')
        self.assertEqual((fila['kind'], fila['enabled'].lower(), fila['keep_raw_payload'].lower()),
                         ("'osint'", 'true', 'true'))
        self.assertEqual(int(fila['daily_limit']), 10 * visita.MAX_CONSULTAS)
        texto = SEMILLA.read_text(encoding='utf-8')
        self.assertIn("SET client_encoding = 'UTF8';", texto)
        self.assertIn('ON CONFLICT (code) DO NOTHING', texto)
        # b3-1: la 014 va antes que la 012, en el encabezado de la semilla y en db/README.md (tabla, carga desde
        # cero y la sección de una base que ya existe)
        self.assertIn('la 014, que va ANTES que esta', texto)
        leeme = (RAIZ / 'db' / 'README.md').read_text(encoding='utf-8')
        m014, s012 = '< db/migraciones/%s' % MIGRACION.name, '< db/semillas/%s' % SEMILLA.name
        self.assertEqual((leeme.count(m014), leeme.count(s012)), (2, 2))
        ordenes = [linea.split('< db/')[1].strip() for linea in leeme.splitlines() if m014 in linea or s012 in linea]
        self.assertEqual(ordenes, ['migraciones/' + MIGRACION.name, 'semillas/' + SEMILLA.name] * 2)
        for archivo in ('migraciones/' + MIGRACION.name, 'semillas/' + SEMILLA.name):
            self.assertIn('| `%s` |' % archivo, leeme)
        # El id no lo usa otra semilla
        otras = [p.name for p in SEMILLA.parent.glob('*.sql') if p != SEMILLA
                 and fila['id'].strip("'") in p.read_text(encoding='utf-8')]
        self.assertEqual(otras, [])

    def test_2_migracion_da_insert_y_nunca_update(self):
        texto = MIGRACION.read_text(encoding='utf-8')
        columnas = [c for c in contrato.COLUMNAS_CVES if c != 'cve_id']
        self.assertIn('GRANT INSERT (%s) ON cves TO cirdan_app;' % ', '.join(columnas), texto)
        sin_comentarios = '\n'.join(l.split('--', 1)[0] for l in texto.splitlines())
        self.assertNotIn('UPDATE', sin_comentarios.upper().replace('ACTUALIZA', ''))
        self.assertIn("SET client_encoding = 'UTF8';", texto)
        numeros = sorted(int(p.name[:3]) for p in MIGRACION.parent.glob('[0-9][0-9][0-9]_*.sql'))
        self.assertEqual(numeros, list(range(1, len(numeros) + 1)))

    def test_3_las_grabaciones_de_web_no_van_al_repo(self):
        self.assertEqual(visita.CARPETA_GRABADAS, contrato.CARPETA_GRABADAS / 'web')
        self.assertTrue((visita.CARPETA_GRABADAS / '.gitkeep').exists())
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
            for ruta in ('web/olmardo.com/sitio_www.olmardo.com_0123456789abcdef.json', 'web/olmardo.com/.grabacion',
                         'web/acme-demo.mx/nvd_0123456789abcdef_nginx.json'):
                self.assertTrue(ignorado(ruta), ruta)
            for ruta in ('web/.gitkeep', 'whois/.gitkeep'):
                self.assertFalse(ignorado(ruta), ruta)



BLOG = 'blog.acme-demo.mx'
SIMPLE = {'estado': 200, 'cabeceras': [['Content-Type', 'text/html']], 'cuerpo': '<html><body>hola</body></html>'}


class Arreglos(unittest.TestCase):
    """Lo que encontró la revisión del 9 nov (_texto, endoflife.date sin dato, cobertura con un sitio que falta, 5xx,
    destinos ya visitados, tiempo, NVD incompleta, grabación truncada, cookies, URL y la base)."""

    def test_1_charset_que_no_es_de_texto_cae_a_utf8(self):
        for charset in ('base64', 'hex', 'zlib', 'rot13', 'uu', 'quopri', 'idna', 'undefined', 'nada-de-esto'):
            with self.subTest(charset):
                self.assertEqual(visita._texto('hola ñ'.encode('utf-8'),
                                               [('Content-Type', 'text/html; charset=%s' % charset)]), 'hola ñ')
        self.assertEqual(visita._texto('ñ'.encode('latin-1'), [('Content-Type', 'text/html; charset=latin-1')]), 'ñ')

    def test_2_endoflife_que_no_se_lee_deja_el_sitio_sin_revisar(self):
        res, _, _ = correr({'https://%s/' % DOMINIO: pagina_nginx()}, apis=Apis(eol=404))   # no tiene el producto
        self.assertNotIn('sin_revisar', activo(res, DOMINIO).atributos['web'])
        for nombre, eol in (('otra forma', {'cambio': True}), ('sin ciclos', {'result': {'releases': [{'otra': 1}]}}),
                            ('vacía', []),
                            ('ciclo sin fin legible', [{'cycle': '1.18', 'eol': 'pronto'}])):
            with self.subTest(nombre):
                res, _, _ = correr({'https://%s/' % DOMINIO: pagina_nginx()}, apis=Apis(eol=eol))
                self.assertEqual(res.estado, 'succeeded', res.error)
                self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['eol'])
                self.assertNotIn('outdated_software', [h.codigo for h in res.hallazgos])
                # no se cierra nada del sitio, solo lo de su saludo TLS (RC-239)
                self.assertEqual((res.revisados, res.sin_revisar), (['tls:' + DOMINIO], [DOMINIO]))

    def test_3_con_un_comodin_y_un_sitio_que_no_respondio_no_se_dice_cuales_faltan(self):
        """La raíz no responde (a lo mejor redirigía a www, que solo está bajo el comodín) y blog no tiene A: solo se
        cierra lo de blog. Un 5xx o un reto de la raíz tampoco dan su página (c3-2): ayer pudo redirigir a www. Sin
        comodín sí se dice cuál falta."""
        raiz = 'https://%s/' % DOMINIO
        reto = fixture('cloudflare_reto_403', FIXTURES_BORDE)
        reto = visita.limpiar_visita({k: reto[k] for k in ('estado', 'cabeceras', 'cuerpo')})
        casos = (('comodín y sin respuesta', paginas('*.' + DOMINIO, BLOG), {'sin_respuesta': 'tiempo'}, None),
                 ('sin comodín', paginas(BLOG), {'sin_respuesta': 'tiempo'}, [DOMINIO]),
                 ('comodín y 5xx', paginas('*.' + DOMINIO, BLOG), pagina_nginx(502), None),
                 ('comodín y reto', paginas('*.' + DOMINIO, BLOG), reto, None),
                 ('sin comodín y 5xx', paginas(BLOG), pagina_nginx(502), [DOMINIO]),
                 ('sin comodín y reto', paginas(BLOG), reto, [DOMINIO]))
        for nombre, ct, raiz_responde, faltan in casos:
            with self.subTest(nombre):
                res, _, _ = correr({raiz: raiz_responde}, zona={DOMINIO: a(IP)}, apis=Apis(ct=ct))
                self.assertIn(BLOG, res.revisados)
                self.assertNotIn(DOMINIO, res.revisados)
                self.assertEqual(None if res.sin_revisar is None else
                                 sorted({x.rstrip('.') for x in res.sin_revisar if not x.startswith('tls:')}), faltan)

    def test_4_un_error_del_servidor_queda_sin_revisar(self):
        """Un 5xx puede ser fijo del sitio (un subdominio olvidado): no es una falla de la corrida y sí se graba."""
        for estado in (500, 502, 504, 520):
            with self.subTest(estado), tempfile.TemporaryDirectory() as d:
                res, cliente, _ = correr({'https://%s/' % DOMINIO: pagina_nginx(estado)}, modo='grabar',
                                         carpeta=Path(d) / DOMINIO)
                self.assertTrue(list((Path(d) / DOMINIO).glob('*.json')))
                self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['error_http'])
                self.assertEqual((res.hallazgos, res.sin_cobertura), ([], [c for c in visita.CODIGOS if c not in visita.CODIGOS_TLS]))
                self.assertNotIn(visita.NO_SE_GRABO, res.avisos)
                self.assertEqual(cliente.fallas, 0)

    def test_5_un_destino_ya_visitado_no_se_pide_otra_vez(self):
        res, cliente, _ = correr(
            {'https://%s/' % DOMINIO: {'redirige': 'https://%s/?sid=CIRDAN_FAKE_sid' % WWW, 'codigo': 301},
             'https://%s/?sid=CIRDAN_FAKE_sid' % WWW: pagina_nginx(),
             'https://%s/' % BLOG: {'redirige': 'https://%s/?sid=CIRDAN_FAKE_sid' % WWW, 'codigo': 302}},
            zona={DOMINIO: a(IP), WWW: a(IP), BLOG: a(IP)}, apis=Apis(ct=paginas(BLOG, WWW)))
        self.assertEqual(cliente.visitar.urls, ['https://%s/' % DOMINIO, 'https://%s/?sid=CIRDAN_FAKE_sid' % WWW,
                                                'https://%s/' % BLOG])
        self.assertEqual(activo(res, BLOG).atributos['web']['redirige_a'], WWW)
        # La URL que se guarda no lleva la consulta (un id de sesión)
        self.assertEqual(activo(res, WWW).atributos['web']['url'], 'https://%s/' % WWW)
        self.assertTrue(res.hallazgos)
        self.assertNotIn('CIRDAN_FAKE_sid', json.dumps([h.evidencia for h in res.hallazgos]))
        self.assertEqual(visita._sin_consulta('https://%s/a;jsessionid=CIRDAN_FAKE_1?state=CIRDAN_FAKE_2' % WWW),
                         'https://%s/a' % WWW)

    def test_6_el_tiempo_no_quita_lo_de_un_destino_ya_visitado(self):
        cliente = visita.ClienteWeb(modo='vivo', carpeta=visita.carpeta_de(DOMINIO), descargar=Apis(ct=paginas(BLOG, WWW)),
                                    visitar=Sitios({'https://%s/' % DOMINIO: {'redirige': 'https://%s/' % WWW,
                                                                             'codigo': 301},
                                                    'https://%s/' % WWW: SIMPLE}),
                                    resolver=ResolvedorSimulado({DOMINIO: a(IP), WWW: a(IP), BLOG: a(IP)}),
                                    cronometro=lambda: 0.0, dormir=lambda _: None)
        restante = cliente.restante
        cliente.restante = lambda: restante() if len(cliente.visitar.urls) < 2 else 0
        with mock.patch.object(visita.geoip, 'bases_por_omision', return_value=bases_geo()):
            res = visita.recolectar(DOMINIO, cliente, ahora=AHORA)
        self.assertEqual(activo(res, BLOG).atributos['web']['sin_revisar'], visita.MOTIVOS['sin_tiempo'])
        self.assertNotIn('sin_revisar', activo(res, WWW).atributos['web'])
        self.assertIn('web: se acabó el tiempo de la corrida antes de visitar 1 sitio', res.avisos)

    def test_7_la_nvd_incompleta_con_alguna_cve_deja_el_sitio_sin_revisar(self):
        nvd = fixture('nvd_nginx_1.18.0')
        nvd['totalResults'] = 9999
        res, _, _ = correr({'https://%s/' % DOMINIO: pagina_nginx()}, apis=Apis(nvd=nvd))
        self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['nvd_falta'])
        self.assertIn('known_vulnerability', [h.codigo for h in res.hallazgos])   # lo que llegó sí se reporta
        self.assertEqual((res.revisados, res.sin_revisar), (['tls:' + DOMINIO], [DOMINIO]))

    def test_8_una_grabacion_que_no_se_lee_no_tumba_la_fuente(self):
        original = visita.ClienteWeb._de_disco

        def de_disco(cliente, consulta):
            if consulta.startswith(('sitio:', 'eol:')):
                raise json.JSONDecodeError('truncada', '', 0)
            return original(cliente, consulta)
        with mock.patch.object(visita.ClienteWeb, '_de_disco', de_disco):
            res, _, _ = correr({'https://%s/' % DOMINIO: pagina_nginx()})
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['grabacion'])
        cliente = visita.ClienteWeb(modo='vivo', carpeta=visita.carpeta_de(DOMINIO), descargar=Apis())
        with mock.patch.object(visita.ClienteWeb, '_de_disco', de_disco):
            with self.assertRaises(contrato.FuenteNoResponde):
                cliente.api('eol:nginx', 'https://endoflife.date/api/v1/products/nginx', 'endoflife.date')

    def test_9_consultar_api_corta_tras_una_caida_y_cuenta_la_pausa(self):
        class Cliente:
            def __init__(self, restante, falla):
                self.pedidas, self._restante, self.falla = [], restante, falla

            def restante(self):
                return self._restante

            def api(self, consulta, url, que, **_):
                self.pedidas.append(consulta)
                if self.falla:
                    raise contrato.FuenteNoResponde('caída')
                return {}
        armar = lambda e: (e, 'https://x/' + e, None, False)
        res, parcial = contrato.Resultado(DOMINIO, 'web'), []
        caida = Cliente(1000, True)
        self.assertEqual(visita._consultar_api(res, caida, ['a', 'b', 'c'], parcial, 6, 'x', armar), {})
        self.assertEqual(caida.pedidas, ['a'])
        self.assertIn('caída. No se consultaron 2 más', res.avisos)
        class Ilegible(Cliente):
            def api(self, consulta, url, que, **_):
                self.pedidas.append(consulta)
                if consulta == 'a':
                    raise shodan.RespuestaIlegible('ilegible')
                return {}
        ilegible = Ilegible(1000, False)
        self.assertEqual(visita._consultar_api(res, ilegible, ['a', 'b'], [], 6, 'x', armar), {'b': {}})
        justo = Cliente(visita.MIN_RESTANTE + 1, False)
        self.assertEqual(visita._consultar_api(res, justo, ['a', 'b'], [], 6, 'x', armar), {'a': {}})

    def test_10_cookies_url_ip_y_fechas(self):
        self.assertEqual(visita._sin_valores('CIRDAN_FAKE_solo_valor; Path=/'), '')
        self.assertEqual(visita._sin_valores('a=CIRDAN_FAKE_1; Path=/, b=2'), 'a=, b=')
        for ip in ('::7f00:1', '::a00:5', '::808:808'):
            self.assertFalse(transporte.publica(ip), ip)
        self.assertTrue(transporte.publica('2606:4700::6810:300a'))
        fila = {'cve_id': 'CVE-2099-0101', 'published_at': '2099-01-01T00:00:00+20:00'}
        self.assertTrue(contrato._errores_cves([fila]))
        self.assertEqual(contrato._errores_cves([dict(fila, published_at='2099-01-01T00:00:00+14:00')]), [])

    def test_11_un_salto_intermedio_no_se_pide_dos_veces(self):
        """red-5: la raíz manda a www y www a blog. Cuando le toca a www, su visita ya se hizo como salto."""
        res, cliente, _ = correr(
            {'https://%s/' % DOMINIO: {'redirige': 'https://%s/' % WWW, 'codigo': 301},
             'https://%s/' % WWW: {'redirige': 'https://%s/' % BLOG, 'codigo': 301},
             'https://%s/' % BLOG: SIMPLE},
            zona={DOMINIO: a(IP), WWW: a(IP), BLOG: a(IP)}, apis=Apis(ct=paginas(BLOG, WWW)))
        self.assertEqual(cliente.visitar.urls, ['https://%s/' % DOMINIO, 'https://%s/' % WWW, 'https://%s/' % BLOG])
        self.assertEqual(activo(res, WWW).atributos['web']['redirige_a'], BLOG)
        self.assertEqual(activo(res, BLOG).atributos['web']['estado'], 'visitado')
        self.assertEqual((res.revisados, res.sin_revisar), (None, None))

    def test_12_un_archivo_truncado_de_la_grabacion_no_tumba_la_fuente(self):
        """cobertura-9: cualquier archivo de la grabación truncado (el A, una página de CT, un sitio, endoflife.date
        o la NVD) deja la corrida parcial, nunca lanza."""
        sitios = {'https://%s/' % DOMINIO: pagina_nginx(), 'https://%s/' % WWW: SIMPLE}
        zona = {DOMINIO: a(IP), WWW: a(IP)}
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            correr(sitios, zona=zona, apis=Apis(ct=paginas(WWW)), modo='grabar', carpeta=carpeta)
            archivos = sorted(carpeta.glob('*.json'))
            self.assertGreaterEqual(len(archivos), 6)   # CT, dos A, dos sitios, endoflife.date y la NVD
            completa, _, _ = correr({}, zona={}, modo='reproducir', carpeta=carpeta)
            self.assertEqual((completa.revisados, len(completa.hallazgos)), (None, 5))
            for archivo in archivos:
                bueno = archivo.read_text(encoding='utf-8')
                for roto in ('', '[]', '{}', bueno[:len(bueno) // 2], '{"datos": 5}', '"x"'):
                    with self.subTest(archivo=archivo.name, roto=roto[:12]):
                        archivo.write_text(roto, encoding='utf-8')
                        try:
                            res, _, _ = correr({}, zona={}, modo='reproducir', carpeta=carpeta)
                        except contrato.FuenteNoResponde:
                            continue   # la fuente no respondió: el orquestador lo sabe leer
                        self.assertTrue(res.revisados is not None or res.sin_cobertura, 'quedó como completa')
                archivo.write_text(bueno, encoding='utf-8')

    def test_13_un_salto_que_empieza_sin_su_tiempo_es_el_fin_de_la_corrida(self):
        """tiempos-6: al salto a www le queda 1.5 s de corrida y no termina. No es que www no responda a tiempo:
        se acabó la corrida, no cuenta como falla del sitio y los dos quedan con 'sin_tiempo'."""
        cliente = visita.ClienteWeb(modo='vivo', carpeta=visita.carpeta_de(DOMINIO), descargar=Apis(ct=paginas(WWW)),
                                    visitar=Sitios({'https://%s/' % DOMINIO: {'redirige': 'https://%s/' % WWW,
                                                                             'codigo': 301},
                                                    'https://%s/' % WWW: {'sin_respuesta': 'tiempo'}}),
                                    resolver=ResolvedorSimulado({DOMINIO: a(IP), WWW: a(IP)}),
                                    cronometro=lambda: 0.0, dormir=lambda _: None)
        restante = cliente.restante
        cliente.restante = lambda: restante() if len(cliente.visitar.urls) < 1 else 1.5
        with mock.patch.object(visita.geoip, 'bases_por_omision', return_value=bases_geo()):
            res = visita.recolectar(DOMINIO, cliente, ahora=AHORA)
        self.assertEqual(cliente.visitar.urls, ['https://%s/' % DOMINIO, 'https://%s/' % WWW])
        self.assertEqual(cliente.fallas, 0)
        for nombre in (DOMINIO, WWW):
            self.assertEqual(activo(res, nombre).atributos['web']['sin_revisar'], visita.MOTIVOS['sin_tiempo'])
        # Con sus TIMEOUT_SITIO segundos completos sí es el sitio el que no respondió a tiempo
        res, cliente, _ = correr({'https://%s/' % DOMINIO: {'sin_respuesta': 'tiempo'}})
        self.assertEqual(cliente.fallas, 1)
        self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['tiempo'])


class Reloj:
    """Un reloj simulado: dormir() lo adelanta."""

    def __init__(self):
        self.t, self.dormidas = 0.0, []

    def ahora(self):
        return self.t

    def dormir(self, segundos):
        self.dormidas.append(segundos)
        self.t += segundos


class Confirmados(unittest.TestCase):
    """Los confirmados de la revisión del 9 nov que quedaban: TLS que no se negocia (tiempos-3), el reintento y el
    ritmo de la NVD (tiempos-4 y tiempos-5) y más de MAX_SITIOS nombres (cobertura-8)."""

    def test_1_un_sitio_que_no_negocia_tls_es_un_dato_del_sitio_y_si_se_graba(self):
        with tempfile.TemporaryDirectory() as d:
            res, cliente, _ = correr({'https://%s/' % DOMINIO: {'sin_respuesta': 'tls'}}, modo='grabar',
                                     carpeta=Path(d) / DOMINIO)
            self.assertTrue(list((Path(d) / DOMINIO).glob('*.json')))
        self.assertEqual(cliente.fallas, 0)
        self.assertNotIn(visita.NO_SE_GRABO, res.avisos)
        self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['tls'])
        self.assertEqual(res.sin_cobertura, list(visita.CODIGOS))   # no se cierra nada
        self.assertIn('tls', visita.OPACOS)   # pudo redirigir a un nombre que solo cubre un comodín
        self.assertNotIn('tls', visita.FALLAS_DE_RED)

    def nvd_con_reloj(self, respuestas):
        """(cliente, reloj, horas de cada petición a la NVD). `respuestas` da la de cada petición, en orden."""
        reloj, horas = Reloj(), []

        def descargar(url, timeout):
            horas.append(reloj.t)
            respuesta = respuestas.pop(0)
            if isinstance(respuesta, int):
                raise error_http(url, respuesta)
            return json.dumps(respuesta).encode()
        cliente = visita.ClienteWeb(modo='vivo', carpeta=visita.carpeta_de(DOMINIO), descargar=descargar,
                                    cronometro=reloj.ahora, dormir=reloj.dormir)
        cliente.empezar()
        return cliente, reloj, horas

    def test_2_el_reintento_de_la_nvd_tambien_espera_su_ritmo(self):
        """tiempos-4: tras un 503 el reintento salía a los 5 s (shodan.ESPERAS), menos que los 6 de la NVD."""
        cliente, reloj, horas = self.nvd_con_reloj([503, fixture('nvd_nginx_1.18.0'), fixture('nvd_nginx_1.18.0')])
        for n in (1, 2):
            cliente.api('nvd:%d' % n, 'https://services.nvd.nist.gov/x', 'la NVD', ritmo=True)
        self.assertEqual(horas, [0.0, 7.0, 14.0])   # PAUSA_NVD, literal: 6 s más 1 de margen (t3-1)
        self.assertEqual(cliente.consultas, 3)
        # Sin ritmo (endoflife.date) el reintento sigue a los 5 s
        cliente, reloj, horas = self.nvd_con_reloj([503, fixture('eol_nginx')])
        cliente.api('eol:nginx', 'https://endoflife.date/x', 'endoflife.date')
        self.assertEqual(horas, [0.0, 5.0])

    def test_3_dos_escaneos_a_la_vez_comparten_el_ritmo_de_la_nvd(self):
        """tiempos-5: el ritmo era de cada cliente y dos escaneos sumaban 10 peticiones cada 30 s desde la misma IP."""
        reloj, horas = Reloj(), []

        def descargar(url, timeout):
            horas.append(reloj.t)
            return json.dumps(fixture('nvd_nginx_1.18.0')).encode()
        ritmo = visita._Ritmo(visita.PAUSA_NVD)
        clientes = []
        for _ in range(2):
            cliente = visita.ClienteWeb(modo='vivo', carpeta=visita.carpeta_de(DOMINIO), descargar=descargar,
                                        cronometro=reloj.ahora, dormir=reloj.dormir)
            cliente.ritmo_nvd = ritmo
            cliente.empezar()
            clientes.append(cliente)
        for n in range(3):
            for cliente in clientes:
                cliente.api('nvd:%d' % n, 'https://services.nvd.nist.gov/x', 'la NVD', ritmo=True)
        self.assertEqual(horas, [0.0, 7.0, 14.0, 21.0, 28.0, 35.0])
        self.assertGreater(horas[5] - horas[0], 30)   # t3-1: la sexta sale a más de 30 s de la primera, con margen
        # Los clientes de verdad (con el reloj del sistema) comparten el del módulo. Con reloj propio, no
        de_verdad = [visita.ClienteWeb(modo='vivo', carpeta=visita.carpeta_de(DOMINIO)) for _ in range(2)]
        self.assertTrue(all(c.ritmo_nvd is visita.RITMO_NVD for c in de_verdad))
        self.assertIsNot(clientes[0].__class__(modo='vivo', carpeta=visita.carpeta_de(DOMINIO),
                                               cronometro=reloj.ahora).ritmo_nvd, visita.RITMO_NVD)
        # Si esperar el turno se pasa de la corrida, es el fin del tiempo y no se pide
        justo = clientes[0]
        justo.restante = lambda: 3
        with self.assertRaises(visita.SinTiempo):
            justo.api('nvd:9', 'https://services.nvd.nist.gov/x', 'la NVD', ritmo=True)
        self.assertEqual(len(horas), 6)

    def test_4_la_corrida_pide_a_la_nvd_con_ritmo_y_a_endoflife_con_su_pausa(self):
        pedidas = []

        class Cliente:
            def restante(self):
                return 1000

            def api(self, consulta, url, que, **otros):
                pedidas.append((consulta, otros['pausa'], otros['ritmo']))
                return {}
        res = contrato.Resultado(DOMINIO, 'web')
        visita._consultar_api(res, Cliente(), ['a', 'b'], [], 1, 'endoflife.date',
                              lambda e: (e, 'https://x', None, False))
        visita._consultar_api(res, Cliente(), ['c', 'd'], [], 6, 'la NVD', lambda e: (e, 'https://x', None, True))
        self.assertEqual(pedidas, [('a', 0, False), ('b', 1, False), ('c', 0, True), ('d', 0, True)])

    def test_5_con_mas_de_max_sitios_los_que_quedan_fuera_cambian_con_el_dia(self):
        """cobertura-8: con 30 nombres siempre quedaban fuera los mismos 10 (orden alfabético)."""
        nombres = ['s%02d.%s' % (n, DOMINIO) for n in range(29)]
        zona = dict({n: a(IP) for n in nombres}, **{DOMINIO: a(IP)})
        visitados = []
        for dia in (6, 7):
            res, _, _ = correr({'https://%s/' % DOMINIO: SIMPLE}, zona=zona, apis=Apis(ct=paginas(*nombres)),
                               ahora=datetime(2026, 11, dia, 12, 0, tzinfo=timezone.utc))
            visitados.append([x.valor for x in res.activos])
            self.assertEqual(len(visitados[-1]), visita.MAX_SITIOS)
            self.assertEqual(visitados[-1][0], DOMINIO)   # la raíz, siempre
            self.assertIn('web: se visitaron 20 de 30 nombres del dominio (MAX_SITIOS)', res.avisos)
            # Solo se cierra lo de los visitados (borde.cobertura da cada nombre también con su punto final)
            self.assertEqual({x.rstrip('.') for x in res.revisados if not x.startswith('tls:')}, set(visitados[-1]))
            self.assertEqual({x for x in res.revisados if x.startswith('tls:')}, {'tls:' + v for v in visitados[-1]})
            self.assertIsNone(res.sin_revisar)
        self.assertEqual(set(visitados[0]) | set(visitados[1]), set(nombres) | {DOMINIO})   # en dos días, todos
        # El mismo día, los mismos
        res, _, _ = correr({'https://%s/' % DOMINIO: SIMPLE}, zona=zona, apis=Apis(ct=paginas(*nombres)),
                           ahora=datetime(2026, 11, 7, 23, 0, tzinfo=timezone.utc))
        self.assertEqual([x.valor for x in res.activos], visitados[1])

    def test_6_al_reproducir_con_mas_de_max_sitios_van_los_que_la_grabacion_trae(self):
        nombres = ['s%02d.%s' % (n, DOMINIO) for n in range(29)]
        zona = dict({n: a(IP) for n in nombres}, **{DOMINIO: a(IP)})
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            grabada, _, _ = correr({'https://%s/' % DOMINIO: SIMPLE}, zona=zona, apis=Apis(ct=paginas(*nombres)),
                                   modo='grabar', carpeta=carpeta,
                                   ahora=datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc))
            self.assertNotIn(visita.NO_SE_GRABO, grabada.avisos)   # el tope de sitios no impide grabar
            res, _, _ = correr({}, zona={}, modo='reproducir', carpeta=carpeta,
                               ahora=datetime(2026, 12, 25, 12, 0, tzinfo=timezone.utc))
        self.assertEqual(sorted(x.valor for x in res.activos), sorted(x.valor for x in grabada.activos))
        self.assertEqual(sorted(res.revisados), sorted(grabada.revisados))
        self.assertFalse([x.valor for x in res.activos if 'sin_revisar' in x.atributos['web']])


def error_certificado(codigo):
    """El error de un certificado que OpenSSL no pudo verificar, con su verify_code."""
    error = ssl.SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed')
    error.verify_code = codigo
    return error


def error_tls(razon):
    """Un ssl.SSLError con la razón de OpenSSL `razon`, como lo arma el módulo ssl."""
    error = ssl.SSLError(1, '[SSL: %s] %s' % (razon, razon.lower()))
    error.reason = razon
    return error


class SaludoTls(unittest.TestCase):
    """tls_certificate_invalid y tls_legacy_only del mismo saludo TLS de la visita (#121, RC-239), sin red."""
    RAIZ_HTTPS = 'https://%s/' % DOMINIO

    def test_1_motivo_y_verify_code_de_lo_que_no_termino(self):
        casos = ((error_certificado(10), {'sin_respuesta': 'certificado', 'verify_code': 10}),
                 (urllib.error.URLError(error_certificado(62)), {'sin_respuesta': 'certificado', 'verify_code': 62}),
                 (urllib.error.URLError(error_certificado(True)), {'sin_respuesta': 'certificado', 'verify_code': None}),
                 (urllib.error.URLError(error_certificado('10')), {'sin_respuesta': 'certificado', 'verify_code': None}),
                 (urllib.error.URLError(error_tls('TLSV1_ALERT_PROTOCOL_VERSION')), {'sin_respuesta': 'tls_viejo'}),
                 (error_tls('UNSUPPORTED_PROTOCOL'), {'sin_respuesta': 'tls_viejo'}),
                 (error_tls('VERSION_TOO_LOW'), {'sin_respuesta': 'tls_viejo'}),
                 # HTTP en texto plano en el 443 no es un protocolo viejo
                 (error_tls('WRONG_VERSION_NUMBER'), {'sin_respuesta': 'tls'}),
                 (error_tls('SSLV3_ALERT_HANDSHAKE_FAILURE'), {'sin_respuesta': 'tls'}))
        for error, esperado in casos:
            with self.subTest(repr(error)), mock.patch.object(transporte, 'abrir', mock.Mock(side_effect=error)):
                self.assertEqual(visita._visitar(self.RAIZ_HTTPS, 5), esperado)
        self.assertIn('tls_viejo', visita.OPACOS)
        self.assertNotIn('tls_viejo', visita.FALLAS_DE_RED)

    def test_2_cada_motivo_del_certificado_da_su_hallazgo(self):
        casos = ((10, 'vencido'), (18, 'autofirmado'), (19, 'autofirmado'), (62, 'otro_nombre'), (66, 'debil'),
                 (67, 'debil'), (68, 'debil'), (20, 'emisor_desconocido'), (2, 'otro'), (None, 'otro'))
        huellas = set()
        for codigo, motivo in casos:
            with self.subTest(codigo):
                res, cliente, _ = correr({self.RAIZ_HTTPS: {'sin_respuesta': 'certificado', 'verify_code': codigo}})
                self.assertEqual(res.estado, 'succeeded', res.error)
                self.assertEqual(contrato.validar(res, codigos=set(visita.CODIGOS)), [])
                self.assertEqual(cliente.fallas, 0)   # es un dato del sitio, no una falla de la red
                [h] = res.hallazgos
                self.assertEqual((h.codigo, h.severidad, h.activo, h.partes),
                                 ('tls_certificate_invalid', 'medium', DOMINIO, ['tls:' + DOMINIO]))
                self.assertEqual(h.evidencia['motivo'], motivo)
                self.assertEqual(h.evidencia['verify_code'], codigo)
                self.assertEqual(h.evidencia['url'], self.RAIZ_HTTPS)
                self.assertEqual(h.evidencia['title'], h.titulo)
                self.assertIn(visita.TEXTO_CERTIFICADO[motivo], h.titulo)
                self.assertEqual('nota' in h.evidencia, motivo == 'emisor_desconocido')
                # Sin la página no hay tecnologías ni cabeceras: el sitio queda sin revisar para el resto
                web = activo(res, DOMINIO).atributos
                self.assertEqual(web['web']['sin_revisar'], visita.MOTIVOS['certificado'])
                self.assertNotIn('tecnologias', web)
                # El saludo sí se revisó: su parte va en revisados aunque el sitio quede sin revisar
                self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura),
                                 (['tls:' + DOMINIO], [DOMINIO], []))
                huellas.add(h.huella)
        self.assertEqual(len(huellas), 1)   # el motivo no cambia la huella: es el mismo hallazgo del sitio

    def test_3_tls_viejo_da_tls_legacy_only(self):
        res, _, _ = correr({self.RAIZ_HTTPS: {'sin_respuesta': 'tls_viejo'}})
        self.assertEqual(contrato.validar(res, codigos=set(visita.CODIGOS)), [])
        [h] = res.hallazgos
        self.assertEqual((h.codigo, h.severidad, h.partes), ('tls_legacy_only', 'medium', ['tls:' + DOMINIO]))
        self.assertEqual(h.evidencia, {'title': 'El sitio %s no acepta TLS 1.2 ni 1.3' % DOMINIO, 'host': DOMINIO,
                                       'url': self.RAIZ_HTTPS, 'minimo': 'TLSv1.2'})
        self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['tls_viejo'])
        otro, _, _ = correr({self.RAIZ_HTTPS: {'sin_respuesta': 'certificado', 'verify_code': 10}})
        self.assertNotEqual(otro.hallazgos[0].huella, h.huella)

    def test_4_sin_hallazgo_si_el_saludo_no_dijo_nada_del_sitio(self):
        for falla in ({'sin_respuesta': 'tls'}, {'sin_respuesta': 'red'}, {'sin_respuesta': 'tiempo'},
                      {'sin_respuesta': 'no_publica'}, {'rechazada': True}):
            with self.subTest(falla):
                res, _, _ = correr({self.RAIZ_HTTPS: falla})
                self.assertEqual([h.codigo for h in res.hallazgos], [])

    def test_5_el_destino_de_una_redireccion_lleva_su_hallazgo(self):
        res, _, _ = correr({self.RAIZ_HTTPS: {'redirige': 'https://%s/' % WWW, 'codigo': 301},
                            'https://%s/' % WWW: {'sin_respuesta': 'certificado', 'verify_code': 62}},
                           zona={DOMINIO: a(IP), WWW: a(IP)}, apis=Apis(ct=paginas(WWW)))
        self.assertEqual(contrato.validar(res, codigos=set(visita.CODIGOS)), [])
        [h] = res.hallazgos
        self.assertEqual((h.codigo, h.activo, h.partes, h.evidencia['url']),
                         ('tls_certificate_invalid', WWW, ['tls:' + WWW], 'https://%s/' % WWW))
        self.assertEqual(h.caracteristicas['exposicion'], 'publica')

    def test_6_la_pagina_por_https_guarda_version_y_cifrado_sin_hallazgo(self):
        pagina = dict(pagina_nginx(), tls={'version': 'TLSv1.3', 'cifrado': 'TLS_AES_256_GCM_SHA384'})
        res, _, _ = correr({self.RAIZ_HTTPS: visita.limpiar_visita(pagina)},
                           apis=Apis(eol=404, nvd={'totalResults': 0, 'vulnerabilities': []}))
        self.assertEqual(activo(res, DOMINIO).atributos['web']['tls'],
                         {'version': 'TLSv1.3', 'cifrado': 'TLS_AES_256_GCM_SHA384'})
        self.assertNotIn('tls_certificate_invalid', [h.codigo for h in res.hallazgos])
        self.assertNotIn('tls_legacy_only', [h.codigo for h in res.hallazgos])
        # La del 80 no lleva saludo aunque la grabación lo traiga
        res, _, _ = correr({self.RAIZ_HTTPS: {'rechazada': True}, 'http://%s/' % DOMINIO: visita.limpiar_visita(pagina)},
                           apis=Apis(eol=404, nvd={'totalResults': 0, 'vulnerabilities': []}))
        self.assertNotIn('tls', activo(res, DOMINIO).atributos['web'])

    def test_7_limpiar_visita_con_saludo_y_verify_code(self):
        base = pagina_nginx()
        self.assertNotIn('tls', visita.limpiar_visita(base))   # una grabación de antes de RC-239
        for tls, esperado in (({'version': 'TLSv1.2', 'cifrado': 'ECDHE-RSA-AES128-GCM-SHA256'},
                               {'version': 'TLSv1.2', 'cifrado': 'ECDHE-RSA-AES128-GCM-SHA256'}),
                              ({'version': 'TLSv1.3', 'cifrado': None}, {'version': 'TLSv1.3'}),
                              ({'version': 'TLS v1.3<script>', 'cifrado': 'x' * 65}, None),
                              ({'version': 13}, None), ('TLSv1.3', None), ({}, None)):
            with self.subTest(tls):
                self.assertEqual(visita.limpiar_visita(dict(base, tls=tls)).get('tls'), esperado)
        self.assertEqual(visita.limpiar_visita({'sin_respuesta': 'certificado'}),
                         {'sin_respuesta': 'certificado', 'verify_code': None})
        self.assertEqual(visita.limpiar_visita({'sin_respuesta': 'certificado', 'verify_code': 20}),
                         {'sin_respuesta': 'certificado', 'verify_code': 20})
        self.assertEqual(visita.limpiar_visita({'sin_respuesta': 'certificado', 'verify_code': '20'}),
                         {'sin_respuesta': 'certificado', 'verify_code': None})
        self.assertEqual(visita.limpiar_visita({'sin_respuesta': 'tls_viejo', 'verify_code': 20}),
                         {'sin_respuesta': 'tls_viejo'})

    def test_8_transporte_llena_el_saludo_solo_si_la_peticion_lo_pide(self):
        class Tls(ssl.SSLSocket):
            def __init__(self):   # sin socket: solo lo que lee _ConPlazo.connect
                pass

            def version(self):
                return 'TLSv1.3'

            def cipher(self):
                return ('TLS_AES_128_GCM_SHA256', 'TLSv1.3', 128)

        for saludo in ({}, None):
            with self.subTest(saludo):
                conexion = transporte._Conexion(DOMINIO, time.monotonic() + 5, time.monotonic, saludo=saludo)
                with mock.patch.object(urllib.request.http.client.HTTPSConnection, 'connect',
                                       lambda self_: setattr(self_, 'sock', Tls())):
                    conexion.connect()
                if saludo is not None:
                    self.assertEqual(saludo, {'version': 'TLSv1.3', 'cifrado': 'TLS_AES_128_GCM_SHA256'})

    def cierra(self, res, codigo, partes):
        """Lo que hace el UPDATE de cierre del orquestador con un hallazgo abierto que ya no salió (#23)."""
        if res.revisados is None:
            return codigo not in res.sin_cobertura
        if res.sin_revisar is None:
            return bool(partes) and set(partes) <= set(res.revisados)
        return bool(partes) and not set(partes) & set(res.sin_revisar)

    def test_9_un_saludo_bueno_cierra_las_reglas_tls_aunque_el_sitio_quede_sin_revisar(self):
        reto = fixture('cloudflare_reto_403', FIXTURES_BORDE)
        reto = dict({k: reto[k] for k in ('estado', 'cabeceras', 'cuerpo')},
                    tls={'version': 'TLSv1.3', 'cifrado': 'TLS_AES_256_GCM_SHA384'})
        error_5xx = dict(pagina_nginx(503), tls={'version': 'TLSv1.2', 'cifrado': 'ECDHE-RSA-AES128-GCM-SHA256'})
        for nombre, pagina in (('reto', reto), ('5xx', error_5xx)):
            with self.subTest(nombre):
                res, _, _ = correr({self.RAIZ_HTTPS: visita.limpiar_visita(pagina)})
                self.assertEqual(contrato.validar(res, codigos=set(visita.CODIGOS)), [])
                self.assertEqual(res.hallazgos, [])
                self.assertIn('tls:' + DOMINIO, res.revisados)
                self.assertIsNone(res.sin_revisar)   # lo demás del sitio no se cierra en esta corrida
                self.assertEqual(res.sin_cobertura, [c for c in visita.CODIGOS if c not in visita.CODIGOS_TLS])
                for codigo in visita.CODIGOS_TLS:   # un certificado renovado o un TLS 1.2 nuevo se cierran
                    self.assertTrue(self.cierra(res, codigo, ['tls:' + DOMINIO]), codigo)
                self.assertFalse(self.cierra(res, 'outdated_software', [DOMINIO]))   # lo demás del sitio espera

    def test_10_un_certificado_malo_cierra_tls_legacy_only_del_mismo_sitio(self):
        res, _, _ = correr({self.RAIZ_HTTPS: {'sin_respuesta': 'certificado', 'verify_code': 18}})
        [h] = res.hallazgos
        self.assertEqual(h.codigo, 'tls_certificate_invalid')
        # negoció TLS 1.2 o más para llegar al certificado: el tls_legacy_only de antes ya no es cierto
        self.assertTrue(self.cierra(res, 'tls_legacy_only', ['tls:' + DOMINIO]))
        self.assertFalse(self.cierra(res, 'outdated_software', [DOMINIO]))

    def test_11_un_saludo_que_no_termino_no_cierra_las_reglas_tls(self):
        for falla in ({'sin_respuesta': 'tls'}, {'sin_respuesta': 'red'}, {'sin_respuesta': 'tiempo'}):
            with self.subTest(falla):
                res, _, _ = correr({self.RAIZ_HTTPS: falla})
                self.assertEqual(contrato.validar(res, codigos=set(visita.CODIGOS)), [])
                for codigo in visita.CODIGOS_TLS:
                    self.assertFalse(self.cierra(res, codigo, ['tls:' + DOMINIO]), codigo)
        # Con dos sitios, el que respondió queda revisado y el saludo del otro no
        res, _, _ = correr({self.RAIZ_HTTPS: {'sin_respuesta': 'red'},
                            'https://%s/' % WWW: visita.limpiar_visita(pagina_nginx())},
                           zona={DOMINIO: a(IP), WWW: a(IP)}, apis=Apis(ct=paginas(WWW), eol=404,
                                                                       nvd={'totalResults': 0, 'vulnerabilities': []}))
        self.assertEqual(contrato.validar(res, codigos=set(visita.CODIGOS)), [])
        self.assertIn('tls:' + WWW, res.revisados)
        self.assertIn('tls:' + DOMINIO, res.sin_revisar)
        self.assertTrue(self.cierra(res, 'tls_certificate_invalid', ['tls:' + WWW]))
        self.assertFalse(self.cierra(res, 'tls_certificate_invalid', ['tls:' + DOMINIO]))

    def test_12_api_docs_toma_tls_viejo_como_tls(self):
        from cirdan.recolectores import api_docs
        with mock.patch.object(transporte, 'abrir', mock.Mock(side_effect=error_tls('UNSUPPORTED_PROTOCOL'))):
            datos = api_docs._visitar(self.RAIZ_HTTPS, 5)
        self.assertEqual(datos, {'sin_respuesta': 'tls'})
        self.assertEqual(api_docs.limpiar(datos), datos)   # antes lanzaba ValueError('forma inesperada')



def ca_y_hoja(carpeta, nombre, **opciones):
    """(ruta de la CA, ruta de la cadena que entrega el servidor, ruta de su llave), hechos en la prueba. opciones:
    vencido, otro_nombre, autofirmado, sin_intermedio (la hoja la firma un intermedio que el servidor no manda) y
    debil (llave RSA de 1024 bits)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    ahora = datetime.now(timezone.utc)

    def nombre_x509(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def emitir(sujeto, publica, emisor, llave_emisor, ca, desde, hasta, san=None):
        b = (x509.CertificateBuilder().subject_name(nombre_x509(sujeto)).issuer_name(nombre_x509(emisor))
             .public_key(publica).serial_number(x509.random_serial_number()).not_valid_before(desde)
             .not_valid_after(hasta)
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(publica), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(llave_emisor.public_key()),
                            critical=False))
        if ca:
            b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                              content_commitment=False, key_encipherment=False,
                                              data_encipherment=False, key_agreement=False, encipher_only=False,
                                              decipher_only=False), critical=True)
        else:
            b = (b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
                 .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
        return b.sign(llave_emisor, hashes.SHA256())

    pem = serialization.Encoding.PEM
    llave_ca = ec.generate_private_key(ec.SECP256R1())
    raiz = emitir('CA de prueba', llave_ca.public_key(), 'CA de prueba', llave_ca, True,
                  ahora - timedelta(days=2), ahora + timedelta(days=2))
    emisor, llave_emisor, cadena = 'CA de prueba', llave_ca, []
    if opciones.get('sin_intermedio'):
        llave_int = ec.generate_private_key(ec.SECP256R1())
        cadena.append(emitir('Intermedio de prueba', llave_int.public_key(), 'CA de prueba', llave_ca, True,
                             ahora - timedelta(days=2), ahora + timedelta(days=2)))
        emisor, llave_emisor = 'Intermedio de prueba', llave_int
    llave = rsa.generate_private_key(65537, 1024) if opciones.get('debil') else ec.generate_private_key(ec.SECP256R1())
    if opciones.get('autofirmado'):
        emisor, llave_emisor = nombre, llave
    desde, hasta = ahora - timedelta(minutes=5), ahora + timedelta(hours=1)
    if opciones.get('vencido'):
        desde, hasta = ahora - timedelta(days=2), ahora - timedelta(days=1)
    hoja = emitir(nombre, llave.public_key(), emisor, llave_emisor, False, desde, hasta,
                  san='otro.prueba.example' if opciones.get('otro_nombre') else nombre)
    rutas = Path(carpeta) / 'ca.pem', Path(carpeta) / 'cadena.pem', Path(carpeta) / 'llave.pem'
    rutas[0].write_bytes(raiz.public_bytes(pem))
    rutas[1].write_bytes(hoja.public_bytes(pem))   # sin_intermedio: el servidor no manda el intermedio
    rutas[2].write_bytes(llave.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return tuple(str(r) for r in rutas)


HOST_SITIO = 'sitio.prueba.example'


@unittest.skipUnless(os.environ.get('TRANSPORTE_TLS') == '1' or importlib.util.find_spec('cryptography'),
                     'pide cryptography para los certificados: corre dentro del contenedor')
class SaludoReal(unittest.TestCase):
    """El saludo TLS de verdad, con el OpenSSL de la imagen, contra un servidor sobre socket.socketpair() con
    certificados hechos aquí (#121, RC-239). Sin red: _conectar devuelve el extremo del servidor. Con
    TRANSPORTE_TLS=1, como en el CI, falla en vez de saltarse si no hay cryptography."""
    PAGINA = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')

    def visitar(self, ca, servidor_ctx):
        servidor = test_rdap.ServidorTls(servidor_ctx, self.PAGINA)
        cliente_ctx = ssl.create_default_context(cafile=ca)   # como transporte._contexto, con esta CA
        cliente_ctx.sslsocket_class = transporte._SocketTls

        def conectar(conexion, direccion, *_):
            self.assertEqual(direccion, (HOST_SITIO, 443))
            servidor.cliente.settimeout(conexion.queda())
            return servidor.cliente
        try:
            with mock.patch.object(transporte, '_contexto', lambda: cliente_ctx), \
                    mock.patch.object(transporte._Conexion, '_conectar', conectar):
                return visita._visitar('https://%s/' % HOST_SITIO, 5)
        finally:
            servidor.cerrar()

    def contexto(self, cadena, llave, maximo=None, debil=False):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if maximo or debil:   # antes de cargar la llave: con el nivel por omisión una RSA de 1024 no carga
            ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
        ctx.load_cert_chain(cadena, llave)
        if maximo:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = maximo
        return ctx

    def test_1_un_certificado_valido_da_la_pagina_con_version_y_cifrado(self):
        with tempfile.TemporaryDirectory() as d:
            ca, cadena, llave = ca_y_hoja(d, HOST_SITIO)
            r = self.visitar(ca, self.contexto(cadena, llave))
        self.assertEqual((r['estado'], r['cuerpo']), (200, 'ok'))
        self.assertIn(r['tls']['version'], ('TLSv1.2', 'TLSv1.3'))
        self.assertTrue(r['tls']['cifrado'])

    def test_2_cada_certificado_malo_da_su_verify_code(self):
        casos = (('vencido', 10), ('autofirmado', 18), ('otro_nombre', 62), ('sin_intermedio', 20), ('debil', 66))
        for opcion, codigo in casos:
            with self.subTest(opcion), tempfile.TemporaryDirectory() as d:
                ca, cadena, llave = ca_y_hoja(d, HOST_SITIO, **{opcion: True})
                r = self.visitar(ca, self.contexto(cadena, llave, debil=opcion == 'debil'))   # el cliente no la acepta
                self.assertEqual(r, {'sin_respuesta': 'certificado', 'verify_code': codigo})
                self.assertEqual(visita.MOTIVOS_CERTIFICADO[codigo], 'otro_nombre' if codigo == 62 else
                                 {'vencido': 'vencido', 'autofirmado': 'autofirmado',
                                  'sin_intermedio': 'emisor_desconocido', 'debil': 'debil'}[opcion])

    def test_3_un_servidor_que_solo_habla_tls_1_0_o_1_1_es_tls_viejo(self):
        for maximo in ('TLSv1', 'TLSv1_1'):
            with self.subTest(maximo), tempfile.TemporaryDirectory() as d:
                ca, cadena, llave = ca_y_hoja(d, HOST_SITIO)
                try:
                    servidor_ctx = self.contexto(cadena, llave, getattr(ssl.TLSVersion, maximo))
                except (ValueError, ssl.SSLError) as e:   # un OpenSSL sin TLS 1.0 ni 1.1 ni con SECLEVEL=0
                    self.fail('el OpenSSL de la imagen no arma un servidor %s: %s' % (maximo, e))
                self.assertEqual(self.visitar(ca, servidor_ctx), {'sin_respuesta': 'tls_viejo'})


FIXTURES_PORTADA = RAIZ / 'pruebas' / 'fixtures' / 'portada'
SEMILLA_PORTADA = RAIZ / 'db' / 'semillas' / '021_reglas_portada.sql'
MIGRACION_PORTADA = RAIZ / 'db' / 'migraciones' / '020_textos_reglas_portada.sql'

# (fixture, código, firma) de cada respuesta armada a mano de pruebas/fixtures/portada/
ESPERADO_PORTADA = (
    ('apache_listado', 'directory_listing', 'index_of'),
    ('nginx_listado', 'directory_listing', 'index_of'),
    ('iis_listado', 'directory_listing', 'iis_listado'),
    ('django_500', 'debug_page_exposed', 'django'),
    ('django_404', 'debug_page_exposed', 'django'),
    ('werkzeug_500', 'debug_page_exposed', 'werkzeug'),
    ('laravel_whoops_500', 'debug_page_exposed', 'laravel_whoops'),
    ('laravel_ignition_500', 'debug_page_exposed', 'laravel_ignition'),
    ('symfony_500', 'debug_page_exposed', 'symfony'),
    ('aspnet_500', 'debug_page_exposed', 'aspnet'),
    ('php_fatal_500', 'debug_page_exposed', 'php'),
    ('php_xdebug_200', 'debug_page_exposed', 'php'),
)
SIN_HALLAZGO_PORTADA = ('blog_index_of', 'aspnet_runtime_error', 'nginx_por_omision')


def pagina_portada(nombre):
    """La respuesta de pruebas/fixtures/portada/<nombre>.json, en la forma de limpiar_visita."""
    datos = json.loads((FIXTURES_PORTADA / (nombre + '.json')).read_text(encoding='utf-8'))
    return {'estado': datos['estado'], 'cabeceras': datos['cabeceras'], 'cuerpo': datos['cuerpo']}


class Portada(unittest.TestCase):
    """Listado de directorio y página de depuración en la portada (cirdan/recolectores/portada.py, #111, RC-228)."""

    def test_1_cada_servidor_y_cada_pagina_de_depuracion(self):
        for nombre, codigo, firma in ESPERADO_PORTADA:
            with self.subTest(nombre):
                pagina = pagina_portada(nombre)
                vistos = portada.revisar(pagina['estado'], pagina['cuerpo'])
                self.assertEqual([(v['codigo'], v['firma']) for v in vistos], [(codigo, firma)])

    def test_2_un_blog_que_dice_index_of_en_su_texto_no_da_hallazgo(self):
        for nombre in SIN_HALLAZGO_PORTADA:
            with self.subTest(nombre):
                pagina = pagina_portada(nombre)
                self.assertEqual(portada.revisar(pagina['estado'], pagina['cuerpo']), [])

    def test_3_solo_miran_el_titulo_el_primer_encabezado_y_el_inicio(self):
        listado = pagina_portada('nginx_listado')['cuerpo']
        # El listado en el texto del cuerpo, en un segundo encabezado o en el <title> de un <svg> no cuenta
        self.assertEqual(portada.revisar(200, '<html><head><title>Acme</title></head><body><h1>Acme</h1>'
                                              '<h2>Index of /</h2><p>Index of /</p></body></html>'), [])
        self.assertEqual(portada.revisar(200, '<html><body><svg><title>Index of /</title></svg>'
                                              '<h1>Acme</h1></body></html>'), [])
        # Un título que pasa del tope de lectura no se ve
        self.assertEqual(portada.revisar(200, ' ' * portada.MAX_LEIDO + listado), [])
        # Lo que sigue a un HTML no es el inicio de PHP
        self.assertEqual(portada.revisar(500, '<!doctype html><p>Fatal error: x in /a.php on line 3</p>'), [])
        # Un HTML roto o algo que no es texto no lanza
        for cuerpo in ('<title>Index of /', '<<<>>>&#xffffffff;<title', None, b'Index of /', 12):
            with self.subTest(cuerpo=cuerpo):
                self.assertEqual(portada.revisar(200, cuerpo), [])

    def test_4_el_listado_solo_en_un_2xx_y_la_depuracion_en_cualquier_estado(self):
        listado = pagina_portada('apache_listado')['cuerpo']
        for estado in (200, 203):
            self.assertEqual([v['codigo'] for v in portada.revisar(estado, listado)], ['directory_listing'])
        for estado in (301, 403, 404, 500, None):
            with self.subTest(estado):
                self.assertEqual(portada.revisar(estado, listado), [])
        django = pagina_portada('django_500')['cuerpo']
        for estado in (200, 404, 500, 503):
            with self.subTest(estado):
                self.assertEqual([v['codigo'] for v in portada.revisar(estado, django)], ['debug_page_exposed'])

    def test_5_el_titulo_va_sin_secretos_y_cortado(self):
        werkzeug = pagina_portada('werkzeug_500')
        symfony = pagina_portada('symfony_500')
        titulos = [portada.revisar(p['estado'], p['cuerpo'])[0]['titulo_pagina'] for p in (werkzeug, symfony)]
        for titulo in titulos:
            self.assertNotIn('CIRDAN_FAKE_', titulo)
        self.assertIn('postgresql://***@db', titulos[0])
        self.assertIn('token=***', titulos[1])
        largo = '<title>%s at /</title>' % ('E' * (portada.MAX_ZONA + 100))
        self.assertEqual(portada.revisar(500, largo), [])   # pasa del tope de la zona y ya no cumple la firma
        largo = '<title>Whoops! There was an error.</title>'
        self.assertLessEqual(len(portada.revisar(500, largo)[0]['titulo_pagina']), portada.MAX_TITULO)
        self.assertEqual(portada.sin_secretos('https://u:p@x/ password = abc, api_key: def'),
                         'https://***@x/ password = ***, api_key: ***')

    def test_6_firmas_versionadas_y_codigos_de_la_visita(self):
        self.assertIsInstance(portada.VERSION, int)
        ids = [f['id'] for f in portada.FIRMAS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertLessEqual(len(ids), 12)   # una lista corta
        zonas = {'titulo', 'encabezado', 'titulo_o_encabezado', 'iguales', 'inicio'}
        for firma in portada.FIRMAS:
            self.assertIn(firma['zona'], zonas)
            self.assertIn(firma['codigo'], portada.CODIGOS)
        self.assertEqual({f['codigo'] for f in portada.FIRMAS}, set(portada.CODIGOS))
        for codigo, severidad in portada.CODIGOS.items():
            self.assertEqual(visita.CODIGOS[codigo], severidad)
        self.assertEqual(portada.CWE, {'directory_listing': 'CWE-548', 'debug_page_exposed': 'CWE-215'})

    def test_7_un_500_con_pagina_de_depuracion_da_hallazgo_y_el_sitio_queda_sin_revisar(self):
        sitios = {'https://%s/' % DOMINIO: pagina_portada('django_500')}
        res, cliente, _ = correr(sitios)
        self.assertEqual(cliente.visitar.urls, ['https://%s/' % DOMINIO])   # ninguna petición nueva
        self.assertEqual([h.codigo for h in res.hallazgos], ['debug_page_exposed'])
        hallazgo = res.hallazgos[0]
        self.assertEqual((hallazgo.severidad, hallazgo.partes), ('high', [DOMINIO]))
        self.assertEqual(hallazgo.evidencia, {
            'title': 'El sitio %s muestra una página de depuración de Django' % DOMINIO, 'firma': 'django',
            'servidor': 'Django', 'firmas_version': portada.VERSION, 'titulo_pagina': 'OperationalError at /',
            'cwe': 'CWE-215', 'estado_http': 500, 'host': DOMINIO, 'url': 'https://%s/' % DOMINIO})
        self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['error_http'])
        # Con un hallazgo y sin ningún sitio revisado la corrida queda parcial y no cierra nada (#23), salvo la parte
        # del saludo TLS, que terminó aunque la página fuera un 500 (RC-239)
        self.assertEqual((res.revisados, res.sin_cobertura), (['tls:' + DOMINIO], []))
        self.assertEqual(res.sin_revisar, [DOMINIO])
        self.assertEqual(contrato.validar(res, visita.CODIGOS), [])

    def test_8_un_listado_en_la_raiz_y_la_evidencia_sin_html(self):
        www = 'https://%s/' % WWW
        sitios = {'https://%s/' % DOMINIO: pagina_portada('nginx_listado'), www: pagina_portada('iis_listado')}
        res, cliente, _ = correr(sitios, zona={DOMINIO: a(IP), WWW: a(IP)}, apis=Apis(ct=paginas(WWW)))
        self.assertEqual(sorted(cliente.visitar.urls), sorted(sitios))
        por_host = {h.activo: h for h in res.hallazgos if h.codigo == 'directory_listing'}
        self.assertEqual(sorted(por_host), sorted([DOMINIO, WWW]))
        self.assertEqual((por_host[DOMINIO].evidencia['firma'], por_host[WWW].evidencia['firma']),
                         ('index_of', 'iis_listado'))
        self.assertEqual(por_host[DOMINIO].evidencia['title'], 'El sitio %s muestra la lista de sus archivos' % DOMINIO)
        self.assertNotEqual(por_host[DOMINIO].huella, por_host[WWW].huella)
        for hallazgo in res.hallazgos:
            texto = json.dumps(hallazgo.evidencia, ensure_ascii=False)
            self.assertNotIn('<', texto)
            self.assertNotIn('respaldo', texto)   # nada del listado, solo la firma y el título
        # Los dos sitios quedaron revisados completos: la corrida es completa y no hay nada sin cobertura
        self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura), (None, None, []))
        self.assertEqual(contrato.validar(res, visita.CODIGOS), [])

    def test_9_sin_hallazgo_el_codigo_se_cierra_y_un_error_del_lector_deja_el_sitio_sin_revisar(self):
        res, _, _ = correr({'https://%s/' % DOMINIO: pagina_portada('blog_index_of')})
        self.assertEqual([h for h in res.hallazgos if h.codigo in portada.CODIGOS], [])
        self.assertNotIn('debug_page_exposed', res.sin_cobertura)
        with mock.patch.object(visita.portada, 'revisar', side_effect=ValueError('raro')):
            res, _, _ = correr({'https://%s/' % DOMINIO: pagina_portada('nginx_listado')})
        self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['portada'])
        self.assertEqual(res.hallazgos, [])

    def test_10_la_misma_pagina_al_reproducir(self):
        sitios = {'https://%s/' % DOMINIO: pagina_portada('werkzeug_500')}
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            grabada, _, _ = correr(sitios, modo='grabar', carpeta=carpeta)
            res, _, _ = correr({}, zona={}, modo='reproducir', carpeta=carpeta)
        self.assertEqual([(h.codigo, h.huella, h.evidencia) for h in res.hallazgos],
                         [(h.codigo, h.huella, h.evidencia) for h in grabada.hallazgos])
        self.assertEqual([h.codigo for h in res.hallazgos], ['debug_page_exposed'])

    def test_11_migracion_y_semilla_de_las_reglas(self):
        migracion = MIGRACION_PORTADA.read_text(encoding='utf-8')
        semilla = SEMILLA_PORTADA.read_text(encoding='utf-8')
        for sql in (migracion, semilla):
            self.assertLess(sql.index("SET client_encoding = 'UTF8';"), sql.index('BEGIN;'))
            self.assertTrue(sql.rstrip().endswith('COMMIT;'))
        for codigo in portada.CODIGOS:
            self.assertIn("WHERE code = '%s';" % codigo, migracion)
            self.assertIn(portada.CWE[codigo], migracion)
        # La semilla también las pone en los juegos de cada organización: sin ellas, contrato.validar tumbaría la
        # fuente web entera al primer hallazgo de la portada
        self.assertIn('FROM scoring_rule_sets s', semilla)
        self.assertIn("WHERE s.id <> '90000000-0000-4000-8000-000000000001'", semilla)
        self.assertEqual(semilla.count('ON CONFLICT (rule_set_id, code) DO NOTHING;'), 2)
        # Un juego que se crea mientras corre la semilla no se queda sin las dos reglas
        self.assertLess(semilla.index('LOCK TABLE scoring_rule_sets IN SHARE ROW EXCLUSIVE MODE;'),
                        semilla.index('INSERT INTO scoring_rules'))

    def test_12_secretos_de_otras_formas_fuera_de_la_evidencia(self):
        casos = (
            ('mysql://root:ab/cd@db/x', 'ab/cd'), ('postgresql://acme:p@ss@db', 'p@ss'),
            ('password="abc def"', 'abc def'), ("password='ab,cd'", 'ab,cd'), ('"password": "hunter2"', 'hunter2'),
            ('PASS=hunter2', 'hunter2'), ('DB_PASSWORD=hunter2', 'hunter2'), ('secret => hunter2', 'hunter2'),
            ('Authorization: Bearer CIRDAN_FAKE_eyJ', 'CIRDAN_FAKE_eyJ'), ('password%3Dhunter2', 'hunter2'),
            ('client_secret:hunter2', 'hunter2'), ('X-Api-Key: hunter2', 'hunter2'))
        for texto, secreto in casos:
            with self.subTest(texto):
                limpio = portada.sin_secretos('Error: %s // Werkzeug Debugger' % texto)
                self.assertNotIn(secreto, limpio)
                self.assertIn('***', limpio)
                self.assertTrue(limpio.endswith('// Werkzeug Debugger'), limpio)
        # Un 'usuario:contraseña' que quedó sin su '@' porque se cortó la zona
        self.assertEqual(portada.sin_secretos('Error: postgresql://acme:CIRDAN_FAKE_x'), 'Error: postgresql://***')

    def test_13_el_titulo_va_sin_marcas_ni_caracteres_que_la_base_no_acepta(self):
        for titulo in ('&lt;img src=x onerror=alert(1)&gt; // Werkzeug Debugger', 'a\x00b // Werkzeug Debugger',
                       'a&#0;b // Werkzeug Debugger', '﻿a\x07b // Werkzeug Debugger'):
            with self.subTest(titulo):
                vistos = portada.revisar(500, '<title>%s</title>' % titulo)
                self.assertEqual([v['firma'] for v in vistos], ['werkzeug'])
                for caracter in '<>\x00\x07﻿':
                    self.assertNotIn(caracter, vistos[0]['titulo_pagina'])
        # Por la visita entera: contrato.validar acepta el hallazgo
        pagina = dict(pagina_portada('werkzeug_500'), cuerpo='<title>a\x00&lt;b&gt; // Werkzeug Debugger</title>')
        res, _, _ = correr({'https://%s/' % DOMINIO: pagina})
        self.assertEqual([h.codigo for h in res.hallazgos], ['debug_page_exposed'])
        self.assertEqual(contrato.validar(res, visita.CODIGOS), [])

    def test_14_un_mensaje_largo_y_los_avisos_de_php_antes_del_fatal(self):
        sql = 'SELECT ' + ', '.join('columna_%d' % i for i in range(60)) + ' FROM tabla'
        self.assertGreater(len(sql), 300)
        for cuerpo, firma in (
                ('<title>OperationalError: %s // Werkzeug Debugger</title>' % sql, 'werkzeug'),
                ('<title>An exception occurred while executing a query: %s (500 Internal Server Error)</title>'
                 % sql, 'symfony'),
                ('<br />\n<b>Warning</b>:  require(/var/www/vendor/autoload.php): Failed to open stream: No such '
                 'file or directory in <b>/var/www/index.php</b> on line <b>3</b><br />\n<br />\n<b>Fatal error</b>'
                 ':  Uncaught Error: Failed opening required in /var/www/index.php:3', 'php'),
                ('﻿<br /><b>Fatal error</b>: x in <b>/a.php</b> on line <b>3</b>', 'php')):
            with self.subTest(firma=firma, cuerpo=cuerpo[:40]):
                self.assertEqual([v['firma'] for v in portada.revisar(500, cuerpo)], [firma])
        # Un aviso solo, sin el Fatal error, no es la página de depuración
        self.assertEqual(portada.revisar(200, '<b>Warning</b>: x in <b>/a.php</b> on line <b>3</b>'), [])

    def test_15_el_lector_es_lineal_y_salta_comentarios_y_scripts(self):
        for cuerpo in ('<a ' * 20000, '<' * 60000, '<svg ' * 12000, '<title>' + '<a ' * 20000, '<!--' * 15000):
            with self.subTest(cuerpo=cuerpo[:12]):
                antes = time.monotonic()
                portada.revisar(200, cuerpo)
                self.assertLess(time.monotonic() - antes, 1.0)
        for cuerpo in ('<!-- <title>Index of /</title> --><title>Acme</title><h1>Acme</h1>',
                       '<script>var t = "<title>Index of /</title>";</script><title>Acme</title><h1>Acme</h1>',
                       '<style>h1:after{content:"<h1>Index of /</h1>"}</style><h1>Acme</h1>'):
            with self.subTest(cuerpo=cuerpo[:20]):
                self.assertEqual(portada.revisar(200, cuerpo), [])
        self.assertEqual(portada.zonas('<svg/><title>Index of /</title>')['titulo'], 'Index of /')


class TurnoHost(unittest.TestCase):
    """Una petición a la vez por host también entre escaneos (comentario 10281.2 de RC-46, turno.py): cada petición a un
    sitio de las actividades 6 (web), 8 (identity) y 9 (api_docs) va dentro del turno de su host. El candado real es de
    PostgreSQL (orquestador._turno_host) y se prueba con la base en test_orquestador.py. Aquí va uno simulado."""

    def setUp(self):
        from cirdan.recolectores import api_docs, identidad, turno
        self.api_docs, self.identidad, self.turno = api_docs, identidad, turno
        self.eventos, self.reloj = [], [0.0]

    def visitar(self, url, timeout):
        self.eventos.append(('pide', url, timeout))
        return {'rechazada': True}

    @contextlib.contextmanager
    def candado(self, host, espera):
        self.eventos.append(('entra', host, espera))
        try:
            yield
        finally:
            self.eventos.append(('sale', host))

    def clientes(self):
        comun = dict(modo='vivo', visitar=self.visitar, cronometro=lambda: self.reloj[0], dormir=self.dormir)
        return {
            'web': (visita.ClienteWeb(carpeta=visita.carpeta_de(DOMINIO), **comun),
                    lambda c, host: c.sitio('https://%s/' % host)),
            'identity': (self.identidad.ClienteIdentidad(carpeta=self.identidad.carpeta_de(DOMINIO), **comun),
                         lambda c, host: c.sitio('https://%s/' % host)),
            'api_docs': (self.api_docs.ClienteApiDocs(carpeta=self.api_docs.carpeta_de(DOMINIO), **comun),
                         lambda c, host: c.ruta(host, self.api_docs.RUTAS[0])),
        }

    def dormir(self, segundos):
        self.eventos.append(('pausa', segundos))

    def test_1_sin_candado_la_peticion_sale_sin_esperar(self):
        # La línea de comandos y las pruebas sin base no ponen candado: turno() no espera nada.
        self.assertIsNone(self.turno._CANDADO.get())
        for fuente, (cliente, pedir) in self.clientes().items():
            with self.subTest(fuente=fuente):
                self.eventos.clear()
                pedir(cliente, 'www.' + DOMINIO)
                self.assertEqual([e[0] for e in self.eventos], ['pide'])

    def test_2_cada_peticion_va_dentro_del_turno_de_su_host(self):
        for fuente, (cliente, pedir) in self.clientes().items():
            with self.subTest(fuente=fuente), self.turno.con_candado(self.candado):
                self.eventos.clear()
                pedir(cliente, 'WWW.' + DOMINIO.upper())
                pedir(cliente, 'blog.' + DOMINIO)
                host1, host2 = 'www.' + DOMINIO, 'blog.' + DOMINIO
                self.assertEqual([e[:2] for e in self.eventos],
                                 [('entra', host1), ('pide', self.eventos[1][1]), ('sale', host1), ('pausa', 1),
                                  ('entra', host2), ('pide', self.eventos[5][1]), ('sale', host2)])
                # La pausa del ritmo fijo va fuera del turno: el host no queda apartado mientras duerme.
                self.assertEqual(urlsplit(self.eventos[1][1]).hostname, host1)
                # La espera es lo que le queda a la corrida, menos lo que necesita la petición.
                self.assertEqual(self.eventos[0][2], cliente.restante() - shodan.MIN_INTENTO)
        self.assertIsNone(self.turno._CANDADO.get(), 'con_candado() no quitó el candado al salir')

    def test_3_sin_turno_no_sale_la_peticion(self):
        @contextlib.contextmanager
        def ocupado(host, espera):
            raise self.turno.SinTurno('otro escaneo tuvo el turno de %s' % host)
            yield
        self.assertTrue(issubclass(self.turno.SinTurno, shodan.SinTiempo), 'lo que falta tiene que quedar sin revisar')
        for fuente, (cliente, pedir) in self.clientes().items():
            with self.subTest(fuente=fuente), self.turno.con_candado(ocupado):
                self.eventos.clear()
                with self.assertRaises(shodan.SinTiempo):
                    pedir(cliente, 'www.' + DOMINIO)
                self.assertEqual(self.eventos, [])
                self.assertEqual((cliente.pedidas, cliente.consultas), (0, 0))

    def test_4_el_plazo_de_la_peticion_es_lo_que_queda_tras_esperar_el_turno(self):
        def tardado(segundos):
            @contextlib.contextmanager
            def candado(host, espera):
                self.reloj[0] += segundos   # otro escaneo tuvo el host todo ese tiempo
                yield
            return candado
        for fuente, (cliente, pedir) in self.clientes().items():
            with self.subTest(fuente=fuente):
                self.reloj[0], self.eventos[:] = 0.0, []
                cliente.restante()   # arranca el reloj de la corrida
                with self.turno.con_candado(tardado(cliente.restante() - 3)):
                    pedir(cliente, 'www.' + DOMINIO)
                self.assertEqual([e[0] for e in self.eventos], ['pide'])
                self.assertAlmostEqual(self.eventos[0][2], 3)
                # Si la espera se comió la corrida, la petición ya no sale.
                with self.turno.con_candado(tardado(cliente.restante())), self.assertRaises(shodan.SinTiempo):
                    pedir(cliente, 'blog.' + DOMINIO)
                self.assertEqual([e[0] for e in self.eventos], ['pide', 'pausa'])

    def test_5_toda_peticion_a_un_sitio_sale_dentro_del_turno(self):
        # Por el texto: la única llamada a la función que pide al sitio está dentro de `with turno.turno(`, en el mismo
        # hilo. identidad.py no pide por su cuenta: pasa por visita.ClienteWeb.sitio.
        raiz = Path(__file__).resolve().parent.parent / 'cirdan' / 'recolectores'
        for archivo in ('visita.py', 'api_docs.py'):
            with self.subTest(archivo=archivo):
                lineas = (raiz / archivo).read_text(encoding='utf-8').splitlines()
                llamadas = [i for i, l in enumerate(lineas) if '(self.visitar or _visitar)(' in l]
                self.assertEqual(len(llamadas), 1)
                bloque = lineas[llamadas[0] - 6:llamadas[0]]
                self.assertTrue(any(l.strip().startswith('with turno.turno(') for l in bloque), archivo)
        identidad = (raiz / 'identidad.py').read_text(encoding='utf-8')
        self.assertNotIn('self.visitar(', identidad)
        self.assertNotIn('transporte.visitar(', identidad)


if __name__ == '__main__':
    unittest.main()
