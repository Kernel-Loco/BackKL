"""Pruebas sin red de la visita web de la actividad 6 (cirdan/recolectores/visita.py, #18, RC-46).

Los sitios se simulan con ClienteWeb(visitar=...), Cert Spotter, endoflife.date y la NVD con ClienteWeb(descargar=...)
y el A con el ResolvedorSimulado de test_shodan. Las conexiones de transporte.py se prueban con resolver y socket
cambiados: nada sale a la red.

Uso, desde la raíz del repo:
  python -m unittest pruebas/test_visita.py
"""
import email.message
import importlib
import json
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))  # también corre como python pruebas/test_visita.py
from pruebas import test_subfinder  # noqa: E402
from pruebas.test_geoip import bases as bases_geo  # noqa: E402
from pruebas.test_huellas import FIXTURES_BORDE, fixture  # noqa: E402
from pruebas.test_shodan import ResolvedorSimulado, a, error_http, paginas  # noqa: E402
from cirdan.recolectores import REGISTRO, contrato, rdap, shodan, transporte, visita  # noqa: E402

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
        if 'certspotter' in url:
            respuesta = self.ct.pop(0) if self.ct else []
        elif 'endoflife.date' in url:
            respuesta = self.eol
        elif 'services.nvd.nist.gov' in url:
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
        self.assertEqual(sorted(h.codigo for h in res.hallazgos), ['known_vulnerability'] * 3 + ['outdated_software'])
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
        self.assertEqual(res.sin_cobertura, list(visita.CODIGOS))
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
        self.assertEqual([h.codigo for h in res.hallazgos], ['outdated_software'])   # lo de endoflife.date sí llegó
        self.assertEqual(res.cves, [])
        self.assertEqual(res.revisados, [])
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

    def test_2_un_403_es_una_respuesta_y_el_cuerpo_se_corta(self):
        def abrir(req, plazo, cronometro, *_):
            raise urllib.error.HTTPError(req.full_url, 403, 'Forbidden', email.message.Message(),
                                         __import__('io').BytesIO(b'x' * (visita.MAX_BYTES_SITIO + 10)))
        with mock.patch.object(transporte, 'abrir', abrir):
            r = visita._visitar('https://%s/' % DOMINIO, 5)
        self.assertEqual((r['estado'], r['cortado'], len(r['cuerpo'])), (403, True, visita.MAX_BYTES_SITIO))

    def test_3_motivos_de_lo_que_no_termino(self):
        casos = ((urllib.error.URLError(transporte.NoPublica('x')), {'sin_respuesta': 'no_publica'}),
                 (urllib.error.URLError(ssl.SSLCertVerificationError('x')), {'sin_respuesta': 'certificado'}),
                 (urllib.error.URLError(ConnectionRefusedError()), {'rechazada': True}),
                 (urllib.error.URLError(OSError('x')), {'sin_respuesta': 'red'}),
                 (urllib.error.URLError(ssl.SSLError(1, '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]')),
                  {'sin_respuesta': 'tls'}),
                 (ssl.SSLError(1, '[SSL: UNSUPPORTED_PROTOCOL]'), {'sin_respuesta': 'tls'}),
                 (urllib.error.URLError(ssl.SSLEOFError(8, 'EOF occurred in violation of protocol')),
                  {'sin_respuesta': 'red'}),
                 (transporte.PlazoVencido('x'), {'sin_respuesta': 'tiempo'}),
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
        self.conectar([nat64, IP])   # sin familia, como las demás fuentes, que piden a servidores fijos
        self.assertEqual(self.Socket.conectadas, [nat64])


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
        self.assertEqual(set(visita.CODIGOS), {'outdated_software', 'known_vulnerability'})


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
                self.assertEqual((res.revisados, res.sin_revisar), ([], [DOMINIO]))   # no se cierra nada

    def test_3_con_un_comodin_y_un_sitio_que_no_respondio_no_se_dice_cuales_faltan(self):
        """La raíz no responde (a lo mejor redirigía a www, que solo está bajo el comodín) y blog no tiene A: solo se
        cierra lo de blog. Sin comodín, o si la raíz respondió (un 5xx), sí se dice cuál falta."""
        raiz = 'https://%s/' % DOMINIO
        casos = (('comodín y sin respuesta', paginas('*.' + DOMINIO, BLOG), {'sin_respuesta': 'tiempo'}, None),
                 ('sin comodín', paginas(BLOG), {'sin_respuesta': 'tiempo'}, [DOMINIO]),
                 ('comodín y 5xx', paginas('*.' + DOMINIO, BLOG), pagina_nginx(502), [DOMINIO]))
        for nombre, ct, raiz_responde, faltan in casos:
            with self.subTest(nombre):
                res, _, _ = correr({raiz: raiz_responde}, zona={DOMINIO: a(IP)}, apis=Apis(ct=ct))
                self.assertIn(BLOG, res.revisados)
                self.assertNotIn(DOMINIO, res.revisados)
                self.assertEqual(None if res.sin_revisar is None else sorted({x.rstrip('.') for x in res.sin_revisar}),
                                 faltan)

    def test_4_un_error_del_servidor_queda_sin_revisar(self):
        """Un 5xx puede ser fijo del sitio (un subdominio olvidado): no es una falla de la corrida y sí se graba."""
        for estado in (500, 502, 504, 520):
            with self.subTest(estado), tempfile.TemporaryDirectory() as d:
                res, cliente, _ = correr({'https://%s/' % DOMINIO: pagina_nginx(estado)}, modo='grabar',
                                         carpeta=Path(d) / DOMINIO)
                self.assertTrue(list((Path(d) / DOMINIO).glob('*.json')))
                self.assertEqual(activo(res, DOMINIO).atributos['web']['sin_revisar'], visita.MOTIVOS['error_http'])
                self.assertEqual((res.hallazgos, res.sin_cobertura), ([], list(visita.CODIGOS)))
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
        self.assertEqual((res.revisados, res.sin_revisar), ([], [DOMINIO]))

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
            self.assertEqual((completa.revisados, len(completa.hallazgos)), (None, 4))
            for archivo in archivos:
                bueno = archivo.read_text(encoding='utf-8')
                for roto in (bueno[:len(bueno) // 2], '{"datos": 5}', '"x"'):
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
        self.assertEqual(horas, [0.0, 6.0, 12.0])   # PAUSA_NVD entre peticiones, literal
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
        self.assertEqual(horas, [0.0, 6.0, 12.0, 18.0, 24.0, 30.0])
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
            self.assertEqual({x.rstrip('.') for x in res.revisados}, set(visitados[-1]))
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


if __name__ == '__main__':
    unittest.main()
