"""Pruebas sin red de la documentación de APIs a la vista (cirdan/recolectores/api_docs.py, #63, RC-118).

Los sitios se simulan con ClienteApiDocs(visitar=...), Cert Spotter con ClienteApiDocs(descargar=...) y el A con el
ResolvedorSimulado de test_shodan. La petición real (_visitar) se prueba con transporte.visitar cambiado: nada sale a
la red. Cada clase lleva el punto del Hecho cuando de RC-118 que cubre.

Uso, desde la raíz del repo:
  python -m unittest pruebas/test_api_docs.py
"""
import itertools
import json
import re
import shutil
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
sys.path.insert(0, str(RAIZ))  # también corre como python pruebas/test_api_docs.py
from pruebas import test_subfinder  # noqa: E402
from pruebas.test_shodan import HttpSimulado, ResolvedorSimulado, a, paginas  # noqa: E402
from cirdan.recolectores import REGISTRO, api_docs, cargar, contrato, transporte  # noqa: E402
from cirdan.recolectores.contrato import Activo  # noqa: E402

DOMINIO = 'acme-demo.mx'
API = 'api.acme-demo.mx'
IP = '104.21.48.10'
AHORA = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
SEMILLA = RAIZ / 'db' / 'semillas' / '013_api_docs.sql'
MIGRACION = RAIZ / 'db' / 'migraciones' / '015_tipo_activo_api_doc.sql'
MARCA = 'CIRDAN_FAKE_token_de_ejemplo_en_la_documentacion'
LLAVE = [{'llave': []}]


def openapi3(paths=None, security=None, **otros):
    """Un documento OpenAPI 3 con un servidor, un esquema de seguridad y un ejemplo con un token falso. Nada de eso se
    pide ni se guarda."""
    doc = {'openapi': '3.0.3', 'info': {'title': 'Pedidos de Acme', 'version': '1.4'},
           'servers': [{'url': 'https://%s/v1' % API}, {'url': 'https://interno.acme-demo.mx/v1'}],
           'components': {'securitySchemes': {'llave': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'}},
                          'examples': {'cabecera': {'value': MARCA}}},
           'paths': PATHS_SEMBRADOS if paths is None else paths}
    if security is not None:
        doc['security'] = security
    doc.update(otros)
    return doc


def swagger2(paths=None, security=None):
    doc = {'swagger': '2.0', 'info': {'title': 'Inventario de Acme', 'version': '2'}, 'host': API, 'basePath': '/v1',
           'schemes': ['https'],
           'securityDefinitions': {'llave': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'}},
           'paths': PATHS_SEMBRADOS if paths is None else paths}
    if security is not None:
        doc['security'] = security
    return doc


# La documentación sembrada: 5 funciones, 3 sin autenticación declarada (sin security, con [] y con [{}])
PATHS_SEMBRADOS = {
    '/pedidos': {'get': {'summary': 'Lista', 'security': LLAVE},
                 'post': {'summary': 'Crea', 'parameters': [{'name': 'token', 'example': MARCA}]},
                 'parameters': [{'name': 'pagina', 'in': 'query'}]},
    '/pedidos/{id}': {'get': {'security': []}, 'delete': {'security': [{}]}, 'put': {'security': LLAVE}},
}
SWAGGER_UI = b'<html><head><title>Swagger UI</title></head><body><div id="swagger-ui"></div></body></html>'


class Sitios:
    """Hace las veces de _visitar(url, timeout). `respuestas` da por URL (estado, cabeceras, cuerpo), que pasa por
    api_docs.resumir como la respuesta real, o un dict ya limpio (una redirección, un 443 cerrado, una falla). Un
    dict o una lista como cuerpo van como JSON. Una URL que no está es un 404."""

    def __init__(self, respuestas):
        self.respuestas, self.urls = respuestas, []

    def __call__(self, url, timeout):
        self.urls.append(url)
        respuesta = self.respuestas.get(url, (404, [], b'Not Found'))
        if isinstance(respuesta, dict):
            return respuesta
        estado, cabeceras, cuerpo = respuesta
        if isinstance(cuerpo, (dict, list)):
            cuerpo = json.dumps(cuerpo).encode()
        return api_docs.resumir(estado, cabeceras, cuerpo)


def correr(respuestas, zona=None, ct=None, modo='vivo', carpeta=None, cronometro=None):
    dormidas = []
    zona = {DOMINIO: a(IP), API: a(IP)} if zona is None else zona
    cliente = api_docs.ClienteApiDocs(
        modo=modo, carpeta=carpeta or api_docs.carpeta_de(DOMINIO), visitar=Sitios(respuestas),
        descargar=HttpSimulado(ct=paginas(API) if ct is None else ct), resolver=ResolvedorSimulado(zona),
        cronometro=cronometro or (lambda: 0.0), dormir=dormidas.append, nueva=(modo == 'grabar'))
    res = api_docs.recolectar(DOMINIO, cliente, ahora=AHORA)
    return res, cliente, dormidas


def url(host, ruta):
    return 'https://%s%s' % (host, ruta)


def activo(res, valor):
    return next(x for x in res.activos if x.valor == valor)


def hallazgos(res, codigo):
    return [h for h in res.hallazgos if h.codigo == codigo]


def partes(lista):
    """Los sitios de revisados o sin_revisar, una vez cada uno: borde.cobertura da cada nombre también con el punto
    final."""
    return None if lista is None else sorted({p.rstrip('.') for p in lista})


def esperadas(*hosts):
    """Las únicas URL que se pueden pedir a esos sitios: sus RUTAS, en orden."""
    return [url(h, r) for h in hosts for r in api_docs.RUTAS]


class Sembrada(unittest.TestCase):
    """Encuentra la documentación sembrada en un subdominio de prueba."""

    def test_1_encuentra_el_documento_sembrado_en_el_subdominio(self):
        res, cliente, dormidas = correr({url(API, '/openapi.json'): (200, [], openapi3())})
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(contrato.validar(res, codigos=set(api_docs.CODIGOS)), [])
        self.assertEqual(sorted(h.codigo for h in res.hallazgos), ['api_auth_not_declared', 'exposed_api_docs'])
        expuesta, = hallazgos(res, 'exposed_api_docs')
        self.assertEqual((expuesta.activo, expuesta.partes, expuesta.severidad), (API, [API], 'medium'))
        self.assertEqual(expuesta.evidencia['url'], url(API, '/openapi.json'))
        self.assertEqual(expuesta.evidencia['documentos'],
                         [{'url': url(API, '/openapi.json'), 'formato': 'OpenAPI', 'version': '3.0.3'}])
        # El documento es un activo api_doc, hijo de su sitio
        doc = activo(res, url(API, '/openapi.json'))
        self.assertEqual((doc.tipo, doc.atributos['host'], doc.atributos['parent']), ('api_doc', API, API))
        datos = doc.atributos
        self.assertEqual((datos['titulo'], datos['operaciones'], datos['no_declaran_autenticacion']),
                         ('Pedidos de Acme', 5, 3))
        self.assertLess(res.activos.index(activo(res, API)), res.activos.index(doc))   # el padre va antes
        self.assertEqual(activo(res, API).atributos['api_docs']['estado'], 'con_documentacion')
        self.assertEqual(activo(res, DOMINIO).atributos['api_docs']['estado'], 'revisado')
        # Todo revisado: nada parcial, y ningún aviso
        self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura, res.avisos), (None, None, [], []))
        # Ritmo fijo: una pausa antes de cada petición salvo la primera
        self.assertEqual(dormidas, [1] * 19)   # PAUSA_RUTA, literal para que la prueba vea si cambia
        self.assertEqual(api_docs.codigo_salida(res), 0)
        self.assertIn('api_doc %s: OpenAPI 3.0.3' % url(API, '/openapi.json'), api_docs.resumen(res))

    def test_2_un_sitio_sin_documentacion_no_da_hallazgos(self):
        res, _, _ = correr({})
        self.assertEqual((res.estado, res.hallazgos), ('succeeded', []))
        self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura), (None, None, []))
        self.assertEqual([x.tipo for x in res.activos], ['domain', 'subdomain'])
        self.assertEqual(contrato.validar(res, codigos=set(api_docs.CODIGOS)), [])

    def test_3_la_pagina_de_swagger_ui_tambien_cuenta_y_no_trae_conteo(self):
        res, _, _ = correr({url(API, '/swagger-ui/'): (200, [], SWAGGER_UI),
                            url(API, '/docs'): (200, [], b'<html><redoc spec-url="/x.json"></redoc></html>'),
                            url(DOMINIO, '/docs'): (200, [], b'<html><h1>Documentos de la empresa</h1></html>')})
        self.assertEqual([h.codigo for h in res.hallazgos], ['exposed_api_docs'])   # la raíz no: su /docs es otra cosa
        self.assertEqual(res.hallazgos[0].activo, API)
        # Swagger UI y ReDoc en el mismo sitio son dos páginas distintas: cada una es su activo
        self.assertEqual([d['url'] for d in res.hallazgos[0].evidencia['documentos']],
                         [url(API, '/swagger-ui/'), url(API, '/docs')])
        pagina = activo(res, url(API, '/swagger-ui/')).atributos
        self.assertEqual((pagina['formato'], pagina['operaciones'], pagina['tambien_en']),
                         ('página de documentación', None, []))
        self.assertEqual(activo(res, url(API, '/docs')).atributos['tambien_en'], [])
        self.assertEqual(contrato.validar(res, codigos=set(api_docs.CODIGOS)), [])

    def test_4_el_mismo_documento_en_dos_rutas_es_un_solo_activo(self):
        res, _, _ = correr({url(API, '/openapi.json'): (200, [], openapi3()),
                            url(API, '/v3/api-docs'): (200, [], openapi3()),
                            url(API, '/swagger.json'): (200, [], swagger2())})
        docs = [x for x in res.activos if x.tipo == 'api_doc']
        self.assertEqual([x.valor for x in docs], [url(API, '/openapi.json'), url(API, '/swagger.json')])
        self.assertEqual(docs[0].atributos['tambien_en'], [url(API, '/v3/api-docs')])
        self.assertEqual(len(hallazgos(res, 'exposed_api_docs')), 1)          # uno por sitio
        self.assertEqual(len(hallazgos(res, 'api_auth_not_declared')), 2)     # uno por documento
        self.assertEqual(contrato.validar(res, codigos=set(api_docs.CODIGOS)), [])

    def test_5_la_huella_no_cambia_con_la_version_ni_con_el_conteo(self):
        uno, _, _ = correr({url(API, '/openapi.json'): (200, [], openapi3())})
        distinto = openapi3(paths={'/a': {'get': {}}}, openapi='3.1.0')
        otro, _, _ = correr({url(API, '/openapi.json'): (200, [], distinto)})
        self.assertEqual([h.huella for h in uno.hallazgos], [h.huella for h in otro.hallazgos])
        self.assertEqual(len({h.huella for h in uno.hallazgos}), 2)


class ListaFija(unittest.TestCase):
    """Usa una lista fija de máximo 10 rutas en el repo, solo GET."""

    def test_1_la_lista_es_fija_de_a_lo_mas_10_rutas(self):
        self.assertEqual(api_docs.MAX_RUTAS, 10)
        self.assertLessEqual(len(api_docs.RUTAS), 10)   # literal: el tope del Anexo A, no el de la constante
        self.assertIsInstance(api_docs.RUTAS, tuple)
        self.assertEqual(len(set(api_docs.RUTAS)), len(api_docs.RUTAS))
        for ruta in api_docs.RUTAS:
            self.assertRegex(ruta, r'\A/[A-Za-z0-9._/-]+\Z')   # sin consulta, sin fragmento y sin '..' que sirva
            self.assertNotIn('..', ruta)
        for ejemplo in ('/openapi.json', '/swagger.json', '/v3/api-docs', '/swagger-ui/'):   # las de la tarjeta
            self.assertIn(ejemplo, api_docs.RUTAS)

    def test_2_solo_se_piden_las_rutas_de_la_lista_y_en_orden(self):
        res, cliente, _ = correr({url(API, '/openapi.json'): (200, [], openapi3())})
        self.assertEqual(cliente.visitar.urls, esperadas(DOMINIO, API))

    def test_3_una_ruta_fuera_de_la_lista_no_se_pide(self):
        cliente = api_docs.ClienteApiDocs(visitar=Sitios({}), cronometro=lambda: 0.0, dormir=lambda s: None)
        for ruta in ('/pedidos', '/openapi.json?x=1', 'openapi.json', '/admin', ''):
            with self.assertRaises(ValueError, msg=ruta):
                cliente.ruta(API, ruta)
        self.assertEqual((cliente.visitar.urls, cliente.consultas), ([], 0))

    def test_4_la_peticion_es_un_get_por_https_sin_cuerpo_y_con_el_agente_de_la_carta(self):
        vistas = []

        def visitar(req, plazo, tope, cronometro=None):
            vistas.append(req)
            return 200, [('Content-Type', 'application/json')], json.dumps(openapi3()).encode(), False
        with mock.patch.object(transporte, 'visitar', visitar):
            respuesta = api_docs._visitar(url(API, '/openapi.json'), 10, cronometro=lambda: 0.0)
        req, = vistas
        self.assertEqual((req.get_method(), req.full_url, req.data), ('GET', url(API, '/openapi.json'), None))
        self.assertEqual(req.get_header('User-agent'), contrato.AGENTE)
        self.assertEqual(sorted(k.lower() for k in req.headers), ['accept', 'user-agent'])   # sin credenciales
        self.assertEqual(respuesta['doc']['operaciones'], 5)

    def test_5_en_el_modulo_no_hay_otro_metodo_http(self):
        fuente = Path(api_docs.__file__).read_text(encoding='utf-8')
        self.assertEqual(re.findall(r"method\s*=\s*'(\w+)'", fuente), ['GET'])
        self.assertNotIn('data=', fuente)


class LimiteDiario(unittest.TestCase):
    """Con el límite diario de #13b."""

    def test_1_declara_su_peor_caso(self):
        # 2 páginas x 2 intentos, 20 A x 3 intentos y 20 sitios x 10 rutas
        self.assertEqual(api_docs.MAX_CONSULTAS, 264)
        self.assertEqual(REGISTRO['api_docs'], 'cirdan.recolectores.api_docs')
        self.assertIs(cargar('api_docs'), api_docs)
        self.assertEqual((api_docs.FUENTE, set(api_docs.CODIGOS.values())), ('api_docs', {'medium'}))

    def test_2_el_peor_caso_no_pasa_de_su_maximo(self):
        """25 nombres con sitio: solo 20 se revisan, con sus 10 rutas, y el DNS y Cert Spotter responden al último
        intento."""
        nombres = ['s%02d.%s' % (i, DOMINIO) for i in range(25)]
        zona = {n: ['falla', 'falla', a(IP)] for n in [DOMINIO] + nombres}
        ct = [502, paginas(*nombres)[0], 502, []]
        res, cliente, _ = correr({}, zona=zona, ct=ct)
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(len(cliente.visitar.urls), 20 * 10)
        self.assertEqual(res.consultas, api_docs.MAX_CONSULTAS)
        self.assertEqual(len(partes(res.revisados)), 20)
        self.assertIsNone(res.sin_revisar)   # no se sabe cuáles nombres quedaron fuera
        self.assertTrue(any('MAX_SITIOS' in x for x in res.avisos))

    def test_3_la_semilla_da_10_corridas_por_dia_y_la_deja_apagada(self):
        with mock.patch.object(test_subfinder, 'SEMILLA', SEMILLA):
            fila = test_subfinder.fila_de_la_semilla('api_docs')
        self.assertIsNotNone(fila, 'la semilla 013 no trae la fila de api_docs')
        self.assertEqual(int(fila['daily_limit']), 10 * api_docs.MAX_CONSULTAS)
        self.assertEqual((fila['kind'], fila['enabled'].lower(), fila['keep_raw_payload'].lower()),
                         ("'osint'", 'false', 'true'))


class Autorizados(unittest.TestCase):
    """Solo en subdominios autorizados."""

    def test_1_un_nombre_de_otro_dominio_en_el_certificado_no_se_pide(self):
        ct = paginas(API, 'api.otra-empresa.com', 'acme-demo.mx.atacante.net', 'xacme-demo.mx')
        zona = {DOMINIO: a(IP), API: a(IP), 'api.otra-empresa.com': a(IP), 'acme-demo.mx.atacante.net': a(IP),
                'xacme-demo.mx': a(IP)}
        res, cliente, _ = correr({}, zona=zona, ct=ct)
        self.assertEqual(cliente.visitar.urls, esperadas(DOMINIO, API))
        self.assertEqual(sorted(cliente.resolver.nombres), [DOMINIO, API])
        self.assertEqual(sorted(x.valor for x in res.activos), [DOMINIO, API])

    def test_2_una_redireccion_no_se_sigue_ni_dentro_del_dominio(self):
        def visitar(req, plazo, tope, cronometro=None):
            raise transporte.Redirigida(302, API, 'https://login.otra-empresa.com/openapi.json')
        with mock.patch.object(transporte, 'visitar', visitar):
            self.assertEqual(api_docs._visitar(url(API, '/openapi.json'), 10, cronometro=lambda: 0.0),
                             {'redirige': True, 'codigo': 302})   # el destino ni se guarda
        respuestas = {u: {'redirige': True, 'codigo': 301} for u in esperadas(API)}
        res, cliente, _ = correr(respuestas)
        self.assertEqual(cliente.visitar.urls, esperadas(DOMINIO, API))
        self.assertEqual(res.hallazgos, [])
        self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura), (None, None, []))

    def test_3_un_nombre_sin_a_o_con_ip_interna_no_se_visita(self):
        zona = {DOMINIO: a(IP), API: a('10.0.0.8'), 'viejo.' + DOMINIO: ('nxdomain', [], [])}
        res, cliente, _ = correr({}, zona=zona, ct=paginas(API, 'viejo.' + DOMINIO))
        self.assertEqual(cliente.visitar.urls, esperadas(DOMINIO))
        self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura), (None, None, []))
        # Sí se reportan, con su estado: si antes tenían documentación, el activo no se queda diciendo que la tiene
        for nombre, estado in ((API, 'no_publica'), ('viejo.' + DOMINIO, 'sin_a')):
            self.assertEqual(activo(res, nombre).atributos['api_docs'],
                             {'fuente': 'api_docs', 'estado': estado, 'documentos': []})
        self.assertEqual(contrato.validar(res, codigos=set(api_docs.CODIGOS)), [])

    def test_4_el_contrato_no_acepta_un_api_doc_de_otro_sitio(self):
        def errores(valor, atributos):
            res = contrato.Resultado(DOMINIO, 'api_docs')
            res.activos = [Activo('api_doc', valor, atributos)]
            return contrato.validar(res)
        self.assertEqual(errores(url(API, '/openapi.json'), {'host': API}), [])
        for valor in ('https://api.otra-empresa.com/openapi.json', 'http://%s/openapi.json' % API,
                      'https://%s:8443/openapi.json' % API, 'https://u:p@%s/openapi.json' % API,
                      'https://%s/openapi.json?x=1' % API, 'https://%s' % API, '/openapi.json',
                      'https://%s@api.otra-empresa.com/openapi.json' % API,
                      # urlsplit quita los tabuladores y los saltos de línea antes de leer la URL
                      'https://%s/open\tapi.json' % API, 'https://%s/openapi.json\n' % API,
                      'ht\ntps://%s/openapi.json' % API, 'https://%s/open api.json' % API):
            self.assertTrue(any('URL https' in e for e in errores(valor, {'host': API})), valor)
        self.assertTrue(any("'host'" in e for e in errores(url(API, '/openapi.json'), {})))
        self.assertIn('api_doc', contrato.TIPOS_ACTIVO)

    def test_5_el_filtro_de_alcance_quita_un_api_doc_de_otro_dominio(self):
        res = contrato.Resultado(DOMINIO, 'api_docs')
        fuera = 'https://api.otra-empresa.com/openapi.json'
        res.activos = [Activo('api_doc', url(API, '/openapi.json'), {'host': API}),
                       Activo('api_doc', fuera, {'host': 'api.otra-empresa.com'})]
        contrato.filtrar_alcance(res)
        self.assertEqual([x.valor for x in res.activos], [url(API, '/openapi.json')])
        self.assertTrue(contrato.en_alcance(res.activos[0], DOMINIO))


class NuncaLlama(unittest.TestCase):
    """Nunca llama a los endpoints documentados."""

    def test_1_nada_de_lo_que_dice_el_documento_se_pide(self):
        doc = openapi3(externalDocs={'url': 'https://%s/manual' % API})
        pagina = SWAGGER_UI.replace(b'</body>', b'<script>SwaggerUIBundle({url: "/interno/api.json"})</script></body>')
        res, cliente, _ = correr({url(API, '/openapi.json'): (200, [], doc),
                                  url(API, '/swagger.json'): (200, [], swagger2()),
                                  url(API, '/swagger-ui/'): (200, [], pagina)})
        self.assertEqual(cliente.visitar.urls, esperadas(DOMINIO, API))
        pedidas = ' '.join(cliente.visitar.urls + cliente.descargar.urls)
        for prohibida in ('/pedidos', API + '/v1', 'interno', '/manual'):
            self.assertNotIn(prohibida, pedidas)
        self.assertEqual(sorted(cliente.resolver.nombres), [DOMINIO, API])   # tampoco resuelve los servidores
        self.assertIn('no se llamaron', hallazgos(res, 'api_auth_not_declared')[0].evidencia['nota'])

    def test_2_del_documento_solo_queda_el_resumen(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            res, _, _ = correr({url(API, '/openapi.json'): (200, [], openapi3())}, modo='grabar', carpeta=carpeta)
            grabado = ''.join(p.read_text(encoding='utf-8') for p in carpeta.glob('*.json'))
            otra, cliente, _ = correr({}, modo='reproducir', carpeta=carpeta)
        self.assertEqual((otra.activos, otra.hallazgos), (res.activos, res.hallazgos))
        self.assertEqual((cliente.visitar.urls, otra.consultas), ([], 0))   # al reproducir no se pide nada
        guardado = grabado + json.dumps([contrato.asdict(x) for x in res.activos + res.hallazgos])
        for ausente in (MARCA, 'X-API-Key', 'interno.acme-demo.mx', 'securitySchemes', 'summary'):
            self.assertNotIn(ausente, guardado)
        self.assertIn('"operaciones": 5', grabado)
        # Primero las que cambian datos
        self.assertEqual(hallazgos(res, 'api_auth_not_declared')[0].evidencia['muestra'],
                         ['POST /pedidos', 'DELETE /pedidos/{id}', 'GET /pedidos/{id}'])


class Conteo(unittest.TestCase):
    """Lee Swagger 2.0 y OpenAPI 3.x y cuenta los endpoints sin security propio ni global, o con security vacío."""

    CASOS = (   # (security global, security de la función o None si no trae, declara)
        (None, None, False),             # ni propio ni global
        (None, [], False),               # propio vacío
        (None, [{}], False),             # un requisito vacío deja entrar sin identificarse
        (None, LLAVE, True),             # propio
        (LLAVE, None, True),             # global
        (LLAVE, [], False),              # el propio vacío quita el global
        (LLAVE, [{}], False),
        (LLAVE, LLAVE + [{}], False),    # autenticación opcional
        ([], None, False),               # global vacío
        ([], LLAVE, True),
        ([{}], None, False),
        (None, [{'llave': []}, {'oauth': ['leer']}], True),
        (None, 'llave', False),          # no es una lista: no declara nada que se pueda leer
    )

    def test_1_cuenta_igual_en_swagger_2_y_en_openapi_3(self):
        for armar, formato, version in ((swagger2, 'swagger', '2.0'), (openapi3, 'openapi', '3.0.3')):
            for general, propia, declara in self.CASOS:
                funcion = {} if propia is None else {'security': propia}
                paths = {'/a': {'get': funcion, 'post': {'security': LLAVE}}}
                doc = api_docs.leer(armar(paths=paths, security=general))
                self.assertEqual((doc['formato'], doc['version'], doc['operaciones']), (formato, version, 2))
                self.assertEqual(doc['sin_declarar'], 0 if declara else 1, (formato, general, propia))
                self.assertEqual(doc['muestra'], [] if declara else ['GET /a'])

    def test_2_openapi_3_1_y_swagger_como_numero(self):
        self.assertEqual(api_docs.leer(openapi3(openapi='3.1.0'))['version'], '3.1.0')
        doc = swagger2()
        doc['swagger'] = 2.0
        self.assertEqual(api_docs.leer(doc)['version'], '2.0')
        for otro in ({'openapi': '4.0.0', 'paths': {}}, {'swagger': '1.2', 'apis': []}, {'paths': {}}, [], 'x', None,
                     {'openapi': True}, {'openapi': '3.0.3 <script>'}):
            self.assertIsNone(api_docs.leer(otro), otro)

    def test_3_solo_cuentan_los_metodos_http_de_cada_ruta(self):
        paths = {'/a': {'get': {}, 'GET ': {}, 'parameters': [], 'summary': 'x', 'x-interno': {}, 'servers': [],
                        'head': {}, 'options': {}, 'trace': {}, 'patch': {}, 'post': 'roto', '$ref': '#/x'},
                 'sin-barra': {'get': {}}, '/b': 'roto', '/c': None, 7: {'get': {}}}
        doc = api_docs.leer(openapi3(paths=paths))
        self.assertEqual((doc['operaciones'], doc['sin_declarar']), (5, 5))
        self.assertEqual(doc['muestra'][0], 'PATCH /a')   # primero las que cambian datos
        for roto in ([], 'x', 7, {}):
            self.assertEqual(api_docs.leer(openapi3(paths=roto))['operaciones'], 0)
        sin_paths = openapi3()
        del sin_paths['paths']
        self.assertEqual(api_docs.leer(sin_paths)['operaciones'], 0)

    def test_4_un_documento_sin_funciones_abiertas_no_da_el_segundo_hallazgo(self):
        res, _, _ = correr({url(API, '/swagger.json'): (200, [], swagger2(security=LLAVE, paths={'/a': {'get': {}}}))})
        self.assertEqual([h.codigo for h in res.hallazgos], ['exposed_api_docs'])
        self.assertEqual(activo(res, url(API, '/swagger.json')).atributos['no_declaran_autenticacion'], 0)

    def test_5_la_muestra_es_de_a_lo_mas_10_y_los_textos_se_cortan(self):
        paths = {'/r%02d' % i: {'get': {}} for i in range(40)}
        paths['/' + 'x' * 500] = {'delete': {}}
        doc = api_docs.leer(openapi3(paths=paths, info={'title': 'T' * 900 + '\x00\n'}))
        self.assertEqual((doc['operaciones'], doc['sin_declarar'], len(doc['muestra'])), (41, 41, 10))
        self.assertEqual(len(doc['muestra'][0]), len('DELETE ') + 200)
        self.assertEqual(len(doc['titulo']), 200)
        self.assertEqual(api_docs.limpiar({'estado': 200, 'doc': doc}), {'estado': 200, 'doc': doc})

    def test_6_lo_que_no_es_un_documento_no_cuenta(self):
        for cuerpo in (b'', b'{"ok": true}', b'[1, 2]', b'{"openapi": "3.0.3"', b'<html>hola</html>', b'\xff\xfe',
                       b'{"swagger": "2.0", "paths": ' + b'[' * 5000, None, 7):
            self.assertIsNone(api_docs.analizar(cuerpo), cuerpo)
        self.assertEqual(api_docs.analizar('﻿' + json.dumps(swagger2()))['formato'], 'swagger')
        self.assertEqual(api_docs.analizar(b'  \n{"openapi": "3.0.3", "paths": {"/a": {"get": {}}}}')['operaciones'], 1)
        # Un 200 con documento solo cuenta con estado 200: un 401 con el mismo cuerpo no
        self.assertIsNone(api_docs.resumir(401, [], json.dumps(openapi3()).encode())['doc'])


class Texto(unittest.TestCase):
    """El portal dice 'no declara autenticación', no 'sin autenticación'."""

    def test_1_el_titulo_y_la_evidencia_dicen_no_declara(self):
        res, _, _ = correr({url(API, '/openapi.json'): (200, [], openapi3())})
        hallazgo, = hallazgos(res, 'api_auth_not_declared')
        self.assertEqual(hallazgo.titulo, 'La documentación de %s no declara autenticación en 3 de 5 funciones' % API)
        self.assertEqual(hallazgo.evidencia['title'], hallazgo.titulo)
        self.assertEqual((hallazgo.activo, hallazgo.partes), (url(API, '/openapi.json'), [API]))
        self.assertEqual((hallazgo.evidencia['sin_declarar'], hallazgo.evidencia['operaciones']), (3, 5))
        self.assertEqual(hallazgo.caracteristicas['sensibilidad'], 'media')
        todo = json.dumps([contrato.asdict(x) for x in res.activos + res.hallazgos], ensure_ascii=False)
        todo += ' '.join(res.avisos) + api_docs.resumen(res)
        self.assertIn('no declara autenticación', todo)
        for prohibido in ('sin autenticación', 'sin autenticacion', 'sin_autenticacion', 'sin protección',
                          'desprotegid', 'vulnerable'):
            self.assertNotIn(prohibido, todo.lower())

    def test_2_con_una_sola_funcion_el_titulo_va_en_singular(self):
        res, _, _ = correr({url(API, '/openapi.json'): (200, [], openapi3(paths={'/a': {'get': {}}}))})
        self.assertTrue(hallazgos(res, 'api_auth_not_declared')[0].titulo.endswith('en 1 de 1 función'))

    def test_3_ningun_texto_del_modulo_dice_sin_autenticacion(self):
        fuente = Path(api_docs.__file__).read_text(encoding='utf-8').lower()
        for prohibido in ('sin autenticación', 'sin autenticacion', 'sin_autenticacion'):
            self.assertNotIn(prohibido, fuente)

    def test_4_los_textos_del_catalogo_tampoco(self):
        """Lo que el portal muestra de la regla sale de scoring_rule_texts (migración 003)."""
        textos = (RAIZ / 'db' / 'migraciones' / '003_textos_reglas.sql').read_text(encoding='utf-8')
        linea = next(x for x in textos.splitlines() if "('api_auth_not_declared'" in x)
        self.assertIn('no declaran', linea)
        self.assertNotIn('sin autenticación', linea.lower())


class Cobertura(unittest.TestCase):
    """Un sitio que no se pudo revisar queda sin revisar, no en 0 (#23)."""

    def test_1_un_reto_del_waf_deja_el_sitio_sin_revisar_y_no_se_insiste(self):
        res, cliente, _ = correr({url(API, '/openapi.json'): (403, [('cf-mitigated', 'challenge')], b'')})
        self.assertEqual(cliente.visitar.urls, esperadas(DOMINIO) + [url(API, '/openapi.json')])
        self.assertEqual((partes(res.revisados), partes(res.sin_revisar), res.sin_cobertura), ([DOMINIO], [API], []))
        self.assertTrue(any('Cloudflare' in x and 'sin revisar, no en 0' in x for x in res.avisos))
        self.assertEqual(contrato.validar(res, codigos=set(api_docs.CODIGOS)), [])
        self.assertEqual(api_docs.codigo_salida(res), 2)
        # Los resúmenes van antes que el detalle de cada sitio: el orquestador solo guarda los primeros avisos
        self.assertIn('1 sitio sin revisar: %s' % api_docs.MOTIVOS['reto'], res.avisos[0])
        self.assertTrue(res.avisos[1].startswith(api_docs.PARCIAL))
        self.assertIn('Cloudflare', res.avisos[2])

    def test_2_un_429_tambien(self):
        res, cliente, _ = correr({url(API, '/swagger.json'): (429, [], b'')})
        self.assertEqual(cliente.visitar.urls[-1], url(API, '/swagger.json'))
        self.assertEqual(partes(res.sin_revisar), [API])
        # Un 429 es de este momento: con --grabar no se graba y lo grabado antes sigue igual. Un reto del WAF sí es
        # un dato del sitio y se graba
        for respuesta, se_graba in (((429, [], b''), False), ((403, [('cf-mitigated', 'challenge')], b''), True)):
            with tempfile.TemporaryDirectory() as d:
                carpeta = Path(d) / DOMINIO
                correr({}, modo='grabar', carpeta=carpeta)
                antes = sorted(p.name for p in carpeta.glob('*.json'))
                self.assertTrue(antes)
                res, _, _ = correr({url(API, '/swagger.json'): respuesta}, modo='grabar', carpeta=carpeta)
                self.assertEqual(api_docs.NO_SE_GRABO in res.avisos, not se_graba)
                if not se_graba:
                    self.assertEqual(sorted(p.name for p in carpeta.glob('*.json')), antes)

    def test_3_lo_encontrado_antes_de_la_falla_si_se_reporta(self):
        res, _, _ = correr({url(API, '/openapi.json'): (200, [], openapi3()),
                            url(API, '/v3/api-docs'): {'sin_respuesta': 'tiempo'}})
        self.assertEqual(sorted(h.codigo for h in res.hallazgos), ['api_auth_not_declared', 'exposed_api_docs'])
        self.assertEqual((partes(res.revisados), partes(res.sin_revisar)), ([DOMINIO], [API]))
        self.assertTrue(all(h.partes == [API] for h in res.hallazgos))
        self.assertEqual(contrato.validar(res, codigos=set(api_docs.CODIGOS)), [])

    def test_4_un_443_cerrado_es_un_sitio_revisado_sin_documentacion(self):
        res, cliente, _ = correr({url(API, '/openapi.json'): {'rechazada': True}})
        self.assertEqual(cliente.visitar.urls, esperadas(DOMINIO) + [url(API, '/openapi.json')])
        self.assertEqual((res.revisados, res.sin_revisar, res.sin_cobertura), (None, None, []))
        self.assertEqual(activo(res, API).atributos['api_docs']['estado'], 'sin_https')

    def test_5_con_errores_del_servidor_se_deja_el_sitio_a_los_3(self):
        respuestas = {u: (503, [], b'error') for u in esperadas(API)}
        res, cliente, _ = correr(respuestas)
        self.assertEqual(cliente.visitar.urls, esperadas(DOMINIO) + esperadas(API)[:3])
        self.assertEqual(partes(res.sin_revisar), [API])

    def test_6_un_documento_que_no_cabe_esta_a_la_vista_y_queda_sin_revisar(self):
        cortado = json.dumps(openapi3()).encode()[:200]
        doc = api_docs.resumir(200, [], cortado, True)['doc']
        self.assertEqual((doc['formato'], sorted(doc)), ('grande', ['formato', 'huella']))
        self.assertIsNone(api_docs.resumir(200, [], cortado, False)['doc'])
        res, _, _ = correr({url(API, '/openapi.json'): {'estado': 200, 'doc': {'formato': 'grande'}}})
        # Está a la vista, pero sus funciones no se contaron
        self.assertEqual(([h.codigo for h in res.hallazgos], partes(res.sin_revisar)), (['exposed_api_docs'], [API]))
        self.assertTrue(any('2 MB' in x for x in res.avisos))

    def test_7_si_ningun_sitio_se_pudo_revisar_no_hay_cobertura(self):
        respuestas = {url(h, '/openapi.json'): {'sin_respuesta': 'red'} for h in (DOMINIO, API)}
        res, _, _ = correr(respuestas)
        self.assertEqual((res.hallazgos, res.revisados, res.sin_revisar), ([], None, None))
        self.assertEqual(sorted(res.sin_cobertura), sorted(api_docs.CODIGOS))
        self.assertEqual(contrato.validar(res, codigos=set(api_docs.CODIGOS)), [])

    def test_8_sin_tiempo_los_sitios_que_faltan_quedan_sin_revisar(self):
        reloj = iter([0.0] * 40 + [599.0] * 1000)
        res, cliente, _ = correr({}, cronometro=lambda: next(reloj))
        self.assertLess(len(cliente.visitar.urls), 20)
        self.assertIn(API, partes(res.sin_revisar) or [])
        self.assertTrue(any('se acabó el tiempo' in x for x in res.avisos))
        self.assertEqual(contrato.validar(res, codigos=set(api_docs.CODIGOS)), [])

    def test_9_si_no_responden_cert_spotter_ni_el_dns_la_fuente_falla(self):
        cliente = api_docs.ClienteApiDocs(visitar=Sitios({}), descargar=HttpSimulado(ct=[502, 502]),
                                          resolver=ResolvedorSimulado({DOMINIO: 'falla'}), cronometro=lambda: 0.0,
                                          dormir=lambda s: None)
        with mock.patch.object(api_docs, 'crear_cliente', lambda modo, dominio: cliente):
            res = contrato.ejecutar(api_docs, DOMINIO, 'vivo', ahora=AHORA)
        self.assertEqual((res.estado, res.activos, res.hallazgos), ('failed', [], []))
        self.assertEqual(cliente.visitar.urls, [])


class Grabacion(unittest.TestCase):
    def test_1_reproducir_sin_grabacion_no_pide_nada(self):
        with tempfile.TemporaryDirectory() as d:
            res, cliente, _ = correr({}, modo='reproducir', carpeta=Path(d) / DOMINIO)
        self.assertEqual((res.estado, sorted(res.sin_cobertura)), ('succeeded', sorted(api_docs.CODIGOS)))
        self.assertEqual((cliente.visitar.urls, cliente.descargar.urls, res.consultas), ([], [], 0))
        self.assertEqual(res.avisos, [api_docs.SIN_GRABACION_DOMINIO])

    def test_2_una_corrida_con_fallas_no_graba(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            res, _, _ = correr({url(API, '/openapi.json'): {'sin_respuesta': 'red'}}, modo='grabar', carpeta=carpeta)
            self.assertEqual(list(carpeta.glob('*.json')), [])
        self.assertEqual(res.avisos[0], api_docs.NO_SE_GRABO)
        self.assertEqual(api_docs.codigo_salida(res), 3)

    def test_3_una_grabacion_rota_no_se_lee_como_un_sitio_limpio(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / DOMINIO
            correr({url(API, '/openapi.json'): (200, [], openapi3())}, modo='grabar', carpeta=carpeta)
            archivo = api_docs.ClienteApiDocs(modo='reproducir', carpeta=carpeta).grabadora.archivo(
                'ruta:%s:%s' % (API, '/openapi.json'))
            sobre = json.loads(archivo.read_text(encoding='utf-8'))
            sobre['datos'] = {'estado': 200, 'doc': {'formato': 'openapi', 'operaciones': -1}}
            archivo.write_text(json.dumps(sobre), encoding='utf-8')
            res, _, _ = correr({}, modo='reproducir', carpeta=carpeta)
        self.assertEqual((res.hallazgos, partes(res.sin_revisar)), ([], [API]))
        self.assertTrue(any('no se puede leer' in x for x in res.avisos))

    def test_4_limpiar_no_acepta_otra_forma(self):
        for rota in (None, [], {}, {'estado': '200'}, {'estado': True, 'doc': None}, {'sin_respuesta': 'otra'},
                     {'estado': 200, 'doc': {'formato': 'pdf'}}, {'estado': 200, 'reto': 'x'},
                     {'estado': 200, 'doc': {'formato': 'swagger', 'version': '2.0', 'titulo': None, 'operaciones': 1,
                                             'sin_declarar': 2, 'muestra': [], 'huella': '0' * 16}}):
            with self.assertRaises(ValueError, msg=rota):
                api_docs.limpiar(rota)
        self.assertEqual(api_docs.limpiar({'redirige': True, 'codigo': 301, 'destino': 'https://x/'}),
                         {'redirige': True, 'codigo': 301})

    def test_5_la_linea_de_comandos_no_consulta_en_vivo_un_dominio_sin_permiso(self):
        with mock.patch.dict('os.environ', {'DOMINIOS_EN_VIVO': ''}), \
                mock.patch.object(api_docs.contrato, 'ejecutar', side_effect=AssertionError('no debe correr')), \
                mock.patch('sys.stderr'):
            self.assertEqual(api_docs._main(['otra-empresa.com']), 1)
            self.assertEqual(api_docs._main(['otra-empresa.com', '--grabar']), 1)


class Revision(unittest.TestCase):
    """Lo que encontró la revisión del cambio: textos que la base o el portal no deben recibir, páginas que no son
    documentación, documentos cortados y el estado de un sitio a medias."""

    def test_1_un_texto_con_media_pareja_o_con_marcas_invisibles_no_tumba_la_corrida(self):
        doc = openapi3(paths={'/x\udc00': {'post': {}}, '/publico/\u202enimda': {'get': {}}, '/a\u200bb': {'get': {}}},
                       info={'title': 'API \ud83d\ufeff'})
        res, _, _ = correr({url(API, '/openapi.json'): (200, [], json.dumps(doc).encode())})
        self.assertEqual((res.estado, contrato.validar(res, codigos=set(api_docs.CODIGOS))), ('succeeded', []))
        self.assertEqual(activo(res, url(API, '/openapi.json')).atributos['titulo'], 'API ??')
        self.assertEqual(hallazgos(res, 'api_auth_not_declared')[0].evidencia['muestra'],
                         ['POST /x?', 'GET /a?b', 'GET /publico/?nimda'])
        json.dumps([h.evidencia for h in res.hallazgos], ensure_ascii=False).encode('utf-8')   # como la grabadora

    def test_2_la_muestra_no_guarda_llaves_correos_ni_consultas_de_una_ruta(self):
        llave = 'bot123456:' + MARCA
        doc = openapi3(paths={'/%s/webhook' % llave: {'post': {}},
                              '/callback?api_key=' + MARCA: {'get': {}},
                              '/usuarios/juan.perez@acme-demo.mx': {'get': {}},
                              '/usuarios/juan%40acme-demo.mx;v=1': {'put': {}},
                              '/pedidos/{id}/autorizaciones-pendientes': {'get': {}}})
        res, _, _ = correr({url(API, '/openapi.json'): (200, [], doc)})
        muestra = hallazgos(res, 'api_auth_not_declared')[0].evidencia['muestra']
        self.assertEqual(muestra, ['POST /\u2026/webhook', 'PUT /usuarios/\u2026', 'GET /callback',
                                   'GET /pedidos/{id}/autorizaciones-pendientes', 'GET /usuarios/\u2026'])
        self.assertNotIn(MARCA, repr((res.hallazgos, res.activos)))

    def test_3_una_pagina_de_respaldo_que_nombra_a_swagger_ui_no_es_un_documento(self):
        respaldo = b'<html><head><link href="/swagger-ui/swagger-ui.css"></head><body>Inicio</body></html>'
        res, _, _ = correr({url(API, r): (200, [], respaldo) for r in api_docs.RUTAS})
        # La misma página donde se espera un documento JSON es la de respaldo del sitio: no cuenta en ninguna ruta
        self.assertEqual(([x for x in res.activos if x.tipo == 'api_doc'], res.hallazgos), ([], []))
        self.assertEqual(activo(res, API).atributos['api_docs']['estado'], 'revisado')
        # Solo en las rutas de página sí cuenta, y es un solo activo por sitio aunque cada respuesta traiga su nonce
        pagina = '<html><head><script nonce="%s">var t=%d</script></head><body id="swagger-ui"></body></html>'
        res, _, _ = correr({url(API, r): (200, [], (pagina % ('CIRDANfake%020d' % i, 1762700000 + i)).encode())
                            for i, r in enumerate(api_docs.RUTAS_UI)})
        docs = [x for x in res.activos if x.tipo == 'api_doc']
        self.assertEqual([(x.valor, x.atributos['tambien_en']) for x in docs],
                         [(url(API, '/api-docs'), [url(API, '/swagger-ui/'), url(API, '/docs')])])
        self.assertEqual(len(hallazgos(res, 'exposed_api_docs')), 1)

    def test_4_security_en_null_hereda_el_general(self):
        for armar in (openapi3, swagger2):
            doc = api_docs.leer(armar(paths={'/a': {'get': {'security': None}, 'post': {}}}, security=LLAVE))
            self.assertEqual((doc['operaciones'], doc['sin_declarar']), (2, 0))

    def test_5_un_documento_cortado_esta_a_la_vista_y_un_json_cualquiera_cortado_no(self):
        cortado = json.dumps(openapi3()).encode()[:-40]
        self.assertEqual(api_docs.analizar(cortado, cortado=True)['formato'], 'grande')
        self.assertIsNone(api_docs.analizar(cortado))                               # entero y roto: no es nada
        otro = b'{"usuarios": [{"id": 1}, {"id"'
        self.assertEqual(api_docs.analizar(otro, cortado=True), {'formato': 'cortado'})
        # Un JSON cortado que no nombra el formato puede ser un documento con esa llave al final:
        # ni hallazgo ni revisado
        res, _, _ = correr({url(API, '/openapi.json'): (200, [], openapi3()),
                            url(API, '/v3/api-docs'): {'estado': 200, 'doc': {'formato': 'cortado'}}})
        self.assertEqual(([x.valor for x in res.activos if x.tipo == 'api_doc'], partes(res.sin_revisar)),
                         ([url(API, '/openapi.json')], [API]))
        # Y el motivo no dice que sea un documento: no se sabe
        self.assertEqual(activo(res, API).atributos['api_docs']['sin_revisar'], api_docs.MOTIVOS['cortado'])
        self.assertIn('no se sabe', api_docs.MOTIVOS['cortado'])
        res, _, _ = correr({url(API, '/v3/api-docs'): {'estado': 200, 'doc': {'formato': 'grande'}}})
        self.assertEqual(contrato.validar(res, codigos=set(api_docs.CODIGOS)), [])
        self.assertEqual([h.codigo for h in res.hallazgos], ['exposed_api_docs'])
        doc = activo(res, url(API, '/v3/api-docs'))
        self.assertEqual((doc.atributos['formato'], doc.atributos['operaciones'], doc.atributos['titulo']),
                         ('documento que no se leyó completo', None, None))
        # Sus funciones no se contaron: el sitio no queda como revisado
        self.assertEqual(partes(res.sin_revisar), [API])
        self.assertEqual(activo(res, API).atributos['api_docs']['sin_revisar'], api_docs.MOTIVOS['grande'])

    def test_6_el_activo_lleva_siempre_las_mismas_llaves(self):
        res, _, _ = correr({url(API, '/openapi.json'): (200, [], openapi3()),
                            url(DOMINIO, '/docs'): (200, [], SWAGGER_UI)})
        llaves = [sorted(x.atributos) for x in res.activos if x.tipo == 'api_doc']
        self.assertEqual(len(llaves), 2)
        self.assertEqual(llaves[0], llaves[1])
        self.assertEqual(activo(res, url(API, '/openapi.json')).atributos['tambien_en'], [])
        pagina = activo(res, url(DOMINIO, '/docs')).atributos
        self.assertEqual((pagina['titulo'], pagina['operaciones'], pagina['no_declaran_autenticacion']),
                         (None, None, None))

    def test_7_un_sitio_que_deja_de_aceptar_conexiones_a_media_corrida_no_se_graba(self):
        carpeta = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, carpeta, True)
        res, cliente, _ = correr({url(API, '/swagger.json'): {'rechazada': True}}, modo='grabar', carpeta=carpeta)
        self.assertEqual(cliente.fallas, 1)
        self.assertEqual((res.avisos[0], api_docs.codigo_salida(res)), (api_docs.NO_SE_GRABO, 3))
        self.assertEqual(partes(res.sin_revisar), [API])

    def test_8_un_sitio_con_errores_del_servidor_no_dice_revisado(self):
        con_doc = {url(API, '/openapi.json'): (503, [], b''), url(API, '/swagger.json'): (200, [], swagger2())}
        res, _, _ = correr(con_doc)
        estado = activo(res, API).atributos['api_docs']
        self.assertEqual((estado['estado'], estado['sin_revisar']),
                         ('con_documentacion', api_docs.MOTIVOS['error_http']))
        for cuantos in (1, api_docs.MAX_ERRORES):
            with self.subTest(errores=cuantos):
                res, cliente, _ = correr({url(API, r): (503, [], b'') for r in api_docs.RUTAS[:cuantos]})
                # Sin documentos no se reporta: no pisa lo que una corrida anterior guardó del sitio
                self.assertEqual([x.valor for x in res.activos], [DOMINIO])
                self.assertEqual(partes(res.sin_revisar), [API])

    def test_9_un_api_doc_con_otro_nombre_en_hosts_no_pasa_el_contrato(self):
        ajena = 'https://otra-empresa.com/openapi.json'
        for atributos in ({'hosts': [DOMINIO, 'otra-empresa.com']}, {'host': DOMINIO}):
            res = contrato.Resultado(DOMINIO, api_docs.FUENTE)
            res.activos.append(Activo('api_doc', ajena, atributos))
            self.assertTrue(any('solo de ese' in e for e in contrato.validar(res, codigos=set(api_docs.CODIGOS))))
        propia = Activo('api_doc', url(API, '/openapi.json'), {'hosts': [API, DOMINIO]})
        res = contrato.Resultado(DOMINIO, api_docs.FUENTE)
        res.activos.append(propia)
        self.assertTrue(contrato.validar(res, codigos=set(api_docs.CODIGOS)))

    def test_10_la_linea_de_comandos_no_consulta_en_vivo_antes_de_que_rija_la_actividad(self):
        vispera = api_docs.VIGENTE_DESDE.replace(day=api_docs.VIGENTE_DESDE.day - 1)
        corrio = mock.Mock(return_value=contrato.Resultado(DOMINIO, api_docs.FUENTE))
        with mock.patch.dict('os.environ', {'DOMINIOS_EN_VIVO': DOMINIO}), mock.patch('sys.stderr'), \
                mock.patch('sys.stdout'), mock.patch.object(api_docs.contrato, 'ejecutar', corrio):
            self.assertEqual(api_docs._main([DOMINIO], hoy=vispera), 1)
            self.assertEqual(api_docs._main([DOMINIO, '--grabar'], hoy=vispera), 1)
            corrio.assert_not_called()
            api_docs._main([DOMINIO, '--reproducir'], hoy=vispera)
            api_docs._main([DOMINIO], hoy=api_docs.VIGENTE_DESDE)
        self.assertEqual([c.args[2] for c in corrio.call_args_list], ['reproducir', 'vivo'])

    def test_11_la_migracion_no_espera_sin_limite_y_deja_al_dia_el_comentario_de_la_tabla(self):
        texto = MIGRACION.read_text(encoding='utf-8')
        sql = '\n'.join(linea.split('--', 1)[0] for linea in texto.splitlines())
        self.assertLess(sql.index("SET LOCAL lock_timeout = '5s';"), sql.index('ALTER TABLE assets'))
        self.assertGreater(sql.index('SET LOCAL lock_timeout'), sql.index('BEGIN;'))
        self.assertRegex(sql, r"COMMENT ON TABLE assets IS '[^']*documentos de API")


class Ronda3(unittest.TestCase):
    """Lo que quedó pendiente de la segunda revisión: qué se tapa del título y de la muestra, qué página cuenta y
    cuándo dos rutas son el mismo activo."""

    def visible(self, ruta):
        return api_docs.leer(openapi3(paths={ruta: {'get': {}}}))['muestra'][0][len('GET '):]

    def test_1_la_muestra_tapa_llaves_partidas_y_datos_personales_cortos(self):
        partida = '/s3/CIRDANfakeXUtnFEMI/K7MDENG/bPxRfiCYEJEMPLOKEY/upload'   # la forma de una llave de AWS, con '/'
        for ruta, queda in ((partida, '/s3/\u2026/upload'),
                            ('/clientes/XEXX850101HDFRRN05', '/clientes/\u2026'),            # forma de CURP
                            ('/proveedores/XEX850101AB1/facturas', '/proveedores/\u2026/facturas'),   # forma de RFC
                            ('/sms/5500000000', '/sms/\u2026'),
                            ('/sms/+52-55-0000-0000', '/sms/\u2026'),
                            ('/sms/tel:55-0000-0000', '/sms/\u2026'),                       # con un prefijo pegado
                            ('/llaves/CIRDAN-FAKE-Ab1C-dE2f-Gh3I-jK4l-Mn5O', '/llaves/\u2026'),   # partida por guiones
                            ('/sesiones/00000000-0000-4000-8000-000000000000', '/sesiones/\u2026'),
                            ('/archivos/00ff00ff00ff00ff', '/archivos/\u2026'),
                            ('/usuarios/a@b', '/usuarios/\u2026')):
            with self.subTest(ruta=ruta):
                self.assertEqual(self.visible(ruta), queda)

    def test_2_el_titulo_tambien_se_tapa(self):
        titulo = 'Pagos v2 (2026-11-09) de juan.perez@acme-demo.mx tel 5500000000 llave %s/x' % MARCA.replace('_', '1')
        doc = api_docs.leer(openapi3(info={'title': titulo}))
        self.assertEqual(doc['titulo'], 'Pagos v2 (2026-11-09) de \u2026 tel \u2026 llave \u2026/x')
        self.assertIsNone(api_docs.leer(openapi3(info={'title': 7}))['titulo'])
        # El principio de una llave no queda a la vista por el corte del texto
        for antes in (95, 395):   # la llave empieza dentro de lo que se guarda (MAX_TEXTO) y donde se corta lo revisado
            larga = api_docs.leer(openapi3(info={'title': 'a ' * antes + 'CIRDAN1FAKE' + 'x' * 40}))['titulo']
            self.assertNotIn('CIRDAN', larga)
        self.assertTrue(api_docs.leer(openapi3(info={'title': 'a ' * 95 + 'CIRDAN1FAKE' + 'x' * 40}))['titulo']
                        .endswith('a …'))
        # Un teléfono escrito con espacios, que al partir el título en palabras quedaría en pedazos
        for titulo in ('Soporte 55 0000 0000 hoy', 'Soporte +52 (55) 0000 0000 hoy'):
            self.assertEqual(api_docs.leer(openapi3(info={'title': titulo}))['titulo'], 'Soporte … hoy')
        # Al reproducir se tapa otra vez: la grabación pudo hacerla una versión que tapaba menos
        grabado = dict(api_docs.leer(openapi3()), titulo='Pagos de a@acme-demo.mx',
                       muestra=['POST /usuarios/a@acme-demo.mx (3 funciones)', 'GET /salud'])
        limpio = api_docs.limpiar({'estado': 200, 'doc': grabado})['doc']
        self.assertEqual((limpio['titulo'], limpio['muestra']),
                         ('Pagos de …', ['POST /usuarios/… (3 funciones)', 'GET /salud']))

    def test_3_un_tramo_legitimo_no_se_tapa(self):
        for ruta in ('/auth/oauth2-token-exchange', '/auth/oauth2-device-authorization', '/v1/s3-presigned-upload-url',
                     '/users/@me', '/reportes/2026-11-09', '/api/v2/getUserById/XMLExport', '/pedidos/{id}/lineas',
                     '/Clientes/ObtenerPedidosPorFecha/ExportarExcel'):
            with self.subTest(ruta=ruta):
                self.assertEqual(self.visible(ruta), ruta)

    def test_4_las_rutas_que_quedan_iguales_van_una_vez_con_cuantas_son(self):
        doc = api_docs.leer(openapi3(paths={'/items': {'get': {}}, '/items?x=1': {'get': {}}, '/otra': {'get': {}},
                                            '/usuarios/a@acme-demo.mx': {'post': {}},
                                            '/usuarios/b@acme-demo.mx': {'post': {}},
                                            '/usuarios/c@acme-demo.mx': {'post': {}}}))
        self.assertEqual(doc['sin_declarar'], 6)
        self.assertEqual(doc['muestra'],
                         ['POST /usuarios/\u2026 (3 funciones)', 'GET /items (2 funciones)', 'GET /otra'])
        self.assertEqual(api_docs.limpiar({'estado': 200, 'doc': doc})['doc'], doc)

    def test_5_dos_paginas_o_dos_documentos_sin_leer_distintos_son_dos_activos(self):
        v3 = (json.dumps(openapi3()) + ' ' * 50).encode()[:-60]
        v2 = (json.dumps(swagger2()) + ' ' * 50).encode()[:-60]
        respuestas = {url(API, '/v3/api-docs'): api_docs.resumir(200, [], v3, True),
                      url(API, '/v2/api-docs'): api_docs.resumir(200, [], v2, True),
                      url(API, '/api/openapi.json'): api_docs.resumir(200, [], v3, True)}
        res, _, _ = correr(respuestas)
        docs = [(x.valor, x.atributos['tambien_en']) for x in res.activos if x.tipo == 'api_doc']
        self.assertEqual(docs, [(url(API, '/v3/api-docs'), [url(API, '/api/openapi.json')]),
                                (url(API, '/v2/api-docs'), [])])
        self.assertEqual(contrato.validar(res, codigos=set(api_docs.CODIGOS)), [])
        # Una grabación sin huella no dice si dos rutas dan lo mismo: cada una es su activo
        sin_huella = {'estado': 200, 'doc': {'formato': 'ui'}}
        res, _, _ = correr({url(API, '/docs'): sin_huella, url(API, '/swagger-ui/'): sin_huella})
        self.assertEqual([x.atributos['tambien_en'] for x in res.activos if x.tipo == 'api_doc'], [[], []])
        with self.assertRaises(ValueError):
            api_docs.limpiar({'estado': 200, 'doc': {'formato': 'ui', 'huella': 'no es una huella'}})

    def test_6_zwj_zwnj_y_el_guion_opcional_se_quedan_y_no_depende_de_la_version_de_python(self):
        for texto in ('Equipo \U0001f469\u200d\U0001f4bb', 'API\u0647\u0627\u200c\u06cc', 'co\u00adoperativa',
                      'sin asignar \U0001fae9 \u0378'):
            with self.subTest(texto=texto):
                self.assertEqual(api_docs._texto(texto), texto)
        raro = 'a\u202eb\u200bc\ufeffd\udc00e\ue000f\U000e0041g\ufffeh\U0001ffffi\x00j\u2028k'
        self.assertEqual(api_docs._texto(raro), 'a?b?c?d?e?f?g?h?i?j?k')
        # Los que no se ven y antes pasaban: el separador mongol, los rellenos Hangul y los de formato musical
        self.assertEqual(api_docs._texto('a᠎bㅤcᅟdﾠe\U0001d173f\U0001bca0g'), 'a?b?c?d?e?f?g')
        self.assertFalse(hasattr(api_docs, 'unicodedata'))   # sus categor\u00edas cambian con la versi\u00f3n de Python

    def test_7_una_pagina_solo_cuenta_si_la_respuesta_es_html(self):
        html = [('Content-Type', 'text/html; charset=utf-8')]
        plano = b'Este README menciona swagger-ui y como instalarlo'
        self.assertEqual(api_docs.resumir(200, html, SWAGGER_UI)['doc']['formato'], 'ui')
        xhtml = [('content-type', 'APPLICATION/XHTML+XML')]
        self.assertEqual(api_docs.resumir(200, xhtml, SWAGGER_UI)['doc']['formato'], 'ui')
        for cabeceras, cuerpo in (([('Content-Type', 'text/plain')], plano), ([], plano),
                                  ([('Content-Type', 'text/plain')], SWAGGER_UI),
                                  ([('Content-Type', 'application/javascript')], b'var x = "swagger-ui";')):
            with self.subTest(cabeceras=cabeceras, cuerpo=cuerpo):
                self.assertIsNone(api_docs.resumir(200, cabeceras, cuerpo)['doc'])
        # Un documento JSON cuenta con cualquier tipo de contenido: muchos sitios lo sirven como texto
        doc = api_docs.resumir(200, [('Content-Type', 'text/plain')], json.dumps(openapi3()).encode())['doc']
        self.assertEqual(doc['formato'], 'openapi')
        res, _, _ = correr({url(API, '/docs'): (200, [('Content-Type', 'text/plain')], plano)})
        self.assertEqual((res.hallazgos, [x.tipo for x in res.activos]), ([], ['domain', 'subdomain']))

    def test_8_un_documento_hostil_de_2_mb_no_se_come_el_tiempo_de_la_corrida(self):
        # 2,300 rutas de 800 caracteres hechas solo de '/' con los 8 métodos vacíos: antes eran unos 26 s de CPU
        metodos = {m: {} for m in api_docs.METODOS}
        paths = {'/' * (800 - len(str(i))) + str(i): metodos for i in range(2300)}
        cuerpo = json.dumps(openapi3(paths=paths)).encode()
        self.assertGreater(len(cuerpo), 1900 * 1024)
        self.assertLessEqual(len(cuerpo), api_docs.MAX_BYTES)
        inicio = time.perf_counter()
        doc = api_docs.resumir(200, [], cuerpo)['doc']
        self.assertLess(time.perf_counter() - inicio, 8)
        # Los conteos siguen exactos: solo la cuenta de cada texto de la muestra es un mínimo, y lo dice
        self.assertEqual((doc['operaciones'], doc['sin_declarar']), (2300 * 8, 2300 * 8))
        self.assertTrue(doc['muestra'])
        # De las rutas que sí se revisaron salen sus 8 métodos, también los que no cambian datos
        self.assertEqual(sorted(texto.split(' ')[0] for texto in doc['muestra']),
                         sorted(m.upper() for m in api_docs.METODOS))
        for texto in doc['muestra']:
            self.assertRegex(texto, r'^[A-Z]+ /\S* \(al menos \d+ funciones\)$')
        self.assertEqual(api_docs.limpiar({'estado': 200, 'doc': doc})['doc'], doc)
        # Un método solo cuenta en minúsculas, como lo pide OpenAPI: sus variantes con mayúsculas no multiplican las
        # funciones de una ruta
        variantes = {v: {} for v in ('get', 'GET', 'Get', 'gEt', 'geT', 'post', 'POST', 'Post', 'pOst', 'poSt')}
        paths = {'/x%d' % i + '/a' * 398: variantes for i in range(900)}
        inicio = time.perf_counter()
        doc = api_docs.leer(openapi3(paths=paths))
        self.assertLess(time.perf_counter() - inicio, 8)
        self.assertEqual((doc['operaciones'], doc['sin_declarar']), (1800, 1800))
        visible = ('/x0' + '/a' * 398)[:api_docs.MAX_TEXTO]
        self.assertEqual(doc['muestra'][0], 'POST %s (al menos 1 función)' % visible)
        # Así la huella, que repite la ruta en cada función, no pasa de 8 veces el tamaño de la ruta más larga
        todas = {''.join(letras): {} for letras in itertools.product(*((c, c.upper()) for c in 'options'))}
        todas.update({m: {} for m in api_docs.METODOS})
        inicio = time.perf_counter()
        doc = api_docs.leer(openapi3(paths={'/' + 'a' * 1500000: todas}))
        self.assertLess(time.perf_counter() - inicio, 8)
        self.assertEqual((doc['operaciones'], doc['sin_declarar']), (8, 8))

    def test_9_un_documento_grande_normal_conserva_la_cuenta_exacta_de_la_muestra(self):
        paths = {'/clientes/c%d@acme-demo.mx/pedidos' % i: {'post': {}, 'get': {}} for i in range(700)}
        paths['/salud'] = {'get': {}}
        doc = api_docs.leer(openapi3(paths=paths))
        self.assertEqual((doc['operaciones'], doc['sin_declarar']), (1401, 1401))
        self.assertEqual(doc['muestra'], ['POST /clientes/…/pedidos (700 funciones)',
                                          'GET /clientes/…/pedidos (700 funciones)', 'GET /salud'])
        # La cuenta más larga que puede salir cabe en lo que limpiar deja de cada texto de la muestra
        largo = 'OPTIONS /%s (al menos 9999999 funciones)' % ('a' * (api_docs.MAX_TEXTO - 1))
        self.assertEqual(api_docs.limpiar({'estado': 200, 'doc': dict(doc, muestra=[largo])})['doc']['muestra'],
                         [largo])
        # Con más rutas de las que se revisan (MAX_REVISADO), las funciones de las rutas ya revisadas sí se cuentan,
        # también las que no cambian datos, y toda cuenta dice que es un mínimo, aunque sea de 1
        paths = {'/clientes/c%d@acme-demo.mx/pedidos' % i: {'post': {}, 'get': {}} for i in range(1000)}
        paths.update({'/salud': {'get': {}}, '/clientes/c0@acme-demo.mx/pagos': {'post': {}},
                      '/clientes/c999@acme-demo.mx/pagos': {'post': {}}})
        doc = api_docs.leer(openapi3(paths=paths))
        self.assertEqual((doc['operaciones'], doc['sin_declarar'], len(doc['muestra'])), (2003, 2003, 3))
        self.assertEqual(doc['muestra'][0], 'POST /clientes/…/pagos (al menos 1 función)')
        cuentas = [re.fullmatch(r'(POST|GET) /clientes/…/pedidos \(al menos (\d+) funciones\)', texto)
                   for texto in doc['muestra'][1:]]
        self.assertEqual([c.group(1) for c in cuentas], ['POST', 'GET'])
        self.assertEqual(cuentas[0].group(2), cuentas[1].group(2))
        self.assertTrue(800 < int(cuentas[0].group(2)) < 1000)
        self.assertEqual(api_docs.limpiar({'estado': 200, 'doc': doc})['doc'], doc)

    def test_10_un_security_general_enorme_se_revisa_una_vez_y_no_en_cada_funcion(self):
        # 50,000 requisitos generales y 32,000 funciones vacías en unos 700 KB: antes eran más de 60 s de CPU, porque
        # cada función sin security propio recorría otra vez el general (con 2 MB, unos 12 minutos)
        # Sin reloj: el general se revisa una vez, y además solo el security propio de la función que lo trae
        chico = {'/a': {'get': {}, 'post': {'security': None}, 'put': {'security': LLAVE}, 'delete': {}}}
        with mock.patch.object(api_docs, 'declara', wraps=api_docs.declara) as cuenta:
            doc = api_docs.leer(openapi3(paths=chico, security=[{}]))
        self.assertEqual((cuenta.call_count, doc['operaciones'], doc['sin_declarar']), (2, 4, 3))
        # La mitad de las funciones no trae security y la otra mitad lo trae en null: las dos usan el general
        vacias = [{}, {'security': None}]
        paths = {'/%d' % i: {m: vacias[(i + j) % 2] for j, m in enumerate(sorted(api_docs.METODOS))}
                 for i in range(4000)}
        for general, sin_declarar in (([{'': 0}] * 50000, 0), ([{'': 0}] * 49999 + [{}], 32000)):
            cuerpo = json.dumps(openapi3(paths=paths, security=general), separators=(',', ':')).encode()
            self.assertLessEqual(len(cuerpo), api_docs.MAX_BYTES)
            inicio = time.perf_counter()
            with mock.patch.object(api_docs, 'declara', wraps=api_docs.declara) as cuenta:
                doc = api_docs.resumir(200, [], cuerpo)['doc']
            self.assertLess(time.perf_counter() - inicio, 8)
            self.assertEqual(cuenta.call_count, 1)
            self.assertEqual((doc['operaciones'], doc['sin_declarar']), (32000, sin_declarar))
        # El security propio de una función sigue mandando sobre el general, y cada uno se recorre una sola vez
        paths['/0'] = {'get': {'security': []}, 'post': {'security': [{'llave': []}] * 50000}, 'put': {}}
        doc = api_docs.leer(openapi3(paths=paths, security=[{'': 0}] * 49999 + [{}]))
        self.assertEqual((doc['operaciones'], doc['sin_declarar']), (31995, 31994))
        doc = api_docs.leer(openapi3(paths=paths, security=LLAVE))
        self.assertEqual((doc['operaciones'], doc['sin_declarar'], doc['muestra']), (31995, 1, ['GET /0']))


class Base(unittest.TestCase):
    """Migración: tipo de activo 'api_doc', su fuente y sus reglas con los códigos mapeados en #68. Lectura estática de
    la migración 015 y la semilla 013, sin base."""

    def test_1_la_migracion_agrega_api_doc_al_check_sin_quitar_ninguno(self):
        texto = MIGRACION.read_text(encoding='utf-8')
        sql = '\n'.join(linea.split('--', 1)[0] for linea in texto.splitlines())
        check, = re.findall(r"CHECK\s*\(asset_type IN \(([^)]*)\)\)", sql)
        tipos = tuple(t.strip().strip("'") for t in check.split(','))
        self.assertEqual(tipos, contrato.TIPOS_ACTIVO)
        inicial = (RAIZ / 'db' / 'migraciones' / '001_esquema_inicial.sql').read_text(encoding='utf-8')
        antes, = re.findall(r"asset_type\s+text NOT NULL CHECK \(asset_type IN \(([^)]*)\)\)", inicial)
        self.assertEqual(tipos[:-1], tuple(t.strip().strip("'") for t in antes.split(',')))
        self.assertEqual(tipos[-1], api_docs.TIPO_ACTIVO)
        # En una transacción, y el CHECK nuevo lleva el nombre que Postgres le dio al de la 001
        self.assertRegex(sql, r"(?s)BEGIN;.*DROP CONSTRAINT IF EXISTS assets_asset_type_check;.*"
                              r"ADD CONSTRAINT assets_asset_type_check\s.*COMMIT;")
        self.assertIn("SET client_encoding = 'UTF8';", texto)
        self.assertNotRegex(sql.upper(), r'\b(UPDATE|DELETE|DROP TABLE|TRUNCATE)\b')
        numeros = sorted(int(p.name[:3]) for p in MIGRACION.parent.glob('[0-9][0-9][0-9]_*.sql'))
        self.assertEqual(numeros, list(range(1, len(numeros) + 1)))

    def test_2_la_semilla_da_de_alta_la_fuente_sin_pisar_otra(self):
        texto = SEMILLA.read_text(encoding='utf-8')
        with mock.patch.object(test_subfinder, 'SEMILLA', SEMILLA):
            fila = test_subfinder.fila_de_la_semilla(api_docs.FUENTE)
        self.assertIn("SET client_encoding = 'UTF8';", texto)
        self.assertIn('ON CONFLICT (code) DO NOTHING', texto)
        self.assertIn('la 015', texto)
        otras = [p.name for p in SEMILLA.parent.glob('*.sql') if p != SEMILLA
                 and fila['id'].strip("'") in p.read_text(encoding='utf-8')]
        self.assertEqual(otras, [])
        numeros = sorted(int(p.name[:3]) for p in SEMILLA.parent.glob('[0-9][0-9][0-9]_*.sql'))
        self.assertEqual(numeros, list(range(1, len(numeros) + 1)))

    def test_3_sus_dos_reglas_ya_tienen_regla_texto_y_mapeo(self):
        carpeta = RAIZ / 'db'
        reglas = (carpeta / 'semillas' / '004_reglas_recolectores.sql').read_text(encoding='utf-8')
        textos = (carpeta / 'migraciones' / '003_textos_reglas.sql').read_text(encoding='utf-8')
        mapeo = (carpeta / 'migraciones' / '011_mapeo_marcos.sql').read_text(encoding='utf-8')
        for codigo, severidad in api_docs.CODIGOS.items():
            self.assertRegex(reglas, r"'%s',\s*'infrastructure',\s*'%s'" % (codigo, severidad))
            self.assertIn("('%s', '" % codigo, textos)
            self.assertIn("('%s', 'Enterprise v19'" % codigo, mapeo)

    def test_4_el_readme_de_db_las_lista_en_orden(self):
        leeme = (RAIZ / 'db' / 'README.md').read_text(encoding='utf-8')
        m015, s013 = '< db/migraciones/%s' % MIGRACION.name, '< db/semillas/%s' % SEMILLA.name
        ordenes = [linea.split('< db/')[1].strip() for linea in leeme.splitlines() if m015 in linea or s013 in linea]
        self.assertEqual(ordenes[:2], ['migraciones/' + MIGRACION.name, 'semillas/' + SEMILLA.name])
        for archivo in ('migraciones/' + MIGRACION.name, 'semillas/' + SEMILLA.name):
            self.assertIn('| `%s` |' % archivo, leeme)

    def test_5_la_api_ordena_el_tipo_nuevo(self):
        v1 = (RAIZ / 'cirdan' / 'api' / 'v1.py').read_text(encoding='utf-8')
        orden, = re.findall(r"array_position\(ARRAY\[([^\]]*)\], a\.asset_type\)", v1)
        self.assertEqual(sorted(t.strip("'") for t in orden.split(',')), sorted(contrato.TIPOS_ACTIVO))

    def test_6_las_grabaciones_no_van_al_repo(self):
        self.assertEqual(api_docs.CARPETA_GRABADAS, contrato.CARPETA_GRABADAS / 'api_docs')
        self.assertTrue((api_docs.CARPETA_GRABADAS / '.gitkeep').exists())
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
            for ruta in ('api_docs/olmardo.com/ruta_api.olmardo.com__openapi.json_0123456789abcdef.json',
                         'api_docs/olmardo.com/.grabacion', 'api_docs/acme-demo.mx/a_acme-demo.mx.json'):
                self.assertTrue(ignorado(ruta), ruta)
            self.assertFalse(ignorado('api_docs/.gitkeep'))


if __name__ == '__main__':
    unittest.main()
