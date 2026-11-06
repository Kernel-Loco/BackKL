"""Pruebas del CDN o WAF delante de un sitio y de las respuestas de reto o bloqueo (#18, RC-46), sin red.

    python -m unittest -v pruebas/test_borde.py

Las respuestas de pruebas/fixtures/borde/ están armadas a mano con las señales públicas de cada proveedor: no son
grabaciones de ningún dominio y sus valores son falsos (las cookies llevan CIRDAN_FAKE_).
"""
import ast
import http.client
import io
import ipaddress
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_borde.py
from cirdan.recolectores import REGISTRO, borde, geoip  # noqa: E402
from cirdan.recolectores.contrato import Activo, Hallazgo, Resultado, validar  # noqa: E402

RAIZ = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'borde'
DOMINIO = 'acme-demo.mx'
SITIO, OTRO = 'www.acme-demo.mx', 'tienda.acme-demo.mx'
CODIGOS = ['known_vulnerability', 'outdated_software', 'server_version_disclosed']   # del catálogo, los de #18 hoy


def respuesta(nombre):
    return json.loads((FIXTURES / (nombre + '.json')).read_text(encoding='utf-8'))


def reto_de(nombre):
    r = respuesta(nombre)
    return borde.reto(r['estado'], r['cabeceras'], r['cuerpo'])


def borde_de(nombre, **otras):
    return borde.detectar(cabeceras=respuesta(nombre)['cabeceras'], **otras)


def se_cierra(partes, revisados, sin_revisar):
    """Si el orquestador cierra un hallazgo abierto que no volvió a salir, por sus partes (#23,
    cirdan/orquestador/__init__.py:415, sin sin_cobertura): las compara tal cual."""
    if revisados is None:
        return True
    if not partes:
        return False
    if sin_revisar is None:
        return set(partes) <= set(revisados)
    return not set(partes) & set(sin_revisar)


def hallazgo(codigo='server_version_disclosed', partes=()):
    titulo = 'Versión del servidor a la vista'
    return Hallazgo(codigo, 'low', SITIO, titulo, {'title': titulo},
                    {'tipo': 'version_servidor', 'antiguedad_dias': 0, 'exposicion': 'directa', 'sensibilidad': 'baja'},
                    'b' * 64, partes=list(partes))


class Senales(unittest.TestCase):
    def test_1_cname_de_un_cdn_en_cualquier_punto_de_la_cadena(self):
        self.assertEqual(borde.por_cname(['www.acme-demo.mx.cdn.cloudflare.net', 'otro.ejemplo.net']),
                         {'cloudflare': ['www.acme-demo.mx.cdn.cloudflare.net']})
        self.assertEqual(borde.por_cname(['WWW.ACME-DEMO.MX.EDGEKEY.NET.', 'e0000.a.akamaiedge.net']),
                         {'akamai': ['e0000.a.akamaiedge.net', 'www.acme-demo.mx.edgekey.net']})
        self.assertEqual(borde.por_cname(['0000000000000000.vercel-dns-017.com']),
                         {'vercel': ['0000000000000000.vercel-dns-017.com']})
        self.assertEqual(borde.por_cname('d0000.cloudfront.net'), {'cloudfront': ['d0000.cloudfront.net']})

    def test_2_un_hosting_no_es_un_borde(self):
        for cname in ('acme.myshopify.com', 'acme.github.io', 'acme.herokudns.com', 'sincdn.ejemplo.net'):
            self.assertEqual(borde.por_cname([cname]), {}, cname)
        self.assertEqual(borde.por_cname(['cdn.cloudflare.net.ejemplo.net', 'xcdn.cloudflare.net']), {})
        self.assertEqual(borde.por_cname([None, 7, '']), {})

    def test_3_ip_en_los_rangos_de_cloudflare(self):
        self.assertEqual(borde.por_rangos(['104.16.0.1', '203.0.113.5', 'no-es-ip', '104.16.0.1']),
                         {'cloudflare': ['104.16.0.1']})
        self.assertEqual(borde.por_rangos(['203.0.113.5', '2001:db8::1']), {})

    def test_4_asn_solo_de_un_cdn(self):
        self.assertEqual(borde.por_asn([13335, 13335, geoip.NO_DISPONIBLE]), {'cloudflare': [13335]})
        self.assertEqual(borde.por_asn([30148, 19551]), {'imperva': [19551], 'sucuri': [30148]})
        for mixto in (16509, 8075, 15169, True, '13335', None):   # nubes mixtas, bool y texto no cuentan
            self.assertEqual(borde.por_asn([mixto]), {}, mixto)

    def test_5_cabeceras_por_proveedor(self):
        casos = {'cloudflare_pagina_200': {'cloudflare': ['cf-cache-status', 'cf-ray', 'server', 'set-cookie:__cf_bm']},
                 'cloudfront_pagina_200': {'cloudfront': ['via', 'x-amz-cf-id', 'x-amz-cf-pop']},
                 'vercel_pagina_200': {'vercel': ['server', 'x-vercel-cache', 'x-vercel-id']},
                 'imperva_bloqueo_403': {'imperva': ['set-cookie:incap_ses_', 'set-cookie:visid_incap_', 'x-cdn',
                                                     'x-iinfo']},
                 'akamai_bloqueo_403': {'akamai': ['server', 'set-cookie:ak_bmsc']},
                 'sucuri_bloqueo_403': {'sucuri': ['server', 'x-sucuri-id']},
                 'sin_borde_200': {}, 'origen_403': {}}
        for nombre, esperado in casos.items():
            self.assertEqual(borde.por_cabeceras(respuesta(nombre)['cabeceras']), esperado, nombre)

    def test_6_el_valor_tiene_que_calzar(self):
        self.assertEqual(borde.por_cabeceras({'Server': 'cloudflare-nginx'}), {'cloudflare': ['server']})
        for cabeceras in ({'Server': 'nginx-cloudflare'}, {'Server': 'cloudflared'}, {'X-CDN': 'Akamai'},
                          {'Via': '1.1 varnish'}, {'Set-Cookie': 'sesion=__cf_bm'}):
            self.assertEqual(borde.por_cabeceras(cabeceras), {}, cabeceras)

    def test_7_nunca_guarda_valores_de_cabeceras(self):
        proveedores = set(borde.PROVEEDORES) | {n.lower() for n in borde.PROVEEDORES.values()}
        for archivo in sorted(FIXTURES.glob('*.json')):
            r = respuesta(archivo.stem)
            datos = borde.detectar(cabeceras=r['cabeceras'])
            reto = borde.reto(r['estado'], r['cabeceras'], r['cuerpo'])
            texto = json.dumps([datos, reto, borde.aviso('web', SITIO, reto) if reto else None]).lower()
            for nombre, valor in r['cabeceras']:
                if valor.lower() not in proveedores:   # 'Server: cloudflare' o 'X-CDN: Imperva' son el proveedor
                    self.assertNotIn(valor.lower(), texto, archivo.stem)
            self.assertNotIn('cirdan_fake_', texto, archivo.stem)

    def test_8_lee_un_httpmessage_con_dos_cookies(self):
        crudo = (b'Server: cloudflare\r\nSet-Cookie: __cf_bm=CIRDAN_FAKE_a; path=/\r\n'
                 b'Set-Cookie: cf_clearance=CIRDAN_FAKE_b; path=/\r\n\r\n')
        mensaje = http.client.parse_headers(io.BytesIO(crudo))
        self.assertEqual(borde.por_cabeceras(mensaje),
                         {'cloudflare': ['server', 'set-cookie:__cf_bm', 'set-cookie:cf_clearance']})
        self.assertEqual(borde.por_cabeceras([('Server', None), ('solo-un-elemento',), 7]), {})
        self.assertEqual(borde.por_cabeceras(None), {})

    def test_9_de_una_cookie_solo_la_parte_fija_del_nombre(self):
        self.assertEqual(borde.por_cabeceras({'Set-Cookie': 'incap_ses_CIRDAN_FAKE_x'}), {})   # sin '=' no es cookie
        self.assertEqual(borde.por_cabeceras({'Set-Cookie': 'incap_ses_\x00=1'}), {})
        datos = borde.detectar(cabeceras=[('Set-Cookie', 'incap_ses_123_456=CIRDAN_FAKE_a'),
                                          ('Set-Cookie', 'sucuri_cloudproxy_uuid_0f=CIRDAN_FAKE_b')])
        self.assertEqual([(p['codigo'], p['cabeceras']) for p in datos['proveedores']],
                         [('imperva', ['set-cookie:incap_ses_']), ('sucuri', ['set-cookie:sucuri_cloudproxy_'])])
        res = Resultado(DOMINIO, 'prueba', activos=[Activo('subdomain', SITIO, {'borde': datos})])
        self.assertEqual(validar(res, codigos=CODIGOS), [])

    def test_10_cookies_juntas_y_valores_largos(self):
        juntas = 'sesion=a; Expires=Thu, 05 Nov 2026 12:00:00 GMT; path=/, __cf_bm=CIRDAN_FAKE_a; path=/'
        self.assertEqual(borde.por_cabeceras({'Set-Cookie': juntas}), {'cloudflare': ['set-cookie:__cf_bm']})
        # Las dos cookies de Imperva salen igual si llegan juntas (dict de requests) o separadas (HTTPMessage).
        dos = ('incap_ses_1_2=CIRDAN_FAKE_a; path=/', 'visid_incap_3=CIRDAN_FAKE_b; path=/')
        esperado = {'imperva': ['set-cookie:incap_ses_', 'set-cookie:visid_incap_']}
        self.assertEqual(borde.por_cabeceras({'Set-Cookie': ', '.join(dos)}), esperado)
        self.assertEqual(borde.por_cabeceras([('Set-Cookie', c) for c in dos]), esperado)
        via = '1.1 ' + 'x' * 300 + '.cloudfront.net (CloudFront)'
        self.assertEqual(borde.por_cabeceras({'Via': via}), {'cloudfront': ['via']})

    def test_11_solo_ascii(self):
        # Con re.IGNORECASE solo, 'ſ' (U+017F) calza con 's', 'İ' (U+0130) con 'i' y 'K' (U+212A) con 'k'.
        for cabeceras in ({'Set-Cookie': 'ſucuri_cloudproxy_x=1'}, {'X-CDN': 'İncapsula'},
                          {'Server': 'aKamaighost'}, {'x-aKamai-transformed': '9'}):
            self.assertEqual(borde.por_cabeceras(cabeceras), {}, ascii(cabeceras))
        self.assertIsNone(borde.reto(200, {'x-amzn-waf-action': 'blocK'}))
        # Las mismas en ASCII sí calzan.
        self.assertEqual(borde.por_cabeceras({'X-CDN': 'Incapsula', 'X-Akamai-Transformed': '9'}),
                         {'akamai': ['x-akamai-transformed'], 'imperva': ['x-cdn']})
        self.assertEqual(borde.reto(200, {'x-amzn-waf-action': 'BLOCK'})['proveedor'], 'aws_waf')
        self.assertEqual(borde.por_cname(['e0000.a.aKamaiedge.net']), {})
        # En el cuerpo tampoco: str.lower() pasaría la K de Kelvin (U+212A) a 'k'.
        self.assertIsNone(borde.reto(403, {}, '<title>Vercel Security ChecKpoint</title>'))
        self.assertEqual(borde.reto(403, {}, '<title>VERCEL SECURITY CHECKPOINT</title>')['proveedor'], 'vercel')

    def test_12_cookies_juntas_despues_de_8_kib(self):
        # Un dict de requests junta todas las Set-Cookie: la del borde puede llegar después de MAX_VALOR caracteres.
        relleno = ', '.join('c%d=CIRDAN_FAKE_%s; path=/' % (i, 'x' * 100) for i in range(100))
        self.assertGreater(len(relleno), borde.MAX_VALOR)
        juntas = relleno + ', __cf_bm=CIRDAN_FAKE_a; path=/'
        self.assertEqual(borde.por_cabeceras({'Set-Cookie': juntas}), {'cloudflare': ['set-cookie:__cf_bm']})
        # Más allá de MAX_COOKIES ya no se mira, como dice el docstring, y las demás cabeceras siguen con MAX_VALOR.
        lejos = 'c=CIRDAN_FAKE_' + 'x' * borde.MAX_COOKIES + ', __cf_bm=CIRDAN_FAKE_a'
        self.assertEqual(borde.por_cabeceras({'Set-Cookie': lejos}), {})
        self.assertEqual(borde.por_cabeceras({'Via': '1.1 ' + 'x' * borde.MAX_VALOR + ' (CloudFront)'}), {})


class Detectar(unittest.TestCase):
    def test_1_todas_las_senales_juntas(self):
        datos = borde_de('cloudflare_pagina_200', cnames=['www.acme-demo.mx.cdn.cloudflare.net'],
                         ips=['104.16.0.1'], asns=[13335])
        self.assertEqual(datos, {'texto': 'Protegido por Cloudflare', 'proveedores': [{
            'codigo': 'cloudflare', 'nombre': 'Cloudflare', 'senales': ['asn', 'cabeceras', 'cname', 'rangos'],
            'asns': [13335], 'cabeceras': ['cf-cache-status', 'cf-ray', 'server', 'set-cookie:__cf_bm'],
            'cnames': ['www.acme-demo.mx.cdn.cloudflare.net'], 'ips': ['104.16.0.1']}]})

    def test_2_basta_una_senal(self):
        self.assertEqual(borde.detectar(asns=[30148])['texto'], 'Protegido por Sucuri')
        self.assertEqual(borde.detectar(cnames=['acme.b-cdn.net'])['texto'], 'Protegido por Bunny')
        self.assertEqual(borde_de('cloudfront_pagina_200')['texto'], 'Protegido por Amazon CloudFront')

    def test_3_varios_proveedores_primero_el_de_mas_senales(self):
        datos = borde_de('cloudflare_pagina_200', cnames=['acme.global.ssl.fastly.net'], asns=[54113, 13335])
        self.assertEqual([(p['codigo'], p['senales']) for p in datos['proveedores']],
                         [('cloudflare', ['asn', 'cabeceras']), ('fastly', ['asn', 'cname'])])
        self.assertEqual(datos['texto'], 'Protegido por Cloudflare y Fastly')
        tres = borde.detectar(asns=[13335, 54113, 30148])
        self.assertEqual(tres['texto'], 'Protegido por Cloudflare, Fastly y Sucuri')

    def test_4_sin_senales_es_none_no_un_sin_cdn(self):
        # No ver un CDN o WAF no prueba que no lo haya: no hay ningún texto que diga 'sin CDN' o 'sin WAF'.
        self.assertIsNone(borde_de('sin_borde_200'))
        self.assertIsNone(borde.detectar(cnames=['acme.herokudns.com'], ips=['203.0.113.5'], asns=[16509]))
        self.assertIsNone(borde.detectar())
        # Ningún texto del módulo, fuera de los docstrings, dice que no hay CDN o WAF.
        arbol = ast.parse((RAIZ / 'cirdan' / 'recolectores' / 'borde.py').read_text(encoding='utf-8'))
        docstrings = {id(n.body[0].value) for n in ast.walk(arbol)
                      if isinstance(n, (ast.Module, ast.FunctionDef)) and ast.get_docstring(n) is not None}
        textos = [n.value.lower() for n in ast.walk(arbol)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]
        self.assertGreater(len(textos), 50)
        for texto in textos:
            for prohibido in ('sin cdn', 'sin waf', 'no hay cdn', 'no hay waf', 'sin protec', 'no protegido'):
                self.assertNotIn(prohibido, texto)

    def test_5_es_un_dato_del_activo_que_cumple_el_contrato(self):
        datos = borde_de('cloudflare_pagina_200', cnames=['www.acme-demo.mx.cdn.cloudflare.net'], asns=[13335])
        res = Resultado(DOMINIO, 'prueba', activos=[Activo('subdomain', SITIO, {'borde': datos}),
                                                    Activo('subdomain', OTRO, {'borde': None})])
        self.assertEqual(validar(res, codigos=CODIGOS), [])

    def test_6_el_reto_tambien_marca_el_borde(self):
        for nombre, proveedor in (('cloudflare_reto_403', 'cloudflare'), ('sucuri_bloqueo_403', 'sucuri'),
                                  ('imperva_bloqueo_403', 'imperva'), ('akamai_bloqueo_403', 'akamai'),
                                  ('aws_waf_reto_202', 'aws_waf'), ('vercel_reto_429', 'vercel')):
            self.assertEqual(borde_de(nombre)['proveedores'][0]['codigo'], proveedor, nombre)


class Retos(unittest.TestCase):
    def test_1_retos_y_bloqueos(self):
        casos = {'cloudflare_reto_403': ('cloudflare', 403, 'cabecera cf-mitigated'),
                 'cloudflare_bloqueo_403': ('cloudflare', 403, 'página de reto o bloqueo'),
                 'cloudflare_reto_503': ('cloudflare', 503, 'página de reto o bloqueo'),
                 'sucuri_bloqueo_403': ('sucuri', 403, 'página de reto o bloqueo'),
                 'imperva_bloqueo_403': ('imperva', 403, 'página de reto o bloqueo'),
                 'akamai_bloqueo_403': ('akamai', 403, 'página de reto o bloqueo'),
                 'aws_waf_reto_202': ('aws_waf', 202, 'cabecera x-amzn-waf-action'),
                 'vercel_reto_429': ('vercel', 429, 'cabecera x-vercel-mitigated'),
                 'limite_429': (None, 429, 'límite de peticiones'),
                 'sucuri_limite_429': (None, 429, 'límite de peticiones')}   # sus cabeceras no dicen de quién es
        for nombre, (proveedor, estado, motivo) in casos.items():
            self.assertEqual(reto_de(nombre), {'proveedor': proveedor, 'estado': estado, 'motivo': motivo}, nombre)

    def test_2_un_403_o_503_sin_marca_es_del_sitio(self):
        for nombre in ('origen_403', 'origen_503', 'cloudflare_pagina_200', 'cloudfront_pagina_200', 'sin_borde_200'):
            self.assertIsNone(reto_de(nombre), nombre)
        # Un captcha genérico puede ser un formulario del propio sitio: no es la página de reto de un proveedor.
        for formulario in ('<div class="g-recaptcha">', '<div class="h-captcha">', '<div class="cf-turnstile">',
                           '<div class="math-captcha">'):
            for estado in (403, 503):
                self.assertIsNone(borde.reto(estado, {'Server': 'nginx'}, '<form>%s</form>' % formulario), formulario)
        # Cloudflare pone su script en cualquier página: un 403 o un 503 del sitio detrás de él no es un reto.
        pagina = ('<html><head><title>En mantenimiento</title></head><body><script src="/cdn-cgi/challenge-platform/'
                  'scripts/jsd/main.js"></script></body></html>')
        for estado in (403, 503):
            self.assertIsNone(borde.reto(estado, {'Server': 'cloudflare', 'CF-RAY': '0-QRO'}, pagina), estado)

    def test_3_las_marcas_solo_cuentan_con_403_429_o_503(self):
        cuerpo = respuesta('cloudflare_bloqueo_403')['cuerpo']
        for estado in (200, 404, 500, 502):
            self.assertIsNone(borde.reto(estado, {}, cuerpo), estado)
        for estado, motivo in ((403, borde.MOTIVO_PAGINA), (429, borde.MOTIVO_LIMITE), (503, borde.MOTIVO_PAGINA)):
            self.assertEqual(borde.reto(estado, {}, cuerpo), {'proveedor': 'cloudflare', 'estado': estado,
                                                               'motivo': motivo}, estado)

    def test_4_la_cabecera_de_reto_vale_con_cualquier_estado_si_su_valor_calza(self):
        self.assertEqual(borde.reto(200, {'CF-Mitigated': 'challenge'})['motivo'], 'cabecera cf-mitigated')
        self.assertEqual(borde.reto(405, {'x-amzn-waf-action': 'captcha'})['proveedor'], 'aws_waf')
        self.assertEqual(borde.reto(403, {'X-Sucuri-Block': 'BW001'})['proveedor'], 'sucuri')
        self.assertIsNone(borde.reto(200, {'cf-mitigated': 'otra-cosa', 'x-sucuri-block': ''}))
        # Las cabeceras se leen una sola vez: un generador también sirve.
        self.assertEqual(borde.reto(429, iter([('cf-mitigated', 'challenge')]))['proveedor'], 'cloudflare')

    def test_5_cuerpo_en_bytes_y_tope(self):
        marca = b'<title>Just a moment...</title>'
        self.assertEqual(borde.reto(503, {}, marca)['proveedor'], 'cloudflare')
        self.assertEqual(borde.reto(503, {}, b'\xff\xfe' + marca)['proveedor'], 'cloudflare')
        self.assertIsNone(borde.reto(503, {}, b' ' * borde.MAX_CUERPO + marca))
        self.assertIsNone(borde.reto(503, {}, None))

    def test_6_estado_que_no_es_entero(self):
        for estado in (None, '403', 403.0, True):
            self.assertIsNone(borde.reto(estado, {'cf-mitigated': 'challenge'}), estado)

    def test_7_aviso(self):
        texto = borde.aviso('web', SITIO, reto_de('cloudflare_reto_403'))
        self.assertEqual(texto, 'web: www.acme-demo.mx respondió con un reto o bloqueo de Cloudflare '
                                '(403, cabecera cf-mitigated): sus tecnologías quedan sin cobertura, no 0')
        # Un 429 sin borde conocido no se atribuye a un WAF.
        self.assertEqual(borde.aviso('web', SITIO, reto_de('limite_429')),
                         'web: www.acme-demo.mx respondió con un límite de peticiones (429): sus tecnologías quedan '
                         'sin cobertura, no 0')
        self.assertIn('con un límite de peticiones (429):', borde.aviso('web', SITIO, reto_de('sucuri_limite_429')))
        limite = borde.reto(429, {'Server': 'cloudflare'}, respuesta('cloudflare_bloqueo_403')['cuerpo'])
        self.assertIn('con un límite de peticiones de Cloudflare (429):', borde.aviso('web', SITIO, limite))
        # Sin datos no dice WAF ni pone None.
        for nada in (None, {}, 'reto'):
            self.assertEqual(borde.aviso('web', SITIO, nada), 'web: www.acme-demo.mx respondió con un reto o bloqueo: '
                                                              'sus tecnologías quedan sin cobertura, no 0', nada)
        # Un proveedor que no es texto no lanza TypeError.
        for raro in ([], {}, 7):
            datos = {'proveedor': raro, 'estado': 403, 'motivo': borde.MOTIVO_PAGINA}
            self.assertEqual(borde.aviso('web', SITIO, datos),
                             'web: www.acme-demo.mx respondió con un reto o bloqueo (403, página de reto o bloqueo): '
                             'sus tecnologías quedan sin cobertura, no 0', raro)

    def test_8_un_429_es_un_limite_y_las_cabeceras_del_cdn_no_dicen_de_quien(self):
        # Las cabeceras del CDN vienen en toda respuesta que pasa por él, también en un 429 del propio sitio.
        for cabeceras in ({'Server': 'cloudflare', 'CF-RAY': '0-QRO'}, {'X-Vercel-Id': 'qro1::0'}, None):
            self.assertEqual(borde.reto(429, cabeceras, 'Too Many Requests'),
                             {'proveedor': None, 'estado': 429, 'motivo': borde.MOTIVO_LIMITE}, cabeceras)
        self.assertEqual(borde.reto(429, {'cf-mitigated': 'challenge'}),
                         {'proveedor': 'cloudflare', 'estado': 429, 'motivo': 'cabecera cf-mitigated'})

    def test_9_un_script_que_va_en_cualquier_pagina_no_es_marca(self):
        # Imperva mete /_Incapsula_Resource en las páginas del sitio y AwsWafIntegration es el SDK dentro de la
        # aplicación: un 403 o un 503 del propio sitio con ellos no es un reto.
        self.assertEqual({m for _, m in borde.MARCAS} & {'_incapsula_resource', 'awswafintegration'}, set())
        for script in ('<script src="/_Incapsula_Resource?SWJIYLWA=0000"></script>',
                       '<script>AwsWafIntegration.getToken()</script>'):
            pagina = '<html><head><title>Sin permiso</title>%s</head><body>No</body></html>' % script
            for estado in (403, 503):
                self.assertIsNone(borde.reto(estado, {'Server': 'nginx'}, pagina), (estado, script))

    def test_10_con_un_429_gana_la_cabecera_de_reto(self):
        datos = reto_de('vercel_reto_429')
        self.assertEqual(borde.aviso('web', SITIO, datos),
                         'web: www.acme-demo.mx respondió con un reto o bloqueo de Vercel (429, cabecera '
                         'x-vercel-mitigated): sus tecnologías quedan sin cobertura, no 0')
        # Sin la cabecera de reto sigue como límite de peticiones, y el proveedor solo sale por una marca.
        r = respuesta('vercel_reto_429')
        sin = [(n, v) for n, v in r['cabeceras'] if n.lower() != 'x-vercel-mitigated']
        self.assertEqual(borde.reto(429, sin, r['cuerpo']),
                         {'proveedor': 'vercel', 'estado': 429, 'motivo': borde.MOTIVO_LIMITE})
        self.assertEqual(borde.reto(429, sin, 'Too Many Requests'),
                         {'proveedor': None, 'estado': 429, 'motivo': borde.MOTIVO_LIMITE})


class Cobertura(unittest.TestCase):
    def test_1_todo_revisado_solo_con_sin_revisar_vacio(self):
        self.assertEqual(borde.cobertura([SITIO, OTRO], [], CODIGOS), (None, None, []))
        self.assertEqual(borde.cobertura([], [], CODIGOS), (None, None, []))   # la visita no tenía sitios
        self.assertEqual(borde.cobertura(None, (), CODIGOS), (None, None, []))
        self.assertEqual(borde.cobertura([], None, CODIGOS), (None, None, CODIGOS))   # no sabe cuáles: test_7

    def test_2_todo_con_reto_es_sin_cobertura_y_no_0_tecnologias(self):
        revisados, sin_revisar, sin_cobertura = borde.cobertura([], [SITIO], CODIGOS)
        self.assertEqual((revisados, sin_revisar, sin_cobertura), (None, None, CODIGOS))
        res = Resultado(DOMINIO, 'prueba', revisados=revisados, sin_revisar=sin_revisar, sin_cobertura=sin_cobertura,
                        avisos=[borde.aviso('prueba', SITIO, reto_de('cloudflare_reto_403'))])
        self.assertEqual(validar(res, codigos=CODIGOS), [])
        res.hallazgos = [hallazgo()]   # con los códigos sin cobertura, ninguna tecnología puede salir como hallazgo
        self.assertTrue(any('sin_cobertura' in e for e in validar(res, codigos=CODIGOS)))

    def test_3_cobertura_parcial_por_sitio(self):
        revisados, sin_revisar, sin_cobertura = borde.cobertura([SITIO, OTRO, ''], [OTRO], CODIGOS)
        self.assertEqual((revisados, sin_revisar, sin_cobertura), ([SITIO], [OTRO], []))
        res = Resultado(DOMINIO, 'prueba', revisados=revisados, sin_revisar=sin_revisar,
                        activos=[Activo('subdomain', SITIO)], hallazgos=[hallazgo(partes=[SITIO])])
        self.assertEqual(validar(res, codigos=CODIGOS), [])
        res.hallazgos = [hallazgo()]   # sin su sitio en partes no se podría cerrar
        self.assertTrue(any('partes' in e for e in validar(res, codigos=CODIGOS)))

    def test_4_codigos_sin_repetir(self):
        self.assertEqual(borde.cobertura([], [SITIO], CODIGOS + CODIGOS[:1])[2], CODIGOS)
        self.assertEqual(borde.cobertura([], [SITIO], 'outdated_software')[2], ['outdated_software'])
        for nada in (None, [], [None, '']):   # sin códigos no se puede decir qué quedó sin cobertura
            with self.assertRaises(ValueError):
                borde.cobertura([SITIO], [OTRO], nada)

    def test_5_nombres_como_llegaron_y_entradas_raras(self):
        self.assertEqual(borde.cobertura(['WWW.acme-demo.mx'], ['www.acme-demo.mx.'], CODIGOS), (None, None, CODIGOS))
        self.assertEqual(borde.cobertura([SITIO, Activo('subdomain', OTRO), 7], SITIO.upper(), CODIGOS),
                         (None, None, CODIGOS))
        # Salen como llegaron, para que calcen con las partes de los hallazgos de la misma visita.
        tienda = 'Tienda.Acme-Demo.mx'
        self.assertEqual(borde.cobertura([SITIO, tienda.upper()], [tienda], CODIGOS), ([SITIO], [tienda, OTRO], []))
        self.assertEqual(borde.cobertura([SITIO.upper(), SITIO], [OTRO], CODIGOS), ([SITIO.upper()], [OTRO], []))

    def test_6_un_sin_revisar_que_no_se_puede_leer_no_cuenta_como_revisado(self):
        # Si no se sabe qué sitio quedó sin revisar, ninguno cuenta como revisado: nunca 'revisó todo'.
        for raro in ([OTRO, None], [7], [''], [Activo('subdomain', OTRO)], Activo('subdomain', OTRO),
                     b'tienda.acme-demo.mx', iter([OTRO]), ['tienda.acme-demо.mx']):
            self.assertEqual(borde.cobertura([SITIO, OTRO], raro, CODIGOS), (None, None, CODIGOS), ascii(raro))

    def test_7_sin_revisar_none_es_que_no_las_sabe(self):
        # contrato.Resultado: sin_revisar None es 'no las sabe', nunca 'revisó todo'. Con revisados es una corrida
        # parcial en la que el orquestador cierra solo lo de revisados.
        for nada in (None, [], [7, ''], 'no es lista'):
            self.assertEqual(borde.cobertura(nada, None, CODIGOS), (None, None, CODIGOS), nada)
        blog = 'blog.' + DOMINIO
        revisados, sin_revisar, sin_cobertura = borde.cobertura([SITIO, OTRO, SITIO.upper()], None, CODIGOS)
        self.assertEqual((revisados, sin_revisar, sin_cobertura), ([OTRO, SITIO], None, []))
        self.assertTrue(se_cierra([SITIO], revisados, sin_revisar))
        self.assertFalse(se_cierra([blog], revisados, sin_revisar))
        res = Resultado(DOMINIO, 'prueba', revisados=revisados, sin_revisar=sin_revisar,
                        activos=[Activo('subdomain', SITIO)], hallazgos=[hallazgo(partes=[SITIO])])
        self.assertEqual(validar(res, codigos=CODIGOS), [])

    def test_8_sin_revisar_lleva_todas_las_formas_del_sitio(self):
        # El orquestador compara las partes tal cual: un hallazgo guardado con otra forma del nombre no se cierra sin
        # revisar su sitio.
        tienda = 'Tienda.Acme-Demo.mx'
        revisados, sin_revisar, _ = borde.cobertura([SITIO], [tienda, OTRO + '.', tienda], CODIGOS)
        self.assertEqual((revisados, sin_revisar), ([SITIO], [tienda, OTRO + '.', OTRO]))
        for partes in ([tienda], [OTRO], [OTRO + '.'], [SITIO, OTRO]):
            self.assertFalse(se_cierra(partes, revisados, sin_revisar), partes)
        self.assertTrue(se_cierra([SITIO], revisados, sin_revisar))
        res = Resultado(DOMINIO, 'prueba', revisados=revisados, sin_revisar=sin_revisar,
                        activos=[Activo('subdomain', SITIO)], hallazgos=[hallazgo(partes=[SITIO])])
        self.assertEqual(validar(res, codigos=CODIGOS), [])

    def test_9_solo_nombres_dns(self):
        # Un NUL haría que validar rechace el resultado, y una URL o un puerto nunca calzan con las partes.
        for raro in (OTRO + '\x00', 'https://' + OTRO + '/', OTRO + ':443', OTRO + '/', ' ' + OTRO, OTRO + '\n',
                     'tienda acme', '.' + OTRO, 'tienda..' + DOMINIO, 'tienda_1.' + DOMINIO, '.'):
            self.assertEqual(borde.cobertura([SITIO, OTRO], [raro], CODIGOS), (None, None, CODIGOS), ascii(raro))
            self.assertEqual(borde.cobertura([SITIO, raro], [OTRO], CODIGOS), ([SITIO], [OTRO], []), ascii(raro))
            self.assertEqual(borde.por_cname([raro.replace(OTRO, 'acme.b-cdn.net')]), {}, ascii(raro))
        # Mayúsculas, punto final y punycode sí son nombres.
        self.assertEqual(borde.cobertura([SITIO], ['TIENDA.acme-demo.mx.', 'xn--tienda-9za.' + DOMINIO], CODIGOS),
                         ([SITIO], ['TIENDA.acme-demo.mx.', OTRO, 'xn--tienda-9za.' + DOMINIO], []))


class Entradas(unittest.TestCase):
    def test_1_un_solo_valor_en_vez_de_lista(self):
        self.assertEqual(borde.detectar(ips='104.16.0.1')['proveedores'][0]['ips'], ['104.16.0.1'])
        self.assertEqual(borde.detectar(asns=13335)['proveedores'][0]['asns'], [13335])
        self.assertEqual(borde.detectar(cnames='acme.b-cdn.net')['texto'], 'Protegido por Bunny')
        ip = ipaddress.ip_address('104.16.0.1')
        self.assertEqual(borde.detectar(ips=ip)['proveedores'][0]['ips'], ['104.16.0.1'])
        self.assertIsNone(borde.detectar(ips=ipaddress.ip_network('104.16.0.0/13')))   # una red no se recorre
        # Un generador o un rango grande se leen hasta el tope, no enteros.
        datos = borde.detectar(ips=ipaddress.ip_network('104.16.0.0/13').hosts(), asns=range(10 ** 12))
        self.assertEqual(len(datos['proveedores'][0]['ips']), borde.MAX_IPS)

    def test_2_tipos_que_no_se_pueden_leer_no_lanzan(self):
        for raro in (7, 3.5, object(), b'\xff', {'a': 1}):
            self.assertIsNone(borde.detectar(cnames=raro, ips=raro, asns=raro, cabeceras=raro), raro)
            self.assertIsNone(borde.reto(403, raro, raro), raro)


class Datos(unittest.TestCase):
    def test_1_proveedores_conocidos(self):
        self.assertLessEqual(set(geoip.CDN_POR_ASN.values()), set(borde.PROVEEDORES))
        firmas = {p for lista in borde.FIRMAS.values() for p, _ in lista}
        retos = {p for p, _ in borde.RETO_POR_CABECERA.values()}
        marcas = {p for p, _ in borde.MARCAS} - {None}
        self.assertLessEqual(firmas | retos | marcas, set(borde.PROVEEDORES))
        self.assertTrue(all(m == m.lower() for _, m in borde.MARCAS))
        self.assertTrue(all(c == c.lower() for c in list(borde.FIRMAS) + list(borde.RETO_POR_CABECERA)))

    def test_2_no_es_un_recolector_ni_una_regla(self):
        self.assertNotIn('borde', REGISTRO)
        for nombre in ('FUENTE', 'CODIGOS', 'MAX_CONSULTAS', 'recolectar', 'crear_cliente'):
            self.assertFalse(hasattr(borde, nombre), nombre)

    def test_3_no_importa_nada_de_red(self):
        arbol = ast.parse((RAIZ / 'cirdan' / 'recolectores' / 'borde.py').read_text(encoding='utf-8'))
        importados = set()
        for nodo in ast.walk(arbol):
            if isinstance(nodo, ast.Import):
                importados |= {a.name for a in nodo.names}
            elif isinstance(nodo, ast.ImportFrom):
                importados |= {'%s.%s' % (nodo.module, a.name) for a in nodo.names}
        self.assertEqual(importados, {'ipaddress', 're', 'cirdan.recolectores.geoip', 'cirdan.recolectores.shodan'})

    def test_4_respuestas_armadas_con_valores_falsos(self):
        archivos = sorted(FIXTURES.glob('*.json'))
        self.assertEqual(len(archivos), 16)
        for archivo in archivos:
            datos = respuesta(archivo.stem)
            self.assertEqual(set(datos), {'nota', 'descripcion', 'estado', 'cabeceras', 'cuerpo'}, archivo.name)
            self.assertIn('no grabada de ningún dominio', datos['nota'])
            for nombre, valor in datos['cabeceras']:
                if nombre.lower() == 'set-cookie':
                    self.assertIn('=CIRDAN_FAKE_', valor, archivo.name)


if __name__ == '__main__':
    unittest.main()
