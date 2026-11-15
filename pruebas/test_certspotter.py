"""Pruebas del respaldo de crt.sh con Cert Spotter (#14b), sin red: crt.sh caído, una API de Cert Spotter simulada
con respuestas de la misma forma que la real, y una fecha fija.

    python -m unittest -v pruebas/test_certspotter.py
"""
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_certspotter.py
from pruebas.test_crtsh import AHORA, SUBDOMINIOS, CrtshSimulado, cert  # noqa: E402
from cirdan.recolectores import cargar, certspotter, contrato, crtsh  # noqa: E402

LE = {'friendly_name': "Let's Encrypt", 'pubkey_sha256': 'b' * 64, 'name': "C=US, O=Let's Encrypt, CN=R11"}
SSLCOM = {'friendly_name': 'SSL.com', 'pubkey_sha256': 'c' * 64, 'name': 'C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3'}


def emision(id_, nombres, inicio, fin, emisor=LE):
    """Una emisión como las devuelve /v1/issuances con expand=dns_names y expand=issuer."""
    sha = hashlib.sha256(id_.encode()).hexdigest()
    return {'id': id_, 'tbs_sha256': sha[::-1], 'cert_sha256': sha, 'dns_names': nombres, 'pubkey_sha256': 'a' * 64,
            'issuer': emisor, 'not_before': inicio, 'not_after': fin, 'revoked': False}


EMISIONES = [
    emision('9001', ['acme-demo.mx', 'www.acme-demo.mx'], '2026-09-20T00:00:00Z', '2026-12-19T00:00:00Z'),
    emision('9002', ['api.acme-demo.mx'], '2026-07-27T00:00:00Z', '2026-10-25T12:00:00Z'),  # vence en 10 días
    emision('9003', ['*.tienda.acme-demo.mx', 'tienda.acme-demo.mx'], '2026-09-01T00:00:00Z', '2026-11-30T00:00:00Z'),
    emision('9004', ['*.acme-demo.mx', 'acme-demo.mx'], '2026-10-01T00:00:00Z', '2027-01-01T00:00:00Z', SSLCOM),
]

# Primera página real de /v1/issuances para olmardo.com, grabada el 18 oct 2026 con crt.sh caído. Son datos públicos de CT:
# las huellas sha256 no son secretos (gitleaks:allow evita el falso positivo de su regla genérica).
OLMARDO = [
    {'id': '17771264516', 'tbs_sha256': '1a51399678c8ea090124f6d4cbc743096cd21e45894c03b8a83b66b6d0ad78c2',
     'cert_sha256': '23a523795ea88120d214f2b7f73b320490998b908b5ff96feb7df037167c0ef0', 'dns_names': ['*.olmardo.com', 'olmardo.com'],
     'pubkey_sha256': '8b43d9f072c905b213f3f610a70e86746c099e594d5c9b0667877a1e20c25db0',  # gitleaks:allow
     'issuer': {'friendly_name': "Let's Encrypt", 'pubkey_sha256': 'b3fb5d00e994cddf2cc9a4eea9f806bc5727e83cc0e4299bf956f2d524fe5376',  # gitleaks:allow
                'name': "C=US, O=Let's Encrypt, CN=YE2"},
     'not_before': '2026-10-14T00:04:32Z', 'not_after': '2027-01-12T00:04:31Z', 'revoked': False},
    {'id': '17772119077', 'tbs_sha256': '91a7609fa947152b4e33500a83ee9ce8a6294320450a17dfc7780b9756072a50',
     'cert_sha256': '9847e6912bca362e7100c6d1ba710e34e01ccb8be737c1e4d3423f4994159434', 'dns_names': ['reservas.olmardo.com'],
     'pubkey_sha256': 'b0c1779e0f03ca9898e7329dbb37a67cd20405287667c8ff4dca270450773399',  # gitleaks:allow
     'issuer': {'friendly_name': "Let's Encrypt", 'pubkey_sha256': 'b3fb5d00e994cddf2cc9a4eea9f806bc5727e83cc0e4299bf956f2d524fe5376',  # gitleaks:allow
                'name': "C=US, O=Let's Encrypt, CN=YE2"},
     'not_before': '2026-10-14T01:10:15Z', 'not_after': '2027-01-12T01:10:14Z', 'revoked': False},
    {'id': '17772281649', 'tbs_sha256': '5faf567416dafdbfda15db054efcf7735f7e60c80ee7892c8eb3516584914d05',
     'cert_sha256': '56d2b431db04768b16d323400d2432132816798fd8c359a02ee073b872a00b9f', 'dns_names': ['camaras.olmardo.com'],
     'pubkey_sha256': '34ef2421a1801438c2d93acf2426ce0e8ab6d6affdd7ca45baa4e7c6cf92c920',  # gitleaks:allow
     'issuer': {'friendly_name': "Let's Encrypt", 'pubkey_sha256': '6ebcefb4210b088654a38b03fea3d7d1c711b4fb1ddc363a45f9b1a4e53da01e',  # gitleaks:allow
                'name': "C=US, O=Let's Encrypt, CN=YE1"},
     'not_before': '2026-10-14T01:23:17Z', 'not_after': '2027-01-12T01:23:16Z', 'revoked': False},
    {'id': '17778865245', 'tbs_sha256': '9684ee820e1bb82e18b10f364fe5f4e4521a99e83719221f57bff08478fec460',
     'cert_sha256': 'd964d1b51b83bd5524fe4a5abfdd7f620d5251ef3997f47fa92d97c54bee7698', 'dns_names': ['*.olmardo.com', 'olmardo.com'],
     'pubkey_sha256': 'fac4dff817a0ba4326e4b90411a6fb9cec8224450f68a7f1271ab8faf2893576',  # gitleaks:allow
     'issuer': {'friendly_name': 'SSL.com', 'pubkey_sha256': '1959e38fb7d3fc16bee5e20e834e2c6667bf0e9e6b9806b86bd40a6d66c716d0',  # gitleaks:allow
                'name': 'C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 4'},
     'not_before': '2026-10-14T10:24:56Z', 'not_after': '2027-01-12T01:00:49Z', 'revoked': False},
]


class RespaldoSimulado:
    """crt.sh (caído con 502 si `crtsh` es None) y la API de Cert Spotter con sus páginas. Anota cada URL."""

    def __init__(self, paginas=None, crtsh=None, certspotter_caido=False, sin_dns=(), limite_en=None):
        """`limite_en`: número de página (desde 0) en que Cert Spotter responde 429, su límite por hora."""
        self.paginas = paginas if paginas is not None else [EMISIONES]
        self.crtsh, self.certspotter_caido, self.sin_dns = crtsh, certspotter_caido, set(sin_dns)
        self.limite_en = limite_en
        self.urls, self.dns = [], []

    def __call__(self, url, timeout):
        self.urls.append(url)
        partes = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(partes.query)
        if partes.netloc == 'api.certspotter.com':
            if self.certspotter_caido:
                raise urllib.error.HTTPError(url, 503, 'Service Unavailable', None, None)
            assert q['include_subdomains'] == ['true'] and q['expand'] == ['dns_names', 'issuer'], q
            despues = q.get('after', [None])[0]
            siguiente = {None: 0} | {p[-1]['id']: i + 1 for i, p in enumerate(self.paginas) if p}
            i = siguiente[despues]
            if i == self.limite_en:
                raise urllib.error.HTTPError(url, 429, 'Too Many Requests', {'Retry-After': '1800'}, None)
            return json.dumps(self.paginas[i] if i < len(self.paginas) else []).encode()
        if self.crtsh is None:
            raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
        return json.dumps(self.crtsh.get(q['q'][0], [])).encode()

    def resolver(self, nombre):
        self.dns.append(nombre)
        return nombre not in self.sin_dns

    def de(self, host):
        return [u for u in self.urls if urllib.parse.urlparse(u).netloc == host]


def recolectar(transporte, carpeta=None, modo='vivo', parecidos=False, **kw):
    cliente = crtsh.ClienteCrtsh(modo=modo, carpeta=carpeta or crtsh.CARPETA_GRABADAS, transporte=transporte,
                                 dormir=lambda s: None, **kw)
    return crtsh.recolectar('acme-demo.mx', cliente, AHORA, propios=['acme-demo.com.mx'], parecidos=parecidos), cliente


def sin_red(url, timeout):
    raise AssertionError('no debe usar la red: %s' % url)


DANOS = ('vacio', 'cortado', 'ilegible')


def danar(archivo, como):
    """Deja el archivo de la grabación vacío, cortado a la mitad o con bytes que no son UTF-8. Devuelve lo que tenía."""
    bueno = archivo.read_bytes()
    archivo.write_bytes({'vacio': b'', 'cortado': bueno[:len(bueno) // 2], 'ilegible': b'\xff\xfe{'}[como])
    return bueno


class Respaldo(unittest.TestCase):

    def setUp(self):
        self.t = RespaldoSimulado()
        self.res, _ = recolectar(self.t, parecidos=True)  # aunque se pidan, con crt.sh caído no se buscan
        self.activos = {a.valor: a for a in self.res.activos}
        self.hallazgos = {(h.codigo, h.activo): h for h in self.res.hallazgos}

    def test_1_si_crtsh_no_responde_los_subdominios_salen_de_cert_spotter(self):
        self.assertEqual((self.res.estado, self.res.error), ('succeeded', ''))
        self.assertEqual(sorted(self.activos), ['acme-demo.mx', 'api.acme-demo.mx', 'tienda.acme-demo.mx', 'www.acme-demo.mx'])
        self.assertEqual(self.activos['acme-demo.mx'].tipo, 'domain')
        for a in self.res.activos:
            self.assertEqual((a.atributos['origen'], a.atributos['fuente']), ('certspotter', 'ct_logs'), a.valor)
            self.assertNotIn('crtsh_id', a.atributos)
        self.assertEqual(self.activos['www.acme-demo.mx'].atributos['certspotter_id'], '9001')
        self.assertEqual(contrato.validar(self.res, codigos=set(crtsh.CODIGOS)), [])

    def test_2_no_busca_parecidos_en_crtsh_caido_y_cuenta_todas_las_consultas(self):
        self.assertEqual(len(self.t.de('crt.sh')), 2 * crtsh.INTENTOS)   # comodín y búsqueda por nombre, sin variantes
        self.assertEqual(len(self.t.de('api.certspotter.com')), 2)       # la página y la vacía que cierra
        self.assertEqual(self.res.consultas, 2 * crtsh.INTENTOS + 2)

    def test_3_por_vencer_con_el_id_de_cert_spotter(self):
        h = self.hallazgos[('cert_expiring_soon', 'api.acme-demo.mx')]
        self.assertEqual(h.evidencia['dias_para_vencer'], 10)
        self.assertEqual((h.evidencia['origen'], h.evidencia['certspotter_id']), ('certspotter', '9002'))
        self.assertEqual(h.evidencia['sha256'], EMISIONES[1]['cert_sha256'])
        self.assertEqual(h.evidencia['emisor'], LE['name'])
        self.assertNotIn('crtsh_id', h.evidencia)
        self.assertEqual({h.codigo for h in self.res.hallazgos}, {'cert_expiring_soon'})

    def test_4_comodines(self):
        dominio = self.activos['acme-demo.mx'].atributos
        self.assertTrue(dominio['comodin'])
        self.assertEqual(dominio['certificados'], 2)
        self.assertEqual((dominio['emisor'], dominio['certspotter_id']), (SSLCOM['name'], '9004'))  # el que vence después
        self.assertTrue(self.activos['tienda.acme-demo.mx'].atributos['comodin'])
        self.assertFalse(self.activos['www.acme-demo.mx'].atributos['comodin'])

    def test_5_vencidos_y_parecidos_quedan_sin_cobertura_con_aviso(self):
        self.assertEqual(self.res.sin_cobertura, ['cert_expired', 'lookalike_domain'])
        self.assertEqual(len(self.res.avisos), 3)
        self.assertTrue(self.res.avisos[0].startswith('crt.sh no respondió a %.acme-demo.mx después de 3 intentos'))
        self.assertTrue(self.res.avisos[1].startswith('crt.sh no respondió a acme-demo.mx después de 3 intentos'))
        self.assertEqual(self.res.avisos[2], certspotter.AVISO)
        self.assertEqual(crtsh.codigo_salida(self.res), 2)
        lineas = crtsh.resumen(self.res)
        self.assertEqual(lineas[0], 'acme-demo.mx · Cert Spotter (crt.sh no respondió) · succeeded · 8 consultas')
        self.assertIn('Cobertura parcial: no se revisaron certificados vencidos (cert_expired) ni dominios parecidos '
                      '(lookalike_domain).', lineas)

    def test_6_paginas(self):
        t = RespaldoSimulado(paginas=[EMISIONES[:2], EMISIONES[2:]])
        res, _ = recolectar(t)
        urls = t.de('api.certspotter.com')
        self.assertEqual(len(urls), 3)
        self.assertEqual([urllib.parse.parse_qs(urllib.parse.urlparse(u).query).get('after') for u in urls],
                         [None, ['9002'], ['9004']])
        self.assertEqual(sorted(a.valor for a in res.activos), sorted(self.activos))
        self.assertEqual([h.huella for h in res.hallazgos], [h.huella for h in self.res.hallazgos])

    def test_7_tope_de_paginas_deja_aviso(self):
        paginas = [[emision(str(9100 + i), ['p%d.acme-demo.mx' % i], '2026-10-01T00:00:00Z', '2026-12-30T00:00:00Z')]
                   for i in range(certspotter.MAX_PAGINAS + 2)]
        t = RespaldoSimulado(paginas=paginas)
        res, _ = recolectar(t)
        self.assertEqual(len(t.de('api.certspotter.com')), certspotter.MAX_PAGINAS)
        self.assertEqual(len(res.activos), certspotter.MAX_PAGINAS)
        self.assertIn('pueden faltar subdominios', res.avisos[-1])

    def test_8_si_cert_spotter_tampoco_responde_queda_failed(self):
        t = RespaldoSimulado(certspotter_caido=True)
        res, _ = recolectar(t)
        self.assertEqual((res.estado, res.activos, res.hallazgos, res.sin_cobertura), ('failed', [], [], []))
        self.assertIn('crt.sh no respondió a acme-demo.mx', res.error)
        self.assertIn('Cert Spotter no respondió a acme-demo.mx después de 3 intentos', res.error)
        self.assertEqual(len(t.de('api.certspotter.com')), crtsh.INTENTOS)
        self.assertEqual(crtsh.codigo_salida(res), 1)

    def test_8b_el_limite_por_hora_no_se_reintenta(self):
        esperas = []
        t = RespaldoSimulado(limite_en=0)
        cliente = crtsh.ClienteCrtsh(transporte=t, dormir=esperas.append)
        res = crtsh.recolectar('acme-demo.mx', cliente, AHORA)
        self.assertEqual(res.estado, 'failed')
        self.assertEqual(len(t.de('api.certspotter.com')), 1)
        self.assertEqual(len(esperas), 2 * (crtsh.INTENTOS - 1))  # solo las de crt.sh
        self.assertIn('Cert Spotter no respondió a acme-demo.mx después de 1 intento (llegó a su límite de consultas, '
                      'Retry-After 1800 s)', res.error)

    def test_8c_si_falla_una_pagina_despues_de_la_primera_sigue_con_lo_que_llego(self):
        t = RespaldoSimulado(limite_en=1)  # la página vacía que cierra da 429
        res, _ = recolectar(t)
        self.assertEqual((res.estado, sorted(a.valor for a in res.activos)), ('succeeded', sorted(self.activos)))
        self.assertEqual(res.avisos[-1], certspotter.INCOMPLETO)
        self.assertEqual(len(t.de('api.certspotter.com')), 2)
        self.assertEqual(res.sin_cobertura, ['cert_expired', 'lookalike_domain'])

    def test_8d_con_paginas_incompletas_el_por_vencer_sigue_y_el_aviso_dice_que_puede_estar_renovado(self):
        res, _ = recolectar(RespaldoSimulado(limite_en=1))
        self.assertIn(('cert_expiring_soon', 'api.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})
        self.assertIn('un certificado por vencer puede estar ya renovado', res.avisos[-1])

    def test_9_si_crtsh_responde_cert_spotter_suma_lo_que_le_falta_sin_repetir(self):
        t = RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS})
        res, _ = recolectar(t, parecidos=True)
        self.assertEqual((len(t.de('api.certspotter.com')), res.sin_cobertura, res.avisos), (2, [], []))
        activos = {a.valor: a.atributos for a in res.activos}
        hallazgos = {(h.codigo, h.activo): h for h in res.hallazgos}
        # 9001 a 9003 son los certificados 2, 3 y 6 de crt.sh (misma vigencia y mismos nombres): quedan los de crt.sh
        self.assertEqual((activos['www.acme-demo.mx']['certificados'], activos['www.acme-demo.mx']['crtsh_id']), (2, 2))
        self.assertEqual([k for k in hallazgos if k[0] == 'cert_expiring_soon'], [('cert_expiring_soon', 'api.acme-demo.mx')])
        h = hallazgos[('cert_expiring_soon', 'api.acme-demo.mx')]
        self.assertEqual((h.evidencia['origen'], h.evidencia['crtsh_id']), ('crtsh', 3))
        # 9004, el comodín de SSL.com, solo lo trae Cert Spotter: es el más reciente del dominio y cubre al vencido de dev
        dominio = activos['acme-demo.mx']
        self.assertEqual((dominio['origen'], dominio['certspotter_id'], dominio['certificados']), ('certspotter', '9004', 3))
        self.assertEqual(activos['dev.acme-demo.mx']['cubierto_por_comodin'], 'acme-demo.mx')
        self.assertNotIn(('cert_expired', 'dev.acme-demo.mx'), hallazgos)
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])
        self.assertTrue(crtsh.resumen(res)[0].startswith('acme-demo.mx · crt.sh y Cert Spotter · succeeded · '))

    def test_9b_si_cert_spotter_no_responde_queda_lo_de_crtsh_con_aviso(self):
        t = RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS}, limite_en=0)  # 429 en la primera página
        res, _ = recolectar(t)
        self.assertEqual((res.estado, res.sin_cobertura, len(t.de('api.certspotter.com'))),
                         ('succeeded', ['lookalike_domain'], 1))  # el 429 no se reintenta
        self.assertEqual(len(res.avisos), 1)
        self.assertTrue(res.avisos[0].startswith('Cert Spotter no respondió a acme-demo.mx después de 1 intento'))
        self.assertTrue(res.avisos[0].endswith(certspotter.SIN_COMPLEMENTO))
        self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})
        self.assertEqual(crtsh.codigo_salida(res), 2)
        self.assertTrue(crtsh.resumen(res)[0].startswith('acme-demo.mx · crt.sh · succeeded · '))

    def test_9c_una_emision_que_no_se_puede_leer_no_tumba_lo_de_crtsh(self):
        vigencia = ('2026-10-01T00:00:00Z', '2027-01-01T00:00:00Z')
        raras = [dict(emision('9101', ['lista.acme-demo.mx'], *vigencia), id=['x']),
                 dict(emision('9102', ['raro.acme-demo.mx'], *vigencia), not_before='2026-10-01 00:00:00 UTC'),
                 dict(emision('9103', ['entero.acme-demo.mx'], *vigencia), not_after=1798761600),
                 dict(emision('9104', [], *vigencia), dns_names=5)]
        for caido in (False, True):  # con crt.sh arriba (complemento) y caído (respaldo)
            t = RespaldoSimulado(paginas=[raras + EMISIONES], crtsh=None if caido else {'%.acme-demo.mx': SUBDOMINIOS})
            res, _ = recolectar(t)
            activos = {a.valor: a.atributos for a in res.activos}
            self.assertEqual(res.estado, 'succeeded', caido)
            self.assertEqual(activos['acme-demo.mx']['certspotter_id'], '9004', caido)
            self.assertFalse({'lista.acme-demo.mx', 'raro.acme-demo.mx', 'entero.acme-demo.mx'} & set(activos), caido)
            self.assertEqual(res.avisos[-1], certspotter.INCOMPLETO, caido)  # el id que no sirve no se calla
            self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [], caido)

    def test_9d_un_comodin_revocado_no_cubre_al_vencido_de_crtsh(self):
        revocado = [dict(e, revoked=True) if e['id'] == '9004' else e for e in EMISIONES]
        copia = cert(99, ['*.acme-demo.mx', 'acme-demo.mx'], '2026-10-01T00:00:00', '2027-01-01T00:00:00')
        for subdominios in (SUBDOMINIOS, SUBDOMINIOS + [copia]):  # el comodín solo en Cert Spotter y en las dos
            res, _ = recolectar(RespaldoSimulado(paginas=[revocado], crtsh={'%.acme-demo.mx': subdominios}))
            activos = {a.valor: a.atributos for a in res.activos}
            self.assertNotIn('cubierto_por_comodin', activos['dev.acme-demo.mx'], len(subdominios))
            self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})
            dominio = activos['acme-demo.mx']
            self.assertEqual((dominio['origen'], dominio['crtsh_id'], dominio['certificados']), ('crtsh', 2, 3))
        gemelo = dict(EMISIONES[3], id='9005')  # misma vigencia y nombres, sin revocar: el comodín sigue vigente
        res, _ = recolectar(RespaldoSimulado(paginas=[revocado + [gemelo]], crtsh={'%.acme-demo.mx': SUBDOMINIOS + [copia]}))
        self.assertEqual({a.valor: a.atributos for a in res.activos}['dev.acme-demo.mx']['cubierto_por_comodin'],
                         'acme-demo.mx')

    def test_9e_si_ninguna_emision_se_puede_leer_cuenta_como_que_no_respondio(self):
        ilegibles = [dict(e, not_after='pronto') for e in EMISIONES]
        t = RespaldoSimulado(paginas=[ilegibles], crtsh={'%.acme-demo.mx': SUBDOMINIOS})
        res, _ = recolectar(t)
        self.assertEqual((res.estado, len(res.avisos)), ('succeeded', 1))
        self.assertEqual(res.avisos[0], 'Cert Spotter no respondió a acme-demo.mx después de 1 intento (ValueError: '
                         'respuesta que no se puede leer). ' + certspotter.SIN_COMPLEMENTO)
        self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})
        self.assertEqual(len(t.de('api.certspotter.com')), 1)  # sí respondió: otro intento solo gastaría cupo
        t = RespaldoSimulado(paginas=[ilegibles])
        res, _ = recolectar(t)  # con crt.sh caído no hay de dónde sacar nada
        self.assertEqual(res.estado, 'failed')
        self.assertIn('respuesta que no se puede leer', res.error)
        self.assertEqual(len(t.de('api.certspotter.com')), 1)
        t = RespaldoSimulado(paginas=[EMISIONES, [dict(EMISIONES[0], id='9100', not_after='pronto')]],
                             crtsh={'%.acme-demo.mx': SUBDOMINIOS})
        res, _ = recolectar(t)  # la segunda página no se lee: queda la primera, con aviso
        self.assertEqual((res.estado, res.avisos), ('succeeded', [certspotter.INCOMPLETO]))
        self.assertEqual(len(t.de('api.certspotter.com')), 2)

    def test_9f_una_pagina_que_no_se_puede_leer_no_borra_la_grabacion_anterior(self):
        ilegibles = [dict(e, not_after='pronto') for e in EMISIONES]
        with tempfile.TemporaryDirectory() as d:
            antes, _ = recolectar(RespaldoSimulado(), d, 'grabar', nueva=True)
            fallida, _ = recolectar(RespaldoSimulado(paginas=[ilegibles]), d, 'grabar', nueva=True)
            despues, _ = recolectar(sin_red, d, 'reproducir')
        self.assertEqual(fallida.estado, 'failed')
        for campo in ('estado', 'activos', 'hallazgos', 'avisos', 'sin_cobertura'):
            self.assertEqual(getattr(despues, campo), getattr(antes, campo), campo)

    def test_9g_un_id_muy_largo_o_cero_no_se_usa(self):
        class CierraDespues(RespaldoSimulado):  # cualquier página siguiente viene vacía
            def __call__(self, url, timeout):
                if 'after' in urllib.parse.parse_qs(urllib.parse.urlparse(url).query):
                    self.urls.append(url)
                    return b'[]'
                return super().__call__(url, timeout)
        for raro in ('9' * 300, 0):  # el largo no cabe en el nombre del archivo, y con 0 se volvería a pedir la página 1
            ultima = dict(emision('9000', ['raro.acme-demo.mx'], '2026-10-01T00:00:00Z', '2027-01-01T00:00:00Z'), id=raro)
            t = CierraDespues(paginas=[EMISIONES + [ultima]], crtsh={'%.acme-demo.mx': SUBDOMINIOS})
            with tempfile.TemporaryDirectory() as d:
                res, _ = recolectar(t, d, 'grabar', nueva=True)
            self.assertEqual((res.estado, res.avisos), ('succeeded', [certspotter.INCOMPLETO]), raro)
            self.assertEqual(len(t.de('api.certspotter.com')), 2, raro)
            self.assertNotIn('raro.acme-demo.mx', {a.valor for a in res.activos}, raro)

    def test_9h_como_complemento_hace_2_intentos_de_20_s(self):
        class Anota(RespaldoSimulado):
            def __call__(self, url, timeout):
                self.timeouts.append((urllib.parse.urlparse(url).netloc, timeout))
                return super().__call__(url, timeout)
        t, esperas = Anota(crtsh={'%.acme-demo.mx': SUBDOMINIOS}, certspotter_caido=True), []
        t.timeouts = []
        res = crtsh.recolectar('acme-demo.mx', crtsh.ClienteCrtsh(transporte=t, dormir=esperas.append), AHORA)
        self.assertEqual([x for x in t.timeouts if x[0] == 'api.certspotter.com'], [('api.certspotter.com', 20)] * 2)
        self.assertEqual(esperas, [5])
        self.assertTrue(res.avisos[0].startswith('Cert Spotter no respondió a acme-demo.mx después de 2 intentos'))
        t = Anota(certspotter_caido=True)  # como respaldo sigue con los 3 intentos de crt.sh
        t.timeouts = []
        crtsh.recolectar('acme-demo.mx', crtsh.ClienteCrtsh(transporte=t, dormir=lambda s: None), AHORA)
        self.assertEqual(len([x for x in t.timeouts if x[0] == 'api.certspotter.com']), crtsh.INTENTOS)

    def test_10_si_pueden_faltar_certificados_la_corrida_es_parcial_y_cada_uno_lleva_su_parte(self):
        """RC-55: cada hallazgo de vigencia lleva como parte su nombre con el vencimiento de su certificado. Si pueden
        faltar certificados (Cert Spotter sin todas sus páginas o sin responder, o crt.sh solo con la búsqueda por
        nombre), revisados lleva las partes de todos los que llegaron y sin_revisar queda en None: el orquestador no
        cierra un certificado que esta corrida no vio. Con el respaldo no van los ya vencidos, porque cert_expired queda
        sin cobertura. Si llegó todo, revisados queda en None."""
        api, dev = 'api.acme-demo.mx@2026-10-25T12:00:00+00:00', 'dev.acme-demo.mx@2026-08-26T00:00:00+00:00'
        www = 'www.acme-demo.mx@2026-12-19T00:00:00+00:00'
        sin_comodin = EMISIONES[:3]   # sin el comodín 9004, que cubriría al vencido de dev
        completo, _ = recolectar(RespaldoSimulado(paginas=[sin_comodin], crtsh={'%.acme-demo.mx': SUBDOMINIOS}))
        self.assertEqual((completo.revisados, completo.sin_revisar), (None, None))
        self.assertEqual({(h.codigo, tuple(h.partes)) for h in completo.hallazgos},
                         {('cert_expiring_soon', (api,)), ('cert_expired', (dev,))})
        vencido = emision('9005', ['viejo.acme-demo.mx'], '2026-06-01T00:00:00Z', '2026-09-01T00:00:00Z')
        # pruebas-2: con crt.sh caído y Cert Spotter con todas sus páginas el respaldo es completo
        respaldo, _ = recolectar(RespaldoSimulado(paginas=[sin_comodin + [vencido], []]))
        self.assertEqual((respaldo.estado, respaldo.revisados, respaldo.sin_revisar), ('succeeded', None, None))
        self.assertEqual({(h.codigo, tuple(h.partes)) for h in respaldo.hallazgos}, {('cert_expiring_soon', (api,))})
        casos = {
            'respaldo sin todas las páginas': RespaldoSimulado(paginas=[sin_comodin + [vencido], []], limite_en=1),
            'complemento sin todas las páginas': RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS},
                                                                  paginas=[sin_comodin, []], limite_en=1),
            'complemento caído': RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS}, limite_en=0),
            'búsqueda por nombre': CrtshSimulado(fallas=crtsh.INTENTOS, respuestas={'acme-demo.mx': SUBDOMINIOS}),
        }
        for caso, t in casos.items():
            with self.subTest(caso=caso):
                res, _ = recolectar(t)
                self.assertEqual(res.estado, 'succeeded')
                self.assertIsNone(res.sin_revisar)
                self.assertIn(api, res.revisados)
                self.assertEqual(dev in res.revisados, caso != 'respaldo sin todas las páginas')
                # crtsh-2: sin el complemento no se sabe qué está revocado, y www tiene dos vigencias
                self.assertEqual(www in res.revisados, caso != 'complemento caído', res.revisados)
                self.assertNotIn('viejo.acme-demo.mx@2026-09-01T00:00:00+00:00', res.revisados)
                self.assertNotIn('otra.com@2026-11-30T00:00:00+00:00', res.revisados)   # fuera del dominio
                self.assertEqual(res.revisados, sorted(res.revisados))
                self.assertTrue(all(len(h.partes) == 1 for h in res.hallazgos))
                self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])
        # crtsh-2: con un *.acme-demo.mx vigente en crt.sh y el complemento caído, un comodín revocado no cubriría al
        # vencido de dev, así que dev no va en revisados. api no ha vencido y el comodín no cambia su hallazgo, así que sí
        # va, y www no por sus dos vigencias. Con el complemento completo van los tres.
        comodin = cert(9, ['*.acme-demo.mx'], '2026-10-01T00:00:00', '2027-01-01T00:00:00')
        caido, _ = recolectar(RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS + [comodin]}, limite_en=0))
        self.assertFalse({dev, www} & set(caido.revisados), caido.revisados)
        self.assertIn(api, caido.revisados)
        # Un comodín que ya venció no cubre a nadie, así que su revocación no importa: dev sí va
        vencido = cert(10, ['*.acme-demo.mx'], '2026-04-01T00:00:00', '2026-06-30T00:00:00')
        viejo, _ = recolectar(RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS + [vencido]}, limite_en=0))
        self.assertIn(dev, viejo.revisados)
        self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in viejo.hallazgos})
        self.assertEqual(contrato.validar(caido, codigos=set(crtsh.CODIGOS)), [])
        por_nombre, _ = recolectar(CrtshSimulado(fallas=crtsh.INTENTOS, respuestas={'acme-demo.mx': SUBDOMINIOS + [comodin]}))
        self.assertTrue({api, dev, www} <= set(por_nombre.revisados), por_nombre.revisados)
        # Un dominio parecido lleva su dominio como parte. B2 y H9 de RC-226: con cobertura parcial de certificados,
        # revisados trae también los dominios parecidos que la corrida sí revisó (los que dejó %marca%, aunque su
        # certificado sea viejo, las variantes que respondieron y el dominio propio), para que el orquestador cierre
        # el que ya no salió. La variante que no respondió no va.
        class SinUnaVariante(CrtshSimulado):
            def __call__(self, url, timeout):
                if 'q=acme-demo.net' in url:
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)
        viejo = cert(31, ['acme-demo-viejo.com'], '2025-01-01T00:00:00', '2025-04-01T00:00:00')
        res, _ = recolectar(SinUnaVariante(fallas=crtsh.INTENTOS, respuestas={
            'acme-demo.mx': SUBDOMINIOS, '%acme-demo%': [viejo],
            'acme-dem0.mx': [cert(30, ['acme-dem0.mx'], '2026-10-01T00:00:00', '2026-12-30T00:00:00')]}), parecidos=True)
        parecido, = [h for h in res.hallazgos if h.codigo == 'lookalike_domain']
        self.assertEqual(parecido.partes, ['acme-dem0.mx'])
        self.assertTrue({'acme-dem0.mx', 'acme-demo-viejo.com', 'acme-demo.com', 'acme-demo.com.mx', api} <=
                        set(res.revisados), res.revisados)
        self.assertNotIn('acme-demo.net', res.revisados)
        self.assertNotIn('acme-demo.mx', res.revisados)
        self.assertEqual(res.omitidos, [crtsh._huella('lookalike_domain', 'acme-demo.mx', 'acme-demo.net')])
        self.assertEqual(res.revisados, sorted(res.revisados))
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])
        # Sin la respuesta de %marca% no hay cobertura de parecidos y revisados no trae ninguno
        class SinMarca(CrtshSimulado):
            def __call__(self, url, timeout):
                if 'q=%25acme-demo%25' in url:
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)
        sin_marca, _ = recolectar(SinMarca(fallas=crtsh.INTENTOS, respuestas={'acme-demo.mx': SUBDOMINIOS}),
                                  parecidos=True)
        self.assertEqual(sin_marca.sin_cobertura, ['lookalike_domain'])
        self.assertTrue(sin_marca.revisados and all('@' in p for p in sin_marca.revisados), sin_marca.revisados)


class GrabarYReproducir(unittest.TestCase):

    def test_1_reproducir_repite_la_falla_de_crtsh_y_el_respaldo_sin_red(self):
        with tempfile.TemporaryDirectory() as d:
            vivo, _ = recolectar(RespaldoSimulado(), d, 'grabar', nueva=True)
            self.assertEqual(sorted(p.name for p in Path(d).glob('*.json') if not p.name.startswith('dns_')), [
                'certspotter_acme-demo.mx.json', 'certspotter_acme-demo.mx_despues_9004.json', 'falla_acme-demo.mx.json',
                'falla_subdominios_acme-demo.mx.json'])
            self.assertTrue((Path(d) / contrato.MARCA).exists())
            grabado, cliente = recolectar(sin_red, d, 'reproducir')
        self.assertEqual(cliente.consultas, 0)
        for campo in ('estado', 'activos', 'hallazgos', 'avisos', 'sin_cobertura'):
            self.assertEqual(getattr(grabado, campo), getattr(vivo, campo), campo)
        lineas = crtsh.resumen(grabado, cliente)
        self.assertIn('acme-demo.mx · Cert Spotter (crt.sh no respondió) · succeeded · sin red, respuestas grabadas el',
                      lineas[0])
        self.assertFalse([l for l in lineas if l.startswith('Falta')])

    def test_2_si_tampoco_responde_cert_spotter_la_grabacion_anterior_queda_intacta(self):
        with tempfile.TemporaryDirectory() as d:
            recolectar(RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS}), d, 'grabar', nueva=True)
            antes = {f.name: f.read_bytes() for f in Path(d).iterdir()}
            res, _ = recolectar(RespaldoSimulado(certspotter_caido=True), d, 'grabar', nueva=True)
            self.assertEqual(res.estado, 'failed')
            self.assertEqual({f.name: f.read_bytes() for f in Path(d).iterdir()}, antes)

    def test_3_completar_vuelve_a_probar_crtsh_sin_repetir_cert_spotter(self):
        with tempfile.TemporaryDirectory() as d:
            recolectar(RespaldoSimulado(), d, 'grabar', nueva=True)
            desde = contrato.Grabadora.inicio(d)

            caido = RespaldoSimulado()
            res, _ = recolectar(caido, d, 'grabar', completar=True, desde=desde)
            self.assertEqual((caido.de('api.certspotter.com'), len(caido.de('crt.sh'))), ([], 2 * crtsh.INTENTOS))
            self.assertEqual(res.sin_cobertura, ['cert_expired', 'lookalike_domain'])

            sano = RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS})
            res, _ = recolectar(sano, d, 'grabar', parecidos=True, completar=True, desde=desde)
            self.assertEqual((sano.de('api.certspotter.com'), res.sin_cobertura, crtsh.codigo_salida(res)), ([], [], 0))
            self.assertFalse(list(Path(d).glob('falla_*.json')))  # crt.sh ya respondió: la falla no se repite

            grabado, _ = recolectar(sin_red, d, 'reproducir', parecidos=True)
        self.assertEqual((grabado.activos, grabado.hallazgos, grabado.sin_cobertura), (res.activos, res.hallazgos, []))

    def danada(self, res, *archivos):
        """Lo común de una corrida con archivos dañados (RC-46): ni failed ni completa, no cierra nada (revisados en
        [], que el orquestador lee como «ninguna parte revisada») y el primer aviso nombra los archivos y dice la
        excepción: el orquestador sí cierra un por vencer cuya fecha ya pasó (punto J de la ronda 6)."""
        self.assertEqual((res.estado, res.error, res.revisados, res.sin_revisar), ('succeeded', '', [], None))
        cuantos = '1 archivo dañado' if len(archivos) == 1 else '%d archivos dañados' % len(archivos)
        self.assertEqual(res.avisos[0], crtsh.DANADA % (cuantos, ', '.join(archivos)))
        self.assertTrue(res.avisos[0].endswith('no se marca nada como resuelto, salvo un certificado por vencer cuya '
                                               'fecha ya pasó'), res.avisos[0])
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])
        self.assertEqual(crtsh.codigo_salida(res), 2)

    def test_3b_un_archivo_danado_de_la_grabacion_muestra_lo_leido_no_cierra_nada_y_lo_nombra(self):
        """RC-46 (Ernesto, 9 nov): con un archivo de la grabación vacío, cortado o ilegible, ct_logs muestra lo que sí
        pudo leer, no cierra nada en ese escaneo y avisa qué archivo está dañado. Ni failed ni completo, y sin decir
        que crt.sh no respondió o que Cert Spotter no dio sus páginas."""
        paginas = [EMISIONES, []]
        with tempfile.TemporaryDirectory() as d:
            completa, _ = recolectar(RespaldoSimulado(paginas, crtsh={'%.acme-demo.mx': SUBDOMINIOS}), d, 'grabar',
                                     nueva=True)
            self.assertEqual((completa.estado, completa.revisados), ('succeeded', None))
            respaldo = 'Cert Spotter (la grabación de crt.sh está dañada)'
            esperado = {'certspotter_acme-demo.mx.json': ('crt.sh', certspotter.SIN_COMPLEMENTO),
                        'certspotter_acme-demo.mx_despues_9004.json': ('crt.sh y Cert Spotter', None),
                        'subdominios_acme-demo.mx.json': (respaldo, certspotter.AVISO_DANADA)}
            for nombre, (origen, aviso) in esperado.items():
                for como in DANOS:
                    bueno = danar(Path(d) / nombre, como)
                    res, cliente = recolectar(sin_red, d, 'reproducir')
                    (Path(d) / nombre).write_bytes(bueno)
                    with self.subTest(nombre=nombre, como=como):
                        self.danada(res, nombre)
                        self.assertEqual((cliente.consultas, cliente.danados), (0, [nombre]))
                        self.assertTrue(res.activos)
                        self.assertFalse([a for a in res.avisos if 'no respondió' in a or a == certspotter.INCOMPLETO],
                                         res.avisos)
                        if aviso:
                            self.assertTrue([a for a in res.avisos if a.endswith(aviso)], res.avisos)
                        self.assertEqual(res.sin_cobertura, certspotter.SIN_COBERTURA if origen == respaldo
                                         else ['lookalike_domain'])
                        self.assertIn('acme-demo.mx · %s · succeeded · sin red' % origen,
                                      crtsh.resumen(res, cliente)[0])
            res, cliente = recolectar(sin_red, d, 'reproducir')
            self.assertEqual((res.activos, res.hallazgos, res.revisados, res.avisos, cliente.danados),
                             (completa.activos, completa.hallazgos, None, completa.avisos, []))

    def test_3d_con_crtsh_danado_no_se_cierra_el_por_vencer_que_solo_traia_crtsh(self):
        """Hallazgo 1 de la ronda 5 (RC-46): el por vencer de pagos solo lo trae crt.sh. Con su archivo dañado ya no
        sale, y como cert_expiring_soon no va en sin_cobertura, con revisados en None el orquestador lo cerraría."""
        pagos = cert(40, ['pagos.acme-demo.mx'], '2026-07-27T00:00:00', '2026-10-24T12:00:00')
        with tempfile.TemporaryDirectory() as d:
            recolectar(RespaldoSimulado([EMISIONES, []], crtsh={'%.acme-demo.mx': SUBDOMINIOS + [pagos]}), d, 'grabar',
                       nueva=True)
            bueno, _ = recolectar(sin_red, d, 'reproducir')
            danar(Path(d) / 'subdominios_acme-demo.mx.json', 'vacio')
            res, _ = recolectar(sin_red, d, 'reproducir')
        de_pagos = ('cert_expiring_soon', 'pagos.acme-demo.mx')
        self.assertIn(de_pagos, {(h.codigo, h.activo) for h in bueno.hallazgos})
        self.assertIsNone(bueno.revisados)
        self.assertNotIn(de_pagos, {(h.codigo, h.activo) for h in res.hallazgos})
        self.assertNotIn('cert_expiring_soon', res.sin_cobertura)
        self.danada(res, 'subdominios_acme-demo.mx.json')
        self.assertIn('www.acme-demo.mx', {a.valor for a in res.activos})   # lo de Cert Spotter sí se muestra

    def test_3e_con_una_pagina_de_cert_spotter_danada_no_se_cierra_el_vencido_del_comodin_revocado(self):
        """Hallazgo 2 de la ronda 5 (RC-46): dev tiene un certificado vencido y el comodín que lo cubriría está
        revocado, lo que solo dice la página 2 de Cert Spotter. Con esa página dañada el vencido de dev ya no sale, y
        con el nombre de dev en revisados el orquestador lo cerraría."""
        sub = [cert(4, ['dev.acme-demo.mx'], '2026-05-27T00:00:00', '2026-08-26T00:00:00'),
               cert(50, ['*.acme-demo.mx', 'acme-demo.mx'], '2026-10-01T00:00:00', '2027-01-01T00:00:00')]
        p1 = [emision('9001', ['www.acme-demo.mx', 'acme-demo.mx'], '2026-09-20T00:00:00Z', '2026-12-19T00:00:00Z')]
        revocado = dict(emision('9004', ['*.acme-demo.mx', 'acme-demo.mx'], '2026-10-01T00:00:00Z',
                                '2027-01-01T00:00:00Z', SSLCOM), revoked=True)
        pagina = 'certspotter_acme-demo.mx_despues_9001.json'
        with tempfile.TemporaryDirectory() as d:
            recolectar(RespaldoSimulado([p1, [revocado], []], crtsh={'%.acme-demo.mx': sub}), d, 'grabar', nueva=True)
            bueno, _ = recolectar(sin_red, d, 'reproducir')
            danar(Path(d) / pagina, 'cortado')
            res, _ = recolectar(sin_red, d, 'reproducir')
        de_dev = ('cert_expired', 'dev.acme-demo.mx')
        self.assertIn(de_dev, {(h.codigo, h.activo) for h in bueno.hallazgos})
        self.assertNotIn(de_dev, {(h.codigo, h.activo) for h in res.hallazgos})
        self.danada(res, pagina)
        self.assertEqual(res.avisos, res.avisos[:1])   # ni «Cert Spotter no dio todas las páginas»
        self.assertIn('dev.acme-demo.mx', {a.valor for a in res.activos})

    def test_3f_con_el_comodin_danado_y_la_busqueda_por_nombre_el_aviso_no_dice_que_crtsh_no_respondio(self):
        """Hallazgo 5 de la ronda 5 (RC-46): el archivo de %.dominio está dañado y la búsqueda por nombre sí está
        grabada. Se usa esa, sin decir que crt.sh no respondió, y tampoco se cierra nada."""
        with tempfile.TemporaryDirectory() as d:
            recolectar(RespaldoSimulado([EMISIONES, []], crtsh={'%.acme-demo.mx': SUBDOMINIOS}), d, 'grabar',
                       nueva=True)
            contrato.Grabadora(d, 'grabar', nombre=crtsh._nombre_grabado).guardar('acme-demo.mx', SUBDOMINIOS[:3])
            danar(Path(d) / 'subdominios_acme-demo.mx.json', 'ilegible')
            res, cliente = recolectar(sin_red, d, 'reproducir')
        self.danada(res, 'subdominios_acme-demo.mx.json')
        self.assertEqual(res.avisos[1:], [crtsh.POR_NOMBRE_DANADA % 'acme-demo.mx'])
        self.assertFalse([a for a in res.avisos if 'no respondió' in a], res.avisos)
        self.assertTrue(res.activos)
        self.assertIn('acme-demo.mx · crt.sh y Cert Spotter · succeeded', crtsh.resumen(res, cliente)[0])

    def test_3h_la_busqueda_de_la_marca_danada_no_es_que_crtsh_no_respondiera(self):
        """G2 de la ronda 3 de RC-226: al reproducir, si el archivo de %marca% está dañado no hubo red. Las variantes
        se leen igual (no sale el aviso SIN_VARIANTES), los parecidos quedan sin cobertura y no se cierra nada."""
        marca = 'contiene_acme-demo.json'
        with tempfile.TemporaryDirectory() as d:
            completa, _ = recolectar(CrtshSimulado(), d, 'grabar', nueva=True, parecidos=True)
            self.assertIn('lookalike_domain', {h.codigo for h in completa.hallazgos})
            for como in DANOS:
                bueno = danar(Path(d) / marca, como)
                res, cliente = recolectar(sin_red, d, 'reproducir', parecidos=True)
                (Path(d) / marca).write_bytes(bueno)
                with self.subTest(como=como):
                    self.danada(res, marca)
                    self.assertEqual((res.sin_cobertura, res.omitidos, res.consultas), (['lookalike_domain'], [], 0))
                    self.assertNotIn('lookalike_domain', {h.codigo for h in res.hallazgos})
                    self.assertEqual(res.avisos[1:], [])  # ni «Sin la respuesta de %acme-demo%» ni «no respondió»
                    leidas = {Path(a).name for a, _ in cliente.leidas}
                    self.assertTrue({'acme-dem0.mx.json', 'acme-demo.net.json'} <= leidas, leidas)  # las variantes sí
                    self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])

    def test_3g_un_dns_o_una_falla_danados_tampoco_dejan_failed(self):
        """Resto de la regresión 2 de la ronda 4 (RC-46): dns_*.json y falla_*.json no pasan por pedir. Con uno dañado
        el DNS queda sin saberse (el vencido de ese nombre no se reporta, punto C de la ronda 6) o crt.sh queda como no
        leído, y no se cierra nada. Una página dañada del respaldo tampoco se lee como que Cert Spotter no la dio."""
        sin_comodin = EMISIONES[:3]   # sin el comodín 9004, que cubriría al vencido de dev
        dns = 'dns_dev.acme-demo.mx.json'
        with tempfile.TemporaryDirectory() as d:
            completa, _ = recolectar(RespaldoSimulado([sin_comodin, []], crtsh={'%.acme-demo.mx': SUBDOMINIOS}), d,
                                     'grabar', nueva=True)
            self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in completa.hallazgos})
            sin_dev = [h for h in completa.hallazgos if (h.codigo, h.activo) != ('cert_expired', 'dev.acme-demo.mx')]
            for como in DANOS:
                bueno = danar(Path(d) / dns, como)
                res, cliente = recolectar(sin_red, d, 'reproducir')
                (Path(d) / dns).write_bytes(bueno)
                with self.subTest(archivo=dns, como=como):
                    self.danada(res, dns)
                    self.assertEqual((res.activos, res.hallazgos, cliente.danados), (completa.activos, sin_dev, [dns]))
                    self.assertEqual(res.avisos[1:], [])   # ni «No se pudo comprobar en DNS»: lo dice el primer aviso
        otra = emision('9005', ['otro.acme-demo.mx'], '2026-09-20T00:00:00Z', '2026-12-19T00:00:00Z')
        fallas = ['falla_subdominios_acme-demo.mx.json', 'falla_acme-demo.mx.json']
        pagina = 'certspotter_acme-demo.mx_despues_9004.json'
        with tempfile.TemporaryDirectory() as d:
            vivo, _ = recolectar(RespaldoSimulado([EMISIONES, [otra], []]), d, 'grabar', nueva=True)   # crt.sh caído
            self.assertEqual(vivo.revisados, None)
            for archivos in (fallas[:1], fallas[1:], fallas, [pagina]):
                buenos = [danar(Path(d) / a, 'vacio') for a in archivos]
                res, _ = recolectar(sin_red, d, 'reproducir')
                for a, bueno in zip(archivos, buenos):
                    (Path(d) / a).write_bytes(bueno)
                with self.subTest(archivos=archivos):
                    self.danada(res, *archivos)
                    self.assertEqual(res.sin_cobertura, certspotter.SIN_COBERTURA)
                    self.assertNotIn(certspotter.INCOMPLETO, res.avisos)
                    if archivos == [pagina]:   # crt.sh sí quedó grabado como caído, y falta lo de la página dañada
                        self.assertEqual(res.avisos[1:], vivo.avisos)
                        self.assertEqual({a.valor for a in vivo.activos} - {a.valor for a in res.activos},
                                         {'otro.acme-demo.mx'})
                    else:
                        self.assertEqual(res.avisos[-1], certspotter.AVISO_DANADA)
                        self.assertNotIn(certspotter.AVISO, res.avisos)
                        self.assertEqual(len([a for a in res.avisos if 'crt.sh no respondió a' in a]),
                                         2 - len(archivos))   # la falla que sí se pudo leer se sigue diciendo
                        self.assertEqual(len(res.avisos), 4 - len(archivos))   # y la dañada solo en el primer aviso
                        self.assertEqual((res.activos, res.hallazgos), (vivo.activos, vivo.hallazgos))

    def test_3i_con_el_dns_danado_de_un_nombre_que_no_resolvia_no_se_abre_su_vencido(self):
        """Punto C de la ronda 6 (RC-46): el DNS grabado de dev era False (ya no resuelve) y por eso su certificado
        vencido no era hallazgo. Con ese dns_ dañado no se sabe si resolvía: el vencido de dev no se reporta (antes
        salía un cert_expired alto y falso) y dev queda como activo sin el atributo resuelve. Con revisados en [] el
        que ya estuviera abierto tampoco se cierra. Lo demás sale igual que con la grabación sana."""
        dns, de_dev = 'dns_dev.acme-demo.mx.json', ('cert_expired', 'dev.acme-demo.mx')
        with tempfile.TemporaryDirectory() as d:
            simulado = RespaldoSimulado([EMISIONES[:3], []], crtsh={'%.acme-demo.mx': SUBDOMINIOS},   # sin el comodín
                                        sin_dns={'dev.acme-demo.mx'})
            recolectar(simulado, d, 'grabar', nueva=True)
            sano, _ = recolectar(sin_red, d, 'reproducir')
            de_sano = {a.valor: a.atributos for a in sano.activos}
            self.assertIs(de_sano['dev.acme-demo.mx']['resuelve'], False)   # el DNS grabado es False
            self.assertNotIn(de_dev, {(h.codigo, h.activo) for h in sano.hallazgos})
            self.assertTrue(sano.hallazgos)
            for como in DANOS:
                bueno = danar(Path(d) / dns, como)
                res, cliente = recolectar(sin_red, d, 'reproducir')
                (Path(d) / dns).write_bytes(bueno)
                with self.subTest(como=como):
                    self.danada(res, dns)
                    self.assertNotIn(de_dev, {(h.codigo, h.activo) for h in res.hallazgos})
                    self.assertEqual((res.hallazgos, res.avisos[1:], cliente.danados), (sano.hallazgos, [], [dns]))
                    de_res = {a.valor: a.atributos for a in res.activos}
                    self.assertNotIn('resuelve', de_res['dev.acme-demo.mx'])   # no se afirma que no resuelve
                    self.assertEqual(de_res, de_sano | {'dev.acme-demo.mx': {
                        k: v for k, v in de_sano['dev.acme-demo.mx'].items() if k != 'resuelve'}})

    def test_3h_si_no_se_pudo_leer_nada_por_un_archivo_danado_sale_sin_activos_y_no_failed(self):
        """RC-46: si lo único que había para leer está dañado, el resultado no trae activos pero tampoco queda failed:
        los tres códigos van en sin_cobertura, no se cierra nada y el aviso nombra el archivo. Sin ningún archivo dañado
        sigue en failed (test_4)."""
        with tempfile.TemporaryDirectory() as d:
            recolectar(RespaldoSimulado(), d, 'grabar', nueva=True)   # crt.sh caído: todo sale de Cert Spotter
            danar(Path(d) / 'certspotter_acme-demo.mx.json', 'vacio')
            res, cliente = recolectar(sin_red, d, 'reproducir')
        self.danada(res, 'certspotter_acme-demo.mx.json')
        self.assertEqual((res.activos, res.hallazgos, res.sin_cobertura), ([], [], list(crtsh.CODIGOS)))
        self.assertEqual(res.avisos[-1], crtsh.SIN_LEER)
        self.assertEqual(len([a for a in res.avisos if 'crt.sh no respondió a' in a]), 2)   # eso sí quedó grabado
        self.assertTrue(crtsh.resumen(res, cliente)[0].startswith('acme-demo.mx · grabación dañada · succeeded'))
        with tempfile.TemporaryDirectory() as d:   # crt.sh dañado y Cert Spotter sin grabar
            contrato.Grabadora(d, 'grabar', nombre=crtsh._nombre_grabado).guardar('%.acme-demo.mx', SUBDOMINIOS)
            danar(Path(d) / 'subdominios_acme-demo.mx.json', 'cortado')
            res, _ = recolectar(sin_red, d, 'reproducir')
        self.danada(res, 'subdominios_acme-demo.mx.json')
        self.assertEqual((res.activos, res.hallazgos, res.sin_cobertura), ([], [], list(crtsh.CODIGOS)))
        self.assertIn(contrato.SIN_GRABACION + 'certspotter:acme-demo.mx', res.avisos)
        self.assertEqual(res.avisos[-1], crtsh.SIN_LEER)

    def test_3c_completar_vuelve_a_consultar_un_archivo_vacio(self):
        """Regresión 3 de la ronda 4 (RC-46): un --grabar que se cortó deja un archivo de 0 bytes y --grabar --completar
        lo consulta otra vez en lugar de caerse."""
        with tempfile.TemporaryDirectory() as d:
            sano = {'%.acme-demo.mx': SUBDOMINIOS}
            completa, _ = recolectar(RespaldoSimulado(crtsh=sano), d, 'grabar', nueva=True)
            desde = contrato.Grabadora.inicio(d)
            for nombre, host in (('subdominios_acme-demo.mx.json', 'crt.sh'),
                                 ('certspotter_acme-demo.mx.json', 'api.certspotter.com')):
                (Path(d) / nombre).write_bytes(b'')
                t = RespaldoSimulado(crtsh=sano)
                res, _ = recolectar(t, d, 'grabar', completar=True, desde=desde)
                with self.subTest(nombre=nombre):
                    self.assertEqual(len(t.de(host)), 1)
                    self.assertEqual((res.estado, res.activos, res.hallazgos, res.revisados),
                                     ('succeeded', completa.activos, completa.hallazgos, None))
                    self.assertTrue((Path(d) / nombre).read_bytes())
            grabado, _ = recolectar(sin_red, d, 'reproducir')
        self.assertEqual((grabado.activos, grabado.hallazgos), (completa.activos, completa.hallazgos))

    def test_4_reproducir_sin_grabacion_de_cert_spotter_queda_failed(self):
        with tempfile.TemporaryDirectory() as d:
            res, _ = recolectar(sin_red, d, 'reproducir')
        self.assertEqual(res.estado, 'failed')
        self.assertIn(contrato.SIN_GRABACION + 'certspotter:acme-demo.mx', res.error)

    def test_5_linea_de_comandos(self):
        def correr(*argv):
            salida = io.StringIO()
            with contextlib.redirect_stdout(salida):
                codigo = crtsh._main(list(argv))
            return codigo, salida.getvalue()

        # El CLI usa la fecha de hoy, no AHORA: el de api.acme-demo.mx vence en 10 días contados desde hoy.
        hoy = datetime.now(timezone.utc)

        def dia(delta):
            return (hoy + timedelta(days=delta)).strftime('%Y-%m-%dT%H:%M:%SZ')
        emisiones = [emision('9002', ['api.acme-demo.mx'], dia(-80), dia(10)) if e['id'] == '9002' else e
                     for e in EMISIONES]
        cobertura = ('Cobertura parcial: no se revisaron certificados vencidos (cert_expired) ni dominios parecidos '
                     '(lookalike_domain).')
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)), mock.patch.object(crtsh.time, 'sleep', lambda s: None):
            with mock.patch.object(crtsh, '_descargar', RespaldoSimulado(paginas=[emisiones])):
                codigo, texto = correr('acme-demo.mx', '--grabar')
            self.assertEqual(codigo, 2)
            self.assertIn(cobertura, texto)
            with mock.patch.object(crtsh, '_descargar', sin_red):
                codigo, texto = correr('acme-demo.mx', '--reproducir')
                self.assertEqual(codigo, 2)
                self.assertIn(cobertura, texto)
                self.assertIn('  [media] El certificado de api.acme-demo.mx vence en', texto)  # con la fecha de hoy
                codigo, texto = correr('acme-demo.mx', '--reproducir', '--json')
            self.assertEqual(json.loads(texto)['sin_cobertura'], ['cert_expired', 'lookalike_domain'])

    def test_5b_completar_sobre_el_respaldo_avisa_antes_de_consultar(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)), mock.patch.object(crtsh.time, 'sleep', lambda s: None):
            with mock.patch.object(crtsh, '_descargar', RespaldoSimulado()), contextlib.redirect_stdout(io.StringIO()):
                crtsh._main(['acme-demo.mx', '--grabar'])
            errores = io.StringIO()
            with mock.patch.object(crtsh, '_descargar', RespaldoSimulado()), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(errores):
                self.assertEqual(crtsh._main(['acme-demo.mx', '--grabar', '--completar']), 2)
        self.assertIn('aviso: esta grabación es el respaldo de Cert Spotter. Si crt.sh responde', errores.getvalue())

    def test_5c_si_cert_spotter_no_queda_grabado_pide_completar(self):
        for limite_en in (0, 1):  # 429 en la primera página o en la vacía que cierra
            errores = io.StringIO()
            with tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)), mock.patch.object(crtsh.time, 'sleep', lambda s: None), \
                    mock.patch.object(crtsh, '_descargar', RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS},
                                                                            limite_en=limite_en)), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errores):
                self.assertEqual(crtsh._main(['acme-demo.mx', '--grabar']), 2)
            self.assertIn('aviso: Cert Spotter no quedó grabado completo', errores.getvalue(), limite_en)
            self.assertIn('--grabar --completar', errores.getvalue(), limite_en)
        errores = io.StringIO()
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)), mock.patch.object(crtsh.time, 'sleep', lambda s: None), \
                mock.patch.object(crtsh, '_descargar', RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS})), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errores):
            self.assertEqual(crtsh._main(['acme-demo.mx', '--grabar']), 0)
        self.assertEqual(errores.getvalue(), '')

    def test_7_si_falla_una_pagina_al_grabar_reproducir_da_lo_mismo(self):
        with tempfile.TemporaryDirectory() as d:
            vivo, _ = recolectar(RespaldoSimulado(limite_en=1), d, 'grabar', nueva=True)
            grabado, cliente = recolectar(sin_red, d, 'reproducir')
        self.assertEqual((vivo.estado, vivo.avisos[-1]), ('succeeded', certspotter.INCOMPLETO))
        for campo in ('estado', 'activos', 'hallazgos', 'avisos', 'sin_cobertura'):
            self.assertEqual(getattr(grabado, campo), getattr(vivo, campo), campo)

    def test_8_si_solo_falla_el_comodin_reproducir_repite_el_aviso(self):
        class SinComodin(RespaldoSimulado):
            def __call__(self, url, timeout):
                if 'q=%25.acme-demo.mx' in url:
                    self.urls.append(url)
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)
        with tempfile.TemporaryDirectory() as d:
            vivo, _ = recolectar(SinComodin(crtsh={'acme-demo.mx': SUBDOMINIOS}), d, 'grabar', parecidos=True,
                                 nueva=True)
            self.assertTrue((Path(d) / 'falla_subdominios_acme-demo.mx.json').exists())
            grabado, _ = recolectar(sin_red, d, 'reproducir', parecidos=True)
        self.assertIn('crt.sh no respondió a %.acme-demo.mx. Se usó la búsqueda por nombre', vivo.avisos[0])
        self.assertEqual((grabado.avisos, grabado.activos, grabado.sin_cobertura), (vivo.avisos, vivo.activos, []))

    def test_9_si_cert_spotter_no_respondio_al_grabar_reproducir_pide_completarlo(self):
        with tempfile.TemporaryDirectory() as d:
            recolectar(RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS}, limite_en=0), d, 'grabar', nueva=True)
            grabado, cliente = recolectar(sin_red, d, 'reproducir')
            self.assertEqual(grabado.avisos, [contrato.SIN_GRABACION + 'certspotter:acme-demo.mx'])
            # pruebas-1 (RC-55): sin la página de Cert Spotter pueden faltar certificados, así que la corrida es parcial
            self.assertIsNone(grabado.sin_revisar)
            self.assertIsInstance(grabado.revisados, list)
            self.assertIn('api.acme-demo.mx@2026-10-25T12:00:00+00:00', grabado.revisados)
            # crtsh-2: sin la grabación del complemento no se sabe qué está revocado, y www tiene dos vigencias
            self.assertNotIn('www.acme-demo.mx@2026-12-19T00:00:00+00:00', grabado.revisados)
            self.assertIn('Falta 1 respuesta grabada: certspotter:acme-demo.mx. Se completa con --grabar --completar.',
                          crtsh.resumen(grabado, cliente))
            t = RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS})
            completo, _ = recolectar(t, d, 'grabar', completar=True, desde=contrato.Grabadora.inicio(d))
        self.assertEqual((t.de('crt.sh'), len(t.de('api.certspotter.com')), completo.avisos), ([], 2, []))
        self.assertEqual((completo.revisados, completo.sin_revisar), (None, None))

    def test_6_por_ejecutar_del_contrato(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)):
            recolectar(RespaldoSimulado(), crtsh.carpeta_de('acme-demo.mx'), 'grabar', nueva=True)
            res = contrato.ejecutar(cargar('ct_logs'), 'acme-demo.mx', modo='reproducir', ahora=AHORA,
                                    codigos=set(crtsh.CODIGOS))
        self.assertEqual((res.estado, res.fuente, len(res.activos)), ('succeeded', 'ct_logs', 4))
        self.assertEqual(res.sin_cobertura, ['cert_expired', 'lookalike_domain'])


class RespuestaReal(unittest.TestCase):
    """La página real de Cert Spotter para olmardo.com: dos comodines del dominio (Let's Encrypt y el de Cloudflare
    con SSL.com), reservas y camaras."""

    def recolectar(self, ahora):
        t = RespaldoSimulado(paginas=[OLMARDO])
        res = crtsh.recolectar('olmardo.com', crtsh.ClienteCrtsh(transporte=t, dormir=lambda s: None), ahora)
        return res, t

    def test_1_tres_activos_y_el_comodin_del_dominio(self):
        res, t = self.recolectar(datetime(2026, 10, 18, 15, 42, tzinfo=timezone.utc))
        activos = {a.valor: a for a in res.activos}
        self.assertEqual(sorted(activos), ['camaras.olmardo.com', 'olmardo.com', 'reservas.olmardo.com'])
        dominio = activos['olmardo.com'].atributos
        self.assertEqual((activos['olmardo.com'].tipo, dominio['comodin'], dominio['certificados']), ('domain', True, 2))
        self.assertEqual((dominio['certspotter_id'], dominio['emisor']),
                         ('17778865245', 'C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 4'))
        self.assertEqual(activos['reservas.olmardo.com'].atributos['certspotter_id'], '17772119077')
        self.assertEqual(activos['camaras.olmardo.com'].atributos['certspotter_id'], '17772281649')
        self.assertFalse(activos['camaras.olmardo.com'].atributos['comodin'])
        self.assertEqual((res.hallazgos, res.sin_cobertura), ([], ['cert_expired', 'lookalike_domain']))
        self.assertEqual(len(t.de('api.certspotter.com')), 2)
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])

    def test_2_por_vencer_cuando_les_queda_menos_de_un_tercio(self):
        res, _ = self.recolectar(datetime(2026, 12, 20, 12, 0, tzinfo=timezone.utc))
        por_vencer = {h.activo: h for h in res.hallazgos if h.codigo == 'cert_expiring_soon'}
        self.assertEqual(sorted(por_vencer), ['camaras.olmardo.com', 'olmardo.com', 'reservas.olmardo.com'])
        h = por_vencer['olmardo.com']
        self.assertEqual((h.evidencia['certspotter_id'], h.evidencia['comodin'], h.evidencia['dias_para_vencer']),
                         ('17778865245', True, 22))
        res, _ = self.recolectar(datetime(2026, 12, 10, 12, 0, tzinfo=timezone.utc))  # les quedan 32 días: aún no
        self.assertEqual(res.hallazgos, [])

    def test_3_el_mismo_certificado_da_la_misma_huella_por_crtsh_y_por_cert_spotter(self):
        # El comodín de Cloudflare tal como lo grabó crt.sh el 18 oct (id 29835188462)
        ssl_com = cert(29835188462, ['*.olmardo.com', 'olmardo.com'], '2026-10-14T10:24:56', '2027-01-12T01:00:49',
                       emisor=OLMARDO[3]['issuer']['name'], serie='68e82773942c257582ffeaeec4de30cf')
        ahora = datetime(2026, 12, 20, 12, 0, tzinfo=timezone.utc)
        t = RespaldoSimulado(crtsh={'%.olmardo.com': [ssl_com]})
        por_crtsh = crtsh.recolectar('olmardo.com', crtsh.ClienteCrtsh(transporte=t, dormir=lambda s: None), ahora,
                                     parecidos=False)
        por_cert_spotter, _ = self.recolectar(ahora)

        def huella(res):
            return {h.activo: h for h in res.hallazgos}['olmardo.com']
        self.assertEqual((huella(por_crtsh).evidencia['origen'], huella(por_cert_spotter).evidencia['origen']),
                         ('crtsh', 'certspotter'))
        self.assertEqual(huella(por_crtsh).huella, huella(por_cert_spotter).huella)

    def test_5_si_crtsh_no_trae_los_de_lets_encrypt_cert_spotter_los_suma(self):
        """Lo que pasó el 23 oct: crt.sh respondió solo con el comodín de SSL.com, sin los 3 de Let's Encrypt."""
        ssl_com = cert(29835188462, ['*.olmardo.com', 'olmardo.com'], '2026-10-14T10:24:56', '2027-01-12T01:00:49',
                       emisor=OLMARDO[3]['issuer']['name'], serie='68e82773942c257582ffeaeec4de30cf')
        t = RespaldoSimulado(paginas=[OLMARDO], crtsh={'%.olmardo.com': [ssl_com]})
        res = crtsh.recolectar('olmardo.com', crtsh.ClienteCrtsh(transporte=t, dormir=lambda s: None),
                               datetime(2026, 12, 20, 12, 0, tzinfo=timezone.utc))
        activos = {a.valor: a.atributos for a in res.activos}
        self.assertEqual(sorted(activos), ['camaras.olmardo.com', 'olmardo.com', 'reservas.olmardo.com'])
        self.assertEqual((activos['olmardo.com']['certificados'], activos['olmardo.com']['origen']), (2, 'crtsh'))
        por_vencer = {h.activo: h.evidencia['origen'] for h in res.hallazgos if h.codigo == 'cert_expiring_soon'}
        self.assertEqual(por_vencer, {'olmardo.com': 'crtsh', 'reservas.olmardo.com': 'certspotter',
                                      'camaras.olmardo.com': 'certspotter'})
        self.assertEqual((res.sin_cobertura, res.avisos), (['lookalike_domain'], []))

    def test_4_al_reproducir_meses_despues_no_salen_vencidos_sin_cobertura(self):
        res, _ = self.recolectar(datetime(2027, 2, 1, tzinfo=timezone.utc))
        self.assertEqual((res.hallazgos, res.sin_cobertura), ([], ['cert_expired', 'lookalike_domain']))
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])


class Emision(unittest.TestCase):

    def test_1_forma_de_certificado_de_crtsh(self):
        c = certspotter.certificado(EMISIONES[2])
        self.assertEqual(crtsh._nombres(c), [('tienda.acme-demo.mx', True)])
        self.assertEqual((c['id'], c['origen'], c['issuer_name']), ('9003', 'certspotter', LE['name']))
        self.assertEqual((c['not_before'], c['not_after']), ('2026-09-01T00:00:00Z', '2026-11-30T00:00:00Z'))

    def test_2_emisor_sin_expandir_o_sin_nombre(self):
        self.assertEqual(certspotter.certificado(dict(EMISIONES[0], issuer={'friendly_name': 'SSL.com'}))['issuer_name'],
                         'SSL.com')
        sin = {k: v for k, v in EMISIONES[0].items() if k not in ('issuer', 'dns_names')}
        c = certspotter.certificado(sin)
        self.assertEqual((c['issuer_name'], c['name_value']), ('', ''))

    def test_3_consultas_y_urls(self):
        self.assertEqual(crtsh._nombre_grabado(certspotter.consulta('acme-demo.mx', '9004')),
                         'certspotter_acme-demo.mx_despues_9004.json')
        self.assertEqual(crtsh._nombre_grabado(crtsh.FALLA + '%.acme-demo.mx'), 'falla_subdominios_acme-demo.mx.json')
        self.assertEqual(certspotter.url('acme-demo.mx', '9004'),
                         'https://api.certspotter.com/v1/issuances?domain=acme-demo.mx&include_subdomains=true'
                         '&expand=dns_names&expand=issuer&after=9004')


if __name__ == '__main__':
    unittest.main(verbosity=2)
