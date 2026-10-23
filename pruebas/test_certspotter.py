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
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_certspotter.py
from pruebas.test_crtsh import AHORA, SUBDOMINIOS, cert  # noqa: E402
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

    def test_9_si_crtsh_responde_no_consulta_cert_spotter(self):
        t = RespaldoSimulado(crtsh={'%.acme-demo.mx': SUBDOMINIOS})
        res, _ = recolectar(t, parecidos=True)
        self.assertEqual((t.de('api.certspotter.com'), res.sin_cobertura), ([], []))
        h = {(h.codigo, h.activo): h for h in res.hallazgos}[('cert_expired', 'dev.acme-demo.mx')]
        self.assertEqual((h.evidencia['origen'], h.evidencia['crtsh_id']), ('crtsh', 4))
        self.assertNotIn('certspotter_id', h.evidencia)
        self.assertTrue(crtsh.resumen(res)[0].startswith('acme-demo.mx · crt.sh · succeeded'))


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

        cobertura = ('Cobertura parcial: no se revisaron certificados vencidos (cert_expired) ni dominios parecidos '
                     '(lookalike_domain).')
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)), mock.patch.object(crtsh.time, 'sleep', lambda s: None):
            with mock.patch.object(crtsh, '_descargar', RespaldoSimulado()):
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
