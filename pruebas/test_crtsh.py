"""Pruebas del recolector de crt.sh (#14), sin red: un crt.sh simulado y una fecha fija.

    python -m unittest -v pruebas/test_crtsh.py
"""
import json
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from recolectores import crtsh

AHORA = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def cert(id_, nombres, inicio, fin, emisor="C=US, O=Let's Encrypt, CN=R11", serie=None):
    return {'id': id_, 'issuer_ca_id': 1, 'issuer_name': emisor, 'common_name': nombres[0],
            'name_value': '\n'.join(nombres), 'not_before': inicio, 'not_after': fin,
            'serial_number': serie or ('%040x' % id_), 'result_count': 1}


SUBDOMINIOS = [
    # www renovado: el viejo venció, el nuevo sigue vigente -> sin hallazgo
    cert(1, ['www.acme-demo.mx', 'acme-demo.mx'], '2026-04-01T00:00:00', '2026-06-30T00:00:00'),
    cert(2, ['www.acme-demo.mx', 'acme-demo.mx'], '2026-09-20T00:00:00', '2026-12-19T00:00:00'),
    # vence en 10 días -> cert_expiring_soon
    cert(3, ['api.acme-demo.mx'], '2026-07-27T00:00:00', '2026-10-25T12:00:00'),
    # venció hace 50 días y no se renovó -> cert_expired
    cert(4, ['dev.acme-demo.mx'], '2026-05-27T00:00:00', '2026-08-26T00:00:00'),
    # venció hace más de un año -> solo activo
    cert(5, ['old.acme-demo.mx'], '2024-01-01T00:00:00', '2024-04-01T00:00:00'),
    # comodín, ruido y nombres fuera del alcance
    cert(6, ['*.tienda.acme-demo.mx', 'tienda.acme-demo.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
    {'id': 8, 'name_value': 'sinfechas.acme-demo.mx'},  # fila incompleta: se ignora
    cert(7, ['contacto@acme-demo.mx', 'prueba intermedia - acme-demo.mx', 'm.testacme-demo.mx', 'otra.com'],
         '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
]
CONTIENE_MARCA = [
    cert(20, ['acme-demo-login.com', 'www.acme-demo-login.com'], '2026-09-30T00:00:00', '2026-12-29T00:00:00'),
    cert(21, ['acme-demo.mx.cuenta-segura.net'], '2026-08-01T00:00:00', '2026-10-30T00:00:00'),
    # certificado compartido de una CDN: solo cuenta el nombre parecido, no los ajenos
    cert(22, ['sni.cdn-ejemplo.com', 'acme-demo-pagos.com', 'tienda-ajena.com'], '2026-09-10T00:00:00', '2026-12-09T00:00:00'),
    # parecido viejo: su último certificado venció hace más de 90 días -> no cuenta
    cert(23, ['acme-demo-viejo.com'], '2025-01-01T00:00:00', '2025-04-01T00:00:00'),
    # dominio propio de la empresa -> no cuenta
    cert(24, ['acme-demo.com.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
    # nombres dentro del propio dominio -> no cuentan
    cert(25, ['shop.acme-demo.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
]
CANDIDATO = [cert(30, ['acme-dem0.mx', 'www.acme-dem0.mx', 'ajeno.org'], '2026-10-01T00:00:00', '2026-12-30T00:00:00')]


class CrtshSimulado:
    """Transporte falso: responde según la consulta y puede fallar las primeras veces."""

    def __init__(self, fallas=0, respuestas=None):
        self.fallas, self.urls = fallas, []
        self.respuestas = respuestas if respuestas is not None else {
            '%.acme-demo.mx': SUBDOMINIOS, '%acme-demo%': CONTIENE_MARCA, 'acme-dem0.mx': CANDIDATO}

    def __call__(self, url, timeout):
        self.urls.append(url)
        if self.fallas:
            self.fallas -= 1
            raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
        q = crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(url).query)['q'][0]
        return json.dumps(self.respuestas.get(q, [])).encode()


def recolectar(transporte, **kw):
    cliente = crtsh.ClienteCrtsh(transporte=transporte, dormir=lambda s: None)
    return crtsh.recolectar('acme-demo.mx', cliente, AHORA, propios=['acme-demo.com.mx'], **kw)


class Subdominios(unittest.TestCase):

    def setUp(self):
        self.res = recolectar(CrtshSimulado(), parecidos=False)
        self.activos = {a.valor: a for a in self.res.activos}
        self.hallazgos = {(h.codigo, h.activo): h for h in self.res.hallazgos}

    def test_1_solo_nombres_del_dominio(self):
        self.assertEqual(self.res.estado, 'succeeded')
        self.assertEqual(sorted(self.activos), ['acme-demo.mx', 'api.acme-demo.mx', 'dev.acme-demo.mx',
                                                'old.acme-demo.mx', 'tienda.acme-demo.mx', 'www.acme-demo.mx'])
        self.assertEqual(self.activos['acme-demo.mx'].tipo, 'domain')
        self.assertEqual(self.activos['www.acme-demo.mx'].tipo, 'subdomain')
        self.assertTrue(self.activos['tienda.acme-demo.mx'].atributos['comodin'])

    def test_2_certificado_renovado_no_es_hallazgo(self):
        self.assertNotIn(('cert_expired', 'www.acme-demo.mx'), self.hallazgos)
        self.assertEqual(self.activos['www.acme-demo.mx'].atributos['certificados'], 2)

    def test_3_vence_en_menos_de_30_dias(self):
        h = self.hallazgos[('cert_expiring_soon', 'api.acme-demo.mx')]
        self.assertEqual(h.severidad, 'medium')
        self.assertEqual(h.evidencia['dias_para_vencer'], 10)
        self.assertEqual(h.evidencia['title'], h.titulo)

    def test_4_vencido_sin_renovar(self):
        h = self.hallazgos[('cert_expired', 'dev.acme-demo.mx')]
        self.assertEqual(h.severidad, 'high')
        self.assertEqual(h.caracteristicas['antiguedad_dias'], 50)
        self.assertEqual(set(h.caracteristicas), {'tipo', 'antiguedad_dias', 'exposicion', 'sensibilidad'})

    def test_5_vencido_hace_mas_de_un_anio_solo_es_activo(self):
        self.assertIn('old.acme-demo.mx', self.activos)
        self.assertNotIn(('cert_expired', 'old.acme-demo.mx'), self.hallazgos)

    def test_6_huella_estable(self):
        otra = recolectar(CrtshSimulado(), parecidos=False)
        self.assertEqual(sorted(h.huella for h in self.res.hallazgos), sorted(h.huella for h in otra.hallazgos))
        self.assertTrue(all(len(h.huella) == 64 for h in self.res.hallazgos))

    def test_7_codigos_con_regla(self):
        self.assertTrue({h.codigo for h in self.res.hallazgos} <= set(crtsh.CODIGOS))


class DominiosParecidos(unittest.TestCase):

    def setUp(self):
        self.res = recolectar(CrtshSimulado())
        self.parecidos = {h.evidencia['dominio_parecido']: h for h in self.res.hallazgos if h.codigo == 'lookalike_domain'}

    def test_1_encuentra_los_parecidos_recientes(self):
        self.assertEqual(sorted(self.parecidos), ['acme-dem0.mx', 'acme-demo-login.com', 'acme-demo-pagos.com',
                                                  'cuenta-segura.net'])
        self.assertEqual(self.parecidos['acme-dem0.mx'].evidencia['tipo_parecido'], 'error_tipografico')
        self.assertEqual(self.parecidos['cuenta-segura.net'].evidencia['nombres'], ['acme-demo.mx.cuenta-segura.net'])

    def test_2_no_cuenta_propios_viejos_ni_ajenos_de_la_cdn(self):
        for fuera in ('acme-demo.com.mx', 'acme-demo-viejo.com', 'cdn-ejemplo.com', 'tienda-ajena.com', 'ajeno.org',
                      'acme-demo.mx'):
            self.assertNotIn(fuera, self.parecidos)

    def test_3_el_hallazgo_es_del_dominio_de_la_empresa(self):
        h = self.parecidos['acme-demo-login.com']
        self.assertEqual((h.activo, h.severidad), ('acme-demo.mx', 'medium'))

    def test_4_variantes(self):
        v = crtsh.candidatos_parecidos('acme-demo.mx')
        self.assertEqual(len(v), crtsh.MAX_CANDIDATOS)
        self.assertNotIn('acme-demo.mx', v)
        self.assertEqual(v[:4], ['acme-demo.com', 'acme-demo.com.mx', 'acme-demo.net', 'acmedemo.mx'])
        self.assertIn('acme-dem0.mx', v)


class FallasYGrabacion(unittest.TestCase):

    def test_1_reintenta_y_sigue(self):
        t = CrtshSimulado(fallas=2)
        res = recolectar(t, parecidos=False)
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.consultas, 3)

    def test_2_si_no_responde_queda_failed(self):
        t = CrtshSimulado(fallas=100)
        res = recolectar(t, parecidos=False)
        self.assertEqual(res.estado, 'failed')
        self.assertEqual((res.activos, res.hallazgos), ([], []))
        self.assertIn('502', res.error)
        self.assertEqual(len(t.urls), 2 * crtsh.INTENTOS)  # la consulta por comodín y la de respaldo

    def test_3_falla_en_parecidos_no_tumba_el_escaneo(self):
        class SoloSubdominios(CrtshSimulado):
            def __call__(self, url, timeout):
                if '%25acme-demo%25' in url or 'q=acme-' in url:
                    raise TimeoutError('timed out')
                return super().__call__(url, timeout)
        res = recolectar(SoloSubdominios())
        self.assertEqual(res.estado, 'succeeded')
        self.assertTrue(res.avisos)

    def test_4_si_crtsh_esta_saturado_deja_de_probar_variantes(self):
        class SinVariantes(CrtshSimulado):
            def __call__(self, url, timeout):
                q = crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(url).query)['q'][0]
                if not q.startswith('%'):
                    self.urls.append(url)
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)
        t = SinVariantes()
        res = recolectar(t)
        self.assertEqual(res.estado, 'succeeded')
        variantes = [u for u in t.urls if 'q=%25' not in u]
        self.assertEqual(len(variantes), crtsh.FALLAS_SEGUIDAS * 2)  # 2 intentos por variante
        self.assertIn('crt.sh saturado', res.avisos[-1])

    def test_4b_grabar_y_reproducir_sin_red(self):
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None)
            vivo = crtsh.recolectar('acme-demo.mx', grab, AHORA, propios=['acme-demo.com.mx'])
            self.assertTrue((Path(d) / 'subdominios_acme-demo.mx.json').exists())

            def sin_red(url, timeout):
                raise AssertionError('no debe usar la red')
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d, transporte=sin_red)
            grabado = crtsh.recolectar('acme-demo.mx', rep, AHORA, propios=['acme-demo.com.mx'])
            self.assertEqual(sorted(h.huella for h in vivo.hallazgos), sorted(h.huella for h in grabado.hallazgos))
            self.assertEqual(rep.consultas, 0)

    def test_5_reproducir_sin_grabacion_queda_failed(self):
        with tempfile.TemporaryDirectory() as d:
            res = crtsh.recolectar('acme-demo.mx', crtsh.ClienteCrtsh(modo='reproducir', carpeta=d), AHORA)
        self.assertEqual(res.estado, 'failed')

    def test_6_dominio_invalido(self):
        res = crtsh.recolectar('no es un dominio', crtsh.ClienteCrtsh(transporte=CrtshSimulado()), AHORA)
        self.assertEqual(res.estado, 'failed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
