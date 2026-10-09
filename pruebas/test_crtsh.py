"""Pruebas del recolector de crt.sh (#14), sin red: un crt.sh simulado y una fecha fija.

    python -m unittest -v pruebas/test_crtsh.py
"""
import contextlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock
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

    def test_7_completar_no_repite_lo_ya_grabado(self):
        with tempfile.TemporaryDirectory() as d:
            primera = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None)
            crtsh.recolectar('acme-demo.mx', primera, AHORA, parecidos=False)
            t = CrtshSimulado()
            segunda = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=t, dormir=lambda s: None, completar=True)
            res = crtsh.recolectar('acme-demo.mx', segunda, AHORA, propios=['acme-demo.com.mx'])
            self.assertEqual(res.estado, 'succeeded')
            self.assertFalse([u for u in t.urls if 'q=%25.acme-demo.mx' in u])  # la de subdominios ya estaba
            self.assertTrue(t.urls)                                              # las variantes sí se consultan
            self.assertEqual([n for n, _ in segunda.leidas], ['subdominios_acme-demo.mx.json'])
            self.assertTrue((Path(d) / 'acme-dem0.mx.json').exists())

    def test_8_falta_de_grabacion_no_es_saturacion(self):
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None)
            crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False)
            res = crtsh.recolectar('acme-demo.mx', crtsh.ClienteCrtsh(modo='reproducir', carpeta=d), AHORA,
                                   propios=['acme-demo.com.mx'])
        self.assertEqual(res.estado, 'succeeded')
        self.assertTrue(res.avisos)
        self.assertTrue(all(a.startswith(crtsh.SIN_GRABACION) for a in res.avisos))
        self.assertEqual(crtsh.codigo_salida(res), 2)

    def test_9_completar_vuelve_a_consultar_lo_de_grabaciones_anteriores(self):
        inicio = datetime(2026, 10, 15, 18, 0, tzinfo=timezone.utc)
        reloj = lambda: inicio + crtsh.timedelta(minutes=1)

        class VarianteCaida(CrtshSimulado):
            def __call__(self, url, timeout):
                if 'q=acme-dem0.mx' in url:
                    self.urls.append(url)
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)

        with tempfile.TemporaryDirectory() as d:
            viejo = Path(d) / 'acme-dem0.mx.json'  # de la semana pasada, cuando no había certificado
            viejo.write_text(json.dumps({'grabado': '2026-10-08T18:00:00+00:00', 'consulta': 'acme-dem0.mx', 'datos': []}),
                             encoding='utf-8')
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=VarianteCaida(), dormir=lambda s: None, reloj=reloj)
            res = crtsh.recolectar('acme-demo.mx', grab, AHORA, propios=['acme-demo.com.mx'])
            self.assertEqual(crtsh.codigo_salida(res), 2)
            self.assertFalse(viejo.exists())  # la respuesta vieja no pasa por la de hoy

            t = CrtshSimulado()
            completa = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=t, dormir=lambda s: None, reloj=reloj,
                                          completar=True, desde=inicio)
            res = crtsh.recolectar('acme-demo.mx', completa, AHORA, propios=['acme-demo.com.mx'])
        self.assertEqual(len(t.urls), 1)
        self.assertIn('q=acme-dem0.mx', t.urls[0])
        self.assertEqual(crtsh.codigo_salida(res), 0)
        self.assertIn('acme-dem0.mx', {h.evidencia.get('dominio_parecido') for h in res.hallazgos})

    def test_10_completar_no_reutiliza_lo_anterior_al_inicio(self):
        inicio = datetime(2026, 10, 15, 18, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'subdominios_acme-demo.mx.json').write_text(json.dumps(
                {'grabado': '2026-10-08T18:00:00+00:00', 'consulta': '%.acme-demo.mx', 'datos': []}), encoding='utf-8')
            t = CrtshSimulado()
            cliente = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=t, dormir=lambda s: None,
                                         completar=True, desde=inicio)
            res = crtsh.recolectar('acme-demo.mx', cliente, AHORA, parecidos=False)
        self.assertEqual(len(t.urls), 1)
        self.assertEqual(len(res.activos), 6)

    def test_11_completar_sin_grabacion_previa_no_arranca(self):
        with tempfile.TemporaryDirectory() as d:
            original = crtsh.CARPETA_GRABADAS
            crtsh.CARPETA_GRABADAS = Path(d)
            try:
                with self.assertRaises(SystemExit) as salida, contextlib.redirect_stderr(io.StringIO()):
                    crtsh._main(['acme-demo.mx', '--grabar', '--completar'])
            finally:
                crtsh.CARPETA_GRABADAS = original
        self.assertEqual(salida.exception.code, 2)

    def test_13_flujo_del_dia_anterior_por_la_linea_de_comandos(self):
        """--grabar con crt.sh saturado, --reproducir con faltantes, --grabar --completar y --reproducir completo."""
        class PrimerasVariantesCaidas(CrtshSimulado):
            caidas = {'acme-demo.com', 'acme-demo.com.mx', 'acme-demo.net'}

            def __call__(self, url, timeout):
                q = crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(url).query)['q'][0]
                if q in self.caidas:
                    self.urls.append(url)
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)

        def correr(*argv):
            salida = io.StringIO()
            with contextlib.redirect_stdout(salida):
                codigo = crtsh._main(list(argv))
            return codigo, salida.getvalue()

        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)), mock.patch.object(crtsh.time, 'sleep', lambda s: None):
            propia, otra = Path(d) / 'acme-demo.mx', Path(d) / 'acme-demo.com.mx'
            propia.mkdir()
            otra.mkdir()
            (propia / 'acme-dem0.mx.json').write_text('[]', encoding='utf-8')     # de una grabación anterior
            (otra / 'contiene_acme-demo.json').write_text('[]', encoding='utf-8')  # de otro dominio

            with mock.patch.object(crtsh, '_descargar', PrimerasVariantesCaidas()):
                codigo, _ = correr('acme-demo.mx', '--grabar')
            self.assertEqual(codigo, 2)
            self.assertFalse((propia / 'acme-dem0.mx.json').exists())
            self.assertTrue((otra / 'contiene_acme-demo.json').exists())

            codigo, texto = correr('acme-demo.mx', '--reproducir')
            self.assertEqual(codigo, 2)
            self.assertIn('Faltan 10 respuestas grabadas', texto)  # 3 caídas y 7 omitidas por saturación
            self.assertNotIn('saturado', texto)

            sana = CrtshSimulado()
            with mock.patch.object(crtsh, '_descargar', sana):
                codigo, _ = correr('acme-demo.mx', '--grabar', '--completar')
            self.assertEqual((codigo, len(sana.urls)), (0, 10))

            codigo, texto = correr('acme-demo.mx', '--reproducir')
            self.assertEqual(codigo, 0)
            self.assertNotIn('Faltan', texto)
            self.assertIn('acme-dem0.mx', texto)

    def test_15_si_crtsh_no_responde_la_grabacion_anterior_queda_intacta(self):
        def correr(*argv):
            with contextlib.redirect_stdout(io.StringIO()):
                return crtsh._main(list(argv))

        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)), mock.patch.object(crtsh.time, 'sleep', lambda s: None):
            with mock.patch.object(crtsh, '_descargar', CrtshSimulado()):
                self.assertEqual(correr('acme-demo.mx', '--grabar'), 0)
            carpeta = Path(d) / 'acme-demo.mx'
            antes = {f.name: f.read_bytes() for f in carpeta.iterdir()}
            with mock.patch.object(crtsh, '_descargar', CrtshSimulado(fallas=100)):
                self.assertEqual(correr('acme-demo.mx', '--grabar'), 1)
            self.assertEqual({f.name: f.read_bytes() for f in carpeta.iterdir()}, antes)
            self.assertEqual(correr('acme-demo.mx', '--reproducir'), 0)

    def test_14_dominio_invalido_no_toca_las_grabaciones(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d) / 'crtsh'):
            fuera = Path(d) / 'otra_cosa.json'
            fuera.write_text('[]', encoding='utf-8')
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                crtsh._main(['..', '--grabar'])
            self.assertTrue(fuera.exists())

    def test_12_respaldo_por_nombre_deja_aviso(self):
        class SinComodin(CrtshSimulado):
            def __call__(self, url, timeout):
                if 'q=%25.acme-demo.mx' in url:
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)
        t = SinComodin(respuestas={'acme-demo.mx': SUBDOMINIOS})
        res = recolectar(t, parecidos=False)
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.error, '')
        self.assertEqual(len(res.avisos), 1)
        self.assertIn('pueden faltar subdominios', res.avisos[0])
        self.assertEqual(crtsh.codigo_salida(res), 2)


class Resumen(unittest.TestCase):
    """Lo que se lee en la terminal durante una demo."""

    def test_1_severidad_y_caracteristicas_en_espanol(self):
        res = recolectar(CrtshSimulado(), parecidos=False)
        lineas = crtsh.resumen(res)
        self.assertEqual(lineas[0], 'acme-demo.mx · crt.sh · succeeded · 1 consulta')
        self.assertIn('  [media] El certificado de api.acme-demo.mx vence en 10 días', lineas)
        self.assertIn('  [alta] Certificado vencido en dev.acme-demo.mx', lineas)
        self.assertIn('      tipo: certificado por vencer · antigüedad: 80 días · exposición: pública · sensibilidad: baja',
                      lineas)
        self.assertIn('  api.acme-demo.mx · vence 25 oct 2026', lineas)
        self.assertIn('  tienda.acme-demo.mx · vence 30 nov 2026 · comodín', lineas)
        self.assertFalse([l for l in lineas if '[medium]' in l or '[high]' in l])
        self.assertEqual(crtsh.codigo_salida(res), 0)

    def test_2_reproducir_dice_de_cuando_es_la_grabacion(self):
        # La fecha va dentro del archivo: una copia o un git clone no la cambian. Mediodía local para que
        # la fecha impresa sea la misma en cualquier zona horaria.
        grabado = datetime(2026, 10, 15, 12, 0).astimezone()
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None,
                                      reloj=lambda: grabado)
            crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False)
            ahora = datetime.now().timestamp()
            for f in Path(d).iterdir():
                os.utime(f, (ahora, ahora))  # como si se acabara de copiar
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d)
            lineas = crtsh.resumen(crtsh.recolectar('acme-demo.mx', rep, AHORA, parecidos=False), rep)
        self.assertIn('sin red, respuestas grabadas el 15 oct 2026 a las 12:00', lineas[0])
        self.assertNotIn('consulta', lineas[0])

    def test_2b_lee_el_formato_anterior(self):
        with tempfile.TemporaryDirectory() as d:
            archivo = Path(d) / 'subdominios_acme-demo.mx.json'
            archivo.write_text(json.dumps(SUBDOMINIOS), encoding='utf-8')
            marca = datetime(2026, 10, 14, 12, 0).timestamp()
            os.utime(archivo, (marca, marca))
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d)
            res = crtsh.recolectar('acme-demo.mx', rep, AHORA, parecidos=False)
            lineas = crtsh.resumen(res, rep)
        self.assertEqual(len(res.activos), 6)
        self.assertIn('respuestas grabadas el 14 oct 2026', lineas[0])

    def test_3_faltantes_agrupados_y_sin_saturacion(self):
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None)
            crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False)
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d)
            lineas = crtsh.resumen(crtsh.recolectar('acme-demo.mx', rep, AHORA, propios=['acme-demo.com.mx']), rep)
        faltan = [l for l in lineas if l.startswith('Faltan ')]
        self.assertEqual(len(faltan), 1)
        self.assertIn('%acme-demo%', faltan[0])
        self.assertTrue(faltan[0].endswith('Se completan con --grabar --completar.'))
        self.assertFalse([l for l in lineas if 'saturado' in l or l.startswith('aviso:')])

    def test_3b_un_solo_faltante_en_singular(self):
        res = crtsh.Resultado('acme-demo.mx', avisos=[crtsh.SIN_GRABACION + '%.acme-demo.mx'])
        self.assertIn('Falta 1 respuesta grabada: %.acme-demo.mx. Se completa con --grabar --completar.',
                      crtsh.resumen(res))

    def test_4_sin_hallazgos_lo_dice(self):
        solo = cert(40, ['acme-demo.mx'], '2026-09-20T00:00:00', '2026-12-19T00:00:00')
        res = recolectar(CrtshSimulado(respuestas={'%.acme-demo.mx': [solo]}), parecidos=False)
        lineas = crtsh.resumen(res)
        self.assertEqual(lineas[-1], 'Sin hallazgos.')
        self.assertIn('1 activo:', lineas)


if __name__ == '__main__':
    unittest.main(verbosity=2)
