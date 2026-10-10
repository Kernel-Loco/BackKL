"""Pruebas del contrato de plugin (#13), sin red.

    python -m unittest -v pruebas/test_contrato.py
"""
import http.client
import json
import sys
import tempfile
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_contrato.py
from pruebas.test_crtsh import AHORA, CrtshSimulado  # noqa: E402
from cirdan.recolectores import REGISTRO, cargar, contrato, crtsh, ejemplo  # noqa: E402
from cirdan.recolectores.contrato import Activo, Hallazgo, Resultado  # noqa: E402

HUELLA = 'a' * 64


def hallazgo(**cambios):
    base = dict(codigo='spf_missing', severidad='low', activo='acme-demo.mx', titulo='Falta SPF',
                evidencia={'title': 'Falta SPF'}, huella=HUELLA,
                caracteristicas={'tipo': 'spf_faltante', 'antiguedad_dias': 3, 'exposicion': 'publica', 'sensibilidad': 'baja'})
    base.update(cambios)
    return Hallazgo(**base)


def resultado(*hallazgos, activos=()):
    return Resultado('acme-demo.mx', 'prueba', activos=list(activos), hallazgos=list(hallazgos))


def recolector(armar, fuente='prueba'):
    """Un recolector mínimo cuyo recolectar(dominio) devuelve armar(dominio)."""
    return SimpleNamespace(FUENTE=fuente, crear_cliente=lambda modo, dominio: None,
                           recolectar=lambda dominio, cliente=None, ahora=None, propios=(): armar(dominio))


def error_http(codigo):
    return urllib.error.HTTPError('https://fuente.example/q', codigo, 'error %d' % codigo, {}, None)


class Esquema(unittest.TestCase):

    def test_1_un_resultado_valido_no_tiene_errores(self):
        self.assertEqual(contrato.validar(resultado(hallazgo()), codigos={'spf_missing'}), [])

    def test_2_crtsh_cumple_el_contrato(self):
        cliente = crtsh.ClienteCrtsh(transporte=CrtshSimulado(), dormir=lambda s: None)
        res = crtsh.recolectar('acme-demo.mx', cliente, AHORA, propios=['acme-demo.com.mx'])
        self.assertTrue(res.hallazgos)
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])

    def test_3_cada_regla_de_los_hallazgos(self):
        c = {'tipo': 'spf_faltante', 'antiguedad_dias': 1, 'exposicion': 'publica', 'sensibilidad': 'baja'}
        malos = {
            'código fuera del catálogo': (hallazgo(codigo='otra_regla'), 'catálogo'),
            'código mal escrito': (hallazgo(codigo='Mal-Codigo'), 'código inválido'),
            'código con salto de línea': (hallazgo(codigo='spf_missing\n'), 'código inválido'),
            'severidad': (hallazgo(severidad='alta'), 'severidad inválida'),
            'activo ajeno': (hallazgo(activo='otro.mx'), 'no es el dominio'),
            'sin título': (hallazgo(titulo='', evidencia={'title': ''}), 'sin título'),
            'título en la evidencia': (hallazgo(evidencia={}), "evidencia['title']"),
            'características incompletas': (hallazgo(caracteristicas={'tipo': 'x'}), 'características deben ser'),
            'tipo': (hallazgo(caracteristicas=dict(c, tipo='X Y')), 'tipo inválido'),
            'tipo con salto de línea': (hallazgo(caracteristicas=dict(c, tipo='spf_faltante\n')), 'tipo inválido'),
            'antigüedad negativa': (hallazgo(caracteristicas=dict(c, antiguedad_dias=-1)), 'antiguedad_dias'),
            'antigüedad booleana': (hallazgo(caracteristicas=dict(c, antiguedad_dias=True)), 'antiguedad_dias'),
            'exposición': (hallazgo(caracteristicas=dict(c, exposicion='privada')), 'exposicion inválida'),
            'sensibilidad': (hallazgo(caracteristicas=dict(c, sensibilidad='critica')), 'sensibilidad inválida'),
            'huella': (hallazgo(huella='abc'), 'huella inválida'),
            'huella con salto de línea': (hallazgo(huella=HUELLA + '\n'), 'huella inválida'),
            'clave': (hallazgo(clave=None), 'la clave debe ser texto'),
            'carácter nulo': (hallazgo(titulo='Falta\x00', evidencia={'title': 'Falta\x00'}), 'la base no acepta'),
            'surrogate suelto': (hallazgo(titulo='Falta\udc80', evidencia={'title': 'Falta\udc80'}), 'la base no acepta'),
        }
        for nombre, (h, esperado) in malos.items():
            errores = contrato.validar(resultado(h), codigos={'spf_missing'})
            self.assertTrue(any(esperado in e for e in errores), (nombre, errores))

    def test_4_cada_regla_del_resultado_y_de_los_activos(self):
        def con(**cambios):
            return Resultado(**dict(dict(dominio='acme-demo.mx', fuente='prueba'), **cambios))

        def activo(*args):
            return resultado(activos=[Activo(*args)])
        malos = {
            'estado': (con(estado='ok'), 'estado inválido'),
            'fuente': (con(fuente=''), 'falta la fuente'),
            'dominio': (con(dominio='mx'), 'dominio inválido'),
            'consultas en texto': (con(consultas='3'), 'consultas debe ser'),
            'consultas negativas': (con(consultas=-7), 'consultas debe ser'),
            'consultas booleanas': (con(consultas=True), 'consultas debe ser'),
            'consultas enormes': (con(consultas=10 ** 5000), 'consultas debe ser'),
            'avisos en texto': (con(avisos='x'), 'avisos debe ser'),
            'avisos que no son texto': (con(avisos=[1, None]), 'avisos debe ser'),
            'error': (con(error=None), 'error debe ser texto'),
            'activos que no son lista': (con(activos=()), 'deben ser listas'),
            'activo que no es Activo': (con(activos=[{'tipo': 'subdomain'}]), 'no es Activo'),
            'hallazgo que no es Hallazgo': (con(hallazgos=['spf_missing']), 'no es Hallazgo'),
            'tipo de activo': (activo('server', 'x.acme-demo.mx'), 'tipo inválido'),
            'activo sin valor': (activo('subdomain', ''), 'activo sin valor'),
            'atributos': (activo('subdomain', 'a.acme-demo.mx', []), 'no es un objeto'),
            'nombre': (activo('subdomain', 'evil.com/x.acme-demo.mx'), 'nombre de dominio'),
            'correo sin arroba': (activo('email', 'ana.acme-demo.mx'), 'correo'),
            'ip': (activo('ip', '999.1.1.1', {'host': 'www.acme-demo.mx'}), 'IP'),
            'ip sin host': (activo('ip', '198.51.100.10', {'hostname': 'www.acme-demo.mx'}), "'host' o 'hosts'"),
            'certificado sin hosts': (activo('certificate', 'ab' * 32), "'host' o 'hosts'"),
            'hosts en texto': (activo('ip', '198.51.100.10', {'hosts': 'www.acme-demo.mx'}), "'host' o 'hosts'"),
            'carácter nulo en atributos': (activo('service', '198.51.100.10:22/tcp',
                                                  {'host': 'www.acme-demo.mx', 'banner': 'SSH-2.0\x00'}), 'la base no acepta'),
            'carácter nulo en una llave': (activo('subdomain', 'a.acme-demo.mx', {'x\x00': 1}), 'la base no acepta'),
            'correo con dominio inválido': (activo('email', 'ana@x y.acme-demo.mx'), 'correo'),
            'host con nombre inválido': (activo('ip', '198.51.100.10', {'host': 'x y.acme-demo.mx'}), "'host' o 'hosts'"),
        }
        for nombre, (res, esperado) in malos.items():
            errores = contrato.validar(res)
            self.assertTrue(any(esperado in e for e in errores), (nombre, errores))
        self.assertEqual(contrato.validar(activo('ip', '198.51.100.10', {'host': 'www.acme-demo.mx'})), [])
        self.assertEqual(contrato.validar(activo('email', 'Ana@ACME-DEMO.mx')), [])

    def test_4b_repetidos(self):
        self.assertTrue(any('huella repetida' in e for e in contrato.validar(resultado(hallazgo(), hallazgo(clave='x')))))
        self.assertTrue(any('repetido' in e for e in contrato.validar(resultado(activos=[Activo('subdomain', 'a.acme-demo.mx')] * 2))))

    def test_5_failed_sin_activos_ni_hallazgos(self):
        res = resultado(hallazgo())
        res.estado = 'failed'
        self.assertTrue(contrato.validar(res))

    def test_6_todo_se_puede_guardar_como_json(self):
        for raro in (datetime(2026, 10, 15, tzinfo=timezone.utc), float('nan'), {1, 2}):
            res = resultado(activos=[Activo('subdomain', 'a.acme-demo.mx', {'visto': raro})])
            self.assertTrue(any('JSON' in e for e in contrato.validar(res)), raro)
        self.assertTrue(contrato.validar(resultado(activos=[Activo('ip', '198.51.100.10', {'hosts': 'www.acme-demo.mx'})])))

    def test_7_la_clave_distingue_hallazgos_del_mismo_codigo_y_activo(self):
        uno = hallazgo(codigo='lookalike_domain', clave='acme-dem0.mx')
        otro = hallazgo(codigo='lookalike_domain', clave='acme-demo.com', huella='b' * 64)
        self.assertEqual(contrato.validar(resultado(uno, otro)), [])
        repetido = hallazgo(codigo='lookalike_domain', clave='acme-dem0.mx', huella='c' * 64)
        self.assertTrue(contrato.validar(resultado(uno, repetido)))

    def test_8_crtsh_da_una_clave_distinta_a_cada_dominio_parecido(self):
        cliente = crtsh.ClienteCrtsh(transporte=CrtshSimulado(), dormir=lambda s: None)
        res = crtsh.recolectar('acme-demo.mx', cliente, AHORA, propios=['acme-demo.com.mx'])
        parecidos = [h for h in res.hallazgos if h.codigo == 'lookalike_domain']
        self.assertTrue(parecidos)
        self.assertEqual(len({h.clave for h in parecidos}), len(parecidos))
        self.assertEqual([h.clave for h in parecidos], [h.evidencia['dominio_parecido'] for h in parecidos])


class Alcance(unittest.TestCase):

    def test_1_nombres_correos_ip_y_servicios(self):
        d = 'acme-demo.mx'
        dentro = [Activo('domain', 'acme-demo.mx'), Activo('subdomain', 'api.acme-demo.mx'),
                  Activo('email', 'ana@acme-demo.mx'), Activo('ip', '198.51.100.10', {'host': 'www.acme-demo.mx'}),
                  Activo('service', '198.51.100.10:443/tcp', {'hosts': ['otro.mx', 'shop.acme-demo.mx']}),
                  Activo('certificate', 'ab12', {'host': 'www.acme-demo.mx'})]
        fuera = [Activo('subdomain', 'acme-demo.mx.evil.com'), Activo('domain', 'xacme-demo.mx'),
                 Activo('email', 'ana@gmail.com'), Activo('ip', '203.0.113.5'),
                 Activo('service', '203.0.113.5:22/tcp', {'host': 'otro.mx'})]
        for a in dentro:
            self.assertTrue(contrato.en_alcance(a, d), a)
        for a in fuera:
            self.assertFalse(contrato.en_alcance(a, d), a)

    def test_2_filtrar_quita_el_activo_y_sus_hallazgos(self):
        res = resultado(hallazgo(activo='acme-demo.mx.evil.com', huella='b' * 64), hallazgo(),
                        activos=[Activo('subdomain', 'acme-demo.mx.evil.com'), Activo('subdomain', 'www.acme-demo.mx')])
        res = contrato.filtrar_alcance(res)
        self.assertEqual([a.valor for a in res.activos], ['www.acme-demo.mx'])
        self.assertEqual([h.huella for h in res.hallazgos], [HUELLA])
        self.assertIn('fuera de alcance', res.avisos[0])

    def test_3_mayusculas_y_punto_final(self):
        self.assertTrue(contrato.en_alcance(Activo('subdomain', 'API.Acme-Demo.MX.'), 'acme-demo.mx'))
        self.assertTrue(contrato.en_alcance_nombre('www.acme-demo.mx', 'ACME-DEMO.MX.'))
        self.assertTrue(contrato.en_alcance(Activo('email', 'Ana@ACME-DEMO.mx'), 'acme-demo.mx'))

    def test_4_certificado_con_hosts(self):
        d = 'acme-demo.mx'
        self.assertTrue(contrato.en_alcance(Activo('certificate', 'ab12', {'hosts': ['otro.mx', 'www.acme-demo.mx']}), d))
        self.assertFalse(contrato.en_alcance(Activo('certificate', 'ab12', {'hosts': ['otro.mx']}), d))
        self.assertFalse(contrato.en_alcance(Activo('certificate', 'ab12'), d))

    def test_5_un_activo_fuera_no_se_lleva_los_hallazgos_de_otro_con_el_mismo_valor(self):
        res = resultado(hallazgo(activo='www.acme-demo.mx'),
                        activos=[Activo('subdomain', 'www.acme-demo.mx'),
                                 Activo('certificate', 'www.acme-demo.mx', {'host': 'otro.mx'})])
        res = contrato.filtrar_alcance(res)
        self.assertEqual([a.tipo for a in res.activos], ['subdomain'])
        self.assertEqual([h.activo for h in res.hallazgos], ['www.acme-demo.mx'])


class Ejecutar(unittest.TestCase):

    def test_1_un_recolector_que_truena_deja_la_fuente_en_failed(self):
        class Roto:
            FUENTE = 'roto'

            @staticmethod
            def crear_cliente(modo, dominio):
                return None

            @staticmethod
            def recolectar(dominio, cliente=None, ahora=None, propios=()):
                raise RuntimeError('se rompió')
        res = contrato.ejecutar(Roto, 'acme-demo.mx')
        self.assertEqual((res.estado, res.fuente), ('failed', 'roto'))
        self.assertIn('se rompió', res.error)

    def test_2_un_resultado_fuera_del_contrato_tambien(self):
        class Tramposo:
            FUENTE = 'tramposo'

            @staticmethod
            def crear_cliente(modo, dominio):
                return None

            @staticmethod
            def recolectar(dominio, cliente=None, ahora=None, propios=()):
                return Resultado(dominio, 'tramposo', hallazgos=[hallazgo(severidad='urgente')])
        res = contrato.ejecutar(Tramposo, 'acme-demo.mx')
        self.assertEqual(res.estado, 'failed')
        self.assertIn('no cumple el contrato', res.error)
        self.assertEqual(res.hallazgos, [])

    def test_3_ejemplo_reproduce_su_grabacion_del_repo(self):
        res = contrato.ejecutar(cargar('ejemplo'), 'acme-demo.mx', modo='reproducir', codigos={'spf_missing'})
        self.assertEqual((res.estado, res.fuente, len(res.activos)), ('succeeded', 'ejemplo', 2))
        self.assertEqual([h.codigo for h in res.hallazgos], ['spf_missing'])

    def test_4_crtsh_por_ejecutar_con_su_grabacion(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)):
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=crtsh.carpeta_de('acme-demo.mx'), transporte=CrtshSimulado(),
                                      dormir=lambda s: None)
            crtsh.recolectar('acme-demo.mx', grab, AHORA)
            res = contrato.ejecutar(cargar('ct_logs'), 'acme-demo.mx', modo='reproducir', ahora=AHORA,
                                    codigos=set(crtsh.CODIGOS))
        self.assertEqual(res.estado, 'succeeded')
        self.assertTrue(res.hallazgos)

    def test_5_fuente_sin_recolector(self):
        with self.assertRaises(KeyError):
            cargar('no_existe')

    def test_6_un_resultado_de_otro_dominio_o_de_otra_fuente_no_pasa(self):
        for armar, ajeno in ((lambda d: Resultado('otro.mx', 'prueba'), 'otro.mx'),
                             (lambda d: Resultado(d, 'otra_fuente'), 'otra_fuente')):
            res = contrato.ejecutar(recolector(armar), 'acme-demo.mx')
            self.assertEqual((res.estado, res.dominio, res.fuente), ('failed', 'acme-demo.mx', 'prueba'))
            self.assertIn(ajeno, res.error)

    def test_7_un_resultado_mal_formado_no_lanza_excepciones(self):
        malos = {'activo que es un dict': lambda d: Resultado(d, 'prueba', activos=[{'tipo': 'subdomain'}]),
                 'tipo de activo inventado': lambda d: Resultado(d, 'prueba', activos=[Activo('hostname', 'www.' + d)]),
                 'hallazgo que es un texto': lambda d: Resultado(d, 'prueba', hallazgos=['spf_missing'])}
        for nombre, armar in malos.items():
            res = contrato.ejecutar(recolector(armar), 'acme-demo.mx')
            self.assertEqual(res.estado, 'failed', nombre)
            self.assertEqual((res.activos, res.hallazgos), ([], []), nombre)
        res = contrato.ejecutar(recolector(lambda d: Resultado(d, 'prueba', consultas=-7)), 'acme-demo.mx')
        self.assertEqual((res.estado, res.consultas), ('failed', 0))

    def test_8_aplica_el_catalogo_y_luego_el_filtro(self):
        def armar(d):
            return Resultado(d, 'prueba', activos=[Activo('subdomain', 'www.' + d), Activo('subdomain', d + '.evil.com')],
                             hallazgos=[hallazgo(activo=d + '.evil.com', huella='b' * 64), hallazgo(),
                                        hallazgo(activo='www.' + d, huella='c' * 64)])
        res = contrato.ejecutar(recolector(armar), 'acme-demo.mx', codigos={'spf_missing'})
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual([a.valor for a in res.activos], ['www.acme-demo.mx'])
        self.assertEqual([h.huella for h in res.hallazgos], [HUELLA, 'c' * 64])
        self.assertTrue(any('acme-demo.mx.evil.com' in a for a in res.avisos))
        res = contrato.ejecutar(recolector(armar), 'acme-demo.mx', codigos={'dmarc_missing'})
        self.assertEqual(res.estado, 'failed')
        self.assertIn('catálogo', res.error)

    def test_9_normaliza_el_dominio_y_completa_la_fuente(self):
        res = contrato.ejecutar(cargar('ejemplo'), ' ACME-DEMO.MX. ', modo='reproducir', codigos={'spf_missing'})
        self.assertEqual((res.estado, res.dominio), ('succeeded', 'acme-demo.mx'))
        res = contrato.ejecutar(recolector(lambda d: Resultado(d)), 'acme-demo.mx')
        self.assertEqual((res.estado, res.fuente), ('succeeded', 'prueba'))

    def test_10_crtsh_crea_el_cliente_de_cada_modo(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)):
            self.assertTrue(crtsh.crear_cliente('grabar', 'acme-demo.mx').grabadora.nueva)
            self.assertFalse(crtsh.crear_cliente('reproducir', 'acme-demo.mx').grabadora.nueva)
            self.assertEqual(crtsh.crear_cliente('vivo', 'Acme-Demo.mx.').carpeta, Path(d) / 'acme-demo.mx')

    def test_11_un_dominio_invalido_no_llega_al_recolector(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(ejemplo, 'CARPETA_GRABADAS', Path(d) / 'a' / 'b'):
            for dominio in (None, 5, b'acme-demo.mx', 'mx', '../../fuera', 'c:/temp/x', 'acme-demo.mx\n.evil'):
                res = contrato.ejecutar(cargar('ejemplo'), dominio, modo='grabar')
                self.assertEqual(res.estado, 'failed', dominio)
                self.assertIn('dominio inválido', res.error)
                json.dumps(res.a_dict(), allow_nan=False)
            self.assertEqual(list(Path(d).rglob('*')), [])

    def test_12_una_excepcion_que_no_se_puede_imprimir(self):
        class Rara(Exception):
            def __str__(self):
                raise RuntimeError('tampoco')

        def armar(d):
            raise Rara()
        res = contrato.ejecutar(recolector(armar), 'acme-demo.mx')
        self.assertEqual((res.estado, res.error), ('failed', 'Rara'))

    def test_13_ejemplo_si_lee_su_grabacion(self):
        res = contrato.ejecutar(cargar('ejemplo'), 'sin-grabacion.mx', modo='reproducir')
        self.assertEqual(res.estado, 'failed')
        self.assertIn(contrato.SIN_GRABACION, res.error)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(ejemplo, 'CARPETA_GRABADAS', Path(d)):
            datos = ejemplo._fijo('acme-demo.mx')
            datos['activos'].append({'tipo': 'subdomain', 'valor': 'api.acme-demo.mx', 'atributos': {}})
            contrato.Grabadora(Path(d) / 'acme-demo.mx', 'grabar').guardar('resultado', datos)
            res = contrato.ejecutar(cargar('ejemplo'), 'acme-demo.mx', modo='reproducir')
        self.assertEqual(res.estado, 'succeeded')
        self.assertIn('api.acme-demo.mx', [a.valor for a in res.activos])

    def test_14_cada_recolector_graba_de_nuevo_y_reproduce_lo_grabado(self):
        for fuente in REGISTRO:
            modulo = cargar(fuente)
            with tempfile.TemporaryDirectory() as d, mock.patch.object(modulo, 'CARPETA_GRABADAS', Path(d)), \
                    mock.patch.object(crtsh, '_descargar', CrtshSimulado()), mock.patch.object(crtsh.time, 'sleep', lambda s: None):
                carpeta = Path(d) / 'acme-demo.mx'
                carpeta.mkdir()
                (carpeta / 'viejo.json').write_text('[]', encoding='utf-8')  # de una grabación anterior
                res = contrato.ejecutar(modulo, 'acme-demo.mx', modo='grabar', ahora=AHORA)
                self.assertEqual(res.estado, 'succeeded', (fuente, res.error))
                self.assertFalse((carpeta / 'viejo.json').exists(), fuente)
                self.assertIsNotNone(contrato.Grabadora.inicio(carpeta), fuente)
                otra = contrato.ejecutar(modulo, 'acme-demo.mx', modo='reproducir', ahora=AHORA)
                self.assertEqual(otra.estado, 'succeeded', (fuente, otra.error))
                self.assertEqual((otra.activos, otra.hallazgos), (res.activos, res.hallazgos), fuente)

    def test_15_cada_recolector_graba_dentro_de_la_carpeta_del_contrato(self):
        self.assertEqual(contrato.CARPETA_GRABADAS.parent, Path(contrato.__file__).resolve().parent)
        self.assertTrue(contrato.CARPETA_GRABADAS.is_dir())
        for fuente in REGISTRO:
            self.assertEqual(cargar(fuente).CARPETA_GRABADAS.parent, contrato.CARPETA_GRABADAS, fuente)


class Reintentos(unittest.TestCase):

    def test_1_a_1_5_y_25_minutos_y_luego_failed(self):
        t = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(contrato.siguiente_estado('succeeded', 0, t), ('succeeded', 0, None))
        self.assertEqual(contrato.siguiente_estado('failed', 0, t), ('retrying', 1, t + timedelta(minutes=1)))
        self.assertEqual(contrato.siguiente_estado('failed', 1, t), ('retrying', 2, t + timedelta(minutes=5)))
        self.assertEqual(contrato.siguiente_estado('failed', 2, t), ('retrying', 3, t + timedelta(minutes=25)))
        self.assertEqual(contrato.siguiente_estado('failed', 3, t), ('failed', 3, None))

    def test_2_reintento_rapido_dentro_de_la_corrida(self):
        llamadas, esperas = [], []

        def consulta():
            llamadas.append(1)
            if len(llamadas) < 3:
                raise OSError('502')
            return 'ok'
        self.assertEqual(contrato.con_reintentos(consulta, dormir=esperas.append), 'ok')
        self.assertEqual(esperas, [5, 15])
        with self.assertRaises(contrato.FuenteNoResponde):
            contrato.con_reintentos(lambda: (_ for _ in ()).throw(OSError('caído')), dormir=lambda s: None)

    def test_3_un_4xx_no_se_reintenta_y_lo_demas_si(self):
        casos = [(error_http(404), 1, urllib.error.HTTPError), (error_http(403), 1, urllib.error.HTTPError),
                 (error_http(408), 3, contrato.FuenteNoResponde), (error_http(429), 3, contrato.FuenteNoResponde),
                 (error_http(503), 3, contrato.FuenteNoResponde),
                 (http.client.IncompleteRead(b'{'), 3, contrato.FuenteNoResponde)]
        for error, esperadas, lanza in casos:
            llamadas = []

            def consulta():
                llamadas.append(1)
                raise error
            with self.assertRaises(lanza):
                contrato.con_reintentos(consulta, dormir=lambda s: None)
            self.assertEqual(len(llamadas), esperadas, error)


class Grabadora(unittest.TestCase):

    def test_1_grabar_y_reproducir_con_la_fecha_dentro_del_archivo(self):
        fecha = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            g = contrato.Grabadora(d, 'grabar', reloj=lambda: fecha)
            self.assertEqual(g.de_disco('q'), (False, None))
            g.guardar('q', {'x': 1})
            r = contrato.Grabadora(d, 'reproducir')
            self.assertEqual(r.de_disco('q'), (True, {'x': 1}))
            self.assertEqual(r.leidas, [('q.json', fecha)])
            with self.assertRaises(contrato.SinGrabacion):
                r.de_disco('otra')

    def test_2_vivo_no_toca_el_disco(self):
        with tempfile.TemporaryDirectory() as d:
            g = contrato.Grabadora(Path(d) / 'nada', 'vivo')
            g.guardar('q', [1])
            self.assertFalse((Path(d) / 'nada').exists())

    def test_3_si_no_se_puede_vaciar_la_carpeta_lo_reintenta_el_siguiente_guardado(self):
        with tempfile.TemporaryDirectory() as d:
            anterior = contrato.Grabadora(d, 'grabar')
            anterior.guardar('a', [1])
            anterior.guardar('b', [2])
            g = contrato.Grabadora(d, 'grabar', nueva=True)
            with self.assertRaises(TypeError):
                g.guardar('a', {1, 2})  # no se puede guardar: no toca la grabación anterior
            self.assertEqual(sorted(p.name for p in Path(d).glob('*.json')), ['a.json', 'b.json'])
            with mock.patch.object(Path, 'unlink', side_effect=PermissionError('abierto en otro programa')):
                with self.assertRaises(PermissionError):
                    g.guardar('a', [3])
            self.assertTrue(g.nueva)
            g.guardar('a', [3])
            self.assertEqual(sorted(p.name for p in Path(d).glob('*.json')), ['a.json'])
            self.assertEqual(contrato.Grabadora.inicio(d), contrato.Grabadora.abrir(Path(d) / 'a.json')[1])

    def test_4_un_texto_que_no_se_puede_escribir_no_borra_la_grabacion_anterior(self):
        with tempfile.TemporaryDirectory() as d:
            contrato.Grabadora(d, 'grabar', nueva=True).guardar('a', [1])
            antes = {p.name: p.read_bytes() for p in Path(d).iterdir()}
            g = contrato.Grabadora(d, 'grabar', nueva=True)
            with self.assertRaises(UnicodeEncodeError):
                g.guardar('b', {'x': '\ud800'})  # un surrogate suelto que sí pasa por json.dumps
            self.assertEqual({p.name: p.read_bytes() for p in Path(d).iterdir()}, antes)
            self.assertTrue(g.nueva)


if __name__ == '__main__':
    unittest.main(verbosity=2)
