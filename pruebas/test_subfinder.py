"""Pruebas del recolector de subfinder (#14b, RC-184), que pide el CDX de Common Crawl directo. Sin red: un CDX
simulado en lugar de transporte.descargar, con la forma de las respuestas reales (collinfo.json, un JSON por captura y
el 404 'No Captures found').

    python -m unittest -v pruebas/test_subfinder.py
"""
import io
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_subfinder.py
from pruebas.test_catalogo_reglas import POR_CODIGO  # noqa: E402
from pruebas.test_crtsh import AHORA  # noqa: E402
from cirdan.recolectores import REGISTRO, cargar, contrato, subfinder, transporte  # noqa: E402
from cirdan.recolectores.contrato import Activo  # noqa: E402

RAIZ = Path(__file__).resolve().parents[1]
SEMILLA = RAIZ / 'db' / 'semillas' / '005_subfinder_y_limites.sql'
SEMILLA_017 = RAIZ / 'db' / 'semillas' / '017_subfinder_commoncrawl.sql'

# 14 índices válidos, más nuevos primero en collinfo.json pero mezclados aquí: el recolector toma los 12 más recientes.
VALIDOS = ['CC-MAIN-2026-%02d' % s for s in (5, 47, 8, 43, 13, 39, 17, 35, 21, 30, 26)] + \
          ['CC-MAIN-2025-%02d' % s for s in (51, 43, 47)]
RECIENTES = sorted(VALIDOS, reverse=True)[:12]
COLLINFO = json.dumps([{'id': i, 'name': i, 'cdx-api': 'https://ajeno.example/%s-index' % i} for i in VALIDOS] +
                      [{'id': 'CC-MAIN-2026-47x'}, {'id': 'otro'}, {'id': 5}, 'no es objeto', {'name': 'sin id'}])


def http(url, codigo, cuerpo=b''):
    return urllib.error.HTTPError(url, codigo, 'simulado', {}, io.BytesIO(cuerpo))


class CdxSimulado:
    """Hace las veces de transporte.descargar: anota cada petición y responde collinfo.json y el CDX de cada índice.

    `capturas` da las URLs de cada índice (sin capturas responde el 404 'No Captures found') y `fallas` lo que lanza
    un índice o 'collinfo': un código HTTP o una excepción, o una lista de ellos, uno por petición, que al acabarse
    deja responder al índice."""

    def __init__(self, capturas=None, fallas=None, collinfo=COLLINFO, crudo=None):
        self.capturas = capturas if capturas is not None else {
            RECIENTES[0]: ['https://www.acme-demo.mx/', 'https://WWW.acme-demo.mx:8443/x?a=1'],
            RECIENTES[3]: ['http://api.acme-demo.mx/v1', 'https://acme-demo.mx/'],
            RECIENTES[11]: ['https://*.dev.acme-demo.mx/', 'https://www.acme-demo.mx/otra']}
        self.fallas, self.collinfo, self.crudo = fallas or {}, collinfo, crudo or {}
        self.pedidas = []

    def __call__(self, req, plazo, tope, cronometro=None):
        url = req.full_url
        self.pedidas.append(SimpleNamespace(url=url, cabeceras=dict(req.header_items()), plazo=plazo, tope=tope))
        if url == subfinder.COLLINFO:
            indice = 'collinfo'
        else:
            indice = urllib.parse.urlsplit(url).path[1:-len('-index')]
        falla = self.fallas.get(indice)
        if isinstance(falla, list):
            falla = falla.pop(0) if falla else None
        if isinstance(falla, int):
            raise http(url, falla, b'Server busy')
        if falla is not None:
            raise falla
        if indice == 'collinfo':
            return self.collinfo.encode('utf-8')
        if indice in self.crudo:
            return self.crudo[indice]
        urls = self.capturas.get(indice)
        if not urls:
            raise http(url, 404, b'No Captures found for: *.acme-demo.mx')
        return '\n'.join(json.dumps({'url': u}) for u in urls).encode('utf-8')

    def indices(self):
        return [urllib.parse.urlsplit(p.url).path[1:-len('-index')] for p in self.pedidas if '-index' in p.url]


def con_cdx(simulado):
    """El transporte de subfinder.py con el CDX simulado. Solo lo ve subfinder.py: las demás fuentes no cambian."""
    falso = SimpleNamespace(descargar=simulado, PlazoVencido=transporte.PlazoVencido, Redirigida=transporte.Redirigida)
    return mock.patch.object(subfinder, 'transporte', falso)


class Cronometro:
    """Hace las veces de time.monotonic: cada lectura avanza `paso` segundos, sin dormir de verdad."""

    def __init__(self, paso):
        self.paso, self.ahora = paso, 1000.0

    def __call__(self):
        actual, self.ahora = self.ahora, self.ahora + self.paso
        return actual


def sin_red(*_, **__):
    raise AssertionError('no debe pedir nada a Common Crawl')


def cliente(modo='vivo', carpeta=None, nueva=False, cronometro=None, ritmo=None):
    """Un cliente con su propio Ritmo (salvo que se le pase uno) para que no dependa de las pruebas anteriores."""
    dormidas = []
    c = subfinder.ClienteSubfinder(modo=modo, carpeta=carpeta or subfinder.CARPETA_GRABADAS, nueva=nueva,
                                   cronometro=cronometro, dormir=dormidas.append, ritmo=ritmo or subfinder.Ritmo())
    c.dormidas = dormidas
    return c


def recolectar(simulado, modo='vivo', carpeta=None, nueva=False, cronometro=None):
    c = cliente(modo, carpeta, nueva, cronometro)
    with con_cdx(simulado):
        return subfinder.recolectar('acme-demo.mx', c, AHORA), c


def por_ejecutar(simulado, modo='vivo', carpeta=None):
    """Por contrato.ejecutar(), como lo llama el orquestador."""
    with tempfile.TemporaryDirectory() as d, mock.patch.object(subfinder, 'CARPETA_GRABADAS', Path(carpeta or d)), \
            con_cdx(simulado), mock.patch.object(subfinder.time, 'sleep', lambda s: None):
        return contrato.ejecutar(cargar('subfinder'), 'acme-demo.mx', modo=modo, ahora=AHORA)


class Activos(unittest.TestCase):

    def test_1_un_activo_subdomain_por_nombre_con_fuente_y_origen(self):
        res, _ = recolectar(CdxSimulado())
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.activos, [
            Activo('subdomain', 'api.acme-demo.mx', {'fuente': 'subfinder', 'origen': ['commoncrawl']}),
            Activo('subdomain', 'dev.acme-demo.mx', {'fuente': 'subfinder', 'origen': ['commoncrawl']}),
            Activo('subdomain', 'www.acme-demo.mx', {'fuente': 'subfinder', 'origen': ['commoncrawl']}),
        ])
        self.assertEqual((res.hallazgos, res.sin_cobertura, res.avisos), ([], [], []))
        for a in res.activos:  # solo el nombre, nunca la URL ni la ruta
            self.assertEqual(set(a.atributos), {'fuente', 'origen'})

    def test_2_fuera_del_dominio_e_invalidos_se_cuentan_y_no_se_nombran(self):
        capturas = {RECIENTES[0]: ['https://acme-demo.mx.ajeno.com/', 'https://otro.com/', 'https://xacme-demo.mx/',
                                   'https://a_b.acme-demo.mx/', 'https://ok.acme-demo.mx/']}
        res, _ = recolectar(CdxSimulado(capturas))
        self.assertEqual([a.valor for a in res.activos], ['ok.acme-demo.mx'])
        self.assertEqual(res.avisos, ['subfinder: se descartaron 3 nombres fuera del dominio',
                                      'subfinder: se descartó 1 nombre que no es un nombre de dominio válido'])
        for nombre in ('ajeno', 'otro.com'):
            self.assertNotIn(nombre, ' '.join(res.avisos))
        self.assertEqual(contrato.validar(res), [])

    def test_3_validar_con_el_catalogo_y_codigos_vacio(self):
        self.assertEqual(subfinder.CODIGOS, {})
        res, _ = recolectar(CdxSimulado())
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        res = por_ejecutar(CdxSimulado())
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_4_esta_en_el_registro_con_su_carpeta(self):
        self.assertIs(cargar('subfinder'), subfinder)
        self.assertEqual(REGISTRO['subfinder'], 'cirdan.recolectores.subfinder')
        self.assertEqual(subfinder.FUENTE, 'subfinder')
        self.assertEqual(subfinder.CARPETA_GRABADAS, contrato.CARPETA_GRABADAS / 'subfinder')

    def test_5_ya_no_corre_el_binario(self):
        texto = Path(subfinder.__file__).read_text(encoding='utf-8')
        self.assertNotIn('import subprocess', texto)
        self.assertFalse(hasattr(subfinder, '_ejecutar'))


class Busqueda(unittest.TestCase):

    def test_1_revisa_los_12_indices_mas_recientes_con_urls_armadas_aqui(self):
        simulado = CdxSimulado()
        res, c = recolectar(simulado)
        self.assertEqual(simulado.pedidas[0].url, 'https://index.commoncrawl.org/collinfo.json')
        self.assertEqual(simulado.indices(), RECIENTES)
        self.assertEqual(len(RECIENTES), subfinder.INDICES)
        self.assertEqual((res.consultas, c.consultas, len(simulado.pedidas)), (13, 13, 13))
        for p in simulado.pedidas[1:]:
            partes = urllib.parse.urlsplit(p.url)
            self.assertEqual((partes.scheme, partes.netloc), ('https', 'index.commoncrawl.org'))  # nunca cdx-api
            self.assertEqual(urllib.parse.parse_qs(partes.query), {
                'url': ['*.acme-demo.mx'], 'output': ['json'], 'fl': ['url'], 'limit': ['5000']})
            self.assertEqual(p.tope, subfinder.MAX_BYTES_CDX)
        self.assertEqual(simulado.pedidas[0].tope, subfinder.MAX_BYTES_COLLINFO)
        for p in simulado.pedidas:
            self.assertEqual(p.cabeceras.get('User-agent'), contrato.AGENTE)

    def test_2_un_404_sin_capturas_no_corta_la_busqueda(self):
        """La causa del 15 nov: subfinder dejaba de buscar en el primer 404 y escondía los índices que sí tenían."""
        capturas = {RECIENTES[-1]: ['https://viejo.acme-demo.mx/']}  # solo el último índice tiene capturas
        simulado = CdxSimulado(capturas)
        res, _ = recolectar(simulado)
        self.assertEqual(simulado.indices(), RECIENTES)
        self.assertEqual([a.valor for a in res.activos], ['viejo.acme-demo.mx'])
        self.assertEqual((res.estado, res.avisos), ('succeeded', []))

    def test_3_sin_capturas_en_ningun_indice_es_succeeded_con_su_aviso(self):
        res, _ = recolectar(CdxSimulado({}))
        self.assertEqual((res.estado, res.activos, res.consultas), ('succeeded', [], 13))
        self.assertEqual(res.avisos, [subfinder.SIN_CAPTURAS % 12])
        self.assertEqual(res.avisos, ['subfinder: Common Crawl no tiene capturas de este dominio en sus últimos 12 '
                                      'índices'])
        solo_dominio, _ = recolectar(CdxSimulado({RECIENTES[2]: ['https://acme-demo.mx/']}))
        self.assertEqual((solo_dominio.activos, solo_dominio.avisos), ([], []))  # sí hay capturas, del dominio

    def test_4_espera_un_segundo_entre_peticion_y_peticion(self):
        _, c = recolectar(CdxSimulado(), cronometro=Cronometro(0))   # el cronómetro no avanza: falta el segundo entero
        self.assertEqual(c.dormidas, [subfinder.PAUSA] * 12)
        self.assertEqual(subfinder.PAUSA, 1.0)

    def test_5_menos_indices_en_collinfo_revisa_los_que_hay(self):
        simulado = CdxSimulado({}, collinfo=json.dumps([{'id': 'CC-MAIN-2026-47'}, {'id': 'CC-MAIN-2026-43'}]))
        res, _ = recolectar(simulado)
        self.assertEqual((simulado.indices(), res.consultas), (['CC-MAIN-2026-47', 'CC-MAIN-2026-43'], 3))
        self.assertEqual(res.avisos, [subfinder.SIN_CAPTURAS % 2])

    def test_6_un_indice_que_llega_al_tope_de_capturas_avisa(self):
        muchas = ['https://n%d.acme-demo.mx/' % (i % 7) for i in range(subfinder.LIMITE_FILAS)]
        res, _ = recolectar(CdxSimulado({RECIENTES[1]: muchas}))
        self.assertEqual(len(res.activos), 7)
        self.assertEqual(res.avisos, ['subfinder: el índice %s llegó al tope de 5000 capturas, la lista puede estar '
                                      'incompleta' % RECIENTES[1]])
        res, _ = recolectar(CdxSimulado({RECIENTES[1]: muchas, RECIENTES[4]: muchas}))
        self.assertEqual(res.avisos, ['subfinder: 2 índices llegaron al tope de 5000 capturas, la lista puede '
                                      'estar incompleta'])

    def test_7_capturas_que_no_se_pueden_leer_se_saltan_con_aviso(self):
        crudo = {RECIENTES[0]: b'{roto\n["no", "objeto"]\n{"sin": "url"}\n{"url": 5}\n\n'
                               b'{"url": "https://ok.acme-demo.mx/"}'}
        res, _ = recolectar(CdxSimulado({}, crudo=crudo))
        self.assertEqual([a.valor for a in res.activos], ['ok.acme-demo.mx'])
        self.assertEqual(res.avisos, ['subfinder: se saltaron 4 capturas del CDX que no se pudieron leer'])

    def test_8_un_200_sin_ninguna_captura_legible_es_falla(self):
        """Un 200 vacío o en otro formato no dice si el índice tiene capturas: no cuenta como revisado."""
        for cuerpo in (b'', b'\n \n', b'com,acme-demo)/ 20250101000000 {"status": "200"}\n{roto'):
            with self.subTest(cuerpo=cuerpo):
                simulado = CdxSimulado(crudo={RECIENTES[5]: cuerpo})
                res = por_ejecutar(simulado)
                self.assertEqual((res.estado, res.consultas), ('failed', 7))
                self.assertIn('Common Crawl no dio ninguna captura legible en %s' % RECIENTES[5], res.error)
                self.assertEqual(simulado.indices(), RECIENTES[:6])   # corta ahí: faltaría ese índice


class Fallas(unittest.TestCase):

    def test_1_un_indice_que_no_responde_deja_la_corrida_failed_sin_el_cuerpo_ni_la_url(self):
        for falla, motivo in ((503, 'HTTP 503'), (429, 'HTTP 429'), (403, 'HTTP 403'),
                              (501, 'HTTP 501'), (ConnectionResetError(), 'ConnectionResetError'),
                              (transporte.Redirigida(301, 'index.commoncrawl.org'), 'Redirigida'),
                              (ValueError('respuesta de más de 4194304 bytes'), 'ValueError')):
            with self.subTest(falla=falla):
                simulado = CdxSimulado(fallas={RECIENTES[5]: falla})
                res = por_ejecutar(simulado)
                self.assertEqual(res.estado, 'failed')
                self.assertEqual(res.error, 'FuenteNoResponde: subfinder: Common Crawl no respondió en %s (%s)'
                                 % (RECIENTES[5], motivo))
                self.assertEqual(res.consultas, 7)          # collinfo y los 6 índices hasta el que falló
                self.assertEqual(simulado.indices(), RECIENTES[:6])  # no sigue gastando peticiones

    def test_2_un_404_sin_no_captures_found_si_es_falla(self):
        res = por_ejecutar(CdxSimulado(fallas={RECIENTES[0]: 404}))
        self.assertEqual(res.estado, 'failed')
        self.assertIn('HTTP 404', res.error)

    def test_3_collinfo_que_no_sirve(self):
        for simulado, texto in ((CdxSimulado(fallas={'collinfo': 503}), 'collinfo.json (HTTP 503)'),
                                (CdxSimulado(fallas={'collinfo': 404}), 'collinfo.json (HTTP 404)'),
                                (CdxSimulado(collinfo='{roto'), 'no es JSON'),
                                (CdxSimulado(collinfo='{"id": "CC-MAIN-2026-47"}'), 'no es una lista'),
                                (CdxSimulado(collinfo='[{"id": "otro"}]'), 'ningún índice')):
            with self.subTest(texto=texto):
                res = por_ejecutar(simulado)
                self.assertEqual((res.estado, res.consultas), ('failed', 1))
                self.assertIn(texto, res.error)
                self.assertEqual(simulado.indices(), [])

    def test_4_toda_la_corrida_tiene_su_tiempo_maximo(self):
        simulado = CdxSimulado()
        c = cliente(cronometro=Cronometro(40))   # cada lectura del cronómetro avanza 40 s
        with con_cdx(simulado):
            datos = c.enumerar('acme-demo.mx')
        # Corta antes de pedir los 12 índices, y lo revisado no se pierde: los que faltan quedan sin revisar.
        self.assertLess(c.consultas, 1 + subfinder.INDICES)
        faltan = datos['indices'][len(datos['revisados']):]
        self.assertEqual(datos['revisados'], RECIENTES[:len(datos['revisados'])])
        self.assertTrue(datos['revisados'] and faltan)
        self.assertIn(subfinder.SIN_TIEMPO % (subfinder.MAX_SEGUNDOS, ', '.join(faltan)), datos['avisos'])
        for p in simulado.pedidas:   # cada plazo es a lo más 30 s y nunca pasa del fin de la corrida
            self.assertLessEqual(p.plazo, 1000.0 + subfinder.MAX_SEGUNDOS)

    def test_5_el_plazo_de_cada_peticion_es_de_30_s(self):
        simulado = CdxSimulado()
        recolectar(simulado, cronometro=Cronometro(0))
        self.assertEqual({p.plazo for p in simulado.pedidas}, {1000.0 + subfinder.TIMEOUT_PETICION})

    def test_6_un_dominio_invalido_no_pide_nada(self):
        res = subfinder.recolectar('no valido', subfinder.ClienteSubfinder(descargar=sin_red))
        self.assertEqual(res.estado, 'failed')
        res = contrato.ejecutar(cargar('subfinder'), '../acme-demo.mx', modo='grabar')  # ni crea el cliente
        self.assertEqual(res.estado, 'failed')
        self.assertIn('dominio inválido', res.error)


class Reloj:
    """Hace las veces de time.monotonic con una hora que solo cambia a mano."""

    def __init__(self):
        self.ahora = 1000.0

    def __call__(self):
        return self.ahora


class IndiceSaltado(unittest.TestCase):
    """El 16 nov CC-MAIN-2026-43 dio 504 dos veces en una hora y la corrida entera quedaba failed sin grabar."""

    def test_1_un_500_502_504_sin_intentos_o_plazo_vencido_se_salta_y_sigue_con_los_demas(self):
        for falla, motivo, intentos in ((504, 'HTTP 504 tras 3 intentos', 3), (502, 'HTTP 502 tras 3 intentos', 3),
                                        (500, 'HTTP 500 tras 3 intentos', 3),
                                        (transporte.PlazoVencido('x'), 'PlazoVencido', 1)):
            with self.subTest(falla=falla):
                simulado = CdxSimulado(fallas={RECIENTES[3]: falla})   # el índice con api.acme-demo.mx
                res = por_ejecutar(simulado)
                self.assertEqual((res.estado, res.error, res.consultas), ('succeeded', '', 12 + intentos))
                self.assertEqual(simulado.indices(), RECIENTES[:3] + [RECIENTES[3]] * intentos + RECIENTES[4:])
                self.assertEqual([a.valor for a in res.activos], ['dev.acme-demo.mx', 'www.acme-demo.mx'])
                self.assertEqual(res.avisos, [subfinder.SALTADOS % ('%s (%s)' % (RECIENTES[3], motivo))])
                self.assertEqual(res.avisos, ['subfinder: Common Crawl no respondió en %s (%s), se revisaron los '
                                              'demás índices' % (RECIENTES[3], motivo)])
                self.assertEqual(res.revisados, RECIENTES[:3] + RECIENTES[4:])
                self.assertEqual(res.sin_revisar, [RECIENTES[3]])

    def test_2_sin_capturas_cuenta_solo_los_indices_revisados(self):
        res = por_ejecutar(CdxSimulado({}, fallas={RECIENTES[0]: 504, RECIENTES[7]: 502}))
        self.assertEqual((res.estado, res.activos), ('succeeded', []))
        saltados = '%s (HTTP 504 tras 3 intentos), %s (HTTP 502 tras 3 intentos)' % (RECIENTES[0], RECIENTES[7])
        self.assertEqual(res.avisos, [subfinder.SALTADOS % saltados, subfinder.SIN_CAPTURAS % 10])
        self.assertEqual(res.sin_revisar, [RECIENTES[0], RECIENTES[7]])

    def test_3_sin_ningun_indice_revisado_es_failed(self):
        """Con todo caído, los 12 reintentos de la corrida se van en los 6 primeros índices y los demás se piden una
        vez: 25 peticiones y no 37 (ni 148 con los 4 intentos del orquestador)."""
        simulado = CdxSimulado(fallas={i: 504 for i in RECIENTES})
        c = cliente(cronometro=Cronometro(0))
        with con_cdx(simulado), self.assertRaises(contrato.FuenteNoResponde) as error:
            c.enumerar('acme-demo.mx')
        self.assertEqual(c.consultas, subfinder.MAX_CONSULTAS)
        self.assertEqual(c.consultas, 25)   # collinfo.json, los 3 intentos de 6 índices y 1 de los otros 6
        self.assertEqual(simulado.indices(), [i for i in RECIENTES[:6] for _ in range(3)] + RECIENTES[6:])
        self.assertEqual([d for d in c.dormidas if d != subfinder.PAUSA], [15, 30] * 6)
        self.assertIn('Common Crawl no respondió en ninguno de sus 12 índices (%s (HTTP 504 tras 3 intentos), '
                      % RECIENTES[0], str(error.exception))
        self.assertIn('%s (HTTP 504 tras 3 intentos), %s (HTTP 504, sin reintentos en la corrida), '
                      % (RECIENTES[5], RECIENTES[6]), str(error.exception))
        res = por_ejecutar(CdxSimulado(fallas={i: 504 for i in RECIENTES}))
        self.assertEqual((res.estado, res.consultas, res.activos), ('failed', 25, []))

    def test_4_una_falla_que_no_se_salta_sigue_cortando_aunque_antes_se_saltara_otro(self):
        simulado = CdxSimulado(fallas={RECIENTES[1]: 504, RECIENTES[5]: 503})
        res = por_ejecutar(simulado)
        self.assertEqual((res.estado, res.consultas), ('failed', 9))
        self.assertIn('no respondió en %s (HTTP 503)' % RECIENTES[5], res.error)
        self.assertEqual(simulado.indices(), RECIENTES[:1] + [RECIENTES[1]] * 3 + RECIENTES[2:6])

    def test_5_un_plazo_vencido_al_final_de_la_corrida_queda_sin_revisar_por_tiempo(self):
        """Si se acabó MAX_SEGUNDOS, ese índice no se revisó por falta de tiempo (SIN_TIEMPO, no SALTADOS) y los 11
        revisados no se pierden."""
        reloj = Reloj()

        def lento(url, plazo, tope, cronometro):
            if RECIENTES[11] in url:   # el último índice se come lo que quedaba de la corrida
                reloj.ahora = 1000.0 + subfinder.MAX_SEGUNDOS
                raise transporte.PlazoVencido('x')
            return subfinder._descargar(url, plazo, tope, cronometro)

        c = cliente(cronometro=reloj)
        c.descargar = lento
        with con_cdx(CdxSimulado()):
            res = subfinder.recolectar('acme-demo.mx', c, AHORA)
        self.assertEqual(res.avisos, [subfinder.SIN_TIEMPO % (subfinder.MAX_SEGUNDOS, RECIENTES[11])])
        self.assertEqual((res.revisados, res.sin_revisar), (RECIENTES[:11], [RECIENTES[11]]))
        self.assertEqual([a.valor for a in res.activos], ['api.acme-demo.mx', 'www.acme-demo.mx'])
        self.assertEqual(c.consultas, 13)

    def test_5b_sin_tiempo_y_sin_ningun_revisado_es_failed(self):
        """Sin tiempo antes del primer índice, o con el único intento saltado, nada revisado: FuenteNoResponde."""
        # (segundos que deja collinfo.json, segundos que deja el 504 del primer índice, error, consultas)
        casos = ((0, None, 'subfinder: Common Crawl no terminó en %d s (faltó %s)' % (subfinder.MAX_SEGUNDOS,
                                                                                      RECIENTES[0]), 1),
                 (30, 10, 'subfinder: Common Crawl no respondió en ninguno de sus 12 índices (%s (HTTP 504, sin tiempo '
                          'para reintentar), sin tiempo para %s)' % (RECIENTES[0], ', '.join(RECIENTES[1:])), 2))
        for tras_collinfo, tras_504, texto, consultas in casos:
            with self.subTest(tras_collinfo=tras_collinfo):
                reloj = Reloj()
                fin = 1000.0 + subfinder.MAX_SEGUNDOS

                def falla(url, plazo, tope, cronometro):
                    if url == subfinder.COLLINFO:
                        reloj.ahora = fin - tras_collinfo
                        return COLLINFO.encode('utf-8')
                    if tras_504 is not None and RECIENTES[0] in url:
                        reloj.ahora = fin - tras_504
                        raise http(url, 504)
                    raise AssertionError('pidió %s sin tiempo' % url)

                c = cliente(cronometro=reloj)
                c.descargar = falla
                with self.assertRaises(contrato.FuenteNoResponde) as error:
                    c.enumerar('acme-demo.mx')
                self.assertEqual(str(error.exception), texto)
                self.assertEqual(c.consultas, consultas)
                self.assertEqual([d for d in c.dormidas if d != subfinder.PAUSA], [])

    def test_6_collinfo_con_504_no_se_salta(self):
        res = por_ejecutar(CdxSimulado(fallas={'collinfo': 504}))
        self.assertEqual((res.estado, res.consultas), ('failed', 1))
        self.assertIn('collinfo.json (HTTP 504)', res.error)

    def test_7_se_graba_y_reproduce_con_los_mismos_revisados(self):
        with tempfile.TemporaryDirectory() as d:
            grabado = por_ejecutar(CdxSimulado(fallas={RECIENTES[3]: 504}), 'grabar', d)
            archivo = json.loads((Path(d) / 'acme-demo.mx' / 'subfinder_acme-demo.mx.json').read_text(encoding='utf-8'))
            self.assertEqual(set(archivo['datos']), {'lineas', 'avisos', 'indices', 'revisados'})
            otra = por_ejecutar(sin_red, 'reproducir', d)
        self.assertEqual((otra.estado, otra.consultas), ('succeeded', 0))
        self.assertEqual((otra.activos, otra.avisos, otra.revisados, otra.sin_revisar),
                         (grabado.activos, grabado.avisos, grabado.revisados, grabado.sin_revisar))
        self.assertEqual(otra.sin_revisar, [RECIENTES[3]])

    def test_8_sin_saltos_no_lleva_revisados(self):
        res = por_ejecutar(CdxSimulado())
        self.assertEqual((res.revisados, res.sin_revisar), (None, None))

    def test_9_revisados_de_una_grabacion_que_no_cuadran_es_failed(self):
        bien = {'lineas': [], 'avisos': [], 'indices': RECIENTES[:3]}
        for revisados in ('CC-MAIN-2026-47', [], [RECIENTES[0], RECIENTES[0]], ['CC-MAIN-2019-01'], RECIENTES[:3],
                          [5], ['../x']):
            with self.subTest(revisados=revisados), tempfile.TemporaryDirectory() as d:
                contrato.Grabadora(Path(d) / 'acme-demo.mx', 'grabar').guardar(
                    'subfinder:acme-demo.mx', dict(bien, revisados=revisados))
                res = por_ejecutar(sin_red, 'reproducir', d)
                self.assertEqual(res.estado, 'failed')
                self.assertIn('no se puede leer', res.error)
        with tempfile.TemporaryDirectory() as d:   # sin 'indices' tampoco
            contrato.Grabadora(Path(d) / 'acme-demo.mx', 'grabar').guardar(
                'subfinder:acme-demo.mx', {'lineas': [], 'avisos': [], 'revisados': [RECIENTES[0]]})
            self.assertEqual(por_ejecutar(sin_red, 'reproducir', d).estado, 'failed')


class Reintento(unittest.TestCase):
    """El 16 nov el nginx del índice cortó a los ~10 s con 504 o 502 y la misma consulta respondió 15 s después: un
    500, 502 o 504 se pide otra vez tras 15 s y tras 30 s antes de saltar el índice."""

    def test_1_un_504_que_luego_responde_revisa_el_indice(self):
        for fallas, esperas in (([504], [15]), ([502, 500], [15, 30])):
            with self.subTest(fallas=fallas):
                simulado = CdxSimulado(fallas={RECIENTES[3]: list(fallas)})   # el índice con api.acme-demo.mx
                res, c = recolectar(simulado, cronometro=Cronometro(0))
                self.assertEqual((res.estado, res.error, res.avisos), ('succeeded', '', []))
                self.assertEqual([a.valor for a in res.activos], ['api.acme-demo.mx', 'dev.acme-demo.mx',
                                                                  'www.acme-demo.mx'])
                self.assertEqual((res.revisados, res.sin_revisar), (None, None))
                self.assertEqual(simulado.indices(), RECIENTES[:3] + [RECIENTES[3]] * (1 + len(fallas)) +
                                 RECIENTES[4:])
                self.assertEqual(res.consultas, 13 + len(fallas))
                # la PAUSA antes de cada petición y, entre los intentos, la espera creciente
                self.assertEqual([d for d in c.dormidas if d != subfinder.PAUSA], esperas)
                self.assertEqual(c.dormidas[:5], [subfinder.PAUSA] * 4 + [15])

    def test_2_reintentos_que_se_acaban_saltan_el_indice(self):
        simulado = CdxSimulado(fallas={RECIENTES[3]: [504, 504, 502]})
        res, c = recolectar(simulado, cronometro=Cronometro(0))
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.avisos, ['subfinder: Common Crawl no respondió en %s (HTTP 502 tras 3 intentos), se '
                                      'revisaron los demás índices' % RECIENTES[3]])
        self.assertEqual(res.sin_revisar, [RECIENTES[3]])
        self.assertEqual(res.consultas, 15)
        self.assertEqual([d for d in c.dormidas if d != subfinder.PAUSA], [15, 30])   # no hay un cuarto intento

    def test_3_503_429_y_los_demas_codigos_no_se_reintentan(self):
        for codigo in (503, 429, 501, 403):
            with self.subTest(codigo=codigo):
                simulado = CdxSimulado(fallas={RECIENTES[3]: [codigo]})   # el segundo intento sí respondería
                c = cliente(cronometro=Cronometro(0))
                with con_cdx(simulado), self.assertRaises(contrato.FuenteNoResponde) as error:
                    c.enumerar('acme-demo.mx')
                self.assertIn('no respondió en %s (HTTP %d)' % (RECIENTES[3], codigo), str(error.exception))
                self.assertEqual(simulado.indices(), RECIENTES[:4])
                self.assertEqual(c.consultas, 5)
                self.assertEqual(set(c.dormidas), {subfinder.PAUSA})

    def test_4_un_plazo_vencido_no_se_reintenta(self):
        simulado = CdxSimulado(fallas={RECIENTES[3]: [transporte.PlazoVencido('x')]})
        res, c = recolectar(simulado, cronometro=Cronometro(0))
        self.assertEqual(res.sin_revisar, [RECIENTES[3]])
        self.assertEqual((res.consultas, set(c.dormidas)), (13, {subfinder.PAUSA}))

    def test_5_un_reintento_que_no_cabe_salta_el_indice_sin_perder_los_revisados(self):
        """El reintento solo va si caben su espera, la PAUSA y MINIMO_INTENTO (20 s) antes del fin. Si no cabe, el
        índice se salta. Con menos de 20 s tampoco se pide el índice siguiente: los que faltan quedan sin revisar."""
        minimo = subfinder.ESPERAS[0] + subfinder.PAUSA + subfinder.MINIMO_INTENTO   # 36 s
        # (segundos que deja el primer 504, esperas, consultas, motivo del saltado, los que quedan sin tiempo)
        casos = ((10, [], 5, 'HTTP 504, sin tiempo para reintentar', RECIENTES[4:]),
                 (minimo - 1, [], 13, 'HTTP 504, sin tiempo para reintentar', []),
                 (minimo, [15], 14, 'HTTP 504 tras 2 intentos, sin tiempo para reintentar', []))
        for queda, esperas, consultas, motivo, faltan in casos:
            with self.subTest(queda=queda):
                reloj = Reloj()

                def falla(url, plazo, tope, cronometro):
                    if RECIENTES[3] in url:
                        if reloj.ahora == 1000.0:   # el primer 504 llega cuando quedan `queda` segundos
                            reloj.ahora = 1000.0 + subfinder.MAX_SEGUNDOS - queda
                        raise http(url, 504)
                    return subfinder._descargar(url, plazo, tope, cronometro)

                c = cliente(cronometro=reloj)
                c.descargar = falla
                with con_cdx(CdxSimulado()):
                    res = subfinder.recolectar('acme-demo.mx', c, AHORA)
                avisos = [subfinder.SALTADOS % ('%s (%s)' % (RECIENTES[3], motivo))]
                if faltan:
                    avisos.append(subfinder.SIN_TIEMPO % (subfinder.MAX_SEGUNDOS, ', '.join(faltan)))
                self.assertEqual(res.avisos, avisos)
                self.assertEqual(res.sin_revisar, [RECIENTES[3]] + faltan)
                self.assertEqual([d for d in c.dormidas if d != subfinder.PAUSA], esperas)
                self.assertEqual(c.consultas, consultas)

    def test_6_la_espera_va_fuera_del_turno_del_proceso(self):
        ritmo = subfinder.Ritmo()
        en_turno = []

        def dormir(segundos):
            if segundos in subfinder.ESPERAS:
                en_turno.append(ritmo.candado.locked())

        c = subfinder.ClienteSubfinder(cronometro=Cronometro(0), dormir=dormir, ritmo=ritmo)
        with con_cdx(CdxSimulado(fallas={RECIENTES[3]: [504, 504]})):
            c.enumerar('acme-demo.mx')
        self.assertEqual(en_turno, [False, False])

    def test_7_el_tiempo_de_la_corrida_cabe_en_el_peor_caso_y_en_el_tope_del_orquestador(self):
        """Peor caso de una corrida sola: las MAX_CONSULTAS peticiones llegan a TIMEOUT_PETICION (un 500, 502 o 504
        puede llegar hasta ahí), cada una con su PAUSA, y la bolsa de reintentos se gasta en pares con las 2 esperas."""
        # el orquestador pide la base al importarse: su TOPE_CORRIDA se lee del código
        texto = (RAIZ / 'cirdan' / 'orquestador' / '__init__.py').read_text(encoding='utf-8')
        tope = re.search(r'^TOPE_CORRIDA = timedelta\(minutes=(\d+)\)', texto, re.MULTILINE)
        self.assertIsNotNone(tope)
        self.assertEqual((subfinder.ESPERAS, subfinder.REINTENTOS), ((15, 30), 12))
        esperas = (subfinder.REINTENTOS // 2) * sum(subfinder.ESPERAS) + (subfinder.REINTENTOS % 2) * 15   # 270 s
        peor = subfinder.MAX_CONSULTAS * (subfinder.TIMEOUT_PETICION + subfinder.PAUSA) + esperas
        self.assertEqual(peor, 1045)
        self.assertLessEqual(peor, subfinder.MAX_SEGUNDOS)
        observado = subfinder.MAX_CONSULTAS * (10.5 + subfinder.PAUSA) + esperas   # el 504 a ~10.5 s del 16 nov
        self.assertLess(observado, 600)
        self.assertLess(subfinder.MAX_SEGUNDOS, 60 * int(tope.group(1)))

    def test_8_una_falla_distinta_en_el_reintento(self):
        """Un 503 o un 429 en el reintento cortan la corrida, como en el primer intento. Un plazo vencido en el
        reintento salta el índice con cuántos intentos llevaba."""
        for segunda in (503, 429):
            with self.subTest(segunda=segunda):
                simulado = CdxSimulado(fallas={RECIENTES[3]: [504, segunda]})
                c = cliente(cronometro=Cronometro(0))
                with con_cdx(simulado), self.assertRaises(contrato.FuenteNoResponde) as error:
                    c.enumerar('acme-demo.mx')
                self.assertIn('no respondió en %s (HTTP %d)' % (RECIENTES[3], segunda), str(error.exception))
                self.assertEqual(simulado.indices(), RECIENTES[:4] + [RECIENTES[3]])
                self.assertEqual(c.consultas, 6)
        simulado = CdxSimulado(fallas={RECIENTES[3]: [504, transporte.PlazoVencido('x')]})
        res, c = recolectar(simulado, cronometro=Cronometro(0))
        self.assertEqual(res.avisos, [subfinder.SALTADOS % ('%s (PlazoVencido tras 2 intentos)' % RECIENTES[3])])
        self.assertEqual((res.sin_revisar, res.consultas), ([RECIENTES[3]], 14))
        self.assertEqual([d for d in c.dormidas if d != subfinder.PAUSA], [15])


class RitmoDelProceso(unittest.TestCase):
    """La pausa y el turno son de todo el proceso, no de cada corrida: la API corre cada escaneo en su hilo."""

    def test_1_los_clientes_del_orquestador_comparten_el_ritmo(self):
        self.assertIs(subfinder.crear_cliente('vivo', 'acme-demo.mx').ritmo, subfinder.RITMO)
        self.assertIs(subfinder.crear_cliente('grabar', 'otro.mx').ritmo, subfinder.RITMO)
        self.assertIs(subfinder.ClienteSubfinder().ritmo, subfinder.RITMO)

    def test_2_la_primera_peticion_de_otra_corrida_tambien_espera(self):
        ritmo, reloj = subfinder.Ritmo(), Cronometro(0)
        primera = cliente(cronometro=reloj, ritmo=ritmo)
        with con_cdx(CdxSimulado({})):
            primera.enumerar('acme-demo.mx')
        segunda = cliente(cronometro=reloj, ritmo=ritmo)
        with con_cdx(CdxSimulado({})):
            segunda.enumerar('otro.mx')
        self.assertEqual(primera.dormidas, [subfinder.PAUSA] * 12)
        self.assertEqual(segunda.dormidas, [subfinder.PAUSA] * 13)   # también antes de su collinfo.json

    def test_3_dos_corridas_en_hilos_nunca_piden_a_la_vez(self):
        estado, candado = {'activas': 0, 'maximo': 0, 'pedidas': 0}, threading.Lock()

        def lento(url, plazo, tope, cronometro):
            with candado:
                estado['activas'] += 1
                estado['pedidas'] += 1
                estado['maximo'] = max(estado['maximo'], estado['activas'])
            time.sleep(0.002)
            with candado:
                estado['activas'] -= 1
            if url == subfinder.COLLINFO:
                return COLLINFO.encode('utf-8')
            raise subfinder.SinCapturas()

        ritmo = subfinder.Ritmo()
        clientes = [subfinder.ClienteSubfinder(descargar=lento, dormir=lambda s: None, ritmo=ritmo) for _ in range(3)]
        hilos = [threading.Thread(target=c.enumerar, args=('acme-demo.mx',)) for c in clientes]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join(10)
        self.assertEqual((estado['maximo'], estado['pedidas']), (1, 3 * (1 + subfinder.INDICES)))
        self.assertEqual([c.consultas for c in clientes], [1 + subfinder.INDICES] * 3)

    def test_4_sin_turno_antes_del_fin_de_la_corrida_es_falla_sin_pedir(self):
        ritmo = subfinder.Ritmo()
        ritmo.candado.acquire()   # otra corrida tiene el turno
        try:
            # fin a 1000 + MAX_SEGUNDOS. Al pedir el turno quedan 0.05 s (de espera real) y después el reloj vuelve
            # a 1000: si no esperara el turno, pediría collinfo.json (sin_red)
            lecturas = iter([1000.0, 1000.0 + subfinder.MAX_SEGUNDOS - 0.05] + [1000.0] * 10)
            c = cliente(cronometro=lambda: next(lecturas), ritmo=ritmo)
            with con_cdx(sin_red), self.assertRaises(contrato.FuenteNoResponde) as error:
                c.enumerar('acme-demo.mx')
        finally:
            ritmo.candado.release()
        self.assertIn('no terminó en %d s (faltó collinfo.json)' % subfinder.MAX_SEGUNDOS, str(error.exception))
        self.assertEqual(c.consultas, 0)

    def test_4b_sin_turno_para_un_indice_deja_los_que_faltan_sin_revisar(self):
        """Otras corridas ocupan el turno hasta que solo quedan MINIMO_INTENTO segundos: los índices que faltan quedan
        sin revisar (SIN_TIEMPO) y los ya revisados no se pierden."""

        class Candado:
            def __init__(self):
                self.ocupado, self.plazos = False, []

            def acquire(self, timeout):
                self.plazos.append(timeout)
                return not self.ocupado

            def release(self):
                pass

        ritmo = SimpleNamespace(candado=Candado(), ultima=None)

        def ocupa(url, plazo, tope, cronometro):
            if RECIENTES[2] in url:   # después de este índice, el turno ya no llega a tiempo
                ritmo.candado.ocupado = True
            return subfinder._descargar(url, plazo, tope, cronometro)

        c = cliente(cronometro=Reloj(), ritmo=ritmo)
        c.descargar = ocupa
        with con_cdx(CdxSimulado()):
            res = subfinder.recolectar('acme-demo.mx', c, AHORA)
        self.assertEqual(res.avisos, [subfinder.SIN_TIEMPO % (subfinder.MAX_SEGUNDOS, ', '.join(RECIENTES[3:]))])
        self.assertEqual((res.revisados, res.sin_revisar), (RECIENTES[:3], RECIENTES[3:]))
        self.assertEqual([a.valor for a in res.activos], ['www.acme-demo.mx'])
        self.assertEqual(c.consultas, 4)
        # el turno de un CDX se espera solo hasta que queden MINIMO_INTENTO segundos
        self.assertEqual(ritmo.candado.plazos[-1], subfinder.MAX_SEGUNDOS - subfinder.MINIMO_INTENTO)

    def test_4c_un_503_que_llega_en_el_fin_de_la_corrida_corta(self):
        """Solo una falla que se salta pasa a SIN_TIEMPO al llegar en `fin`: un 503 sigue cortando la corrida."""
        reloj = Reloj()

        def tarde(url, plazo, tope, cronometro):
            if RECIENTES[3] in url:
                reloj.ahora = 1000.0 + subfinder.MAX_SEGUNDOS
                raise http(url, 503)
            return subfinder._descargar(url, plazo, tope, cronometro)

        c = cliente(cronometro=reloj)
        c.descargar = tarde
        with con_cdx(CdxSimulado()), self.assertRaises(contrato.FuenteNoResponde) as error:
            c.enumerar('acme-demo.mx')
        self.assertIn('no respondió en %s (HTTP 503)' % RECIENTES[3], str(error.exception))

    def test_5_una_falla_tambien_suelta_el_turno_y_marca_la_hora(self):
        ritmo = subfinder.Ritmo()
        with self.assertRaises(contrato.FuenteNoResponde):
            c = cliente(cronometro=Cronometro(0), ritmo=ritmo)
            with con_cdx(CdxSimulado(fallas={'collinfo': 503})):
                c.enumerar('acme-demo.mx')
        self.assertFalse(ritmo.candado.locked())
        self.assertEqual(ritmo.ultima, 1000.0)


class Descargar(unittest.TestCase):
    """subfinder._descargar con transporte.descargar simulado."""

    def test_1_pide_por_transporte_con_el_agente_y_el_plazo_y_tope_tal_cual(self):
        simulado = CdxSimulado()
        with con_cdx(simulado):
            cuerpo = subfinder._descargar(subfinder.COLLINFO, 1234.5, 99, None)
        self.assertEqual(cuerpo, COLLINFO.encode('utf-8'))
        (p,) = simulado.pedidas
        self.assertEqual((p.url, p.plazo, p.tope, p.cabeceras), (subfinder.COLLINFO, 1234.5, 99,
                                                                 {'User-agent': contrato.AGENTE}))

    def test_2_solo_el_404_con_no_captures_found_es_sin_capturas(self):
        url = subfinder.url_cdx(RECIENTES[0], 'acme-demo.mx')
        with con_cdx(CdxSimulado({})), self.assertRaises(subfinder.SinCapturas):
            subfinder._descargar(url, 1, 1, None)
        for codigo in (404, 503):
            with self.subTest(codigo=codigo), con_cdx(CdxSimulado(fallas={RECIENTES[0]: codigo})), \
                    self.assertRaises(urllib.error.HTTPError):
                subfinder._descargar(url, 1, 1, None)

    def test_3_el_transporte_real_verifica_tls_y_no_sigue_redirecciones(self):
        """subfinder.py usa transporte.descargar, el de rdap.py y shodan.py: https, sin proxies y solo el 443."""
        self.assertIs(subfinder.transporte, transporte)
        self.assertEqual(transporte.PUERTOS, frozenset({443}))
        with self.assertRaises(ValueError):   # http no sale
            transporte.descargar(urllib.request.Request('http://index.commoncrawl.org/collinfo.json'), 1, 1)


class GrabarYReproducir(unittest.TestCase):

    def test_1_grabar_y_reproducir_dan_lo_mismo_sin_red(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / 'acme-demo.mx'
            carpeta.mkdir()
            (carpeta / 'viejo.json').write_text('[]', encoding='utf-8')  # de una grabación anterior
            grabado, c = recolectar(CdxSimulado(), 'grabar', carpeta, nueva=True)
            self.assertEqual(c.consultas, 1 + subfinder.INDICES)
            self.assertFalse((carpeta / 'viejo.json').exists())
            self.assertIsNotNone(contrato.Grabadora.inicio(carpeta))
            archivo = json.loads((carpeta / 'subfinder_acme-demo.mx.json').read_text(encoding='utf-8'))
            self.assertEqual(set(archivo['datos']), {'lineas', 'avisos', 'indices'})
            self.assertEqual(archivo['datos']['indices'], RECIENTES)
            self.assertNotIn('8443', json.dumps(archivo))   # ni URLs ni puertos: solo hosts
            otra, c = recolectar(sin_red, 'reproducir', carpeta)
        self.assertEqual((c.consultas, otra.consultas), (0, 0))
        self.assertEqual((otra.activos, otra.avisos), (grabado.activos, grabado.avisos))

    def test_2_una_corrida_fallida_no_borra_la_grabacion_anterior(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / 'acme-demo.mx'
            recolectar(CdxSimulado(), 'grabar', carpeta, nueva=True)
            antes = (carpeta / 'subfinder_acme-demo.mx.json').read_bytes()
            with self.assertRaises(contrato.FuenteNoResponde):
                recolectar(CdxSimulado(fallas={RECIENTES[-1]: 503}), 'grabar', carpeta, nueva=True)
            self.assertEqual((carpeta / 'subfinder_acme-demo.mx.json').read_bytes(), antes)

    def test_2b_un_200_sin_capturas_legibles_no_pisa_la_grabacion_anterior(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / 'acme-demo.mx'
            recolectar(CdxSimulado(), 'grabar', carpeta, nueva=True)
            antes = (carpeta / 'subfinder_acme-demo.mx.json').read_bytes()
            with self.assertRaises(contrato.FuenteNoResponde):
                recolectar(CdxSimulado({}, crudo={RECIENTES[0]: b''}), 'grabar', carpeta, nueva=True)
            self.assertEqual((carpeta / 'subfinder_acme-demo.mx.json').read_bytes(), antes)
            self.assertIn(b'www.acme-demo.mx', antes)

    def test_3_cero_nombres_con_todos_los_indices_revisados_si_se_graba(self):
        """Lo que pedía el arreglo: ahora un 0 es de verdad (se revisaron los 12) y la demo lo reproduce."""
        with tempfile.TemporaryDirectory() as d:
            vacia = por_ejecutar(CdxSimulado({}), 'grabar', d)
            self.assertEqual((vacia.estado, vacia.activos), ('succeeded', []))
            otra = por_ejecutar(sin_red, 'reproducir', d)
        self.assertEqual((otra.estado, otra.activos, otra.avisos, otra.consultas),
                         ('succeeded', [], [subfinder.SIN_CAPTURAS % 12], 0))

    def test_4_reproducir_sin_grabacion_es_succeeded_con_aviso(self):
        res = por_ejecutar(sin_red, modo='reproducir')
        self.assertEqual((res.estado, res.error, res.activos, res.consultas), ('succeeded', '', [], 0))
        self.assertEqual(res.avisos, [subfinder.SIN_GRABACION_DOMINIO])
        self.assertEqual(res.avisos, ['subfinder: no hay grabación de Common Crawl de este dominio, no se revisó '
                                      'Common Crawl'])

    def test_5_por_ejecutar_graba_y_reproduce(self):
        with tempfile.TemporaryDirectory() as d:
            res = por_ejecutar(CdxSimulado(), 'grabar', d)
            self.assertEqual((res.estado, res.consultas), ('succeeded', 1 + subfinder.INDICES))
            otra = por_ejecutar(sin_red, 'reproducir', d)
        self.assertEqual((otra.estado, otra.consultas), ('succeeded', 0))
        self.assertEqual(otra.activos, res.activos)

    def test_6_una_grabacion_que_no_se_puede_leer_si_es_failed(self):
        with tempfile.TemporaryDirectory() as d:
            contrato.Grabadora(Path(d) / 'acme-demo.mx', 'grabar').guardar('subfinder:acme-demo.mx', ['otra', 'forma'])
            res = por_ejecutar(sin_red, 'reproducir', d)
        self.assertEqual(res.estado, 'failed')
        self.assertIn('no se puede leer', res.error)


class Consultas(unittest.TestCase):

    def test_1_collinfo_mas_12_indices_en_vivo_y_ninguna_al_reproducir(self):
        self.assertEqual(por_ejecutar(CdxSimulado()).consultas, 13)
        self.assertEqual(por_ejecutar(CdxSimulado({})).consultas, 13)   # un 404 también es una petición
        self.assertEqual(por_ejecutar(sin_red, 'reproducir').consultas, 0)

    def test_2_max_consultas_cuenta_un_cdx_por_indice_y_los_reintentos_de_la_corrida(self):
        self.assertEqual(subfinder.MAX_CONSULTAS, 1 + 12 + subfinder.REINTENTOS)
        self.assertEqual(subfinder.MAX_CONSULTAS, 25)
        # cada intento es una consulta, también los que dan 504
        self.assertEqual(por_ejecutar(CdxSimulado(fallas={RECIENTES[0]: [504], RECIENTES[5]: [502, 504]})).consultas,
                         16)


def fila_de_la_semilla(code):
    """{columna: valor} de la fila `code` en el INSERT INTO data_sources de la semilla 005, sin comentarios."""
    texto = re.sub(r'--[^\n]*', '', SEMILLA.read_text(encoding='utf-8'))
    insert = re.search(r'INSERT\s+INTO\s+data_sources\s*\(([^)]*)\)\s*VALUES(.*?)(?:ON\s+CONFLICT|;)', texto,
                       re.IGNORECASE | re.DOTALL)
    if not insert:
        return None
    columnas = [c.strip() for c in insert.group(1).split(',')]
    for valores in re.findall(r'\(([^()]*)\)', insert.group(2)):
        valores = [v.strip() for v in valores.split(',')]
        fila = dict(zip(columnas, valores))
        if len(valores) == len(columnas) and fila.get('code') == "'%s'" % code:
            return fila
    return None


class Semilla(unittest.TestCase):
    """Lectura estática de las semillas 005 y 017, sin base."""

    def test_1_la_005_lo_siembra_apagado_con_400(self):
        fila = fila_de_la_semilla('subfinder')
        self.assertIsNotNone(fila, 'la semilla 005 no trae la fila de subfinder en su INSERT INTO data_sources')
        self.assertEqual(fila['enabled'].lower(), 'false')
        self.assertEqual(int(fila['daily_limit']), 400)  # 50 corridas de las 8 fuentes de entonces

    def test_2_la_016_lo_prende_con_390_por_dia_sin_pisar_un_limite_puesto_a_mano(self):
        texto = re.sub(r'--[^\n]*', '', SEMILLA_017.read_text(encoding='utf-8'))
        cambios = re.findall(r"UPDATE\s+data_sources\s+SET\s+(\w+)\s*=\s*(\w+)\s+WHERE\s+code\s*=\s*'subfinder'"
                             r"\s+AND\s+(\w+)\s*=\s*(\w+)\s*;", texto, re.IGNORECASE)
        self.assertEqual(sorted(cambios), [('daily_limit', '390', 'daily_limit', '400'),
                                           ('enabled', 'true', 'enabled', 'false')])
        # El orquestador reserva MAX_CONSULTAS (25) antes de cada corrida y luego ajusta a las 13 de una sin fallas:
        # la corrida k reserva si 13 (k - 1) + 25 <= 390, o sea 29 por día (la 30 queda sin cupo). 15 reservas a la vez.
        limpia = 1 + subfinder.INDICES
        sin_fallas = (390 - subfinder.MAX_CONSULTAS) // limpia + 1
        self.assertEqual((sin_fallas, 390 // subfinder.MAX_CONSULTAS), (29, 15))
        self.assertGreater(limpia * sin_fallas + subfinder.MAX_CONSULTAS, 390)   # la 30: 377 + 25 = 402
        self.assertIn("RAISE EXCEPTION", texto)   # sin la fila de la 005 falla
        self.assertRegex(texto, r'daily_limit\s*<\s*%d\b' % subfinder.MAX_CONSULTAS)
        self.assertTrue(texto.lstrip().startswith("SET client_encoding = 'UTF8';"))
        self.assertEqual(sorted(p.name[:3] for p in SEMILLA_017.parent.glob('*.sql')).count('017'), 1)


@unittest.skipUnless((RAIZ / 'Dockerfile').exists(), 'sin Dockerfile: dentro de la imagen no se copia')
class Imagen(unittest.TestCase):
    """El Dockerfile le da respuestas_grabadas/subfinder/ al usuario cirdan y nada más (lectura estática)."""

    def test_1_chown_solo_de_la_grabacion_de_subfinder_antes_de_user_cirdan(self):
        texto = (RAIZ / 'Dockerfile').read_text(encoding='utf-8')
        chown = re.search(r'chown -R cirdan:cirdan (\S+)', texto)
        self.assertIsNotNone(chown, 'el Dockerfile no le da respuestas_grabadas/subfinder/ al usuario cirdan')
        self.assertEqual(chown.group(1), 'cirdan/recolectores/respuestas_grabadas/subfinder')
        self.assertEqual(len(re.findall(r'chown', texto)), 1)
        self.assertLess(texto.index('COPY cirdan/ cirdan/'), chown.start())
        self.assertLess(chown.start(), texto.index('USER cirdan'))


def sin_dns(host, *_, **__):
    """Hace las veces de socket.getaddrinfo sin red: el transporte real nunca llega a conectarse."""
    sin_dns.pedidos.append(host)
    raise socket.gaierror(socket.EAI_NONAME, 'sin red en la prueba')


@unittest.skipUnless(os.environ.get('INTEGRACION_SUBFINDER') == '1',
                     'corre dentro del contenedor con INTEGRACION_SUBFINDER=1')
class Integracion(unittest.TestCase):
    """Dentro de la imagen y como el usuario cirdan. El DNS va bloqueado en la propia prueba (socket.getaddrinfo
    falla), así que el transporte real no llega a Common Crawl aunque el contenedor tenga red, como en el paso del
    contenedor del CI: queda en FuenteNoResponde y no graba nada."""

    def test_1_sin_red_queda_failed_y_no_graba(self):
        sin_dns.pedidos = []
        with tempfile.TemporaryDirectory() as d, mock.patch.object(transporte.socket, 'getaddrinfo', sin_dns):
            carpeta = Path(d) / 'acme-demo.mx'
            c = subfinder.ClienteSubfinder(modo='grabar', carpeta=carpeta, nueva=True, dormir=lambda s: None)
            with self.assertRaises(contrato.FuenteNoResponde) as error:
                c.enumerar('acme-demo.mx')
            self.assertIn('Common Crawl no respondió en collinfo.json', str(error.exception))
            self.assertEqual(sin_dns.pedidos, ['index.commoncrawl.org'])   # pasó por el transporte real
            self.assertEqual(c.consultas, 1)
            self.assertFalse((carpeta / 'subfinder_acme-demo.mx.json').exists())
        res = contrato.ejecutar(cargar('subfinder'), 'acme-demo.mx', modo='reproducir')  # sin grabación: aviso
        self.assertEqual((res.estado, res.avisos), ('succeeded', [subfinder.SIN_GRABACION_DOMINIO]))

    def test_2_el_usuario_cirdan_escribe_en_la_grabacion_de_subfinder_y_no_en_las_demas_ni_en_el_codigo(self):
        if os.geteuid() == 0:
            self.skipTest('corre como root: no prueba los permisos del usuario cirdan')
        self.assertTrue(os.access(subfinder.CARPETA_GRABADAS, os.W_OK))
        self.assertFalse(os.access(contrato.CARPETA_GRABADAS, os.W_OK))
        self.assertFalse(os.access(contrato.CARPETA_GRABADAS / 'crtsh', os.W_OK))
        self.assertFalse(os.access(Path(subfinder.__file__), os.W_OK))
        self.assertFalse(os.access(Path(subfinder.__file__).parent, os.W_OK))


if __name__ == '__main__':
    unittest.main()
