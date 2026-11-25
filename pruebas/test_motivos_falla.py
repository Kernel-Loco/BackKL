"""RC-300: los escaneos solo dan motivos de falla de una lista fija, nunca el texto de una excepción. Sin red ni base.

    python -m unittest -v pruebas/test_motivos_falla.py
"""
import contextlib
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_motivos_falla.py
from cirdan import orquestador  # noqa: E402
from cirdan.orquestador import motivos  # noqa: E402
from cirdan.recolectores import contrato, crtsh, shodan, transporte  # noqa: E402

SCAN = '60000000-0000-4000-8000-0000000000aa'
# Un error de psycopg como el que da la base: tabla, restricción y los valores de la fila.
SECRETO = 'secreto-cliente.acme-demo.mx'
ERROR_BASE = psycopg.errors.UniqueViolation(
    'duplicate key value violates unique constraint "assets_organization_id_kind_value_key"\n'
    'DETAIL:  Key (organization_id, kind, value)=(11111111-1111-4111-8111-111111111111, subdomain, %s) already exists.'
    % SECRETO)
FRASE = 'Frase inventada del servidor %s' % SECRETO
PROFUNDO = b'[' * 10_000 + b']' * 10_000  # un JSON de 10 000 niveles


def recolector_que_lanza(error):
    """Un recolector mínimo del contrato cuyo recolectar() lanza `error`."""
    def recolectar(dominio, cliente, **_):
        raise error
    return SimpleNamespace(FUENTE='ejemplo', crear_cliente=lambda modo, dominio: SimpleNamespace(consultas=1),
                           recolectar=recolectar)


def http_error(codigo, frase=FRASE, cabeceras=None):
    return urllib.error.HTTPError('https://crt.sh/?q=%25.acme-demo.mx&output=json', codigo, frase, cabeceras or {}, None)


def falla_crtsh(respuesta, **kw):
    """El texto con el que ClienteCrtsh.pedir no pudo leer `respuesta` (una excepción que lanza o el cuerpo)."""
    def transporte(url, timeout):
        if isinstance(respuesta, BaseException):
            raise respuesta
        return respuesta
    cliente = crtsh.ClienteCrtsh(transporte=transporte, dormir=lambda s: None)
    with self_raises(crtsh.FuenteNoResponde) as error:
        cliente.pedir('%.acme-demo.mx', 'https://crt.sh/?q=%25.acme-demo.mx&output=json', **kw)
    return str(error[0])


@contextlib.contextmanager
def self_raises(tipo):
    atrapado = []
    try:
        yield atrapado
    except tipo as e:
        atrapado.append(e)
    if not atrapado:
        raise AssertionError('no lanzó %s' % tipo.__name__)


class Motivos(unittest.TestCase):

    def test_1_todo_texto_da_un_motivo_de_la_lista(self):
        casos = {
            None: None, '': None,
            'crt.sh no respondió': 'no respondió',
            'crt.sh no respondió a %.acme-demo.mx después de 2 intentos (HTTPError: HTTP 503)': 'no respondió (HTTP 503)',
            'HTTPError: HTTP Error 502: Bad Gateway': 'no respondió (HTTP 502)',
            'TimeoutError: shodan: www tardó más de 10 s en responder': 'no respondió',
            'URLError: <urlopen error [Errno -2] Name or service not known>': 'no respondió',
            'shodan: 1.2.3.4 llegó a su límite de consultas (429, Retry-After 30 s)': 'sin cupo (HTTP 429)',
            orquestador.SIN_CUPO % 'ct_logs': 'sin cupo',
            'shodan: la API de host respondió 403': 'consulta rechazada (HTTP 403)',
            'RespuestaIlegible: shodan: la API de host respondió 403': 'respuesta que no se puede leer (HTTP 403)',
            'HTTPError: HTTP 404': 'consulta rechazada (HTTP 404)',
            'RecursionError: maximum recursion depth exceeded while decoding a JSON array': 'respuesta que no se puede leer',
            'JSONDecodeError: Expecting value: line 1 column 1 (char 0)': 'respuesta que no se puede leer',
            'no quedó tiempo para consultar %acme-demo%': 'plazo vencido',
            'Fuente shodan no autorizada por la carta (actividad 7 del Anexo A).': 'no autorizada por la carta',
            'El escaneo se cortó: pasaron más de 30 minutos sin marca de vida': 'escaneo interrumpido',
            'no cumple el contrato: activo repetido': 'error interno',
            'KeyError: password': 'error interno',
            '%s: %s' % (type(ERROR_BASE).__name__, ERROR_BASE): 'error interno',
            # aunque el texto de la base diga otra cosa, es de la base
            'OperationalError: connection to server failed: no respondió (HTTP 503)': 'error interno',
        }
        for texto, esperado in casos.items():
            with self.subTest(texto=texto):
                self.assertEqual(motivos.motivo(texto), esperado)
                if esperado:
                    self.assertTrue(motivos.PATRON.fullmatch(esperado))
        for motivo in motivos.MOTIVOS:  # un motivo se queda igual, con o sin código
            self.assertEqual(motivos.motivo(motivo), motivo)
            self.assertEqual(motivos.motivo(motivo + ' (HTTP 500)'), motivo + ' (HTTP 500)')

    def test_2_publico_deja_solo_los_motivos_y_lo_demas_es_error_interno(self):
        for viejo in (str(ERROR_BASE), 'crt.sh no respondió', 'KeyboardInterrupt', 'no respondió (HTTP 999)',
                      'no respondió (HTTP 503) y más', ' no respondió', 12, ['no respondió']):
            with self.subTest(viejo=viejo):
                self.assertEqual(motivos.publico(viejo), 'error interno')
        for vigente in ('no respondió', 'sin cupo (HTTP 429)', 'error interno', 'escaneo interrumpido'):
            self.assertEqual(motivos.publico(vigente), vigente)
        self.assertIsNone(motivos.publico(None))
        self.assertEqual(orquestador.ERROR_ABANDONO, motivos.publico(orquestador.ERROR_ABANDONO))

    def test_3_un_error_de_psycopg_no_sale_en_las_dos_rutas(self):
        """ejecutar() guarda el texto para el log; lo que guarda el orquestador y lo que devuelven GET /scans y
        /scans/{id} (stats_publicas y fuentes_publicas) es 'error interno'."""
        res = contrato.ejecutar(recolector_que_lanza(ERROR_BASE), 'acme-demo.mx')
        self.assertEqual(res.estado, 'failed')
        self.assertIn(SECRETO, res.error)  # el detalle que va al log
        self.assertEqual(motivos.motivo(res.error), 'error interno')
        # una fila de antes de RC-300 que guardó ese texto, como la leen las dos rutas
        stats = orquestador.stats_publicas({'error': str(ERROR_BASE)[:300], 'queries': 4, 'findings': 0})
        fuentes = orquestador.fuentes_publicas([{'source': 'ct_logs', 'status': 'failed', 'error': res.error},
                                                {'source': 'dns_records', 'status': 'succeeded', 'error': None}])
        self.assertEqual(stats, {'error': 'error interno', 'findings': 0})
        self.assertEqual([f['error'] for f in fuentes], ['error interno', None])
        self.assertNotIn(SECRETO, repr((stats, fuentes)))
        # el portal sigue diciendo que falló: ScanButton.tsx revisa que stats.error tenga algo
        self.assertTrue(stats['error'])

    def test_4_marcar_fallido_guarda_error_interno_y_manda_el_texto_al_log(self):
        sql = []
        conn = SimpleNamespace(execute=lambda q, p=None: sql.append((q, p)))
        with mock.patch.object(orquestador, 'transaction', lambda org: contextlib.nullcontext(conn)), \
                self.assertLogs('cirdan.orquestador', 'ERROR') as logs:
            orquestador.marcar_fallido('11111111-1111-4111-8111-111111111111', SCAN, ERROR_BASE)
        self.assertNotIn(SECRETO, repr(sql))
        self.assertEqual(sql[0][1][0].obj, {'error': 'error interno'})  # scans.stats
        self.assertEqual(sql[1][1][0], 'error interno')                  # scan_source_runs.error de las que esperaban
        self.assertTrue(any(SCAN in linea and SECRETO in linea for linea in logs.output))
        self.assertTrue(all('\n' not in linea.split(':', 2)[2] for linea in logs.output))  # una línea (%r)


class CrtshYShodan(unittest.TestCase):

    def test_5_la_frase_http_de_crtsh_no_se_guarda(self):
        texto = falla_crtsh(http_error(503))
        self.assertNotIn('Frase inventada', texto)
        self.assertNotIn(SECRETO, texto)
        self.assertIn('HTTPError: HTTP 503', texto)
        self.assertEqual(motivos.motivo(texto), 'no respondió (HTTP 503)')
        texto = falla_crtsh(http_error(403))  # un 4xx corta los intentos: tampoco su frase
        self.assertNotIn('Frase inventada', texto)
        self.assertEqual(motivos.motivo(texto), 'consulta rechazada (HTTP 403)')

    def test_6_el_retry_after_de_crtsh_solo_entra_como_segundos(self):
        casos = (({'Retry-After': '120'}, 'Retry-After 120 s'),
                 ({'Retry-After': 'mañana <b>%s</b>' % SECRETO}, 'Retry-After ? s'),
                 ({'Retry-After': '-5'}, 'Retry-After ? s'),
                 ({'Date': 'Sun, 22 Nov 2026 12:00:00 GMT', 'Retry-After': 'Sun, 22 Nov 2026 12:00:30 GMT'},
                  'Retry-After 30 s'),
                 ({}, 'Retry-After ? s'))
        for cabeceras, esperado in casos:
            with self.subTest(cabeceras=cabeceras):
                texto = falla_crtsh(http_error(429, cabeceras=cabeceras), sin_reintento=(429,))
                self.assertIn('llegó a su límite de consultas, %s' % esperado, texto)
                self.assertNotIn(SECRETO, texto)
                self.assertNotIn('Frase inventada', texto)
                self.assertEqual(motivos.motivo(texto), 'sin cupo (HTTP 429)')

    def test_7_un_json_de_10000_niveles_en_crtsh_es_respuesta_que_no_se_puede_leer(self):
        texto = falla_crtsh(PROFUNDO)
        self.assertIn('JsonProfundo: respuesta que no se puede leer', texto)
        self.assertNotIn('maximum recursion', texto)
        self.assertEqual(motivos.motivo(texto), 'respuesta que no se puede leer')
        # por el contrato completo, como la deja el orquestador
        res = contrato.ejecutar(recolector_que_lanza(crtsh.FuenteNoResponde(texto)), 'acme-demo.mx')
        self.assertEqual(motivos.motivo(res.error), 'respuesta que no se puede leer')

    def test_8_un_json_de_10000_niveles_en_shodan_es_respuesta_que_no_se_puede_leer(self):
        cliente = shodan.ClienteShodan(descargar=lambda url, timeout: PROFUNDO, dormir=lambda s: None)
        with self.assertRaises(shodan.RespuestaIlegible) as error:
            cliente._http('https://internetdb.shodan.io/192.0.2.1', 1, 5, '192.0.2.1')
        self.assertNotIn('maximum recursion', str(error.exception))
        self.assertEqual(motivos.motivo('%s: %s' % (type(error.exception).__name__, error.exception)),
                         'respuesta que no se puede leer')

    def test_9_el_recursionerror_sin_atrapar_de_otra_fuente_tambien_es_ilegible(self):
        res = contrato.ejecutar(recolector_que_lanza(RecursionError('maximum recursion depth exceeded')), 'acme-demo.mx')
        self.assertEqual(motivos.motivo(res.error), 'respuesta que no se puede leer')


class JsonDe(unittest.TestCase):

    def test_10_json_de_lee_lo_normal_y_corta_en_el_tope(self):
        crt = b'[{"id": 1, "name_value": "a.acme-demo.mx\\nb.acme-demo.mx", "issuer_name": "C=US, O=\\"[{x\\"]"}]'
        self.assertEqual(transporte.json_de(crt)[0]['id'], 1)
        self.assertEqual(transporte.json_de('{"a": "]]]}}}[[[{{{", "b": [1, {"c": []}]}'),
                         {'a': ']]]}}}[[[{{{', 'b': [1, {'c': []}]})

        def nivel(n):
            return b'[' * n + b']' * n

        self.assertEqual(transporte.json_de(nivel(transporte.MAX_NIVELES_JSON)),
                         json.loads(nivel(transporte.MAX_NIVELES_JSON)))  # justo en el tope, se lee
        for cuerpo in (nivel(transporte.MAX_NIVELES_JSON + 1), PROFUNDO, b'{"a":' * 10_000 + b'1' + b'}' * 10_000):
            with self.subTest(largo=len(cuerpo)), self.assertRaises(transporte.JsonProfundo):
                transporte.json_de(cuerpo)
        self.assertTrue(issubclass(transporte.JsonProfundo, ValueError))
        with self.assertRaises(ValueError):  # lo que no es JSON sigue siendo JSONDecodeError
            transporte.json_de(b'<html>')


    def test_11_una_cadena_sin_cerrar_llena_de_comillas_escapadas_no_congela_la_api(self):
        # Revisión de riesgo de RC-300 (D1): contar los niveles con una expresión regular antes de leer tardaba 8 s
        # con 40 KB así, en forma cuadrática, con el GIL tomado. Ahora es lo que tarda json.loads en rechazarlo.
        import time
        cuerpo = b'"' + b'\\"' * 500_000  # 1 MB
        inicio = time.perf_counter()
        with self.assertRaises(ValueError):
            transporte.json_de(cuerpo)
        self.assertLess(time.perf_counter() - inicio, 1.0)

    def test_12_el_tope_de_niveles_vale_tambien_en_utf16_y_utf32(self):
        # D2: el conteo sobre los bytes se desfasaba con UTF-16 y dejaba pasar 10 000 niveles.
        profundo = '["\\"",' + '[' * 10_000 + ']' * 10_000 + ',"x"]'
        normal = '[{"id": 1, "name_value": "a.acme-demo.mx"}]'
        for codificacion in ('utf-8', 'utf-16-le', 'utf-16', 'utf-32'):
            with self.subTest(codificacion=codificacion):
                with self.assertRaises(transporte.JsonProfundo):
                    transporte.json_de(profundo.encode(codificacion))
                self.assertEqual(transporte.json_de(normal.encode(codificacion))[0]['id'], 1)

    def test_13_al_apagar_y_al_dejar_de_correr_queda_escaneo_interrumpido(self):
        # T3 y T5: también estos cierres guardan un motivo de la lista.
        sql = []
        conn = SimpleNamespace(execute=lambda q, p=None: sql.append((q, p)))
        with (mock.patch.object(orquestador, 'transaction', lambda org: contextlib.nullcontext(conn)),
              self.assertLogs('cirdan.orquestador', 'ERROR')):
            orquestador.marcar_fallido('11111111-1111-4111-8111-111111111111', SCAN, RuntimeError('x'),
                                       motivos.INTERRUMPIDO)
            orquestador.marcar_fallido('11111111-1111-4111-8111-111111111111', SCAN, RuntimeError('x'), 'texto suelto')
        self.assertEqual([sql[0][1][0].obj, sql[1][1][0]], [{'error': 'escaneo interrumpido'}, 'escaneo interrumpido'])
        self.assertEqual([sql[2][1][0].obj, sql[3][1][0]], [{'error': 'error interno'}, 'error interno'])
        from cirdan import programador
        vivo = SimpleNamespace(is_alive=lambda: True)
        # _reintentar_pronto abriría una conexión real a la base: aquí solo importa el motivo.
        with (mock.patch.dict(programador._hilos, {SCAN: ('org', vivo)}, clear=True),
              mock.patch.object(programador, '_reintentar_pronto') as reintentar,
              mock.patch.object(orquestador, 'marcar_fallido') as marcar):
            programador.detener()
        self.assertEqual(marcar.call_args.args[3], motivos.INTERRUMPIDO)
        reintentar.assert_called_once()
        cerradas = []
        fila = SimpleNamespace(fetchone=lambda: {'status': 'failed', 'stats': None})
        c = SimpleNamespace(execute=lambda q, p=None: fila)
        with (mock.patch.object(orquestador, '_tx', lambda org, conn: contextlib.nullcontext(c)),
              mock.patch.object(orquestador, '_cerrar_corridas', lambda c, ids, texto: cerradas.append(texto))):
            orquestador._ya_no_corre('org', SCAN, None, [])
        self.assertEqual(cerradas, [motivos.INTERRUMPIDO])
        self.assertIn(motivos.INTERRUMPIDO, motivos.MOTIVOS)


if __name__ == '__main__':
    unittest.main()
