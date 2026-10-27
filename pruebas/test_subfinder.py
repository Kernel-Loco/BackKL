"""Pruebas del recolector de subfinder (#14b, RC-184), sin red y sin el binario: un proceso simulado con la salida de
la misma forma que la real (-oJ -cs) y los avisos de stderr.

    python -m unittest -v pruebas/test_subfinder.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_subfinder.py
from pruebas.test_catalogo_reglas import POR_CODIGO  # noqa: E402
from pruebas.test_crtsh import AHORA  # noqa: E402
from cirdan.recolectores import REGISTRO, cargar, contrato, subfinder  # noqa: E402
from cirdan.recolectores.contrato import Activo  # noqa: E402

BINARIO = '/usr/local/bin/subfinder'
RAIZ = Path(__file__).resolve().parents[1]
SEMILLA = RAIZ / 'db' / 'semillas' / '005_subfinder_y_limites.sql'
PROHIBIDAS = ('-active', '-nW', '-oI', '-ip', '-all', '-r', '-rL', '-recursive', '-silent')


def linea(host, *fuentes, entrada='acme-demo.mx'):
    """Una línea de stdout con -oJ -cs."""
    return json.dumps({'host': host, 'input': entrada, 'sources': list(fuentes)})


SALIDA = [
    linea('www.acme-demo.mx', 'anubis', 'crtname'),
    linea('api.acme-demo.mx', 'hackertarget'),
    linea('WWW.ACME-DEMO.MX.', 'thc'),              # el mismo nombre con otra forma: se junta con el primero
    linea('*.dev.acme-demo.mx', 'rapiddns'),        # comodín: queda dev.acme-demo.mx
    linea('acme-demo.mx', 'anubis'),                # el propio dominio no es subdominio
]


def caida(fuente):
    """El aviso que subfinder escribe en stderr cuando una fuente falla."""
    return ('[WRN] Encountered an error with source %s: Get "https://%s.example/api?d=acme-demo.mx": '
            'dial tcp: lookup %s.example: no such host' % (fuente, fuente, fuente))


class SubfinderSimulado:
    """Hace las veces de subprocess.run: anota cada comando con sus opciones y responde lo que se le diga."""

    def __init__(self, salida=None, stderr='', codigo=0, lanza=None):
        self.salida = SALIDA if salida is None else salida
        self.stderr, self.codigo, self.lanza = stderr, codigo, lanza
        self.llamadas = []

    def __call__(self, comando, **opciones):
        casa = opciones.get('env', {}).get('HOME')
        self.llamadas.append((list(comando), dict(opciones), casa and os.path.isdir(casa)))
        if self.lanza:
            raise self.lanza
        return SimpleNamespace(returncode=self.codigo, stdout='\n'.join(self.salida) + '\n', stderr=self.stderr)


def sin_proceso(comando, **opciones):
    raise AssertionError('no debe correr subfinder: %s' % comando)


class Cronometro:
    """Hace las veces de time.monotonic: cada lectura avanza `paso` segundos, sin dormir de verdad."""

    def __init__(self, paso):
        self.paso, self.ahora = paso, 1000.0

    def __call__(self):
        actual, self.ahora = self.ahora, self.ahora + self.paso
        return actual


def recolectar(simulado, modo='vivo', carpeta=None, binario=BINARIO, nueva=False, cronometro=None):
    cliente = subfinder.ClienteSubfinder(modo=modo, carpeta=carpeta or subfinder.CARPETA_GRABADAS, ejecutar=simulado,
                                         binario=binario, nueva=nueva, cronometro=cronometro)
    return subfinder.recolectar('acme-demo.mx', cliente, AHORA), cliente


def por_ejecutar(simulado, modo='vivo', carpeta=None, binario=BINARIO):
    """Por contrato.ejecutar(), como lo llama el orquestador."""
    with tempfile.TemporaryDirectory() as d, mock.patch.object(subfinder, 'CARPETA_GRABADAS', Path(carpeta or d)), \
            mock.patch.object(subfinder, '_ejecutar', simulado), mock.patch.object(subfinder, '_binario', lambda: binario):
        return contrato.ejecutar(cargar('subfinder'), 'acme-demo.mx', modo=modo, ahora=AHORA)


class Activos(unittest.TestCase):

    def test_1_un_activo_subdomain_por_nombre_con_fuente_y_origen(self):
        res, _ = recolectar(SubfinderSimulado())
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.activos, [
            Activo('subdomain', 'api.acme-demo.mx', {'fuente': 'subfinder', 'origen': ['hackertarget']}),
            Activo('subdomain', 'dev.acme-demo.mx', {'fuente': 'subfinder', 'origen': ['rapiddns']}),
            Activo('subdomain', 'www.acme-demo.mx', {'fuente': 'subfinder', 'origen': ['anubis', 'crtname', 'thc']}),
        ])
        self.assertEqual((res.hallazgos, res.sin_cobertura, res.avisos), ([], [], []))
        for a in res.activos:  # nada de llaves de certificado
            self.assertEqual(set(a.atributos), {'fuente', 'origen'})

    def test_2_deduplica_y_junta_las_fuentes(self):
        salida = [linea('mail.acme-demo.mx', 'submd'), linea('mail.acme-demo.mx', 'anubis', 'submd'),
                  linea('Mail.Acme-Demo.mx', 'digitorus')]
        res, _ = recolectar(SubfinderSimulado(salida))
        self.assertEqual([(a.valor, a.atributos['origen']) for a in res.activos],
                         [('mail.acme-demo.mx', ['anubis', 'digitorus', 'submd'])])

    def test_3_comodines_y_nombres_invalidos(self):
        salida = [linea('*.*.vpn.acme-demo.mx', 'anubis'), linea('a_b.acme-demo.mx', 'anubis'),
                  linea('-x.acme-demo.mx', 'thc'), linea('portal.*.acme-demo.mx', 'thc'), linea('', 'thc')]
        res, _ = recolectar(SubfinderSimulado(salida))
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual([a.valor for a in res.activos], ['vpn.acme-demo.mx'])
        self.assertEqual(res.avisos, ['subfinder: se descartaron 4 nombres que no son nombres de dominio válidos'])
        self.assertEqual(contrato.validar(res), [])  # un nombre inválido no tumba la corrida

    def test_4_fuera_del_dominio_se_cuenta_y_no_se_nombra(self):
        salida = [linea('acme-demo.mx.ajeno.com', 'thc'), linea('otro.com', 'anubis'), linea('xacme-demo.mx', 'anubis'),
                  linea('ok.acme-demo.mx', 'anubis')]
        res, _ = recolectar(SubfinderSimulado(salida))
        self.assertEqual([a.valor for a in res.activos], ['ok.acme-demo.mx'])
        self.assertEqual(res.avisos, ['subfinder: se descartaron 3 nombres fuera del dominio'])
        for nombre in ('ajeno', 'otro.com'):  # el aviso cuenta los nombres, no los repite
            self.assertNotIn(nombre, ' '.join(res.avisos))
        uno, _ = recolectar(SubfinderSimulado([linea('otro.com', 'anubis')]))
        self.assertEqual(uno.avisos, ['subfinder: se descartó 1 nombre fuera del dominio'])

    def test_5_lineas_que_no_son_json_se_saltan_con_aviso(self):
        salida = ['[INF] Enumerating subdomains for acme-demo.mx', linea('ok.acme-demo.mx', 'anubis'), '{roto',
                  json.dumps(['no', 'es', 'objeto']), '']
        res, _ = recolectar(SubfinderSimulado(salida))
        self.assertEqual([a.valor for a in res.activos], ['ok.acme-demo.mx'])
        self.assertEqual(res.avisos, ['subfinder: se saltaron 3 líneas que no son JSON'])

    def test_6_validar_con_el_catalogo_y_codigos_vacio(self):
        self.assertEqual(subfinder.CODIGOS, {})
        res, _ = recolectar(SubfinderSimulado())
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        res = por_ejecutar(SubfinderSimulado())
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_7_esta_en_el_registro_con_su_carpeta(self):
        self.assertIs(cargar('subfinder'), subfinder)
        self.assertEqual(REGISTRO['subfinder'], 'cirdan.recolectores.subfinder')
        self.assertEqual(subfinder.FUENTE, 'subfinder')
        self.assertEqual(subfinder.CARPETA_GRABADAS, contrato.CARPETA_GRABADAS / 'subfinder')


class Fallas(unittest.TestCase):

    def test_1_una_fuente_caida_deja_un_aviso_corto(self):
        res, _ = recolectar(SubfinderSimulado(stderr='\n'.join([caida('anubis'), caida('anubis'), caida('thc')])))
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.avisos, ['subfinder: la fuente anubis no respondió', 'subfinder: la fuente thc no respondió'])
        self.assertFalse(any('http' in a or 'dial' in a or '.example' in a for a in res.avisos))

    def test_2_si_caen_todas_las_fuentes_queda_failed(self):
        stderr = '\n'.join(caida(f) for f in subfinder.FUENTES_SUBFINDER)
        res = por_ejecutar(SubfinderSimulado(salida=[], stderr=stderr))
        self.assertEqual(res.estado, 'failed')
        self.assertIn('ninguna', res.error)
        self.assertEqual((res.activos, res.consultas), ([], len(subfinder.FUENTES_SUBFINDER)))
        self.assertNotIn('http', res.error)

    def test_3_codigo_de_salida_distinto_de_0(self):
        res = por_ejecutar(SubfinderSimulado(stderr='could not create config file https://x.example', codigo=1))
        self.assertEqual(res.estado, 'failed')
        self.assertIn('código 1', res.error)
        self.assertNotIn('x.example', res.error)  # sin el texto crudo de stderr

    def test_4_timeout(self):
        res = por_ejecutar(SubfinderSimulado(lanza=subprocess.TimeoutExpired(['subfinder'], subfinder.TIMEOUT)))
        self.assertEqual(res.estado, 'failed')
        self.assertIn('no terminó en %d s' % subfinder.TIMEOUT, res.error)
        self.assertEqual(res.consultas, len(subfinder.FUENTES_SUBFINDER))

    def test_5_sin_binario_no_corre_nada(self):
        simulado = SubfinderSimulado()
        res = por_ejecutar(simulado, binario=None)
        self.assertEqual(res.estado, 'failed')
        self.assertIn('subfinder no está instalado', res.error)
        self.assertEqual((simulado.llamadas, res.consultas), ([], 0))

    def test_6_un_error_al_lanzar_el_proceso(self):
        res = por_ejecutar(SubfinderSimulado(lanza=PermissionError(13, 'Permission denied', BINARIO)))
        self.assertEqual(res.estado, 'failed')
        self.assertIn('no se pudo correr subfinder', res.error)

    def test_7_un_dominio_invalido_no_corre_nada(self):
        res = subfinder.recolectar('no valido', subfinder.ClienteSubfinder(ejecutar=sin_proceso, binario=BINARIO))
        self.assertEqual(res.estado, 'failed')
        res = contrato.ejecutar(cargar('subfinder'), '../acme-demo.mx', modo='grabar')  # ni crea el cliente
        self.assertEqual(res.estado, 'failed')
        self.assertIn('dominio inválido', res.error)

    def test_8_si_llega_a_su_tiempo_maximo_avisa_que_la_lista_puede_estar_incompleta(self):
        """-max-time corta la enumeración y subfinder sale con 0 con lo que tenga: sigue succeeded, con el aviso."""
        limite = subfinder.MAX_MINUTOS * 60
        res, _ = recolectar(SubfinderSimulado(stderr=caida('thc')), cronometro=Cronometro(limite))
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(len(res.activos), 3)
        self.assertEqual(res.avisos, ['subfinder: la fuente thc no respondió', subfinder.INCOMPLETO])
        self.assertEqual(subfinder.INCOMPLETO, 'subfinder: la lista puede estar incompleta (llegó a su tiempo máximo)')
        res, _ = recolectar(SubfinderSimulado(), cronometro=Cronometro(limite + 30))
        self.assertIn(subfinder.INCOMPLETO, res.avisos)
        res, _ = recolectar(SubfinderSimulado(), cronometro=Cronometro(limite - 0.5))  # un poco antes del corte
        self.assertNotIn(subfinder.INCOMPLETO, res.avisos)
        with tempfile.TemporaryDirectory() as d:  # el aviso se graba y vuelve al reproducir
            carpeta = Path(d) / 'acme-demo.mx'
            recolectar(SubfinderSimulado(), 'grabar', carpeta, nueva=True, cronometro=Cronometro(limite))
            otra, _ = recolectar(sin_proceso, 'reproducir', carpeta, binario=None)
        self.assertEqual(otra.avisos, [subfinder.INCOMPLETO])


class Proceso(unittest.TestCase):

    def test_1_el_comando_es_pasivo(self):
        simulado = SubfinderSimulado()
        recolectar(simulado)
        (comando, opciones, _), = simulado.llamadas
        self.assertEqual(comando[:3], [BINARIO, '-d', 'acme-demo.mx'])
        self.assertEqual(comando[comando.index('-s') + 1], ','.join(subfinder.FUENTES_SUBFINDER))
        self.assertEqual(comando[comando.index('-es') + 1], ','.join(subfinder.EXCLUIDAS))
        for bandera in ('-duc', '-oJ', '-cs', '-nc'):
            self.assertIn(bandera, comando)
        for bandera in PROHIBIDAS:
            self.assertNotIn(bandera, comando)
        self.assertEqual(comando[comando.index('-timeout') + 1], '30')
        self.assertEqual(comando[comando.index('-max-time') + 1], '5')
        self.assertFalse(opciones.get('shell', False))
        self.assertEqual((opciones['capture_output'], opciones['text'], opciones['check']), (True, True, False))
        self.assertEqual(opciones['stdin'], subprocess.DEVNULL)
        self.assertGreaterEqual(opciones['timeout'], subfinder.MAX_MINUTOS * 60)

    def test_2_la_lista_blanca_no_trae_las_excluidas(self):
        self.assertEqual(len(subfinder.FUENTES_SUBFINDER), 8)
        self.assertFalse(set(subfinder.FUENTES_SUBFINDER) & set(subfinder.EXCLUIDAS))
        self.assertTrue({'crtsh', 'certspotter', 'censys', 'hudsonrock', 'intelx', 'leakix'} <= set(subfinder.EXCLUIDAS))

    def test_3_el_entorno_solo_trae_path_home_y_xdg_en_una_carpeta_temporal(self):
        simulado = SubfinderSimulado()
        falsas = {'CIRDAN_APP_PASSWORD': 'CIRDAN_FAKE_clave', 'VALKEY_PASSWORD': 'CIRDAN_FAKE_valkey',
                  'TOTP_ENCRYPTION_KEY': 'CIRDAN_FAKE_totp', 'HACKERTARGET_API_KEY': 'CIRDAN_FAKE_ht',
                  'SUBFINDER_PROVIDER_CONFIG': '/tmp/no-usar.yaml'}
        with mock.patch.dict(os.environ, falsas):
            recolectar(simulado)
        (_, opciones, existia), = simulado.llamadas
        entorno = opciones['env']
        self.assertEqual(set(entorno), {'PATH', 'HOME', 'XDG_CONFIG_HOME'})
        self.assertFalse(any(v.startswith('CIRDAN_FAKE_') for v in entorno.values()))
        self.assertTrue(existia)  # la carpeta existe mientras corre...
        self.assertFalse(os.path.exists(entorno['HOME']))  # ...y se borra al terminar
        self.assertTrue(Path(entorno['XDG_CONFIG_HOME']).is_relative_to(Path(entorno['HOME'])))
        self.assertEqual(opciones['cwd'], entorno['HOME'])
        self.assertEqual(entorno['PATH'], os.environ.get('PATH', os.defpath))

    def test_4_la_carpeta_temporal_tambien_se_borra_si_falla(self):
        simulado = SubfinderSimulado(lanza=subprocess.TimeoutExpired(['subfinder'], 1))
        with self.assertRaises(contrato.FuenteNoResponde):
            recolectar(simulado)
        (_, opciones, _), = simulado.llamadas
        self.assertFalse(os.path.exists(opciones['env']['HOME']))


class GrabarYReproducir(unittest.TestCase):

    def test_1_grabar_y_reproducir_dan_lo_mismo_sin_correr_nada(self):
        stderr = caida('submd')
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / 'acme-demo.mx'
            carpeta.mkdir()
            (carpeta / 'viejo.json').write_text('[]', encoding='utf-8')  # de una grabación anterior
            grabado, cliente = recolectar(SubfinderSimulado(stderr=stderr), 'grabar', carpeta, nueva=True)
            self.assertEqual(cliente.consultas, len(subfinder.FUENTES_SUBFINDER))
            self.assertFalse((carpeta / 'viejo.json').exists())
            self.assertIsNotNone(contrato.Grabadora.inicio(carpeta))
            archivo = json.loads((carpeta / 'subfinder_acme-demo.mx.json').read_text(encoding='utf-8'))
            self.assertEqual(set(archivo['datos']), {'lineas', 'avisos'})
            self.assertEqual(archivo['datos']['avisos'], ['subfinder: la fuente submd no respondió'])
            otra, cliente = recolectar(sin_proceso, 'reproducir', carpeta, binario=None)
        self.assertEqual(cliente.consultas, 0)
        self.assertEqual(otra.consultas, 0)
        self.assertEqual((otra.activos, otra.avisos), (grabado.activos, grabado.avisos))

    def test_2_una_corrida_fallida_no_borra_la_grabacion_anterior(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / 'acme-demo.mx'
            recolectar(SubfinderSimulado(), 'grabar', carpeta, nueva=True)
            antes = (carpeta / 'subfinder_acme-demo.mx.json').read_bytes()
            stderr = '\n'.join(caida(f) for f in subfinder.FUENTES_SUBFINDER)
            with self.assertRaises(contrato.FuenteNoResponde):
                recolectar(SubfinderSimulado(salida=[], stderr=stderr), 'grabar', carpeta, nueva=True)
            self.assertEqual((carpeta / 'subfinder_acme-demo.mx.json').read_bytes(), antes)

    def test_3_reproducir_sin_grabacion_queda_failed(self):
        res = por_ejecutar(sin_proceso, modo='reproducir')
        self.assertEqual(res.estado, 'failed')
        self.assertIn(contrato.SIN_GRABACION, res.error)
        self.assertEqual(res.consultas, 0)

    def test_4_por_ejecutar_graba_y_reproduce(self):
        with tempfile.TemporaryDirectory() as d:
            res = por_ejecutar(SubfinderSimulado(), 'grabar', d)
            self.assertEqual((res.estado, res.consultas), ('succeeded', len(subfinder.FUENTES_SUBFINDER)))
            otra = por_ejecutar(sin_proceso, 'reproducir', d, binario=None)
        self.assertEqual((otra.estado, otra.consultas), ('succeeded', 0))
        self.assertEqual(otra.activos, res.activos)

    def test_5_una_grabacion_que_no_se_puede_leer(self):
        with tempfile.TemporaryDirectory() as d:
            contrato.Grabadora(Path(d) / 'acme-demo.mx', 'grabar').guardar('subfinder:acme-demo.mx', ['otra', 'forma'])
            res = por_ejecutar(sin_proceso, 'reproducir', d)
        self.assertEqual(res.estado, 'failed')
        self.assertIn('no se puede leer', res.error)


class Consultas(unittest.TestCase):

    def test_1_una_por_fuente_en_vivo_y_ninguna_al_reproducir(self):
        self.assertEqual(subfinder.MAX_CONSULTAS, len(subfinder.FUENTES_SUBFINDER))
        res, _ = recolectar(SubfinderSimulado())
        self.assertEqual(res.consultas, subfinder.MAX_CONSULTAS)
        res = por_ejecutar(SubfinderSimulado())
        self.assertEqual(res.consultas, subfinder.MAX_CONSULTAS)


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
    """Lectura estática de db/semillas/005_subfinder_y_limites.sql, sin base."""

    def test_1_subfinder_va_apagado_y_con_50_corridas_por_dia(self):
        fila = fila_de_la_semilla('subfinder')
        self.assertIsNotNone(fila, 'la semilla 005 no trae la fila de subfinder en su INSERT INTO data_sources')
        self.assertEqual(fila['enabled'].lower(), 'false')  # apagado hasta RC-40, la grabación y el contenedor
        self.assertEqual(int(fila['daily_limit']), 50 * subfinder.MAX_CONSULTAS)


if __name__ == '__main__':
    unittest.main()
