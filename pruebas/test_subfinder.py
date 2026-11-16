"""Pruebas del recolector de subfinder (#14b, RC-184), que lee el URL Index de Common Crawl con Amazon Athena. Sin red:
unos clientes de Athena, Glue y S3 simulados en lugar de boto3, con la forma de las respuestas reales. El runner del CI
corre este archivo con un Python sin dependencias, así que esas pruebas no usan botocore. ClientesReales sí: arma los
clientes reales con una llave CIRDAN_FAKE_ y los cubre con botocore.stub.Stubber, que revisa cada pedido y cada
respuesta contra el modelo de la API de AWS sin abrir la red. Corre en el contenedor (INTEGRACION_SUBFINDER=1).

    python -m unittest -v pruebas/test_subfinder.py
"""
import contextlib
import importlib.util
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

RAIZ = Path(__file__).resolve().parents[1]
SEMILLA = RAIZ / 'db' / 'semillas' / '005_subfinder_y_limites.sql'
SEMILLA_017 = RAIZ / 'db' / 'semillas' / '017_subfinder_commoncrawl.sql'
SEMILLA_018 = RAIZ / 'db' / 'semillas' / '018_subfinder_athena.sql'

# 14 crawls válidos, mezclados: el recolector toma los 12 más recientes.
VALIDOS = ['CC-MAIN-2026-%02d' % s for s in (5, 47, 8, 43, 13, 39, 17, 35, 21, 30, 26)] + \
          ['CC-MAIN-2025-%02d' % s for s in (51, 43, 47)]
RECIENTES = sorted(VALIDOS, reverse=True)[:12]
PREFIJOS = ['cc-index/table/cc-main/warc/crawl=%s/' % c for c in VALIDOS] + [
    'cc-index/table/cc-main/warc/crawl=CC-MAIN-2026-47x/', 'cc-index/table/cc-main/warc/otra/',
    'cc-index/table/cc-main/warc/crawl=CC-MAIN-2027-01/sub/', 'otro/crawl=CC-MAIN-2027-02/']
SALIDA = 's3://lowtide-cc-prueba/athena/'
LLAVE = 'CIRDAN_FAKE_AKIA0000000000'
CLAVE = 'CIRDAN_FAKE_clave0de0la0prueba0sin0valor'
ENTORNO = {'CC_ATHENA_ACCESS_KEY_ID': LLAVE, 'CC_ATHENA_SECRET_ACCESS_KEY': CLAVE,
           'CC_ATHENA_WORKGROUP': 'cc-subdominios', 'CC_ATHENA_SALIDA': SALIDA}
HOSTS = ['www.acme-demo.mx', 'WWW.acme-demo.mx', 'api.acme-demo.mx', 'acme-demo.mx', '*.dev.acme-demo.mx',
         'www.acme-demo.mx']


def workgroup(**cambios):
    """La respuesta de GetWorkGroup de un workgroup como el de los pasos de AWS (tope de 1 GB, salida propia)."""
    config = {'ResultConfiguration': {'OutputLocation': SALIDA}, 'EnforceWorkGroupConfiguration': True,
              'BytesScannedCutoffPerQuery': 1 << 30}
    grupo = {'Name': 'cc-subdominios', 'State': 'ENABLED', 'Configuration': config}
    for clave, valor in cambios.items():
        (grupo if clave in ('State',) else config)[clave] = valor
    return {'WorkGroup': grupo}


class FallaAws(Exception):
    """Hace las veces de botocore.exceptions.ClientError: el código va en response y el mensaje lleva datos de la
    cuenta y la llave, que nunca deben salir."""

    def __init__(self, codigo):
        super().__init__('An error occurred (%s): cuenta 123456789012, llave %s' % (codigo, LLAVE))
        self.response = {'Error': {'Code': codigo, 'Message': 'arn:aws:iam::123456789012:user/x %s' % CLAVE}}


class AthenaSimulada:
    """Hace las veces de _clientes_reales: anota cada llamada y responde como Athena, Glue y S3.

    `hosts` son los url_host_name del SELECT. `faltan` los crawls sin partición en la tabla. `estados` da, por número
    de StartQueryExecution (desde 0), la lista de estados que devuelve GetQueryExecution: un texto, o (estado,
    categoría) para FAILED. Sin entrada, la consulta sale SUCCEEDED a la primera. `fallas` da, por nombre de método, una
    lista de lo que lanza cada llamada (None la deja responder)."""

    def __init__(self, hosts=None, faltan=(), estados=None, fallas=None, grupo=None, paginas_s3=None, filas=None,
                 leidos=4 << 20):
        self.hosts = HOSTS if hosts is None else hosts
        self.faltan, self.estados, self.fallas = set(faltan), estados or {}, fallas or {}
        self.grupo = workgroup() if grupo is None else grupo
        self.paginas_s3 = paginas_s3 or [{'CommonPrefixes': [{'Prefix': p} for p in PREFIJOS], 'IsTruncated': False}]
        self.filas, self.leidos = filas, leidos
        self.llamadas, self.consultas, self.paradas, self.cred = [], [], [], None
        nombres = {'athena': ('get_work_group', 'start_query_execution', 'get_query_execution', 'get_query_results',
                              'stop_query_execution'),
                   'glue': ('batch_get_partition',), 's3': ('list_objects_v2',)}
        for servicio, metodos in nombres.items():
            setattr(self, servicio, SimpleNamespace(**{m: self._anotada(m) for m in metodos}))

    def __call__(self, cred):
        self.cred = dict(cred)
        return self.athena, self.glue, self.s3, (FallaAws,)

    def _anotada(self, metodo):
        def llamada(**parametros):
            self.llamadas.append((metodo, parametros))
            fallas = self.fallas.get(metodo) or []
            falla = fallas.pop(0) if fallas else None
            if falla is not None:
                raise falla
            return getattr(self, '_' + metodo)(**parametros)
        return llamada

    def metodos(self):
        return [m for m, _ in self.llamadas]

    def _get_work_group(self, WorkGroup):
        return self.grupo

    def _list_objects_v2(self, **pedido):
        pagina = sum(1 for m, _ in self.llamadas if m == 'list_objects_v2') - 1
        return self.paginas_s3[pagina]

    def _batch_get_partition(self, DatabaseName, TableName, PartitionsToGet):
        return {'Partitions': [{'Values': list(p['Values']), 'DatabaseName': DatabaseName, 'TableName': TableName}
                               for p in PartitionsToGet if p['Values'][0] not in self.faltan], 'UnprocessedKeys': []}

    def _start_query_execution(self, **pedido):
        self.consultas.append(pedido)
        return {'QueryExecutionId': 'q%d' % (len(self.consultas) - 1)}

    def _get_query_execution(self, QueryExecutionId):
        n = int(QueryExecutionId[1:])
        pendientes = self.estados.setdefault(n, ['SUCCEEDED'])
        estado = pendientes.pop(0) if len(pendientes) > 1 else pendientes[0]
        estado, categoria = estado if isinstance(estado, tuple) else (estado, None)
        status = {'State': estado}
        if categoria is not None:
            status['AthenaError'] = {'ErrorCategory': categoria, 'ErrorType': 1000}
        return {'QueryExecution': {'QueryExecutionId': QueryExecutionId, 'Status': status,
                                   'Statistics': {'DataScannedInBytes': self.leidos}}}

    def _get_query_results(self, QueryExecutionId, MaxResults, NextToken=None):
        filas = self.filas if self.filas is not None else [{'Data': [{'VarCharValue': h}]} for h in self.hosts]
        todas = [{'Data': [{'VarCharValue': 'url_host_name'}]}] + filas
        inicio = int(NextToken or 0)
        respuesta = {'ResultSet': {'Rows': todas[inicio:inicio + MaxResults]}}
        if inicio + MaxResults < len(todas):
            respuesta['NextToken'] = str(inicio + MaxResults)
        return respuesta

    def _stop_query_execution(self, QueryExecutionId):
        self.paradas.append(QueryExecutionId)
        return {}


def sin_aws(*_, **__):
    raise AssertionError('no debe preparar clientes de AWS')


@contextlib.contextmanager
def con_athena(simulado, entorno=ENTORNO):
    """subfinder.py con Athena simulada y las 4 CC_ATHENA_* falsas en os.environ, como lo crea el orquestador. Solo lo
    ve subfinder.py: las demás fuentes no cambian."""
    with mock.patch.object(subfinder, '_clientes_reales', simulado), mock.patch.dict(os.environ, entorno):
        yield simulado


class Cronometro:
    """Hace las veces de time.monotonic: cada lectura avanza `paso` segundos, sin dormir de verdad."""

    def __init__(self, paso):
        self.paso, self.ahora = paso, 1000.0

    def __call__(self):
        actual, self.ahora = self.ahora, self.ahora + self.paso
        return actual


def cliente(simulado=None, modo='vivo', carpeta=None, nueva=False, cronometro=None, entorno=ENTORNO):
    dormidas = []
    c = subfinder.ClienteSubfinder(modo=modo, carpeta=carpeta or subfinder.CARPETA_GRABADAS, nueva=nueva,
                                   aws=simulado or sin_aws, entorno=entorno, cronometro=cronometro or Cronometro(0),
                                   dormir=dormidas.append)
    c.dormidas = dormidas
    return c


def recolectar(simulado=None, **opciones):
    c = cliente(simulado, **opciones)
    return subfinder.recolectar('acme-demo.mx', c, AHORA), c


def enumerar(simulado, **opciones):
    """(cliente, FuenteNoResponde) de una corrida que tiene que fallar."""
    c = cliente(simulado, **opciones)
    with unittest.TestCase().assertRaises(contrato.FuenteNoResponde) as error:
        c.enumerar('acme-demo.mx')
    return c, error.exception


def por_ejecutar(simulado, modo='vivo', carpeta=None, entorno=ENTORNO):
    """Por contrato.ejecutar(), como lo llama el orquestador."""
    with tempfile.TemporaryDirectory() as d, mock.patch.object(subfinder, 'CARPETA_GRABADAS', Path(carpeta or d)), \
            con_athena(simulado or sin_aws, entorno), mock.patch.object(subfinder.time, 'sleep', lambda s: None):
        return contrato.ejecutar(cargar('subfinder'), 'acme-demo.mx', modo=modo, ahora=AHORA)


def parametros_select(crawls=RECIENTES, dominio='acme-demo.mx', surt='mx,acme-demo'):
    return ["'%s'" % c for c in crawls] + ["'%s'" % surt, "'%s~'" % surt, "'%s'" % dominio, "'%%.%s'" % dominio]


class Activos(unittest.TestCase):

    def test_1_un_activo_subdomain_por_nombre_con_fuente_y_origen(self):
        res, c = recolectar(AthenaSimulada())
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.activos, [
            Activo('subdomain', 'api.acme-demo.mx', {'fuente': 'subfinder', 'origen': ['commoncrawl']}),
            Activo('subdomain', 'dev.acme-demo.mx', {'fuente': 'subfinder', 'origen': ['commoncrawl']}),
            Activo('subdomain', 'www.acme-demo.mx', {'fuente': 'subfinder', 'origen': ['commoncrawl']}),
        ])
        self.assertEqual((res.hallazgos, res.sin_cobertura, res.avisos), ([], [], []))
        self.assertEqual((res.consultas, c.bytes_leidos), (1, 4 << 20))
        for a in res.activos:  # solo el nombre
            self.assertEqual(set(a.atributos), {'fuente', 'origen'})

    def test_2_fuera_del_dominio_e_invalidos_se_cuentan_y_no_se_nombran(self):
        hosts = ['acme-demo.mx.ajeno.com', 'otro.com', 'xacme-demo.mx', 'a_b.acme-demo.mx', 'ok.acme-demo.mx']
        res, _ = recolectar(AthenaSimulada(hosts))
        self.assertEqual([a.valor for a in res.activos], ['ok.acme-demo.mx'])
        self.assertEqual(res.avisos, ['subfinder: se descartaron 3 nombres fuera del dominio',
                                      'subfinder: se descartó 1 nombre que no es un nombre de dominio válido'])
        for nombre in ('ajeno', 'otro.com'):
            self.assertNotIn(nombre, ' '.join(res.avisos))
        self.assertEqual(contrato.validar(res), [])

    def test_3_validar_con_el_catalogo_y_codigos_vacio(self):
        self.assertEqual(subfinder.CODIGOS, {})
        res, _ = recolectar(AthenaSimulada())
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])
        res = por_ejecutar(AthenaSimulada())
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(contrato.validar(res, codigos=set(POR_CODIGO)), [])

    def test_4_esta_en_el_registro_con_su_carpeta(self):
        self.assertIs(cargar('subfinder'), subfinder)
        self.assertEqual(REGISTRO['subfinder'], 'cirdan.recolectores.subfinder')
        self.assertEqual(subfinder.FUENTE, 'subfinder')
        self.assertEqual(subfinder.CARPETA_GRABADAS, contrato.CARPETA_GRABADAS / 'subfinder')

    def test_5_ya_no_corre_el_binario_ni_pide_el_cdx(self):
        texto = Path(subfinder.__file__).read_text(encoding='utf-8')
        self.assertNotIn('import subprocess', texto)
        self.assertNotIn('import boto3', texto.split('def _clientes_reales')[0])   # boto3 solo dentro de esa función
        for viejo in ('_ejecutar', 'COLLINFO', 'CDX', 'transporte', 'Ritmo', 'RITMO'):
            self.assertFalse(hasattr(subfinder, viejo), viejo)


class Consulta(unittest.TestCase):

    def test_1_pide_el_workgroup_los_crawls_las_particiones_y_un_select_sin_el_dominio_en_el_texto(self):
        simulado = AthenaSimulada()
        recolectar(simulado)
        self.assertEqual(simulado.metodos(), ['get_work_group', 'list_objects_v2', 'batch_get_partition',
                                              'start_query_execution', 'get_query_execution', 'get_query_results'])
        llamadas = dict(simulado.llamadas)
        self.assertEqual(llamadas['get_work_group'], {'WorkGroup': 'cc-subdominios'})
        self.assertEqual(llamadas['list_objects_v2'],
                         {'Bucket': 'commoncrawl', 'Prefix': 'cc-index/table/cc-main/warc/', 'Delimiter': '/'})
        self.assertEqual(llamadas['batch_get_partition'], {
            'DatabaseName': 'ccindex', 'TableName': 'ccindex', 'PartitionsToGet': [{'Values': [c, 'warc']}
                                                                                 for c in RECIENTES]})
        (pedido,) = simulado.consultas
        self.assertEqual(set(pedido), {'QueryString', 'WorkGroup', 'QueryExecutionContext', 'ExecutionParameters'})
        self.assertEqual((pedido['WorkGroup'], pedido['QueryExecutionContext']), ('cc-subdominios',
                                                                                  {'Database': 'ccindex'}))
        self.assertEqual(pedido['ExecutionParameters'], parametros_select())
        texto = pedido['QueryString']
        for nunca in ('acme', 'CC-MAIN', 'mx'):
            self.assertNotIn(nunca, texto)
        self.assertEqual(texto.count('?'), len(pedido['ExecutionParameters']))
        self.assertEqual(texto, "SELECT DISTINCT url_host_name FROM ccindex WHERE crawl IN (%s) AND subset = 'warc' "
                         "AND url_surtkey >= ? AND url_surtkey < ? AND (url_host_name = ? OR url_host_name LIKE ?) "
                         "LIMIT 5001" % ', '.join(['?'] * 12))
        self.assertEqual(llamadas['get_query_results'], {'QueryExecutionId': 'q0', 'MaxResults': 1000})
        self.assertEqual(simulado.cred, ENTORNO)

    def test_2_la_clave_surt_del_dominio(self):
        for dominio, surt in (('olmardo.com', 'com,olmardo'), ('ejemplo.com.mx', 'mx,com,ejemplo'),
                              ('app.ejemplo.com', 'com,ejemplo,app'), ('lowtidesec.com', 'com,lowtidesec')):
            with self.subTest(dominio=dominio):
                self.assertEqual(subfinder.clave_surt(dominio), surt)
                _, parametros = subfinder.consulta_select(dominio, RECIENTES[:2])
                self.assertEqual(parametros, parametros_select(RECIENTES[:2], dominio, surt))

    def test_3_los_12_crawls_mas_recientes_salen_de_los_prefijos_de_s3(self):
        simulado = AthenaSimulada()
        res, _ = recolectar(simulado)
        self.assertEqual(simulado.consultas[0]['ExecutionParameters'][:12], ["'%s'" % c for c in RECIENTES])
        self.assertEqual(len(RECIENTES), subfinder.INDICES)
        self.assertNotIn("'CC-MAIN-2027-01'", simulado.consultas[0]['ExecutionParameters'])
        # menos crawls: los que hay
        pocos = AthenaSimulada([], paginas_s3=[{'CommonPrefixes': [{'Prefix': PREFIJOS[0]}, {'Prefix': PREFIJOS[1]}],
                                                'IsTruncated': False}])
        res, _ = recolectar(pocos)
        self.assertEqual(res.avisos, [subfinder.SIN_CAPTURAS % 2])

    def test_4_la_lista_de_s3_en_varias_paginas(self):
        paginas = [{'CommonPrefixes': [{'Prefix': p} for p in PREFIJOS[:7]], 'IsTruncated': True,
                    'NextContinuationToken': 'sigue'},
                   {'CommonPrefixes': [{'Prefix': p} for p in PREFIJOS[7:]], 'IsTruncated': False}]
        simulado = AthenaSimulada(paginas_s3=paginas)
        recolectar(simulado)
        pedidos = [p for m, p in simulado.llamadas if m == 'list_objects_v2']
        self.assertEqual([p.get('ContinuationToken') for p in pedidos], [None, 'sigue'])
        self.assertEqual(simulado.consultas[0]['ExecutionParameters'][:12], ["'%s'" % c for c in RECIENTES])

    def test_5_una_lista_de_s3_rara_o_sin_crawls_es_falla_sin_consultar(self):
        for paginas, texto in (([{'CommonPrefixes': [{'Prefix': 'otra/'}], 'IsTruncated': False}], 'ningún crawl'),
                               ([{'IsTruncated': True}], 'no se puede leer'),
                               ([{'CommonPrefixes': 'no lista', 'IsTruncated': False}], 'no se puede leer'),
                               ([{'IsTruncated': True, 'NextContinuationToken': 't'}] * 3, 'pasa de 3 páginas')):
            with self.subTest(texto=texto):
                simulado = AthenaSimulada(paginas_s3=paginas)
                c, error = enumerar(simulado)
                self.assertIn(texto, str(error))
                self.assertEqual((c.consultas, simulado.consultas), (0, []))

    def test_6_una_particion_que_falta_se_agrega_con_un_alter_y_luego_el_select(self):
        simulado = AthenaSimulada(faltan=RECIENTES[:2])
        res, _ = recolectar(simulado)
        self.assertEqual((res.estado, res.consultas), ('succeeded', 2))
        alter, select = simulado.consultas
        self.assertNotIn('ExecutionParameters', alter)   # DDL: no los acepta
        self.assertEqual(alter['QueryString'], 'ALTER TABLE ccindex ADD IF NOT EXISTS ' + ' '.join(
            "PARTITION (crawl = '%s', subset = 'warc') LOCATION "
            "'s3://commoncrawl/cc-index/table/cc-main/warc/crawl=%s/subset=warc/'" % (c, c) for c in RECIENTES[:2]))
        self.assertEqual(select['ExecutionParameters'], parametros_select())
        self.assertEqual([m for m in simulado.metodos() if m == 'get_query_execution'], ['get_query_execution'] * 2)

    def test_7_un_crawl_o_un_parametro_con_otra_forma_nunca_llega_al_sql(self):
        for malo in ("CC-MAIN-2026-47' OR 1=1", 'CC-MAIN-26-1', ''):
            with self.subTest(malo=malo), self.assertRaises(contrato.FuenteNoResponde):
                subfinder.consulta_particiones([malo])
        for malo in ("a'b", 'A.MX', 'a b', ''):
            with self.subTest(malo=malo), self.assertRaises(contrato.FuenteNoResponde):
                subfinder._literal(malo)

    def test_8_cero_nombres_es_succeeded_con_su_aviso(self):
        res, _ = recolectar(AthenaSimulada([]))
        self.assertEqual((res.estado, res.activos, res.consultas), ('succeeded', [], 1))
        self.assertEqual(res.avisos, ['subfinder: Common Crawl no tiene capturas de este dominio en sus últimos 12 '
                                      'índices'])
        solo_dominio, _ = recolectar(AthenaSimulada(['acme-demo.mx']))
        self.assertEqual((solo_dominio.activos, solo_dominio.avisos), ([], []))  # sí hay capturas, del dominio

    def test_9_5001_nombres_en_6_paginas_llevan_el_aviso_recortado(self):
        muchos = ['n%d.acme-demo.mx' % i for i in range(subfinder.LIMITE_FILAS + 1)]
        simulado = AthenaSimulada(muchos)
        res, _ = recolectar(simulado)
        self.assertEqual(len(res.activos), subfinder.LIMITE_FILAS)
        self.assertEqual(res.avisos, ['subfinder: Common Crawl llegó al tope de 5000 nombres, la lista puede estar '
                                      'incompleta'])
        tokens = [p.get('NextToken') for m, p in simulado.llamadas if m == 'get_query_results']
        self.assertEqual(tokens, [None, '1000', '2000', '3000', '4000', '5000'])
        cabe, _ = recolectar(AthenaSimulada(muchos[:-1]))
        self.assertEqual((len(cabe.activos), cabe.avisos), (subfinder.LIMITE_FILAS, []))

    def test_10_filas_que_no_se_pueden_leer_se_saltan_con_aviso(self):
        filas = [{'Data': [{'VarCharValue': 'ok.acme-demo.mx'}]}, {'Data': [{}]}, {'Data': []}, 'no es fila',
                 {'Data': [{'VarCharValue': ''}]}, {'Data': [{'VarCharValue': 5}]}]
        res, _ = recolectar(AthenaSimulada(filas=filas))
        self.assertEqual([a.valor for a in res.activos], ['ok.acme-demo.mx'])
        self.assertEqual(res.avisos, ['subfinder: se saltaron 5 filas de Athena que no se pudieron leer'])
        res, _ = recolectar(AthenaSimulada(filas=filas[:2]))
        self.assertEqual(res.avisos, ['subfinder: se saltó 1 fila de Athena que no se pudo leer'])

    def test_11_ninguna_fila_legible_o_un_encabezado_raro_es_falla(self):
        c, error = enumerar(AthenaSimulada(filas=[{'Data': [{}]}, {'Data': []}]))
        self.assertIn('ninguna fila legible', str(error))
        simulado = AthenaSimulada()
        simulado._get_query_results = lambda **_: {'ResultSet': {'Rows': [{'Data': [{'VarCharValue': 'otra'}]}]}}
        _, error = enumerar(simulado)
        self.assertIn('no se puede leer en los resultados', str(error))


class Workgroup(unittest.TestCase):
    """Sin un workgroup que imponga un tope de bytes de a lo más 1 GB no se pide ninguna consulta."""

    def test_1_un_workgroup_sin_tope_apagado_sin_imponer_o_con_otra_salida_no_consulta(self):
        casos = ((workgroup(BytesScannedCutoffPerQuery=None), 'tope de bytes'),
                 (workgroup(BytesScannedCutoffPerQuery=(1 << 30) + 1), 'tope de bytes'),
                 (workgroup(BytesScannedCutoffPerQuery=0), 'tope de bytes'),
                 (workgroup(BytesScannedCutoffPerQuery='1073741824'), 'tope de bytes'),
                 (workgroup(BytesScannedCutoffPerQuery=True), 'tope de bytes'),
                 (workgroup(State='DISABLED'), 'no está prendido'),
                 (workgroup(EnforceWorkGroupConfiguration=False), 'no impone'),
                 (workgroup(ResultConfiguration={'OutputLocation': 's3://otro-bucket/athena/'}), 'CC_ATHENA_SALIDA'),
                 (workgroup(ResultConfiguration={}), 'CC_ATHENA_SALIDA'),
                 ({'WorkGroup': {'State': 'ENABLED'}}, 'no se puede leer'),
                 ({}, 'no se puede leer'))
        for grupo, texto in casos:
            with self.subTest(texto=texto, grupo=grupo):
                simulado = AthenaSimulada(grupo=grupo)
                c, error = enumerar(simulado)
                self.assertIn(texto, str(error))
                self.assertEqual(simulado.metodos(), ['get_work_group'])
                self.assertEqual(c.consultas, 0)

    def test_2_la_salida_se_compara_sin_la_barra_final(self):
        res, _ = recolectar(AthenaSimulada(grupo=workgroup(ResultConfiguration={'OutputLocation': SALIDA[:-1]})))
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(subfinder.TOPE_BYTES, 1 << 30)


class Fallas(unittest.TestCase):

    def test_1_faltan_variables_da_sus_nombres_sin_valores_y_no_prepara_clientes(self):
        for quitar in subfinder.VARIABLES:
            with self.subTest(quitar=quitar):
                entorno = dict(ENTORNO)
                del entorno[quitar]
                _, error = enumerar(None, entorno=entorno)
                self.assertIn(quitar, str(error))
                for valor in (LLAVE, CLAVE, SALIDA):
                    self.assertNotIn(valor, str(error))
        _, error = enumerar(None, entorno={})
        self.assertEqual(str(error), 'subfinder: faltan las variables %s o no tienen la forma esperada'
                         % ', '.join(subfinder.VARIABLES))
        for variable, malo in (('CC_ATHENA_SALIDA', 'https://lowtide-cc-prueba/athena/'),
                               ('CC_ATHENA_WORKGROUP', 'cc subdominios'), ('CC_ATHENA_ACCESS_KEY_ID', 'akia-minus'),
                               ('CC_ATHENA_SECRET_ACCESS_KEY', '   ')):
            with self.subTest(variable=variable):
                _, error = enumerar(None, entorno=dict(ENTORNO, **{variable: malo}))
                self.assertIn(variable, str(error))
                self.assertNotIn(malo.strip() or '\0', str(error))
        res = por_ejecutar(None, entorno={v: '' for v in subfinder.VARIABLES})   # el compose las pone vacías
        self.assertEqual((res.estado, res.consultas), ('failed', 0))
        self.assertIn('faltan las variables CC_ATHENA_ACCESS_KEY_ID', res.error)

    def test_2_failed_de_categoria_1_se_reintenta_una_vez_en_la_corrida(self):
        simulado = AthenaSimulada(estados={0: ['RUNNING', ('FAILED', 1)]})
        res, c = recolectar(simulado)
        self.assertEqual((res.estado, res.consultas, [a.valor for a in res.activos]),
                         ('succeeded', 2, ['api.acme-demo.mx', 'dev.acme-demo.mx', 'www.acme-demo.mx']))
        self.assertEqual(simulado.consultas[0], simulado.consultas[1])
        # dos seguidas: FuenteNoResponde con 2 consultas, o 3 con el ALTER
        simulado = AthenaSimulada(estados={0: [('FAILED', 1)], 1: [('FAILED', 1)]})
        c, error = enumerar(simulado)
        self.assertEqual((str(error), c.consultas), ('subfinder: Athena dio FAILED en la consulta (categoría 1)', 2))
        simulado = AthenaSimulada(faltan=[RECIENTES[0]], estados={1: [('FAILED', 1)], 2: [('FAILED', 1)]})
        c, _ = enumerar(simulado)
        self.assertEqual(c.consultas, subfinder.MAX_CONSULTAS)
        self.assertEqual(subfinder.MAX_CONSULTAS, 3)

    def test_3_failed_de_categoria_2_o_3_y_cancelled_no_se_reintentan(self):
        for estado, texto in ((('FAILED', 2), 'FAILED en la consulta (categoría 2)'),
                              (('FAILED', 3), 'FAILED en la consulta (categoría 3)'),
                              (('FAILED', None), 'FAILED en la consulta (categoría None)'),
                              ('CANCELLED', 'canceló la consulta (el tope de bytes')):
            with self.subTest(estado=estado):
                simulado = AthenaSimulada(estados={0: [estado]})
                c, error = enumerar(simulado)
                self.assertIn(texto, str(error))
                self.assertEqual((c.consultas, simulado.paradas), (1, []))   # ya terminó: nada que parar

    def test_4_throttling_al_pedir_se_reintenta_y_los_demas_codigos_no(self):
        for codigo in subfinder.LENTO:
            with self.subTest(codigo=codigo):
                simulado = AthenaSimulada(fallas={'start_query_execution': [FallaAws(codigo)]})
                res, _ = recolectar(simulado)
                self.assertEqual((res.estado, res.consultas, len(simulado.consultas)), ('succeeded', 2, 1))
        for codigo in ('AccessDeniedException', 'InvalidRequestException', 'ResourceNotFoundException'):
            with self.subTest(codigo=codigo):
                simulado = AthenaSimulada(fallas={'start_query_execution': [FallaAws(codigo)]})
                c, error = enumerar(simulado)
                self.assertEqual(str(error), 'subfinder: AWS no respondió en la consulta (%s)' % codigo)
                self.assertEqual(c.consultas, 1)

    def test_5_una_falla_de_aws_en_cualquier_paso_lleva_solo_su_codigo(self):
        for metodo, que in (('get_work_group', 'el workgroup'), ('list_objects_v2', 'la lista de crawls'),
                            ('batch_get_partition', 'las particiones'), ('get_query_execution', 'la consulta'),
                            ('get_query_results', 'los resultados')):
            with self.subTest(metodo=metodo):
                simulado = AthenaSimulada(fallas={metodo: [FallaAws('AccessDeniedException')]})
                _, error = enumerar(simulado)
                self.assertEqual(str(error), 'subfinder: AWS no respondió en %s (AccessDeniedException)' % que)
                for nunca in ('123456789012', LLAVE, CLAVE, 'arn:'):
                    self.assertNotIn(nunca, str(error))
        falla = FallaAws('x')
        falla.response = {'Error': {'Code': 'Código <raro>'}}   # un código con otra forma: el tipo
        _, error = enumerar(AthenaSimulada(fallas={'get_work_group': [falla]}))
        self.assertIn('(FallaAws)', str(error))

    def test_6_sin_tiempo_se_para_la_consulta_y_es_falla(self):
        simulado = AthenaSimulada(estados={0: ['RUNNING']})   # nunca termina
        reloj = Cronometro(0)
        c = cliente(simulado, cronometro=reloj)
        c.dormir = lambda s: (c.dormidas.append(s), setattr(reloj, 'ahora', reloj.ahora + s))
        with self.assertRaises(contrato.FuenteNoResponde) as error:
            c.enumerar('acme-demo.mx')
        self.assertEqual(str(error.exception), 'subfinder: Athena no terminó en 180 s (faltó la consulta)')
        self.assertEqual(simulado.paradas, ['q0'])
        self.assertEqual(c.dormidas[:4], [1, 2, 4, 5])
        self.assertEqual(set(c.dormidas[3:]), {subfinder.ESPERA_MAXIMA})
        self.assertLess(sum(c.dormidas), subfinder.MAX_SEGUNDOS)
        self.assertGreater(sum(c.dormidas), subfinder.MAX_SEGUNDOS - subfinder.ESPERA_MAXIMA - 1)

    def test_7_sin_el_minimo_de_tiempo_no_pide_la_consulta(self):
        lecturas = iter([1000.0] + [1000.0 + subfinder.MAX_SEGUNDOS - subfinder.MINIMO_CONSULTA + 1] * 20)
        simulado = AthenaSimulada()
        c, error = enumerar(simulado, cronometro=lambda: next(lecturas))
        self.assertIn('faltó la consulta', str(error))
        self.assertEqual((c.consultas, simulado.consultas), (0, []))

    def test_8_una_falla_inesperada_al_esperar_tambien_para_la_consulta(self):
        for falla in (RuntimeError('raro'), KeyboardInterrupt()):
            with self.subTest(falla=falla):
                simulado = AthenaSimulada(fallas={'get_query_execution': [falla]})
                c = cliente(simulado)
                with self.assertRaises(type(falla)):
                    c.enumerar('acme-demo.mx')
                self.assertEqual(simulado.paradas, ['q0'])
        # y una falla de AWS al pararla no tapa la de antes
        simulado = AthenaSimulada(estados={0: ['RUNNING']},
                                  fallas={'stop_query_execution': [FallaAws('InternalServerException')]})
        _, error = enumerar(simulado, cronometro=Cronometro(1))
        self.assertIn('no terminó', str(error))

    def test_9_un_estado_o_un_id_raros_son_falla(self):
        simulado = AthenaSimulada(estados={0: ['PENDIENTE']})
        _, error = enumerar(simulado)
        self.assertIn('no se puede leer en la consulta', str(error))
        self.assertEqual(simulado.paradas, ['q0'])
        for qid in ('../x', '', None, 'q' * 129):
            with self.subTest(qid=qid):
                simulado = AthenaSimulada()
                simulado._start_query_execution = lambda **_: {'QueryExecutionId': qid}
                _, error = enumerar(simulado)
                self.assertIn('no se puede leer en la consulta', str(error))

    def test_10_un_cliente_que_no_se_puede_preparar_da_solo_el_tipo(self):
        def roto(cred):
            raise ImportError("No module named 'boto3' en /home/%s" % CLAVE)
        _, error = enumerar(roto)
        self.assertEqual(str(error), 'subfinder: no se pudo preparar el cliente de AWS (ImportError)')

    def test_11_un_dominio_invalido_no_pide_nada(self):
        res = subfinder.recolectar('no valido', cliente())
        self.assertEqual(res.estado, 'failed')
        res = contrato.ejecutar(cargar('subfinder'), '../acme-demo.mx', modo='grabar')  # ni crea el cliente
        self.assertEqual(res.estado, 'failed')
        self.assertIn('dominio inválido', res.error)

    def test_12_el_tiempo_de_la_corrida_cabe_en_el_tope_del_orquestador(self):
        """Peor caso: MAX_SEGUNDOS más una llamada que empezó justo antes, con sus INTENTOS_AWS intentos de a lo más
        TIMEOUT_CONEXION + TIMEOUT_LECTURA y las esperas de botocore entre ellos (a lo más 20 s cada una)."""
        texto = (RAIZ / 'cirdan' / 'orquestador' / '__init__.py').read_text(encoding='utf-8')
        tope = re.search(r'^TOPE_CORRIDA = timedelta\(minutes=(\d+)\)', texto, re.MULTILINE)
        self.assertIsNotNone(tope)
        llamada = subfinder.INTENTOS_AWS * (subfinder.TIMEOUT_CONEXION + subfinder.TIMEOUT_LECTURA) + \
            (subfinder.INTENTOS_AWS - 1) * 20
        self.assertEqual(subfinder.MAX_SEGUNDOS + llamada, 340)
        self.assertLess(subfinder.MAX_SEGUNDOS + llamada, 60 * int(tope.group(1)))
        self.assertEqual((subfinder.ESPERAS, subfinder.ESPERA_MAXIMA, subfinder.MINIMO_CONSULTA), ((1, 2, 4), 5, 10))


class Llave(unittest.TestCase):
    """La llave CIRDAN_FAKE_ nunca sale en errores, avisos ni grabaciones."""

    def test_1_la_llave_no_sale_en_el_resultado_ni_en_lo_grabado(self):
        with tempfile.TemporaryDirectory() as d:
            grabado = por_ejecutar(AthenaSimulada(), 'grabar', d)
            texto = (Path(d) / 'acme-demo.mx' / 'subfinder_acme-demo.mx.json').read_text(encoding='utf-8')
            fallido = por_ejecutar(AthenaSimulada(fallas={'get_query_results': [FallaAws('AccessDenied')]}))
        self.assertEqual((grabado.estado, fallido.estado), ('succeeded', 'failed'))
        todo = texto + json.dumps([grabado.avisos, grabado.error, fallido.avisos, fallido.error])
        for nunca in (LLAVE, CLAVE, 'CIRDAN_FAKE_', '123456789012', SALIDA, 'cc-subdominios'):
            self.assertNotIn(nunca, todo)

    def test_2_el_cliente_recibe_solo_las_4_variables(self):
        simulado = AthenaSimulada()
        otras = dict(ENTORNO, AWS_ACCESS_KEY_ID='CIRDAN_FAKE_OTRA0000000000')
        cliente(simulado, entorno=otras).enumerar('acme-demo.mx')
        self.assertEqual(simulado.cred, ENTORNO)


class GrabarYReproducir(unittest.TestCase):

    def test_1_grabar_y_reproducir_dan_lo_mismo_sin_aws(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / 'acme-demo.mx'
            carpeta.mkdir()
            (carpeta / 'viejo.json').write_text('[]', encoding='utf-8')  # de una grabación anterior
            grabado, c = recolectar(AthenaSimulada(), modo='grabar', carpeta=carpeta, nueva=True)
            self.assertEqual(c.consultas, 1)
            self.assertFalse((carpeta / 'viejo.json').exists())
            self.assertIsNotNone(contrato.Grabadora.inicio(carpeta))
            archivo = json.loads((carpeta / 'subfinder_acme-demo.mx.json').read_text(encoding='utf-8'))
            self.assertEqual(set(archivo['datos']), {'lineas', 'avisos', 'indices', 'via'})
            self.assertEqual((archivo['datos']['indices'], archivo['datos']['via']), (RECIENTES, 'athena'))
            otra, c = recolectar(None, modo='reproducir', carpeta=carpeta, entorno={})
        self.assertEqual((c.consultas, otra.consultas), (0, 0))
        self.assertEqual((otra.activos, otra.avisos), (grabado.activos, grabado.avisos))

    def test_2_una_corrida_fallida_no_borra_la_grabacion_anterior(self):
        for fallas in ({'get_query_results': [FallaAws('InternalServerException')]},
                       {'get_work_group': [FallaAws('AccessDeniedException')]}):
            with self.subTest(fallas=list(fallas)), tempfile.TemporaryDirectory() as d:
                carpeta = Path(d) / 'acme-demo.mx'
                recolectar(AthenaSimulada(), modo='grabar', carpeta=carpeta, nueva=True)
                antes = (carpeta / 'subfinder_acme-demo.mx.json').read_bytes()
                with self.assertRaises(contrato.FuenteNoResponde):
                    recolectar(AthenaSimulada(fallas=fallas), modo='grabar', carpeta=carpeta, nueva=True)
                self.assertEqual((carpeta / 'subfinder_acme-demo.mx.json').read_bytes(), antes)
                self.assertIn(b'www.acme-demo.mx', antes)

    def test_3_cero_nombres_si_se_graba_y_se_reproduce(self):
        with tempfile.TemporaryDirectory() as d:
            vacia = por_ejecutar(AthenaSimulada([]), 'grabar', d)
            self.assertEqual((vacia.estado, vacia.activos), ('succeeded', []))
            otra = por_ejecutar(None, 'reproducir', d, entorno={})
        self.assertEqual((otra.estado, otra.activos, otra.avisos, otra.consultas),
                         ('succeeded', [], [subfinder.SIN_CAPTURAS % 12], 0))

    def test_4_reproducir_sin_grabacion_es_succeeded_con_aviso(self):
        res = por_ejecutar(None, modo='reproducir', entorno={})
        self.assertEqual((res.estado, res.error, res.activos, res.consultas), ('succeeded', '', [], 0))
        self.assertEqual(res.avisos, ['subfinder: no hay grabación de Common Crawl de este dominio, no se revisó '
                                      'Common Crawl'])

    def test_5_una_grabacion_del_cdx_se_sigue_leyendo_con_sus_revisados(self):
        viejo = {'lineas': [{'host': 'www.acme-demo.mx', 'input': 'acme-demo.mx', 'sources': ['commoncrawl']}],
                 'avisos': ['subfinder: Common Crawl no respondió en %s (HTTP 504 tras 3 intentos), se revisaron los '
                            'demás índices' % RECIENTES[3]], 'indices': RECIENTES,
                 'revisados': RECIENTES[:3] + RECIENTES[4:]}
        with tempfile.TemporaryDirectory() as d:
            contrato.Grabadora(Path(d) / 'acme-demo.mx', 'grabar').guardar('subfinder:acme-demo.mx', viejo)
            res = por_ejecutar(None, 'reproducir', d, entorno={})
        self.assertEqual((res.estado, res.consultas), ('succeeded', 0))
        self.assertEqual([a.valor for a in res.activos], ['www.acme-demo.mx'])
        self.assertEqual((res.revisados, res.sin_revisar), (RECIENTES[:3] + RECIENTES[4:], [RECIENTES[3]]))
        self.assertEqual(res.avisos, viejo['avisos'])

    def test_6_una_grabacion_de_athena_no_lleva_revisados(self):
        with tempfile.TemporaryDirectory() as d:
            por_ejecutar(AthenaSimulada(), 'grabar', d)
            res = por_ejecutar(None, 'reproducir', d, entorno={})
        self.assertEqual((res.revisados, res.sin_revisar), (None, None))

    def test_7_revisados_de_una_grabacion_que_no_cuadran_es_failed(self):
        bien = {'lineas': [], 'avisos': [], 'indices': RECIENTES[:3]}
        for revisados in ('CC-MAIN-2026-47', [], [RECIENTES[0], RECIENTES[0]], ['CC-MAIN-2019-01'], RECIENTES[:3],
                          [5], ['../x']):
            with self.subTest(revisados=revisados), tempfile.TemporaryDirectory() as d:
                contrato.Grabadora(Path(d) / 'acme-demo.mx', 'grabar').guardar(
                    'subfinder:acme-demo.mx', dict(bien, revisados=revisados))
                res = por_ejecutar(None, 'reproducir', d, entorno={})
                self.assertEqual(res.estado, 'failed')
                self.assertIn('no se puede leer', res.error)

    def test_8_una_grabacion_que_no_se_puede_leer_si_es_failed(self):
        for datos in (['otra', 'forma'], {'lineas': 'x', 'avisos': []}, {'lineas': []}):
            with self.subTest(datos=datos), tempfile.TemporaryDirectory() as d:
                contrato.Grabadora(Path(d) / 'acme-demo.mx', 'grabar').guardar('subfinder:acme-demo.mx', datos)
                res = por_ejecutar(None, 'reproducir', d, entorno={})
                self.assertEqual(res.estado, 'failed')
                self.assertIn('no se puede leer', res.error)

    def test_9_reproducir_no_importa_boto3_ni_pide_variables(self):
        with tempfile.TemporaryDirectory() as d:
            por_ejecutar(AthenaSimulada(), 'grabar', d)
            # Con boto3 en None, `import boto3` lanza ImportError: reproducir no llega a pedirlo.
            with mock.patch.dict(sys.modules, {'boto3': None, 'botocore': None}):
                res = por_ejecutar(None, 'reproducir', d, entorno={v: '' for v in subfinder.VARIABLES})
        self.assertEqual((res.estado, res.consultas), ('succeeded', 0))
        self.assertEqual(len(res.activos), 3)


class Consultas(unittest.TestCase):

    def test_1_una_consulta_sin_fallas_dos_con_crawl_nuevo_y_ninguna_al_reproducir(self):
        self.assertEqual(por_ejecutar(AthenaSimulada()).consultas, 1)
        self.assertEqual(por_ejecutar(AthenaSimulada([])).consultas, 1)
        self.assertEqual(por_ejecutar(AthenaSimulada(faltan=[RECIENTES[0]])).consultas, 2)
        self.assertEqual(por_ejecutar(None, 'reproducir', entorno={}).consultas, 0)

    def test_2_max_consultas_es_el_alter_el_select_y_un_reintento(self):
        self.assertEqual(subfinder.MAX_CONSULTAS, 1 + 1 + subfinder.REINTENTOS)
        self.assertEqual((subfinder.MAX_CONSULTAS, subfinder.REINTENTOS), (3, 1))
        # un throttling también cuenta: se pidió
        res = por_ejecutar(AthenaSimulada(fallas={'start_query_execution': [FallaAws('ThrottlingException')]}))
        self.assertEqual(res.consultas, 2)

    def test_3_las_llamadas_que_no_cobran_no_cuentan(self):
        simulado = AthenaSimulada(estados={0: ['QUEUED', 'RUNNING', 'SUCCEEDED']})
        res, _ = recolectar(simulado)
        self.assertEqual(res.consultas, 1)
        self.assertEqual(simulado.metodos().count('get_query_execution'), 3)


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


def cambios_de(semilla):
    texto = re.sub(r'--[^\n]*', '', semilla.read_text(encoding='utf-8'))
    return texto, re.findall(r"UPDATE\s+data_sources\s+SET\s+(\w+)\s*=\s*(\w+)\s+WHERE\s+code\s*=\s*'subfinder'"
                             r"\s+AND\s+(\w+)\s*=\s*(\w+)\s*;", texto, re.IGNORECASE)


class Semilla(unittest.TestCase):
    """Lectura estática de las semillas 005, 017 y 018, sin base."""

    def test_1_la_005_lo_siembra_apagado_con_400(self):
        fila = fila_de_la_semilla('subfinder')
        self.assertIsNotNone(fila, 'la semilla 005 no trae la fila de subfinder en su INSERT INTO data_sources')
        self.assertEqual(fila['enabled'].lower(), 'false')
        self.assertEqual(int(fila['daily_limit']), 400)  # 50 corridas de las 8 fuentes de entonces

    def test_2_la_017_lo_prende_con_390(self):
        _, cambios = cambios_de(SEMILLA_017)
        self.assertEqual(sorted(cambios), [('daily_limit', '390', 'daily_limit', '400'),
                                           ('enabled', 'true', 'enabled', 'false')])

    def test_3_la_018_baja_el_limite_a_100_sin_pisar_uno_puesto_a_mano(self):
        texto, cambios = cambios_de(SEMILLA_018)
        self.assertEqual(cambios, [('daily_limit', '100', 'daily_limit', '390')])
        # El orquestador reserva MAX_CONSULTAS (3) antes de cada corrida y luego ajusta a las que se pidieron: 33 de
        # peor caso por día, y 98 de una consulta (la 99 pide 98 + 3 = 101).
        self.assertEqual(100 // subfinder.MAX_CONSULTAS, 33)
        self.assertEqual((100 - subfinder.MAX_CONSULTAS) // 1 + 1, 98)
        self.assertIn('RAISE EXCEPTION', texto)   # sin la fila falla
        self.assertRegex(texto, r'daily_limit\s*<\s*%d\b' % subfinder.MAX_CONSULTAS)
        self.assertTrue(texto.lstrip().startswith("SET client_encoding = 'UTF8';"))
        self.assertEqual(sorted(p.name[:3] for p in SEMILLA_018.parent.glob('*.sql')).count('018'), 1)
        self.assertIn('018_subfinder_athena.sql', (RAIZ / 'db' / 'README.md').read_text(encoding='utf-8'))


@unittest.skipUnless((RAIZ / 'docker-compose.yml').exists(), 'sin docker-compose.yml: dentro de la imagen no se copia')
class Despliegue(unittest.TestCase):
    """Las 4 variables llegan al contenedor de la API, solo por nombre (lectura estática)."""

    def test_1_el_compose_pasa_las_4_variables_vacias_por_omision(self):
        texto = (RAIZ / 'docker-compose.yml').read_text(encoding='utf-8')
        api = texto[texto.index('\n  api:'):texto.index('\n  demo-accounts:')]
        for variable in subfinder.VARIABLES:
            self.assertIn('%s: ${%s:-}' % (variable, variable), api)
        ejemplo = (RAIZ / '.env.example').read_text(encoding='utf-8')
        for variable in subfinder.VARIABLES:
            self.assertRegex(ejemplo, r'(?m)^# %s=(cc-subdominios)?$' % variable)

    def test_2_boto3_va_fijo_en_requirements(self):
        texto = (RAIZ / 'requirements.txt').read_text(encoding='utf-8')
        self.assertRegex(texto, r'(?m)^boto3==\d+\.\d+\.\d+$')
        self.assertNotRegex(texto, r'(?m)^botocore')   # lo fija boto3


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


HAY_BOTOCORE = importlib.util.find_spec('botocore') is not None


@unittest.skipUnless(HAY_BOTOCORE or os.environ.get('INTEGRACION_SUBFINDER') == '1',
                     'sin botocore: corre dentro del contenedor con INTEGRACION_SUBFINDER=1')
class ClientesReales(unittest.TestCase):
    """_clientes_reales con la llave falsa y botocore.stub.Stubber: cada pedido y cada respuesta se revisan contra el
    modelo de la API de AWS, sin red. Con INTEGRACION_SUBFINDER=1 y sin boto3 en la imagen falla en vez de saltarse."""

    def reales(self):
        cred = subfinder.credenciales(ENTORNO)
        with mock.patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'CIRDAN_FAKE_OTRA0000000000',
                                          'AWS_SECRET_ACCESS_KEY': 'CIRDAN_FAKE_otra', 'AWS_PROFILE': ''}):
            return subfinder._clientes_reales(cred)

    def test_1_extremos_fijos_de_us_east_1_con_tls_la_llave_de_cc_athena_y_sus_tiempos(self):
        athena, glue, s3, fallas = self.reales()
        from botocore.exceptions import BotoCoreError, ClientError
        self.assertEqual(fallas, (BotoCoreError, ClientError))
        for c, servicio in ((athena, 'athena'), (glue, 'glue'), (s3, 's3')):
            with self.subTest(servicio=servicio):
                self.assertEqual(c.meta.service_model.service_name, servicio)
                self.assertEqual(c.meta.endpoint_url, 'https://%s.us-east-1.amazonaws.com' % servicio)
                self.assertEqual(c.meta.region_name, 'us-east-1')
                self.assertEqual(c.meta.config.connect_timeout, 10)
                self.assertEqual(c.meta.config.read_timeout, 30)
                self.assertEqual(c.meta.config.retries, {'mode': 'standard', 'total_max_attempts': 3})
                self.assertEqual(c._endpoint.http_session._verify, True)
                credencial = c._request_signer._credentials
                self.assertEqual((credencial.access_key, credencial.secret_key, credencial.token), (LLAVE, CLAVE, None))

    def test_2_una_corrida_entera_con_stubber(self):
        from botocore.stub import Stubber
        athena, glue, s3, fallas = self.reales()
        stubs = [Stubber(c) for c in (athena, glue, s3)]
        sa, sg, ss = stubs
        sa.add_response('get_work_group', workgroup(), {'WorkGroup': 'cc-subdominios'})
        ss.add_response('list_objects_v2', {'CommonPrefixes': [{'Prefix': p} for p in PREFIJOS], 'IsTruncated': False},
                        {'Bucket': 'commoncrawl', 'Prefix': 'cc-index/table/cc-main/warc/', 'Delimiter': '/'})
        sg.add_response('batch_get_partition', {'Partitions': [
            {'Values': [c, 'warc'], 'DatabaseName': 'ccindex', 'TableName': 'ccindex'} for c in RECIENTES[1:]]},
            {'DatabaseName': 'ccindex', 'TableName': 'ccindex',
             'PartitionsToGet': [{'Values': [c, 'warc']} for c in RECIENTES]})
        sa.add_response('start_query_execution', {'QueryExecutionId': 'id-alter'}, {
            'QueryString': subfinder.consulta_particiones([RECIENTES[0]]), 'WorkGroup': 'cc-subdominios',
            'QueryExecutionContext': {'Database': 'ccindex'}})
        sa.add_response('get_query_execution', {'QueryExecution': {'QueryExecutionId': 'id-alter', 'Status': {
            'State': 'SUCCEEDED'}, 'Statistics': {'DataScannedInBytes': 0}}}, {'QueryExecutionId': 'id-alter'})
        texto, parametros = subfinder.consulta_select('acme-demo.mx', RECIENTES)
        sa.add_response('start_query_execution', {'QueryExecutionId': 'id-select'}, {
            'QueryString': texto, 'WorkGroup': 'cc-subdominios', 'QueryExecutionContext': {'Database': 'ccindex'},
            'ExecutionParameters': parametros})
        sa.add_response('get_query_execution', {'QueryExecution': {'QueryExecutionId': 'id-select', 'Status': {
            'State': 'RUNNING'}}}, {'QueryExecutionId': 'id-select'})
        sa.add_response('get_query_execution', {'QueryExecution': {'QueryExecutionId': 'id-select', 'Status': {
            'State': 'SUCCEEDED'}, 'Statistics': {'DataScannedInBytes': 5 << 20}}}, {'QueryExecutionId': 'id-select'})
        sa.add_response('get_query_results', {'ResultSet': {'Rows': [
            {'Data': [{'VarCharValue': 'url_host_name'}]}, {'Data': [{'VarCharValue': 'www.acme-demo.mx'}]}]},
            'NextToken': 'pagina2'}, {'QueryExecutionId': 'id-select', 'MaxResults': 1000})
        sa.add_response('get_query_results',
                        {'ResultSet': {'Rows': [{'Data': [{'VarCharValue': 'api.acme-demo.mx'}]}]}},
                        {'QueryExecutionId': 'id-select', 'MaxResults': 1000, 'NextToken': 'pagina2'})
        for s in stubs:
            s.activate()
        c = cliente(lambda cred: (athena, glue, s3, fallas))
        res = subfinder.recolectar('acme-demo.mx', c, AHORA)
        for s in stubs:
            s.assert_no_pending_responses()
        self.assertEqual((res.estado, res.error, res.consultas, c.bytes_leidos), ('succeeded', '', 2, 5 << 20))
        self.assertEqual([a.valor for a in res.activos], ['api.acme-demo.mx', 'www.acme-demo.mx'])

    def test_3_un_client_error_de_aws_sale_con_su_codigo_y_sin_el_mensaje(self):
        from botocore.stub import Stubber
        athena, glue, s3, fallas = self.reales()
        stub = Stubber(athena)
        stub.add_client_error('get_work_group', service_error_code='AccessDeniedException',
                              service_message='User arn:aws:iam::123456789012:user/x %s' % LLAVE, http_status_code=400)
        stub.activate()
        _, error = enumerar(lambda cred: (athena, glue, s3, fallas))
        self.assertEqual(str(error), 'subfinder: AWS no respondió en el workgroup (AccessDeniedException)')

    def test_4_un_tope_de_bytes_de_10_mb_tambien_vale(self):
        """El mínimo que acepta Athena es 10 MB: el código acepta cualquier tope entre 1 byte y 1 GB."""
        from botocore.stub import Stubber
        athena, glue, s3, fallas = self.reales()
        stub = Stubber(athena)
        stub.add_response('get_work_group', workgroup(BytesScannedCutoffPerQuery=10 << 20))
        stub.activate()
        c = cliente(lambda cred: (athena, glue, s3, fallas))
        c.athena, c.workgroup = athena, 'cc-subdominios'
        c.fallas = fallas
        c._revisar_workgroup(subfinder.credenciales(ENTORNO), 1e12)

    def test_5_un_perfil_ajeno_de_aws_config_file_no_cambia_nada(self):
        """AWS_PROFILE apunta a un perfil que sí existe en AWS_CONFIG_FILE, con otra región, otros reintentos y otra
        llave: el cliente sigue con lo suyo."""
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / 'config'
            config.write_text('[profile ajeno]\nregion = eu-west-1\nretry_mode = legacy\nmax_attempts = 9\n'
                              'aws_access_key_id = CIRDAN_FAKE_AJENA000000000\naws_secret_access_key = CIRDAN_FAKE_x\n',
                              encoding='utf-8')
            otras = {'AWS_PROFILE': 'ajeno', 'AWS_CONFIG_FILE': str(config), 'AWS_SHARED_CREDENTIALS_FILE': str(config)}
            with mock.patch.dict(os.environ, otras):
                athena, glue, s3, fallas = subfinder._clientes_reales(subfinder.credenciales(ENTORNO))
        for c in (athena, glue, s3):
            self.assertEqual(c.meta.region_name, 'us-east-1')
            self.assertEqual(c.meta.config.retries, {'mode': 'standard', 'total_max_attempts': 3})
            self.assertEqual(c._request_signer._credentials.access_key, LLAVE)


@unittest.skipUnless(os.environ.get('INTEGRACION_SUBFINDER') == '1',
                     'corre dentro del contenedor con INTEGRACION_SUBFINDER=1')
class Integracion(unittest.TestCase):
    """Dentro de la imagen y como el usuario cirdan, sin las variables de Athena: grabar queda en FuenteNoResponde con
    sus nombres y no graba, y reproducir no carga boto3."""

    def test_1_sin_variables_queda_failed_y_no_graba(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d) / 'acme-demo.mx'
            c = subfinder.ClienteSubfinder(modo='grabar', carpeta=carpeta, nueva=True, entorno={},
                                           dormir=lambda s: None)
            with self.assertRaises(contrato.FuenteNoResponde) as error:
                c.enumerar('acme-demo.mx')
            self.assertIn('faltan las variables CC_ATHENA_ACCESS_KEY_ID', str(error.exception))
            self.assertEqual(c.consultas, 0)
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

    def test_3_reproducir_en_un_proceso_nuevo_no_importa_boto3(self):
        codigo = ('import sys; from cirdan.recolectores import contrato, cargar; '
                  "r = contrato.ejecutar(cargar('subfinder'), 'acme-demo.mx', modo='reproducir'); "
                  "print(r.estado, 'boto3' in sys.modules, 'botocore' in sys.modules)")
        salida = subprocess.run([sys.executable, '-c', codigo], capture_output=True, text=True, timeout=60,
                                cwd=str(RAIZ), env={k: v for k, v in os.environ.items() if not k.startswith('CC_')})
        self.assertEqual((salida.returncode, salida.stdout.strip()), (0, 'succeeded False False'), salida.stderr)

    def test_4_boto3_esta_en_la_imagen(self):
        import boto3   # noqa: F401
        import botocore   # noqa: F401


if __name__ == '__main__':
    unittest.main()
