"""Subdominios pasivos del URL Index de Common Crawl con Amazon Athena (#14b, RC-184), en la fuente subfinder.

La fuente se llama subfinder porque nació para correr el binario de ProjectDiscovery con sus fuentes pasivas. El 15 nov,
de sus 20 fuentes solo commoncrawl pasó la revisión de términos (decisión 6 de docs/servicios_externos.md). Del 15 al
16 nov este recolector pidió el CDX de index.commoncrawl.org, pero ese servidor está saturado y corta con 504 a los
~10 s. Desde el 16 nov lee la copia columnar del mismo índice (el URL Index, s3://commoncrawl/cc-index/table/) con una
consulta de Athena en us-east-1, en la cuenta de AWS de LowTide. La fila de data_sources, la carpeta de grabaciones, el
origen 'commoncrawl' de los activos y la forma de lo grabado siguen iguales. El binario sigue en la imagen sin usarse.

Qué pide, sin tocar los servidores del dominio ni a index.commoncrawl.org:
- GetWorkGroup del workgroup CC_ATHENA_WORKGROUP: que esté prendido, que imponga su configuración, que su salida sea
  CC_ATHENA_SALIDA y que tenga un tope de bytes por consulta de a lo más TOPE_BYTES. Sin eso no corre ninguna consulta:
  el tope es lo que impide que una consulta mal podada cueste más de unos centavos.
- ListObjectsV2 de s3://commoncrawl/cc-index/table/cc-main/warc/ con Delimiter '/': los prefijos crawl=CC-MAIN-AAAA-SS/
  dan los INDICES crawls más recientes. Cada id pasa por ID_INDICE.
- BatchGetPartition de la tabla ccindex.ccindex: qué crawls ya tiene. Los que falten (un crawl nuevo, uno al mes) se
  agregan con un ALTER TABLE ADD IF NOT EXISTS PARTITION, que es DDL: Athena no lo cobra.
- Un SELECT DISTINCT url_host_name de los INDICES crawls, con la poda por url_surtkey (las etiquetas del dominio al
  revés, unidas con coma) y el filtro exacto url_host_name = dominio o termina en '.' + dominio, LIMIT LIMITE_FILAS + 1.
  El dominio, su clave SURT y los crawls van en ExecutionParameters, nunca pegados en el texto del SQL.
De cada fila solo se guarda el nombre del host. Lo recibe AWS (Athena, Glue y S3), no Common Crawl.

La consulta es todo o nada: si termina, se revisaron los INDICES crawls, y 0 nombres es un resultado de verdad que se
graba, con el aviso SIN_CAPTURAS. Con LIMITE_FILAS + 1 filas lleva el aviso RECORTADO. Una consulta FAILED con categoría
de error 1 (del sistema) o una StartQueryExecution con ThrottlingException se intenta otra vez, una sola en la corrida.
Un error de categoría 2 o 3, una consulta CANCELLED (el tope de bytes del workgroup la cancela) o cualquier falla de
AWS deja la corrida en FuenteNoResponde, sin grabar. Toda la corrida tiene MAX_SEGUNDOS: el estado se pregunta tras
ESPERAS y luego cada ESPERA_MAXIMA s, y si ya no cabe otra espera se pide StopQueryExecution y queda FuenteNoResponde.
Cada llamada a AWS tiene a lo más TIMEOUT_CONEXION + TIMEOUT_LECTURA por intento y INTENTOS_AWS intentos (botocore,
modo standard). Una llamada que empezó antes de MAX_SEGUNDOS puede terminar después: el peor caso de una corrida es
MAX_SEGUNDOS más una llamada, unos 180 + 3 x 40 + 40 de esperas de botocore = 340 s, debajo de TOPE_CORRIDA (20 min).

Credenciales: CC_ATHENA_ACCESS_KEY_ID, CC_ATHENA_SECRET_ACCESS_KEY, CC_ATHENA_WORKGROUP y CC_ATHENA_SALIDA (VARIABLES).
El cliente arma su propia sesión de boto3 con esas y los extremos fijos de us-east-1, así nunca toma otras credenciales
de AWS_* ni de ~/.aws. Si falta alguna, vivo y grabar dan FuenteNoResponde con los nombres de las que faltan, nunca sus
valores. La llave no va a errores, avisos ni grabaciones: los errores solo llevan el código de AWS o el tipo.

Modos: 'vivo' consulta; 'grabar' además guarda el resultado ya leído (líneas, avisos, crawls y 'via': 'athena') en
cirdan/recolectores/respuestas_grabadas/subfinder/<dominio>/ con la Grabadora del contrato (#13); 'reproducir' solo lee
esa grabación, no importa boto3 ni pide variables. Las grabaciones del CDX (sin 'via', quizá con 'revisados') se siguen
leyendo. Sin grabación del dominio, reproducir sale succeeded con el aviso SIN_GRABACION_DOMINIO y sin activos, como
github.py. Un archivo de la grabación que no se puede leer sí es FuenteNoResponde. En la imagen, el usuario cirdan es
dueño de respuestas_grabadas/subfinder/ y de nada más (Dockerfile), así que puede grabar dentro del contenedor.

Consultas del límite diario (#13b): una consulta es una StartQueryExecution, lo que cobra Athena. GetWorkGroup,
ListObjectsV2, BatchGetPartition, GetQueryExecution, GetQueryResults y StopQueryExecution no cuentan: cuestan fracciones
de centavo y no leen el índice. MAX_CONSULTAS es el ALTER de particiones, el SELECT y el reintento de la corrida (3).
`consultas` cuenta las que sí se pidieron (1 o 2 sin fallas), y 0 al reproducir.
"""
import os
import re
import time

from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import (NOMBRE_VALIDO, Activo, FuenteNoResponde, Grabadora, Resultado, SinGrabacion,
                                          en_alcance_nombre)

FUENTE = 'subfinder'
CARPETA_GRABADAS = RAIZ_GRABADAS / 'subfinder'

# Solo activos: ningún código de regla (pruebas/test_catalogo_reglas.py acepta el dict vacío).
CODIGOS = {}

# La única fuente que pasó la regla de la decisión 6 de docs/servicios_externos.md (sus términos publicados permiten el
# uso automático y mostrar sus datos a terceros). Va en 'origen' de cada activo.
ORIGEN = 'commoncrawl'
VIA = 'athena'                       # va en lo grabado: las grabaciones del CDX no lo llevan
REGION = 'us-east-1'                 # ahí vive s3://commoncrawl y Athena lo lee sin cargo de transferencia
BUCKET_CC = 'commoncrawl'
PREFIJO_CC = 'cc-index/table/cc-main/warc/'
CRAWL_DE_PREFIJO = re.compile(re.escape(PREFIJO_CC) + r'crawl=(CC-MAIN-[0-9]{4}-[0-9]{2})/')
BASE = 'ccindex'                     # base y tabla del DDL oficial de commoncrawl/cc-index-table
TABLA = 'ccindex'
ID_INDICE = re.compile(r'CC-MAIN-[0-9]{4}-[0-9]{2}')
INDICES = 12                         # los crawls más recientes que se revisan: unos 12 son un año
LIMITE_FILAS = 5000                  # nombres distintos. La consulta pide uno más: si llega, el aviso RECORTADO
FILAS_POR_PAGINA = 1000              # el máximo de GetQueryResults
MAX_PAGINAS_RESULTADOS = 7           # 5001 filas y el encabezado caben en 6
MAX_PAGINAS_S3 = 3                   # unos 120 crawls caben en una página de ListObjectsV2 (1000 prefijos)
TOPE_BYTES = 1 << 30                 # el tope de bytes por consulta del workgroup no puede pasar de 1 GB (0.005 USD)
MAX_SEGUNDOS = 180                   # de toda la corrida, esperas incluidas
MINIMO_CONSULTA = 10                 # segundos que tienen que quedar para pedir una StartQueryExecution
ESPERAS = (1, 2, 4)                  # segundos antes de preguntar otra vez el estado de una consulta
ESPERA_MAXIMA = 5                    # y luego cada 5 s
TIMEOUT_CONEXION = 10
TIMEOUT_LECTURA = 30
INTENTOS_AWS = 3                     # de cada llamada, con los reintentos de botocore (modo standard)
REINTENTOS = 1                       # StartQueryExecution de más en toda la corrida
MAX_CONSULTAS = 1 + 1 + REINTENTOS   # el ALTER de particiones, el SELECT y el reintento: 3
VARIABLES = ('CC_ATHENA_ACCESS_KEY_ID', 'CC_ATHENA_SECRET_ACCESS_KEY', 'CC_ATHENA_WORKGROUP', 'CC_ATHENA_SALIDA')
LLAVE_VALIDA = re.compile(r'[A-Z0-9_]{16,128}')   # AKIA... de AWS, o la CIRDAN_FAKE_ de las pruebas
WORKGROUP_VALIDO = re.compile(r'[A-Za-z0-9._-]{1,128}')
SALIDA_VALIDA = re.compile(r's3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](/[A-Za-z0-9!_.*\'()/-]*)?')
ID_CONSULTA = re.compile(r'[A-Za-z0-9-]{1,128}')
CODIGO_AWS = re.compile(r'[A-Za-z0-9.]{1,64}')
LENTO = ('ThrottlingException', 'TooManyRequestsException')   # StartQueryExecution: bajar el ritmo y reintentar
# Lo que va en ExecutionParameters, ya entre comillas simples: nunca trae una comilla porque el dominio pasó
# NOMBRE_VALIDO y los crawls ID_INDICE. Se revisa otra vez aquí, por si alguien cambia esas reglas.
PARAMETRO_VALIDO = re.compile(r'[a-z0-9.,~%-]{1,260}|CC-MAIN-[0-9]{4}-[0-9]{2}')
CONSULTA = 'subfinder:'              # consulta de la grabadora: subfinder_<dominio>.json
SIN_CAPTURAS = 'subfinder: Common Crawl no tiene capturas de este dominio en sus últimos %d índices'
SIN_GRABACION_DOMINIO = 'subfinder: no hay grabación de Common Crawl de este dominio, no se revisó Common Crawl'
RECORTADO = 'subfinder: Common Crawl llegó al tope de %d nombres, la lista puede estar incompleta'
NOMBRE_FUENTE = re.compile(r'[a-z0-9_-]{1,40}')

SQL = ('SELECT DISTINCT url_host_name FROM ccindex WHERE crawl IN (%s) AND subset = \'warc\' '
       'AND url_surtkey >= ? AND url_surtkey < ? AND (url_host_name = ? OR url_host_name LIKE ?) LIMIT %d')


def clave_surt(dominio):
    """Las etiquetas del dominio al revés, unidas con coma: olmardo.com da 'com,olmardo'. Es el principio de la
    url_surtkey de sus páginas y de las de sus subdominios ('com,olmardo)/', 'com,olmardo,www)/')."""
    return ','.join(reversed(dominio.split('.')))


def _literal(valor):
    """Un texto de ExecutionParameters: Athena pone cada uno tal cual en su '?', así que va entre comillas simples."""
    if not PARAMETRO_VALIDO.fullmatch(valor):
        raise FuenteNoResponde('subfinder: un parámetro de la consulta no tiene la forma esperada')
    return "'%s'" % valor


def consulta_select(dominio, crawls):
    """(texto del SQL, ExecutionParameters) del SELECT: el texto no lleva el dominio ni los crawls."""
    surt = clave_surt(dominio)
    texto = SQL % (', '.join('?' for _ in crawls), LIMITE_FILAS + 1)
    return texto, [_literal(c) for c in crawls] + [_literal(surt), _literal(surt + '~'), _literal(dominio),
                                                   _literal('%.' + dominio)]


def consulta_particiones(crawls):
    """El ALTER TABLE que agrega las particiones que faltan. Es DDL y no acepta ExecutionParameters: cada crawl pasó
    ID_INDICE, así que no trae comillas ni espacios."""
    partes = []
    for c in crawls:
        if not ID_INDICE.fullmatch(c):
            raise FuenteNoResponde('subfinder: un crawl no tiene la forma CC-MAIN-AAAA-SS')
        partes.append("PARTITION (crawl = '%s', subset = 'warc') LOCATION 's3://%s/%scrawl=%s/subset=warc/'" % (
            c, BUCKET_CC, PREFIJO_CC, c))
    return 'ALTER TABLE %s ADD IF NOT EXISTS %s' % (TABLA, ' '.join(partes))


def _codigo(error):
    """El código de AWS de una falla (ThrottlingException, AccessDeniedException...) o el tipo, nunca el mensaje."""
    respuesta = getattr(error, 'response', None)
    codigo = respuesta.get('Error', {}).get('Code') if isinstance(respuesta, dict) else None
    return codigo if isinstance(codigo, str) and CODIGO_AWS.fullmatch(codigo) else type(error).__name__


def _sin_tiempo(que):
    return FuenteNoResponde('subfinder: Athena no terminó en %d s (faltó %s)' % (MAX_SEGUNDOS, que))


def _rara(que):
    return FuenteNoResponde('subfinder: AWS dio una respuesta que no se puede leer en %s' % que)


def credenciales(entorno):
    """{nombre: valor} de VARIABLES, o FuenteNoResponde con los nombres de las que faltan o no tienen la forma."""
    valores = {v: (entorno.get(v) or '').strip() for v in VARIABLES}
    reglas = {'CC_ATHENA_ACCESS_KEY_ID': LLAVE_VALIDA, 'CC_ATHENA_WORKGROUP': WORKGROUP_VALIDO,
              'CC_ATHENA_SALIDA': SALIDA_VALIDA}
    malas = [v for v in VARIABLES if not valores[v] or (v in reglas and not reglas[v].fullmatch(valores[v]))]
    if malas:
        raise FuenteNoResponde('subfinder: faltan las variables %s o no tienen la forma esperada' % ', '.join(malas))
    return valores


def _clientes_reales(cred):
    """(athena, glue, s3, fallas) con boto3. Se importa aquí: reproducir nunca lo carga. La sesión lleva solo la llave
    de CC_ATHENA_* y cada cliente su extremo fijo de us-east-1, con TLS verificado."""
    import boto3
    import botocore.session
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError
    # Sin ~/.aws ni AWS_CONFIG_FILE, AWS_SHARED_CREDENTIALS_FILE, AWS_PROFILE o AWS_DEFAULT_PROFILE: (nombre en el
    # config, variable de entorno, valor por omisión, conversión) sin variable de entorno. Un perfil ajeno no cambia la
    # llave, la región ni los reintentos, y uno que no existe no hace fallar la sesión.
    base = botocore.session.Session(session_vars={'profile': (None, None, None, None),
                                                  'config_file': (None, None, os.devnull, None),
                                                  'credentials_file': (None, None, os.devnull, None)})
    sesion = boto3.session.Session(aws_access_key_id=cred['CC_ATHENA_ACCESS_KEY_ID'],
                                   aws_secret_access_key=cred['CC_ATHENA_SECRET_ACCESS_KEY'],
                                   aws_session_token=None, region_name=REGION, botocore_session=base)
    config = Config(region_name=REGION, connect_timeout=TIMEOUT_CONEXION, read_timeout=TIMEOUT_LECTURA,
                    retries={'mode': 'standard', 'total_max_attempts': INTENTOS_AWS})
    clientes = [sesion.client(s, config=config, verify=True, endpoint_url='https://%s.%s.amazonaws.com' % (s, REGION))
                for s in ('athena', 'glue', 's3')]
    return clientes + [(BotoCoreError, ClientError)]


class ClienteSubfinder:
    """Pide el URL Index de Common Crawl a Athena y, según el modo, graba o reproduce el resultado ya leído con la
    Grabadora (#13).

    `aws` (athena, glue, s3, fallas), `entorno`, `cronometro` y `dormir` se inyectan en las pruebas. Por omisión son
    _clientes_reales, os.environ, time.monotonic y time.sleep. `reloj` es el de la Grabadora (fecha de grabación).
    `consultas` suma cada StartQueryExecution que sí se pidió y `bytes_leidos` lo que Athena dice que leyó."""

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, aws=None, entorno=None, nueva=False, reloj=None,
                 cronometro=None, dormir=None):
        self.modo = modo
        self.grabadora = Grabadora(carpeta, modo, nueva=nueva, reloj=reloj)
        self.fabrica = aws or _clientes_reales
        self.entorno = entorno if entorno is not None else os.environ
        self.cronometro = cronometro or time.monotonic
        self.dormir = dormir or time.sleep
        self.consultas = 0
        self.bytes_leidos = 0
        self.reintentos = REINTENTOS
        self.athena = self.glue = self.s3 = None
        self.fallas = ()
        self.workgroup = None

    @property
    def leidas(self):
        """(archivo, fecha de grabación) de cada respuesta tomada del disco."""
        return self.grabadora.leidas

    def _aws(self, que, llamada, fin, **parametros):
        """Una llamada a AWS si la corrida todavía tiene tiempo. Una falla sale como FuenteNoResponde con el código de
        AWS en `codigo` y en el texto, sin el mensaje (puede traer la cuenta o el texto de la consulta)."""
        if self.cronometro() >= fin:
            raise _sin_tiempo(que)
        try:
            return llamada(**parametros)
        except self.fallas as e:
            codigo = _codigo(e)
            error = FuenteNoResponde('subfinder: AWS no respondió en %s (%s)' % (que, codigo))
            error.codigo = codigo
            raise error from None

    def _revisar_workgroup(self, cred, fin):
        r = self._aws('el workgroup', self.athena.get_work_group, fin, WorkGroup=self.workgroup)
        try:
            grupo = r['WorkGroup']
            config = grupo['Configuration']
            salida = config.get('ResultConfiguration', {}).get('OutputLocation')
            tope = config.get('BytesScannedCutoffPerQuery')
            prendido, impone = grupo.get('State'), config.get('EnforceWorkGroupConfiguration')
        except (KeyError, TypeError, AttributeError):
            raise _rara('el workgroup') from None
        if prendido != 'ENABLED' or impone is not True:
            raise FuenteNoResponde('subfinder: el workgroup de Athena no está prendido o no impone su configuración')
        if type(tope) is not int or not 0 < tope <= TOPE_BYTES:
            raise FuenteNoResponde('subfinder: el workgroup de Athena no tiene un tope de bytes por consulta de a lo '
                                   'más %d MB' % (TOPE_BYTES >> 20))
        if not isinstance(salida, str) or salida.rstrip('/') != cred['CC_ATHENA_SALIDA'].rstrip('/'):
            raise FuenteNoResponde('subfinder: la salida del workgroup de Athena no es CC_ATHENA_SALIDA')

    def _crawls(self, fin):
        """Los INDICES crawls más recientes según los prefijos de S3, del más nuevo al más viejo."""
        ids, pedido = set(), {'Bucket': BUCKET_CC, 'Prefix': PREFIJO_CC, 'Delimiter': '/'}
        for _ in range(MAX_PAGINAS_S3):
            r = self._aws('la lista de crawls', self.s3.list_objects_v2, fin, **pedido)
            try:
                prefijos = r.get('CommonPrefixes') or []
                if not isinstance(prefijos, list):
                    raise TypeError
                for p in prefijos:
                    m = CRAWL_DE_PREFIJO.fullmatch(p.get('Prefix') or '') if isinstance(p, dict) else None
                    if m:
                        ids.add(m.group(1))
                sigue, token = r.get('IsTruncated') is True, r.get('NextContinuationToken')
            except (TypeError, AttributeError):
                raise _rara('la lista de crawls') from None
            if not sigue:
                break
            if not isinstance(token, str) or not token:
                raise _rara('la lista de crawls')
            pedido['ContinuationToken'] = token
        else:
            raise FuenteNoResponde('subfinder: la lista de crawls de Common Crawl pasa de %d páginas' % MAX_PAGINAS_S3)
        if not ids:
            raise FuenteNoResponde('subfinder: la lista de crawls de Common Crawl no trae ningún crawl')
        return sorted(ids, reverse=True)[:INDICES]

    def _faltantes(self, crawls, fin):
        """Los crawls que la tabla todavía no tiene. Uno sin procesar cuenta como faltante (el ALTER es IF NOT
        EXISTS)."""
        r = self._aws('las particiones', self.glue.batch_get_partition, fin, DatabaseName=BASE, TableName=TABLA,
                      PartitionsToGet=[{'Values': [c, 'warc']} for c in crawls])
        try:
            hay = {tuple(p['Values']) for p in r.get('Partitions') or []
                   if isinstance(p, dict) and isinstance(p.get('Values'), list)}
        except (TypeError, AttributeError):
            raise _rara('las particiones') from None
        return [c for c in crawls if (c, 'warc') not in hay]

    def _parar(self, qid):
        """StopQueryExecution aunque ya no quede tiempo: la consulta seguiría leyendo (y cobrando) sin nadie."""
        try:
            self.athena.stop_query_execution(QueryExecutionId=qid)
        except self.fallas:
            pass

    def _esperar(self, que, qid, fin):
        """Pregunta el estado hasta SUCCEEDED. FAILED y CANCELLED salen como FuenteNoResponde, y FAILED con categoría
        1 lleva reintentable. Si ya no cabe otra espera o falla la pregunta, la para antes de salir."""
        esperas, terminada = iter(ESPERAS), False
        try:
            while True:
                r = self._aws(que, self.athena.get_query_execution, fin, QueryExecutionId=qid)
                try:
                    ejecucion = r['QueryExecution']
                    estado = ejecucion['Status']['State']
                except (KeyError, TypeError):
                    raise _rara(que) from None
                if estado == 'SUCCEEDED':
                    terminada = True
                    leidos = (ejecucion.get('Statistics') or {}).get('DataScannedInBytes')
                    self.bytes_leidos += leidos if type(leidos) is int and leidos >= 0 else 0
                    return
                if estado in ('FAILED', 'CANCELLED'):
                    terminada = True
                    categoria = ((ejecucion['Status'].get('AthenaError') or {}).get('ErrorCategory')
                                 if estado == 'FAILED' else None)
                    error = FuenteNoResponde(
                        'subfinder: Athena dio FAILED en %s (categoría %s)' % (que, categoria) if estado == 'FAILED'
                        else 'subfinder: Athena canceló %s (el tope de bytes del workgroup o una parada)' % que)
                    error.reintentable = categoria == 1
                    raise error
                if estado not in ('QUEUED', 'RUNNING'):
                    raise _rara(que)
                espera = next(esperas, ESPERA_MAXIMA)
                if self.cronometro() + espera >= fin:
                    raise _sin_tiempo(que)
                self.dormir(espera)
        except BaseException:   # también un error inesperado: la consulta no se queda corriendo
            if not terminada:
                self._parar(qid)
            raise

    def _una(self, que, texto, fin, parametros):
        if self.cronometro() + MINIMO_CONSULTA > fin:
            raise _sin_tiempo(que)
        if self.consultas >= MAX_CONSULTAS:   # no pasa con REINTENTOS: es el seguro del cupo reservado
            raise FuenteNoResponde('subfinder: la corrida ya pidió sus %d consultas' % MAX_CONSULTAS)
        pedido = {'QueryString': texto, 'WorkGroup': self.workgroup, 'QueryExecutionContext': {'Database': BASE}}
        if parametros:
            pedido['ExecutionParameters'] = parametros
        self.consultas += 1
        try:
            r = self._aws(que, self.athena.start_query_execution, fin, **pedido)
        except FuenteNoResponde as e:
            e.reintentable = getattr(e, 'codigo', None) in LENTO
            raise
        qid = r.get('QueryExecutionId') if isinstance(r, dict) else None
        if not isinstance(qid, str) or not ID_CONSULTA.fullmatch(qid):
            raise _rara(que)
        self._esperar(que, qid, fin)
        return qid

    def _correr(self, que, texto, fin, parametros=None):
        """Una consulta hasta SUCCEEDED, con el reintento de la corrida si la falla es reintentable."""
        while True:
            try:
                return self._una(que, texto, fin, parametros)
            except FuenteNoResponde as e:
                if not getattr(e, 'reintentable', False) or self.reintentos <= 0:
                    raise
                self.reintentos -= 1

    def _filas(self, qid, fin):
        """Los url_host_name del SELECT, hasta LIMITE_FILAS + 1, y cuántas filas no se pudieron leer."""
        nombres, raras, pedido = [], 0, {'QueryExecutionId': qid, 'MaxResults': FILAS_POR_PAGINA}
        for pagina in range(MAX_PAGINAS_RESULTADOS):
            r = self._aws('los resultados', self.athena.get_query_results, fin, **pedido)
            try:
                filas = r['ResultSet']['Rows']
                if pagina == 0:   # el encabezado del SELECT
                    if not filas or filas[0].get('Data') != [{'VarCharValue': 'url_host_name'}]:
                        raise _rara('los resultados')
                    filas = filas[1:]
                for fila in filas:
                    datos = fila.get('Data') if isinstance(fila, dict) else None
                    valor = datos[0].get('VarCharValue') if isinstance(datos, list) and len(datos) == 1 and \
                        isinstance(datos[0], dict) else None
                    if isinstance(valor, str) and valor:
                        nombres.append(valor)
                    else:
                        raras += 1
                token = r.get('NextToken')
            except (KeyError, TypeError, AttributeError, IndexError):
                raise _rara('los resultados') from None
            if not token or len(nombres) + raras > LIMITE_FILAS:
                return nombres, raras
            if not isinstance(token, str):
                raise _rara('los resultados')
            pedido['NextToken'] = token
        raise FuenteNoResponde('subfinder: los resultados de Athena pasan de %d páginas' % MAX_PAGINAS_RESULTADOS)

    def _consultar(self, dominio):
        fin = self.cronometro() + MAX_SEGUNDOS
        self.reintentos = REINTENTOS
        cred = credenciales(self.entorno)
        self.workgroup = cred['CC_ATHENA_WORKGROUP']
        try:
            self.athena, self.glue, self.s3, self.fallas = self.fabrica(cred)
        except Exception as e:   # boto3 no instalado, un perfil de ~/.aws roto: nunca el mensaje, que puede traer rutas
            raise FuenteNoResponde('subfinder: no se pudo preparar el cliente de AWS (%s)' % type(e).__name__) from None
        self._revisar_workgroup(cred, fin)
        crawls = self._crawls(fin)
        faltan = self._faltantes(crawls, fin)
        if faltan:
            self._correr('las particiones nuevas', consulta_particiones(faltan), fin)
        texto, parametros = consulta_select(dominio, crawls)
        qid = self._correr('la consulta', texto, fin, parametros)
        nombres, raras = self._filas(qid, fin)
        if raras and not nombres:   # ninguna fila legible: no se sabe qué hay, no se graba
            raise FuenteNoResponde('subfinder: Athena no dio ninguna fila legible')
        avisos = []
        if not nombres:
            avisos.append(SIN_CAPTURAS % len(crawls))
        if len(nombres) + raras > LIMITE_FILAS:
            avisos.append(RECORTADO % LIMITE_FILAS)
            nombres = nombres[:LIMITE_FILAS]
        if raras:
            avisos.append('subfinder: se %s %s de Athena que no se %s leer' % (
                'saltó' if raras == 1 else 'saltaron', '1 fila' if raras == 1 else '%d filas' % raras,
                'pudo' if raras == 1 else 'pudieron'))
        lineas = [{'host': h, 'input': dominio, 'sources': [ORIGEN]} for h in sorted(set(nombres))]
        return {'lineas': lineas, 'avisos': avisos, 'indices': crawls, 'via': VIA}

    def enumerar(self, dominio):
        """{'lineas', 'avisos', 'indices', 'via'} de Common Crawl para el dominio. Una grabación del CDX puede traer
        además 'revisados' y no traer 'via'. Sale del disco al reproducir (SinGrabacion si no hay grabación) y se graba
        al grabar. Si la corrida queda en FuenteNoResponde no se graba nada, así la grabación anterior queda intacta."""
        consulta = CONSULTA + dominio
        del_disco, datos = self.grabadora.de_disco(consulta)
        if del_disco:
            if not (isinstance(datos, dict) and isinstance(datos.get('lineas'), list) and
                    isinstance(datos.get('avisos'), list) and _revisados_validos(datos)):
                raise FuenteNoResponde('la grabación de subfinder de %s no se puede leer' % dominio)
            return datos
        datos = self._consultar(dominio)
        self.grabadora.guardar(consulta, datos)
        return datos


def _revisados_validos(datos):
    """'revisados' de una grabación del CDX: falta, o es una parte sin repetir de sus 'indices', con al menos uno."""
    if 'revisados' not in datos:
        return True
    rev, ids = datos['revisados'], datos.get('indices')
    return (isinstance(rev, list) and isinstance(ids, list) and rev and len(set(map(str, rev))) == len(rev) and
            all(isinstance(i, str) and ID_INDICE.fullmatch(i) and i in ids for i in rev) and
            all(isinstance(i, str) and ID_INDICE.fullmatch(i) for i in ids) and len(rev) < len(ids))


def _normalizar(nombre):
    nombre = nombre.strip().lower().rstrip('.')
    while nombre.startswith('*.'):
        nombre = nombre[2:]
    return nombre


def subdominios(dominio, lineas):
    """(activos, fuera, invalidos): un Activo 'subdomain' por nombre, sin repetir y con las fuentes juntas.

    Cada nombre va en minúsculas, sin punto final y sin '*.' delante. El propio dominio no sale como subdominio.
    `fuera` y `invalidos` cuentan los nombres que se descartaron por no ser del dominio o por no pasar la validación
    de nombres del contrato."""
    origen, fuera, invalidos = {}, set(), set()
    for linea in lineas:
        if not isinstance(linea, dict) or not isinstance(linea.get('host'), str):
            continue
        nombre = _normalizar(linea['host'])
        if nombre == dominio:
            continue
        if not NOMBRE_VALIDO.fullmatch(nombre):
            invalidos.add(nombre)
            continue
        if not en_alcance_nombre(nombre, dominio):
            fuera.add(nombre)
            continue
        fuentes = linea.get('sources') if isinstance(linea.get('sources'), list) else []
        origen.setdefault(nombre, set()).update(f for f in fuentes if isinstance(f, str) and NOMBRE_FUENTE.fullmatch(f))
    activos = [Activo('subdomain', n, {'fuente': FUENTE, 'origen': sorted(origen[n])}) for n in sorted(origen)]
    return activos, len(fuera), len(invalidos)


def carpeta_de(dominio):
    """Carpeta de la grabación de un dominio."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' consulta Athena, 'reproducir' usa la grabación del dominio y 'grabar'
    empieza una grabación nueva."""
    return ClienteSubfinder(modo=modo, carpeta=carpeta_de(dominio), nueva=(modo == 'grabar'))


def recolectar(dominio, cliente=None, ahora=None, propios=()):
    """Subdominios de `dominio` según el URL Index de Common Crawl. `ahora` y `propios` no se usan: Common Crawl no da
    fechas de los nombres ni busca dominios parecidos."""
    dominio = dominio.strip().lower().rstrip('.')
    res = Resultado(dominio, FUENTE)
    if not NOMBRE_VALIDO.fullmatch(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res
    cliente = cliente or crear_cliente('vivo', dominio)
    try:
        datos = cliente.enumerar(dominio)
    except SinGrabacion:  # reproducir sin grabación del dominio: no se revisó, no es una caída
        res.avisos.append(SIN_GRABACION_DOMINIO)
        return res
    finally:
        res.consultas = cliente.consultas
    res.avisos += [a for a in datos['avisos'] if isinstance(a, str)]
    if 'revisados' in datos:   # una grabación del CDX con índices saltados: el escaneo termina 'partial' (#23)
        res.revisados = list(datos['revisados'])
        res.sin_revisar = [i for i in datos['indices'] if i not in datos['revisados']]
    res.activos, fuera, invalidos = subdominios(dominio, datos['lineas'])
    if fuera:  # cuántos, no cuáles: pueden ser de terceros
        res.avisos.append('subfinder: %s fuera del dominio' % _descartados(fuera))
    if invalidos:
        res.avisos.append('subfinder: %s que no %s' % (_descartados(invalidos), 'es un nombre de dominio válido'
                                                         if invalidos == 1 else 'son nombres de dominio válidos'))
    return res


def _descartados(n):
    return 'se descartó 1 nombre' if n == 1 else 'se descartaron %d nombres' % n
