"""Pruebas del catálogo de reglas del score (#30, RC-66), sin base de datos ni red.

Leen con regex las reglas, los textos y los mapeos a marcos de todas las migraciones y semillas de db/, sin sus
comentarios (también los de los cuerpos $tag$ de DO, FUNCTION y PROCEDURE), la tabla de docs/codigos_reglas.md y
docs/api_v1/pesos.json y explicacion.json, y revisan que digan lo mismo entre sí y con los CODIGOS de cada recolector.
No leen las transacciones ni si un DO o una función corre: eso lo revisan la base al cargarse y la prueba 15 de
pruebas/test_aislamiento.py. Fallan si un recolector declara en CODIGOS un código sin regla o con otra severidad, si
una regla no tiene texto o mapeo, si un texto no cumple las reglas de redacción o si un archivo de db/ que puede cambiar
el catálogo es nuevo o cambió y no tiene su huella en HUELLAS_DB (test_4b). Lo que un recolector emite de verdad solo se
revisa en ejemplo. test_13 revisa que NOTICE atribuya los marcos del mapeo y que el README lo diga.

    python -m unittest -v pruebas/test_catalogo_reglas.py
"""
import functools
import hashlib
import json
import re
import sys
import unittest
from collections import Counter
from decimal import Decimal
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))  # también corre como python pruebas/test_catalogo_reglas.py
from cirdan.recolectores import REGISTRO, cargar, certspotter, contrato, ejemplo  # noqa: E402

# Lee todas las migraciones y semillas de db/, así una migración o una semilla nueva entra sola.
ARCHIVOS_SQL = sorted(RAIZ.glob('db/migraciones/*.sql')) + sorted(RAIZ.glob('db/semillas/*.sql'))
SEMILLA_001 = 'db/semillas/001_datos_demo.sql'
JUEGO_V1 = '90000000-0000-4000-8000-000000000001'
CATEGORIAS = ('infrastructure', 'digital_identity', 'configuration', 'data_leaks')
SEVERIDADES = ('critical', 'high', 'medium', 'low')
# Tope por hallazgo de las reglas nuevas, por severidad. medium sube a 15 en digital_identity, como lookalike_domain.
TOPES = {'critical': Decimal('40.00'), 'high': Decimal('25.00'), 'medium': Decimal('10.00'), 'low': Decimal('8.00')}
TOPE_MEDIUM_IDENTIDAD = Decimal('15.00')

UUID = r"'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'"
# Cada INSERT de una tabla, hasta su ; o su ON CONFLICT, para no leer filas de otras tablas.
BLOQUE_REGLAS = re.compile(r"INSERT INTO scoring_rules\s*\(.*?;[ \t]*$", re.DOTALL | re.MULTILINE)
BLOQUE_TEXTOS = re.compile(r"INSERT INTO scoring_rule_texts\s*\(.*?(?:^\s*ON CONFLICT|;[ \t]*$)",
                           re.DOTALL | re.MULTILINE)
# Inicio de una fila: después de VALUES, de la coma que la separa de la anterior o al principio de una línea. Se cuenta
# con las cadenas vaciadas (CADENA), así un '), (' dentro de un valor no cuenta como fila.
INICIO_DE_FILA = re.compile(r"(?:\bVALUES|,|^)\s*\(\s*'", re.IGNORECASE | re.MULTILINE)
CADENA = re.compile(r"'(?:[^']|'')*'")
FILA_REGLA = re.compile(r"\(\s*%s\s*,\s*%s\s*,\s*'([a-z0-9_]+)'\s*,\s*'([a-z_]+)'\s*,\s*'([a-z]+)'\s*,"
                        r"\s*([0-9.]+)\s*,\s*([0-9.]+)\s*\)" % (UUID, UUID))
BLOQUE_MAPEOS = re.compile(r"INSERT INTO scoring_rule_framework_mappings\s*\(.*?(?:^\s*ON CONFLICT|;[ \t]*$)",
                           re.DOTALL | re.MULTILINE)
COLUMNAS_INSERT_MAPEO = re.compile(r"INSERT INTO scoring_rule_framework_mappings\s*\(([^)]*)\)")
COLUMNAS_MAPEO = ('rule_code', 'attack_version', 'attack_technique_id', 'attack_technique_name', 'attack_source_url',
                  'attack_unmapped_reason', 'iso_version', 'iso_control_id', 'iso_control_name', 'iso_source_url',
                  'cis_version', 'cis_safeguard_id', 'cis_safeguard_name', 'cis_source_url')
# Una fila del mapeo: el código y sus otras 13 columnas, cada una '...' (con '') o NULL.
FILA_MAPEO = re.compile(r"\(\s*('[a-z0-9_]+')" + r"\s*,\s*('(?:[^']|'')*'|NULL)" * 13 + r"\s*\)")
# Lo mínimo para no leer los comentarios: se saltan las cadenas '...' y E'...' (su \ escapa también un salto de línea),
# los nombres "..." y los $tag$...$tag$, que pueden llevar -- o /* sin ser comentario. Como en Postgres, la etiqueta de
# un $tag$ y lo que va antes de E' o de $ pueden llevar letras que no son ASCII.
LETRA = 'A-Za-z_\x80-\U0010ffff'
NO_COMENTARIO = re.compile(r"(?<![%s0-9$])[Ee]'(?:[^'\\]|''|\\[\s\S])*'?|'(?:[^']|'')*'?|\"(?:[^\"]|\"\")*\"?"
                           r"|(?<![%s0-9$])(\$(?:[%s][%s0-9]*)?\$)[\s\S]*?(?:\1|\Z)|--[^\n]*|/\*"
                           % (LETRA, LETRA, LETRA, LETRA))
MARCA_DE_COMENTARIO = re.compile(r"/\*|\*/")
FILA_TEXTO = re.compile(r"\(\s*'([a-z0-9_]+)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*\)")
# Corrección de un texto ya aplicado (docs/codigos_reglas.md): un UPDATE por código con WHERE code = '...'.
UPDATE_TEXTO = re.compile(r"UPDATE scoring_rule_texts\s+SET\s+(.*?)\s+WHERE\s+code\s*=\s*'([a-z0-9_]+)'\s*;",
                          re.DOTALL)
CAMPOS_TEXTO = ('title', 'meaning', 'recommendation')
CAMPO_TEXTO = re.compile(r"\b(title|meaning|recommendation)\s*=\s*'([^']*)'")
OTRO_CAMPO = re.compile(r"\b(reviewed_by\s*=\s*(?:'[^']*'|NULL)|updated_at\s*=\s*now\(\))")
REVISOR = re.compile(r"\breviewed_by\s*=\s*(?:'([^']*)'|NULL)")
# Filas con que la 005 revisa los textos antes de cambiarlos: código, md5 de antes, md5 de después y revisor.
HUELLA = re.compile(r"^\s*\('([a-z0-9_]+)', '([0-9a-f]{32})', '([0-9a-f]{32})', (?:'([^']*)'|NULL)\),?[ \t]*$",
                    re.MULTILINE)
# Comentario de la columna reviewed_by en las migraciones y su nota en el DBML (la 007 corrige el de la 003).
COMENTARIO_REVISOR = re.compile(r"COMMENT ON COLUMN scoring_rule_texts\.reviewed_by IS '([^']*)'\s*;")
NOTA_REVISOR = re.compile(r"^Table scoring_rule_texts\b.*?^\s*reviewed_by\s+text\s+\[note:\s*'([^']*)'\]",
                          re.DOTALL | re.MULTILINE)
FILA_DOC = re.compile(r"^\|\s*(\d{2})\s*\|\s*`([a-z0-9_]+)`\s*\|\s*([a-z_]+)\s*\|\s*([a-z]+)\s*\|\s*([0-9.]+)\s*\|"
                      r"\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*$", re.MULTILINE)
POR_CATEGORIA_DOC = re.compile(r'^Por categoría: (.*)$', re.MULTILINE)
TITULO_TABLA_DOC = re.compile(r'^## Las (\d+) reglas$', re.MULTILINE)
EMITE_HOY = 'Lo emite hoy'
# Sigla: una palabra con dos o más mayúsculas, aunque lleve minúsculas o dígitos (APIs, IPs, IoT, IPv6, 2FA, TLS1).
SIGLA = re.compile(r'\b\w*?[A-ZÁÉÍÓÚÑ]\w*?[A-ZÁÉÍÓÚÑ]\w*')
NOMBRES_PROPIOS = ('GitHub',)  # nombres propios con dos mayúsculas que sí aparecen en los textos
SIGLAS_EN_MINUSCULA = ('dns', 'spf', 'dkim', 'dmarc', 'vpn', 'mfa', '2fa', 'rdp', 'smb', 'ftp', 'ssh', 'tls', 'ssl',
                       'http', 'https', 'url', 'urls', 'ip', 'ips', 'ipv4', 'ipv6', 'api', 'apis', 'cms', 'cve',
                       'cves', 'iot', 'ot', 'sql', 'aws', 's3')
FIN_DE_FRASE = re.compile(r'[.!?…](\s|$)')
PROHIBIDO = (';', '"', "'", '«', '»', '“', '”', '‘', '’', '—', '–', '_', '=', '…', '...')
CLIENTES = ('acme', 'olmardo', 'beta')

# Aviso sin base de test_4b. Lo que estas pruebas no leen del SQL (transacciones, UPDATE, DELETE, DO o funciones que
# corren o no) lo revisa la prueba 15 de pruebas/test_aislamiento.py en una base recién cargada. Por eso cada archivo de
# db/ que puede cambiar el catálogo guarda en HUELLAS_DB el SHA-256 que tenía cuando pasó esa prueba, y uno nuevo o
# cambiado hace fallar test_4b hasta que se pruebe y se ponga su huella. El aviso no lee el SQL ni decide si está bien.
# Entran los archivos de db/init/, que deciden qué se carga y cómo, y las migraciones y semillas que:
# - nombran el mapeo, los textos o las reglas (NOMBRES_DB). Se busca en el texto crudo, con los comentarios y las
#   cadenas, también entre comillas y sin distinguir mayúsculas;
# - nombran un objeto que crea o renombra un archivo que nombra el mapeo o los textos (CREA_NOMBRE: una función, una
#   vista, una tabla...). Se busca en el SQL sin comentarios, y una función solo como llamada (ver _aviso);
# - traen algo que arma SQL que no se ve o cambia cómo corre (MARCAS_DB), aunque no nombren las tablas.
NOMBRES_DB = re.compile(r'scoring_rule(?:_framework_mappings|_texts|s)', re.IGNORECASE)
MAPEO_O_TEXTOS = re.compile(r'scoring_rule_(?:framework_mappings|texts)', re.IGNORECASE)
CREA_NOMBRE = re.compile(r'''
    \bCREATE\s+(?:OR\s+REPLACE\s+)?(?P<modos>(?:(?:TEMP|TEMPORARY|UNLOGGED|MATERIALIZED|RECURSIVE)\s+)*)
    (?P<tipo>TABLE|VIEW|FUNCTION|PROCEDURE|SEQUENCE|TYPE|DOMAIN|AGGREGATE)\s+(?:IF\s+NOT\s+EXISTS\s+)?
    (?:(?:"[^"]+"|\w[\w$]*)\s*\.\s*)?(?P<nombre>"[^"]+"|\w[\w$]*)
  | \bRENAME\s+TO\s+(?P<nuevo>"[^"]+"|\w[\w$]*)''', re.IGNORECASE | re.VERBOSE)
MARCAS_DB = re.compile(r'''
    \bEXECUTE\b(?!\s+ON\b)                                  # SQL dinámico o un PREPARE (GRANT EXECUTE ON no)
  | \bformat\s*\( | \bU&\s*['"]
  | \bDO\s+(?:LANGUAGE\s+\w+\s+)?(?:E|U&)?'                 # DO con el cuerpo en una cadena '...'
  | \bset_config\s*\( | \bsearch_path\b | \bsession_replication_role\b
  | \bstandard_conforming_strings\b | \bSET\s+NAMES\b
  | \bclient_encoding\b(?!\s*(?:=|TO)\s*'?UTF-?8'?\s*;)     # otra codificación cambia cómo se leen ' y \ (UTF8 no)
  | \bCREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+|EVENT\s+)?(?:TRIGGER|RULE)\b
  | \bALTER\s+TABLE\b[^;]*\bUSING\b                         # ALTER COLUMN ... TYPE ... USING calcula cada fila
  | \bCOPY\b | \bCALL\b | \bCASCADE\b | \bdblink\w*\s*\(
  | \b(?:DROP|ALTER)\s+SCHEMA\b | \b(?:DROP|REASSIGN)\s+OWNED\b
  | \b(?:UPDATE|DELETE\s+FROM|INSERT\s+INTO)\s+(?:pg_catalog\s*\.\s*)?pg_\w+   # escribe en el catálogo de Postgres
  | \\[A-Za-z!?]                                            # meta-comando de psql (\i, \set, \gexec, \copy, \!...)
''', re.IGNORECASE | re.VERBOSE)
# Los archivos del aviso que ya pasaron la prueba 15 en una base recién cargada, con su SHA-256 (los \r\n se cuentan
# como \n, como los guarda git, así la huella es la misma en Windows y en el CI). Cómo se agrega uno: db/README.md.
HUELLAS_DB = {
    'db/init/cargar_cirdan.sh': 'f2ced66729f048f0d9d7c75e4aea764341c9b253ad98dcd05c6e65dd3c698684',
    'db/migraciones/001_esquema_inicial.sql': '94a5eecc28b57eb1d2d275f9f40bf7e562ddbe7a65bf724c3b4d94f21cead8d4',
    'db/migraciones/002_login.sql': 'a2e4900b8a00aa496e8d95acb97a1e1232ed75aa265e5af449032bba4a1518ee',
    'db/migraciones/003_textos_reglas.sql': '1301a671fe7bf650033d378a36eacf8a9b792a78c1ac4173f76e6c8a84875b9e',
    'db/migraciones/004_login_lookup_seguro.sql': '3cf7c31fc21f88bbb4d0ac06950e665787e202b62d6772391c2e95c951ca1fe3',
    'db/migraciones/005_textos_revisados.sql': '095a7e92fedb26c08909a50919ba2ecd6e22a54be952aa15346195837fb545b8',
    'db/migraciones/006_firma_reglas_extras.sql': 'd2ba0ef5ffec27877db9664e0f771914197e63fa107ec0d8d1ed8dab974186bd',
    'db/migraciones/007_comentario_revisor.sql': '3d63a98a4a990be2004e58d4371bd967965ce9ec22ba9d50bf9a5d1fe6e521b9',
    'db/migraciones/008_limite_diario_fuentes.sql': '82393a2be6a9f5c31c9b260b4d86cbd27c4c22a7bf9a3ef043af5539c6799689',
    'db/migraciones/011_mapeo_marcos.sql': '16e9af658a85a93917810750618222980b1bfc2af8a9250702b0a4abb5c7a243',
    'db/migraciones/012_garantia_mapeo_marcos.sql': 'e22b8ca49dd1527b54a399386197b27c7f0f73175a1e6f3c403215ebf6e856b8',
    'db/migraciones/013_pesos_por_organizacion.sql': 'db5970965485762c492907a6f29f194ef362cbc877349552a4d9098b0669f2f8',
    'db/migraciones/016_api_key_lookup.sql': '4f665442ba0e0d340f120d39baac57348cd8048e9f7051cd8a3dd4e61affa6c0',
    'db/semillas/001_datos_demo.sql': 'fe4bd48276a8366a15578bdc14c3d65d869bc4586afec745d5a3dc97b1e71efb',
    'db/semillas/004_reglas_recolectores.sql': '7d7ce5d07352db3a706a892681c2fd70a9182e3ff0a72e7b83aebd1c2eec47c0',
}


def _relativa(ruta):
    return ruta.relative_to(RAIZ).as_posix()


def _huella(ruta):
    return hashlib.sha256(ruta.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def _aviso():
    """{archivo: motivo} de los archivos de db/ que entran en el aviso de test_4b, con lo que los hizo entrar."""
    crudos = {_relativa(r): r.read_text(encoding='utf-8') for r in ARCHIVOS_SQL}
    codigo = {archivo: _sin_comentarios(sql) for archivo, sql in crudos.items()}
    aviso = {_relativa(r): 'está en db/init/' for r in sorted(RAIZ.glob('db/init/*')) if r.is_file()}
    # Lo que crea o renombra un archivo que nombra el mapeo o los textos cuenta como ellos. Esos nombres se buscan en el
    # SQL sin comentarios, y los de funciones solo como llamada (nombre o "nombre" con su paréntesis), así una función
    # llamada begin o uno no hace entrar cada BEGIN ni cada comentario. Una llamada armada en una cadena entra por
    # MARCAS_DB. Lo TEMP no cuenta: cargar_cirdan.sh corre cada archivo en su propio psql y se borra al terminar.
    nombres, derivados = {}, None
    while True:
        nuevos = {}
        for archivo, sql in codigo.items():
            if MAPEO_O_TEXTOS.search(crudos[archivo]) or (derivados and derivados.search(sql)):
                for m in CREA_NOMBRE.finditer(sql):
                    if 'TEMP' in (m.group('modos') or '').upper():
                        continue
                    nombre = (m.group('nombre') or m.group('nuevo')).strip('"').lower()
                    funcion = (m.group('tipo') or '').upper() in ('FUNCTION', 'PROCEDURE', 'AGGREGATE')
                    nuevos[nombre] = nuevos.get(nombre, True) and funcion
        nuevos = {n: f for n, f in nuevos.items() if n not in nombres or (nombres[n] and not f)}
        if not nuevos:
            break
        nombres.update(nuevos)
        derivados = re.compile('|'.join(r'(?<![\w$])%s%s' % (re.escape(n), r'"?\s*\(' if f else r'(?![\w$])')
                                        for n, f in sorted(nombres.items())), re.IGNORECASE)
    for archivo, sql in crudos.items():
        nombre = (MAPEO_O_TEXTOS.search(sql) or NOMBRES_DB.search(sql)
                  or (derivados and derivados.search(codigo[archivo])))
        marca = MARCAS_DB.search(sql)
        if nombre or marca:
            aviso[archivo] = 'nombra %r' % nombre.group(0).strip() if nombre else 'trae %r' % marca.group(0).strip()
    return aviso


def _sin_comentarios(sql):
    """El SQL con sus comentarios -- y /* */ (anidados, como en Postgres) cambiados por espacios, del mismo largo y con
    sus saltos de línea. No mira dentro de las cadenas ni de los nombres entre comillas. En el cuerpo de un $tag$, que
    en un DO, una FUNCTION o un PROCEDURE es SQL, también quita los comentarios."""
    partes, i = [], 0
    for m in iter(lambda: NO_COMENTARIO.search(sql, i), None):
        fin = m.end()
        if m.group(0) == '/*':
            nivel = 1
            while nivel:
                marca = MARCA_DE_COMENTARIO.search(sql, fin)
                if not marca:
                    fin = len(sql)
                    break
                nivel += 1 if marca.group(0) == '/*' else -1
                fin = marca.end()
        if m.group(0).startswith(('/*', '--')):
            partes.append(sql[i:m.start()] + re.sub(r'[^\n]', ' ', sql[m.start():fin]))
        elif m.group(1):
            etiqueta = m.group(1)
            cerrado = len(m.group(0)) >= 2 * len(etiqueta) and m.group(0).endswith(etiqueta)
            cuerpo = sql[m.start() + len(etiqueta):fin - len(etiqueta) if cerrado else fin]
            partes.append(sql[i:m.start()] + etiqueta + _sin_comentarios(cuerpo) + (etiqueta if cerrado else ''))
        else:
            partes.append(sql[i:fin])
        i = fin
    return ''.join(partes) + sql[i:]


@functools.lru_cache(maxsize=None)
def _sql(ruta):
    """Un archivo de db/ sin comentarios, también los de los cuerpos $tag$."""
    return _sin_comentarios(ruta.read_text(encoding='utf-8'))


def _filas(bloque, fila):
    """Las filas de todos los INSERT de una tabla en todos los archivos de db/, más los INSERT con filas sin leer."""
    filas, mal_leidos = [], []
    for ruta in ARCHIVOS_SQL:
        sql = _sql(ruta)
        for m in bloque.finditer(sql):
            leidas = fila.findall(m.group(0))
            esperadas = len(INICIO_DE_FILA.findall(CADENA.sub("''", m.group(0))))
            if len(leidas) != esperadas:
                mal_leidos.append('%s: %d filas y se leyeron %d' % (_relativa(ruta), esperadas, len(leidas)))
            filas += [(_relativa(ruta),) + f for f in leidas]
    return filas, mal_leidos


def leer_reglas():
    """Lista de (archivo, id, juego, code, category, base_severity, weight, max_penalty) de todos los juegos."""
    filas, mal_leidos = _filas(BLOQUE_REGLAS, FILA_REGLA)
    reglas = [(a, i, juego, code, cat, sev, Decimal(peso), Decimal(tope))
              for a, i, juego, code, cat, sev, peso, tope in filas]
    return reglas, mal_leidos


def leer_textos():
    """Los (code, title, meaning, recommendation) de los INSERT INTO scoring_rule_texts, los mismos textos como quedan
    después de los UPDATE scoring_rule_texts de db/ en orden, y lo que no se pudo leer."""
    filas, mal_leidos = _filas(BLOQUE_TEXTOS, FILA_TEXTO)
    insertados = [f[1:] for f in filas]
    finales = {}
    for code, *campos in insertados:
        finales.setdefault(code, dict(zip(CAMPOS_TEXTO, campos)))
    for ruta in ARCHIVOS_SQL:
        sql = _sql(ruta)
        cambios = UPDATE_TEXTO.findall(sql)
        if len(cambios) != len(re.findall(r'UPDATE scoring_rule_texts\b', sql)):
            mal_leidos.append('%s: UPDATE scoring_rule_texts que la prueba no pudo leer' % _relativa(ruta))
        for asignaciones, code in cambios:
            if OTRO_CAMPO.sub('', CAMPO_TEXTO.sub('', asignaciones)).replace(',', '').strip():
                mal_leidos.append('%s: UPDATE de %r con campos que la prueba no pudo leer' % (_relativa(ruta), code))
            if code not in finales:
                mal_leidos.append('%s: UPDATE de %r, que no tiene INSERT' % (_relativa(ruta), code))
                continue
            finales[code].update(CAMPO_TEXTO.findall(asignaciones))
    finales = {c: (c,) + tuple(t[k] for k in CAMPOS_TEXTO) for c, t in finales.items()}
    return insertados, finales, mal_leidos


def leer_mapeos():
    """Los (archivo, code) de las filas de los INSERT INTO scoring_rule_framework_mappings de todo db/ (la 011 y las
    migraciones que vengan, porque la 011 ya no se edita) y lo que no se pudo leer: un INSERT con otras columnas o en
    otro orden que COLUMNAS_MAPEO, o con filas que no son el código y 13 valores '...' o NULL. Los valores no se revisan
    sin base: los revisan los CHECK de la 011 al cargarla y la prueba 15 de pruebas/test_aislamiento.py."""
    filas, mal_leidos = _filas(BLOQUE_MAPEOS, FILA_MAPEO)
    for ruta in ARCHIVOS_SQL:
        for columnas in COLUMNAS_INSERT_MAPEO.findall(_sql(ruta)):
            if tuple(c.strip() for c in columnas.split(',')) != COLUMNAS_MAPEO:
                mal_leidos.append('%s: INSERT del mapeo con otras columnas o en otro orden' % _relativa(ruta))
    return [(archivo, code[1:-1]) for archivo, code, *_ in filas], mal_leidos


def leer_doc():
    return (RAIZ / 'docs' / 'codigos_reglas.md').read_text(encoding='utf-8')


def leer_json(nombre):
    return json.loads((RAIZ / 'docs' / 'api_v1' / nombre).read_text(encoding='utf-8'), parse_float=Decimal)


REGLAS, REGLAS_MAL_LEIDAS = leer_reglas()
REGLAS_V1 = sorted((r for r in REGLAS if r[2] == JUEGO_V1), key=lambda r: r[1])
POR_CODIGO = {r[3]: r for r in REGLAS_V1}
TEXTOS, TEXTOS_POR_CODIGO, TEXTOS_MAL_LEIDOS = leer_textos()
MAPEOS, MAPEOS_MAL_LEIDOS = leer_mapeos()
FILAS_DOC = FILA_DOC.findall(leer_doc())


class Recolectores(unittest.TestCase):

    def test_1_cada_codigo_de_un_recolector_tiene_regla_con_su_severidad(self):
        for fuente in REGISTRO:
            modulo = cargar(fuente)
            codigos = getattr(modulo, 'CODIGOS', None)
            self.assertIsInstance(codigos, dict, 'el recolector %r no declara CODIGOS' % fuente)
            for codigo, severidad in codigos.items():
                self.assertTrue(codigo in POR_CODIGO, 'el recolector %r emite %r, que no tiene regla' % (fuente, codigo))
                self.assertEqual(severidad, POR_CODIGO[codigo][5],
                                 '%r: %r lo emite con %r y su regla dice %r' % (codigo, fuente, severidad,
                                                                                POR_CODIGO[codigo][5]))

    def test_1b_ejemplo_emite_solo_sus_codigos(self):
        for h in ejemplo._fijo('acme-demo.mx')['hallazgos']:
            self.assertEqual(ejemplo.CODIGOS.get(h['codigo']), h['severidad'], h['codigo'])

    def test_2_sin_cobertura_de_cert_spotter_tiene_regla(self):
        for codigo in certspotter.SIN_COBERTURA:
            self.assertTrue(codigo in POR_CODIGO, 'certspotter.SIN_COBERTURA tiene %r, que no tiene regla' % codigo)


class Reglas(unittest.TestCase):

    def test_3_reglas_del_juego_v1_sin_repetir_en_las_4_categorias(self):
        self.assertEqual(REGLAS_MAL_LEIDAS, [], 'INSERT INTO scoring_rules con filas que la prueba no pudo leer')
        repetidos = sorted(k for k, n in Counter((r[2], r[3]) for r in REGLAS).items() if n > 1)
        self.assertEqual(repetidos, [], 'códigos repetidos en un mismo juego: %s' % repetidos)
        ids = Counter(r[1] for r in REGLAS)
        self.assertEqual(sorted(i for i, n in ids.items() if n > 1), [], 'hay ids de regla repetidos')
        for archivo, i, juego, code, cat, sev, _, _ in REGLAS:
            self.assertTrue(contrato.CODIGO_VALIDO.fullmatch(code), '%r no cumple CODIGO_VALIDO' % code)
            self.assertIn(cat, CATEGORIAS, '%r tiene la categoría %r' % (code, cat))
            self.assertIn(sev, SEVERIDADES, '%r tiene la severidad %r' % (code, sev))
        self.assertEqual(len(REGLAS_V1), len(FILAS_DOC), 'hay %d reglas del juego v1 y docs/codigos_reglas.md tiene '
                                                         '%d filas' % (len(REGLAS_V1), len(FILAS_DOC)))
        self.assertEqual(set(r[4] for r in REGLAS_V1), set(CATEGORIAS), 'alguna categoría quedó sin reglas')

    def test_3b_las_reglas_nuevas_no_reusan_los_ids_de_la_semilla_001(self):
        base = {r[1] for r in REGLAS if r[0] == SEMILLA_001}
        self.assertEqual(len(base), 7)
        self.assertEqual(base, {'91000000-0000-4000-8000-0000000000%02d' % n for n in range(1, 8)})
        for archivo, i, _, code, *_ in REGLAS:
            if archivo != SEMILLA_001:
                self.assertNotIn(i, base, '%r reusa el id %s de la semilla 001' % (code, i))

    def test_4_toda_regla_tiene_texto_y_todo_texto_tiene_regla(self):
        self.assertEqual(TEXTOS_MAL_LEIDOS, [], 'INSERT o UPDATE de scoring_rule_texts que la prueba no pudo leer')
        repetidos = sorted(c for c, n in Counter(t[0] for t in TEXTOS).items() if n > 1)
        self.assertEqual(repetidos, [], 'hay textos repetidos: %s' % repetidos)
        codigos = {r[3] for r in REGLAS}
        for code in sorted(codigos):
            self.assertTrue(code in TEXTOS_POR_CODIGO, '%r no tiene texto en scoring_rule_texts' % code)
        for code in TEXTOS_POR_CODIGO:
            self.assertTrue(code in codigos, 'el texto de %r no tiene regla' % code)

    def test_4b_toda_regla_tiene_mapeo_a_marcos(self):
        # Sin base: los mismos códigos en los textos y en los mapeos de todo db/, sin repetidos. No revisa las versiones
        # de los marcos ni lee el SQL como Postgres (transacciones, orden, UPDATE ni ON CONFLICT DO UPDATE): lo que de
        # verdad queda en la base, con la versión que espera de cada marco, lo revisan la base al cargarla (los CHECK de la
        # 011 y la FK diferida de la 012) y la prueba 15 de pruebas/test_aislamiento.py. Para no perderlo sin base, el
        # aviso de HUELLAS_DB falla si un archivo de db/ que puede cambiar el catálogo es nuevo o cambió y no tiene la
        # huella con que pasó la prueba 15. Un cambio de versión de los marcos sigue la receta de db/README.md.
        with self.subTest('códigos de los mapeos'):
            self.assertEqual(MAPEOS_MAL_LEIDOS, [],
                             'INSERT de scoring_rule_framework_mappings que la prueba no pudo leer')
            codigos = [code for _, code in MAPEOS]
            repetidos = sorted(c for c, n in Counter(codigos).items() if n > 1)
            self.assertEqual(repetidos, [], 'hay mapeos insertados dos veces (una corrección va con UPDATE ... '
                                            "SET ..., updated_at = now() WHERE rule_code = '...'): %s" % repetidos)
            self.assertEqual(set(codigos), set(TEXTOS_POR_CODIGO),
                             'los mapeos no cubren exactamente las reglas del catálogo')
        with self.subTest('huellas de db/'):
            problemas, lineas = [], []
            for archivo, motivo in sorted(_aviso().items()):
                huella = _huella(RAIZ / archivo)
                if HUELLAS_DB.get(archivo) != huella:
                    estado = 'cambió' if archivo in HUELLAS_DB else 'es nuevo'
                    problemas.append('%s %s y %s' % (archivo, estado, motivo))
                    lineas.append("    '%s': '%s'," % (archivo, huella))
            for archivo in sorted(set(HUELLAS_DB) - set(_aviso())):
                ruta = RAIZ / archivo
                if not ruta.is_file():
                    problemas.append('%s está en HUELLAS_DB y ya no existe (si ya no va, quítalo)' % archivo)
                elif _huella(ruta) != HUELLAS_DB[archivo]:
                    problemas.append('%s está en HUELLAS_DB y cambió' % archivo)
                    lineas.append("    '%s': '%s'," % (archivo, _huella(ruta)))
            if problemas:
                self.fail('archivos de db/ que pueden cambiar el catálogo y no pasaron la prueba 15 así:\n  %s\n'
                          'Carga una base desde cero con todo db/ y corre en ella la prueba 15 de '
                          'pruebas/test_aislamiento.py. El CI lo hace en cada PR antes de esta prueba. No la cargues '
                          'sobre la base con la que trabajas (db/README.md, Huellas de db/). Si pasa, pon en '
                          'HUELLAS_DB de pruebas/test_catalogo_reglas.py:'
                          '\n%s' % ('\n  '.join(problemas), '\n'.join(lineas)))

    def test_5_textos_simples(self):
        for code, title, meaning, recommendation in TEXTOS_POR_CODIGO.values():
            self.assertTrue(title.strip(), '%r: title vacío' % code)
            self.assertFalse(title.rstrip().endswith('.'), '%r: title con punto final' % code)
            self.assertEqual(len(FIN_DE_FRASE.findall(title)), 0, '%r: title con más de una frase' % code)
            for campo, texto in (('title', title), ('meaning', meaning), ('recommendation', recommendation)):
                if campo != 'title':
                    self.assertTrue(texto.endswith('.'), '%r: %s sin punto final' % (code, campo))
                    frases = len(FIN_DE_FRASE.findall(texto))
                    self.assertIn(frases, (1, 2), '%r: %s tiene %d frases' % (code, campo, frases))
                siglas = [s for s in SIGLA.findall(texto) if s not in NOMBRES_PROPIOS]
                self.assertEqual(siglas, [], '%r: %s con siglas' % (code, campo))
                palabras = set(re.findall(r'\w+', texto.lower()))
                self.assertEqual(sorted(palabras.intersection(SIGLAS_EN_MINUSCULA)), [],
                                 '%r: %s con siglas en minúscula' % (code, campo))
                for signo in PROHIBIDO:
                    self.assertNotIn(signo, texto, '%r: %s tiene %r' % (code, campo, signo))
                for cliente in CLIENTES:
                    self.assertNotIn(cliente, texto.lower(), '%r: %s nombra a %s' % (code, campo, cliente))

    def test_6_la_lista_del_repo_coincide_con_las_semillas(self):
        doc = leer_doc()
        self.assertEqual(sorted(f[1] for f in FILAS_DOC), sorted(POR_CODIGO),
                         'docs/codigos_reglas.md no tiene los mismos códigos que las reglas del juego v1')
        emite_hoy = {c for fuente in REGISTRO if fuente != 'ejemplo' for c in cargar(fuente).CODIGOS}
        for nn, code, cat, sev, tope, _, estado in FILAS_DOC:
            _, i, _, _, cat_r, sev_r, _, tope_r = POR_CODIGO[code]
            self.assertEqual((i[-2:], cat, sev, Decimal(tope)), (nn, cat_r, sev_r, tope_r),
                             '%r: docs/codigos_reglas.md no coincide con su semilla' % code)
            self.assertEqual(estado == EMITE_HOY, code in emite_hoy,
                             '%r: docs/codigos_reglas.md dice %r y su recolector en REGISTRO %s lo declara'
                             % (code, estado, 'sí' if code in emite_hoy else 'no'))
        titulo = TITULO_TABLA_DOC.search(doc)
        self.assertIsNotNone(titulo, 'docs/codigos_reglas.md sin el título Las N reglas')
        self.assertEqual(int(titulo.group(1)), len(REGLAS_V1), 'el título de docs/codigos_reglas.md no cuadra')
        linea = POR_CATEGORIA_DOC.search(doc)
        self.assertIsNotNone(linea, 'docs/codigos_reglas.md sin la línea Por categoría')
        conteo_doc = {cat: int(n) for cat, n in re.findall(r'([a-z_]+) (\d+)', linea.group(1))}
        self.assertEqual(conteo_doc, dict(Counter(r[4] for r in REGLAS_V1)),
                         'la línea Por categoría de docs/codigos_reglas.md no cuadra con las reglas del juego v1')

    def test_7_los_pesos_de_categoria_suman_1(self):
        sql = (RAIZ / SEMILLA_001).read_text(encoding='utf-8')
        desde = sql.index('INSERT INTO scoring_rule_sets (')
        bloque = sql[desde:sql.index(';', desde)]
        pesos = json.loads(re.search(r"'(\{[^']*\})'", bloque).group(1), parse_float=Decimal)
        self.assertEqual(sorted(pesos), sorted(CATEGORIAS))
        self.assertEqual(sum(pesos.values()), Decimal('1.00'), 'category_weights suma %s' % sum(pesos.values()))

    def test_8_tope_y_peso_de_las_reglas_nuevas(self):
        for archivo, _, _, code, cat, sev, peso, tope in REGLAS_V1:
            if archivo == SEMILLA_001:
                continue  # las 7 de la semilla 001 no se tocan
            esperado = TOPE_MEDIUM_IDENTIDAD if (sev, cat) == ('medium', 'digital_identity') else TOPES[sev]
            self.assertEqual(tope, esperado, '%r (%s, %s): max_penalty %s y se espera %s' % (code, sev, cat, tope,
                                                                                         esperado))
            self.assertEqual(peso, Decimal('1.000'), '%r: weight %s y se espera 1.000' % (code, peso))

    def test_9_los_ejemplos_de_la_api_coinciden_con_las_reglas_y_sus_textos(self):
        pesos = leer_json('pesos.json')['rules']
        self.assertEqual([r['code'] for r in pesos], [r[3] for r in REGLAS_V1],
                         'docs/api_v1/pesos.json no tiene las reglas del juego v1 en orden de id')
        for r, (_, _, _, code, cat, sev, peso, tope) in zip(pesos, REGLAS_V1):
            _, title, meaning, recommendation = TEXTOS_POR_CODIGO[code]
            esperado = {'code': code, 'category': cat, 'base_severity': sev, 'weight': peso, 'max_penalty': tope,
                        'title': title, 'meaning': meaning, 'recommendation': recommendation}
            for campo, valor in esperado.items():
                self.assertEqual(r.get(campo), valor, '%r: %s de docs/api_v1/pesos.json no coincide con su semilla '
                                                      'o con su texto de scoring_rule_texts' % (code, campo))
        explicacion = leer_json('explicacion.json')
        code = explicacion['rule_code']
        self.assertTrue(code in TEXTOS_POR_CODIGO, 'docs/api_v1/explicacion.json usa %r, que no tiene texto' % code)
        _, title, meaning, recommendation = TEXTOS_POR_CODIGO[code]
        for campo, valor in (('rule_title', title), ('meaning', meaning), ('recommendation', recommendation)):
            self.assertEqual(explicacion[campo], valor, '%r: %s de docs/api_v1/explicacion.json no coincide con su '
                                                        'texto de scoring_rule_texts' % (code, campo))

    def test_10_los_textos_osint_los_firma_ernesto(self):
        # backlog.md fila 30: los textos de las reglas OSINT (#14 a #20) los revisa Ernesto. Quién firma el resto no se
        # revisa, y ErnestoDL también puede firmarlo (decisión de Ernesto del 26 oct).
        # Un UPDATE que cambia un texto dice en reviewed_by quién revisó el nuevo, o NULL si nadie: sin reviewed_by la
        # fila conservaría la firma del texto anterior. Se lee sin comentarios, también los de los cuerpos $tag$, pero
        # no sabe si un UPDATE corre: uno dentro de un DO o una función cuenta aunque no se llame
        revisor, sin_firma = {}, []
        for ruta in ARCHIVOS_SQL:
            for asignaciones, code in UPDATE_TEXTO.findall(_sql(ruta)):
                m = REVISOR.search(asignaciones)
                if m:
                    revisor[code] = m.group(1)
                elif CAMPO_TEXTO.search(asignaciones):
                    sin_firma.append('%s: %s' % (_relativa(ruta), code))
        self.assertEqual(sin_firma, [], 'UPDATE que cambian un texto sin decir en reviewed_by quién revisó el nuevo')
        osint = []
        for fila in FILAS_DOC:
            numero = re.match(r'#(\d+)', fila[5])
            self.assertIsNotNone(numero, '%r: su recolector en docs/codigos_reglas.md no empieza con #' % fila[1])
            if 14 <= int(numero.group(1)) <= 20:
                osint.append(fila[1])
        self.assertEqual(len(osint), 25, 'docs/codigos_reglas.md ya no tiene 25 reglas de #14 a #20')
        self.assertEqual([c for c in sorted(osint) if revisor.get(c) != 'ErnestoDL'], [],
                         'reglas OSINT cuyo texto final no firmó ErnestoDL en las migraciones de db/')

    def test_11_las_huellas_que_revisa_la_005_coinciden_con_sus_textos(self):
        # Antes de cambiar nada, la 005 revisa que cada texto sea el de antes o el de después de ella. Si alguien cambia un
        # texto en un UPDATE y no su huella, la carga desde cero pasa, pero volver a correrla en una base que ya la tiene
        # falla
        def huella(textos):
            # Igual que md5(title || E'\n' || meaning || E'\n' || recommendation) en una base UTF8
            return hashlib.md5('\n'.join(textos[k] for k in CAMPOS_TEXTO).encode('utf-8')).hexdigest()

        insertados, _ = _filas(BLOQUE_TEXTOS, FILA_TEXTO)
        textos, con_huellas = {}, 0
        for ruta in ARCHIVOS_SQL:
            sql, nombre = _sql(ruta), _relativa(ruta)  # sin comentarios, también los de los cuerpos $tag$
            for _, code, *campos in (f for f in insertados if f[0] == nombre):
                textos.setdefault(code, dict(zip(CAMPOS_TEXTO, campos)))
            antes = {code: huella(t) for code, t in textos.items()}
            firma = {}
            for asignaciones, code in UPDATE_TEXTO.findall(sql):
                if code in textos:
                    textos[code].update(CAMPO_TEXTO.findall(asignaciones))
                m = REVISOR.search(asignaciones)
                firma[code] = m.group(1) if m else None
            huellas = HUELLA.findall(sql)
            if not huellas:
                continue
            con_huellas += 1
            self.assertEqual(sorted(h[0] for h in huellas), sorted(firma),
                             '%s: las filas que revisa no son los códigos de sus UPDATE' % nombre)
            for code, de_antes, de_despues, revisor in huellas:
                self.assertEqual((de_antes, de_despues), (antes.get(code), huella(textos[code])),
                                 '%s: la huella de %r no es la de su texto de antes o de después' % (nombre, code))
                self.assertEqual(revisor or None, firma[code],
                                 '%s: el revisor de %r en sus huellas no es el que escribe su UPDATE' % (nombre, code))
        self.assertGreater(con_huellas, 0, 'ninguna migración tiene huellas: cambió la forma del VALUES de la 005')

    def test_12_el_comentario_de_reviewed_by_dice_lo_mismo_que_el_dbml(self):
        # En la base queda el último COMMENT de las migraciones en orden. Debe decir quién firma lo mismo que el DBML y
        # docs/codigos_reglas.md, sin contar el punto final. Si cambia quién firma, va otra migración con su COMMENT
        comentarios = [c for ruta in ARCHIVOS_SQL if 'migraciones' in ruta.parts
                       for c in COMENTARIO_REVISOR.findall(ruta.read_text(encoding='utf-8'))]
        self.assertTrue(comentarios, 'ninguna migración comenta scoring_rule_texts.reviewed_by')
        nota = NOTA_REVISOR.search((RAIZ / 'db' / 'cirdan_esquema.dbml').read_text(encoding='utf-8'))
        self.assertIsNotNone(nota, 'db/cirdan_esquema.dbml no trae la nota de reviewed_by en scoring_rule_texts')
        self.assertEqual(comentarios[-1].rstrip('.'), nota.group(1).rstrip('.'),
                         'el último COMMENT de reviewed_by en db/migraciones/ no dice lo mismo que el DBML')

    def test_13_notice_atribuye_los_marcos_del_mapeo(self):
        # La tarjeta #68 (RC-131) pide que el repo anote que el uso comercial de CIS requiere su permiso, y los
        # términos de MITRE piden su aviso de derechos y la licencia en cada copia. Se compara sin saltos de línea.
        aviso = ' '.join((RAIZ / 'NOTICE').read_text(encoding='utf-8').split())
        for texto in ('CIS Controls v8.1',
                      'Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0)',
                      'El uso comercial de CIS Controls requiere permiso previo de CIS.',
                      'The MITRE Corporation. This work is reproduced and distributed with the permission of '
                      'The MITRE Corporation.',
                      'hereby grants you a non-exclusive, royalty-free license to use ATT&CK®',
                      "provided that you reproduce MITRE's copyright designation and this license in any such copy."):
            self.assertIn(texto, aviso, 'NOTICE ya no trae este texto de la atribución de los marcos')
        # Sin fijar el año del aviso de MITRE, que puede cambiar cuando NOTICE pase a otra versión de ATT&CK.
        self.assertRegex(aviso, r'© \d{4} The MITRE Corporation\. This work is reproduced')
        filas = [linea for linea in (RAIZ / 'README.md').read_text(encoding='utf-8').splitlines()
                 if linea.startswith('| `LICENSE`, `NOTICE` |')]
        self.assertEqual(len(filas), 1, 'el README debe tener una sola fila de NOTICE en su tabla de archivos')
        for nombre in ('CIS Controls', 'MITRE ATT&CK'):
            self.assertIn(nombre, filas[0], 'la fila de NOTICE del README no nombra %s' % nombre)


if __name__ == '__main__':
    unittest.main()
