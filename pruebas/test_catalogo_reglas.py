"""Pruebas del catálogo de reglas del score (#30, RC-66), sin base de datos ni red.

Leen con regex las reglas y los textos de todas las migraciones y semillas de db/, la tabla de docs/codigos_reglas.md
y docs/api_v1/pesos.json y explicacion.json, y revisan que digan lo mismo entre sí y con los CODIGOS de cada
recolector. Fallan si un recolector declara en CODIGOS un código sin regla o con otra severidad, si una regla no tiene
texto o si un texto no cumple las reglas de redacción. Lo que un recolector emite de verdad solo se revisa en ejemplo.

    python -m unittest -v pruebas/test_catalogo_reglas.py
"""
import bisect
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
INICIO_DE_FILA = re.compile(r"^\s*\(\s*'", re.MULTILINE)
FILA_REGLA = re.compile(r"\(\s*%s\s*,\s*%s\s*,\s*'([a-z0-9_]+)'\s*,\s*'([a-z_]+)'\s*,\s*'([a-z]+)'\s*,"
                        r"\s*([0-9.]+)\s*,\s*([0-9.]+)\s*\)" % (UUID, UUID))
# El SQL se lee como Postgres (_sql): cadenas con '' o E'\'', identificadores entre comillas, comentarios anidados y
# $tag$...$tag$. Un \ fuera de todo eso empieza un meta-comando de psql, que llega hasta el fin de la línea y no es SQL.
CADENA_SQL = r"'(?:[^']|'')*'"
ESPECIAL_SQL = re.compile(r"--|/\*|['\"$\\]")
DOLAR_SQL = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")
# Los meta-comandos que no cambian qué corre ni cómo se confirma. \set AUTOCOMMIT sí lo cambia, y lo que va después de
# otro \ en la misma línea puede ser SQL.
METACOMANDOS_LEIDOS = ('\\echo', '\\qecho', '\\warn', '\\set', '\\unset')
# Variable de psql en el SQL de primer nivel (:nombre, :'nombre', :"nombre" o :{?nombre}): psql la cambia por su valor.
VARIABLE_PSQL = re.compile(r"(?<!:):(?!:)")
INICIO_DE_VARIABLE = re.compile(r"[^\W\d]|['\"{]")
# Las sentencias se cortan como en psql: en cada ; fuera de paréntesis y, en un CREATE FUNCTION o PROCEDURE, fuera de
# su BEGIN ATOMIC ... END (cuenta BEGIN y CASE, que también cierra con END).
PALABRA_SQL = re.compile(r"[^\W\d][\w$]*|[();]")
CREA_FUNCION = re.compile(r"create (?:or replace )?(?:function|procedure)\b")
# Sentencias de primer nivel que abren o cierran una transacción o vuelven a un SAVEPOINT. Fuera de un BEGIN psql
# confirma cada sentencia sola, y si el archivo termina con un BEGIN abierto la base lo deshace.
ABRE_TRANSACCION = re.compile(r"\s*(?:BEGIN|START\s+TRANSACTION)\b", re.IGNORECASE)
CIERRA_TRANSACCION = re.compile(r"\s*(COMMIT|END|ROLLBACK|ABORT)(?:\s+(?:WORK|TRANSACTION))?(\s+AND\s+(NO\s+)?CHAIN)?"
                                r"\s*;?\s*", re.IGNORECASE)
PUNTO_DE_RETORNO = re.compile(r"\s*(?:(SAVEPOINT)|(RELEASE)(?:\s+SAVEPOINT)?|(ROLLBACK)(?:\s+(?:WORK|TRANSACTION))?"
                              r"\s+TO(?:\s+SAVEPOINT)?)\s+([^\W\d][\w$]*)\s*;?\s*", re.IGNORECASE)
OTRO_CIERRE = re.compile(r"\s*(?:COMMIT|END|ROLLBACK|ABORT|PREPARE\s+TRANSACTION|SAVEPOINT|RELEASE)\b", re.IGNORECASE)
# El mapeo se lee sin comentarios: cada INSERT con su lista de columnas, hasta su primer ; fuera de comillas.
BLOQUE_MAPEOS = re.compile(r"INSERT INTO (?:public\.)?scoring_rule_framework_mappings\s*\(([^)]*)\)"
                           r"((?:%s|[^';])*);" % CADENA_SQL)
TABLA_MAPEO = r"(?:ONLY\s+)?(?:public\s*\.\s*)?scoring_rule_framework_mappings\b"
INSERT_MAPEO = re.compile(r"\bINSERT\s+INTO\s+" + TABLA_MAPEO, re.IGNORECASE)
UPDATE_MAPEO = re.compile(r"\bUPDATE\s+" + TABLA_MAPEO, re.IGNORECASE)
# Corrección de un mapeo ya aplicado: un UPDATE por código con WHERE rule_code = '...', que pone updated_at = now().
UPDATE_MAPEO_LEIDO = re.compile(r"UPDATE scoring_rule_framework_mappings\s+SET\s+([^;]*?)\s+WHERE\s+rule_code\s*=\s*"
                                r"('[^']*')\s*;")
CODIGO_MAPEO = re.compile(r"'([a-z][a-z0-9_]+)'")
ASIGNACION_MAPEO = re.compile(r"\s*([a-z_]+)\s*=\s*(NULL|now\(\)|%s)\s*(,|$)" % CADENA_SQL)
# Lo que la prueba no lee del mapeo: borrar filas o cargarlas sin INSERT. Un TRUNCATE cuenta si el mapeo va en su lista
# de tablas, no en un trigger BEFORE TRUNCATE ON ni en un GRANT o REVOKE TRUNCATE ON.
NOMBRE_SQL = r"[^\W\d][\w$]*(?:\s*\.\s*[^\W\d][\w$]*)?"
BORRADO_MAPEO = re.compile(r"\b(?:DELETE\s+FROM\s+|MERGE\s+INTO\s+|COPY\s+|TRUNCATE\s+(?:TABLE\s+)?"
                           r"(?:(?:ONLY\s+)?%s\s*\*?\s*,\s*)*)" % NOMBRE_SQL + TABLA_MAPEO, re.IGNORECASE)
# Un INSERT del mapeo se lee si es VALUES con sus filas y, si acaso, ON CONFLICT (rule_code) DO NOTHING. Cada fila
# leída se cambia por \0, que no puede ir en el SQL. Un upsert con DO UPDATE o un INSERT ... SELECT no se leen.
FORMA_MAPEO = re.compile(r"\s*VALUES\s*\x00(?:\s*,\s*\x00)*"
                         r"(?:\s+ON\s+CONFLICT\s*\(\s*rule_code\s*\)\s*DO\s+NOTHING)?\s*")
COLUMNAS_MAPEO = ('rule_code', 'attack_version', 'attack_technique_id', 'attack_technique_name', 'attack_source_url',
                  'attack_unmapped_reason', 'iso_version', 'iso_control_id', 'iso_control_name', 'iso_source_url',
                  'cis_version', 'cis_safeguard_id', 'cis_safeguard_name', 'cis_source_url')
# Una fila de mapeo entera, aunque vaya en la misma línea que otra: el código y los otros 13 valores, en ese orden.
FILA_MAPEO = re.compile(r"\(\s*'([a-z][a-z0-9_]+)'\s*,\s*" + r"\s*,\s*".join([r"(NULL|%s)" % CADENA_SQL] * 13) +
                        r"\s*\)")
INICIO_DE_MAPEO = re.compile(r"\(\s*'")
# Las versiones de los marcos que dicen el DBML y db/README para todas las reglas.
VERSIONES_MAPEO = {'attack_version': 'Enterprise v19', 'iso_version': 'ISO/IEC 27001:2022',
                   'cis_version': 'CIS Controls v8.1'}
NULOS_MAPEO = ('attack_technique_id', 'attack_technique_name', 'attack_unmapped_reason')  # las únicas sin NOT NULL
MIGRACION_011 = 'db/migraciones/011_mapeo_marcos.sql'
FILA_TEXTO = re.compile(r"\(\s*'([a-z0-9_]+)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*\)")
# Corrección de un texto ya aplicado (docs/codigos_reglas.md): un UPDATE por código con WHERE code = '...'.
UPDATE_TEXTO = re.compile(r"UPDATE scoring_rule_texts\s+SET\s+(.*?)\s+WHERE\s+code\s*=\s*'([a-z0-9_]+)'\s*;",
                          re.DOTALL)
CAMPOS_TEXTO = ('title', 'meaning', 'recommendation')
CAMPO_TEXTO = re.compile(r"\b(title|meaning|recommendation)\s*=\s*'([^']*)'")
OTRO_CAMPO = re.compile(r"\b(reviewed_by\s*=\s*(?:'[^']*'|NULL)|updated_at\s*=\s*now\(\))")
REVISOR = re.compile(r"\breviewed_by\s*=\s*(?:'([^']*)'|NULL)")
# Filas con que la 005 revisa los textos antes de cambiarlos: código, md5 de antes, md5 de después y revisor.
HUELLA = re.compile(r"^\s*\('([a-z0-9_]+)', '([0-9a-f]{32})', '([0-9a-f]{32})', (?:'([^']*)'|NULL)\),?$", re.MULTILINE)
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


def _relativa(ruta):
    return ruta.relative_to(RAIZ).as_posix()


def _de_nombre(c):
    return c.isalnum() or c in '_$'


@functools.lru_cache(maxsize=None)
def _sql(ruta):
    """Un archivo de db/ en tres copias del mismo largo, así las posiciones coinciden: sin comentarios ni meta-comandos
    de psql, además sin lo que va entre comillas (quedan las comillas de las cadenas, y los identificadores entre
    comillas quedan sin ellas) y además sin el cuerpo de los $tag$...$tag$, para ver las sentencias de primer nivel. El
    cuerpo de un $tag$ se lee como SQL, porque el de un DO corre, y lo que quede abierto en él termina con él. Da
    también los meta-comandos de primer nivel (psql no los busca dentro de un $tag$)."""
    sql = ruta.read_text(encoding='utf-8')
    copias, metacomandos = [list(sql), list(sql), list(sql)], []

    def blanco(desde, i, j):
        for copia in copias[desde:]:
            for k in range(i, j):
                if sql[k] != '\n':
                    copia[k] = ' '

    def recorrer(i, fin, cuerpo=False):
        while (m := ESPECIAL_SQL.search(sql, i, fin)):
            i, j = m.start(), m.end()
            if m.group() == '\\' and not cuerpo:
                j = sql.find('\n', i, fin)
                j = fin if j < 0 else j
                metacomandos.append(sql[i:j])
                blanco(0, i, j)
            elif m.group() == '--':
                j = sql.find('\n', i, fin)
                j = fin if j < 0 else j
                blanco(0, i, j)
            elif m.group() == '/*':
                nivel = 1
                while nivel and j < fin:
                    if sql.startswith('/*', j, fin):
                        nivel, j = nivel + 1, j + 2
                    elif sql.startswith('*/', j, fin):
                        nivel, j = nivel - 1, j + 2
                    else:
                        j += 1
                blanco(0, i, j)
            elif m.group() == "'":
                con_escape = i > 0 and sql[i - 1] in 'eE' and (i < 2 or not _de_nombre(sql[i - 2]))
                while j < fin and sql[j] != "'" or sql.startswith("''", j, fin):
                    j += 2 if (con_escape and sql[j] == '\\') or sql.startswith("''", j, fin) else 1
                j = min(j, fin)
                blanco(1, i + 1, j)
                if con_escape:
                    blanco(1, i - 1, i)
                j += 1
            elif m.group() == '"':
                while j < fin and sql[j] != '"' or sql.startswith('""', j, fin):
                    j += 2 if sql.startswith('""', j, fin) else 1
                j = min(j + 1, fin)
                for k in range(i, j):
                    if not _de_nombre(sql[k]) and sql[k] != '\n':
                        copias[1][k] = copias[2][k] = ' '
            elif m.group() == '\\' or i > 0 and _de_nombre(sql[i - 1]) or not (d := DOLAR_SQL.match(sql, i, fin)):
                j = i + 1
            else:
                k = sql.find(d.group(), d.end(), fin)
                k = fin if k < 0 else k
                recorrer(d.end(), k, True)
                blanco(2, d.end(), k)
                j = k + len(d.group())
            i = j

    recorrer(0, len(sql))
    return tuple(''.join(c) for c in copias) + (tuple(metacomandos),)


@functools.lru_cache(maxsize=None)
def _sentencias(ruta):
    """Los fines de las sentencias de primer nivel, cada sentencia con (inicio, fin, transacción, se confirma) y lo que
    la prueba no entiende de las transacciones. Las de un BEGIN ... COMMIT comparten transacción y cada una de las de
    fuera lleva la suya, porque psql la confirma al terminarla. COMMIT AND CHAIN abre otra enseguida. No se confirma lo
    que deshace un ROLLBACK, un ROLLBACK TO o el final del archivo con el BEGIN abierto."""
    primer_nivel = _sql(ruta)[2]
    cortes, inicio, palabras, parentesis, bloques = [], 0, [], 0, 0
    for m in PALABRA_SQL.finditer(primer_nivel):
        palabra = m.group().lower()
        if palabra == '(':
            parentesis += 1
        elif palabra == ')':
            parentesis = max(parentesis - 1, 0)
        elif palabra == ';':
            if not parentesis and not bloques:
                cortes.append((inicio, m.end()))
                inicio, palabras = m.end(), []
        else:
            palabras.append(palabra)
            if palabra in ('begin', 'case', 'end') and not parentesis and CREA_FUNCION.match(' '.join(palabras[:4])):
                if palabra == 'begin' or palabra == 'case' and bloques:
                    bloques += 1
                elif palabra == 'end' and bloques:
                    bloques -= 1
    if primer_nivel[inicio:].strip():
        cortes.append((inicio, len(primer_nivel)))  # psql corre lo que quede al final del archivo
    sentencias, no_entendidas, confirma, deshechas, puntos, n, abierta = [], [], {}, set(), [], 0, False
    for k, (i, j) in enumerate(cortes):
        texto = primer_nivel[i:j]
        if not abierta:
            n += 1
        sentencias.append((i, j, n))
        cierre, punto = CIERRA_TRANSACCION.fullmatch(texto), PUNTO_DE_RETORNO.fullmatch(texto)
        if ABRE_TRANSACCION.match(texto):
            abierta = True
        elif cierre:
            confirma[n], puntos = cierre.group(1).upper() in ('COMMIT', 'END'), []
            if cierre.group(2) and not cierre.group(3) and abierta:
                n += 1
            elif cierre.group(2) and not cierre.group(3):
                no_entendidas.append(' '.join(texto.split()))  # AND CHAIN fuera de un BEGIN da error
            else:
                abierta = False
        elif punto and abierta:
            orden, nombre = (punto.group(1) or punto.group(2) or punto.group(3)).upper(), punto.group(4).lower()
            previos = [x for x, (p, _) in enumerate(puntos) if p == nombre]
            if orden == 'SAVEPOINT':
                puntos.append((nombre, k))
            elif not previos:
                no_entendidas.append(' '.join(texto.split()))
            elif orden == 'ROLLBACK':
                deshechas.update(range(puntos[previos[-1]][1] + 1, k))
                del puntos[previos[-1] + 1:]
            else:
                del puntos[previos[-1]:]
        elif punto or OTRO_CIERRE.match(texto):
            no_entendidas.append(' '.join(texto.split()))
        if not abierta:
            confirma.setdefault(n, True)
    if abierta:
        confirma[n] = False
    sentencias = [(i, j, t, confirma[t] and k not in deshechas) for k, (i, j, t) in enumerate(sentencias)]
    return [s[1] for s in sentencias], sentencias, no_entendidas


def _sentencia(ruta, posicion):
    """(inicio, fin, transacción, se confirma) de la sentencia de primer nivel en que cae la posición."""
    fines, sentencias, _ = _sentencias(ruta)
    k = bisect.bisect_right(fines, posicion)
    return sentencias[k] if k < len(sentencias) else (posicion, posicion, None, False)


def _aplicada(ruta, posicion):
    """Si en la posición empieza una sentencia de primer nivel que se confirma, o sea que corre y queda. No lo es la que
    va en el cuerpo de un $tag$ (una función, un DO o una cadena), dentro de otra sentencia (un WITH, un CREATE RULE o
    una función con BEGIN ATOMIC) ni la que deshace un ROLLBACK."""
    primer_nivel = _sql(ruta)[2]
    inicio, _, _, confirmada = _sentencia(ruta, posicion)
    return confirmada and not primer_nivel[inicio:posicion].strip() and not primer_nivel[posicion].isspace()


def _filas(bloque, fila):
    """Las filas de todos los INSERT de una tabla en todos los archivos de db/, más los INSERT con filas sin leer."""
    filas, mal_leidos = [], []
    for ruta in ARCHIVOS_SQL:
        sql = _sql(ruta)[0]
        for m in bloque.finditer(sql):
            leidas = fila.findall(m.group(0))
            esperadas = len(INICIO_DE_FILA.findall(m.group(0)))
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
        sql = _sql(ruta)[0]
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


def posiciones_textos():
    """{code: (archivo, posición, transacción, se aplica)} del INSERT de cada texto, para ver que su mapeo vaya después
    y en la misma transacción, y que el INSERT sea una sentencia de primer nivel que se confirma (_aplicada)."""
    posiciones = {}
    for ruta in ARCHIVOS_SQL:
        sql = _sql(ruta)[0]
        for m in BLOQUE_TEXTOS.finditer(sql):
            aplicado = _aplicada(ruta, m.start())
            for f in FILA_TEXTO.finditer(m.group(0)):
                posicion = m.start() + f.start()
                posiciones.setdefault(f.group(1), (_relativa(ruta), posicion, _sentencia(ruta, posicion)[2], aplicado))
    return posiciones


def _valor(v):
    return None if v == 'NULL' else v[1:-1].replace("''", "'")


def _asignaciones(texto):
    """{columna: valor como va en el SQL} de un SET con col = 'x', col = NULL o col = now(), o None si no se lee."""
    pares, i = [], 0
    while (a := ASIGNACION_MAPEO.match(texto, i)):
        pares.append(a.group(1, 2))
        i = a.end()
        if not a.group(3):
            return dict(pares) if i == len(texto) and len(dict(pares)) == len(pares) else None
    return None


def leer_mapeos():
    """Los (archivo, orden, posición, transacción, code, {columna: valor}) de los INSERT INTO
    scoring_rule_framework_mappings de todo db/ (la 011 y las migraciones que vengan, porque la 011 ya no se edita),
    los (archivo, orden, posición, code, {columna: valor como va en el SQL}) de sus UPDATE, con orden el del archivo en
    ARCHIVOS_SQL, y lo que no se pudo leer. También van en lo que no se pudo leer un DELETE, TRUNCATE, MERGE o COPY del
    mapeo, un INSERT o UPDATE del mapeo que no es una sentencia de primer nivel que se confirma, y en cualquier archivo
    un meta-comando de psql fuera de METACOMANDOS_LEIDOS, una variable de psql o un cierre de transacción que la prueba
    no entiende."""
    mapeos, cambios, mal_leidos = [], [], []
    for orden, ruta in enumerate(ARCHIVOS_SQL):
        archivo, (sql, sin_cadenas, primer_nivel, metacomandos) = _relativa(ruta), _sql(ruta)
        for texto in metacomandos:
            partes = texto.split()
            if partes[0] not in METACOMANDOS_LEIDOS or '\\' in texto[1:] or partes[1:2] == ['AUTOCOMMIT']:
                mal_leidos.append('%s: meta-comando de psql %r, y la prueba solo lee %s (sin \\set AUTOCOMMIT)'
                                  % (archivo, texto, ', '.join(METACOMANDOS_LEIDOS)))
        if any(INICIO_DE_VARIABLE.match(sql, v.end()) for v in VARIABLE_PSQL.finditer(primer_nivel)):
            mal_leidos.append('%s: variable de psql (:nombre) en el SQL, que la prueba no lee' % archivo)
        for texto in _sentencias(ruta)[2]:
            mal_leidos.append('%s: %r, y la prueba no sabe cómo deja la transacción' % (archivo, texto))
        if BORRADO_MAPEO.search(sin_cadenas):
            mal_leidos.append('%s: DELETE, TRUNCATE, MERGE o COPY de scoring_rule_framework_mappings, que la prueba no '
                              'lee' % archivo)
        for m in (*INSERT_MAPEO.finditer(sin_cadenas), *UPDATE_MAPEO.finditer(sin_cadenas)):
            if not _aplicada(ruta, m.start()):
                mal_leidos.append('%s: INSERT o UPDATE de scoring_rule_framework_mappings que no es una sentencia de '
                                  'primer nivel que se confirma (va en un $tag$, dentro de otra sentencia o en lo que '
                                  'deshace un ROLLBACK), y la prueba no sabe si corre' % archivo)
        updates = list(UPDATE_MAPEO_LEIDO.finditer(sin_cadenas))
        if len(updates) != len(UPDATE_MAPEO.findall(sin_cadenas)):
            mal_leidos.append('%s: UPDATE scoring_rule_framework_mappings que la prueba no pudo leer' % archivo)
        for u in updates:
            code = CODIGO_MAPEO.fullmatch(sql[u.start(2):u.end(2)])
            asignaciones = _asignaciones(sql[u.start(1):u.end(1)])
            if not code or asignaciones is None:
                mal_leidos.append('%s: UPDATE del mapeo con un SET o un WHERE que la prueba no pudo leer' % archivo)
                continue
            cambios.append((archivo, orden, u.start(), code.group(1), asignaciones))
        # Los bloques se buscan sin cadenas, así una comilla dentro de una cadena no los corta, y se leen con ellas.
        bloques = list(BLOQUE_MAPEOS.finditer(sin_cadenas))
        if len(bloques) != len(INSERT_MAPEO.findall(sin_cadenas)):
            mal_leidos.append('%s: INSERT INTO scoring_rule_framework_mappings que la prueba no pudo leer' % archivo)
        for m in bloques:
            columnas = tuple(c.strip() for c in m.group(1).split(','))
            if columnas != COLUMNAS_MAPEO:
                mal_leidos.append('%s: INSERT del mapeo con las columnas %s' % (archivo, ', '.join(columnas)))
                continue
            filas = list(FILA_MAPEO.finditer(sql, m.start(2), m.end(2)))
            esperadas = len(INICIO_DE_MAPEO.findall(m.group(2)))
            if len(filas) != esperadas:
                mal_leidos.append('%s: %d filas de mapeo y se leyeron %d' % (archivo, esperadas, len(filas)))
            forma, i = '', m.start(2)
            for f in filas:
                forma, i = forma + sql[i:f.start()] + '\0', f.end()
            if not FORMA_MAPEO.fullmatch(forma + sql[i:m.end(2)]):
                mal_leidos.append('%s: INSERT del mapeo que no es VALUES con sus filas y, si acaso, ON CONFLICT '
                                  '(rule_code) DO NOTHING (un upsert con DO UPDATE o un INSERT ... SELECT no se leen)'
                                  % archivo)
            for f in filas:
                valores = dict(zip(COLUMNAS_MAPEO, (f.group(1),) + tuple(_valor(v) for v in f.groups()[1:])))
                mapeos.append((archivo, orden, f.start(), _sentencia(ruta, f.start())[2], f.group(1), valores))
    return mapeos, cambios, mal_leidos


def leer_doc():
    return (RAIZ / 'docs' / 'codigos_reglas.md').read_text(encoding='utf-8')


def leer_json(nombre):
    return json.loads((RAIZ / 'docs' / 'api_v1' / nombre).read_text(encoding='utf-8'), parse_float=Decimal)


REGLAS, REGLAS_MAL_LEIDAS = leer_reglas()
REGLAS_V1 = sorted((r for r in REGLAS if r[2] == JUEGO_V1), key=lambda r: r[1])
POR_CODIGO = {r[3]: r for r in REGLAS_V1}
TEXTOS, TEXTOS_POR_CODIGO, TEXTOS_MAL_LEIDOS = leer_textos()
POSICION_TEXTOS = posiciones_textos()
MAPEOS, CAMBIOS_MAPEO, MAPEOS_MAL_LEIDOS = leer_mapeos()
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
        # Una regla nueva trae su mapeo en la migración de su texto, después de él y en la misma transacción: la FK de
        # la 011 (del mapeo al texto) se revisa en el momento y la de la 012 (del texto al mapeo) en el COMMIT. Los
        # textos de antes de la 011 tienen su mapeo en la 011. Un mapeo se corrige en una migración posterior con un
        # UPDATE por código que pone updated_at = now() (comentario de la columna en la 012), y no se borra. Solo se
        # leen el INSERT y el UPDATE que son sentencias de primer nivel que se confirman: lo que va en un $tag$, en otra
        # sentencia o en lo que deshace un ROLLBACK hace fallar la prueba, porque no se sabe si corre.
        self.assertEqual(MAPEOS_MAL_LEIDOS, [], 'INSERT, UPDATE, DELETE o TRUNCATE de scoring_rule_framework_mappings, '
                                                'meta-comandos de psql o transacciones que la prueba no pudo leer')
        codigos = [m[4] for m in MAPEOS]
        repetidos = sorted(c for c, n in Counter(codigos).items() if n > 1)
        self.assertEqual(repetidos, [], 'hay mapeos insertados dos veces (una corrección va con UPDATE ... SET ..., '
                                        "updated_at = now() WHERE rule_code = '...'): %s" % repetidos)
        self.assertEqual(set(codigos), set(TEXTOS_POR_CODIGO),
                         'los mapeos no cubren exactamente las reglas del catálogo')
        for archivo, _, posicion, transaccion, code, _ in MAPEOS:
            self.assertTrue(archivo.startswith('db/migraciones/'),
                            '%s: el mapeo de %r va en una semilla y las semillas corren después de todas las migraciones'
                            % (archivo, code))
            archivo_texto, posicion_texto, transaccion_texto, aplicado_texto = POSICION_TEXTOS[code]
            self.assertTrue(aplicado_texto, '%s: el INSERT del texto de %r no es una sentencia de primer nivel que se '
                            'confirma, y la prueba no sabe si corre' % (archivo_texto, code))
            if archivo_texto < MIGRACION_011:
                self.assertEqual(archivo, MIGRACION_011, '%r tiene su texto en %s y su mapeo en %s, no en la 011'
                                 % (code, archivo_texto, archivo))
            else:
                self.assertEqual(archivo, archivo_texto, '%r tiene su texto en %s y su mapeo en %s'
                                 % (code, archivo_texto, archivo))
                self.assertGreater(posicion, posicion_texto, '%s: el mapeo de %r va antes que su texto' % (archivo, code))
                self.assertEqual(transaccion, transaccion_texto, '%s: el texto y el mapeo de %r van en transacciones '
                                 'distintas (sin BEGIN o con un COMMIT entre ellos), y la FK de la 012 se revisa en el '
                                 'COMMIT del texto' % (archivo, code))
        # Las versiones se revisan como quedan después de los UPDATE, en el orden en que corren.
        insertados = {m[4]: (m[1], m[2]) for m in MAPEOS}
        finales = {m[4]: dict(m[5]) for m in MAPEOS}
        for archivo, orden, posicion, code, asignaciones in sorted(CAMBIOS_MAPEO, key=lambda c: c[1:3]):
            self.assertTrue(archivo.startswith('db/migraciones/'),
                            '%s: el UPDATE del mapeo de %r va en una semilla, y un mapeo se corrige con una migración'
                            % (archivo, code))
            self.assertTrue(code in insertados and insertados[code] < (orden, posicion),
                            '%s: UPDATE del mapeo de %r, que no tiene INSERT antes' % (archivo, code))
            asignaciones = dict(asignaciones)
            self.assertEqual(asignaciones.pop('updated_at', None), 'now()',
                             '%s: el UPDATE del mapeo de %r no pone updated_at = now()' % (archivo, code))
            for columna, valor in asignaciones.items():
                self.assertTrue(columna in COLUMNAS_MAPEO[1:] and valor != 'now()',
                                '%s: el UPDATE del mapeo de %r pone %s = %s' % (archivo, code, columna, valor))
                finales[code][columna] = _valor(valor)
        for code, valores in sorted(finales.items()):
            for columna, version in VERSIONES_MAPEO.items():
                self.assertEqual(valores[columna], version, 'el mapeo de %r queda con %s = %r'
                                 % (code, columna, valores[columna]))
            for columna in COLUMNAS_MAPEO:
                self.assertTrue(columna in NULOS_MAPEO or valores[columna] is not None, 'el mapeo de %r queda con %s '
                                'en NULL, y en la 011 la columna es NOT NULL' % (code, columna))

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
        # fila conservaría la firma del texto anterior
        revisor, sin_firma = {}, []
        for ruta in ARCHIVOS_SQL:
            for asignaciones, code in UPDATE_TEXTO.findall(ruta.read_text(encoding='utf-8')):
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
            sql, nombre = ruta.read_text(encoding='utf-8'), _relativa(ruta)
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


if __name__ == '__main__':
    unittest.main()
