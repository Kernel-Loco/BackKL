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
from collections import Counter, namedtuple
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
# El SQL se lee como lo leen psql y Postgres (_Lexico): cadenas '...' con '' (y la que la sigue en otra línea),
# E'...' con \, B'...' y X'...', identificadores entre comillas (distinguen mayúsculas y nunca son palabras clave),
# $tag$ con cualquier letra en la etiqueta, comentarios -- y /* */ anidados, y palabras sin comillas, que se comparan en
# minúsculas ASCII como en Postgres. Un \ fuera de todo eso y de un $tag$ empieza un meta-comando de psql, hasta el fin
# de la línea.
Token = namedtuple('Token', 'tipo inicio fin valor cuerpo')  # cuerpo: los tokens dentro de un $tag$
LETRA = 'A-Za-z_\x80-\U0010ffff'  # Postgres: ident_start, con todo lo que no es ASCII
PALABRA = re.compile(r"[%s][%s0-9$]*" % (LETRA, LETRA))
ETIQUETA = re.compile(r"\$(?:[%s][%s0-9]*)?\$" % (LETRA, LETRA))
PARAMETRO = re.compile(r"\$[0-9]+")
NUMERO = re.compile(r"0[xXoObB][0-9A-Fa-f_]+|(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9]+)?")
ESPACIOS = re.compile(r"[ \t\n\r\f\v]+")
HASTA_SALTO = re.compile(r"[^\n\r]*")  # un comentario -- termina en \n o en \r
HASTA_FIN_DE_LINEA = re.compile(r"[^\n]*")  # psql lee el SQL por líneas, cortadas solo en \n
MARCA_DE_COMENTARIO = re.compile(r"/\*|\*/")
# Lo que va dentro de cada clase de cadena hasta su comilla de cierre. Las B'...' y X'...' cierran en la primera '.
DENTRO = {'cadena': re.compile(r"(?:[^']+|'')*"), 'cadena_u': re.compile(r"(?:[^']+|'')*"),
          'cadena_e': re.compile(r"(?:[^'\\]+|''|\\.)*", re.DOTALL), 'cadena_b': re.compile(r"[^']*"),
          'cadena_x': re.compile(r"[^']*"), 'nombre': re.compile(r'(?:[^"]+|"")*'),
          'nombre_u': re.compile(r'(?:[^"]+|"")*')}
PREFIJO_DE_CADENA = {'e': 'cadena_e', 'b': 'cadena_b', 'x': 'cadena_x', 'n': 'cadena'}
ESCAPE_E = re.compile(r"''|\\(x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)", re.DOTALL)
ESCAPES_E = {'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}
MINUSCULAS_ASCII = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
OPERADORES = '~!@#^&|`?+-*/%<>='  # Postgres: op_chars. Un -- o un /* corta el operador
SIMBOLOS = ',()[].;'
# Variable de psql (:nombre, :'nombre', :"nombre" o :{?nombre}) en el SQL o en un meta-comando: psql la cambia por su
# valor.
VARIABLE_PSQL = re.compile(r":(?:[A-Za-z0-9_\x80-\U0010ffff'\"]|\{\?)")
# Los únicos meta-comandos que se leen, porque no cambian qué corre ni cómo se confirma: \echo, \qecho y \warn sin
# comillas invertidas (corren un comando del sistema), variables de psql ni otro \ fuera de comillas (empieza otro
# meta-comando o vuelve al SQL en la misma línea), y \set ON_ERROR_STOP on. Cualquier otro hace fallar la prueba.
ECOS_PSQL = ('\\echo', '\\qecho', '\\warn')
NOMBRE_METACOMANDO = re.compile(r'\\[^ \t\n\r\f\v\\]*')
# Argumentos de un meta-comando como los lee psql: '...' con \ y '', "..." tal cual, texto suelto o un carácter
# especial.
ARGUMENTO_PSQL = re.compile(r"'(?:[^'\\]+|''|\\.?)*'?|\"[^\"]*\"?|[^'\"`:\\]+|(.)")
ON_ERROR_STOP = re.compile(r"\\set[ \t\r\f\v]+ON_ERROR_STOP[ \t\r\f\v]+(?i:on|true|1)[ \t\r\f\v]*")
# Cada sentencia se lee también en forma pareja (_forma), con regex: sus tokens separados por un espacio.
NOMBRE_SIMPLE = re.compile(r"[a-z_][a-z0-9_$]*")
PALABRA_F = '[a-z_\x80-\U0010ffff][a-z0-9_$\x80-\U0010ffff]*'
# psql corta las sentencias en cada ; fuera de paréntesis y, en un CREATE FUNCTION o PROCEDURE, fuera de su BEGIN
# ... END (_sentencias). Fuera de un BEGIN confirma cada sentencia sola, y si el archivo termina con un BEGIN abierto la
# base lo deshace. Un SAVEPOINT, RELEASE o ROLLBACK TO se lee solo con el nombre sin comillas.
CREA_FUNCION = re.compile(r"create (?:or replace )?(?:function|procedure)(?![^ ])")
ABRE_TRANSACCION = re.compile(r"(?:begin|start transaction)(?![^ ])")
CIERRA_TRANSACCION = re.compile(r"(commit|end|rollback|abort)(?: (?:work|transaction))?( and( no)? chain)?(?: ;)?")
PUNTO_DE_RETORNO = re.compile(r"(?:(savepoint)|(release)(?: savepoint)?|(rollback)(?: (?:work|transaction))? to"
                              r"(?: savepoint)?) (%s|\"[^\"]*\")(?: ;)?" % PALABRA_F)
OTRO_CIERRE = re.compile(r"(?:commit|end|rollback|abort|savepoint|release|prepare transaction)(?![^ ])")
# Lo que cambia cómo leen las cadenas psql y Postgres, que la prueba no imita: standard_conforming_strings (con off un \
# escapa la ' en toda cadena), client_encoding y SET NAMES (otra codificación lee otros bytes como \ o '). Solo se lee
# SET client_encoding = 'UTF8', que llevan los archivos de db/.
CLIENT_ENCODING_UTF8 = re.compile(r"set(?: session)? client_encoding (?:=|to) '([0-9]+)'(?: ;)?")
AJUSTE_DE_LECTURA = re.compile(r'(?<![^ ])(?:"?(?:standard_conforming_strings|client_encoding)"?|'
                               r'set(?: session| local)? names|(?:reset|discard) all)(?![^ ])')
# El mapeo se escribe con INSERT o UPDATE, en cualquier sentencia y en el cuerpo de cualquier $tag$. DELETE, MERGE,
# COPY y un TRUNCATE con el mapeo en su lista de tablas (no un trigger BEFORE TRUNCATE ON ni un GRANT o REVOKE TRUNCATE
# ON) no se leen.
MAPEO_F = r'(?:scoring_rule_framework_mappings|"scoring_rule_framework_mappings")(?![^ ])'
ESCRIBE_MAPEO = re.compile(r"(?<![^ ])(insert into|update(?: only)?) (?:[^ ]+ \. )*" + MAPEO_F)
BORRADO_MAPEO = re.compile(r"(?<![^ ])(?:(?:delete from|merge into)(?: only)? |copy )(?:[^ ]+ \. )*" + MAPEO_F +
                           r"|(?<![^ ])truncate (?!on |or |, )[^;]*?(?<![^ ])" + MAPEO_F)
COLUMNAS_MAPEO = ('rule_code', 'attack_version', 'attack_technique_id', 'attack_technique_name', 'attack_source_url',
                  'attack_unmapped_reason', 'iso_version', 'iso_control_id', 'iso_control_name', 'iso_source_url',
                  'cis_version', 'cis_safeguard_id', 'cis_safeguard_name', 'cis_source_url')
# Un INSERT del mapeo se lee si es INSERT INTO [public.]scoring_rule_framework_mappings con sus 14 columnas en orden,
# VALUES con filas de cadenas '...' o NULL y, si acaso, ON CONFLICT (rule_code) DO NOTHING.
INSERT_MAPEO = re.compile(r"insert into (?:(?:public|\"public\") \. )?%s \( (.*?) \) (.*)" % MAPEO_F)
VALOR_F = r"(?:'[0-9]+'|null)"
FILA_F = r"\( '[0-9]+'" + r" , %s" % VALOR_F * 13 + r" \)"
FORMA_INSERT = re.compile(r"values %s(?: , %s)*(?: on conflict \( (?:rule_code|\"rule_code\") \) do nothing)?(?: ;)?"
                          % (FILA_F, FILA_F))
FILA_LEIDA = re.compile(r"\( '([0-9]+)'" + r" , (%s)" % VALOR_F * 13 + r" \)")
# Corrección de un mapeo ya aplicado: un UPDATE por código con WHERE rule_code = '...', que pone updated_at = now().
UPDATE_MAPEO = re.compile(r"update (?:only )?(?:(?:public|\"public\") \. )?%s set (.*) "
                          r"where (?:rule_code|\"rule_code\") = '([0-9]+)'(?: ;)?" % MAPEO_F)
ASIGNACION = re.compile(r"(?:([a-z_][a-z0-9_$]*)|\"([a-z_][a-z0-9_$]*)\") = ('[0-9]+'|null|now \( \))")
# Las versiones de los marcos que dicen el DBML y db/README para todas las reglas.
VERSIONES_MAPEO = {'attack_version': 'Enterprise v19', 'iso_version': 'ISO/IEC 27001:2022',
                   'cis_version': 'CIS Controls v8.1'}
NULOS_MAPEO = ('attack_technique_id', 'attack_technique_name', 'attack_unmapped_reason')  # las únicas sin NOT NULL
# Los CHECK de la 011, que la base revisa en cada INSERT y en cada UPDATE del mapeo: btrim(x) <> '', x ~ '^...$' y
# x LIKE 'https://%', más la técnica de ATT&CK con id y nombre o, sin ellos, con su motivo.
NO_VACIAS_MAPEO = ('attack_version', 'iso_version', 'iso_control_name', 'cis_version', 'cis_safeguard_name')
FORMATOS_MAPEO = {'attack_technique_id': re.compile(r'T[0-9]{4}(?:\.[0-9]{3})?'),
                  'iso_control_id': re.compile(r'A\.[5-8]\.[0-9]{1,2}'),
                  'cis_safeguard_id': re.compile(r'(?:[1-9]|1[0-8])\.[0-9]{1,2}')}
FUENTES_MAPEO = ('attack_source_url', 'iso_source_url', 'cis_source_url')
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


def _relativa(ruta):
    return ruta.relative_to(RAIZ).as_posix()


def _linea(sql, posicion):
    return sql.count('\n', 0, posicion) + 1


def _de_escapes(texto):
    """El valor de una cadena E'...': \\b, \\f, \\n, \\r, \\t, \\uXXXX y \\UXXXXXXXX, bytes de UTF8 con \\ooo y
    \\xhh, '' como ' y cualquier otro carácter tal cual después de \\."""
    valor, i = bytearray(), 0
    for m in ESCAPE_E.finditer(texto):
        valor += texto[i:m.start()].encode('utf-8', 'surrogatepass')
        e, i = m.group(1), m.end()
        if e is None:
            valor += b"'"
        elif e[0] == 'x' and len(e) > 1 or e[0] in '01234567':
            valor.append(int(e[1:], 16) if e[0] == 'x' else int(e, 8) & 0xFF)
        elif e[0] in 'uU' and len(e) > 1:
            valor += chr(min(int(e[1:], 16), 0xFFFD)).encode('utf-8', 'surrogatepass')
        else:
            valor += ESCAPES_E.get(e, e).encode('utf-8', 'surrogatepass')
    valor += texto[i:].encode('utf-8', 'surrogatepass')
    return valor.decode('utf-8', 'replace')


def _motivo_eco(argumentos):
    """Por qué psql no se limita a escribir los argumentos de un \\echo, \\qecho o \\warn, o None."""
    for m in ARGUMENTO_PSQL.finditer(argumentos):
        if m.group(1) == '`':
            return 'corre un comando del sistema (comillas invertidas)'
        if m.group(1) == '\\':
            return 'lleva otro \\ fuera de comillas, que empieza otro meta-comando o vuelve al SQL en la misma línea'
        if m.group(1) == ':' and VARIABLE_PSQL.match(argumentos, m.start()):
            return 'usa una variable de psql'
    return None


class _Lexico:
    """Lee un archivo de db/ en tokens como psql y Postgres. Deja en sin_comentarios el texto sin comentarios ni
    meta-comandos, del mismo largo para que las posiciones coincidan, y en problemas lo que la prueba no lee. El cuerpo
    de un $tag$ se lee como SQL, porque el de un DO corre, y lo que quede abierto en él termina con él."""

    def __init__(self, sql):
        self.sql, self.sin_comentarios, self.problemas = sql, list(sql), []

    def problema(self, posicion, texto):
        self.problemas.append('línea %d: %s' % (_linea(self.sql, posicion), texto))

    def blanco(self, i, j):
        for k in range(i, j):
            if self.sql[k] != '\n':
                self.sin_comentarios[k] = ' '

    def leer(self, i, fin, cuerpo=False):
        """Los tokens de sql[i:fin]. En el cuerpo de un $tag$ un \\ o un :nombre son SQL, no de psql."""
        sql, tokens = self.sql, []
        while i < fin:
            c, j, tipo, dentro = sql[i], i + 1, None, ()
            if c in ' \t\n\r\f\v':
                j = ESPACIOS.match(sql, i, fin).end()
            elif sql.startswith('--', i, fin):
                j = HASTA_SALTO.match(sql, i, fin).end()
                self.blanco(i, j)
            elif sql.startswith('/*', i, fin):
                j = self.comentario(i, fin, cuerpo)
                self.blanco(i, j)
            elif c == '\\' and not cuerpo:
                j = HASTA_FIN_DE_LINEA.match(sql, i, fin).end()
                self.metacomando(i, sql[i:j])
                self.blanco(i, j)
            elif c in '\'"':
                tipo = 'cadena' if c == "'" else 'nombre'
                j, valor = self.cadena(tipo, i, fin, cuerpo)
            elif (m := PALABRA.match(sql, i, fin)):
                j, prefijo = m.end(), m.group().lower()
                if prefijo in PREFIJO_DE_CADENA and sql.startswith("'", j, fin):
                    tipo = PREFIJO_DE_CADENA[prefijo]
                    j, valor = self.cadena(tipo, j, fin, cuerpo)
                elif prefijo == 'u' and sql.startswith(("&'", '&"'), j) and j + 1 < fin:
                    tipo = 'cadena_u' if sql[j + 1] == "'" else 'nombre_u'
                    j, valor = self.cadena(tipo, j + 1, fin, cuerpo)
                    self.problema(i, "U&'...' o U&\"...\" con escapes Unicode, que la prueba no lee")
                else:
                    tipo, valor = 'palabra', m.group().translate(MINUSCULAS_ASCII)
            elif c == '$' and (m := ETIQUETA.match(sql, i, fin)):
                k = sql.find(m.group(), m.end(), fin)
                if k < 0 and not cuerpo:
                    self.problema(i, 'cadena %s sin cerrar' % m.group())
                k = fin if k < 0 else k
                tipo, valor, dentro = 'dolar', sql[m.end():k], tuple(self.leer(m.end(), k, True))
                j = min(k + len(m.group()), fin)
            elif c in '0123456789' or c == '.' and sql[i + 1:i + 2].isdigit():
                tipo, j = 'numero', NUMERO.match(sql, i, fin).end()
                valor = sql[i:j]
            elif c == ':':
                j = i + 2 if sql.startswith(('::', ':='), i) and i + 1 < fin else i + 1
                if not cuerpo and j == i + 1 and VARIABLE_PSQL.match(sql, i, fin):
                    self.problema(i, 'variable de psql (:nombre, :\'nombre\', :"nombre" o :{?nombre}) en el SQL, '
                                     'que psql cambia por su valor')
                tipo, valor = 'simbolo', sql[i:j]
            elif c in OPERADORES:
                while j < fin and sql[j] in OPERADORES and not sql.startswith(('--', '/*'), j):
                    j += 1
                tipo, valor = 'operador', sql[i:j]
            else:
                if c == '$' and (m := PARAMETRO.match(sql, i, fin)):
                    j = m.end()
                tipo, valor = 'simbolo' if c in SIMBOLOS else 'otro', sql[i:j]
            if tipo:
                tokens.append(Token(tipo, i, j, valor, dentro))
            i = j
        return tokens

    def comentario(self, i, fin, cuerpo):
        """El fin del comentario /* */ que abre en i, con los de adentro (Postgres los anida)."""
        nivel, j = 1, i + 2
        while nivel and (m := MARCA_DE_COMENTARIO.search(self.sql, j, fin)):
            nivel, j = nivel + (1 if m.group() == '/*' else -1), m.end()
        if nivel and not cuerpo:
            self.problema(i, 'comentario /* sin cerrar')
        return fin if nivel else j

    def cadena(self, tipo, j, fin, cuerpo):
        """El fin y el valor de la cadena o el nombre entre comillas cuya comilla abre en j, con las cadenas que lo
        siguen después de un salto de línea (Postgres: quotecontinue, solo con espacios y comentarios -- en medio)."""
        sql, comilla, partes = self.sql, self.sql[j], []
        while True:
            k = DENTRO[tipo].match(sql, j + 1, fin).end()
            partes.append(sql[j + 1:k])
            if k >= fin or sql[k] != comilla:
                if not cuerpo:
                    self.problema(j, ('cadena %s sin cerrar' if comilla == "'" else 'nombre %s sin cerrar')
                                  % sql[j:j + 20].split('\n')[0])
                return fin, self.valor(tipo, partes)
            j = self.continuacion(k + 1, fin) if comilla == "'" else None
            if j is None:
                return k + 1, self.valor(tipo, partes)

    def continuacion(self, j, fin):
        """Dónde abre la cadena que sigue a la que cierra antes de j, o None."""
        sql, salto = self.sql, False
        while j < fin:
            if sql[j] in ' \t\n\r\f\v':
                salto, j = salto or sql[j] in '\n\r', j + 1
            elif sql.startswith('--', j, fin):
                k = HASTA_SALTO.match(sql, j, fin).end()
                self.blanco(j, k)
                j = k
            else:
                return j if salto and sql[j] == "'" else None
        return None

    @staticmethod
    def valor(tipo, partes):
        texto = ''.join(partes)
        if tipo == 'cadena_e':
            return _de_escapes(texto)
        return texto.replace('""', '"') if tipo.startswith('nombre') else texto.replace("''", "'")

    def metacomando(self, i, texto):
        """Revisa un meta-comando de psql (del \\ al fin de la línea) contra la lista blanca."""
        nombre = NOMBRE_METACOMANDO.match(texto).group()
        if ON_ERROR_STOP.fullmatch(texto):
            return
        if nombre in ECOS_PSQL:
            motivo = _motivo_eco(texto[len(nombre):])
        else:
            motivo = 'la prueba solo lee \\echo, \\qecho y \\warn con texto fijo y \\set ON_ERROR_STOP on'
        if motivo:
            self.problema(i, 'meta-comando de psql %r: %s' % (texto.strip(), motivo))


@functools.lru_cache(maxsize=None)
def _sql(ruta):
    """Un archivo de db/ leído como lo leen psql y Postgres (_Lexico): el texto sin comentarios ni meta-comandos, del
    mismo largo, sus tokens de primer nivel y lo que la prueba no lee, con su línea. Un \\r sin \\n después no se lee:
    Postgres lo toma como fin de un comentario -- y psql no como fin de línea."""
    sql = ruta.read_bytes().decode('utf-8').replace('\r\n', '\n')
    lexico = _Lexico(sql)
    for m in re.finditer(r'\r', sql):
        lexico.problema(m.start(), '\\r sin \\n después, y psql corta las líneas solo en \\n')
    tokens = lexico.leer(0, len(sql))
    return ''.join(lexico.sin_comentarios), tuple(tokens), tuple(lexico.problemas)


def _forma(tokens):
    """Una lista de tokens en forma pareja, para leerla con regex: separados por un espacio, las palabras en minúsculas,
    cada cadena '...' o E'...' como 'n' con su valor en valores[n], un nombre entre comillas como "nombre" (o "?" si
    lleva mayúsculas u otros caracteres) y las otras cadenas como $$, b'', x'', u&'' y u&""."""
    partes, valores = [], []
    for t in tokens:
        if t.tipo in ('cadena', 'cadena_e'):
            partes.append("'%d'" % len(valores))
            valores.append(t.valor)
        elif t.tipo == 'nombre':
            partes.append('"%s"' % (t.valor if NOMBRE_SIMPLE.fullmatch(t.valor) else '?'))
        else:
            partes.append({'dolar': '$$', 'cadena_b': "b''", 'cadena_x': "x''", 'cadena_u': "u&''",
                           'nombre_u': 'u&""'}.get(t.tipo, t.valor))
    return ' '.join(partes), tuple(valores)


def _cuerpos(tokens):
    """(token, tokens de su cuerpo) de cada $tag$, también los que van dentro de otro."""
    for t in tokens:
        if t.tipo == 'dolar':
            yield t, t.cuerpo
            yield from _cuerpos(t.cuerpo)


Sentencia = namedtuple('Sentencia', 'inicio fin transaccion confirmada forma valores')


@functools.lru_cache(maxsize=None)
def _sentencias(ruta):
    """Los fines de las sentencias de primer nivel, las Sentencia y lo que la prueba no entiende de cómo psql las
    corta o deja la transacción. psql corta en cada ; fuera de paréntesis y, en un CREATE FUNCTION o PROCEDURE, fuera de
    su BEGIN ATOMIC ... END (cuenta BEGIN y CASE, que también cierra con END). Un BEGIN que no es ATOMIC junta
    sentencias. Las de un BEGIN ... COMMIT comparten transacción y cada una de las de fuera lleva la suya, porque psql
    la confirma al terminarla. COMMIT AND CHAIN abre otra enseguida. No se confirma lo que deshace un ROLLBACK, un ROLLBACK TO o el
    final del archivo con el BEGIN abierto."""
    sql, tokens, _ = _sql(ruta)
    grupos, actual, palabras, parentesis, bloques, no_entendidas = [], [], [], 0, 0, []
    for k, t in enumerate(tokens):
        actual.append(t)
        if t.tipo == 'simbolo' and t.valor == '(':
            parentesis += 1
        elif t.tipo == 'simbolo' and t.valor == ')':
            parentesis = max(parentesis - 1, 0)
        elif t.tipo == 'simbolo' and t.valor == ';' and not parentesis and not bloques:
            grupos.append(actual)
            actual, palabras = [], []
        elif t.tipo == 'palabra':
            palabras.append(t.valor)
            if t.valor in ('begin', 'case', 'end') and not parentesis and CREA_FUNCION.match(' '.join(palabras[:4])):
                siguiente = tokens[k + 1] if k + 1 < len(tokens) else None
                if t.valor == 'begin':
                    bloques += 1
                    if not siguiente or (siguiente.tipo, siguiente.valor) != ('palabra', 'atomic'):
                        no_entendidas.append('línea %d: CREATE FUNCTION o PROCEDURE con un BEGIN que no es BEGIN '
                                             'ATOMIC, y psql junta las sentencias que siguen hasta un END'
                                             % _linea(sql, t.inicio))
                elif t.valor == 'case' and bloques:
                    bloques += 1
                elif t.valor == 'end' and bloques:
                    bloques -= 1
    if actual:
        grupos.append(actual)  # psql corre lo que quede al final del archivo
    sentencias, confirma, deshechas, puntos, n, abierta = [], {}, set(), [], 0, False
    for k, grupo in enumerate(grupos):
        inicio, fin = grupo[0].inicio, grupo[-1].fin
        forma, valores = _forma(grupo)
        if not abierta:
            n += 1
        sentencias.append((inicio, fin, n, forma, valores))
        cierre, punto = CIERRA_TRANSACCION.fullmatch(forma), PUNTO_DE_RETORNO.fullmatch(forma)
        no_entendida = 'línea %d: %r, y la prueba no sabe cómo deja la transacción' % (
            _linea(sql, inicio), ' '.join(sql[inicio:fin].split()))
        if ABRE_TRANSACCION.match(forma):
            abierta = True
        elif cierre:
            confirma[n], puntos = cierre.group(1) in ('commit', 'end'), []
            if cierre.group(2) and not cierre.group(3) and abierta:
                n += 1
            elif cierre.group(2) and not cierre.group(3):
                no_entendidas.append(no_entendida)  # AND CHAIN fuera de un BEGIN da error
            else:
                abierta = False
        elif punto and punto.group(4).startswith('"'):
            no_entendidas.append(no_entendida + ' (un SAVEPOINT se lee solo con el nombre sin comillas)')
        elif punto and abierta:
            orden, nombre = punto.group(1) or punto.group(2) or punto.group(3), punto.group(4)
            previos = [x for x, (p, _) in enumerate(puntos) if p == nombre]
            if orden == 'savepoint':
                puntos.append((nombre, k))
            elif not previos:
                no_entendidas.append(no_entendida)
            elif orden == 'rollback':
                deshechas.update(range(puntos[previos[-1]][1] + 1, k))
                del puntos[previos[-1] + 1:]
            else:
                del puntos[previos[-1]:]
        elif punto or OTRO_CIERRE.match(forma):
            no_entendidas.append(no_entendida)
        if not abierta:
            confirma.setdefault(n, True)
    if abierta:
        confirma[n] = False
    sentencias = [Sentencia(i, j, t, confirma[t] and k not in deshechas, forma, valores)
                  for k, (i, j, t, forma, valores) in enumerate(sentencias)]
    return [s.fin for s in sentencias], sentencias, no_entendidas


def _sentencia(ruta, posicion):
    """La Sentencia de primer nivel en que cae la posición."""
    fines, sentencias, _ = _sentencias(ruta)
    k = bisect.bisect_right(fines, posicion)
    return sentencias[k] if k < len(sentencias) else Sentencia(posicion, posicion, None, False, '', ())


def _aplicada(ruta, posicion):
    """Si en la posición empieza una sentencia de primer nivel que se confirma, o sea que corre y queda. No lo es la que
    va en el cuerpo de un $tag$ (una función, un DO o una cadena), dentro de otra sentencia (un WITH, un CREATE RULE o
    una función con BEGIN ATOMIC) ni la que deshace un ROLLBACK."""
    sentencia = _sentencia(ruta, posicion)
    return sentencia.confirmada and sentencia.inicio == posicion


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


def _literal(v, valores):
    """Un valor de la forma pareja ('n', null o now ( )) como va en el SQL: '...', NULL o now()."""
    if v.startswith("'"):
        return "'%s'" % valores[int(v[1:-1])].replace("'", "''")
    return 'NULL' if v == 'null' else 'now()'


def _incumple_011(fila):
    """Las restricciones de la 011 que no cumple una fila del mapeo, {columna: valor o None}. Un CHECK con NULL pasa."""
    malas = ['%s NOT NULL' % c for c in COLUMNAS_MAPEO if c not in NULOS_MAPEO and fila[c] is None]
    malas += ["btrim(%s) <> ''" % c for c in NO_VACIAS_MAPEO if fila[c] is not None and not fila[c].strip(' ')]
    malas += ["%s ~ '^%s$'" % (c, r.pattern) for c, r in FORMATOS_MAPEO.items()
              if fila[c] is not None and not r.fullmatch(fila[c])]
    malas += ["%s LIKE 'https://%%'" % c for c in FUENTES_MAPEO
              if fila[c] is not None and not fila[c].startswith('https://')]
    tecnica, nombre, motivo = (fila[c] for c in NULOS_MAPEO)
    if not (tecnica is not None and nombre is not None and nombre.strip(' ') and motivo is None or
            tecnica is None and nombre is None and motivo is not None and motivo.strip(' ')):
        malas.append('técnica de ATT&CK con id y nombre, o sin ellos y con su motivo')
    return malas


def leer_mapeos():
    """Los (archivo, orden, posición, transacción, code, {columna: valor}) de los INSERT INTO
    scoring_rule_framework_mappings de todo db/ (la 011 y las migraciones que vengan, porque la 011 ya no se edita),
    los (archivo, orden, posición, code, {columna: valor como va en el SQL}) de sus UPDATE, con orden el del archivo en
    ARCHIVOS_SQL y posición el inicio de la sentencia, y lo que no se pudo leer. Solo se leen el INSERT y el UPDATE que
    son sentencias de primer nivel que se confirman (_sentencias). También van en lo que no se pudo leer un INSERT o un
    UPDATE del mapeo en otro lado, un DELETE, TRUNCATE, MERGE o COPY del mapeo y, en cualquier archivo, lo que _sql y
    _sentencias no leen o lo que cambia cómo se leen las cadenas (AJUSTE_DE_LECTURA)."""
    mapeos, cambios, mal_leidos = [], [], []
    for orden, ruta in enumerate(ARCHIVOS_SQL):
        archivo, (sql, tokens, problemas) = _relativa(ruta), _sql(ruta)
        _, sentencias, no_entendidas = _sentencias(ruta)
        mal_leidos += ['%s: %s' % (archivo, p) for p in problemas + tuple(no_entendidas)]
        formas = [(s.inicio, s, s.forma, s.valores) for s in sentencias]
        formas += [(t.inicio, None) + _forma(cuerpo) for t, cuerpo in _cuerpos(tokens)]
        for posicion, s, forma, valores in formas:
            donde = '%s: línea %d:' % (archivo, _linea(sql, posicion))
            utf8 = CLIENT_ENCODING_UTF8.fullmatch(forma)
            if not (utf8 and valores[int(utf8.group(1))] == 'UTF8') and (
                    AJUSTE_DE_LECTURA.search(forma) or
                    {v.strip().lower() for v in valores} & {'standard_conforming_strings', 'client_encoding'}):
                mal_leidos.append("%s cambia standard_conforming_strings o client_encoding (SET, set_config, SET "
                                  "NAMES, RESET ALL o DISCARD ALL), y la prueba solo lee SET client_encoding = 'UTF8'"
                                  % donde)
            if BORRADO_MAPEO.search(forma):
                mal_leidos.append('%s DELETE, TRUNCATE, MERGE o COPY de scoring_rule_framework_mappings, que la prueba '
                                  'no lee' % donde)
            escrituras = list(ESCRIBE_MAPEO.finditer(forma))
            for m in escrituras:
                if s is None:
                    motivo = 'va en el cuerpo de un $tag$ (una función, un DO o una cadena)'
                elif m.start():
                    motivo = ('va dentro de otra sentencia (un WITH, un EXPLAIN, un CREATE RULE o una función con '
                              'BEGIN ATOMIC)')
                elif not s.confirmada:
                    motivo = ('va en lo que deshace un ROLLBACK, un ROLLBACK TO o el final del archivo con el BEGIN '
                              'abierto')
                else:
                    continue
                mal_leidos.append('%s %s de scoring_rule_framework_mappings que %s, y la prueba no sabe si corre'
                                  % (donde, m.group(1).upper(), motivo))
            if s is None or not escrituras or escrituras[0].start() or not s.confirmada:
                continue
            if escrituras[0].group(1) == 'insert into':
                m = INSERT_MAPEO.fullmatch(forma)
                if not m:
                    mal_leidos.append('%s INSERT INTO scoring_rule_framework_mappings que la prueba no pudo leer (con '
                                      'otro esquema, un alias o sin la lista de columnas)' % donde)
                    continue
                columnas = tuple(c.strip('"') for c in m.group(1).split(' , '))
                if columnas != COLUMNAS_MAPEO:
                    mal_leidos.append('%s INSERT del mapeo con las columnas %s' % (donde, ', '.join(columnas)))
                elif not FORMA_INSERT.fullmatch(m.group(2)):
                    mal_leidos.append("%s INSERT del mapeo que no es VALUES con filas de cadenas '...' o NULL y, si "
                                      'acaso, ON CONFLICT (rule_code) DO NOTHING (un upsert con DO UPDATE, un INSERT '
                                      '... SELECT o un valor con $tag$ u otra expresión no se leen)' % donde)
                else:
                    for f in FILA_LEIDA.finditer(m.group(2)):
                        fila = [valores[int(f.group(1))]] + [None if v == 'null' else valores[int(v[1:-1])]
                                                             for v in f.groups()[1:]]
                        mapeos.append((archivo, orden, s.inicio, s.transaccion, fila[0],
                                       dict(zip(COLUMNAS_MAPEO, fila))))
                continue
            m = UPDATE_MAPEO.fullmatch(forma)
            asignaciones = [ASIGNACION.fullmatch(a) for a in m.group(1).split(' , ')] if m else [None]
            if not all(asignaciones):
                mal_leidos.append("%s UPDATE del mapeo que no es SET columna = '...', NULL o now() con WHERE rule_code "
                                  "= '...', y la prueba no lo pudo leer" % donde)
                continue
            pares = [(a.group(1) or a.group(2), _literal(a.group(3), valores)) for a in asignaciones]
            if len(dict(pares)) != len(pares):
                mal_leidos.append('%s UPDATE del mapeo que pone dos veces la misma columna' % donde)
                continue
            cambios.append((archivo, orden, s.inicio, valores[int(m.group(2))], dict(pares)))
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
        # sentencia o en lo que deshace un ROLLBACK hace fallar la prueba, porque no se sabe si corre. El SQL se lee
        # como psql y Postgres (_Lexico), y lo que la prueba no imita (meta-comandos y variables de psql, U&'...', un \r
        # suelto, SAVEPOINT con comillas o standard_conforming_strings) la hace fallar con su motivo.
        self.assertEqual(MAPEOS_MAL_LEIDOS, [], 'lo que la prueba no pudo leer en db/: INSERT, UPDATE, DELETE o '
                                                'TRUNCATE de scoring_rule_framework_mappings, meta-comandos o '
                                                'variables de psql, transacciones o cadenas sin cerrar')
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
        # Los CHECK y los NOT NULL de la 011 se revisan en cada INSERT y en cada UPDATE, como en la base, y las
        # versiones como quedan después de los UPDATE, en el orden en que corren.
        for archivo, _, _, _, code, valores in MAPEOS:
            self.assertEqual(_incumple_011(valores), [], '%s: el mapeo de %r no cumple estas restricciones de la 011'
                             % (archivo, code))
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
            self.assertEqual(_incumple_011(finales[code]), [], '%s: después del UPDATE el mapeo de %r no cumple estas '
                             'restricciones de la 011' % (archivo, code))
        for code, valores in sorted(finales.items()):
            for columna, version in VERSIONES_MAPEO.items():
                self.assertEqual(valores[columna], version, 'el mapeo de %r queda con %s = %r'
                                 % (code, columna, valores[columna]))

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
        # fila conservaría la firma del texto anterior. Se lee sin comentarios, como corre
        revisor, sin_firma = {}, []
        for ruta in ARCHIVOS_SQL:
            for asignaciones, code in UPDATE_TEXTO.findall(_sql(ruta)[0]):
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
            sql, nombre = _sql(ruta)[0], _relativa(ruta)  # sin comentarios, como corre
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
