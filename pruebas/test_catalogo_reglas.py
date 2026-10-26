"""Pruebas del catálogo de reglas del score (#30, RC-66), sin base de datos ni red.

Leen con regex las reglas y los textos de todas las migraciones y semillas de db/, la tabla de docs/codigos_reglas.md
y docs/api_v1/pesos.json y explicacion.json, y revisan que digan lo mismo entre sí y con los CODIGOS de cada
recolector. Fallan si un recolector declara en CODIGOS un código sin regla o con otra severidad, si una regla no tiene
texto o si un texto no cumple las reglas de redacción. Lo que un recolector emite de verdad solo se revisa en ejemplo.

    python -m unittest -v pruebas/test_catalogo_reglas.py
"""
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


def _filas(bloque, fila):
    """Las filas de todos los INSERT de una tabla en todos los archivos de db/, más los INSERT con filas sin leer."""
    filas, mal_leidos = [], []
    for ruta in ARCHIVOS_SQL:
        sql = ruta.read_text(encoding='utf-8')
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
        sql = ruta.read_text(encoding='utf-8')
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


def leer_doc():
    return (RAIZ / 'docs' / 'codigos_reglas.md').read_text(encoding='utf-8')


def leer_json(nombre):
    return json.loads((RAIZ / 'docs' / 'api_v1' / nombre).read_text(encoding='utf-8'), parse_float=Decimal)


REGLAS, REGLAS_MAL_LEIDAS = leer_reglas()
REGLAS_V1 = sorted((r for r in REGLAS if r[2] == JUEGO_V1), key=lambda r: r[1])
POR_CODIGO = {r[3]: r for r in REGLAS_V1}
TEXTOS, TEXTOS_POR_CODIGO, TEXTOS_MAL_LEIDOS = leer_textos()
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

    def test_10_los_textos_osint_los_firma_ernesto_y_el_resto_no(self):
        # backlog.md fila 30: los textos de las reglas OSINT (#14 a #20) los revisa Ernesto y el resto alguien de otra área.
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
        osint, resto = [], []
        for fila in FILAS_DOC:
            numero = re.match(r'#(\d+)', fila[5])
            self.assertIsNotNone(numero, '%r: su recolector en docs/codigos_reglas.md no empieza con #' % fila[1])
            (osint if 14 <= int(numero.group(1)) <= 20 else resto).append(fila[1])
        self.assertEqual(len(osint), 25, 'docs/codigos_reglas.md ya no tiene 25 reglas de #14 a #20')
        self.assertEqual([c for c in sorted(osint) if revisor.get(c) != 'ErnestoDL'], [],
                         'reglas OSINT cuyo texto final no firmó ErnestoDL en las migraciones de db/')
        self.assertEqual([c for c in sorted(resto) if revisor.get(c) == 'ErnestoDL'], [],
                         'reglas fuera de OSINT firmadas por ErnestoDL: las revisa alguien de otra área')

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


if __name__ == '__main__':
    unittest.main()
