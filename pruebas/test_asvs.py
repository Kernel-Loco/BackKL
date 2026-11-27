"""Pruebas sin base ni red de la revisión con OWASP ASVS 5.0 nivel 1 de #75 (RC-136, docs/asvs_nivel1.md).

Leen el reporte como texto y lo comparan con la lista oficial fijada en docs/asvs/asvs_5.0.0_nivel1.json: que estén
los 70 requisitos, cada uno una vez y con un estado válido; que el resumen cuadre con la tabla; que cada «No cumple»
traiga su riesgo y su arreglo y cada «No aplica» su porqué; que las rutas citadas existan, y que el texto público, el
que copia la página /seguridad/asvs del portal, no traiga rutas, claves de Jira ni el nombre clave.

    python -m unittest -v pruebas/test_asvs.py
"""
import hashlib
import json
import re
import unittest
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
REPORTE = RAIZ / 'docs' / 'asvs_nivel1.md'
LISTA = RAIZ / 'docs' / 'asvs' / 'asvs_5.0.0_nivel1.json'
ESTADOS = ('Cumple', 'No cumple', 'No aplica')
COLUMNAS = ['ID', 'Requisito', 'Estado', 'Evidencia', 'Riesgo y arreglo o justificación', 'Texto público']
CAPITULOS = tuple('V%d' % n for n in range(1, 18))

# Las mismas reglas que FrontKL/src/config/seguridad.test.mjs aplica a la página Seguridad.
PROHIBIDO_PUBLICO = (
    (re.compile(r'RC-\d', re.I), 'una clave de Jira'),
    (re.compile(r'#\d'), 'un número de backlog o de PR'),
    (re.compile(r'\bPR\s*\d', re.I), 'un número de PR'),
    (re.compile(r'cirdan', re.I), 'el nombre clave'),
    (re.compile(r'\b(src|cirdan|db|docs|pruebas|scripts)/|\.(py|sql|tsx?|mjs|md|ya?ml)\b'), 'una ruta del repo'),
    (re.compile(r'`'), 'código'),
)
# Una ruta citada entre comillas invertidas: con una carpeta y una extensión conocida.
RUTA = re.compile(r'`((?:\.?[\w-]+/)+[\w.-]+\.(?:py|md|sql|ya?ml|tsx?|mjs|html|json|toml))`')


def seccion(texto, titulo):
    """El cuerpo de la sección `## titulo`, hasta la siguiente de nivel 2."""
    inicio = texto.index('\n## %s\n' % titulo)
    fin = texto.find('\n## ', inicio + 1)
    return texto[inicio:fin if fin != -1 else len(texto)]


def celdas(linea):
    return [c.strip() for c in linea.strip().strip('|').split('|')]


def tabla(cuerpo):
    """Encabezado y filas de la primera tabla de `cuerpo`."""
    lineas = [ln for ln in cuerpo.splitlines() if ln.startswith('|')]
    return celdas(lineas[0]), [celdas(ln) for ln in lineas[2:]]


class ReporteAsvs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texto = REPORTE.read_text(encoding='utf-8')
        cls.lista = json.loads(LISTA.read_text(encoding='utf-8'))
        cls.encabezado, cls.filas = tabla(seccion(cls.texto, 'Requisitos'))
        cls.por_id = {f[0]: f for f in cls.filas}

    def test_1_la_lista_fijada_es_la_de_nivel_1_de_la_5_0_0(self):
        self.assertEqual(self.lista['version'], '5.0.0')
        self.assertEqual(self.lista['nivel'], 1)
        self.assertEqual(self.lista['total'], 70)
        self.assertEqual(len(self.lista['requisitos']), 70)
        self.assertRegex(self.lista['sha256_fuente'], r'^[0-9a-f]{64}$')
        self.assertIn('CC BY-SA 4.0', self.lista['licencia'])
        self.assertTrue(self.lista['fuente'].startswith('https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/'))
        ids = [r['id'] for r in self.lista['requisitos']]
        self.assertEqual(len(set(ids)), 70)
        for r in self.lista['requisitos']:
            with self.subTest(id=r['id']):
                self.assertTrue(r['id'].startswith(r['seccion'] + '.'))
                self.assertTrue(r['seccion'].startswith(r['capitulo'] + '.'))
                self.assertTrue(r['texto'].startswith('Verify that'))

    def test_2_cada_requisito_una_sola_vez_y_ninguno_de_mas(self):
        self.assertEqual(self.encabezado, COLUMNAS)
        ids = [f[0] for f in self.filas]
        repetidos = [i for i, n in Counter(ids).items() if n > 1]
        self.assertEqual(repetidos, [], 'requisitos repetidos en la tabla')
        esperados = [r['id'] for r in self.lista['requisitos']]
        self.assertEqual(sorted(set(esperados) - set(ids)), [], 'requisitos de nivel 1 que faltan')
        self.assertEqual(sorted(set(ids) - set(esperados)), [], 'filas que no son de nivel 1')
        self.assertEqual(ids, esperados, 'la tabla va en el orden de ASVS')

    def test_3_estado_valido_y_columnas_llenas(self):
        for fila in self.filas:
            with self.subTest(id=fila[0]):
                self.assertEqual(len(fila), len(COLUMNAS))
                self.assertIn(fila[2], ESTADOS)
                self.assertTrue(fila[1] and fila[5], 'requisito y texto público no van vacíos')

    def test_4_cada_estado_trae_lo_suyo(self):
        for id_, _, estado, evidencia, riesgo, publico in self.filas:
            with self.subTest(id=id_):
                if estado == 'Cumple':
                    self.assertGreater(len(evidencia), 20, 'un Cumple sin evidencia')
                    self.assertEqual(riesgo, '—')
                elif estado == 'No cumple':
                    self.assertGreater(len(evidencia), 20, 'un No cumple también dice qué se revisó')
                    self.assertRegex(riesgo, r'^Riesgo (bajo|medio|alto)', 'un No cumple sin su riesgo')
                    self.assertIn('Arreglo', riesgo, 'un No cumple sin su arreglo')
                    self.assertTrue(publico.startswith('En corrección:'), 'el portal lo muestra como En corrección')
                else:
                    self.assertEqual(evidencia, '—')
                    self.assertGreater(len(riesgo), 20, 'un No aplica sin su porqué')
                    self.assertTrue(publico.startswith('No aplica:'))

    def test_5_el_resumen_cuadra_con_la_tabla(self):
        encabezado, filas = tabla(seccion(self.texto, 'Resumen'))
        self.assertEqual(encabezado, ['Capítulo', 'Requisitos', 'Cumple', 'No cumple', 'No aplica'])
        cuenta = {c: Counter() for c in CAPITULOS}
        for fila in self.filas:
            cuenta[fila[0].split('.')[0]][fila[2]] += 1
        por_capitulo = {f[0].split()[0]: f for f in filas if not f[0].startswith('**')}
        self.assertEqual(sorted(por_capitulo), sorted(CAPITULOS))
        for capitulo in CAPITULOS:
            with self.subTest(capitulo=capitulo):
                fila = por_capitulo[capitulo]
                esperado = [sum(cuenta[capitulo].values())] + [cuenta[capitulo][e] for e in ESTADOS]
                self.assertEqual([int(x) for x in fila[1:]], esperado)
        total = [f for f in filas if f[0].startswith('**')][0]
        todos = Counter(f[2] for f in self.filas)
        self.assertEqual([int(x.strip('*')) for x in total[1:]], [70] + [todos[e] for e in ESTADOS])

    def test_6_cada_no_cumple_esta_en_pendientes(self):
        _, pendientes = tabla(seccion(self.texto, 'Pendientes'))
        en_pendientes = {f[0].split()[0] for f in pendientes}
        abiertos = {f[0] for f in self.filas if f[2] == 'No cumple'}
        self.assertEqual(en_pendientes, abiertos)

    def test_7_las_rutas_citadas_existen(self):
        # Las de FrontKL solo se revisan con una copia de FrontKL en una rama que ya trae la página: el CI de BackKL no
        # tiene ese repo, y una copia local puede estar en cualquier rama (RC-93 la encontró en una sin la página). La
        # señal no es una de las rutas citadas: es que algún archivo de src/ traiga HUELLA_PUBLICA (hoy
        # src/config/asvs.test.mjs). Así, si asvs.ts se mueve, su ruta citada falla en vez de apagar la revisión de
        # las demás. Cuando no se revisan, cada ruta sale como omitida, no en verde. Si la huella de aquí cambia antes
        # de copiarla a FrontKL, la copia local deja de dar la señal y las rutas salen omitidas hasta copiarla.
        frontkl = RAIZ.parent / 'FrontKL'
        con_pagina = (frontkl / 'src').is_dir() and any(
            HUELLA_PUBLICA in p.read_text(encoding='utf-8', errors='ignore')
            for p in (frontkl / 'src').rglob('*') if p.is_file() and p.suffix in ('.ts', '.tsx', '.mjs', '.js'))
        for ruta in sorted(set(RUTA.findall(self.texto))):
            if ruta.startswith('FrontKL/'):
                with self.subTest(ruta=ruta):
                    if not con_pagina:
                        self.skipTest('sin una copia de FrontKL con la página ASVS junto a BackKL')
                    self.assertTrue((RAIZ.parent / ruta).exists(), ruta)
                continue
            with self.subTest(ruta=ruta):
                if ruta.startswith(('asvs/', 'api_v1/', 'zap/')) or ruta == 'pruebas_zap.md':
                    self.assertTrue((RAIZ / 'docs' / ruta).exists(), ruta)
                else:
                    self.assertTrue((RAIZ / ruta).exists(), ruta)

    def test_8_el_texto_publico_no_trae_nada_interno(self):
        for fila in self.filas:
            for patron, que in PROHIBIDO_PUBLICO:
                with self.subTest(id=fila[0], prohibido=que):
                    self.assertIsNone(patron.search(fila[5]), 'el texto público trae %s' % que)

    def test_9_lo_enlazan_el_indice_de_docs_la_politica_y_zap(self):
        for doc in ('README.md', 'politica_seguridad_privacidad.md', 'pruebas_zap.md'):
            with self.subTest(doc=doc):
                self.assertIn('asvs_nivel1.md', (RAIZ / 'docs' / doc).read_text(encoding='utf-8'))

    def test_10_huella_de_la_tabla(self):
        # El requisito (sin comillas invertidas), el estado y el texto público son lo que copia FrontKL
        # (src/config/asvs.ts), con la misma huella. Si cambian aquí, se copian de nuevo allá y se actualizan las dos
        # huellas, esta y la de src/config/asvs.test.mjs.
        publico = '\n'.join('%s|%s|%s|%s' % (f[0], f[1].replace('`', ''), f[2], f[5]) for f in self.filas)
        self.assertEqual(hashlib.sha256(publico.encode('utf-8')).hexdigest(), HUELLA_PUBLICA)


HUELLA_PUBLICA = 'a433b1acf2973733e20e79f6174648b1d885ccc0921a434d6d82d5ac323f3c72'

if __name__ == '__main__':
    unittest.main(verbosity=2)
