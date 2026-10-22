"""Pruebas del lote semisintético del ML (#33, RC-65), sin base de datos ni red.

Revisan que el maestro tenga la forma de #21, que las copias no delaten la severidad, el bloque común, el reparto y la
partición, que la misma semilla dé los mismos bytes y que acuerdo.py calcule bien el kappa.

    python -m unittest -v pruebas/test_dataset_ml.py
"""
import ast
import csv
import ipaddress
import json
import re
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))  # también corre como python pruebas/test_dataset_ml.py
from cirdan.ml import acuerdo, caracteristicas, generar_lote, plantillas  # noqa: E402
from cirdan.recolectores import contrato, crtsh  # noqa: E402

MAESTRO, COPIAS = generar_lote.generar()
POR_ID = {h['id']: h for h in MAESTRO}
EJEMPLO = json.loads((RAIZ / 'docs' / 'api_v1' / 'hallazgos.json').read_text(encoding='utf-8'))['items'][0]
EXTRAS = ('plantilla', 'particion', 'clase_esperada', 'bloque', 'asignado_a')
FUENTES = ('ct_logs', 'dns', 'whois', 'shodan', 'hibp', 'censys')       # data_sources.code de la semilla 001
ETIQUETADORES = generar_lote.ETIQUETADORES
# Palabras que delatan la clase o la severidad en lo que ve el etiquetador
DELATAN = re.compile(r'\b(cr[ií]tic[oa]s?|alt[ao]s?|medi[ao]s?|baj[ao]s?|severidad|critical|high|medium|low)\b', re.I)
CEROS = {'cve_id': None, 'cvss': None, 'epss': None, 'in_kev': False}
TEMPORAL = None


def setUpModule():
    global TEMPORAL
    TEMPORAL = tempfile.TemporaryDirectory()
    generar_lote.escribir(Path(TEMPORAL.name) / 'lote', MAESTRO, COPIAS)


def tearDownModule():
    TEMPORAL.cleanup()


def lote():
    return Path(TEMPORAL.name) / 'lote'


def leer_copia(carpeta, etiquetador):
    with open(carpeta / 'copias' / ('%s.csv' % etiquetador), encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def archivos(carpeta):
    return sorted(p.relative_to(carpeta).as_posix() for p in carpeta.rglob('*') if p.is_file())


class Maestro(unittest.TestCase):

    def test_1_forma_del_contrato_21(self):
        for h in MAESTRO:
            self.assertEqual(list(h)[:len(EJEMPLO)], list(EJEMPLO), h['id'])
            self.assertEqual(tuple(h)[len(EJEMPLO):], EXTRAS, h['id'])

    def test_2_caracteristicas_del_contrato_de_plugin(self):
        # las mismas revisiones de pruebas/test_contrato_api.py:103-111
        for h in MAESTRO:
            c = h['caracteristicas']
            self.assertEqual(tuple(c), contrato.CARACTERISTICAS, h['id'])
            self.assertRegex(c['tipo'], contrato.CODIGO_VALIDO)
            self.assertIsInstance(c['antiguedad_dias'], int)
            self.assertGreaterEqual(c['antiguedad_dias'], 0)
            self.assertIn(c['exposicion'], contrato.EXPOSICIONES)
            self.assertIn(c['sensibilidad'], contrato.SENSIBILIDADES)

    def test_3_severidad_y_categoria_del_mapa(self):
        for h in MAESTRO:
            categoria, base = plantillas.REGLAS[h['rule_code']]
            self.assertEqual((h['category'], h['base_severity'], h['severity']), (categoria, base, base), h['id'])
            self.assertIn(h['asset_type'], contrato.TIPOS_ACTIVO)
            self.assertIn(h['source'], FUENTES)
            self.assertEqual(h['status'], 'open')
            self.assertIn(h['recurrence'], ('new', 'recurring'))
            if h['cve_id'] is None:
                self.assertEqual({k: h[k] for k in CEROS}, CEROS, h['id'])

    def test_4_el_mapa_sale_de_la_semilla_y_de_crtsh(self):
        semilla = (RAIZ / 'db' / 'semillas' / '001_datos_demo.sql').read_text(encoding='utf-8')
        reglas = dict((c, (cat, sev)) for c, cat, sev in re.findall(
            r"'([a-z_]+)',\s*'(infrastructure|digital_identity|configuration|data_leaks)',\s*'(critical|high|medium|low)'",
            semilla))
        self.assertEqual(len(reglas), 7)
        self.assertEqual(plantillas.REGLAS, dict(reglas, cert_expiring_soon=('infrastructure',
                                                                             crtsh.CODIGOS['cert_expiring_soon'])))
        for codigo, severidad in crtsh.CODIGOS.items():
            self.assertEqual(plantillas.REGLAS[codigo][1], severidad, codigo)

    def test_5_caracteristicas_salen_de_la_rubrica(self):
        for h in MAESTRO:
            self.assertEqual(h['caracteristicas'], caracteristicas.calcular(
                h['rule_code'], h['asset_type'], h['evidence'], plantillas.REFERENCIA), h['id'])

    def test_6_evidencia_sin_secretos(self):
        texto = json.dumps(MAESTRO).lower()
        for prohibido in ('password":', 'token":', 'hash":', 'secret'):
            self.assertNotIn(prohibido, texto)

    def test_7_datos_ficticios(self):
        texto = json.dumps(MAESTRO, ensure_ascii=False)
        nombres = re.findall(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', texto)
        self.assertTrue(nombres)
        for nombre in nombres:
            if not re.fullmatch(r'v=spf1|p=reject|[a-z-]+\.js', nombre):
                self.assertTrue(nombre.endswith('.example'), nombre)   # RFC 2606
        redes = [ipaddress.ip_network(r) for r in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]
        for h in MAESTRO:
            if 'ip' in h['evidence']:
                self.assertTrue(any(ipaddress.ip_address(h['evidence']['ip']) in r for r in redes))  # RFC 5737
            if h['cve_id']:
                self.assertRegex(h['cve_id'], r'^CVE-2099-\d{4,5}$')
            if 'breach_name' in h['evidence']:
                self.assertTrue(h['evidence']['breach_name'].startswith('DemoBreach'))


class Balance(unittest.TestCase):

    def test_1_tamano_y_clases_esperadas(self):
        self.assertEqual(len(MAESTRO), 425)
        por_clase = Counter(h['clase_esperada'] for h in MAESTRO)
        for clase in plantillas.CLASES:
            self.assertGreaterEqual(por_clase[clase], 60, clase)
            self.assertAlmostEqual(por_clase[clase], 140, delta=5)
        self.assertEqual(sum(h['rule_code'] == 'spf_missing' for h in MAESTRO), 72)
        self.assertEqual(Counter(p.codigo for p in plantillas.PLANTILLAS), {c: 3 for c in plantillas.REGLAS})

    def test_2_bloque_comun(self):
        comun = [h for h in MAESTRO if h['bloque'] == 'comun']
        self.assertEqual(len(comun), 60)
        self.assertEqual(Counter(h['clase_esperada'] for h in comun), {c: 20 for c in plantillas.CLASES})
        por_plantilla = Counter(h['plantilla'] for h in comun)
        for p in plantillas.PLANTILLAS:
            self.assertGreaterEqual(por_plantilla[p.id], 2, p.id)

    def test_3_reparto(self):
        comun = {h['id'] for h in MAESTRO if h['bloque'] == 'comun'}
        self.assertEqual({h['id'] for h in COPIAS['etiquetador_1']}, comun)   # solo el bloque común
        partes = Counter()
        for h in MAESTRO:
            if h['bloque'] == 'comun':
                self.assertEqual(h['asignado_a'], list(ETIQUETADORES))
            else:
                self.assertEqual(len(h['asignado_a']), 1)
                self.assertNotEqual(h['asignado_a'], ['etiquetador_1'])
                partes[h['asignado_a'][0]] += 1
        self.assertEqual(sum(partes.values()), 365)
        self.assertLessEqual(max(partes.values()) - min(partes.values()), 1)
        for e in ETIQUETADORES[1:]:
            self.assertEqual(len(COPIAS[e]), 60 + partes[e])
            self.assertAlmostEqual(len(COPIAS[e]), 182, delta=1)

    def test_4_particion(self):
        en_prueba = [p for p in plantillas.PLANTILLAS if p.prueba]
        self.assertEqual(Counter(p.codigo for p in en_prueba), {c: 1 for c in plantillas.REGLAS})
        for clase in plantillas.CLASES:
            self.assertGreaterEqual(sum(p.clase_esperada == clase for p in en_prueba), 2, clase)
        for h in MAESTRO:
            self.assertEqual(h['particion'], 'prueba' if plantillas.POR_ID[h['plantilla']].prueba else 'entrenamiento')
        entrenamiento = {h['caracteristicas']['tipo'] for h in MAESTRO if h['particion'] == 'entrenamiento'}
        self.assertEqual(entrenamiento, set(caracteristicas.TIPO.values()))


class Copias(unittest.TestCase):

    def test_1_solo_las_columnas_visibles(self):
        for e in ETIQUETADORES:
            ruta = lote() / 'copias' / ('%s.csv' % e)
            self.assertTrue(ruta.read_bytes().startswith(b'\xef\xbb\xbf'), e)   # BOM para Excel
            filas = leer_copia(lote(), e)
            self.assertEqual(tuple(filas[0]), generar_lote.COLUMNAS_COPIA)
        prohibidas = {'rule_code', 'severity', 'base_severity', 'plantilla', 'clase_esperada', 'tipo', 'exposicion',
                      'sensibilidad', 'penalty', 'factors', 'summary', 'score', 'category', 'recomendacion'}
        self.assertFalse(prohibidas & set(generar_lote.COLUMNAS_COPIA))

    def test_2_ningun_valor_delata_la_severidad(self):
        ocultos = (set(plantillas.REGLAS) | set(caracteristicas.TIPO.values()) | set(plantillas.POR_ID)
                   | {'data_leaks', 'infrastructure', 'digital_identity', 'configuration'})
        patron = re.compile(r'\b(%s)\b' % '|'.join(sorted(ocultos)))
        for e in ETIQUETADORES:
            for fila in leer_copia(lote(), e):
                self.assertEqual((fila['etiqueta'], fila['nota']), ('', ''))
                for columna, valor in fila.items():
                    self.assertIsNone(DELATAN.search(valor), (e, columna, valor))
                    self.assertIsNone(patron.search(valor), (e, columna, valor))

    def test_3_bloque_comun_igual_en_todas(self):
        copias = {e: {f['id']: f for f in leer_copia(lote(), e)} for e in ETIQUETADORES}
        comun = set(copias['etiquetador_1'])
        self.assertEqual(len(comun), 60)
        for e in ETIQUETADORES[1:]:
            self.assertLessEqual(comun, set(copias[e]))
            for id_ in comun:
                self.assertEqual(copias[e][id_], copias['etiquetador_1'][id_], (e, id_))

    def test_4_orden_propio_y_no_por_severidad(self):
        comun = {h['id'] for h in COPIAS['etiquetador_1']}
        ordenes = {e: [f['id'] for f in leer_copia(lote(), e) if f['id'] in comun] for e in ETIQUETADORES}
        for a in ETIQUETADORES:
            for b in ETIQUETADORES:
                if a < b:
                    self.assertNotEqual(ordenes[a], ordenes[b], (a, b))
        for e in ETIQUETADORES:
            orden = [contrato.SEVERIDADES.index(POR_ID[f['id']]['severity']) for f in leer_copia(lote(), e)]
            self.assertNotIn(orden, (sorted(orden), sorted(orden, reverse=True)), e)

    def test_5_cada_fila_sale_del_maestro(self):
        for e in ETIQUETADORES:
            for fila in leer_copia(lote(), e):
                self.assertEqual(fila, generar_lote.fila_copia(POR_ID[fila['id']]))
                self.assertIn(e, POR_ID[fila['id']]['asignado_a'])

    def test_6_ids_unicos_y_opacos(self):
        ids = [h['id'] for h in MAESTRO]
        self.assertEqual(len(ids), len(set(ids)))
        for id_ in ids:
            self.assertRegex(id_, r'^h[%s]{7}$' % generar_lote.ALFABETO_ID)
        # ordenados por id, las plantillas quedan revueltas: casi cada fila cambia de plantilla
        cambios = sum(a['plantilla'] != b['plantilla'] for a, b in zip(MAESTRO, MAESTRO[1:]))
        self.assertGreater(cambios, 350)


class Semilla(unittest.TestCase):

    def test_1_misma_semilla_mismos_bytes(self):
        with tempfile.TemporaryDirectory() as otra:
            otra = Path(otra)
            generar_lote.escribir(otra, *generar_lote.generar(generar_lote.SEMILLA))
            self.assertEqual(archivos(otra), archivos(lote()))
            for nombre in archivos(otra):
                self.assertEqual((otra / nombre).read_bytes(), (lote() / nombre).read_bytes(), nombre)

    def test_2_el_lote_del_repo_es_el_de_la_semilla(self):
        repo = generar_lote.CARPETA
        for nombre in archivos(lote()):
            self.assertEqual((repo / nombre).read_bytes(), (lote() / nombre).read_bytes(), nombre)

    def test_3_otra_semilla_da_otro_lote(self):
        otro, _ = generar_lote.generar(generar_lote.SEMILLA + 1)
        self.assertNotEqual([h['id'] for h in otro], [h['id'] for h in MAESTRO])


class Caracteristicas(unittest.TestCase):

    def test_1_tipos_con_los_nombres_de_la_api(self):
        arbol = ast.parse((RAIZ / 'cirdan' / 'api' / 'v1.py').read_text(encoding='utf-8'))
        tipo = next(ast.literal_eval(n.value) for n in arbol.body
                    if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', '') == 'TIPO')
        self.assertEqual(caracteristicas.TIPO, tipo)

    def test_2_rubrica_de_sensibilidad(self):
        s, ref = caracteristicas.sensibilidad, plantillas.REFERENCIA
        casos = [
            ('breach_exposure', {'data_classes': ['Email addresses', 'Passwords']}, 'alta'),     # credenciales
            ('breach_exposure', {'data_classes': ['Email addresses', 'Phone numbers']}, 'alta'),  # datos personales
            ('breach_exposure', {'data_classes': ['Email addresses', 'Names']}, 'media'),         # el correo
            ('exposed_rdp', {'ultima_vez': '2026-10-19'}, 'alta'),                                # acceso remoto
            ('exposed_rdp', {'ultima_vez': '2026-03-01'}, 'media'),                               # sin ver 6 meses
            ('outdated_software', {'uso': 'inicio_de_sesion'}, 'alta'),
            ('outdated_software', {'uso': 'servidor'}, 'media'),
            ('cert_expired', {'uso': 'correo'}, 'media'),
            ('cert_expiring_soon', {'uso': 'sitio_publico'}, 'baja'),
            ('cert_expired', {'uso': 'sin_contenido'}, 'baja'),
            ('dmarc_missing', {'mx': ['mx1.a.example']}, 'media'),
            ('dmarc_missing', {'mx': []}, 'baja'),
            ('spf_missing', {'mx': ['mx1.a.example'], 'dmarc': 'p=reject'}, 'baja'),
            ('spf_missing', {'mx': ['mx1.a.example'], 'dmarc': None}, 'media'),
            ('lookalike_domain', {'dominio_parecido': 'a-pagos.com.example', 'nombres': []}, 'alta'),
            ('lookalike_domain', {'dominio_parecido': 'a.net.example', 'nombres': ['www.a.net.example']}, 'baja'),
        ]
        for codigo, evidencia, esperada in casos:
            self.assertEqual(s(codigo, evidencia, ref), esperada, (codigo, evidencia))

    def test_3_exposicion_como_la_api(self):
        e = caracteristicas.exposicion
        self.assertEqual([e('exposed_rdp', 'service'), e('outdated_software', 'subdomain'), e('cert_expired', 'ip'),
                          e('cert_expired', 'subdomain'), e('spf_missing', 'domain')],
                         ['directa', 'directa', 'directa', 'publica', 'publica'])

    def test_4_antiguedad_desde_la_fecha_de_cada_codigo(self):
        a, ref = caracteristicas.antiguedad_dias, '2026-10-20T10:00:00-06:00'
        self.assertEqual(a('breach_exposure', {'breach_date': '2026-06-18'}, ref), 124)
        self.assertEqual(a('cert_expired', {'not_before': '2026-07-01', 'not_after': '2026-10-02'}, ref), 18)
        self.assertEqual(a('cert_expiring_soon', {'not_before': '2026-07-22', 'not_after': '2026-10-20'}, ref), 90)
        self.assertEqual(a('lookalike_domain', {'primer_certificado': '2026-10-10'}, ref), 10)
        self.assertEqual(a('spf_missing', {'primera_vez': '2026-10-21'}, ref), 0)   # nunca negativa
        self.assertEqual(a('dmarc_missing', {}, ref), 0)


def escribir_etiquetas(carpeta, etiquetador, valores):
    (carpeta / 'etiquetas').mkdir(exist_ok=True)
    with open(carpeta / 'etiquetas' / ('%s.csv' % etiquetador), 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f)
        w.writerow(['id', 'etiqueta', 'nota'])
        w.writerows([id_, v, ''] for id_, v in valores.items())


class Acuerdo(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.carpeta = Path(self.dir.name)
        generar_lote.escribir(self.carpeta, MAESTRO, COPIAS)
        # etiquetador_1 a etiquetador_3 ponen la clase esperada. etiquetador_4 pone media en todo.
        self.etiquetas = {e: {h['id']: h['clase_esperada'] if e != 'etiquetador_4' else 'media' for h in COPIAS[e]}
                          for e in ETIQUETADORES}

    def tearDown(self):
        self.dir.cleanup()

    def procesar(self):
        for e, valores in self.etiquetas.items():
            escribir_etiquetas(self.carpeta, e, valores)
        return acuerdo.procesar(self.carpeta)

    def test_1_fleiss_con_un_ejemplo_a_mano(self):
        # 4 filas y 3 etiquetadores: P = 2/3, Pe = 25/72, kappa = 23/47
        self.assertAlmostEqual(acuerdo.fleiss_kappa([[3, 0, 0], [2, 1, 0], [0, 2, 1], [0, 0, 3]]), 23 / 47)

    def test_2_fleiss_con_el_ejemplo_de_wikipedia(self):
        # 10 filas, 14 etiquetadores y 5 clases: kappa 0.210
        conteos = [[0, 0, 0, 0, 14], [0, 2, 6, 4, 2], [0, 0, 3, 5, 6], [0, 3, 9, 2, 0], [2, 2, 8, 1, 1],
                   [7, 7, 0, 0, 0], [3, 2, 6, 3, 0], [2, 5, 3, 2, 2], [6, 5, 2, 1, 0], [0, 2, 2, 3, 7]]
        self.assertAlmostEqual(acuerdo.fleiss_kappa(conteos), 0.210, places=3)
        self.assertIsNone(acuerdo.fleiss_kappa([[3, 0, 0], [3, 0, 0]]))   # una sola clase
        with self.assertRaises(ValueError):
            acuerdo.fleiss_kappa([[3, 0, 0], [1, 1, 0]])

    def test_3_cohen_con_un_ejemplo_a_mano(self):
        # acuerdo 3/4, esperado 5/16: kappa 7/11
        self.assertAlmostEqual(acuerdo.cohen_kappa(['alta', 'alta', 'media', 'baja'],
                                                   ['alta', 'media', 'media', 'baja']), 7 / 11)

    def test_4_etiqueta_final_por_mayoria(self):
        f = acuerdo.etiqueta_final
        self.assertEqual([f(['alta', 'alta', 'baja']), f(['alta', 'media', 'baja']), f(['baja', 'alta']), f(['baja']),
                          f([])], ['alta', 'media', 'media', 'baja', None])

    def test_5_etiquetas_falsas_en_el_lote(self):
        dataset, r, errores = self.procesar()
        self.assertEqual(errores, [])
        comun = r['bloque_comun']
        # Con los 4, cada fila del bloque tiene 3 votos de su clase y 1 de media (media: 4): P = 2/3, Pe = 3/8
        self.assertAlmostEqual(comun['los_4']['fleiss_kappa'], round(7 / 15, 4))
        # Sin etiquetador_1: P = 5/9, Pe = 11/27
        self.assertAlmostEqual(comun['sin_etiquetador_1']['fleiss_kappa'], 0.25)
        self.assertAlmostEqual(comun['los_4']['acuerdo_simple'], round(1 / 3, 4))
        pares = comun['cohen_por_pares']
        self.assertEqual(pares['etiquetador_2 con etiquetador_3']['cohen_kappa'], 1.0)
        self.assertEqual(pares['etiquetador_2 con etiquetador_4']['cohen_kappa'], 0.0)
        self.assertEqual(comun['sin_mayoria_queda_media'], 0)
        self.assertEqual(len(dataset), 425)
        for fila in dataset:
            h = POR_ID[fila['id']]
            self.assertEqual(fila['clase_reglas'], plantillas.CLASE_DE_SEVERIDAD[h['severity']])
            if h['bloque'] == 'comun':   # mayoría de 2 a 4, que aquí es la clase esperada
                self.assertEqual((fila['etiqueta'], fila['n_etiquetas']), (h['clase_esperada'], 3))
            else:
                self.assertEqual(fila['n_etiquetas'], 1)
        with open(self.carpeta / 'dataset.csv', encoding='utf-8', newline='') as f:
            self.assertEqual(tuple(csv.DictReader(f).fieldnames), acuerdo.COLUMNAS_DATASET)
        self.assertEqual(json.loads((self.carpeta / 'acuerdo.json').read_text(encoding='utf-8')), r)

    def test_6_sin_mayoria_queda_media(self):
        id_ = next(h['id'] for h in COPIAS['etiquetador_1'])
        for e, valor in zip(ETIQUETADORES[1:], ('alta', 'media', 'baja')):
            self.etiquetas[e][id_] = valor
        dataset, r, _ = self.procesar()
        fila = next(f for f in dataset if f['id'] == id_)
        self.assertEqual((fila['etiqueta'], fila['n_etiquetas']), ('media', 3))
        self.assertEqual(r['bloque_comun']['sin_mayoria_queda_media'], 1)

    def test_7_valida_ids_y_valores(self):
        e2 = self.etiquetas['etiquetador_2']
        ids = list(e2)
        e2[ids[0]] = 'alto'
        del e2[ids[1]]
        self.etiquetas['etiquetador_3']['hzzzzzzz'] = 'baja'
        dataset, _, errores = self.procesar()
        self.assertIsNone(dataset)
        texto = '\n'.join(errores)
        self.assertIn("'alto'", texto)
        self.assertIn('faltan 1 ids', texto)
        self.assertIn('hzzzzzzz', texto)
        self.assertFalse((self.carpeta / 'dataset.csv').exists())

    def test_8_si_falta_un_etiquetador_sus_filas_salen(self):
        del self.etiquetas['etiquetador_3']
        dataset, r, errores = self.procesar()
        self.assertEqual((errores, r['faltan']), ([], ['etiquetador_3']))
        suyas = {h['id'] for h in MAESTRO if h['asignado_a'] == ['etiquetador_3']}
        self.assertEqual(len(dataset), 425 - len(suyas))
        self.assertFalse(suyas & {f['id'] for f in dataset})
        self.assertEqual(r['bloque_comun']['sin_etiquetador_1']['etiquetadores'], ['etiquetador_2', 'etiquetador_4'])


if __name__ == '__main__':
    unittest.main()
