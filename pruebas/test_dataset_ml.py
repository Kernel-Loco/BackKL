"""Pruebas del lote semisintético del ML (#33, RC-65), sin base de datos ni red.

Revisan que el maestro tenga la forma de #21, que las copias no delaten la severidad, el bloque común, el reparto y la
partición, que la misma semilla dé los mismos bytes, que acuerdo.py calcule bien el kappa y que el etiquetador LLM
nunca vote y solo cubra a quien no entregó cuando su kappa contra las personas alcanza el umbral.

    python -m unittest -v pruebas/test_dataset_ml.py
"""
import ast
import contextlib
import csv
import io
import ipaddress
import json
import re
import sys
import tempfile
import unittest
from collections import Counter, defaultdict
from datetime import datetime, timezone
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
COMUN = [h['id'] for h in MAESTRO if h['bloque'] == 'comun']     # en el orden del maestro
OTRA = {'alta': 'media', 'media': 'baja', 'baja': 'alta'}         # para cambiar una etiqueta por otra
# Las columnas de dataset.csv que ya usa #34: no cambian con el LLM
COLUMNAS_DATASET = ('id', 'plantilla', 'particion', 'tipo', 'antiguedad_dias', 'exposicion', 'sensibilidad',
                    'etiqueta', 'n_etiquetas', 'clase_reglas')
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

    def test_8_lo_que_se_repite_no_se_contradice(self):
        vistos = defaultdict(set)
        con_certificado = Counter()
        for h in MAESTRO:
            e, c = h['evidence'], h['rule_code']
            if c == 'breach_exposure':
                vistos['brecha', e['breach_name']].add((e['breach_date'], tuple(e['data_classes'])))
                vistos['mx', h['asset']].add('con_mx')   # una empresa sin MX no tiene correos en una brecha
            if c == 'outdated_software':
                vistos['version', e['producto'], e['version']].add(e['fin_de_soporte'])
            if h['cve_id']:
                vistos['cve', h['cve_id']].add((h['cvss'], h['epss'], h['in_kev']))
            if c in ('cert_expired', 'cert_expiring_soon'):
                con_certificado[h['asset']] += 1
                if e['uso'] == 'correo':
                    vistos['mx', h['asset'].split('.', 1)[1]].add('con_mx')
            if c in ('dmarc_missing', 'spf_missing') and h['asset_type'] == 'domain':
                vistos['mx', h['asset']].add('con_mx' if e['mx'] else 'sin_mx')
            if c == 'exposed_rdp':
                self.assertNotIn('responde', h['title'])   # puede que ya no se vea: el título no dice que siga abierto
        for clave, valores in vistos.items():
            self.assertEqual(len(valores), 1, (clave, valores))
        self.assertEqual(max(con_certificado.values()), 1)   # un host, un solo hallazgo de certificado

    def test_9_parecidos_que_crtsh_puede_encontrar(self):
        for h in MAESTRO:
            if h['rule_code'] != 'lookalike_domain':
                continue
            e, marca = h['evidence'], h['asset'].split('.')[0]
            self.assertNotEqual(e['dominio_parecido'], h['asset'])
            if e['tipo_parecido'] == 'contiene_marca':
                self.assertIn(marca, e['dominio_parecido'])   # lo encuentra la consulta %marca%
            else:   # está entre las variantes que consulta crt.sh, con .example al final
                self.assertIn(e['dominio_parecido'][:-len('.example')], plantillas.variantes_de_crtsh(marca))


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

    def test_5_prueba_sin_celdas_que_contradigan_al_entrenamiento(self):
        # una plantilla de prueba no comparte (tipo, exposicion, sensibilidad) con una de entrenamiento de otra clase
        # esperada: con esas características el modelo no podría distinguirlas
        celdas = defaultdict(set)
        for h in MAESTRO:
            c = h['caracteristicas']
            celdas[h['particion'], c['tipo'], c['exposicion'], c['sensibilidad']].add(h['clase_esperada'])
        for (particion, *celda), clases in celdas.items():
            if particion == 'prueba':
                self.assertLessEqual(celdas.get(('entrenamiento', *celda), clases), clases, celda)


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
            ('dmarc_missing', {'mx': ['mx1.a.example'], 'spf': None}, 'media'),
            ('dmarc_missing', {'mx': [], 'spf': None}, 'media'),            # se puede suplantar aunque no reciba
            ('dmarc_missing', {'mx': [], 'spf': 'v=spf1 -all'}, 'baja'),    # dice que no manda correo
            ('dmarc_missing', {'mx': ['mx1.a.example'], 'spf': 'v=spf1 -all'}, 'media'),
            ('spf_missing', {'mx': ['mx1.a.example'], 'dmarc': 'p=reject'}, 'baja'),
            ('spf_missing', {'mx': [], 'dmarc': 'p=reject'}, 'baja'),
            ('spf_missing', {'mx': ['mx1.a.example'], 'dmarc': None}, 'media'),
            ('spf_missing', {'mx': [], 'dmarc': None}, 'media'),
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
        self.assertEqual(a('cert_expired', {'vence': '2026-10-08'}, ref), 12)   # la clave que pone crt.sh
        # sin la fecha en la evidencia: detected_at, o asset_first_seen en outdated_software y exposed_rdp (v1.py:67-74)
        self.assertEqual(a('dmarc_missing', {}, ref, detectado='2026-10-01T09:00:00-06:00'), 19)
        self.assertEqual(a('exposed_rdp', {}, ref, detectado='2026-10-19', activo_visto='2026-09-20'), 30)
        self.assertEqual(a('exposed_rdp', {}, ref, detectado='2026-10-19'), 1)

    def test_5_con_la_evidencia_que_da_crtsh(self):
        # crt.sh pone vence y no not_after en cert_expired, y no pone not_before en cert_expiring_soon (crtsh.py:369)
        ahora = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
        certs = [cert(1, ['api.menorvento.example'], '2026-05-01T00:00:00', '2026-10-08T00:00:00'),
                 cert(2, ['www.menorvento.example'], '2026-07-26T00:00:00', '2026-11-01T00:00:00')]
        _, hallazgos = crtsh._subdominios('menorvento.example', certs, ahora)
        h = {x.codigo: x for x in hallazgos}
        self.assertEqual(set(h), {'cert_expired', 'cert_expiring_soon'})
        calc = caracteristicas.calcular
        vencido = h['cert_expired']
        self.assertNotIn('not_after', vencido.evidencia)
        self.assertEqual(calc('cert_expired', 'subdomain', vencido.evidencia, ahora)['antiguedad_dias'],
                         vencido.caracteristicas['antiguedad_dias'])   # 12, desde vence
        por_vencer = h['cert_expiring_soon']
        self.assertNotIn('not_before', por_vencer.evidencia)
        self.assertEqual(calc('cert_expiring_soon', 'subdomain', por_vencer.evidencia, ahora,
                              detectado='2026-10-15')['antiguedad_dias'], 5)   # sin not_before, desde detected_at
        con_emision = dict(por_vencer.evidencia, not_before='2026-07-26')
        self.assertEqual(calc('cert_expiring_soon', 'subdomain', con_emision, ahora)['antiguedad_dias'],
                         por_vencer.caracteristicas['antiguedad_dias'])   # 86, cuando crt.sh agregue not_before
        parecido = cert(3, ['menorvento-pagos.example', 'www.menorvento-pagos.example'], '2026-10-01T00:00:00',
                        '2026-12-30T00:00:00')
        p, = crtsh._parecidos('menorvento.example', [('contiene_marca', [parecido], lambda n: True)], set(), ahora)
        self.assertEqual(calc(p.codigo, 'domain', p.evidencia, ahora)['antiguedad_dias'],
                         p.caracteristicas['antiguedad_dias'])   # 19, desde el primer certificado
        self.assertEqual(calc(p.codigo, 'domain', p.evidencia, ahora)['sensibilidad'], 'alta')


def cert(id_, nombres, inicio, fin):
    """Un certificado como los que devuelve crt.sh (pruebas/test_crtsh.py:24)."""
    return {'id': id_, 'issuer_ca_id': 1, 'issuer_name': 'CA Ejemplo TLS', 'common_name': nombres[0],
            'name_value': '\n'.join(nombres), 'not_before': inicio, 'not_after': fin, 'serial_number': '%040x' % id_,
            'result_count': 1}


def escribir_etiquetas(carpeta, nombre, valores):
    """etiquetas/<nombre>.csv. `valores` es {id: etiqueta} o una lista de pares, que puede repetir ids."""
    (carpeta / 'etiquetas').mkdir(exist_ok=True)
    with open(carpeta / 'etiquetas' / ('%s.csv' % nombre), 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f)
        w.writerow(['id', 'etiqueta', 'nota'])
        w.writerows([id_, v, ''] for id_, v in (valores.items() if isinstance(valores, dict) else valores))


class ConLote(unittest.TestCase):
    """Un lote en una carpeta temporal con etiquetas falsas. No trae pruebas."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.carpeta = Path(self.dir.name)
        generar_lote.escribir(self.carpeta, MAESTRO, COPIAS)
        # etiquetador_1 a etiquetador_3 ponen la clase esperada. etiquetador_4 pone media en todo.
        self.etiquetas = {e: {h['id']: h['clase_esperada'] if e != 'etiquetador_4' else 'media' for h in COPIAS[e]}
                          for e in ETIQUETADORES}

    def tearDown(self):
        self.dir.cleanup()

    def procesar(self, llm=None, repeticion=None):
        for e, valores in self.etiquetas.items():
            escribir_etiquetas(self.carpeta, e, valores)
        if llm is not None:
            escribir_etiquetas(self.carpeta, acuerdo.LLM, llm)
        if repeticion is not None:
            escribir_etiquetas(self.carpeta, acuerdo.LLM_REPETICION, repeticion)
        return acuerdo.procesar(self.carpeta)


class Acuerdo(ConLote):

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

    def test_4b_f1_macro_con_un_ejemplo_a_mano(self):
        # alta 2/3, media 2/4 y baja 0: F1 macro 7/18
        self.assertAlmostEqual(acuerdo.macro_f1(['alta', 'alta', 'media', 'baja'],
                                                ['alta', 'media', 'media', 'media']), 7 / 18)
        self.assertEqual(acuerdo.macro_f1(['alta', 'baja'], ['alta', 'baja']), 1.0)
        self.assertIsNone(acuerdo.macro_f1([], []))

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
        prueba = [f for f in dataset if f['particion'] == 'prueba']
        self.assertEqual(r['linea_base_prueba']['filas'], len(prueba))
        self.assertEqual(r['linea_base_prueba']['f1_macro_sensibilidad'], round(acuerdo.macro_f1(
            [f['etiqueta'] for f in prueba], [f['sensibilidad'] for f in prueba]), 4))
        self.assertEqual(set(r['coincidencia']), {'final', 'final_entrenamiento', 'final_prueba', *ETIQUETADORES})

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

    def test_7b_sin_etiquetas_no_escribe_nada(self):
        dataset, _, errores = acuerdo.procesar(self.carpeta)
        self.assertIsNone(dataset)
        self.assertIn('no hay etiquetas', errores[0])
        self.assertFalse((self.carpeta / 'dataset.csv').exists())
        self.assertFalse((self.carpeta / 'acuerdo.json').exists())

    def test_8_si_falta_un_etiquetador_sus_filas_salen(self):
        del self.etiquetas['etiquetador_3']
        dataset, r, errores = self.procesar()
        self.assertEqual((errores, r['faltan']), ([], ['etiquetador_3']))
        suyas = {h['id'] for h in MAESTRO if h['asignado_a'] == ['etiquetador_3']}
        self.assertEqual(len(dataset), 425 - len(suyas))
        self.assertFalse(suyas & {f['id'] for f in dataset})
        self.assertEqual(r['bloque_comun']['sin_etiquetador_1']['etiquetadores'], ['etiquetador_2', 'etiquetador_4'])
        comun = [f for f in dataset if POR_ID[f['id']]['bloque'] == 'comun']
        self.assertEqual({f['n_etiquetas'] for f in comun}, {2})   # con 2 ciegos, si no coinciden queda media
        self.assertEqual({f['etiqueta'] for f in comun if POR_ID[f['id']]['clase_esperada'] != 'media'}, {'media'})

    def test_9_si_las_etiquetas_siguen_la_clase_esperada(self):
        for e in ETIQUETADORES:
            self.etiquetas[e] = {h['id']: h['clase_esperada'] for h in COPIAS[e]}
        _, r, _ = self.procesar()
        # En prueba la sensibilidad es igual a la clase esperada: copiarla da F1 1.0 y rubrica_trivial avisa
        self.assertEqual(r['linea_base_prueba']['f1_macro_sensibilidad'], 1.0)
        self.assertTrue(r['rubrica_trivial'])
        self.assertFalse(r['lote_trivial'])
        # clase_reglas en las 138 de prueba: alta 2*47/(47+73), media 2*26/(52+41) y baja 2*24/(39+24)
        self.assertEqual(r['linea_base_prueba']['f1_macro_clase_reglas'],
                         round((94 / 120 + 52 / 93 + 48 / 63) / 3, 4))


class EtiquetadorLlm(ConLote):
    """El LLM nunca vota. Solo cubre las filas del reparto de quien no entregó, y solo si su kappa contra la etiqueta
    final de las personas en el bloque común es de 0.6 o más."""

    CLAVES_ANTES = {'filas_maestro', 'filas_dataset', 'faltan', 'por_clase', 'por_particion', 'al_menos_60_por_clase',
                    'linea_base_prueba', 'bloque_comun', 'coincidencia', 'lote_trivial', 'rubrica_trivial'}

    def setUp(self):
        super().setUp()
        self.llm = {h['id']: h['clase_esperada'] for h in MAESTRO}

    def sin_un_ciego(self, quien='etiquetador_3'):
        """Quita a `quien` y los otros dos ciegos ponen la clase esperada: la final del bloque común es la clase
        esperada, 20 filas de cada clase. Devuelve los ids de su reparto."""
        del self.etiquetas[quien]
        for e in acuerdo.CIEGOS:
            if e in self.etiquetas:
                self.etiquetas[e] = {h['id']: h['clase_esperada'] for h in COPIAS[e]}
        return {h['id'] for h in MAESTRO if h['bloque'] == 'reparto' and h['asignado_a'] == [quien]}

    def errar_en_el_comun(self, n):
        """El LLM cambia su etiqueta en n filas del bloque común. Con la final en 20 filas por clase, el esperado del
        kappa es 1/3 y el kappa es (acuerdo - 1/3) / (2/3)."""
        for id_ in COMUN[:n]:
            self.llm[id_] = OTRA[self.llm[id_]]

    def test_1_no_vota(self):
        dataset_sin, sin, _ = self.procesar()
        # pone baja en todo: si votara, la final del bloque común cambiaría (alta, alta, media y baja no tienen mayoría)
        dataset, con, errores = self.procesar(llm={h['id']: 'baja' for h in MAESTRO},
                                              repeticion={id_: 'baja' for id_ in COMUN})
        self.assertEqual(errores, [])
        self.assertEqual(dataset, dataset_sin)
        self.assertEqual({k: v for k, v in con.items() if k != 'llm'}, {k: v for k, v in sin.items() if k != 'llm'})
        comun = con['bloque_comun']
        self.assertEqual(comun['los_4']['etiquetadores'], list(ETIQUETADORES))
        self.assertEqual(comun['sin_etiquetador_1']['etiquetadores'], list(acuerdo.CIEGOS))
        self.assertEqual(len(comun['cohen_por_pares']), 6)   # solo los pares de personas
        self.assertNotIn(acuerdo.LLM, con['coincidencia'])
        self.assertTrue(con['llm']['esta'])
        self.assertFalse(con['llm']['cubre_faltantes'])
        self.assertIn('No falta nadie del reparto.', con['llm']['motivo'])

    def test_2_cubre_si_el_kappa_llega_a_0_6(self):
        suyas = self.sin_un_ciego()
        self.errar_en_el_comun(16)   # acuerdo 44/60: kappa 0.6
        for id_ in suyas:   # en las filas que va a cubrir pone baja, para ver que la etiqueta sale del LLM
            self.llm[id_] = 'baja'
        dataset, r, errores = self.procesar(llm=self.llm)
        self.assertEqual(errores, [])
        x = r['llm']
        self.assertEqual(x['contra_final_personas'], {'filas': 60, 'cohen_kappa': 0.6,
                                                      'acuerdo_simple': round(44 / 60, 4),
                                                      'filas_sin_mayoria_excluidas': 0,
                                                      'personas': ['etiquetador_2', 'etiquetador_4']})
        self.assertEqual((x['alcanza_umbral'], x['cubre_faltantes']), (True, True))
        self.assertEqual(x['filas_cubiertas'], {'etiquetador_3': len(suyas)})
        self.assertIn('Cubre las filas del reparto de etiquetador_3.', x['motivo'])
        self.assertEqual(set(x['contra_cada_persona']), {'etiquetador_1', 'etiquetador_2', 'etiquetador_4'})
        self.assertEqual(r['faltan'], ['etiquetador_3'])
        # las filas del LLM llevan su etiqueta y n_etiquetas 0
        self.assertEqual(len(dataset), 425)
        llenas = [f for f in dataset if f['n_etiquetas'] == 0]
        self.assertEqual({f['id'] for f in llenas}, suyas)
        self.assertEqual({f['etiqueta'] for f in llenas}, {'baja'})
        # el bloque común sigue con la final de las personas, aun en las 16 filas en que el LLM puso otra
        for f in dataset:
            if POR_ID[f['id']]['bloque'] == 'comun':
                self.assertEqual((f['etiqueta'], f['n_etiquetas']), (POR_ID[f['id']]['clase_esperada'], 2))
        # por_clase cuenta todo y por_clase_solo_personas no cuenta las filas del LLM
        personas = Counter(f['etiqueta'] for f in dataset if f['n_etiquetas'] > 0)
        self.assertEqual(r['por_clase_solo_personas'], {c: personas[c] for c in plantillas.CLASES})
        self.assertEqual(r['por_clase']['baja'], r['por_clase_solo_personas']['baja'] + len(suyas))
        # lo demás sale del dataset completo
        prueba = [f for f in dataset if f['particion'] == 'prueba']
        self.assertEqual((r['filas_dataset'], r['linea_base_prueba']['filas']), (425, len(prueba)))
        self.assertEqual(r['al_menos_60_por_clase'], min(r['por_clase'].values()) >= acuerdo.MINIMO_POR_CLASE)
        self.assertEqual(r['coincidencia']['final']['clase_reglas'],
                         round(sum(f['etiqueta'] == f['clase_reglas'] for f in dataset) / 425, 4))
        with open(self.carpeta / 'dataset.csv', encoding='utf-8', newline='') as f:
            filas = list(csv.DictReader(f))
        self.assertEqual(tuple(filas[0]), COLUMNAS_DATASET)
        self.assertEqual(sum(fila['n_etiquetas'] == '0' for fila in filas), len(suyas))
        self.assertEqual(json.loads((self.carpeta / 'acuerdo.json').read_text(encoding='utf-8')), r)

    def test_3_no_cubre_si_el_kappa_es_menor(self):
        suyas = self.sin_un_ciego()
        self.errar_en_el_comun(17)   # acuerdo 43/60: kappa 0.575
        dataset, r, errores = self.procesar(llm=self.llm)
        self.assertEqual(errores, [])
        x = r['llm']
        self.assertEqual(x['contra_final_personas']['cohen_kappa'], 0.575)
        self.assertEqual((x['alcanza_umbral'], x['cubre_faltantes'], x['filas_cubiertas']), (False, False, {}))
        self.assertIn('0.575, menor que 0.6.', x['motivo'])
        self.assertIn('Las filas del reparto de etiquetador_3 salen del dataset.', x['motivo'])
        self.assertEqual(len(dataset), 425 - len(suyas))
        self.assertFalse(suyas & {f['id'] for f in dataset})
        self.assertNotIn(0, {f['n_etiquetas'] for f in dataset})
        self.assertEqual(r['por_clase_solo_personas'], r['por_clase'])

    def test_4_no_cubre_si_el_kappa_no_se_puede_calcular(self):
        suyas = {h['id'] for h in MAESTRO if h['asignado_a'] == ['etiquetador_3']}
        del self.etiquetas['etiquetador_3']
        self.etiquetas['etiquetador_2'] = {id_: 'media' for id_ in self.etiquetas['etiquetador_2']}
        self.llm.update({id_: 'media' for id_ in COMUN})   # todo media en el bloque: coinciden en todo, sin kappa
        dataset, r, _ = self.procesar(llm=self.llm)
        x = r['llm']
        self.assertEqual(x['contra_final_personas'], {'filas': 60, 'cohen_kappa': None, 'acuerdo_simple': 1.0,
                                                      'filas_sin_mayoria_excluidas': 0,
                                                      'personas': ['etiquetador_2', 'etiquetador_4']})
        self.assertFalse(x['cubre_faltantes'])
        self.assertTrue(x['motivo'].startswith('No se pudo calcular el kappa'))
        self.assertEqual(len(dataset), 425 - len(suyas))

    def test_5_nunca_llena_el_bloque_comun(self):
        # aunque se le pida cubrir a los 3 ciegos, solo llena filas del reparto
        filas = acuerdo.armar_dataset(MAESTRO, {}, self.llm, acuerdo.CIEGOS)
        self.assertEqual(len(filas), 365)
        self.assertEqual({POR_ID[f['id']]['bloque'] for f in filas}, {'reparto'})
        self.assertEqual({f['n_etiquetas'] for f in filas}, {0})
        # sin ningún ciego no hay etiqueta final de personas: no hay kappa y el bloque común no sale
        for e in acuerdo.CIEGOS:
            del self.etiquetas[e]
        dataset, r, errores = self.procesar(llm=self.llm)
        self.assertEqual((errores, dataset), ([], []))
        self.assertEqual(r['llm']['contra_final_personas'], {'filas': 0, 'cohen_kappa': None, 'acuerdo_simple': None,
                                                             'filas_sin_mayoria_excluidas': 0, 'personas': []})
        self.assertFalse(r['llm']['cubre_faltantes'])

    def test_6_valida_llm_y_su_repeticion(self):
        ids = [h['id'] for h in MAESTRO]
        llm = [(id_, self.llm[id_]) for id_ in ids[1:]]      # falta ids[0]
        llm[0] = (ids[1], 'alto')
        llm += [(ids[2], 'baja'), ('hzzzzzzz', 'baja')]     # uno repetido y uno que no está en el maestro
        reparto = next(h['id'] for h in MAESTRO if h['bloque'] == 'reparto')
        repeticion = [(id_, 'media') for id_ in COMUN[1:]] + [(reparto, 'media')]
        dataset, _, errores = self.procesar(llm=llm, repeticion=repeticion)
        self.assertIsNone(dataset)
        texto = '\n'.join(errores)
        self.assertIn("llm.csv, línea 2: la etiqueta de %s es 'alto'" % ids[1], texto)
        self.assertIn('llm.csv: faltan 1 ids del maestro, por ejemplo %s' % ids[0], texto)
        self.assertIn('llm.csv, línea %d: el id %s está repetido' % (len(ids) + 1, ids[2]), texto)
        self.assertIn("'hzzzzzzz' no está en el maestro", texto)
        self.assertIn('llm_repeticion.csv, línea 61: el id %r no está en el bloque común' % reparto, texto)
        self.assertIn('llm_repeticion.csv: faltan 1 ids del bloque común, por ejemplo %s' % COMUN[0], texto)
        self.assertFalse((self.carpeta / 'dataset.csv').exists())
        self.assertFalse((self.carpeta / 'acuerdo.json').exists())

    def test_7_repeticion_sin_llm_o_sin_columnas(self):
        escribir_etiquetas(self.carpeta, acuerdo.LLM_REPETICION, {id_: self.llm[id_] for id_ in COMUN})
        dataset, _, errores = self.procesar()
        self.assertIsNone(dataset)
        self.assertEqual(errores, ['llm_repeticion.csv: está la repetición del LLM pero falta llm.csv'])
        (self.carpeta / 'etiquetas' / 'llm.csv').write_text('id,clase\n', encoding='utf-8')
        _, _, errores = acuerdo.procesar(self.carpeta)
        self.assertEqual(errores, ['llm.csv: le faltan las columnas id y etiqueta'])
        self.assertFalse((self.carpeta / 'dataset.csv').exists())

    def test_8_repeticion_y_comparaciones(self):
        repeticion = {id_: self.llm[id_] for id_ in COMUN}
        for id_ in COMUN[:6]:
            repeticion[id_] = OTRA[repeticion[id_]]
        _, r, errores = self.procesar(llm=self.llm, repeticion=repeticion)
        self.assertEqual(errores, [])
        x = r['llm']
        # repite 54 de 60 y la primera pasada tiene 20 de cada clase: kappa (0.9 - 1/3) / (2/3) = 0.85
        self.assertEqual(x['repeticion'], {'filas': 60, 'cohen_kappa': 0.85, 'acuerdo_simple': 0.9})
        self.assertEqual(x['umbral_kappa'], acuerdo.UMBRAL_LLM)
        self.assertEqual(set(x['contra_cada_persona']), set(ETIQUETADORES))
        self.assertEqual(x['contra_cada_persona']['etiquetador_2']['cohen_kappa'], 1.0)
        self.assertEqual(x['contra_cada_persona']['etiquetador_4']['cohen_kappa'], 0.0)   # etiquetador_4 pone media
        self.assertEqual(x['coincidencia'], {
            'clase_reglas': round(sum(h['clase_esperada'] == plantillas.CLASE_DE_SEVERIDAD[h['severity']]
                                      for h in MAESTRO) / 425, 4),
            'sensibilidad': round(sum(h['clase_esperada'] == h['caracteristicas']['sensibilidad']
                                      for h in MAESTRO) / 425, 4)})
        (self.carpeta / 'etiquetas' / 'llm_repeticion.csv').unlink()
        _, r, _ = self.procesar(llm=self.llm)
        self.assertTrue(r['llm']['esta'])
        self.assertIsNone(r['llm']['repeticion'])

    def test_9_sin_archivos_del_llm_todo_como_antes(self):
        suyas = {h['id'] for h in MAESTRO if h['asignado_a'] == ['etiquetador_3']}
        del self.etiquetas['etiquetador_3']
        dataset, r, errores = self.procesar()
        self.assertEqual(errores, [])
        self.assertEqual(set(r), self.CLAVES_ANTES | {'por_clase_solo_personas', 'llm'})
        x = r['llm']
        self.assertEqual((x['esta'], x['cubre_faltantes'], x['filas_cubiertas'], x['repeticion']),
                         (False, False, {}, None))
        self.assertEqual(x['motivo'], 'No hay etiquetas del LLM.')
        self.assertEqual(r['por_clase_solo_personas'], r['por_clase'])
        self.assertEqual(len(dataset), 425 - len(suyas))
        self.assertNotIn(0, {f['n_etiquetas'] for f in dataset})
        self.assertEqual(dataset, acuerdo.armar_dataset(MAESTRO, {e: v for e, v in self.etiquetas.items()}))
        salida = io.StringIO()
        with contextlib.redirect_stdout(salida):
            self.assertEqual(acuerdo._main(['--carpeta', str(self.carpeta)]), 0)
        self.assertIn('Etiquetador LLM: no hay etiquetas del LLM.', salida.getvalue())
        self.assertIn('Las filas del reparto de etiquetador_3 no están en el dataset.', salida.getvalue())

    def test_10_solo_el_llm_no_escribe_nada(self):
        escribir_etiquetas(self.carpeta, acuerdo.LLM, self.llm)
        dataset, _, errores = acuerdo.procesar(self.carpeta)
        self.assertIsNone(dataset)
        self.assertIn('no hay etiquetas de personas', errores[0])
        self.assertFalse((self.carpeta / 'dataset.csv').exists())

    def test_11_main_imprime_el_llm(self):
        suyas = self.sin_un_ciego()
        self.procesar(llm=self.llm)
        salida = io.StringIO()
        with contextlib.redirect_stdout(salida):
            self.assertEqual(acuerdo._main(['--carpeta', str(self.carpeta)]), 0)
        texto = salida.getvalue()
        self.assertIn('Etiquetador LLM (no vota): kappa de Cohen 1.0 contra la etiqueta final de las personas', texto)
        self.assertIn('Filas que cubre: etiquetador_3 %d.' % len(suyas), texto)
        self.assertIn('El LLM cubre las filas del reparto de etiquetador_3.', texto)

    def test_12_columnas_de_dataset_sin_cambio(self):
        self.assertEqual(acuerdo.COLUMNAS_DATASET, COLUMNAS_DATASET)

    def salida_de_main(self):
        salida = io.StringIO()
        with contextlib.redirect_stdout(salida):
            self.assertEqual(acuerdo._main(['--carpeta', str(self.carpeta)]), 0)
        return salida.getvalue()

    def test_13_con_2_personas_las_filas_sin_mayoria_no_cuentan_y_no_las_desempata(self):
        # Con 2 ciegos, donde no coinciden la final queda media por regla. Esas filas no cuentan en el kappa del LLM:
        # da lo mismo si ahí pone media o la etiqueta de una de las dos personas. Y el LLM no las desempata.
        self.sin_un_ciego()
        difieren = [id_ for id_ in COMUN if POR_ID[id_]['clase_esperada'] != 'media'][::2]   # 20, de alta o baja
        for id_ in difieren:
            self.etiquetas['etiquetador_4'][id_] = OTRA[self.etiquetas['etiquetador_4'][id_]]
        cuentan = [id_ for id_ in COMUN if id_ not in difieren]
        for id_ in cuentan[:8]:   # se equivoca en 8 de las 40 filas con mayoría
            self.llm[id_] = OTRA[self.llm[id_]]
        suave, duro = dict(self.llm), dict(self.llm)
        for id_ in difieren:
            suave[id_] = 'media'                                # media donde las personas no coinciden
            duro[id_] = self.etiquetas['etiquetador_2'][id_]    # la etiqueta de una de las dos
        dataset_sin, sin, _ = self.procesar()
        dataset_suave, con_suave, _ = self.procesar(llm=suave)
        dataset, r, errores = self.procesar(llm=duro)
        self.assertEqual(errores, [])
        x = r['llm']['contra_final_personas']
        self.assertEqual(x, con_suave['llm']['contra_final_personas'])
        self.assertEqual((x['filas'], x['filas_sin_mayoria_excluidas'], x['personas']),
                         (40, 20, ['etiquetador_2', 'etiquetador_4']))
        self.assertEqual(x['cohen_kappa'], round(acuerdo.cohen_kappa(
            [duro[i] for i in cuentan], [POR_ID[i]['clase_esperada'] for i in cuentan]), 4))
        self.assertGreaterEqual(x['cohen_kappa'], acuerdo.UMBRAL_LLM)
        self.assertEqual(con_suave['llm']['filas_cubiertas'], r['llm']['filas_cubiertas'])
        self.assertEqual(dataset_suave, dataset)
        # El LLM no desempata: esas 20 filas quedan en media con 2 etiquetas, como sin el LLM
        self.assertEqual(r['bloque_comun'], sin['bloque_comun'])
        self.assertEqual(r['bloque_comun']['sin_mayoria_queda_media'], 20)
        comun = [f for f in dataset if POR_ID[f['id']]['bloque'] == 'comun']
        self.assertEqual(comun, [f for f in dataset_sin if POR_ID[f['id']]['bloque'] == 'comun'])
        self.assertEqual({(f['etiqueta'], f['n_etiquetas']) for f in comun if f['id'] in difieren}, {('media', 2)})

    def test_14_sin_etiquetador_1_no_cubre_a_nadie(self):
        # El caso del domingo: etiquetador_1 no entrega. Sale en faltan y nada más cambia
        del self.etiquetas['etiquetador_1']
        dataset_sin, sin, _ = self.procesar()
        dataset, r, errores = self.procesar(llm=self.llm)
        self.assertEqual((errores, r['faltan']), ([], ['etiquetador_1']))
        x = r['llm']
        self.assertTrue(x['alcanza_umbral'])
        self.assertEqual((x['cubre_faltantes'], x['filas_cubiertas']), (False, {}))
        self.assertIn('No falta nadie del reparto.', x['motivo'])
        self.assertEqual(x['contra_final_personas']['personas'], list(acuerdo.CIEGOS))
        self.assertEqual(set(x['contra_cada_persona']), set(acuerdo.CIEGOS))
        self.assertEqual(dataset, dataset_sin)
        self.assertNotIn(0, {f['n_etiquetas'] for f in dataset})
        self.assertEqual({k: v for k, v in r.items() if k != 'llm'}, {k: v for k, v in sin.items() if k != 'llm'})
        comun = r['bloque_comun']
        self.assertEqual(comun['los_4'], comun['sin_etiquetador_1'])   # los_4 queda con los mismos 3
        self.assertEqual(len(comun['cohen_por_pares']), 3)
        texto = self.salida_de_main()
        self.assertIn('Bloque común: kappa de Fleiss 0.25 entre etiquetador_2, etiquetador_3, etiquetador_4. '
                      'etiquetador_1 no entregó', texto)
        self.assertNotIn('con los 4 y', texto)
        self.assertIn('aviso: faltan las etiquetas de etiquetador_1.\n', texto)
        self.assertNotIn('El LLM cubre', texto)
        self.assertNotIn('no están en el dataset', texto)

    def test_15_sin_etiquetador_1_ni_etiquetador_3_solo_cubre_a_etiquetador_3(self):
        del self.etiquetas['etiquetador_1']
        suyas = self.sin_un_ciego('etiquetador_3')
        dataset, r, errores = self.procesar(llm=self.llm)
        self.assertEqual((errores, r['faltan']), ([], ['etiquetador_1', 'etiquetador_3']))
        x = r['llm']
        self.assertEqual(x['filas_cubiertas'], {'etiquetador_3': len(suyas)})
        self.assertTrue(x['motivo'].endswith(' Cubre las filas del reparto de etiquetador_3.'), x['motivo'])
        self.assertEqual(len(dataset), 425)
        self.assertEqual({f['id'] for f in dataset if f['n_etiquetas'] == 0}, suyas)
        texto = self.salida_de_main()
        self.assertIn('aviso: faltan las etiquetas de etiquetador_1, etiquetador_3. El LLM cubre las filas del '
                      'reparto de etiquetador_3.\n', texto)
        self.assertNotIn('no están en el dataset', texto)
        self.assertNotIn('una sola persona', texto)

    def test_16_con_una_sola_persona_cubre_y_lo_avisa(self):
        # Si solo entrega un ciego, la referencia es esa persona. Con kappa de 0.6 o más cubre a los otros dos y lo dice
        del self.etiquetas['etiquetador_1']
        del self.etiquetas['etiquetador_4']
        suyas = self.sin_un_ciego('etiquetador_3')
        de_4 = {h['id'] for h in MAESTRO if h['bloque'] == 'reparto' and h['asignado_a'] == ['etiquetador_4']}
        dataset, r, errores = self.procesar(llm=self.llm)
        self.assertEqual(errores, [])
        x = r['llm']
        self.assertEqual(x['contra_final_personas'], {'filas': 60, 'cohen_kappa': 1.0, 'acuerdo_simple': 1.0,
                                                      'filas_sin_mayoria_excluidas': 0, 'personas': ['etiquetador_2']})
        self.assertIn('La referencia es una sola persona, etiquetador_2.', x['motivo'])
        self.assertEqual(x['filas_cubiertas'], {'etiquetador_3': len(suyas), 'etiquetador_4': len(de_4)})
        self.assertEqual(len(dataset), 425)
        self.assertEqual(Counter(f['n_etiquetas'] for f in dataset), {0: len(suyas) + len(de_4), 1: 182})
        self.assertEqual(r['bloque_comun']['cohen_por_pares'], {})
        self.assertIsNone(r['bloque_comun']['los_4']['fleiss_kappa'])
        self.assertIn('aviso: el LLM cubre con un kappa medido contra una sola persona.', self.salida_de_main())

    def test_17_al_menos_60_por_clase_cuenta_las_filas_del_llm(self):
        suyas = self.sin_un_ciego()
        for e in ('etiquetador_2', 'etiquetador_4'):   # fuera del bloque común las personas no ponen baja
            for id_, valor in self.etiquetas[e].items():
                if POR_ID[id_]['bloque'] == 'reparto' and valor == 'baja':
                    self.etiquetas[e][id_] = 'media'
        for id_ in suyas:
            self.llm[id_] = 'baja'
        _, r, errores = self.procesar(llm=self.llm)
        self.assertEqual(errores, [])
        self.assertEqual(r['por_clase_solo_personas']['baja'], 20)   # solo las del bloque común
        self.assertEqual(r['por_clase']['baja'], 20 + len(suyas))
        self.assertTrue(r['al_menos_60_por_clase'])

    def test_18_lote_y_rubrica_trivial_cuentan_las_filas_del_llm(self):
        # Las personas coinciden con la referencia en 267 de sus 303 filas (0.88) y el LLM en todas las que cubre.
        # Con el dataset completo son 389 de 425 (0.915), así que el aviso sale.
        suyas = self.sin_un_ciego()
        referencias = {'clase_reglas': lambda h: plantillas.CLASE_DE_SEVERIDAD[h['severity']],
                       'sensibilidad': lambda h: h['caracteristicas']['sensibilidad']}
        otras = [h['id'] for h in MAESTRO if h['bloque'] == 'reparto' and h['asignado_a'] != ['etiquetador_3']][:36]
        for cual, aviso in (('clase_reglas', 'lote_trivial'), ('sensibilidad', 'rubrica_trivial')):
            with self.subTest(cual):
                ref = referencias[cual]
                for e in ('etiquetador_2', 'etiquetador_4'):
                    self.etiquetas[e] = {h['id']: ref(h) for h in COPIAS[e]}
                for id_ in otras:
                    e = POR_ID[id_]['asignado_a'][0]
                    self.etiquetas[e][id_] = OTRA[self.etiquetas[e][id_]]
                self.llm = {h['id']: ref(h) for h in MAESTRO}
                dataset, r, errores = self.procesar(llm=self.llm)
                self.assertEqual(errores, [])
                self.assertEqual(r['llm']['filas_cubiertas'], {'etiquetador_3': len(suyas)})
                personas = [f for f in dataset if f['n_etiquetas'] > 0]
                self.assertEqual((len(personas), sum(f['etiqueta'] == f[cual] for f in personas)), (303, 267))
                self.assertEqual(r['coincidencia']['final'][cual], round(389 / 425, 4))
                self.assertTrue(r[aviso])


class DatasetDelRepo(unittest.TestCase):

    @unittest.skipUnless((generar_lote.CARPETA / 'dataset.csv').exists(), 'todavía no hay etiquetas')
    def test_1_al_menos_60_por_clase_en_las_etiquetas_finales(self):
        with open(generar_lote.CARPETA / 'dataset.csv', encoding='utf-8', newline='') as f:
            por_clase = Counter(fila['etiqueta'] for fila in csv.DictReader(f))
        for clase in plantillas.CLASES:
            self.assertGreaterEqual(por_clase[clase], acuerdo.MINIMO_POR_CLASE, clase)

    @unittest.skipUnless((generar_lote.CARPETA / 'etiquetas' / 'llm.csv').exists(), 'no hay etiquetas del LLM')
    def test_2_las_etiquetas_del_llm_pasan_la_revision(self):
        maestro = acuerdo.leer_maestro(generar_lote.CARPETA)
        llm, repeticion, errores = acuerdo.leer_llm(generar_lote.CARPETA, maestro)
        self.assertEqual(errores, [])
        self.assertEqual(set(llm), {h['id'] for h in maestro})
        if repeticion is not None:
            self.assertEqual(set(repeticion), {h['id'] for h in maestro if h['bloque'] == 'comun'})


if __name__ == '__main__':
    unittest.main()
