"""Pruebas de los JSON de ejemplo del contrato de API v1 (#21), sin base de datos ni red.

Revisan que los ejemplos cumplan el criterio de criticidad (#29) y el contrato de plugin (#13),
porque el portal, el dataset de ML y las demos los usan tal cual.

    python -m unittest -v pruebas/test_contrato_api.py
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_contrato_api.py
from cirdan.recolectores import contrato  # noqa: E402
from cirdan.score import criterio, motor  # noqa: E402

EJEMPLOS = Path(__file__).resolve().parents[1] / 'docs' / 'api_v1'


def leer(nombre):
    return json.loads((EJEMPLOS / nombre).read_text(encoding='utf-8'))


DOMINIOS, HALLAZGOS, SCORE = leer('dominios.json'), leer('hallazgos.json'), leer('score.json')
HISTORICO, EXPLICACION, PESOS = leer('historico.json'), leer('explicacion.json'), leer('pesos.json')
ESTADOS_HALLAZGO = ('open', 'resolved', 'accepted_risk', 'false_positive')  # findings.status
MOTIVOS_BLOQUEO = ('authorization_missing', 'authorization_not_started', 'authorization_expired',
                   'authorization_revoked', 'txt_not_verified', 'domain_paused')  # scan_eligibility.reasons


def calcular(categorias, criticos):
    return criterio.score_dominio(categorias, PESOS['category_weights'], criticos)


class Listas(unittest.TestCase):

    def test_1_total_cuadra_con_items(self):
        for nombre, doc in (('dominios', DOMINIOS), ('hallazgos', HALLAZGOS), ('historico', HISTORICO)):
            self.assertEqual(doc['total'], len(doc['items']), nombre)


class Pesos(unittest.TestCase):

    def test_1_cuatro_categorias_que_suman_1(self):
        w = PESOS['category_weights']
        self.assertEqual(set(w), set(criterio.CATEGORIAS))
        self.assertAlmostEqual(sum(w.values()), 1)

    def test_2_bandas_piso_y_umbral_del_criterio(self):
        self.assertEqual([(b['from'], b['to'], b['band']) for b in PESOS['bands']],
                         [(d, h, c) for d, h, c, _ in criterio.BANDAS])
        self.assertEqual(PESOS['floor']['one_critical'], criterio.PISO_UN_CRITICO)
        self.assertEqual(PESOS['floor']['two_or_more_critical'], criterio.PISO_VARIOS_CRITICOS)
        self.assertEqual(tuple(PESOS['floor']['counts_statuses']), criterio.ESTADOS_VIGENTES)
        self.assertEqual(PESOS['alert_threshold_default'], criterio.UMBRAL_ALERTA)

    def test_3_reglas_validas(self):
        for r in PESOS['rules']:
            self.assertIn(r['category'], criterio.CATEGORIAS, r['code'])
            self.assertIn(r['base_severity'], contrato.SEVERIDADES, r['code'])
            self.assertRegex(r['code'], contrato.CODIGO_VALIDO)


class Score(unittest.TestCase):

    def test_1_cuadra_con_el_criterio(self):
        notas = {c['category']: c['score'] for c in SCORE['categories']}
        r = calcular(notas, SCORE['critical_open'])
        self.assertEqual((SCORE['weighted'], SCORE['floor'], SCORE['score'], SCORE['band'], SCORE['floor_applied']),
                         (r['ponderado'], r['piso'], r['score'], r['banda'], r['piso_aplicado']))
        self.assertEqual(SCORE['floor_message'], motor.mensaje_piso(r, SCORE['critical_open']))

    def test_2_categorias_con_su_peso_y_banda(self):
        self.assertEqual([c['category'] for c in SCORE['categories']], list(criterio.CATEGORIAS))
        for c in SCORE['categories']:
            self.assertEqual(c['weight'], PESOS['category_weights'][c['category']])
            self.assertEqual(c['band'], criterio.banda(c['score']))

    def test_3_alerta(self):
        self.assertEqual(SCORE['alert']['triggered'], criterio.dispara_alerta(SCORE['score'], SCORE['alert']['threshold']))

    def test_4_criticos_vigentes_cuadran_con_los_hallazgos(self):
        criticos = sum(criterio.cuenta_para_piso(h['severity'], h['status']) for h in HALLAZGOS['items'])
        self.assertEqual(SCORE['critical_open'], criticos)


class Historico(unittest.TestCase):

    def test_1_cada_punto_cuadra_con_el_criterio(self):
        for p in HISTORICO['items']:
            r = calcular(p['categories'], p['critical_open'])
            self.assertEqual((p['weighted'], p['floor'], p['score'], p['band'], p['floor_applied']),
                             (r['ponderado'], r['piso'], r['score'], r['banda'], r['piso_aplicado']), p['computed_at'])
            self.assertEqual(p['floor_message'], motor.mensaje_piso(r, p['critical_open']), p['computed_at'])

    def test_2_del_mas_viejo_al_mas_nuevo_y_termina_en_el_score_actual(self):
        fechas = [p['computed_at'] for p in HISTORICO['items']]
        self.assertEqual(fechas, sorted(fechas))
        ultimo = HISTORICO['items'][-1]
        self.assertEqual((ultimo['score_id'], ultimo['score']), (SCORE['score_id'], SCORE['score']))


class Hallazgos(unittest.TestCase):

    def test_1_caracteristicas_del_contrato_de_plugin(self):
        for h in HALLAZGOS['items']:
            c = h['caracteristicas']
            self.assertEqual(tuple(c), contrato.CARACTERISTICAS, h['id'])
            self.assertRegex(c['tipo'], contrato.CODIGO_VALIDO)
            self.assertIsInstance(c['antiguedad_dias'], int)
            self.assertGreaterEqual(c['antiguedad_dias'], 0)
            self.assertIn(c['exposicion'], contrato.EXPOSICIONES)
            self.assertIn(c['sensibilidad'], contrato.SENSIBILIDADES)

    def test_2_codigos_de_la_base(self):
        reglas = {r['code']: r for r in PESOS['rules']}
        for h in HALLAZGOS['items']:
            self.assertIn(h['severity'], contrato.SEVERIDADES)
            self.assertIn(h['asset_type'], contrato.TIPOS_ACTIVO)
            self.assertIn(h['status'], ESTADOS_HALLAZGO)
            self.assertIn(h['recurrence'], ('new', 'recurring'))
            regla = reglas[h['rule_code']]
            self.assertEqual((h['category'], h['base_severity']), (regla['category'], regla['base_severity']))

    def test_3_ordenados_por_severidad(self):
        orden = [contrato.SEVERIDADES.index(h['severity']) for h in HALLAZGOS['items']]
        self.assertEqual(orden, sorted(orden))

    def test_4_activos_dentro_del_dominio(self):
        for h in HALLAZGOS['items']:
            self.assertTrue(contrato.en_alcance_nombre(h['asset'], HALLAZGOS['domain']), h['asset'])

    def test_5_evidencia_sin_secretos(self):
        texto = json.dumps(HALLAZGOS).lower()
        for prohibido in ('password":', 'token":', 'hash":', 'secret'):
            self.assertNotIn(prohibido, texto)


class Explicacion(unittest.TestCase):

    def test_1_factores_suman_la_penalizacion_sin_pasar_el_tope(self):
        self.assertEqual(sum(f['points'] for f in EXPLICACION['factors']), EXPLICACION['penalty'])
        self.assertLessEqual(EXPLICACION['penalty'], EXPLICACION['max_penalty'])

    def test_2_coincide_con_su_hallazgo_y_su_score(self):
        h = next(h for h in HALLAZGOS['items'] if h['id'] == EXPLICACION['finding_id'])
        for campo in ('title', 'severity', 'base_severity', 'category', 'rule_code', 'caracteristicas'):
            self.assertEqual(EXPLICACION[campo], h[campo], campo)
        self.assertEqual(EXPLICACION['score_id'], SCORE['score_id'])
        regla = next(r for r in PESOS['rules'] if r['code'] == EXPLICACION['rule_code'])
        self.assertEqual(EXPLICACION['max_penalty'], regla['max_penalty'])

    def test_3_shap_solo_con_ml(self):
        if EXPLICACION['method'] == 'rules':
            self.assertIsNone(EXPLICACION['shap'])

    def test_4_textos_de_su_regla(self):
        regla = next(r for r in PESOS['rules'] if r['code'] == EXPLICACION['rule_code'])
        self.assertEqual((EXPLICACION['rule_title'], EXPLICACION['meaning'], EXPLICACION['recommendation']),
                         (regla['title'], regla['meaning'], regla['recommendation']))


class Dominios(unittest.TestCase):

    def test_1_banda_del_score(self):
        for d in DOMINIOS['items']:
            self.assertEqual(d['band'], None if d['score'] is None else criterio.banda(d['score']), d['fqdn'])

    def test_2_solo_se_escanea_con_autorizacion_vigente_y_txt_verificado(self):
        for d in DOMINIOS['items']:
            puede = (d['authorization']['status'] == 'valid' and d['txt']['status'] == 'verified'
                     and d['status'] == 'verified')
            self.assertEqual(d['scan_eligibility']['can_scan'], puede, d['fqdn'])
            self.assertEqual(not d['scan_eligibility']['reasons'], puede, d['fqdn'])
            for motivo in d['scan_eligibility']['reasons']:
                self.assertIn(motivo, MOTIVOS_BLOQUEO)

    def test_3_cuadra_con_score_y_hallazgos(self):
        d = next(d for d in DOMINIOS['items'] if d['fqdn'] == SCORE['domain'])
        self.assertEqual((d['score'], d['band']), (SCORE['score'], SCORE['band']))
        conteo = {s: 0 for s in contrato.SEVERIDADES}
        for h in HALLAZGOS['items']:
            conteo[h['severity']] += h['status'] == 'open'
        self.assertEqual(d['open_findings'], conteo)

    def test_4_motivos_como_en_el_contrato_y_el_orquestador(self):
        # Los de docs/contrato_api_v1.md, y el orquestador tiene el texto de cada uno
        fila = next(l for l in (EJEMPLOS.parent / 'contrato_api_v1.md').read_text(encoding='utf-8').splitlines()
                    if l.startswith('| `scan_eligibility`'))
        self.assertEqual(set(fila.split('dice por qué:')[1].split('.')[0].split('`')[1::2]), set(MOTIVOS_BLOQUEO))
        orquestador = (EJEMPLOS.parents[1] / 'cirdan' / 'orquestador' / '__init__.py').read_text(encoding='utf-8')
        for motivo in MOTIVOS_BLOQUEO:
            self.assertIn("'%s':" % motivo, orquestador)


class Textos(unittest.TestCase):
    # Al final del archivo para no recorrer las líneas que cita pruebas/test_dataset_ml.py:78.

    def test_1_cada_regla_con_sus_textos(self):
        for r in PESOS['rules']:
            for campo in ('title', 'meaning', 'recommendation'):
                self.assertIsInstance(r.get(campo), str, (r['code'], campo))
                self.assertTrue(r[campo].strip(), (r['code'], campo))


if __name__ == '__main__':
    unittest.main()
