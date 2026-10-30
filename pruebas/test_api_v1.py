"""Pruebas de la API v1 del portal (RC-17) contra el contrato #21 (biblioteca estándar).

    python -m unittest -v pruebas/test_api_v1.py      (con `docker compose up -d`)

Con los datos demo de Acme, las respuestas deben coincidir con los JSON de docs/api_v1/. Las únicas
diferencias aceptadas son los campos «propuestos» del portal (signer_email) y los
textos que todavía no calcula el motor de score (#31). Los textos de cada regla (#30) sí se comparan.
"""
import json
import unittest
from pathlib import Path

from pruebas import sesion

EJEMPLOS = Path(__file__).resolve().parents[1] / 'docs' / 'api_v1'
PROPUESTOS = {'signer_email'}


def ejemplo(nombre):
    return json.loads((EJEMPLOS / nombre).read_text(encoding='utf-8'))


def sin_propuestos(x):
    if isinstance(x, dict):
        return {k: sin_propuestos(v) for k, v in x.items() if k not in PROPUESTOS}
    if isinstance(x, list):
        return [sin_propuestos(v) for v in x]
    return x


class ApiV1(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sesion.reset()
        cls.acme = sesion.login('alex.morgan@acme-demo.mx')
        cls.beta = sesion.login('dana.cruz@beta-corp.mx')
        cls.olmardo = sesion.login('admin@olmardo.com')

    def get(self, client, url):
        code, body = client.get(url)
        self.assertEqual(code, 200, (url, body))
        return body

    def test_1_dominios_como_el_contrato(self):
        body = sin_propuestos(self.get(self.acme, '/api/v1/domains'))
        esperado = ejemplo('dominios.json')
        self.assertEqual([d['fqdn'] for d in body['items']], [d['fqdn'] for d in esperado['items']])
        for real, ej in zip(body['items'], esperado['items']):
            for campo in ('id', 'status', 'authorization', 'scan_eligibility', 'score', 'band', 'open_findings'):
                self.assertEqual(real[campo], ej[campo], (real['fqdn'], campo))

    def test_2_hallazgos_como_el_contrato(self):
        body = self.get(self.acme, '/api/v1/domains/acme-demo.mx/findings')
        esperado = ejemplo('hallazgos.json')
        self.assertEqual(body['total'], esperado['total'])
        for real, ej in zip(body['items'], esperado['items']):
            for campo in ('id', 'title', 'asset', 'category', 'rule_code', 'source', 'severity', 'recurrence', 'caracteristicas'):
                self.assertEqual(real[campo], ej[campo], (real['id'], campo))

    def test_3_score_igual_al_contrato(self):
        self.assertEqual(self.get(self.acme, '/api/v1/domains/acme-demo.mx/score'), ejemplo('score.json'))

    def test_4_explicacion_y_pesos(self):
        exp = sin_propuestos(self.get(self.acme, '/api/v1/findings/80000000-0000-4000-8000-000000000001/explanation'))
        esperado = ejemplo('explicacion.json')
        for campo in ('title', 'severity', 'penalty', 'max_penalty', 'factors', 'caracteristicas', 'score_id',
                      'model_version', 'model_prediction', 'explanation_model_version', 'confidence', 'shap',
                      'rule_title', 'meaning', 'recommendation'):
            self.assertEqual(exp[campo], esperado[campo], campo)
        pesos = self.get(self.acme, '/api/v1/scoring/weights')
        esperado = ejemplo('pesos.json')
        for campo in ('rule_set_version', 'category_weights', 'bands', 'floor', 'alert_threshold_default', 'rules'):
            self.assertEqual(pesos[campo], esperado[campo], campo)

    def test_5_historico_activos_y_escaneos(self):
        hist = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score/history')
        self.assertEqual([(p['score'], p['reason'], p['new_findings']) for p in hist['items']],
                         [(68, 'scan', 3), (60, 'rules_change', 0)])
        activos = self.get(self.acme, '/api/v1/domains/acme-demo.mx/assets')
        self.assertEqual(activos['total'], 6)
        escaneos = self.get(self.acme, '/api/v1/scans')
        self.assertIn('acme-demo.mx', [s['domain'] for s in escaneos['items']])

    def test_6_cada_empresa_ve_solo_lo_suyo(self):
        self.assertEqual([d['fqdn'] for d in self.get(self.beta, '/api/v1/domains')['items']], ['beta-corp.mx'])
        olmardo = self.get(self.olmardo, '/api/v1/domains')['items']
        self.assertEqual([(d['fqdn'], d['score'], d['scan_eligibility']['can_scan']) for d in olmardo], [('olmardo.com', None, True)])
        for url in ('/api/v1/domains/acme-demo.mx/findings', '/api/v1/domains/acme-demo.mx/score',
                    '/api/v1/findings/80000000-0000-4000-8000-000000000001/explanation'):
            self.assertEqual(self.beta.get(url)[0], 404, url)
        self.assertEqual(sesion.Client().get('/api/v1/domains')[0], 401)

    def test_7_txt_solo_para_admin_y_de_su_empresa(self):
        txt = self.get(self.olmardo, '/api/v1/domains/txt')['items']
        self.assertEqual([(t['fqdn'], t['expected_value']) for t in txt], [('olmardo.com', 'cirdan-verification=ab439d2b39a7')])
        analista = sesion.login('jordan.tate@acme-demo.mx')
        self.assertEqual(analista.get('/api/v1/domains/txt')[0], 403)

    def test_8_plan_y_simulacion_no_modifican_hallazgos_ni_score(self):
        score_before = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
        findings_before = self.get(self.acme, '/api/v1/domains/acme-demo.mx/findings')
        action_plan = self.get(self.acme, '/api/v1/domains/acme-demo.mx/action-plan')
        self.assertEqual(action_plan['domain'], 'acme-demo.mx')
        self.assertEqual(action_plan['score_before'], score_before['score'])
        self.assertTrue(action_plan['actions'])

        selected = [action['id'] for action in action_plan['actions'][:2]]
        code, simulated = self.acme.post('/api/v1/domains/acme-demo.mx/action-plan/simulate',
                                         {'action_ids': selected})
        self.assertEqual(code, 200, simulated)
        self.assertEqual(simulated['action_ids'], selected)
        self.assertEqual(simulated['score_before'], score_before['score'])
        self.assertLessEqual(simulated['score_after'], simulated['score_before'])

        code, error = self.acme.post('/api/v1/domains/acme-demo.mx/action-plan/simulate',
                                     {'action_ids': ['not-a-plan-action']})
        self.assertEqual(code, 422, error)
        self.assertEqual(self.get(self.acme, '/api/v1/domains/acme-demo.mx/score'), score_before)
        self.assertEqual(self.get(self.acme, '/api/v1/domains/acme-demo.mx/findings'), findings_before)

    def test_9_actual_del_plan_igual_al_score_guardado_y_exportaciones(self):
        for fqdn in ('acme-demo.mx', 'acme-tienda.mx', 'acme-portal.mx'):
            score = self.get(self.acme, '/api/v1/domains/%s/score' % fqdn)
            action_plan = self.get(self.acme, '/api/v1/domains/%s/action-plan' % fqdn)
            self.assertEqual((action_plan['score_before'], action_plan['band_before']), (score['score'], score['band']), fqdn)
            self.assertEqual(action_plan['category_scores_before'],
                             {c['category']: c['score'] for c in score['categories']}, fqdn)
            for accion in action_plan['actions']:  # el 'Actual' es el punto de partida de cada estimado
                self.assertEqual(accion['score_after'] + accion['score_reduction'], action_plan['score_before'],
                                 (fqdn, accion['id']))
            if fqdn == 'acme-demo.mx':
                # El piso de 60 por la brecha crítica deja en 60 todo lo demás: solo resolverla baja el score.
                self.assertEqual([(a['id'], a['score_after'], a['score_reduction']) for a in action_plan['actions']],
                                 [('breach_exposure', 16, 44), ('dmarc_missing', 60, 0), ('cert_expired', 60, 0),
                                  ('outdated_software', 60, 0)])
            else:
                self.assertEqual(action_plan['actions'], [], fqdn)
            for formato, tipo in (('csv', 'text/csv'), ('json', 'application/json')):
                url = '%s/api/v1/domains/%s/action-plan/export?formato=%s' % (sesion.BASE, fqdn, formato)
                with self.acme.opener.open(url, timeout=10) as r:
                    self.assertEqual(r.status, 200, url)
                    self.assertTrue(r.headers['Content-Type'].startswith(tipo), url)


if __name__ == '__main__':
    unittest.main(verbosity=2)
