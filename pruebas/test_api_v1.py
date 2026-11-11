"""Pruebas de la API v1 del portal (RC-17) contra el contrato #21 (biblioteca estándar).

    python -m unittest -v pruebas/test_api_v1.py      (con `docker compose up -d`)

Con los datos demo de Acme, las respuestas deben coincidir con los JSON de docs/api_v1/. Las únicas
diferencias aceptadas son los campos «propuestos» del portal (signer_email) y los
textos que todavía no calcula el motor de score (#31). Los textos de cada regla (#30) sí se comparan.
"""
import csv
import io
import json
import unittest
from datetime import datetime
from pathlib import Path

from cirdan.score import criterio, subcategorias
from pruebas import sesion
from pruebas.test_aislamiento import psql

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
            marcos = real['frameworks']
            self.assertEqual(set(marcos), {'mitre_attack', 'iso_27001_2022', 'cis_controls_v8_1'})
            self.assertEqual(marcos['mitre_attack']['version'], 'Enterprise v19')
            self.assertTrue(marcos['mitre_attack']['source_url'].startswith('https://'))
            if marcos['mitre_attack']['technique_id'] is None:
                self.assertIsNone(marcos['mitre_attack']['technique_name'])
                self.assertTrue(marcos['mitre_attack']['unmapped_reason'])
            else:
                self.assertRegex(marcos['mitre_attack']['technique_id'], r'^T\d{4}(\.\d{3})?$')
                self.assertTrue(marcos['mitre_attack']['technique_name'])
                self.assertIsNone(marcos['mitre_attack']['unmapped_reason'])
            self.assertEqual(marcos['iso_27001_2022']['version'], 'ISO/IEC 27001:2022')
            self.assertRegex(marcos['iso_27001_2022']['control_id'], r'^A\.[5-8]\.\d{1,2}$')
            self.assertTrue(marcos['iso_27001_2022']['control_name'])
            self.assertTrue(marcos['iso_27001_2022']['source_url'].startswith('https://'))
            self.assertEqual(marcos['cis_controls_v8_1']['version'], 'CIS Controls v8.1')
            self.assertRegex(marcos['cis_controls_v8_1']['safeguard_id'], r'^(?:[1-9]|1[0-8])\.\d{1,2}$')
            self.assertTrue(marcos['cis_controls_v8_1']['safeguard_name'])
            self.assertTrue(marcos['cis_controls_v8_1']['source_url'].startswith('https://'))

    def test_3_score_igual_al_contrato(self):
        self.assertEqual(self.get(self.acme, '/api/v1/domains/acme-demo.mx/score'), ejemplo('score.json'))

    def test_3b_cada_regla_de_la_base_tiene_subcategoria_y_cada_kri_apunta_a_una_que_existe(self):
        # De base (#114, RC-232): lee las reglas de todos los juegos que hay en la base, no las semillas del repo.
        ok, out, err = psql('SELECT DISTINCT code, category FROM scoring_rules ORDER BY 1, 2;', user='postgres')
        self.assertTrue(ok, err)
        reglas = [tuple(linea.split('|')) for linea in out.splitlines()]   # pares de todos los juegos
        self.assertGreaterEqual(len(reglas), 30)
        self.assertEqual(subcategorias.revisar(reglas, criterio.CATEGORIAS), [])
        ok, out, err = psql('SELECT code FROM data_sources ORDER BY 1;', user='postgres')
        self.assertTrue(ok, err)
        for kri, _, _, fuentes in subcategorias.KRIS:
            self.assertEqual([f for f in fuentes if f not in out.splitlines()], [], 'fuentes del KRI %s' % kri)

    def test_3c_un_kri_con_su_fuente_caida_sale_sin_cobertura(self):
        # La corrida de ct_logs del escaneo del score de acme-demo.mx pasa a failed y vuelve a succeeded al terminar.
        corrida = "UPDATE scan_source_runs SET status = '%s' WHERE id = '61000000-0000-4000-8000-000000000001';"
        antes = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
        kri = {k['kri']: k for k in antes['kris']}
        self.assertEqual((kri['certificates']['status'], kri['certificates']['findings'],
                          kri['certificates']['max_severity'], kri['certificates']['penalty']), ('ok', 1, 'high', 20.0))
        ok, _, err = psql(corrida % 'failed', user='postgres')
        self.assertTrue(ok, err)
        try:
            caida = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
            kri = {k['kri']: k for k in caida['kris']}
            for clave in ('certificates', 'impersonation'):   # los dos se alimentan de ct_logs
                self.assertEqual((kri[clave]['status'], kri[clave]['findings'], kri[clave]['max_severity'],
                                  kri[clave]['penalty'], kri[clave]['sources_failed']),
                                 ('no_coverage', None, None, None, ['ct_logs']), clave)
            self.assertEqual((kri['email']['status'], kri['email']['findings']), ('ok', 1))   # dns sí respondió
            # exposición: shodan respondió y api_docs no corrió en ese escaneo, así que no sale ok
            self.assertEqual((kri['service_exposure']['status'], kri['service_exposure']['sources_not_run']),
                             ('partial', ['api_docs']))
            self.assertEqual(kri['reputation']['status'], 'no_source_yet')
            # la letra, el score, la alerta y las subcategorías no cambian: salen del score guardado
            for campo in ('score', 'grade', 'band', 'alert', 'subcategories', 'categories'):
                self.assertEqual(caida[campo], antes[campo], campo)
        finally:
            ok, _, err = psql(corrida % 'succeeded', user='postgres')
            self.assertTrue(ok, err)
        self.assertEqual(self.get(self.acme, '/api/v1/domains/acme-demo.mx/score'), antes)

    def test_3c2_el_score_usa_la_cobertura_que_guardo_el_escaneo(self):
        # /score pasa rules_without_coverage y sources_partial de scans.stats a los KRI. El escaneo del score de
        # acme-demo.mx no los trae en la semilla: se le ponen y se le quitan al terminar.
        escaneo = "WHERE id = '60000000-0000-4000-8000-000000000001';"
        antes = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
        cobertura = ('{"rules_without_coverage": ["exposed_iot_device", "exposed_ot_device", "dmarc_missing"], '
                     '"sources_partial": ["ct_logs"]}')
        ok, _, err = psql("UPDATE scans SET stats = stats || '%s'::jsonb %s" % (cobertura, escaneo), user='postgres')
        self.assertTrue(ok, err)
        try:
            con = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
            kri = {k['kri']: k for k in con['kris']}
            # las reglas sin cobertura van al KRI que las tiene, en el orden del mapa
            self.assertEqual((kri['service_exposure']['status'], kri['service_exposure']['rules_without_coverage']),
                             ('partial', ['exposed_ot_device', 'exposed_iot_device']))
            self.assertEqual((kri['email']['status'], kri['email']['rules_without_coverage'], kri['email']['findings']),
                             ('partial', ['dmarc_missing'], 1))
            # ct_logs revisó solo una parte: sus dos KRI pasan de ok a partial y conservan sus conteos
            for clave, hallazgos in (('certificates', 1), ('impersonation', 0)):
                self.assertEqual((kri[clave]['status'], kri[clave]['sources_partial'], kri[clave]['findings']),
                                 ('partial', ['ct_logs'], hallazgos), clave)
            for campo in ('score', 'grade', 'band', 'alert', 'subcategories', 'categories', 'partial_coverage'):
                self.assertEqual(con[campo], antes[campo], campo)
        finally:
            ok, _, err = psql("UPDATE scans SET stats = stats - 'rules_without_coverage' - 'sources_partial' "
                              + escaneo, user='postgres')
            self.assertTrue(ok, err)
        self.assertEqual(self.get(self.acme, '/api/v1/domains/acme-demo.mx/score'), antes)

    def test_3d_letra_en_dominios_historico_y_pesos_y_la_alerta_sigue_con_el_score(self):
        for d in self.get(self.acme, '/api/v1/domains')['items']:
            self.assertEqual(d['grade'], None if d['score'] is None else criterio.letra(d['score']), d['fqdn'])
        for p in self.get(self.acme, '/api/v1/domains/acme-demo.mx/score/history')['items']:
            self.assertEqual(p['grade'], criterio.letra(p['score']), p['score_id'])
        pesos = self.get(self.acme, '/api/v1/scoring/weights')
        self.assertEqual([(g['from'], g['to'], g['grade']) for g in pesos['grades']], list(criterio.LETRAS))
        score = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')   # 60, letra D, umbral 60
        self.assertEqual((score['grade'], score['alert']), ('D', {'threshold': 60, 'triggered': True}))
        self.assertIsInstance(score['alert']['threshold'], int)   # el umbral es un número de 0 a 100, no una letra
        # con el umbral de la empresa en 61 el score sigue en 60 y en D, pero ya no dispara: manda el número
        umbral = ("UPDATE organizations SET alert_score_threshold = %d "
                  "WHERE id = '20000000-0000-4000-8000-000000000001';")
        ok, _, err = psql(umbral % 61, user='postgres')
        self.assertTrue(ok, err)
        try:
            con_61 = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
            self.assertEqual((con_61['score'], con_61['grade'], con_61['alert']),
                             (60, 'D', {'threshold': 61, 'triggered': False}))
        finally:
            ok, _, err = psql(umbral % 60, user='postgres')
            self.assertTrue(ok, err)
        self.assertEqual(self.get(self.acme, '/api/v1/domains/acme-demo.mx/score'), score)
        # acme-tienda.mx tiene score 0 y su escaneo no guardó corridas: letra A, pero ningún KRI sale en cero
        tienda = self.get(self.acme, '/api/v1/domains/acme-tienda.mx/score')
        self.assertEqual((tienda['score'], tienda['grade']), (0, 'A'))
        self.assertEqual([(k['status'], k['findings']) for k in tienda['kris']],
                         [('no_coverage', None)] * 4 + [('no_source_yet', None)])

    def test_4_explicacion_y_pesos(self):
        exp = sin_propuestos(self.get(self.acme, '/api/v1/findings/80000000-0000-4000-8000-000000000001/explanation'))
        esperado = ejemplo('explicacion.json')
        for campo in ('title', 'severity', 'penalty', 'max_penalty', 'factors', 'caracteristicas', 'score_id',
                      'model_version', 'model_prediction', 'explanation_model_version', 'confidence', 'shap',
                      'rule_title', 'meaning', 'recommendation'):
            self.assertEqual(exp[campo], esperado[campo], campo)
        hallazgos = self.get(self.acme, '/api/v1/domains/acme-demo.mx/findings')
        hallazgo = next(item for item in hallazgos['items'] if item['id'] == exp['finding_id'])
        self.assertEqual(exp['frameworks'], hallazgo['frameworks'])
        pesos = self.get(self.acme, '/api/v1/scoring/weights')
        esperado = ejemplo('pesos.json')
        for campo in ('rule_set_version', 'category_weights', 'bands', 'floor', 'alert_threshold_default', 'rules'):
            self.assertEqual(pesos[campo], esperado[campo], campo)

    def test_5_historico_activos_y_escaneos(self):
        hist = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score/history')
        self.assertEqual([(p['score'], p['reason'], p['new_findings']) for p in hist['items']],
                         [(68, 'scan', 3), (60, 'correction', 0)])
        self.assertEqual([p['weekly_changes'] for p in hist['items']],
                         [p['weekly_changes'] for p in ejemplo('historico.json')['items']])
        tienda = self.get(self.acme, '/api/v1/domains/acme-tienda.mx/score/history')['items']
        semilla = next(p for p in tienda if p['score_id'] == 'a0000000-0000-4000-8000-000000000002')
        self.assertEqual((semilla['new_findings'], semilla['resolved_findings']), (None, None))  # su escaneo no los contó
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

    def descargar(self, client, url):
        with client.opener.open(sesion.BASE + url, timeout=10) as r:
            return r.status, r.headers, r.read().decode('utf-8')

    def test_9b_comparacion_hallazgo_por_hallazgo(self):
        # a..01 (escaneo de la semilla 001) solo trae el aporte de la brecha. a..04 (corrección de la 009) trae
        # los cuatro hallazgos abiertos de acme-demo.mx, con la brecha en 40 puntos en vez de 24.
        url = ('/api/v1/domains/acme-demo.mx/score/compare?desde=a0000000-0000-4000-8000-000000000001'
               '&hasta=a0000000-0000-4000-8000-000000000004')
        comp = self.get(self.acme, url)
        self.assertEqual((comp['from']['score'], comp['to']['score']), (68, 60))
        self.assertEqual(comp['summary'], {'new': 3, 'gone': 0, 'kept': 1, 'severity_changed': 0})
        brecha = next(i for i in comp['items'] if i['finding_id'] == '80000000-0000-4000-8000-000000000001')
        self.assertEqual((brecha['change'], brecha['penalty_from'], brecha['penalty_to']), ('kept', 24.0, 40.0))
        self.assertEqual(comp['total'], 4)
        self.assertEqual([i['change'] for i in comp['items']], ['new', 'new', 'new', 'kept'])
        # Al revés, los tres nuevos pasan a 'gone'.
        reves = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score/compare?desde=a0000000-0000-4000-8000-000000000004'
                                    '&hasta=a0000000-0000-4000-8000-000000000001')
        self.assertEqual(reves['summary'], {'new': 0, 'gone': 3, 'kept': 1, 'severity_changed': 0})
        # Un score de otro dominio, de otra empresa o mal formado responde 404, igual que uno que no existe.
        for desde in ('a0000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000000', 'no-es-uuid'):
            code, _ = self.acme.get(url.replace('a0000000-0000-4000-8000-000000000001', desde))
            self.assertEqual(code, 404, desde)
        self.assertEqual(self.beta.get(url)[0], 404)
        self.assertEqual(self.acme.get('/api/v1/domains/acme-demo.mx/score/compare')[0], 422)
        # Exportaciones de la comparación: CSV con BOM y un renglón por hallazgo, JSON igual a la respuesta.
        code, headers, texto = self.descargar(self.acme, url.replace('/compare?', '/compare/export?formato=csv&'))
        self.assertEqual(code, 200)
        self.assertTrue(headers['Content-Type'].startswith('text/csv'))
        self.assertIn('acme-demo.mx-comparacion.csv', headers['Content-Disposition'])
        self.assertTrue(texto.startswith('﻿'))
        filas = list(csv.reader(io.StringIO(texto[1:], newline='')))
        self.assertEqual(len(filas), 1 + comp['total'])
        self.assertEqual(sorted(f[5] for f in filas[1:]), sorted(i['finding_id'] for i in comp['items']))
        code, headers, texto = self.descargar(self.acme, url.replace('/compare?', '/compare/export?formato=json&'))
        self.assertTrue(headers['Content-Type'].startswith('application/json'))
        self.assertEqual(json.loads(texto), comp)
        self.assertEqual(self.acme.get(url.replace('/compare?', '/compare/export?formato=xlsx&'))[0], 422)

    def test_9c_exportacion_de_hallazgos_escapa_formulas(self):
        # Un hallazgo abierto con un título que Excel tomaría por fórmula. Se borra al terminar.
        hallazgo = '80000000-0000-4000-8000-0000000005f7'
        ok, _, err = psql('''
            INSERT INTO findings (id, organization_id, domain_id, asset_id, rule_id, source_id, fingerprint,
                                  severity, status, evidence, detected_at)
            SELECT '%s', d.organization_id, d.id,
                   (SELECT a.id FROM assets a WHERE a.domain_id = d.id ORDER BY a.id LIMIT 1),
                   (SELECT r.id FROM scoring_rules r WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001'
                       AND r.code = 'spf_missing'),
                   (SELECT s.id FROM data_sources s WHERE s.code = 'dns'),
                   sha256('rc57-prueba-formula'), 'low', 'open',
                   '{"title": "=HYPERLINK(\\"http://x\\",\\"clic\\")", "banner": "@SUM(1)"}', now()
              FROM domains d WHERE d.fqdn = 'acme-demo.mx';
        ''' % hallazgo, user='postgres')
        self.assertTrue(ok, err)
        try:
            _, headers, texto = self.descargar(self.acme, '/api/v1/domains/acme-demo.mx/findings/export?formato=csv')
            self.assertTrue(headers['Content-Type'].startswith('text/csv'))
            self.assertTrue(texto.startswith('﻿'))
            filas = list(csv.reader(io.StringIO(texto[1:], newline='')))
            fila = dict(zip(filas[0], next(f for f in filas[1:] if f[1] == hallazgo)))
            self.assertEqual(fila['titulo'], '\'=HYPERLINK("http://x","clic")')
            self.assertEqual(json.loads(fila['evidencia'])['banner'], '@SUM(1)')  # el JSON empieza con {, no es fórmula
            _, headers, texto = self.descargar(self.acme, '/api/v1/domains/acme-demo.mx/findings/export?formato=json')
            data = json.loads(texto)
            self.assertEqual(data, self.get(self.acme, '/api/v1/domains/acme-demo.mx/findings'))
            self.assertEqual(len(filas), 1 + data['total'])
            self.assertEqual(next(i for i in data['items'] if i['id'] == hallazgo)['title'],
                             '=HYPERLINK("http://x","clic")')  # el JSON no se toca
        finally:
            ok, _, err = psql("DELETE FROM findings WHERE id = '%s';" % hallazgo, user='postgres')
            self.assertTrue(ok, err)

    def test_9e_comparacion_con_hallazgo_que_cambio_de_dominio(self):
        # El upsert por huella puede mover domain_id (orquestador/__init__.py). El aporte guardado en el score sigue
        # siendo del dominio del score, así que la comparación lo cuenta igual. Se regresa al terminar.
        url = ('/api/v1/domains/acme-demo.mx/score/compare?desde=a0000000-0000-4000-8000-000000000001'
               '&hasta=a0000000-0000-4000-8000-000000000004')
        antes = self.get(self.acme, url)
        movido = next(i['finding_id'] for i in antes['items'] if i['change'] == 'new')
        ok, activo, err = psql("SELECT asset_id FROM findings WHERE id = '%s';" % movido, user='postgres')
        self.assertTrue(ok and activo, err)
        # La llave (organization_id, domain_id, asset_id) pide un activo del otro dominio, y la semilla no trae
        # activos de acme-tienda.mx: se crea uno de prueba y se borra al terminar.
        temporal = '70000000-0000-4000-8000-0000000005f7'
        ok, _, err = psql('''
            INSERT INTO assets (id, organization_id, domain_id, asset_type, value, attributes, first_seen_at, last_seen_at)
            SELECT '%s', d.organization_id, d.id, 'domain', 'rc57-prueba.acme-tienda.mx', '{}', now(), now()
              FROM domains d WHERE d.fqdn = 'acme-tienda.mx' ON CONFLICT (id) DO NOTHING;
            UPDATE findings f SET domain_id = a.domain_id, asset_id = a.id FROM assets a
             WHERE a.id = '%s' AND f.id = '%s';
        ''' % (temporal, temporal, movido), user='postgres')
        self.assertTrue(ok, err)
        try:
            despues = self.get(self.acme, url)
            self.assertEqual((despues['summary'], despues['total']), (antes['summary'], antes['total']))
            self.assertIn(movido, [i['finding_id'] for i in despues['items']])
        finally:
            ok, _, err = psql("UPDATE findings SET domain_id = (SELECT id FROM domains WHERE fqdn = 'acme-demo.mx'), "
                              "asset_id = '%s' WHERE id = '%s'; DELETE FROM assets WHERE id = '%s';"
                              % (activo, movido, temporal), user='postgres')
            self.assertTrue(ok, err)

    def test_9d_403_sin_autorizacion_vigente_y_404_de_otra_empresa(self):
        # old-example.net es de Acme y su autorización venció el 15 ago 2026.
        for url in ('/api/v1/domains/old-example.net/findings/export?formato=csv',
                    '/api/v1/domains/old-example.net/findings/export?formato=json',
                    '/api/v1/domains/old-example.net/score/compare?desde=a0000000-0000-4000-8000-000000000001'
                    '&hasta=a0000000-0000-4000-8000-000000000004',
                    '/api/v1/domains/old-example.net/score/compare/export?formato=csv'
                    '&desde=a0000000-0000-4000-8000-000000000001&hasta=a0000000-0000-4000-8000-000000000004'):
            code, body = self.acme.get(url)
            self.assertEqual(code, 403, (url, body))
            self.assertEqual(self.beta.get(url)[0], 404, url)
        self.assertEqual(self.beta.get('/api/v1/domains/acme-demo.mx/findings/export')[0], 404)
        self.assertEqual(self.get(self.beta, '/api/v1/domains/beta-corp.mx/findings/export')['domain'], 'beta-corp.mx')
        self.assertEqual(sesion.Client().get('/api/v1/domains/acme-demo.mx/findings/export')[0], 401)

    def test_10_salida_siem_con_plan_y_sin_evidencia(self):
        url = '%s/api/v1/domains/beta-corp.mx/export/siem' % sesion.BASE
        with self.beta.opener.open(url, timeout=10) as r:
            self.assertEqual(r.status, 200)
            self.assertTrue(r.headers['Content-Type'].startswith('application/x-ndjson'))
            self.assertIn('beta-corp.mx-siem.ndjson', r.headers['Content-Disposition'])
            self.assertEqual(r.headers['Cache-Control'], 'no-store')
            texto = r.read().decode('utf-8')
        eventos = [json.loads(x) for x in texto.splitlines()]
        # beta-corp.mx tiene un hallazgo abierto y ningún escaneo ni score en la semilla 001. La exportación siempre
        # cierra con su evento lowtide:export.
        self.assertEqual([e['sourcetype'] for e in eventos], ['lowtide:finding', 'lowtide:export'])
        ev = eventos[0]['event']
        self.assertEqual((ev['finding_id'], ev['signature_id'], ev['dest'], ev['dest_port'], ev['domain'],
                          ev['vendor_product']),
                         ('80000000-0000-4000-8000-000000000011', 'exposed_rdp', '192.0.2.50', 3389,
                          'beta-corp.mx', 'LowTide'))
        # signature es el título de la regla (003_textos_reglas.sql), no el de la evidencia (semilla 003_titulos_espanol).
        self.assertEqual(ev['signature'], 'Puerto del escritorio remoto de Windows abierto a internet')
        self.assertNotIn('evidence', texto)
        self.assertNotIn('Escritorio remoto (RDP) expuesto', texto)
        # El hallazgo es del 28 sep, pero el time de HEC es el de la exportación, igual en todos los eventos.
        self.assertEqual(len({(e['time'], e['event']['export_id']) for e in eventos}), 1)
        self.assertGreater(eventos[0]['time'], datetime.fromisoformat(ev['detected_at']).timestamp() + 86400)
        self.assertEqual(eventos[1]['event']['findings'], 1)
        # Con la empresa suspendida, la sesión que ya tenía abierta no exporta (como el login, solo trial o active).
        beta = "UPDATE organizations SET status = '%s' WHERE id = '20000000-0000-4000-8000-000000000002';"
        ok, _, err = psql(beta % 'suspended', user='postgres')
        self.assertTrue(ok, err)
        self.addCleanup(psql, beta % 'active', user='postgres')
        self.assertEqual(self.beta.get('/api/v1/domains/beta-corp.mx/export/siem')[0], 403)
        ok, _, err = psql(beta % 'active', user='postgres')
        self.assertTrue(ok, err)
        # Acme tiene el plan starter, sin API ni SIEM. Un dominio de otra empresa responde 404 y sin sesión, 401.
        self.assertEqual(self.acme.get('/api/v1/domains/acme-demo.mx/export/siem')[0], 403)
        for fqdn in ('acme-demo.mx', 'olmardo.com'):
            self.assertEqual(self.beta.get('/api/v1/domains/%s/export/siem' % fqdn)[0], 404, fqdn)
        self.assertEqual(sesion.Client().get('/api/v1/domains/beta-corp.mx/export/siem')[0], 401)

if __name__ == '__main__':
    unittest.main(verbosity=2)
