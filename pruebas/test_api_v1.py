"""Pruebas de la API v1 del portal (RC-17) contra el contrato #21 (biblioteca estándar).

    python -m unittest -v pruebas/test_api_v1.py      (con `docker compose up -d`)

Con los datos demo de Acme, las respuestas deben coincidir con los JSON de docs/api_v1/. Las únicas
diferencias aceptadas son los campos «propuestos» del portal (signer_email) y los
textos que todavía no calcula el motor de score (#31). Los textos de cada regla (#30) sí se comparan.
"""
import csv
import io
import json
import os
import subprocess
import unittest
from datetime import date, datetime, timedelta
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

    def psql_o_falla(self, sql, motivo):
        """psql como postgres que falla con su motivo: una limpieza que no regresa la base no pasa en silencio."""
        ok, _, err = psql(sql, user='postgres')
        if not ok:
            raise AssertionError('%s: %s' % (motivo, err))

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

    def test_1b_carta_que_empieza_manana_no_cuenta_como_vigente(self):
        # RC-313. La API va en UTC y la base decide con la fecha de México (cirdan/db.py). De 18:00 a 24:00 de México
        # el reloj de la API ya va en el día siguiente: una carta que empieza ese día salía 'expired'. Dos renovaciones
        # empiezan mañana en México y vencen después que su carta de la semilla. La de old-example.net (41...05,
        # vencida) es la que se muestra y sale 'missing' en /api/v1/domains y 'Not authorized' en GET /domains. La de
        # acme-demo.mx (41...01, vigente) no le quita la vigencia en ninguna de las dos. La tabla es inmutable: las filas
        # se borran al final sin triggers, solo en esa transacción.
        cartas = (('41000000-0000-4000-8000-0000000000f1', '41000000-0000-4000-8000-000000000005', 60),
                  ('41000000-0000-4000-8000-0000000000f2', '41000000-0000-4000-8000-000000000001', 400))
        hoy = "(now() AT TIME ZONE 'America/Mexico_City')::date"
        sql = ("BEGIN; SELECT %s, (now() AT TIME ZONE 'UTC')::date, valid_from, valid_until, "
               '%s BETWEEN valid_from AND valid_until AND revoked_at IS NULL FROM domain_authorizations '
               "WHERE id = '41000000-0000-4000-8000-000000000001';" % (hoy, hoy))
        for nueva, base, dias in cartas:
            sql += ('INSERT INTO domain_authorizations (id, organization_id, domain_id, signer_name, signer_title, '
                    'signer_email, signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by) '
                    "SELECT '%s', organization_id, domain_id, signer_name, signer_title, signer_email, "
                    "signed_document_key || '.rc313', signed_document_sha256, %s + 1, %s + %d, accepted_by "
                    "FROM domain_authorizations WHERE id = '%s';" % (nueva, hoy, hoy, dias, base))
        ok, salida, err = psql(sql + 'COMMIT;', user='postgres')
        self.assertTrue(ok, err)
        self.addCleanup(self.psql_o_falla, 'BEGIN; SET LOCAL session_replication_role = replica; '
                        'DELETE FROM domain_authorizations WHERE id IN (%s); COMMIT;'
                        % ', '.join("'%s'" % c[0] for c in cartas), 'quedaron las cartas de prueba de RC-313')
        hoy_antes, utc, acme_desde, acme_hasta, acme_vigente = salida.splitlines()[0].split('|')
        v1 = {x['fqdn']: x for x in self.get(self.acme, '/api/v1/domains')['items']}
        viejo = {x['domain']: x for x in self.get(self.acme, '/domains')}
        ok, hoy_despues, err = psql('SELECT %s;' % hoy, user='postgres')
        self.assertTrue(ok, err)
        if hoy_despues != hoy_antes:
            # Si cruzó las 00:00 de México entre el INSERT y los GET, la carta ya empezó y 'valid' sería correcto.
            self.skipTest('Cruzó las 00:00 de México (%s a %s): se corre otra vez' % (hoy_antes, hoy_despues))
        manana = date.fromisoformat(hoy_antes) + timedelta(days=1)
        contexto = ('fecha en México %s, en UTC %s' % (hoy_antes, utc), v1['old-example.net'], viejo['old-example.net'],
                    v1['acme-demo.mx']['authorization'], viejo['acme-demo.mx'])
        old = v1['old-example.net']
        self.assertEqual(old['authorization']['valid_from'], manana.isoformat(), contexto)
        self.assertEqual(old['authorization']['status'], 'missing', contexto)
        self.assertIsNone(old['authorization']['signer_email'], contexto)   # sin empezar, RC-274
        self.assertEqual(old['scan_eligibility']['reasons'], ['authorization_not_started', 'domain_paused'], contexto)
        self.assertEqual((viejo['old-example.net']['authorization'], viejo['old-example.net']['valid_until']),
                         ('Not authorized', (manana + timedelta(days=59)).isoformat()), contexto)
        if acme_vigente != 't':
            # Desde que vence la carta de la semilla (2026-12-31) no hay vigente que proteger.
            self.skipTest('La carta 41...01 de acme-demo.mx ya no está vigente (%s a %s)' % (acme_desde, acme_hasta))
        acme = v1['acme-demo.mx']['authorization']
        self.assertEqual((acme['status'], acme['valid_from']), ('valid', acme_desde), contexto)
        self.assertEqual(acme['signer_email'], 'security@acme-demo.mx', contexto)
        self.assertEqual((viejo['acme-demo.mx']['authorization'], viejo['acme-demo.mx']['valid_until']),
                         ('Authorized', acme_hasta), contexto)

    def test_1d_correo_de_quien_firma_solo_con_la_carta_vigente(self):
        # RC-274. Al terminar la carta, los datos de quien firma pasan a bloqueo (sección 5.6 de la política): con
        # 'revoked', 'expired' o 'missing' signer_email sale null y los demás campos no cambian. Cartas con correos que
        # no están en la semilla y fechas relativas a la fecha de México de la base, así la prueba no depende de que
        # siga vigente la 41...01 de la semilla (vence 2026-12-31). acme-demo.mx suma una vigente propia que vence
        # después que la de la semilla, una vencida y una revocada que vence después que la vigente, así la vigente gana
        # aunque no sea la de valid_until más lejano. partner-example.com, sin carta en la semilla, suma solo una
        # revocada. old-example.net sigue con su carta vencida de la semilla.
        hoy = "(now() AT TIME ZONE 'America/Mexico_City')::date"
        acme_dom, partner_dom = '40000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000004'
        cartas = (('41000000-0000-4000-8000-0000000000f6', acme_dom, 'vigente.rc274@acme-demo.mx',
                   '%s - 10' % hoy, '%s + 400' % hoy, 'NULL'),
                  ('41000000-0000-4000-8000-0000000000f3', acme_dom, 'vencida.rc274@acme-demo.mx',
                   "DATE '2025-01-01'", "DATE '2025-06-30'", 'NULL'),
                  ('41000000-0000-4000-8000-0000000000f4', acme_dom, 'revocada.rc274@acme-demo.mx',
                   '%s - 10' % hoy, '%s + 800' % hoy, 'now()'),
                  ('41000000-0000-4000-8000-0000000000f5', partner_dom, 'revocada.rc274@partner-example.com',
                   '%s - 10' % hoy, '%s + 100' % hoy, 'now()'))
        sql = 'BEGIN;'
        for nueva, dominio, correo, desde, hasta, revocada in cartas:
            sql += ('INSERT INTO domain_authorizations (id, organization_id, domain_id, signer_name, signer_title, '
                    'signer_email, signed_document_key, signed_document_sha256, valid_from, valid_until, revoked_at, '
                    "accepted_by) SELECT '%s', organization_id, '%s', 'Firma RC-274', 'Prueba', '%s', "
                    "signed_document_key || '.rc274-%s', signed_document_sha256, %s, %s, %s, accepted_by "
                    "FROM domain_authorizations WHERE id = '41000000-0000-4000-8000-000000000001';"
                    % (nueva, dominio, correo, nueva[-2:], desde, hasta, revocada))
        ok, _, err = psql(sql + 'COMMIT;', user='postgres')
        self.assertTrue(ok, err)
        self.addCleanup(self.psql_o_falla, 'BEGIN; SET LOCAL session_replication_role = replica; '
                        'DELETE FROM domain_authorizations WHERE id IN (%s); COMMIT;'
                        % ', '.join("'%s'" % c[0] for c in cartas), 'quedaron las cartas de prueba de RC-274')
        cuerpo = self.get(self.acme, '/api/v1/domains')
        v1 = {x['fqdn']: x['authorization'] for x in cuerpo['items']}
        esperado = {
            'acme-demo.mx': ('valid', 'vigente.rc274@acme-demo.mx'),
            'old-example.net': ('expired', None),
            'partner-example.com': ('revoked', None),
        }
        for fqdn, (estado, correo) in esperado.items():
            with self.subTest(fqdn=fqdn):
                self.assertEqual((v1[fqdn]['status'], v1[fqdn]['signer_email']), (estado, correo), v1[fqdn])
                self.assertEqual(set(v1[fqdn]), {'status', 'valid_from', 'valid_until', 'signer_email'})
        self.assertEqual((v1['old-example.net']['valid_from'], v1['old-example.net']['valid_until']),
                         ('2025-08-15', '2026-08-15'), 'los demás campos no cambian')
        self.assertIsNotNone(v1['partner-example.com']['valid_until'], 'la revocada sigue dando sus fechas')
        texto = json.dumps(cuerpo)
        for correo in ('it@old-example.net', 'vencida.rc274@', 'revocada.rc274@'):
            self.assertNotIn(correo, texto, 'el correo de una carta que no está vigente no sale en ningún campo')

    @unittest.skipUnless(os.environ.get('HORA_BASE_FIJA') == '1',
                         'solo con la base en libfaketime (pruebas/hora_base, paso del CI de RC-313)')
    def test_1c_carta_que_empieza_manana_con_la_base_a_las_20(self):
        # RC-313, punto 3b. test_1b usa el reloj real y solo ejercita el caso de 18:00 a 24:00 de México. Aquí la base
        # corre con libfaketime a las 20:00 de México, que son las 02:00 UTC del día en que va la API, y la API sigue en
        # UTC con el reloj real. Así la API va un día delante de la base a cualquier hora en que corra el CI.
        ok, salida, err = psql("SELECT to_char(now() AT TIME ZONE 'America/Mexico_City', 'YYYY-MM-DD HH24:MI');",
                               user='postgres')
        self.assertTrue(ok, err)
        mexico = datetime.strptime(salida.strip(), '%Y-%m-%d %H:%M')
        self.assertEqual(mexico.hour, 20, 'la base no está fijada a las 20:00 de México: %s' % salida)
        api = subprocess.run(['docker', 'exec', os.environ.get('CIRDAN_TEST_API_CONTAINER', 'cirdan-api'), 'python',
                              '-c', 'import datetime, time; print(time.tzname[0], datetime.date.today())'],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(api.returncode, 0, api.stderr)
        zona, hoy_api = api.stdout.split()
        self.assertEqual(zona, 'UTC', 'la API debe ir en UTC')
        self.assertGreater(date.fromisoformat(hoy_api), mexico.date(),
                           'la API debe ir un día delante de la base (API %s, México %s)' % (hoy_api, mexico))
        self.test_1b_carta_que_empieza_manana_no_cuenta_como_vigente()

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
        # Certificados sale 'partial' antes de la caída: ese escaneo de la semilla no corrió web (RC-239).
        corrida = "UPDATE scan_source_runs SET status = '%s' WHERE id = '61000000-0000-4000-8000-000000000001';"
        antes = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
        kri = {k['kri']: k for k in antes['kris']}
        self.assertEqual((kri['certificates']['status'], kri['certificates']['findings'],
                          kri['certificates']['max_severity'], kri['certificates']['penalty']), ('partial', 1, 'high', 20.0))
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

    def test_4c_cortes_de_bandas_por_cliente_solo_admin_y_con_auditoria(self):
        # RC-237. Acme cambia sus cortes a 50, 70 y 85. acme-demo.mx tiene un crítico abierto: su piso pasa de 60 a 70,
        # que es banda alto y letra D. Al final se borra lo que dejó el PUT (juego de Acme, scores rules_change y la cola
        # de su audit_log), sin triggers y solo en esa transacción, y el global vuelve a ser el único juego.
        acme = '20000000-0000-4000-8000-000000000001'
        ok, seq, err = psql("SELECT coalesce(max(chain_seq), 0) FROM audit_log WHERE organization_id = '%s';" % acme,
                            user='postgres')
        self.assertTrue(ok, err)
        antes_pesos = self.get(self.acme, '/api/v1/scoring/weights')
        antes_score = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
        self.addCleanup(self.psql_o_falla,
                        "BEGIN; SET LOCAL session_replication_role = replica; "
                        "DELETE FROM score_contributions WHERE score_id IN (SELECT id FROM domain_scores "
                        "WHERE organization_id = '{o}' AND reason = 'rules_change'); "
                        "DELETE FROM domain_scores WHERE organization_id = '{o}' AND reason = 'rules_change'; "
                        "DELETE FROM scoring_rules WHERE rule_set_id IN (SELECT id FROM scoring_rule_sets "
                        "WHERE organization_id = '{o}'); "
                        "DELETE FROM scoring_rule_sets WHERE organization_id = '{o}'; "
                        "DELETE FROM audit_log WHERE organization_id = '{o}' AND chain_seq > {s}; COMMIT;"
                        .format(o=acme, s=int(seq)), 'quedó el juego de reglas de prueba de Acme (RC-237)')
        self.assertEqual((antes_pesos['band_cutoffs'], antes_score['score'], antes_score['grade']),
                         ({'medium': 40, 'high': 60, 'critical': 80}, 60, 'D'))
        pesos = dict(antes_pesos['category_weights'])
        nuevos = {'medium': 50, 'high': 70, 'critical': 85}

        # Solo admin: el analista y el gerente reciben 403 y no se crea nada.
        for correo in ('jordan.tate@acme-demo.mx', 'maya.reed@acme-demo.mx'):
            otro = sesion.login(correo)
            code, _ = otro.request('PUT', '/api/v1/scoring/weights',
                                   {'category_weights': pesos, 'band_cutoffs': nuevos})
            self.assertEqual(code, 403, correo)
        # Cortes que el CHECK rechaza: 422 y tampoco se crea nada.
        for malos in ({'medium': 9, 'high': 60, 'critical': 80}, {'medium': 40, 'high': 49, 'critical': 80},
                      {'medium': 40, 'high': 60, 'critical': 92}, {'medium': 60, 'high': 40, 'critical': 80},
                      {'medium': 40, 'high': 60}, {'medium': 40.5, 'high': 60, 'critical': 80},
                      {'medium': '40', 'high': 60, 'critical': 80}, {'medium': True, 'high': 60, 'critical': 80}):
            code, body = self.acme.request('PUT', '/api/v1/scoring/weights',
                                           {'category_weights': pesos, 'band_cutoffs': malos})
            self.assertEqual(code, 422, (malos, body))
        ok, juegos, err = psql("SELECT count(*) FROM scoring_rule_sets WHERE organization_id = '%s';" % acme,
                               user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual(int(juegos), 0)

        code, body = self.acme.request('PUT', '/api/v1/scoring/weights',
                                       {'category_weights': pesos, 'band_cutoffs': nuevos})
        self.assertEqual(code, 200, body)
        self.assertEqual((body['band_cutoffs'], body['unchanged'], body['recalculated_domains']), (nuevos, False, 3))
        score = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
        self.assertEqual((score['score'], score['band'], score['grade']), (70, 'high', 'D'))
        for c in score['categories']:   # cada categoría con los cortes del cliente
            self.assertEqual(c['band'], criterio.banda(c['score'], nuevos), c)
        demo = next(d for d in self.get(self.acme, '/api/v1/domains')['items'] if d['fqdn'] == 'acme-demo.mx')
        self.assertEqual((demo['score'], demo['band'], demo['grade']), (70, 'high', 'D'))
        plan = self.get(self.acme, '/api/v1/domains/acme-demo.mx/action-plan')
        self.assertEqual((plan['score_before'], plan['band_before']), (70, 'high'))
        # El después del plan también usa el piso del cliente: si el crítico sigue abierto, no baja de 70.
        ok, criticos, err = psql("SELECT DISTINCT r.code FROM findings f JOIN scoring_rules r ON r.id = f.rule_id "
                                 "JOIN domains d ON d.id = f.domain_id WHERE d.fqdn = 'acme-demo.mx' "
                                 "AND f.severity = 'critical' AND f.status = 'open';", user='postgres')
        self.assertTrue(ok, err)
        sin_critico = [a['id'] for a in plan['actions'] if a['id'] not in criticos.splitlines()]
        self.assertTrue(sin_critico, plan['actions'])
        code, simulado = self.acme.request('POST', '/api/v1/domains/acme-demo.mx/action-plan/simulate',
                                           {'action_ids': sin_critico})
        self.assertEqual(code, 200, simulado)
        self.assertEqual((simulado['score_before'], simulado['band_before'], simulado['score_after'],
                          simulado['band_after']), (70, 'high', 70, 'high'))
        activos =self.get(self.acme, '/api/v1/scoring/weights')
        self.assertEqual((activos['band_cutoffs'], activos['floor']['one_critical'],
                          activos['floor']['two_or_more_critical']), (nuevos, 70, 85))
        self.assertEqual([(b['band'], b['from'], b['to']) for b in activos['bands']],
                         [('low', 0, 49), ('medium', 50, 69), ('high', 70, 84), ('critical', 85, 100)])
        self.assertEqual([(g['grade'], g['from'], g['to']) for g in activos['grades']],
                         [('A', 0, 24), ('B', 25, 49), ('C', 50, 69), ('D', 70, 84), ('F', 85, 100)])
        self.assertEqual(activos['band_cutoffs_template'], {'medium': 40, 'high': 60, 'critical': 80})
        # El histórico se explica con los cortes de su propio juego: el 68 del escaneo sigue en D (con 50/70/85 sería C).
        hist = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score/history')['items']
        self.assertCountEqual([(p['score'], p['reason'], p['grade']) for p in hist],
                              [(70, 'rules_change', 'D'), (68, 'scan', 'D'), (60, 'correction', 'D')])
        # Beta no ve el cambio de Acme: sigue con la plantilla.
        self.assertEqual(self.get(self.beta, '/api/v1/scoring/weights')['band_cutoffs'],
                         {'medium': 40, 'high': 60, 'critical': 80})
        ok, salida, err = psql(
            "SELECT details->'band_cutoffs', details->'previous_band_cutoffs' FROM audit_log "
            "WHERE organization_id = '%s' AND action = 'scoring.weights_changed' AND chain_seq > %d;" % (acme, int(seq)),
            user='postgres')
        self.assertTrue(ok, err)
        filas = [linea.split('|') for linea in salida.splitlines()]
        self.assertEqual(len(filas), 1, salida)
        self.assertEqual((json.loads(filas[0][0]), json.loads(filas[0][1])),
                         (nuevos, {'medium': 40, 'high': 60, 'critical': 80}))
        # El mismo PUT otra vez no crea versión; sin band_cutoffs la versión nueva copia los de la anterior.
        code, body = self.acme.request('PUT', '/api/v1/scoring/weights',
                                       {'category_weights': pesos, 'band_cutoffs': nuevos})
        self.assertEqual((code, body['unchanged']), (200, True), body)
        otros = dict(zip(criterio.CATEGORIAS, (0.4, 0.2, 0.2, 0.2)))
        self.assertNotEqual(otros, pesos)
        code, body = self.acme.request('PUT', '/api/v1/scoring/weights', {'category_weights': otros})
        self.assertEqual((code, body['band_cutoffs'], body['unchanged']), (200, nuevos, False), body)
        ok, salida, err = psql("SELECT version, band_medium_from, band_high_from, band_critical_from "
                               "FROM scoring_rule_sets WHERE organization_id = '%s' ORDER BY version;" % acme,
                               user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual([linea.split('|')[1:] for linea in salida.splitlines()],
                         [['50', '70', '85'], ['50', '70', '85']])
        # Con 50, 80 y 90 el piso de un crítico es 80: alto y D para Acme, crítico y F con la plantilla. Así /domains,
        # /score y el histórico no pasan si usaran la plantilla.
        altos = {'medium': 50, 'high': 80, 'critical': 90}
        code, body = self.acme.request('PUT', '/api/v1/scoring/weights', {'category_weights': otros,
                                                                          'band_cutoffs': altos})
        self.assertEqual(code, 200, body)
        demo = next(d for d in self.get(self.acme, '/api/v1/domains')['items'] if d['fqdn'] == 'acme-demo.mx')
        score = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
        ultimo = [p for p in self.get(self.acme, '/api/v1/domains/acme-demo.mx/score/history')['items']
                  if p['score_id'] == score['score_id']]
        self.assertEqual((demo['score'], demo['band'], demo['grade']), (80, 'high', 'D'))
        self.assertEqual((score['score'], score['band'], score['grade']), (80, 'high', 'D'))
        self.assertEqual([(p['score'], p['grade']) for p in ultimo], [(80, 'D')])
        reporte = self.get(self.acme, '/api/v1/domains/acme-demo.mx/report?formato=json')['score']
        self.assertEqual((reporte['score'], reporte['band'], reporte['grade']), (80, 'high', 'D'))
        self.assertEqual((criterio.banda(80), criterio.letra(80)), ('critical', 'F'))

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

    def test_5b_escaneos_por_dominio_y_paginados(self):
        # RC-318. Un escaneo fallido de acme-tienda.mx y 60 de acme-demo.mx más nuevos: sin filtro, la página de 50 ya no
        # trae el fallido y con ?domain sí. Entran sin triggers (el de la autorización pide un TXT de menos de 1 hora),
        # solo en esa transacción, y se borran al final.
        fallido = '60000000-0000-4000-8000-000000318000'
        self.addCleanup(self.psql_o_falla, "DELETE FROM scans WHERE id::text LIKE '60000000-0000-4000-8000-000000318%';",
                        'quedaron escaneos de prueba de RC-318')
        self.psql_o_falla(
            "BEGIN; SET LOCAL session_replication_role = replica; "
            "INSERT INTO scans (id, organization_id, domain_id, authorization_id, txt_verification_id, trigger_type, "
            "status, queued_at, finished_at) VALUES ('%s', '20000000-0000-4000-8000-000000000001', "
            "'40000000-0000-4000-8000-000000000002', '41000000-0000-4000-8000-000000000002', "
            "'42000000-0000-4000-8000-000000000012', 'on_demand', 'failed', now() - interval '2 minutes', "
            "now() - interval '90 seconds'); "
            "INSERT INTO scans (id, organization_id, domain_id, authorization_id, txt_verification_id, trigger_type, "
            "status, queued_at, finished_at) SELECT ('60000000-0000-4000-8000-000000318' || lpad(g::text, 3, '0'))::uuid, "
            "'20000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000001', "
            "'41000000-0000-4000-8000-000000000001', '42000000-0000-4000-8000-000000000011', 'on_demand', 'completed', "
            "now() - g * interval '1 second', now() "
            "FROM generate_series(1, 60) g; COMMIT;" % fallido, 'no entraron los escaneos de prueba de RC-318')

        def cuantos(domain_id):
            ok, salida, err = psql("SELECT count(*) FROM scans WHERE domain_id = '%s';" % domain_id, user='postgres')
            self.assertTrue(ok, err)
            return int(salida)

        todos = self.get(self.acme, '/api/v1/scans')
        self.assertEqual((todos['limit'], todos['offset'], len(todos['items'])), (50, 0, 50))
        self.assertGreaterEqual(todos['total'], 61)
        self.assertNotIn(fallido, [s['id'] for s in todos['items']])
        # Lo que pide la página del dominio: el fallido sale, y total es el de la empresa con ese filtro.
        for fqdn in ('acme-tienda.mx', 'ACME-Tienda.mx'):
            tienda = self.get(self.acme, '/api/v1/scans?domain=%s&limit=5' % fqdn)
            self.assertEqual((tienda['total'], tienda['limit']), (cuantos('40000000-0000-4000-8000-000000000002'), 5))
            self.assertEqual({s['domain'] for s in tienda['items']}, {'acme-tienda.mx'})
            self.assertIn((fallido, 'failed'), [(s['id'], s['status']) for s in tienda['items']])
        demo = self.get(self.acme, '/api/v1/scans?domain=acme-demo.mx&limit=100')
        self.assertEqual(demo['total'], cuantos('40000000-0000-4000-8000-000000000001'))
        self.assertGreaterEqual(demo['total'], 60)
        self.assertEqual(len(demo['items']), min(100, demo['total']))
        # offset: dos páginas de 30 seguidas dan lo mismo que una de 60, sin repetir ni saltar ninguno.
        paginas = [self.get(self.acme, '/api/v1/scans?domain=acme-demo.mx&limit=30&offset=%d' % o)['items']
                   for o in (0, 30)]
        self.assertEqual([s['id'] for s in paginas[0] + paginas[1]], [s['id'] for s in demo['items']][:60])
        lejos = self.get(self.acme, '/api/v1/scans?domain=acme-demo.mx&offset=1000')
        self.assertEqual((lejos['items'], lejos['total']), ([], demo['total']))
        for consulta in ('limit=0', 'limit=101', 'offset=-1', 'offset=1000001', 'offset=99999999999999999999',
                         'limit=abc', 'domain='):
            self.assertEqual(self.acme.get('/api/v1/scans?' + consulta)[0], 422, consulta)
        # RLS sigue igual: otra empresa no ve los de Acme, con o sin filtro.
        otra = self.get(self.beta, '/api/v1/scans?domain=acme-tienda.mx')
        self.assertEqual((otra['items'], otra['total']), ([], 0))
        self.assertNotIn('acme', str(self.get(self.beta, '/api/v1/scans?limit=100')))

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
                    '&desde=a0000000-0000-4000-8000-000000000001&hasta=a0000000-0000-4000-8000-000000000004',
                    '/api/v1/domains/old-example.net/action-plan/export?formato=csv',  # RC-307
                    '/api/v1/domains/old-example.net/action-plan/export?formato=json'):
            code, body = self.acme.get(url)
            self.assertEqual(code, 403, (url, body))
            self.assertEqual(self.beta.get(url)[0], 404, url)
        self.assertEqual(self.beta.get('/api/v1/domains/acme-demo.mx/findings/export')[0], 404)
        self.assertEqual(self.get(self.beta, '/api/v1/domains/beta-corp.mx/findings/export')['domain'], 'beta-corp.mx')
        self.assertEqual(sesion.Client().get('/api/v1/domains/acme-demo.mx/findings/export')[0], 401)

    def test_9f_reporte_ejecutivo_json_html_y_403(self):
        # RC-70: 403 sin carta vigente (old-example.net venció el 15 ago 2026), 404 de otra empresa y 401 sin sesión.
        for formato in ('json', 'html'):
            url = '/api/v1/domains/old-example.net/report?formato=%s' % formato
            self.assertEqual(self.acme.get(url)[0], 403, url)
            self.assertEqual(self.beta.get(url)[0], 404, url)
            self.assertEqual(sesion.Client().get(url.replace('old-example.net', 'acme-demo.mx'))[0], 401, url)
        self.assertEqual(self.acme.get('/api/v1/domains/acme-demo.mx/report?formato=pdf')[0], 422)

        datos = self.get(self.acme, '/api/v1/domains/acme-demo.mx/report')
        hallazgos = self.get(self.acme, '/api/v1/domains/acme-demo.mx/findings')
        self.assertEqual(datos['domain'], 'acme-demo.mx')
        self.assertEqual(datos['total_open'], hallazgos['total'])
        self.assertEqual(sum(datos['open_findings'].values()), hallazgos['total'])
        self.assertEqual([h['title'] for h in datos['findings']], [h['title'] for h in hallazgos['items']][:8])
        self.assertTrue(all(h['action'] for h in datos['findings']))  # toda regla tiene recomendación (003)
        self.assertEqual(datos['score']['score'], self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')['score'])
        self.assertIn('Have I Been Pwned', next(a['text'] for a in datos['attributions'] if a['source'] == 'hibp'))
        self.assertLessEqual(datos['authorization']['valid_from'], datetime.now().date().isoformat())

        _, headers, texto = self.descargar(self.acme, '/api/v1/domains/acme-demo.mx/report?formato=html')
        self.assertTrue(headers['Content-Type'].startswith('text/html'))
        self.assertIn('attachment', headers['Content-Disposition'])
        self.assertIn("default-src 'none'", headers['Content-Security-Policy'])
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(headers['Cache-Control'], 'no-store')
        _, cabeceras_json, _ = self.descargar(self.acme, '/api/v1/domains/acme-demo.mx/report')
        self.assertEqual(cabeceras_json['Cache-Control'], 'no-store')
        self.assertIn('Have I Been Pwned', texto)
        for h in datos['findings']:
            self.assertIn(h['asset'], texto)
        # El resto de la API conserva su CSP de RC-283.
        _, otras, _ = self.descargar(self.acme, '/api/v1/domains/acme-demo.mx/findings/export?formato=json')
        self.assertEqual(otras['Content-Security-Policy'], "frame-ancestors 'none'")

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
        self.addCleanup(self.psql_o_falla, beta % 'active', 'Beta Corp se quedó suspendida')
        estado, cuerpo = self.beta.get('/api/v1/domains/beta-corp.mx/export/siem')[:2]
        # El texto dice que la empresa está suspendida, no que el plan no incluye SIEM (Beta Corp sí lo incluye).
        self.assertEqual((estado, cuerpo['detail']),
                         (403, 'La empresa está suspendida o cancelada: no puede exportar a SIEM'))
        self.psql_o_falla(beta % 'active', 'Beta Corp se quedó suspendida')
        # Una cuenta desactivada después de iniciar sesión ya no exporta: 401 y la sesión se borra (como las llaves).
        dana = "UPDATE users SET is_active = %s WHERE email = 'dana.cruz@beta-corp.mx';"
        vieja = sesion.login('dana.cruz@beta-corp.mx')
        self.psql_o_falla(dana % 'false', 'no se pudo desactivar a Dana')
        try:
            estado, cuerpo = vieja.get('/api/v1/domains/beta-corp.mx/export/siem')[:2]
        finally:
            self.psql_o_falla(dana % 'true', 'Dana se quedó desactivada')
        self.assertEqual((estado, cuerpo['detail']), (401, 'Tu sesión terminó. Vuelve a iniciar sesión.'))
        self.assertEqual(vieja.get('/api/v1/domains/beta-corp.mx/export/siem')[0], 401)
        # Con un escaneo del dominio en curso responde 409: sus fuentes ya guardaron hallazgos y el escaneo y el score
        # serían los anteriores. El trigger de la autorización pide un TXT de menos de 1 hora y dns_txt_verifications
        # no deja borrar, así que la fila del escaneo entra sin triggers (solo en esta transacción) y se borra al final.
        escaneo = "'60000000-0000-4000-8000-0000000000f1'"
        ok, _, err = psql(
            "BEGIN; SET LOCAL session_replication_role = replica; "
            "INSERT INTO scans (id, organization_id, domain_id, authorization_id, txt_verification_id, trigger_type, "
            "status) SELECT %s, organization_id, domain_id, id, '42000000-0000-4000-8000-000000000006', 'on_demand', "
            "'running' "
            "FROM domain_authorizations WHERE id = '41000000-0000-4000-8000-000000000006'; COMMIT;" % escaneo,
            user='postgres')
        self.assertTrue(ok, err)
        borrar = 'DELETE FROM scans WHERE id = %s;' % escaneo
        self.addCleanup(self.psql_o_falla, borrar, 'quedó un escaneo en curso de beta-corp.mx')
        estado, cuerpo = self.beta.get('/api/v1/domains/beta-corp.mx/export/siem')[:2]
        self.assertEqual(estado, 409, cuerpo)
        # Sin marca de vida en 30 minutos (la API se reinició a mitad), la exportación lo da por caído, como GET /scans.
        ok, _, err = psql("UPDATE scans SET updated_at = now() - interval '31 minutes' WHERE id = %s;" % escaneo,
                          user='postgres')
        self.assertTrue(ok, err)
        with self.beta.opener.open(url, timeout=10) as r:
            self.assertEqual(r.status, 200)
        ok, salida, err = psql('SELECT status FROM scans WHERE id = %s;' % escaneo, user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual(salida.strip(), 'failed')
        self.psql_o_falla(borrar, 'quedó un escaneo de prueba de beta-corp.mx')
        with self.beta.opener.open(url, timeout=10) as r:
            self.assertEqual(r.status, 200)
        # Acme tiene el plan starter, sin API ni SIEM. Un dominio de otra empresa responde 404 y sin sesión, 401.
        self.assertEqual(self.acme.get('/api/v1/domains/acme-demo.mx/export/siem')[0], 403)
        for fqdn in ('acme-demo.mx', 'olmardo.com'):
            self.assertEqual(self.beta.get('/api/v1/domains/%s/export/siem' % fqdn)[0], 404, fqdn)
        self.assertEqual(sesion.Client().get('/api/v1/domains/beta-corp.mx/export/siem')[0], 401)

if __name__ == '__main__':
    unittest.main(verbosity=2)
