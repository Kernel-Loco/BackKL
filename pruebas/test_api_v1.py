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

from cirdan.score import cobertura, criterio, subcategorias
from pruebas import sesion
from pruebas.pila import exigir_desechable
from pruebas.test_aislamiento import psql, scalar

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

    # RC-316: un crítico de acme-demo.mx abierto después de su score, y la brecha que sí tiene el score.
    CRITICO_NUEVO = '80000000-0000-4000-8000-000000000316'
    BRECHA = '80000000-0000-4000-8000-000000000001'
    INSERTAR_CRITICO_NUEVO = '''
            INSERT INTO findings (id, organization_id, domain_id, asset_id, rule_id, source_id, fingerprint,
                                  severity, status, evidence, detected_at)
            SELECT '%s', d.organization_id, d.id,
                   (SELECT a.id FROM assets a WHERE a.domain_id = d.id ORDER BY a.id LIMIT 1),
                   (SELECT r.id FROM scoring_rules r WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001'
                       AND r.code = 'breach_exposure'),
                   (SELECT s.id FROM data_sources s WHERE s.code = 'dns'),
                   sha256('rc316-critico-nuevo'), 'critical', 'open', '{"title": "Crítico nuevo de prueba"}', now()
              FROM domains d WHERE d.fqdn = 'acme-demo.mx';
        ''' % CRITICO_NUEVO

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
                    'signer_email, signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by, '
                    'template_version, activities) '
                    "SELECT '%s', organization_id, domain_id, signer_name, signer_title, signer_email, "
                    "signed_document_key || '.rc313', signed_document_sha256, %s + 1, %s + %d, accepted_by, "
                    "template_version, activities "
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
                    "accepted_by, template_version, activities) SELECT '%s', organization_id, '%s', 'Firma RC-274', 'Prueba', '%s', "
                    "signed_document_key || '.rc274-%s', signed_document_sha256, %s, %s, %s, accepted_by, "
                    "template_version, activities "
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
                self.assertEqual(set(v1[fqdn]), {'status', 'valid_from', 'valid_until', 'signer_email',
                                                 'template_version', 'activities'})
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
        exigir_desechable()
        api = subprocess.run(['docker', 'exec', os.environ.get('CIRDAN_TEST_API_CONTAINER', 'cirdan-api'), 'python',
                              '-c', 'import datetime, time; print(time.tzname[0], datetime.date.today())'],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(api.returncode, 0, api.stderr)
        zona, hoy_api = api.stdout.split()
        self.assertEqual(zona, 'UTC', 'la API debe ir en UTC')
        self.assertGreater(date.fromisoformat(hoy_api), mexico.date(),
                           'la API debe ir un día delante de la base (API %s, México %s)' % (hoy_api, mexico))
        self.test_1b_carta_que_empieza_manana_no_cuenta_como_vigente()

    def test_1e_open_findings_con_la_severidad_del_ultimo_score(self):
        # RC-229. Se guardan dos scores de acme-demo.mx, copias del último. En el primero dos hallazgos abiertos no
        # críticos tienen aporte 'critical'. El segundo, el más nuevo, deja 'critical' al primero (otro) y no trae
        # aporte del segundo (omitido). /domains, /findings y la explicación usan el último score: otro sale
        # 'critical' y omitido con su severidad de findings, no con la del score anterior. Las dos tablas son de solo
        # inserción: las filas de prueba se borran al final sin triggers, como en test_3a.
        antes = next(d for d in self.get(self.acme, '/api/v1/domains')['items'] if d['fqdn'] == 'acme-demo.mx')
        viejo = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')['score_id']
        medio = '70000000-0000-4000-8000-000000000228'
        nuevo = '70000000-0000-4000-8000-000000000229'
        ok, salida, err = psql(f"""
            BEGIN;
            INSERT INTO domain_scores (id, organization_id, domain_id, scan_id, rule_set_id, score, category_scores,
                                       reason, method, model_version, model_fallback_reason, partial_coverage,
                                       computed_at)
            SELECT v.id, organization_id, domain_id, scan_id, rule_set_id, score, category_scores, reason, method,
                   model_version, v.motivo, partial_coverage, computed_at + v.paso
              FROM domain_scores, (VALUES ('{medio}'::uuid, NULL, interval '1 second'),
                                          ('{nuevo}'::uuid, 'artefacto_ml_no_disponible', interval '2 seconds'))
                                   v(id, motivo, paso)
             WHERE domain_scores.id = '{viejo}';
            CREATE TEMP TABLE rc229_otro ON COMMIT DROP AS
            SELECT x.finding_id, row_number() OVER (ORDER BY x.finding_id) AS n
              FROM score_contributions x JOIN findings f ON f.id = x.finding_id
             WHERE x.score_id = '{viejo}' AND x.severity <> 'critical' AND f.severity <> 'critical'
               AND f.status = 'open' ORDER BY x.finding_id LIMIT 2;
            INSERT INTO score_contributions (organization_id, score_id, finding_id, rule_id, penalty, severity, factors)
            SELECT organization_id, s.id, x.finding_id, rule_id, penalty,
                   CASE WHEN o.n = 1 OR (o.n = 2 AND s.id = '{medio}') THEN 'critical' ELSE severity END, factors
              FROM score_contributions x LEFT JOIN rc229_otro o ON o.finding_id = x.finding_id,
                   (VALUES ('{medio}'::uuid), ('{nuevo}'::uuid)) s(id)
             WHERE x.score_id = '{viejo}' AND NOT (coalesce(o.n, 0) = 2 AND s.id = '{nuevo}');
            SELECT string_agg(finding_id::text, ' ' ORDER BY n) FROM rc229_otro;
            COMMIT;""", user='postgres')
        self.assertTrue(ok, err)
        try:
            otro, omitido = (salida.split() + ['', ''])[:2]
            self.assertRegex(omitido, r'^[0-9a-f-]{36}$', 'no hay dos hallazgos abiertos no críticos con aporte')
            dominio = next(d for d in self.get(self.acme, '/api/v1/domains')['items'] if d['fqdn'] == 'acme-demo.mx')
            lista = self.get(self.acme, '/api/v1/domains/acme-demo.mx/findings')['items']
            conteo = {s: 0 for s in ('critical', 'high', 'medium', 'low')}
            for item in lista:
                conteo[item['severity']] += 1
            self.assertEqual(dominio['open_findings'], conteo)
            self.assertEqual(dominio['open_findings']['critical'], antes['open_findings']['critical'] + 1)
            self.assertEqual(next(i['severity'] for i in lista if i['id'] == otro), 'critical')
            # sin aporte en el último score vale su severidad de findings, no la 'critical' del score anterior
            ok, propia, err = psql(f"SELECT severity FROM findings WHERE id = '{omitido}'", user='postgres')
            self.assertTrue(ok, err)
            self.assertNotEqual(propia, 'critical')
            self.assertEqual(next(i['severity'] for i in lista if i['id'] == omitido), propia)
            self.assertEqual(self.get(self.acme, '/api/v1/findings/%s/explanation' % omitido)['severity'], propia)
            # la explicación del hallazgo lleva el motivo de caída del último score (RC-229)
            exp = self.get(self.acme, '/api/v1/findings/%s/explanation' % otro)
            self.assertEqual((exp['score_id'], exp['severity'], exp['model_fallback_reason']),
                             (nuevo, 'critical', 'artefacto_ml_no_disponible'))
        finally:
            self.psql_o_falla(f"BEGIN; SET LOCAL session_replication_role = replica; "
                              f"DELETE FROM score_contributions WHERE score_id IN ('{medio}', '{nuevo}'); "
                              f"DELETE FROM domain_scores WHERE id IN ('{medio}', '{nuevo}'); COMMIT;",
                              'quedó el score de prueba de RC-229')
        despues = next(d for d in self.get(self.acme, '/api/v1/domains')['items'] if d['fqdn'] == 'acme-demo.mx')
        self.assertEqual(despues['open_findings'], antes['open_findings'])

    def test_2b_cvss_epss_y_kev_del_catalogo_de_cves(self):
        # RC-229 punto 2. Ningún hallazgo de la semilla trae CVE. Se abren dos known_vulnerability en acme-demo.mx: uno
        # con su CVE completo en cves (CVSS, EPSS y KEV) y otro con el CVE solo como stub, como lo deja un recolector
        # (migración 014), con el CVSS en la evidencia. /findings da los tres campos que pinta el panel del portal.
        # in_kev solo es true o false si el cargador diario pasó por la fila (intel_updated_at). El stub, con el
        # in_kev = false por omisión de la tabla, da null, y una CVE revisada que no está en KEV da false.
        completo, stub = '80000000-0000-4000-8000-000000002291', '80000000-0000-4000-8000-000000002292'
        fuera = '80000000-0000-4000-8000-000000002293'
        cve_completo, cve_stub, cve_fuera = 'CVE-2099-22901', 'CVE-2099-22902', 'CVE-2099-22903'
        borrar = (f"DELETE FROM findings WHERE id IN ('{completo}', '{stub}', '{fuera}'); "
                  f"DELETE FROM cves WHERE cve_id IN ('{cve_completo}', '{cve_stub}', '{cve_fuera}');")
        ok, _, err = psql(f"""
            BEGIN;
            INSERT INTO cves (cve_id, cvss_base_score, epss_score, in_kev, intel_updated_at)
            VALUES ('{cve_completo}', 9.8, 0.00043, true, now()), ('{cve_stub}', NULL, NULL, false, NULL),
                   ('{cve_fuera}', 5.3, 0.001, false, now());
            INSERT INTO findings (id, organization_id, domain_id, asset_id, rule_id, source_id, fingerprint,
                                  severity, status, cve_id, evidence, detected_at)
            SELECT v.id::uuid, d.organization_id, d.id,
                   (SELECT a.id FROM assets a WHERE a.domain_id = d.id ORDER BY a.id LIMIT 1),
                   (SELECT r.id FROM scoring_rules r WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001'
                       AND r.code = 'known_vulnerability'),
                   (SELECT s.id FROM data_sources s WHERE s.code = 'shodan'),
                   sha256(convert_to('rc229-' || v.cve, 'UTF8')), 'medium', 'open', v.cve, v.evidencia::jsonb, now()
              FROM domains d, (VALUES ('{completo}', '{cve_completo}', '{{"title": "CVE con CVSS, EPSS y KEV"}}'),
                                      ('{stub}', '{cve_stub}', '{{"title": "CVE sin intel", "cvss": 7.5}}'),
                                      ('{fuera}', '{cve_fuera}', '{{"title": "CVE revisada fuera de KEV"}}'))
                              v(id, cve, evidencia)
             WHERE d.fqdn = 'acme-demo.mx';
            COMMIT;""", user='postgres')
        self.assertTrue(ok, err)
        try:
            lista = {i['id']: i for i in self.get(self.acme, '/api/v1/domains/acme-demo.mx/findings')['items']}
            campos = ('cve_id', 'cvss', 'epss', 'in_kev')
            self.assertEqual(tuple(lista[completo][c] for c in campos), (cve_completo, 9.8, 0.00043, True))
            self.assertEqual(tuple(lista[stub][c] for c in campos), (cve_stub, 7.5, None, None))
            self.assertEqual(tuple(lista[fuera][c] for c in campos), (cve_fuera, 5.3, 0.001, False))
        finally:
            self.psql_o_falla(borrar, 'quedaron los hallazgos con CVE de prueba de RC-229')

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

    def test_3a_el_piso_se_explica_con_los_criticos_del_snapshot(self):
        # RC-316. El score de acme-demo.mx se guardó con 1 crítico (la brecha 80…01). Primero se abre otro crítico
        # después del score, luego se resuelve a mano la brecha y al final se juntan los dos (1 contra 1). En los tres
        # casos el piso, su mensaje y el score son los del snapshot, critical_open cuenta los de ahora y needs_rescan
        # sale en true, porque compara cuáles críticos y no cuántos. Todo se regresa.
        url = '/api/v1/domains/acme-demo.mx/score'
        antes = self.get(self.acme, url)
        self.assertEqual((antes['critical_open'], antes['critical_at_time'], antes['needs_rescan']), (1, 1, False))
        del_snapshot = {c: antes[c] for c in ('score', 'band', 'grade', 'weighted', 'floor', 'floor_applied',
                                              'floor_message', 'alert')}
        self.assertEqual(antes['floor_message'], 'Subido a 60 por 1 hallazgo crítico vigente; la suma ponderada da 28.')
        nuevo, brecha = self.CRITICO_NUEVO, self.BRECHA
        insertar = self.INSERTAR_CRITICO_NUEVO
        borrar = "DELETE FROM findings WHERE id = '%s';" % nuevo
        ok, _, err = psql(insertar, user='postgres')
        self.assertTrue(ok, err)
        try:
            con_nuevo = self.get(self.acme, url)
            self.assertEqual((con_nuevo['critical_open'], con_nuevo['critical_at_time'], con_nuevo['needs_rescan']),
                             (2, 1, True))
            self.assertEqual({c: con_nuevo[c] for c in del_snapshot}, del_snapshot)
        finally:
            self.psql_o_falla(borrar, 'no se borró el crítico de prueba')
        self.psql_o_falla("UPDATE findings SET status = 'resolved', resolved_at = now() WHERE id = '%s';" % brecha,
                          'no se resolvió la brecha')
        try:
            resuelto = self.get(self.acme, url)
            self.assertEqual((resuelto['critical_open'], resuelto['critical_at_time'], resuelto['needs_rescan']),
                             (0, 1, True))
            self.assertEqual({c: resuelto[c] for c in del_snapshot}, del_snapshot)
            # Brecha resuelta más un crítico nuevo: la cuenta queda 1 contra 1, pero ya no es el mismo hallazgo.
            ok, _, err = psql(insertar, user='postgres')
            self.assertTrue(ok, err)
            try:
                cambiado = self.get(self.acme, url)
                self.assertEqual((cambiado['critical_open'], cambiado['critical_at_time'], cambiado['needs_rescan']),
                                 (1, 1, True))
                self.assertEqual({c: cambiado[c] for c in del_snapshot}, del_snapshot)
            finally:
                self.psql_o_falla(borrar, 'no se borró el crítico de prueba')
        finally:
            self.psql_o_falla("UPDATE findings SET status = 'open', resolved_at = NULL WHERE id = '%s';" % brecha,
                              'no se regresó la brecha a open')
        self.assertEqual(self.get(self.acme, url), antes)

    def test_3a_ml_needs_rescan_usa_la_severidad_del_modelo(self):
        # RC-316. En un score 'ml', score_contributions guarda la severidad que predijo el modelo. Se guarda un score
        # 'ml' de acme-demo.mx, copia del último, en el que el modelo predijo high para la brecha (critical en
        # findings) y critical para otro hallazgo vigente que en findings no lo es. Los críticos de ahora se juzgan
        # con la severidad del aporte: 1 contra 1, el mismo hallazgo y needs_rescan en false. Un crítico nuevo sin
        # aporte cuenta con la de findings y sí lo pone en true. Las dos tablas son de solo inserción: las filas de
        # prueba se borran al final sin triggers, solo en esa transacción, y el score vuelve a ser el de antes.
        url = '/api/v1/domains/acme-demo.mx/score'
        antes = self.get(self.acme, url)
        self.assertEqual((antes['method'], antes['critical_at_time'], antes['needs_rescan']), ('rules', 1, False))
        viejo, ml = antes['score_id'], '70000000-0000-4000-8000-000000000316'
        ok, otro, err = psql(f'''
            BEGIN;
            INSERT INTO domain_scores (id, organization_id, domain_id, scan_id, rule_set_id, score, category_scores,
                                       reason, method, model_version, partial_coverage, computed_at)
            SELECT '{ml}', organization_id, domain_id, scan_id, rule_set_id, score, category_scores, reason, 'ml',
                   'rc316-prueba', partial_coverage, computed_at + interval '1 second'
              FROM domain_scores WHERE id = '{viejo}';
            CREATE TEMP TABLE rc316_otro ON COMMIT DROP AS
            SELECT x.finding_id FROM score_contributions x JOIN findings f ON f.id = x.finding_id
             WHERE x.score_id = '{viejo}' AND x.severity <> 'critical' AND f.severity <> 'critical'
               AND f.status IN ('open', 'accepted_risk')
             ORDER BY x.finding_id LIMIT 1;
            INSERT INTO score_contributions (organization_id, score_id, finding_id, rule_id, penalty, severity, factors)
            SELECT organization_id, '{ml}', finding_id, rule_id, penalty,
                   CASE WHEN finding_id = '{self.BRECHA}' THEN 'high'
                        WHEN finding_id IN (SELECT finding_id FROM rc316_otro) THEN 'critical'
                        ELSE severity END, factors
              FROM score_contributions WHERE score_id = '{viejo}';
            SELECT finding_id FROM rc316_otro;
            COMMIT;''', user='postgres')
        self.assertTrue(ok, err)
        try:
            self.assertRegex(otro, r'^[0-9a-f-]{36}$', 'no hay otro hallazgo vigente no crítico con aporte')
            predicho = self.get(self.acme, url)
            self.assertEqual((predicho['score_id'], predicho['method'], predicho['model_version']),
                             (ml, 'ml', 'rc316-prueba'))
            self.assertEqual((predicho['critical_open'], predicho['critical_at_time'], predicho['needs_rescan']),
                             (1, 1, False))
            self.assertEqual(predicho['floor_message'], antes['floor_message'])
            ok, _, err = psql(self.INSERTAR_CRITICO_NUEVO, user='postgres')
            self.assertTrue(ok, err)
            try:
                con_nuevo = self.get(self.acme, url)
                self.assertEqual((con_nuevo['critical_open'], con_nuevo['critical_at_time'],
                                  con_nuevo['needs_rescan']), (2, 1, True))
            finally:
                self.psql_o_falla("DELETE FROM findings WHERE id = '%s';" % self.CRITICO_NUEVO,
                                  'no se borró el crítico de prueba')
        finally:
            self.psql_o_falla(f"BEGIN; SET LOCAL session_replication_role = replica; "
                              f"DELETE FROM score_contributions WHERE score_id = '{ml}'; "
                              f"DELETE FROM domain_scores WHERE id = '{ml}'; COMMIT;",
                              'quedó el score ml de prueba de RC-316')
        self.assertEqual(self.get(self.acme, url), antes)

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

    def test_3c3_codigos_sin_cobertura_con_su_fuente_y_su_motivo(self):
        # RC-229. ct_logs cae, Shodan dice en su raw_payload qué no revisó y qué le faltó por la llave, dns deja un
        # código en rules_without_coverage y whois queda en sources_partial. exposed_iot_device y exposed_rdp van solo
        # en el raw_payload, así la prueba falla si no se lee. Todo vuelve como estaba al terminar.
        url = '/api/v1/domains/acme-demo.mx/score'
        antes = self.get(self.acme, url)
        self.assertEqual({(h['source'], h['reason']) for h in antes['coverage_gaps']},
                         {('api_docs', 'source_not_run'), ('github', 'source_not_run'), ('identity', 'source_not_run'),
                          ('web', 'source_not_run')})
        corrida = "UPDATE scan_source_runs SET %s WHERE id = '61000000-0000-4000-8000-0000000000%s';"
        escaneo = "UPDATE scans SET stats = %s WHERE id = '60000000-0000-4000-8000-000000000001';"
        ok, _, err = psql(corrida % ("status = 'failed'", '01')
                          + corrida % ("""raw_payload = raw_payload || '{"sin_cobertura": ["exposed_iot_device", """
                                       """"exposed_rdp"], "sin_llave": ["exposed_iot_device"]}'""", '04')
                          + escaneo % ("""stats || '{"rules_without_coverage": ["dmarc_missing"], """
                                       """"sources_partial": ["whois"]}'"""),
                          user='postgres')
        self.assertTrue(ok, err)
        try:
            huecos = self.get(self.acme, url)['coverage_gaps']
            por_fuente = {}
            for h in huecos:
                por_fuente.setdefault((h['source'], h['reason']), []).append(h['code'])
            self.assertIn('lookalike_domain', por_fuente[('ct_logs', 'source_failed')])
            self.assertEqual(por_fuente[('shodan', 'no_api_key')], ['exposed_iot_device'])
            self.assertEqual(por_fuente[('shodan', 'source_partial')], ['exposed_rdp'])
            self.assertEqual(sorted(por_fuente[('whois', 'partially_checked')]), sorted(cobertura.codigos_de('whois')))
            # dns no guarda sin_cobertura en la semilla: su código de rules_without_coverage se le da por CODIGOS
            self.assertEqual(por_fuente[('dns', 'source_partial')], ['dmarc_missing'])
            self.assertEqual([h['code'] for h in huecos], sorted(h['code'] for h in huecos))
        finally:
            ok, _, err = psql(corrida % ("status = 'succeeded'", '01')
                              + corrida % ("raw_payload = raw_payload - 'sin_cobertura' - 'sin_llave'", '04')
                              + escaneo % "stats - 'rules_without_coverage' - 'sources_partial'", user='postgres')
            self.assertTrue(ok, err)
        self.assertEqual(self.get(self.acme, url), antes)

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
                      'rule_title', 'meaning', 'recommendation', 'model_fallback_reason'):
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

    def test_4d_mismos_pesos_ponen_al_dia_un_score_con_otro_juego(self):
        # RC-310. Acme cambia sus pesos y después queda como último score de acme-demo.mx una copia del de la semilla, con
        # el juego global, como el de un escaneo que cerró con los pesos de antes. El mismo PUT otra vez no crea versión,
        # pero recalcula ese dominio con el juego activo y lo deja en audit_log. Uno más ya responde 'unchanged'.
        acme = '20000000-0000-4000-8000-000000000001'
        ok, seq, err = psql("SELECT coalesce(max(chain_seq), 0) FROM audit_log WHERE organization_id = '%s';" % acme,
                            user='postgres')
        self.assertTrue(ok, err)
        antes = self.get(self.acme, '/api/v1/scoring/weights')
        self.addCleanup(self.psql_o_falla,
                        "BEGIN; SET LOCAL session_replication_role = replica; "
                        "DELETE FROM score_contributions WHERE score_id IN (SELECT id FROM domain_scores "
                        "WHERE organization_id = '{o}' AND reason = 'rules_change'); "
                        "DELETE FROM domain_scores WHERE organization_id = '{o}' AND reason = 'rules_change'; "
                        "DELETE FROM scoring_rules WHERE rule_set_id IN (SELECT id FROM scoring_rule_sets "
                        "WHERE organization_id = '{o}'); "
                        "DELETE FROM scoring_rule_sets WHERE organization_id = '{o}'; "
                        "DELETE FROM audit_log WHERE organization_id = '{o}' AND chain_seq > {s}; COMMIT;"
                        .format(o=acme, s=int(seq)), 'quedó el juego de reglas de prueba de Acme (RC-310)')
        otros = dict(zip(criterio.CATEGORIAS, (0.4, 0.2, 0.2, 0.2)))
        self.assertNotEqual(otros, antes['category_weights'])
        code, body = self.acme.request('PUT', '/api/v1/scoring/weights', {'category_weights': otros})
        self.assertEqual((code, body['unchanged']), (200, False), body)
        version = body['rule_set_version']
        self.assertNotEqual(version, antes['rule_set_version'])

        # El score de la semilla para acme-demo.mx, con el juego global, otra vez como el último y como 'scan'.
        ok, copia, err = psql(
            "WITH semilla AS (SELECT s.* FROM domain_scores s JOIN domains d ON d.id = s.domain_id "
            "  WHERE s.organization_id = '{o}' AND d.fqdn = 'acme-demo.mx' AND s.reason <> 'rules_change' "
            "  ORDER BY s.computed_at DESC, s.created_at DESC, s.id DESC LIMIT 1), "
            "nuevo AS (INSERT INTO domain_scores (organization_id, domain_id, scan_id, rule_set_id, score, "
            "  category_scores, reason, method, model_version, model_fallback_reason, partial_coverage, computed_at) "
            "  SELECT organization_id, domain_id, scan_id, rule_set_id, score, category_scores, 'scan', method, "
            "  model_version, model_fallback_reason, partial_coverage, clock_timestamp() FROM semilla "
            "  RETURNING id), "
            "aportes AS (INSERT INTO score_contributions (organization_id, score_id, finding_id, rule_id, penalty, "
            "  severity, factors) SELECT c.organization_id, nuevo.id, c.finding_id, c.rule_id, c.penalty, "
            "  c.severity, c.factors FROM score_contributions c, nuevo, semilla WHERE c.score_id = semilla.id) "
            "SELECT nuevo.id::text FROM nuevo;".format(o=acme), user='postgres')
        self.assertTrue(ok and copia, err)
        self.addCleanup(self.psql_o_falla,
                        "BEGIN; SET LOCAL session_replication_role = replica; "
                        "DELETE FROM score_contributions WHERE score_id = '{c}'; "
                        "DELETE FROM domain_scores WHERE id = '{c}'; COMMIT;".format(c=copia),
                        'quedó la copia del score de la semilla (RC-310)')
        score = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
        self.assertEqual((score['score_id'], score['rule_set_version']), (copia, antes['rule_set_version']))

        code, body = self.acme.request('PUT', '/api/v1/scoring/weights', {'category_weights': otros})
        self.assertEqual(code, 200, body)
        self.assertEqual((body['rule_set_version'], body['unchanged'], body['recalculated_domains']),
                         (version, False, 1))
        score = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
        self.assertNotEqual(score['score_id'], copia)
        self.assertEqual(score['rule_set_version'], version)
        ok, salida, err = psql(
            "SELECT version FROM scoring_rule_sets WHERE organization_id = '%s';" % acme, user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual(salida.splitlines(), [str(version)])  # no se creó otra versión
        ok, salida, err = psql(
            "SELECT action, details->>'version', details->>'recalculated_domains' FROM audit_log "
            "WHERE organization_id = '%s' AND chain_seq > %d AND action LIKE 'scoring.%%' ORDER BY chain_seq;"
            % (acme, int(seq)), user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual([linea.split('|') for linea in salida.splitlines()],
                         [['scoring.weights_changed', str(version), '3'],
                          ['scoring.scores_recalculated', str(version), '1']])

        code, body = self.acme.request('PUT', '/api/v1/scoring/weights', {'category_weights': otros})
        self.assertEqual((code, body['unchanged'], body['recalculated_domains']), (200, True, 0), body)

    def test_4e_mismos_pesos_saltan_un_score_ml_sin_severidades_y_siguen_con_los_demas(self):
        # RC-310. Después de un cambio de pesos, el último score de acme-demo.mx es uno 'ml' con el juego global y sin
        # severidades congeladas (como cuando un hallazgo llegó en un escaneo que se cayó), y el de acme-tienda.mx
        # uno 'scan' con el juego global. El mismo PUT otra vez responde 200: salta acme-demo.mx, lo cuenta en
        # skipped_domains y pone al día acme-tienda.mx. Antes respondía 409 y no ponía al día a ninguno.
        acme = '20000000-0000-4000-8000-000000000001'
        demo = '40000000-0000-4000-8000-000000000001'
        ok, seq, err = psql("SELECT coalesce(max(chain_seq), 0) FROM audit_log WHERE organization_id = '%s';" % acme,
                            user='postgres')
        self.assertTrue(ok, err)
        antes = self.get(self.acme, '/api/v1/scoring/weights')
        self.addCleanup(self.psql_o_falla,
                        "BEGIN; SET LOCAL session_replication_role = replica; "
                        "DELETE FROM score_contributions WHERE score_id IN (SELECT id FROM domain_scores "
                        "WHERE organization_id = '{o}' AND reason = 'rules_change'); "
                        "DELETE FROM domain_scores WHERE organization_id = '{o}' AND reason = 'rules_change'; "
                        "DELETE FROM scoring_rules WHERE rule_set_id IN (SELECT id FROM scoring_rule_sets "
                        "WHERE organization_id = '{o}'); "
                        "DELETE FROM scoring_rule_sets WHERE organization_id = '{o}'; "
                        "DELETE FROM audit_log WHERE organization_id = '{o}' AND chain_seq > {s}; COMMIT;"
                        .format(o=acme, s=int(seq)), 'quedó el juego de reglas de prueba de Acme (RC-310)')
        otros = dict(zip(criterio.CATEGORIAS, (0.4, 0.2, 0.2, 0.2)))
        code, body = self.acme.request('PUT', '/api/v1/scoring/weights', {'category_weights': otros})
        self.assertEqual((code, body['unchanged'], body['recalculated_domains']), (200, False, 3), body)
        version = body['rule_set_version']

        # Copias de los scores de la semilla, con el juego global, otra vez como los últimos de los dos dominios.
        ok, copias, err = psql(
            "WITH semilla AS (SELECT DISTINCT ON (s.domain_id) s.*, d.fqdn FROM domain_scores s "
            "  JOIN domains d ON d.id = s.domain_id WHERE s.organization_id = '{o}' "
            "  AND d.fqdn IN ('acme-demo.mx', 'acme-tienda.mx') AND s.reason <> 'rules_change' "
            "  ORDER BY s.domain_id, s.computed_at DESC, s.created_at DESC, s.id DESC) "
            "INSERT INTO domain_scores (organization_id, domain_id, scan_id, rule_set_id, score, category_scores, "
            "  reason, method, model_version, model_fallback_reason, partial_coverage, computed_at) "
            "SELECT organization_id, domain_id, scan_id, rule_set_id, score, category_scores, 'scan', "
            "  CASE WHEN fqdn = 'acme-demo.mx' THEN 'ml' ELSE 'rules' END, "
            "  CASE WHEN fqdn = 'acme-demo.mx' THEN 'v-prueba-rc310' END, NULL, partial_coverage, clock_timestamp() "
            "FROM semilla RETURNING id::text;".format(o=acme), user='postgres')
        copias = copias.split()
        self.assertTrue(ok and len(copias) == 2, err or copias)
        self.addCleanup(self.psql_o_falla,
                        "BEGIN; SET LOCAL session_replication_role = replica; "
                        "DELETE FROM domain_scores WHERE id IN ({c}); COMMIT;"
                        .format(c=', '.join("'%s'" % c for c in copias)),
                        'quedaron las copias de los scores de la semilla (RC-310)')
        demo_ml = self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')
        self.assertIn(demo_ml['score_id'], copias)
        self.assertEqual(demo_ml['rule_set_version'], antes['rule_set_version'])

        code, body = self.acme.request('PUT', '/api/v1/scoring/weights', {'category_weights': otros})
        self.assertEqual(code, 200, body)
        self.assertEqual((body['rule_set_version'], body['unchanged'], body['recalculated_domains'],
                          body['skipped_domains']), (version, False, 1, 1))
        self.assertEqual(self.get(self.acme, '/api/v1/domains/acme-demo.mx/score')['score_id'], demo_ml['score_id'])
        tienda = self.get(self.acme, '/api/v1/domains/acme-tienda.mx/score')
        self.assertNotIn(tienda['score_id'], copias)
        self.assertEqual(tienda['rule_set_version'], version)
        ok, salida, err = psql(
            "SELECT details->>'recalculated_domains', details->>'skipped_domains', details->'skipped_domain_ids' "
            "FROM audit_log WHERE organization_id = '%s' AND chain_seq > %d "
            "AND action = 'scoring.scores_recalculated';" % (acme, int(seq)), user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual([linea.split('|') for linea in salida.splitlines()], [['1', '1', '["%s"]' % demo]])

        # Sigue saltando acme-demo.mx, pero ya no hay nada que poner al día.
        code, body = self.acme.request('PUT', '/api/v1/scoring/weights', {'category_weights': otros})
        self.assertEqual((code, body['unchanged'], body['recalculated_domains'], body['skipped_domains']),
                         (200, True, 0, 1), body)

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

    def test_5c_escaneos_sin_el_costo_interno(self):
        # RC-87: el orquestador guarda en scans.stats las consultas y los segundos de cada fuente, pero GET /api/v1/scans
        # y GET /api/v1/scans/{id} no los entregan. Las llaves de antes salen igual (RC-229 las lee). El escaneo de la
        # semilla no trae ese costo: se le pone y se le quita al terminar.
        escaneo = '60000000-0000-4000-8000-000000000001'
        internas = {'queries', 'queries_by_source', 'seconds_by_source', 'duration_seconds'}

        def de_la_lista():
            items = self.get(self.acme, '/api/v1/scans?domain=acme-demo.mx&limit=100')['items']
            return next(s for s in items if s['id'] == escaneo)

        antes = self.get(self.acme, '/api/v1/scans/' + escaneo)['stats']
        self.assertTrue(antes)
        self.assertFalse(internas & set(antes), antes)
        self.assertEqual(de_la_lista()['stats'], antes)
        costo = ('{"queries": 5, "queries_by_source": {"ct_logs": 4, "dns": 1}, '
                 '"seconds_by_source": {"ct_logs": 8.0, "dns": 0.5}, "duration_seconds": 1868.5}')
        self.addCleanup(self.psql_o_falla, "UPDATE scans SET stats = stats - '%s'::text[] WHERE id = '%s';"
                        % ('{' + ','.join(sorted(internas)) + '}', escaneo),
                        'el escaneo de la semilla se quedó con el costo de prueba')
        self.psql_o_falla("UPDATE scans SET stats = stats || '%s'::jsonb WHERE id = '%s';" % (costo, escaneo),
                          'no entró el costo de prueba')
        ok, salida, err = psql("SELECT stats->>'queries' FROM scans WHERE id = '%s';" % escaneo, user='postgres')
        self.assertEqual((ok, salida.strip()), (True, '5'), err)
        for ruta, stats in (('/scans/{id}', self.get(self.acme, '/api/v1/scans/' + escaneo)['stats']),
                            ('/scans', de_la_lista()['stats'])):
            self.assertFalse(internas & set(stats), (ruta, stats))
            self.assertEqual(stats, antes, ruta)

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

    def test_7b_el_gerente_no_lee_hallazgos_como_en_el_portal(self):
        # RC-280: la lista, el CSV, la explicación y la comparación son de analista y admin, como Hallazgos en el
        # portal. El gerente se queda con los conteos por severidad de /domains y con lo demás de su rol.
        hallazgo = '80000000-0000-4000-8000-000000000001'
        comparar = ('/api/v1/domains/acme-demo.mx/score/compare?desde=a0000000-0000-4000-8000-000000000001'
                    '&hasta=a0000000-0000-4000-8000-000000000004')
        exportar_comparacion = comparar.replace('/compare?', '/compare/export?') + '&formato=%s'
        rutas = ('/api/v1/domains/acme-demo.mx/findings', '/api/v1/domains/acme-demo.mx/findings/export?formato=json',
                 '/api/v1/domains/acme-demo.mx/findings/export?formato=csv',
                 '/api/v1/findings/%s/explanation' % hallazgo, '/domains/acme-demo.mx/findings', comparar,
                 exportar_comparacion % 'json', exportar_comparacion % 'csv')
        acme = '20000000-0000-4000-8000-000000000001'
        descargas = ("SELECT count(*) FROM audit_log WHERE organization_id = '%s' AND action = 'report.downloaded';"
                     % acme)
        gerente = sesion.login('maya.reed@acme-demo.mx')
        antes = scalar(descargas, user='postgres')
        for url in rutas + ('/api/v1/findings/no-es-un-id/explanation',
                            '/api/v1/findings/00000000-0000-4000-8000-000000000000/explanation',
                            '/api/v1/domains/no-existe.mx/findings', '/api/v1/domains/no-existe.mx/score/compare'
                            '?desde=a0000000-0000-4000-8000-000000000001&hasta=a0000000-0000-4000-8000-000000000004'):
            code, body = gerente.get(url)
            # 403 antes de buscar: no dice si el hallazgo o el dominio existen.
            self.assertEqual((code, body['detail']), (403, 'Tu rol no tiene permiso para esta acción.'), url)
        # El 403 llega antes de la exportación: la bitácora no anota una descarga que no hubo.
        self.assertEqual(scalar(descargas, user='postgres'), antes)
        analista = sesion.login('jordan.tate@acme-demo.mx')
        for cliente, quien in ((analista, 'analista'), (self.acme, 'admin')):
            for url in rutas:
                if 'formato=csv' in url:
                    req = sesion.urllib.request.Request(sesion.BASE + url)   # el CSV no es JSON
                    with cliente.opener.open(req, timeout=10) as r:
                        self.assertEqual(r.status, 200, (quien, url))
                else:
                    self.assertEqual(cliente.get(url)[0], 200, (quien, url))
        # Una llave de API entra igual, también junto a la cookie del gerente: el Bearer manda. Uno que no sirve es
        # 401 y no cae a la cookie. La descarga con llave ya la prueban test_llaves_api y test_bitacora_descargas.
        self.psql_o_falla("UPDATE organizations SET plan_id = (SELECT id FROM plans WHERE code = 'business') "
                          "WHERE id = '%s';" % acme, 'plan business para la llave')
        try:
            code, body = self.acme.post('/api/v1/api-keys', {'own_use': True, 'name': 'CIRDAN_FAKE_rc280'})
            self.assertEqual(code, 201, body)
            llave = {'Authorization': 'Bearer ' + body['key']}
            mala = {'Authorization': 'Bearer ' + body['key'] + 'x'}
            for url in (rutas[0], rutas[3], comparar):
                self.assertEqual(sesion.Client().get(url, headers=llave)[0], 200, url)
                self.assertEqual(gerente.get(url, headers=llave)[0], 200, url)
                self.assertEqual(gerente.get(url, headers=mala)[0], 401, url)
        finally:
            self.psql_o_falla("DELETE FROM api_keys WHERE name = 'CIRDAN_FAKE_rc280'; UPDATE organizations SET plan_id = "
                              "(SELECT id FROM plans WHERE code = 'starter') WHERE id = '%s';" % acme,
                              'quitar la llave y volver a starter')
        # Lo que sí es del gerente sigue igual: conteos, score, histórico, plan y reporte.
        dominio = next(d for d in self.get(gerente, '/api/v1/domains')['items'] if d['fqdn'] == 'acme-demo.mx')
        self.assertEqual(set(dominio['open_findings']), {'critical', 'high', 'medium', 'low'})
        for url in ('/api/v1/domains/acme-demo.mx/score', '/api/v1/domains/acme-demo.mx/score/history',
                    '/api/v1/domains/acme-demo.mx/action-plan', '/api/v1/domains/acme-demo.mx/report'):
            self.assertEqual(gerente.get(url)[0], 200, url)

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
            self.assertEqual((filas[0][-1], fila['atribucion']), ('atribucion', ''))  # solo las filas de HIBP (RC-54)
            _, headers, texto = self.descargar(self.acme, '/api/v1/domains/acme-demo.mx/findings/export?formato=json')
            data = json.loads(texto)
            self.assertEqual(data, self.get(self.acme, '/api/v1/domains/acme-demo.mx/findings'))
            self.assertEqual(len(filas), 1 + data['total'])
            self.assertEqual(next(i for i in data['items'] if i['id'] == hallazgo)['title'],
                             '=HYPERLINK("http://x","clic")')  # el JSON no se toca
        finally:
            ok, _, err = psql("DELETE FROM findings WHERE id = '%s';" % hallazgo, user='postgres')
            self.assertTrue(ok, err)

    def test_9f_exportacion_con_la_atribucion_de_hibp(self):
        # RC-54: la licencia CC BY 4.0 de HIBP pide la fuente con enlace donde se muestran sus datos. Un hallazgo de
        # HIBP con su brecha, que se borra al terminar.
        hallazgo = '80000000-0000-4000-8000-0000000005f8'
        ok, _, err = psql('''
            INSERT INTO findings (id, organization_id, domain_id, asset_id, rule_id, source_id, fingerprint,
                                  severity, status, evidence, detected_at)
            SELECT '%s', d.organization_id, d.id,
                   (SELECT a.id FROM assets a WHERE a.domain_id = d.id ORDER BY a.id LIMIT 1),
                   (SELECT r.id FROM scoring_rules r WHERE r.rule_set_id = '90000000-0000-4000-8000-000000000001'
                       AND r.code = 'breach_exposure'),
                   (SELECT s.id FROM data_sources s WHERE s.code = 'hibp'),
                   sha256('rc54-prueba-atribucion'), 'critical', 'open',
                   '{"title": "Correos de acme-demo.mx en la brecha Prueba", "breach_name": "Prueba"}', now()
              FROM domains d WHERE d.fqdn = 'acme-demo.mx';
            INSERT INTO breach_exposures (finding_id, organization_id, breach_name, breach_date, data_classes)
            SELECT id, organization_id, 'Prueba', '2026-06-01', ARRAY['Email addresses', 'Passwords']
              FROM findings WHERE id = '%s';
        ''' % (hallazgo, hallazgo), user='postgres')
        self.assertTrue(ok, err)
        try:
            _, _, texto = self.descargar(self.acme, '/api/v1/domains/acme-demo.mx/findings/export?formato=csv')
            filas = list(csv.reader(io.StringIO(texto[1:], newline='')))
            fila = dict(zip(filas[0], next(f for f in filas[1:] if f[1] == hallazgo)))
            self.assertEqual(fila['fuente'], 'hibp')
            self.assertEqual(fila['atribucion'], 'Fuente: Have I Been Pwned (https://haveibeenpwned.com), CC BY 4.0 '
                                                 '(https://creativecommons.org/licenses/by/4.0/)')
            self.assertTrue(all(f[-1] == '' for f in filas[1:] if f[1] != hallazgo and f[9] != 'hibp'))
        finally:
            ok, _, err = psql("DELETE FROM breach_exposures WHERE finding_id = '%s'; "
                              "DELETE FROM findings WHERE id = '%s';" % (hallazgo, hallazgo), user='postgres')
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
        # El resto de la API lleva la CSP de main.py (RC-283 y RC-89).
        _, otras, _ = self.descargar(self.acme, '/api/v1/domains/acme-demo.mx/findings/export?formato=json')
        self.assertIn("default-src 'none'", otras['Content-Security-Policy'])
        self.assertIn("frame-ancestors 'none'", otras['Content-Security-Policy'])
        self.assertIn("base-uri 'none'", otras['Content-Security-Policy'])
        self.assertIn("form-action 'none'", otras['Content-Security-Policy'])

    def test_9g_reporte_tecnico_json_html_403_y_sin_gerente(self):
        # RC-81: la misma autorización que el ejecutivo y el mismo permiso que la lista de hallazgos (trae evidencia).
        for formato in ('json', 'html'):
            url = '/api/v1/domains/old-example.net/report/technical?formato=%s' % formato
            self.assertEqual(self.acme.get(url)[0], 403, url)
            self.assertEqual(self.beta.get(url)[0], 404, url)
            self.assertEqual(sesion.Client().get(url.replace('old-example.net', 'acme-demo.mx'))[0], 401, url)
        self.assertEqual(self.acme.get('/api/v1/domains/acme-demo.mx/report/technical?formato=pdf')[0], 422)
        self.assertEqual(sesion.login('maya.reed@acme-demo.mx').get('/api/v1/domains/acme-demo.mx/report/technical')[0], 403)

        datos = self.get(self.acme, '/api/v1/domains/acme-demo.mx/report/technical')
        ejecutivo = self.get(self.acme, '/api/v1/domains/acme-demo.mx/report')
        hallazgos = self.get(self.acme, '/api/v1/domains/acme-demo.mx/findings')
        self.assertEqual(datos['kind'], 'technical')
        for clave in ('total_open', 'open_findings', 'by_category', 'score', 'authorization', 'attributions'):
            self.assertEqual(datos[clave], ejecutivo[clave], clave)
        self.assertEqual([h['id'] for h in datos['findings']], [h['id'] for h in hallazgos['items']][:200])
        self.assertTrue(all(h['recommendation'] and h['meaning'] for h in datos['findings']))  # textos de 003
        self.assertEqual(sum(r['count'] for r in datos['remediations']), datos['total_open'])
        self.assertTrue(all(set(f) == {'source', 'status', 'attempt', 'finished_at'} for f in datos['sources']))

        _, headers, texto = self.descargar(self.acme, '/api/v1/domains/acme-demo.mx/report/technical?formato=html')
        self.assertTrue(headers['Content-Type'].startswith('text/html'))
        self.assertIn('acme-demo.mx-reporte-tecnico.html', headers['Content-Disposition'])
        self.assertIn("default-src 'none'", headers['Content-Security-Policy'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertIn('Have I Been Pwned', texto)
        self.assertIn('Detalle de hallazgos', texto)

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
