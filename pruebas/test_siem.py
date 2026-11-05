"""Pruebas sin base ni red de la salida a SIEM (#98, RC-212): eventos de HEC con campos del CIM.

    python -m unittest -v pruebas/test_siem.py
"""
import json
import unittest
from datetime import datetime, timedelta, timezone

from cirdan import siem

MX = timezone(timedelta(hours=-6))
ESCANEO_FIN = datetime(2026, 11, 4, 12, 30, 15, 250000, tzinfo=MX)
CORREO = 'ana.lopez@olmardo.com'


def hallazgo(**cambios):
    h = {
        'id': '80000000-0000-4000-8000-000000000001', 'rule_title': 'Servicio de escritorio remoto expuesto',
        'rule_code': 'exposed_rdp', 'category': 'infrastructure', 'severity': 'high', 'status': 'open',
        'cve_id': None, 'cvss': None, 'asset': '192.0.2.50:3389/tcp', 'asset_type': 'service',
        'attack_technique_id': 'T1133', 'data_source': 'shodan',
        'detected_at': datetime(2026, 11, 1, 9, 0, tzinfo=MX), 'last_scan_id': '60000000-0000-4000-8000-000000000009',
        'scan_finished_at': ESCANEO_FIN,
    }
    h.update(cambios)
    return h


ESCANEO = {
    'id': '60000000-0000-4000-8000-000000000009', 'status': 'partial', 'trigger': 'on_demand',
    'queued_at': datetime(2026, 11, 4, 12, 28, tzinfo=MX), 'finished_at': ESCANEO_FIN,
    'stats': {'assets': 14, 'findings': 6, 'new_findings': 2, 'resolved_findings': 1, 'sources_ok': 4,
              'sources_failed': 1, 'rules_without_coverage': ['cert_expired'], 'sources_partial': ['github'],
              'otra_llave': 'no sale'},
    'sources': [{'data_source': 'ct_logs', 'status': 'succeeded'},
                {'data_source': 'whois', 'status': 'failed', 'error': 'Traceback con datos internos'}],
}
SCORE = {
    'id': 'a0000000-0000-4000-8000-000000000009', 'scan_id': '60000000-0000-4000-8000-000000000009', 'score': 64,
    'category_scores': {'infrastructure': 70, 'digital_identity': 20, 'configuration': 45, 'data_leaks': 80},
    'method': 'rules', 'model_version': None, 'rule_set_version': 2, 'reason': 'scan', 'partial_coverage': True,
    'computed_at': datetime(2026, 11, 4, 12, 30, 16, tzinfo=MX),
}
CAMPOS_HALLAZGO = {'vendor_product', 'dvc', 'app', 'signature', 'signature_id', 'severity', 'category', 'dest',
                   'asset_type', 'finding_id', 'scan_id', 'domain', 'status', 'data_source', 'detected_at'}


def lineas(texto):
    return [json.loads(x) for x in texto.splitlines()]


class SalidaSiem(unittest.TestCase):

    def test_1_hallazgo_con_campos_de_cim_vulnerabilities(self):
        e = siem.evento_hallazgo('olmardo.com', hallazgo(cve_id='CVE-2024-1234', cvss=9.8))
        self.assertEqual({k: e[k] for k in ('host', 'source', 'sourcetype')},
                         {'host': 'lowtide', 'source': 'lowtide', 'sourcetype': 'lowtide:finding'})
        self.assertEqual(e['time'], round(ESCANEO_FIN.timestamp(), 3))
        ev = e['event']
        self.assertEqual(set(ev), CAMPOS_HALLAZGO | {'cve', 'cvss', 'mitre_technique_id'})
        self.assertEqual((ev['signature'], ev['signature_id'], ev['severity'], ev['category'], ev['dest']),
                         ('Servicio de escritorio remoto expuesto', 'exposed_rdp', 'high', 'infrastructure',
                          '192.0.2.50:3389/tcp'))
        self.assertEqual((ev['vendor_product'], ev['dvc'], ev['cve'], ev['cvss'], ev['mitre_technique_id']),
                         ('LowTide', 'LowTide', 'CVE-2024-1234', 9.8, 'T1133'))
        self.assertNotIn('type', ev)  # solo los críticos entran a CIM Alerts

    def test_2_sin_cve_ni_tecnica_no_manda_campos_vacios(self):
        ev = siem.evento_hallazgo('olmardo.com', hallazgo(attack_technique_id=None))['event']
        self.assertEqual(set(ev), CAMPOS_HALLAZGO)

    def test_3_critico_tambien_es_alerta(self):
        ev = siem.evento_hallazgo('olmardo.com', hallazgo(severity='critical'))['event']
        self.assertEqual((ev['type'], ev['app']), ('alert', 'LowTide'))

    def test_4_un_correo_nunca_sale_y_dest_es_el_dominio(self):
        for asset in (CORREO, None):  # la consulta de la API ya lo deja en NULL, y aquí tampoco pasa
            texto = siem.ndjson('olmardo.com', [hallazgo(asset=asset, asset_type='email', rule_code='breach_exposure')])
            self.assertNotIn(CORREO, texto)
            self.assertNotIn('ana.lopez', texto)
            self.assertEqual(lineas(texto)[0]['event']['dest'], 'olmardo.com')

    def test_5_sin_evidencia_aunque_la_fila_la_traiga(self):
        h = hallazgo(evidence={'title': 'Token CIRDAN_FAKE_abc123 en config.py', 'huella': 'f00d'},
                     breach_name='DemoBreach-2026')
        texto = siem.ndjson('olmardo.com', [h])
        for prohibido in ('evidence', 'CIRDAN_FAKE_', 'huella', 'f00d', 'DemoBreach'):
            self.assertNotIn(prohibido, texto)

    def test_6_sin_escaneo_el_tiempo_es_la_deteccion(self):
        e = siem.evento_hallazgo('beta-corp.mx', hallazgo(last_scan_id=None, scan_finished_at=None))
        self.assertEqual(e['time'], round(datetime(2026, 11, 1, 9, 0, tzinfo=MX).timestamp(), 3))
        self.assertIsNone(e['event']['scan_id'])

    def test_7_escaneo_con_cobertura_parcial_sin_errores_ni_llaves_de_mas(self):
        e = siem.evento_escaneo('olmardo.com', ESCANEO)
        self.assertEqual((e['sourcetype'], e['time']), ('lowtide:scan', round(ESCANEO_FIN.timestamp(), 3)))
        ev = e['event']
        self.assertTrue(ev['partial_coverage'])
        self.assertEqual((ev['rules_without_coverage'], ev['sources_partial'], ev['sources_failed']),
                         (['cert_expired'], ['github'], 1))
        self.assertEqual(ev['source_runs'], [{'data_source': 'ct_logs', 'status': 'succeeded'},
                                             {'data_source': 'whois', 'status': 'failed'}])
        texto = json.dumps(e)
        for prohibido in ('otra_llave', 'Traceback', 'error'):
            self.assertNotIn(prohibido, texto)

    def test_8_escaneo_completo_sin_stats(self):
        ev = siem.evento_escaneo('olmardo.com', dict(ESCANEO, status='completed', stats=None, sources=[]))['event']
        self.assertFalse(ev['partial_coverage'])
        self.assertEqual((ev['assets'], ev['rules_without_coverage'], ev['source_runs']), (None, [], []))

    def test_9_score_con_banda_y_categorias_planas(self):
        e = siem.evento_score('olmardo.com', SCORE)
        self.assertEqual(e['sourcetype'], 'lowtide:score')
        ev = e['event']
        self.assertEqual((ev['score'], ev['band'], ev['score_infrastructure'], ev['score_data_leaks']),
                         (64, 'high', 70, 80))
        self.assertTrue(ev['partial_coverage'])
        self.assertNotIn('category_scores', ev)

    def test_10_ndjson_un_evento_por_linea_y_en_utf8(self):
        h = hallazgo(rule_title='Línea uno\nlínea dos')
        texto = siem.ndjson('olmardo.com', [h, hallazgo(id='otro')], ESCANEO, SCORE)
        self.assertTrue(texto.endswith('\n'))
        eventos = lineas(texto)
        self.assertEqual([e['sourcetype'] for e in eventos],
                         ['lowtide:finding', 'lowtide:finding', 'lowtide:scan', 'lowtide:score'])
        self.assertEqual(eventos[0]['event']['signature'], 'Línea uno\nlínea dos')
        self.assertIn('Línea', texto)
        self.assertEqual(siem.ndjson('olmardo.com', []), '')

    def test_11_sin_zona_horaria_no_adivina(self):
        with self.assertRaisesRegex(ValueError, 'zona horaria'):
            siem.evento_hallazgo('olmardo.com', hallazgo(scan_finished_at=datetime(2026, 11, 4, 12, 30)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
