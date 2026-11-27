"""Tarjeta de Teams y URL del flujo (#65, RC-114), sin base ni red.

    python -m unittest -v pruebas/test_alertas_tarjeta.py

El outbox y la entrega se prueban contra la base en pruebas/test_alertas.py y la API en pruebas/test_integracion_teams.py.
"""
import json
import unittest

from cirdan.alertas import tarjeta

URL = ('https://prod-12.westus.logic.azure.com:443/workflows/abc123/triggers/manual/paths/invoke'
       '?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=CIRDAN_FAKE_firma')
URL_PP = ('https://default0123.ab.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/x'
          '/triggers/manual/paths/invoke?api-version=1&sig=CIRDAN_FAKE_firma')


class Url(unittest.TestCase):

    def test_1_acepta_los_flujos_de_workflows(self):
        self.assertEqual(tarjeta.validar_url(URL), 'prod-12.westus.logic.azure.com')
        self.assertEqual(tarjeta.validar_url('  ' + URL_PP + ' '), 'default0123.ab.environment.api.powerplatform.com')

    def test_2_rechaza_otros_hosts_http_usuario_puerto_y_sin_firma(self):
        malas = [
            None, '', 'x' * 3000,
            URL.replace('https://', 'http://'),
            URL.replace('prod-12.westus.logic.azure.com', 'logic.azure.com.evil.example'),
            URL.replace('prod-12.westus.logic.azure.com', '169.254.169.254'),
            URL.replace('https://', 'https://user:pass@'),
            URL.replace(':443', ':8443'),
            URL.replace('&sig=CIRDAN_FAKE_firma', ''),
            'https://outlook.office.com/webhook/x?sig=1',
            'https://[::1]/x?sig=1', 'file:///etc/passwd',
        ]
        for url in malas:
            with self.subTest(url=url), self.assertRaises(tarjeta.UrlInvalida) as error:
                tarjeta.validar_url(url)
            self.assertNotIn('CIRDAN_FAKE_firma', str(error.exception))   # el error nunca repite la firma


class Reintentos(unittest.TestCase):

    def test_1_esperas_crecen_y_al_quinto_fallo_ya_no_hay_otro(self):
        self.assertEqual([tarjeta.espera(i) for i in range(1, 6)], [10, 60, 300, 1800, None])
        self.assertEqual(tarjeta.MAX_INTENTOS, 5)


class Tarjeta(unittest.TestCase):

    def test_1_hallazgo_critico_con_enlace_y_sin_correos(self):
        mensaje = tarjeta.tarjeta('finding.created', {
            'domain': 'acme-demo.mx', 'title': 'El correo ana.perez@acme-demo.mx aparece en una brecha',
            'severity': 'critical', 'rule_code': 'breach_exposure', 'detected_at': '2026-11-26T10:00:00-06:00'},
            'https://lowtidesec.com')
        self.assertEqual(mensaje['type'], 'message')
        adjunto = mensaje['attachments'][0]
        self.assertEqual(adjunto['contentType'], 'application/vnd.microsoft.card.adaptive')
        tarjeta_ = adjunto['content']
        self.assertEqual((tarjeta_['type'], tarjeta_['version']), ('AdaptiveCard', '1.4'))
        texto = json.dumps(mensaje, ensure_ascii=False)
        self.assertIn('Hallazgo crítico nuevo en acme-demo.mx', texto)
        self.assertIn('Crítica', texto)
        self.assertNotIn('ana.perez@', texto)
        self.assertIn('[correo]', texto)
        self.assertEqual(tarjeta_['actions'][0]['url'], 'https://lowtidesec.com/dashboard/hallazgos?dominio=acme-demo.mx')

    def test_2_score_sobre_el_umbral_y_prueba(self):
        mensaje = tarjeta.tarjeta('score.above_threshold', {'domain': 'acme-demo.mx', 'score': 72, 'threshold': 60,
                                                            'previous_score': 55, 'computed_at': '2026-11-26'}, None)
        hechos = {h['title']: h['value'] for h in mensaje['attachments'][0]['content']['body'][1]['facts']}
        self.assertEqual((hechos['Score'], hechos['Umbral'], hechos['Score anterior']), ('72', '60', '55'))
        self.assertNotIn('actions', mensaje['attachments'][0]['content'])   # sin portal no hay enlace
        self.assertIn('Prueba', json.dumps(tarjeta.tarjeta('test', {}, None), ensure_ascii=False))
        with self.assertRaises(ValueError):
            tarjeta.tarjeta('scan.partial', {}, None)

    def test_3_el_titulo_se_recorta(self):
        self.assertEqual(len(tarjeta.sin_correos('x' * 500)), tarjeta.TITULO_MAXIMO)
        self.assertEqual(tarjeta.sin_correos(None), '')


if __name__ == '__main__':
    unittest.main()
