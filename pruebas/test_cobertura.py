"""Códigos sin cobertura del score con su fuente y su motivo (RC-229), sin base ni red.

    python -m unittest -v pruebas/test_cobertura.py
"""
import unittest

from cirdan.recolectores import REGISTRO, api_docs, crtsh, shodan
from cirdan.score import cobertura

TODAS = [f for f in REGISTRO if f != cobertura.FUENTE_PRUEBAS]


def corrida(fuente, estado='succeeded', sin_cobertura=()):
    return {'source': fuente, 'status': estado, 'sin_cobertura': None if sin_cobertura is None else list(sin_cobertura)}


def de(huecos, motivo=None, fuente=None):
    return [(h['code'], h['source']) for h in huecos
            if (motivo is None or h['reason'] == motivo) and (fuente is None or h['source'] == fuente)]


class Huecos(unittest.TestCase):

    def test_sin_corridas_no_hay_de_donde_sacarlo(self):
        self.assertEqual(cobertura.huecos([], ['exposed_iot_device']), [])

    def test_todas_completas_y_sin_sin_cobertura_da_lista_vacia(self):
        self.assertEqual(cobertura.huecos([corrida(f) for f in TODAS]), [])

    def test_fuente_caida_deja_todos_sus_codigos(self):
        huecos = cobertura.huecos([corrida(f, 'failed' if f == 'ct_logs' else 'succeeded') for f in TODAS])
        self.assertEqual(de(huecos), [(c, 'ct_logs') for c in sorted(crtsh.CODIGOS)])
        self.assertEqual({h['reason'] for h in huecos}, {'source_failed'})

    def test_fuente_que_no_corrio_deja_sus_codigos_y_la_de_pruebas_no_cuenta(self):
        huecos = cobertura.huecos([corrida(f) for f in TODAS if f != 'api_docs'])
        self.assertEqual(de(huecos, 'source_not_run'), [(c, 'api_docs') for c in sorted(api_docs.CODIGOS)])
        self.assertEqual(de(huecos, fuente=cobertura.FUENTE_PRUEBAS), [])

    def test_shodan_sin_llave_y_parcial_de_otra_fuente(self):
        corridas = [corrida(f) for f in TODAS if f not in ('shodan', 'ct_logs')]
        corridas += [corrida('shodan', sin_cobertura=['exposed_iot_device', 'exposed_rdp']),
                     corrida('ct_logs', sin_cobertura=['lookalike_domain'])]
        huecos = cobertura.huecos(corridas, ['exposed_iot_device', 'exposed_rdp', 'lookalike_domain'])
        self.assertIn('exposed_iot_device', shodan.SIN_LLAVE)
        self.assertEqual(huecos, [{'code': 'exposed_iot_device', 'source': 'shodan', 'reason': 'no_api_key'},
                                  {'code': 'exposed_rdp', 'source': 'shodan', 'reason': 'source_partial'},
                                  {'code': 'lookalike_domain', 'source': 'ct_logs', 'reason': 'source_partial'}])

    def test_outdated_software_va_por_fuente(self):
        # Está en SIN_LLAVE de Shodan y también lo revisa la visita web: cada fuente lleva su motivo.
        corridas = [corrida(f) for f in TODAS if f not in ('shodan', 'web')]
        corridas += [corrida('shodan', sin_cobertura=['outdated_software']),
                     corrida('web', sin_cobertura=['outdated_software'])]
        self.assertEqual(de(cobertura.huecos(corridas, ['outdated_software']), 'no_api_key'),
                         [('outdated_software', 'shodan')])
        self.assertEqual(de(cobertura.huecos(corridas, ['outdated_software']), 'source_partial'),
                         [('outdated_software', 'web')])

    def test_sin_raw_payload_se_atribuye_por_codigos_y_si_no_va_sin_fuente(self):
        # GitHub no guarda raw_payload: lo de rules_without_coverage que es suyo va con GitHub.
        corridas = [corrida(f) for f in TODAS if f != 'github'] + [corrida('github', sin_cobertura=None)]
        huecos = cobertura.huecos(corridas, ['email_in_public_commits', 'codigo_que_nadie_emite'])
        self.assertEqual(huecos, [{'code': 'codigo_que_nadie_emite', 'source': None, 'reason': 'source_partial'},
                                  {'code': 'email_in_public_commits', 'source': 'github', 'reason': 'source_partial'}])

    def test_lo_ya_atribuido_por_raw_payload_no_se_repite(self):
        corridas = [corrida(f) for f in TODAS if f != 'dns'] + [corrida('dns', sin_cobertura=['dmarc_missing'])]
        self.assertEqual(de(cobertura.huecos(corridas, ['dmarc_missing'])), [('dmarc_missing', 'dns')])

    def test_motivos_conocidos(self):
        corridas = [corrida('ct_logs', 'failed'), corrida('shodan', sin_cobertura=['exposed_ot_device']),
                    corrida('dns', sin_cobertura=['spf_missing'])]
        self.assertTrue({h['reason'] for h in cobertura.huecos(corridas)} <= set(cobertura.MOTIVOS))


if __name__ == '__main__':
    unittest.main()
