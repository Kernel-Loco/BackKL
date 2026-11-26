"""Códigos sin cobertura del score con su fuente y su motivo (RC-229), sin base ni red.

    python -m unittest -v pruebas/test_cobertura.py
"""
import unittest

from cirdan.recolectores import REGISTRO, api_docs, crtsh, github, shodan
from cirdan.score import cobertura

TODAS = [f for f in REGISTRO if f != cobertura.FUENTE_PRUEBAS]


def corrida(fuente, estado='succeeded', sin_cobertura=(), sin_llave=None, avisos=None):
    return {'source': fuente, 'status': estado, 'sin_cobertura': None if sin_cobertura is None else list(sin_cobertura),
            'sin_llave': sin_llave, 'avisos': avisos}


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
        corridas += [corrida('shodan', sin_cobertura=['exposed_iot_device', 'exposed_rdp'],
                             sin_llave=['exposed_iot_device']),
                     corrida('ct_logs', sin_cobertura=['lookalike_domain'])]
        huecos = cobertura.huecos(corridas, ['exposed_iot_device', 'exposed_rdp', 'lookalike_domain'])
        self.assertIn('exposed_iot_device', shodan.SIN_LLAVE)
        self.assertEqual(huecos, [{'code': 'exposed_iot_device', 'source': 'shodan', 'reason': 'no_api_key'},
                                  {'code': 'exposed_rdp', 'source': 'shodan', 'reason': 'source_partial'},
                                  {'code': 'lookalike_domain', 'source': 'ct_logs', 'reason': 'source_partial'}])

    def test_outdated_software_va_por_fuente(self):
        # Está en SIN_LLAVE de Shodan y también lo revisa la visita web: cada fuente lleva su motivo.
        corridas = [corrida(f) for f in TODAS if f not in ('shodan', 'web')]
        corridas += [corrida('shodan', sin_cobertura=['outdated_software'], sin_llave=['outdated_software']),
                     corrida('web', sin_cobertura=['outdated_software'])]
        self.assertEqual(de(cobertura.huecos(corridas, ['outdated_software']), 'no_api_key'),
                         [('outdated_software', 'shodan')])
        self.assertEqual(de(cobertura.huecos(corridas, ['outdated_software']), 'source_partial'),
                         [('outdated_software', 'web')])

    def test_shodan_con_llave_y_api_de_host_incompleta_no_es_falta_de_llave(self):
        # Con la llave, la API de host respondió por una parte de las IP: sus códigos son cobertura parcial (hallazgo 2).
        corridas = [corrida(f) for f in TODAS if f != 'shodan']
        corridas.append(corrida('shodan', sin_cobertura=list(shodan.SIN_LLAVE), sin_llave=[],
                                avisos=[shodan.LIMITES_CON_LLAVE, shodan.ETIQUETAS_PARCIAL % (1, 2)]))
        huecos = cobertura.huecos(corridas, list(shodan.SIN_LLAVE))
        self.assertEqual(de(huecos, 'no_api_key'), [])
        self.assertEqual(de(huecos, 'source_partial'), [(c, 'shodan') for c in sorted(shodan.SIN_LLAVE)])

    def test_shodan_que_reproduce_sin_grabacion_no_es_falta_de_llave(self):
        corridas = [corrida(f) for f in TODAS if f != 'shodan']
        corridas.append(corrida('shodan', sin_cobertura=list(shodan.CODIGOS), sin_llave=[]))
        self.assertEqual(de(cobertura.huecos(corridas), 'no_api_key'), [])

    def test_corrida_de_antes_de_sin_llave_lo_toma_del_aviso_de_shodan(self):
        otras = [corrida(f) for f in TODAS if f != 'shodan']
        sin = ['exposed_iot_device', 'exposed_rdp']
        sin_llave = cobertura.huecos(otras + [corrida('shodan', sin_cobertura=sin, avisos=[shodan.LIMITES])])
        con_llave = cobertura.huecos(otras + [corrida('shodan', sin_cobertura=sin, avisos=[shodan.LIMITES_CON_LLAVE])])
        sin_aviso = cobertura.huecos(otras + [corrida('shodan', sin_cobertura=sin)])
        self.assertEqual(de(sin_llave, 'no_api_key'), [('exposed_iot_device', 'shodan')])
        self.assertEqual(de(sin_llave, 'source_partial'), [('exposed_rdp', 'shodan')])
        self.assertEqual(de(con_llave, 'no_api_key'), [])
        self.assertEqual(de(sin_aviso, 'no_api_key'), [])

    # LIMITES tal como lo guardó una corrida de antes del 17 nov: copia de shodan.py en 839af0f^, líneas 219 a 223.
    LIMITES_16_NOV = (
        'shodan: solo IPv4 y sin la llave de Shodan (#8): exposed_iot_device, exposed_ot_device y outdated_software '
        'quedan sin cobertura, y no se detecta un CDN que no llegue por un CNAME conocido, cuyo ASN no esté en '
        'geoip.CDN_POR_ASN y cuya IP no esté en los rangos publicados de CloudFront, Azure Front Door y los bordes '
        'de Google del %s (en las nubes mixtas, por ejemplo Cloud CDN en un balanceador de Google Cloud, que '
        'comparte rangos con las VM, y otros fuera de la lista)' % shodan.RANGOS_CDN_FECHA)

    def test_corrida_con_el_aviso_de_una_version_anterior_sigue_siendo_sin_llave(self):
        # El escaneo de olmardo.com del 16 nov guardó el LIMITES de entonces: Shodan sale 'Sin llave', no 'respondió
        # pero no pudo revisarlas'.
        self.assertTrue(shodan.LIMITES.startswith(cobertura.AVISO_SIN_LLAVE))
        self.assertTrue(shodan.LIMITES_CON_LLAVE.startswith(cobertura.AVISO_CON_LLAVE))
        self.assertFalse(shodan.LIMITES_CON_LLAVE.startswith(cobertura.AVISO_SIN_LLAVE))
        self.assertNotEqual(self.LIMITES_16_NOV, shodan.LIMITES)
        otras = [corrida(f) for f in TODAS if f != 'shodan']
        sin = list(shodan.SIN_LLAVE) + ['exposed_rdp']
        vieja = corrida('shodan', sin_cobertura=sin, avisos=['otro aviso', self.LIMITES_16_NOV])
        huecos = cobertura.huecos(otras + [vieja])
        self.assertEqual(de(huecos, 'no_api_key'), [(c, 'shodan') for c in sorted(shodan.SIN_LLAVE)])
        self.assertEqual(de(huecos, 'source_partial'), [('exposed_rdp', 'shodan')])

    def test_fuente_parcial_sin_sin_cobertura_no_da_lista_vacia(self):
        # stats.sources_partial con sin_cobertura vacía: sus códigos se revisaron solo en una parte (hallazgo 3).
        huecos = cobertura.huecos([corrida(f) for f in TODAS], (), ['ct_logs'])
        self.assertEqual(de(huecos), [(c, 'ct_logs') for c in sorted(crtsh.CODIGOS)])
        self.assertEqual({h['reason'] for h in huecos}, {'partially_checked'})

    def test_fuente_parcial_conserva_el_motivo_de_lo_que_no_reviso(self):
        corridas = [corrida(f) for f in TODAS if f != 'ct_logs'] + [corrida('ct_logs', sin_cobertura=['lookalike_domain'])]
        huecos = cobertura.huecos(corridas, ['lookalike_domain'], ['ct_logs'])
        self.assertEqual(de(huecos, 'source_partial'), [('lookalike_domain', 'ct_logs')])
        self.assertNotIn(('lookalike_domain', 'ct_logs'), de(huecos, 'partially_checked'))

    def test_fuente_parcial_que_no_corrio_no_se_inventa(self):
        corridas = [corrida(f) for f in TODAS if f != 'api_docs']
        self.assertEqual(de(cobertura.huecos(corridas, (), ['api_docs']), 'partially_checked'), [])

    def test_sin_raw_payload_se_atribuye_por_codigos_y_si_no_va_sin_fuente(self):
        # GitHub no guarda raw_payload: lo de rules_without_coverage que es suyo va con GitHub.
        corridas = [corrida(f) for f in TODAS if f != 'github'] + [corrida('github', sin_cobertura=None)]
        huecos = cobertura.huecos(corridas, ['email_in_public_commits', 'codigo_que_nadie_emite'])
        self.assertEqual(huecos, [{'code': 'codigo_que_nadie_emite', 'source': None, 'reason': 'source_partial'},
                                  {'code': 'email_in_public_commits', 'source': 'github', 'reason': 'source_partial'}])

    def test_lo_ya_atribuido_por_raw_payload_no_se_repite(self):
        corridas = [corrida(f) for f in TODAS if f != 'dns'] + [corrida('dns', sin_cobertura=['dmarc_missing'])]
        self.assertEqual(de(cobertura.huecos(corridas, ['dmarc_missing'])), [('dmarc_missing', 'dns')])

    def test_fuente_que_la_carta_no_autoriza_sale_una_vez_y_con_su_fuente(self):
        # RC-59: carta sin la actividad 4. GitHub queda 'failed' y sus reglas también llegan a rules_without_coverage.
        corridas = [corrida(f) for f in TODAS if f != 'github'] + [corrida('github', 'failed', sin_cobertura=None)]
        huecos = cobertura.huecos(corridas, sorted(github.CODIGOS))
        self.assertEqual(de(huecos), [(c, 'github') for c in sorted(github.CODIGOS)])
        self.assertEqual({h['reason'] for h in huecos}, {'source_failed'})

    def test_motivos_conocidos(self):
        corridas = [corrida('ct_logs', 'failed'), corrida('shodan', sin_cobertura=['exposed_ot_device'],
                                                          sin_llave=['exposed_ot_device']),
                    corrida('dns', sin_cobertura=['spf_missing']), corrida('web')]
        motivos = {h['reason'] for h in cobertura.huecos(corridas, (), ['web'], apagadas=['github'])}
        self.assertEqual(motivos, set(cobertura.MOTIVOS))

    def test_fuente_apagada_por_la_organizacion_va_con_su_motivo(self):
        # #117, RC-235: no corrió porque la empresa la apagó, no porque esté apagada en la plataforma.
        huecos = cobertura.huecos([corrida(f) for f in TODAS if f != 'github'], apagadas=['github'])
        self.assertEqual(de(huecos, 'source_disabled_by_org'), [(c, 'github') for c in sorted(github.CODIGOS)])
        self.assertEqual(de(huecos, 'source_not_run'), [])

    def test_apagada_que_si_corrio_no_cambia_su_motivo(self):
        huecos = cobertura.huecos([corrida(f, 'failed' if f == 'github' else 'succeeded') for f in TODAS],
                                  apagadas=['github'])
        self.assertEqual({h['reason'] for h in huecos}, {'source_failed'})

    def test_todo_apagado_sin_corridas_si_dice_que_falto(self):
        huecos = cobertura.huecos([], apagadas=TODAS)
        self.assertEqual({h['reason'] for h in huecos}, {'source_disabled_by_org'})
        self.assertEqual({h['source'] for h in huecos}, {f for f in TODAS if cobertura.codigos_de(f)})


if __name__ == '__main__':
    unittest.main()
