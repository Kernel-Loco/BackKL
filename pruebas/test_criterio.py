"""Pruebas del criterio de criticidad (#29), sin base de datos.

    python -m unittest -v pruebas/test_criterio.py
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_criterio.py
from cirdan.score import criterio as c  # noqa: E402
from cirdan.score import subcategorias as sub  # noqa: E402

PESOS_V1 = {'infrastructure': 0.30, 'digital_identity': 0.20, 'configuration': 0.20, 'data_leaks': 0.30}  # db/semillas/001_datos_demo.sql


def notas(infra, identidad, config, fugas):
    return {'infrastructure': infra, 'digital_identity': identidad, 'configuration': config, 'data_leaks': fugas}


class Bandas(unittest.TestCase):

    def test_1_limites(self):
        casos = {0: 'low', 39: 'low', 40: 'medium', 59: 'medium', 60: 'high', 79: 'high', 80: 'critical', 100: 'critical'}
        for score, esperado in casos.items():
            self.assertEqual(c.banda(score), esperado, score)

    def test_2_ejemplo_del_reto_68_es_riesgo_alto(self):
        self.assertEqual((c.banda(68), c.nombre_banda(68)), ('high', 'alto'))

    def test_3_fuera_de_rango(self):
        for malo in (-1, 101):
            with self.assertRaises(ValueError):
                c.banda(malo)


class Letras(unittest.TestCase):
    """Calificación de la A a la F (#114, RC-232)."""

    def test_1_cortes(self):
        casos = {0: 'A', 19: 'A', 20: 'B', 39: 'B', 40: 'C', 59: 'C', 60: 'D', 79: 'D', 80: 'F', 100: 'F'}
        for score, esperado in casos.items():
            self.assertEqual(c.letra(score), esperado, score)

    def test_2_cada_letra_cae_en_una_sola_banda(self):
        bandas = {'A': 'low', 'B': 'low', 'C': 'medium', 'D': 'high', 'F': 'critical'}
        for score in range(101):
            self.assertEqual(bandas[c.letra(score)], c.banda(score), score)
        self.assertEqual([l for _, _, l in c.LETRAS], ['A', 'B', 'C', 'D', 'F'])   # no hay E

    def test_3_regla_de_piso(self):
        limpio = notas(0, 0, 0, 0)
        self.assertEqual(c.letra(c.score_dominio(limpio, PESOS_V1, criticos=0)['score']), 'A')
        self.assertEqual(c.letra(c.score_dominio(limpio, PESOS_V1, criticos=1)['score']), 'D')   # un crítico: al menos D
        self.assertEqual(c.letra(c.score_dominio(limpio, PESOS_V1, criticos=2)['score']), 'F')   # dos: F
        self.assertEqual(c.letra(c.score_dominio(limpio, PESOS_V1, criticos=5)['score']), 'F')
        # con un crítico y notas que ya dan crítico, la letra sale del score final, no del piso
        self.assertEqual(c.letra(c.score_dominio(notas(100, 100, 100, 100), PESOS_V1, criticos=1)['score']), 'F')

    def test_4_fuera_de_rango(self):
        for malo in (-1, 101, 39.5):
            with self.assertRaises(ValueError):
                c.letra(malo)

    def test_5_la_alerta_sigue_con_el_score_no_con_la_letra(self):
        # 60 y 79 son D: con umbral 70 uno dispara y el otro no
        self.assertEqual((c.letra(60), c.letra(79)), ('D', 'D'))
        self.assertEqual((c.dispara_alerta(60, 70), c.dispara_alerta(79, 70)), (False, True))


def aporte(code, category, severity, penalty):
    return {'code': code, 'category': category, 'severity': severity, 'penalty': penalty}


APORTES = [aporte('cert_expired', 'infrastructure', 'high', 20), aporte('cert_expiring_soon', 'infrastructure', 'medium', 10),
           aporte('exposed_rdp', 'infrastructure', 'high', 25), aporte('exposed_api_docs', 'infrastructure', 'medium', 10),
           aporte('dmarc_missing', 'configuration', 'medium', 10), aporte('lookalike_domain', 'digital_identity', 'medium', 15),
           aporte('breach_exposure', 'data_leaks', 'critical', 40)]
TODAS = {f: 'succeeded' for f in ('ct_logs', 'dns', 'shodan', 'api_docs', 'whois')}


class SubcategoriasYKri(unittest.TestCase):
    """Vista de subcategorías y KRI (#114, RC-232), sin base."""

    def kri(self, kris, clave):
        return next(k for k in kris if k['kri'] == clave)

    def test_1_el_mapa_esta_bien_armado(self):
        self.assertEqual(sub.revisar(categorias=c.CATEGORIAS), [])
        self.assertEqual([k[1] for k in sub.KRIS],
                         ['Certificados', 'Exposición de servicios', 'Correo', 'Suplantación', 'Reputación'])
        self.assertIsInstance(sub.VERSION, int)

    def test_2_revisar_avisa_de_un_codigo_sin_subcategoria_o_de_otra_categoria(self):
        self.assertEqual(sub.revisar({'cert_expired': 'infrastructure', 'regla_nueva': 'data_leaks'})[0],
                         'el código de regla regla_nueva no tiene subcategoría')
        self.assertIn('cert_expired es de data_leaks y su subcategoría certificates es de infrastructure',
                      sub.revisar({'cert_expired': 'data_leaks'}))

    def test_3_cuenta_y_suma_por_subcategoria(self):
        subs, _ = sub.resumen(APORTES, TODAS)
        por = {s['subcategory']: s for s in subs}
        self.assertEqual((por['certificates']['findings'], por['certificates']['penalty']), (2, 30.0))
        self.assertEqual((por['exposed_secrets']['findings'], por['exposed_secrets']['penalty']), (0, 0.0))
        self.assertEqual(sum(s['findings'] for s in subs), len(APORTES))
        self.assertEqual([(s['category'], s['subcategory']) for s in subs], [(s[1], s[0]) for s in sub.SUBCATEGORIAS])

    def test_4_un_kri_junta_subcategorias_y_una_regla_sin_kri_sigue_en_su_categoria(self):
        subs, kris = sub.resumen(APORTES, TODAS)
        exposicion = self.kri(kris, 'service_exposure')   # exposed_services y exposed_apis
        self.assertEqual((exposicion['status'], exposicion['findings'], exposicion['max_severity'], exposicion['penalty']),
                         ('ok', 2, 'high', 35.0))
        self.assertEqual(self.kri(kris, 'certificates')['max_severity'], 'high')
        # la brecha no está en ningún KRI: los KRI no cubren todo el score, pero sí cuenta en su subcategoría
        self.assertLess(sum(k['findings'] for k in kris if k['findings']), len(APORTES))
        self.assertEqual(next(s for s in subs if s['subcategory'] == 'breaches')['findings'], 1)
        self.assertEqual(self.kri(kris, 'email')['findings'], 1)
        self.assertEqual(self.kri(kris, 'impersonation')['penalty'], 15.0)

    def test_5_fuente_caida_es_sin_cobertura_no_cero(self):
        for estado in ('failed', 'retrying', 'running', 'pending'):
            _, kris = sub.resumen(APORTES, dict(TODAS, ct_logs=estado))
            for clave in ('certificates', 'impersonation'):   # los dos se alimentan de ct_logs
                k = self.kri(kris, clave)
                self.assertEqual((k['status'], k['findings'], k['max_severity'], k['penalty'], k['sources_failed']),
                                 ('no_coverage', None, None, None, ['ct_logs']), (clave, estado))
            self.assertEqual(self.kri(kris, 'email')['status'], 'ok')
        _, kris = sub.resumen([], dict(TODAS, shodan='failed'))   # con una de sus dos fuentes caída ya no hay cobertura
        self.assertEqual(self.kri(kris, 'service_exposure')['status'], 'no_coverage')

    def test_6_fuente_que_no_corrio(self):
        _, kris = sub.resumen([], {'shodan': 'succeeded'})
        exposicion = self.kri(kris, 'service_exposure')   # api_docs no corrió, shodan sí: hay datos, pero a medias
        self.assertEqual((exposicion['status'], exposicion['findings'], exposicion['max_severity'],
                          exposicion['sources_not_run']), ('partial', 0, None, ['api_docs']))
        correo = self.kri(kris, 'email')                  # su única fuente no corrió
        self.assertEqual((correo['status'], correo['findings']), ('no_coverage', None))

    def test_7_reputacion_sin_fuente_todavia(self):
        for corridas in ({}, TODAS):
            k = self.kri(sub.resumen(APORTES, corridas)[1], 'reputation')
            self.assertEqual((k['status'], k['findings'], k['max_severity'], k['penalty'], k['sources']),
                             ('no_source_yet', None, None, None, []))

    def test_8_reglas_sin_cobertura_de_un_kri(self):
        _, kris = sub.resumen([], TODAS, sin_cobertura=['lookalike_domain', 'cert_expired', 'outdated_software'])
        suplantacion = self.kri(kris, 'impersonation')   # ct_logs respondió, pero su única regla no se revisó
        self.assertEqual((suplantacion['status'], suplantacion['findings'], suplantacion['penalty'],
                          suplantacion['rules_without_coverage']), ('no_coverage', None, None, ['lookalike_domain']))
        certificados = self.kri(kris, 'certificates')    # una de sus dos reglas sí se revisó: a medias, no ok
        self.assertEqual((certificados['status'], certificados['findings'], certificados['rules_without_coverage']),
                         ('partial', 0, ['cert_expired']))
        self.assertEqual((self.kri(kris, 'email')['status'], self.kri(kris, 'email')['rules_without_coverage']), ('ok', []))
        # correo con NXDOMAIN: dns responde y deja sus 4 reglas sin cobertura
        _, kris = sub.resumen([], TODAS, sin_cobertura=['spf_missing', 'spf_allow_all', 'dmarc_missing', 'dmarc_policy_none'])
        self.assertEqual((self.kri(kris, 'email')['status'], self.kri(kris, 'email')['findings']), ('no_coverage', None))

    def test_8b_fuente_que_reviso_solo_una_parte(self):
        _, kris = sub.resumen(APORTES, TODAS, a_medias=['shodan', 'github'])
        exposicion = self.kri(kris, 'service_exposure')
        self.assertEqual((exposicion['status'], exposicion['findings'], exposicion['sources_partial']),
                         ('partial', 2, ['shodan']))
        self.assertEqual(self.kri(kris, 'certificates')['status'], 'ok')

    def test_8c_ningun_estado_sin_datos_completos_sale_ok_en_cero(self):
        # lo esperado va escrito a mano, en el orden de sub.KRIS: certificados, exposición, correo, suplantación
        # y reputación
        nc, sf = 'no_coverage', 'no_source_yet'
        casos = [
            (({}, (), ()), (nc, nc, nc, nc, sf)),
            (({'ct_logs': 'failed'}, (), ()), (nc, nc, nc, nc, sf)),
            ((TODAS, ['lookalike_domain'], ()), ('ok', 'ok', 'ok', nc, sf)),
            ((TODAS, ['cert_expired'], ()), ('partial', 'ok', 'ok', 'ok', sf)),
            ((TODAS, (), ['ct_logs']), ('partial', 'ok', 'ok', 'partial', sf)),
            (({'shodan': 'succeeded', 'ct_logs': 'succeeded'}, (), ()), ('ok', 'partial', nc, 'ok', sf)),
            ((TODAS, (), ()), ('ok', 'ok', 'ok', 'ok', sf)),
        ]
        for (corridas, sin_cobertura, a_medias), esperado in casos:
            kris = sub.resumen([], corridas, sin_cobertura, a_medias)[1]
            self.assertEqual(tuple(k['status'] for k in kris), esperado, (corridas, sin_cobertura, a_medias))
            for k in kris:
                self.assertEqual(k['findings'], 0 if k['status'] in ('ok', 'partial') else None, k['kri'])

    def test_8f_reglas_de_una_fuente_que_no_corrio_cuentan_como_sin_revisar(self):
        # shodan respondió sin poder revisar nada (reproducir sin grabación) y api_docs no corrió: ningún dato real
        de_shodan = ['exposed_rdp', 'exposed_remote_admin', 'exposed_file_sharing', 'exposed_database',
                     'exposed_service', 'known_vulnerability', 'exposed_iot_device', 'exposed_ot_device',
                     'outdated_software']
        _, kris = sub.resumen([], {'shodan': 'succeeded'}, sin_cobertura=de_shodan)
        k = self.kri(kris, 'service_exposure')
        self.assertEqual((k['status'], k['findings'], k['max_severity'], k['penalty'], k['sources_not_run']),
                         ('no_coverage', None, None, None, ['api_docs']))
        self.assertEqual(len(k['rules_without_coverage']), 7)   # solo las que dio el escaneo, no las de api_docs
        # con una sola regla de shodan revisada ya hay un dato: a medias
        _, kris = sub.resumen([], {'shodan': 'succeeded'}, sin_cobertura=de_shodan[1:])
        k = self.kri(kris, 'service_exposure')
        self.assertEqual((k['status'], k['findings']), ('partial', 0))
        # sin llave de Shodan sus 2 reglas de IoT y OT nunca se revisan: aun con las dos fuentes completas no sale ok
        _, kris = sub.resumen([], TODAS, sin_cobertura=['exposed_iot_device', 'exposed_ot_device', 'outdated_software'])
        self.assertEqual(self.kri(kris, 'service_exposure')['status'], 'partial')

    def test_8g_revisar_avisa_de_una_regla_de_un_kri_sin_fuente_en_emiten(self):
        bueno = sub.EMITEN
        try:
            sub.EMITEN = tuple((f, tuple(c for c in codigos if c != 'spf_missing')) for f, codigos in bueno)
            self.assertEqual(sub.revisar(), ['la regla spf_missing del KRI email debe estar en EMITEN con una sola '
                                             'fuente del KRI'])
            sub.EMITEN = bueno + (('shodan', ('cert_expired',)),)   # dos fuentes para una regla
            self.assertEqual(len(sub.revisar()), 1)
        finally:
            sub.EMITEN = bueno
        self.assertEqual(sub.revisar(), [])

    def test_8d_revisar_avisa_de_un_kri_que_apunta_a_una_subcategoria_que_no_existe(self):
        bueno = sub.KRIS
        try:
            sub.KRIS = bueno + (('nuevo', 'Nuevo', ('no_existe',), ('dns',)),)
            self.assertEqual(sub.revisar(), ['el KRI nuevo apunta a la subcategoría no_existe, que no existe'])
        finally:
            sub.KRIS = bueno
        self.assertEqual(sub.revisar(), [])

    def test_8e_un_codigo_en_dos_juegos_con_categorias_distintas(self):
        pares = [('cert_expired', 'infrastructure'), ('cert_expired', 'configuration')]
        self.assertIn('cert_expired es de configuration y su subcategoría certificates es de infrastructure',
                      sub.revisar(pares))
        # su aporte no se pierde: va a 'other' de la categoría de su regla y sigue contando en su KRI, que no sale en 0
        subs, kris = sub.resumen([aporte('cert_expired', 'configuration', 'high', 20)], TODAS)
        self.assertEqual(subs[-1], {'category': 'configuration', 'subcategory': 'other', 'name': 'Sin clasificar',
                                    'findings': 1, 'penalty': 20.0})
        self.assertEqual(sum(s['penalty'] for s in subs), 20.0)
        k = self.kri(kris, 'certificates')
        self.assertEqual((k['status'], k['findings'], k['max_severity'], k['penalty']), ('ok', 1, 'high', 20.0))

    def test_9_un_aporte_de_una_regla_que_el_mapa_no_conoce_no_se_pierde(self):
        subs, _ = sub.resumen(APORTES + [aporte('regla_nueva', 'data_leaks', 'low', 8)], TODAS)
        self.assertEqual(subs[-1], {'category': 'data_leaks', 'subcategory': 'other', 'name': 'Sin clasificar',
                                    'findings': 1, 'penalty': 8.0})


class Piso(unittest.TestCase):

    def test_1_que_cuenta(self):
        self.assertTrue(c.cuenta_para_piso('critical', 'open'))
        self.assertTrue(c.cuenta_para_piso('critical', 'accepted_risk'))  # sigue en el score (#80)
        for severidad, estado in (('critical', 'resolved'), ('critical', 'false_positive'), ('high', 'open')):
            self.assertFalse(c.cuenta_para_piso(severidad, estado))

    def test_2_valores(self):
        self.assertEqual([c.piso(n) for n in (0, 1, 2, 5)], [0, 60, 80, 80])

    def test_3_notas_80_55_30_90_quedan_en_68(self):
        # 80, 55, 30 y 90 con los pesos v1 dan 68, y una fuga crítica abierta pone el piso en 60
        r = c.score_dominio(notas(80, 55, 30, 90), PESOS_V1, criticos=1)
        self.assertEqual(r, {'ponderado': 68, 'piso': 60, 'score': 68, 'banda': 'high', 'piso_aplicado': False})

    def test_4_el_promedio_no_esconde_un_critico(self):
        # un dominio con una fuga crítica abierta: la nota de fugas sube a 70 y el ponderado a 43
        r = c.score_dominio(notas(40, 30, 20, 70), PESOS_V1, criticos=1)
        self.assertEqual((r['ponderado'], r['score'], r['banda'], r['piso_aplicado']), (43, 60, 'high', True))
        r = c.score_dominio(notas(40, 30, 20, 70), PESOS_V1, criticos=2)
        self.assertEqual((r['score'], r['banda']), (80, 'critical'))

    def test_5_sin_criticos_solo_cuenta_el_ponderado(self):
        r = c.score_dominio(notas(60, 50, 40, 60), PESOS_V1)
        self.assertEqual((r['score'], r['banda'], r['piso_aplicado']), (54, 'medium', False))


class Ponderado(unittest.TestCase):

    def test_1_redondeo_hacia_arriba_en_punto_cinco(self):
        pesos = {'infrastructure': 0.5, 'digital_identity': 0.5, 'configuration': 0.0, 'data_leaks': 0.0}
        self.assertEqual(c.score_dominio(notas(60, 61, 0, 0), pesos)['ponderado'], 61)  # 60.5

    def test_2_pesos_que_no_suman_1(self):
        with self.assertRaises(ValueError):
            c.score_dominio(notas(1, 1, 1, 1), dict(PESOS_V1, data_leaks=0.4))

    def test_3_categorias_incompletas_o_fuera_de_rango(self):
        with self.assertRaises(ValueError):
            c.score_dominio({'infrastructure': 50}, PESOS_V1)
        with self.assertRaises(ValueError):
            c.score_dominio(notas(120, 0, 0, 0), PESOS_V1)


class Alerta(unittest.TestCase):

    def test_1_llega_o_pasa_el_umbral(self):
        self.assertTrue(c.dispara_alerta(60))
        self.assertTrue(c.dispara_alerta(68))
        self.assertFalse(c.dispara_alerta(59))

    def test_2_umbral_de_la_empresa(self):
        self.assertFalse(c.dispara_alerta(68, umbral=70))
        self.assertTrue(c.dispara_alerta(70, umbral=70))


if __name__ == '__main__':
    unittest.main(verbosity=2)
