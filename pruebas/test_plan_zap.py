"""Pruebas sin base ni red del plan de ZAP de RC-89 (docs/zap/plan.yaml, docs/pruebas_zap.md).

Leen el plan como texto (el CI sin base no instala PyYAML) y revisan que la cookie de la cuenta de prueba solo vaya a
lowtidesec.com y que las reglas de denegación de servicio estén apagadas en el propio plan, no por la imagen de ZAP.

    python -m unittest -v pruebas/test_plan_zap.py
"""
import re
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
PLAN = RAIZ / 'docs' / 'zap' / 'plan.yaml'
GUIA = RAIZ / 'docs' / 'pruebas_zap.md'
# Anclada con ^ y $: así vale igual si ZAP compara con matches() o con find() (una URL de otro host que traiga
# https://lowtidesec.com/ en la query no lleva la cookie).
URL_LOWTIDE = 'url: "^https://lowtidesec\\\\.com/.*$"'
# https://www.zaproxy.org/docs/alerts/ : Billion Laughs, Apache Range Header DoS, Buffer Overflow, Format String Error
# e Integer Overflow Error.
REGLAS_DOS = (40044, 10053, 30001, 30002, 30003)


def bloque(texto, inicio, fin):
    """El texto entre la primera línea que contiene `inicio` y la siguiente que contiene `fin`."""
    desde = texto.index(inicio)
    return texto[desde:texto.index(fin, desde + len(inicio))]


class PlanZap(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.plan = PLAN.read_text(encoding='utf-8')
        cls.guia = GUIA.read_text(encoding='utf-8')

    def test_1_el_replacer_solo_toca_lowtidesec(self):
        """Sin `url`, ZAP pondría la cookie en cualquier petición que saliera de él, también hacia terceros."""
        replacer = bloque(self.plan, '- type: replacer', '- type: spider')
        reglas = re.split(r'\n\s+- description:', replacer)[1:]
        self.assertEqual(len(reglas), 2, replacer)
        for regla in reglas:
            self.assertIn(URL_LOWTIDE, regla)
        self.assertIn('lt_session=${ZAP_LT_SESSION}', replacer)
        # Cada regla tiene un solo url y es el de lowtidesec.com.
        self.assertEqual(re.findall(r'^\s+url: .*$', replacer, re.M), ['        ' + URL_LOWTIDE] * 2)

    def test_2_reglas_de_denegacion_de_servicio_apagadas(self):
        ascan = bloque(self.plan, '- type: activeScan', '- type: report')
        reglas = dict(re.findall(r'- id: (\d+)\n\s+name: [^\n]+\n\s+threshold: "?(\w+)"?', ascan))
        for regla in REGLAS_DOS:
            self.assertEqual(reglas.get(str(regla)), 'off', regla)
            self.assertIn(str(regla), self.guia, regla)

    def test_3_la_cookie_no_queda_en_el_historial(self):
        """La guía pide leer la cookie sin eco y no cerrar sesión hasta el final."""
        self.assertIn("Read-Host -AsSecureString", self.guia)
        self.assertIn('read -rs ZAP_LT_SESSION', self.guia)
        self.assertIn('Cierra la pestaña sin cerrar sesión', self.guia)
        self.assertIn('Remove-Item Env:ZAP_LT_SESSION', self.guia)
        # Ningún ejemplo de la guía escribe el valor en la línea del comando.
        self.assertNotRegex(self.guia, r"\$env:ZAP_LT_SESSION = '[^…]")
        self.assertNotRegex(self.guia, r'-e ZAP_LT_SESSION=')


if __name__ == '__main__':
    unittest.main()
