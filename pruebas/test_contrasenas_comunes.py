"""La lista de contraseñas comunes (RC-281), sin base ni red y sin importar cirdan (biblioteca estándar).

    python -m unittest -v pruebas/test_contrasenas_comunes.py
"""
import hashlib
import re
import unittest
from pathlib import Path

DATOS = Path(__file__).resolve().parents[1] / 'cirdan' / 'auth' / 'datos'
LISTA = DATOS / 'contrasenas_comunes.txt'


class Lista(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.crudo = LISTA.read_bytes()
        cls.lineas = cls.crudo.decode('utf-8').split('\n')

    def test_1_al_menos_3000_de_12_a_128_caracteres(self):
        self.assertEqual(self.lineas[-1], '', 'termina con un salto de línea')
        lineas = self.lineas[:-1]
        self.assertGreaterEqual(len(lineas), 3000)
        fuera = [l for l in lineas if not 12 <= len(l) <= 128]
        self.assertEqual(fuera, [], 'MIN_LENGTH y MAX_LENGTH de cirdan/auth/passwords.py')

    def test_2_sin_repetidas_sin_importar_mayusculas_ni_lineas_raras(self):
        lineas = self.lineas[:-1]
        self.assertEqual(len({l.casefold() for l in lineas}), len(lineas))
        self.assertEqual([l for l in lineas if l != l.strip() or not l.isprintable()], [])
        self.assertNotIn(b'\r', self.crudo, 'fin de línea LF: .gitattributes lo fija para que el sha256 no cambie')

    def test_3_el_readme_dice_su_fuente_su_licencia_y_su_sha256(self):
        leeme = (DATOS / 'README.md').read_text(encoding='utf-8')
        self.assertIn('https://github.com/danielmiessler/SecLists', leeme)
        self.assertRegex(leeme, r'Commit: `[0-9a-f]{40}`')
        self.assertIn('MIT', leeme)
        self.assertIn(hashlib.sha256(self.crudo).hexdigest(), leeme)
        self.assertIn('%s contraseñas' % format(len(self.lineas) - 1, ',').replace(',', ' '), leeme)
        licencia = (DATOS / 'LICENSE-SecLists').read_text(encoding='utf-8')
        self.assertTrue(re.match(r'MIT License\s+Copyright \(c\) \d{4} Daniel Miessler', licencia), licencia[:80])


if __name__ == '__main__':
    unittest.main(verbosity=2)
