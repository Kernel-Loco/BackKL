"""Pruebas de la política de seguridad y privacidad (#78, RC-39), sin base de datos ni red.

Leen docs/politica_seguridad_privacidad.md y revisan su Hecho cuando: que integre las reglas de la política de uso
ético de #6, que nombre todos los controles del Anexo A de ISO/IEC 27001:2022 (los que aplican y los que no), que el
aviso de privacidad traiga las 6 fracciones del artículo 15 de la LFPDPPP, minimización, retención, derechos ARCO y a
quién se dirigen, la validez legal, la tabla de pros y contras y el proveedor de IA de #38. También revisan que cada
'sección N.M de #6' exista en la política de #6, que cada 'sección N.M' propia exista y que los enlaces a otros
documentos lleven a un archivo que existe.

    python -m unittest -v pruebas/test_politica_seguridad.py
"""
import re
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
POLITICA = RAIZ / 'docs' / 'politica_seguridad_privacidad.md'
USO_ETICO = RAIZ / 'docs' / 'politica_uso_etico.md'

# Controles del Anexo A de ISO/IEC 27001:2022: 37 organizacionales, 8 de personas, 14 físicos y 34 tecnológicos.
ANEXO_A = {5: 37, 6: 8, 7: 14, 8: 34}


def _texto(ruta):
    return ruta.read_text(encoding='utf-8')


def _seccion(texto, titulo):
    """Devuelve el cuerpo de la sección cuyo encabezado empieza con titulo, hasta el siguiente del mismo nivel."""
    m = re.search(r'^(#+) ' + re.escape(titulo) + r'.*$', texto, re.MULTILINE)
    if not m:
        return None
    nivel = len(m.group(1))
    resto = texto[m.end():]
    fin = re.search(r'^#{1,%d} ' % nivel, resto, re.MULTILINE)
    return resto[:fin.start()] if fin else resto


def _controles_nombrados(texto):
    """Controles del Anexo A citados en la sección 4, sueltos (5.1) o en rango (5.19 a 5.22)."""
    cuerpo = _seccion(texto, '4. Controles del Anexo A')
    vistos = set()
    for a, b, c in re.findall(r'\b([5-8])\.(\d{1,2})(?: a \1\.(\d{1,2}))?\b', cuerpo):
        inicio = int(b)
        fin = int(c) if c else inicio
        vistos.update((int(a), n) for n in range(inicio, fin + 1))
    return vistos


class PoliticaSeguridadPrivacidad(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.texto = _texto(POLITICA)
        cls.uso_etico = _texto(USO_ETICO)

    def test_1_secciones_del_hecho_cuando(self):
        for titulo in ('1. Alcance', '2. Metodología de ISO/IEC 27001:2022', '3. Reglas que se integran',
                       '4. Controles del Anexo A', '5. Privacidad y aviso de privacidad', '5.2 Aviso de privacidad',
                       '5.3 Datos de empleados', '5.5 Minimización', '5.6 Retención', '5.7 Derechos ARCO',
                       '5.8 Proveedor de IA', '6. Validez legal', '7. Pros y contras', '9. Pendientes'):
            with self.subTest(titulo=titulo):
                self.assertIsNotNone(_seccion(self.texto, titulo), f'falta la sección {titulo}')

    def test_2_integra_la_politica_de_6(self):
        self.assertIn('](politica_uso_etico.md)', self.texto)
        self.assertTrue('](politica_seguridad_privacidad.md)' in self.uso_etico,
                        'la política de #6 debe enlazar a la de #78')
        self.assertFalse('integrará estas reglas' in self.uso_etico, '#6 todavía dice que #78 está por hacerse')

    def test_3_todos_los_controles_del_anexo_a(self):
        vistos = _controles_nombrados(self.texto)
        esperados = {(tema, n) for tema, total in ANEXO_A.items() for n in range(1, total + 1)}
        self.assertEqual(sorted(esperados - vistos), [], 'controles del Anexo A sin nombrar en la sección 4')
        self.assertEqual(sorted(vistos - esperados), [], 'controles que no existen en el Anexo A de 2022')

    def test_4_aviso_con_las_fracciones_del_articulo_15(self):
        aviso = _seccion(self.texto, '5.2 Aviso de privacidad')
        # Cada punto del aviso cierra con su fracción, como '(fracción II):'.
        for fraccion in ('I', 'II', 'III', 'IV', 'V', 'VI'):
            with self.subTest(fraccion=fraccion):
                self.assertIn(f'(fracción {fraccion}):', aviso)
        self.assertIn('art. 16, fracción II', aviso, 'falta el aviso simplificado')

    def test_5_datos_de_empleados_minimizacion_y_arco(self):
        empleados = _seccion(self.texto, '5.3 Datos de empleados')
        for dato in ('correos', 'brecha', 'GitHub', 'identidad pasiva', 'Para qué'):
            self.assertIn(dato, empleados)
        self.assertIn('art. 2, fracción X', empleados, 'falta por qué una brecha no es fuente de acceso público')
        minimizacion = _seccion(self.texto, '5.5 Minimización')
        self.assertIn('huella', minimizacion)
        self.assertIn('contraseñas', minimizacion)
        retencion = _seccion(self.texto, '5.6 Retención')
        self.assertIn('12 meses', retencion)
        arco = _seccion(self.texto, '5.7 Derechos ARCO')
        self.assertIn('La empresa, que es la responsable', arco, 'falta a quién se dirigen los empleados')
        self.assertIn('20 días hábiles', arco)

    def test_6_validez_legal(self):
        legal = _seccion(self.texto, '6. Validez legal')
        for cita in ('211 bis 1', 'art. 5', 'art. 18', 'art. 20', 'Secretaría Anticorrupción y Buen Gobierno'):
            self.assertIn(cita, legal)
        self.assertIn('DOF 20 de marzo de 2025', self.texto)

    def test_7_tabla_de_pros_y_contras(self):
        tabla = _seccion(self.texto, '7. Pros y contras')
        self.assertIn('| Decisión | Pros | Contras |', tabla)
        filas = [f for f in tabla.splitlines() if f.startswith('|') and not f.startswith('|---')]
        self.assertGreaterEqual(len(filas) - 1, 5, 'la tabla de pros y contras debe tener al menos 5 decisiones')

    def test_8_proveedor_de_ia_y_alcance_territorial(self):
        ia = _seccion(self.texto, '5.8 Proveedor de IA')
        for nombre in ('Cloudflare Workers AI', 'Groq', 'gpt-oss-120b', 'fuera de México', 'art. 2, fracción XX'):
            self.assertIn(nombre, ia)
        self.assertNotIn('gpt-oss-20b', ia)
        alcance = _seccion(self.texto, '1. Alcance')
        for cita in ('artículo 28 del RGPD', '2021/914', 'artículo 14 del RGPD'):
            self.assertIn(cita, alcance)

    def test_9_referencias_y_enlaces(self):
        # Secciones de #6: 'sección 4.3 de #6' pide la regla 3 de la sección 4, 'sección 8 de #6' la sección 8.
        secciones_6 = {int(n) for n in re.findall(r'^## (\d+)\. ', self.uso_etico, re.MULTILINE)}
        for sec, regla in re.findall(r'[Ss]ecci(?:ón|ones) (\d+)(?:\.(\d+))? de #6', self.texto):
            with self.subTest(seccion=f'{sec}.{regla}' if regla else sec):
                self.assertIn(int(sec), secciones_6)
                if regla:
                    cuerpo = _seccion(self.uso_etico, f'{sec}. ')
                    self.assertRegex(cuerpo, rf'(?m)^{regla}\. ', f'#6 no tiene la regla {sec}.{regla}')
        # Secciones propias con número, como 'sección 5.7'.
        propias = set(re.findall(r'^#{2,3} (\d+(?:\.\d+)?)\.? ', self.texto, re.MULTILINE))
        sin_6 = re.sub(r'[Ss]ecci(?:ón|ones) [\d., y]+ de (?:#6|la carta)', '', self.texto)
        for ref in re.findall(r'[Ss]ección (\d+\.\d+)(?! de)', sin_6):
            with self.subTest(ref=ref):
                self.assertIn(ref, propias, f'la sección {ref} no existe')
        for destino in re.findall(r'\]\(([^)#]+)\)', self.texto):
            with self.subTest(enlace=destino):
                self.assertTrue((POLITICA.parent / destino).exists(), f'{destino} no existe')


if __name__ == '__main__':
    unittest.main()
