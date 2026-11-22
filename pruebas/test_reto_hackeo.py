"""Pruebas sin base ni red del reto de hackeo de #85 (RC-157, docs/reto_hackeo.md).

Leen el documento como texto y revisan lo que pide el Hecho cuando: permiso del profesor, alcance solo sobre nuestro
despliegue, sin denegación de servicio ni ingeniería social, y un registro donde cada reporte va con su arreglo y los
de severidad Alta no se cierran sin él.

    python -m unittest -v pruebas/test_reto_hackeo.py
"""
import re
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
RETO = RAIZ / 'docs' / 'reto_hackeo.md'
SECCIONES = ('Estado', 'Alcance', 'Reglas', 'Lo que pone Ernesto antes de la ventana', 'Cómo reportar',
             'Clasificación', 'Al cerrar la ventana', 'Registro')
COLUMNAS = ['ID', 'Fecha', 'Equipo', 'Título', 'Severidad', 'Estado', 'Arreglo', 'Por qué']
SEVERIDADES = ('Alta', 'Media', 'Baja', 'Informativa')
ESTADOS = ('abierto', 'corregido', 'justificado', 'duplicado')


def seccion(texto, titulo):
    """El cuerpo de la sección `## titulo`, hasta la siguiente de nivel 2."""
    inicio = texto.index('\n## %s\n' % titulo)
    fin = texto.find('\n## ', inicio + 1)
    return texto[inicio:fin if fin != -1 else len(texto)]


ARREGLO = re.compile(r'(#\d+|https://github\.com/\S+/(pull|commit)/\S+|\b[0-9a-f]{7,40}\b)')
DOMINIO = re.compile(r'\b(?:[a-z0-9-]+\.)+(?:com|mx|net|org|io|dev)\b')


def celdas(linea):
    """Celdas de una fila markdown; un `\\|` escapado no parte la celda."""
    partes = re.split(r'(?<!\\)\|', linea.strip().strip('|'))
    return [c.strip().replace('\\|', '|') for c in partes]


def filas(tabla_texto, columnas):
    """Filas de la tabla markdown cuyo encabezado es `columnas`, hasta la primera línea que no es de tabla."""
    lineas = tabla_texto.splitlines()
    encabezado = '| ' + ' | '.join(columnas) + ' |'
    salida = []
    for linea in lineas[lineas.index(encabezado) + 2:]:
        if not linea.startswith('|'):
            break
        salida.append(celdas(linea))
    return salida


class RetoDeHackeo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texto = RETO.read_text(encoding='utf-8')

    def test_1_secciones_del_hecho_cuando(self):
        for titulo in SECCIONES:
            with self.subTest(seccion=titulo):
                self.assertIn('\n## %s\n' % titulo, self.texto)
        estado = seccion(self.texto, 'Estado')
        self.assertIn('Permiso escrito del profesor', estado)
        self.assertIn('Sin el permiso escrito, el reto no empieza.', estado)

    def test_2_alcance_solo_nuestro_despliegue(self):
        alcance = seccion(self.texto, 'Alcance')
        dentro, fuera = alcance.split('**Fuera**', 1)
        # Con o sin https://: el único host dentro del alcance es lowtidesec.com.
        self.assertEqual(set(DOMINIO.findall(dentro.lower())), {'lowtidesec.com'})
        self.assertIn('cuentas de prueba', dentro)
        for excluido in ('dominios de clientes', 'olmardo.com', 'pruebas.lowtidesec.com', 'PC del plan B',
                         'Cloudflare', 'Azure', 'Resend', 'cuentas de demo', 'equipo@lowtidesec.com'):
            with self.subTest(fuera=excluido):
                self.assertIn(excluido, fuera)

    def test_3_reglas_sin_dos_ni_ingenieria_social(self):
        reglas = seccion(self.texto, 'Reglas')
        for regla in ('Sin denegación de servicio', 'Sin ingeniería social', 'Sin pivotear', 'se para ahí',
                      'Solo dentro de la ventana', 'Nada se publica'):
            with self.subTest(regla=regla):
                self.assertIn(regla, reglas)

    def test_4_reportes_por_correo_y_escala(self):
        self.assertIn('seguridad@lowtidesec.com', seccion(self.texto, 'Cómo reportar'))
        escala = {f[0]: f for f in filas(seccion(self.texto, 'Clasificación'), ['Severidad', 'Cuándo', 'Qué se hace'])}
        self.assertEqual(tuple(escala), SEVERIDADES)
        self.assertEqual(escala['Alta'][2], 'Se corrige antes del 25 nov')
        self.assertEqual(escala['Media'][2], 'Corregido o justificado')
        for acceso in ('otra organización', 'RLS', 'secretos'):
            self.assertIn(acceso, escala['Alta'][1])

    def test_5_registro_con_arreglo_y_altas_cerradas_solo_con_el(self):
        registro = seccion(self.texto, 'Registro')
        for fila in filas(registro, COLUMNAS):
            with self.subTest(reporte=fila[0]):
                self.assertEqual(len(fila), len(COLUMNAS))
                self.assertRegex(fila[0], r'^R-\d{2,}$')
                self.assertIn(fila[4], SEVERIDADES)
                self.assertIn(fila[5], ESTADOS)
                if fila[4] == 'Alta':
                    self.assertNotEqual(fila[5], 'justificado', 'un reporte Alto se corrige, no se justifica')
                    if fila[5] == 'corregido':
                        self.assertRegex(fila[6], ARREGLO, 'un reporte Alto se cierra con su PR o commit')
                if fila[5] in ('justificado', 'duplicado'):
                    self.assertTrue(fila[7], 'justificado o duplicado dice por qué')

    def test_6_las_politicas_enlazan_el_reto(self):
        for nombre in ('politica_uso_etico.md', 'politica_seguridad_privacidad.md', 'README.md'):
            with self.subTest(documento=nombre):
                self.assertIn('(reto_hackeo.md)', (RAIZ / 'docs' / nombre).read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
