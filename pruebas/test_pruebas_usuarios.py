"""Pruebas sin base ni red de las pruebas con usuarios de #50 (RC-93, docs/pruebas_usuarios.md).

Leen el documento como texto. Revisan el guion (las 5 tareas del Hecho cuando, cada una con lo que se lee, su criterio
de éxito y su tiempo límite), el cuestionario SUS, que no haya datos personales de los participantes y, cuando ya hay
resultados, que cuadren: 3 personas con sus 5 tareas, cada SUS sale de sus 10 respuestas, el promedio y el resumen
para S16 salen de las tablas, y cada tarea no completada tiene su hallazgo con arreglo y tarjeta.

    python -m unittest -v pruebas/test_pruebas_usuarios.py
"""
import re
import statistics
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
DOC = RAIZ / 'docs' / 'pruebas_usuarios.md'
SECCIONES = ('Estado', 'Quiénes participan', 'Lo que pone Ernesto antes de las sesiones', 'Consentimiento',
             'Protocolo de quien modera', 'Guion de las tareas', 'Cuestionario SUS', 'Al cerrar', 'Resultados')
# Las 5 tareas del Hecho cuando, en su orden.
TAREAS = {'T1': 'Entrar', 'T2': 'Dar de alta un dominio', 'T3': 'Ver el score y su porqué',
          'T4': 'Revisar el plan de acción', 'T5': 'Descargar un reporte'}
PERSONAS = ('P1', 'P2', 'P3')
TIEMPO = re.compile(r'^(\d{1,2}):([0-5]\d)$')
SIN_SESIONES = 'Sin sesiones todavía'
# Solo estas palabras pueden ir con mayúscula en un perfil: un nombre, una escuela o una empresa casi siempre la llevan.
MAYUSCULAS_PERMITIDAS = {'TI'}


def perfil_general(perfil):
    """Si `perfil` es general: 60 caracteres o menos, sin cifras (edad) y en minúsculas salvo «TI»."""
    if len(perfil) > 60 or re.search(r'\d', perfil):
        return False
    return all(p in MAYUSCULAS_PERMITIDAS or p.lower() == p for p in re.findall(r'\w+', perfil))


def seccion(texto, titulo, nivel='##'):
    """El cuerpo de la sección `titulo` del nivel dado, hasta la siguiente del mismo nivel o uno mayor."""
    inicio = texto.index('\n%s %s\n' % (nivel, titulo))
    fin = len(texto)
    for marca in ('\n## ', '\n### ')[:len(nivel) - 1]:
        siguiente = texto.find(marca, inicio + 1)
        if siguiente != -1:
            fin = min(fin, siguiente)
    return texto[inicio:fin]


def tabla(cuerpo):
    """Las filas de datos de la primera tabla de `cuerpo`, sin encabezado ni separador."""
    lineas = [ln for ln in cuerpo.splitlines() if ln.startswith('|')]
    return [[c.strip() for c in ln.strip().strip('|').split('|')] for ln in lineas[2:]]


def segundos(tiempo):
    m = TIEMPO.match(tiempo)
    return int(m.group(1)) * 60 + int(m.group(2)) if m else None


def mmss(s):
    return '%02d:%02d' % divmod(int(s + 0.5), 60)  # medio segundo hacia arriba, como dice el documento


def sus(respuestas):
    """El puntaje SUS de 10 respuestas de 1 a 5 (Brooke, 1996)."""
    return 2.5 * sum(r - 1 if i % 2 == 0 else 5 - r for i, r in enumerate(respuestas))


def limites(texto):
    """El tiempo límite en segundos de cada tarea, leído del guion."""
    guion = seccion(texto, 'Guion de las tareas')
    salida = {}
    for tarea in TAREAS:
        cuerpo = seccion(guion, '%s · %s' % (tarea, TAREAS[tarea]), '###')
        m = re.search(r'\*\*Límite:\*\* (\d+) min', cuerpo)
        salida[tarea] = int(m.group(1)) * 60 if m else None
    return salida


def revisar_resultados(texto):
    """Los errores de la sección Resultados. Vacía (antes de las sesiones) no da errores."""
    errores = []
    resultados = seccion(texto, 'Resultados')
    participantes = tabla(seccion(resultados, 'Participantes', '###'))
    tareas = tabla(seccion(resultados, 'Tareas', '###'))
    filas_sus = tabla(seccion(resultados, 'SUS', '###'))
    hallazgos = tabla(seccion(resultados, 'Hallazgos y tarjetas', '###'))
    s16 = tabla(seccion(resultados, 'Para S16', '###'))
    promedio = re.search(r'^SUS promedio: (.+)$', seccion(resultados, 'SUS', '###'), re.M)
    estado = [f[1] for f in tabla(seccion(texto, 'Estado')) if len(f) == 2 and f[0] == 'Resultados']
    sin_sesiones = estado == [SIN_SESIONES]

    if not (participantes or tareas or filas_sus or hallazgos or s16):
        if not promedio or promedio.group(1) != 'pendiente':
            errores.append('sin resultados, el SUS promedio debe decir «pendiente»')
        if not sin_sesiones:
            errores.append('Estado: sin resultados, la fila Resultados debe decir «%s»' % SIN_SESIONES)
        return errores
    if sin_sesiones:
        errores.append('Estado: hay resultados y la fila Resultados sigue diciendo «%s»' % SIN_SESIONES)

    if [p[0] for p in participantes] != list(PERSONAS):
        errores.append('Participantes: deben ser P1, P2 y P3, en orden')
    for p in participantes:
        if len(p) != 3 or not p[1] or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', p[2]):
            errores.append('Participantes: %s sin perfil o con una fecha que no es AAAA-MM-DD' % p[0])
        elif not perfil_general(p[1]):
            errores.append('Participantes: %s con un perfil que no es general (nombre, escuela, empresa o edad)' % p[0])

    tope = limites(texto)
    esperadas = [(p, t) for p in PERSONAS for t in TAREAS]
    if [tuple(f[:2]) for f in tareas] != esperadas:
        errores.append('Tareas: deben ser las 5 tareas de cada persona, en orden (P1 T1 … P3 T5)')
    no_completadas = set()
    for fila in tareas:
        if len(fila) != 5:
            errores.append('Tareas: fila con %d columnas' % len(fila))
            continue
        persona, tarea, completada, tiempo, atoro = fila
        if completada not in ('Sí', 'No'):
            errores.append('Tareas: %s %s debe decir Sí o No' % (persona, tarea))
        s = segundos(tiempo)
        if s is None:
            errores.append('Tareas: %s %s con un tiempo que no es mm:ss' % (persona, tarea))
        elif completada == 'Sí' and tope.get(tarea) and s > tope[tarea]:
            errores.append('Tareas: %s %s completada después de su límite' % (persona, tarea))
        if completada == 'No':
            no_completadas.add((persona, tarea))
            if len(atoro) < 10:
                errores.append('Tareas: %s %s no completada sin decir dónde se atoró' % (persona, tarea))

    puntajes = []
    if [f[0] for f in filas_sus] != list(PERSONAS):
        errores.append('SUS: deben ser P1, P2 y P3, en orden')
    for fila in filas_sus:
        try:
            respuestas = [int(x) for x in fila[1:11]]
            anotado = float(fila[11])
        except (ValueError, IndexError):
            errores.append('SUS: %s debe tener 10 respuestas enteras y su puntaje' % fila[0])
            continue
        if any(r not in range(1, 6) for r in respuestas):
            errores.append('SUS: %s con una respuesta fuera de 1 a 5' % fila[0])
            continue
        if anotado != sus(respuestas):
            errores.append('SUS: %s anota %s y sus respuestas dan %s' % (fila[0], fila[11], sus(respuestas)))
        puntajes.append(sus(respuestas))
    if puntajes:
        esperado = round(statistics.mean(puntajes), 1)
        if not promedio or promedio.group(1) != ('%.1f' % esperado):
            errores.append('SUS promedio: debe ser %.1f' % esperado)

    con_hallazgo, ids = set(), []
    for fila in hallazgos:
        if len(fila) != 6 or not re.fullmatch(r'H\d+', fila[0]):
            errores.append('Hallazgos: fila sin las 6 columnas o con un ID que no es H1, H2…')
            continue
        id_, persona, tarea, atoro, arreglo, tarjeta = fila
        ids.append(id_)
        if (persona, tarea) not in esperadas:
            errores.append('Hallazgos: %s es de %s %s, que no está en las tareas' % (id_, persona, tarea))
        con_hallazgo.add((persona, tarea))
        if len(atoro) < 10 or len(arreglo) < 10:
            errores.append('Hallazgos: %s sin dónde se atoró o sin arreglo' % id_)
        if not re.fullmatch(r'RC-\d+', tarjeta):
            errores.append('Hallazgos: %s sin la clave de su tarjeta (RC-NNN)' % id_)
    if len(ids) != len(set(ids)):
        errores.append('Hallazgos: IDs repetidos')
    for persona, tarea in sorted(no_completadas - con_hallazgo):
        errores.append('Hallazgos: %s %s no se completó y no tiene su hallazgo' % (persona, tarea))

    por_tarea = {t: [f for f in tareas if len(f) == 5 and f[1] == t] for t in TAREAS}
    if [f[0] for f in s16] != list(TAREAS):
        errores.append('Para S16: debe traer T1 a T5, en orden')
    for fila in s16:
        filas = por_tarea.get(fila[0], [])
        hechas = [segundos(f[3]) for f in filas if f[2] == 'Sí' and segundos(f[3]) is not None]
        completaron = '%d de %d' % (len(hechas), len(filas))
        mediano = mmss(statistics.median(hechas)) if hechas else '—'
        if fila[1:] != [completaron, mediano]:
            errores.append('Para S16: %s debe decir %s y %s' % (fila[0], completaron, mediano))
    return errores


CORREO = re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+')
# 8 cifras o más seguidas, con espacios, guiones o puntos sueltos entre ellas: un teléfono de 8 (8123 4567) o de 10
# (81 2345 6789). Las fechas AAAA-MM-DD de Participantes también tienen 8 cifras y no cuentan.
CIFRAS = re.compile(r'(?<![\w-])(?<!\d\.)\+?\d(?:[ .-]?\d){7,}(?![\w-])(?!\.\d)')
FECHA = re.compile(r'\d{4}-\d{2}-\d{2}')


def telefonos(texto):
    """Las cadenas de `texto` que parecen teléfonos (8 cifras o más), sin las fechas AAAA-MM-DD."""
    return [c for c in CIFRAS.findall(texto) if not FECHA.fullmatch(c)]


class PruebasConUsuarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texto = DOC.read_text(encoding='utf-8')

    def test_1_secciones(self):
        for titulo in SECCIONES:
            with self.subTest(seccion=titulo):
                self.assertIn('\n## %s\n' % titulo, self.texto)

    def test_2_las_5_tareas_con_lo_que_se_lee_su_exito_y_su_limite(self):
        guion = seccion(self.texto, 'Guion de las tareas')
        self.assertEqual(re.findall(r'^### (T\d) · ', guion, re.M), list(TAREAS))
        for tarea, nombre in TAREAS.items():
            with self.subTest(tarea=tarea):
                cuerpo = seccion(guion, '%s · %s' % (tarea, nombre), '###')
                self.assertRegex(cuerpo, r'\*\*Se lee:\*\* «[^»]{20,}»')
                self.assertRegex(cuerpo, r'\*\*Éxito:\*\* .{20,}')
                self.assertIsNotNone(limites(self.texto)[tarea], 'sin tiempo límite')

    def test_3_la_tarea_5_no_cuenta_la_lista_simulada(self):
        # La tarjeta «Reportes» de Histórico es simulada en el portal (getReports): descargar de ahí no es el reporte.
        t5 = seccion(seccion(self.texto, 'Guion de las tareas'), 'T5 · Descargar un reporte', '###')
        self.assertIn('ejemplo', t5)
        self.assertIn('no cuenta como éxito', t5)

    def test_4_sus_con_10_preguntas_y_su_calculo(self):
        cuestionario = seccion(self.texto, 'Cuestionario SUS')
        self.assertEqual([int(n) for n in re.findall(r'^(\d+)\. ', cuestionario, re.M)], list(range(1, 11)))
        for frase in ('de 1', 'a 5', 'cada respuesta impar', 'cada respuesta par', '2.5'):
            self.assertIn(frase, cuestionario)
        # El cálculo de la prueba es el de Brooke: todo 3 da 50, lo mejor 100 y lo peor 0.
        self.assertEqual(sus([3] * 10), 50)
        self.assertEqual(sus([5, 1] * 5), 100)
        self.assertEqual(sus([1, 5] * 5), 0)

    def test_5_sin_datos_personales_de_los_participantes(self):
        for correo in CORREO.findall(self.texto):
            with self.subTest(correo=correo):
                self.assertTrue(correo.endswith('@lowtidesec.com'), 'solo correos del equipo')
        self.assertEqual(telefonos(self.texto), [], 'un teléfono')
        resultados = seccion(self.texto, 'Resultados')
        for persona in re.findall(r'\bP\d+\b', resultados):
            self.assertIn(persona, PERSONAS)
        # Los perfiles de Participantes los revisa revisar_resultados (perfil_general) en test_6.
        consentimiento = seccion(self.texto, 'Consentimiento')
        for frase in ('no grabamos', 'Puedes parar cuando quieras', 'sin tu nombre', 'se destruye'):
            self.assertIn(frase, consentimiento)

    def test_6_los_resultados_cuadran(self):
        # Antes de las sesiones las tablas van vacías y Estado dice «Sin sesiones todavía»; si Estado dice que hubo
        # sesiones, las tablas no pueden ir vacías. Que pase no basta para Done: RC-93 pide los resultados.
        self.assertEqual(revisar_resultados(self.texto), [])

    def test_8_el_detector_de_telefonos(self):
        for numero in ('8123 4567', '81234567', '81 2345 6789', '+52 81 2345 6789', '81-2345-6789'):
            with self.subTest(numero=numero):
                self.assertEqual(telefonos('llamar al %s hoy' % numero), [numero])
                self.assertEqual(telefonos('me pidió llamar al %s.' % numero), [numero])
        for otro in ('2026-11-24', 'RC-93', '1996', 'S16', '01:30', '2.5'):
            with self.subTest(otro=otro):
                self.assertEqual(telefonos('el %s del documento' % otro), [])

    def test_7_lo_enlaza_el_indice_de_docs(self):
        self.assertIn('pruebas_usuarios.md', (RAIZ / 'docs' / 'README.md').read_text(encoding='utf-8'))


def _con_resultados(texto, tareas, sus_filas, promedio, hallazgos, s16, perfil='estudiante de otra carrera',
                    estado='3 sesiones el 2026-11-24'):
    """Una copia del documento con las tablas de Resultados llenas, para probar revisar_resultados."""
    filas = lambda datos: ''.join('| %s |\n' % ' | '.join(f) for f in datos)
    participantes = filas([[p, perfil, '2026-11-24'] for p in PERSONAS])
    texto = texto.replace('| Resultados | %s |' % SIN_SESIONES, '| Resultados | %s |' % estado)
    for titulo, extra in (('### Participantes', participantes), ('### Tareas', filas(tareas)),
                          ('### SUS', filas(sus_filas)), ('### Hallazgos y tarjetas', filas(hallazgos)),
                          ('### Para S16', filas(s16))):
        inicio = texto.index(titulo)
        separador = texto.index('|---', inicio)
        fin_linea = texto.index('\n', separador) + 1
        texto = texto[:fin_linea] + extra + texto[fin_linea:]
    return texto.replace('SUS promedio: pendiente', 'SUS promedio: %s' % promedio)


class RevisionDeResultados(unittest.TestCase):
    """revisar_resultados con resultados de ejemplo, bien y mal hechos."""

    @classmethod
    def setUpClass(cls):
        cls.base = DOC.read_text(encoding='utf-8')
        cls.tareas = [[p, t, 'Sí', '01:30', '—'] for p in PERSONAS for t in TAREAS]
        cls.tareas[4] = ['P1', 'T5', 'No', '03:00', 'Descargó de la tarjeta Reportes de Histórico']
        cls.sus = [['P1'] + '4 2 4 2 4 2 4 2 4 2'.split() + ['75'],
                   ['P2'] + '5 1 5 1 5 1 5 1 5 1'.split() + ['100'],
                   ['P3'] + '3 3 3 3 3 3 3 3 3 3'.split() + ['50']]
        cls.hallazgos = [['H1', 'P1', 'T5', 'Descargó de la tarjeta Reportes de Histórico',
                          'Quitar la tarjeta simulada o llevarla al reporte real', 'RC-999']]
        cls.s16 = [['T1', '3 de 3', '01:30'], ['T2', '3 de 3', '01:30'], ['T3', '3 de 3', '01:30'],
                   ['T4', '3 de 3', '01:30'], ['T5', '2 de 3', '01:30']]

    def revisar(self, **cambios):
        datos = dict(tareas=self.tareas, sus_filas=self.sus, promedio='75.0', hallazgos=self.hallazgos, s16=self.s16)
        datos.update(cambios)
        return revisar_resultados(_con_resultados(self.base, **datos))

    def test_1_bien_hechos_no_dan_errores(self):
        self.assertEqual(self.revisar(), [])

    def test_2_un_sus_mal_calculado(self):
        malo = [list(f) for f in self.sus]
        malo[0][11] = '80'
        self.assertTrue(any('P1 anota 80' in e for e in self.revisar(sus_filas=malo)))

    def test_3_un_promedio_mal_hecho(self):
        self.assertTrue(any('SUS promedio' in e for e in self.revisar(promedio='70.0')))

    def test_4_una_tarea_no_completada_sin_hallazgo(self):
        self.assertTrue(any('P1 T5 no se completó' in e for e in self.revisar(hallazgos=[])))

    def test_5_completada_despues_del_limite(self):
        tarde = [list(f) for f in self.tareas]
        tarde[0][3] = '03:01'  # T1 tiene 3 min
        errores = self.revisar(tareas=tarde)
        self.assertTrue(any('P1 T1 completada después' in e for e in errores))

    def test_7_hallazgo_sin_tarjeta_repetido_o_de_otra_tarea(self):
        sin_clave = [self.hallazgos[0][:5] + ['Por crear']]
        self.assertTrue(any('sin la clave de su tarjeta' in e for e in self.revisar(hallazgos=sin_clave)))
        repetido = self.hallazgos + [['H1', 'P2', 'T2', 'Buscó el botón en Activos', 'Poner el alta a la vista', 'RC-998']]
        self.assertTrue(any('IDs repetidos' in e for e in self.revisar(hallazgos=repetido)))
        otra = [['H1', 'P1', 'T6'] + self.hallazgos[0][3:]]
        self.assertTrue(any('T6, que no está' in e for e in self.revisar(hallazgos=otra)))

    def test_8_una_fila_corta_da_un_error_y_no_truena(self):
        corta = self.tareas[:-1] + [['P3']]
        self.assertTrue(any('en orden (P1 T1' in e for e in self.revisar(tareas=corta)))

    def test_9_mediana_con_medio_segundo_sube(self):
        self.assertEqual(mmss(statistics.median([90, 91])), '01:31')

    def test_10_estado_y_tablas_dicen_lo_mismo(self):
        # Con resultados, Estado no puede seguir sin sesiones.
        errores = self.revisar(estado=SIN_SESIONES)
        self.assertTrue(any('sigue diciendo' in e for e in errores))
        # Sin resultados, Estado no puede decir que ya hubo sesiones.
        vacio = self.base.replace('| Resultados | %s |' % SIN_SESIONES, '| Resultados | 3 sesiones hechas |')
        self.assertTrue(any('la fila Resultados debe decir' in e for e in revisar_resultados(vacio)))

    def test_11_un_perfil_con_nombre_escuela_o_edad(self):
        for perfil in ('estudiante del Tec de Monterrey', 'Ana, trabaja en TI', 'estudiante de 21 años',
                       'trabaja en TI en Grupo Bimbo', 'Estudiante de otra carrera'):
            with self.subTest(perfil=perfil):
                self.assertTrue(any('no es general' in e for e in self.revisar(perfil=perfil)))
        for perfil in ('trabaja en TI', 'estudiante de otra carrera', 'dirige una pyme de comercio'):
            with self.subTest(perfil=perfil):
                self.assertEqual(self.revisar(perfil=perfil), [])

    def test_6_falta_una_tarea_o_el_resumen_no_cuadra(self):
        self.assertTrue(any('en orden (P1 T1' in e for e in self.revisar(tareas=self.tareas[1:])))
        malo = [list(f) for f in self.s16]
        malo[4][1] = '3 de 3'
        self.assertTrue(any('T5 debe decir 2 de 3' in e for e in self.revisar(s16=malo)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
