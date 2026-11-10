"""Pruebas de la política de seguridad y privacidad (#78, RC-39), sin base de datos ni red.

Leen docs/politica_seguridad_privacidad.md y revisan su Hecho cuando: que integre las reglas de la política de uso
ético de #6, que nombre todos los controles del Anexo A de ISO/IEC 27001:2022 (los que aplican y los que no), que el
aviso de privacidad traiga las 6 fracciones del artículo 15 de la LFPDPPP, minimización, retención, derechos ARCO y a
quién se dirigen, la validez legal, la tabla de pros y contras y el proveedor de IA de #38. También revisan que cada
sección de #6 que se cite, sola o en lista ('secciones 1, 2 y 7 de #6'), exista en la política de #6, que cada sección
propia que se cite ('sección 9', 'secciones 5.1 y 5.2' o 'sección 1 de esta política') exista, igual que cada
'punto N' que se cite de una sección propia, y que los enlaces a otros documentos lleven a un archivo que existe. Las
citas a la carta no se revisan.

test_10 revisa el Hecho cuando de #96g (RC-207): los términos de uso de la sección 11 en 1 página con cada pieza en su
punto, el responsable provisional en el aviso integral y en el simplificado, la matriz de responsable y encargado de la
sección 5.1 y el buzón arco@lowtidesec.com probado con un correo real. También revisa que hallazgos_esperados.md y
servicios_externos.md pongan #19 (RC-54) y la llave de HIBP detrás de la revisión legal de la sección 9, y que esa
fila de la sección 9 lleve como pendiente de carta la fecha prevista de #19 en el Anexo A de la carta.

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
                       '5.8 Proveedor de IA', '6. Validez legal', '7. Pros y contras', '9. Pendientes',
                       '5.1 Quién responde', '11. Términos de uso del portal'):
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
        # Una brecha puede revelar datos sensibles, que piden consentimiento expreso y por escrito (r15-datos-1).
        for cita in ('5. Brechas que revelan datos sensibles:', '(art. 2, fracción VI)',
                     'el consentimiento expreso y por escrito, que el aviso de la empresa no da',
                     'Hoy nada separa esas brechas', 'es parte de la revisión legal de la sección 9',
                     'antes de que exista el recolector de brechas (#19, RC-54)'):
            with self.subTest(seccion='5.3', cita=cita):
                self.assertIn(cita, empleados)
        matriz = _seccion(self.texto, '5.1 Quién responde')
        fila = next(f for f in matriz.splitlines() if f.startswith('| Empleados, exempleados'))
        self.assertIn('Una brecha que revela datos sensibles pide consentimiento expreso y por escrito '
                      '(sección 5.3, punto 5) |', fila, 'la matriz no dice lo de las brechas sensibles')
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
        # También en lista, como 'secciones 1, 2, 7 y 8 de #6'.
        secciones_6 = {int(n) for n in re.findall(r'^## (\d+)\. ', self.uso_etico, re.MULTILINE)}
        num = r'\d+(?:\.\d+)?'
        for lista in re.findall(rf'[Ss]ecci(?:ón|ones) ({num}(?:(?:, | y ){num})*) de #6', self.texto):
            for sec, regla in re.findall(r'(\d+)(?:\.(\d+))?', lista):
                with self.subTest(seccion=f'{sec}.{regla}' if regla else sec):
                    self.assertIn(int(sec), secciones_6)
                    if regla:
                        cuerpo = _seccion(self.uso_etico, f'{sec}. ')
                        self.assertRegex(cuerpo, rf'(?m)^{regla}\. ', f'#6 no tiene la regla {sec}.{regla}')
        # Secciones propias, como 'sección 5.7', 'sección 9' o 'sección 1 de esta política', y sus puntos, como
        # '(sección 11, punto 2)' o 'punto 6 de la sección 5.2'. Las citas de #6 y de la carta se quitan antes, y
        # cualquier otra 'sección N de' que quede se revisa como propia.
        propias = set(re.findall(r'^#{2,3} (\d+(?:\.\d+)?)\.? ', self.texto, re.MULTILINE))
        sin_6 = re.sub(r'[Ss]ecci(?:ón|ones) [\d., y]+ de (?:#6|la carta|su carta)', '', self.texto)
        sin_6 = sin_6.replace(' de esta política', '')
        for lista in re.findall(rf'[Ss]ecci(?:ón|ones) ({num}(?:(?:, | y ){num})*)(?![\d.]*\d)', sin_6):
            for ref in re.findall(num, lista):
                with self.subTest(ref=ref):
                    self.assertIn(ref, propias, f'la sección {ref} no existe')
        citas_de_puntos = re.findall(rf'[Ss]ección ({num}), puntos? (\d+)', sin_6)
        citas_de_puntos += [(s, p) for p, s in re.findall(rf'punto (\d+) de la sección ({num})(?![\d.]*\d)', sin_6)]
        for sec, punto in citas_de_puntos:
            with self.subTest(seccion=sec, punto=punto):
                encabezado = next((t for t in re.findall(r'(?m)^#{2,3} (.*)$', self.texto)
                                   if re.match(re.escape(sec) + r'\.? ', t)), None)
                self.assertIsNotNone(encabezado, f'la sección {sec} no existe')
                self.assertRegex(_seccion(self.texto, encabezado), rf'(?m)^{punto}\. ',
                                 f'la sección {sec} no tiene el punto {punto}')
        for destino in re.findall(r'\]\(([^)#]+)\)', self.texto):
            with self.subTest(enlace=destino):
                self.assertTrue((POLITICA.parent / destino).exists(), f'{destino} no existe')

    def test_10_terminos_responsable_y_buzon_arco(self):
        # Hecho cuando de #96g (RC-207): términos de 1 página, responsable provisional, matriz y buzón ARCO.
        terminos = _seccion(self.texto, '11. Términos de uso del portal')
        for cita in ('sección 1 de #6', 'sección 2 de #6', 'sección 7 de #6', 'nombre provisional',
                     'arco@lowtidesec.com'):
            with self.subTest(cita=cita):
                self.assertIn(cita, terminos)
        # Cada pieza en su punto: quién puede usarlo, qué dominios (carta y TXT) y qué pasa al terminar.
        puntos = {m.group(1): m.group(2) for m in re.finditer(r'(?m)^(\d+)\. (.*)$', terminos)}
        self.assertTrue(puntos.get('2', '').startswith('Quién puede usarlo:'), 'falta quién puede usarlo')
        for cita in ('cuenta propia', 'empresa que firmó la carta de autorización',
                     'mientras tenga una vigente (punto 7)'):
            with self.subTest(punto=2, cita=cita):
                self.assertIn(cita, puntos['2'])
        self.assertTrue(puntos.get('3', '').startswith('Qué dominios:'), 'falta qué dominios')
        # La base lo exige solo al orquestador, porque un recolector a mano no pasa por ella (sección 1.2 de #6), y
        # frena una revocación solo desde que se registra (sección 5.6): no lo rechaza todo (r13-1, r14-1, r14-2).
        for cita in ('carta firmada y vigente', 'TXT verificado', 'con carta firmada y vigente y TXT verificado',
                     'La base lo exige al orquestador, pero frena una revocación solo desde que se registra '
                     '(sección 5.6).'):
            with self.subTest(punto=3, cita=cita):
                self.assertIn(cita, puntos['3'])
        self.assertNotRegex(puntos['3'], r'(?i)aunque no|sin carta|sin TXT',
                            'el punto 3 no puede abrir una excepción a la carta y el TXT')
        self.assertTrue(puntos.get('4', '').startswith('Qué hace: solo observa'), 'falta la observación pasiva')
        self.assertIn('sección 2 de #6', puntos['4'])
        self.assertTrue(puntos.get('7', '').startswith('Al terminar:'), 'falta qué pasa al terminar')
        # Dos disparadores, cada uno en su frase y en este orden. El fin de la última carta solo desactiva la cuenta,
        # que vuelve si en [30] días llega una carta nueva, cuando empiece y sin otra causa de baja (r8-1, r8-2). La
        # huella se borra a los [30] días sin carta, al cerrar el curso o con el escrito. Desde ese fin, o antes si el
        # equipo revoca las cartas, lo que queda como prueba pasa a bloqueo y los hallazgos se borran (r8-4, r8-7).
        # Son 5 frases: una frase nueva no puede sumar otro borrado (r7-8 caso B, r9-8).
        frases = re.split(r'(?<=\.) (?=[A-ZÁÉÍÓÚ])', puntos['7'])
        self.assertEqual(len(frases), 5, 'el punto 7 tiene 5 frases')

        def frase(cita):
            hay = [i for i, f in enumerate(frases) if cita in f]
            self.assertEqual(len(hay), 1, f'el punto 7 debe tener una sola frase con {cita!r}')
            return hay[0], frases[hay[0]]

        i_carta, carta = frase('al vencer o revocarse la última carta de la empresa')
        # Lista blanca: la frase del fin de la carta no admite agregados ni paráfrasis (r8-9, r8-10).
        self.assertEqual(carta, 'Al terminar: al vencer o revocarse la última carta de la empresa, la cuenta se '
                         'desactiva, y si en [30] días el equipo carga una carta nueva, se reactiva cuando esta '
                         'empiece, salvo que otra causa la mantenga desactivada.',
                         'el fin de la carta solo desactiva la cuenta hasta que empiece la carta nueva')
        i_cuenta, cuenta = frase('se borran la huella')
        # Lista blanca: la huella no se borra al vencer, terminar ni expirar la carta (r7-8 caso A, r9-8), y el
        # escrito es el que pide borrar todos los datos, no una cuenta ni un dominio (r9-5, r10-3).
        self.assertEqual(cuenta, 'A los [30] días de ese fin sin carta nueva, al cerrar el curso o antes si la '
                         'empresa pide por escrito borrar todos sus datos, la cuenta se desactiva, se borran la '
                         'huella de su contraseña y su semilla TOTP, y su nombre y correo quedan en bloqueo y al '
                         'final se anonimizan.',
                         'la huella se borra a los [30] días, al cerrar el curso o con el escrito de borrado')
        # Ninguna otra frase borra claves (r7-8 caso B).
        self.assertEqual(sum(bool(re.search(r'(?i)huella|TOTP|contraseña|clave|dos pasos', f)) for f in frases), 1,
                         'solo una frase del punto 7 borra la huella o la semilla TOTP')
        # Los registros de acceso son filas de la bitácora: un solo inicio y un solo final de bloqueo (r8-5).
        self.assertNotIn('registros de acceso', puntos['7'], 'los registros de acceso van con la bitácora')
        i_prueba, prueba = frase('quedan en bloqueo por [plazo]')
        self.assertTrue(prueba.startswith('Desde ese fin, o antes cuando el equipo revoca las cartas de la empresa '
                                          'al cerrar el curso o con ese escrito,'),
                        'el bloqueo cuenta desde el fin de la carta, o desde que el equipo la revoca (r9-5)')
        for cita in ('las cartas, los datos de quien firma, las verificaciones del TXT, la bitácora hasta entonces',
                     'y, desde que se cierran, las solicitudes ARCO de usuarios y de quien firma',
                     'quedan en bloqueo por [plazo], solo como prueba, y al final se suprimen o se anonimizan '
                     '(sección 5.6), y',
                     'hallazgos, activos y reportes de la empresa se borrarán en [30] días, con confirmación.'):
            with self.subTest(punto=7, frase='prueba', cita=cita):
                self.assertIn(cita, prueba)
        # Lista blanca: la frase 3 no admite sinónimos como 'credenciales' ni agregados (r10-7), y las solicitudes ARCO
        # cuentan su [plazo] desde que se cierran, no desde el fin de la carta ni del curso, como dice la sección 5.6
        # (r11-6, r12-8). Con las 5 frases en lista blanca, la cuenta de frases que borran claves y la de 'registros de
        # acceso' son de respaldo.
        self.assertEqual(prueba, 'Desde ese fin, o antes cuando el equipo revoca las cartas de la empresa al cerrar '
                         'el curso o con ese escrito, las cartas, los datos de quien firma, las verificaciones del '
                         'TXT, la bitácora hasta entonces y, desde que se cierran, las solicitudes ARCO de usuarios '
                         'y de quien firma quedan en bloqueo por [plazo], solo como prueba, y al final se suprimen o '
                         'se anonimizan (sección 5.6), y los hallazgos, activos y reportes de la empresa se borrarán '
                         'en [30] días, con confirmación.',
                         'la frase 3 pone en bloqueo lo que queda como prueba y borra los hallazgos (r10-7, r11-6, '
                         'r12-8)')
        self.assertLess(i_carta, i_cuenta, 'el fin de la carta va antes que el borrado de la huella')
        self.assertLess(i_cuenta, i_prueba, "'ese fin' es el de la primera frase y el bloqueo va al final")
        self.assertEqual(frases[3], 'Los de un dominio, igual al vencer o revocarse su última carta.')
        # Lo que la base no deja hacer: hoy no se borra ningún hallazgo que ya entró en un score, porque el rol de
        # retención no existe y cirdan_app no borra hallazgos (r9-7, r9-9, r10-6).
        self.assertEqual(frases[4], 'Hoy la base no deja borrar ni anonimizar lo bloqueado ni los hallazgos que ya '
                         'entraron en un score, y el fin de la carta no desactiva ni reactiva las cuentas '
                         '(sección 9).', 'el punto 7 cierra con lo que hoy la base no permite')
        # Fuera del punto 7 dicen lo mismo el aviso, la retención y los pendientes (r8-1 a r8-4, r8-8, r8-10, r9-1 a
        # r9-3, r9-5 a r9-7, r9-10, r10-1 a r10-8, r11-1 a r11-9 y r12-1 a r12-9). La revocación de la empresa termina
        # la carta cuando llega su escrito, como dice la sección 8 de la carta, que manda sobre esta política (r11-1).
        # Un análisis que entra antes de la pausa corre sin carta vigente: la carta no lo deja (r12-2, r12-3). La
        # venta termina la carta en la fecha de la venta, y se revocan todas las cartas sin revocar del dominio, porque
        # una revocación no se deshace (r12-4, r12-5, r13-2). Su fecha es a las 0:00 en hora del centro de México, y
        # sin ella los análisis entre la venta y el aviso parecen autorizados (r13-3). La pausa es una sola regla, en
        # cuanto el equipo lee el escrito o el aviso (r13-4, r13-5).
        retencion = _seccion(self.texto, '5.6 Retención')
        for cita in ('Mientras la carta esté vigente se usan para autorizar cada análisis',
                     'al vencer o revocarse la última carta de la empresa o al cerrar el curso',
                     'o antes si la empresa lo pide por escrito (sección 6 de la carta y sección 11, punto 7)',
                     'Se borran en un plazo de [30] días, con confirmación',
                     '`cirdan_app` no puede borrar hallazgos, activos, reportes, alertas ni `breach_exposures`, y un '
                     'hallazgo que ya entró en un score no se puede borrar',
                     'porque solo `cirdan_retention`, que todavía no existe, podrá borrar scores, y solo los de más '
                     'de 12 meses',
                     'Al terminar la carta, o antes cuando el equipo la revoca al cerrar el curso o porque la empresa '
                     'pide por escrito borrar todos sus datos (sección 11, punto 7), pasan a bloqueo por [plazo] '
                     '(sección 6 de la carta), solo como prueba',
                     'La revocación de la empresa termina la carta cuando llega su escrito o su correo, y no cuando '
                     'el equipo pone el dominio en pausa ni cuando la registra',
                     'salvo en un análisis que entre después del fin y antes de que el dominio quede en pausa, que '
                     'hoy los usa sin carta vigente (sección 9)',
                     'Entre ese fin y la pausa, que el equipo hace ese mismo día, todavía puede entrar un análisis',
                     'porque el orquestador lo frena desde la pausa y la base solo desde que se registra la '
                     'revocación',
                     'Ese análisis corre sin carta vigente, algo que la carta y la sección 1 de #6 no permiten',
                     'Si el dominio ya estaba en pausa por una suspensión no se inicia ninguno (sección 8 de la '
                     'carta)',
                     'Ni el escrito de la sección 6 de la carta, que pide borrar los hallazgos, activos y reportes, '
                     'ni el que pide borrar solo una cuenta o un dominio revocan las cartas.',
                     'La bitácora no se separa por dominio ni por carta, así que por el fin de una carta pasa a '
                     'bloqueo solo al terminar la última de la empresa',
                     'Lo que ya estaba en bloqueo, como una carta anterior que ya terminó, no reinicia su plazo',
                     'las filas de la bitácora que se escriban después del fin de la última carta de la empresa y '
                     'antes de que empiece una carta nueva', 'pasan a bloqueo desde que se escriben',
                     'igual que las verificaciones del TXT que se escriban después del fin de la última carta de su '
                     'dominio',
                     'Las filas de un usuario sí se separan por `actor_user_id`, así que las de quien revoca su '
                     'consentimiento o cancela su cuenta pasan a bloqueo desde ese momento',
                     'Hoy la carta solo deja revocar a la empresa, aunque la sección 8 de #6 también la revoca por '
                     'uso indebido',
                     'con la fecha de su último acceso, pasan a bloqueo',
                     '[plazo] contado desde que se cierran',
                     'El fin de la carta no reinicia el plazo de las que ya estaban cerradas',
                     'Se borra el mismo día. Hoy no se puede si llegó en un TXT del dominio raíz, porque queda en '
                     '`dns_txt_verifications.observed_values` (sección 5.5, punto 5), ni la fila de un hallazgo '
                     'que ya entró en un score ni la de su activo (sección 9). Su evidencia y el valor del activo '
                     'sí se sobrescriben el mismo día |'):
            with self.subTest(seccion='5.6', cita=cita):
                self.assertIn(cita, retencion)
        fila = next(f for f in retencion.splitlines() if f.startswith('| Carta, datos de quien firma'))
        self.assertEqual(fila.count('ese fin'), 1, "la fila de la carta tiene un solo 'ese fin' (r12-1)")
        self.assertIn('ni cuando la registra (sección 8 de la carta). Entre ese fin y la pausa', fila,
                      "'ese fin' es el de la revocación de la empresa, en la frase justo antes (r12-9)")
        aviso = _seccion(self.texto, '5.2 Aviso de privacidad')
        self.assertIn('a los que tienen la cuenta desactivada en espera de una carta nueva (sección 11, punto 7)',
                      aviso, 'el aviso no avisa a las cuentas en espera')
        self.assertIn('Mientras la carta no venza, no termine porque la empresa vende o deja el dominio (sección 10 '
                      'de la carta), que el equipo registra revocando todas las cartas sin revocar del dominio con '
                      'la fecha de la venta o del abandono, o con la hora de su aviso si este no la trae (sección '
                      '9), y ni la empresa ni el equipo la revoquen, la carta sigue vigente', aviso,
                      'la carta también vence, termina con el dominio y la revoca el equipo (r9-1, r10-8, r11-7, '
                      'r12-4, r12-5, r13-2)')
        self.assertIn('Cuando la carta vence o se revoca, también cuando la empresa firma una carta nueva con otra '
                      'persona y el equipo revoca la anterior, pasan al bloqueo de la sección 5.6', aviso,
                      'los datos de quien firma pasan a bloqueo cuando la carta vence o se revoca')
        pendientes = _seccion(self.texto, '9. Pendientes')
        for cita in ('Borrado en [30] días al vencer o revocarse la última carta de la empresa o de un dominio, al '
                     'cerrar el curso',
                     'ni se reactivan cuando empieza la carta nueva que el equipo cargue en los [30] días siguientes',
                     'Cuando la empresa revoca la carta, el fin cuenta desde que llega su escrito o su correo',
                     '`revoked_at` debe llevar esa hora y no la de la pausa ni la del registro',
                     'Cuando revoca el equipo, lleva la hora en que la revoca.',
                     'la carta termina con la venta o el abandono y no con su aviso (sección 10 de la carta)',
                     'el equipo revoca todas las cartas sin revocar del dominio, porque el orquestador toma '
                     'cualquiera vigente',
                     'con la fecha de la venta o del abandono, a las 0:00 de ese día en hora del centro de México, o '
                     'con la hora del aviso si este no la trae (sección 5.2, punto 7). El equipo',
                     'El equipo pone el dominio en pausa en cuanto lee el escrito o el aviso, a más tardar ese mismo '
                     'día, aunque la carta le da hasta el fin del día del escrito y no dice nada de la pausa por la '
                     'venta.',
                     'Entre el escrito y la pausa, y entre la venta y la pausa, todavía puede entrar un análisis, '
                     'que corre sin carta vigente (sección 5.6 y sección 10 de la carta)',
                     'así que uno que entre en ese rato queda con `queued_at` posterior a `revoked_at`, salvo si el '
                     'aviso de la venta no trae la fecha: entonces `revoked_at` lleva la hora del aviso y lo que '
                     'entró entre la venta y el aviso parece autorizado.',
                     'el [plazo] y los [30] días del borrado y de la cuenta cuentan desde una fecha que el equipo '
                     'conoce tarde', 'falta decidir desde cuándo cuentan esos plazos',
                     'y lo que se guardó entre la venta y la pausa es de un dominio que ya no es de la empresa, '
                     'que la sección 5.6 manda borrar el mismo día como dato fuera del alcance y que hoy tampoco '
                     'se puede borrar: falta decidir',
                     'hay que guardar la hora de cada pausa, en la bitácora o en una columna',
                     'porque de la pausa `domains` solo guarda `status`, sin hora, y `updated_at`, que el '
                     'orquestador pisa al terminar cada análisis',
                     'Solo se reactivan las cuentas que desactivó el fin de la carta, así que hay que guardar cada '
                     'causa de desactivación, también la que llegue durante la espera',
                     'la base no tiene dónde guardar la causa | Tarjetas de API y de base por crear |',
                     'La sección 8 de la carta también solo deja revocar a la empresa',
                     'solo prevé el escrito que pide borrar los hallazgos, activos y reportes, y no el que pide '
                     'borrar todos los datos: falta que defina ese escrito',
                     'y que deje revocar al equipo al cerrar el curso o con ese escrito',
                     'o antes si la empresa pide el borrado por escrito (sección 6 de la carta y sección 11, punto 7)',
                     'al cargar una carta nueva del mismo dominio (sección 5.2, punto 7) y por uso indebido',
                     '`domain_authorizations.accepted_by` es obligatorio', 'Falta registrar que la cargó el equipo',
                     'que la sección 8 de la carta pida pausar el dominio en cuanto el equipo lee el escrito, a más '
                     'tardar ese mismo día,',
                     'que la sección 10 pida avisar de la venta o del abandono antes de que ocurran, con su fecha, y '
                     'diga que el equipo pone el dominio en pausa y revoca todas sus cartas sin revocar el día del '
                     'aviso',
                     'Falta también que la sección 1.2 de #6 diga que la base frena una revocación solo desde que se '
                     'registra (sección 11, punto 3)',
                     'hoy no se puede, porque `score_contributions` referencia a `findings` y solo el rol de '
                     'retención puede borrar scores', 'Hace falta una excepción por organización o anonimizar',
                     'Por la misma referencia, tampoco se puede borrar el mismo día la fila de un hallazgo '
                     'guardado por error que ya entró en un score ni la de su activo, como pide la sección 5.6',
                     'una carta que sigue vigente'):
            with self.subTest(seccion='9', cita=cita):
                self.assertIn(cita, pendientes)
        legal = next(f for f in pendientes.splitlines() if f.startswith('| Que Cloudflare, Groq y Microsoft'))
        self.assertTrue(legal.endswith('| Revisión legal, antes del primer cliente real y de #19 (RC-54) |'),
                        'la fila de las brechas sensibles no es la de revisión legal antes de #19 '
                        '(r15-datos-1 y r16-reg-1)')
        for cita in ('cómo se tratan las brechas que revelan datos sensibles (sección 5.3, punto 5)',
                     'si basta el texto modelo de la sección 5.4'):
            with self.subTest(seccion='9 revisión legal', cita=cita):
                self.assertIn(cita, legal, 'las brechas sensibles no van a la revisión legal (r15-datos-1)')
        # La fecha prevista de #19 en la carta (Anexo A, actividad 7) queda como pendiente de carta (r17-reg-1).
        with self.subTest(seccion='9 revisión legal', regla='fecha de #19 en la carta'):
            self.assertIn('que la carta mueva la fecha prevista de la actividad 7 de su Anexo A (Have I Been '
                          'Pwned, #19), hoy el 6 nov 2026, a después de esta revisión', legal,
                          'la fecha de #19 en la carta no queda como pendiente de la revisión legal (r17-reg-1)')
        # Los documentos que fechan #19 o la llave de HIBP los ponen detrás de esa revisión (r17-reg-1).
        esperados = _texto(RAIZ / 'docs' / 'hallazgos_esperados.md')
        fila13 = next(f for f in esperados.splitlines() if f.startswith('| 13 |'))
        servicios = _texto(RAIZ / 'docs' / 'servicios_externos.md')
        inicios = ('| HIBP | Correos del dominio en brechas', '| HIBP, 1 mes |', '10. **HIBP:**')
        hibp = [f for f in servicios.splitlines() if f.startswith(inicios)]
        self.assertEqual(len(hibp), 3, 'faltan las líneas de HIBP en servicios_externos.md')
        lineas = [('fila 13 de hallazgos_esperados.md', fila13, 'que espera toda la revisión legal de la sección 9'),
                  ('fila 13 de hallazgos_esperados.md', fila13, '| La revisión legal y la llave de #19 |'),
                  ('fechas de hallazgos_esperados.md', esperados, '#19 llega después de la revisión legal'),
                  ('HIBP en servicios_externos.md', hibp[0], 'Se compra después de la revisión legal'),
                  ('gasto de HIBP en servicios_externos.md', hibp[1], 'Sin compra: espera la revisión legal'),
                  ('pregunta 10 de servicios_externos.md', hibp[2], 'No se compra antes de la revisión legal')]
        vence = next((f for f in servicios.splitlines() if f.startswith('| Ninguna llave vence antes')), '')
        with self.subTest(documento='vencimientos de servicios_externos.md'):
            self.assertIn('La de HIBP se compra después de la revisión legal que #19 espera', vence,
                          'el vencimiento de HIBP no espera la revisión legal (r17-reg-1)')
            self.assertNotIn('si se compra el 5 nov', vence, 'el vencimiento de HIBP sigue con la compra del 5 nov')
        for donde, linea, cita in lineas:
            with self.subTest(documento=donde, cita=cita):
                self.assertIn(cita, linea, '#19 o la llave de HIBP no esperan la revisión legal (r17-reg-1)')
        for donde, linea in (('hallazgos_esperados.md', esperados), ('servicios_externos.md', servicios)):
            with self.subTest(documento=donde, regla='sin fecha vieja'):
                self.assertNotRegex(linea, r'6 nov, cuando llegue #19|#18 y #19 el 6 nov|Compra prevista la',
                                    'queda una fecha de #19 sin la revisión legal (r17-reg-1)')
        # 1 página en Times New Roman 12 con interlineado sencillo: unas 550 palabras como máximo.
        self.assertLessEqual(len(terminos.split()), 550, 'los términos pasan de 1 página')
        titular = '[Titular por definir según el convenio Tec e IKUSI]'
        aviso = _seccion(self.texto, '5.2 Aviso de privacidad')
        self.assertIn(f"'{titular}'", aviso.split('(fracción II)')[0], 'el aviso no nombra al responsable provisional')
        simplificado = aviso.split('art. 16, fracción II')[1]
        self.assertIn(f"'{titular}, con domicilio", simplificado, 'el aviso simplificado no nombra al responsable')
        self.assertIn('arco@lowtidesec.com', aviso.split('art. 16, fracción II')[0], 'el aviso integral sin arco@')
        self.assertIn('arco@lowtidesec.com', simplificado, 'el aviso simplificado no dice dónde ejercer los derechos')
        matriz = _seccion(self.texto, '5.1 Quién responde')
        self.assertIn('| Responsable | Encargados |', matriz)
        # Sin cartas de clientes reales mientras la carta nombre a otro responsable que la matriz.
        for cita in ('no nombre al mismo responsable que esta tabla',
                     'no se firma ni se carga la carta de un cliente real'):
            with self.subTest(matriz=cita):
                self.assertIn(cita, matriz)
        filas = {f.split('|')[1].strip(): [c.strip() for c in f.split('|')[1:-1]]
                 for f in matriz.splitlines() if f.startswith('| ') and not f.startswith('| Titulares')}
        empleados = next(c for t, c in filas.items() if t.startswith('Empleados'))
        self.assertEqual(empleados[2], 'La empresa cliente', 'el responsable de los datos de empleados es la empresa')
        self.assertTrue(empleados[3].startswith('El equipo'), 'el equipo es encargado de los datos de empleados')
        for titulares in ('Usuarios del portal', 'Quien firma la carta'):
            with self.subTest(titulares=titulares):
                self.assertEqual(filas[titulares][2], f"'{titular}'")
                self.assertTrue(filas[titulares][3].startswith('El equipo'), 'el equipo es encargado del titular')
        arco = _seccion(self.texto, '5.7 Derechos ARCO')
        self.assertIn('arco@lowtidesec.com', arco)
        self.assertIn('Email Routing', arco)
        self.assertNotIn('pendiente de RC-207', self.texto)
        self.assertNotIn('buzón ARCO de RC-207', self.texto)
        # Mientras el buzón no se pruebe con un correo real, la sección 9 lo trae como pendiente.
        marcador = re.search(r'\[(?:destino|fecha)\]', self.texto, re.I)
        probado = re.search(r'Se probó con un correo real[^.]* el \d{1,2} \w{3} \d{4}', arco)
        if marcador or not probado:
            self.assertIn('Activar Email Routing', _seccion(self.texto, '9. Pendientes'),
                          'el buzón sin probar debe estar en los pendientes')
        # Al final y en su subTest, para que una falla no corte las demás comprobaciones (r13-8). También caza 'la
        # carta termina con la pausa' y 'el fin de la carta cuenta desde la pausa' (r12-9).
        with self.subTest(regla='vieja'):
            self.assertNotRegex(self.texto, r'(?i)carta (?:solo )?deja iniciar|termina la carta con la pausa|carta '
                                r'termina con la pausa|el fin (?:de la carta )?cuenta desde la pausa|`revoked_at` '
                                r'(?:debe llevar|lleva) la hora de (?:esa|la) pausa',
                                'vuelve la regla vieja: la carta no termina con la pausa ni deja iniciar análisis '
                                'sin carta vigente (r11-1, r12-2, r12-9, r13-8)')


if __name__ == '__main__':
    unittest.main()
