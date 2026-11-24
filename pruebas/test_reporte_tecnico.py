"""Pruebas sin red del reporte técnico (cirdan/reporte_tecnico.py, #46, RC-81).

Uso, desde la raíz del repo:
  python -m unittest pruebas/test_reporte_tecnico.py

La ruta, el 403 sin carta vigente, el 403 al gerente y la descarga en HTML se prueban contra la API en
test_api_v1.py (test_9g).
"""
import re
import sys
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cirdan import reporte, reporte_tecnico as rt  # noqa: E402

AHORA = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
SEV = ('critical', 'high', 'medium', 'low')
TEXTOS = {
    'dmarc_missing': {'title': 'Falta DMARC', 'meaning': 'Cualquiera puede mandar correo a tu nombre.',
                      'recommendation': 'Publica DMARC con p=none. Luego súbelo a p=reject.'},
    'secret_in_public_repo': {'title': 'Secreto en un repositorio público', 'meaning': 'Hay una llave a la vista.',
                              'recommendation': 'Revoca la llave. Bórrala del historial.'},
}
FUENTES = [{'source': 'dns', 'status': 'succeeded', 'attempt': 1, 'finished_at': AHORA},
           {'source': 'ct_logs', 'status': 'failed', 'attempt': 3, 'finished_at': None}]


def hallazgo(i, severidad='high', regla='dmarc_missing', activo=None, tipo='subdomain', evidencia=None, **extra):
    h = {'id': 'f%d' % i, 'title': 'Hallazgo %d' % i, 'severity': severidad, 'base_severity': 'medium',
         'category': 'configuration', 'rule_code': regla, 'asset': activo or 'a%d.olmardo.com' % i, 'asset_type': tipo,
         'source': 'dns', 'detected_at': datetime(2026, 11, 3, tzinfo=timezone.utc), 'recurrence': 'new',
         'last_scan_id': 's1', 'cve_id': None, 'cvss': None, 'epss': None, 'in_kev': False,
         'evidence': evidencia if evidencia is not None else {'registro': 'v=spf1 -all'}}
    h.update(extra)
    return h


def armar(hallazgos, fuentes=FUENTES):
    score = {'score': 64, 'band': 'high', 'grade': 'D', 'partial_coverage': False, 'computed_at': AHORA}
    return rt.armar('olmardo.com', 'Grupo Olmardo', {'valid_from': date(2026, 10, 19), 'valid_until': date(2027, 10, 19)},
                    score, AHORA, hallazgos, TEXTOS, fuentes, generado=AHORA)


class Armado(unittest.TestCase):

    def test_1_mismas_cifras_que_el_ejecutivo(self):
        hs = [hallazgo(i, SEV[i % 4]) for i in range(30)]
        r = armar(hs)
        e = reporte.armar('olmardo.com', 'Grupo Olmardo', r['authorization'], r['score'], AHORA, hs,
                          {c: t['recommendation'] for c, t in TEXTOS.items()}, generado=AHORA)
        for clave in ('total_open', 'open_findings', 'by_category', 'score', 'authorization', 'attributions'):
            self.assertEqual(r[clave], e[clave], clave)
        self.assertEqual(r['kind'], 'technical')
        self.assertNotIn('kind', e)

    def test_2_trae_todos_hasta_el_tope_con_remediacion_completa(self):
        r = armar([hallazgo(i) for i in range(rt.MAX_HALLAZGOS + 5)])
        self.assertEqual(len(r['findings']), rt.MAX_HALLAZGOS)
        self.assertEqual(r['findings_omitted'], 5)
        h = r['findings'][0]
        self.assertEqual(h['recommendation'], 'Publica DMARC con p=none. Luego súbelo a p=reject.')
        self.assertEqual(h['meaning'], 'Cualquiera puede mandar correo a tu nombre.')
        self.assertEqual((h['base_severity'], h['last_scan_id']), ('medium', 's1'))

    def test_3_remediaciones_por_regla_en_orden_de_severidad(self):
        hs = [hallazgo(1, 'critical', 'secret_in_public_repo')] + [hallazgo(i, 'medium') for i in range(2, 16)]
        hs.append(hallazgo(16, 'low', activo='a2.olmardo.com'))  # activo repetido: va una vez
        r = armar(hs)
        self.assertEqual([x['rule_code'] for x in r['remediations']], ['secret_in_public_repo', 'dmarc_missing'])
        dmarc = r['remediations'][1]
        self.assertEqual((dmarc['count'], dmarc['severity'], dmarc['title']), (15, 'medium', 'Falta DMARC'))
        self.assertEqual(len(dmarc['assets']), rt.MAX_ACTIVOS)
        self.assertEqual(dmarc['assets_omitted'], 14 - rt.MAX_ACTIVOS)
        self.assertEqual(dmarc['recommendation'], TEXTOS['dmarc_missing']['recommendation'])

    def test_4_sin_correos_completos_ni_en_activo_ni_en_evidencia(self):
        ev = {'autores': ['juan.perez@olmardo.com', 'ana@correo.olmardo.com'], 'nota': 'de x_y+z@ejemplo.mx'}
        r = armar([hallazgo(1, regla='email_in_public_commits', activo='juan.perez@olmardo.com', tipo='email',
                            evidencia=ev)])
        h = r['findings'][0]
        self.assertEqual(h['asset'], 'Correo de olmardo.com')
        texto = rt.html(r)
        for correo in ('juan.perez', 'ana@', 'x_y+z'):
            self.assertNotIn(correo, str(h) + str(r['remediations']) + texto, correo)
        self.assertIn('…@correo.olmardo.com', texto)

    def test_5_evidencia_sin_vacios_con_topes(self):
        ev = {'a': None, 'b': '', 'c': [], 'd': {}, 'e': True, 'f': 'x' * 1000, 'g': {'puerto': 3389},
              **{'z%02d' % i: i for i in range(20)}}
        pares = rt.evidencia(ev)
        self.assertEqual(len(pares), rt.MAX_CLAVES)
        self.assertEqual(pares[0], {'key': 'e', 'value': 'sí'})
        self.assertEqual(len(pares[1]['value']), rt.MAX_VALOR)
        self.assertEqual(pares[2], {'key': 'g', 'value': '{"puerto": 3389}'})
        self.assertEqual(rt.evidencia(None), [])

    def test_6_cobertura_del_ultimo_escaneo_sin_error(self):
        r = armar([], fuentes=[dict(FUENTES[1], error='token interno 123')])
        self.assertEqual(r['sources'], [{'source': 'ct_logs', 'status': 'failed', 'attempt': 3, 'finished_at': None}])
        self.assertNotIn('token interno', rt.html(r))


class Html(unittest.TestCase):

    def test_1_escapa_todo_lo_que_viene_de_la_base(self):
        malo = '<script>alert(1)</script>'
        r = armar([hallazgo(1, title=malo, evidencia={'<img src=x>': '<b>v</b>'})])
        r['organization'] = '<i>Org</i>'
        texto = rt.html(r)
        for crudo in ('<script', '<img', '<b>v', '<i>Org'):
            self.assertNotIn(crudo, texto)
        self.assertIn('&lt;script&gt;', texto)

    def test_2_trae_detalle_remediacion_cobertura_y_atribucion(self):
        r = armar([hallazgo(1, 'critical', 'secret_in_public_repo', cve_id='CVE-2026-1234', cvss=9.8, epss=0.42,
                            in_kev=None), hallazgo(2)])
        texto = rt.html(r)
        for frase in ('Reporte técnico de riesgo', 'Detalle de hallazgos', 'Remediaciones por regla',
                      'Cobertura del último escaneo', 'Revoca la llave. Bórrala del historial.', 'Hay una llave a la vista.',
                      'CVE-2026-1234 · CVSS 9.8 · EPSS 42.0 % · En KEV: sin dato', 'Evidencia · registro', 'v=spf1 -all',
                      'Falló', 'Respondió', 'Have I Been Pwned', 'CC BY 4.0', '64, letra D (Alto)', '19/10/2026 a 19/10/2027'):
            self.assertIn(frase, texto)
        for frase in reporte.lectura(r):
            self.assertIn(frase, texto)

    def test_3_sin_recursos_externos_ni_scripts(self):
        texto = rt.html(armar([hallazgo(1)]))
        self.assertTrue(texto.startswith('<!doctype html>'))
        self.assertIsNone(re.search(r'<(script|link|img|iframe)\b', texto))
        self.assertIsNone(re.search(r'\bsrc=', texto))

    def test_4_sin_hallazgos_ni_escaneos(self):
        texto = rt.html(armar([], fuentes=[]))
        self.assertIn('El dominio no tiene hallazgos abiertos.', texto)
        self.assertIn('El dominio no tiene escaneos todavía.', texto)

    def test_6_marcos_iso_y_cis_en_json_y_html(self):
        """RC-160: el detalle de cada hallazgo trae su control ISO y su salvaguarda CIS; sin mapeo, sin fila."""
        from pruebas.test_reporte import MARCOS
        r = armar([hallazgo(1, frameworks=MARCOS), hallazgo(2)])
        self.assertEqual(r['findings'][0]['frameworks']['iso_27001_2022']['control_id'], 'A.5.17')
        self.assertEqual(r['findings'][0]['frameworks']['cis_controls_v8_1']['safeguard_id'], '5.2')
        self.assertIsNone(r['findings'][1]['frameworks']['iso_27001_2022'])
        texto = rt.html(r)
        self.assertIn('<th scope="row">ISO/IEC 27001:2022</th><td>A.5.17 Protección de credenciales</td>', texto)
        self.assertIn('<th scope="row">CIS Controls v8.1</th><td>5.2 Contraseñas únicas</td>', texto)
        self.assertEqual(texto.count('<th scope="row">ISO/IEC 27001:2022</th>'), 1)
        self.assertIn('CC BY-NC-ND 4.0', texto)

    def test_5_omitidos_apuntan_a_la_exportacion(self):
        texto = rt.html(armar([hallazgo(i) for i in range(rt.MAX_HALLAZGOS + 3)]))
        self.assertIn('Y 3 hallazgos abiertos más', texto)


if __name__ == '__main__':
    unittest.main()
