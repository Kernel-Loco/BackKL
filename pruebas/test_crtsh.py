"""Pruebas del recolector de crt.sh (#14), sin red: un crt.sh simulado y una fecha fija.

    python -m unittest -v pruebas/test_crtsh.py
"""
import contextlib
import io
import json
import functools
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_crtsh.py
from cirdan.recolectores import contrato, crtsh  # noqa: E402

AHORA = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def cert(id_, nombres, inicio, fin, emisor="C=US, O=Let's Encrypt, CN=R11", serie=None):
    return {'id': id_, 'issuer_ca_id': 1, 'issuer_name': emisor, 'common_name': nombres[0],
            'name_value': '\n'.join(nombres), 'not_before': inicio, 'not_after': fin,
            'serial_number': serie or ('%040x' % id_), 'result_count': 1}


SUBDOMINIOS = [
    # www renovado: el viejo venció, el nuevo sigue vigente -> sin hallazgo
    cert(1, ['www.acme-demo.mx', 'acme-demo.mx'], '2026-04-01T00:00:00', '2026-06-30T00:00:00'),
    cert(2, ['www.acme-demo.mx', 'acme-demo.mx'], '2026-09-20T00:00:00', '2026-12-19T00:00:00'),
    # vence en 10 días -> cert_expiring_soon
    cert(3, ['api.acme-demo.mx'], '2026-07-27T00:00:00', '2026-10-25T12:00:00'),
    # venció hace 50 días y no se renovó -> cert_expired
    cert(4, ['dev.acme-demo.mx'], '2026-05-27T00:00:00', '2026-08-26T00:00:00'),
    # venció hace más de un año -> solo activo
    cert(5, ['old.acme-demo.mx'], '2024-01-01T00:00:00', '2024-04-01T00:00:00'),
    # comodín, ruido y nombres fuera del alcance
    cert(6, ['*.tienda.acme-demo.mx', 'tienda.acme-demo.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
    {'id': 8, 'name_value': 'sinfechas.acme-demo.mx'},  # fila incompleta: se ignora
    cert(7, ['contacto@acme-demo.mx', 'prueba intermedia - acme-demo.mx', 'm.testacme-demo.mx', 'otra.com'],
         '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
]
CONTIENE_MARCA = [
    cert(20, ['acme-demo-login.com', 'www.acme-demo-login.com'], '2026-09-30T00:00:00', '2026-12-29T00:00:00'),
    # el dominio autorizado completo dentro de un dominio ajeno: se reporta como cuenta-segura.net (RC-226, R1)
    cert(21, ['acme-demo.mx.cuenta-segura.net'], '2026-08-01T00:00:00', '2026-10-30T00:00:00'),
    # certificado compartido de una CDN: solo cuenta el nombre parecido, no los ajenos
    cert(22, ['sni.cdn-ejemplo.com', 'acme-demo-pagos.com', 'tienda-ajena.com'], '2026-09-10T00:00:00', '2026-12-09T00:00:00'),
    # parecido viejo: su último certificado venció hace más de 90 días -> no cuenta
    cert(23, ['acme-demo-viejo.com'], '2025-01-01T00:00:00', '2025-04-01T00:00:00'),
    # dominio propio de la empresa -> no cuenta
    cert(24, ['acme-demo.com.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
    # nombres dentro del propio dominio -> no cuentan
    cert(25, ['shop.acme-demo.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
]
CANDIDATO = [cert(30, ['acme-dem0.mx', 'www.acme-dem0.mx', 'ajeno.org'], '2026-10-01T00:00:00', '2026-12-30T00:00:00')]


class CrtshSimulado:
    """Transporte falso: responde según la consulta y puede fallar las primeras veces. Las consultas a Cert Spotter (#14b)
    van aparte, en `cert_spotter`, y por defecto no suman certificados."""

    def __init__(self, fallas=0, respuestas=None, sin_dns=(), emisiones=()):
        self.fallas, self.urls, self.sin_dns, self.dns = fallas, [], set(sin_dns), []
        self.respuestas = respuestas if respuestas is not None else {
            '%.acme-demo.mx': SUBDOMINIOS, '%acme-demo%': CONTIENE_MARCA, 'acme-dem0.mx': CANDIDATO}
        self.emisiones, self.cert_spotter = list(emisiones), []

    def __call__(self, url, timeout):
        partes = crtsh.urllib.parse.urlparse(url)
        cert_spotter = partes.netloc == 'api.certspotter.com'
        (self.cert_spotter if cert_spotter else self.urls).append(url)
        if self.fallas:
            self.fallas -= 1
            raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
        if cert_spotter:  # una página con las emisiones y la vacía que cierra
            return json.dumps([] if 'after' in crtsh.urllib.parse.parse_qs(partes.query) else self.emisiones).encode()
        q = crtsh.urllib.parse.parse_qs(partes.query)['q'][0]
        return json.dumps(self.respuestas.get(q, [])).encode()

    def resolver(self, nombre):
        """DNS falso: todo resuelve salvo los nombres de sin_dns."""
        self.dns.append(nombre)
        return nombre not in self.sin_dns


def recolectar(transporte, **kw):
    cliente = crtsh.ClienteCrtsh(transporte=transporte, dormir=lambda s: None)
    kw.setdefault('propios', ['acme-demo.com.mx'])
    return crtsh.recolectar('acme-demo.mx', cliente, AHORA, **kw)


def consulta(url):
    """El parámetro q de una URL de crt.sh: %.acme-demo.mx, %acme-demo% o una variante."""
    return crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(url).query)['q'][0]


class Subdominios(unittest.TestCase):

    def setUp(self):
        self.res = recolectar(CrtshSimulado(), parecidos=False)
        self.activos = {a.valor: a for a in self.res.activos}
        self.hallazgos = {(h.codigo, h.activo): h for h in self.res.hallazgos}

    def test_1_solo_nombres_del_dominio(self):
        self.assertEqual(self.res.estado, 'succeeded')
        self.assertEqual(sorted(self.activos), ['acme-demo.mx', 'api.acme-demo.mx', 'dev.acme-demo.mx',
                                                'old.acme-demo.mx', 'tienda.acme-demo.mx', 'www.acme-demo.mx'])
        self.assertEqual(self.activos['acme-demo.mx'].tipo, 'domain')
        self.assertEqual(self.activos['www.acme-demo.mx'].tipo, 'subdomain')
        self.assertTrue(self.activos['tienda.acme-demo.mx'].atributos['comodin'])

    def test_2_certificado_renovado_no_es_hallazgo(self):
        self.assertNotIn(('cert_expired', 'www.acme-demo.mx'), self.hallazgos)
        self.assertEqual(self.activos['www.acme-demo.mx'].atributos['certificados'], 2)

    def test_3_vence_en_menos_de_30_dias(self):
        h = self.hallazgos[('cert_expiring_soon', 'api.acme-demo.mx')]
        self.assertEqual(h.severidad, 'medium')
        self.assertEqual(h.evidencia['dias_para_vencer'], 10)
        self.assertEqual(h.evidencia['title'], h.titulo)

    def test_4_vencido_sin_renovar(self):
        h = self.hallazgos[('cert_expired', 'dev.acme-demo.mx')]
        self.assertEqual(h.severidad, 'high')
        self.assertEqual(h.caracteristicas['antiguedad_dias'], 50)
        self.assertEqual(set(h.caracteristicas), {'tipo', 'antiguedad_dias', 'exposicion', 'sensibilidad'})

    def test_5_vencido_hace_mas_de_un_anio_solo_es_activo(self):
        self.assertIn('old.acme-demo.mx', self.activos)
        self.assertNotIn(('cert_expired', 'old.acme-demo.mx'), self.hallazgos)

    def test_6_huella_estable(self):
        otra = recolectar(CrtshSimulado(), parecidos=False)
        self.assertEqual(sorted(h.huella for h in self.res.hallazgos), sorted(h.huella for h in otra.hallazgos))
        self.assertTrue(all(len(h.huella) == 64 for h in self.res.hallazgos))

    def test_7_codigos_con_regla(self):
        self.assertTrue({h.codigo for h in self.res.hallazgos} <= set(crtsh.CODIGOS))


class DominiosParecidos(unittest.TestCase):

    def setUp(self):
        self.res = recolectar(CrtshSimulado(), parecidos=True)
        self.parecidos = {h.evidencia['dominio_parecido']: h for h in self.res.hallazgos if h.codigo == 'lookalike_domain'}

    def test_1_encuentra_los_parecidos_recientes(self):
        self.assertEqual(sorted(self.parecidos),
                         ['acme-dem0.mx', 'acme-demo-login.com', 'acme-demo-pagos.com', 'cuenta-segura.net'])
        # R1: el dominio autorizado completo dentro de un dominio ajeno se reporta con ese dominio.
        self.assertEqual(self.parecidos['cuenta-segura.net'].evidencia['nombres'], ['acme-demo.mx.cuenta-segura.net'])
        self.assertEqual(self.parecidos['cuenta-segura.net'].evidencia['tipo_parecido'], 'contiene_marca')
        self.assertEqual(self.parecidos['acme-dem0.mx'].evidencia['tipo_parecido'], 'error_tipografico')
        self.assertEqual(self.parecidos['acme-demo-login.com'].evidencia['nombres'],
                         ['acme-demo-login.com', 'www.acme-demo-login.com'])

    def test_2_no_cuenta_propios_viejos_ni_ajenos_de_la_cdn(self):
        for fuera in ('acme-demo.com.mx', 'acme-demo-viejo.com', 'cdn-ejemplo.com', 'tienda-ajena.com', 'ajeno.org',
                      'acme-demo.mx'):
            self.assertNotIn(fuera, self.parecidos)

    def test_3_el_hallazgo_es_del_dominio_de_la_empresa(self):
        h = self.parecidos['acme-demo-login.com']
        self.assertEqual((h.activo, h.severidad), ('acme-demo.mx', 'medium'))

    def test_4_variantes(self):
        v = crtsh.candidatos_parecidos('acme-demo.mx')
        self.assertEqual(len(v), crtsh.MAX_CANDIDATOS)
        self.assertNotIn('acme-demo.mx', v)
        self.assertEqual(v[:4], ['acme-demo.com', 'acme-demo.com.mx', 'acme-demo.net', 'acmedemo.mx'])
        self.assertIn('acme-dem0.mx', v)

    def test_4c_la_lista_aprobada_de_olmardo_com(self):
        """Las 10 variantes de docs/contrato_plugin.md, que ErnestoDL aprobó el 10 nov 2026 (#109, RC-226). Si
        candidatos_parecidos() cambia, cambia lo que se consulta de terceros: se aprueba otra vez y se corrige el doc."""
        self.assertEqual(crtsh.candidatos_parecidos('olmardo.com'),
                         ['olmardo.mx', 'olmardo.com.mx', 'olmardo.net', '0lmardo.com', 'o1mardo.com', 'olrnardo.com',
                          'olm4rdo.com', 'olmardo.org', 'olmardo.co', 'olmardo.io'])
        doc = (Path(__file__).resolve().parents[1] / 'docs' / 'contrato_plugin.md').read_text(encoding='utf-8')
        for variante in ['%olmardo%'] + crtsh.candidatos_parecidos('olmardo.com'):
            self.assertIn('`%s`' % variante, doc)

    def test_5_por_defecto_no_se_buscan_y_quedan_sin_cobertura(self):
        t = CrtshSimulado()
        res = recolectar(t)
        self.assertEqual((res.estado, res.sin_cobertura), ('succeeded', ['lookalike_domain']))
        self.assertEqual([consulta(u) for u in t.urls], ['%.acme-demo.mx'])  # ni %acme-demo% ni variantes
        self.assertNotIn('lookalike_domain', {h.codigo for h in res.hallazgos})
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])
        self.assertEqual(crtsh.resumen(res)[-1],
                         'Cobertura parcial: no se revisaron dominios parecidos (lookalike_domain).')

    def test_6_la_linea_de_comandos_los_busca_salvo_con_sin_parecidos(self):
        def correr(*argv):
            t, salida = CrtshSimulado(), io.StringIO()
            with mock.patch.object(crtsh, '_descargar', t), mock.patch.object(crtsh.time, 'sleep', lambda s: None), \
                    contextlib.redirect_stdout(salida):
                codigo = crtsh._main(['acme-demo.mx', '--json'] + list(argv))
            return codigo, json.loads(salida.getvalue()), [consulta(u) for u in t.urls]

        codigo, res, consultas = correr('--sin-parecidos')
        self.assertEqual((codigo, res['sin_cobertura'], consultas), (0, ['lookalike_domain'], ['%.acme-demo.mx']))
        for argv in ((), ('--con-parecidos',)):  # desde #109 (RC-226) es lo predeterminado
            codigo, res, consultas = correr(*argv)
            self.assertEqual(res['sin_cobertura'], [], argv)
            self.assertEqual(consultas, ['%.acme-demo.mx', '%acme-demo%'] + crtsh.candidatos_parecidos('acme-demo.mx'),
                             argv)
        with self.assertRaises(SystemExit) as salida, contextlib.redirect_stderr(io.StringIO()):
            crtsh._main(['acme-demo.mx', '--con-parecidos', '--sin-parecidos'])
        self.assertEqual(salida.exception.code, 2)
        ayuda = io.StringIO()  # la terminal no recibe los dominios propios: la ayuda avisa que no los excluye
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(ayuda):
            crtsh._main(['--help'])
        self.assertIn('no los excluye', ' '.join(ayuda.getvalue().split()))

    def test_7_sin_marca_no_se_busca_ningun_parecido(self):
        """A1 de RC-226. registrable() solo conoce SUFIJOS_DOBLES: de acme.com.kg la etiqueta saldría 'com' y se
        consultarían com.com o com.mx, que no son variantes del dominio autorizado. Con un dominio que no es su
        propio dominio registrable no se consulta nada de parecidos y lookalike_domain queda sin cobertura."""
        for dominio in ('acme.com.kg', 'api.acme-demo.mx', 'tienda.acme.com.mx', 'acme-demo.github.io'):
            t = CrtshSimulado(respuestas={
                '%.' + dominio: [cert(50, ['www.' + dominio], '2026-09-20T00:00:00', '2026-12-19T00:00:00')]})
            cliente = crtsh.ClienteCrtsh(transporte=t, dormir=lambda s: None)
            res = crtsh.recolectar(dominio, cliente, AHORA, parecidos=True, max_candidatos=50)
            self.assertEqual([consulta(u) for u in t.urls], ['%.' + dominio], dominio)  # ni %com% ni com.com
            self.assertEqual((res.estado, res.sin_cobertura, res.omitidos), ('succeeded', ['lookalike_domain'], []),
                             dominio)
            self.assertEqual(res.avisos, [crtsh.SIN_MARCA % dominio], dominio)
            self.assertNotIn('lookalike_domain', {h.codigo for h in res.hallazgos}, dominio)
            self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [], dominio)
            self.assertEqual(crtsh.candidatos_parecidos(dominio), [], dominio)
            self.assertIsNone(crtsh._marca(dominio), dominio)
        for solo in ('com.mx', 'com.gt', 'github.io', 'mx'):  # un sufijo solo tampoco tiene marca
            self.assertEqual((crtsh.candidatos_parecidos(solo), crtsh._marca(solo)), ([], None), solo)
        self.assertEqual((crtsh._marca('acme.com.mx'), crtsh._marca('acme-demo.mx')), ('acme', 'acme-demo'))
        self.assertEqual(crtsh.candidatos_parecidos('acme.com.mx')[:3], ['acme.com', 'acme.mx', 'acme.net'])

    def test_8_la_marca_tiene_que_estar_en_el_dominio_registrable(self):
        """A2 de RC-226: acme-demo.github.io traído por %acme-demo% nunca es un parecido de github.io. R1: en un
        hosting de HOSTINGS el parecido es el sitio del cliente, y el dominio autorizado completo dentro de un dominio
        ajeno se reporta con ese dominio. La marca sola como subdominio de un dominio ajeno no cuenta. R2: un parecido
        bajo un sufijo de dos niveles de la lista sale con su dominio registrable, no como el sufijo."""
        vigente = ('2026-09-10T00:00:00', '2026-12-09T00:00:00')
        marca = [cert(60, ['acme-demo.github.io', 'www.acme-demo.github.io'], *vigente),
                 cert(61, ['acme-demo.mx.cuenta-segura.net'], *vigente),
                 cert(62, ['www.acme-demo-login.com'], *vigente), cert(63, ['miacme-demo.com.mx'], *vigente),
                 cert(64, ['acme-demo-login.netlify.app'], *vigente), cert(65, ['acme-demo.sharepoint.com'], *vigente),
                 cert(66, ['www.acme-demo.com.gt'], *vigente), cert(67, ['acme-demo.org.ar'], *vigente),
                 cert(68, ['acme-demo.co.za'], *vigente), cert(69, ['xacme-demo.mx.otro.org'], *vigente),
                 cert(70, ['acme-demo.com.kg'], *vigente), cert(71, ['acme-demo-pagos.github.io'], *vigente)]
        t = CrtshSimulado(respuestas={'%.acme-demo.mx': SUBDOMINIOS, '%acme-demo%': marca})
        res = recolectar(t, parecidos=True)
        self.assertEqual(res.sin_cobertura, [])
        parecidos = {h.clave: h for h in res.hallazgos if h.codigo == 'lookalike_domain'}
        self.assertEqual(sorted(parecidos), [
            'acme-demo-login.com', 'acme-demo-login.netlify.app', 'acme-demo-pagos.github.io', 'acme-demo.co.za',
            'acme-demo.com.gt',
            'acme-demo.github.io', 'acme-demo.org.ar', 'cuenta-segura.net'])  # miacme-demo.com.mx va pegada: H2
        self.assertEqual(parecidos['cuenta-segura.net'].evidencia['nombres'], ['acme-demo.mx.cuenta-segura.net'])
        self.assertEqual(parecidos['acme-demo.github.io'].evidencia['nombres'],
                         ['acme-demo.github.io', 'www.acme-demo.github.io'])
        for fuera in ('github.io', 'netlify.app', 'sharepoint.com', 'otro.org', 'com.gt', 'org.ar', 'co.za', 'com.kg'):
            self.assertNotIn(fuera, parecidos)  # com.kg no está en SUFIJOS_DOBLES: acme-demo.com.kg se descarta
        # Un sitio del hosting dado de alta como propio no sale, y no esconde el de otro cliente del mismo hosting.
        t = CrtshSimulado(respuestas={'%.acme-demo.mx': SUBDOMINIOS, '%acme-demo%': marca})
        res = recolectar(t, parecidos=True, propios=['acme-demo.github.io'])
        claves = {h.clave for h in res.hallazgos if h.codigo == 'lookalike_domain'}
        self.assertEqual(claves & {'acme-demo.github.io', 'acme-demo-pagos.github.io'}, {'acme-demo-pagos.github.io'})

    def test_8c_sufijos_y_hostings(self):
        """R1 y R2 de RC-226: registrable() con los sufijos de dos niveles y con los hostings, y la marca."""
        for nombre, esperado in (('www.acme.com.gt', 'acme.com.gt'), ('a.b.acme.org.ar', 'acme.org.ar'),
                                 ('acme.co.za', 'acme.co.za'), ('www.acme.github.io', 'acme.github.io'),
                                 ('acme.github.io', 'acme.github.io'), ('github.io', 'github.io'),
                                 ('x.acme.com.kg', 'com.kg'), ('www.acme.mx', 'acme.mx')):
            self.assertEqual(crtsh.registrable(nombre), esperado, nombre)
        self.assertEqual(crtsh.SUFIJOS_DOBLES & crtsh.HOSTINGS, set())
        self.assertTrue(all(s.count('.') == 1 for s in crtsh.SUFIJOS_DOBLES | crtsh.HOSTINGS))
        self.assertEqual((crtsh._marca('acme.com.gt'), crtsh._marca('acme.co.nz')), ('acme', 'acme'))
        self.assertEqual(crtsh.candidatos_parecidos('acme-demo.com.gt'), [
            'acme-demo.com', 'acme-demo.mx', 'acme-demo.com.mx', 'acme-demo.net', 'acmedemo.com.gt',
            'acme-dem0.com.gt', 'acrne-demo.com.gt', 'acm3-demo.com.gt', '4cme-demo.com.gt', 'acme-demo.org'])
        # El dominio autorizado no cuenta como dirección dentro de un dominio ajeno, ni un nombre que solo termina igual.
        for nombre, cuenta in (('acme-demo.mx.cuenta-segura.net', True), ('login.acme-demo.mx.otro.org', True),
                               ('acme-demo.mx', True), ('acme-demo.sharepoint.com', False),
                               ('xacme-demo.mx.otro.org', False), ('acme-demo.mxx.otro.org', False),
                               ('acme-demo-pagos.com', True), ('tienda.github.io', False),
                               ('acme-demo.mx.com', False), ('acme-demo.mx.sitio.com.kg', True),
                               ('acme-demo.mx.github.io', False), ('acme-demo.mx.sitio.github.io', True),
                               # H1 de la ronda 3: el dominio autorizado pegado con guion al dominio de un tercero
                               ('acme-demo.mx-login.com', True), ('www.acme-demo.mx-login.com', True),
                               ('x.acme-demo.mx-login.com.mx', True), ('acme-demo.mx-login.github.io', True),
                               ('acme-demo.mx-login.com.kg', False), ('acme-demo.mx-login.otro.org', False),
                               ('xacme-demo.mx-login.com', False), ('acme-demo.mxlogin.com', False),
                               ('www.acme-demo.mx', True)):
            self.assertEqual(crtsh._lleva_marca(nombre, 'acme-demo', 'acme-demo.mx'), cuenta, nombre)
        # Un sufijo nunca sale como parecido: el dominio autorizado tiene que quedar a la izquierda del registrable.
        for nombre in ('olmardo.com.kg', 'olmardo.com.de', 'olmardo.com.github.io', 'www.olmardo.com.kg'):
            self.assertFalse(crtsh._lleva_marca(nombre, 'olmardo', 'olmardo.com'), nombre)
        vigente = ('2026-09-10T00:00:00', '2026-12-09T00:00:00')
        t = CrtshSimulado(respuestas={'%.olmardo.com': [], '%olmardo%': [
            cert(80, ['olmardo.com.kg'], *vigente), cert(81, ['olmardo.com.de'], *vigente),
            cert(82, ['olmardo.com.github.io'], *vigente), cert(83, ['olmardo.com.otro.net'], *vigente)]})
        cliente = crtsh.ClienteCrtsh(transporte=t, dormir=lambda s: None)
        res = crtsh.recolectar('olmardo.com', cliente, AHORA, parecidos=True)
        self.assertEqual([h.clave for h in res.hallazgos if h.codigo == 'lookalike_domain'], ['otro.net'])

    def test_8d_el_dominio_autorizado_pegado_al_dominio_de_un_tercero(self):
        """H1 de la ronda 3 de RC-226: acme-demo.mx-login.com (registrable mx-login.com) trae el dominio autorizado
        completo a la vista y sale como parecido, también con un sufijo de dos niveles. El dominio autorizado, sus
        subdominios y un dominio propio no salen, y tampoco un sufijo desconocido (R1) ni un proveedor (N1)."""
        vigente = ('2026-09-10T00:00:00', '2026-12-09T00:00:00')
        for dominio, pegado, clave, propio in (
                ('acme-demo.mx', 'acme-demo.mx-login.com', 'mx-login.com', 'mx-propio.com'),
                ('acme-demo.com.mx', 'acme-demo.com.mx-seguro.net', 'mx-seguro.net', 'mx-propio.com')):
            self.assertTrue(crtsh._lleva_marca(pegado, 'acme-demo', dominio), pegado)
            marca = [cert(90, [pegado, 'www.' + pegado], *vigente), cert(91, [dominio, 'www.' + dominio], *vigente),
                     cert(92, [dominio + '-login.com.kg'], *vigente), cert(93, [dominio + '-login.otro.org'], *vigente),
                     cert(94, [dominio + '-propio.com'], *vigente)]
            t = CrtshSimulado(respuestas={'%.' + dominio: [], '%acme-demo%': marca})
            cliente = crtsh.ClienteCrtsh(transporte=t, dormir=lambda s: None)
            res = crtsh.recolectar(dominio, cliente, AHORA, parecidos=True, propios=[propio])
            self.assertEqual(res.sin_cobertura, [], dominio)
            parecidos = [h for h in res.hallazgos if h.codigo == 'lookalike_domain']
            self.assertEqual([h.clave for h in parecidos], [clave], dominio)
            self.assertEqual((parecidos[0].evidencia['nombres'], parecidos[0].evidencia['tipo_parecido']),
                             ([pegado, 'www.' + pegado], 'contiene_marca'), dominio)
            self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [], dominio)
            sin_propio = crtsh.recolectar(dominio, crtsh.ClienteCrtsh(transporte=t, dormir=lambda s: None), AHORA,
                                          parecidos=True)
            self.assertEqual([h.clave for h in sin_propio.hallazgos if h.codigo == 'lookalike_domain'],
                             sorted([clave, propio]), dominio)  # sin darlo de alta, el pegado propio sí sale

    def test_8e_la_marca_cuenta_como_palabra_y_no_hay_tope_de_parecidos(self):
        """H2 de la ronda 3 de RC-226: la marca pegada a otras letras no cuenta ('plata' en plataforma.com). No hay
        tope de parecidos: todo el que pasa el filtro se reporta, ninguno va en omitidos ni deja aviso."""
        for nombre, cuenta in (('plataforma.com', False), ('www.plataformadigital.mx', False), ('laplata.com', False),
                               ('plata-pagos.com', True), ('mi-plata.mx', True), ('plata2.com', True),
                               ('1plata.com', True), ('pagos-plata-mx.com', True), ('plata.net', True),
                               ('plataplata-plata.com', True), ('plata.sharepoint.com', False)):
            self.assertEqual(crtsh._lleva_marca(nombre, 'plata', 'plata.mx'), cuenta, nombre)
        self.assertFalse(crtsh._lleva_marca('fernandes.com', 'andes', 'andes.mx'))
        self.assertFalse(crtsh._lleva_marca('miacme-demo.com.mx', 'acme-demo', 'acme-demo.mx'))
        self.assertTrue(crtsh._lleva_marca('mi-acme-demo.com.mx', 'acme-demo', 'acme-demo.mx'))

        def de_marca(n):  # n dominios con la marca como palabra: el más reciente es el de número más alto
            return [cert(100 + i, ['plata-%02d.com' % i], '2026-09-10T00:00:00', '2026-12-%02dT00:00:00' % (i + 1))
                    for i in range(n)]
        variante = cert(99, ['p1ata.mx'], '2026-09-01T00:00:00', '2026-11-20T00:00:00')  # vence antes que todos

        def correr(n):
            t = CrtshSimulado(respuestas={'%.plata.mx': [], '%plata%': de_marca(n) + [cert(98, ['plataforma.com'],
                              '2026-09-10T00:00:00', '2026-12-30T00:00:00')], 'p1ata.mx': [variante]})
            return crtsh.recolectar('plata.mx', crtsh.ClienteCrtsh(transporte=t, dormir=lambda s: None), AHORA,
                                    parecidos=True)
        res = correr(25)
        claves = sorted(h.clave for h in res.hallazgos)
        # los 25 de %marca% y la variante, aunque su certificado sea el más viejo. plataforma.com no
        self.assertEqual(claves, sorted(['p1ata.mx'] + ['plata-%02d.com' % i for i in range(25)]))
        self.assertEqual((res.omitidos, res.avisos), ([], []))
        self.assertEqual((res.sin_cobertura, res.revisados), ([], None))
        self.assertFalse(hasattr(crtsh, 'MAX_PARECIDOS'))
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])

    def test_8f_un_tld_que_es_palabra_no_acusa_a_un_proveedor(self):
        """G1 de la ronda 3 de RC-226: olmardo.no-ip.org es un cliente de no-ip.org, no el dominio olmardo.no pegado
        con un guion. Con un TLD de TLD_PALABRA esa regla no aplica. Con .mx o .com sigue aplicando (H1)."""
        for nombre, dominio in (('olmardo.no-ip.org', 'olmardo.no'), ('olmardo.is-a.dev', 'olmardo.is'),
                                ('olmardo.in-berlin.de', 'olmardo.in'), ('www.olmardo.at-band-camp.net', 'olmardo.at'),
                                ('olmardo.com.co-op.net', 'olmardo.com.co')):
            self.assertFalse(crtsh._lleva_marca(nombre, 'olmardo', dominio), nombre)
        for nombre, dominio in (('olmardo.mx-login.com', 'olmardo.mx'), ('olmardo.com-login.net', 'olmardo.com'),
                                ('olmardo.net-pagos.org', 'olmardo.net'),
                                ('olmardo.no.cuenta-segura.net', 'olmardo.no'),  # dentro de un dominio ajeno sí cuenta
                                ('olmardo-login.org', 'olmardo.no')):
            self.assertTrue(crtsh._lleva_marca(nombre, 'olmardo', dominio), nombre)
        t = CrtshSimulado(respuestas={'%.olmardo.no': [], '%olmardo%': [
            cert(95, ['olmardo.no-ip.org'], '2026-09-10T00:00:00', '2026-12-09T00:00:00')]})
        res = crtsh.recolectar('olmardo.no', crtsh.ClienteCrtsh(transporte=t, dormir=lambda s: None), AHORA,
                               parecidos=True)
        self.assertEqual(([h.clave for h in res.hallazgos], res.sin_cobertura), ([], []))

    def test_8g_la_variante_le_gana_a_contiene_marca(self):
        """Pendiente de la ronda 4 de RC-226: acme-demo.com llega por %acme-demo% y por su variante. El tipo es el de
        la variante (otro_tld), sin importar el orden de las búsquedas, y la huella y la clave no cambian."""
        vigente = ('2026-09-10T00:00:00', '2026-12-09T00:00:00')
        por_marca = [cert(90, ['acme-demo.com'], *vigente), cert(92, ['acme-demo-pagos.com'], *vigente)]
        por_variante = [cert(90, ['acme-demo.com'], *vigente), cert(91, ['www.acme-demo.com'], *vigente)]

        def correr(variante):
            t = CrtshSimulado(respuestas={'%.acme-demo.mx': [], '%acme-demo%': por_marca, 'acme-demo.com': variante})
            res = crtsh.recolectar('acme-demo.mx', crtsh.ClienteCrtsh(transporte=t, dormir=lambda s: None), AHORA,
                                   parecidos=True)
            self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])
            return {h.clave: h for h in res.hallazgos if h.codigo == 'lookalike_domain'}
        con, sin = correr(por_variante), correr([])
        self.assertEqual({k: h.evidencia['tipo_parecido'] for k, h in con.items()},
                         {'acme-demo.com': 'otro_tld', 'acme-demo-pagos.com': 'contiene_marca'})
        self.assertEqual((con['acme-demo.com'].evidencia['certificados'], con['acme-demo.com'].evidencia['nombres']),
                         (2, ['acme-demo.com', 'www.acme-demo.com']))
        # si la variante responde vacía, lo que trajo %marca% sigue como contiene_marca, con la misma huella
        self.assertEqual(sin['acme-demo.com'].evidencia['tipo_parecido'], 'contiene_marca')
        self.assertEqual(con['acme-demo.com'].huella, sin['acme-demo.com'].huella)
        self.assertEqual(con['acme-demo.com'].huella,
                         crtsh._huella('lookalike_domain', 'acme-demo.mx', 'acme-demo.com'))
        marca = ('contiene_marca', crtsh._con_fechas(por_marca),
                 lambda n: crtsh._lleva_marca(n, 'acme-demo', 'acme-demo.mx'))
        for tipo in ('otro_tld', 'error_tipografico'):
            variante = (tipo, crtsh._con_fechas(por_variante), lambda n: crtsh.registrable(n) == 'acme-demo.com')
            for orden in ([marca, variante], [variante, marca]):
                hallados = crtsh._parecidos('acme-demo.mx', orden, set(), AHORA)
                tipos = {h.clave: h.evidencia['tipo_parecido'] for h in hallados}
                self.assertEqual(tipos, {'acme-demo.com': tipo, 'acme-demo-pagos.com': 'contiene_marca'})

    def test_9_nunca_mas_de_diez_variantes(self):
        """A3 de RC-226: el tope de 10 es fijo, aunque quien llame pida más. Es lo que cuenta MAX_CONSULTAS."""
        diez = crtsh.candidatos_parecidos('acme-demo.mx')
        self.assertEqual(crtsh.candidatos_parecidos('acme-demo.mx', 50), diez)
        self.assertEqual(crtsh.candidatos_parecidos('acme-demo.mx', 3), diez[:3])
        self.assertEqual(crtsh.candidatos_parecidos('acme-demo.mx', -1), [])
        t = CrtshSimulado()
        res = recolectar(t, parecidos=True, max_candidatos=50)
        self.assertEqual([consulta(u) for u in t.urls][2:], [v for v in diez if v != 'acme-demo.com.mx'])
        self.assertLessEqual(res.consultas, crtsh.MAX_CONSULTAS)


class SemillaDelCupo(unittest.TestCase):
    """Lectura estática de db/semillas/014_cupo_ct_logs.sql, sin base (RC-226)."""

    def test_1_la_014_sube_el_limite_a_11_corridas_sin_pisar_uno_puesto_a_mano(self):
        semilla = Path(__file__).resolve().parents[1] / 'db' / 'semillas' / '014_cupo_ct_logs.sql'
        texto = semilla.read_text(encoding='utf-8')
        sin_comentarios = '\n'.join(linea.split('--')[0] for linea in texto.splitlines())
        [(limite, anterior)] = re.findall(
            r"UPDATE\s+data_sources\s+SET\s+daily_limit\s*=\s*(\d+)\s+WHERE\s+code\s*=\s*'ct_logs'"
            r"\s+AND\s+daily_limit\s*=\s*(\d+);", sin_comentarios)
        limite, normal = int(limite), 14  # un escaneo normal: la del dominio, 2 de Cert Spotter y 11 de parecidos
        self.assertEqual((limite, int(anterior)), (400, 200))  # solo cambia el 200 de la semilla 005
        self.assertEqual(limite // crtsh.MAX_CONSULTAS, 11)  # corridas de peor caso, como antes con 18 y 200
        self.assertEqual(1 + (limite - crtsh.MAX_CONSULTAS) // normal, 27)  # escaneos en vivo por día
        self.assertLess(sin_comentarios.index("SET client_encoding = 'UTF8';"), sin_comentarios.index('BEGIN;'))
        self.assertRegex(sin_comentarios, r"code\s*=\s*'ct_logs'\s+AND\s+daily_limit\s*<\s*%d\)" % crtsh.MAX_CONSULTAS)
        self.assertIn("RAISE WARNING 'ct_logs tiene un límite diario menor que %d" % crtsh.MAX_CONSULTAS, sin_comentarios)
        self.assertEqual([p.name for p in semilla.parent.glob('014_*.sql')], ['014_cupo_ct_logs.sql'])


class FallasYGrabacion(unittest.TestCase):

    def test_1_reintenta_y_sigue(self):
        t = CrtshSimulado(fallas=2)
        res = recolectar(t, parecidos=False)
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.consultas, 4)  # 2 fallas, crt.sh y Cert Spotter (#14b)

    def test_2_si_no_responde_queda_failed(self):
        t = CrtshSimulado(fallas=100)
        res = recolectar(t, parecidos=False)
        self.assertEqual(res.estado, 'failed')
        self.assertEqual((res.activos, res.hallazgos), ([], []))
        self.assertIn('502', res.error)
        # comodín y búsqueda por nombre en crt.sh, y el respaldo de Cert Spotter (#14b)
        self.assertEqual((len(t.urls), len(t.cert_spotter)), (2 * crtsh.INTENTOS, crtsh.INTENTOS))
        self.assertIn('Cert Spotter no respondió', res.error)

    def test_3_falla_en_parecidos_no_tumba_el_escaneo(self):
        class SoloSubdominios(CrtshSimulado):
            def __call__(self, url, timeout):
                if '%25acme-demo%25' in url or 'q=acme-' in url:
                    raise TimeoutError('timed out')
                return super().__call__(url, timeout)
        res = recolectar(SoloSubdominios(), parecidos=True)
        self.assertEqual(res.estado, 'succeeded')
        self.assertTrue(res.avisos)

    def test_4_si_crtsh_esta_saturado_deja_de_probar_variantes(self):
        class SinVariantes(CrtshSimulado):
            def __call__(self, url, timeout):
                q = crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(url).query).get('q')  # Cert Spotter no lleva q
                if q and not q[0].startswith('%'):
                    self.urls.append(url)
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)
        t = SinVariantes()
        res = recolectar(t, parecidos=True)
        self.assertEqual(res.estado, 'succeeded')
        variantes = [u for u in t.urls if 'q=%25' not in u]
        self.assertEqual(len(variantes), crtsh.FALLAS_SEGUIDAS * 2)  # 2 intentos por variante
        self.assertIn('crt.sh saturado', res.avisos[-1])

    def test_4c_las_variantes_sin_respuesta_van_en_omitidos_tambien_las_del_corte(self):
        """B4 de RC-226. Si %marca% responde y las variantes no, hay cobertura y van en omitidos las huellas de las 3
        que fallaron y de las que se dejaron de probar por el corte: el orquestador no cierra su parecido."""
        class SinVariantes(CrtshSimulado):
            def __call__(self, url, timeout):
                q = crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(url).query).get('q')
                if q and not q[0].startswith('%'):
                    self.urls.append(url)
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)
        t = SinVariantes()
        res = recolectar(t, parecidos=True)
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        probadas = [consulta(u) for u in t.urls if 'q=%25' not in u]
        self.assertEqual(probadas, [v for v in variantes[:crtsh.FALLAS_SEGUIDAS]
                                    for _ in range(crtsh.INTENTOS_PARECIDOS)])
        self.assertEqual((res.estado, res.sin_cobertura), ('succeeded', []))
        self.assertEqual(sorted(res.omitidos),
                         sorted(crtsh._huella('lookalike_domain', 'acme-demo.mx', v) for v in variantes))
        self.assertEqual(sorted(h.clave for h in res.hallazgos if h.codigo == 'lookalike_domain'),
                         ['acme-demo-login.com', 'acme-demo-pagos.com', 'cuenta-segura.net'])  # lo de %marca% sí
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])
        # B3 y H10: con búsquedas de parecidos sin respuesta la corrida es parcial. revisados trae las partes de los
        # certificados y los parecidos que sí se revisaron, nunca el de una variante que no respondió.
        completo = recolectar(CrtshSimulado(), parecidos=True)
        self.assertEqual((completo.revisados, completo.sin_revisar), (None, None))
        self.assertIsNone(res.sin_revisar)
        sin_certificados = recolectar(CrtshSimulado(), parecidos=False)
        partes = {p for h in sin_certificados.hallazgos for p in h.partes}
        self.assertTrue(partes and partes <= set(res.revisados))
        de_parecidos = [p for p in res.revisados if '@' not in p]
        self.assertEqual(de_parecidos, ['acme-demo-login.com', 'acme-demo-pagos.com', 'acme-demo-viejo.com',
                                        'acme-demo.com.mx', 'cuenta-segura.net'])  # el viejo y el propio también
        self.assertFalse(set(variantes) & set(res.revisados))

    def test_4b_grabar_y_reproducir_sin_red(self):
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None)
            vivo = crtsh.recolectar('acme-demo.mx', grab, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
            self.assertTrue((Path(d) / 'subdominios_acme-demo.mx.json').exists())

            def sin_red(url, timeout):
                raise AssertionError('no debe usar la red')
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d, transporte=sin_red)
            grabado = crtsh.recolectar('acme-demo.mx', rep, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
            self.assertEqual(sorted(h.huella for h in vivo.hallazgos), sorted(h.huella for h in grabado.hallazgos))
            self.assertEqual(rep.consultas, 0)

    def test_5_reproducir_sin_grabacion_queda_failed(self):
        with tempfile.TemporaryDirectory() as d:
            res = crtsh.recolectar('acme-demo.mx', crtsh.ClienteCrtsh(modo='reproducir', carpeta=d), AHORA)
        self.assertEqual(res.estado, 'failed')

    def test_6_dominio_invalido(self):
        res = crtsh.recolectar('no es un dominio', crtsh.ClienteCrtsh(transporte=CrtshSimulado()), AHORA)
        self.assertEqual(res.estado, 'failed')

    def test_7_completar_no_repite_lo_ya_grabado(self):
        with tempfile.TemporaryDirectory() as d:
            primera = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None)
            crtsh.recolectar('acme-demo.mx', primera, AHORA, parecidos=False)
            t = CrtshSimulado()
            segunda = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=t, dormir=lambda s: None, completar=True)
            res = crtsh.recolectar('acme-demo.mx', segunda, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
            self.assertEqual(res.estado, 'succeeded')
            self.assertFalse([u for u in t.urls if 'q=%25.acme-demo.mx' in u])  # la de subdominios ya estaba
            self.assertTrue(t.urls)                                              # las variantes sí se consultan
            leidas = [n for n, _ in segunda.leidas]
            self.assertEqual(leidas[0], 'subdominios_acme-demo.mx.json')
            self.assertEqual(sorted(leidas[1:]), ['certspotter_acme-demo.mx.json'] + ['dns_%s.json' % n for n in (
                'acme-demo.mx', 'api.acme-demo.mx', 'dev.acme-demo.mx', 'tienda.acme-demo.mx', 'www.acme-demo.mx')])
            self.assertEqual((t.dns, t.cert_spotter), ([], []))  # el DNS y Cert Spotter también estaban grabados
            self.assertTrue((Path(d) / 'acme-dem0.mx.json').exists())

    def test_8_falta_de_grabacion_no_es_saturacion(self):
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None)
            crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False)
            res = crtsh.recolectar('acme-demo.mx', crtsh.ClienteCrtsh(modo='reproducir', carpeta=d), AHORA,
                                   propios=['acme-demo.com.mx'], parecidos=True)
        self.assertEqual(res.estado, 'succeeded')
        self.assertTrue(res.avisos)
        self.assertTrue(all(a.startswith(crtsh.SIN_GRABACION) for a in res.avisos))
        self.assertEqual(crtsh.codigo_salida(res), 2)

    def test_8b_una_variante_sin_grabar_va_en_omitidos_si_otra_busqueda_respondio(self):
        """B4 de RC-226. Al reproducir, la variante que falta en la grabación no cuenta como saturación ni quita la
        cobertura si %marca% está grabada: su huella va en omitidos y lo demás se reporta."""
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None)
            vivo = crtsh.recolectar('acme-demo.mx', grab, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
            (Path(d) / 'acme-dem0.mx.json').unlink()
            res = crtsh.recolectar('acme-demo.mx', crtsh.ClienteCrtsh(modo='reproducir', carpeta=d), AHORA,
                                   propios=['acme-demo.com.mx'], parecidos=True)
        del_0 = next(h.huella for h in vivo.hallazgos if h.clave == 'acme-dem0.mx')
        self.assertEqual((res.estado, res.sin_cobertura, res.omitidos), ('succeeded', [], [del_0]))
        self.assertEqual([a for a in res.avisos if a.startswith(crtsh.SIN_GRABACION)], res.avisos)
        self.assertEqual(len(res.avisos), 1)
        self.assertEqual(sorted(h.clave for h in res.hallazgos if h.codigo == 'lookalike_domain'),
                         ['acme-demo-login.com', 'acme-demo-pagos.com', 'cuenta-segura.net'])
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])

    def test_9_completar_vuelve_a_consultar_lo_de_grabaciones_anteriores(self):
        inicio = datetime(2026, 10, 15, 18, 0, tzinfo=timezone.utc)
        reloj = lambda: inicio + crtsh.timedelta(minutes=1)

        class VarianteCaida(CrtshSimulado):
            def __call__(self, url, timeout):
                if 'q=acme-dem0.mx' in url:
                    self.urls.append(url)
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)

        with tempfile.TemporaryDirectory() as d:
            viejo = Path(d) / 'acme-dem0.mx.json'  # de la semana pasada, cuando no había certificado
            viejo.write_text(json.dumps({'grabado': '2026-10-08T18:00:00+00:00', 'consulta': 'acme-dem0.mx', 'datos': []}),
                             encoding='utf-8')
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=VarianteCaida(), dormir=lambda s: None, reloj=reloj)
            res = crtsh.recolectar('acme-demo.mx', grab, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
            self.assertEqual(crtsh.codigo_salida(res), 2)
            self.assertFalse(viejo.exists())  # la respuesta vieja no pasa por la de hoy

            t = CrtshSimulado()
            completa = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=t, dormir=lambda s: None, reloj=reloj,
                                          completar=True, desde=inicio)
            res = crtsh.recolectar('acme-demo.mx', completa, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
        self.assertEqual(len(t.urls), 1)
        self.assertIn('q=acme-dem0.mx', t.urls[0])
        self.assertEqual(crtsh.codigo_salida(res), 0)
        self.assertIn('acme-dem0.mx', {h.evidencia.get('dominio_parecido') for h in res.hallazgos})

    def test_10_completar_no_reutiliza_lo_anterior_al_inicio(self):
        inicio = datetime(2026, 10, 15, 18, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'subdominios_acme-demo.mx.json').write_text(json.dumps(
                {'grabado': '2026-10-08T18:00:00+00:00', 'consulta': '%.acme-demo.mx', 'datos': []}), encoding='utf-8')
            t = CrtshSimulado()
            cliente = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=t, dormir=lambda s: None,
                                         completar=True, desde=inicio)
            res = crtsh.recolectar('acme-demo.mx', cliente, AHORA, parecidos=False)
        self.assertEqual(len(t.urls), 1)
        self.assertEqual(len(res.activos), 6)

    def test_11_completar_sin_grabacion_previa_no_arranca(self):
        with tempfile.TemporaryDirectory() as d:
            original = crtsh.CARPETA_GRABADAS
            crtsh.CARPETA_GRABADAS = Path(d)
            try:
                with self.assertRaises(SystemExit) as salida, contextlib.redirect_stderr(io.StringIO()):
                    crtsh._main(['acme-demo.mx', '--grabar', '--completar'])
            finally:
                crtsh.CARPETA_GRABADAS = original
        self.assertEqual(salida.exception.code, 2)

    def test_13_flujo_del_dia_anterior_por_la_linea_de_comandos(self):
        """--grabar con crt.sh saturado, --reproducir con faltantes, --grabar --completar y --reproducir completo."""
        class PrimerasVariantesCaidas(CrtshSimulado):
            caidas = {'acme-demo.com', 'acme-demo.com.mx', 'acme-demo.net'}

            def __call__(self, url, timeout):
                q = crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(url).query).get('q', [''])[0]
                if q in self.caidas:
                    self.urls.append(url)
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)

        def correr(*argv):
            salida = io.StringIO()
            with contextlib.redirect_stdout(salida):
                codigo = crtsh._main(list(argv))
            return codigo, salida.getvalue()

        # El CLI con la fecha de AHORA: con la de hoy, acme-dem0.mx deja de ser reciente el 30 mar 2027 y la prueba falla.
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)), mock.patch.object(crtsh.time, 'sleep', lambda s: None), \
                mock.patch.object(crtsh, 'recolectar', functools.partial(crtsh.recolectar, ahora=AHORA)):
            propia, otra = Path(d) / 'acme-demo.mx', Path(d) / 'acme-demo.com.mx'
            propia.mkdir()
            otra.mkdir()
            (propia / 'acme-dem0.mx.json').write_text('[]', encoding='utf-8')     # de una grabación anterior
            (otra / 'contiene_acme-demo.json').write_text('[]', encoding='utf-8')  # de otro dominio

            with mock.patch.object(crtsh, '_descargar', PrimerasVariantesCaidas()):
                codigo, _ = correr('acme-demo.mx', '--grabar', '--con-parecidos')
            self.assertEqual(codigo, 2)
            self.assertFalse((propia / 'acme-dem0.mx.json').exists())
            self.assertTrue((otra / 'contiene_acme-demo.json').exists())

            codigo, texto = correr('acme-demo.mx', '--reproducir', '--con-parecidos')
            self.assertEqual(codigo, 2)
            self.assertIn('Faltan 10 respuestas grabadas', texto)  # 3 caídas y 7 omitidas por saturación
            self.assertNotIn('saturado', texto)

            sana = CrtshSimulado()
            with mock.patch.object(crtsh, '_descargar', sana):
                codigo, _ = correr('acme-demo.mx', '--grabar', '--completar', '--con-parecidos')
            self.assertEqual((codigo, len(sana.urls), sana.cert_spotter), (0, 10, []))

            codigo, texto = correr('acme-demo.mx', '--reproducir', '--con-parecidos')
            self.assertEqual(codigo, 0)
            self.assertNotIn('Faltan', texto)
            self.assertIn('acme-dem0.mx', texto)

    def test_15_si_crtsh_no_responde_la_grabacion_anterior_queda_intacta(self):
        def correr(*argv):
            with contextlib.redirect_stdout(io.StringIO()):
                return crtsh._main(list(argv))

        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d)), mock.patch.object(crtsh.time, 'sleep', lambda s: None):
            with mock.patch.object(crtsh, '_descargar', CrtshSimulado()):
                self.assertEqual(correr('acme-demo.mx', '--grabar'), 0)
            carpeta = Path(d) / 'acme-demo.mx'
            antes = {f.name: f.read_bytes() for f in carpeta.iterdir()}
            with mock.patch.object(crtsh, '_descargar', CrtshSimulado(fallas=100)):
                self.assertEqual(correr('acme-demo.mx', '--grabar'), 1)
            self.assertEqual({f.name: f.read_bytes() for f in carpeta.iterdir()}, antes)
            self.assertEqual(correr('acme-demo.mx', '--reproducir'), 0)

    def test_14_dominio_invalido_no_toca_las_grabaciones(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(crtsh, 'CARPETA_GRABADAS', Path(d) / 'crtsh'):
            fuera = Path(d) / 'otra_cosa.json'
            fuera.write_text('[]', encoding='utf-8')
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                crtsh._main(['..', '--grabar'])
            self.assertTrue(fuera.exists())

    def test_16_sin_ninguna_busqueda_de_parecidos_queda_sin_cobertura(self):
        class SoloSubdominios(CrtshSimulado):
            def __call__(self, url, timeout):
                if 'q=%25.acme-demo.mx' not in url:
                    self.urls.append(url)
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)
        res = recolectar(SoloSubdominios(), parecidos=True)
        self.assertEqual((res.estado, res.sin_cobertura), ('succeeded', ['lookalike_domain']))
        self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])
        self.assertEqual(recolectar(CrtshSimulado(), parecidos=False).sin_cobertura, ['lookalike_domain'])
        self.assertEqual(recolectar(CrtshSimulado(), parecidos=True).sin_cobertura, [])  # con una que responda basta

    def test_12_respaldo_por_nombre_deja_aviso(self):
        class SinComodin(CrtshSimulado):
            def __call__(self, url, timeout):
                if 'q=%25.acme-demo.mx' in url:
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)
        t = SinComodin(respuestas={'acme-demo.mx': SUBDOMINIOS})
        res = recolectar(t, parecidos=False)
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.error, '')
        self.assertEqual(len(res.avisos), 1)
        self.assertIn('pueden faltar subdominios', res.avisos[0])
        self.assertEqual(crtsh.codigo_salida(res), 2)

    def test_17_las_grabaciones_de_crtsh_no_van_al_repo(self):
        """Una grabación real, como la de olmardo.com, no se sube con un git add. La del recolector ejemplo sí va.
        Revisa solo el .gitignore del repo, copiado a un repo vacío, sin las exclusiones propias de cada PC."""
        reglas = Path(__file__).resolve().parents[1] / '.gitignore'
        if not reglas.exists() or not shutil.which('git'):
            self.skipTest('sin .gitignore o sin git, por ejemplo dentro del contenedor')
        with tempfile.TemporaryDirectory() as d:
            repo, vacio = Path(d) / 'repo', Path(d) / 'sin_exclusiones'
            vacio.write_text('', encoding='utf-8')
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            (repo / '.git' / 'info').mkdir(exist_ok=True)
            (repo / '.git' / 'info' / 'exclude').write_text('', encoding='utf-8')
            (repo / '.gitignore').write_bytes(reglas.read_bytes())

            def ignorado(ruta):
                r = subprocess.run(['git', '-c', 'core.excludesFile=' + vacio.as_posix(), 'check-ignore', '-q',
                                    '--no-index', 'cirdan/recolectores/respuestas_grabadas/' + ruta], cwd=repo)
                self.assertIn(r.returncode, (0, 1), ruta)  # 128: git no pudo revisarlo
                return r.returncode == 0
            for ruta in ('crtsh/olmardo.com/subdominios_olmardo.com.json', 'crtsh/olmardo.com/certspotter_olmardo.com.json',
                         'crtsh/olmardo.com/.grabacion', 'crtsh/subdominios_olmardo.com.json'):  # el último, formato del 9 oct
                self.assertTrue(ignorado(ruta), ruta)
            for ruta in ('crtsh/.gitkeep', 'ejemplo/acme-demo.mx/resultado.json'):
                self.assertFalse(ignorado(ruta), ruta)


class ErroresQueNoSonDeCrtsh(unittest.TestCase):

    def test_1_un_4xx_no_se_reintenta(self):
        def transporte(url, timeout):
            raise urllib.error.HTTPError(url, 400, 'Bad Request', None, None)
        cliente = crtsh.ClienteCrtsh(transporte=transporte, dormir=lambda s: None)
        with self.assertRaises(crtsh.CrtshNoResponde) as e:
            cliente.consultar('%.acme-demo.mx')
        self.assertEqual(cliente.consultas, 1)
        self.assertIn('después de 1 intento (', str(e.exception))

    def test_1b_408_y_429_si_se_reintentan(self):
        for codigo in (408, 429):
            def transporte(url, timeout, codigo=codigo):
                raise urllib.error.HTTPError(url, codigo, 'espera', None, None)
            cliente = crtsh.ClienteCrtsh(transporte=transporte, dormir=lambda s: None)
            with self.assertRaises(crtsh.CrtshNoResponde):
                cliente.consultar('%.acme-demo.mx')
            self.assertEqual(cliente.consultas, crtsh.INTENTOS, codigo)

    def test_2_un_error_del_disco_al_grabar_no_cuenta_como_falla_de_crtsh(self):
        with tempfile.TemporaryDirectory() as d:
            t = CrtshSimulado()
            cliente = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=t, dormir=lambda s: None)
            with mock.patch.object(cliente.grabadora, 'guardar', side_effect=PermissionError('abierto')):
                with self.assertRaises(PermissionError):
                    cliente.consultar('%.acme-demo.mx')
            self.assertEqual((cliente.consultas, len(t.urls)), (1, 1))

    def test_3_un_certificado_que_empieza_despues_de_ahora_tiene_antiguedad_0(self):
        t = CrtshSimulado(respuestas={
            '%.acme-demo.mx': [cert(40, ['nuevo.acme-demo.mx'], '2026-10-15T12:05:00', '2026-10-21T00:00:00')],
            'acme-dem0.mx': [cert(41, ['acme-dem0.mx'], '2026-10-15T12:00:01', '2026-12-30T00:00:00')]})
        res = recolectar(t, parecidos=True)
        edades = {h.codigo: h.caracteristicas['antiguedad_dias'] for h in res.hallazgos}
        self.assertEqual(edades, {'lookalike_domain': 0})  # al recién emitido le queda toda su vida: no está por vencer
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])


def iso(delta_dias):
    return (AHORA + timedelta(days=delta_dias)).strftime('%Y-%m-%dT%H:%M:%S')


class VigenciaReal(unittest.TestCase):
    """cert_expired solo si el nombre resuelve y no lo cubre un comodín vigente. Por vencer con el tercio de vida."""

    def test_1_vencido_de_un_nombre_que_ya_no_resuelve_solo_es_activo(self):
        t = CrtshSimulado(sin_dns={'dev.acme-demo.mx'})
        res = recolectar(t, parecidos=False)
        activos = {a.valor: a for a in res.activos}
        self.assertNotIn('cert_expired', {h.codigo for h in res.hallazgos})
        self.assertIs(activos['dev.acme-demo.mx'].atributos['resuelve'], False)
        self.assertEqual(t.dns, ['dev.acme-demo.mx', 'acme-demo.mx'])  # solo el del vencido, y el dominio como control

    def test_2_un_comodin_vigente_cubre_al_vencido_y_uno_vencido_no(self):
        vigente = cert(9, ['*.acme-demo.mx', 'acme-demo.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00')
        t = CrtshSimulado(respuestas={'%.acme-demo.mx': SUBDOMINIOS + [vigente]})
        res = recolectar(t, parecidos=False)
        activos = {a.valor: a for a in res.activos}
        self.assertNotIn('cert_expired', {h.codigo for h in res.hallazgos})
        self.assertEqual(activos['dev.acme-demo.mx'].atributos['cubierto_por_comodin'], 'acme-demo.mx')
        self.assertEqual(t.dns, [])
        vencido = cert(9, ['*.acme-demo.mx', 'acme-demo.mx'], '2026-01-01T00:00:00', '2026-04-01T00:00:00')
        res = recolectar(CrtshSimulado(respuestas={'%.acme-demo.mx': SUBDOMINIOS + [vencido]}), parecidos=False)
        self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})

    def test_3_por_vencer_cuando_queda_menos_de_un_tercio_de_su_vida(self):
        certs = [cert(50, ['corto.acme-demo.mx'], iso(-25), iso(20)),    # 45 días, le quedan 20: aún no
                 cert(51, ['corto2.acme-demo.mx'], iso(-35), iso(10)),   # 45 días, le quedan 10: sí
                 cert(52, ['anual.acme-demo.mx'], iso(-336), iso(29))]   # 365 días, le quedan 29: sí
        res = recolectar(CrtshSimulado(respuestas={'%.acme-demo.mx': certs}), parecidos=False)
        por_vencer = sorted(h.activo for h in res.hallazgos if h.codigo == 'cert_expiring_soon')
        self.assertEqual(por_vencer, ['anual.acme-demo.mx', 'corto2.acme-demo.mx'])

    def test_4_la_respuesta_de_dns_se_graba_y_se_reproduce(self):
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(sin_dns={'dev.acme-demo.mx'}),
                                      dormir=lambda s: None, nueva=True)
            crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False)
            self.assertEqual(json.loads((Path(d) / 'dns_dev.acme-demo.mx.json').read_text(encoding='utf-8'))['datos'], False)
            t = CrtshSimulado()  # su DNS diría que sí resuelve: no se debe consultar
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d, transporte=t)
            res = crtsh.recolectar('acme-demo.mx', rep, AHORA, parecidos=False)
        self.assertEqual((res.estado, t.dns, t.urls), ('succeeded', [], []))
        self.assertNotIn('cert_expired', {h.codigo for h in res.hallazgos})

    def test_5_sin_la_respuesta_de_dns_grabada_reporta_el_vencido_y_avisa(self):
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None)
            crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False)
            (Path(d) / 'dns_dev.acme-demo.mx.json').unlink()
            res = crtsh.recolectar('acme-demo.mx', crtsh.ClienteCrtsh(modo='reproducir', carpeta=d), AHORA, parecidos=False)
        self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})
        self.assertTrue(any('No se pudo comprobar en DNS si dev.acme-demo.mx' in a for a in res.avisos))
        self.assertFalse([a for a in res.avisos if a.startswith(crtsh.SIN_GRABACION)])  # no pide completar la grabación

    def test_6_si_el_dns_no_responde_reporta_el_vencido_y_avisa(self):
        cliente = crtsh.ClienteCrtsh(transporte=CrtshSimulado(), dormir=lambda s: None, resolver=lambda n: None)
        res = crtsh.recolectar('acme-demo.mx', cliente, AHORA, parecidos=False)
        self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})
        self.assertTrue(any('No se pudo comprobar en DNS si dev.acme-demo.mx' in a for a in res.avisos))

    def test_8_un_comodin_vencido_cuenta_aunque_el_padre_tenga_uno_vigente_o_el_nombre_base_no_resuelva(self):
        comodin_vencido = cert(100, ['*.dev.acme-demo.mx'], '2026-06-01T00:00:00', '2026-08-30T00:00:00')
        padre_vigente = cert(101, ['*.acme-demo.mx', 'acme-demo.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00')
        t = CrtshSimulado(respuestas={'%.acme-demo.mx': [comodin_vencido, padre_vigente]}, sin_dns={'dev.acme-demo.mx'})
        res = recolectar(t, parecidos=False)
        activos = {a.valor: a for a in res.activos}
        self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})
        self.assertNotIn('cubierto_por_comodin', activos['dev.acme-demo.mx'].atributos)
        self.assertNotIn('dev.acme-demo.mx', t.dns)  # el DNS del nombre base no dice nada del comodín

    def test_9_reproducir_dias_despues_tiene_el_dns_de_lo_que_vencio_en_medio(self):
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None, nueva=True)
            self.assertEqual(crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False).avisos, [])
            despues = AHORA + timedelta(days=11)  # el certificado de api vence el 25 oct
            res = crtsh.recolectar('acme-demo.mx', crtsh.ClienteCrtsh(modo='reproducir', carpeta=d), despues, parecidos=False)
        self.assertIn(('cert_expired', 'api.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})
        self.assertEqual(res.avisos, [])

    def test_10_sin_servidor_dns_no_se_descarta_ni_se_graba(self):
        todos = {'acme-demo.mx', 'www.acme-demo.mx', 'api.acme-demo.mx', 'dev.acme-demo.mx', 'tienda.acme-demo.mx'}
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(sin_dns=todos),
                                      dormir=lambda s: None, nueva=True)
            res = crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False)
            self.assertEqual(sorted(p.name for p in Path(d).glob('dns_*.json')), [])
        self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})
        self.assertTrue(any('No se pudo comprobar en DNS si dev.acme-demo.mx' in a for a in res.avisos))

    def test_11_titulo_de_por_vencer_en_singular_y_con_menos_de_un_dia(self):
        certs = [cert(53, ['horas.acme-demo.mx'], iso(-9), iso(0.5)),
                 cert(54, ['uno.acme-demo.mx'], iso(-9), iso(1.5)),
                 cert(55, ['dos.acme-demo.mx'], iso(-9), iso(2.5)),
                 cert(56, ['justo1.acme-demo.mx'], iso(-9), iso(1)),   # justo un día: ya no es menos de un día
                 cert(57, ['justo0.acme-demo.mx'], iso(-9), iso(0))]   # vence en este segundo: aún no está vencido
        res = recolectar(CrtshSimulado(respuestas={'%.acme-demo.mx': certs}), parecidos=False)
        por_vencer = {h.activo: (h.titulo, h.evidencia['dias_para_vencer'])
                      for h in res.hallazgos if h.codigo == 'cert_expiring_soon'}
        self.assertEqual(por_vencer, {
            'horas.acme-demo.mx': ('El certificado de horas.acme-demo.mx vence en menos de un día', 0),
            'uno.acme-demo.mx': ('El certificado de uno.acme-demo.mx vence en 1 día', 1),
            'dos.acme-demo.mx': ('El certificado de dos.acme-demo.mx vence en 2 días', 2),
            'justo1.acme-demo.mx': ('El certificado de justo1.acme-demo.mx vence en 1 día', 1),
            'justo0.acme-demo.mx': ('El certificado de justo0.acme-demo.mx vence en menos de un día', 0)})

    def test_7_resolvedor_del_sistema(self):
        casos = [(None, True), (socket.gaierror(socket.EAI_NONAME, 'no existe'), False),
                 (socket.gaierror(socket.EAI_AGAIN, 'temporal'), None), (OSError('red'), None)]
        for error, esperado in casos:
            efecto = error if error else [('familia', 'tipo', 'proto', '', ('198.51.100.10', 0))]
            with mock.patch.object(crtsh.socket, 'getaddrinfo', side_effect=efecto if error else None,
                                   return_value=None if error else efecto):
                self.assertIs(crtsh._resolver_dns('www.acme-demo.mx'), esperado, error)


class Resumen(unittest.TestCase):
    """Lo que se lee en la terminal durante una demo."""

    def test_1_severidad_y_caracteristicas_en_espanol(self):
        res = recolectar(CrtshSimulado(), parecidos=False)
        lineas = crtsh.resumen(res)
        self.assertEqual(lineas[0], 'acme-demo.mx · crt.sh y Cert Spotter · succeeded · 2 consultas')
        self.assertIn('  [media] El certificado de api.acme-demo.mx vence en 10 días', lineas)
        self.assertIn('  [alta] Certificado vencido en dev.acme-demo.mx', lineas)
        self.assertIn('      tipo: certificado por vencer · antigüedad: 80 días · exposición: pública · sensibilidad: baja',
                      lineas)
        self.assertIn('6 activos, con su vencimiento en UTC:', lineas)
        # Una fecha con otro desfase se pasa a UTC antes de imprimirla: el 31 dic a la 01:00 en UTC+2 es el 30 dic.
        self.assertEqual(crtsh._dia(crtsh._fecha('2026-12-31T01:00:00+02:00')), '30 dic 2026')
        self.assertIn('  api.acme-demo.mx · vence 25 oct 2026', lineas)
        self.assertIn('  tienda.acme-demo.mx · vence 30 nov 2026 · comodín', lineas)
        self.assertFalse([l for l in lineas if '[medium]' in l or '[high]' in l])
        self.assertEqual(crtsh.codigo_salida(res), 0)

    def test_2_reproducir_dice_de_cuando_es_la_grabacion(self):
        # La fecha va dentro del archivo: una copia o un git clone no la cambian. Mediodía local para que
        # la fecha impresa sea la misma en cualquier zona horaria.
        grabado = datetime(2026, 10, 15, 12, 0).astimezone()
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None,
                                      reloj=lambda: grabado)
            crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False)
            ahora = datetime.now().timestamp()
            for f in Path(d).iterdir():
                os.utime(f, (ahora, ahora))  # como si se acabara de copiar
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d)
            lineas = crtsh.resumen(crtsh.recolectar('acme-demo.mx', rep, AHORA, parecidos=False), rep)
        self.assertIn('sin red, respuestas grabadas el 15 oct 2026 a las 12:00 (%s)' % crtsh._zona(grabado), lineas[0])
        self.assertEqual([crtsh._zona(datetime(2026, 10, 15, tzinfo=timezone(timedelta(hours=h)))) for h in (-6, 0, 5.5)],
                         ['UTC-06:00', 'UTC', 'UTC+05:30'])
        self.assertNotIn('consulta', lineas[0])

    def test_2b_lee_el_formato_anterior(self):
        with tempfile.TemporaryDirectory() as d:
            archivo = Path(d) / 'subdominios_acme-demo.mx.json'
            archivo.write_text(json.dumps(SUBDOMINIOS), encoding='utf-8')
            marca = datetime(2026, 10, 14, 12, 0).timestamp()
            os.utime(archivo, (marca, marca))
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d)
            res = crtsh.recolectar('acme-demo.mx', rep, AHORA, parecidos=False)
            lineas = crtsh.resumen(res, rep)
        self.assertEqual(len(res.activos), 6)
        self.assertIn('respuestas grabadas el 14 oct 2026', lineas[0])

    def test_3_faltantes_agrupados_y_sin_saturacion(self):
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(), dormir=lambda s: None)
            crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False)
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d)
            res = crtsh.recolectar('acme-demo.mx', rep, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
            lineas = crtsh.resumen(res, rep)
        faltan = [l for l in lineas if l.startswith('Faltan ')]
        self.assertEqual(len(faltan), 1)
        self.assertIn('%acme-demo%', faltan[0])
        self.assertTrue(faltan[0].endswith('Se completan con --grabar --completar.'))
        self.assertFalse([l for l in lineas if 'saturado' in l or l.startswith('aviso:')])

    def test_3b_un_solo_faltante_en_singular(self):
        res = crtsh.Resultado('acme-demo.mx', avisos=[crtsh.SIN_GRABACION + '%.acme-demo.mx'])
        self.assertIn('Falta 1 respuesta grabada: %.acme-demo.mx. Se completa con --grabar --completar.',
                      crtsh.resumen(res))

    def test_4_sin_hallazgos_lo_dice(self):
        solo = cert(40, ['acme-demo.mx'], '2026-09-20T00:00:00', '2026-12-19T00:00:00')
        res = recolectar(CrtshSimulado(respuestas={'%.acme-demo.mx': [solo]}), parecidos=True)
        lineas = crtsh.resumen(res)
        self.assertEqual(lineas[-1], 'Sin hallazgos.')
        self.assertIn('1 activo, con su vencimiento en UTC:', lineas)
        # sin buscar parecidos (lo predeterminado) no es lo mismo que 0 parecidos
        res = recolectar(CrtshSimulado(respuestas={'%.acme-demo.mx': [solo]}), parecidos=False)
        self.assertEqual(crtsh.resumen(res)[-2:], [
            'Sin hallazgos.', 'Cobertura parcial: no se revisaron dominios parecidos (lookalike_domain).'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
