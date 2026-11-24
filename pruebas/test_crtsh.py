"""Pruebas del recolector de crt.sh (#14), sin red: un crt.sh simulado y una fecha fija.

    python -m unittest -v pruebas/test_crtsh.py
"""
import contextlib
import io
import json
import functools
import importlib.util
import os
import re
import shutil
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

    def __init__(self, fallas=0, respuestas=None, sin_dns=(), emisiones=(), san=None):
        """`san`: respuestas del respaldo de las variantes (dNSName=X y dNSName=%.X, RC-337). Sin él, ese respaldo da
        502: una variante caída en q= sigue caída, como en las pruebas de antes del respaldo."""
        self.fallas, self.urls, self.sin_dns, self.dns = fallas, [], set(sin_dns), []
        self.respuestas = respuestas if respuestas is not None else {
            '%.acme-demo.mx': SUBDOMINIOS, '%acme-demo%': CONTIENE_MARCA, 'acme-dem0.mx': CANDIDATO}
        self.emisiones, self.cert_spotter, self.san = list(emisiones), [], san

    def __call__(self, url, timeout):
        partes = crtsh.urllib.parse.urlparse(url)
        cert_spotter = partes.netloc == 'api.certspotter.com'
        (self.cert_spotter if cert_spotter else self.urls).append(url)
        if self.fallas:
            self.fallas -= 1
            raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
        if cert_spotter:  # una página con las emisiones y la vacía que cierra
            return json.dumps([] if 'after' in crtsh.urllib.parse.parse_qs(partes.query) else self.emisiones).encode()
        parametros = crtsh.urllib.parse.parse_qs(partes.query)
        if 'dNSName' in parametros:
            if self.san is None:
                raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
            return json.dumps(self.san.get(parametros['dNSName'][0], [])).encode()
        q = parametros['q'][0]
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

    def test_2b_emitido_es_el_not_before_del_certificado_mas_reciente(self):
        """RC-219: www y el dominio raíz tienen el certificado 1 (abr) y el 2 (sep). 'emitido' es el del 2."""
        for nombre in ('www.acme-demo.mx', 'acme-demo.mx'):
            a = self.activos[nombre].atributos
            self.assertEqual((a['emitido'], a['primer_certificado']),
                             ('2026-09-20T00:00:00+00:00', '2026-04-01T00:00:00+00:00'), nombre)
        self.assertEqual(self.activos['api.acme-demo.mx'].atributos['emitido'], '2026-07-27T00:00:00+00:00')

    def test_2d_emitido_es_el_emitido_mas_tarde_aunque_venza_antes(self):
        """RC-219: uno de un año (mar) y uno de 90 días emitido después (oct) que vence antes. Gana el de oct."""
        certs = [cert(1, ['www.acme-demo.mx'], '2026-03-01T00:00:00', '2027-03-01T00:00:00',
                      emisor='C=US, O=DigiCert Inc'),
                 cert(2, ['www.acme-demo.mx'], '2026-10-10T00:00:00', '2027-01-08T00:00:00')]
        a = crtsh._subdominios('acme-demo.mx', certs, AHORA)[0][0].atributos
        self.assertEqual((a['emitido'], a['vence']), ('2026-10-10T00:00:00+00:00', '2027-03-01T00:00:00+00:00'))

    def test_2e_emitido_tambien_con_un_certificado_de_cert_spotter(self):
        """RC-219: un certificado que solo trae Cert Spotter pasa por el mismo camino y deja 'emitido'."""
        c = dict(cert(9, ['cs.acme-demo.mx'], '2026-10-01T00:00:00', '2026-12-30T00:00:00'), origen='certspotter')
        a = crtsh._subdominios('acme-demo.mx', [c], AHORA)[0][0].atributos
        self.assertEqual(a['emitido'], '2026-10-01T00:00:00+00:00')

    def test_2c_emitido_no_toma_un_revocado_aunque_sea_mas_nuevo(self):
        """RC-219: un revocado no cuenta para 'emitido' mientras haya otro sin revocar."""
        certs = [cert(1, ['www.acme-demo.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
                 dict(cert(2, ['www.acme-demo.mx'], '2026-10-10T00:00:00', '2027-01-08T00:00:00'), revocado=True)]
        activos, _ = crtsh._subdominios('acme-demo.mx', certs, AHORA)
        self.assertEqual(activos[0].atributos['emitido'], '2026-09-01T00:00:00+00:00')

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

    def test_3b_ningun_parecido_es_cobertura_completa_con_cero(self):
        """Punto 5 de RC-226, sin red: crt.sh responde %marca% y todas las variantes, y ninguna trae un parecido de
        menos de 90 días (solo el viejo, el propio y nombres del dominio). lookalike_domain queda revisado con 0
        hallazgos, no en sin_cobertura. La corrida queda 'complete': orquestador.cobertura() da 'complete' con estado
        succeeded, revisados en None y algún código fuera de sin_cobertura (aquí ninguno está). El orquestador no se
        importa porque pide la base y dnspython, que el runner de 'Pruebas sin base ni red' no trae."""
        sin_parecidos = [c for c in CONTIENE_MARCA if c['id'] in (23, 24, 25)]
        t = CrtshSimulado(respuestas={'%.acme-demo.mx': SUBDOMINIOS, '%acme-demo%': sin_parecidos})
        res = recolectar(t, parecidos=True)
        consultas = [consulta(u) for u in t.urls]
        self.assertIn('%acme-demo%', consultas)
        for variante in crtsh.candidatos_parecidos('acme-demo.mx'):
            if variante != 'acme-demo.com.mx':  # propio de la empresa (recolectar), no se pregunta
                self.assertIn(variante, consultas, variante)  # cada variante se preguntó y respondió vacía
        self.assertEqual((res.estado, res.sin_cobertura, res.omitidos, res.revisados), ('succeeded', [], [], None))
        self.assertEqual([h for h in res.hallazgos if h.codigo == 'lookalike_domain'], [])
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])
        # Los de subdominios siguen saliendo: el 0 es solo de parecidos.
        self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})

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

    def _con_cronometro(self, tarda, duerme=None, **cliente):
        """Corre los parecidos de acme-demo.mx con un cronómetro falso. `tarda(variante, intento)` dice cuántos
        segundos tarda crt.sh con esa petición: si pasa del timeout que recibe el transporte, es un timeout.
        `duerme(segundos, cronómetro)` dice cuánto dura de verdad una pausa (sin él, lo pedido). `cliente` va a
        ClienteCrtsh, que queda en self.cliente.
        Devuelve el resultado, las peticiones de variantes (variante, timeout) y los segundos que duraron."""
        reloj, pedidas, intentos = [0.0], [], {}

        class Lento(CrtshSimulado):
            def __call__(self, url, timeout):
                q = crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(url).query).get('q')
                if not q or q[0].startswith('%'):
                    return super().__call__(url, timeout)
                intentos[q[0]] = intentos.get(q[0], 0) + 1
                pedidas.append((q[0], timeout))
                segundos = tarda(q[0], intentos[q[0]])
                if segundos > timeout:
                    reloj[0] += timeout
                    raise TimeoutError('timed out')
                reloj[0] += segundos
                return super().__call__(url, timeout)

        def dormir(s):
            reloj[0] += duerme(s, reloj[0]) if duerme else s
        self.cliente = crtsh.ClienteCrtsh(transporte=Lento(), dormir=dormir, cronometro=lambda: reloj[0], **cliente)
        res = crtsh.recolectar('acme-demo.mx', self.cliente, AHORA, parecidos=True, propios=['acme-demo.com.mx'])
        return res, pedidas, reloj[0]

    def test_4d_una_variante_de_35_segundos_responde(self):
        """El 11 nov olmardo.com.mx tardó unos 35 s y con 2 intentos de 20 s dejaba el escaneo parcial. El segundo
        intento de una variante espera hasta 45 s (TIMEOUTS_VARIANTE) y la lenta responde ahí."""
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        lenta = variantes[1]
        res, pedidas, duro = self._con_cronometro(lambda v, n: 35 if v == lenta else 1)
        self.assertEqual(crtsh.TIMEOUTS_VARIANTE, (20, 45))
        self.assertEqual(pedidas, [(variantes[0], 20), (lenta, 20), (lenta, 45)] + [(v, 45) for v in variantes[2:]])
        self.assertEqual((res.estado, res.sin_cobertura, res.omitidos), ('succeeded', [], []))
        self.assertFalse([a for a in res.avisos if 'no respondió' in a or 'tiempo de las variantes' in a])
        self.assertIsNone(res.revisados)  # corrida completa: el escaneo no termina 'partial' por la variante lenta
        self.assertEqual(duro, (len(variantes) - 1) * (crtsh.PAUSA_PARECIDOS + 1)
                         + crtsh.PAUSA_PARECIDOS + 20 + crtsh.ESPERAS[0] + 35)
        # Todas se cuelgan al primer intento y responden en 1 s al segundo: cuesta lo mismo que antes y caben todas
        res, pedidas, duro = self._con_cronometro(lambda v, n: 1000 if n == 1 else 1)
        self.assertEqual((res.omitidos, res.revisados), ([], None))
        self.assertEqual(duro, len(variantes) * (crtsh.PAUSA_PARECIDOS + 20 + crtsh.ESPERAS[0] + 1))

    def test_4e_las_variantes_no_pasan_de_su_presupuesto(self):
        """Con crt.sh lento en todas las variantes (un timeout y luego 40 s), las variantes juntas no pasan de
        PRESUPUESTO_VARIANTES: las que no caben quedan sin consultar, con su aviso y su huella en omitidos, ninguna
        petición recibe menos de MINIMO_VARIANTE ni más de 45 s y nunca hay más de 2 por variante."""
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        res, pedidas, duro = self._con_cronometro(lambda v, n: 100 if n == 1 else 40)
        self.assertLessEqual(duro, crtsh.PRESUPUESTO_VARIANTES)
        self.assertTrue(all(crtsh.MINIMO_VARIANTE <= t <= crtsh.TIMEOUTS_VARIANTE[1] for _, t in pedidas), pedidas)
        # La 1.ª responde en 40 s al reintento y la 2.ª prueba 45 s desde el primer intento. Ese intento falla y el
        # resto vuelve a 20 y 45: 67 + 92 + 4 x 67 = 427 s con 6 respuestas. La 7.ª hace su primer intento (449 s) y
        # ya no le caben la espera y otro de 20 s. A las 3 últimas no se les pregunta.
        primeros = {}
        for v, t in pedidas:
            primeros.setdefault(v, t)
        self.assertEqual(primeros, {v: 45 if v == variantes[1] else 20 for v in variantes[:7]})
        self.assertEqual([[v for v, _ in pedidas].count(v) for v in variantes[:7]],
                         [crtsh.INTENTOS_PARECIDOS] * 6 + [1])
        self.assertEqual(duro, 449)
        cortada, faltan = variantes[6], variantes[7:]
        self.assertEqual(res.avisos[-2:], [
            crtsh.SIN_REINTENTO % (crtsh.PRESUPUESTO_VARIANTES, '1 variante', cortada),
            crtsh.SIN_TIEMPO % (crtsh.PRESUPUESTO_VARIANTES, '%d variantes' % len(faltan), ', '.join(faltan))])
        # a las que faltan no se les preguntó y a la cortada la cortó el tiempo: ninguna es falla de crt.sh
        self.assertFalse([a for a in res.avisos if 'después de' in a or 'saturado' in a])
        self.assertEqual(sorted(res.omitidos),
                         sorted(crtsh._huella('lookalike_domain', 'acme-demo.mx', v) for v in [cortada] + faltan))
        self.assertIsNotNone(res.revisados)  # faltaron variantes: el escaneo termina 'partial'
        self.assertEqual(res.consultas, 3 + len(pedidas))  # la del dominio, Cert Spotter, %marca% y lo que sí se pidió
        # crt.sh colgado en todas: corta a las FALLAS_SEGUIDAS variantes, también dentro del presupuesto
        res, pedidas, duro = self._con_cronometro(lambda v, n: 1000)
        self.assertEqual(len(pedidas), crtsh.FALLAS_SEGUIDAS * crtsh.INTENTOS_PARECIDOS)
        self.assertLessEqual(duro, crtsh.PRESUPUESTO_VARIANTES)
        self.assertIn('crt.sh saturado', res.avisos[-1])
        # el último intento se recorta a lo que queda (42 s) y el presupuesto se gasta exacto
        ultima = variantes[-1]
        caida = variantes[-2]
        res, pedidas, duro = self._con_cronometro(lambda v, n: 1000 if v in (caida, ultima) or n == 1 else 20)
        cada_una = crtsh.PAUSA_PARECIDOS + 20 + crtsh.ESPERAS[0]  # pausa, timeout del primer intento y espera
        # 7 variantes de 47 s y una caída de 72 s: a la última le quedan 42 s para su segundo intento
        resto = crtsh.PRESUPUESTO_VARIANTES - (len(variantes) - 2) * (cada_una + 20) - (cada_una + 45) - cada_una
        self.assertTrue(crtsh.MINIMO_VARIANTE <= resto < crtsh.TIMEOUTS_VARIANTE[1], resto)
        self.assertEqual(pedidas[-2:], [(ultima, 20), (ultima, resto)])
        self.assertEqual(duro, crtsh.PRESUPUESTO_VARIANTES)
        self.assertIn('no respondió a %s después de 2 intentos' % ultima, res.avisos[-1])  # sí tuvo sus 2 intentos
        # si después del primer intento ya no caben la espera y MINIMO_VARIANTE, no hay segundo intento ni espera: 6
        # variantes de 47 s y 2 caídas de 72 s dejan 44 s, y tras la pausa y el primer intento de la última quedan 22
        caidas = variantes[-3:-1]
        res, pedidas, duro = self._con_cronometro(lambda v, n: 1000 if v in caidas + [ultima] or n == 1 else 20)
        self.assertEqual([t for v, t in pedidas if v == ultima], [20])
        # Con los 22 s que quedan, el respaldo de la primera caída (RC-337) hace su pausa y su dNSName da 502 al
        # momento. Al de la segunda ya no le cabe una petición (20 s < pausa + MINIMO_VARIANTE).
        self.assertEqual(duro, (len(variantes) - 3) * (cada_una + 20) + 2 * (cada_una + 45)
                         + crtsh.PAUSA_PARECIDOS + 20 + crtsh.PAUSA_PARECIDOS)
        self.assertEqual(crtsh.PRESUPUESTO_VARIANTES - duro, 20)
        self.assertEqual([u for u in self.cliente.transporte.urls if 'dNSName' in u],
                         ['https://crt.sh/?dNSName=%s&output=json' % caidas[0]])
        self.assertEqual(res.avisos[-1], crtsh.SIN_REINTENTO % (crtsh.PRESUPUESTO_VARIANTES, '1 variante', ultima))
        self.assertFalse([a for a in res.avisos if 'saturado' in a])

    def test_4g_si_crtsh_viene_lento_las_siguientes_esperan_45_desde_el_primer_intento(self):
        """Con casi todas las variantes entre 21 y 45 s, el primer intento de 20 s se perdía en cada una: de 10
        variantes de 35 s respondían 7. Cuando una respuesta tarda más de 20 s, las siguientes esperan 45 s desde el
        primer intento, y vuelven a 20 s si con eso una falla su primer intento."""
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        corto, largo = crtsh.TIMEOUTS_VARIANTE
        pausa, espera = crtsh.PAUSA_PARECIDOS, crtsh.ESPERAS[0]
        self.assertEqual(len(variantes), 9)
        # todas tardan 35 s: 62 + 8 x 37 = 358 s, responden las 9 con 10 consultas. Antes eran 7 con 15
        res, pedidas, duro = self._con_cronometro(lambda v, n: 35)
        self.assertEqual(pedidas, [(variantes[0], corto), (variantes[0], largo)] + [(v, largo) for v in variantes[1:]])
        self.assertEqual(duro, pausa + corto + espera + 35 + 8 * (pausa + 35))
        self.assertEqual((duro, res.estado, res.omitidos, res.revisados), (358, 'succeeded', [], None))
        self.assertFalse([a for a in res.avisos if 'no respondió' in a or 'tiempo de las variantes' in a])
        self.assertEqual(res.consultas, 3 + len(variantes) + 1)
        # una lenta y las demás se cuelgan al primer intento y responden en 1 s: solo la 2.ª paga el intento largo
        res, pedidas, duro = self._con_cronometro(lambda v, n: 35 if v == variantes[0] else 1000 if n == 1 else 1)
        self.assertEqual(pedidas, [(variantes[0], corto), (variantes[0], largo), (variantes[1], largo),
                                   (variantes[1], largo)] + [(v, t) for v in variantes[2:] for t in (corto, largo)])
        self.assertEqual(duro, 62 + (pausa + largo + espera + 1) + 7 * (pausa + corto + espera + 1))
        self.assertEqual((res.omitidos, res.revisados), ([], None))
        # con 45 s, una respuesta rápida al primer intento no cambia nada: la lenta que sigue responde al primero
        res, pedidas, duro = self._con_cronometro(lambda v, n: 35 if v in (variantes[0], variantes[4]) else 1)
        self.assertEqual(pedidas, [(variantes[0], corto), (variantes[0], largo)] + [(v, largo) for v in variantes[1:]])
        # con 45 s, una variante que no responde regresa las siguientes a 20 y 45, y ahí se quedan aunque tarden
        res, pedidas, duro = self._con_cronometro(lambda v, n: 1000 if v == variantes[1] else 35)
        self.assertEqual(pedidas[:8], [(variantes[0], corto), (variantes[0], largo), (variantes[1], largo),
                                       (variantes[1], largo), (variantes[2], corto), (variantes[2], largo),
                                       (variantes[3], corto), (variantes[3], largo)])
        self.assertLessEqual(duro, crtsh.PRESUPUESTO_VARIANTES)
        # el ritmo, caso por caso: (intentos, segundos de la respuesta), o None si salió del disco
        normal, lento, fijo = crtsh.NORMAL, crtsh.LENTO, crtsh.FIJO
        for ritmo, ultima, sigue in ((normal, (1, 1), normal), (normal, (2, 1), normal), (normal, (2, 20), normal),
                                     (normal, (2, 20.5), lento), (normal, (1, 21), lento), (normal, None, normal),
                                     (lento, (1, 1), lento), (lento, (1, 44), lento), (lento, None, lento),
                                     (lento, (2, 1), fijo), (lento, (2, 40), fijo),
                                     (fijo, (2, 40), fijo), (fijo, (1, 30), fijo), (fijo, None, fijo)):
            self.assertEqual(crtsh._ritmo(ritmo, ultima), sigue, (ritmo, ultima))
        self.assertEqual([crtsh._timeouts_variante(r) for r in (normal, lento, fijo)],
                         [(corto, largo), (largo, largo), (corto, largo)])

    def test_4h_el_tiempo_se_vuelve_a_medir_despues_de_la_pausa_y_antes_de_cada_intento(self):
        """Si la pausa o la espera duran de más, la petición no sale con menos de MINIMO_VARIANTE, ni con 0 o menos
        segundos: una variante a la que no se le preguntó no es falla de crt.sh ni toca la grabación."""
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        una = crtsh.PAUSA_PARECIDOS + 20 + crtsh.ESPERAS[0] + 20  # se cuelga al primer intento y responde en 20 s
        for de_mas in (0.5, 30):  # la pausa se pasa medio segundo, o el proceso se detiene 30 s
            # la 2.ª variante empieza con 22 s, justo la pausa y MINIMO_VARIANTE, y su pausa dura de más
            with mock.patch.object(crtsh, 'PRESUPUESTO_VARIANTES', una + 22):
                res, pedidas, duro = self._con_cronometro(lambda v, n: 1000 if n == 1 else 20,
                                                          duerme=lambda s, t: s + de_mas if t >= una else s)
            self.assertEqual(pedidas, [(variantes[0], 20), (variantes[0], 42)], de_mas)  # 42 s: lo que quedaba
            self.assertEqual(res.avisos[-1], crtsh.SIN_TIEMPO % (una + 22, '8 variantes', ', '.join(variantes[1:])))
            self.assertFalse([a for a in res.avisos if 'no respondió' in a or 'saturado' in a], de_mas)
            self.assertEqual(res.consultas, 3 + len(pedidas))  # a la 2.ª no se le preguntó: no gasta cupo
        # la espera entre intentos dura de más: no hay segundo intento, y el aviso dice que fue el tiempo
        with mock.patch.object(crtsh, 'PRESUPUESTO_VARIANTES', 72):
            res, pedidas, duro = self._con_cronometro(lambda v, n: 1000,
                                                      duerme=lambda s, t: s + 31 if s == crtsh.ESPERAS[0] else s)
        self.assertEqual(pedidas, [(variantes[0], 20)])
        self.assertEqual(res.avisos[-2:], [crtsh.SIN_REINTENTO % (72, '1 variante', variantes[0]),
                                           crtsh.SIN_TIEMPO % (72, '8 variantes', ', '.join(variantes[1:]))])
        self.assertFalse([a for a in res.avisos if 'después de' in a or 'saturado' in a])
        # en el cliente: sin preguntar no se descarta lo grabado ni se cuenta la consulta. Con un intento sí
        reloj = [0.0]

        def colgado(url, timeout):
            reloj[0] += timeout
            raise TimeoutError('timed out')

        def dormir(s):
            reloj[0] += s + 0.5
        with tempfile.TemporaryDirectory() as d:
            viejo = crtsh._archivo_grabado('acme-demo.com', d)
            viejo.write_text(json.dumps({'grabado': '2026-10-08T18:00:00+00:00', 'consulta': 'acme-demo.com',
                                         'datos': []}), encoding='utf-8')
            cliente = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=colgado, dormir=dormir,
                                         cronometro=lambda: reloj[0])
            pedir = functools.partial(cliente.consultar, 'acme-demo.com', intentos=2, timeout=crtsh.TIMEOUTS_VARIANTE,
                                      pausa=crtsh.PAUSA_PARECIDOS)
            with self.assertRaises(crtsh.SinTiempo) as sin:
                pedir(plazo=reloj[0] + 22)
            self.assertEqual((sin.exception.intentos, cliente.consultas, viejo.exists()), (0, 0, True))
            self.assertEqual(str(sin.exception), 'no quedó tiempo para consultar acme-demo.com')
            with self.assertRaises(crtsh.SinTiempo) as sin:
                pedir(plazo=reloj[0] + 46)  # pausa de 2.5 s, un intento de 20 s y quedan 23.5: no cabe otro
            self.assertEqual((sin.exception.intentos, cliente.consultas, viejo.exists()), (1, 1, False))
            self.assertIn('después de 1 intento (TimeoutError: timed out) y no quedó tiempo para otro',
                          str(sin.exception))
            self.assertIsNone(cliente.ultima)

    def test_4i_una_variante_cortada_por_el_tiempo_no_cuenta_como_saturacion(self):
        """Dos variantes sin respuesta y luego una a la que el tiempo no le dejó su segundo intento no son 3 fallas
        seguidas: el aviso dice que fue el tiempo, no 'crt.sh saturado', y a la que sigue sí se le pregunta."""
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        # 2 caídas de 72 s (144), la 3.ª hace un intento (166) y quedan 22 s: la 4.ª hace el suyo (188)
        with mock.patch.object(crtsh, 'PRESUPUESTO_VARIANTES', 188):
            res, pedidas, duro = self._con_cronometro(lambda v, n: 1000)
        self.assertEqual(duro, 188)
        self.assertEqual(pedidas, [(variantes[0], 20), (variantes[0], 45), (variantes[1], 20), (variantes[1], 45),
                                   (variantes[2], 20), (variantes[3], 20)])
        self.assertFalse([a for a in res.avisos if 'saturado' in a])
        self.assertEqual([a.split(' después de ')[0] for a in res.avisos if ' después de ' in a],
                         ['crt.sh no respondió a %s' % v for v in variantes[:2]])
        self.assertEqual(res.avisos[-2:], [
            crtsh.SIN_REINTENTO % (188, '2 variantes', ', '.join(variantes[2:4])),
            crtsh.SIN_TIEMPO % (188, '5 variantes', ', '.join(variantes[4:]))])
        self.assertEqual(sorted(res.omitidos),
                         sorted(crtsh._huella('lookalike_domain', 'acme-demo.mx', v) for v in variantes))
        self.assertIsNotNone(res.revisados)  # el escaneo termina 'partial'
        self.assertEqual(res.consultas, 3 + len(pedidas))

    def test_4j_sin_tiempo_no_es_saturacion_y_lo_grabado_se_lee_igual(self):
        """Más de FALLAS_SEGUIDAS variantes seguidas sin tiempo no cortan las demás por saturación, y con --grabar
        --completar la que ya está en el disco se lee aunque el presupuesto se haya acabado."""
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        grabada, vigente = variantes[8], ('2026-09-10T00:00:00', '2026-12-09T00:00:00')
        with tempfile.TemporaryDirectory() as d, mock.patch.object(crtsh, 'PRESUPUESTO_VARIANTES', 100):
            crtsh._archivo_grabado(grabada, d).write_text(json.dumps({
                'grabado': '2026-11-11T18:00:00+00:00', 'consulta': grabada,
                'datos': [cert(97, [grabada], *vigente)]}), encoding='utf-8')
            res, pedidas, duro = self._con_cronometro(lambda v, n: 1000 if n == 1 else 20, modo='grabar', carpeta=d,
                                                      completar=True)
        self.assertEqual(pedidas, [(variantes[0], 20), (variantes[0], 45), (variantes[1], 20), (variantes[1], 26)])
        self.assertEqual(duro, 94)  # 2 x 47 s y quedan 6
        faltan = variantes[2:8] + variantes[9:]
        self.assertGreater(len(variantes[2:8]), crtsh.FALLAS_SEGUIDAS)
        self.assertEqual(res.avisos[-1], crtsh.SIN_TIEMPO % (100, '%d variantes' % len(faltan), ', '.join(faltan)))
        self.assertFalse([a for a in res.avisos if 'saturado' in a or 'no respondió' in a])
        self.assertIn(crtsh._nombre_grabado(grabada), [archivo for archivo, _ in self.cliente.leidas])
        self.assertIn(grabada, {h.evidencia.get('dominio_parecido') for h in res.hallazgos})
        self.assertEqual(sorted(res.omitidos),
                         sorted(crtsh._huella('lookalike_domain', 'acme-demo.mx', v) for v in faltan))

    def test_4k_la_pausa_cuenta_al_revisar_si_cabe_la_variante(self):
        """Una variante que empieza con menos de la pausa más MINIMO_VARIANTE (entre 20 y 22 s) no se consulta ni
        gasta la pausa. Con 22 s justos sí se consulta."""
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        una = crtsh.PAUSA_PARECIDOS + 20 + crtsh.ESPERAS[0] + 20
        for quedan in (20, 21, 21.9):
            with mock.patch.object(crtsh, 'PRESUPUESTO_VARIANTES', una + quedan):
                res, pedidas, duro = self._con_cronometro(lambda v, n: 1000 if n == 1 else 20)
            self.assertEqual(([v for v, _ in pedidas], duro), ([variantes[0]] * 2, una), quedan)
            self.assertEqual(res.avisos[-1], crtsh.SIN_TIEMPO % (una + quedan, '8 variantes', ', '.join(variantes[1:])))
        with mock.patch.object(crtsh, 'PRESUPUESTO_VARIANTES', una + 22):
            res, pedidas, duro = self._con_cronometro(lambda v, n: 1000 if n == 1 else 20)
        self.assertEqual(pedidas[2:], [(variantes[1], 20)])
        self.assertEqual(duro, una + 22)

    def test_4f_el_peor_caso_de_tiempo_documentado(self):
        """El peor caso de una corrida, que citan el orquestador y docs/contrato_plugin.md, sale de las constantes:
        865 s, debajo de TOPE_CORRIDA. Si cambia un timeout o el presupuesto, cambian los textos y se revisa el tope.
        Las dos búsquedas de subdominios tienen juntas PLAZO_PRINCIPAL (RC-218)."""
        from cirdan.recolectores import certspotter
        general = crtsh.ClienteCrtsh(transporte=CrtshSimulado()).timeout
        busquedas = crtsh.PLAZO_PRINCIPAL
        pagina = (certspotter.COMPLEMENTO['intentos'] * certspotter.COMPLEMENTO['timeout']
                  + sum(crtsh.ESPERAS[:certspotter.COMPLEMENTO['intentos'] - 1]))
        marca = crtsh.INTENTOS_PARECIDOS * general + sum(crtsh.ESPERAS[:crtsh.INTENTOS_PARECIDOS - 1])
        peor = busquedas + certspotter.MAX_PAGINAS * pagina + marca + crtsh.PRESUPUESTO_VARIANTES
        self.assertEqual((busquedas, pagina, marca, crtsh.PRESUPUESTO_VARIANTES, peor), (120, 45, 95, 470, 865))
        raiz = Path(crtsh.__file__).resolve().parents[2]
        orquestador = (raiz / 'cirdan' / 'orquestador' / '__init__.py').read_text(encoding='utf-8')
        tope = int(re.search(r'^TOPE_CORRIDA = timedelta\(minutes=(\d+)\)', orquestador, re.M).group(1)) * 60
        self.assertLess(peor, tope)
        self.assertLessEqual(peor + crtsh.PLAZO_DNS, tope)   # el DNS de los vencidos también cabe (RC-288)
        self.assertIn('PLAZO_DNS (%d s de crtsh.py' % crtsh.PLAZO_DNS, orquestador)
        self.assertIn('%d s en el peor' % peor, orquestador)
        self.assertIn('Quedan %d s antes de TOPE_CORRIDA' % (tope - peor), orquestador)
        doc = (raiz / 'docs' / 'contrato_plugin.md').read_text(encoding='utf-8')
        self.assertIn('espera %d segundos y el segundo hasta %d segundos (`TIMEOUTS_VARIANTE`)' % crtsh.TIMEOUTS_VARIANTE, doc)
        self.assertIn('con %d s en el primer intento y hasta %d s en el segundo, o %d s desde el primero'
                      % (crtsh.TIMEOUTS_VARIANTE + crtsh.TIMEOUTS_VARIANTE[1:]), orquestador)
        self.assertIn('tarda más de %d segundos, las siguientes esperan %d segundos desde el primer intento'
                      % crtsh.TIMEOUTS_VARIANTE, doc)
        self.assertIn('vuelven a %d segundos por el resto de la corrida' % crtsh.TIMEOUTS_VARIANTE[0], doc)
        self.assertEqual(crtsh._timeouts_variante(crtsh.LENTO),
                         (crtsh.TIMEOUTS_VARIANTE[1],) * crtsh.INTENTOS_PARECIDOS)
        self.assertIn('tienen %d segundos (`PRESUPUESTO_VARIANTES`)' % crtsh.PRESUPUESTO_VARIANTES, doc)
        self.assertIn('queda en %d segundos' % peor, doc)

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
        de_parecidos = [p for p in res.revisados if '@' not in p and not p.startswith(crtsh.EMISOR)]
        # llegaron todos los certificados: también se revisaron sus emisores para cert_new_issuer (RC-218)
        self.assertEqual([p for p in res.revisados if p.startswith(crtsh.EMISOR)], ["emisor:let's encrypt"])
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
        def reloj():
            return inicio + crtsh.timedelta(minutes=1)

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


class QCaido(CrtshSimulado):
    """crt.sh como desde vm-lowtide el 17 nov (RC-337): q= de las variantes de `caidas` da `codigo` y lo demás
    responde."""

    def __init__(self, caidas=('acme-dem0.mx',), codigo=404, **kw):
        kw.setdefault('san', {'acme-dem0.mx': CANDIDATO, '%.acme-dem0.mx': CANDIDATO})  # el mismo id en las dos
        super().__init__(**kw)
        self.caidas, self.codigo = set(caidas), codigo

    def __call__(self, url, timeout):
        q = crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(url).query).get('q', [''])[0]
        if q in self.caidas:
            self.urls.append(url)
            raise urllib.error.HTTPError(url, self.codigo, 'Not Found', None, None)
        return super().__call__(url, timeout)


def sin_red(url, timeout):
    raise AssertionError('consultó la red: %s' % url)


def huellas(res):
    return sorted(h.huella for h in res.hallazgos)


class RespaldoDeVariantes(unittest.TestCase):
    """RC-337: si q= de una variante no responde, al final se piden dNSName=X y dNSName=%.X."""

    def test_1_q_caido_y_dnsname_responde_deja_la_corrida_completa(self):
        sano = recolectar(CrtshSimulado(), parecidos=True)
        t = QCaido()
        res = recolectar(t, parecidos=True)
        self.assertEqual(huellas(res), huellas(sano))
        self.assertIn('acme-dem0.mx', {h.evidencia.get('dominio_parecido') for h in res.hallazgos})
        self.assertIsNone(res.revisados)  # nada quedó sin revisar: el escaneo no termina 'partial'
        self.assertEqual((res.omitidos, res.sin_cobertura, res.avisos), ([], [], []))
        self.assertEqual(crtsh.codigo_salida(res), 0)
        self.assertEqual([u for u in t.urls if 'dNSName' in u], [
            'https://crt.sh/?dNSName=acme-dem0.mx&output=json', 'https://crt.sh/?dNSName=%25.acme-dem0.mx&output=json'])
        self.assertEqual(res.consultas, len(t.urls) + len(t.cert_spotter))  # un 404 de q= es 1 intento y el respaldo 2
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])
        self.assertEqual(crtsh.MAX_CONSULTAS, 36)  # el respaldo cabe en el cupo de antes: la semilla 014 no cambia

    def test_2_si_el_respaldo_tampoco_responde_sigue_parcial(self):
        class SinSubdominios(QCaido):  # dNSName=X responde y dNSName=%.X no: tampoco basta
            def __call__(self, url, timeout):
                if 'dNSName=%25.' in url:
                    self.urls.append(url)
                    raise TimeoutError('timed out')
                return super().__call__(url, timeout)

        for t in (QCaido(codigo=502, san=None), SinSubdominios(codigo=502)):
            with self.subTest(t=type(t).__name__):
                res = recolectar(t, parecidos=True)
                self.assertIsNotNone(res.revisados)  # el escaneo termina 'partial', como antes del respaldo
                self.assertIn(crtsh._huella('lookalike_domain', 'acme-demo.mx', 'acme-dem0.mx'), res.omitidos)
                self.assertNotIn('acme-dem0.mx', {h.evidencia.get('dominio_parecido') for h in res.hallazgos})
                [aviso] = [a for a in res.avisos if 'acme-dem0.mx' in a]
                self.assertIn('no respondió a acme-dem0.mx después de 2 intentos', aviso)
                self.assertIn('Tampoco respondió su respaldo: crt.sh no respondió a dNSName=', aviso)
                self.assertEqual(crtsh.codigo_salida(res), 2)

    def test_3_una_fila_sin_fechas_en_el_respaldo_no_da_cero_parecidos(self):
        bien = {'id': 30, 'name_value': 'acme-dem0.mx', 'not_before': '2026-10-01T00:00:00',
                'not_after': '2026-12-30T00:00:00'}
        malas = [{'id': 30, 'name_value': 'acme-dem0.mx'},  # sin las llaves de las fechas
                 dict(bien, not_before=None), dict(bien, not_after=''), dict(bien, not_before='1 oct 2026'),
                 dict(bien, name_value=None), dict(bien, name_value=' ')]
        for fila in malas:
            with self.subTest(fila=fila):
                t = QCaido(san={'acme-dem0.mx': [fila], '%.acme-dem0.mx': []})
                res = recolectar(t, parecidos=True)
                self.assertIsNotNone(res.revisados)
                self.assertIn(crtsh._huella('lookalike_domain', 'acme-demo.mx', 'acme-dem0.mx'), res.omitidos)
                self.assertIn('respuesta que no se puede leer', ' '.join(res.avisos))
                self.assertEqual(len([u for u in t.urls if 'dNSName' in u]), 1)  # no se reintenta ni pide la segunda
        res = recolectar(QCaido(san={'acme-dem0.mx': [bien], '%.acme-dem0.mx': []}), parecidos=True)
        self.assertEqual((res.revisados, res.omitidos), (None, []))  # la misma fila con todo bien sí cuenta

    def test_4_con_crtsh_saturado_no_se_pide_el_respaldo(self):
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        t = QCaido(caidas=variantes[:crtsh.FALLAS_SEGUIDAS], codigo=502)
        res = recolectar(t, parecidos=True)
        self.assertFalse([u for u in t.urls if 'dNSName' in u])
        self.assertIn('crt.sh saturado', res.avisos[-1])  # después de los avisos de cada variante, como antes
        self.assertIsNotNone(res.revisados)

    def test_5_el_respaldo_no_pasa_del_tope_de_consultas_de_parecidos(self):
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        caidas = variantes[::2]  # una sí y una no: nunca 3 seguidas, así que no hay saturación
        t = QCaido(caidas=caidas, codigo=502, san={})

        def de_parecidos(url):
            parametros = crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(url).query)
            return 'dNSName' in parametros or parametros['q'][0] in variantes + ['%acme-demo%']
        res = recolectar(t, parecidos=True)
        # 9 variantes (sin acme-demo.com.mx, que es propio). %marca% 1, 4 sanas 4 y 5 caídas con 2 intentos 10: de las
        # 22 quedan 7, para 3 respaldos de 2 consultas. Un 4.º llegaría a 23
        self.assertEqual((len(variantes), len(caidas)), (9, 5))
        self.assertEqual(len([u for u in t.urls if 'dNSName' in u]), 2 * 3)
        self.assertEqual(len([u for u in t.urls if de_parecidos(u)]), 1 + 4 + 10 + 6)
        self.assertLess(crtsh.TOPE_PARECIDOS - (1 + 4 + 10 + 6), 2 * crtsh.INTENTOS_RESPALDO)
        self.assertLessEqual(res.consultas, crtsh.MAX_CONSULTAS)
        self.assertEqual(sorted(res.omitidos), sorted(crtsh._huella('lookalike_domain', 'acme-demo.mx', v)
                                                      for v in caidas[3:]))
        sin_respaldo = [a for a in res.avisos if 'después de 2 intentos' in a and 'respaldo' not in a]
        self.assertEqual(len(sin_respaldo), len(caidas) - 3)

    def test_5b_el_respaldo_que_llega_justo_al_tope_si_se_pide(self):
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        caidas = variantes[1::2]  # 4 caídas alternadas: %marca% 1, 5 sanas 5 y 4 caídas con 2 intentos 8, 14
        t = QCaido(caidas=caidas, codigo=502, san={})
        res = recolectar(t, parecidos=True)
        # los respaldos empiezan en 14, 16, 18 y 20: el 4.º deja la cuenta justo en TOPE_PARECIDOS y sí se pide
        self.assertEqual(1 + (len(variantes) - len(caidas)) + 2 * len(caidas) + 2 * 3, crtsh.TOPE_PARECIDOS - 2)
        self.assertEqual(len([u for u in t.urls if 'dNSName' in u]), 2 * len(caidas))
        self.assertEqual((res.revisados, res.omitidos, res.avisos), (None, [], []))

    def test_6_grabar_y_reproducir_repiten_el_respaldo_sin_red(self):
        sano = recolectar(CrtshSimulado(), parecidos=True)
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=QCaido(), dormir=lambda s: None)
            res = crtsh.recolectar('acme-demo.mx', grab, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
            self.assertEqual(huellas(res), huellas(sano))
            nombres = {f.name for f in Path(d).iterdir()}
            self.assertTrue({'san_acme-dem0.mx.json', 'san_subdominios_acme-dem0.mx.json'} <= nombres, nombres)
            self.assertNotIn('acme-dem0.mx.json', nombres)

            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d, transporte=sin_red, dormir=lambda s: None)
            res = crtsh.recolectar('acme-demo.mx', rep, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
        self.assertEqual(huellas(res), huellas(sano))
        self.assertEqual((res.revisados, res.omitidos, res.avisos), (None, [], []))

    def test_7_reproducir_sin_q_ni_respaldo_grabados_deja_el_aviso_de_siempre(self):
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=QCaido(san=None), dormir=lambda s: None)
            crtsh.recolectar('acme-demo.mx', grab, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
            self.assertFalse([f.name for f in Path(d).iterdir() if f.name.startswith('san_')])
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d, transporte=sin_red, dormir=lambda s: None)
            res = crtsh.recolectar('acme-demo.mx', rep, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
        self.assertEqual([a for a in res.avisos if 'acme-dem0.mx' in a], [contrato.SIN_GRABACION + 'acme-dem0.mx'])
        self.assertIn('Falta 1 respuesta grabada: acme-dem0.mx.', '\n'.join(crtsh.resumen(res)))

    def test_8_tres_fallas_seguidas_al_final_tambien_son_saturacion(self):
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        caidas = variantes[-crtsh.FALLAS_SEGUIDAS:]
        t = QCaido(caidas=caidas, codigo=502, san={})
        res = recolectar(t, parecidos=True)
        self.assertFalse([u for u in t.urls if 'dNSName' in u])  # el bucle terminó con crt.sh ya saturado
        self.assertEqual(sorted(res.omitidos), sorted(crtsh._huella('lookalike_domain', 'acme-demo.mx', v)
                                                      for v in caidas))
        self.assertFalse([a for a in res.avisos if 'respaldo' in a])

    def test_9_si_un_respaldo_no_responde_no_se_piden_los_demas(self):
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        caidas = variantes[::2]  # nunca 3 seguidas: sin el corte se pedirían 3 respaldos (test_5)
        t = QCaido(caidas=caidas, codigo=502, san=None)
        res = recolectar(t, parecidos=True)
        self.assertEqual([u for u in t.urls if 'dNSName' in u],
                         ['https://crt.sh/?dNSName=%s&output=json' % caidas[0]])  # dNSName=X falló: ni %.X
        self.assertEqual(len([a for a in res.avisos if 'Tampoco respondió su respaldo' in a]), 1)
        self.assertEqual(sorted(res.omitidos), sorted(crtsh._huella('lookalike_domain', 'acme-demo.mx', v)
                                                      for v in caidas))

    def test_10_sin_tiempo_o_con_el_archivo_danado_el_aviso_no_culpa_a_crtsh(self):
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        caidas = variantes[:2]
        casos = [(crtsh.SinTiempo('no quedó tiempo para consultar dNSName=x'), False, True),
                 (crtsh.GrabacionDanada('san_x.json'), False, True),
                 (crtsh.SinTiempo('crt.sh no respondió a dNSName=x después de 1 intento', 1), True, False)]
        for error, culpa, sigue in casos:
            with self.subTest(error=str(error)):
                cliente = crtsh.ClienteCrtsh(transporte=QCaido(caidas=caidas, codigo=502, san={}),
                                             dormir=lambda s: None)
                original = cliente.consultar_san

                def respaldo(nombre, error=error, original=original, **kw):
                    if nombre == caidas[0]:
                        raise error
                    return original(nombre, **kw)
                with mock.patch.object(cliente, 'consultar_san', side_effect=respaldo):
                    res = crtsh.recolectar('acme-demo.mx', cliente, AHORA, propios=['acme-demo.com.mx'],
                                           parecidos=True)
                [aviso] = [a for a in res.avisos if caidas[0] in a]
                self.assertTrue(aviso.startswith('crt.sh no respondió a %s después de 2 intentos' % caidas[0]))
                self.assertEqual('Tampoco respondió su respaldo' in aviso, culpa)
                # ni el tiempo ni el disco dicen que crt.sh esté caído: el respaldo de la 2.ª se pide igual
                self.assertEqual(crtsh._huella('lookalike_domain', 'acme-demo.mx', caidas[1]) not in res.omitidos,
                                 sigue)

    def test_11_completar_lee_el_respaldo_grabado_aunque_crtsh_quede_saturado(self):
        variantes = [v for v in crtsh.candidatos_parecidos('acme-demo.mx') if v != 'acme-demo.com.mx']
        x, *otras = variantes[-crtsh.FALLAS_SEGUIDAS:]
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=QCaido(caidas=[x], san={}),
                                      dormir=lambda s: None, nueva=True)
            crtsh.recolectar('acme-demo.mx', grab, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
            self.assertTrue((Path(d) / ('san_%s.json' % x)).exists())
            for v in otras:  # una grabación que se cortó antes de estas dos
                (Path(d) / ('%s.json' % v)).unlink()
            t = QCaido(caidas=[x] + otras, codigo=502, san=None)
            comp = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=t, dormir=lambda s: None, completar=True,
                                      desde=contrato.Grabadora.inicio(d))
            completada = crtsh.recolectar('acme-demo.mx', comp, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
            self.assertFalse([u for u in t.urls if 'dNSName' in u])  # el de x salió del disco y crt.sh quedó saturado
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d, transporte=sin_red, dormir=lambda s: None)
            reproducida = crtsh.recolectar('acme-demo.mx', rep, AHORA, propios=['acme-demo.com.mx'], parecidos=True)
        omitidos = sorted(crtsh._huella('lookalike_domain', 'acme-demo.mx', v) for v in otras)
        self.assertEqual((sorted(completada.omitidos), sorted(reproducida.omitidos)), (omitidos, omitidos))
        self.assertEqual(huellas(completada), huellas(reproducida))


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


class TopeDeBytes(unittest.TestCase):
    """RC-288: crt.sh baja con transporte.descargar() y a lo más TOPE_BYTES. Sin red: transporte.abrir, la conexión, se
    cambia por un servidor simulado que manda 60 MiB a %.acme-demo.mx. Se deja de leer al pasar el tope, no se
    reintenta, el aviso dice el tope y entra la búsqueda por nombre."""

    class Respuesta:
        def __init__(self, cuerpo=None, total=0):
            self.cuerpo, self.total, self.leidos = cuerpo, total, 0

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read1(self, n):
            if self.cuerpo is not None:
                parte, self.cuerpo = self.cuerpo[:n], self.cuerpo[n:]
            else:
                parte = b' ' * min(n, self.total - self.leidos)
            self.leidos += len(parte)
            return parte

    def test_1_mas_del_tope_se_corta_sin_leer_todo_y_sin_reintentar(self):
        pedidas = []

        def abrir(req, plazo, cronometro):
            q = crtsh.urllib.parse.parse_qs(crtsh.urllib.parse.urlparse(req.full_url).query).get('q', [''])[0]
            if req.host == 'crt.sh' and q == '%.acme-demo.mx':
                r = self.Respuesta(total=60 * 1024 * 1024)
            else:
                r = self.Respuesta(cuerpo=json.dumps(SUBDOMINIOS if q == 'acme-demo.mx' else []).encode())
            pedidas.append((req.host, q, r))
            return r
        with mock.patch.object(crtsh.transporte, 'abrir', abrir):
            cliente = crtsh.ClienteCrtsh(dormir=lambda s: None, resolver=lambda n: True)
            res = crtsh.recolectar('acme-demo.mx', cliente, AHORA, parecidos=False)
        grandes = [r for h, q, r in pedidas if q == '%.acme-demo.mx']
        self.assertEqual(len(grandes), 1)   # un solo intento
        self.assertEqual(grandes[0].leidos, crtsh.TOPE_BYTES + 1)   # no lee los 60 MiB
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.avisos[0], crtsh.POR_NOMBRE_GRANDE % ('acme-demo.mx', crtsh.TOPE_BYTES))
        self.assertIn('52428800 bytes', res.avisos[0])
        self.assertIn(('cert_expired', 'dev.acme-demo.mx'), {(h.codigo, h.activo) for h in res.hallazgos})
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])

    @unittest.skipUnless(os.environ.get('TRANSPORTE_TLS') == '1' or importlib.util.find_spec('cryptography'),
                         'pide cryptography para el certificado: corre dentro del contenedor')
    def test_2_un_servidor_tls_local_que_manda_mas_del_tope_se_corta(self):
        """El servidor local que pide el Hecho cuando: TLS de verdad sobre socket.socketpair() (sin red), con el
        certificado y el extremo de test_rdap. Con TOPE_BYTES en 256 KiB el servidor intenta mandar 16 MiB sin
        Content-Length: _descargar corta con RespuestaGrande y el servidor no alcanza a mandarlo todo."""
        import socket
        import ssl
        import threading
        from pruebas.test_rdap import Extremo, certificado
        carpeta = tempfile.TemporaryDirectory()
        self.addCleanup(carpeta.cleanup)
        ruta_cert, ruta_llave = certificado(carpeta.name, 'crt.sh')
        servidor_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        servidor_ctx.load_cert_chain(ruta_cert, ruta_llave)
        cliente_ctx = ssl.create_default_context(cafile=ruta_cert)   # como transporte._contexto, con esta CA
        cliente_ctx.sslsocket_class = crtsh.transporte._SocketTls
        total, tope, enviados, pedidos = 16 * 1024 * 1024, 256 * 1024, [], []
        a, b = socket.socketpair()
        extremo = Extremo(fileno=a.detach())

        def atender():
            b.settimeout(10)
            try:
                with servidor_ctx.wrap_socket(b, server_side=True) as tls:
                    pedido = b''
                    while b'\r\n\r\n' not in pedido:
                        parte = tls.recv(4096)
                        if not parte:
                            return
                        pedido += parte
                    pedidos.append(pedido)
                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n')
                    bloque = b' ' * 65536
                    for _ in range(total // len(bloque)):
                        tls.sendall(bloque)
                        enviados.append(len(bloque))
            except OSError:
                pass
            finally:
                b.close()
        hilo = threading.Thread(target=atender, daemon=True)
        hilo.start()

        def conectar(conexion, direccion, *_):
            self.assertEqual(direccion, ('crt.sh', 443))
            extremo.settimeout(conexion.queda())   # como _conectar antes del handshake
            return extremo
        try:
            with mock.patch.object(crtsh, 'TOPE_BYTES', tope), \
                    mock.patch.object(crtsh.transporte, '_contexto', lambda: cliente_ctx), \
                    mock.patch.object(crtsh.transporte._Conexion, '_conectar', conectar), \
                    self.assertRaises(crtsh.RespuestaGrande):
                crtsh._descargar('https://crt.sh/?q=%25.acme-demo.mx&output=json', 10)
        finally:
            extremo.close()
            hilo.join(15)
        self.assertFalse(hilo.is_alive())
        [pedido] = pedidos
        self.assertTrue(pedido.startswith(b'GET /?q=%25.acme-demo.mx&output=json HTTP/1.1\r\n'), pedido)
        self.assertLess(sum(enviados), total // 2)   # dejó de leer: el servidor no alcanzó a mandar los 16 MiB


class TopeDelDns(unittest.TestCase):
    """RC-288, comentario 10394: toda la corrida de DNS cabe en PLAZO_DNS. Con un resolvedor lento (cada pregunta se
    come COSTO_DNS segundos de un reloj falso) la corrida no se estira: lo que ya no cabe no se pregunta y queda como
    'no se pudo saber', nunca como hallazgo, con su huella en omitidos."""

    def correr(self, n, respuesta):
        reloj, preguntas = {'t': 0.0}, []

        def resolver(nombre):
            preguntas.append((nombre, reloj['t']))
            reloj['t'] += crtsh.COSTO_DNS
            return respuesta
        vencidos = [cert(500 + i, ['v%02d.acme-demo.mx' % i], iso(-90), iso(-10)) for i in range(n)]
        cliente = crtsh.ClienteCrtsh(transporte=CrtshSimulado(respuestas={'%.acme-demo.mx': vencidos}),
                                     dormir=lambda s: None, resolver=resolver, cronometro=lambda: reloj['t'])
        res = crtsh.recolectar('acme-demo.mx', cliente, AHORA, parecidos=False)
        return res, preguntas, reloj['t']

    def test_1_un_resolvedor_que_no_responde_no_pasa_del_tope_ni_da_hallazgos(self):
        res, preguntas, fin = self.correr(40, None)
        cabe = int(crtsh.PLAZO_DNS // crtsh.COSTO_DNS)
        self.assertLessEqual(fin, crtsh.PLAZO_DNS)
        self.assertEqual(len(preguntas), cabe)
        self.assertNotIn('cert_expired', {h.codigo for h in res.hallazgos})
        self.assertEqual(len(res.omitidos), 40)
        preguntados = [n for n, _ in preguntas]
        cortados = ['v%02d.acme-demo.mx' % i for i in range(40) if 'v%02d.acme-demo.mx' % i not in preguntados]
        self.assertEqual(len(cortados), 40 - cabe)
        self.assertEqual([a for a in res.avisos if a.startswith('No se pudo comprobar')],
                         [crtsh.SIN_DNS % crtsh._lista(preguntados)])   # uno solo, con a lo más 10 nombres
        self.assertTrue(crtsh._lista(preguntados).endswith(' y %d más' % (cabe - crtsh.MAX_NOMBRES_AVISO)))
        self.assertIn(crtsh.DNS_SIN_TIEMPO % (crtsh.PLAZO_DNS, crtsh._lista(cortados)), res.avisos)
        self.assertIsNotNone(res.revisados)   # la corrida queda parcial
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])

    def test_2_lo_que_si_respondio_dentro_del_tope_se_reporta(self):
        res, preguntas, fin = self.correr(40, True)
        cabe = int(crtsh.PLAZO_DNS // crtsh.COSTO_DNS)
        self.assertLessEqual(fin, crtsh.PLAZO_DNS)
        self.assertEqual(len([h for h in res.hallazgos if h.codigo == 'cert_expired']), cabe)
        self.assertEqual(len(res.omitidos), 40 - cabe)
        self.assertFalse([a for a in res.avisos if a.startswith('No se pudo comprobar')])
        self.assertEqual(len([a for a in res.avisos if a.startswith('El DNS de los nombres vencidos')]), 1)
        self.assertIsNotNone(res.revisados)
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])

    def test_3_un_no_existe_sin_tiempo_para_el_control_no_se_cree(self):
        """El último nombre que cabe dice que no existe, pero ya no queda tiempo para preguntar por el dominio: no se
        graba como False y su vencido va en omitidos."""
        reloj, preguntas = {'t': 0.0}, []

        def resolver(nombre):
            preguntas.append(nombre)
            reloj['t'] += crtsh.COSTO_DNS
            return False
        cliente = crtsh.ClienteCrtsh(transporte=CrtshSimulado(), dormir=lambda s: None, resolver=resolver,
                                     cronometro=lambda: reloj['t'])
        cliente._fin_dns = crtsh.COSTO_DNS   # solo cabe una pregunta
        self.assertIsNone(cliente.resuelve('dev.acme-demo.mx', control='acme-demo.mx'))
        self.assertEqual((preguntas, cliente.dns_sin_tiempo, cliente.dns_sin_respuesta),
                         (['dev.acme-demo.mx'], ['dev.acme-demo.mx'], []))
        self.assertNotIn('acme-demo.mx', cliente._dns_funciona)   # sin tiempo no dice nada del DNS

    def test_4_un_dominio_sin_a_en_la_raiz_si_cuenta_como_dns_que_responde(self):
        """Con el resolvedor de omisión el control pregunta si el dominio existe: con solo MX o TXT en la raíz (A vacía)
        el NXDOMAIN de un nombre se cree. Un NXDOMAIN del propio dominio no: ese resolvedor miente."""
        for raiz, esperado in ((('vacio', []), False), (('ok', ['198.51.100.1']), False), (('nxdomain', []), None)):
            pedidos = []

            def consultar(nombre, tipo, raiz=raiz, pedidos=pedidos):
                pedidos.append((nombre, tipo))
                return raiz if nombre == 'acme-demo.mx' else ('nxdomain', [])
            with self.subTest(raiz=raiz), mock.patch.object(crtsh.registros_dns, '_consultar', consultar), \
                    mock.patch('socket.getaddrinfo', side_effect=AssertionError('DNS del sistema')):
                cliente = crtsh.ClienteCrtsh(dormir=lambda s: None)
                self.assertIs(cliente.resolver, crtsh._resolver_dns)
                self.assertIs(cliente.resuelve('dev.acme-demo.mx', control='acme-demo.mx'), esperado)
                self.assertEqual(pedidos, [('dev.acme-demo.mx', 'A'), ('acme-demo.mx', 'A')])
                self.assertEqual(cliente.dns_sin_respuesta, [] if esperado is False else ['dev.acme-demo.mx'])

    def test_5_un_control_sin_respuesta_no_se_guarda_para_toda_la_corrida(self):
        """Un tiempo agotado pasajero en el control deja ese nombre como 'no se pudo saber', pero el siguiente
        NXDOMAIN vuelve a preguntar por el dominio y, si responde, sí se cree."""
        respuestas = {'a.acme-demo.mx': [False], 'b.acme-demo.mx': [False], 'acme-demo.mx': [None, True]}
        preguntas = []

        def resolver(nombre):
            preguntas.append(nombre)
            return respuestas[nombre].pop(0)
        cliente = crtsh.ClienteCrtsh(transporte=CrtshSimulado(), dormir=lambda s: None, resolver=resolver)
        self.assertIsNone(cliente.resuelve('a.acme-demo.mx', control='acme-demo.mx'))
        self.assertIs(cliente.resuelve('b.acme-demo.mx', control='acme-demo.mx'), False)
        self.assertEqual(preguntas, ['a.acme-demo.mx', 'acme-demo.mx', 'b.acme-demo.mx', 'acme-demo.mx'])
        self.assertEqual((cliente.dns_sin_respuesta, cliente._dns_funciona),
                         (['a.acme-demo.mx'], {'acme-demo.mx': True}))

    def test_6_sin_dnspython_el_aviso_lo_dice(self):
        cliente = crtsh.ClienteCrtsh(transporte=CrtshSimulado(), dormir=lambda s: None, resolver=crtsh._resolver_dns)
        with mock.patch.object(crtsh.registros_dns, '_consultar', side_effect=ImportError('sin dnspython')), \
                mock.patch.object(crtsh, '_hay_dnspython', return_value=False):
            res = crtsh.recolectar('acme-demo.mx', cliente, AHORA, parecidos=False)
        [aviso] = [a for a in res.avisos if 'dnspython' in a]
        self.assertEqual(aviso, crtsh.SIN_DNSPYTHON % crtsh._lista(cliente.dns_sin_respuesta))
        self.assertIn('dev.acme-demo.mx', aviso)
        self.assertFalse([a for a in res.avisos if a.startswith('No se pudo comprobar')])
        self.assertNotIn('cert_expired', {h.codigo for h in res.hallazgos})
        self.assertIsNotNone(res.revisados)
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])



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

    def test_6_si_el_dns_no_responde_no_reporta_el_vencido_ni_lo_cierra(self):
        """RC-288, comentario 10394: no se sabe si resuelve. Ni hallazgo ni cierre: la huella del vencido va en
        omitidos, la misma que tendría el hallazgo, así el orquestador deja abierto el de un escaneo anterior."""
        si = crtsh.ClienteCrtsh(transporte=CrtshSimulado(), dormir=lambda s: None, resolver=lambda n: True)
        esperadas = [h.huella for h in crtsh.recolectar('acme-demo.mx', si, AHORA, parecidos=False).hallazgos
                     if h.codigo == 'cert_expired']
        cliente = crtsh.ClienteCrtsh(transporte=CrtshSimulado(), dormir=lambda s: None, resolver=lambda n: None)
        res = crtsh.recolectar('acme-demo.mx', cliente, AHORA, parecidos=False)
        self.assertNotIn('cert_expired', {h.codigo for h in res.hallazgos})
        self.assertTrue(esperadas)
        self.assertEqual(res.omitidos, esperadas)
        self.assertIn(crtsh.SIN_DNS % 'dev.acme-demo.mx', res.avisos)
        self.assertIsNotNone(res.revisados)   # parcial: el escaneo no termina completo con 0 vencidos
        self.assertFalse([a for a in res.avisos if 'Se reporta su certificado vencido' in a])
        self.assertNotIn('resuelve', {a.valor: a for a in res.activos}['dev.acme-demo.mx'].atributos)
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])

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

    def test_10_sin_servidor_dns_no_se_descarta_ni_se_graba_ni_se_reporta(self):
        """El control tampoco resuelve: un «no existe» no se cree (no se graba ni queda resuelve False) y, como no se
        sabe, el vencido tampoco se reporta (RC-288): va en omitidos, con aviso."""
        todos = {'acme-demo.mx', 'www.acme-demo.mx', 'api.acme-demo.mx', 'dev.acme-demo.mx', 'tienda.acme-demo.mx'}
        with tempfile.TemporaryDirectory() as d:
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=CrtshSimulado(sin_dns=todos),
                                      dormir=lambda s: None, nueva=True)
            res = crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False)
            self.assertEqual(sorted(p.name for p in Path(d).glob('dns_*.json')), [])
        self.assertNotIn('cert_expired', {h.codigo for h in res.hallazgos})
        self.assertIn(crtsh.SIN_DNS % 'dev.acme-demo.mx', res.avisos)
        self.assertTrue(res.omitidos)
        self.assertNotIn('resuelve', {a.valor: a for a in res.activos}['dev.acme-demo.mx'].atributos)

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

    def test_7_el_resolvedor_pregunta_a_los_publicos_con_plazo_y_nunca_al_del_sistema(self):
        """RC-288: A y, si no la tiene, AAAA a registros_dns.RESOLVEDORES (_consultar, con TIMEOUT_S cada una). Nunca
        getaddrinfo, que pregunta al DNS del sistema y no tiene plazo."""
        falla = crtsh.registros_dns.ConsultaFallida('LifetimeTimeout: 5 s')
        casos = [({'A': ('ok', ['198.51.100.10'])}, True, ['A']),
                 ({'A': ('nxdomain', [])}, False, ['A']),
                 ({'A': ('vacio', []), 'AAAA': ('ok', ['2001:db8::10'])}, True, ['A', 'AAAA']),
                 ({'A': ('vacio', []), 'AAAA': ('vacio', [])}, False, ['A', 'AAAA']),
                 ({'A': falla}, None, ['A']),
                 ({'A': ('vacio', []), 'AAAA': falla}, None, ['A', 'AAAA'])]
        for respuestas, esperado, tipos in casos:
            pedidos = []

            def consultar(nombre, tipo, respuestas=respuestas, pedidos=pedidos):
                pedidos.append((nombre, tipo))
                if isinstance(respuestas[tipo], Exception):
                    raise respuestas[tipo]
                return respuestas[tipo]
            with mock.patch.object(crtsh.registros_dns, '_consultar', consultar), \
                    mock.patch('socket.getaddrinfo', side_effect=AssertionError('DNS del sistema')):
                self.assertIs(crtsh._resolver_dns('www.acme-demo.mx'), esperado, respuestas)
            self.assertEqual(pedidos, [('www.acme-demo.mx', t) for t in tipos])
        with mock.patch.object(crtsh.registros_dns, '_consultar', side_effect=ImportError('sin dnspython')):
            self.assertIsNone(crtsh._resolver_dns('www.acme-demo.mx'))   # no se sabe, no truena
        self.assertEqual(crtsh.registros_dns.RESOLVEDORES, ('1.1.1.1', '8.8.8.8'))
        self.assertEqual(crtsh.COSTO_DNS, 2 * crtsh.registros_dns.TIMEOUT_S)
        self.assertIs(crtsh.ClienteCrtsh().resolver, crtsh._resolver_dns)   # el de omisión


class Resumen(unittest.TestCase):
    """Lo que se lee en la terminal durante una demo."""

    def test_1_severidad_y_caracteristicas_en_espanol(self):
        res = recolectar(CrtshSimulado(), parecidos=False)
        lineas = crtsh.resumen(res)
        self.assertEqual(lineas[0], 'acme-demo.mx · crt.sh y Cert Spotter · succeeded · 2 consultas')
        self.assertIn('  [media] El certificado de api.acme-demo.mx vence en 10 días', lineas)
        self.assertIn('  [alta] Certificado vencido en dev.acme-demo.mx', lineas)
        self.assertIn('      tipo: certificado por vencer · antigüedad: 80 días · exposición: pública'
                      ' · sensibilidad: media', lineas)
        self.assertIn('6 activos, con su vencimiento en UTC:', lineas)
        # Una fecha con otro desfase se pasa a UTC antes de imprimirla: el 31 dic a la 01:00 en UTC+2 es el 30 dic.
        self.assertEqual(crtsh._dia(crtsh._fecha('2026-12-31T01:00:00+02:00')), '30 dic 2026')
        self.assertIn('  api.acme-demo.mx · vence 25 oct 2026', lineas)
        self.assertIn('  tienda.acme-demo.mx · vence 30 nov 2026 · comodín', lineas)
        self.assertFalse([linea for linea in lineas if '[medium]' in linea or '[high]' in linea])
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
        faltan = [linea for linea in lineas if linea.startswith('Faltan ')]
        self.assertEqual(len(faltan), 1)
        self.assertIn('%acme-demo%', faltan[0])
        self.assertTrue(faltan[0].endswith('Se completan con --grabar --completar.'))
        self.assertFalse([linea for linea in lineas if 'saturado' in linea or linea.startswith('aviso:')])

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


LE = "C=US, O=Let's Encrypt, CN=R11"
GS = 'C=BE, O=GlobalSign nv-sa, CN=GlobalSign GCC R3 DV TLS CA 2020'
SECTIGO = 'C=GB, ST=Greater Manchester, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA'


def higiene(certs, dominio='acme-demo.mx'):
    """Los hallazgos de _higiene por (código, activo), con los certificados como los deja recolectar()."""
    return {(h.codigo, h.activo): h for h in crtsh._higiene(dominio, crtsh._con_fechas(certs), AHORA)}


def emision_cs(id_, nombres, inicio, fin, emisor=LE, revocado=False):
    """Una emisión de Cert Spotter (/v1/issuances con expand=dns_names y expand=issuer)."""
    return {'id': id_, 'cert_sha256': ('%064x' % int(id_)), 'dns_names': nombres, 'not_before': inicio,
            'not_after': fin, 'issuer': {'name': emisor, 'friendly_name': emisor}, 'revoked': revocado}


class HigieneCertificados(unittest.TestCase):
    """RC-218: cert_internal_name, cert_broad_wildcard y cert_new_issuer salen de los mismos certificados de CT."""

    def test_1_nombre_interno_cuenta_y_uno_parecido_no(self):
        hs = higiene([
            cert(1, ['dev-api.acme-demo.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
            cert(2, ['developer.acme-demo.mx', 'dev2.acme-demo.mx', 'devops-x.acme-demo.mx'],
                 '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
            cert(3, ['jenkins.ci.acme-demo.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
            cert(4, ['vpn.otra.com', 'dev.acme-demo.mx.otra.com'], '2026-09-01T00:00:00', '2026-11-30T00:00:00'),
        ])
        internos = {a: h for (c, a), h in hs.items() if c == 'cert_internal_name'}
        self.assertEqual(sorted(internos), ['dev-api.acme-demo.mx', 'jenkins.ci.acme-demo.mx'])
        h = internos['dev-api.acme-demo.mx']
        self.assertEqual((h.severidad, h.evidencia['etiqueta'], h.evidencia['host']),
                         ('low', 'dev', 'dev-api.acme-demo.mx'))
        self.assertEqual(internos['jenkins.ci.acme-demo.mx'].evidencia['etiqueta'], 'jenkins')
        # evidencia: host, emisor, vigencia, id del certificado y etiqueta (Hecho cuando 2), sin nada de más
        self.assertEqual(h.evidencia, {
            'title': h.titulo, 'host': 'dev-api.acme-demo.mx', 'etiqueta': 'dev', 'lista_version': 1, 'emisor': LE,
            'emitido': '2026-09-01T00:00:00+00:00', 'vence': '2026-11-30T00:00:00+00:00', 'origen': 'crtsh',
            'crtsh_id': 1, 'serie': '%040x' % 1, 'certificados': 1, 'primera_vez': '2026-09-01T00:00:00+00:00'})
        self.assertEqual(h.partes, [crtsh.INTERNO + 'dev-api.acme-demo.mx@2026-11-30T00:00:00+00:00'])
        self.assertEqual(h.huella, crtsh._huella('cert_internal_name', 'dev-api.acme-demo.mx'))
        # la etiqueta del dominio autorizado no cuenta: dev es la marca de dev.mx
        self.assertEqual(higiene([cert(5, ['dev.mx', 'www.dev.mx', 'api.dev.mx'], '2026-09-01T00:00:00',
                                       '2026-11-30T00:00:00')], 'dev.mx'), {})

    def test_2_nombre_interno_vencido_dentro_de_la_ventana_y_fuera(self):
        hs = higiene([
            cert(1, ['staging.acme-demo.mx'], '2026-05-27T00:00:00', '2026-08-26T00:00:00'),  # venció hace 50 días
            cert(2, ['qa.acme-demo.mx'], '2025-01-01T00:00:00', '2025-04-01T00:00:00'),       # hace más de un año
            cert(3, ['uat.acme-demo.mx'], '2026-11-01T00:00:00', '2027-01-30T00:00:00'),      # todavía no empieza
            cert(4, ['staging.acme-demo.mx'], '2026-08-20T00:00:00', '2026-11-18T00:00:00', serie='ab'),
        ])
        self.assertEqual(sorted(a for c, a in hs if c == 'cert_internal_name'), ['staging.acme-demo.mx'])
        h = hs[('cert_internal_name', 'staging.acme-demo.mx')]
        # uno por nombre, con una parte por cada certificado que cuenta; la evidencia es del que vence después
        self.assertEqual(h.partes, [crtsh.INTERNO + 'staging.acme-demo.mx@2026-08-26T00:00:00+00:00',
                                    crtsh.INTERNO + 'staging.acme-demo.mx@2026-11-18T00:00:00+00:00'])
        self.assertEqual((h.evidencia['certificados'], h.evidencia['crtsh_id'], h.evidencia['primera_vez']),
                         (2, 4, '2026-05-27T00:00:00+00:00'))

    def test_3_comodin_vigente_si_y_vencido_no(self):
        vigente = cert(1, ['*.acme-demo.mx', 'acme-demo.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00', emisor=GS)
        otro = cert(2, ['*.acme-demo.mx'], '2026-10-01T00:00:00', '2026-12-30T00:00:00')
        vencido = cert(3, ['*.acme-demo.mx'], '2026-05-01T00:00:00', '2026-07-30T00:00:00')
        hs = higiene([vigente, otro, vencido])
        h = hs[('cert_broad_wildcard', 'acme-demo.mx')]
        self.assertEqual(len([c for c, _ in hs if c == 'cert_broad_wildcard']), 1)
        self.assertEqual(h.severidad, 'low')
        self.assertEqual(h.evidencia, {
            'title': h.titulo, 'host': '*.acme-demo.mx', 'certificados': 2, 'ids': ['1', '2'], 'emisor': LE,
            'emitido': '2026-10-01T00:00:00+00:00', 'vence': '2026-12-30T00:00:00+00:00', 'origen': 'crtsh',
            'crtsh_id': 2, 'serie': '%040x' % 2, 'primera_vez': '2026-09-01T00:00:00+00:00'})
        self.assertEqual(h.partes, ['acme-demo.mx@2026-11-30T00:00:00+00:00', 'acme-demo.mx@2026-12-30T00:00:00+00:00'])
        # vencido, revocado o de un subdominio: no es el comodín de todo el dominio
        self.assertEqual(higiene([vencido]), {})
        self.assertEqual(higiene([dict(otro, revocado=True)]), {})
        self.assertEqual(higiene([cert(4, ['*.tienda.acme-demo.mx'], '2026-09-01T00:00:00', '2026-11-30T00:00:00')]),
                         {})

    def test_4_autoridad_nueva(self):
        antes = [cert(i, ['www.acme-demo.mx'], '2025-0%d-01T00:00:00' % i, '2025-0%d-28T00:00:00' % (i + 2))
                 for i in (1, 2, 3)]
        nuevo = cert(10, ['acme-demo.mx', 'pagos.acme-demo.mx', 'otra.com'], '2026-09-15T00:00:00',
                     '2026-12-14T00:00:00', emisor=GS)
        segundo = cert(11, ['www.acme-demo.mx'], '2026-10-01T00:00:00', '2026-12-30T00:00:00', emisor=GS)
        mayusculas = cert(12, ['www.acme-demo.mx'], '2026-10-02T00:00:00', '2026-12-31T00:00:00',
                          emisor="C=US, O=LET'S  ENCRYPT, CN=R10")
        hs = higiene(antes + [nuevo, segundo, mayusculas])
        nuevas = [h for (c, _), h in hs.items() if c == 'cert_new_issuer']
        self.assertEqual(len(nuevas), 1)  # uno por organización; Let's Encrypt en mayúsculas no es otra
        h = nuevas[0]
        self.assertEqual((h.activo, h.severidad, h.clave, h.partes),
                         ('acme-demo.mx', 'medium', 'globalsign nv-sa', ['emisor:globalsign nv-sa']))
        self.assertEqual(h.evidencia, {
            'title': h.titulo, 'host': 'acme-demo.mx', 'nombres': ['acme-demo.mx', 'pagos.acme-demo.mx'],
            'organizacion': 'GlobalSign nv-sa', 'emisor': GS, 'emitido': '2026-09-15T00:00:00+00:00',
            'vence': '2026-12-14T00:00:00+00:00', 'origen': 'crtsh', 'crtsh_id': 10, 'serie': '%040x' % 10,
            'certificados_anteriores': 3, 'organizaciones_anteriores': ["let's encrypt"],
            'primera_vez': '2026-09-15T00:00:00+00:00'})
        self.assertEqual(h.huella, crtsh._huella('cert_new_issuer', 'acme-demo.mx', 'globalsign nv-sa'))
        self.assertEqual(crtsh._emisores(antes + [nuevo]), {"emisor:let's encrypt", 'emisor:globalsign nv-sa'})

    def test_5_cambio_de_autoridad_sin_historia_suficiente_no_es_hallazgo(self):
        antes = [cert(i, ['www.acme-demo.mx'], '2025-0%d-01T00:00:00' % i, '2025-0%d-28T00:00:00' % (i + 2))
                 for i in (1, 2, 3)]
        nuevo = cert(10, ['www.acme-demo.mx'], '2026-09-15T00:00:00', '2026-12-14T00:00:00', emisor=GS)
        self.assertEqual(higiene(antes[:2] + [nuevo]), {})        # solo 2 anteriores
        self.assertEqual(higiene([nuevo]), {})                    # el primero del dominio
        viejo = cert(10, ['www.acme-demo.mx'], '2026-06-01T00:00:00', '2026-12-14T00:00:00', emisor=GS)
        self.assertEqual(higiene(antes + [viejo]), {})            # emitido hace más de 90 días
        self.assertEqual(higiene(antes + [dict(nuevo, revocado=True)]), {})
        # el mismo día que otro de Sectigo: ninguno de los dos es anterior al otro, así que los dos son nuevos
        mismo_dia = cert(11, ['api.acme-demo.mx'], '2026-09-15T00:00:00', '2026-12-14T00:00:00', emisor=SECTIGO)
        self.assertEqual(sorted(h.clave for h in crtsh._higiene('acme-demo.mx', antes + [nuevo, mismo_dia], AHORA)),
                         ['globalsign nv-sa', 'sectigo limited'])
        # sin O= en el emisor no se sabe la organización: ni cuenta como anterior ni es nueva
        sin_o = [cert(20 + i, ['www.acme-demo.mx'], '2025-0%d-01T00:00:00' % i, '2025-0%d-28T00:00:00' % (i + 2),
                      emisor='CN=Sin organizacion') for i in (1, 2, 3)]
        self.assertEqual(higiene(sin_o + [nuevo]), {})

    def test_6_organizacion_del_emisor(self):
        for emisor, org in [("C=US, O=Let's Encrypt, CN=R11", "Let's Encrypt"),
                            ('C=US, O="DigiCert, Inc.", CN=DigiCert TLS RSA SHA256 2020 CA1', 'DigiCert, Inc.'),
                            (r'C=US, O=Amazon\, Inc., CN=Amazon RSA 2048 M02', 'Amazon, Inc.'),
                            ('CN=R3+O=Uno  dos , C=US', 'Uno dos'), ('2.5.4.10=Por OID', 'Por OID'),
                            ('CN=Solo nombre', None), ('O=  ', None), ('', None), (None, None), (5, None)]:
            with self.subTest(emisor=emisor):
                self.assertEqual(crtsh.organizacion(emisor), org)

    def test_7_las_caracteristicas_son_las_de_la_rubrica(self):
        from cirdan.ml import caracteristicas as rubrica
        antes = [cert(i, ['www.acme-demo.mx'], '2025-0%d-01T00:00:00' % i, '2025-0%d-28T00:00:00' % (i + 2))
                 for i in (1, 2, 3)]
        hs = higiene(antes + [
            cert(10, ['*.acme-demo.mx', 'admin.acme-demo.mx'], '2026-09-15T00:00:00', '2026-12-14T00:00:00',
                 emisor=GS)])
        self.assertEqual(sorted(c for c, _ in hs), ['cert_broad_wildcard', 'cert_internal_name', 'cert_new_issuer'])
        for (codigo, activo), h in hs.items():
            with self.subTest(codigo=codigo):
                tipo = 'domain' if activo == 'acme-demo.mx' else 'subdomain'
                self.assertEqual(h.caracteristicas, rubrica.calcular(codigo, tipo, h.evidencia, AHORA))
                self.assertEqual(set(h.caracteristicas), {'tipo', 'antiguedad_dias', 'exposicion', 'sensibilidad'})

    def test_8_salen_en_la_corrida_con_sus_partes(self):
        """Por recolectar(): con crt.sh completo salen los 3 y las partes emisor: de todas las organizaciones van en
        revisados solo cuando llegaron todos los certificados. Con la búsqueda por nombre no van."""
        antes = [cert(100 + i, ['www.acme-demo.mx'], '2025-0%d-01T00:00:00' % i, '2025-0%d-28T00:00:00' % (i + 2))
                 for i in (1, 2, 3)]
        certs = antes + [cert(110, ['*.acme-demo.mx', 'vpn.acme-demo.mx'], '2026-09-15T00:00:00',
                              '2026-12-14T00:00:00', emisor=GS)]
        res = recolectar(CrtshSimulado(respuestas={'%.acme-demo.mx': certs}), parecidos=False)
        self.assertEqual((res.estado, res.sin_cobertura, res.revisados), ('succeeded', ['lookalike_domain'], None))
        codigos = {(h.codigo, h.activo) for h in res.hallazgos}
        self.assertTrue({('cert_internal_name', 'vpn.acme-demo.mx'), ('cert_broad_wildcard', 'acme-demo.mx'),
                         ('cert_new_issuer', 'acme-demo.mx')} <= codigos)
        self.assertEqual(contrato.validar(res, codigos=set(crtsh.CODIGOS)), [])
        self.assertTrue(all(h.partes for h in res.hallazgos))

        class SinComodin(CrtshSimulado):
            def __call__(self, url, timeout):
                partes = crtsh.urllib.parse.urlparse(url)
                if partes.netloc != 'api.certspotter.com' and consulta(url).startswith('%.'):
                    self.urls.append(url)
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return super().__call__(url, timeout)
        parcial = recolectar(SinComodin(respuestas={'acme-demo.mx': certs}), parecidos=False)
        self.assertIn(('cert_new_issuer', 'acme-demo.mx'), {(h.codigo, h.activo) for h in parcial.hallazgos})
        self.assertIsNotNone(parcial.revisados)
        self.assertFalse([p for p in parcial.revisados if p.startswith(crtsh.EMISOR)])  # no se cierra ninguno
        self.assertIn('acme-demo.mx@2026-12-14T00:00:00+00:00', parcial.revisados)

    def test_9_con_el_respaldo_internos_y_autoridades_quedan_sin_cobertura(self):
        """crt.sh no responde y los certificados vigentes salen de Cert Spotter: cert_internal_name y cert_new_issuer
        van en sin_cobertura y no traen hallazgos aunque los datos alcanzarían. El comodín vigente sí sale."""
        emisiones = [emision_cs(str(9000 + i), ['www.acme-demo.mx'], '2026-0%d-01T00:00:00Z' % i,
                                '2026-12-0%dT00:00:00Z' % i) for i in (1, 2, 3)]
        emisiones.append(emision_cs('9010', ['*.acme-demo.mx', 'dev.acme-demo.mx'], '2026-09-15T00:00:00Z',
                                    '2026-12-14T00:00:00Z', emisor=GS))
        t = CrtshSimulado(fallas=2 * crtsh.INTENTOS, emisiones=emisiones)
        res = recolectar(t, parecidos=False)
        self.assertEqual(res.estado, 'succeeded')
        self.assertTrue(t.cert_spotter)
        self.assertTrue({'cert_internal_name', 'cert_new_issuer'} <= set(res.sin_cobertura))
        codigos = {h.codigo for h in res.hallazgos}
        self.assertFalse(codigos & {'cert_internal_name', 'cert_new_issuer'})
        h = [h for h in res.hallazgos if h.codigo == 'cert_broad_wildcard'][0]
        self.assertEqual((h.evidencia['origen'], h.evidencia['certspotter_id']), ('certspotter', '9010'))
        # los mismos datos con crt.sh sí dan los dos
        self.assertTrue({'cert_internal_name', 'cert_new_issuer'} <=
                        {c for c, _ in higiene([crtsh.certspotter.certificado(e) for e in emisiones])})

    def test_10_respuesta_de_mas_de_50_mib_pasa_a_la_busqueda_por_nombre_sin_reintentar(self):
        class Grande(CrtshSimulado):
            def __init__(self, grandes, **kw):
                super().__init__(**kw)
                self.grandes = grandes

            def __call__(self, url, timeout):
                partes = crtsh.urllib.parse.urlparse(url)
                if partes.netloc != 'api.certspotter.com' and consulta(url) in self.grandes:
                    self.urls.append(url)
                    raise crtsh.RespuestaGrande('respuesta de más de %d bytes' % crtsh.TOPE_BYTES)
                return super().__call__(url, timeout)
        t = Grande({'%.acme-demo.mx'}, respuestas={'acme-demo.mx': SUBDOMINIOS})
        res = recolectar(t, parecidos=False)
        self.assertEqual([consulta(u) for u in t.urls], ['%.acme-demo.mx', 'acme-demo.mx'])  # un solo intento
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.avisos[0], 'La respuesta de crt.sh a %.acme-demo.mx pasó de su tope de 52428800 bytes y '
                                        'no se leyó. Se usó la búsqueda por nombre y pueden faltar subdominios')
        # las dos de más: entra Cert Spotter
        www = emision_cs('9001', ['www.acme-demo.mx'], '2026-09-20T00:00:00Z', '2026-12-19T00:00:00Z')
        t = Grande({'%.acme-demo.mx', 'acme-demo.mx'}, emisiones=[www])
        res = recolectar(t, parecidos=False)
        self.assertEqual(len(t.urls), 2)
        self.assertTrue(t.cert_spotter)
        self.assertEqual(res.sin_cobertura, crtsh.certspotter.SIN_COBERTURA)
        self.assertIn('después de 1 intento (RespuestaGrande: respuesta de más de 52428800 bytes)', res.avisos[0])

    def test_11_descargar_pasa_el_tope_y_su_error_es_respuesta_grande(self):
        pedidas = []

        def descargar(req, plazo, tope, cronometro):
            pedidas.append((req.full_url, tope, req.get_header('User-agent')))
            raise ValueError('respuesta de más de %d bytes' % tope)
        with mock.patch.object(crtsh.transporte, 'descargar', descargar):
            with self.assertRaises(crtsh.RespuestaGrande):
                crtsh._descargar('https://crt.sh/?q=acme-demo.mx&output=json', 45)
        self.assertEqual(pedidas, [('https://crt.sh/?q=acme-demo.mx&output=json', 50 * 1024 * 1024, crtsh.AGENTE)])
        self.assertTrue(issubclass(crtsh.RespuestaGrande, ValueError))

    def test_12_las_dos_busquedas_comparten_plazo_principal(self):
        reloj, timeouts = [0.0], []

        class Reloj(CrtshSimulado):
            def __init__(self, tarda, **kw):
                super().__init__(**kw)
                self.tarda = tarda

            def __call__(self, url, timeout):
                if crtsh.urllib.parse.urlparse(url).netloc != 'api.certspotter.com':
                    timeouts.append((consulta(url), timeout))
                    segundos = self.tarda(consulta(url))
                    if segundos is None:  # 502 al instante
                        self.urls.append(url)
                        raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                    if segundos > timeout:
                        reloj[0] += timeout
                        raise crtsh.transporte.PlazoVencido('crt.sh no terminó dentro de su plazo')
                    reloj[0] += segundos
                return super().__call__(url, timeout)

        def correr(tarda, **kw):
            reloj[0], timeouts[:] = 0.0, []
            cliente = crtsh.ClienteCrtsh(transporte=Reloj(tarda, **kw), cronometro=lambda: reloj[0],
                                         dormir=lambda s: reloj.__setitem__(0, reloj[0] + s))
            return crtsh.recolectar('acme-demo.mx', cliente, AHORA, parecidos=False)
        # %.dominio da 502 tres veces (5 y 15 s de espera) dentro de sus 75 s: la búsqueda por nombre espera lo que
        # queda de los 120, 100 s
        res = correr(lambda q: None if q.startswith('%') else 1)
        self.assertEqual(timeouts, [('%.acme-demo.mx', 75), ('%.acme-demo.mx', 70), ('%.acme-demo.mx', 55),
                                    ('acme-demo.mx', 100)])
        self.assertEqual(res.estado, 'succeeded')
        # %.dominio se cuelga: se corta a los 75 s y la búsqueda por nombre todavía tiene RESERVA_NOMBRE
        res = correr(lambda q: 1000 if q.startswith('%') else 2, respuestas={'acme-demo.mx': SUBDOMINIOS})
        self.assertEqual(timeouts, [('%.acme-demo.mx', 75), ('acme-demo.mx', 45)])
        self.assertEqual((res.estado, res.sin_cobertura), ('succeeded', ['lookalike_domain']))
        self.assertIn('Se usó la búsqueda por nombre', res.avisos[0])
        # las dos se cuelgan: no pasan de los 120 s y entra Cert Spotter
        res = correr(lambda q: 1000, emisiones=[emision_cs('9001', ['www.acme-demo.mx'], '2026-09-20T00:00:00Z',
                                                          '2026-12-19T00:00:00Z')])
        self.assertEqual(timeouts, [('%.acme-demo.mx', 75), ('acme-demo.mx', 45)])
        self.assertEqual(reloj[0], 120)
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.sin_cobertura, crtsh.certspotter.SIN_COBERTURA)
        self.assertIn('no quedó tiempo', ' '.join(res.avisos))

    def test_13_volumen_5000_subdominios_y_20000_certificados(self):
        """recolectar() completa, sin red, con un dominio de 5,000 subdominios y 20,000 certificados (comentario 10276):
        tiempo, memoria y filas, desde el cuerpo JSON de crt.sh hasta activos, revisados y hallazgos.

        Cada h<n> lleva 4 certificados de 90 días, emitidos de ene 2024 a abr 2026, y dev-<n> (n múltiplo de 100, 50
        nombres) va en los mismos 4. El último de cada uno venció entre dic 2025 y jul 2026 y lo cubre el comodín
        vigente *.acme-demo.mx, así que no hay cert_expired. h4990 a h4999 tienen uno vigente, de oct 2026, de 10
        organizaciones nuevas."""
        import time
        import tracemalloc
        certs = []
        for i in range(20000):
            n = i % 5000
            nombres = ['h%d.acme-demo.mx' % n] + (['dev-%d.acme-demo.mx' % n] if n % 100 == 0 else [])
            emisor = (LE, GS, SECTIGO)[i % 3] if i < 19990 else 'C=US, O=Nueva %d, CN=x' % i
            dia = (datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(hours=i) if i < 19990 else
                   datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(hours=i - 19990))
            certs.append(cert(i + 1, nombres, dia.strftime('%Y-%m-%dT%H:%M:%S'),
                              (dia + timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%S'), emisor=emisor))
        certs.append(cert(30000, ['*.acme-demo.mx'], '2026-10-01T00:00:00', '2026-12-30T00:00:00'))
        cuerpo = json.dumps(certs).encode()  # unos 5 MB, por debajo de TOPE_BYTES
        self.assertLess(len(cuerpo), crtsh.TOPE_BYTES)
        internos = sorted('dev-%d.acme-demo.mx' % n for n in range(0, 5000, 100))

        class Volumen:
            """crt.sh da el mismo cuerpo a %.dominio y a la búsqueda por nombre. Cert Spotter da la página vacía."""

            def __init__(self, comodin_cae=False, cert_spotter_cae=False):
                self.comodin_cae, self.cert_spotter_cae, self.urls = comodin_cae, cert_spotter_cae, []

            def __call__(self, url, timeout):
                self.urls.append(url)
                if crtsh.urllib.parse.urlparse(url).netloc == 'api.certspotter.com':
                    if self.cert_spotter_cae:
                        raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                    return b'[]'
                if consulta(url) == '%.acme-demo.mx' and self.comodin_cae:
                    raise urllib.error.HTTPError(url, 502, 'Bad Gateway', None, None)
                return cuerpo

            def resolver(self, nombre):
                raise AssertionError('el comodín cubre todos los vencidos: no se consulta el DNS de %s' % nombre)

        def medir(memoria=False, **kw):
            """Corre recolectar() y revisa tiempo y filas. Con `memoria`, otra vez con tracemalloc, que la hace unas 6
            veces más lenta."""
            inicio = time.perf_counter()
            res = recolectar(Volumen(**kw))
            dura = time.perf_counter() - inicio
            self.assertLess(dura, 10, 'tardó %.1f s' % dura)  # 1 a 1.3 s en una PC del equipo
            if memoria:
                tracemalloc.start()
                try:
                    recolectar(Volumen(**kw))
                    _, pico = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                self.assertLess(pico, 100 * 1024 * 1024, 'pico de %d bytes' % pico)  # unos 31 MB
            self.assertEqual(res.estado, 'succeeded')
            self.assertEqual(sorted({a.tipo for a in res.activos}), ['domain', 'subdomain'])
            self.assertEqual(len(res.activos), 5051)  # h0 a h4999, los 50 dev-<n> y acme-demo.mx del comodín
            self.assertEqual(len({a.valor for a in res.activos}), 5051)
            por_codigo = {}
            for h in res.hallazgos:
                por_codigo[h.codigo] = por_codigo.get(h.codigo, 0) + 1
            self.assertEqual(por_codigo, {'cert_internal_name': 50, 'cert_broad_wildcard': 1, 'cert_new_issuer': 10})
            self.assertEqual(sorted(h.activo for h in res.hallazgos if h.codigo == 'cert_internal_name'), internos)
            nuevas = sorted(h.evidencia['organizacion'] for h in res.hallazgos if h.codigo == 'cert_new_issuer')
            self.assertEqual(nuevas, sorted('Nueva %d' % i for i in range(19990, 20000)))
            return res
        # todo respondió: revisados en None, el orquestador da por revisado todo
        res = medir()
        self.assertIsNone(res.revisados)
        self.assertEqual(res.sin_cobertura, ['lookalike_domain'])  # parecidos=False
        # %.dominio no respondió: la búsqueda por nombre da los mismos certificados y revisados trae cada parte, 4 por
        # nombre (h<n> y dev-<n>), la del comodín y la interno: de cada certificado de dev-<n>. Es la corrida que más
        # guarda, así que aquí se mide la memoria
        res = medir(memoria=True, comodin_cae=True)
        self.assertEqual(len(res.revisados), 5050 * 4 + 1 + 50 * 4)
        self.assertEqual(len([p for p in res.revisados if p.startswith(crtsh.INTERNO)]), 50 * 4)
        self.assertIn('Se usó la búsqueda por nombre', res.avisos[0])
        # el complemento de Cert Spotter no respondió: no se sabe qué se revocó, así que no van los nombres de más de
        # un certificado; quedan la parte del comodín y las interno:
        res = medir(cert_spotter_cae=True)
        self.assertEqual(len(res.revisados), 1 + 50 * 4)
        self.assertIn('acme-demo.mx@2026-12-30T00:00:00+00:00', res.revisados)
        self.assertIn(crtsh.certspotter.SIN_COMPLEMENTO, ' '.join(res.avisos))

    def test_14_reproducir_da_los_mismos_hallazgos_sin_otra_consulta(self):
        antes = [cert(100 + i, ['www.acme-demo.mx'], '2025-0%d-01T00:00:00' % i, '2025-0%d-28T00:00:00' % (i + 2))
                 for i in (1, 2, 3)]
        certs = antes + [cert(110, ['*.acme-demo.mx', 'grafana.acme-demo.mx'], '2026-09-15T00:00:00',
                              '2026-12-14T00:00:00', emisor=GS)]
        with tempfile.TemporaryDirectory() as d:
            t = CrtshSimulado(respuestas={'%.acme-demo.mx': certs})
            grab = crtsh.ClienteCrtsh(modo='grabar', carpeta=d, transporte=t, dormir=lambda s: None)
            vivo = crtsh.recolectar('acme-demo.mx', grab, AHORA, parecidos=False)
            pedidas = len(t.urls) + len(t.cert_spotter)

            def sin_red(url, timeout):
                raise AssertionError('reproducir no consulta la red: %s' % url)
            rep = crtsh.ClienteCrtsh(modo='reproducir', carpeta=d, transporte=sin_red, dormir=lambda s: None)
            repetido = crtsh.recolectar('acme-demo.mx', rep, AHORA, parecidos=False)
        self.assertGreater(pedidas, 0)
        nuevos = {'cert_internal_name', 'cert_broad_wildcard', 'cert_new_issuer'}

        def de_higiene(res):
            return sorted((h.codigo, h.activo, h.huella, tuple(h.partes), json.dumps(h.evidencia, sort_keys=True))
                          for h in res.hallazgos if h.codigo in nuevos)
        self.assertEqual(len(de_higiene(vivo)), 3)
        self.assertEqual(de_higiene(repetido), de_higiene(vivo))

    def test_15_el_respaldo_de_universal_ssl_no_es_autoridad_nueva(self):
        """Revisión de riesgo (base-1): Cloudflare emite, por cada certificado, uno de respaldo de otra autoridad con
        los mismos nombres. Como olmardo.com el 14 oct (aquí un mes antes, por AHORA): 3 de Let's Encrypt y, 10 h después del comodín, el de SSL.com."""
        ssl_com = 'C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 4'
        antes = [cert(1, ['olmardo.com', '*.olmardo.com'], '2026-09-14T00:04:00', '2027-01-12T00:04:00'),
                 cert(2, ['reservas.olmardo.com'], '2026-09-14T01:10:00', '2027-01-12T01:10:00'),
                 cert(3, ['camaras.olmardo.com'], '2026-09-14T01:23:00', '2027-01-12T01:23:00')]
        respaldo = cert(4, ['*.olmardo.com', 'olmardo.com'], '2026-09-14T10:24:00', '2027-01-12T01:00:00',
                        emisor=ssl_com)
        hs = higiene(antes + [respaldo], 'olmardo.com')
        self.assertEqual(sorted(c for c, _ in hs), ['cert_broad_wildcard'])
        # con otros nombres o más de VENTANA_RESPALDO_HORAS después sí es una autoridad nueva
        for otro in (dict(respaldo, name_value='*.olmardo.com\nolmardo.com\npagos.olmardo.com'),
                     cert(4, ['*.olmardo.com', 'olmardo.com'], '2026-09-17T00:05:00', '2027-01-12T01:00:00',
                          emisor=ssl_com)):
            with self.subTest(otro=otro['not_before']):
                self.assertIn(('cert_new_issuer', 'olmardo.com'), higiene(antes + [otro], 'olmardo.com'))
        self.assertEqual(crtsh.VENTANA_RESPALDO_HORAS, 72)
        # si las dos autoridades de la pareja son nuevas, cuenta la primera y la segunda es su respaldo
        digicert = [cert(10 + i, ['www.olmardo.com'], '2025-0%d-01T00:00:00' % i, '2025-0%d-28T00:00:00' % (i + 2),
                         emisor='C=US, O=DigiCert Inc, CN=x') for i in (1, 2, 3)]
        hs = higiene(digicert + [antes[0], respaldo], 'olmardo.com')
        self.assertEqual([h.clave for (c, _), h in hs.items() if c == 'cert_new_issuer'], ["let's encrypt"])

    def test_16_una_etiqueta_en_punycode_no_es_nombre_interno(self):
        """Revisión de riesgo (logica-5): 'xn--test-epa' es 'testé', no 'test'."""
        for nombre, etiqueta in (('xn--test-epa.acme-demo.mx', None), ('xn--dev-xyz.api.acme-demo.mx', None),
                                 ('dev.xn--bcher-kva.acme-demo.mx', 'dev'), ('test.acme-demo.mx', 'test')):
            with self.subTest(nombre=nombre):
                self.assertEqual(crtsh.nombres_internos.etiqueta_interna(nombre, 'acme-demo.mx'), etiqueta)

    def test_17_el_respaldo_de_cert_spotter_no_da_por_revisado_un_nombre_interno(self):
        """Revisión de riesgo (logica-1): con crt.sh caído y Cert Spotter sin todas sus páginas, revisados lleva la
        parte de vigencia del certificado de staging pero no su parte interno:, así el orquestador no cierra el
        cert_internal_name abierto, que esta corrida no revisó. Con crt.sh y una corrida parcial sí va."""
        staging = emision_cs('9020', ['staging.acme-demo.mx'], '2026-09-20T00:00:00Z', '2026-12-19T00:00:00Z')
        parte = 'staging.acme-demo.mx@2026-12-19T00:00:00+00:00'

        class SinSegundaPagina(CrtshSimulado):
            def __call__(self, url, timeout):
                partes = crtsh.urllib.parse.urlparse(url)
                if partes.netloc == 'api.certspotter.com' and 'after' in crtsh.urllib.parse.parse_qs(partes.query):
                    self.cert_spotter.append(url)
                    raise urllib.error.HTTPError(url, 429, 'Too Many Requests', {}, None)
                return super().__call__(url, timeout)
        res = recolectar(SinSegundaPagina(fallas=2 * crtsh.INTENTOS, emisiones=[staging]), parecidos=False)
        self.assertIn('cert_internal_name', res.sin_cobertura)
        self.assertIsNotNone(res.revisados)
        self.assertIn(parte, res.revisados)
        self.assertNotIn(crtsh.INTERNO + parte, res.revisados)
        # la misma corrida parcial pero con crt.sh (búsqueda por nombre): la parte interno: sí va
        certs = [cert(20, ['staging.acme-demo.mx'], '2026-09-20T00:00:00', '2026-12-19T00:00:00')]
        parcial = recolectar(CrtshSimulado(fallas=crtsh.INTENTOS, respuestas={'acme-demo.mx': certs}), parecidos=False)
        self.assertIn(crtsh.INTERNO + parte, parcial.revisados)
        [h] = [h for h in parcial.hallazgos if h.codigo == 'cert_internal_name']
        self.assertEqual(h.partes, [crtsh.INTERNO + parte])


if __name__ == '__main__':
    unittest.main(verbosity=2)
