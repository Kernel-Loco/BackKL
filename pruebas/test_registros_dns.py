"""Pruebas del recolector de registros DNS con SPF y DMARC (#15, RC-48), sin red y sin dnspython: un resolvedor simulado.

    python -m unittest -v pruebas/test_registros_dns.py
"""
import ast
import contextlib
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))  # también corre como python pruebas/test_registros_dns.py
from cirdan.recolectores import REGISTRO, cargar, contrato, registros_dns  # noqa: E402
from cirdan.recolectores.contrato import FuenteNoResponde, SinGrabacion  # noqa: E402

AHORA = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
TOKEN = 'CIRDAN_FAKE_9f2c41d07be3a65e'
VERIFICACION = 'cirdan-verification=' + TOKEN
REGISTRADOS = set(registros_dns.CODIGOS)


def zona_olmardo():
    """Lo que publica el DNS de olmardo.com desde el 19 oct (docs/hallazgos_esperados.md): NS de Cloudflare, el TXT de
    verificación y un SPF, sin A, AAAA ni MX en la raíz y sin _dmarc."""
    return {'olmardo.com': {'NS': ['kehlani.ns.cloudflare.com.', 'wilson.ns.cloudflare.com.'],
                            'TXT': ['v=spf1 -all', VERIFICACION]}}


def zona(dominio='acme-demo.mx', spf=(), dmarc=None, **registros):
    """{nombre: {tipo: valores}} de un dominio. `spf`: los TXT de la raíz. `dmarc`: los TXT de _dmarc.<dominio>, [] si el
    nombre existe sin TXT y None si no existe. `registros`: a, aaaa, mx y ns de la raíz."""
    raiz = {tipo: list(registros[tipo.lower()]) for tipo in ('A', 'AAAA', 'MX', 'NS') if registros.get(tipo.lower())}
    if spf:
        raiz['TXT'] = list(spf)
    resultado = {dominio: raiz}
    if dmarc is not None:
        resultado['_dmarc.' + dominio] = {'TXT': list(dmarc)} if dmarc else {}
    return resultado


class DnsSimulado:
    """Resolvedor falso con la forma de registros_dns._consultar. Un nombre que no está en `zona` da NXDOMAIN y uno que está
    sin ese tipo da «vacío», igual que el DNS. `caidas` es {(nombre, tipo): n}: las primeras n consultas fallan con
    ConsultaFallida y n None quiere decir que siempre fallan. `llamadas` anota cada intento."""

    def __init__(self, zona, caidas=None):
        self.zona, self.caidas, self.llamadas = zona, dict(caidas or {}), []

    def __call__(self, nombre, tipo):
        self.llamadas.append((nombre, tipo))
        restantes = self.caidas.get((nombre, tipo), 0)
        if restantes is None or restantes > 0:
            if restantes is not None:
                self.caidas[(nombre, tipo)] = restantes - 1
            raise registros_dns.ConsultaFallida('Timeout: The DNS operation timed out after 5.0 seconds')
        if nombre not in self.zona:
            return 'nxdomain', []
        valores = self.zona[nombre].get(tipo)
        return ('ok', list(valores)) if valores else ('vacio', [])


def correr(zona_dns, dominio='acme-demo.mx', caidas=None):
    """Una corrida en vivo con el resolvedor simulado. Anota también cuánto durmió entre reintentos, sin dormir."""
    dns, dormidas = DnsSimulado(zona_dns, caidas), []
    cliente = registros_dns.ClienteDns(resolver=dns, dormir=dormidas.append)
    return SimpleNamespace(res=registros_dns.recolectar(dominio, cliente, AHORA), dns=dns, dormidas=dormidas, cliente=cliente)


def codigos_de(res, prefijo=''):
    return [h.codigo for h in res.hallazgos if h.codigo.startswith(prefijo)]


def sin_red(nombre, tipo):
    raise AssertionError('no debe consultar el DNS: %s %s' % (tipo, nombre))


def grabar(carpeta, zona_dns, dominio='acme-demo.mx', caidas=None, nueva=True):
    cliente = registros_dns.ClienteDns(modo='grabar', carpeta=carpeta, resolver=DnsSimulado(zona_dns, caidas),
                                       dormir=lambda s: None, nueva=nueva)
    return registros_dns.recolectar(dominio, cliente, AHORA)


def reproducir(carpeta, dominio='acme-demo.mx'):
    cliente = registros_dns.ClienteDns(modo='reproducir', carpeta=carpeta, resolver=sin_red)
    return registros_dns.recolectar(dominio, cliente, AHORA), cliente


class Olmardo(unittest.TestCase):
    """El Hecho cuando de la tarjeta: el escaneo del dominio de prueba encuentra el SPF sin DMARC que sembró #10."""

    def setUp(self):
        self.c = correr(zona_olmardo(), 'olmardo.com')
        self.res = self.c.res

    def test_1_solo_sale_dmarc_missing(self):
        self.assertEqual((self.res.estado, self.res.fuente, self.res.error), ('succeeded', 'dns', ''))
        self.assertEqual(codigos_de(self.res), ['dmarc_missing'])
        self.assertEqual((self.res.hallazgos[0].severidad, self.res.hallazgos[0].activo), ('medium', 'olmardo.com'))
        self.assertEqual((self.res.avisos, self.res.sin_cobertura), ([], []))
        self.assertEqual(contrato.validar(self.res, codigos=REGISTRADOS), [])

    def test_2_ningun_activo_ip_y_el_dns_va_en_los_atributos_del_dominio(self):
        self.assertEqual([(a.tipo, a.valor) for a in self.res.activos], [('domain', 'olmardo.com')])
        dns = self.res.activos[0].atributos['dns']
        self.assertEqual(dns['ns'], ['kehlani.ns.cloudflare.com', 'wilson.ns.cloudflare.com'])
        self.assertEqual((dns['a'], dns['aaaa'], dns['mx'], dns['dmarc']), ([], [], [], []))
        self.assertEqual((dns['spf'], dns['txt_otros']), (['v=spf1 -all'], {'cirdan-verification': 1}))

    def test_3_el_token_no_sale_ni_en_el_resultado_ni_en_la_grabacion(self):
        self.assertNotIn(TOKEN, json.dumps(self.res.a_dict()))
        self.assertNotIn('cirdan-verification=', json.dumps(self.res.a_dict()))
        with tempfile.TemporaryDirectory() as d:
            res = grabar(d, zona_olmardo(), 'olmardo.com')
            archivos = sorted(Path(d).iterdir())
            self.assertEqual(len(archivos), 7)  # las 6 consultas y la marca de inicio
            for archivo in archivos:
                self.assertNotIn(TOKEN, archivo.read_text(encoding='utf-8'), archivo.name)
                self.assertNotIn('cirdan-verification=', archivo.read_text(encoding='utf-8'), archivo.name)
        self.assertNotIn(TOKEN, json.dumps(res.a_dict()))

    def test_4_hace_las_seis_consultas_y_ninguna_mas(self):
        self.assertEqual(self.c.dns.llamadas, [
            ('olmardo.com', 'A'), ('olmardo.com', 'AAAA'), ('olmardo.com', 'MX'), ('olmardo.com', 'NS'),
            ('olmardo.com', 'TXT'), ('_dmarc.olmardo.com', 'TXT')])
        self.assertEqual(self.res.consultas, 6)

    def test_5_las_caracteristicas_y_la_evidencia_son_las_que_lee_el_ml(self):
        h = self.res.hallazgos[0]
        # sin MX y con v=spf1 -all el dominio dice que no manda correo: sensibilidad baja (cirdan/ml/caracteristicas.py)
        self.assertEqual(h.caracteristicas, {'tipo': 'dmarc_faltante', 'antiguedad_dias': 0, 'exposicion': 'publica',
                                             'sensibilidad': 'baja'})
        self.assertEqual(h.evidencia['title'], h.titulo)
        self.assertEqual({k: h.evidencia[k] for k in ('consulta', 'registro', 'observado', 'mx', 'spf', 'dmarc')},
                         {'consulta': '_dmarc.olmardo.com', 'registro': None, 'observado': 'NXDOMAIN', 'mx': [],
                          'spf': 'v=spf1 -all', 'dmarc': None})
        self.assertEqual(h.huella, registros_dns._huella('dmarc_missing', 'olmardo.com'))

    def test_6_ejecutar_lo_deja_succeeded_con_el_catalogo(self):
        with mock.patch.object(registros_dns, '_consultar', DnsSimulado(zona_olmardo())):
            res = contrato.ejecutar(registros_dns, 'olmardo.com', ahora=AHORA, codigos=REGISTRADOS)
        self.assertEqual((res.estado, res.error, codigos_de(res)), ('succeeded', '', ['dmarc_missing']))


CASOS_SPF = [  # (caso, TXT de la raíz, código esperado o None)
    ('ninguno', [], 'spf_missing'),
    ('solo TXT que no son SPF', ['v=spf10 -all', 'hola', 'google-site-verification=CIRDAN_FAKE_g'], 'spf_missing'),
    ('dos SPF', ['v=spf1 -all', 'v=spf1 include:_spf.example.com -all'], 'spf_missing'),
    ('+all', ['v=spf1 +all'], 'spf_allow_all'),
    ('all sin calificador', ['v=spf1 mx all'], 'spf_allow_all'),
    ('mayúsculas', ['V=SPF1 +ALL'], 'spf_allow_all'),
    ('un tabulador después de v=spf1 no es SPF', ['v=spf1\t+all'], 'spf_missing'),
    ('un espacio al inicio no es SPF', [' v=spf1 -all'], 'spf_missing'),
    ('un SPF junto a otro TXT con espacio al inicio', ['v=spf1 -all', ' v=spf1 +all'], None),
    ('?all', ['v=spf1 mx ?all'], 'spf_missing'),
    ('sin all ni redirect', ['v=spf1 mx include:_spf.example.com'], 'spf_missing'),
    ('solo la versión', ['v=spf1'], 'spf_missing'),
    ('un include que se llama all', ['v=spf1 include:all.example.com'], 'spf_missing'),
    ('-all', ['v=spf1 mx -all'], None),
    ('~all', ['v=spf1 mx ~all'], None),
    ('~ALL en mayúsculas', ['V=SPF1 MX ~ALL'], None),
    ('redirect sin all', ['v=spf1 redirect=_spf.example.com'], None),
    ('el primer all manda', ['v=spf1 -all +all'], None),
]


class ReglasSpf(unittest.TestCase):

    def test_1_cada_caso(self):
        for caso, txt, esperado in CASOS_SPF:
            with self.subTest(caso):
                res = correr(zona(spf=txt, dmarc=['v=DMARC1; p=reject'])).res
                self.assertEqual(codigos_de(res, 'spf'), [esperado] if esperado else [])
                self.assertEqual(codigos_de(res, 'dmarc'), [])
                self.assertEqual(res.sin_cobertura, [])
                self.assertEqual(contrato.validar(res, codigos=REGISTRADOS), [])

    def test_2_redirect_sin_all_avisa_que_no_se_evaluo_y_no_deja_codigos_sin_cobertura(self):
        res = correr(zona(spf=['v=spf1 redirect=_spf.example.com'], dmarc=['v=DMARC1; p=reject'])).res
        self.assertEqual(len(res.avisos), 1)
        self.assertIn('redirect=', res.avisos[0])
        self.assertIn('no se evaluó', res.avisos[0])
        self.assertEqual((res.hallazgos, res.sin_cobertura), ([], []))

    def test_3_dos_spf_dan_un_solo_hallazgo_con_los_dos_registros(self):
        dos = ['v=spf1 -all', 'v=spf1 include:_spf.example.com -all']
        res = correr(zona(spf=dos, dmarc=['v=DMARC1; p=reject'])).res
        self.assertEqual(len(res.hallazgos), 1)
        evidencia = res.hallazgos[0].evidencia
        self.assertEqual((evidencia['registro'], evidencia['registros'], evidencia['spf']), (None, sorted(dos), None))
        self.assertIn('2 registros', evidencia['observado'])

    def test_4_la_huella_no_depende_de_lo_observado(self):
        sin_spf = correr(zona(spf=[], dmarc=['v=DMARC1; p=reject'])).res.hallazgos[0]
        neutral = correr(zona(spf=['v=spf1 mx ?all'], dmarc=['v=DMARC1; p=reject'])).res.hallazgos[0]
        otro_dominio = correr(zona('otra-demo.mx', spf=[], dmarc=['v=DMARC1; p=reject']), 'otra-demo.mx').res.hallazgos[0]
        permite = correr(zona(spf=['v=spf1 +all'], dmarc=['v=DMARC1; p=reject'])).res.hallazgos[0]
        self.assertNotEqual(sin_spf.observado if hasattr(sin_spf, 'observado') else sin_spf.evidencia['observado'],
                            neutral.evidencia['observado'])
        self.assertEqual(sin_spf.huella, neutral.huella)
        self.assertEqual(len({sin_spf.huella, otro_dominio.huella, permite.huella}), 3)

    def test_5_la_evidencia_lleva_la_politica_dmarc_que_lee_la_rubrica(self):
        rechaza = correr(zona(spf=[], dmarc=['v=DMARC1; p=reject'])).res.hallazgos[0]
        observa = correr(zona(spf=[], dmarc=['v=DMARC1; p=none'])).res
        sin_dmarc = correr(zona(spf=[])).res
        self.assertEqual((rechaza.evidencia['dmarc'], rechaza.caracteristicas['sensibilidad']), ('p=reject', 'baja'))
        self.assertEqual(observa.hallazgos[0].evidencia['dmarc'], 'p=none')
        self.assertEqual(observa.hallazgos[0].caracteristicas['sensibilidad'], 'media')
        self.assertEqual(codigos_de(sin_dmarc), ['spf_missing', 'dmarc_missing'])
        self.assertEqual(sin_dmarc.hallazgos[0].evidencia['dmarc'], None)

    def test_6_spf_allow_all_trae_su_titulo_y_su_severidad(self):
        h = correr(zona(spf=['v=spf1 +all'], dmarc=['v=DMARC1; p=reject'])).res.hallazgos[0]
        self.assertEqual((h.codigo, h.severidad, h.activo), ('spf_allow_all', 'medium', 'acme-demo.mx'))
        self.assertEqual(h.titulo, 'La lista de servidores de correo de acme-demo.mx acepta a cualquiera')
        self.assertEqual(h.caracteristicas['tipo'], 'spf_allow_all')
        self.assertEqual(h.evidencia['registro'], 'v=spf1 +all')


CASOS_DMARC = [  # (caso, TXT de _dmarc o None si el nombre no existe, código esperado o None)
    ('el nombre no existe', None, 'dmarc_missing'),
    ('el nombre existe sin TXT', [], 'dmarc_missing'),
    ('un TXT que no es DMARC', ['v=spf1 -all'], 'dmarc_missing'),
    ('dos DMARC', ['v=DMARC1; p=reject', 'v=DMARC1; p=none'], 'dmarc_missing'),
    ('p=none', ['v=DMARC1; p=none'], 'dmarc_policy_none'),
    ('mayúsculas', ['V=DMARC1; P=NONE'], 'dmarc_policy_none'),
    ('con espacio al inicio no es DMARC', [' v=DMARC1; p=reject'], 'dmarc_missing'),
    ('v=dmarc1 en minúsculas no es DMARC', ['v=dmarc1; p=none'], 'dmarc_missing'),
    ('espacios alrededor del igual de v', ['v = DMARC1; p=reject'], None),
    ('tabuladores alrededor del igual de v', ['v\t=\tDMARC1; p=reject'], None),
    ('sin espacios', ['v=DMARC1;p=none'], 'dmarc_policy_none'),
    ('p=quarantine', ['v=DMARC1; p=quarantine'], None),
    ('p=reject con pct=100', ['v=DMARC1; p=reject; pct=100'], None),
    ('espacio antes del punto y coma', ['v=DMARC1 ; p=reject'], None),
    ('sin p y con rua', ['v=DMARC1; rua=mailto:dmarc@acme-demo.mx'], 'dmarc_policy_none'),
    ('sin p y sin rua', ['v=DMARC1; pct=100'], 'dmarc_missing'),
    ('p vacío y con rua', ['v=DMARC1; p=; rua=mailto:dmarc@acme-demo.mx'], 'dmarc_policy_none'),
    ('p inválido y con rua', ['v=DMARC1; p=bloquear; rua=mailto:dmarc@acme-demo.mx,https://acme-demo.mx/reportes'],
     'dmarc_policy_none'),
    ('p inválido y sin rua', ['v=DMARC1; p=bloquear'], 'dmarc_missing'),
    ('sp inválido y con rua', ['v=DMARC1; p=reject; sp=bloquear; rua=mailto:dmarc@acme-demo.mx'], 'dmarc_policy_none'),
    ('sp inválido y sin rua', ['v=DMARC1; p=reject; sp=bloquear'], 'dmarc_missing'),
    ('un rua sin esquema no cuenta', ['v=DMARC1; p=bloquear; rua=dmarc@acme-demo.mx'], 'dmarc_missing'),
    ('un rua vacío no cuenta', ['v=DMARC1; p=bloquear; rua='], 'dmarc_missing'),
    ('basta una parte de rua con esquema', ['v=DMARC1; rua=dmarc@acme-demo.mx, mailto:dmarc@acme-demo.mx'], 'dmarc_policy_none'),
    ('solo la versión', ['v=DMARC1'], 'dmarc_missing'),
    ('sp=none no genera hallazgo', ['v=DMARC1; p=reject; sp=none'], None),
    ('pct menor a 100 no genera hallazgo', ['v=DMARC1; p=quarantine; pct=10'], None),
    ('si p se repite vale el primero', ['v=DMARC1; p=reject; p=none'], None),
]


class ReglasDmarc(unittest.TestCase):

    def test_1_cada_caso(self):
        for caso, txt, esperado in CASOS_DMARC:
            with self.subTest(caso):
                res = correr(zona(spf=['v=spf1 -all'], dmarc=txt)).res
                self.assertEqual(codigos_de(res, 'dmarc'), [esperado] if esperado else [])
                self.assertEqual(codigos_de(res, 'spf'), [])
                self.assertEqual(res.sin_cobertura, [])
                self.assertEqual(contrato.validar(res, codigos=REGISTRADOS), [])

    def test_2_lo_observado_distingue_nxdomain_de_sin_registro(self):
        nxdomain = correr(zona(spf=['v=spf1 -all'])).res.hallazgos[0]
        vacio = correr(zona(spf=['v=spf1 -all'], dmarc=[])).res.hallazgos[0]
        self.assertEqual((nxdomain.evidencia['observado'], vacio.evidencia['observado']), ('NXDOMAIN', 'sin TXT v=DMARC1'))

    def test_3_dmarc_policy_none_trae_el_registro_completo(self):
        completo = 'v=DMARC1; p=none; rua=mailto:dmarc@acme-demo.mx'
        h = correr(zona(spf=['v=spf1 -all'], dmarc=[completo])).res.hallazgos[0]
        self.assertEqual((h.codigo, h.severidad), ('dmarc_policy_none', 'medium'))
        self.assertEqual((h.evidencia['registro'], h.evidencia['observado']), (completo, 'p=none'))
        self.assertEqual(h.titulo, 'La regla contra correos falsos de acme-demo.mx solo observa')

    def test_4_la_sensibilidad_depende_de_si_el_dominio_manda_correo(self):
        sin_mx = correr(zona(spf=['v=spf1 -all'])).res.hallazgos[0]
        con_mx = correr(zona(spf=['v=spf1 -all'], mx=[(10, 'mail.acme-demo.mx.')])).res.hallazgos[0]
        self.assertEqual((sin_mx.caracteristicas['sensibilidad'], con_mx.caracteristicas['sensibilidad']), ('baja', 'media'))
        self.assertEqual(con_mx.evidencia['mx'], ['mail.acme-demo.mx'])

    def test_5_un_p_o_un_sp_no_validos_se_leen_como_los_lee_un_receptor(self):
        """RFC 7489 6.6.3 paso 6: con un URI en rua el receptor lo toma como p=none, y sin él lo ignora."""
        con_rua = correr(zona(spf=['v=spf1 -all'], dmarc=['v=DMARC1; p=reject; sp=bloquear; rua=mailto:dmarc@acme-demo.mx'])).res
        sin_rua = correr(zona(spf=['v=spf1 -all'], dmarc=['v=DMARC1; p=reject; sp=bloquear'])).res
        self.assertEqual((codigos_de(con_rua), codigos_de(sin_rua)), (['dmarc_policy_none'], ['dmarc_missing']))
        self.assertIn('sp no válido', con_rua.hallazgos[0].evidencia['observado'])
        self.assertIn('se toma como p=none', con_rua.hallazgos[0].evidencia['observado'])
        self.assertIn('sp no válido', sin_rua.hallazgos[0].evidencia['observado'])
        self.assertIn('lo ignora', sin_rua.hallazgos[0].evidencia['observado'])
        # la política que lee el ML es la que aplica el receptor, no el p=reject escrito
        self.assertEqual((con_rua.hallazgos[0].evidencia['dmarc'], sin_rua.hallazgos[0].evidencia['dmarc']), ('p=none', None))


class ActivosYAtributos(unittest.TestCase):

    def test_1_a_y_aaaa_dan_activos_ip_dentro_del_alcance(self):
        z = zona(spf=['v=spf1 -all'], dmarc=['v=DMARC1; p=reject'], a=['203.0.113.11', '203.0.113.10', '203.0.113.10'],
                 aaaa=['2001:DB8::1'])
        with mock.patch.object(registros_dns, '_consultar', DnsSimulado(z)):
            res = contrato.ejecutar(registros_dns, 'acme-demo.mx', ahora=AHORA)
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(res.avisos, [])  # el filtro de alcance no descartó ninguno
        ips = [a for a in res.activos if a.tipo == 'ip']
        self.assertEqual([a.valor for a in ips], ['203.0.113.10', '203.0.113.11', '2001:db8::1'])
        self.assertEqual([a.atributos for a in ips], [
            {'host': 'acme-demo.mx', 'fuente': 'dns', 'origen': 'a'}, {'host': 'acme-demo.mx', 'fuente': 'dns', 'origen': 'a'},
            {'host': 'acme-demo.mx', 'fuente': 'dns', 'origen': 'aaaa'}])
        self.assertEqual(res.activos[0].atributos['dns']['a'], ['203.0.113.10', '203.0.113.11'])

    def test_2_una_ip_invalida_o_de_otra_familia_se_ignora(self):
        z = zona(spf=['v=spf1 -all'], dmarc=['v=DMARC1; p=reject'], a=['no-es-una-ip', '2001:db8::1', '203.0.113.5'])
        res = correr(z).res
        self.assertEqual([a.valor for a in res.activos if a.tipo == 'ip'], ['203.0.113.5'])

    def test_3_mx_y_ns_dentro_del_dominio_dan_subdomain_y_los_de_terceros_solo_atributos(self):
        z = zona(spf=['v=spf1 -all'], dmarc=['v=DMARC1; p=reject'],
                 mx=[(30, 'alt1.aspmx.l.google.com.'), (20, 'MX2.Acme-Demo.MX.'), (10, 'mail.acme-demo.mx.')],
                 ns=['ns1.acme-demo.mx.', 'ns1.otro-dns.example.'])
        res = correr(z).res
        subdominios = {a.valor: a.atributos for a in res.activos if a.tipo == 'subdomain'}
        self.assertEqual(subdominios, {
            'mail.acme-demo.mx': {'fuente': 'dns', 'origen': 'mx', 'origenes': ['mx'], 'prioridad': 10},
            'mx2.acme-demo.mx': {'fuente': 'dns', 'origen': 'mx', 'origenes': ['mx'], 'prioridad': 20},
            'ns1.acme-demo.mx': {'fuente': 'dns', 'origen': 'ns', 'origenes': ['ns']}})
        dns = res.activos[0].atributos['dns']
        self.assertEqual(dns['mx'], [{'prioridad': 10, 'host': 'mail.acme-demo.mx'},
                                     {'prioridad': 20, 'host': 'mx2.acme-demo.mx'},
                                     {'prioridad': 30, 'host': 'alt1.aspmx.l.google.com'}])
        self.assertEqual(dns['ns'], ['ns1.acme-demo.mx', 'ns1.otro-dns.example'])
        self.assertEqual(contrato.validar(res, codigos=REGISTRADOS), [])

    def test_4_el_mx_del_propio_dominio_no_es_un_subdominio(self):
        res = correr(zona(spf=['v=spf1 -all'], dmarc=['v=DMARC1; p=reject'], mx=[(10, 'acme-demo.mx.')])).res
        self.assertEqual([(a.tipo, a.valor) for a in res.activos], [('domain', 'acme-demo.mx')])
        self.assertEqual(res.activos[0].atributos['dns']['mx'], [{'prioridad': 10, 'host': 'acme-demo.mx'}])

    def test_5_un_host_que_es_mx_y_ns_es_un_solo_activo(self):
        res = correr(zona(spf=['v=spf1 -all'], dmarc=['v=DMARC1; p=reject'], mx=[(10, 'mail.acme-demo.mx.')],
                          ns=['mail.acme-demo.mx.'])).res
        self.assertEqual([a.atributos for a in res.activos if a.tipo == 'subdomain'],
                         [{'fuente': 'dns', 'origen': 'mx', 'origenes': ['mx', 'ns'], 'prioridad': 10}])
        self.assertEqual(contrato.validar(res, codigos=REGISTRADOS), [])

    def test_6_el_mx_nulo_queda_en_los_atributos_y_no_cuenta_como_correo(self):
        res = correr(zona(spf=['v=spf1 -all'], mx=[(0, '.')])).res
        self.assertEqual([a.tipo for a in res.activos], ['domain'])
        self.assertEqual(res.activos[0].atributos['dns']['mx'], [{'prioridad': 0, 'host': '.'}])
        h = res.hallazgos[0]
        self.assertEqual((h.evidencia['mx'], h.caracteristicas['sensibilidad']), ([], 'baja'))

    def test_7_los_atributos_del_dominio_solo_traen_dns(self):
        """Dos fuentes dan el activo domain y #23 junta sus atributos. Una llave como 'fuente' pisaría la de crt.sh."""
        res = correr(zona(spf=['v=spf1 -all'], dmarc=['v=DMARC1; p=reject'], a=['203.0.113.10'])).res
        self.assertEqual(list(res.activos[0].atributos), ['dns'])
        self.assertEqual(set(res.activos[0].atributos['dns']), {'a', 'aaaa', 'mx', 'ns', 'spf', 'txt_otros', 'dmarc'})


class TxtSinTokens(unittest.TestCase):

    def test_1_de_un_txt_que_no_es_spf_solo_se_guarda_su_prefijo_y_el_conteo(self):
        valores = ['v=spf1 -all', VERIFICACION, 'google-site-verification=CIRDAN_FAKE_a',
                   'google-site-verification=CIRDAN_FAKE_b', 'CIRDAN_FAKE_texto suelto sin igual',
                   'CIRDAN_FAKE_dGhpcyBpcyBhIHRva2Vu==',     # base64 que termina en =: su «prefijo» sería el token
                   'x' * 100 + '=CIRDAN_FAKE_largo']          # un prefijo tan largo no es el nombre de un registro
        limpio = registros_dns._limpiar('TXT', 'acme-demo.mx', valores)
        self.assertEqual(limpio, {'registros': ['v=spf1 -all'],
                                  'otros': {'cirdan-verification': 1, 'google-site-verification': 2, 'otro': 3}})
        self.assertNotIn('CIRDAN_FAKE_', json.dumps(limpio))

    def test_2_en_dmarc_solo_se_guarda_un_dmarc_completo_y_en_la_raiz_solo_un_spf(self):
        dmarc = registros_dns._limpiar('TXT', '_dmarc.acme-demo.mx', ['v=DMARC1; p=none', 'v=spf1 -all',
                                                                       'secreto=CIRDAN_FAKE_z'])
        self.assertEqual(dmarc, {'registros': ['v=DMARC1; p=none'], 'otros': {'secreto': 1, 'v': 1}})
        raiz = registros_dns._limpiar('TXT', 'acme-demo.mx', ['v=DMARC1; p=none'])
        self.assertEqual(raiz, {'registros': [], 'otros': {'v': 1}})

    def test_3_un_caracter_nulo_en_un_txt_no_tumba_la_fuente(self):
        z = zona(spf=['v=spf1 -all\x00', 'otro\x00=CIRDAN_FAKE_nulo'], dmarc=['v=DMARC1; p=reject'])
        res = correr(z).res
        self.assertEqual(contrato.validar(res, codigos=REGISTRADOS), [])
        self.assertNotIn('\\u0000', json.dumps(res.a_dict()))

    def test_4_el_orden_y_los_repetidos_no_cambian_lo_guardado(self):
        uno = registros_dns._limpiar('MX', 'acme-demo.mx', [(20, 'b.example.'), (10, 'A.example'), (10, 'a.example.')])
        self.assertEqual(uno, [{'prioridad': 10, 'host': 'a.example'}, {'prioridad': 20, 'host': 'b.example'}])
        self.assertEqual(registros_dns._limpiar('NS', 'acme-demo.mx', ['NS2.example.', 'ns1.example', 'ns1.example.']),
                         ['ns1.example', 'ns2.example'])


class Fallas(unittest.TestCase):

    def test_1_tiempo_agotado_en_el_txt_de_la_raiz_deja_el_spf_sin_cobertura(self):
        # sin SPF publicado: si la falla se tomara por «no hay», saldría spf_missing
        c = correr(zona(spf=[], dmarc=None), caidas={('acme-demo.mx', 'TXT'): None})
        self.assertEqual(c.res.sin_cobertura, ['spf_missing', 'spf_allow_all'])
        self.assertEqual(codigos_de(c.res), ['dmarc_missing'])  # lo de _dmarc sí se supo
        self.assertEqual(len(c.res.avisos), 1)
        self.assertIn('TXT de acme-demo.mx', c.res.avisos[0])
        self.assertIn('3 intentos', c.res.avisos[0])
        self.assertEqual(c.res.estado, 'succeeded')
        self.assertEqual(c.res.consultas, 5 + registros_dns.INTENTOS)
        self.assertEqual(c.dormidas, list(registros_dns.ESPERAS))
        self.assertNotIn('spf', c.res.activos[0].atributos['dns'])
        self.assertEqual(contrato.validar(c.res, codigos=REGISTRADOS), [])

    def test_2_tiempo_agotado_en_dmarc_deja_dmarc_sin_cobertura(self):
        c = correr(zona(spf=['v=spf1 +all'], dmarc=None), caidas={('_dmarc.acme-demo.mx', 'TXT'): None})
        self.assertEqual(c.res.sin_cobertura, ['dmarc_missing', 'dmarc_policy_none'])
        self.assertEqual(codigos_de(c.res), ['spf_allow_all'])
        self.assertEqual(len(c.res.avisos), 1)
        self.assertIn('TXT de _dmarc.acme-demo.mx', c.res.avisos[0])
        self.assertNotIn('dmarc', c.res.activos[0].atributos['dns'])
        self.assertEqual(contrato.validar(c.res, codigos=REGISTRADOS), [])

    def test_3_si_responde_en_el_segundo_intento_no_hay_aviso(self):
        c = correr(zona(spf=['v=spf1 -all'], dmarc=['v=DMARC1; p=reject']), caidas={('acme-demo.mx', 'MX'): 1})
        self.assertEqual((c.res.avisos, c.res.sin_cobertura, c.res.hallazgos), ([], [], []))
        self.assertEqual(c.res.consultas, 7)
        self.assertEqual(c.dormidas, [registros_dns.ESPERAS[0]])

    def test_4_la_falla_de_un_tipo_sin_hallazgos_solo_avisa(self):
        c = correr(zona(spf=['v=spf1 -all'], dmarc=['v=DMARC1; p=reject'], a=['203.0.113.10']),
                   caidas={('acme-demo.mx', 'A'): None})
        self.assertEqual(len(c.res.avisos), 1)
        self.assertEqual((c.res.sin_cobertura, c.res.hallazgos), ([], []))
        self.assertNotIn('a', c.res.activos[0].atributos['dns'])
        self.assertEqual([a.tipo for a in c.res.activos], ['domain'])

    def test_5_si_todo_falla_la_fuente_se_cae_para_que_el_orquestador_reintente(self):
        todo = {(n + p, t): None for t in ('A', 'AAAA', 'MX', 'NS', 'TXT') for n, p in (('', 'acme-demo.mx'),)}
        todo = {(nombre, tipo): None for nombre in ('acme-demo.mx', '_dmarc.acme-demo.mx') for tipo in ('A', 'AAAA', 'MX', 'NS', 'TXT')}
        cliente = registros_dns.ClienteDns(resolver=DnsSimulado(zona(), todo), dormir=lambda s: None)
        with self.assertRaises(FuenteNoResponde) as e:
            registros_dns.recolectar('acme-demo.mx', cliente, AHORA)
        self.assertNotIsInstance(e.exception, SinGrabacion)
        self.assertEqual(cliente.consultas, registros_dns.MAX_CONSULTAS)
        with mock.patch.object(registros_dns, '_consultar', DnsSimulado(zona(), todo)), \
                mock.patch.object(registros_dns.time, 'sleep', lambda s: None):
            res = contrato.ejecutar(registros_dns, 'acme-demo.mx', ahora=AHORA)
        self.assertEqual((res.estado, res.consultas, res.activos, res.hallazgos), ('failed', registros_dns.MAX_CONSULTAS, [], []))
        self.assertIn('no respondió a ninguna consulta', res.error)

    def test_6_si_la_raiz_no_existe_no_hay_activos_ni_hallazgos_y_nada_queda_como_cero(self):
        c = correr({})
        res = c.res
        self.assertEqual((res.estado, res.activos, res.hallazgos), ('succeeded', [], []))
        self.assertEqual(len(res.avisos), 1)
        self.assertIn('NXDOMAIN', res.avisos[0])
        self.assertEqual(res.sin_cobertura, list(registros_dns.CODIGOS))
        self.assertEqual(res.consultas, 6)
        self.assertEqual(contrato.validar(res, codigos=REGISTRADOS), [])

    def test_7_un_dominio_invalido_no_consulta_nada(self):
        c = correr(zona(), 'no es un dominio')
        self.assertEqual((c.res.estado, c.dns.llamadas), ('failed', []))

    def test_8_las_fallas_del_dns_cuentan_cada_intento_y_nunca_pasan_el_maximo(self):
        todas = {(n, t): 2 for n in ('acme-demo.mx', '_dmarc.acme-demo.mx') for t in ('A', 'AAAA', 'MX', 'NS', 'TXT')}
        c = correr(zona(spf=['v=spf1 -all'], dmarc=['v=DMARC1; p=reject']), caidas=todas)
        self.assertEqual((c.res.avisos, c.res.consultas), ([], registros_dns.MAX_CONSULTAS))

    def test_9_un_mx_que_no_se_supo_nunca_baja_la_sensibilidad(self):
        """La rúbrica da 'baja' solo con la certeza de que no hay MX (cirdan/ml/caracteristicas.py)."""
        c = correr(zona(spf=['v=spf1 -all'], dmarc=None), caidas={('acme-demo.mx', 'MX'): None})
        h = c.res.hallazgos[0]
        self.assertEqual(codigos_de(c.res), ['dmarc_missing'])
        self.assertEqual((h.caracteristicas['sensibilidad'], h.evidencia['mx']), ('media', None))
        self.assertEqual((len(c.res.avisos), c.res.sin_cobertura), (1, []))
        self.assertNotIn('mx', c.res.activos[0].atributos['dns'])
        # el mismo dominio con el MX sabido como vacío (sin correo) sí baja
        sabido = correr(zona(spf=['v=spf1 -all'], dmarc=None)).res.hallazgos[0]
        self.assertEqual((sabido.caracteristicas['sensibilidad'], sabido.evidencia['mx']), ('baja', []))


def dnspython_falso():
    """Los módulos dns.exception y dns.resolver mínimos que usa _consultar, para probarla sin dnspython."""
    excepcion, resolver, dns = types.ModuleType('dns.exception'), types.ModuleType('dns.resolver'), types.ModuleType('dns')

    class DNSException(Exception):
        pass

    class NXDOMAIN(DNSException):
        pass

    class NoAnswer(DNSException):
        pass

    class Timeout(DNSException):
        pass

    class Resolver:
        creados, respuesta, error = [], None, None

        def __init__(self, configure=True):
            self.configure, self.nameservers, self.lifetime, self.pedidos = configure, None, None, []
            Resolver.creados.append(self)

        def resolve(self, nombre, tipo):
            self.pedidos.append((nombre, tipo))
            if Resolver.error:
                raise Resolver.error
            return Resolver.respuesta

    excepcion.DNSException = DNSException
    resolver.NXDOMAIN, resolver.NoAnswer, resolver.Resolver = NXDOMAIN, NoAnswer, Resolver
    dns.exception, dns.resolver = excepcion, resolver
    return {'dns': dns, 'dns.exception': excepcion, 'dns.resolver': resolver}, SimpleNamespace(
        Resolver=Resolver, NXDOMAIN=NXDOMAIN, NoAnswer=NoAnswer, Timeout=Timeout)


class Resolvedor(unittest.TestCase):
    """_consultar es la única función que habla con dnspython. Aquí se prueba con módulos falsos, sin dnspython ni red."""

    def consultar(self, tipo, respuesta=None, error=None):
        modulos, clases = dnspython_falso()
        clases.Resolver.respuesta = respuesta
        clases.Resolver.error = error(clases) if error else None
        with mock.patch.dict(sys.modules, modulos):
            return registros_dns._consultar('acme-demo.mx', tipo), clases.Resolver.creados

    def test_1_usa_un_resolvedor_publico_fijo_y_nunca_el_del_sistema(self):
        _, creados = self.consultar('A', respuesta=[SimpleNamespace(address='203.0.113.7')])
        self.assertEqual(len(creados), 1)
        self.assertIs(creados[0].configure, False)
        self.assertEqual((creados[0].nameservers, creados[0].lifetime), (['1.1.1.1', '8.8.8.8'], 5.0))
        self.assertEqual(creados[0].pedidos, [('acme-demo.mx', 'A')])

    def test_2_nxdomain_y_sin_registros_son_respuestas_y_lo_demas_es_una_falla(self):
        self.assertEqual(self.consultar('TXT', error=lambda c: c.NXDOMAIN())[0], ('nxdomain', []))
        self.assertEqual(self.consultar('TXT', error=lambda c: c.NoAnswer())[0], ('vacio', []))
        with self.assertRaises(registros_dns.ConsultaFallida) as e:
            self.consultar('TXT', error=lambda c: c.Timeout('tiempo agotado'))
        self.assertIn('Timeout: tiempo agotado', str(e.exception))

    def test_3_el_valor_de_cada_tipo(self):
        def nombre(texto):
            return SimpleNamespace(to_text=lambda: texto)
        self.assertEqual(self.consultar('A', [SimpleNamespace(address='203.0.113.7')])[0], ('ok', ['203.0.113.7']))
        self.assertEqual(self.consultar('AAAA', [SimpleNamespace(address='2001:db8::1')])[0], ('ok', ['2001:db8::1']))
        self.assertEqual(self.consultar('MX', [SimpleNamespace(preference=10, exchange=nombre('mail.acme-demo.mx.'))])[0],
                         ('ok', [(10, 'mail.acme-demo.mx.')]))
        self.assertEqual(self.consultar('NS', [SimpleNamespace(target=nombre('ns1.acme-demo.mx.'))])[0],
                         ('ok', ['ns1.acme-demo.mx.']))
        # las cadenas partidas de un TXT largo se unen sin separador, y lo que no es ASCII se reemplaza
        partido = SimpleNamespace(strings=(b'v=spf1 include:_spf.example.com ', b'-all \xff'))
        self.assertEqual(self.consultar('TXT', [partido])[0], ('ok', ['v=spf1 include:_spf.example.com -all �']))

    def test_4_el_modulo_carga_sin_dnspython(self):
        arbol = ast.parse((RAIZ / 'cirdan' / 'recolectores' / 'registros_dns.py').read_text(encoding='utf-8'))
        for nodo in arbol.body:  # ni import dns ni from dns... al cargar el módulo
            nombres = [a.name for a in nodo.names] if isinstance(nodo, ast.Import) else \
                [nodo.module or ''] if isinstance(nodo, ast.ImportFrom) else []
            self.assertFalse([n for n in nombres if n == 'dns' or n.startswith('dns.')], ast.dump(nodo))
        # y se carga una copia con dnspython bloqueado: _consultar es lo único que lo pide
        spec = importlib.util.spec_from_file_location('registros_dns_sin_dnspython', registros_dns.__file__)
        copia = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {'dns': None, 'dns.exception': None, 'dns.resolver': None}):
            spec.loader.exec_module(copia)
            self.assertEqual(copia.FUENTE, 'dns')
            with self.assertRaises(ImportError):
                copia._consultar('acme-demo.mx', 'A')


class GrabarYReproducir(unittest.TestCase):

    Z = staticmethod(lambda: zona(spf=['v=spf1 +all', ], dmarc=['v=DMARC1; p=none'], a=['203.0.113.10'], aaaa=['2001:db8::1'],
                                  mx=[(10, 'mail.acme-demo.mx.'), (20, 'alt.otro-correo.example.')],
                                  ns=['ns1.acme-demo.mx.', 'ns1.otro-dns.example.']))

    def test_1_grabar_y_reproducir_dan_el_mismo_resultado_sin_consultar_el_dns(self):
        with tempfile.TemporaryDirectory() as d:
            vivo = grabar(d, self.Z())
            grabado, cliente = reproducir(d)
        self.assertEqual(codigos_de(vivo), ['spf_allow_all', 'dmarc_policy_none'])
        for campo in ('activos', 'hallazgos', 'avisos', 'sin_cobertura', 'estado'):
            self.assertEqual(getattr(grabado, campo), getattr(vivo, campo), campo)
        self.assertEqual((vivo.consultas, grabado.consultas, cliente.consultas), (6, 0, 0))
        self.assertEqual(len(cliente.leidas), 6)

    def test_2_reproducir_sin_grabacion_lanza_singrabacion_y_ejecutar_la_deja_failed(self):
        with tempfile.TemporaryDirectory() as d:
            cliente = registros_dns.ClienteDns(modo='reproducir', carpeta=Path(d) / 'acme-demo.mx', resolver=sin_red)
            with self.assertRaises(SinGrabacion) as e:
                registros_dns.recolectar('acme-demo.mx', cliente, AHORA)
            self.assertTrue(str(e.exception).startswith(contrato.SIN_GRABACION))
            with mock.patch.object(registros_dns, 'CARPETA_GRABADAS', Path(d)), \
                    mock.patch.object(registros_dns, '_consultar', sin_red):
                res = contrato.ejecutar(registros_dns, 'acme-demo.mx', modo='reproducir', ahora=AHORA)
        self.assertEqual(res.estado, 'failed')
        self.assertIn(contrato.SIN_GRABACION, res.error)

    def test_3_una_consulta_fallida_no_se_graba_ni_deja_pasar_la_vieja(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = Path(d)
            vieja = carpeta / 'dmarc_acme-demo.mx.json'

            def grabar_vieja():  # la misma Grabadora que usa ClienteDns, con la función de nombre del módulo
                contrato.Grabadora(carpeta, 'grabar', nombre=registros_dns._nombre_grabado).guardar(
                    'txt:_dmarc.acme-demo.mx', {'estado': 'ok', 'valores': {'registros': ['v=DMARC1; p=reject'], 'otros': {}}})
            grabar_vieja()  # de una grabación anterior
            self.assertTrue(vieja.exists())
            res = grabar(d, self.Z(), caidas={('_dmarc.acme-demo.mx', 'TXT'): None})
            archivos = {a.name for a in carpeta.iterdir()}
            self.assertEqual(codigos_de(res), ['spf_allow_all'])
            self.assertEqual(res.sin_cobertura, ['dmarc_missing', 'dmarc_policy_none'])
            self.assertEqual(archivos, {'a_acme-demo.mx.json', 'aaaa_acme-demo.mx.json', 'mx_acme-demo.mx.json',
                                        'ns_acme-demo.mx.json', 'txt_acme-demo.mx.json', contrato.MARCA})
            # grabando sin vaciar la carpeta (nueva=False), la respuesta vieja de la consulta que falló se borra
            grabar_vieja()
            self.assertTrue(vieja.exists())  # sin esto, el assertFalse de abajo pasaría aunque descartar no hiciera nada
            grabar(d, self.Z(), caidas={('_dmarc.acme-demo.mx', 'TXT'): None}, nueva=False)
            self.assertFalse(vieja.exists())

    def test_4_cada_consulta_tiene_su_archivo(self):
        with tempfile.TemporaryDirectory() as d:
            grabar(d, self.Z())
            self.assertEqual(sorted(a.name for a in Path(d).iterdir()), sorted([
                'a_acme-demo.mx.json', 'aaaa_acme-demo.mx.json', 'mx_acme-demo.mx.json', 'ns_acme-demo.mx.json',
                'txt_acme-demo.mx.json', 'dmarc_acme-demo.mx.json', contrato.MARCA]))
            self.assertIsNotNone(contrato.Grabadora.inicio(d))

    def test_5_lo_grabado_ya_va_limpio(self):
        with tempfile.TemporaryDirectory() as d:
            grabar(d, zona_olmardo(), 'olmardo.com')
            txt = json.loads((Path(d) / 'txt_olmardo.com.json').read_text(encoding='utf-8'))
            dmarc = json.loads((Path(d) / 'dmarc_olmardo.com.json').read_text(encoding='utf-8'))
            ns = json.loads((Path(d) / 'ns_olmardo.com.json').read_text(encoding='utf-8'))
        self.assertEqual((txt['consulta'], txt['datos']), ('txt:olmardo.com', {'estado': 'ok', 'valores': {
            'registros': ['v=spf1 -all'], 'otros': {'cirdan-verification': 1}}}))
        self.assertEqual((dmarc['consulta'], dmarc['datos']), ('txt:_dmarc.olmardo.com', {'estado': 'nxdomain', 'valores': {
            'registros': [], 'otros': {}}}))
        self.assertEqual(ns['datos'], {'estado': 'ok', 'valores': ['kehlani.ns.cloudflare.com', 'wilson.ns.cloudflare.com']})

    def test_6_si_falta_una_respuesta_al_reproducir_es_un_aviso_y_no_un_cero(self):
        with tempfile.TemporaryDirectory() as d:
            grabar(d, self.Z())
            (Path(d) / 'dmarc_acme-demo.mx.json').unlink()
            res, cliente = reproducir(d)
            lineas = registros_dns.resumen(res, cliente)
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(len(res.avisos), 1)
        self.assertTrue(res.avisos[0].startswith(contrato.SIN_GRABACION))
        self.assertEqual((codigos_de(res), res.sin_cobertura), (['spf_allow_all'], ['dmarc_missing', 'dmarc_policy_none']))
        self.assertEqual(registros_dns.codigo_salida(res), 2)
        self.assertTrue(any(l.startswith('Falta 1 respuesta grabada') for l in lineas), lineas)

    def test_7_un_archivo_ilegible_es_un_aviso(self):
        with tempfile.TemporaryDirectory() as d:
            grabar(d, self.Z())
            (Path(d) / 'txt_acme-demo.mx.json').write_text('{no es json', encoding='utf-8')
            (Path(d) / 'mx_acme-demo.mx.json').write_text(json.dumps({'grabado': AHORA.isoformat(), 'consulta': 'mx:acme-demo.mx',
                                                                      'datos': {'estado': 'raro', 'valores': []}}), encoding='utf-8')
            res, _ = reproducir(d)
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(len(res.avisos), 2)
        self.assertTrue(all('no se puede leer' in a for a in res.avisos), res.avisos)
        self.assertEqual(res.sin_cobertura, ['spf_missing', 'spf_allow_all'])

    def test_8_si_nada_responde_la_grabacion_anterior_queda_intacta(self):
        todo = {(n, t): None for n in ('acme-demo.mx', '_dmarc.acme-demo.mx') for t in ('A', 'AAAA', 'MX', 'NS', 'TXT')}
        with tempfile.TemporaryDirectory() as d:
            grabar(d, self.Z())
            antes = {a.name: a.read_bytes() for a in Path(d).iterdir()}
            with self.assertRaises(FuenteNoResponde):
                grabar(d, self.Z(), caidas=todo)
            self.assertEqual({a.name: a.read_bytes() for a in Path(d).iterdir()}, antes)

    @staticmethod
    def reemplazar(carpeta, archivo, datos):
        """Deja en `archivo` una respuesta con la fecha buena y `datos` como contenido."""
        (Path(carpeta) / archivo).write_text(json.dumps({'grabado': AHORA.isoformat(), 'consulta': archivo, 'datos': datos}),
                                             encoding='utf-8')

    def test_9_una_forma_inesperada_en_un_txt_es_un_aviso_y_sus_codigos_quedan_sin_cobertura(self):
        buena = {'registros': ['v=spf1 -all'], 'otros': {}}
        formas = {
            'registros null': {'estado': 'ok', 'valores': {'registros': None, 'otros': {}}},
            'registros texto': {'estado': 'ok', 'valores': {'registros': 'v=spf1 -all', 'otros': {}}},
            'sin la llave registros': {'estado': 'ok', 'valores': {'otros': {}}},
            'sin la llave otros': {'estado': 'ok', 'valores': {'registros': []}},
            'otros null': {'estado': 'ok', 'valores': {'registros': [], 'otros': None}},
            'otros lista': {'estado': 'ok', 'valores': {'registros': [], 'otros': ['a']}},
            'un conteo negativo': {'estado': 'ok', 'valores': dict(buena, otros={'a': -1})},
            'un conteo texto': {'estado': 'ok', 'valores': dict(buena, otros={'a': '1'})},
            'un conteo booleano': {'estado': 'ok', 'valores': dict(buena, otros={'a': True})},
            'un registro que no es texto': {'estado': 'ok', 'valores': {'registros': [7], 'otros': {}}},
            'valores lista': {'estado': 'ok', 'valores': []},
            'valores null': {'estado': 'ok', 'valores': None},
            'sin valores': {'estado': 'ok'},
            'estado desconocido': {'estado': 'raro', 'valores': buena},
            'datos lista': [],
            'datos null': None,
        }
        for archivo, codigos, de_cada in (('txt_acme-demo.mx.json', ['spf_missing', 'spf_allow_all'], ['dmarc_policy_none']),
                                          ('dmarc_acme-demo.mx.json', ['dmarc_missing', 'dmarc_policy_none'], ['spf_allow_all'])):
            for caso, datos in formas.items():
                with self.subTest(archivo=archivo, caso=caso), tempfile.TemporaryDirectory() as d:
                    grabar(d, self.Z())
                    self.reemplazar(d, archivo, datos)
                    res, _ = reproducir(d)
                    self.assertEqual(res.estado, 'succeeded')
                    self.assertEqual(len(res.avisos), 1, res.avisos)
                    self.assertIn('no se puede leer', res.avisos[0])
                    self.assertEqual((res.sin_cobertura, codigos_de(res)), (codigos, de_cada))
                    self.assertEqual(contrato.validar(res, codigos=REGISTRADOS), [])

    def test_10_una_forma_inesperada_en_los_demas_tipos_deja_ese_tipo_sin_saber_y_no_como_vacio(self):
        formas = {
            'a': [None, 'texto', {'a': 1}, [7], ['203.0.113.10', None], ['no-es-ip'], ['2001:db8::10']],
            'aaaa': ['texto', [7], ['no-es-ip'], ['203.0.113.10']],
            'ns': ['texto', None, [7], [{'host': 'ns1.acme-demo.mx'}]],
            'mx': ['texto', None, ['mail.acme-demo.mx'], [{'host': 'mail.acme-demo.mx'}], [{'prioridad': 10}],
                   [{'prioridad': '10', 'host': 'mail.acme-demo.mx'}], [{'prioridad': 10, 'host': 7}],
                   [{'prioridad': True, 'host': 'mail.acme-demo.mx'}]],
        }
        for tipo, valores_malos in formas.items():
            for valores in valores_malos:
                with self.subTest(tipo=tipo, valores=valores), tempfile.TemporaryDirectory() as d:
                    grabar(d, self.Z())
                    self.reemplazar(d, '%s_acme-demo.mx.json' % tipo, {'estado': 'ok', 'valores': valores})
                    res, _ = reproducir(d)
                    self.assertEqual(res.estado, 'succeeded')
                    self.assertEqual(len(res.avisos), 1, res.avisos)
                    self.assertIn('no se puede leer', res.avisos[0])
                    dns = res.activos[0].atributos['dns']
                    self.assertNotIn(tipo, dns)  # sin saber: no existe la llave, no es una lista vacía
                    self.assertEqual(sorted(set(dns) - {tipo}), sorted({'a', 'aaaa', 'mx', 'ns', 'spf', 'txt_otros', 'dmarc'} - {tipo}))
                    self.assertEqual((res.sin_cobertura, codigos_de(res)), ([], ['spf_allow_all', 'dmarc_policy_none']))

    def test_11_un_estado_valido_con_su_forma_se_lee_igual_que_antes(self):
        """Lo que graba el cliente para cada tipo pasa la revisión de forma, incluidos los vacíos."""
        with tempfile.TemporaryDirectory() as d:
            vivo = grabar(d, zona(spf=['v=spf1 -all'], mx=[(10, 'mail.acme-demo.mx.')]))   # A, AAAA y NS «vacio», _dmarc NXDOMAIN
            grabado, _ = reproducir(d)
        self.assertEqual((grabado.avisos, grabado.sin_cobertura), ([], []))
        for campo in ('activos', 'hallazgos', 'estado'):
            self.assertEqual(getattr(grabado, campo), getattr(vivo, campo), campo)


class Registro(unittest.TestCase):

    def test_1_esta_en_el_registro_con_su_fuente_y_su_carpeta(self):
        self.assertEqual(REGISTRO['dns'], 'cirdan.recolectores.registros_dns')
        self.assertIs(cargar('dns'), registros_dns)
        self.assertEqual(registros_dns.FUENTE, 'dns')
        self.assertEqual(registros_dns.CARPETA_GRABADAS, contrato.CARPETA_GRABADAS / 'dns')
        self.assertTrue((registros_dns.CARPETA_GRABADAS / '.gitkeep').exists())

    def test_2_declara_sus_cuatro_codigos_con_la_severidad_del_catalogo(self):
        self.assertEqual(registros_dns.CODIGOS, {'spf_missing': 'low', 'spf_allow_all': 'medium', 'dmarc_missing': 'medium',
                                                 'dmarc_policy_none': 'medium'})

    def test_3_max_consultas_es_un_entero_y_ninguna_corrida_lo_pasa(self):
        self.assertIs(type(registros_dns.MAX_CONSULTAS), int)
        self.assertEqual(registros_dns.MAX_CONSULTAS, 6 * registros_dns.INTENTOS)
        peor = {(n, t): registros_dns.INTENTOS - 1 for n in ('acme-demo.mx', '_dmarc.acme-demo.mx')
                for t in ('A', 'AAAA', 'MX', 'NS', 'TXT')}
        self.assertEqual(correr(zona(), caidas=peor).res.consultas, registros_dns.MAX_CONSULTAS)

    def test_4_su_fila_de_data_sources_existe_y_esta_prendida(self):
        semilla = (RAIZ / 'db' / 'semillas' / '001_datos_demo.sql').read_text(encoding='utf-8')
        self.assertRegex(semilla, r"'dns'\s*,\s*'osint'\s*,\s*true\s*,\s*true")

    def test_5_las_grabaciones_de_dns_no_van_al_repo(self):
        """Igual que la de crt.sh: un git add no sube la zona de una empresa a un repo público. Revisa solo el .gitignore."""
        reglas = RAIZ / '.gitignore'
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
            for ruta in ('dns/olmardo.com/txt_olmardo.com.json', 'dns/olmardo.com/dmarc_olmardo.com.json',
                         'dns/olmardo.com/.grabacion'):
                self.assertTrue(ignorado(ruta), ruta)
            for ruta in ('dns/.gitkeep', 'crtsh/.gitkeep', 'ejemplo/acme-demo.mx/resultado.json'):
                self.assertFalse(ignorado(ruta), ruta)

    def test_6_los_titulos_son_propios_y_no_llevan_siglas(self):
        """El título del hallazgo no es el de la regla (docs/contrato_api_v1.md) y va en lenguaje simple (docs/contrato_plugin.md)."""
        self.assertEqual(set(registros_dns.TITULOS), set(registros_dns.CODIGOS))
        self.assertEqual({c: t % 'acme-demo.mx' for c, t in registros_dns.TITULOS.items()}, {
            'spf_missing': 'Sin lista válida de servidores de correo en acme-demo.mx',
            'spf_allow_all': 'La lista de servidores de correo de acme-demo.mx acepta a cualquiera',
            'dmarc_missing': 'Sin regla contra correos falsos en acme-demo.mx',
            'dmarc_policy_none': 'La regla contra correos falsos de acme-demo.mx solo observa'})
        for codigo, titulo in registros_dns.TITULOS.items():
            self.assertNotRegex(titulo, r'SPF|DMARC', codigo)


class Terminal(unittest.TestCase):

    def correr(self, *argumentos, dns=None):
        salida, errores = io.StringIO(), io.StringIO()
        with mock.patch.object(registros_dns, '_consultar', dns or sin_red), \
                mock.patch.object(registros_dns.time, 'sleep', lambda s: None), \
                contextlib.redirect_stdout(salida), contextlib.redirect_stderr(errores):
            try:
                codigo = registros_dns._main(list(argumentos))
            except SystemExit as e:
                codigo = e.code
        return codigo, salida.getvalue(), errores.getvalue()

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        parche = mock.patch.object(registros_dns, 'CARPETA_GRABADAS', Path(self.d.name))
        parche.start()
        self.addCleanup(parche.stop)

    def test_1_grabar_y_reproducir(self):
        codigo, texto, _ = self.correr('olmardo.com', '--grabar', dns=DnsSimulado(zona_olmardo()))
        self.assertEqual(codigo, 0, texto)
        self.assertIn('olmardo.com · DNS público (1.1.1.1 y 8.8.8.8) · succeeded · 6 consultas', texto)
        self.assertIn('Sin regla contra correos falsos en olmardo.com', texto)
        self.assertIn('observado: NXDOMAIN', texto)
        self.assertNotIn(TOKEN, texto)
        self.assertTrue((Path(self.d.name) / 'olmardo.com' / 'txt_olmardo.com.json').exists())
        codigo, texto, _ = self.correr('olmardo.com', '--reproducir')   # sin_red falla la prueba si consulta
        self.assertEqual(codigo, 0, texto)
        self.assertIn('sin red, respuestas grabadas el', texto)
        self.assertIn('Sin regla contra correos falsos en olmardo.com', texto)

    def test_2_json(self):
        codigo, texto, _ = self.correr('olmardo.com', '--json', dns=DnsSimulado(zona_olmardo()))
        datos = json.loads(texto)
        self.assertEqual((codigo, datos['fuente'], datos['estado'], [h['codigo'] for h in datos['hallazgos']]),
                         (0, 'dns', 'succeeded', ['dmarc_missing']))

    def test_3_grabar_y_reproducir_no_van_juntos(self):
        codigo, _, errores = self.correr('olmardo.com', '--grabar', '--reproducir')
        self.assertEqual(codigo, 2)
        self.assertIn('not allowed with', errores)

    def test_4_dominio_invalido(self):
        codigo, _, errores = self.correr('../etc')
        self.assertEqual(codigo, 2)
        self.assertIn('dominio inválido', errores)

    def test_5_reproducir_sin_grabacion_sale_con_1(self):
        codigo, texto, _ = self.correr('olmardo.com', '--reproducir')
        self.assertEqual(codigo, 1)
        self.assertIn('failed', texto)
        self.assertIn(contrato.SIN_GRABACION, texto)

    def test_6_si_el_dns_no_responde_sale_con_1_y_no_graba(self):
        todo = {(n, t): None for n in ('olmardo.com', '_dmarc.olmardo.com') for t in ('A', 'AAAA', 'MX', 'NS', 'TXT')}
        codigo, texto, _ = self.correr('olmardo.com', '--grabar', dns=DnsSimulado(zona_olmardo(), todo))
        self.assertEqual(codigo, 1)
        self.assertIn('failed · 18 consultas', texto)
        self.assertFalse((Path(self.d.name) / 'olmardo.com').exists())

    def test_7_con_avisos_sale_con_2_y_dice_la_cobertura_parcial(self):
        codigo, texto, _ = self.correr('olmardo.com', dns=DnsSimulado(zona_olmardo(), {('_dmarc.olmardo.com', 'TXT'): None}))
        self.assertEqual(codigo, 2)
        self.assertIn('Cobertura parcial: no se revisaron DMARC válido (dmarc_missing) ni política DMARC (dmarc_policy_none).', texto)
        self.assertIn('aviso: El DNS no respondió a TXT de _dmarc.olmardo.com después de 3 intentos', texto)
        self.assertIn('Sin hallazgos.', texto)

    def test_8_una_grabacion_rota_no_suelta_un_traceback(self):
        self.correr('olmardo.com', '--grabar', dns=DnsSimulado(zona_olmardo()))
        archivo = Path(self.d.name) / 'olmardo.com' / 'txt_olmardo.com.json'

        def roto(datos, grabado=AHORA.isoformat()):
            archivo.write_text(json.dumps({'grabado': grabado, 'consulta': 'txt:olmardo.com', 'datos': datos}), encoding='utf-8')

        def carpeta():
            archivo.unlink()
            archivo.mkdir()
        casos = {
            'registros null': lambda: roto({'estado': 'ok', 'valores': {'registros': None, 'otros': {}}}),
            'registros texto': lambda: roto({'estado': 'ok', 'valores': {'registros': 'v=spf1 -all', 'otros': {}}}),
            'sin la llave registros': lambda: roto({'estado': 'ok', 'valores': {'otros': {}}}),
            'datos null': lambda: roto(None),
            'fecha que no es texto': lambda: roto({'estado': 'ok', 'valores': []}, grabado=5),
            'no es json': lambda: archivo.write_text('{no es json', encoding='utf-8'),
            'es una carpeta': carpeta,
        }
        for caso, romper in casos.items():
            with self.subTest(caso):
                if archivo.is_dir():
                    archivo.rmdir()
                romper()
                codigo, texto, errores = self.correr('olmardo.com', '--reproducir')  # un traceback haría fallar la prueba
                self.assertEqual((codigo, errores), (2, ''), texto)
                self.assertIn('Cobertura parcial: no se revisaron SPF válido (spf_missing) ni SPF que no acepta a todos', texto)
                self.assertIn('no se puede leer', texto)
                self.assertNotIn('Traceback', texto)
                codigo, texto, _ = self.correr('olmardo.com', '--reproducir', '--json')
                self.assertEqual(json.loads(texto)['sin_cobertura'], ['spf_missing', 'spf_allow_all'])


if __name__ == '__main__':
    unittest.main()
