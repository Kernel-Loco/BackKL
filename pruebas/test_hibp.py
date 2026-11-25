"""Pruebas sin red del recolector de Have I Been Pwned (cirdan/recolectores/hibp.py, #19, RC-54).

La API se simula con ClienteHibp(descargar=...), y el reloj y las esperas con un reloj falso: nada sale a la red y
ninguna prueba duerme. Usan la llave de prueba pública de HIBP (32 ceros, LLAVE_PRUEBA) y los correos de prueba de
hibp-integration-tests.com con las brechas que HIBP documenta para ellos (account-exists, multiple-breaches,
spam-list-only, sensitive-breach, unverified-breach, not-active-breach y opt-out). No es un secreto: HIBP la publica
para probar y solo sirve con esos correos. Las llaves que no son la de prueba llevan el prefijo CIRDAN_FAKE_.

Puntos del Hecho cuando de RC-54 que se prueban aquí, sin base:
1. Con el dominio verificado en HIBP se usa la búsqueda por dominio: PorDominio.
2. Si no (403), se consultan uno por uno los correos de #16, dentro del límite del plan: PorCorreo.
3. Sin llave o sin cobertura, 'Sin cobertura de HIBP' y nunca 0: SinCobertura.
4. La atribución con enlace en la evidencia: PorDominio.test_3. La del CSV y la del reporte, en test_llave_fuentes.py
   y test_reporte.py.
5. Nunca se guardan contraseñas ni la descripción de la brecha: PorDominio.test_3 y Grabacion.test_2.
6. Ritmo de 10 consultas por minuto, 429 y tope de tiempo: Ritmo.
La llave cifrada, la función de la 032 y el upsert en breach_exposures van con base en pruebas/test_llave_fuentes.py.

Uso, desde la raíz del repo:
  python -m unittest pruebas/test_hibp.py
"""
import http.client
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import unquote

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))  # también corre como python pruebas/test_hibp.py
from cirdan.recolectores import REGISTRO, cargar, contrato, hibp, transporte  # noqa: E402
from cirdan.score import cobertura  # noqa: E402

DOMINIO = 'hibp-integration-tests.com'
AHORA = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
LLAVE_PRUEBA = '0' * 32   # la llave de prueba que publica HIBP (haveibeenpwned.com/API/v3, 'Test API key')
LLAVE_FALSA = 'CIRDAN_FAKE_hibp_llave_0123456789'


def brecha(nombre, fecha='2023-01-01', clases=('Email addresses', 'Passwords'), **marcas):
    b = {'Name': nombre, 'Title': nombre + ' Inc', 'Domain': nombre.lower() + '.com', 'BreachDate': fecha,
         'AddedDate': '2024-01-01T00:00:00Z', 'PwnCount': 123456, 'DataClasses': list(clases),
         'Description': 'Texto largo con <a href="x">enlace</a> que nunca se guarda', 'LogoPath': 'https://x/logo.png',
         'IsVerified': True, 'IsFabricated': False, 'IsSensitive': False, 'IsRetired': False, 'IsSpamList': False,
         'IsMalware': False}
    b.update(marcas)
    return b


# Las brechas de los correos de prueba de HIBP, con fechas y clases fijas para las pruebas
BRECHAS = {
    'Adobe': brecha('Adobe', '2013-10-04'),                                    # con contraseñas y más de un año
    'Reciente': brecha('Reciente', '2026-06-01'),                              # con contraseñas y menos de un año
    'Nombres': brecha('Nombres', '2025-01-01', ('Email addresses', 'Names')),  # sin datos de acceso
    'Preguntas': brecha('Preguntas', '2026-10-01', ('Email addresses', 'Security questions and answers')),
    'SpamList': brecha('SpamList', clases=('Email addresses',), IsSpamList=True),
    'Sensible': brecha('Sensible', IsSensitive=True),
    'SinVerificar': brecha('SinVerificar', '2026-09-01', IsVerified=False),
    'Retirada': brecha('Retirada', IsRetired=True),
    'Fabricada': brecha('Fabricada', IsFabricated=True),
}
# Correos de prueba de HIBP -> sus brechas. opt-out no sale en ninguna
CUENTAS = {
    'account-exists': ['Adobe'],
    'multiple-breaches': ['Adobe', 'Reciente', 'Nombres'],
    'spam-list-only': ['SpamList'],
    'sensitive-breach': ['Sensible'],
    'unverified-breach': ['SinVerificar'],
    'not-active-breach': ['Retirada'],
    'opt-out': [],
}
CORREOS = sorted('%s@%s' % (a, DOMINIO) for a in CUENTAS)


class Api:
    """La API v3 simulada. `dominio`: código de /breacheddomain (200 con CUENTAS). `fallas`: {ruta: [códigos]} que se
    devuelven antes de la respuesta buena. Guarda cada petición con su URL y sus cabeceras."""

    def __init__(self, dominio=200, fallas=None, alias=None, retry_after=None):
        self.dominio, self.fallas, self.retry_after = dominio, dict(fallas or {}), retry_after
        self.alias = alias if alias is not None else {a: b for a, b in CUENTAS.items() if b}
        self.peticiones = []

    def __call__(self, url, cabeceras, timeout):
        self.peticiones.append((url, dict(cabeceras)))
        assert url.startswith(hibp.URL), url
        ruta = url[len(hibp.URL):]
        clave = ruta.split('?')[0]
        if self.fallas.get(clave):
            codigo = self.fallas[clave].pop(0)
            if codigo == 'red':
                raise OSError('sin red')
            if codigo == 'corte':   # la conexión se corta a media respuesta
                raise http.client.IncompleteRead(b'')
            return codigo, self.retry_after, b''
        if clave.startswith('breacheddomain/'):
            if self.dominio != 200:
                return self.dominio, None, b''
            return 200, None, json.dumps(self.alias).encode()
        if clave.startswith('breach/'):
            nombre = unquote(clave.split('/', 1)[1])
            return (200, None, json.dumps(BRECHAS[nombre]).encode()) if nombre in BRECHAS else (404, None, b'')
        if clave.startswith('breachedaccount/'):
            assert ruta.endswith('?truncateResponse=false'), ruta
            alias, _, dominio = unquote(clave.split('/', 1)[1]).partition('@')
            nombres = CUENTAS.get(alias) if dominio == DOMINIO else None
            if not nombres:
                return 404, None, b''
            # breachedaccount nunca da sensibles ni retiradas (API v3)
            visibles = [BRECHAS[n] for n in nombres if not BRECHAS[n]['IsSensitive'] and not BRECHAS[n]['IsRetired']]
            return (200, None, json.dumps(visibles).encode()) if visibles else (404, None, b'')
        raise AssertionError('ruta inesperada: %s' % ruta)

    def con_llave(self):
        return [(u, c) for u, c in self.peticiones if 'hibp-api-key' in c]


class Reloj:
    def __init__(self):
        self.t, self.dormido, self.momentos = 0.0, [], []

    def __call__(self):
        return self.t

    def dormir(self, s):
        self.dormido.append(s)
        self.t += s


def cliente(api, modo='vivo', carpeta=None, reloj=None):
    reloj = reloj or Reloj()
    c = hibp.ClienteHibp(modo, carpeta or Path(tempfile.gettempdir()) / 'no-se-usa', descargar=api, reloj=reloj,
                         dormir=reloj.dormir, nueva=(modo == 'grabar'))
    return c, reloj


class Modulo:
    """hibp con el cliente simulado, para pasar por contrato.ejecutar() como el orquestador."""

    def __init__(self, c):
        self.FUENTE, self.CODIGOS, self.recolectar = hibp.FUENTE, hibp.CODIGOS, hibp.recolectar
        self.crear_cliente = lambda modo, dominio: c


def correr(api=None, llave=LLAVE_PRUEBA, correos=(), modo='vivo', carpeta=None, reloj=None, total=None):
    c, reloj = cliente(api or Api(), modo, carpeta, reloj)
    extras = {'correos': list(correos)}
    if total is not None:
        extras['correos_total'] = total
    if modo != 'reproducir':
        extras['llave'] = llave
    res = contrato.ejecutar(Modulo(c), DOMINIO, modo, ahora=AHORA, codigos=list(hibp.CODIGOS), extras=extras)
    return res, reloj


def por_clave(res):
    return {h.clave: h for h in res.hallazgos}


class Registro(unittest.TestCase):

    def test_1_en_el_registro_y_con_el_contrato(self):
        self.assertEqual(REGISTRO['hibp'], 'cirdan.recolectores.hibp')
        self.assertIs(cargar('hibp'), hibp)
        self.assertEqual(set(hibp.SIN_LLAVE), set(hibp.CODIGOS))
        self.assertIs(hibp.PIDE_CORREOS, True)
        self.assertIs(hibp.PIDE_LLAVE, True)
        # Lo que reserva del cupo diario cubre la corrida más larga con todos sus intentos
        self.assertGreaterEqual(hibp.MAX_CONSULTAS, (1 + max(hibp.MAX_CORREOS, hibp.MAX_BRECHAS)) * hibp.INTENTOS)

    def test_2_extras_no_pisan_las_opciones_del_contrato(self):
        c, _ = cliente(Api())
        for malas in ({'dominio': 'otro.mx'}, {'propios': []}, ['llave']):
            res = contrato.ejecutar(Modulo(c), DOMINIO, 'vivo', ahora=AHORA, extras=malas)
            self.assertEqual(res.estado, 'failed')
            self.assertIn('opciones del orquestador', res.error)


class PorDominio(unittest.TestCase):

    def test_1_un_hallazgo_por_brecha_con_su_codigo(self):
        res, _ = correr()
        self.assertEqual(res.estado, 'succeeded', res.error)
        h = por_clave(res)
        self.assertEqual({k: v.codigo for k, v in h.items()}, {
            'Adobe': 'breach_exposure_old', 'Reciente': 'breach_exposure', 'Nombres': 'breach_exposure_no_passwords',
            'SinVerificar': 'breach_exposure'})
        self.assertEqual(h['Adobe'].evidencia['emails'], ['account-exists@' + DOMINIO, 'multiple-breaches@' + DOMINIO])
        self.assertEqual(h['Adobe'].evidencia['emails_exposed'], 2)
        self.assertEqual(h['Adobe'].evidencia['search'], 'domain')
        self.assertFalse(h['SinVerificar'].evidencia['verified'])
        self.assertTrue(all(x.activo == DOMINIO and x.severidad == hibp.CODIGOS[x.codigo] for x in res.hallazgos))
        self.assertEqual(res.sin_cobertura, [])
        self.assertIsNone(res.revisados)   # vio todo el dominio: cierra lo que ya no sale

    def test_2_spam_sensibles_retiradas_y_fabricadas_no_cuentan(self):
        alias = dict(CUENTAS, fabricada=['Fabricada'])
        res, _ = correr(Api(alias={a: b for a, b in alias.items() if b}))
        self.assertNotIn('SpamList', por_clave(res))
        self.assertNotIn('Sensible', por_clave(res))
        self.assertNotIn('Retirada', por_clave(res))
        self.assertNotIn('Fabricada', por_clave(res))
        # La sensible solo se cuenta, sin su nombre ni el correo
        aviso = next(a for a in res.avisos if 'sensibles' in a)
        self.assertNotIn('Sensible', aviso)
        self.assertNotIn('sensitive-breach', json.dumps(res.a_dict()))
        self.assertIn('hibp: 3 brechas fabricadas, de spam o retiradas no cuentan', res.avisos)
        # El correo que solo sale en spam o en la sensible no queda como activo
        self.assertEqual(sorted(a.valor for a in res.activos),
                         sorted('%s@%s' % (a, DOMINIO) for a in ('account-exists', 'multiple-breaches',
                                                                 'unverified-breach')))

    def test_3_evidencia_solo_con_el_hecho_y_la_atribucion(self):
        res, _ = correr()
        texto = json.dumps([h.evidencia for h in res.hallazgos])
        for nunca in ('Description', 'enlace', 'PwnCount', '123456', 'LogoPath', 'logo.png', LLAVE_PRUEBA):
            self.assertNotIn(nunca, texto)
        for h in res.hallazgos:
            self.assertEqual(h.evidencia['attribution'],
                             'Fuente: Have I Been Pwned (https://haveibeenpwned.com), CC BY 4.0 '
                             '(https://creativecommons.org/licenses/by/4.0/)')
            self.assertEqual(h.evidencia['source_url'], 'https://haveibeenpwned.com')
            self.assertEqual(set(h.caracteristicas), set(contrato.CARACTERISTICAS))
            self.assertEqual(h.caracteristicas['tipo'], 'correos_en_brecha')
        adobe = por_clave(res)['Adobe']
        self.assertEqual(adobe.evidencia['access_data'], ['Passwords'])
        self.assertEqual(adobe.caracteristicas['sensibilidad'], 'alta')
        self.assertEqual(adobe.caracteristicas['antiguedad_dias'], (AHORA.date() - datetime(2013, 10, 4).date()).days)
        self.assertEqual(por_clave(res)['Nombres'].caracteristicas['sensibilidad'], 'media')

    def test_4_la_llave_solo_va_en_su_cabecera_y_breach_sin_llave(self):
        api = Api()
        correr(api)
        for url, cab in api.peticiones:
            self.assertNotIn(LLAVE_PRUEBA, url)
            self.assertEqual(cab['user-agent'], contrato.AGENTE)
            if '/breach/' in url:
                self.assertNotIn('hibp-api-key', cab)   # /breach no pide llave: no se manda
            else:
                self.assertEqual(cab['hibp-api-key'], LLAVE_PRUEBA)
        self.assertEqual(len(api.con_llave()), 1)   # una sola búsqueda por dominio

    def test_5_dominio_sin_brechas_es_completo_y_sin_hallazgos(self):
        res, _ = correr(Api(dominio=404))
        self.assertEqual((res.estado, res.hallazgos, res.sin_cobertura, res.revisados), ('succeeded', [], [], None))

    def test_6_brecha_sin_datos_queda_sin_revisar(self):
        res, _ = correr(Api(fallas={'breach/Adobe': [500, 500, 500]}))
        self.assertEqual(res.estado, 'succeeded')
        self.assertNotIn('Adobe', por_clave(res))
        self.assertNotIn('brecha:Adobe', res.revisados)   # no se cierra un hallazgo viejo de Adobe
        self.assertIn('brecha:Reciente', res.revisados)
        self.assertIn('hibp: 1 brechas sin sus datos (fecha y clases), quedan sin revisar', res.avisos)
        self.assertTrue(all(h.partes == ['brecha:' + h.clave] for h in res.hallazgos))

    def test_7_la_huella_no_cambia_con_el_codigo(self):
        """Al cumplir un año la brecha pasa a breach_exposure_old con la misma huella: el upsert la cambia de regla."""
        reciente = hibp.hallazgo(DOMINIO, hibp.limpiar_brecha(BRECHAS['Reciente']), ['a@' + DOMINIO], AHORA,
                                 'domain', ['brecha:Reciente'])
        despues = AHORA.replace(year=2027, month=7)
        vieja = hibp.hallazgo(DOMINIO, hibp.limpiar_brecha(BRECHAS['Reciente']), ['a@' + DOMINIO], despues,
                              'domain', ['brecha:Reciente'])
        self.assertEqual((reciente.codigo, vieja.codigo), ('breach_exposure', 'breach_exposure_old'))
        self.assertEqual(reciente.huella, vieja.huella)

    def test_8_codigo_por_clases_y_fecha(self):
        def de(b):
            return hibp.codigo_de(hibp.limpiar_brecha(b), AHORA)
        self.assertEqual(de(BRECHAS['Preguntas']), 'breach_exposure')   # preguntas de seguridad son datos de acceso
        self.assertEqual(de(brecha('SinFecha', fecha=None)), 'breach_exposure')   # sin fecha cuenta como reciente
        self.assertEqual(de(brecha('Rota', fecha='no-es-fecha')), 'breach_exposure')
        self.assertEqual(de(brecha('Vieja', '2020-01-01', ('Names',))), 'breach_exposure_no_passwords')

    def test_9_alias_y_nombres_raros_se_descartan(self):
        res, _ = correr(Api(alias={'ok': ['Adobe'], 'con espacio': ['Adobe'], '../x': ['Adobe'], 'nul\x00': ['Adobe'],
                                   'bien': [7, '', None]}))
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(por_clave(res)['Adobe'].evidencia['emails'], ['ok@' + DOMINIO])


class PorCorreo(unittest.TestCase):

    def test_1_dominio_sin_verificar_consulta_los_correos_de_github(self):
        api = Api(dominio=403)
        res, _ = correr(api, correos=CORREOS + ['alguien@otro.com', 'mal', 'x@sub.' + DOMINIO])
        self.assertEqual(res.estado, 'succeeded', res.error)
        consultados = sorted(unquote(u.split('breachedaccount/')[1].split('?')[0]) for u, _ in api.peticiones
                             if 'breachedaccount/' in u)
        self.assertEqual(consultados, sorted(CORREOS + ['x@sub.' + DOMINIO]))   # nunca uno de otro dominio
        h = por_clave(res)
        self.assertEqual(set(h), {'Adobe', 'Reciente', 'Nombres', 'SinVerificar'})
        self.assertEqual(h['Adobe'].evidencia['search'], 'emails')
        self.assertEqual(h['Adobe'].partes, ['correo:account-exists@' + DOMINIO, 'correo:multiple-breaches@' + DOMINIO])
        # Solo esos correos y no todo el dominio: siempre parcial, sin sin_revisar
        self.assertEqual(len(res.revisados), len(CORREOS) + 1)
        self.assertIsNone(res.sin_revisar)
        self.assertTrue(res.avisos[0].startswith('hibp: el dominio no está verificado en HIBP (403)'))

    def test_2_sin_correos_es_sin_cobertura_sin_llave_vacia(self):
        res, _ = correr(Api(dominio=403), correos=[])
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.sin_cobertura, list(hibp.CODIGOS))
        self.assertEqual(res.sin_llave, [])
        self.assertEqual(res.avisos, [hibp.SIN_CORREOS])

    def test_3_tope_de_correos(self):
        muchos = ['p%02d@%s' % (i, DOMINIO) for i in range(hibp.MAX_CORREOS + 7)]
        api = Api(dominio=403)
        res, _ = correr(api, correos=muchos)
        self.assertEqual(len([u for u, _ in api.peticiones if 'breachedaccount/' in u]), hibp.MAX_CORREOS)
        self.assertIn(hibp.SOBRAN_CORREOS % (7, hibp.MAX_CORREOS), res.avisos)
        self.assertLessEqual(res.consultas, hibp.MAX_CONSULTAS)

    def test_4_correo_que_no_responde_queda_sin_revisar(self):
        correo = 'account-exists@' + DOMINIO
        res, _ = correr(Api(dominio=403, fallas={'breachedaccount/' + correo.replace('@', '%40'): [503, 503, 503]}),
                        correos=CORREOS)
        self.assertNotIn('correo:' + correo, res.revisados)
        self.assertIn(hibp.CORREO_SIN_RESPUESTA % 1, res.avisos)
        self.assertEqual(por_clave(res)['Adobe'].partes, ['correo:multiple-breaches@' + DOMINIO])

    def test_5_ningun_correo_responde_es_sin_cobertura(self):
        fallas = {'breachedaccount/' + c.replace('@', '%40'): [503] * 3 for c in CORREOS[:2]}
        res, _ = correr(Api(dominio=403, fallas=fallas), correos=CORREOS[:2])
        self.assertEqual((res.estado, res.hallazgos, res.revisados), ('succeeded', [], None))
        self.assertEqual(res.sin_cobertura, list(hibp.CODIGOS))

    def test_6_orden_del_orquestador_total_real_y_hora_de_consulta(self):
        # datos-6 (RC-54 ronda 3): el orden lo da el orquestador (primero los que hace más que no se consultan) y no se
        # vuelve a ordenar por alfabeto. El aviso cuenta los que sobraron antes del tope de CORREOS_SQL.
        muchos = ['z%02d@%s' % (i, DOMINIO) for i in range(hibp.MAX_CORREOS)] + ['a%02d@%s' % (i, DOMINIO)
                                                                                for i in range(5)]
        api = Api(dominio=403)
        res, _ = correr(api, correos=muchos, total=300)
        consultados = [unquote(u.split('breachedaccount/')[1].split('?')[0]) for u, _ in api.peticiones
                       if 'breachedaccount/' in u]
        self.assertEqual(consultados, muchos[:hibp.MAX_CORREOS])
        self.assertIn(hibp.SOBRAN_CORREOS % (300 - hibp.MAX_CORREOS, hibp.MAX_CORREOS), res.avisos)
        self.assertTrue(res.avisos[0].endswith(hibp.POR_CORREO.split('%d de %d')[1]))
        self.assertIn('%d de 300' % hibp.MAX_CORREOS, res.avisos[0])
        # Cada correo consultado lleva la hora en attributes.hibp_consultado, también los que no salen en una brecha
        marcados = {a.valor: a.atributos.get('hibp_consultado') for a in res.activos if a.tipo == 'email'}
        self.assertEqual(set(marcados), set(muchos[:hibp.MAX_CORREOS]))
        self.assertEqual(set(marcados.values()), {'2026-11-22T12:00:00Z'})
        # Un total que no es entero, o menor que la lista, no cambia la cuenta
        res, _ = correr(Api(dominio=403), correos=muchos, total=True)
        self.assertIn(hibp.SOBRAN_CORREOS % (5, hibp.MAX_CORREOS), res.avisos)


class SinCobertura(unittest.TestCase):

    def test_1_sin_llave_no_consulta_y_no_es_failed(self):
        for llave in (None, '', '   '):
            api = Api()
            res, _ = correr(api, llave=llave)
            self.assertEqual(res.estado, 'succeeded')   # 'failed' se reintentaría a 1, 5 y 25 min sin traer la llave
            self.assertEqual((res.sin_cobertura, res.sin_llave), (list(hibp.CODIGOS), list(hibp.CODIGOS)))
            self.assertEqual(res.avisos, [hibp.SIN_LLAVE_AVISO])
            self.assertEqual((res.consultas, api.peticiones, res.hallazgos), (0, [], []))

    def test_2_llave_rechazada_es_sin_llave(self):
        res, _ = correr(Api(dominio=401), llave=LLAVE_FALSA)
        self.assertEqual(res.estado, 'succeeded')
        self.assertEqual(res.sin_llave, list(hibp.CODIGOS))
        self.assertEqual(res.avisos, [hibp.LLAVE_RECHAZADA])
        self.assertEqual(res.consultas, 1)   # un 401 no se reintenta
        self.assertNotIn(LLAVE_FALSA, json.dumps(res.a_dict()))

    def test_3_llave_mal_formada_no_sale_a_la_red(self):
        for mala in ('CIRDAN_FAKE_con\nsalto_de_linea_123', 'corta', 'CIRDAN_FAKE_con espacio_0123456'):
            api = Api()
            res, _ = correr(api, llave=mala)
            self.assertEqual((res.estado, res.sin_llave, api.peticiones), ('succeeded', list(hibp.CODIGOS), []))
            self.assertNotIn(mala.strip(), json.dumps(res.a_dict()))

    def test_4_hibp_caido_es_failed_sin_la_llave(self):
        res, _ = correr(Api(dominio=503), llave=LLAVE_FALSA)
        self.assertEqual(res.estado, 'failed')
        self.assertEqual(res.consultas, hibp.INTENTOS)
        self.assertNotIn(LLAVE_FALSA, res.error)
        res, _ = correr(Api(fallas={'breacheddomain/' + DOMINIO: ['red'] * 3}), llave=LLAVE_FALSA)
        self.assertEqual(res.estado, 'failed')
        self.assertNotIn(LLAVE_FALSA, res.error)

    def test_5_otro_4xx_es_failed(self):
        res, _ = correr(Api(dominio=400))
        self.assertEqual((res.estado, res.consultas), ('failed', 1))

    def test_6_cobertura_da_no_api_key_desde_stats(self):
        """HIBP no guarda raw_payload: el motivo sale de rules_without_key de scans.stats."""
        corridas = [{'source': f, 'status': 'succeeded', 'sin_cobertura': [], 'sin_llave': [], 'avisos': []}
                    for f in REGISTRO if f not in ('ejemplo', 'hibp')]
        corridas.append({'source': 'hibp', 'status': 'succeeded', 'sin_cobertura': None, 'sin_llave': None,
                         'avisos': None})
        con_llave = cobertura.huecos(corridas, list(hibp.CODIGOS), sin_llave=list(hibp.CODIGOS))
        self.assertEqual({(h['code'], h['source'], h['reason']) for h in con_llave},
                         {(c, 'hibp', 'no_api_key') for c in hibp.CODIGOS})
        sin = cobertura.huecos(corridas, list(hibp.CODIGOS))
        self.assertEqual({h['reason'] for h in sin}, {'source_partial'})


class Ritmo(unittest.TestCase):

    def test_1_diez_por_minuto_con_llave(self):
        api, reloj = Api(dominio=403), Reloj()
        momentos = []
        original = api.__call__

        def con_hora(url, cab, timeout):
            if 'hibp-api-key' in cab:
                momentos.append(reloj.t)
            return original(url, cab, timeout)
        c, _ = cliente(con_hora, reloj=reloj)
        res = contrato.ejecutar(Modulo(c), DOMINIO, 'vivo', ahora=AHORA, extras={'correos': CORREOS,
                                                                                'llave': LLAVE_PRUEBA})
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertEqual(len(momentos), 1 + len(CORREOS))
        self.assertTrue(all(b - a >= hibp.PAUSA for a, b in zip(momentos, momentos[1:])))
        # En cualquier minuto caben a lo más 10
        self.assertTrue(all(sum(1 for m in momentos if t <= m < t + 60) <= 10 for t in momentos))

    def test_2_429_espera_su_retry_after(self):
        res, reloj = correr(Api(fallas={'breacheddomain/' + DOMINIO: [429]}, retry_after=7))
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertIn(7, reloj.dormido)
        # Un Retry-After de más de MAX_ESPERA no se espera ni se reintenta antes de tiempo: no detiene el escaneo
        api = Api(fallas={'breacheddomain/' + DOMINIO: [429]}, retry_after=10 ** 6)
        res, reloj = correr(api)
        self.assertEqual((res.estado, reloj.dormido, len(api.peticiones)), ('failed', [], 1))
        self.assertIn('Retry-After', res.error)
        res, _ = correr(Api(fallas={'breacheddomain/' + DOMINIO: [429] * 3}, retry_after=1))
        self.assertEqual(res.estado, 'failed')

    def test_4_un_corte_a_media_respuesta_se_reintenta(self):
        # http.client.HTTPException (IncompleteRead) no es OSError: se reintenta como una falla de red y no tumba
        # la corrida ni pierde lo ya consultado
        res, _ = correr(Api(dominio=403, fallas={'breachedaccount/' + 'account-exists%40' + DOMINIO: ['corte']}),
                        correos=CORREOS)
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertIn('Adobe', por_clave(res))

    def test_5_un_retry_after_largo_frena_tambien_los_correos_siguientes(self):
        api = Api(dominio=403, fallas={'breachedaccount/' + 'account-exists%40' + DOMINIO: [429]}, retry_after=600)
        res, reloj = correr(api, correos=CORREOS)
        self.assertEqual(len(api.con_llave()), 2)   # el dominio y el primer correo, nada durante el bloqueo
        self.assertEqual(reloj.dormido, [hibp.PAUSA])   # solo la pausa entre el dominio y el primer correo
        self.assertEqual((res.estado, res.sin_cobertura), ('succeeded', list(hibp.CODIGOS)))

    def test_3_ninguna_consulta_despues_del_tope_de_tiempo(self):
        muchos = ['p%02d@%s' % (i, DOMINIO) for i in range(hibp.MAX_CORREOS)]
        api = Api(dominio=403, fallas={'breachedaccount/' + c.replace('@', '%40'): [429] * 3 for c in muchos},
                  retry_after=hibp.MAX_ESPERA)
        res, reloj = correr(api, correos=muchos)
        self.assertLessEqual(reloj.t, hibp.TIEMPO_CORRIDA)
        self.assertEqual(res.estado, 'succeeded', res.error)
        self.assertLess(len(api.peticiones), 1 + 3 * hibp.MAX_CORREOS)


class Transporte(unittest.TestCase):
    """_descargar va por transporte.descargar (sin redirecciones ni proxies): la llave nunca sigue un 3xx."""

    def test_1_una_redireccion_no_se_sigue(self):
        with mock.patch.object(transporte, 'descargar',
                               side_effect=transporte.Redirigida(302, 'haveibeenpwned.com', 'http://otro.example/')):
            with self.assertRaises(contrato.FuenteNoResponde) as e:
                hibp._descargar(hibp.URL + 'breacheddomain/' + DOMINIO, {'hibp-api-key': LLAVE_FALSA})
        self.assertNotIn(LLAVE_FALSA, str(e.exception))
        self.assertNotIn('otro.example', str(e.exception))

    def test_2_respuesta_y_codigos(self):
        with mock.patch.object(transporte, 'descargar', return_value=b'[]') as d:
            self.assertEqual(hibp._descargar(hibp.URL + 'breach/Adobe', {}), (200, None, b'[]'))
        self.assertEqual(d.call_args.args[2], hibp.MAX_BYTES)
        casos = [
            ([('retry-after', '7')], 7),
            ([('Date', 'Sun, 22 Nov 2026 12:00:00 GMT'), ('Retry-After', 'Sun, 22 Nov 2026 12:00:30 GMT')], 30),
            ([('Retry-After', 'pronto')], None),
            ([], None),
        ]
        for cabeceras, espera in casos:
            mensaje = http.client.HTTPMessage()
            for nombre, valor in cabeceras:
                mensaje[nombre] = valor
            error = HTTPError(hibp.URL, 429, 'Too Many', mensaje, None)
            with mock.patch.object(transporte, 'descargar', side_effect=error):
                self.assertEqual(hibp._descargar(hibp.URL + 'breach/Adobe', {}), (429, espera, b''))
        with mock.patch.object(transporte, 'descargar', side_effect=ValueError('respuesta de más de 1 bytes')):
            with self.assertRaises(contrato.FuenteNoResponde):
                hibp._descargar(hibp.URL + 'breach/Adobe', {})


class Grabacion(unittest.TestCase):

    def test_1_grabar_y_reproducir_dan_lo_mismo(self):
        with tempfile.TemporaryDirectory() as t:
            vivo, _ = correr(Api(), modo='grabar', carpeta=Path(t))
            api = Api()
            repro, _ = correr(api, modo='reproducir', carpeta=Path(t))
            self.assertEqual(api.peticiones, [])   # al reproducir no sale a la red ni pide la llave
            self.assertEqual([(h.codigo, h.huella, h.evidencia) for h in vivo.hallazgos],
                             [(h.codigo, h.huella, h.evidencia) for h in repro.hallazgos])

    def test_2_la_grabacion_no_trae_la_llave_ni_la_descripcion(self):
        with tempfile.TemporaryDirectory() as t:
            correr(Api(dominio=403), modo='grabar', carpeta=Path(t), llave=LLAVE_FALSA, correos=CORREOS)
            archivos = list(Path(t).glob('*.json'))
            self.assertTrue(archivos)
            texto = ''.join(a.read_text(encoding='utf-8') for a in archivos)
            for nunca in (LLAVE_FALSA, 'Description', 'PwnCount', 'LogoPath'):
                self.assertNotIn(nunca, texto)
            # Los nombres de archivo no traen el correo
            self.assertFalse(any('@' in a.name or 'account' in a.name for a in archivos))

    def test_3_un_401_no_se_graba(self):
        with tempfile.TemporaryDirectory() as t:
            correr(Api(dominio=401), modo='grabar', carpeta=Path(t), llave=LLAVE_FALSA)
            self.assertEqual(list(Path(t).glob('*.json')), [])

    def test_4_reproducir_sin_grabacion_es_sin_cobertura(self):
        with tempfile.TemporaryDirectory() as t:
            res, _ = correr(Api(), modo='reproducir', carpeta=Path(t))
            self.assertEqual(res.estado, 'succeeded')
            self.assertEqual((res.sin_cobertura, res.sin_llave), (list(hibp.CODIGOS), []))
            self.assertEqual(res.avisos, [hibp.SIN_GRABACION_DOMINIO])

    def test_6_la_grabacion_no_liga_una_sensible_a_un_correo(self):
        # Política de privacidad, sección 5.3, punto 5: ni la del dominio ni la de un correo
        with tempfile.TemporaryDirectory() as t:
            correr(Api(), modo='grabar', carpeta=Path(t))
            archivo = hibp.ClienteHibp('reproducir', Path(t)).grabadora.archivo(hibp.CONSULTA_DOMINIO)
            datos = json.loads(archivo.read_text(encoding='utf-8'))['datos']['datos']
        self.assertEqual(datos, {'account-exists': ['Adobe'], 'multiple-breaches': ['Adobe', 'Nombres', 'Reciente'],
                                 'unverified-breach': ['SinVerificar']})
        brechas = [hibp.limpiar_brecha(BRECHAS[n]) for n in ('Sensible', 'Adobe', 'SpamList', 'Retirada')]
        self.assertEqual([b['Name'] for b in hibp.cuenta_al_disco(brechas)], ['Adobe'])

    def test_7_una_grabacion_parcial_no_guarda_el_dominio(self):
        # Al reproducir sería una corrida completa que da por resueltas las brechas que quedaron fuera
        with tempfile.TemporaryDirectory() as t:
            correr(Api(fallas={'breach/Adobe': ['red'] * 3}), modo='grabar', carpeta=Path(t))
            self.assertFalse(hibp.ClienteHibp('reproducir', Path(t)).grabadora.archivo(hibp.CONSULTA_DOMINIO).exists())
            res, _ = correr(Api(), modo='reproducir', carpeta=Path(t))
        self.assertEqual(res.avisos, [hibp.SIN_GRABACION_DOMINIO])

    def test_5_la_carpeta_esta_fuera_de_git(self):
        gitignore = (RAIZ / '.gitignore').read_text(encoding='utf-8')
        self.assertIn('cirdan/recolectores/respuestas_grabadas/hibp/*', gitignore)
        self.assertIn('!cirdan/recolectores/respuestas_grabadas/hibp/.gitkeep', gitignore)
        self.assertTrue((hibp.CARPETA_GRABADAS / '.gitkeep').exists())
        dockerignore = (RAIZ / '.dockerignore').read_text(encoding='utf-8')   # ni en la imagen
        self.assertIn('cirdan/recolectores/respuestas_grabadas/hibp/*', dockerignore)


if __name__ == '__main__':
    unittest.main()
