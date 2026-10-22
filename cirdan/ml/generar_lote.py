"""Genera el lote semisintético del ML (#33, RC-65) con semilla fija.

    python -m cirdan.ml.generar_lote                      # escribe datos/ml/rc65/
    python -m cirdan.ml.generar_lote --salida otra/carpeta

Arma 425 hallazgos con las plantillas de cirdan/ml/plantillas.py, unos 140 por clase esperada, y los reparte:
- un bloque común de 60, 20 por clase esperada y al menos 2 por plantilla, que etiquetan los 4,
- el resto en 3 partes de unos 122 para etiquetador_2, etiquetador_3 y etiquetador_4,
- etiquetador_1 solo etiqueta el bloque común, porque armó el lote y conoce la clase esperada de cada plantilla.

Escribe copias/etiquetador_N.csv, cada una barajada en su propio orden y solo con lo que el etiquetador puede ver, y
maestro.jsonl, un hallazgo por línea con la forma de #21 (docs/api_v1/hallazgos.json) y los campos del lote. La misma
semilla da los mismos bytes.
"""
import argparse
import csv
import json
import random
import sys
import uuid
from datetime import date
from pathlib import Path

from cirdan import RAIZ
from cirdan.ml import caracteristicas, plantillas
from cirdan.ml.plantillas import CLASES, PLANTILLAS, REFERENCIA
from cirdan.recolectores.crtsh import MESES

SEMILLA = 65
CARPETA = RAIZ / 'datos' / 'ml' / 'rc65'
ETIQUETADORES = ('etiquetador_1', 'etiquetador_2', 'etiquetador_3', 'etiquetador_4')
SOLO_COMUN = 'etiquetador_1'      # conoce la clase esperada: solo etiqueta el bloque común
COMUN_POR_CLASE = 20
MIN_POR_PLANTILLA = 2             # filas mínimas de cada plantilla en el bloque común
ALFABETO_ID = 'abcdefghjkmnpqrstuvwxyz23456789'   # sin 0, 1, i, l ni o, que se confunden
COLUMNAS_COPIA = ('id', 'titulo', 'tipo_de_activo', 'activo', 'fuente', 'evidencia', 'cve', 'cvss', 'epss', 'kev',
                  'etiqueta', 'nota')
TIPO_ACTIVO_ES = {'domain': 'dominio', 'subdomain': 'subdominio', 'ip': 'IP', 'service': 'servicio'}
FUENTE_ES = {'hibp': 'HIBP (brechas de datos)', 'shodan': 'Shodan', 'dns': 'DNS',
             'ct_logs': 'Certificate Transparency (crt.sh)'}


# ---------------------------------------------------------------- evidencia en texto para las copias

DATOS_ES = {'Email addresses': 'correos', 'Passwords': 'contraseñas', 'Usernames': 'nombres de usuario',
            'Names': 'nombres', 'Phone numbers': 'teléfonos'}
USO_ES = {
    'inicio_de_sesion': 'La página pide usuario y contraseña.',
    'api': 'Atiende una API.',
    'correo': 'Atiende correo.',
    'servidor': 'Atiende una aplicación web de la empresa.',
    'sitio_publico': 'Es un sitio informativo, sin formularios ni inicio de sesión.',
    'sin_contenido': 'No muestra contenido.',
}
PARECIDO_ES = {'contiene_marca': 'contiene la marca', 'error_tipografico': 'cambia letras de la marca',
               'otro_tld': 'la misma marca con otra terminación'}


def _fecha(texto):
    d = date.fromisoformat(texto[:10])
    return '%d %s %d' % (d.day, MESES[d.month - 1], d.year)


def _dias(n):
    return '%d %s' % (n, 'día' if n == 1 else 'días')


def _cuando(texto):
    """'18 jun 2026, hace 124 días' o '23 oct 2026, en 3 días', contando desde el día del escaneo."""
    n = (date.fromisoformat(texto[:10]) - REFERENCIA).days
    if n == 0:
        return '%s, el día del escaneo' % _fecha(texto)
    return '%s, %s %s' % (_fecha(texto), 'en' if n > 0 else 'hace', _dias(abs(n)))


def _lista(cosas):
    return cosas[0] if len(cosas) == 1 else ', '.join(cosas[:-1]) + ' y ' + cosas[-1]


def texto_evidencia(h):
    """La evidencia del hallazgo en español, con sus fechas, como la vería alguien en el portal."""
    c, e = h['rule_code'], h['evidence']
    if c == 'breach_exposure':
        n = e['emails_exposed']
        return 'Brecha %s del %s. %s de la empresa. Datos expuestos: %s.' % (
            e['breach_name'], _cuando(e['breach_date']), 'Aparecen %d correos' % n if n > 1 else 'Aparece 1 correo',
            _lista([DATOS_ES[d] for d in e['data_classes']]))
    if c == 'outdated_software':
        soporte = ('Esa versión no tiene soporte desde el %s.' % _cuando(e['fin_de_soporte']) if e['fin_de_soporte']
                   else 'Esa versión sigue con soporte.')
        return '%s:%d responde con %s %s. %s %s Se vio por primera vez el %s.' % (
            h['asset'], e['port'], e['producto'], e['version'], soporte, USO_ES[e['uso']], _cuando(e['primera_vez']))
    if c == 'exposed_rdp':
        return ('En %s se vio abierto el puerto 3389 (escritorio remoto). La IP es de %s. Nombre del equipo en su '
                'certificado RDP: %s. Se vio por primera vez el %s y por última vez el %s.') % (
            e['ip'], e['host'], e['equipo'], _cuando(e['primera_vez']), _cuando(e['ultima_vez']))
    if c in ('cert_expired', 'cert_expiring_soon'):
        vida = (date.fromisoformat(e['not_after']) - date.fromisoformat(e['not_before'])).days
        texto = 'Certificado de %s emitido por %s, válido del %s al %s (%s de vigencia). ' % (
            e['host'], e['emisor'], _fecha(e['not_before']), _fecha(e['not_after']), _dias(vida))
        if c == 'cert_expired':
            texto += 'Venció hace %s. El nombre todavía resuelve en DNS. ' % _dias(e['dias_vencido'])
        else:
            texto += 'Vence en %s. ' % _dias(e['dias_para_vencer'])
        return texto + USO_ES[e['uso']]
    if c in ('dmarc_missing', 'spf_missing'):
        if c == 'dmarc_missing':
            texto = 'La consulta de %s no encuentra registro DMARC (NXDOMAIN).' % e['record']
        else:
            texto = '%s no publica registro SPF (ningún TXT empieza con v=spf1).' % e['record']
        texto += ' Tiene MX: %s.' % ', '.join(e['mx']) if e['mx'] else ' No tiene registros MX.'
        if c == 'dmarc_missing' and e['spf'] == caracteristicas.SPF_NULO:
            texto += ' Su SPF no autoriza a ningún servidor a enviar correo (%s).' % e['spf']
        elif c == 'dmarc_missing' and e['spf']:
            texto += ' Su SPF autoriza servidores de envío: %s.' % e['spf']
        if c == 'spf_missing':
            texto += ' Su DMARC tiene la política %s.' % e['dmarc'] if e['dmarc'] else ' Tampoco tiene DMARC.'
        return texto + ' Se vio por primera vez el %s.' % _cuando(e['primera_vez'])
    if c == 'lookalike_domain':
        n = e['certificados']
        vencio = date.fromisoformat(e['vence']) < REFERENCIA
        return ('Dominio parecido: %s (%s). Nombres en sus certificados: %s. %s, el primero del %s. El más reciente '
                '%s el %s. Emisor: %s.') % (
            e['dominio_parecido'], PARECIDO_ES[e['tipo_parecido']], ', '.join(e['nombres']),
            '%d certificados' % n if n > 1 else '1 certificado', _cuando(e['primer_certificado']),
            'venció' if vencio else 'vence', _cuando(e['vence']), e['emisor'])
    raise ValueError('código sin texto de evidencia: %s' % c)


def fila_copia(h):
    """Lo que el etiquetador ve de un hallazgo: nada de la regla, la severidad, la plantilla ni las características."""
    cve = h['cve_id']
    return {
        'id': h['id'], 'titulo': h['title'], 'tipo_de_activo': TIPO_ACTIVO_ES[h['asset_type']], 'activo': h['asset'],
        'fuente': FUENTE_ES[h['source']], 'evidencia': texto_evidencia(h), 'cve': cve or '',
        'cvss': '%.1f' % h['cvss'] if cve else '', 'epss': '%.3f' % h['epss'] if cve else '',
        'kev': ('sí' if h['in_kev'] else 'no') if cve else '', 'etiqueta': '', 'nota': '',
    }


# ---------------------------------------------------------------- lote y reparto

def _ids(rng, n):
    """Ids opacos que no dicen nada de la plantilla ni del orden: h y 7 caracteres al azar."""
    ids = []
    while len(ids) < n:
        nuevo = 'h' + ''.join(rng.choice(ALFABETO_ID) for _ in range(7))
        if nuevo not in ids:
            ids.append(nuevo)
    return ids


def _hallazgo(rng, id_, p, armado, escaneo):
    e = armado['evidence']
    categoria, base = plantillas.REGLAS[p.codigo]
    cve = armado['cve'] or {'cve_id': None, 'cvss': None, 'epss': None, 'in_kev': False}
    visto = e.get('primera_vez') or REFERENCIA.isoformat()
    return {
        'id': id_, 'title': plantillas.titulo(p.codigo, armado['asset'], e), 'asset': armado['asset'],
        'asset_type': armado['asset_type'], 'category': categoria, 'rule_code': p.codigo,
        'source': plantillas.FUENTE[p.codigo], 'severity': base, 'base_severity': base, 'status': 'open',
        'recurrence': 'recurring' if visto < REFERENCIA.isoformat() else 'new', **cve, 'evidence': e,
        'caracteristicas': caracteristicas.calcular(p.codigo, armado['asset_type'], e, REFERENCIA),
        'detected_at': '%sT%02d:%02d:%02d-06:00' % (visto, rng.randint(6, 22), rng.randrange(60), rng.randrange(60)),
        'last_scan_id': escaneo,
        'plantilla': p.id, 'particion': 'prueba' if p.prueba else 'entrenamiento', 'clase_esperada': p.clase_esperada,
        'bloque': None, 'asignado_a': None,
    }


def _cuantas_en_comun():
    """Filas de cada plantilla en el bloque común: 20 por clase esperada, al menos 2 por plantilla y lo que sobra a
    las plantillas con más filas."""
    cuantas = {}
    for clase in CLASES:
        suyas = sorted((p for p in PLANTILLAS if p.clase_esperada == clase), key=lambda p: -p.filas)
        resto = COMUN_POR_CLASE - MIN_POR_PLANTILLA * len(suyas)
        if resto < 0:
            raise ValueError('el bloque común no alcanza para %d plantillas de la clase %s' % (len(suyas), clase))
        for i, p in enumerate(suyas):
            cuantas[p.id] = MIN_POR_PLANTILLA + resto // len(suyas) + (i < resto % len(suyas))
    return cuantas


def generar(semilla=SEMILLA):
    """(maestro, copias): los hallazgos del lote ordenados por id y, por etiquetador, sus filas en su orden barajado."""
    rng = random.Random(semilla)
    lista = plantillas.empresas(rng)
    escaneos = {e.dominio: str(uuid.UUID(int=rng.getrandbits(128), version=4)) for e in lista}
    ctx = plantillas.Contexto(rng, lista)
    ids = iter(_ids(rng, sum(p.filas for p in PLANTILLAS)))
    por_plantilla = {}
    for p in PLANTILLAS:
        ctx.nueva_plantilla()
        filas = por_plantilla[p.id] = []
        for _ in range(p.filas):
            armado = p.armar(ctx)
            filas.append(_hallazgo(rng, next(ids), p, armado, escaneos[armado['empresa'].dominio]))

    cuantas, siguiente = _cuantas_en_comun(), 0
    for p in PLANTILLAS:
        filas = por_plantilla[p.id]
        comun = rng.sample(filas, cuantas[p.id])
        for h in comun:
            h['bloque'], h['asignado_a'] = 'comun', list(ETIQUETADORES)
        resto = [h for h in filas if h['bloque'] is None]
        rng.shuffle(resto)
        for h in resto:   # en turno entre los 3, así cada parte queda con unas 122 y una mezcla parecida de plantillas
            h['bloque'], h['asignado_a'] = 'reparto', [ETIQUETADORES[1 + siguiente % 3]]
            siguiente += 1

    maestro = sorted((h for filas in por_plantilla.values() for h in filas), key=lambda h: h['id'])
    copias = {}
    for etiquetador in ETIQUETADORES:
        suyas = [h for h in maestro if etiquetador in h['asignado_a']]
        random.Random('%s-%s' % (semilla, etiquetador)).shuffle(suyas)
        copias[etiquetador] = suyas
    return maestro, copias


def escribir(carpeta, maestro, copias):
    """maestro.jsonl y copias/etiquetador_N.csv (UTF-8 con BOM, para que Excel muestre los acentos)."""
    carpeta = Path(carpeta)
    (carpeta / 'copias').mkdir(parents=True, exist_ok=True)
    with open(carpeta / 'maestro.jsonl', 'w', encoding='utf-8', newline='') as f:
        for h in maestro:
            f.write(json.dumps(h, ensure_ascii=False) + '\n')
    for etiquetador, filas in copias.items():
        with open(carpeta / 'copias' / ('%s.csv' % etiquetador), 'w', encoding='utf-8-sig', newline='') as f:
            w = csv.DictWriter(f, fieldnames=COLUMNAS_COPIA)
            w.writeheader()
            w.writerows(fila_copia(h) for h in filas)


def resumen(maestro, copias):
    """Líneas para la terminal: tamaño, clases esperadas, bloque común y reparto."""
    por_clase = {c: sum(h['clase_esperada'] == c for h in maestro) for c in CLASES}
    comun = sum(h['bloque'] == 'comun' for h in maestro)
    prueba = sum(h['particion'] == 'prueba' for h in maestro)
    return ['%d hallazgos de %d plantillas. Clase esperada: %s.' % (
                len(maestro), len(PLANTILLAS), ', '.join('%s %d' % kv for kv in por_clase.items())),
            'Bloque común: %d. Prueba: %d, entrenamiento: %d.' % (comun, prueba, len(maestro) - prueba),
            'Copias: %s.' % ', '.join('%s %d' % (e, len(f)) for e, f in copias.items())]


def _main(argv=None):
    if (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    p = argparse.ArgumentParser(description='Genera el lote semisintético del ML (#33) con semilla fija')
    p.add_argument('--salida', default=str(CARPETA), help='carpeta de salida (por defecto datos/ml/rc65/)')
    p.add_argument('--semilla', type=int, default=SEMILLA)
    a = p.parse_args(argv)
    maestro, copias = generar(a.semilla)
    escribir(a.salida, maestro, copias)
    print('\n'.join(resumen(maestro, copias)))
    return 0


if __name__ == '__main__':
    sys.exit(_main())
