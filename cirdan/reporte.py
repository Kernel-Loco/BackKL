"""Reporte ejecutivo de un dominio (#45, RC-70): 1 a 2 páginas para directivos, en JSON y en HTML.

El portal arma el PDF con el JSON de GET /api/v1/domains/{fqdn}/report y el HTML sale de este mismo
diccionario, así que los dos traen las mismas cifras, los mismos hallazgos y las mismas atribuciones.
Aquí no se lee la base: la ruta junta los datos (con la carta vigente revisada) y este módulo solo arma.
"""
from datetime import date, datetime
from html import escape
from zoneinfo import ZoneInfo

SEVERIDADES = ('critical', 'high', 'medium', 'low')
CATEGORIAS = ('infrastructure', 'digital_identity', 'configuration', 'data_leaks')

# El HTML no trae scripts, imágenes ni hojas externas: solo su <style>. frame-ancestors va igual que en el resto de la API.
CSP_HTML = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

# Para que quepa en 2 páginas: los más severos, con la primera frase de qué hacer. Los conteos sí cuentan todos.
MAX_HALLAZGOS = 8
MAX_ACCION = 220
# El título y el activo no tienen tope en el contrato. Con estos topes 8 hallazgos caben en 2 páginas (RC-70).
MAX_TITULO = 160
MAX_ACTIVO = 120

# La misma zona que la base (db.py) y el portal: el contenedor de la API corre en UTC.
ZONA = ZoneInfo('America/Mexico_City')

ETIQUETA_SEVERIDAD = {'critical': 'Crítico', 'high': 'Alto', 'medium': 'Medio', 'low': 'Bajo'}
ETIQUETA_CATEGORIA = {'infrastructure': 'Infraestructura', 'digital_identity': 'Identidad digital',
                      'configuration': 'Configuración', 'data_leaks': 'Fugas de datos'}
ETIQUETA_BANDA = {'low': 'Bajo', 'medium': 'Medio', 'high': 'Alto', 'critical': 'Crítico'}
# Las de SOURCE_LABELS del portal (FrontKL src/config/labels.ts). Una fuente sin etiqueta sale con su código.
ETIQUETA_FUENTE = {'ct_logs': 'crt.sh', 'dns': 'DNS', 'whois': 'WHOIS', 'shodan': 'Shodan', 'github': 'GitHub',
                   'censys': 'Censys', 'hibp': 'HIBP API'}

# La misma atribución de NOTICE. Va siempre: la categoría de fugas de datos sale de HIBP aunque hoy no haya
# hallazgos suyos, y su licencia (CC BY 4.0) pide nombrar la fuente donde se muestran sus datos.
ATRIBUCIONES = (
    {'source': 'hibp', 'name': 'Have I Been Pwned',
     'text': 'Los datos de exposición en brechas provienen de Have I Been Pwned (https://haveibeenpwned.com), '
             'de Troy Hunt, bajo la licencia CC BY 4.0. LowTide solo guarda el hecho de la exposición, '
             'nunca contraseñas ni otros datos filtrados.',
     'url': 'https://haveibeenpwned.com', 'license_url': 'https://creativecommons.org/licenses/by/4.0/'},
)


def tope(texto, maximo):
    """El texto en una línea, con tope de `maximo` caracteres (el último es '…')."""
    texto = ' '.join((texto or '').split())
    if len(texto) > maximo:
        texto = texto[:maximo - 1].rstrip() + '…'
    return texto


def accion_corta(texto):
    """Primera frase de la recomendación, con tope de MAX_ACCION caracteres."""
    texto = ' '.join((texto or '').split())
    corte = texto.find('. ')
    if corte != -1:
        texto = texto[:corte + 1]
    return tope(texto, MAX_ACCION)


def activo(h):
    """El activo como sale del reporte. Un correo sale solo con su dominio, como la salida a SIEM, que lo anula
    (v1.py, SIEM_FINDINGS_SQL): el reporte es un documento para salir de la plataforma (README, recolector de GitHub)."""
    valor = h.get('asset') or ''
    if h.get('asset_type') == 'email':
        valor = 'Correo de %s' % valor.rpartition('@')[2] if '@' in valor else 'Correo'
    return tope(valor, MAX_ACTIVO)


def armar(dominio, organizacion, autorizacion, score, ultimo_escaneo, hallazgos, recomendaciones, generado=None):
    """hallazgos: los de GET /findings, ya ordenados de más a menos severo. recomendaciones: {código de regla: texto}."""
    por_severidad = {s: 0 for s in SEVERIDADES}
    por_categoria = {c: 0 for c in CATEGORIAS}
    for h in hallazgos:
        por_severidad[h['severity']] = por_severidad.get(h['severity'], 0) + 1
        por_categoria[h['category']] = por_categoria.get(h['category'], 0) + 1
    principales = [{
        'title': tope(h['title'], MAX_TITULO), 'severity': h['severity'], 'category': h['category'], 'asset': activo(h),
        'source': h['source'], 'detected_at': h['detected_at'], 'recurrence': h['recurrence'],
        'action': accion_corta(recomendaciones.get(h['rule_code'])),
    } for h in hallazgos[:MAX_HALLAZGOS]]
    return {
        'domain': dominio, 'organization': organizacion,
        'generated_at': generado or datetime.now(ZONA),
        'authorization': autorizacion, 'score': score, 'last_scan_at': ultimo_escaneo,
        'open_findings': por_severidad, 'by_category': por_categoria, 'total_open': len(hallazgos),
        'findings': principales, 'findings_omitted': max(0, len(hallazgos) - MAX_HALLAZGOS),
        'attributions': [dict(a) for a in ATRIBUCIONES],
    }


def _fecha(valor):
    if valor is None:
        return 'Sin fecha'
    if isinstance(valor, str):
        valor = datetime.fromisoformat(valor) if 'T' in valor else date.fromisoformat(valor)
    return valor.strftime('%d/%m/%Y')


def _e(valor):
    return escape('' if valor is None else str(valor), quote=True)


def lectura(r):
    """Las mismas frases de 'Lectura ejecutiva' en el PDF y en el HTML."""
    if r['total_open'] == 0:
        return ['El dominio no tiene hallazgos abiertos.']
    altos = r['open_findings']['critical'] + r['open_findings']['high']
    frases = [
        ('%d %s prioridad de remediación.' % (altos, 'hallazgo crítico o alto sigue abierto y requiere' if altos == 1
                                               else 'hallazgos críticos o altos siguen abiertos y requieren'))
        if altos else 'No hay hallazgos críticos o altos abiertos.',
    ]
    cat = max(CATEGORIAS, key=lambda c: r['by_category'].get(c, 0))
    frases.append('%s es la categoría con más hallazgos abiertos (%d).' % (ETIQUETA_CATEGORIA[cat], r['by_category'][cat]))
    nuevos = sum(1 for h in r['findings'] if h['recurrence'] == 'new')
    if r['findings_omitted'] == 0:
        # recurrence se calcula contra el último escaneo de cada hallazgo (FINDINGS_SQL), no el del dominio.
        frases.append('%d de los %d hallazgos abiertos son nuevos en el escaneo más reciente que los revisó.'
                      % (nuevos, r['total_open']))
    return frases


def html(r):
    """El reporte como página HTML sola, sin scripts ni recursos externos. Todo valor va escapado."""
    s = r['score']
    if s:
        score = '%s, letra %s (%s)' % (s['score'], s['grade'], ETIQUETA_BANDA.get(s['band'], s['band']))
        if s['partial_coverage']:
            score += ' · Cobertura parcial: el score y su letra pueden estar incompletos.'
    else:
        score = 'Sin score todavía'
    a = r['authorization'] or {}
    indicadores = [
        ('Score y letra', score),
        ('Hallazgos abiertos', r['total_open']),
        ('Críticos / altos abiertos', r['open_findings']['critical'] + r['open_findings']['high']),
        ('Último escaneo', _fecha(r['last_scan_at'])),
        ('Autorización vigente', '%s a %s' % (_fecha(a.get('valid_from')), _fecha(a.get('valid_until')))),
    ]
    filas_ind = ''.join('<tr><th scope="row">%s</th><td>%s</td></tr>' % (_e(k), _e(v)) for k, v in indicadores)
    filas_dist = ''.join('<tr><td>%s</td><td>%d</td><td>%s</td><td>%d</td></tr>' % (
        _e(ETIQUETA_SEVERIDAD[sv]), r['open_findings'][sv], _e(ETIQUETA_CATEGORIA[c]), r['by_category'][c])
        for sv, c in zip(SEVERIDADES, CATEGORIAS))
    if r['findings']:
        filas_h = ''.join(
            '<tr><td>%s</td><td><strong>%s</strong><br>Activo: %s<br>Fuente: %s</td><td>%s</td><td>%s</td></tr>' % (
                _e(ETIQUETA_SEVERIDAD.get(h['severity'], h['severity'])), _e(h['title']), _e(h['asset']),
                _e(ETIQUETA_FUENTE.get(h['source'], h['source'])), _e(_fecha(h['detected_at'])), _e(h['action']))
            for h in r['findings'])
    else:
        filas_h = '<tr><td colspan="4">El dominio no tiene hallazgos abiertos.</td></tr>'
    omitidos = ''
    if r['findings_omitted']:
        omitidos = ('<p class="nota">Y %d hallazgos abiertos más, de menor severidad. La lista completa está en la '
                    'exportación de hallazgos del portal.</p>' % r['findings_omitted'])
    atrib = ''.join('<p class="nota">%s Licencia: <a href="%s">%s</a>.</p>' % (
        _e(x['text']), _e(x['license_url']), _e(x['license_url'])) for x in r['attributions'])
    return '''<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Resumen ejecutivo de riesgo · %(dominio)s · LowTide</title>
<style>
@page { size: A4; margin: 14mm; }
body { font-family: Helvetica, Arial, sans-serif; color: #1c2230; background: #fff; font-size: 10pt; max-width: 182mm; margin: 0 auto; }
h1 { font-size: 18pt; margin: 0 0 2mm; } h2 { font-size: 11pt; margin: 6mm 0 2mm; }
.meta, .nota { color: #596579; font-size: 8.5pt; }
table { width: 100%%; border-collapse: collapse; font-size: 8.5pt; }
th, td { border: 1px solid #e8ebf1; padding: 1.8mm; text-align: left; vertical-align: top; }
thead th { background: #18274b; color: #fff; }
tr { break-inside: avoid; }
</style>
</head>
<body>
<h1>Resumen ejecutivo de riesgo</h1>
<p class="meta">Dominio: %(dominio)s · Empresa: %(org)s · Generado: %(generado)s</p>
<h2>Indicadores clave</h2>
<table>%(ind)s</table>
<h2>Lectura ejecutiva</h2>
<ul>%(lectura)s</ul>
<h2>Hallazgos abiertos por severidad y categoría</h2>
<table><thead><tr><th scope="col">Severidad</th><th scope="col">Cantidad</th><th scope="col">Categoría</th><th scope="col">Cantidad</th></tr></thead>
<tbody>%(dist)s</tbody></table>
<h2>Hallazgos principales y acción recomendada</h2>
<table><thead><tr><th scope="col">Severidad</th><th scope="col">Hallazgo</th><th scope="col">Detectado</th><th scope="col">Acción recomendada</th></tr></thead>
<tbody>%(hallazgos)s</tbody></table>
%(omitidos)s
<h2>Fuentes y atribuciones</h2>
%(atrib)s
<p class="nota">LowTide · Confidencial. Solo observación pasiva de fuentes públicas, con autorización firmada del dominio.</p>
</body>
</html>
''' % {'dominio': _e(r['domain']), 'org': _e(r['organization']), 'generado': _e(_fecha(r['generated_at'])),
       'ind': filas_ind, 'lectura': ''.join('<li>%s</li>' % _e(f) for f in lectura(r)), 'dist': filas_dist,
       'hallazgos': filas_h, 'omitidos': omitidos, 'atrib': atrib}
