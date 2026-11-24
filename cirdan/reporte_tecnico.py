"""Reporte técnico de un dominio (#46, RC-81): el detalle de cada hallazgo y su remediación, en JSON y en HTML.

Es la segunda plantilla del generador de #45 (cirdan/reporte.py): parte del mismo diccionario del ejecutivo, así los
dos traen las mismas cifras, el mismo score y la misma atribución de HIBP. A eso le suma, para el equipo técnico:
- cada hallazgo abierto con su regla, severidad base, CVE, CVSS, EPSS, KEV, evidencia y qué hacer completo;
- las remediaciones agrupadas por regla, con los activos que toca cada una;
- la cobertura del último escaneo: qué fuentes respondieron y cuáles no;
- el control ISO 27001 y la salvaguarda CIS de cada hallazgo (RC-160).
El portal arma el PDF con el JSON de GET /api/v1/domains/{fqdn}/report/technical y el HTML sale de aquí.
Como el ejecutivo, no lee la base y sale de la plataforma: un correo va solo con su dominio, también en la evidencia.
"""
import json
import re

from cirdan import reporte
from cirdan.reporte import ETIQUETA_CATEGORIA, ETIQUETA_FUENTE, ETIQUETA_SEVERIDAD, _e, _fecha, tope

# Más allá de esto la lista completa está en la exportación de hallazgos (CSV o JSON). Los conteos cuentan todos.
MAX_HALLAZGOS = 200
MAX_TITULO = 300
MAX_CLAVES = 12  # claves de evidencia por hallazgo
MAX_VALOR = 300  # caracteres por valor de evidencia
MAX_ACTIVOS = 10  # activos listados por remediación

CORREO = re.compile(r'[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})')

ETIQUETA_ESTADO_FUENTE = {'succeeded': 'Respondió', 'failed': 'Falló', 'retrying': 'Reintentando',
                          'pending': 'Pendiente', 'running': 'En curso'}
ETIQUETA_RECURRENCIA = {'new': 'Nuevo', 'recurring': 'Recurrente'}


def sin_correos(texto):
    """Cada correo del texto queda como …@dominio."""
    return CORREO.sub(lambda m: '…@' + m.group(1), texto)


def evidencia(ev):
    """La evidencia como pares {key, value} de texto, sin vacíos, con topes y sin correos completos."""
    pares = []
    for clave in sorted(ev or {}):
        valor = ev[clave]
        if valor is None or valor == '' or valor == [] or valor == {}:
            continue
        if isinstance(valor, (list, dict)):
            valor = json.dumps(valor, ensure_ascii=False, sort_keys=True, default=str)
        elif isinstance(valor, bool):
            valor = 'sí' if valor else 'no'
        pares.append({'key': str(clave), 'value': tope(sin_correos(str(valor)), MAX_VALOR)})
    return pares[:MAX_CLAVES]


def _detalle(h, textos):
    texto = textos.get(h['rule_code']) or {}
    return {
        'id': h['id'], 'title': tope(sin_correos(h['title'] or ''), MAX_TITULO), 'severity': h['severity'],
        'base_severity': h.get('base_severity'), 'category': h['category'], 'rule_code': h['rule_code'],
        'asset': reporte.activo(h), 'asset_type': h.get('asset_type'), 'source': h['source'],
        'detected_at': h['detected_at'], 'recurrence': h['recurrence'], 'last_scan_id': h.get('last_scan_id'),
        'cve_id': h.get('cve_id'), 'cvss': h.get('cvss'), 'epss': h.get('epss'), 'in_kev': h.get('in_kev'),
        'evidence': evidencia(h.get('evidence')), 'frameworks': reporte.marcos(h),
        'meaning': ' '.join((texto.get('meaning') or '').split()),
        'recommendation': ' '.join((texto.get('recommendation') or '').split()),
    }


def remediaciones(hallazgos, textos):
    """Una por regla, en el orden del hallazgo más severo de cada una (los hallazgos ya vienen ordenados)."""
    por_regla = {}
    for h in hallazgos:
        r = por_regla.get(h['rule_code'])
        if r is None:
            texto = textos.get(h['rule_code']) or {}
            r = por_regla[h['rule_code']] = {
                'rule_code': h['rule_code'], 'title': texto.get('title') or h['rule_code'], 'severity': h['severity'],
                'category': h['category'], 'count': 0, 'assets': [],
                'recommendation': ' '.join((texto.get('recommendation') or '').split()),
            }
        r['count'] += 1
        a = reporte.activo(h)
        if a not in r['assets']:
            r['assets'].append(a)
    for r in por_regla.values():
        r['assets_omitted'] = max(0, len(r['assets']) - MAX_ACTIVOS)
        r['assets'] = r['assets'][:MAX_ACTIVOS]
    return list(por_regla.values())


def armar(dominio, organizacion, autorizacion, score, ultimo_escaneo, hallazgos, textos, fuentes, generado=None):
    """hallazgos: los de GET /findings, de más a menos severo. textos: {código: {title, meaning, recommendation}}.
    fuentes: las corridas del último escaneo, [{source, status, attempt, finished_at}]."""
    r = reporte.armar(dominio, organizacion, autorizacion, score, ultimo_escaneo, hallazgos,
                      {c: t.get('recommendation') for c, t in textos.items()}, generado)
    r.update(
        kind='technical',
        findings=[_detalle(h, textos) for h in hallazgos[:MAX_HALLAZGOS]],
        findings_omitted=max(0, len(hallazgos) - MAX_HALLAZGOS),
        remediations=remediaciones(hallazgos, textos),
        sources=[{'source': f['source'], 'status': f['status'], 'attempt': f.get('attempt'),
                  'finished_at': f.get('finished_at')} for f in fuentes],
    )
    return r


def _bloque_hallazgo(i, h):
    campos = [
        ('Severidad', '%s (base: %s)' % (ETIQUETA_SEVERIDAD.get(h['severity'], h['severity']),
                                         ETIQUETA_SEVERIDAD.get(h['base_severity'], h['base_severity'] or '—'))),
        ('Categoría', ETIQUETA_CATEGORIA.get(h['category'], h['category'])),
        ('Regla', h['rule_code']),
        ('Activo', '%s (%s)' % (h['asset'], h['asset_type'] or '—')),
        ('Fuente', ETIQUETA_FUENTE.get(h['source'], h['source'])),
        ('Detectado', '%s · %s' % (_fecha(h['detected_at']), ETIQUETA_RECURRENCIA.get(h['recurrence'], h['recurrence']))),
    ]
    if h['cve_id']:
        kev = {True: 'sí', False: 'no', None: 'sin dato'}[h['in_kev']]
        campos.append(('Vulnerabilidad', '%s · CVSS %s · EPSS %s · En KEV: %s' % (
            h['cve_id'], h['cvss'] if h['cvss'] is not None else '—',
            '%.1f %%' % (h['epss'] * 100) if h['epss'] is not None else '—', kev)))
    campos += [('Evidencia · %s' % p['key'], p['value']) for p in h['evidence']]
    # El control ISO y la salvaguarda CIS de la regla (RC-160). Sin mapeo no se inventa la fila.
    campos += [(k, v) for k, v in (('ISO/IEC 27001:2022', reporte.marco_iso(h.get('frameworks'))),
                                   ('CIS Controls v8.1', reporte.marco_cis(h.get('frameworks')))) if v]
    campos += [('Qué significa', h['meaning'] or '—'), ('Remediación', h['recommendation'] or '—')]
    filas = ''.join('<tr><th scope="row">%s</th><td>%s</td></tr>' % (_e(k), _e(v)) for k, v in campos)
    return '<section class="hallazgo"><h3>%d. %s</h3><table>%s</table></section>' % (i, _e(h['title']), filas)


def html(r):
    """El reporte técnico como página HTML sola, sin scripts ni recursos externos. Todo valor va escapado."""
    if r['sources']:
        filas_f = ''.join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
            _e(ETIQUETA_FUENTE.get(f['source'], f['source'])), _e(ETIQUETA_ESTADO_FUENTE.get(f['status'], f['status'])),
            _e(f['attempt'] if f['attempt'] is not None else '—'), _e(_fecha(f['finished_at'])))
            for f in r['sources'])
    else:
        filas_f = '<tr><td colspan="4">El dominio no tiene escaneos todavía.</td></tr>'
    if r['remediations']:
        filas_r = ''.join('<tr><td>%s</td><td><strong>%s</strong><br>Regla: %s</td><td>%d</td><td>%s%s</td><td>%s</td></tr>' % (
            _e(ETIQUETA_SEVERIDAD.get(x['severity'], x['severity'])), _e(x['title']), _e(x['rule_code']), x['count'],
            _e(', '.join(x['assets'])), _e(' y %d más' % x['assets_omitted']) if x['assets_omitted'] else '',
            _e(x['recommendation'] or '—')) for x in r['remediations'])
    else:
        filas_r = '<tr><td colspan="5">El dominio no tiene hallazgos abiertos.</td></tr>'
    detalle = ''.join(_bloque_hallazgo(i, h) for i, h in enumerate(r['findings'], 1)) or \
        '<p>El dominio no tiene hallazgos abiertos.</p>'
    omitidos = ''
    if r['findings_omitted']:
        omitidos = ('<p class="nota">Y %d hallazgos abiertos más, de menor severidad. La lista completa está en la '
                    'exportación de hallazgos del portal.</p>' % r['findings_omitted'])
    return '''<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reporte técnico · %(dominio)s · LowTide</title>
<style>
@page { size: A4; margin: 14mm; }
body { font-family: Helvetica, Arial, sans-serif; color: #1c2230; background: #fff; font-size: 10pt; max-width: 182mm; margin: 0 auto; }
h1 { font-size: 18pt; margin: 0 0 2mm; } h2 { font-size: 11pt; margin: 6mm 0 2mm; } h3 { font-size: 10pt; margin: 4mm 0 1.5mm; }
.meta, .nota { color: #596579; font-size: 8.5pt; }
table { width: 100%%; border-collapse: collapse; font-size: 8.5pt; }
th, td { border: 1px solid #e8ebf1; padding: 1.8mm; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
thead th { background: #18274b; color: #fff; }
.hallazgo th { width: 32%%; background: #f5f7fa; font-weight: 600; }
tr, .hallazgo { break-inside: avoid; }
</style>
</head>
<body>
<h1>Reporte técnico de riesgo</h1>
<p class="meta">Dominio: %(dominio)s · Empresa: %(org)s · Generado: %(generado)s</p>
<h2>Indicadores clave</h2>
<table>%(ind)s</table>
<h2>Lectura</h2>
<ul>%(lectura)s</ul>
<h2>Hallazgos abiertos por severidad y categoría</h2>
<table><thead><tr><th scope="col">Severidad</th><th scope="col">Cantidad</th><th scope="col">Categoría</th><th scope="col">Cantidad</th></tr></thead>
<tbody>%(dist)s</tbody></table>
<h2>Cobertura del último escaneo</h2>
<table><thead><tr><th scope="col">Fuente</th><th scope="col">Estado</th><th scope="col">Intentos</th><th scope="col">Terminó</th></tr></thead>
<tbody>%(fuentes)s</tbody></table>
<h2>Remediaciones por regla</h2>
<table><thead><tr><th scope="col">Severidad</th><th scope="col">Regla</th><th scope="col">Hallazgos</th><th scope="col">Activos</th><th scope="col">Remediación</th></tr></thead>
<tbody>%(remediaciones)s</tbody></table>
<h2>Detalle de hallazgos</h2>
%(detalle)s
%(omitidos)s
<h2>Fuentes y atribuciones</h2>
%(atrib)s
<p class="nota">Los correos van solo con su dominio. La evidencia nunca trae secretos ni contraseñas: solo dónde están.</p>
<p class="nota">LowTide · Confidencial. Solo observación pasiva de fuentes públicas, con autorización firmada del dominio.</p>
</body>
</html>
''' % {'dominio': _e(r['domain']), 'org': _e(r['organization']), 'generado': _e(_fecha(r['generated_at'])),
       'ind': reporte._filas_indicadores(r), 'lectura': ''.join('<li>%s</li>' % _e(f) for f in reporte.lectura(r)),
       'dist': reporte._filas_distribucion(r), 'fuentes': filas_f, 'remediaciones': filas_r, 'detalle': detalle,
       'omitidos': omitidos, 'atrib': reporte._atribuciones(r)}
