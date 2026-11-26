"""Medición de cobertura y falsos positivos de un escaneo de olmardo.com (#84, RC-143).

Aplica el método de docs/medicion_cobertura.md a un escaneo terminado:

- **Detección por fuente**: cada caso esperado de docs/hallazgos_esperados.md (#10b) cuenta como verdadero positivo
  (VP) si el escaneo lo vio en su activo, como falso negativo (FN) si la fuente corrió completa y no lo vio, y como no
  evaluable si la fuente no corrió, falló o quedó parcial, o si el caso ya no está vigente. La proporción detectada es
  VP / (VP + FN); sin casos evaluables es `None` (no evaluable), nunca 0.
- **Falsos positivos**: de los hallazgos del dominio que alguien revisó con el triage (#80, RC-133), los marcados
  `false_positive` entre todos los revisados (`resolved`, `accepted_risk` y `false_positive`): FP / (VP + FP), la
  proporción de falsos entre alertas revisadas. Sin revisados es no evaluable.
- **Inesperados**: lo que el escaneo vio y no está en la lista. Son posibles falsos positivos para revisar a mano, no
  errores confirmados.

Sin base ni red, `medir()` trabaja con listas. La línea de comandos lee el último escaneo terminado de la base, como
cirdan_app con RLS de la empresa, y no lanza escaneos:

    docker compose exec api python -m cirdan.medicion                 # olmardo.com, último escaneo terminado
    docker compose exec api python -m cirdan.medicion --scan <uuid>   # uno en particular

La salida es Markdown para pegar en docs/medicion_cobertura.md y en el deck (#59b).
"""
import argparse
import re
import sys
from dataclasses import dataclass
from datetime import date

ORG_OLMARDO = '20000000-0000-4000-8000-000000000003'   # db/semillas/002_dominio_prueba.sql
DOMINIO = 'olmardo.com'


@dataclass(frozen=True)
class Esperado:
    fila: int            # fila de docs/hallazgos_esperados.md
    fuente: str          # data_sources.code
    codigo: str          # regla del catálogo
    activo: str          # expresión regular sobre assets.value
    descripcion: str
    hasta: date | None = None   # último día en que el caso es vigente (fila 5: el certificado venció el 31 oct)
    requiere: str | None = None  # condición fuera del escaneo, solo informativa


# Los casos con código de la lista por fuente de docs/hallazgos_esperados.md. Las filas sin código (activos o nada)
# no son casos de detección: si sale un hallazgo de ellas, aparece entre los inesperados.
ESPERADOS = (
    Esperado(3, 'ct_logs', 'cert_broad_wildcard', r'^olmardo\.com$', 'Comodines de Cloudflare'),
    Esperado(5, 'ct_logs', 'cert_expiring_soon', r'^eventos\.olmardo\.com$', 'Certificado de vida corta de eventos',
             hasta=date(2026, 10, 31)),
    Esperado(6, 'dns', 'dmarc_missing', r'^olmardo\.com$', 'Sin _dmarc'),
    Esperado(8, 'github', 'secret_in_public_repo', r'olmardo', 'Token falso CIRDAN_FAKE_ en el repo público'),
    Esperado(9, 'github', 'email_in_public_commits', r'@olmardo\.com$', 'Correo @olmardo.com en los commits'),
    Esperado(10, 'shodan', 'exposed_service', r':8080/tcp$', 'Cámara IP en el 8080'),
    Esperado(11, 'shodan', 'exposed_iot_device', r'.', 'La cámara como dispositivo IoT',
             requiere='la API de host de Shodan o su respuesta grabada'),
    Esperado(12, 'web', 'server_version_disclosed', r'^reservas\.olmardo\.com', 'Cabecera Server con versión'),
)

REVISADOS = ('resolved', 'accepted_risk', 'false_positive')


def _proporcion(numerador, denominador):
    return round(100 * numerador / denominador, 1) if denominador else None


def medir(hallazgos, corridas, fecha_escaneo, esperados=ESPERADOS):
    """La medición de un escaneo.

    `hallazgos`: dicts con rule_code, asset, source y status (todos los del dominio que tocó el escaneo).
    `corridas`: {fuente: estado de scan_source_runs}; 'succeeded' es la única que permite contar un FN.
    `fecha_escaneo`: date del escaneo, para la vigencia de cada caso.
    """
    casos = []
    for esperado in esperados:
        visto = any(h['rule_code'] == esperado.codigo and h['source'] == esperado.fuente
                    and re.search(esperado.activo, h['asset'] or '') for h in hallazgos)
        if visto:
            resultado = 'VP'
        elif esperado.hasta and fecha_escaneo > esperado.hasta:
            resultado = 'fuera de vigencia'
        elif corridas.get(esperado.fuente) != 'succeeded':
            resultado = 'sin cobertura (%s)' % (corridas.get(esperado.fuente) or 'no corrió')
        else:
            resultado = 'FN'
        casos.append({'esperado': esperado, 'resultado': resultado})

    por_fuente = {}
    for caso in casos:
        fuente = por_fuente.setdefault(caso['esperado'].fuente, {'VP': 0, 'FN': 0, 'no_evaluables': 0})
        clave = caso['resultado'] if caso['resultado'] in ('VP', 'FN') else 'no_evaluables'
        fuente[clave] += 1
    for fuente in por_fuente.values():
        fuente['detectado_pct'] = _proporcion(fuente['VP'], fuente['VP'] + fuente['FN'])
    vp = sum(f['VP'] for f in por_fuente.values())
    fn = sum(f['FN'] for f in por_fuente.values())

    revisados = [h for h in hallazgos if h['status'] in REVISADOS]
    falsos = sum(1 for h in revisados if h['status'] == 'false_positive')
    claves = {(e.codigo, e.fuente) for e in esperados}
    inesperados = sorted({(h['source'], h['rule_code'], h['asset']) for h in hallazgos
                          if (h['rule_code'], h['source']) not in claves})
    return {
        'casos': casos,
        'por_fuente': dict(sorted(por_fuente.items())),
        'total': {'VP': vp, 'FN': fn, 'no_evaluables': sum(f['no_evaluables'] for f in por_fuente.values()),
                  'detectado_pct': _proporcion(vp, vp + fn)},
        'falsos_positivos': {'revisados': len(revisados), 'falsos': falsos,
                             'proporcion_pct': _proporcion(falsos, len(revisados))},
        'inesperados': inesperados,
    }


def _pct(valor):
    return 'no evaluable' if valor is None else ('%s %%' % valor).replace('.', ',')


def markdown(m, dominio, escaneo):
    """La medición como Markdown, con el escaneo del que sale."""
    lineas = [
        '### Medición del escaneo %s de %s (%s, %s)' % (escaneo['id'], dominio, escaneo['fecha'], escaneo['status']),
        '',
        '| Fila | Fuente | Código esperado | Resultado |',
        '|---:|---|---|---|',
    ]
    for caso in m['casos']:
        e = caso['esperado']
        nota = ' (requiere %s)' % e.requiere if e.requiere and caso['resultado'] != 'VP' else ''
        lineas.append('| %d | %s | `%s` | %s%s |' % (e.fila, e.fuente, e.codigo, caso['resultado'], nota))
    lineas += ['', '| Fuente | VP | FN | No evaluables | Detectado |', '|---|---:|---:|---:|---:|']
    for fuente, f in m['por_fuente'].items():
        lineas.append('| %s | %d | %d | %d | %s |' % (fuente, f['VP'], f['FN'], f['no_evaluables'],
                                                     _pct(f['detectado_pct'])))
    t = m['total']
    lineas.append('| **Total** | **%d** | **%d** | **%d** | **%s** |' % (t['VP'], t['FN'], t['no_evaluables'],
                                                                     _pct(t['detectado_pct'])))
    fp = m['falsos_positivos']
    lineas += ['', '**Falsos positivos entre alertas revisadas:** %s (%d de %d revisados con el triage).'
               % (_pct(fp['proporcion_pct']), fp['falsos'], fp['revisados'])]
    if m['inesperados']:
        lineas += ['', '**Hallazgos fuera de la lista** (posibles falsos positivos, revisar a mano):', '']
        lineas += ['- %s · `%s` · %s' % fila for fila in m['inesperados']]
    return '\n'.join(lineas) + '\n'


def leer(conn, dominio, scan_id=None):
    """El escaneo (el último terminado si no se da uno), sus corridas por fuente y los hallazgos del dominio."""
    escaneo = conn.execute(
        "SELECT s.id::text, s.status, (coalesce(s.finished_at, s.queued_at) AT TIME ZONE 'America/Mexico_City')::date "
        "AS fecha FROM scans s JOIN domains d ON d.id = s.domain_id WHERE d.fqdn = %s "
        "AND s.status IN ('completed', 'partial') AND (%s::uuid IS NULL OR s.id = %s::uuid) "
        'ORDER BY s.finished_at DESC NULLS LAST LIMIT 1', (dominio, scan_id, scan_id)).fetchone()
    if not escaneo:
        return None, {}, []
    corridas = {f['code']: f['status'] for f in conn.execute(
        'SELECT ds.code, r.status FROM scan_source_runs r JOIN data_sources ds ON ds.id = r.source_id '
        'WHERE r.scan_id = %s', (escaneo['id'],))}
    hallazgos = conn.execute(
        'SELECT r.code AS rule_code, a.value AS asset, ds.code AS source, f.status FROM findings f '
        'JOIN domains d ON d.id = f.domain_id JOIN scoring_rules r ON r.id = f.rule_id '
        'JOIN assets a ON a.id = f.asset_id JOIN data_sources ds ON ds.id = f.source_id WHERE d.fqdn = %s',
        (dominio,)).fetchall()
    return escaneo, corridas, hallazgos


def main(argv=None):
    parser = argparse.ArgumentParser(description='Cobertura y falsos positivos de un escaneo de olmardo.com (#84).')
    parser.add_argument('--dominio', default=DOMINIO)
    parser.add_argument('--org', default=ORG_OLMARDO, help='empresa del dominio, para RLS')
    parser.add_argument('--scan', help='id del escaneo; por omisión el último terminado')
    args = parser.parse_args(argv)
    from cirdan.db import transaction   # solo aquí: medir() y las pruebas no piden base
    with transaction(args.org) as conn:
        escaneo, corridas, hallazgos = leer(conn, args.dominio, args.scan)
    if not escaneo:
        print('No hay un escaneo terminado de %s: no hay nada que medir.' % args.dominio, file=sys.stderr)
        return 1
    sys.stdout.write(markdown(medir(hallazgos, corridas, escaneo['fecha']), args.dominio, escaneo))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
