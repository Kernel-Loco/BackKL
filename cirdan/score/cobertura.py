"""Códigos de regla que el escaneo de un score no revisó, con su motivo (RC-229).

Es una vista al leer, como subcategorias.py: no cambia el cálculo ni la base. Sale de las corridas de
`scan_source_runs` del escaneo del score y de `rules_without_coverage` de `scans.stats`. Cada código va con la fuente
que no lo revisó y el motivo:
- 'source_failed': la fuente corrió y no terminó 'succeeded'. Ninguno de sus códigos se revisó.
- 'source_not_run': la fuente tiene recolector pero no corrió en ese escaneo, porque está apagada en `data_sources`
  o porque aún no existía. Ninguno de sus códigos se revisó.
- 'no_api_key': un código de shodan.SIN_LLAVE que Shodan no revisó porque falta la API de host.
- 'source_partial': la fuente respondió pero no pudo revisar ese código (su `sin_cobertura`).

La lista de cada fuente sale de `raw_payload->'sin_cobertura'` de su corrida. Una fuente con keep_raw_payload en
false (GitHub) no lo guarda: sus códigos de `rules_without_coverage` se le dan por su CODIGOS. Un código de
`rules_without_coverage` que no se puede atribuir va con la fuente en None. Sin corridas (un escaneo sembrado) no hay
de dónde sacarlo y la lista sale vacía.
"""
from cirdan.recolectores import REGISTRO, cargar, shodan

FUENTE_PRUEBAS = 'ejemplo'
MOTIVOS = ('source_failed', 'source_not_run', 'no_api_key', 'source_partial')


def codigos_de(fuente):
    """Los códigos de regla que revisa el recolector de una fuente. Una fuente sin recolector no revisa ninguno."""
    try:
        return tuple(cargar(fuente).CODIGOS)
    except KeyError:
        return ()


def _motivo_parcial(fuente, codigo):
    return 'no_api_key' if fuente == 'shodan' and codigo in shodan.SIN_LLAVE else 'source_partial'


def huecos(corridas, sin_cobertura=(), codigos=codigos_de):
    """[{code, source, reason}] ordenada por código y fuente.

    `corridas`: las de `scan_source_runs` del escaneo, cada una con source, status y sin_cobertura (la lista de su
    raw_payload, o None si no la guardó). `sin_cobertura`: `rules_without_coverage` de `scans.stats`.
    """
    if not corridas:
        return []
    motivos = {}
    for r in corridas:
        if r['status'] != 'succeeded':
            for c in codigos(r['source']):
                motivos.setdefault((c, r['source']), 'source_failed')
    corrieron = {r['source'] for r in corridas}
    for fuente in REGISTRO:
        if fuente != FUENTE_PRUEBAS and fuente not in corrieron:
            for c in codigos(fuente):
                motivos.setdefault((c, fuente), 'source_not_run')
    sin_lista = []
    for r in corridas:
        if r['status'] != 'succeeded':
            continue
        if r.get('sin_cobertura') is None:
            sin_lista.append(r['source'])
            continue
        for c in r['sin_cobertura']:
            motivos.setdefault((c, r['source']), _motivo_parcial(r['source'], c))
    atribuidos = {c for (c, _), m in motivos.items() if m in ('no_api_key', 'source_partial')}
    for c in sin_cobertura:
        if c in atribuidos:
            continue
        for fuente in [f for f in sin_lista if c in codigos(f)] or [None]:
            motivos.setdefault((c, fuente), _motivo_parcial(fuente, c))
    return [{'code': c, 'source': f, 'reason': m}
            for (c, f), m in sorted(motivos.items(), key=lambda kv: (kv[0][0], kv[0][1] or ''))]
