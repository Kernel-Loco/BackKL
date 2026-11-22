"""Códigos de regla que el escaneo de un score no revisó, con su motivo (RC-229).

Es una vista al leer, como subcategorias.py: no cambia el cálculo ni la base. Sale de las corridas de
`scan_source_runs` del escaneo del score y de `rules_without_coverage` y `sources_partial` de `scans.stats`. Cada
código va con la fuente que no lo revisó y el motivo:
- 'source_failed': la fuente corrió y no terminó 'succeeded'. Ninguno de sus códigos se revisó.
- 'source_not_run': la fuente tiene recolector pero no corrió en ese escaneo, porque está apagada en `data_sources`
  o porque aún no existía. Ninguno de sus códigos se revisó.
- 'no_api_key': la fuente no revisó ese código porque le faltó la llave. Hoy solo pasa con los códigos de
  shodan.SIN_LLAVE cuando no hubo API de host.
- 'source_partial': la fuente respondió pero no pudo revisar ese código (su `sin_cobertura`).
- 'partially_checked': la fuente revisó solo una parte de lo suyo (`sources_partial`: un sitio web de varios, una
  variante de crt.sh sin respuesta). Sus códigos se revisaron en esa parte y no en el resto.

La lista de cada fuente sale de `raw_payload->'sin_cobertura'` de su corrida y la de la llave, de `sin_llave`. Una
corrida de antes de `sin_llave` lo toma del aviso fijo de Shodan (LIMITES dice que no hubo llave), por su comienzo y no
por el texto de hoy. Una fuente con
keep_raw_payload en false (GitHub) no guarda nada: sus códigos de `rules_without_coverage` se le dan por su CODIGOS.
Un código de `rules_without_coverage` que no se puede atribuir va con la fuente en None. Sin corridas (un escaneo
sembrado) no hay de dónde sacarlo y la lista sale vacía.

Un código que revisan dos fuentes (outdated_software y known_vulnerability, en Shodan y en la visita web) sale una
vez por cada fuente que no lo revisó. Que una no lo revisara no dice nada de la otra.
"""
from cirdan.recolectores import REGISTRO, cargar, shodan

FUENTE_PRUEBAS = 'ejemplo'
MOTIVOS = ('source_failed', 'source_not_run', 'no_api_key', 'source_partial', 'partially_checked')
# Cómo empiezan shodan.LIMITES y shodan.LIMITES_CON_LLAVE. Una corrida guarda el aviso con el texto de su versión, y el
# resto del texto cambió varias veces (la del CDN el 12 nov, la de las etiquetas el 17 nov en 839af0f). Todas las
# versiones de LIMITES, desde la primera (42e545c), empiezan con AVISO_SIN_LLAVE, y antes de 839af0f no había API de
# host: lo de SIN_LLAVE que quedó sin revisar fue por la llave.
AVISO_SIN_LLAVE = 'shodan: solo IPv4 y sin la llave de Shodan'
AVISO_CON_LLAVE = 'shodan: solo IPv4. exposed_iot_device, exposed_ot_device y outdated_software se revisan con las '


def codigos_de(fuente):
    """Los códigos de regla que revisa el recolector de una fuente. Una fuente sin recolector no revisa ninguno."""
    try:
        return tuple(cargar(fuente).CODIGOS)
    except KeyError:
        return ()


def _lista(valor):
    return valor if isinstance(valor, list) else None


def _sin_llave(corrida):
    """Los códigos que la corrida dejó sin revisar por la llave, o None si no se sabe."""
    sin_llave = _lista(corrida.get('sin_llave'))
    if sin_llave is not None:
        return set(sin_llave)
    avisos = [a for a in _lista(corrida.get('avisos')) or [] if isinstance(a, str)]
    if corrida['source'] == 'shodan':
        if any(a.startswith(AVISO_SIN_LLAVE) for a in avisos):
            return set(shodan.SIN_LLAVE)
        if any(a.startswith(AVISO_CON_LLAVE) for a in avisos):
            return set()
    return None


def huecos(corridas, sin_cobertura=(), parciales=(), codigos=codigos_de):
    """[{code, source, reason}] ordenada por código y fuente.

    `corridas`: las de `scan_source_runs` del escaneo, cada una con source, status y, de su raw_payload, sin_cobertura,
    sin_llave y avisos (None si no los guardó). `sin_cobertura`: `rules_without_coverage` de `scans.stats`.
    `parciales`: `sources_partial` de `scans.stats`.
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
        lista = _lista(r.get('sin_cobertura'))
        if lista is None:
            sin_lista.append(r['source'])
            continue
        por_llave = _sin_llave(r) or set()
        for c in lista:
            motivos.setdefault((c, r['source']), 'no_api_key' if c in por_llave else 'source_partial')
    atribuidos = {c for (c, _), m in motivos.items() if m in ('no_api_key', 'source_partial')}
    # Las reglas de una fuente que la carta no autoriza llegan a rules_without_coverage con su corrida en 'failed'
    # (RC-59): ya salen con source_failed y no se repiten sin fuente.
    caidos = {c for (c, _), m in motivos.items() if m == 'source_failed'}
    for c in sin_cobertura:
        if c in atribuidos:
            continue
        fuentes = [f for f in sin_lista if c in codigos(f)]
        if not fuentes and c in caidos:
            continue
        for fuente in fuentes or [None]:
            motivos.setdefault((c, fuente), 'source_partial')
    for fuente in parciales:
        if fuente in corrieron:
            for c in codigos(fuente):
                motivos.setdefault((c, fuente), 'partially_checked')
    return [{'code': c, 'source': f, 'reason': m}
            for (c, f), m in sorted(motivos.items(), key=lambda kv: (kv[0][0], kv[0][1] or ''))]
