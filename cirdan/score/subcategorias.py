"""Subcategorías del score y vista de KRI (#114, RC-232).

Es una vista sobre el score que ya existe: no cambia el cálculo ni la base. Cada código de regla del
catálogo (#30) cae en una subcategoría de su categoría, y 5 KRI juntan subcategorías aunque sean de
categorías distintas. Una regla puede quedar sin KRI y sigue contando en su categoría, así que los KRI
no cubren todo el score. Todo se calcula al leer, con los aportes de `score_contributions` del score y
las corridas de `scan_source_runs` de su escaneo. El documento está en docs/criterio_criticidad.md.

Al cambiar el mapa (una regla nueva, otra subcategoría u otro KRI) sube VERSION.
"""
VERSION = 1

# (clave, categoría, nombre, códigos de regla). El orden es el que muestra el portal.
SUBCATEGORIAS = (
    ('certificates', 'infrastructure', 'Certificados', ('cert_expired', 'cert_expiring_soon')),
    ('exposed_services', 'infrastructure', 'Exposición de servicios',
     ('exposed_rdp', 'exposed_remote_admin', 'exposed_file_sharing', 'exposed_database', 'exposed_ot_device',
      'exposed_iot_device', 'exposed_service')),
    ('exposed_apis', 'infrastructure', 'Documentación de APIs expuesta', ('exposed_api_docs', 'api_auth_not_declared')),
    ('vulnerable_software', 'infrastructure', 'Software vulnerable o sin soporte',
     ('outdated_software', 'known_vulnerability')),
    ('domain_registration', 'infrastructure', 'Registro del dominio', ('domain_expiring_soon',)),
    ('impersonation', 'digital_identity', 'Suplantación', ('lookalike_domain',)),
    ('exposed_emails', 'digital_identity', 'Correos expuestos',
     ('email_in_public_commits', 'personal_email_exposed', 'email_pattern_exposed')),
    ('email', 'configuration', 'Correo', ('spf_missing', 'spf_allow_all', 'dmarc_missing', 'dmarc_policy_none')),
    ('server_configuration', 'configuration', 'Configuración de servidores',
     ('server_version_disclosed', 'subdomain_takeover_risk')),
    ('breaches', 'data_leaks', 'Brechas de datos',
     ('breach_exposure', 'breach_exposure_old', 'breach_exposure_no_passwords')),
    ('exposed_secrets', 'data_leaks', 'Secretos expuestos', ('secret_in_public_repo', 'secret_in_container_image')),
    ('public_storage', 'data_leaks', 'Almacenamiento público', ('public_bucket',)),
)

# (clave, nombre, subcategorías que junta, fuentes de data_sources.code que lo alimentan).
# Reputación no tiene fuente hasta que RC-234 esté en dev: sale 'sin fuente todavía'.
KRIS = (
    ('certificates', 'Certificados', ('certificates',), ('ct_logs',)),
    ('service_exposure', 'Exposición de servicios', ('exposed_services', 'exposed_apis'), ('shodan', 'api_docs')),
    ('email', 'Correo', ('email',), ('dns',)),
    ('impersonation', 'Suplantación', ('impersonation',), ('ct_logs',)),
    ('reputation', 'Reputación', (), ()),
)

# Qué fuente revisa cada regla de un KRI, para saber cuáles quedaron sin revisar cuando la fuente no corrió.
# Trae también las reglas que shodan no puede revisar sin su llave (SIN_LLAVE de shodan.py).
EMITEN = (
    ('ct_logs', ('cert_expired', 'cert_expiring_soon', 'lookalike_domain')),
    ('shodan', ('exposed_rdp', 'exposed_remote_admin', 'exposed_file_sharing', 'exposed_database', 'exposed_ot_device',
                'exposed_iot_device', 'exposed_service')),
    ('api_docs', ('exposed_api_docs', 'api_auth_not_declared')),
    ('dns', ('spf_missing', 'spf_allow_all', 'dmarc_missing', 'dmarc_policy_none')),
)

# Fila de un aporte de una regla que el mapa no conoce o que su juego de reglas puso en otra categoría.
SIN_CLASIFICAR = ('other', 'Sin clasificar')
ESTADOS_KRI = ('ok', 'partial', 'no_coverage', 'no_source_yet')
ORDEN_SEVERIDAD = ('low', 'medium', 'high', 'critical')

_POR_CODIGO = {codigo: (clave, categoria) for clave, categoria, _, codigos in SUBCATEGORIAS for codigo in codigos}


def subcategoria(codigo):
    """Clave de la subcategoría de un código de regla, o None si el mapa no lo conoce."""
    return _POR_CODIGO.get(codigo, (None, None))[0]


def revisar(reglas=None, categorias=None):
    """Errores del mapa, lista vacía si está bien.

    `reglas`: pares (código, categoría) del catálogo, de todos los juegos de reglas. Si llegan, cada par debe
    tener subcategoría de su categoría y el mapa no puede nombrar códigos que no existen. Un {código: categoría}
    también sirve. `categorias`: las válidas (criterio.CATEGORIAS).
    """
    if isinstance(reglas, dict):
        reglas = reglas.items()
    errores = []
    claves = [s[0] for s in SUBCATEGORIAS]
    errores += ['subcategoría repetida: %s' % c for c in sorted(set(c for c in claves if claves.count(c) > 1))]
    codigos = [codigo for s in SUBCATEGORIAS for codigo in s[3]]
    errores += ['código en dos subcategorías: %s' % c for c in sorted(set(c for c in codigos if codigos.count(c) > 1))]
    for clave, categoria, nombre, de_la_sub in SUBCATEGORIAS:
        if categorias is not None and categoria not in categorias:
            errores.append('la subcategoría %s tiene la categoría %r' % (clave, categoria))
        if not nombre or not de_la_sub:
            errores.append('la subcategoría %s no tiene nombre o no tiene códigos' % clave)
    codigos_sub = {s[0]: s[3] for s in SUBCATEGORIAS}
    kris = [k[0] for k in KRIS]
    errores += ['KRI repetido: %s' % k for k in sorted(set(k for k in kris if kris.count(k) > 1))]
    for clave, nombre, subs, fuentes in KRIS:
        errores += ['el KRI %s apunta a la subcategoría %s, que no existe' % (clave, s) for s in subs if s not in claves]
        if not nombre:
            errores.append('el KRI %s no tiene nombre' % clave)
        if bool(subs) != bool(fuentes):
            errores.append('el KRI %s tiene subcategorías sin fuentes o fuentes sin subcategorías' % clave)
        for s in subs:
            for codigo in codigos_sub.get(s, ()):
                de = [f for f, suyos in EMITEN if codigo in suyos]
                if len(de) != 1 or de[0] not in fuentes:
                    errores.append('la regla %s del KRI %s debe estar en EMITEN con una sola fuente del KRI' % (
                        codigo, clave))
    if reglas is not None:
        reglas = sorted(set(reglas))
        for codigo, categoria in reglas:
            if codigo not in _POR_CODIGO:
                errores.append('el código de regla %s no tiene subcategoría' % codigo)
            elif _POR_CODIGO[codigo][1] != categoria:
                errores.append('%s es de %s y su subcategoría %s es de %s' % (
                    codigo, categoria, _POR_CODIGO[codigo][0], _POR_CODIGO[codigo][1]))
        errores += ['el mapa nombra %s, que no es una regla del catálogo' % c for c in sorted(set(codigos) - {c for c, _ in reglas})]
    return errores


def _suma(aportes):
    return round(float(sum(a['penalty'] for a in aportes)), 2)


def _clave(aporte):
    """Subcategoría del aporte. Si el mapa no conoce su código o lo tiene en otra categoría, va a 'other'."""
    clave, categoria = _POR_CODIGO.get(aporte['code'], (None, None))
    return clave if categoria == aporte['category'] else SIN_CLASIFICAR[0]


def resumen(aportes, corridas, sin_cobertura=(), a_medias=()):
    """Subcategorías y KRI de un score.

    `aportes`: los de `score_contributions` del score, cada uno con code, category, severity y penalty. Son la
    foto de los hallazgos vigentes cuando se calculó. `corridas`: {fuente: estado} de `scan_source_runs` del
    escaneo del score. `sin_cobertura` y `a_medias`: `rules_without_coverage` y `sources_partial` de `scans.stats`.

    Estado de un KRI:
    - 'no_source_yet': todavía no tiene fuentes.
    - 'no_coverage': alguna de sus fuentes corrió y no terminó 'succeeded', ninguna corrió, o ninguna regla suya
      se revisó: cada una quedó sin cobertura o es de una fuente que no corrió. Sus conteos van en None, nunca en
      cero. Una sola fuente caída basta, aunque otra sí haya encontrado algo (así lo pide la tarjeta).
    - 'partial': hay datos pero no de todo: alguna fuente suya no corrió o revisó solo una parte, o alguna regla
      suya quedó sin cobertura. Trae conteos, y un cero aquí no quiere decir sin riesgo.
    - 'ok': todas sus fuentes corrieron completas y ninguna regla suya quedó sin cobertura.

    `sources_partial` va por fuente, no por regla: si a ct_logs solo le faltó una variante de dominios parecidos,
    Certificados también sale 'partial' aunque sus dos reglas se revisaron completas. Es el límite de `scans.stats`.
    Los aportes de un KRI se juntan por código de regla: si un juego puso una regla suya en otra categoría, en las
    subcategorías va a 'other' y en su KRI sigue contando.
    """
    por_sub = {}
    for a in aportes:
        por_sub.setdefault((a['category'], _clave(a)), []).append(a)
    subcategorias = [{'category': categoria, 'subcategory': clave, 'name': nombre,
                      'findings': len(por_sub.get((categoria, clave), ())),
                      'penalty': _suma(por_sub.get((categoria, clave), ()))}
                     for clave, categoria, nombre, _ in SUBCATEGORIAS]
    subcategorias += [{'category': categoria, 'subcategory': clave, 'name': SIN_CLASIFICAR[1],
                       'findings': len(lista), 'penalty': _suma(lista)}
                      for (categoria, clave), lista in sorted(por_sub.items()) if clave == SIN_CLASIFICAR[0]]

    codigos_sub = {clave: codigos for clave, _, _, codigos in SUBCATEGORIAS}
    fuente_de = {codigo: fuente for fuente, codigos in EMITEN for codigo in codigos}
    kris = []
    for clave, nombre, subs, fuentes in KRIS:
        caidas = [f for f in fuentes if f in corridas and corridas[f] != 'succeeded']
        sin_correr = [f for f in fuentes if f not in corridas]
        parciales = [f for f in fuentes if f in a_medias and f not in caidas and f not in sin_correr]
        codigos = [c for s in subs for c in codigos_sub[s]]
        suyos = [a for a in aportes if a['code'] in codigos]
        sin_revisar = [c for c in codigos if c in sin_cobertura]
        # las reglas de una fuente que no corrió tampoco se revisaron, aunque no vengan en sin_cobertura
        sin_dato = [c for c in codigos if c in sin_cobertura or fuente_de.get(c) in sin_correr]
        if not fuentes:
            estado = 'no_source_yet'
        elif caidas or len(sin_correr) == len(fuentes) or len(sin_dato) == len(codigos):
            estado = 'no_coverage'
        elif sin_correr or parciales or sin_revisar:
            estado = 'partial'
        else:
            estado = 'ok'
        item = {'kri': clave, 'name': nombre, 'status': estado, 'subcategories': list(subs), 'sources': list(fuentes),
                'sources_failed': caidas, 'sources_not_run': sin_correr, 'sources_partial': parciales,
                'rules_without_coverage': sin_revisar,
                'findings': None, 'max_severity': None, 'penalty': None}
        if estado in ('ok', 'partial'):
            item['findings'] = len(suyos)
            item['penalty'] = _suma(suyos)
            if suyos:
                item['max_severity'] = max((a['severity'] for a in suyos), key=ORDEN_SEVERIDAD.index)
        kris.append(item)
    return subcategorias, kris
