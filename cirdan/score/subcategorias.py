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

SIN_CLASIFICAR = ('other', 'Sin clasificar')   # solo si llega un aporte de una regla que el mapa no conoce
ESTADOS_KRI = ('ok', 'no_coverage', 'no_source_yet')
ORDEN_SEVERIDAD = ('low', 'medium', 'high', 'critical')

_POR_CODIGO = {codigo: (clave, categoria) for clave, categoria, _, codigos in SUBCATEGORIAS for codigo in codigos}


def subcategoria(codigo):
    """Clave de la subcategoría de un código de regla, o None si el mapa no lo conoce."""
    return _POR_CODIGO.get(codigo, (None, None))[0]


def revisar(reglas=None, categorias=None):
    """Errores del mapa, lista vacía si está bien.

    `reglas`: {código: categoría} del catálogo. Si llega, cada código debe tener subcategoría de su categoría
    y el mapa no puede nombrar códigos que no existen. `categorias`: las válidas (criterio.CATEGORIAS).
    """
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
    kris = [k[0] for k in KRIS]
    errores += ['KRI repetido: %s' % k for k in sorted(set(k for k in kris if kris.count(k) > 1))]
    for clave, nombre, subs, fuentes in KRIS:
        errores += ['el KRI %s apunta a la subcategoría %s, que no existe' % (clave, s) for s in subs if s not in claves]
        if not nombre:
            errores.append('el KRI %s no tiene nombre' % clave)
        if bool(subs) != bool(fuentes):
            errores.append('el KRI %s tiene subcategorías sin fuentes o fuentes sin subcategorías' % clave)
    if reglas is not None:
        for codigo, categoria in sorted(reglas.items()):
            if codigo not in _POR_CODIGO:
                errores.append('el código de regla %s no tiene subcategoría' % codigo)
            elif _POR_CODIGO[codigo][1] != categoria:
                errores.append('%s es de %s y su subcategoría %s es de %s' % (
                    codigo, categoria, _POR_CODIGO[codigo][0], _POR_CODIGO[codigo][1]))
        errores += ['el mapa nombra %s, que no es una regla del catálogo' % c for c in sorted(set(codigos) - set(reglas))]
    return errores


def _suma(aportes):
    return round(float(sum(a['penalty'] for a in aportes)), 2)


def resumen(aportes, corridas, sin_cobertura=()):
    """Subcategorías y KRI de un score.

    `aportes`: los de `score_contributions` del score, cada uno con code, category, severity y penalty. Son la
    foto de los hallazgos vigentes cuando se calculó. `corridas`: {fuente: estado} de `scan_source_runs` del
    escaneo del score. `sin_cobertura`: códigos de `scans.stats.rules_without_coverage`.

    Un KRI queda 'no_coverage' si alguna de sus fuentes corrió y no terminó 'succeeded', o si ninguna corrió.
    Ahí y en 'no_source_yet' sus conteos van en None, nunca en cero. Con 'ok' dice además qué fuentes suyas no
    corrieron en ese escaneo y qué reglas suyas quedaron sin cobertura.
    """
    por_sub = {}
    for a in aportes:
        por_sub.setdefault((a['category'], subcategoria(a['code']) or SIN_CLASIFICAR[0]), []).append(a)
    subcategorias = [{'category': categoria, 'subcategory': clave, 'name': nombre,
                      'findings': len(por_sub.get((categoria, clave), ())),
                      'penalty': _suma(por_sub.get((categoria, clave), ()))}
                     for clave, categoria, nombre, _ in SUBCATEGORIAS]
    subcategorias += [{'category': categoria, 'subcategory': clave, 'name': SIN_CLASIFICAR[1],
                       'findings': len(lista), 'penalty': _suma(lista)}
                      for (categoria, clave), lista in sorted(por_sub.items()) if clave == SIN_CLASIFICAR[0]]

    codigos_sub = {clave: codigos for clave, _, _, codigos in SUBCATEGORIAS}
    categoria_sub = {clave: categoria for clave, categoria, _, _ in SUBCATEGORIAS}
    kris = []
    for clave, nombre, subs, fuentes in KRIS:
        caidas = [f for f in fuentes if f in corridas and corridas[f] != 'succeeded']
        sin_correr = [f for f in fuentes if f not in corridas]
        estado = ('no_source_yet' if not fuentes
                  else 'no_coverage' if caidas or len(sin_correr) == len(fuentes) else 'ok')
        suyos = [a for s in subs for a in por_sub.get((categoria_sub[s], s), ())]
        codigos = [c for s in subs for c in codigos_sub[s]]
        item = {'kri': clave, 'name': nombre, 'status': estado, 'subcategories': list(subs), 'sources': list(fuentes),
                'sources_failed': caidas, 'sources_not_run': sin_correr,
                'rules_without_coverage': [c for c in codigos if c in sin_cobertura],
                'findings': None, 'max_severity': None, 'penalty': None}
        if estado == 'ok':
            item['findings'] = len(suyos)
            item['penalty'] = _suma(suyos)
            if suyos:
                item['max_severity'] = max((a['severity'] for a in suyos), key=ORDEN_SEVERIDAD.index)
        kris.append(item)
    return subcategorias, kris
