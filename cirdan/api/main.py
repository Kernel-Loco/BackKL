"""Cirdan · API REST (FastAPI) sobre la base `cirdan`.

Entra como el rol de la aplicación `cirdan_app` (sin superusuario ni BYPASSRLS). La empresa
de quien llama sale de su sesión (cookie httpOnly `lt_session`, #25): cada petición fija
`app.current_org` con ella y Row-Level Security hace el resto, así que ninguna consulta
filtra por organización. Ninguna ruta toma la empresa de un encabezado. El explorador de /demo
y /db solo existe con DEMO_EXPLORER=true y también pide sesión (RC-58). Los GET de datos de
/api/v1 también aceptan una llave de API en `Authorization: Bearer` (#87, RC-129): ahí la empresa
sale de la fila de la llave, que se busca por su hash.

    docker compose up -d            (o, fuera de Docker: python -m uvicorn cirdan.api.main:app --port 8000)
    Documentación: con API_DOCS=true en el .env, http://127.0.0.1:8000/docs (por omisión no existe, RC-303).
"""
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.routing import Match

from cirdan.auth.deps import Session, client_ip, comprobar_cookie_segura, current_session, require_roles
from cirdan.api.asistente import ClientDisconnectWatch, router as assistant_router
from cirdan.api.bitacora import router as audit_log_router
from cirdan.api.escaneos import router as scans_router
from cirdan.api.explorer import router as explorer_router
from cirdan.api.firmas import MAX_SUBIDA_BODY, router as signatures_router
from cirdan.api.fuentes import router as sources_router
from cirdan.api.llaves import router as api_keys_router
from cirdan.api.operador import router as operator_router
from cirdan.api.plataforma import router as platform_router
from cirdan.api.v1 import MAX_ALTA_BODY, router as v1_router
from cirdan.auth import passwords, totp
from cirdan.auth.routes import router as auth_router
from cirdan.config import config, origenes_permitidos
from cirdan.db import audit, transaction
from cirdan.version import VERSION


@asynccontextmanager
async def _arranque(app):
    # Sin la llave del MFA la API no arranca: con Key Vault, un error de la identidad o del rol sale aquí, en
    # `docker compose logs api`, y no en el primer inicio de sesión (#49, RC-91). Igual con la llave de las huellas de
    # contraseña (RC-330), que además tiene que ser otra que la del MFA aunque una venga del .env y la otra de Key
    # Vault.
    # Antes que las llaves, que pueden tardar con Key Vault: publicada por HTTPS, la cookie de sesión va con Secure
    # o la API no arranca (RC-286).
    comprobar_cookie_segura()
    passwords.comprobar_llave(totp.comprobar_llave())
    yield


# Documentación de la API (/openapi.json, /docs y /redoc). Por omisión no existe: LowTide escanea su propio dominio y
# no debe darse exposed_api_docs a sí mismo (comentario 10063 de RC-91, RC-303). Solo API_DOCS=true la pone, para verla
# en una PC de desarrollo. El despliegue además la fija en false (docker-compose.despliegue.yml).
API_DOCS = config('API_DOCS', 'false').lower() == 'true'

app = FastAPI(
    lifespan=_arranque,
    # Con openapi_url en None, FastAPI tampoco registra /docs ni /redoc.
    openapi_url='/openapi.json' if API_DOCS else None,
    title='LowTide API',
    version=VERSION,   # la misma del User-Agent (cirdan/version.py)
    description='Inicio de sesión con MFA y endpoints de solo lectura sobre la base cirdan (PostgreSQL 16). '
                'La empresa sale de la sesión y el aislamiento lo aplica Row-Level Security en la base. '
                'Con DEMO_EXPLORER=true, vista visual de la base en /demo, también con sesión.',
)

# Tope al cuerpo de las peticiones (RC-298). uvicorn no trae tope y FastAPI junta el cuerpo entero antes de revisar
# los max_length de los modelos, también en /api/v1/auth/login, que no pide sesión: un JSON de 1 GB dejaba sin memoria
# el único proceso de la API, donde también corren los recolectores. El cuerpo válido más grande es el de las passkeys
# (/api/v1/auth/passkeys/register/verify y /passkeys/login/verify), con un credential de hasta 16 KB según json.dumps
# (webauthn.MAX_CREDENTIAL_JSON). Le siguen /action-plan/simulate, con 100 códigos de regla de hasta 63 caracteres
# (003_textos_reglas.sql:25), unos 6.6 KB, y el login, con el captcha de hasta 4,096 caracteres (captcha.py:30), que no
# llega a 6 KB. 64 KB deja unas 4 veces de margen sobre el de las passkeys.
TOPE_CUERPO = 64 * 1024

# Rutas con otro tope, por método y ruta exactos (RC-59). El alta de dominio manda la carta en base64 dentro del JSON:
# hasta 5 MB de PDF, unos 6.7 MB con los demás campos (v1.MAX_ALTA_BODY). register_domain lee el stream solo después
# de la sesión de Admin y cuenta los bytes él mismo. Aquí el tope de esa ruta es el mismo, así que un Content-Length de
# más se corta antes de entrar y un chunked sin sesión se lee y se tira hasta ese tope, sin juntarlo. Cualquier otra
# ruta, también '/api/v1/domains/' con diagonal final u otro método, se queda en TOPE_CUERPO.
# RC-211: mandar la carta a firmar con Mifiel lleva el mismo cuerpo que el alta, y subir lo firmado en la web de
# Mifiel suma el XML, de hasta 7 MB (firmas.MAX_SUBIDA_BODY). Las dos leen el stream como register_domain.
TOPES_POR_RUTA = {('POST', '/api/v1/domains'): (MAX_ALTA_BODY, 'El PDF no puede superar 5 MB.'),
                  ('POST', '/api/v1/signature-requests'): (MAX_ALTA_BODY, 'El PDF no puede superar 5 MB.'),
                  ('POST', '/api/v1/signature-uploads'): (MAX_SUBIDA_BODY, 'El PDF no puede superar 5 MB y el XML 7 MB.')}


class CuerpoDemasiadoGrande(Exception):
    """El cuerpo pasó el tope mientras llegaba."""


def _content_length_excedido(scope, tope):
    """True si algún Content-Length pasa el tope. Uno que no sea un número no cuenta aquí: lo rechaza el servidor y,
    si llegara, el conteo de bytes lo corta igual."""
    for nombre, valor in scope.get('headers', ()):
        if nombre.lower() == b'content-length':
            valor = valor.strip()
            # Más de 18 cifras ya pasa cualquier tope y int() de miles de cifras es lento o falla.
            if valor.isdigit() and (len(valor) > 18 or int(valor) > tope):
                return True
    return False


def _trae_transfer_encoding(scope):
    """True si el cuerpo viene por pedazos (chunked): su largo no se sabe hasta que termina."""
    return any(nombre.lower() == b'transfer-encoding' for nombre, _ in scope.get('headers', ()))


class TopeDeCuerpo:
    """Middleware ASGI: 413 si el cuerpo pasa el tope, en todas las rutas, con o sin sesión.

    Con Content-Length de más responde antes de entrar a la app. Sin él (chunked), o si llegan más bytes de los
    anunciados, cuenta los bytes conforme la app los pide y corta al pasar el tope, sin juntar el cuerpo. FastAPI
    convierte la excepción de receive() en un 400 ('There was an error parsing the body'): ese 400 no sale y en su lugar
    va el 413. Si la ruta responde sin haber leído todo un cuerpo chunked (/auth/me, /health, logout), el resto se lee
    y se tira, contando, antes de dejar salir la respuesta: si pasa el tope sale el 413. Sin eso uvicorn seguiría
    leyendo y tirando un cuerpo sin fin después de responder, sin tope ni timeout.
    Las rutas de topes_por_ruta llevan su propio tope y su mensaje, con el mismo conteo. Se buscan por método y por
    scope['path'] exactos: una ruta escrita de otra forma, o con un root_path delante, cae en el tope general.
    """

    def __init__(self, app, tope=TOPE_CUERPO, topes_por_ruta=None):
        self.app = app
        self.tope = tope
        self.topes_por_ruta = TOPES_POR_RUTA if topes_por_ruta is None else topes_por_ruta

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        tope, detalle = self.topes_por_ruta.get(
            (scope.get('method'), scope.get('path')),
            (self.tope, 'El cuerpo de la petición pasa el tope de %d KB' % (self.tope // 1024)))
        if _content_length_excedido(scope, tope):
            await self._responder_413(scope, receive, send, detalle)
            return

        recibidos = 0
        excedido = False
        iniciada = False
        # Con Content-Length el servidor lee a lo más lo anunciado, que ya no pasa el tope. Con chunked no hay largo.
        pendiente = _trae_transfer_encoding(scope)

        async def recibir():
            nonlocal recibidos, excedido, pendiente
            if excedido:
                raise CuerpoDemasiadoGrande()
            mensaje = await receive()
            if mensaje['type'] == 'http.request':
                recibidos += len(mensaje.get('body', b''))
                if recibidos > tope:
                    excedido = True
                    raise CuerpoDemasiadoGrande()
                if not mensaje.get('more_body', False):
                    pendiente = False
            else:  # http.disconnect: el cliente se fue y ya no llega más cuerpo
                pendiente = False
            return mensaje

        async def enviar(mensaje):
            nonlocal iniciada
            if mensaje['type'] == 'http.response.start' and pendiente and not excedido:
                # La ruta responde sin haber leído todo el cuerpo chunked: se lee el resto y se tira, sin juntarlo.
                try:
                    while pendiente:
                        await recibir()
                except CuerpoDemasiadoGrande:
                    pass
            if excedido:
                return  # la respuesta que la app arme después del corte no sale
            if mensaje['type'] == 'http.response.start':
                iniciada = True
            await send(mensaje)

        try:
            await self.app(scope, recibir, enviar)
        except Exception:
            if not excedido or iniciada:
                raise
        if excedido:
            if iniciada:
                # La respuesta ya había empezado: no hay cómo cambiarla por un 413 y el servidor corta la conexión.
                raise CuerpoDemasiadoGrande()
            await self._responder_413(scope, receive, send, detalle)

    async def _responder_413(self, scope, receive, send, detalle):
        # Connection: close porque el resto del cuerpo no se lee: la conexión no sirve para otra petición.
        respuesta = JSONResponse({'detail': detalle}, status_code=413, headers={'Connection': 'close'})
        await respuesta(scope, receive, send)


# Va antes de los dos middlewares de abajo para quedar dentro de ellos: Starlette pone afuera el último que se agrega.
# Así el 413 también sale con CABECERAS_SEGURIDAD.
app.add_middleware(TopeDeCuerpo)

# Orígenes que pueden mandar POST con la cookie: el portal y la propia API. Vacía vale como sin poner (RC-277).
ALLOWED_ORIGINS = set(origenes_permitidos())


@app.middleware('http')
async def same_origin_writes(request: Request, call_next):
    """Contra CSRF: además de SameSite=Lax, una escritura con Origin ajeno se rechaza."""
    origin = request.headers.get('origin')
    if request.method not in ('GET', 'HEAD', 'OPTIONS') and origin:
        parts = urlsplit(origin)
        if '%s://%s' % (parts.scheme, parts.netloc) not in ALLOWED_ORIGINS:
            return JSONResponse({'detail': 'Origen no permitido'}, status_code=403)
    return await call_next(request)


# Ningún sitio mete una respuesta de la API en un marco y el navegador no adivina su tipo (RC-283). Van aquí y no
# solo en el portal porque la API también se llama sin él, y porque el portal entrega tal cual lo que reenvía a
# /api/v1/*: sus cabeceras de next.config.ts no llegan a esas respuestas. La CSP completa, HSTS, Referrer-Policy y
# Permissions-Policy son de RC-89. HSTS va sin preload: hstspreload.org acepta el dominio de quien lo inscriba y
# salir de la lista tarda meses. Por http (la API local) el navegador lo ignora.
CABECERAS_SEGURIDAD = {
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), usb=()',
}

# /docs y /redoc (solo con API_DOCS=true, nunca en el despliegue) son páginas de FastAPI que cargan swagger-ui y redoc
# de cdn.jsdelivr.net, la tipografía de redoc de Google Fonts y el ícono de fastapi.tiangolo.com, y /docs y
# /docs/oauth2-redirect traen un script en línea. Con la CSP de arriba quedarían en blanco. El script en línea cambia
# con la versión de FastAPI, así que va 'unsafe-inline' en vez de su hash: es una página de una PC de desarrollo.
# Conserva frame-ancestors 'none', así que el middleware de abajo la deja.
RUTAS_DOCS_HTML = frozenset({'/docs', '/docs/oauth2-redirect', '/redoc'})
CSP_DOCS = '; '.join([
    "default-src 'none'",
    "script-src 'unsafe-inline' https://cdn.jsdelivr.net",
    "style-src 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
    'font-src https://fonts.gstatic.com',
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly",
    "connect-src 'self'",
    'worker-src blob:',
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'none'",
])


@app.middleware('http')
async def cabeceras_de_seguridad(request: Request, call_next):
    """Va después de same_origin_writes para envolverlo: su 403 también sale con las cabeceras."""
    response = await call_next(request)
    if API_DOCS and request.url.path in RUTAS_DOCS_HTML and response.status_code == 200:
        response.headers['Content-Security-Policy'] = CSP_DOCS
    for nombre, valor in CABECERAS_SEGURIDAD.items():
        # Una CSP propia que ya trae frame-ancestors 'none' se queda, como la del reporte en HTML (RC-70) y la de
        # /demo (explorer.py), que necesitan sus estilos o su script.
        if nombre == 'Content-Security-Policy' and "frame-ancestors 'none'" in response.headers.get(nombre, ''):
            continue
        response.headers[nombre] = valor
    # Ninguna respuesta de la API se guarda en una caché, ni la del navegador ni la de Cloudflare: casi todas traen
    # datos de la cuenta o de la empresa. Lo que quedó abierto del escaneo de ZAP (#51, RC-89) era /api/v1/auth/me sin
    # Cache-Control. Una ruta que ya pone el suyo lo conserva (#75, RC-136).
    response.headers.setdefault('Cache-Control', 'no-store')
    return response


@app.middleware('http')
async def auditar_lecturas_de_operador(request: Request, call_next):
    """Registra las lecturas exitosas que un superadmin hace dentro de una empresa cliente."""
    response = await call_next(request)
    route_path, path_params = '', {}
    for route in app.router.routes:
        router = getattr(route, 'original_router', None)
        candidates = router.routes if router else (route,)
        for candidate in candidates:
            if not getattr(candidate, 'path', None):
                continue
            match, child_scope = candidate.matches(request.scope)
            if match is Match.FULL:
                route_path = candidate.path
                path_params = child_scope.get('path_params', {})
                break
        if route_path:
            break
    session = getattr(request.state, 'cirdan_session', None)
    if (
        request.method not in ('GET', 'HEAD') or response.status_code < 200 or response.status_code >= 300
        or not route_path.startswith('/api/v1/') or route_path.startswith(('/api/v1/auth/', '/api/v1/platform/'))
        or request.headers.get('authorization') or not session or not session.acting_elsewhere
    ):
        return response
    with transaction(session.org_id) as conn:
        audit(conn, session.org_id, 'platform.client_data_read', ip=client_ip(request), entity_type='api_route',
              details={'method': request.method, 'route': route_path,
                       'path_params': {key: str(value) for key, value in path_params.items()},
                       'status_code': response.status_code},
              platform=session.audit_platform)
    return response


# Afuera de los @app.middleware('http') de arriba, que no dejan ver el corte del cliente (asistente.py lo explica).
app.add_middleware(ClientDisconnectWatch)


@app.exception_handler(Exception)
async def error_no_manejado(request: Request, exc: Exception):
    """El 500 de un error sin manejar lo arma Starlette por fuera de los middlewares: aquí lleva las cabeceras, también
    el Cache-Control que el middleware pone a las demás respuestas (#75, RC-136)."""
    return PlainTextResponse('Internal Server Error', status_code=500,
                             headers={**CABECERAS_SEGURIDAD, 'Cache-Control': 'no-store'})


app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(api_keys_router)
app.include_router(sources_router)
app.include_router(platform_router)
app.include_router(operator_router)
app.include_router(v1_router)
app.include_router(signatures_router)
app.include_router(assistant_router)
app.include_router(audit_log_router)

# Explorador de la base para la demo (/demo y /db, RC-58). Con false, que es lo de omisión, esas
# rutas no existen (404). Nunca true en producción.
if config('DEMO_EXPLORER', 'false').lower() == 'true':
    app.include_router(explorer_router)


def query(session, sql, params=()):
    if any(chr(0) in str(p) for p in params):
        raise HTTPException(400, 'Parámetro inválido')
    with transaction(session.org_id) as conn:
        return conn.execute(sql, params).fetchall()


LEVEL = """CASE WHEN {s} IS NULL THEN NULL WHEN {s} >= 80 THEN 'Critical' WHEN {s} >= 60 THEN 'High'
                WHEN {s} >= 40 THEN 'Medium' ELSE 'Low' END"""

DOMAINS = """
SELECT d.fqdn AS domain,
       CASE WHEN d.status = 'pending_verification' THEN 'Pending TXT'
            WHEN a.id IS NULL                      THEN 'Not authorized'
            WHEN a.revoked_at IS NOT NULL          THEN 'Revoked'
            WHEN current_date < a.valid_from       THEN 'Not authorized'
            WHEN current_date > a.valid_until      THEN 'Expired'
            ELSE 'Authorized' END                                   AS authorization,
       CASE WHEN t.result = 'match'                THEN 'Verified'
            WHEN d.status = 'pending_verification' THEN 'Pending'
            ELSE 'Not found' END                                    AS txt,
       a.valid_until::text                                          AS valid_until,
       s.score                                                      AS score,
       """ + LEVEL.format(s='s.score') + """                        AS level,
       d.last_scan_at                                               AS last_scan
  FROM domains d
  LEFT JOIN LATERAL (SELECT * FROM domain_authorizations x WHERE x.domain_id = d.id
                      ORDER BY (x.revoked_at IS NULL AND current_date BETWEEN x.valid_from AND x.valid_until) DESC,
                               x.valid_until DESC LIMIT 1) a ON true
  LEFT JOIN LATERAL (SELECT v.result FROM dns_txt_verifications v
                      WHERE v.domain_id = d.id ORDER BY v.checked_at DESC LIMIT 1) t ON true
  LEFT JOIN LATERAL (SELECT ds.score FROM domain_scores ds
                      WHERE ds.domain_id = d.id ORDER BY ds.computed_at DESC LIMIT 1) s ON true
 ORDER BY s.score DESC NULLS LAST, d.status = 'pending_verification' DESC, d.fqdn
"""

FINDINGS = """
SELECT f.evidence->>'title'                                 AS finding,
       a.value                                              AS asset,
       initcap(replace(r.category, '_', ' '))               AS category,
       CASE s.code WHEN 'hibp' THEN 'HIBP API' WHEN 'shodan' THEN 'Shodan' WHEN 'dns' THEN 'DNS'
                   WHEN 'ct_logs' THEN 'CT' WHEN 'whois' THEN 'WHOIS' ELSE s.code END AS source,
       initcap(f.severity)                                  AS severity,
       CASE WHEN f.status <> 'open'            THEN initcap(f.status)
            WHEN sc.id IS NULL                 THEN 'New'
            WHEN f.detected_at >= sc.queued_at THEN 'New'
            ELSE 'Recurring' END                            AS status
  FROM findings f
  JOIN domains d       ON d.id = f.domain_id
  JOIN assets a        ON a.id = f.asset_id
  JOIN scoring_rules r ON r.id = f.rule_id
  JOIN data_sources s  ON s.id = f.source_id
  LEFT JOIN scans sc   ON sc.id = f.last_scan_id
 WHERE d.fqdn = %s AND f.status = 'open'
 ORDER BY array_position(ARRAY['critical','high','medium','low'], f.severity), f.detected_at DESC, f.id
"""

SCORE = """
SELECT ds.score, """ + LEVEL.format(s='ds.score') + """ AS level, rs.version AS rule_set,
       ds.category_scores, rs.category_weights, ds.computed_at
  FROM domain_scores ds
  JOIN domains d            ON d.id = ds.domain_id
  JOIN scoring_rule_sets rs ON rs.id = ds.rule_set_id
 WHERE d.fqdn = %s
 ORDER BY ds.computed_at DESC LIMIT 1
"""

CATEGORIES = [('infrastructure', 'Infrastructure'), ('digital_identity', 'Digital Identity'),
              ('configuration', 'Configuration'), ('data_leaks', 'Data Leaks')]


def known_domain(session, fqdn):
    if not query(session, 'SELECT 1 FROM domains WHERE fqdn = %s', (fqdn,)):
        # RLS hides other clients' domains, so they look exactly like domains that do not exist
        raise HTTPException(404, 'Dominio no encontrado para esta organización')


@app.get('/health', tags=['sistema'], summary='Estado de la API y de la base')
def health():
    # Público y sin sesión: solo dice que la API y la base responden. Sin la versión de PostgreSQL ni el rol (RC-291).
    # Si la base no contesta, la excepción da el 500 de siempre.
    with transaction() as conn:
        conn.execute('SELECT 1')
    return {'status': 'ok'}


@app.get('/domains', tags=['dominios'], summary='Dominios del cliente con autorización, TXT y score')
def list_domains(session: Session = Depends(current_session)):
    return query(session, DOMAINS)


@app.get('/domains/{fqdn}/findings', tags=['dominios'], summary='Hallazgos abiertos de un dominio, por severidad')
def list_findings(fqdn: str, session: Session = Depends(require_roles('analyst', 'admin'))):  # RC-280
    known_domain(session, fqdn)
    return query(session, FINDINGS, (fqdn,))


@app.get('/domains/{fqdn}/score', tags=['dominios'], summary='Score de exposición por categoría con sus pesos')
def domain_score(fqdn: str, session: Session = Depends(current_session)):
    known_domain(session, fqdn)
    rows = query(session, SCORE, (fqdn,))
    if not rows:
        raise HTTPException(404, 'El dominio aún no tiene score')
    r = rows[0]
    return {
        'domain': fqdn, 'score': r['score'], 'level': r['level'], 'rule_set': r['rule_set'],
        'computed_at': r['computed_at'],
        'categories': [{'category': label, 'score': r['category_scores'][key],
                        'weight': float(r['category_weights'][key])} for key, label in CATEGORIES],
    }
