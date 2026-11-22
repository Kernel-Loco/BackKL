"""Dependencias de FastAPI: quién llama, a partir de la cookie de sesión o de una llave de API."""
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import HTTPException, Request

from cirdan.auth import api_keys, sessions
from cirdan.config import config, origenes_permitidos
from cirdan.db import transaction

COOKIE = 'lt_session'
COOKIE_SECURE = config('COOKIE_SECURE', 'false').lower() == 'true'  # true en producción (HTTPS)


def comprobar_cookie_segura():
    """La API no arranca publicada por HTTPS con la cookie de sesión sin Secure (RC-286). Un origen https en
    ALLOWED_ORIGINS dice que el portal está publicado, y sin Secure el navegador también manda `lt_session` por http,
    por ejemplo con un enlace viejo a http://lowtidesec.com antes de la redirección. Con los orígenes locales
    (http://localhost) arranca como siempre. Lee el mismo COOKIE_SECURE que usa cirdan/auth/routes.py."""
    https = [o for o in origenes_permitidos() if urlsplit(o).scheme == 'https']
    if https and not COOKIE_SECURE:
        raise RuntimeError('ALLOWED_ORIGINS trae un origen https (%s) y COOKIE_SECURE no es true: la cookie de sesión '
                           'saldría sin Secure. Pon COOKIE_SECURE=true en .env (RC-286).' % ', '.join(https))


ROL_LLAVE = 'api_key'  # no es un rol de la base: ningún require_roles() lo deja pasar
LLAVE_INVALIDA = 'La llave de API no es válida, venció o fue revocada.'
SESION_TERMINADA = 'Tu sesión terminó. Vuelve a iniciar sesión.'
SIN_PERMISO = 'Tu rol no tiene permiso para esta acción.'


@dataclass(frozen=True)
class Session:
    token: str
    user_id: str | None
    org_id: str
    role: str
    email: str
    domain_id: str | None = None    # solo con una llave de API de un dominio: lo único que puede leer
    api_key_id: str | None = None   # solo con llave de API
    created_at: int | None = None   # solo con sesión: cuándo se creó en Valkey, para el tope de 8 h
    home_org_id: str | None = None  # solo con sesión: la empresa de la cuenta. org_id es la activa (RC-332)
    platform_admin: bool = False    # solo con sesión: superadmin de la plataforma al iniciarla (RC-332)

    @property
    def own_org_id(self) -> str:
        """La empresa de la cuenta. La fila del usuario (contraseña, MFA, /me) solo se ve con RLS de esta empresa."""
        return self.home_org_id or self.org_id

    @property
    def acting_elsewhere(self) -> bool:
        """Si un superadmin trabaja en una empresa que no es la suya. Ahí no puede quedar como autor de nada: las FK
        compuestas de la 001 piden un usuario de esa empresa."""
        return self.home_org_id is not None and self.org_id != self.home_org_id

    @property
    def audit_user_id(self) -> str | None:
        """actor_user_id para audit(): None en una empresa ajena, donde el autor va en `audit_platform`."""
        return None if self.acting_elsewhere else self.user_id

    @property
    def audit_platform(self) -> dict | None:
        """El superadmin que actúa en una empresa ajena, para audit(..., platform=...). None en su propia empresa."""
        return {'user_id': self.user_id} if self.acting_elsewhere else None

    @property
    def author(self) -> str:
        """Quién firma un registro que guarda texto libre (validated_by de los pesos): el correo en su empresa y
        'platform:<id>' en una ajena, donde el correo del personal de LowTide no debe quedar."""
        return 'platform:%s' % self.user_id if self.acting_elsewhere else self.email


def current_session(request: Request) -> Session:
    """La sesión vigente o 401. La empresa siempre sale de aquí, nunca de un encabezado."""
    token = request.cookies.get(COOKIE)
    data = sessions.get(token)
    if not data:
        raise HTTPException(401, SESION_TERMINADA)
    session = Session(token=token, user_id=data['user_id'], org_id=data['org_id'], role=data['role'], email=data['email'],
                      created_at=data.get('created_at'), home_org_id=data.get('home_org_id'),
                      platform_admin=bool(data.get('platform_admin')))
    if session.acting_elsewhere and not can_work_in(session.user_id, session.org_id):
        # Se le quitó el permiso o el TOTP, se desactivó la cuenta, se suspendió su empresa o se suspendió o canceló
        # la empresa ajena con la sesión abierta en ella: la sesión se cierra en la siguiente petición y no espera a
        # las 8 h.
        sessions.delete(token)
        raise HTTPException(401, SESION_TERMINADA)
    request.state.cirdan_session = session
    return session


def is_platform_admin(user_id) -> bool:
    """Lo dice la base en cada llamada (migración 017), no la sesión: cirdan_app no puede leer platform_admins."""
    with transaction() as conn:
        return bool(conn.execute('SELECT public.is_platform_admin(%s) AS ok', (user_id,)).fetchone()['ok'])


def can_work_in(user_id, org_id) -> bool:
    """Si el superadmin puede seguir trabajando en la empresa ajena `org_id`: sigue siendo superadmin y esa empresa
    sigue en trial o active. La empresa se lee con su propia RLS, en la misma transacción."""
    with transaction(org_id) as conn:
        return bool(conn.execute("SELECT public.is_platform_admin(%s) AND EXISTS (SELECT 1 FROM organizations"
                                 " WHERE id = %s AND status IN ('trial', 'active')) AS ok",
                                 (user_id, org_id)).fetchone()['ok'])


def session_or_api_key(request: Request) -> Session:
    """Para las lecturas que un sistema de la empresa puede hacer con su llave (#87, RC-129).

    Con `Authorization: Bearer` manda la llave y la cookie no cuenta: una llave que no sirve
    responde 401 aunque el navegador traiga una sesión. Sin ese encabezado, la sesión de siempre.
    La empresa sale de la fila de la llave, igual que con la cookie sale de la sesión."""
    llave = api_keys.del_encabezado(request.headers.get('authorization'))
    if llave is None:
        return current_session(request)
    fila = api_keys.buscar(llave)
    if not fila:
        raise HTTPException(401, LLAVE_INVALIDA, headers={'WWW-Authenticate': 'Bearer'})
    return Session(token='', user_id=None, org_id=str(fila['organization_id']), role=ROL_LLAVE, email='',
                   domain_id=str(fila['domain_id']) if fila['domain_id'] else None, api_key_id=str(fila['key_id']))


def in_scope(session: Session, domain_id) -> bool:
    """Si quien llama puede ver ese dominio de su empresa. Solo lo limita una llave de un dominio."""
    return session.domain_id is None or session.domain_id == str(domain_id)


def client_ip(request: Request):
    return request.client.host if request.client else None


def require_roles(*roles):
    """Dependencia que solo deja pasar a ciertos roles de la base (`analyst`, `manager`, `admin`).

    Siempre con la cookie de sesión: una llave de API no entra aquí."""
    def dependency(request: Request) -> Session:
        session = current_session(request)
        if session.role not in roles:
            raise HTTPException(403, SIN_PERMISO)
        return session
    return dependency


def api_key_or_roles(*roles):
    """Como session_or_api_key, pero con cookie solo deja pasar a esos roles de la base (RC-280).

    Una llave de API entra igual que con session_or_api_key: la crea un Admin y la limita su dominio. Con cookie, otro
    rol recibe 403, como require_roles(). Así el gerente no lee por la API lo que el portal no le muestra."""
    def dependency(request: Request) -> Session:
        session = session_or_api_key(request)
        if session.role != ROL_LLAVE and session.role not in roles:
            raise HTTPException(403, SIN_PERMISO)
        return session
    return dependency
