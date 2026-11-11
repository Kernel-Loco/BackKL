"""Dependencias de FastAPI: quién llama, a partir de la cookie de sesión o de una llave de API."""
from dataclasses import dataclass

from fastapi import HTTPException, Request

from cirdan.auth import api_keys, sessions
from cirdan.config import config

COOKIE = 'lt_session'
COOKIE_SECURE = config('COOKIE_SECURE', 'false').lower() == 'true'  # true en producción (HTTPS)
ROL_LLAVE = 'api_key'  # no es un rol de la base: ningún require_roles() lo deja pasar
LLAVE_INVALIDA = 'La llave de API no es válida, venció o fue revocada.'


@dataclass(frozen=True)
class Session:
    token: str
    user_id: str | None
    org_id: str
    role: str
    email: str
    domain_id: str | None = None    # solo con una llave de API de un dominio: lo único que puede leer
    api_key_id: str | None = None   # solo con llave de API


def current_session(request: Request) -> Session:
    """La sesión vigente o 401. La empresa siempre sale de aquí, nunca de un encabezado."""
    token = request.cookies.get(COOKIE)
    data = sessions.get(token)
    if not data:
        raise HTTPException(401, 'Tu sesión terminó. Vuelve a iniciar sesión.')
    return Session(token=token, user_id=data['user_id'], org_id=data['org_id'], role=data['role'], email=data['email'])


def session_or_api_key(request: Request) -> Session:
    """Para las lecturas que un integrador puede hacer con su llave (#87, RC-129).

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
            raise HTTPException(403, 'Tu rol no tiene permiso para esta acción.')
        return session
    return dependency
