"""Dependencias de FastAPI: quién llama, a partir de la cookie de sesión."""
from dataclasses import dataclass

from fastapi import HTTPException, Request

from cirdan.auth import sessions
from cirdan.config import config

COOKIE = 'lt_session'
COOKIE_SECURE = config('COOKIE_SECURE', 'false').lower() == 'true'  # true en producción (HTTPS)


@dataclass(frozen=True)
class Session:
    token: str
    user_id: str
    org_id: str
    role: str
    email: str


def current_session(request: Request) -> Session:
    """La sesión vigente o 401. La empresa siempre sale de aquí, nunca de un encabezado."""
    token = request.cookies.get(COOKIE)
    data = sessions.get(token)
    if not data:
        raise HTTPException(401, 'Tu sesión terminó. Vuelve a iniciar sesión.')
    return Session(token=token, user_id=data['user_id'], org_id=data['org_id'], role=data['role'], email=data['email'])


def client_ip(request: Request):
    return request.client.host if request.client else None
