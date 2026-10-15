"""Verificación del registro TXT de propiedad: `cirdan-verification=<txt_token>`.

Es una consulta DNS normal (pasiva) al dominio autorizado. El resolvedor se puede
cambiar en las pruebas para no salir a la red.
"""
from dataclasses import dataclass

import dns.exception
import dns.resolver

PREFIJO = 'cirdan-verification='
RESOLVER_IP = '1.1.1.1'
TIMEOUT_S = 5.0


@dataclass(frozen=True)
class ConsultaTxt:
    """Lo que respondió el DNS: los valores TXT, o None si no hay registro; `error` si el DNS falló."""
    valores: tuple | None
    resolver_ip: str = RESOLVER_IP
    error: str = ''


def consultar_dns(fqdn):
    """Consulta real de los TXT de un dominio con el resolvedor público 1.1.1.1."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [RESOLVER_IP]
    resolver.lifetime = TIMEOUT_S
    try:
        respuesta = resolver.resolve(fqdn, 'TXT')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return ConsultaTxt(None)
    except dns.exception.DNSException as e:
        return ConsultaTxt(None, error='%s: %s' % (type(e).__name__, e))
    valores = tuple(b''.join(r.strings).decode('utf-8', 'replace') for r in respuesta)
    return ConsultaTxt(valores)


def esperado(txt_token):
    return PREFIJO + txt_token


def resultado(consulta, txt_token):
    """`match`, `mismatch`, `missing` o `dns_error`, como dns_txt_verifications.result."""
    if consulta.error:
        return 'dns_error'
    if not consulta.valores:
        return 'missing'
    return 'match' if esperado(txt_token) in consulta.valores else 'mismatch'
