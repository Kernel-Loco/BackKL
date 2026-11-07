"""Verificación del registro TXT de propiedad: `cirdan-verification=<txt_token>`.

Es una consulta DNS normal (pasiva) al dominio autorizado, primero a 1.1.1.1 por el puerto 53. Si ese camino falla con
algo que no sea NXDOMAIN ni NoAnswer (un timeout en una red que bloquea el 53 hacia afuera, como la del Tec, o un
SERVFAIL), se pregunta lo mismo por DNS sobre HTTPS (RFC 8484) a https://1.0.0.1/dns-query: un POST del mensaje DNS en
formato wire con transporte.descargar, que le da un plazo absoluto de 5 s a toda la petición (connect, TLS y lectura),
revisa el certificado contra la IP, no usa proxies, no sigue redirecciones y no lee más de 65535 bytes. Nunca se usa el
DNS del sistema. El peor caso pasa de unos 5 s a unos 10 s: dnspython puede pasarse unas décimas de su lifetime en el 53
(#119, RC-236).

El resolvedor y el transporte se pueden cambiar en las pruebas para no salir a la red.
"""
import http.client
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver

from cirdan.recolectores import transporte

PREFIJO = 'cirdan-verification='
RESOLVER_IP = '1.1.1.1'
TIMEOUT_S = 5.0
DOH_IP = '1.0.0.1'        # fija: getaddrinfo no consulta DNS por una IP literal y su certificado la trae en el SAN
DOH_URL = 'https://%s/dns-query' % DOH_IP
DOH_TIPO = 'application/dns-message'
DOH_TOPE = 65535          # el mensaje DNS más largo que existe: su largo es de 16 bits
AGENTE = 'lowtide-osint/0.1 (+https://github.com/Kernel-Loco)'   # el mismo de crtsh.py

# Lo que puede salir de una petición DoH que no respondió bien: la red, el TLS y un HTTP 4xx o 5xx (OSError, con
# urllib.error.HTTPError), una respuesta HTTP mal formada (HTTPException), el tope o el tipo de contenido (ValueError),
# el plazo, una redirección y un mensaje DNS que no se puede leer o un nombre inválido (DNSException).
FALLAS_DOH = (OSError, http.client.HTTPException, ValueError, transporte.PlazoVencido, transporte.Redirigida,
              dns.exception.DNSException)


@dataclass(frozen=True)
class ConsultaTxt:
    """Lo que respondió el DNS: los valores TXT, o None si no hay registro; `error` si el DNS falló.

    `resolver_ip` es el resolvedor del camino que dio el resultado: RESOLVER_IP si respondió el 53, DOH_IP si se
    preguntó por DoH, también cuando DoH falló."""
    valores: tuple | None
    resolver_ip: str = RESOLVER_IP
    error: str = ''


def consultar_dns(fqdn, cronometro=None):
    """Los TXT de `fqdn`: por el 53 a RESOLVER_IP y, si ese camino falla, por DoH a DOH_URL. NXDOMAIN o NoAnswer por
    el 53 ya son una respuesta (no hay registro) y no pasan a DoH. `cronometro` (time.monotonic por omisión) mide el
    plazo de DoH."""
    consulta = _por_53(fqdn)
    if not consulta.error:
        return consulta
    doh = _por_doh(fqdn, cronometro or time.monotonic)
    if doh.error:
        return ConsultaTxt(None, DOH_IP, '%s | DoH: %s' % (consulta.error, doh.error))
    return doh


def _por_53(fqdn):
    """Los TXT de `fqdn` con el resolvedor público RESOLVER_IP por el puerto 53, con TIMEOUT_S de lifetime."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [RESOLVER_IP]
    resolver.lifetime = TIMEOUT_S
    try:
        respuesta = resolver.resolve(fqdn, 'TXT')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return ConsultaTxt(None)
    except dns.exception.DNSException as e:
        return ConsultaTxt(None, error='%s: %s' % (type(e).__name__, e))
    return ConsultaTxt(_valores(respuesta))


def _por_doh(fqdn, cronometro):
    """Los TXT de `fqdn` por DNS sobre HTTPS (RFC 8484) a DOH_URL, todo dentro de TIMEOUT_S. La respuesta tiene que
    ser de la pregunta y no venir truncada. NXDOMAIN es que no hay registro, NOERROR sigue la cadena de CNAME como
    resolve() y cualquier otro rcode es un error."""
    plazo = cronometro() + TIMEOUT_S
    try:
        pregunta = dns.message.make_query(fqdn, dns.rdatatype.TXT)
        pregunta.id = 0   # RFC 8484, 4.1: el ID va en 0. TLS ya protege la respuesta y la pregunta se compara entera
        req = urllib.request.Request(DOH_URL, data=pregunta.to_wire(), method='POST', headers={
            'User-Agent': AGENTE, 'Accept': DOH_TIPO, 'Content-Type': DOH_TIPO})
        respuesta = dns.message.from_wire(transporte.descargar(req, plazo, DOH_TOPE, cronometro, tipo=DOH_TIPO))
        if not pregunta.is_response(respuesta):
            return ConsultaTxt(None, DOH_IP, 'la respuesta no es de la pregunta')
        if respuesta.flags & dns.flags.TC:
            return ConsultaTxt(None, DOH_IP, 'la respuesta viene truncada')
        rcode = respuesta.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            return ConsultaTxt(None, DOH_IP)
        if rcode != dns.rcode.NOERROR:
            return ConsultaTxt(None, DOH_IP, 'rcode %s' % dns.rcode.to_text(rcode))
        cadena = respuesta.resolve_chaining()
    except FALLAS_DOH as e:
        if isinstance(e, urllib.error.HTTPError):
            e.close()   # trae la respuesta abierta, con su socket
        return ConsultaTxt(None, DOH_IP, '%s: %s' % (type(e).__name__, e))
    if cadena.answer is None:   # NOERROR sin TXT al final de la cadena, como NoAnswer
        return ConsultaTxt(None, DOH_IP)
    return ConsultaTxt(_valores(cadena.answer), DOH_IP)


def _valores(rrset):
    """Cada TXT de `rrset` con sus cadenas unidas, como texto. Un byte NUL, válido en DNS, sale como U+FFFD igual que un
    byte que no es UTF-8: PostgreSQL no guarda NUL en text y observed_values lo rechazaría."""
    return tuple(b''.join(r.strings).decode('utf-8', 'replace').replace('\x00', '\ufffd') for r in rrset)


def esperado(txt_token):
    return PREFIJO + txt_token


def resultado(consulta, txt_token):
    """`match`, `mismatch`, `missing` o `dns_error`, como dns_txt_verifications.result."""
    if consulta.error:
        return 'dns_error'
    if not consulta.valores:
        return 'missing'
    return 'match' if esperado(txt_token) in consulta.valores else 'mismatch'
