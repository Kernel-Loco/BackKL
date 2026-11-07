"""Pruebas de la verificación del TXT de propiedad (cirdan/orquestador/txt.py) con su respaldo por DNS sobre HTTPS
(#119, RC-236), sin red: el puerto 53 con un Resolver falso y DoH con un transporte.abrir falso, o con el TLS de verdad
sobre socket.socketpair() y un certificado hecho en la prueba, sin dirección de red (como Transporte de test_rdap.py).
Los mensajes DNS son de dnspython, armados aquí.

    python -m unittest -v pruebas/test_txt.py

Pide dnspython y cryptography, que están en la imagen y no en el runner del CI: corre dentro del contenedor, como
test_orquestador.py.
"""
import io
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from http.client import HTTPMessage, IncompleteRead
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_txt.py

import dns.flags  # noqa: E402
import dns.message  # noqa: E402
import dns.name  # noqa: E402
import dns.rcode  # noqa: E402
import dns.rdataclass  # noqa: E402
import dns.rdatatype  # noqa: E402
import dns.resolver  # noqa: E402
import dns.rrset  # noqa: E402

from cirdan.orquestador import txt  # noqa: E402
from cirdan.recolectores import transporte  # noqa: E402

FQDN = 'olmardo.com'
TOKEN = 'c41d7e2a9b06'
TXT_BUENO = 'cirdan-verification=' + TOKEN
TIMEOUT_53 = dns.resolver.LifetimeTimeout(timeout=5.0, errors=[])


class Cronometro:
    """Un reloj que avanza solo cuando la prueba lo mueve."""

    def __init__(self, t=100.0):
        self.t = t

    def __call__(self):
        return self.t


def resolver_falso(respuesta=None, error=None, antes=None):
    """Una clase Resolver que responde `respuesta` (una lista de TXT, cada uno una tupla de cadenas) o lanza `error`.
    `antes` corre antes de responder (para mover el reloj lo que tarda el 53). `creados` guarda cada instancia para
    revisar cómo se configuró."""
    class Rdata:
        def __init__(self, cadenas):
            self.strings = tuple(c.encode() for c in cadenas)

    class Resolver:
        creados = []

        def __init__(self, configure=True):
            self.configure, self.nameservers, self.lifetime, self.pedidos = configure, None, None, []
            Resolver.creados.append(self)

        def resolve(self, nombre, tipo):
            self.pedidos.append((nombre, tipo))
            if antes is not None:
                antes()
            if error is not None:
                raise error
            return [Rdata(r) for r in respuesta]
    return Resolver


def respuesta_dns(pedido, rcode=dns.rcode.NOERROR, txt_=(), nombre=None, cname=None, otro_id=False, sin_qr=False,
                  truncada=False, otra_pregunta=False):
    """El mensaje DNS en wire que responde a `pedido` (la pregunta en wire): los TXT de `txt_` (cada uno una tupla de
    cadenas) en `nombre` (el de la pregunta por omisión) o, con `cname`, un CNAME del nombre a `cname` con los TXT
    allá."""
    pregunta = dns.message.from_wire(pedido)
    if otra_pregunta:
        pregunta = dns.message.make_query('otro-' + FQDN, dns.rdatatype.TXT)
        pregunta.id = 0
    r = dns.message.make_response(pregunta)
    r.set_rcode(rcode)
    qname = pregunta.question[0].name
    destino = dns.name.from_text(cname) if cname else (dns.name.from_text(nombre) if nombre else qname)
    if cname:
        r.answer.append(dns.rrset.from_text(qname, 300, 'IN', 'CNAME', destino.to_text()))
    if txt_:
        r.answer.append(dns.rrset.from_text_list(destino, 300, 'IN', 'TXT',
                                                 [' '.join('"%s"' % c for c in t) for t in txt_]))
    if otro_id:
        r.id = 4242
    if sin_qr:
        r.flags &= ~dns.flags.QR
    if truncada:
        r.flags |= dns.flags.TC
    return r.to_wire()


class RespuestaFalsa(io.BytesIO):
    """Una respuesta HTTP 200 con `tipo` en Content-Type, que entrega a lo más `bloque` bytes por lectura. `al_leer`
    corre antes de cada lectura (para mover el reloj o lanzar una excepción)."""

    def __init__(self, cuerpo, tipo=txt.DOH_TIPO, al_leer=None, bloque=None):
        super().__init__(cuerpo)
        self.headers = HTTPMessage()
        if tipo is not None:
            self.headers['Content-Type'] = tipo
        self.al_leer, self.bloque = al_leer, bloque

    def read1(self, n=-1):
        if self.al_leer:
            self.al_leer()
        return super().read1(min(n, self.bloque) if self.bloque else n)


class Doh:
    """Un transporte.abrir falso que guarda cada petición y responde lo que diga `responder(pedido)`: una RespuestaFalsa
    o una excepción, que se lanza."""

    def __init__(self, responder):
        self.responder, self.peticiones = responder, []

    def __call__(self, req, plazo, cronometro):
        self.peticiones.append((req, plazo, cronometro()))
        salida = self.responder(req.data)
        if isinstance(salida, BaseException):
            raise salida
        return salida


def sin_red(req, plazo, cronometro):
    raise AssertionError('se preguntó por DoH: %s' % req.full_url)


class Respaldo(unittest.TestCase):
    """consultar_dns con el 53 y DoH falsos."""

    def consultar(self, resolver, abrir, cronometro=None):
        with mock.patch.object(txt.dns.resolver, 'Resolver', resolver), mock.patch.object(transporte, 'abrir', abrir):
            return txt.consultar_dns(FQDN, cronometro=cronometro)

    def doh(self, cuerpo=None, **opciones):
        """La consulta con el 53 vencido y DoH respondiendo `respuesta_dns(pedido, **opciones)` (o `cuerpo`)."""
        abrir = Doh(lambda pedido: RespuestaFalsa(cuerpo if cuerpo is not None else respuesta_dns(pedido, **opciones)))
        return self.consultar(resolver_falso(error=TIMEOUT_53), abrir), abrir

    def test_1_el_53_bueno_no_pregunta_por_doh(self):
        resolver = resolver_falso([('cirdan-verification=', TOKEN), ('v=spf1 -all',)])
        consulta = self.consultar(resolver, sin_red)
        self.assertEqual(consulta, txt.ConsultaTxt((TXT_BUENO, 'v=spf1 -all'), '1.1.1.1'))
        self.assertEqual(txt.resultado(consulta, TOKEN), 'match')
        [creado] = resolver.creados
        self.assertEqual((creado.configure, creado.nameservers, creado.lifetime, creado.pedidos),
                         (False, ['1.1.1.1'], 5.0, [(FQDN, 'TXT')]))
        otro = self.consultar(resolver_falso([('cirdan-verification=otro',)]), sin_red)
        self.assertEqual((txt.resultado(otro, TOKEN), otro.resolver_ip), ('mismatch', '1.1.1.1'))

    def test_2_nxdomain_y_noanswer_por_el_53_son_missing_sin_doh(self):
        for error in (dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()):
            with self.subTest(error=type(error).__name__):
                consulta = self.consultar(resolver_falso(error=error), sin_red)
                self.assertEqual(consulta, txt.ConsultaTxt(None, '1.1.1.1'))
                self.assertEqual(txt.resultado(consulta, TOKEN), 'missing')

    def test_3_con_el_53_caido_pregunta_por_post_a_la_url_fija_dentro_de_5_s(self):
        """Un timeout o NoNameservers (un SERVFAIL de 1.1.1.1) pasan a DoH: un POST del mensaje DNS en wire, con el ID
        en 0 (RFC 8484, 4.1), a https://1.0.0.1/dns-query con su tipo de contenido y un plazo de 5 s desde que
        empieza DoH, después de lo que tardó el 53 (5.4 s aquí), no desde que empezó la consulta."""
        for error in (TIMEOUT_53, dns.resolver.NoNameservers(request=dns.message.make_query(FQDN, 'TXT'), errors=[])):
            with self.subTest(error=type(error).__name__):
                reloj = Cronometro(100.0)

                def tarda():
                    reloj.t += 5.4
                abrir = Doh(lambda pedido: RespuestaFalsa(respuesta_dns(pedido, txt_=[(TXT_BUENO,)])))
                consulta = self.consultar(resolver_falso(error=error, antes=tarda), abrir, cronometro=reloj)
                self.assertEqual(consulta, txt.ConsultaTxt((TXT_BUENO,), '1.0.0.1'))
                self.assertEqual(txt.resultado(consulta, TOKEN), 'match')
                [(req, plazo, inicio)] = abrir.peticiones
                self.assertEqual((req.get_method(), req.full_url), ('POST', 'https://1.0.0.1/dns-query'))
                self.assertAlmostEqual(inicio, 105.4)
                self.assertAlmostEqual(plazo, 110.4)
                self.assertEqual((req.get_header('Content-type'), req.get_header('Accept'),
                                  req.get_header('User-agent')),
                                 ('application/dns-message', 'application/dns-message', txt.AGENTE))
                pregunta = dns.message.from_wire(req.data)
                self.assertEqual((pregunta.id, pregunta.flags & dns.flags.QR, bool(pregunta.flags & dns.flags.RD)),
                                 (0, 0, True))
                [q] = pregunta.question
                self.assertEqual((q.name, q.rdtype, q.rdclass),
                                 (dns.name.from_text(FQDN), dns.rdatatype.TXT, dns.rdataclass.IN))

    def test_4_doh_da_match_mismatch_y_missing(self):
        casos = [
            ('match con varias cadenas', {'txt_': [('cirdan-verification=', TOKEN), ('v=spf1 -all',)]}, 'match',
             (TXT_BUENO, 'v=spf1 -all')),
            ('match por un CNAME', {'cname': 'verifica.otro.example', 'txt_': [(TXT_BUENO,)]}, 'match', (TXT_BUENO,)),
            ('mismatch', {'txt_': [('cirdan-verification=otro',)]}, 'mismatch', ('cirdan-verification=otro',)),
            ('NOERROR sin TXT', {}, 'missing', None),
            ('NOERROR con el TXT en otro nombre', {'nombre': 'otro.example', 'txt_': [(TXT_BUENO,)]}, 'missing', None),
            ('NXDOMAIN', {'rcode': dns.rcode.NXDOMAIN}, 'missing', None),
        ]
        for nombre, opciones, esperado, valores in casos:
            with self.subTest(nombre):
                consulta, abrir = self.doh(**opciones)
                # un RRset no tiene orden: se comparan los valores como conjunto
                self.assertEqual((set(consulta.valores) if consulta.valores is not None else None,
                                  consulta.resolver_ip, consulta.error),
                                 (set(valores) if valores is not None else None, '1.0.0.1', ''))
                self.assertEqual(txt.resultado(consulta, TOKEN), esperado)
                self.assertEqual(len(abrir.peticiones), 1)

    def test_5_cada_falla_de_doh_es_dns_error_con_1_0_0_1(self):
        """Ninguna falla de DoH lanza: todas dan dns_error, con el error del 53 y el de DoH."""
        grande = b'\x00' * (txt.DOH_TOPE + 1)
        casos = [
            # los que fallan traen el TXT bueno: un match aquí sería leer la cadena antes del rcode o del estado HTTP
            ('SERVFAIL', lambda p: RespuestaFalsa(respuesta_dns(p, rcode=dns.rcode.SERVFAIL, txt_=[(TXT_BUENO,)])),
             'rcode SERVFAIL'),
            ('REFUSED', lambda p: RespuestaFalsa(respuesta_dns(p, rcode=dns.rcode.REFUSED, txt_=[(TXT_BUENO,)])),
             'rcode REFUSED'),
            ('HTTP 503', lambda p: urllib.error.HTTPError(txt.DOH_URL, 503, 'falla', HTTPMessage(),
                                                          io.BytesIO(respuesta_dns(p, txt_=[(TXT_BUENO,)]))),
             'HTTPError'),
            ('HTTP 400', lambda p: urllib.error.HTTPError(txt.DOH_URL, 400, 'mal', HTTPMessage(),
                                                          io.BytesIO(respuesta_dns(p, txt_=[(TXT_BUENO,)]))),
             'HTTPError'),
            ('tipo de contenido', lambda p: RespuestaFalsa(respuesta_dns(p, txt_=[(TXT_BUENO,)]), tipo='text/html'),
             'respuesta de tipo text/html, no application/dns-message'),
            ('sin tipo de contenido', lambda p: RespuestaFalsa(respuesta_dns(p, txt_=[(TXT_BUENO,)]), tipo=None),
             'respuesta de tipo text/plain'),
            ('JSON de Cloudflare', lambda p: RespuestaFalsa(b'{"Status":0}', tipo='application/dns-json'),
             'respuesta de tipo application/dns-json'),
            ('mensaje roto', lambda p: RespuestaFalsa(b'\x00\x01\x02'), 'ShortHeader'),
            ('cuerpo vacío', lambda p: RespuestaFalsa(b''), 'ShortHeader'),
            ('basura después del mensaje', lambda p: RespuestaFalsa(respuesta_dns(p) + b'\x00'), 'TrailingJunk'),
            ('otra pregunta', lambda p: RespuestaFalsa(respuesta_dns(p, otra_pregunta=True, txt_=[(TXT_BUENO,)])),
             'la respuesta no es de la pregunta'),
            ('otro ID', lambda p: RespuestaFalsa(respuesta_dns(p, otro_id=True, txt_=[(TXT_BUENO,)])),
             'la respuesta no es de la pregunta'),
            ('la pregunta de regreso', lambda p: RespuestaFalsa(p), 'la respuesta no es de la pregunta'),
            ('sin QR', lambda p: RespuestaFalsa(respuesta_dns(p, sin_qr=True, txt_=[(TXT_BUENO,)])),
             'la respuesta no es de la pregunta'),
            ('truncada', lambda p: RespuestaFalsa(respuesta_dns(p, truncada=True, txt_=[(TXT_BUENO,)])),
             'la respuesta viene truncada'),
            ('más de 65535 bytes', lambda p: RespuestaFalsa(grande), 'respuesta de más de 65535 bytes'),
            ('redirección', lambda p: transporte.Redirigida(302, '1.0.0.1'), 'Redirigida'),
            ('TLS', lambda p: urllib.error.URLError(ssl.SSLCertVerificationError(1, 'certificate verify failed')),
             'certificate verify failed'),
            ('conexión rechazada', lambda p: urllib.error.URLError(ConnectionRefusedError(111, 'rechazada')),
             'rechazada'),
            ('lectura incompleta', lambda p: RespuestaFalsa(b'', al_leer=self._lanza(IncompleteRead(b'', 10))),
             'IncompleteRead'),
        ]
        for nombre, responder, error in casos:
            with self.subTest(nombre):
                consulta = self.consultar(resolver_falso(error=TIMEOUT_53), Doh(responder))
                self.assertEqual((consulta.valores, consulta.resolver_ip, txt.resultado(consulta, TOKEN)),
                                 (None, '1.0.0.1', 'dns_error'))
                self.assertTrue(consulta.error.startswith('LifetimeTimeout: '), consulta.error)
                self.assertIn(' | DoH: ', consulta.error)
                self.assertIn(error, consulta.error)

    @staticmethod
    def _lanza(excepcion):
        def lanza():
            raise excepcion
        return lanza

    def test_6_el_plazo_de_doh_es_absoluto(self):
        """Una respuesta que llega de a poco no estira la consulta: con el reloj ya en el plazo antes del siguiente
        bloque, descargar lanza PlazoVencido y la verificación da dns_error. Un timeout del socket con el plazo vencido
        también es PlazoVencido."""
        reloj = Cronometro(0.0)

        def lento(pedido):
            cuerpo = respuesta_dns(pedido, txt_=[(TXT_BUENO,)])

            def avanza():
                reloj.t += 2.6   # el segundo bloque ya empieza pasado el plazo de 5 s
            return RespuestaFalsa(cuerpo, al_leer=avanza, bloque=10)
        consulta = self.consultar(resolver_falso(error=TIMEOUT_53), Doh(lento), cronometro=reloj)
        self.assertEqual((txt.resultado(consulta, TOKEN), consulta.resolver_ip), ('dns_error', '1.0.0.1'))
        self.assertIn('PlazoVencido: 1.0.0.1 no terminó dentro de su plazo', consulta.error)
        reloj = Cronometro(0.0)

        def timeout(pedido):
            reloj.t = 5.0
            return TimeoutError('timed out')
        consulta = self.consultar(resolver_falso(error=TIMEOUT_53), Doh(timeout), cronometro=reloj)
        self.assertIn('PlazoVencido', consulta.error)

    def test_7_un_nombre_invalido_es_dns_error_sin_lanzar(self):
        largo = 'a' * 64 + '.example'
        with mock.patch.object(txt.dns.resolver, 'Resolver', resolver_falso(error=dns.name.LabelTooLong())), \
                mock.patch.object(transporte, 'abrir', sin_red):
            consulta = txt.consultar_dns(largo)
        self.assertEqual((txt.resultado(consulta, TOKEN), consulta.resolver_ip), ('dns_error', '1.0.0.1'))
        self.assertIn('DoH: LabelTooLong', consulta.error)

    def test_7b_un_nul_en_el_txt_no_llega_a_la_evidencia(self):
        """Un TXT con un byte NUL (válido en DNS) sale con U+FFFD, por el 53 y por DoH: PostgreSQL no guarda NUL en
        text y el INSERT de la evidencia fallaría."""
        por_53 = self.consultar(resolver_falso([(TXT_BUENO,), ('a\x00b',)]), sin_red)
        consulta, _ = self.doh(txt_=[(TXT_BUENO,), ('a\\000b',)])
        for c in (por_53, consulta):
            self.assertEqual(set(c.valores), {TXT_BUENO, 'a\ufffdb'})
            self.assertEqual(txt.resultado(c, TOKEN), 'match')

    def test_8_el_resultado_no_cambia(self):
        self.assertEqual([txt.resultado(c, TOKEN) for c in (
            txt.ConsultaTxt((TXT_BUENO,)), txt.ConsultaTxt(('otro',)), txt.ConsultaTxt(None), txt.ConsultaTxt(()),
            txt.ConsultaTxt(None, error='x'), txt.ConsultaTxt((TXT_BUENO,), error='x'))],
            ['match', 'mismatch', 'missing', 'missing', 'dns_error', 'dns_error'])
        self.assertEqual(txt.ConsultaTxt(None).resolver_ip, '1.1.1.1')


class Extremo(socket.socket):
    """Un extremo de socket.socketpair() (AF_UNIX, sin red) que hace de socket TCP: http.client le pide TCP_NODELAY."""

    def setsockopt(self, *_):
        pass


def certificado(carpeta, nombre, ips=()):
    """Un certificado autofirmado de `nombre` con las IP `ips` también en el SAN, y su llave, hechos en la prueba:
    (ruta del certificado, ruta de la llave). Como el de Cloudflare, que lleva cloudflare-dns.com y 1.0.0.1."""
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    llave = ec.generate_private_key(ec.SECP256R1())
    sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre)])
    ahora = datetime.now(timezone.utc)
    publica = llave.public_key()
    san = [x509.DNSName(nombre)] + [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    cert = (x509.CertificateBuilder().subject_name(sujeto).issuer_name(sujeto).public_key(publica)
            .serial_number(x509.random_serial_number())
            .not_valid_before(ahora - timedelta(minutes=5)).not_valid_after(ahora + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(publica), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(publica), critical=False)
            .sign(llave, hashes.SHA256()))
    ruta_cert, ruta_llave = Path(carpeta) / 'cert.pem', Path(carpeta) / 'llave.pem'
    ruta_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ruta_llave.write_bytes(llave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    return str(ruta_cert), str(ruta_llave)


class ServidorDoh:
    """Un servidor DoH de una sola conexión sobre socket.socketpair(): lee la petición entera (cabeceras y el cuerpo
    de su Content-Length) y responde con un 200 de `tipo` y la respuesta DNS que arma `responder(pregunta)`, de una vez
    o de a un byte cada `paso` segundos."""

    def __init__(self, contexto, responder, tipo=txt.DOH_TIPO, paso=0):
        a, b = socket.socketpair()
        self.cliente, self.pedidos = Extremo(fileno=a.detach()), []
        self.hilo = threading.Thread(target=self._atender, args=(contexto, b, responder, tipo, paso), daemon=True)
        self.hilo.start()

    def _atender(self, contexto, extremo, responder, tipo, paso):
        extremo.settimeout(10)
        try:
            with contexto.wrap_socket(extremo, server_side=True) as tls:
                pedido = b''
                while b'\r\n\r\n' not in pedido:
                    parte = tls.recv(4096)
                    if not parte:
                        return
                    pedido += parte
                cabeceras, cuerpo = pedido.split(b'\r\n\r\n', 1)
                largo = next(int(linea.split(b':', 1)[1]) for linea in cabeceras.split(b'\r\n')
                             if linea.lower().startswith(b'content-length:'))
                while len(cuerpo) < largo:
                    parte = tls.recv(4096)
                    if not parte:
                        return
                    cuerpo += parte
                self.pedidos.append((cabeceras, cuerpo))
                dns_ = responder(cuerpo)
                respuesta = (b'HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n'
                             % (tipo.encode(), len(dns_))) + dns_
                for i in range(0, len(respuesta), 1 if paso else len(respuesta)):
                    tls.sendall(respuesta[i:i + 1] if paso else respuesta)
                    time.sleep(paso)
        except (OSError, StopIteration):
            pass
        finally:
            extremo.close()

    def cerrar(self):
        self.cliente.close()
        self.hilo.join(10)


class TlsDeVerdad(unittest.TestCase):
    """DoH con el transporte de verdad: http.client, el TLS de la imagen y el certificado revisado contra la IP 1.0.0.1
    del SAN. Solo el connect se cambia para que llegue a un extremo de socket.socketpair(), y revisa que el destino sea
    (1.0.0.1, 443), sin resolver nombres. El certificado pide cryptography, que está en la imagen."""

    def setUp(self):
        carpeta = tempfile.TemporaryDirectory()
        self.addCleanup(carpeta.cleanup)
        self.carpeta = carpeta.name

    def contextos(self, ips):
        Path(self.carpeta, str(len(ips))).mkdir()
        cert, llave = certificado(Path(self.carpeta, str(len(ips))), 'cloudflare-dns.com', ips)
        servidor_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        servidor_ctx.load_cert_chain(cert, llave)
        cliente_ctx = ssl.create_default_context(cafile=cert)   # como transporte._contexto, con esta CA
        cliente_ctx.sslsocket_class = transporte._SocketTls
        return servidor_ctx, cliente_ctx

    def consultar(self, servidor, cliente_ctx=None, timeout=txt.TIMEOUT_S):
        def conectar(conexion, direccion, *_):
            self.assertEqual(direccion, ('1.0.0.1', 443))
            servidor.cliente.settimeout(conexion.queda())   # como _conectar antes del handshake
            return servidor.cliente
        parches = [mock.patch.object(txt.dns.resolver, 'Resolver', resolver_falso(error=TIMEOUT_53)),
                   mock.patch.object(transporte._Conexion, '_conectar', conectar),
                   mock.patch.object(txt, 'TIMEOUT_S', timeout)]
        if cliente_ctx is not None:
            parches.append(mock.patch.object(transporte, '_contexto', lambda: cliente_ctx))
        try:
            for p in parches:
                p.start()
            return txt.consultar_dns(FQDN)
        finally:
            for p in reversed(parches):
                p.stop()
            servidor.cerrar()

    def test_1_un_post_de_verdad_con_el_certificado_de_la_ip_da_match(self):
        servidor_ctx, cliente_ctx = self.contextos(['1.0.0.1'])
        servidor = ServidorDoh(servidor_ctx, lambda p: respuesta_dns(p, txt_=[(TXT_BUENO,)]))
        consulta = self.consultar(servidor, cliente_ctx)
        self.assertEqual(consulta, txt.ConsultaTxt((TXT_BUENO,), '1.0.0.1'))
        [(cabeceras, cuerpo)] = servidor.pedidos
        self.assertTrue(cabeceras.startswith(b'POST /dns-query HTTP/1.1\r\n'), cabeceras)
        self.assertIn(b'\r\nHost: 1.0.0.1\r\n', cabeceras)
        self.assertIn(b'\r\nContent-Type: application/dns-message\r\n', cabeceras)
        self.assertEqual(dns.message.from_wire(cuerpo).question[0].name, dns.name.from_text(FQDN))

    def test_2_un_certificado_sin_la_ip_en_el_san_es_dns_error(self):
        servidor_ctx, cliente_ctx = self.contextos([])   # solo cloudflare-dns.com: no vale para 1.0.0.1
        servidor = ServidorDoh(servidor_ctx, lambda p: respuesta_dns(p, txt_=[(TXT_BUENO,)]))
        consulta = self.consultar(servidor, cliente_ctx)
        self.assertEqual((txt.resultado(consulta, TOKEN), consulta.resolver_ip), ('dns_error', '1.0.0.1'))
        self.assertIn('certificate verify failed', consulta.error)
        self.assertEqual(servidor.pedidos, [])

    def test_3_un_certificado_de_una_ca_que_no_es_del_sistema_es_dns_error(self):
        servidor_ctx, _ = self.contextos(['1.0.0.1'])
        servidor = ServidorDoh(servidor_ctx, lambda p: respuesta_dns(p, txt_=[(TXT_BUENO,)]))
        consulta = self.consultar(servidor)   # el contexto por omisión, con las CA del sistema
        self.assertEqual((txt.resultado(consulta, TOKEN), consulta.resolver_ip), ('dns_error', '1.0.0.1'))
        self.assertIn('certificate verify failed', consulta.error)
        self.assertEqual(servidor.pedidos, [])

    def test_4_un_servidor_lento_no_pasa_del_plazo(self):
        """De a un byte cada 0.05 s, la respuesta tardaría más de 4 s. Con el plazo en 0.5 s, la consulta termina con
        PlazoVencido en poco más de eso."""
        servidor_ctx, cliente_ctx = self.contextos(['1.0.0.1'])
        servidor = ServidorDoh(servidor_ctx, lambda p: respuesta_dns(p, txt_=[(TXT_BUENO,)]), paso=0.05)
        inicio = time.monotonic()
        consulta = self.consultar(servidor, cliente_ctx, timeout=0.5)
        self.assertLess(time.monotonic() - inicio, 2.0)
        self.assertEqual((txt.resultado(consulta, TOKEN), consulta.resolver_ip), ('dns_error', '1.0.0.1'))
        self.assertIn('PlazoVencido', consulta.error)


if __name__ == '__main__':
    unittest.main()
