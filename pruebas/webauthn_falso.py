"""Autenticador WebAuthn de prueba, solo con la biblioteca estándar (RC-331).

Arma las respuestas que daría un navegador con una passkey ES256 (P-256): navigator.credentials.create() con
attestation 'none' y navigator.credentials.get() firmado. Sirve para probar la API sin red, sin navegador y sin
cryptography, que el runner del CI no trae. La llave privada es de la prueba y no protege nada.

Las banderas, el origen, el RP ID, el user handle y el contador se pueden cambiar para armar respuestas malas.
"""
import base64
import hashlib
import json
import secrets

# P-256 (FIPS 186-4, D.1.2.3)
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

UP, UV, BE, BS, AT = 0x01, 0x04, 0x08, 0x10, 0x40


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64url(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        m = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (m * m - x1 - x2) % P
    return x3, (m * (x1 - x3) - y1) % P


def _mul(k, point):
    result = None
    while k:
        if k & 1:
            result = _add(result, point)
        point = _add(point, point)
        k >>= 1
    return result


def _der_int(value):
    raw = value.to_bytes((value.bit_length() + 8) // 8, 'big')
    return b'\x02' + bytes([len(raw)]) + raw


def sign(private, message):
    """ECDSA P-256 con SHA-256, firma en DER como la da un autenticador."""
    e = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    while True:
        k = secrets.randbelow(N - 1) + 1
        r = _mul(k, G)[0] % N
        s = pow(k, -1, N) * (e + r * private) % N
        if r and s:
            break
    body = _der_int(r) + _der_int(s)
    return b'\x30' + bytes([len(body)]) + body


def cbor(value):
    """CBOR mínimo (RFC 8949) para lo que lleva WebAuthn: enteros, bytes, texto y mapas."""
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for extra, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | extra]) + n.to_bytes(size, 'big')
        raise ValueError(n)
    if isinstance(value, bool):
        return b'\xf5' if value else b'\xf4'
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, dict):
        return head(5, len(value)) + b''.join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


class Autenticador:
    """Una passkey de prueba. `aaguid` va en ceros, como las de Windows Hello y los navegadores sin atestación."""

    def __init__(self, rp_id='localhost', origin='http://localhost:3000', sign_count=0):
        self.rp_id, self.origin, self.sign_count = rp_id, origin, sign_count
        self.private = secrets.randbelow(N - 1) + 1
        self.public = _mul(self.private, G)
        self.credential_id = secrets.token_bytes(32)
        self.user_handle = None

    def cose_key(self):
        x, y = self.public
        return cbor({1: 2, 3: -7, -1: 1, -2: x.to_bytes(32, 'big'), -3: y.to_bytes(32, 'big')})

    def _client_data(self, kind, challenge, origin=None):
        return json.dumps({'type': kind, 'challenge': challenge, 'origin': origin or self.origin,
                           'crossOrigin': False}).encode()

    def registro(self, options, flags=UP | UV | AT, origin=None, rp_id=None, transports=('hybrid', 'internal')):
        """Respuesta de navigator.credentials.create() a las opciones de /passkeys/register/options."""
        self.user_handle = unb64url(options['user']['id'])
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        auth_data = (rp_hash + bytes([flags]) + self.sign_count.to_bytes(4, 'big') + bytes(16)
                     + len(self.credential_id).to_bytes(2, 'big') + self.credential_id + self.cose_key())
        attestation = cbor({'fmt': 'none', 'attStmt': {}, 'authData': auth_data})
        cid = b64url(self.credential_id)
        return {'id': cid, 'rawId': cid, 'type': 'public-key', 'clientExtensionResults': {},
                'authenticatorAttachment': 'platform',
                'response': {'clientDataJSON': b64url(self._client_data('webauthn.create', options['challenge'], origin)),
                             'attestationObject': b64url(attestation), 'transports': list(transports)}}

    def entrada(self, options, flags=UP | UV, origin=None, rp_id=None, user_handle=None, sign_count=None,
                kind='webauthn.get', firma_mala=False):
        """Respuesta de navigator.credentials.get() a las opciones de /passkeys/login/options. Sin `sign_count`, el
        contador sube uno si ya no era 0, como en una llave física; en 0 se queda en 0, como en una passkey."""
        if sign_count is None:
            sign_count = self.sign_count + 1 if self.sign_count else 0
        self.sign_count = sign_count
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        auth_data = rp_hash + bytes([flags]) + sign_count.to_bytes(4, 'big')
        client_data = self._client_data(kind, options['challenge'], origin)
        signature = sign(self.private, auth_data + hashlib.sha256(client_data).digest())
        if firma_mala:
            signature = sign(self.private, b'otra cosa')
        handle = self.user_handle if user_handle is None else user_handle
        cid = b64url(self.credential_id)
        response = {'clientDataJSON': b64url(client_data), 'authenticatorData': b64url(auth_data),
                    'signature': b64url(signature)}
        if handle:
            response['userHandle'] = b64url(handle)
        return {'id': cid, 'rawId': cid, 'type': 'public-key', 'clientExtensionResults': {},
                'authenticatorAttachment': 'platform', 'response': response}
