"""Llaves de API de las fuentes, cifradas en data_sources.api_key_enc (#19, RC-54).

La llave de una fuente (hoy solo la de Have I Been Pwned) se guarda cifrada con AES-256-GCM en la base y se descifra
aquí, con SOURCE_KEYS_ENCRYPTION_KEY del entorno o del .env: 32 bytes en base64 url-safe, como TOTP_ENCRYPTION_KEY
(cirdan/auth/totp.py). La base nunca ve la llave en claro y esta llave de cifrado nunca entra a la base.

El bytea es: versión (1 byte, hoy 1), nonce de 12 bytes, texto cifrado y tag. El dato asociado (AAD) es
'data_sources.api_key_enc:' más el código de la fuente: un valor copiado a la fila de otra fuente no descifra.

cirdan_app no puede leer api_key_enc: leer() llama a source_api_key() de la migración 032, que devuelve el bytea de
una fuente habilitada. El orquestador la llama solo en vivo y al grabar, y pasa la llave al recolector que declara
PIDE_LLAVE. Nunca se escribe en un log, un aviso, un error ni una grabación.

Para guardar la llave, quien tiene la cuenta de la fuente corre, con SOURCE_KEYS_ENCRYPTION_KEY puesta:

    python -m cirdan.recolectores.llaves cifrar hibp

Pide la llave sin mostrarla (getpass) y escribe el UPDATE que se corre como postgres (docs/servicios_externos.md). La
salida es la llave cifrada, no la llave.
"""
import base64
import binascii
import getpass
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cirdan.config import config

VARIABLE = 'SOURCE_KEYS_ENCRYPTION_KEY'
VERSION = 1
AAD = 'data_sources.api_key_enc:%s'
MAX_LLAVE = 256   # caracteres de una llave de API. La de HIBP es de 32


class LlaveIlegible(Exception):
    """La llave guardada no se puede descifrar: falta SOURCE_KEYS_ENCRYPTION_KEY, es otra o el valor está roto. El
    texto nunca trae la llave ni el valor cifrado."""


def _llave_de_cifrado():
    valor = (config(VARIABLE) or '').strip()
    if not valor:
        raise LlaveIlegible('falta %s: sin ella no se puede descifrar la llave de la fuente' % VARIABLE)
    try:
        llave = base64.urlsafe_b64decode(valor)
    except (binascii.Error, ValueError):
        llave = b''
    if len(llave) != 32:
        raise LlaveIlegible('%s debe ser de 32 bytes en base64 url-safe' % VARIABLE)
    return llave


def _bytes(blob):
    if isinstance(blob, memoryview):
        return blob.tobytes()
    return bytes(blob)


def cifrar(codigo, llave_api):
    """El bytea para data_sources.api_key_enc de la fuente `codigo`."""
    if not isinstance(llave_api, str) or not llave_api.strip() or len(llave_api.strip()) > MAX_LLAVE:
        raise ValueError('la llave de la fuente debe ser un texto de 1 a %d caracteres' % MAX_LLAVE)
    nonce = os.urandom(12)
    cifrado = AESGCM(_llave_de_cifrado()).encrypt(nonce, llave_api.strip().encode(), (AAD % codigo).encode())
    return bytes([VERSION]) + nonce + cifrado


def descifrar(codigo, blob):
    """La llave en claro de la fuente `codigo`, o LlaveIlegible."""
    blob = _bytes(blob)
    if len(blob) < 1 + 12 + 16 or blob[0] != VERSION:
        raise LlaveIlegible('la llave guardada de %s no tiene la forma de la versión %d' % (codigo, VERSION))
    try:
        texto = AESGCM(_llave_de_cifrado()).decrypt(blob[1:13], blob[13:], (AAD % codigo).encode())
        return texto.decode()
    except (InvalidTag, UnicodeDecodeError):
        raise LlaveIlegible('la llave guardada de %s no abre con %s' % (codigo, VARIABLE)) from None


def leer(conn, codigo):
    """La llave en claro de una fuente habilitada, None si no tiene, o LlaveIlegible si no se puede descifrar."""
    fila = conn.execute('SELECT public.source_api_key(%s) AS llave', (codigo,)).fetchone()
    blob = fila['llave'] if isinstance(fila, dict) else fila[0]
    if blob is None:
        return None
    return descifrar(codigo, blob)


def _main(argv):
    if len(argv) != 2 or argv[0] != 'cifrar':
        print('uso: python -m cirdan.recolectores.llaves cifrar <código de la fuente>', file=sys.stderr)
        return 2
    codigo = argv[1]
    llave_api = getpass.getpass('Llave de %s (no se muestra): ' % codigo)
    try:
        blob = cifrar(codigo, llave_api)
    except (ValueError, LlaveIlegible) as e:
        print(str(e), file=sys.stderr)
        return 1
    print("UPDATE data_sources SET api_key_enc = '\\x%s'::bytea, key_rotated_at = now(), updated_at = now() "
          "WHERE code = '%s';" % (blob.hex(), codigo.replace("'", "''")))
    return 0


if __name__ == '__main__':
    sys.exit(_main(sys.argv[1:]))
