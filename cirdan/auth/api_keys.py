"""Llaves de API para integradores (#87, RC-129).

La llave es `lt_<8 hex>_<43 caracteres>`: 256 bits al azar después del prefijo visible. Se entrega
una sola vez, al crearla. En la base solo quedan el prefijo (`lt_<8 hex>`) y el SHA-256 de la
llave completa, así que ni quien lea la base puede usarla. Como la llave ya es aleatoria de
256 bits, el SHA-256 sin sal basta: no hay nada que adivinar por diccionario.

Viaja en `Authorization: Bearer <llave>`. La empresa no sale de ningún encabezado: sale de la
fila de la llave, que se busca con api_key_lookup() (migración 016).
"""
import hashlib
import re
import secrets

from cirdan.db import transaction

FORMATO = re.compile(r'lt_[0-9a-f]{8}_[A-Za-z0-9_-]{43}')
LECTURA = 'read'   # único alcance de RC-129: los GET de datos de /api/v1


def huella(llave):
    return hashlib.sha256(llave.encode('ascii')).digest()


def generar():
    """Llave nueva: (llave completa, prefijo visible, SHA-256)."""
    prefijo = 'lt_' + secrets.token_hex(4)
    llave = prefijo + '_' + secrets.token_urlsafe(32)
    return llave, prefijo, huella(llave)


def del_encabezado(valor):
    """La llave de `Authorization: Bearer <llave>`. None si la petición no trae ese esquema."""
    if not valor:
        return None
    esquema, _, resto = valor.strip().partition(' ')
    if esquema.lower() != 'bearer':
        return None
    return resto.strip()


def buscar(llave):
    """La llave vigente (key_id, organization_id, domain_id, scopes) o None.

    Una llave con otro formato no llega a la base. El último uso se guarda a lo más una vez por
    minuto, en la misma conexión y ya con la empresa fijada para RLS."""
    if not FORMATO.fullmatch(llave):
        return None
    with transaction() as conn:
        fila = conn.execute('SELECT * FROM api_key_lookup(%s)', (huella(llave),)).fetchone()
        if not fila or LECTURA not in fila['scopes']:
            return None
        if fila['touch']:
            conn.execute("SELECT set_config('app.current_org', %s, true)", (str(fila['organization_id']),))
            conn.execute("UPDATE api_keys SET last_used_at = now() WHERE id = %s "
                         "AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')",
                         (fila['key_id'],))
    return fila
