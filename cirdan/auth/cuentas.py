"""Cuentas del portal (#141, RC-259): reglas del cambio de rol y de la baja, y la baja misma.

`desactivar()` es la misma función que usa el comando del operador (RC-227) cuando llegue: marca la cuenta inactiva,
revoca las llaves de API que creó y devuelve lo que hay que cerrar en Valkey. `cerrar_sesiones()` va después del
commit, para no cerrar sesiones de un cambio que al final no se guardó.

Reglas (control 5.18 de docs/politica_seguridad_privacidad.md):
- Un Admin no puede quitarse su rol ni desactivarse a sí mismo.
- No se puede quitar el rol ni desactivar al último Admin activo de la empresa.
- El rol `operator` (integrador, migración 033) no se da ni se quita aquí: lo pone el equipo como postgres.
- Cada cambio lleva un motivo, que queda en la bitácora con quién, a quién y qué.
"""
ROLES = ('analyst', 'manager', 'admin')
MOTIVO_MINIMO, MOTIVO_MAXIMO = 3, 300


class CambioInvalido(ValueError):
    """El cambio no se puede hacer. `codigo` es el HTTP: 409 por las reglas de arriba, 422 por un cuerpo inválido."""

    def __init__(self, mensaje, codigo=409):
        super().__init__(mensaje)
        self.codigo = codigo


def motivo_valido(motivo):
    if not isinstance(motivo, str):
        raise CambioInvalido('Escribe el motivo del cambio (reason).', 422)
    limpio = ' '.join(''.join(c for c in motivo if c.isprintable()).split())
    if not MOTIVO_MINIMO <= len(limpio) <= MOTIVO_MAXIMO:
        raise CambioInvalido('El motivo debe tener entre %d y %d caracteres.' % (MOTIVO_MINIMO, MOTIVO_MAXIMO), 422)
    return limpio


def validar_cambio(actor_id, objetivo, rol=None, activo=None, admins_activos=()):
    """Revisa el cambio pedido sobre `objetivo` ({id, role, is_active}) y devuelve lo que cambia de verdad.

    `admins_activos`: ids de los Admin activos de la empresa, leídos con FOR UPDATE por quien llama.
    Devuelve {'role': nuevo o None, 'is_active': nuevo o None}; los dos en None si no cambia nada.
    """
    if rol is None and activo is None:
        raise CambioInvalido('Indica el rol nuevo (role) o si la cuenta queda activa (is_active).', 422)
    if rol is not None and rol not in ROLES:
        raise CambioInvalido('role debe ser uno de: %s' % ', '.join(ROLES), 422)
    if activo is not None and not isinstance(activo, bool):
        raise CambioInvalido('is_active debe ser true o false.', 422)
    if objetivo['role'] not in ROLES:
        raise CambioInvalido('El rol de un integrador (operator) no se cambia desde aquí.')
    nuevo_rol = rol if rol is not None and rol != objetivo['role'] else None
    nuevo_activo = activo if activo is not None and activo != objetivo['is_active'] else None
    if str(objetivo['id']) == str(actor_id) and (nuevo_rol is not None or nuevo_activo is False):
        raise CambioInvalido('No puedes quitarte tu propio rol ni desactivar tu cuenta. Pídeselo a otro Admin.')
    deja_de_ser_admin = objetivo['role'] == 'admin' and objetivo['is_active'] and (
        (nuevo_rol is not None and nuevo_rol != 'admin') or nuevo_activo is False)
    if deja_de_ser_admin and not ({str(a) for a in admins_activos} - {str(objetivo['id'])}):
        raise CambioInvalido('Es el último Admin activo de la empresa: primero da el rol de Admin a otra cuenta.')
    return {'role': nuevo_rol, 'is_active': nuevo_activo}


def desactivar(conn, user_id):
    """Marca la cuenta inactiva y revoca sus llaves de API vigentes, en la transacción de quien llama (RLS de la
    empresa). Devuelve los prefijos de las llaves revocadas. Las sesiones se cierran con cerrar_sesiones() después del
    commit."""
    conn.execute('UPDATE users SET is_active = false, updated_at = now() WHERE id = %s', (user_id,))
    filas = conn.execute(
        'UPDATE api_keys SET revoked_at = now(), updated_at = now() '
        'WHERE created_by = %s AND revoked_at IS NULL RETURNING key_prefix', (user_id,)).fetchall()
    return sorted(f['key_prefix'] for f in filas)


def cerrar_sesiones(user_id):
    """Cierra todas las sesiones abiertas de la cuenta, para que un cambio de rol o una baja apliquen al momento."""
    from cirdan.auth import sessions   # Valkey solo al usarla: las reglas de arriba se prueban sin servicios
    sessions.delete_others(str(user_id), None)
