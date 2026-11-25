"""El entorno del proceso fuera del alcance de sus hijos (RC-324).

La API y el programador tienen en su entorno la contraseña de la base y otras llaves (docker-compose.yml). Sus hijos
(git, gitleaks y subfinder) ya corren con un entorno limpio, pero con el mismo uid 10001, y un proceso con el mismo uid
puede leer /proc/<pid>/environ del padre: la prueba en un compose aislado lo logró con el código de antes. Si un repo
ajeno explota un fallo de git o de gitleaks, leería los secretos de ahí.

prctl(PR_SET_DUMPABLE, 0) hace que /proc/<pid>/* del proceso sea de root y que ptrace no lo alcance sin
CAP_SYS_PTRACE, que el contenedor no tiene. Vale para todos los hilos del proceso y no pasa a los hijos: execve los
deja volcables, lo que no importa porque no traen secretos. Otro uid para los hijos no se puede: el contenedor corre
sin CAP_SETUID.
"""
import ctypes
import ctypes.util
import sys

PR_SET_DUMPABLE = 4
PR_GET_DUMPABLE = 3


def no_volcable():
    """Pone el proceso en no volcable y lo confirma. Fuera de Linux no hace nada (PC de desarrollo con Windows).

    Si prctl falla o el proceso sigue volcable, lanza RuntimeError: la API y el programador no arrancan."""
    if not sys.platform.startswith('linux'):
        return False
    libc = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6', use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise RuntimeError('prctl(PR_SET_DUMPABLE, 0) falló con errno %d' % ctypes.get_errno())
    if libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise RuntimeError('el proceso sigue volcable después de prctl(PR_SET_DUMPABLE, 0)')
    return True
