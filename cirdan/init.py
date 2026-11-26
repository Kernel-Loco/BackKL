"""PID 1 de la imagen (RC-324), en lugar de tini (`init: true` de docker-compose.yml).

tini corría con el uid 10001 y con todo el entorno del contenedor: un hijo de git o de gitleaks leía la contraseña de la
base, la de Valkey y la llave del MFA en /proc/1/environ aunque la API ya no fuera volcable. Este init hace lo mismo que
tini con lo que la API y el programador necesitan, pero antes se pone no volcable (cirdan/proceso.py):

- lanza el comando (el CMD de la imagen o el `command:` del servicio) con el mismo entorno,
- recoge a todos los procesos huérfanos, como los git que el recolector de GitHub mata por tiempo (#16), también si no
  es el PID 1 (PR_SET_CHILD_SUBREAPER, como `tini -s`),
- pasa SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1 y SIGUSR2 al comando,
- sale con el código del comando, o 128 + la señal que lo terminó.

    ENTRYPOINT ["python", "-m", "cirdan.init"]   (Dockerfile)
"""
import os
import signal
import sys

from cirdan.proceso import no_volcable, recoge_huerfanos

SENALES = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2)


def codigo_de_salida(estado):
    codigo = os.waitstatus_to_exitcode(estado)
    return 128 - codigo if codigo < 0 else codigo


def main(argv):
    if not argv:
        print('uso: python -m cirdan.init <comando> [argumentos]', file=sys.stderr)
        return 2
    no_volcable()  # antes de lanzar el comando: este proceso guarda el entorno completo
    recoge_huerfanos()  # como PID 1 ya le llegan; así también fuera de él (pruebas, `docker run --init`)
    pendientes = []
    hijo = None

    def pasar(senal, _marco):
        if hijo is None:
            pendientes.append(senal)  # llegó antes de lanzar el comando: se la pasa en cuanto exista
            return
        try:
            os.kill(hijo, senal)
        except ProcessLookupError:
            pass

    for senal in SENALES:
        signal.signal(senal, pasar)
    hijo = os.posix_spawnp(argv[0], argv, os.environ)
    for senal in pendientes:
        pasar(senal, None)
    while True:
        try:
            pid, estado = os.wait()  # recoge al comando y a cualquier huérfano que le llegue al PID 1
        except ChildProcessError:
            return 1  # no debería pasar: el comando siempre es hijo de este proceso
        if pid == hijo:
            return codigo_de_salida(estado)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
