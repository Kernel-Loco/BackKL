#!/usr/bin/env bash
# Respaldo diario coordinado de la base y las cartas (#115, RC-233, RC-28 y RC-339). Lo corre lowtide-respaldo.timer.
#
# 1. Espera hasta 5 min a que Postgres acepte conexiones (al arrancar la VM el timer corre antes que la base).
# 2. Cifra por separado pg_dump, el volumen de cartas cifradas y la llave de cartas, luego los agrupa y cifra con age.
#    Los temporales solo viven en /run (tmpfs); la llave privada de age no vive en la VM.
# 3. Deja el paquete en CARPETA con permisos 600 como cirdan_<fecha UTC>_<8 hex al azar>.backup.age. El sufijo
#    aleatorio evita que alguien ocupe antes en Azure el nombre del respaldo de mañana.
# 5. Con SUBIR=1 sube a Azure Blob, con la identidad administrada de la VM (IMDS) y sin llaves en disco, el
#    respaldo nuevo y cualquier local que todavía no esté allá (una subida que falló un día se repite al siguiente).
# 4. Conserva juntos los respaldos completos de los últimos RETENCION días. Las copias antiguas .dump.age se retienen
#    y suben como legado, pero no incluyen cartas y no sirven para habilitar un alta restaurada.
#
# Configuración en /etc/lowtide/respaldo.conf (o en RESPALDO_CONF), una CLAVE=valor por línea. No es un
# script: solo se leen las claves de abajo y cada valor se revisa. No lleva secretos, pero quien la cambie decide
# para quién se cifran los respaldos: tiene que ser del usuario que corre esto y nadie más puede escribirla.
set -Eeuo pipefail
umask 077
export LC_ALL=C

CONF=${RESPALDO_CONF:-/etc/lowtide/respaldo.conf}
CONTENEDOR_BASE=cirdan-pg16
CONTENEDOR_CARTAS=cirdan-api
CARPETA=/var/backups/lowtide
RECEPTOR_AGE=
RETENCION=7
SUBIR=1
CUENTA_BLOB=
CONTENEDOR_BLOB=respaldos
ESPERA_BASE=300        # segundos esperando a Postgres
PRESUPUESTO_SUBIDA=1200  # segundos desde el arranque después de los cuales ya no empieza otra subida

falla() { echo "respaldo: ERROR: $*" >&2; exit 1; }

[ -e "$CONF" ] || falla "no existe $CONF"
[ ! -L "$CONF" ] && [ -f "$CONF" ] || falla "$CONF tiene que ser un archivo, no un enlace"
read -r dueno modo < <(stat -c '%u %a' -- "$CONF")
[ "$dueno" = "$(id -u)" ] || falla "$CONF tiene que ser de $(id -un)"
(( (8#$modo & 8#022) == 0 )) || falla "$CONF no puede tener escritura para el grupo ni para otros (modo $modo)"
while IFS= read -r linea || [ -n "$linea" ]; do
  linea=${linea%$'\r'}
  case $linea in ''|'#'*) continue ;; esac
  clave=${linea%%=*}
  valor=${linea#*=}
  case $clave in
    CONTENEDOR_BASE|CONTENEDOR_CARTAS|CARPETA|RECEPTOR_AGE|RETENCION|SUBIR|CUENTA_BLOB|CONTENEDOR_BLOB) printf -v "$clave" '%s' "$valor" ;;
    *) falla "clave desconocida en $CONF: $clave" ;;
  esac
done < "$CONF"

[[ $CONTENEDOR_BASE =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || falla "CONTENEDOR_BASE no válido"
[[ $CONTENEDOR_CARTAS =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || falla "CONTENEDOR_CARTAS no válido"
while [[ $CARPETA == */ && $CARPETA != / ]]; do CARPETA=${CARPETA%/}; done
[[ $CARPETA =~ ^(/[A-Za-z0-9._-]+)+$ && $CARPETA != *..* ]] || falla "CARPETA tiene que ser una ruta absoluta sin '..' ni espacios"
[[ $RECEPTOR_AGE =~ ^age1[02-9ac-hj-np-z]{58}$ ]] || falla "RECEPTOR_AGE no es una llave pública de age"
[[ $RETENCION =~ ^[1-9][0-9]?$ ]] || falla "RETENCION va de 1 a 99"
[[ $SUBIR == 0 || $SUBIR == 1 ]] || falla "SUBIR es 0 o 1"
if [ "$SUBIR" = 1 ]; then
  [[ $CUENTA_BLOB =~ ^[a-z0-9]{3,24}$ ]] || falla "CUENTA_BLOB no es un nombre de cuenta de almacenamiento"
  [[ $CONTENEDOR_BLOB =~ ^[a-z0-9]([a-z0-9]|-[a-z0-9]){2,62}$ ]] || falla "CONTENEDOR_BLOB no válido"
fi
command -v age >/dev/null || falla "falta age (apt-get install age)"
command -v python3 >/dev/null || falla "falta python3"
temporal=/run
[ -w "$temporal" ] || temporal=/run/lock
[[ $(findmnt -n -o FSTYPE --target "$temporal" 2>/dev/null) == tmpfs ]] || falla "$temporal debe ser tmpfs para proteger los temporales"
# Archivos locales como máximo, aunque Azure lleve semanas sin recibir nada: 31, o 4 por día de retención.
TOPE_LOCAL=$(( RETENCION * 4 > 31 ? RETENCION * 4 : 31 ))

mkdir -p -m 700 "$CARPETA"
[ -d "$CARPETA" ] && [ ! -L "$CARPETA" ] || falla "$CARPETA no es una carpeta"
chmod 700 "$CARPETA"

# Un solo respaldo a la vez: un segundo arranque del timer, o uno a mano, espera hasta 10 min y luego se rinde.
exec 9>"$CARPETA/.candado"
flock -w 600 9 || falla "otro respaldo sigue corriendo"

PATRON='^cirdan_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}\.(backup|dump)\.age$'
raiz_nombre="cirdan_$(date -u +%Y%m%dT%H%M%SZ)_$(openssl rand -hex 4)"
parcial=

trabajo=$(mktemp -d "$temporal/lowtide-respaldo.XXXXXX")
limpiar() {
  [ -z "$parcial" ] || rm -f -- "$parcial"
  rm -rf -- "$trabajo"
}
trap limpiar EXIT

# Al arrancar la VM, Persistent=true lanza la corrida atrasada antes de que cirdan-pg16 acepte conexiones. Un
# contenedor que no existe falla enseguida; uno que existe se espera hasta ESPERA_BASE segundos.
docker inspect --type container "$CONTENEDOR_BASE" >/dev/null 2>&1 || falla "no existe el contenedor $CONTENEDOR_BASE"
docker inspect --type container "$CONTENEDOR_CARTAS" >/dev/null 2>&1 || falla "no existe el contenedor $CONTENEDOR_CARTAS"
# La base que se respalda es la que usa la API (PGDATABASE de su contenedor, docker-compose.yml). Tras una
# restauración completa apunta a la base nueva: respaldar la vieja junto al volumen actual dejaría un paquete
# incoherente. Sale de la configuración del contenedor, así que sirve aunque la API esté detenida.
base_datos=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$CONTENEDOR_CARTAS" \
  | sed -n 's/^PGDATABASE=//p' | tail -n 1)
base_datos=${base_datos:-cirdan}
[[ $base_datos =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || falla "PGDATABASE de $CONTENEDOR_CARTAS no es un nombre de base válido"
listo=0
for ((t = 0; t < ESPERA_BASE; t += 5)); do
  if docker exec -e BASE="$base_datos" "$CONTENEDOR_BASE" sh -c \
      'exec pg_isready -q -U "$POSTGRES_USER" -d "$BASE"' 2>/dev/null; then
    listo=1; break
  fi
  sleep 5
done
[ "$listo" = 1 ] || falla "$CONTENEDOR_BASE no aceptó conexiones en $ESPERA_BASE s"

# Un despliegue que todavía no configura la llave de cartas (alta apagada) y no tiene cartas sigue con el respaldo
# de solo la base, en el formato antiguo .dump.age: así el respaldo diario no se pierde, pero ese archivo no sirve
# para habilitar un alta restaurada. Con cartas en el volumen y sin llave, el respaldo falla.
estado_llave=0
docker exec "$CONTENEDOR_CARTAS" python -c '
import os, sys
from cirdan.config import config
if config("CARTA_KEY_VAULT_SECRET_URL") or config("CARTA_ENCRYPTION_KEY"):
    sys.exit(0)
root = os.environ.get("CARTA_STORAGE_DIR", "")
sys.exit(4 if os.path.isdir(root) and os.listdir(root) else 3)
' || estado_llave=$?
case $estado_llave in
  0) nombre="$raiz_nombre.backup.age" ;;
  3) nombre="$raiz_nombre.dump.age"
     echo "respaldo: AVISO: $CONTENEDOR_CARTAS no tiene llave de cartas; respaldo solo de la base (.dump.age)" >&2 ;;
  4) falla "hay cartas en el volumen, pero $CONTENEDOR_CARTAS no tiene llave de cartas" ;;
  *) falla "no se pudo revisar la llave de cartas en $CONTENEDOR_CARTAS" ;;
esac
[[ $nombre =~ $PATRON ]] || falla "no se pudo armar el nombre del respaldo"
final="$CARPETA/$nombre"
[ ! -e "$final" ] || falla "$final ya existe"
parcial="$CARPETA/.$nombre.parcial"

# La base se captura primero. Una carta nueva se escribe y sincroniza antes de que la transacción la referencie;
# por eso la captura posterior del volumen puede incluir huérfanos, pero no dejar referencias sin archivo.
if [ "$estado_llave" = 3 ]; then
  docker exec -e BASE="$base_datos" "$CONTENEDOR_BASE" sh -c \
    'exec pg_dump -U "$POSTGRES_USER" -d "$BASE" -Fc --no-password' | age -r "$RECEPTOR_AGE" -o "$parcial"
else
docker exec -e BASE="$base_datos" "$CONTENEDOR_BASE" sh -c \
  'exec pg_dump -U "$POSTGRES_USER" -d "$BASE" -Fc --no-password' \
  | age -r "$RECEPTOR_AGE" -o "$trabajo/cirdan.dump.age"

docker exec "$CONTENEDOR_CARTAS" python -c '
import os, re, sys, tarfile
root = os.environ.get("CARTA_STORAGE_DIR", "")
if not os.path.isabs(root) or not os.path.isdir(root) or os.path.islink(root):
    raise SystemExit("CARTA_STORAGE_DIR no es un directorio absoluto válido")
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
    for name in sorted(os.listdir(root)):
        if not re.fullmatch(r"[0-9a-f]{32}\.lt1", name):
            raise SystemExit("nombre de carta inválido")
        path = os.path.join(root, name)
        if os.path.islink(path) or not os.path.isfile(path) or not 31 <= os.path.getsize(path) <= 25 * 1024 * 1024 + 31:
            raise SystemExit("archivo de carta inválido")
        with open(path, "rb") as carta:
            if carta.read(3) != b"LT1":
                raise SystemExit("formato de carta inválido")
        archive.add(path, arcname=name, recursive=False)
' | age -r "$RECEPTOR_AGE" -o "$trabajo/cartas.tar.age"

# La llave se exporta solo por una tubería y queda cifrada con el mismo receptor de recuperación.
docker exec "$CONTENEDOR_CARTAS" python -c \
  'import base64, sys; from cirdan.cartas import _key; sys.stdout.write(base64.urlsafe_b64encode(_key()).decode("ascii"))' \
  | age -r "$RECEPTOR_AGE" -o "$trabajo/carta.key.age"

python3 "$(dirname -- "$0")/paquete.py" crear "$trabajo" | age -r "$RECEPTOR_AGE" -o "$parcial"
fi
bytes=$(stat -c %s "$parcial")
[ "$bytes" -ge 1024 ] || falla "el paquete cifrado mide $bytes bytes"
chmod 600 "$parcial"
mv -n -- "$parcial" "$final"
[ -f "$final" ] || falla "no se pudo dejar $final"
sync -f "$final" 2>/dev/null || true
echo "respaldo: $nombre, $bytes bytes, sha256 $(sha256sum "$final" | cut -d' ' -f1)"

# Respaldos locales con el nombre exacto, dentro de CARPETA y sin bajar a subcarpetas. El nombre lleva la fecha en
# UTC, así que el orden por nombre es el orden por fecha.
mapfile -t respaldos < <(find "$CARPETA" -maxdepth 1 -type f -printf '%f\n' | grep -E "$PATRON" | sort)

declare -A en_azure=()
pendientes=0
token=

# 0: el blob ya está y es este archivo. 1: no está. 2: está, pero es otro archivo. 3: no se pudo saber.
revisar_blob() {
  local url=$1 md5=$2 cabeceras codigo remoto
  cabeceras=$(printf 'Authorization: Bearer %s\n' "$token" | curl -sS --proto '=https' --tlsv1.2 --max-time 30 \
    --retry 3 --retry-delay 5 -I -H @- -H 'x-ms-version: 2023-11-03' -w '\ncodigo:%{http_code}' "$url" \
    | tr -d '\r') || return 3
  codigo=${cabeceras##*codigo:}
  case $codigo in
    404) return 1 ;;
    200) remoto=$(printf '%s\n' "$cabeceras" | sed -n 's/^[Cc]ontent-[Mm][Dd]5: //p')
         [ "$remoto" = "$md5" ] && return 0 || return 2 ;;
    *) return 3 ;;
  esac
}

# Sube un respaldo local si no está en Azure. Devuelve 0 si al final está allá y es el mismo archivo.
subir_uno() {
  local n=$1 archivo="$CARPETA/$1" url md5 sha codigo estado=0
  url="https://$CUENTA_BLOB.blob.core.windows.net/$CONTENEDOR_BLOB/$n"
  md5=$(openssl dgst -md5 -binary "$archivo" | base64)
  revisar_blob "$url" "$md5" || estado=$?
  case $estado in
    0) return 0 ;;
    2) echo "respaldo: ERROR: en Azure hay otro blob $n" >&2; return 1 ;;
    3) echo "respaldo: ERROR: no se pudo revisar $n en Azure" >&2; return 1 ;;
  esac
  sha=$(sha256sum "$archivo" | cut -d' ' -f1)
  # If-None-Match: * nunca escribe encima de un blob con el mismo nombre. Content-MD5 hace que Azure rechace
  # un archivo que llegó distinto.
  codigo=$(printf 'Authorization: Bearer %s\n' "$token" | curl -sS --proto '=https' --tlsv1.2 --max-time 300 \
    --retry 2 --retry-delay 5 -o /dev/null -w '%{http_code}' -H @- \
    -H 'x-ms-version: 2023-11-03' -H 'x-ms-blob-type: BlockBlob' -H 'If-None-Match: *' \
    -H "Content-MD5: $md5" -H 'Content-Type: application/octet-stream' \
    -H "x-ms-meta-sha256: $sha" -T "$archivo" "$url") || codigo=000
  if [ "$codigo" = 409 ] || [ "$codigo" = 403 ]; then
    # Un reintento después de una subida que sí llegó: vale si el blob que ya está es este mismo archivo. Con el
    # rol de la VM (blobs/add/action, sin blobs/write) Azure responde 403 UnauthorizedBlobOverwrite y no 409. Un
    # 403 con un blob que no está o que no se puede leer (falta el rol) sigue siendo error y lleva su pista.
    estado=0
    revisar_blob "$url" "$md5" || estado=$?
    case $estado in
      0) codigo=201 ;;
      2) echo "respaldo: ERROR: en Azure hay otro blob $n" >&2; return 1 ;;
    esac
  fi
  if [ "$codigo" != 201 ]; then
    local pista=
    [ "$codigo" = 403 ] && pista=' (falta el rol en la identidad, o Azure todavía no lo ve)'
    echo "respaldo: ERROR: Azure respondió $codigo al subir $n$pista" >&2
    return 1
  fi
  echo "respaldo: subido a $CUENTA_BLOB/$CONTENEDOR_BLOB/$n"
}

if [ "$SUBIR" = 1 ]; then
  # Token de la identidad administrada. Solo vive en memoria: llega a curl por stdin (-H @-), no por argumentos,
  # que cualquier proceso de la VM ve en /proc. --retry cubre los 429 y 5xx pasajeros de IMDS.
  token=$(curl -sS --fail --max-time 20 --retry 5 --retry-delay 5 --retry-connrefused --noproxy '*' -H 'Metadata: true' \
    'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F' \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])') || token=
  if [ -z "$token" ]; then
    echo "respaldo: ERROR: IMDS no dio token" >&2
  else
    # Primero el de hoy, después los que quedaron pendientes, del más nuevo al más viejo.
    for ((i = ${#respaldos[@]} - 1; i >= 0; i--)); do
      if (( SECONDS > PRESUPUESTO_SUBIDA )); then
        echo "respaldo: ERROR: se acabó el tiempo de subida, el resto queda para la siguiente corrida" >&2
        break
      fi
      subir_uno "${respaldos[i]}" && en_azure[${respaldos[i]}]=1
    done
  fi
  token=
  for n in "${respaldos[@]}"; do [ -n "${en_azure[$n]:-}" ] || pendientes=$((pendientes + 1)); done
fi

# Retención local por días, no por archivos: una corrida a mano no le quita su lugar a un día. Se quedan todos los
# respaldos de los RETENCION días más recientes que tienen alguno. Con SUBIR=1 uno que no está en Azure tampoco se
# borra, salvo que pase de TOPE_LOCAL archivos: entonces se borran los más viejos aunque no se hayan subido.
mapfile -t dias < <(printf '%s\n' "${respaldos[@]}" | cut -c8-15 | sort -u)
corte=
(( ${#dias[@]} > RETENCION )) && corte=${dias[${#dias[@]} - RETENCION]}
quedan=${#respaldos[@]}
for n in "${respaldos[@]}"; do
  dia=${n:7:8}
  sobra=0
  if (( quedan > TOPE_LOCAL )); then
    sobra=1
  elif [ -n "$corte" ] && [[ $dia < $corte ]] && { [ "$SUBIR" = 0 ] || [ -n "${en_azure[$n]:-}" ]; }; then
    sobra=1
  fi
  if [ "$sobra" = 1 ]; then
    rm -f -- "$CARPETA/$n"
    quedan=$((quedan - 1))
    [ -z "${en_azure[$n]:-}" ] && [ "$SUBIR" = 1 ] && pendientes=$((pendientes - 1))
    echo "respaldo: borrado el local $n"
  fi
done
# Restos de una corrida que se cortó (apagón o kill -9, que no corren el trap).
find "$CARPETA" -maxdepth 1 -type f -name '.cirdan_*.age.parcial' -mmin +60 -delete
echo "respaldo: $quedan respaldos locales"
if [ "$SUBIR" = 1 ] && { [ -z "${en_azure[$nombre]:-}" ] || (( pendientes > 0 )); }; then
  falla "$pendientes respaldos locales sin subir a Azure (se reintentan en la siguiente corrida)"
fi
echo "respaldo: listo"
