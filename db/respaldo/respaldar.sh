#!/usr/bin/env bash
# Respaldo diario de la base cirdan (#115, RC-233, y RC-91). Lo corre el timer lowtide-respaldo.timer en la VM.
#
# 1. pg_dump en formato custom con el usuario postgres dentro del contenedor de la base, nunca con cirdan_app,
#    que con FORCE RLS no ve todas las filas.
# 2. Lo cifra al vuelo con age y la llave pública de RECEPTOR_AGE. El respaldo sin cifrar nunca toca el disco
#    y la llave privada no vive en la VM: quien entre a la VM no lee los respaldos.
# 3. Lo deja en CARPETA con permisos 600 y conserva los últimos RETENCION respaldos de ese nombre.
# 4. Con SUBIR=1 lo sube a Azure Blob con la identidad administrada de la VM (IMDS), sin llaves en disco.
#    El contenedor de Azure es inmutable 7 días y borra solo a los 8 (docs/despliegue.md, 'Respaldo diario').
#
# Configuración en /etc/lowtide/respaldo.conf (o en RESPALDO_CONF), una CLAVE=valor por línea. No es un
# script: solo se leen las claves de abajo y cada valor se revisa. No lleva secretos.
set -Eeuo pipefail
umask 077
export LC_ALL=C

CONF=${RESPALDO_CONF:-/etc/lowtide/respaldo.conf}
CONTENEDOR_BASE=cirdan-pg16
CARPETA=/var/backups/lowtide
RECEPTOR_AGE=
RETENCION=7
SUBIR=1
CUENTA_BLOB=
CONTENEDOR_BLOB=respaldos

falla() { echo "respaldo: ERROR: $*" >&2; exit 1; }

[ -f "$CONF" ] || falla "no existe $CONF"
while IFS= read -r linea || [ -n "$linea" ]; do
  linea=${linea%$'\r'}
  case $linea in ''|'#'*) continue ;; esac
  clave=${linea%%=*}
  valor=${linea#*=}
  case $clave in
    CONTENEDOR_BASE|CARPETA|RECEPTOR_AGE|RETENCION|SUBIR|CUENTA_BLOB|CONTENEDOR_BLOB) printf -v "$clave" '%s' "$valor" ;;
    *) falla "clave desconocida en $CONF: $clave" ;;
  esac
done < "$CONF"

[[ $CONTENEDOR_BASE =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || falla "CONTENEDOR_BASE no válido"
[[ $CARPETA == /* && $CARPETA != *..* ]] || falla "CARPETA tiene que ser una ruta absoluta sin '..'"
[[ $RECEPTOR_AGE =~ ^age1[02-9ac-hj-np-z]{58}$ ]] || falla "RECEPTOR_AGE no es una llave pública de age"
[[ $RETENCION =~ ^[1-9][0-9]?$ ]] || falla "RETENCION va de 1 a 99"
[[ $SUBIR == 0 || $SUBIR == 1 ]] || falla "SUBIR es 0 o 1"
if [ "$SUBIR" = 1 ]; then
  [[ $CUENTA_BLOB =~ ^[a-z0-9]{3,24}$ ]] || falla "CUENTA_BLOB no es un nombre de cuenta de almacenamiento"
  [[ $CONTENEDOR_BLOB =~ ^[a-z0-9]([a-z0-9]|-[a-z0-9]){2,62}$ ]] || falla "CONTENEDOR_BLOB no válido"
fi
command -v age >/dev/null || falla "falta age (apt-get install age)"

mkdir -p -m 700 "$CARPETA"
[ -d "$CARPETA" ] && [ ! -L "$CARPETA" ] || falla "$CARPETA no es una carpeta"
chmod 700 "$CARPETA"

# Un solo respaldo a la vez: un segundo arranque del timer, o uno a mano, espera hasta 10 min y luego se rinde.
exec 9>"$CARPETA/.candado"
flock -w 600 9 || falla "otro respaldo sigue corriendo"

PATRON='^cirdan_[0-9]{8}T[0-9]{6}Z\.dump\.age$'
nombre="cirdan_$(date -u +%Y%m%dT%H%M%SZ).dump.age"
final="$CARPETA/$nombre"
parcial="$CARPETA/.$nombre.parcial"
[ ! -e "$final" ] || falla "$final ya existe"

limpiar() { rm -f -- "$parcial"; }
trap limpiar EXIT

# POSTGRES_USER es la del contenedor (sale del .env, postgres si no se puso). Va entre comillas simples para que
# la expanda el sh del contenedor y no este script.
docker exec "$CONTENEDOR_BASE" sh -c 'exec pg_dump -U "$POSTGRES_USER" -d cirdan -Fc --no-password' \
  | age -r "$RECEPTOR_AGE" -o "$parcial"

bytes=$(stat -c %s "$parcial")
# Un respaldo de la base con su esquema mide mucho más que esto. Menos es un pg_dump que no escribió nada.
[ "$bytes" -ge 1024 ] || falla "el respaldo cifrado mide $bytes bytes"
sha256=$(sha256sum "$parcial" | cut -d' ' -f1)
md5_b64=$(openssl dgst -md5 -binary "$parcial" | base64)
chmod 600 "$parcial"
mv -n -- "$parcial" "$final"
[ -f "$final" ] || falla "no se pudo dejar $final"
sync -f "$final" 2>/dev/null || true
echo "respaldo: $nombre, $bytes bytes, sha256 $sha256"

subir() {
  local url="https://$CUENTA_BLOB.blob.core.windows.net/$CONTENEDOR_BLOB/$nombre"
  local token codigo md5_remoto
  # Token de la identidad administrada. Solo vive en memoria: llega a curl por stdin (-H @-), no por argumentos,
  # que cualquier proceso de la VM ve en /proc.
  token=$(curl -sS --fail --max-time 20 --noproxy '*' -H 'Metadata: true' \
    'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F' \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])') || falla "IMDS no dio token"
  [ -n "$token" ] || falla "IMDS no dio token"
  # If-None-Match: * nunca escribe encima de un blob con el mismo nombre. Content-MD5 hace que Azure rechace
  # un archivo que llegó distinto.
  codigo=$(printf 'Authorization: Bearer %s\n' "$token" | curl -sS --proto '=https' --tlsv1.2 --max-time 300 \
    --retry 3 --retry-delay 5 -o /dev/null -w '%{http_code}' -H @- \
    -H 'x-ms-version: 2023-11-03' -H 'x-ms-blob-type: BlockBlob' -H 'If-None-Match: *' \
    -H "Content-MD5: $md5_b64" -H 'Content-Type: application/octet-stream' \
    -H "x-ms-meta-sha256: $sha256" -T "$final" "$url") || codigo=000
  if [ "$codigo" = 409 ]; then
    # Un reintento después de una subida que sí llegó: vale si el blob que ya está es este mismo archivo.
    md5_remoto=$(printf 'Authorization: Bearer %s\n' "$token" | curl -sS --proto '=https' --max-time 30 -I -H @- \
      -H 'x-ms-version: 2023-11-03' "$url" | tr -d '\r' | sed -n 's/^[Cc]ontent-[Mm][Dd]5: //p') || md5_remoto=
    [ "$md5_remoto" = "$md5_b64" ] || falla "ya hay otro blob $nombre en $CUENTA_BLOB/$CONTENEDOR_BLOB"
    codigo=201
  fi
  [ "$codigo" = 201 ] || falla "Azure respondió $codigo al subir $nombre (403: falta el rol en la identidad)"
  echo "respaldo: subido a $CUENTA_BLOB/$CONTENEDOR_BLOB/$nombre"
}
[ "$SUBIR" = 1 ] && subir

# Retención local: solo archivos con el nombre exacto del respaldo, dentro de CARPETA y sin bajar a subcarpetas.
# El nombre lleva la fecha en UTC, así que el orden por nombre es el orden por fecha.
mapfile -t respaldos < <(find "$CARPETA" -maxdepth 1 -type f -printf '%f\n' | grep -E "$PATRON" | sort)
borrar=$(( ${#respaldos[@]} - RETENCION ))
for ((i = 0; i < borrar; i++)); do
  rm -f -- "$CARPETA/${respaldos[i]}"
  echo "respaldo: borrado el local ${respaldos[i]}"
done
# Restos de una corrida que se cortó (apagón o kill -9, que no corren el trap).
find "$CARPETA" -maxdepth 1 -type f -name '.cirdan_*.dump.age.parcial' -mmin +60 -delete
echo "respaldo: listo, $(( ${#respaldos[@]} - (borrar > 0 ? borrar : 0) )) respaldos locales"
