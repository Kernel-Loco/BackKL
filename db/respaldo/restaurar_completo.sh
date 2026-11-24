#!/usr/bin/env bash
# Restaura base, cartas cifradas y su llave en destinos nuevos; nunca sustituye datos existentes.
set -Eeuo pipefail
umask 077
export LC_ALL=C

falla() { echo "restaurar_completo: ERROR: $*" >&2; exit 1; }

[ $# -eq 7 ] || falla "uso: AGE_IDENTIDAD=<archivo de la llave o -> $0 <respaldo.backup.age> <contenedor_base> <contenedor_api> <base_nueva> <volumen_nuevo> <boveda> <secreto>"
respaldo=$1 contenedor_base=$2 contenedor_api=$3 base=$4 volumen=$5 boveda=$6 secreto=$7
identidad=${AGE_IDENTIDAD:-}
llave=

[ -n "$identidad" ] || falla "falta AGE_IDENTIDAD (la ruta de la llave privada de age, o -)"
case $identidad in
  *AGE-SECRET-KEY-*) falla "AGE_IDENTIDAD lleva la llave misma: tiene que ser la ruta de su archivo, o -" ;;
esac
if [ "$identidad" = - ]; then
  llave=$(cat)
  [[ $llave == *AGE-SECRET-KEY-1* ]] || falla "stdin no trae una llave privada de age"
else
  [ -f "$identidad" ] || falla "no existe el archivo de la llave de AGE_IDENTIDAD"
fi
[ -f "$respaldo" ] || falla "no existe $respaldo"
[[ ! -L $respaldo ]] || falla "el respaldo no puede ser un enlace"
[[ $contenedor_base =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || falla "contenedor de base no válido"
[[ $contenedor_api =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || falla "contenedor de API no válido"
[[ $base =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || falla "la base nueva va en minúsculas, dígitos y _"
case $base in cirdan|postgres|template0|template1) falla "no se restaura sobre $base: usa otro nombre" ;; esac
[[ $volumen =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || falla "nombre de volumen inválido"
[[ $boveda =~ ^[a-z0-9-]{3,24}$ ]] || falla "nombre de Key Vault inválido"
[[ $secreto =~ ^[A-Za-z0-9-]{1,127}$ ]] || falla "nombre de secreto inválido"
temporal=/run
[ -w "$temporal" ] || temporal=/run/lock
[ "$(findmnt -n -o FSTYPE --target "$temporal" 2>/dev/null)" = tmpfs ] || falla "$temporal debe ser tmpfs para proteger los temporales"
for herramienta in age python3 docker az; do command -v "$herramienta" >/dev/null || falla "falta $herramienta"; done
python3 - "$respaldo" "$temporal" <<'PY' || falla "no hay espacio temporal suficiente en $temporal"
import os
import sys
espacio = os.statvfs(sys.argv[2])
if os.path.getsize(sys.argv[1]) > espacio.f_bavail * espacio.f_frsize:
    raise SystemExit(1)
PY

directorio_script=$(cd -- "$(dirname -- "$0")" && pwd)
trabajo=$(mktemp -d "$temporal/lowtide-restaurar.XXXXXX")
limpiar() { rm -rf -- "$trabajo"; }
trap limpiar EXIT

descifrar() {
  local archivo=$1
  if [ "$identidad" = - ]; then
    printf '%s\n' "$llave" | age -d -i - "$archivo"
  else
    age -d -i "$identidad" "$archivo"
  fi
}

descifrar "$respaldo" > "$trabajo/paquete.tar" || falla "no se pudo descifrar el respaldo"
mkdir -m 700 "$trabajo/cifrado"
python3 "$directorio_script/paquete.py" extraer "$trabajo/paquete.tar" "$trabajo/cifrado" \
  || falla "el paquete cifrado no tiene una estructura válida"
descifrar "$trabajo/cifrado/carta.key.age" > "$trabajo/carta.key" \
  || falla "no se pudo descifrar la llave de cartas"
python3 "$directorio_script/paquete.py" llave "$trabajo/carta.key" || falla "la llave de cartas no es válida"
descifrar "$trabajo/cifrado/cartas.tar.age" > "$trabajo/cartas.tar" \
  || falla "no se pudo descifrar el volumen de cartas"
mkdir -m 700 "$trabajo/cartas"
python3 "$directorio_script/paquete.py" cartas "$trabajo/cartas.tar" "$trabajo/cartas" \
  || falla "el volumen de cartas no tiene una estructura válida"

docker inspect --type container "$contenedor_base" >/dev/null 2>&1 || falla "no existe el contenedor $contenedor_base"
docker inspect --type container "$contenedor_api" >/dev/null 2>&1 || falla "no existe el contenedor $contenedor_api"
if docker volume inspect "$volumen" >/dev/null 2>&1; then
  falla "el volumen $volumen ya existe"
fi
existe=$(printf "SELECT count(*) FROM pg_database WHERE datname = '%s';\n" "$base" \
  | MSYS_NO_PATHCONV=1 docker exec -i "$contenedor_base" sh -c \
    'exec psql -U "$POSTGRES_USER" -d postgres -X -q -At -v ON_ERROR_STOP=1')
[ "$existe" = 0 ] || falla "la base $base ya existe"

# La llave se recupera como una nueva versión de Key Vault; solo la URL versionada vuelve a la terminal.
url=$(az keyvault secret set --vault-name "$boveda" --name "$secreto" --file "$trabajo/carta.key" --query id -o tsv) \
  || falla "no se pudo guardar la llave recuperada en Key Vault"
[[ $url =~ ^https://$boveda\.vault\.azure\.net/secrets/$secreto/[0-9a-f]{32}$ ]] \
  || falla "Key Vault no devolvió la URL versionada esperada"

if [ "$identidad" = - ]; then
  printf '%s\n' "$llave" | AGE_IDENTIDAD=- bash "$directorio_script/restaurar.sh" \
    "$trabajo/cifrado/cirdan.dump.age" "$contenedor_base" "$base"
else
  AGE_IDENTIDAD="$identidad" bash "$directorio_script/restaurar.sh" \
    "$trabajo/cifrado/cirdan.dump.age" "$contenedor_base" "$base"
fi

docker volume create "$volumen" >/dev/null
imagen=$(docker inspect --format '{{.Config.Image}}' "$contenedor_api")
uid=$(docker exec "$contenedor_api" id -u)
gid=$(docker exec "$contenedor_api" id -g)
[[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ ]] || falla "no se pudo identificar al usuario de la API"
docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN \
  --security-opt no-new-privileges --entrypoint python \
  -v "$volumen:/restore" -v "$trabajo/cartas:/source:ro" "$imagen" -c '
import os, shutil
import sys
uid, gid = map(int, sys.argv[1:])
os.chmod("/restore", 0o700)
os.chown("/restore", uid, gid)
for nombre in sorted(os.listdir("/source")):
    origen = os.path.join("/source", nombre)
    destino = os.path.join("/restore", nombre)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destino, flags, 0o600)
    with os.fdopen(fd, "wb") as salida, open(origen, "rb") as entrada:
        os.fchown(salida.fileno(), uid, gid)
        shutil.copyfileobj(entrada, salida)
        salida.flush()
        os.fsync(salida.fileno())
fd = os.open("/restore", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
os.fsync(fd)
os.close(fd)
' "$uid" "$gid" || falla "no se pudieron copiar las cartas al volumen nuevo $volumen"

printf '%s\n' "SELECT organization_id, domain_id, signed_document_key, encode(signed_document_sha256, 'hex') FROM domain_authorizations" \
  | MSYS_NO_PATHCONV=1 docker exec -i -e BASE="$base" "$contenedor_base" sh -c \
    'exec psql -U "$POSTGRES_USER" -d "$BASE" -X -q -At -F "|" -v ON_ERROR_STOP=1' \
  > "$trabajo/referencias.tsv"
docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add DAC_OVERRIDE \
  --security-opt no-new-privileges --entrypoint python \
  -v "$volumen:/cartas:ro" -v "$trabajo/carta.key:/run/carta.key:ro" \
  -v "$trabajo/referencias.tsv:/run/referencias.tsv:ro" \
  -v "$directorio_script/verificar_cartas.py:/run/verificar_cartas.py:ro" \
  "$imagen" /run/verificar_cartas.py /run/carta.key /run/referencias.tsv /cartas

echo "restaurar_completo: base $base y volumen $volumen restaurados y verificados"
echo "restaurar_completo: configura PGDATABASE=$base, CARTA_VOLUME_NAME=$volumen y CARTA_KEY_VAULT_SECRET_URL=$url antes de levantar la API"
