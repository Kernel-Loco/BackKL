#!/bin/sh
# Ningún token de los enlaces que vio pruebas/test_enlace.py aparece en el log de la API (#28, RC-63). Recibe la salida
# de `$C run --rm pruebas`, con las líneas TOKEN_VISTO que imprime la prueba 8, y lee el log del compose aislado.
set -eu
salida="$1"
C='docker compose -p backkl-enlace -f docker-compose.yml -f pruebas/enlace/docker-compose.yml'
tokens=$(grep '^TOKEN_VISTO ' "$salida" | cut -d' ' -f2)
[ -n "$tokens" ] || { echo "No hay líneas TOKEN_VISTO en $salida"; exit 1; }
log=$($C logs --no-color api)
for t in $tokens; do
  if printf '%s' "$log" | grep -qF "$t"; then
    echo "El log de la API trae un token de enlace"; exit 1
  fi
done
echo "Ningún token en el log de la API ($(printf '%s\n' "$tokens" | wc -l) revisados)"
