#!/usr/bin/env bash
# Verifica con cosign la firma y el SBOM de las imágenes de LowTide antes de levantarlas (#82, RC-117).
# Guía: docs/cadena_de_suministro.md.
#
#   infra/verificar_imagenes.sh             solo verifica
#   infra/verificar_imagenes.sh --levantar  verifica y, si todo pasa, levanta la pila sin compilar nada
#
# Lee LOWTIDE_API_IMAGEN y LOWTIDE_PORTAL_IMAGEN del entorno o del .env de BackKL. Las dos van por digest
# (ghcr.io/kernel-loco/backkl@sha256:...), nunca por etiqueta: una etiqueta se puede mover a otra imagen.
# Una imagen pasa solo si la firmó el workflow imagenes.yml de su repo en un push a main o dev.
set -euo pipefail

COSIGN=${COSIGN_IMAGEN:-ghcr.io/sigstore/cosign/cosign:v3.1.4}
EMISOR=https://token.actions.githubusercontent.com
cd "$(dirname "$0")/.."

del_env() {
  [ -f .env ] || return 0
  sed -n "s/^$1=//p" .env | tail -n 1
}

API=${LOWTIDE_API_IMAGEN:-$(del_env LOWTIDE_API_IMAGEN)}
PORTAL=${LOWTIDE_PORTAL_IMAGEN:-$(del_env LOWTIDE_PORTAL_IMAGEN)}

verificar() {
  local repo=$1 paquete=$2 imagen=$3
  if [[ ! $imagen =~ ^ghcr\.io/kernel-loco/$paquete@sha256:[0-9a-f]{64}$ ]]; then
    echo "verificar_imagenes: la imagen de $repo tiene que ser ghcr.io/kernel-loco/$paquete@sha256:<digest>, no '$imagen'" >&2
    return 1
  fi
  # Cada `|| return 1` hace falta: dentro de `verificar ... || falla=1`, bash no aplica set -e.
  local identidad="^https://github\\.com/Kernel-Loco/$repo/\\.github/workflows/imagenes\\.yml@refs/heads/(main|dev)$"
  docker run --rm "$COSIGN" verify --certificate-oidc-issuer "$EMISOR" \
    --certificate-identity-regexp "$identidad" "$imagen" > /dev/null || return 1
  docker run --rm "$COSIGN" verify-attestation --type spdxjson --certificate-oidc-issuer "$EMISOR" \
    --certificate-identity-regexp "$identidad" "$imagen" > /dev/null || return 1
  echo "verificar_imagenes: $repo firmada por imagenes.yml y con SBOM: $imagen"
}

falla=0
verificar BackKL backkl "$API" || falla=1
verificar FrontKL frontkl "$PORTAL" || falla=1
if [ "$falla" -ne 0 ]; then
  echo "verificar_imagenes: no se levanta nada" >&2
  exit 1
fi

if [ "${1:-}" = "--levantar" ]; then
  export LOWTIDE_API_IMAGEN=$API LOWTIDE_PORTAL_IMAGEN=$PORTAL
  docker compose pull api demo-accounts portal
  docker compose up -d --no-build
fi
