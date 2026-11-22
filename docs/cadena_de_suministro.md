# Cadena de suministro de las imágenes (#82, RC-117)

Cada imagen de LowTide (la API de BackKL y el portal de FrontKL) pasa por tres controles en el CI y se verifica
otra vez antes de levantarse en la VM.

## En pocas palabras (para la presentación)

- **Trivy** revisa la imagen contra bases de vulnerabilidades conocidas (CVE). Si encuentra una **crítica** que ya
  tiene arreglo, el PR no pasa.
- **Syft** saca el **SBOM**: la lista de ingredientes de la imagen (paquetes del sistema, de Python o de npm y sus
  versiones). Si mañana sale una vulnerabilidad nueva, se sabe en minutos si nos afecta.
- **cosign** **firma** la imagen. La VM solo levanta una imagen firmada por nuestro CI. Si alguien sube una imagen
  alterada al registro, la firma no cuadra y no se levanta nada.

## En el CI (`.github/workflows/imagenes.yml`)

| Evento | Qué hace |
|---|---|
| PR a dev o main | Compila la imagen, corre Trivy (frena con `CRITICAL` que tenga arreglo) y saca el SBOM SPDX con Syft como artefacto de la corrida (30 días). |
| Push a dev o main (el merge) | Lo mismo y además: sube la imagen a `ghcr.io/kernel-loco/backkl` (o `frontkl`) con la etiqueta del commit y la de la rama, la firma con cosign por **digest**, le pega el SBOM como atestación firmada y verifica las dos cosas. El digest sale en el resumen de la corrida. |

- **Sin llaves que cuidar.** La firma es *keyless*: cosign usa la identidad OIDC del workflow de GitHub, y Sigstore
  (Fulcio y Rekor) deja un registro público de cada firma. El certificado dice qué repo, qué workflow y qué rama
  firmó.
- **Imágenes de terceros.** En BackKL, el job `terceros` pasa por Trivy cada `image:` de `docker-compose.yml` y de
  `docker-compose.despliegue.yml` (PostgreSQL, Valkey y cloudflared). Si una tiene una crítica con arreglo, se sube
  su versión en el compose. No se firman: no son nuestras.
- **`--ignore-unfixed`.** Una crítica sin arreglo publicado no tiene versión a la cual subir. Sale en la tabla de
  altas y críticas, que no frena, y se revisa a mano.
- **Herramientas con versión fija.** Trivy 0.76.2, Syft 1.57.2 y cosign 3.1.4 corren como imágenes de Docker.
  Ninguna acción de terceros recibe el token, y los permisos `packages: write` e `id-token: write` son solo del job
  que firma.

### Una vez, en GitHub (quien administra la organización)

La primera subida crea los paquetes `backkl` y `frontkl` en ghcr.io. En *Package settings* hay que:

1. Conectarlos a su repo (Kernel-Loco/BackKL y Kernel-Loco/FrontKL), para que el `GITHUB_TOKEN` de cada uno pueda
   escribir.
2. Hacerlos públicos, o darle a la VM un token de solo lectura (`read:packages`) para `docker login ghcr.io`. Los dos
   repos ya son públicos.

## En la VM: verificar antes de levantar

Hoy la VM compila las imágenes con `docker compose up -d --build`. Para levantar las firmadas en vez de compilarlas,
quien administra la VM (Ernesto) agrega al `.env`:

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.despliegue.yml:docker-compose.imagenes.yml
LOWTIDE_API_IMAGEN=ghcr.io/kernel-loco/backkl@sha256:<digest del resumen de la corrida de BackKL>
LOWTIDE_PORTAL_IMAGEN=ghcr.io/kernel-loco/frontkl@sha256:<digest del resumen de la corrida de FrontKL>
```

y desde la carpeta de BackKL:

```bash
infra/verificar_imagenes.sh --levantar
```

El script:

1. Rechaza una imagen por etiqueta (`:main`): solo acepta `@sha256:`, porque una etiqueta se puede mover a otra
   imagen.
2. Corre `cosign verify` y `cosign verify-attestation --type spdxjson`. La firma tiene que ser de
   `https://github.com/Kernel-Loco/<repo>/.github/workflows/imagenes.yml` en `refs/heads/main` o `refs/heads/dev`,
   emitida por `https://token.actions.githubusercontent.com`.
3. Solo si las dos imágenes pasan, hace `docker compose pull` y `docker compose up -d --no-build`. Si una falla, dice
   `no se levanta nada` y sale con error.

`docker-compose.imagenes.yml` solo cambia `image` y quita `build` de la API, demo-accounts y el portal. Todo lo demás
del despliegue (redes, IP fija de la API, sin puertos) sigue igual. Sin `LOWTIDE_API_IMAGEN` o
`LOWTIDE_PORTAL_IMAGEN`, la pila no arranca.

Para regresar a compilar en la VM, se quita `:docker-compose.imagenes.yml` de `COMPOSE_FILE` y se vuelve a
`docker compose up -d --build`.

## Revisar a mano

```bash
cosign verify ghcr.io/kernel-loco/backkl@sha256:<digest> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/Kernel-Loco/BackKL/\.github/workflows/imagenes\.yml@refs/heads/(main|dev)$'
cosign download attestation ghcr.io/kernel-loco/backkl@sha256:<digest>    # el SBOM firmado
trivy image ghcr.io/kernel-loco/backkl@sha256:<digest>
```

## Pruebas

- `python -m unittest -v pruebas/test_cadena_suministro.py` (BackKL, sin red):
  - el workflow frena con críticas, saca el SBOM y firma solo en push y por digest;
  - los permisos de escritura están solo en el job que firma;
  - las versiones son fijas;
  - `verificar_imagenes.sh`, con un docker falso, rechaza etiquetas y no levanta nada si cosign falla;
  - el compose con imágenes no compila y conserva la red del despliegue.
- `npm test` (FrontKL): `src/config/flujoImagenes.test.mjs` revisa lo mismo del workflow del portal.
