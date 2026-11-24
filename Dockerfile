# syntax=docker/dockerfile:1
# API de Cirdan. La base y Valkey corren en sus propios contenedores (docker-compose.yml).

# La imagen pide BuildKit: Docker Desktop, o Docker Engine con el plugin buildx. El builder clásico (DOCKER_BUILDKIT=0,
# o Docker sin buildx) ignora ADD --checksum sin avisar, así que bajaría subfinder sin revisar su sha256, y
# tampoco define TARGETARCH. Ese builder corre todas las etapas en orden y se detiene aquí, antes de bajar nada, con el
# aviso de Docker de que --chmod pide BuildKit. BuildKit salta esta etapa porque ninguna otra la usa. No agregues
# ARG TARGETARCH con valor por omisión: le gana a la plataforma que pone BuildKit, y en una Mac con Apple Silicon la
# imagen arm64 llevaría los binarios amd64 (PR 79 y 81).
FROM scratch AS pide-buildkit
COPY --chmod=0644 requirements.txt /

# subfinder 2.17.0 (#14b, RC-184) entra desde los zips del release oficial, en etapas aparte:
# - El release se compila con CGO_ENABLED=0 (.goreleaser.yml de v2.17.0), así que el binario es estático
#   y corre en python:3.15-slim (Debian, glibc). La imagen oficial projectdiscovery/subfinder es Alpine
#   (musl), por eso no se copia de ahí.
# - Cada arquitectura tiene su zip con su sha256 fijo, sacado de subfinder_2.17.0_checksums.txt del
#   release. Si el zip cambia, ADD --checksum detiene la construcción. amd64 es la VM y la mayoría de las
#   PC, arm64 las Mac con Apple Silicon. Docker solo construye la etapa de TARGETARCH y baja un solo zip.
# - Dependabot no vigila esta versión: se sube a mano, con la versión de las dos URL, los dos hash y NOTICE.
# - ADD --checksum pide BuildKit con el frontend del Dockerfile 1.6 o más. Por eso la primera línea pide
#   docker/dockerfile:1, que exige el frontend 1.x y toma el más nuevo de esa rama. No fija una versión.
FROM python:3.15-slim AS subfinder-zip-amd64
ADD --checksum=sha256:a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37 \
    https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_linux_amd64.zip /tmp/subfinder.zip

FROM python:3.15-slim AS subfinder-zip-arm64
ADD --checksum=sha256:24913d49dddc1d3a5e99a4a7580da5be980959b9415b96f52c4f7f4124392190 \
    https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_linux_arm64.zip /tmp/subfinder.zip

# slim no trae unzip: zipfile de Python saca solo el binario y su licencia. Si al zip le falta alguno de
# los dos, z.read() lanza KeyError y la construcción se detiene. La licencia va en su propia carpeta, con
# 0755 y 0644 puestos aquí, para copiarla sin --chmod: con --chmod=0644 BuildKit también se lo pone a las
# carpetas que crea (/usr/share/licenses y la de subfinder) y el usuario cirdan ya no puede leerla.
FROM subfinder-zip-${TARGETARCH} AS subfinder
RUN python -c "import os, pathlib, zipfile; z = zipfile.ZipFile('/tmp/subfinder.zip'); d = pathlib.Path('/out/licencia'); d.mkdir(parents=True); pathlib.Path('/out/subfinder').write_bytes(z.read('subfinder')); (d / 'LICENSE.md').write_bytes(z.read('LICENSE.md')); os.chmod(d, 0o755); os.chmod(d / 'LICENSE.md', 0o644)"

# gitleaks 8.21.2 (#16, RC-50), la misma versión del pre-commit (.pre-commit-config.yaml), se compila desde su código
# con Go 1.27.4. Los binarios del release traen la crítica CVE-2025-68121 de crypto/tls: 8.21.2 se armó con Go 1.23.2
# y 8.30.1, la más nueva, con Go 1.24.11, y el arreglo llegó en Go 1.24.13 y 1.25.7 (RC-117). Trivy frena con
# cualquier crítica y sin excepciones (.github/workflows/imagenes.yml), así que el binario se arma aquí.
# - go install con @v8.21.2 baja el módulo de proxy.golang.org y lo revisa contra sum.golang.org (GOSUMDB por
#   omisión), y sus dependencias contra el go.sum del módulo. Si alguno cambia, la construcción se detiene.
# - CGO_ENABLED=0 como el release: binario estático que corre en python:3.15-slim.
# - Mismo código y misma config embebida, así que cirdan/recolectores/gitleaks_cirdan.toml no cambia.
# - Dependabot vigila el FROM de golang, no la versión de gitleaks. Esa se sube a mano en los tres v8.21.2 de abajo,
#   en NOTICE y en el pre-commit, y se vuelve a generar gitleaks_cirdan.toml (ver gitleaks_reglas.py).
FROM golang:1.27.4-trixie AS gitleaks
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
RUN go install -ldflags "-s -w -X github.com/zricethezav/gitleaks/v8/cmd.Version=8.21.2" \
        github.com/zricethezav/gitleaks/v8@v8.21.2 \
    && install -D -m 0755 "$(go env GOPATH)/bin/gitleaks" /out/gitleaks \
    && install -D -m 0644 "$(go env GOMODCACHE)/github.com/zricethezav/gitleaks/v8@v8.21.2/LICENSE" \
        /out/licencia/LICENSE \
    && chmod 0755 /out/licencia

FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
# git para clonar los repos públicos que revisa el recolector de GitHub (#16, RC-50). Sin recomendados: no
# trae ssh ni otros transportes, y el recolector solo permite https.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install -r requirements.txt

# subfinder y gitleaks con sus licencias MIT, que viajan con cada binario (ver NOTICE). Van antes de cirdan/
# para que un cambio en el código no vuelva a copiarlos.
COPY --from=subfinder --chmod=0755 /out/subfinder /usr/local/bin/subfinder
COPY --from=subfinder /out/licencia/ /usr/share/licenses/subfinder/
COPY --from=gitleaks --chmod=0755 /out/gitleaks /usr/local/bin/gitleaks
COPY --from=gitleaks /out/licencia/ /usr/share/licenses/gitleaks/
# PRUEBA DE RC-117, NO FUSIONAR: gosu de postgres:16.15 trae la crítica CVE-2025-68121. Trivy tiene que frenar.
COPY --from=postgres:16.15 /usr/local/bin/gosu /usr/local/bin/gosu-sembrado

# Bases de DB-IP Lite para el país y el ASN de las IP (#15b, RC-166), bajadas a mano a datos/geo/ (ver
# cirdan/recolectores/geoip.py y NOTICE). Van antes de cirdan/ para que un cambio en el código no vuelva a copiar sus
# 17 MB. Sin bases solo entra .gitkeep, que está en git, y las IP salen 'No disponible'.
COPY datos/geo/ datos/geo/

COPY cirdan/ cirdan/

# Sin privilegios de root dentro del contenedor. El código sigue siendo de root y el usuario cirdan no lo puede
# cambiar. Solo respuestas_grabadas/subfinder/ es suya, para grabar subfinder ahí (solo corre en la imagen, RC-184).
# Las grabaciones de las demás fuentes, como la de crt.sh, siguen de root. Una grabación hecha así se pierde al
# recrear el contenedor: para guardarla se monta la carpeta de la fuente, como dice el README.
RUN useradd --system --uid 10001 cirdan \
    && chown -R cirdan:cirdan cirdan/recolectores/respuestas_grabadas/subfinder \
    && install -d -m 0700 -o cirdan -g cirdan /var/lib/cirdan/cartas
USER cirdan

EXPOSE 8000
# start-period mayor que dos veces keyvault.PLAZO (90 s): al arrancar, la API lee de Key Vault la llave del MFA y
# la de las huellas de contraseña (RC-330), cada lectura con su plazo, y puede tardar mientras IMDS se recupera.
# Así no se marca unhealthy antes de rendirse (#49, RC-91). Llega a healthy en el primer chequeo que pasa, así que
# no retrasa un arranque normal.
HEALTHCHECK --interval=10s --timeout=3s --start-period=200s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"
# --proxy-headers: X-Forwarded-For solo se toma en cuenta si quien conecta está en FORWARDED_ALLOW_IPS
# (ver docker-compose.yml). Por omisión nadie de fuera, porque el portal (Next) no lo limpia: reenvía el que mande el
# navegador y solo pone la IP de quien le conecta si no viene. En el despliegue, Cloudflare agrega la IP real al final y
# uvicorn la toma de derecha a izquierda (docker-compose.despliegue.yml, comentario 10389 de RC-277).
# --no-server-header: sin el encabezado 'server: uvicorn', que dice el servidor a quien escanee (comentario 10063 de
# RC-91).
CMD ["python", "-m", "uvicorn", "cirdan.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", \
     "--no-server-header"]
