# syntax=docker/dockerfile:1
# API de Cirdan. La base y Valkey corren en sus propios contenedores (docker-compose.yml).

# subfinder 2.17.0 (#14b, RC-184) entra desde los zips del release oficial, en etapas aparte:
# - El release se compila con CGO_ENABLED=0 (.goreleaser.yml de v2.17.0), así que el binario es estático
#   y corre en python:3.14-slim (Debian, glibc). La imagen oficial projectdiscovery/subfinder es Alpine
#   (musl), por eso no se copia de ahí.
# - Cada arquitectura tiene su zip con su sha256 fijo, sacado de subfinder_2.17.0_checksums.txt del
#   release. Si el zip cambia, ADD --checksum detiene la construcción. amd64 es la VM y la mayoría de las
#   PC, arm64 las Mac con Apple Silicon. Docker solo construye la etapa de TARGETARCH y baja un solo zip.
# - Dependabot no vigila esta versión: se sube a mano, con la versión de las dos URL, los dos hash y NOTICE.
# - ADD --checksum pide BuildKit con el frontend del Dockerfile 1.6 o más. Por eso la primera línea pide
#   docker/dockerfile:1, que exige el frontend 1.x y toma el más nuevo de esa rama. No fija una versión.
FROM python:3.14-slim AS subfinder-zip-amd64
ADD --checksum=sha256:a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37 \
    https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_linux_amd64.zip /tmp/subfinder.zip

FROM python:3.14-slim AS subfinder-zip-arm64
ADD --checksum=sha256:24913d49dddc1d3a5e99a4a7580da5be980959b9415b96f52c4f7f4124392190 \
    https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_linux_arm64.zip /tmp/subfinder.zip

# slim no trae unzip: zipfile de Python saca solo el binario y su licencia. Si al zip le falta alguno de
# los dos, z.read() lanza KeyError y la construcción se detiene. La licencia va en su propia carpeta, con
# 0755 y 0644 puestos aquí, para copiarla sin --chmod: con --chmod=0644 BuildKit también se lo pone a las
# carpetas que crea (/usr/share/licenses y la de subfinder) y el usuario cirdan ya no puede leerla.
FROM subfinder-zip-${TARGETARCH} AS subfinder
RUN python -c "import os, pathlib, zipfile; z = zipfile.ZipFile('/tmp/subfinder.zip'); d = pathlib.Path('/out/licencia'); d.mkdir(parents=True); pathlib.Path('/out/subfinder').write_bytes(z.read('subfinder')); (d / 'LICENSE.md').write_bytes(z.read('LICENSE.md')); os.chmod(d, 0o755); os.chmod(d / 'LICENSE.md', 0o644)"

FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# subfinder y su licencia MIT, que viaja con el binario (ver NOTICE). Van antes de cirdan/ para que un
# cambio en el código no vuelva a copiarlos.
COPY --from=subfinder --chmod=0755 /out/subfinder /usr/local/bin/subfinder
COPY --from=subfinder /out/licencia/ /usr/share/licenses/subfinder/

COPY cirdan/ cirdan/

# Sin privilegios de root dentro del contenedor.
RUN useradd --system --uid 10001 cirdan
USER cirdan

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"
# --proxy-headers: X-Forwarded-For solo se toma en cuenta si quien conecta está en FORWARDED_ALLOW_IPS
# (ver docker-compose.yml). Por omisión nadie de fuera, porque el portal (Next) no lo agrega.
CMD ["python", "-m", "uvicorn", "cirdan.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
