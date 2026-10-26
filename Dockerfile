# API de Cirdan. La base y Valkey corren en sus propios contenedores (docker-compose.yml).
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

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
