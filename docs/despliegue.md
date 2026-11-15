# Despliegue de LowTide (#49, RC-91)

La VM y el plan B levantan la misma pila: `docker-compose.yml` más `docker-compose.despliegue.yml`. El segundo archivo suma el portal (FrontKL) y Cloudflare Tunnel. Ningún puerto queda abierto a la red. Lo que entra por lowtidesec.com llega por el túnel al portal, y el portal reenvía `/api/v1` a la API. La API no tiene nombre público.

```
navegador → Cloudflare (HTTPS) → cloudflared ─borde─ portal ─interna─ api ─default─ db, valkey
```

## Antes de levantar

1. FrontKL clonado junto a BackKL (`../FrontKL`), o su ruta en `PORTAL_DIR`.
2. `.env` copiado de `.env.example`, con contraseñas propias y además:
   - `ALLOWED_ORIGINS=https://lowtidesec.com`. Sin ella la pila no arranca. También apaga las cuentas de demo (RC-287).
   - `TUNNEL_TOKEN`, el token del túnel de Cloudflare. Sin él la pila no arranca. Nunca va en git.
   - `DOMINIOS_EN_VIVO` y `ORGS_GITHUB_DECLARADAS` según las cartas vigentes.
3. En Cloudflare Zero Trust, el túnel publica `lowtidesec.com` y `www.lowtidesec.com` hacia `http://portal:3000`.
4. `docker login` con `DOCKERHUB_USERNAME` y `DOCKERHUB_TOKEN` de la cuenta 'lowtidesec' (solo lectura).

## Levantar

```bash
docker compose -f docker-compose.yml -f docker-compose.despliegue.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.despliegue.yml logs demo-accounts
```

La segunda línea tiene que decir 'DEMO_ACCOUNTS no es true: no se tocan las cuentas.' (comentario 10420 de RC-91).

## Lo que fija el archivo del despliegue

Ningún .env le gana a estos valores:

- `DEMO_ACCOUNTS=false` y `DEMO_EXPLORER=false`.
- `COOKIE_SECURE=true`, porque el despliegue siempre va con HTTPS.
- `FORWARDED_ALLOW_IPS` con las IP fijas del portal (172.31.91.10) y de cloudflared (172.31.92.11). Cloudflare agrega la IP real al final de X-Forwarded-For y Next no le agrega nada si ya viene. uvicorn toma la primera IP de la derecha que no es de confianza, así que el bloqueo por intentos del login cuenta por visitante. Una IP falsa que mande el navegador queda a la izquierda y no cuenta.
- Rotación del registro de Docker en todos los servicios: 3 archivos de 10 MB.

Las redes `interna` (172.31.91.0/28) y `borde` (172.31.92.0/28) tienen subred fija. Si otra red de la máquina ya usa esas subredes, `up` falla con un aviso de Docker.

## Plan B

En una PC del equipo, el mismo comando con un túnel propio (otro `TUNNEL_TOKEN`). Para pasar el tráfico se cambia en Cloudflare el destino de `lowtidesec.com` al túnel del plan B. Al probarlo se anotan la fecha, los pasos y los minutos hasta que respondió lowtidesec.com (comentario 10383 de RC-91).

En una PC que ya tiene la pila local, la red y el registro cambian, así que `up` recrea `cirdan-pg16` y `cirdan-valkey`. El volumen de la base sobrevive, pero Valkey pierde las sesiones. Antes revisa con `docker compose -f docker-compose.yml -f docker-compose.despliegue.yml --dry-run up -d --build`.

## Pruebas

`python -m unittest pruebas/test_despliegue.py` arma la config con valores falsos y revisa todo lo de arriba, sin crear nada. El CI la corre con las pruebas sin base ni red.
