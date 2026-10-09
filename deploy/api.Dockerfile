FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# lightgbm needs libgomp at runtime
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*

COPY api/requirements.txt api/requirements.txt
COPY engine/requirements.txt engine/requirements.txt
RUN pip install --no-cache-dir -r api/requirements.txt -r engine/requirements.txt

COPY . .

# Run as an unprivileged user. The code stays root-owned (read-only to the app); only data/ (demo background files)
# is writable. Keys and the CA certificate are mounted read-only into data/keys and data/certs by docker-compose.
RUN groupadd --system --gid 10001 fm && useradd --system --uid 10001 --gid fm --create-home --home-dir /home/fm fm \
    && mkdir -p /app/data && chown fm:fm /app/data
USER fm

EXPOSE 8000
# Behind the TLS proxy (deploy/nginx-proxy.conf): --proxy-headers takes the client IP and scheme from X-Forwarded-*.
# --forwarded-allow-ips '*' is safe ONLY because this container publishes no port (compose `expose`, not `ports`), so
# the proxy is the only peer. --no-server-header hides the server banner; short keep-alive limits idle connections.
CMD ["sh", "-c", "alembic -c api/db/alembic.ini upgrade head && exec uvicorn api.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips '*' --no-server-header --timeout-keep-alive 5"]
