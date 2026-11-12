FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CODEGUARD_DB_PATH=/data/codeguard.db

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir . && \
    useradd --create-home --shell /bin/bash codeguard && \
    mkdir -p /data /workspace && \
    chown -R codeguard:codeguard /data /app

USER codeguard

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=3)"

CMD ["codeguard", "ui", "--host", "0.0.0.0", "--port", "8765"]

