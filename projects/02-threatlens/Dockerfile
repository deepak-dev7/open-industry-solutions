FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    THREATLENS_DB_PATH=/data/threatlens.db

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir . && \
    useradd --create-home --shell /bin/bash threatlens && \
    mkdir -p /data && \
    chown -R threatlens:threatlens /data /app

USER threatlens

EXPOSE 8766

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8766/api/health', timeout=3)"

CMD ["threatlens", "serve", "--host", "0.0.0.0", "--port", "8766"]
