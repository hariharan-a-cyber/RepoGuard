FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app . .
RUN mkdir -p /app/data && chown -R app:app /app

USER app
ENV PYTHONUNBUFFERED=1 \
    SQLITE_DB_PATH=/app/data/repoguard.db

EXPOSE 7860
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-7860} --proxy-headers --forwarded-allow-ips='*'"]
