# SkillProof service image. Configuration is mounted at /config/skillproof.toml (see deploy/skillproof.example.toml);
# in a container set [server] host = "0.0.0.0" and put a TLS-terminating proxy in front.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

# git: lock-check reads locked skill repositories (bare clones, nothing checked out); pg_dump: PostgreSQL backups.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[postgres]" \
    && useradd --create-home --uid 10001 skillproof \
    && mkdir -p /data /backups /config \
    && chown skillproof /data /backups

USER skillproof
EXPOSE 8045
VOLUME ["/data", "/backups"]

# Ready only when every store answers (503 otherwise).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8045/health/ready', timeout=4).status == 200 else 1)"

CMD ["skillproof", "serve", "--config", "/config/skillproof.toml"]
