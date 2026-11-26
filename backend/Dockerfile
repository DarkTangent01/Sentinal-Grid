# pinned by digest (multi-arch index); Dependabot proposes updates (.github/dependabot.yml)
FROM python:3.12.16-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337 AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# fontconfig (PDF reports) needs a writable cache; the root filesystem is read-only, /tmp is a tmpfs
ENV XDG_CACHE_HOME=/tmp/.cache
WORKDIR /app
# upgrade: security fixes published after the pinned base image (Trivy, security/DOCKER_SECURITY_AUDIT.md)
# pango / harfbuzz / fonts: PDF reports (WeasyPrint, app/reports.py; it never fetches remote resources)
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ca-certificates tzdata \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /app siem \
    && mkdir -p /var/lib/siem/deadletter && chown siem:siem /var/lib/siem/deadletter  # named volume inherits this owner
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY alembic.ini .
COPY migrations ./migrations
COPY app ./app
COPY rules ./rules
# release version (scripts/release.sh: <UTC date>-<source hash>); shown to administrators on the Deployments page
ARG BUILD_VERSION=dev
ENV SENTINEL_VERSION=$BUILD_VERSION
LABEL org.opencontainers.image.version=$BUILD_VERSION
# numeric: lets the runtime verify non-root without resolving names (uid 10001 = siem, its group from /etc/passwd)
USER 10001
EXPOSE 8000 5514/udp 5514/tcp
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-server-header", \
     "--timeout-graceful-shutdown", "25"]
# SIGTERM (docker stop, rolling deploys): uvicorn stops accepting, finishes in-flight requests for up to 25 s, then exits;
# docker-compose.yml stop_grace_period (30 s) leaves room for it
