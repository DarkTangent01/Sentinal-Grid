FROM python:3.12.8-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /app siem
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY alembic.ini .
COPY migrations ./migrations
COPY app ./app
USER siem
EXPOSE 8000 5514/udp 5514/tcp
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-server-header"]
