# Sphinx API — FastAPI server with JWT/RBAC
# No forensic tools here; those live in the REPL container.

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq-dev gcc postgresql-client ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

ENTRYPOINT ["./docker/entrypoint.sh"]
CMD ["--api"]