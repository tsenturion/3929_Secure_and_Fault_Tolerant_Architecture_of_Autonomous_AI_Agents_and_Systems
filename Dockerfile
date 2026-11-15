FROM ghcr.io/astral-sh/uv:0.12.17 AS uv
FROM python:3.14-slim-bookworm AS backend
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-cache \
    && mkdir -p /app/logs /app/state /app/tpm-trust /app/checkpoints \
    && chown 10001:10001 /app/logs /app/state /app/tpm-trust /app/checkpoints
COPY dispatcher ./dispatcher
COPY config/on-call.json ./config/on-call.json
USER 10001:10001
ENTRYPOINT ["/app/.venv/bin/python", "-m", "uvicorn"]

FROM backend AS tpm
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends swtpm tpm2-tools libtss2-tcti-swtpm0 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 -o 10001 -g 10001 /app/tpm-state
USER 10001:10001

FROM node:26-bookworm-slim AS frontend-build
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/index.html frontend/tsconfig.json frontend/vite.config.ts ./
COPY frontend/src ./src
RUN npm run build

FROM nginxinc/nginx-unprivileged:stable-alpine AS frontend
COPY docker/frontend.conf /etc/nginx/conf.d/default.conf
COPY --from=frontend-build /frontend/dist /usr/share/nginx/html
