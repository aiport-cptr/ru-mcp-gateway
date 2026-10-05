FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev

FROM python:3.12-slim
RUN useradd --system --uid 10001 --home /app rugw
WORKDIR /app
COPY --from=build --chown=rugw:rugw /app /app
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
USER rugw
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD ["python", "-c", "import json,urllib.request as u; d=json.load(u.urlopen('http://127.0.0.1:8000/healthz')); assert d['auth_enabled'] is True"]
CMD ["python", "-m", "rugw", "serve", "--host", "0.0.0.0", "--port", "8000"]
