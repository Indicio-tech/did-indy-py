FROM python:3.12-slim-bookworm
WORKDIR /usr/src/app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Setup project
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-install-project --all-extras

COPY healthcheck.py ./
COPY scripts/ scripts/
COPY src ./src
RUN uv sync --locked --all-extras

ENTRYPOINT ["uv", "run"]
CMD ["fastapi", "dev", "src/did_indy/driver/app.py", "--host", "0.0.0.0", "--port", "80"]
