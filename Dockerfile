FROM python:3.12-slim-bookworm as base
WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y curl && apt-get clean
ENV PDM_VERSION=2.20.0.post1
ENV PDM_HOME=/opt/pdm
RUN curl -sSL https://pdm-project.org/install-pdm.py | python3 -


FROM python:3.12-slim-bookworm
WORKDIR /usr/src/app
COPY --from=base /opt/pdm /opt/pdm

ENV PATH="/opt/pdm/bin:$PATH"

# Setup project
COPY pyproject.toml pdm.lock README.md ./
RUN mkdir -p src/driver_did_indy && touch src/driver_did_indy/__init__.py
RUN pdm install

COPY healthcheck.py ./
COPY src ./src

ENTRYPOINT ["pdm", "run"]
CMD ["fastapi", "dev", "src/driver_did_indy/app.py", "--host", "0.0.0.0", "--port", "80"]
