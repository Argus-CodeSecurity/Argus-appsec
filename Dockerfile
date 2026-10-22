# Argus container image.
#
# Multi-stage build: install into a venv in the builder, copy the venv into a
# slim runtime. Includes git so remote repository targets can be cloned.
#
# Supply chain: the base image is pinned by digest (Dependabot keeps it current)
# and runtime dependencies are installed from the hash-pinned requirements.lock,
# so a substituted or tampered package fails the build instead of shipping.
ARG PYTHON_IMAGE=python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2

FROM ${PYTHON_IMAGE} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /src
COPY requirements.lock ./
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --require-hashes -r requirements.lock

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-deps .

# --- runtime ---------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="Argus" \
      org.opencontainers.image.description="Open-source application security scanner" \
      org.opencontainers.image.source="https://github.com/Argus-CodeSecurity/Argus-appsec" \
      org.opencontainers.image.documentation="https://argus-codesecurity.github.io/Argus-appsec/" \
      org.opencontainers.image.licenses="Apache-2.0"

# git is needed to scan remote repositories.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Run as a non-root user.
RUN useradd --create-home --uid 10001 argus
USER 10001
WORKDIR /work

# Mount the project to scan at /work.
ENTRYPOINT ["argus"]
CMD ["--help"]
