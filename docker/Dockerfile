# syntax=docker/dockerfile:1.7
# =============================================================================
# osl-agent-sentinel — production image
# =============================================================================
# Multi-stage:
#   1. rust-builder   — compile sentinel-engine release binary / cdylib.
#   2. python-builder — install Python deps into a venv.
#   3. runtime        — minimal distroless-style image (slim + non-root).
# =============================================================================

ARG PYTHON_VERSION=3.12
ARG RUST_VERSION=1.78

# --- Stage 1: rust-builder ----------------------------------------------------
FROM rust:${RUST_VERSION}-slim-bookworm AS rust-builder
WORKDIR /build
COPY sentinel-engine/ sentinel-engine/
RUN cargo build --manifest-path sentinel-engine/Cargo.toml --release \
 && strip sentinel-engine/target/release/libsentinel_engine.so 2>/dev/null || true

# --- Stage 2: python-builder --------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS python-builder
ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md ./
COPY src/ src/
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
 && /opt/venv/bin/pip install .

# --- Stage 3: runtime ---------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    SENTINEL_ENV=production \
    SENTINEL_API_HOST=0.0.0.0 \
    SENTINEL_API_PORT=8080
RUN groupadd --system --gid 1000 sentinel \
 && useradd  --system --uid 1000 --gid 1000 --home /home/sentinel --shell /usr/sbin/nologin sentinel \
 && mkdir -p /var/lib/sentinel /etc/sentinel \
 && chown -R sentinel:sentinel /var/lib/sentinel /etc/sentinel
COPY --from=python-builder /opt/venv /opt/venv
COPY --from=rust-builder /build/sentinel-engine/target/release/libsentinel_engine.so /opt/sentinel/libsentinel_engine.so
COPY config/ /etc/sentinel/
USER sentinel
WORKDIR /home/sentinel
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"SENTINEL_API_PORT\",\"8080\")}/livez').read()" \
  || exit 1
ENTRYPOINT ["python", "-m", "uvicorn", "sentinel.bootstrap:app", "--host", "0.0.0.0", "--port", "8080"]
