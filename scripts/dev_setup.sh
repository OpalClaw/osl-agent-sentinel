#!/usr/bin/env bash
# Idempotent development setup.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"

if command -v cargo >/dev/null 2>&1; then
  cargo build --manifest-path sentinel-engine/Cargo.toml --release
else
  echo "warning: cargo not found — skipping Rust build" >&2
fi

echo "ready. activate with: source .venv/bin/activate"
