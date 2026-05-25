# Development

## Prerequisites

- Python 3.11 or 3.12
- Rust stable (`rustup default stable`)
- `make`, `git`, and Docker (for container builds)

## First-time setup

```bash
git clone https://github.com/OpalClaw/osl-agent-sentinel.git
cd osl-agent-sentinel
make install
```

`make install` creates a virtualenv at `.venv`, installs the project in editable mode with the `dev` extra, and builds the Rust engine in release mode.

## Day-to-day commands

| Command | Description |
| --- | --- |
| `make format` | Run Black, Ruff `--fix`, and `cargo fmt`. |
| `make lint` | Run Ruff, Black `--check`, and `cargo clippy -- -D warnings`. |
| `make type` | Run `mypy --strict`. |
| `make test` | Run the full Python test suite with coverage and the Rust test suite. |
| `make security` | Run Bandit, pip-audit, and `cargo audit`. |
| `make docker` | Build the production Docker image. |
| `make run` | Start the control plane locally with reload. |
| `make engine` | Rebuild the Rust engine. |
| `make clean` | Remove build artifacts. |

## Repository layout

See the top-level `README.md` and `docs/ARCHITECTURE.md`. The short version:

- `src/sentinel/` — Python control plane.
- `sentinel-engine/` — Rust execution-ring engine.
- `tests/` — Unit, integration, end-to-end, chaos, and fuzz suites.
- `config/` — Default policy bundles and tool registries.
- `docs/` — All architectural and operational documentation.

## Pre-commit checks

The CI runs the equivalent of `make lint type test security` on every pull request. Run these locally before pushing to keep the loop tight.
