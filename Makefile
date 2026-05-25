# =============================================================================
# osl-agent-sentinel — developer Makefile
# =============================================================================
# Standard commands for install, build, test, lint, format, docker, and deploy.
# Every command is non-interactive and CI-safe.
# =============================================================================

.DEFAULT_GOAL := help
SHELL := /bin/bash

PY            ?= python3
VENV          ?= .venv
VENV_BIN      := $(VENV)/bin
PIP           := $(VENV_BIN)/pip
PYTHON        := $(VENV_BIN)/python
RUFF          := $(VENV_BIN)/ruff
BLACK         := $(VENV_BIN)/black
MYPY          := $(VENV_BIN)/mypy
PYTEST        := $(VENV_BIN)/pytest
COVERAGE      := $(VENV_BIN)/coverage

PROJECT       := osl-agent-sentinel
IMAGE         := ghcr.io/opalclaw/$(PROJECT)
VERSION       := $(shell $(PYTHON) -c "from sentinel._version import __version__; print(__version__)" 2>/dev/null || echo "0.0.0-dev")

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: install
install: ## Create venv, install Python deps, build Rust engine.
	$(PY) -m venv $(VENV)
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install -e ".[dev,test,docs]"
	cargo build --manifest-path sentinel-engine/Cargo.toml --release

.PHONY: pre-commit
pre-commit: ## Install pre-commit hooks.
	$(VENV_BIN)/pre-commit install --install-hooks

.PHONY: format
format: ## Format Python and Rust sources.
	$(BLACK) src tests
	$(RUFF) check --fix src tests
	cargo fmt --manifest-path sentinel-engine/Cargo.toml --all

.PHONY: lint
lint: ## Lint Python and Rust sources.
	$(RUFF) check src tests
	$(BLACK) --check src tests
	cargo fmt --manifest-path sentinel-engine/Cargo.toml --all -- --check
	cargo clippy --manifest-path sentinel-engine/Cargo.toml --all-targets --all-features -- -D warnings

.PHONY: typecheck
typecheck: ## Run mypy in strict mode.
	$(MYPY) --strict src

.PHONY: test
test: ## Run the full test suite with coverage.
	$(PYTEST) -q --cov=sentinel --cov-report=term-missing --cov-report=xml
	cargo test --manifest-path sentinel-engine/Cargo.toml --all-features

.PHONY: test-unit
test-unit: ## Run unit tests only.
	$(PYTEST) -q tests/unit

.PHONY: test-integration
test-integration: ## Run integration tests only.
	$(PYTEST) -q tests/integration

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests only.
	$(PYTEST) -q tests/e2e

.PHONY: test-redteam
test-redteam: ## Run the red-team harness.
	$(PYTEST) -q tests/redteam

.PHONY: security-scan
security-scan: ## Run all SAST and dependency scanners.
	$(VENV_BIN)/bandit -r src -ll
	$(VENV_BIN)/pip-audit
	cargo audit --manifest-path sentinel-engine/Cargo.toml

.PHONY: docs
docs: ## Build the documentation site.
	$(VENV_BIN)/mkdocs build --strict

.PHONY: docs-serve
docs-serve: ## Serve the documentation site locally.
	$(VENV_BIN)/mkdocs serve

.PHONY: docker
docker: ## Build the production container image.
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest -f docker/Dockerfile .

.PHONY: docker-dev
docker-dev: ## Start the local development stack.
	docker compose -f docker/docker-compose.yml up --build

.PHONY: sbom
sbom: ## Generate CycloneDX and SPDX SBOMs.
	$(VENV_BIN)/cyclonedx-py environment -o sbom/cyclonedx.json
	bash scripts/release/generate_spdx.sh sbom/spdx.json

.PHONY: clean
clean: ## Remove caches and build artifacts.
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml .coverage
	cargo clean --manifest-path sentinel-engine/Cargo.toml || true

.PHONY: release-check
release-check: lint typecheck test security-scan ## Run the full release gate.
	@echo "release-check OK for $(VERSION)"
