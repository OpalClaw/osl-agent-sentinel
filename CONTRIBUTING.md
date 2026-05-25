# Contributing to osl-agent-sentinel

Thank you for considering a contribution. This project is the runtime security layer for production agent systems, so contributions are held to the same engineering standard as the rest of the OpalSageLabs portfolio: complete, tested, secure-by-default, and ready to ship.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Bug reports** — file a GitHub issue using the bug template.
- **Feature requests** — file a GitHub issue using the feature template and describe the threat or use case being addressed.
- **Security findings** — see [SECURITY.md](SECURITY.md). Do not open a public issue for these.
- **Pull requests** — read this document fully first.

## Development environment

Requirements:

- Python 3.11 or newer
- Rust stable (1.75+) with `cargo`, `rustfmt`, `clippy`
- Docker 24+ and Docker Compose v2
- `make`, `git`, `pre-commit`

Set up:

```bash
git clone https://github.com/OpalClaw/osl-agent-sentinel.git
cd osl-agent-sentinel
make install        # creates .venv and installs Python + Rust toolchains
make pre-commit     # installs git hooks
make test           # runs the full local test matrix
```

## Coding standards

- **Python** — full type hints, `black`, `ruff`, `mypy --strict`, PEP 8. No untyped function bodies. No `# type: ignore` without a justification comment.
- **Rust** — idiomatic, safe, `cargo fmt`, `cargo clippy -- -D warnings`, zero `unsafe` outside the explicit FFI boundary.
- **Tests** — every new module ships with unit tests; every new control-plane endpoint ships with an integration test; every security-relevant code path ships with a red-team test case in `tests/redteam/`.
- **Docs** — every public function, class, and CLI command has a docstring or `///` doc comment. Updates to behavior require updates to the relevant `docs/` page.
- **Commits** — follow [Conventional Commits](https://www.conventionalcommits.org/). Valid prefixes: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `security`, `perf`, `build`, `ci`.
- **Branches** — branch from `main`. Feature branches: `feat/<short-name>`. Security branches: `security/<short-name>`.

## Pull request process

1. Open a draft PR early. Link the related issue.
2. Fill in every section of the PR template, including the security review checklist.
3. Ensure CI is green. PRs are not reviewed until CI passes.
4. Request review from the appropriate `CODEOWNERS`.
5. Squash-merge once approved. The merge commit must use a Conventional Commit subject.

## Review priorities

Reviewers focus on, in order:

1. **Security** — does this change weaken any control? Could it be exploited by a compromised agent?
2. **Correctness** — does it do what the description says, and is it covered by tests?
3. **Performance** — does it meet the latency budget documented in `docs/PERFORMANCE.md`?
4. **API design** — is the public surface minimal, well-named, and stable?
5. **Documentation** — would a senior engineer be able to operate this in production without asking questions?

## Releasing

Releases are cut by maintainers. The flow is documented in `docs/RELEASE-PROCESS.md` and is fully automated by `.github/workflows/release.yml`.

## Questions

Open a GitHub Discussion or reach out at `engineering@opalsagelabs.click`.
