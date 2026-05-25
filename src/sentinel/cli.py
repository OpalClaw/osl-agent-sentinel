"""Command-line interface.

Usage examples::

    sentinel serve --host 0.0.0.0 --port 8080
    sentinel policy verify config/policies/default.yaml --public-key keys/policy.pub
    sentinel policy sign config/policies/default.yaml --private-key keys/policy.key
    sentinel redteam run
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING

import typer

from sentinel._version import __version__
from sentinel.utils.logging import configure_logging, get_logger

if TYPE_CHECKING:
    from pathlib import Path

app = typer.Typer(add_completion=False, no_args_is_help=True, help="osl-agent-sentinel CLI")
policy_app = typer.Typer(help="Policy bundle operations")
redteam_app = typer.Typer(help="Red-team harness")
app.add_typer(policy_app, name="policy")
app.add_typer(redteam_app, name="redteam")

log = get_logger("sentinel.cli")


@app.callback()
def main(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    configure_logging(level="DEBUG" if verbose else None)


@app.command()
def version() -> None:
    """Print the installed sentinel version."""
    typer.echo(__version__)


@app.command()
def serve(
    host: str = "0.0.0.0",  # nosec B104 — intentional server bind, operator-controlled
    port: int = 8080,
    workers: int = 1,
    reload: bool = False,
) -> None:
    """Run the control plane HTTP server."""
    import uvicorn

    uvicorn.run(
        "sentinel.bootstrap:asgi_app",
        host=host,
        port=port,
        workers=workers,
        reload=reload,
        log_level="info",
    )


@policy_app.command("verify")
def policy_verify(
    path: Path = typer.Argument(..., exists=True, readable=True),
    public_key: Path = typer.Option(..., "--public-key", exists=True, readable=True),
) -> None:
    """Verify a signed policy bundle on disk."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from sentinel.policy_pac.loader import load_bundle_from_path

    pk = serialization.load_pem_public_key(public_key.read_bytes())
    if not isinstance(pk, Ed25519PublicKey):
        typer.echo("error: provided key is not Ed25519", err=True)
        sys.exit(2)
    bundle = load_bundle_from_path(path, public_key=pk)
    typer.echo(f"ok: version={bundle.version} rules={len(bundle.rules)}")


@policy_app.command("sign")
def policy_sign(
    path: Path = typer.Argument(..., exists=True, readable=True),
    private_key: Path = typer.Option(..., "--private-key", exists=True, readable=True),
    out: Path = typer.Option(..., "--out"),
) -> None:
    """Sign a policy bundle and write the signature alongside the data."""
    import base64
    import json

    import yaml
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from sentinel.models.policy import PolicyBundle
    from sentinel.utils.canonical import canonical_bytes
    from sentinel.utils.crypto import sign

    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw) if path.suffix in {".yaml", ".yml"} else json.loads(raw)
    bundle = PolicyBundle.model_validate(data)
    sk = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        typer.echo("error: provided key is not Ed25519", err=True)
        sys.exit(2)
    sig = sign(sk, canonical_bytes(bundle.model_dump(mode="json")))
    payload = bundle.model_dump(mode="json")
    payload["signature"] = base64.b64encode(sig).decode("ascii")
    out.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    typer.echo(f"signed: {out}")


@redteam_app.command("run")
def redteam_run() -> None:
    """Run the bundled red-team scenarios against an embedded pipeline."""
    from sentinel.bootstrap import build_default_interceptor
    from sentinel.redteam import RedTeamHarness, default_scenarios

    async def _go() -> int:
        interceptor = build_default_interceptor()
        await interceptor.start()
        try:
            harness = RedTeamHarness(interceptor)
            report = await harness.run(default_scenarios())
        finally:
            await interceptor.stop()
        typer.echo(
            f"total={report.total} passed={report.passed} "
            f"false_negatives={len(report.false_negatives)} "
            f"false_positives={len(report.false_positives)} "
            f"pass_rate={report.pass_rate:.2%}"
        )
        return 0 if not report.false_negatives else 1

    sys.exit(asyncio.run(_go()))


if __name__ == "__main__":  # pragma: no cover
    app()
