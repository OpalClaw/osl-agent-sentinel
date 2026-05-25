"""FastAPI application factory."""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from sentinel._version import __version__
from sentinel.api.dependencies import AppState, get_state, install_state
from sentinel.api.middleware.auth import BearerAuthMiddleware
from sentinel.api.middleware.rate_limit import TenantRateLimitMiddleware
from sentinel.api.middleware.request_id import RequestIdMiddleware
from sentinel.api.routes import approvals, audit, evaluate, health, identities, policies


def create_app(*, state: AppState | None = None) -> FastAPI:
    """Build the FastAPI application.

    The ``state`` argument is optional. When omitted, the factory looks up
    a previously-installed global :class:`AppState` (via
    :func:`install_state`). Production deployments should pass ``state``
    explicitly; the global hook exists for ergonomic test wiring.
    """
    if state is not None:
        install_state(state)
    else:
        # Will raise if no state has been installed — fail fast with a
        # readable error rather than crash on the first request.
        get_state()

    app = FastAPI(
        title="osl-agent-sentinel",
        version=__version__,
        description="Autonomous AI agent runtime security control plane.",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    cors_origins = (
        os.getenv("SENTINEL_CORS_ORIGINS", "").split(",")
        if os.getenv("SENTINEL_CORS_ORIGINS")
        else []
    )
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["authorization", "content-type", "x-tenant-id", "x-request-id"],
        )

    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(
        TenantRateLimitMiddleware,
        rpm=int(os.getenv("SENTINEL_RATE_LIMIT_RPM", "1200")),
        burst=int(os.getenv("SENTINEL_RATE_LIMIT_BURST", "240")),
    )
    app.add_middleware(BearerAuthMiddleware)

    app.include_router(health.router)
    app.include_router(evaluate.router)
    app.include_router(policies.router)
    app.include_router(identities.router)
    app.include_router(audit.router)
    app.include_router(approvals.router)

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app
