"""Bearer-token authentication middleware.

Verifies the ``Authorization: Bearer <token>`` header against the
``SENTINEL_API_TOKEN`` environment variable using a constant-time compare.
Unauthenticated requests to non-public paths get a 401.
"""

from __future__ import annotations

import hmac
import os
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.types import ASGIApp

_PUBLIC_PATHS = {"/healthz", "/livez", "/readyz", "/metrics", "/docs", "/openapi.json", "/redoc"}


class BearerAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, env_var: str = "SENTINEL_API_TOKEN") -> None:
        super().__init__(app)
        self._token = os.getenv(env_var, "")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        if path in _PUBLIC_PATHS or path.startswith("/static/"):
            return await call_next(request)
        if not self._token:
            # Fail closed when no token is configured but auth is required.
            return JSONResponse(
                {"error": "service_unconfigured", "detail": "SENTINEL_API_TOKEN not set"},
                status_code=503,
            )
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        presented = auth.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(presented, self._token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)
