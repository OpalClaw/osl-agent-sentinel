"""Request ID middleware. Adds ``X-Request-Id`` if missing and echoes it back."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import ASGIApp


class RequestIdMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        rid = request.headers.get("x-request-id") or uuid4().hex
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["x-request-id"] = rid
        return response
