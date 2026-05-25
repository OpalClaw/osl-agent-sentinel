"""Token-bucket rate limiter per tenant."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp


@dataclass(slots=True)
class _Bucket:
    capacity: float
    tokens: float
    refill_per_second: float
    last_refill: float = field(default_factory=time.monotonic)

    def take(self, n: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.last_refill = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


class TenantRateLimitMiddleware(BaseHTTPMiddleware):
    """Per-tenant token bucket. Tenant is read from ``X-Tenant-Id``."""

    def __init__(self, app: ASGIApp, *, rpm: int = 1200, burst: int = 240) -> None:
        super().__init__(app)
        self._rpm = rpm
        self._burst = burst
        self._buckets: dict[str, _Bucket] = {}

    def _bucket(self, tenant: str) -> _Bucket:
        b = self._buckets.get(tenant)
        if b is None:
            b = _Bucket(capacity=self._burst, tokens=self._burst, refill_per_second=self._rpm / 60.0)
            self._buckets[tenant] = b
        return b

    async def dispatch(self, request: Request, call_next):
        tenant = request.headers.get("x-tenant-id", "default")
        if not self._bucket(tenant).take():
            return JSONResponse(
                {"error": "rate_limited", "tenant": tenant},
                status_code=429,
                headers={"retry-after": "1"},
            )
        return await call_next(request)
