"""HTTP API integration tests."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.api.app import create_app
from sentinel.api.dependencies import AppState, install_state
from sentinel.tenancy.manager import TenantManager

if TYPE_CHECKING:
    from sentinel.core.interceptor import Interceptor


@pytest.mark.asyncio
async def test_healthz(interceptor: Interceptor):
    install_state(AppState(interceptor=interceptor, tenants=TenantManager.with_default()))
    os.environ["SENTINEL_API_TOKEN"] = ""  # public health bypass
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_evaluate_requires_auth(interceptor: Interceptor):
    install_state(AppState(interceptor=interceptor, tenants=TenantManager.with_default()))
    os.environ["SENTINEL_API_TOKEN"] = "secret"
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.post("/v1/evaluate", json={})
    assert r.status_code == 401
