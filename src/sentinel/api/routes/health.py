"""Health, liveness, and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from sentinel._version import __version__
from sentinel.api.dependencies import AppState, get_state

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/livez")
async def livez() -> dict[str, str]:
    return {"status": "alive"}


@router.get("/readyz")
async def readyz(state: AppState = Depends(get_state)) -> dict[str, object]:
    ready = state.interceptor.is_ready()
    return {"status": "ready" if ready else "not_ready", "ready": ready}
