"""Shared FastAPI dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import Depends, Header, HTTPException, status

if TYPE_CHECKING:
    from sentinel.core.interceptor import Interceptor
    from sentinel.tenancy.manager import TenantConfig, TenantManager


@dataclass(slots=True)
class AppState:
    interceptor: Interceptor
    tenants: TenantManager


_state: AppState | None = None


def install_state(state: AppState) -> None:
    global _state
    _state = state


def get_state() -> AppState:
    if _state is None:
        raise RuntimeError("AppState not installed; call install_state() at startup")
    return _state


def get_tenant(
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    state: AppState = Depends(get_state),
) -> TenantConfig:
    tenant_id = x_tenant_id or "default"
    try:
        return state.tenants.get(tenant_id)
    except Exception as exc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"unknown tenant: {tenant_id}"
        ) from exc
