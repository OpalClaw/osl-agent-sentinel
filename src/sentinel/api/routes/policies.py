"""Policy bundle management."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, status

from sentinel.api.dependencies import AppState, get_state, get_tenant
from sentinel.models.policy import PolicyBundle

if TYPE_CHECKING:
    from sentinel.tenancy.manager import TenantConfig

router = APIRouter(prefix="/v1/policies", tags=["policies"])


@router.get("", response_model=PolicyBundle)
async def get_policy(
    tenant: TenantConfig = Depends(get_tenant),
    state: AppState = Depends(get_state),
) -> PolicyBundle:
    bundle = state.interceptor.current_policy(tenant.tenant_id)
    if bundle is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="no policy loaded")
    return bundle


@router.post("/reload", status_code=status.HTTP_202_ACCEPTED)
async def reload_policy(
    tenant: TenantConfig = Depends(get_tenant),
    state: AppState = Depends(get_state),
) -> dict[str, str]:
    bundle = state.interceptor.reload_policy(tenant.tenant_id)
    return {"status": "reloaded", "version": bundle.version}
