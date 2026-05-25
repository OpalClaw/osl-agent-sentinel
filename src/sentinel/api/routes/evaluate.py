"""Action evaluation endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from sentinel.api.dependencies import AppState, get_state, get_tenant
from sentinel.models.action import Action
from sentinel.models.decision import Decision
from sentinel.tenancy.manager import TenantConfig

router = APIRouter(prefix="/v1", tags=["evaluate"])


@router.post("/evaluate", response_model=Decision, status_code=status.HTTP_200_OK)
async def evaluate(
    action: Action,
    tenant: TenantConfig = Depends(get_tenant),
    state: AppState = Depends(get_state),
) -> Decision:
    """Submit an action for sentinel evaluation. Returns a typed decision."""

    if action.tenant_id and action.tenant_id != tenant.tenant_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="tenant scope mismatch")
    if not action.tenant_id:
        action = action.model_copy(update={"tenant_id": tenant.tenant_id})
    return await state.interceptor.evaluate(action)
