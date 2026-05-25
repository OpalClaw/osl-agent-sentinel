"""Approval workflow endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from sentinel.api.dependencies import AppState, get_state, get_tenant
from sentinel.core.approval import PendingApproval
from sentinel.tenancy.manager import TenantConfig

router = APIRouter(prefix="/v1/approvals", tags=["approvals"])


@router.get("", response_model=list[PendingApproval])
async def list_pending(
    tenant: TenantConfig = Depends(get_tenant),
    state: AppState = Depends(get_state),
) -> list[PendingApproval]:
    return await state.interceptor.list_pending_approvals(tenant.tenant_id)


@router.post("/{approval_id}/resolve")
async def resolve(
    approval_id: str,
    verdict: str,
    reviewer: str,
    note: str = "",
    tenant: TenantConfig = Depends(get_tenant),
    state: AppState = Depends(get_state),
) -> dict[str, str]:
    if verdict not in {"allow", "deny"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="verdict must be allow|deny")
    await state.interceptor.resolve_approval(approval_id, verdict, reviewer, note, tenant.tenant_id)
    return {"status": "resolved", "verdict": verdict}
