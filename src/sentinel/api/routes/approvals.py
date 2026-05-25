"""Approval workflow endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, status

from sentinel.api.dependencies import AppState, get_state, get_tenant

if TYPE_CHECKING:
    from sentinel.tenancy.manager import TenantConfig

router = APIRouter(prefix="/v1/approvals", tags=["approvals"])


@router.get("")
async def list_pending(
    tenant: TenantConfig = Depends(get_tenant),  # noqa: ARG001
    state: AppState = Depends(get_state),
) -> list[Any]:
    return await state.interceptor.list_pending_approvals()


@router.post("/{approval_id}/resolve")
async def resolve(
    approval_id: str,
    verdict: str,
    reviewer: str,
    tenant: TenantConfig = Depends(get_tenant),  # noqa: ARG001
    state: AppState = Depends(get_state),
) -> dict[str, str]:
    if verdict not in {"allow", "deny"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="verdict must be allow|deny")
    try:
        await state.interceptor.resolve_approval(
            approval_id, approve=(verdict == "allow"), approver=reviewer
        )
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    return {"status": "resolved", "verdict": verdict}
