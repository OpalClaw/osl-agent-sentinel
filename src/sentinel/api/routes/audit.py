"""Audit query endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from sentinel.api.dependencies import AppState, get_state, get_tenant
from sentinel.models.audit import AuditRecord
from sentinel.tenancy.manager import TenantConfig

router = APIRouter(prefix="/v1/audit", tags=["audit"])


@router.get("", response_model=list[AuditRecord])
async def list_audit(
    limit: int = Query(default=100, ge=1, le=1000),
    cursor: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
    tenant: TenantConfig = Depends(get_tenant),
    state: AppState = Depends(get_state),
) -> list[AuditRecord]:
    return await state.interceptor.list_audit(
        tenant.tenant_id, limit=limit, cursor=cursor, verdict=verdict
    )
