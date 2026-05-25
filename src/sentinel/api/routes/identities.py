"""Identity management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from sentinel.api.dependencies import AppState, get_state, get_tenant
from sentinel.models.identity import Identity
from sentinel.tenancy.manager import TenantConfig

router = APIRouter(prefix="/v1/identities", tags=["identities"])


@router.get("/{did:path}", response_model=Identity)
async def get_identity(
    did: str,
    tenant: TenantConfig = Depends(get_tenant),
    state: AppState = Depends(get_state),
) -> Identity:
    identity = await state.interceptor.lookup_identity(did, tenant.tenant_id)
    if identity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="identity not found")
    return identity


@router.post("", response_model=Identity, status_code=status.HTTP_201_CREATED)
async def upsert_identity(
    identity: Identity,
    tenant: TenantConfig = Depends(get_tenant),
    state: AppState = Depends(get_state),
) -> Identity:
    return await state.interceptor.upsert_identity(identity, tenant.tenant_id)
