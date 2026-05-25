"""Tenant manager.

Sentinel is multi-tenant by default. Every action carries a ``tenant_id``;
identities, policies, audit streams, and trust scores are all isolated by
tenant. The :class:`TenantManager` resolves the active tenant for a
request and supplies its configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.models.policy import PolicyBundle
from sentinel.utils.errors import TenantNotFoundError


@dataclass(slots=True)
class TenantConfig:
    """Per-tenant configuration knobs."""

    tenant_id: str
    display_name: str
    policy_bundle: PolicyBundle | None = None
    siem_endpoint: str | None = None
    siem_token: str | None = None
    require_signed_actions: bool = False
    max_actions_per_minute: int = 1200
    metadata: dict[str, str] = field(default_factory=dict)


class TenantManager:
    """In-memory tenant registry. Replace with a DB-backed store in production."""

    def __init__(self, seed: list[TenantConfig] | None = None) -> None:
        self._tenants: dict[str, TenantConfig] = {t.tenant_id: t for t in seed or []}

    def register(self, config: TenantConfig) -> None:
        self._tenants[config.tenant_id] = config

    def get(self, tenant_id: str) -> TenantConfig:
        try:
            return self._tenants[tenant_id]
        except KeyError as exc:
            raise TenantNotFoundError(tenant_id) from exc

    def list_tenants(self) -> list[TenantConfig]:
        return list(self._tenants.values())
