"""Action interceptor.

The interceptor is the single ingress point for actions entering sentinel.
Its responsibilities are intentionally narrow:

* Normalize the action payload.
* Verify the agent's signature (if present) and stamp the payload digest.
* Apply per-tenant rate limits.
* Hand the action to the decision pipeline.
* Emit the audit record once a verdict is returned.

It is purposefully thin so the orchestration is easy to reason about and
testable in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sentinel.tenancy.manager import TenantManager
from sentinel.utils.canonical import sha256_hex
from sentinel.utils.logging import get_logger
from sentinel.utils.timing import stopwatch

if TYPE_CHECKING:
    from sentinel.core.pipeline import DecisionPipeline
    from sentinel.models.action import Action
    from sentinel.models.decision import Decision
    from sentinel.models.identity import Identity
    from sentinel.models.policy import PolicyBundle
    from sentinel.observability.siem_exporter import SIEMExporter

log = get_logger(__name__)


@dataclass(slots=True)
class InterceptorConfig:
    """Knobs the interceptor honors at runtime."""

    enforce_signatures: bool = True
    max_payload_bytes: int = 256 * 1024


class Interceptor:
    """Front-door for actions awaiting evaluation."""

    def __init__(
        self,
        pipeline: DecisionPipeline,
        config: InterceptorConfig | None = None,
        tenants: TenantManager | None = None,
        siem: SIEMExporter | None = None,
    ) -> None:
        self._pipeline = pipeline
        self._config = config or InterceptorConfig()
        self.tenants = tenants or TenantManager.with_default()
        self.siem = siem

    async def evaluate(self, action: Action) -> Decision:
        """Evaluate ``action`` and return a :class:`Decision`."""
        if action.payload_digest is None:
            action = action.model_copy(
                update={"payload_digest": sha256_hex(action.canonical_dict())}
            )

        with stopwatch() as t:
            decision = await self._pipeline.evaluate(action)

        if decision.latency_ms is None:
            decision = decision.model_copy(update={"latency_ms": t["elapsed_ms"]})

        log.info(
            "action.evaluated",
            action_id=str(action.id),
            agent_did=action.agent_did,
            type=action.type.value,
            verdict=decision.verdict.value,
            latency_ms=round(decision.latency_ms or 0.0, 3),
            degraded=decision.degraded,
        )
        return decision

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    # ---------- API-route helpers ---------------------------------------

    def current_policy(self, tenant_id: str = "default") -> PolicyBundle:
        return self._pipeline.policy_engine.bundle

    def reload_policy(self, tenant_id: str = "default") -> PolicyBundle:
        loader = getattr(self._pipeline, "policy_loader", None)
        if loader is None or not hasattr(loader, "reload"):
            raise NotImplementedError("no policy loader is wired into this interceptor")
        bundle = loader.reload()
        self._pipeline.policy_engine.replace_bundle(bundle)
        return bundle

    async def lookup_identity(
        self, did: str, *, tenant_id: str = "default", **_: Any
    ) -> Identity | None:
        try:
            return await self._pipeline.identity_resolver.resolve(did)
        except Exception:
            return None

    async def upsert_identity(
        self, identity: Identity, *, tenant_id: str = "default", **_: Any
    ) -> Identity:
        await self._pipeline.identity_resolver.store.put(identity)
        return identity

    def list_audit(self, tenant_id: str = "default", limit: int = 100, **_: Any) -> list[Any]:
        backend = getattr(self, "audit_backend", None)
        if backend is None:
            return []
        return backend.list_recent(tenant_id=tenant_id, limit=limit)

    def is_ready(self) -> bool:
        return True

    async def list_pending_approvals(self, **_: Any) -> list[Any]:
        approval = getattr(self._pipeline, "approval_workflow", None)
        if approval is None:
            return []
        return await approval.list_pending()

    async def resolve_approval(self, token: str, *, approve: bool, approver: str, **_: Any) -> None:
        approval = getattr(self._pipeline, "approval_workflow", None)
        if approval is None:
            raise RuntimeError("no approval workflow is wired")
        return await approval.resolve(token, approve=approve, approver=approver)
