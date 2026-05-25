"""High-level Sentinel SDK.

Embed :class:`Sentinel` in an agent runtime to gate every action before
execution. Two usage modes:

* **Remote** — point at a hosted control plane via HTTP. Recommended for
  production deployments.
* **Embedded** — instantiate a local pipeline. Useful for tests,
  benchmarks, and single-process deployments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from sentinel.core.interceptor import Interceptor
from sentinel.models.action import Action
from sentinel.models.decision import Decision, DecisionVerdict
from sentinel.utils.errors import SentinelError


@dataclass(slots=True)
class RemoteConfig:
    base_url: str
    token: str
    tenant_id: str = "default"
    timeout_seconds: float = 5.0
    fail_closed: bool = True


class Sentinel:
    """SDK facade. Either embedded or remote."""

    def __init__(
        self,
        *,
        interceptor: Interceptor | None = None,
        remote: RemoteConfig | None = None,
    ) -> None:
        if not interceptor and not remote:
            raise SentinelError("Sentinel requires either an interceptor or a RemoteConfig")
        self._interceptor = interceptor
        self._remote = remote
        self._client: httpx.AsyncClient | None = None
        if remote:
            self._client = httpx.AsyncClient(
                base_url=remote.base_url,
                timeout=remote.timeout_seconds,
                headers={
                    "authorization": f"Bearer {remote.token}",
                    "x-tenant-id": remote.tenant_id,
                    "content-type": "application/json",
                },
            )

    @classmethod
    def from_env(cls) -> "Sentinel":
        base_url = os.environ["SENTINEL_BASE_URL"]
        token = os.environ["SENTINEL_API_TOKEN"]
        tenant = os.getenv("SENTINEL_TENANT_ID", "default")
        return cls(remote=RemoteConfig(base_url=base_url, token=token, tenant_id=tenant))

    async def evaluate(self, action: Action) -> Decision:
        if self._interceptor:
            return await self._interceptor.evaluate(action)
        assert self._client is not None
        try:
            resp = await self._client.post("/v1/evaluate", json=action.model_dump(mode="json"))
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            if self._remote and self._remote.fail_closed:
                return Decision.deny(
                    action_id=action.id,
                    reason="sentinel_unreachable",
                    explanation=f"control plane error: {exc}",
                    degraded=True,
                )
            raise
        return Decision.model_validate(resp.json())

    async def allow(self, action: Action) -> bool:
        decision = await self.evaluate(action)
        return decision.verdict == DecisionVerdict.ALLOW

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
