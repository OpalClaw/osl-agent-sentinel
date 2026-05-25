"""DID resolution and identity registry.

Production deployments typically front this with a real DID resolver
(``did:web``, ``did:key``, ``did:ion``). The default in-memory store is
suitable for tests and small single-node deployments.
"""

from __future__ import annotations

from typing import Protocol

from sentinel.models.identity import Identity
from sentinel.utils.errors import IdentityError


class IdentityStore(Protocol):
    """Pluggable backend for identity lookup."""

    async def get(self, did: str) -> Identity | None: ...
    async def put(self, identity: Identity) -> None: ...
    async def revoke(self, did: str) -> None: ...


class InMemoryIdentityStore:
    """Default backend; suitable for tests and single-node deployments."""

    def __init__(self, seed: list[Identity] | None = None) -> None:
        self._items: dict[str, Identity] = {}
        for item in seed or []:
            self._items[item.did] = item

    async def get(self, did: str) -> Identity | None:
        return self._items.get(did)

    async def put(self, identity: Identity) -> None:
        self._items[identity.did] = identity

    async def revoke(self, did: str) -> None:
        if did in self._items:
            self._items[did] = self._items[did].model_copy(update={"revoked": True})


class IdentityResolver:
    """Resolve an agent DID into an :class:`Identity`."""

    def __init__(self, store: IdentityStore | None = None) -> None:
        self._store = store or InMemoryIdentityStore()

    async def resolve(self, did: str) -> Identity:
        identity = await self._store.get(did)
        if identity is None:
            raise IdentityError(f"Unknown DID: {did}")
        if identity.revoked:
            raise IdentityError(f"DID {did} is revoked")
        return identity

    @property
    def store(self) -> IdentityStore:
        return self._store
