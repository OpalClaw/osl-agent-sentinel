"""Local policy cache used during fail-closed degradation.

When the upstream policy source is unreachable, the cache supplies the last
known-good signed bundle so the pipeline can continue to make conservative
decisions instead of crashing or, worse, opening up.

Decisions made while the cache is serving the bundle are flagged
``degraded=True``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sentinel.models.policy import PolicyBundle
from sentinel.utils.canonical import canonical_bytes
from sentinel.utils.logging import get_logger

log = get_logger(__name__)


class LocalPolicyCache:
    """File-backed, signed policy cache."""

    BUNDLE_FILE = "policy_bundle.json"
    META_FILE = "policy_meta.json"

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, bundle: PolicyBundle) -> None:
        bundle_path = self._dir / self.BUNDLE_FILE
        meta_path = self._dir / self.META_FILE
        bundle_path.write_bytes(canonical_bytes(bundle.model_dump(mode="json")))
        meta = {
            "version": bundle.version,
            "issuer": bundle.issuer,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        meta_path.write_text(json.dumps(meta, indent=2))
        log.info("policy.cache.saved", version=bundle.version, path=str(bundle_path))

    def load(self) -> PolicyBundle | None:
        path = self._dir / self.BUNDLE_FILE
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            return PolicyBundle.model_validate(data)
        except Exception as exc:  # noqa: BLE001
            log.error("policy.cache.load_failed", error=str(exc), path=str(path))
            return None

    def is_present(self) -> bool:
        return (self._dir / self.BUNDLE_FILE).exists()
