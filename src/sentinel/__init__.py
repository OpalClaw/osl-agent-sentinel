"""osl-agent-sentinel — autonomous AI agent runtime security layer.

Public entry points:

* :class:`sentinel.client.Sentinel` — embed in an agent runtime to evaluate actions.
* :mod:`sentinel.cli` — operate the control plane from the command line.
* :func:`sentinel.api.create_app` — ASGI factory for hosting the control plane.

The package is import-safe: importing :mod:`sentinel` does not trigger network
calls, file I/O against the policy store, or any side effects.
"""

from __future__ import annotations

from sentinel._version import __version__
from sentinel.client import Sentinel
from sentinel.models import (
    Action,
    ActionType,
    AuditRecord,
    Decision,
    DecisionVerdict,
    Identity,
    PolicyBundle,
    PolicyRule,
    RiskFactor,
    RuleEffect,
    TrustTier,
)

__all__ = [
    "Action",
    "ActionType",
    "AuditRecord",
    "Decision",
    "DecisionVerdict",
    "Identity",
    "PolicyBundle",
    "PolicyRule",
    "RiskFactor",
    "RuleEffect",
    "Sentinel",
    "TrustTier",
    "__version__",
]
