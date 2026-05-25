"""Process bootstrap.

Builds a default :class:`Interceptor` from environment variables and exposes
the ASGI app for ``uvicorn``. Production deployments typically replace
:func:`build_default_interceptor` with their own factory.
"""

from __future__ import annotations

import os
from pathlib import Path

from sentinel.api.app import create_app
from sentinel.api.dependencies import AppState
from sentinel.classifiers import AnomalyDetector, IntentClassifier, PromptInjectionDetector, ToolValidator
from sentinel.core.approval import ApprovalWorkflow
from sentinel.core.cache import LocalPolicyCache
from sentinel.core.circuit_breaker import CircuitBreaker
from sentinel.core.interceptor import Interceptor
from sentinel.core.pipeline import DecisionPipeline
from sentinel.core.policy_engine import PolicyEngine
from sentinel.dlp import DLPScanner
from sentinel.identity import IdentityResolver, InMemoryIdentityStore, TrustScorer
from sentinel.observability.metrics import Metrics
from sentinel.observability.siem_exporter import SIEMExporter
from sentinel.observability.telemetry import configure_telemetry
from sentinel.policy_pac.loader import PolicyLoader
from sentinel.tenancy.manager import TenantConfig, TenantManager
from sentinel.utils.logging import configure_logging


def build_default_interceptor() -> Interceptor:
    """Construct an interceptor wired from environment variables."""

    configure_logging()
    configure_telemetry()

    policy_path = Path(os.getenv("SENTINEL_POLICY_PATH", "config/policies/default.yaml"))
    cache_dir = Path(os.getenv("SENTINEL_CACHE_DIR", ".sentinel-cache"))
    cache_dir.mkdir(parents=True, exist_ok=True)

    loader = PolicyLoader(policy_path)
    cache = LocalPolicyCache(cache_dir / "last-known-good.json")
    engine = PolicyEngine(loader=loader, cache=cache)

    pipeline = DecisionPipeline(
        engine=engine,
        intent=IntentClassifier(),
        tool_validator=ToolValidator(),
        anomaly=AnomalyDetector(),
        injection=PromptInjectionDetector(),
        dlp=DLPScanner.default(),
        identity=IdentityResolver(store=InMemoryIdentityStore()),
        trust=TrustScorer(),
        approval=ApprovalWorkflow(),
        breakers={
            "identity": CircuitBreaker(name="identity"),
            "policy": CircuitBreaker(name="policy"),
            "dlp": CircuitBreaker(name="dlp"),
        },
        metrics=Metrics.default(),
    )

    siem = SIEMExporter()
    return Interceptor(
        pipeline=pipeline,
        siem=siem,
        tenants=TenantManager(seed=[TenantConfig(tenant_id="default", display_name="Default")]),
    )


_interceptor = build_default_interceptor()
asgi_app = create_app(state=AppState(interceptor=_interceptor, tenants=_interceptor.tenants))
