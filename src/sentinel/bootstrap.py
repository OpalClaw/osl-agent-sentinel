"""Process bootstrap.

Builds a default Interceptor from environment variables and exposes the
ASGI app for uvicorn. Production deployments typically replace
build_default_interceptor with their own factory.
"""

from __future__ import annotations

import os
from pathlib import Path

from sentinel.api.app import create_app
from sentinel.api.dependencies import AppState, install_state
from sentinel.classifiers import (
    AnomalyDetector,
    IntentClassifier,
    PromptInjectionDetector,
    ToolValidator,
)
from sentinel.core.approval import ApprovalWorkflow, InMemoryApprovalBackend
from sentinel.core.cache import LocalPolicyCache
from sentinel.core.circuit_breaker import CircuitBreaker
from sentinel.core.interceptor import Interceptor, InterceptorConfig
from sentinel.core.pipeline import DecisionPipeline, PipelineDeps
from sentinel.core.policy_engine import PolicyEngine
from sentinel.dlp import DLPScanner
from sentinel.identity import IdentityResolver, InMemoryIdentityStore, TrustScorer
from sentinel.observability.metrics import Metrics
from sentinel.observability.telemetry import configure_telemetry
from sentinel.policy_pac.loader import PolicyLoader
from sentinel.tenancy.manager import TenantManager
from sentinel.utils.logging import configure_logging


def build_default_interceptor() -> Interceptor:
    """Construct an interceptor wired from environment variables."""

    configure_logging()
    configure_telemetry()

    policy_path = Path(os.getenv("SENTINEL_POLICY_PATH", "config/policies/default.yaml"))
    cache_dir = Path(os.getenv("SENTINEL_CACHE_DIR", ".sentinel-cache"))
    cache_dir.mkdir(parents=True, exist_ok=True)

    loader = PolicyLoader(policy_path)
    cache = LocalPolicyCache(directory=cache_dir)
    try:
        bundle = loader.load()
        cache.save(bundle)
    except Exception:
        # Fail-closed degradation: fall back to last-known-good.
        cached = cache.load()
        if cached is None:
            raise
        bundle = cached
    engine = PolicyEngine(bundle=bundle)

    deps = PipelineDeps(
        policy_engine=engine,
        identity_resolver=IdentityResolver(store=InMemoryIdentityStore()),
        intent_classifier=IntentClassifier(),
        tool_validator=ToolValidator(),
        anomaly_detector=AnomalyDetector(),
        injection_detector=PromptInjectionDetector(),
        dlp_scanner=DLPScanner.default(),
        trust_scorer=TrustScorer(),
        approval_workflow=ApprovalWorkflow(backend=InMemoryApprovalBackend()),
        policy_cache=cache,
        identity_breaker=CircuitBreaker(name="identity"),
        policy_breaker=CircuitBreaker(name="policy"),
        dlp_breaker=CircuitBreaker(name="dlp"),
        tenants=TenantManager.with_default(),
        metrics=Metrics.default(),
    )

    pipeline = DecisionPipeline(deps=deps)
    return Interceptor(
        pipeline=pipeline,
        config=InterceptorConfig(),
        tenants=TenantManager.with_default(),
    )


_interceptor = build_default_interceptor()
_state = AppState(interceptor=_interceptor, tenants=_interceptor.tenants)
install_state(_state)
asgi_app = create_app(state=_state)
