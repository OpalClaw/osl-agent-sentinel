"""OpenTelemetry wiring (optional).

Configures OTel tracing and metrics exporters when
``opentelemetry-sdk`` is installed and ``OTEL_EXPORTER_OTLP_ENDPOINT`` is
set. Otherwise it is a no-op.
"""

from __future__ import annotations

import os

from sentinel.utils.logging import get_logger

log = get_logger(__name__)


def configure_telemetry(service_name: str = "osl-agent-sentinel") -> bool:
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        log.info("telemetry.disabled", reason="no_endpoint")
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception as exc:  # noqa: BLE001
        log.warning("telemetry.import_failed", error=str(exc))
        return False

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    log.info("telemetry.enabled", endpoint=endpoint, service=service_name)
    return True
