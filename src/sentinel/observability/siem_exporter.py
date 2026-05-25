"""SIEM exporter.

Pushes audit records to a downstream SIEM. Supports two transports out
of the box:

* ``stdout`` — newline-delimited JSON (NDJSON), suitable for sidecars
  that tail and forward.
* ``http`` — POST NDJSON batches to an HTTP endpoint (e.g., Splunk HEC,
  Elasticsearch, generic webhook).

Both transports include a retry loop with exponential backoff and a
bounded outbox to bound memory growth during outages.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections import deque
from dataclasses import dataclass
from typing import Deque, Protocol

import httpx

from sentinel.models.audit import AuditRecord
from sentinel.utils.logging import get_logger

log = get_logger(__name__)


class _Transport(Protocol):
    async def send(self, batch: list[str]) -> None: ...


class StdoutTransport:
    async def send(self, batch: list[str]) -> None:
        for line in batch:
            sys.stdout.write(line + "\n")
        sys.stdout.flush()


@dataclass(slots=True)
class HTTPTransportConfig:
    endpoint: str
    headers: dict[str, str]
    timeout_seconds: float = 5.0


class HTTPTransport:
    def __init__(self, config: HTTPTransportConfig) -> None:
        self._config = config
        self._client = httpx.AsyncClient(timeout=config.timeout_seconds, headers=config.headers)

    async def send(self, batch: list[str]) -> None:
        payload = "\n".join(batch).encode("utf-8")
        resp = await self._client.post(self._config.endpoint, content=payload)
        if resp.status_code >= 400:
            raise RuntimeError(f"SIEM export failed: {resp.status_code} {resp.text[:200]}")


class SIEMExporter:
    """Buffered exporter with bounded outbox and exponential-backoff retry."""

    def __init__(
        self,
        transport: _Transport | None = None,
        *,
        max_outbox: int = 10_000,
        batch_size: int = 100,
        flush_interval_seconds: float = 1.0,
    ) -> None:
        self._transport = transport or self._default_transport()
        self._outbox: Deque[str] = deque(maxlen=max_outbox)
        self._batch_size = batch_size
        self._flush_interval = flush_interval_seconds
        self._task: asyncio.Task[None] | None = None

    def _default_transport(self) -> _Transport:
        endpoint = os.getenv("SENTINEL_SIEM_HTTP_ENDPOINT")
        if endpoint:
            token = os.getenv("SENTINEL_SIEM_HTTP_TOKEN", "")
            headers = {"content-type": "application/x-ndjson"}
            if token:
                headers["authorization"] = f"Bearer {token}"
            return HTTPTransport(HTTPTransportConfig(endpoint=endpoint, headers=headers))
        return StdoutTransport()

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="siem-exporter")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self._flush()

    def enqueue(self, record: AuditRecord) -> None:
        self._outbox.append(json.dumps(record.model_dump(mode="json"), separators=(",", ":")))

    async def _run(self) -> None:
        backoff = 0.5
        while True:
            try:
                await asyncio.sleep(self._flush_interval)
                await self._flush()
                backoff = 0.5
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                log.warning("siem.flush_failed", error=str(exc), backoff=backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)

    async def _flush(self) -> None:
        while self._outbox:
            batch = [self._outbox.popleft() for _ in range(min(self._batch_size, len(self._outbox)))]
            if not batch:
                break
            await self._transport.send(batch)
