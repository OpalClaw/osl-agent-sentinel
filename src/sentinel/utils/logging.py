"""Structured logging setup.

We use ``structlog`` with JSON output by default so that every log line is
SIEM-ingestible. Console output is available for local development.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

import structlog


def configure_logging(level: str | None = None, fmt: str | None = None) -> None:
    """Configure structlog + stdlib logging.

    Idempotent: safe to call from CLI entry points and from tests.
    """
    log_level = (level or os.getenv("SENTINEL_LOG_LEVEL", "INFO")).upper()
    log_format = (fmt or os.getenv("SENTINEL_LOG_FORMAT", "json")).lower()

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level, logging.INFO),
    )

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    processors.append(
        structlog.processors.JSONRenderer()
        if log_format == "json"
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level, logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a configured structlog logger."""
    return structlog.get_logger(name)
