"""Typed exception hierarchy.

We use a small, intention-revealing exception tree so callers can distinguish
recoverable failures from policy violations and configuration errors.
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base class for all sentinel errors."""


class ConfigurationError(SentinelError):
    """Configuration is missing or invalid."""


class PolicyError(SentinelError):
    """The policy bundle is invalid or could not be loaded."""


class PolicySignatureError(PolicyError):
    """Policy bundle signature could not be verified."""


class IdentityError(SentinelError):
    """The agent identity is unknown, revoked, or malformed."""


class PipelineError(SentinelError):
    """The decision pipeline could not complete normally."""


class DependencyUnavailableError(PipelineError):
    """A required external dependency (policy source, DB, etc.) is unreachable."""
