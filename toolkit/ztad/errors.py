from __future__ import annotations


class ZTADError(Exception):
    """Base exception for deterministic toolkit failures."""


class ConfigurationError(ZTADError):
    """Raised when policy, schema, or configuration is invalid."""


class RepositoryError(ZTADError):
    """Raised when repository facts cannot be obtained safely."""


class PolicyViolation(ZTADError):
    """Raised when an operation violates an enforced policy."""
