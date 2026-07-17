"""Structured exceptions for the BBOT integration.

BBOT is an optional, external, AGPLv3-licensed tool (see NOTICE_BBOT.md).
Every failure mode here must degrade gracefully: BBOT problems must never
crash the analysis worker or produce a blockable decision by themselves.
"""

from __future__ import annotations


class BBOTError(Exception):
    """Base class for all BBOT integration errors."""


class BBOTNotAvailableError(BBOTError):
    """No usable BBOT runtime (native/WSL/Docker) could be found."""


class BBOTRuntimeError(BBOTError):
    """BBOT (or its runtime wrapper: WSL/Docker) failed to execute."""


class BBOTTimeoutError(BBOTError):
    """The BBOT process exceeded the configured timeout and was killed."""


class BBOTCancelledError(BBOTError):
    """The scan was cancelled by the user before completion."""


class BBOTValidationError(BBOTError):
    """A target, module, preset, or argument failed safety validation."""


class BBOTCapabilityError(BBOTError):
    """Capability discovery (modules/presets/output modules) failed."""


class BBOTConfigError(BBOTError):
    """Persisted BBOT settings are missing or invalid."""
