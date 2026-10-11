"""Exception types for the Snap engine. The CLI maps these to exit codes, so keep the hierarchy flat."""
from __future__ import annotations

from typing import Any


class SnapError(Exception):
    """Base class: anything that went wrong talking to Snap."""


class SnapAuthError(SnapError):
    """401/403 (or no key at all): fail fast, retrying cannot help."""


class SnapQuotaError(SnapError):
    """402: no credits left. Fail fast."""


class SnapTooLargeError(SnapError):
    """400/413/422: the state is too big for one call. The engine halves the window and retries."""


class SnapRateLimitError(SnapError):
    """429/503 that persisted after all retries."""


class BudgetExceeded(SnapError):
    """The token budget would be crossed by the next call. `.partial` is the ScanResult gathered so far."""

    def __init__(self, message: str, partial: Any = None):
        super().__init__(message)
        self.partial = partial
