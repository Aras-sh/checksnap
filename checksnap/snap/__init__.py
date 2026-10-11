"""Snap engine. Public names are listed in docs/SPEC.md section 4."""
from __future__ import annotations

from .cache import DiskCache
from .calibrate import Calibration
from .client import DEFAULT_URL, AskResult, Question, SnapClient
from .engine import QuestionResult, ScanResult, SnapEngine
from .errors import (BudgetExceeded, SnapAuthError, SnapError, SnapQuotaError, SnapRateLimitError,
                     SnapTooLargeError)
from .fake_server import FakeSnapServer
from .localize import bisect_hit
from .windows import Window, split_windows

__all__ = ["AskResult", "BudgetExceeded", "Calibration", "DEFAULT_URL", "DiskCache", "FakeSnapServer", "Question",
           "QuestionResult", "ScanResult", "SnapAuthError", "SnapClient", "SnapEngine", "SnapError",
           "SnapQuotaError", "SnapRateLimitError", "SnapTooLargeError", "Window", "bisect_hit", "split_windows"]
