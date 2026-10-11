from __future__ import annotations

import checksnap.snap as s


def test_spec_names_exported():
    for n in ["SnapError", "SnapAuthError", "SnapQuotaError", "SnapTooLargeError", "SnapRateLimitError", "BudgetExceeded",
              "Question", "SnapClient", "AskResult", "Window", "split_windows", "SnapEngine", "QuestionResult",
              "Calibration", "ScanResult", "FakeSnapServer", "DEFAULT_URL"]:
        assert hasattr(s, n), n
    assert issubclass(s.BudgetExceeded, s.SnapError) and issubclass(s.SnapAuthError, s.SnapError)
