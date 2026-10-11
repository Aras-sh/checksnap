"""Measured quality of one run (decoys, canaries) and the learned chars-per-token ratio."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CHARS_PER_TOKEN = 3.3
CANARY_THRESHOLD = 0.5      # canaries_found counts canary scores at or above this


@dataclass
class Calibration:
    """Decoys are always-false questions, canaries always-true; together they measure THIS run's error rates."""
    decoys: int = 0
    decoy_scores: list[float] = field(default_factory=list)
    canaries: int = 0
    canaries_found: int = 0
    canary_scores: list[float] = field(default_factory=list)

    def false_positive_rate(self, threshold: float) -> float | None:
        if not self.decoy_scores:
            return None
        return sum(s >= threshold for s in self.decoy_scores) / len(self.decoy_scores)

    def canary_recall(self, threshold: float) -> float | None:
        if self.canary_scores:
            return sum(s >= threshold for s in self.canary_scores) / len(self.canary_scores)
        if self.canaries:
            return self.canaries_found / self.canaries
        return None


class CharsPerToken:
    """Running chars/token ratio from real calls, persisted in cache_dir/calibration.json."""

    def __init__(self, cache_dir: Path | None):
        self.path = Path(cache_dir) / "calibration.json" if cache_dir else None
        self.chars = 0
        self.tokens = 0
        if self.path:
            try:
                d = json.loads(self.path.read_text())
                self.chars, self.tokens = int(d["chars"]), int(d["tokens"])
            except (OSError, ValueError, KeyError, TypeError):
                pass

    @property
    def value(self) -> float:
        # ignore tiny samples: a 100-char probe says nothing about 800K-char windows
        if self.tokens < 1000 or self.chars <= 0:
            return DEFAULT_CHARS_PER_TOKEN
        return max(0.5, self.chars / self.tokens)

    def add(self, chars: int, tokens: int) -> None:
        if tokens > 0 and chars > 0:
            self.chars += chars
            self.tokens += tokens

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
            with os.fdopen(fd, "w") as f:
                json.dump({"chars": self.chars, "tokens": self.tokens, "chars_per_token": self.value}, f)
            os.replace(tmp, self.path)
        except OSError:
            pass
