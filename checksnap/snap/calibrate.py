"""Measured quality of one run (decoys, canaries) and the learned chars-per-token ratio."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CHARS_PER_TOKEN = 3.3   # optimistic: the lower-bound ratio, and the global fallback
# Conservative seeds (chars/token) that never under-estimate. Real API probe (2026-10-11): Python state ~3.5 chars/token,
# question text ~3.2 (the service bills both). The old 1.3 seed came from a run where question tokens were mistaken for state.
SEED_CHARS_PER_TOKEN = {"code": 2.5, "json": 1.8, "prose": 3.0}
QUESTION_CHARS_PER_TOKEN = 3.0  # conservative for question instructions + criteria (measured ~3.2); never calibrated from state
QUESTION_ENVELOPE_CHARS = 30    # per question: id, type and criteria keys in the request JSON
CALL_OVERHEAD_TOKENS = 50       # fixed cost of any call (measured ~50)
CALIBRATION_VERSION = 2         # v1 files folded question tokens into the state ratio; they are ignored
MARGIN = 0.9                    # calibrated upper bound uses 90% of the measured ratio
MIN_SAMPLE_TOKENS = 1000
_EXT = {".py": "code", ".js": "code", ".ts": "code", ".tsx": "code", ".jsx": "code", ".go": "code", ".rs": "code",
        ".java": "code", ".c": "code", ".h": "code", ".cpp": "code", ".rb": "code", ".php": "code", ".sh": "code",
        ".sql": "code", ".yml": "code", ".yaml": "code", ".toml": "code", ".html": "code", ".css": "code",
        ".json": "json", ".jsonl": "json", ".ndjson": "json",
        ".md": "prose", ".txt": "prose", ".rst": "prose"}


def question_chars(q) -> int:
    """Characters of one question as billed: instructions + criteria + a small envelope."""
    return len(q.instructions) + len(q.true) + len(q.false) + QUESTION_ENVELOPE_CHARS


def detect_kind(text: str = "", name: str = "") -> str:
    """'code' | 'json' | 'prose': by file extension when known, else by character mix of the first 20k chars."""
    kind = _EXT.get(os.path.splitext(name)[1].lower())
    if kind or not text:
        return kind or "code"       # unknown content is assumed to be the expensive kind
    s = text[:20_000]
    if s.lstrip()[:1] in ("{", "[") and s.count('"') > len(s) * 0.05:
        return "json"
    symbols = sum(not (c.isalnum() or c.isspace()) for c in s)
    return "code" if symbols > 0.15 * len(s) else "prose"
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
        self.kinds: dict[str, list[int]] = {}       # kind -> [chars, tokens]; absent in files written by older versions
        if self.path:
            try:
                d = json.loads(self.path.read_text())
                if d.get("version") != CALIBRATION_VERSION:
                    raise ValueError("stale calibration format")
                self.chars, self.tokens = int(d["chars"]), int(d["tokens"])
                self.kinds = {k: [int(v[0]), int(v[1])] for k, v in (d.get("kinds") or {}).items()}
            except (OSError, ValueError, KeyError, TypeError, IndexError):
                pass

    @property
    def value(self) -> float:
        # ignore tiny samples: a 100-char probe says nothing about 800K-char windows
        if self.tokens < 1000 or self.chars <= 0:
            return DEFAULT_CHARS_PER_TOKEN
        return max(0.5, self.chars / self.tokens)

    def measured(self, kind: str) -> float | None:
        c, t = self.kinds.get(kind, (0, 0))
        return max(0.5, c / t) if t >= MIN_SAMPLE_TOKENS and c > 0 else None

    def bounds(self, kind: str) -> tuple[float, float]:
        """(optimistic, conservative) chars/token. Conservative is the one budgets must use."""
        m = self.measured(kind)
        if m is not None:
            return m, m * MARGIN
        return DEFAULT_CHARS_PER_TOKEN, SEED_CHARS_PER_TOKEN.get(kind, SEED_CHARS_PER_TOKEN["code"])

    def add(self, chars: int, tokens: int, kind: str | None = None) -> None:
        if tokens > 0 and chars > 0:
            self.chars += chars
            self.tokens += tokens
            if kind:
                k = self.kinds.setdefault(kind, [0, 0])
                k[0] += chars
                k[1] += tokens

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
            with os.fdopen(fd, "w") as f:
                json.dump({"chars": self.chars, "tokens": self.tokens, "chars_per_token": self.value, "kinds": self.kinds,
                           "version": CALIBRATION_VERSION}, f)
            os.replace(tmp, self.path)
        except OSError:
            pass
