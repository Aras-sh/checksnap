"""Shared types for checksnap: findings, the Check base class, the registry and the run context.

This file is the contract between the CLI, the Snap engine and every check. Change it only with
a note in docs/SPEC.md, because five people build against it in parallel.
"""
from __future__ import annotations

import abc
import argparse
import dataclasses
import enum
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: "str | int | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]


@dataclass
class Evidence:
    """Where a finding comes from. `file` is relative to the scanned root when possible."""
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    snippet: str = ""
    extra: dict[str, Any] = field(default_factory=dict)      # e.g. {"window": [start_char, end_char]}


@dataclass
class Finding:
    check: str                      # "dataset" | "optimization" | ...
    rule_id: str                    # stable id, e.g. "DS-CONTAM-001", "OPT-ML-004"
    severity: Severity
    title: str
    detail: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    score: float | None = None      # model probability or similarity in [0, 1], when there is one
    source: str = "local"           # "snap" | "static" | "hash" | "local"
    fix_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class CostEstimate:
    """What a check would spend / upload. Shown to the user BEFORE any Snap call."""
    snap_calls: int = 0
    input_tokens: int = 0           # lower bound; the engine's calibration may correct it
    uploads_bytes: int = 0          # bytes of the user's data that would leave the machine
    notes: str = ""

    def __add__(self, other: "CostEstimate") -> "CostEstimate":
        return CostEstimate(self.snap_calls + other.snap_calls, self.input_tokens + other.input_tokens,
                            self.uploads_bytes + other.uploads_bytes, "; ".join(n for n in (self.notes, other.notes) if n))


@dataclass
class CheckResult:
    check: str
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)      # free-form numbers for the report
    notes: list[str] = field(default_factory=list)           # human-readable caveats ("Snap skipped: --no-snap")
    usage: dict[str, int] = field(default_factory=lambda: {"snap_calls": 0, "input_tokens": 0})
    duration_s: float = 0.0
    error: str | None = None        # set when the check could not run at all

    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.check, "findings": [f.to_dict() for f in self.findings], "stats": self.stats,
                "notes": self.notes, "usage": self.usage, "duration_s": round(self.duration_s, 2), "error": self.error}


@dataclass
class Context:
    """Everything a check needs from the outside world. Built by the CLI, faked in tests."""
    snap: Any | None = None                     # checksnap.snap.SnapEngine, or None when --no-snap
    no_snap: bool = False
    budget_tokens: int | None = None            # hard ceiling on Snap input tokens for the whole run
    cache_dir: Path = Path(".checksnap-cache")
    workers: int = 4
    threshold: float = 0.5                      # Snap probability above which an item counts as flagged
    quiet: bool = False
    progress: Callable[[str], None] = lambda msg: None
    extra: dict[str, Any] = field(default_factory=dict)


class Check(abc.ABC):
    """One thing checksnap can check. Subclasses are registered with @register."""

    name: str = ""                  # "dataset"
    flag: str = ""                  # "--check-dataset"
    summary: str = ""               # one line for --list-checks
    uses_snap: bool = True
    in_check_all: bool = True       # False = hidden from --check-all, still available by its own flag

    def snap_wanted(self, args: argparse.Namespace) -> bool:
        """Whether this run needs Snap at all (a check may only use it behind an opt-in flag)."""
        return self.uses_snap

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add this check's own options (all must be prefixed or clearly scoped, e.g. --benchmark)."""

    @abc.abstractmethod
    def estimate(self, ctx: Context, args: argparse.Namespace) -> CostEstimate:
        """No network, no spending. Must be cheap and safe to call before the privacy prompt."""

    @abc.abstractmethod
    def run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        """Do the work. Never raise for expected problems: put them in result.error / result.notes."""

    # helper for subclasses
    def timed(self, fn: Callable[[], CheckResult]) -> CheckResult:
        t = time.time()
        res = fn()
        res.duration_s = time.time() - t
        return res


REGISTRY: dict[str, Check] = {}


def register(cls: type[Check]) -> type[Check]:
    """Class decorator: instantiate and register a Check under its name."""
    inst = cls()
    if not inst.name or not inst.flag.startswith("--"):
        raise ValueError(f"{cls.__name__} needs name and flag")
    REGISTRY[inst.name] = inst
    return cls


def all_checks() -> list[Check]:
    from . import checks  # noqa: F401  (importing registers the built-in checks)
    return [REGISTRY[k] for k in sorted(REGISTRY)]


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    out = {s.name: 0 for s in Severity}
    for f in findings:
        out[f.severity.name] += 1
    return out


CANARY_MISSED = "Snap did not read the text (canary missed); Snap findings are not valid"


def invalidate_on_missed_canary(res: CheckResult) -> None:
    """A planted canary sentence that Snap does not find means it never read the window: drop its findings, keep local
    ones, and set res.error so the CLI exits 3 (docs/REDESIGN.md section 3)."""
    rec = (res.stats.get("calibration") or {}).get("canary_recall")
    if rec is None or rec >= 1.0:
        return
    dropped = sum(f.source == "snap" for f in res.findings)
    res.findings = [f for f in res.findings if f.source != "snap"]
    res.error = res.error or CANARY_MISSED
    res.notes.append(f"{CANARY_MISSED} (canary recall {rec:.0%}; {dropped} Snap finding(s) dropped, local findings kept)")
