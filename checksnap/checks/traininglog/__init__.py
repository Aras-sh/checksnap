"""--check-training-log: local rules over training logs (JSONL, JSON, CSV/TSV, plain text). No Snap layer: everything is free and offline."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from checksnap.core import Check, CheckResult, Context, CostEstimate, register

from .analyze import analyze
from .parse import parse_file
from .rules import RULES, RuleInfo  # noqa: F401  (RULES is the catalog the CLI reads)

EXTS = {".jsonl", ".json", ".csv", ".tsv", ".log", ".txt", ".out"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
MAX_BYTES = 200_000_000
MAX_FILES = 500


def _root(args: argparse.Namespace) -> Path:
    v = getattr(args, "check_training_log", None)
    if not isinstance(v, (str, os.PathLike)):
        v = getattr(args, "check_all", None)
    return Path(v if isinstance(v, (str, os.PathLike)) else ".")


def collect(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    out: list[Path] = []
    for d, dirs, names in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
        out += [Path(d) / n for n in sorted(names) if Path(n).suffix.lower() in EXTS]
    return out


@register
class TrainingLogCheck(Check):
    name = "traininglog"
    flag = "--check-training-log"
    summary = "Find NaNs, spikes, plateaus, overfitting and resume duplicates in training logs"
    uses_snap = False

    def estimate(self, ctx: Context, args: argparse.Namespace) -> CostEstimate:
        return CostEstimate(notes="local analysis only; nothing is uploaded")

    def run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        return self.timed(lambda: self._run(args))

    def _run(self, args: argparse.Namespace) -> CheckResult:
        res = CheckResult(self.name)
        root = _root(args)
        if not root.exists():
            res.error = f"path not found: {root}"
            return res
        files = collect(root)
        if len(files) > MAX_FILES:
            res.notes.append(f"{len(files)} files found; only the first {MAX_FILES} were checked")
            files = files[:MAX_FILES]
        base = root if root.is_dir() else root.parent
        parsed = 0
        for p in files:
            rel = p.relative_to(base).as_posix()
            try:
                if p.stat().st_size > MAX_BYTES:
                    res.notes.append(f"skipped {rel}: over {MAX_BYTES // 1_000_000} MB")
                    continue
                recs = parse_file(p)
            except OSError as e:
                res.notes.append(f"could not read {rel}: {type(e).__name__}")
                continue
            if len(recs) < 2:
                continue
            parsed += 1
            res.findings += analyze(recs, rel)
        res.stats["files"] = len(files)
        res.stats["logs_parsed"] = parsed
        if not parsed:
            res.notes.append("no training-log records found (need >= 2 lines with numeric metrics)")
        res.findings.sort(key=lambda f: (-int(f.severity), f.evidence[0].file or "", f.evidence[0].line_start or 0, f.rule_id))
        by: dict[str, int] = {}
        for f in res.findings:
            by[f.rule_id] = by.get(f.rule_id, 0) + 1
        res.stats["by_rule"] = by
        return res
