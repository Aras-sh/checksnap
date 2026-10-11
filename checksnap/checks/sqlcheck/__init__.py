"""--check-sql: lint .sql files and migrations (tokenizer-based, comments and strings skipped). Local only, nothing is uploaded."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from checksnap.checks.optimization import SKIP_DIRS, _is_test
from checksnap.core import Check, CheckResult, Context, CostEstimate, register

from .rules import RULES, RuleInfo  # noqa: F401
from .scan import analyze, analyze_files  # noqa: F401

MAX_BYTES = 5_000_000


def _root(args: argparse.Namespace) -> Path:
    v = getattr(args, "check_sql", None)
    if not isinstance(v, (str, os.PathLike)):
        v = getattr(args, "check_all", None)
    return Path(v if isinstance(v, (str, os.PathLike)) else ".")


def collect(root: Path, tests: bool) -> list[tuple[str, Path]]:
    if root.is_file():
        return [(root.name, root)]
    found = []
    for dp, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(names):
            p = Path(dp) / n
            rel = p.relative_to(root).as_posix()
            if p.suffix.lower() == ".sql" and (tests or not _is_test(rel)):
                found.append((rel, p))
    return sorted(found)


@register
class SqlCheck(Check):
    name = "sql"
    flag = "--check-sql"
    summary = "Lint .sql files and migrations: missing WHERE, risky DDL, missing indexes, money as float, plaintext passwords"
    uses_snap = False

    def estimate(self, ctx: Context, args: argparse.Namespace) -> CostEstimate:
        return CostEstimate(notes="static analysis only; nothing is uploaded")

    def run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        return self.timed(lambda: self._run(args))

    def _run(self, args: argparse.Namespace) -> CheckResult:
        res = CheckResult(self.name)
        root = _root(args)
        if not root.exists():
            res.error = f"path not found: {root}"
            return res
        files = collect(root, bool(getattr(args, "include_tests", False)))
        res.stats["files"] = len(files)
        texts = []
        for rel, p in files:
            try:
                if p.stat().st_size > MAX_BYTES:
                    res.notes.append(f"skipped {rel}: over {MAX_BYTES // 1_000_000} MB")
                    continue
                texts.append((rel, p.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue
        res.findings = analyze_files(texts)
        res.findings.sort(key=lambda f: (-int(f.severity), f.evidence[0].file or "", f.evidence[0].line_start or 0, f.rule_id))
        res.stats["by_rule"] = {}
        for f in res.findings:
            res.stats["by_rule"][f.rule_id] = res.stats["by_rule"].get(f.rule_id, 0) + 1
        res.notes.append("static analysis only (no Snap layer); dialect-neutral heuristics, index checks only see the scanned files")
        return res
