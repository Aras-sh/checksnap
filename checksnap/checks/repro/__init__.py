"""--check-reproducibility: static ast + file checks for run-to-run reproducibility. Local only: no Snap layer,
because every signal here is a syntactic fact (a seed call exists or it does not)."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from checksnap.core import Check, CheckResult, Context, CostEstimate, register

from .analyze import MANIFESTS, LOCKS, _is_req, analyze_project
from .rules import RULES, RuleInfo  # noqa: F401  (RULES is the catalog the CLI reads)

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", ".tox", ".mypy_cache", ".pytest_cache", ".checksnap-cache", "site-packages"}
MAX_BYTES = 2_000_000
MAX_FILES = 3000


def _root(args: argparse.Namespace) -> Path:
    v = getattr(args, "check_reproducibility", None)
    if not isinstance(v, (str, os.PathLike)):
        v = getattr(args, "check_all", None)
    return Path(v if isinstance(v, (str, os.PathLike)) else ".")


def _is_test(rel: str) -> bool:
    p = Path(rel)
    return any(x in ("tests", "test") for x in p.parts[:-1]) or p.name.startswith("test_") or p.stem.endswith("_test") or p.name == "conftest.py"


def collect(root: Path) -> tuple[dict[str, str], dict[str, str], list[str]]:
    py: dict[str, str] = {}
    other: dict[str, str] = {}
    notes: list[str] = []
    if root.is_file():
        return {root.name: root.read_text(encoding="utf-8", errors="replace")}, other, notes
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(names):
            p = Path(dirpath) / n
            rel = p.relative_to(root).as_posix()
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
                if n.endswith(".py"):
                    if not _is_test(rel) and len(py) < MAX_FILES:
                        py[rel] = p.read_text(encoding="utf-8", errors="replace")
                elif n in LOCKS:
                    other[rel] = ""
                elif n in MANIFESTS or _is_req(rel):
                    other[rel] = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    if len(py) >= MAX_FILES:
        notes.append(f"only the first {MAX_FILES} Python files were checked")
    return py, other, notes


@register
class ReproCheck(Check):
    name = "reproducibility"
    flag = "--check-reproducibility"
    summary = "Find reproducibility problems: unseeded randomness, unordered data, unpinned dependencies, missing run provenance"
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
        py, other, res.notes = collect(root)
        res.stats["files"] = len(py)
        if not py:
            res.notes.append("no Python files found (tests are skipped)")
        if root.is_file():
            res.notes.append("single file: dependency/lockfile/provenance rules need a directory and were skipped")
        res.findings, more = analyze_project(py, other, project_files=not root.is_file())
        res.notes += more
        res.notes.append("local static analysis only (no Snap layer for this check)")
        res.stats["by_rule"] = {}
        for f in res.findings:
            res.stats["by_rule"][f.rule_id] = res.stats["by_rule"].get(f.rule_id, 0) + 1
        return res
