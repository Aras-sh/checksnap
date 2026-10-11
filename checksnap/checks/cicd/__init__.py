"""--check-ci: GitHub Actions and GitLab CI pipeline files, scanned line by line. Local only, nothing is uploaded."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from checksnap.checks.optimization import SKIP_DIRS
from checksnap.core import Check, CheckResult, Context, CostEstimate, register

from .rules import RULES, RuleInfo  # noqa: F401
from .scan import analyze

MAX_BYTES = 1_000_000


def _root(args: argparse.Namespace) -> Path:
    v = getattr(args, "check_ci", None)
    if not isinstance(v, (str, os.PathLike)):
        v = getattr(args, "check_all", None)
    return Path(v if isinstance(v, (str, os.PathLike)) else ".")


def collect(root: Path) -> list[tuple[str, Path]]:
    """Workflow files live in .github/workflows; GitLab's file is .gitlab-ci.yml (a file path is taken as-is)."""
    if root.is_file():
        return [(root.name, root)]
    found = []
    for dp, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(names):
            p = Path(dp) / n
            rel = p.relative_to(root).as_posix()
            if n.endswith(".gitlab-ci.yml") or (".github/workflows/" in "/" + rel and p.suffix in (".yml", ".yaml")):
                found.append((rel, p))
    return sorted(found)


@register
class CICheck(Check):
    name = "ci"
    flag = "--check-ci"
    summary = "Find CI/CD pipeline risks in GitHub Actions and GitLab CI: unpinned actions, script injection, loose permissions"
    uses_snap = False

    def estimate(self, ctx: Context, args: argparse.Namespace) -> CostEstimate:
        return CostEstimate(notes="local file scan only; nothing is uploaded")

    def run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        return self.timed(lambda: self._run(args))

    def _run(self, args: argparse.Namespace) -> CheckResult:
        res = CheckResult(self.name)
        root = _root(args)
        if not root.exists():
            res.error = f"path not found: {root}"
            return res
        files = collect(root)
        res.stats["files"] = len(files)
        for rel, p in files:
            try:
                if p.stat().st_size > MAX_BYTES:
                    res.notes.append(f"skipped {rel}: over 1 MB")
                    continue
                res.findings += analyze(p.read_text(encoding="utf-8", errors="replace"), rel)
            except OSError:
                continue
        res.findings.sort(key=lambda f: (-int(f.severity), f.evidence[0].file or "", f.evidence[0].line_start or 0, f.rule_id))
        res.stats["by_rule"] = {}
        for f in res.findings:
            res.stats["by_rule"][f.rule_id] = res.stats["by_rule"].get(f.rule_id, 0) + 1
        if not files:
            res.notes.append("no .github/workflows/*.yml or .gitlab-ci.yml found")
        res.notes.append("line-based scan, not a YAML parser: unusual formatting (anchors, includes) can be missed; secret values are never printed")
        return res
