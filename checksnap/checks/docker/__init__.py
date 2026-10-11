"""--check-docker: static rules for Dockerfiles and docker-compose files. Local only, nothing is uploaded."""
from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

from checksnap.checks.optimization import SKIP_DIRS, _is_test
from checksnap.core import Check, CheckResult, Context, CostEstimate, register

from .rules import RULES, RuleInfo  # noqa: F401
from .scan import analyze_compose, analyze_dockerfile

MAX_BYTES = 2_000_000
DOCKERFILE = re.compile(r"^(dockerfile(\..+)?|.+\.dockerfile)$", re.I)
COMPOSE = re.compile(r"^(docker-)?compose([.-].+)?\.ya?ml$", re.I)


def _root(args: argparse.Namespace) -> Path:
    v = getattr(args, "check_docker", None)
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
            if (DOCKERFILE.match(n) or COMPOSE.match(n)) and (tests or not _is_test(rel)):
                found.append((rel, p))
    return sorted(found)


@register
class DockerCheck(Check):
    name = "docker"
    flag = "--check-docker"
    summary = "Find Dockerfile and docker-compose problems: unpinned images, root user, secrets, exposed ports, bloated layers"
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
        for rel, p in files:
            try:
                if p.stat().st_size > MAX_BYTES:
                    res.notes.append(f"skipped {rel}: over {MAX_BYTES // 1_000_000} MB")
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
                if COMPOSE.match(p.name):
                    res.findings += analyze_compose(text, rel)
                else:
                    ignore = (p.parent / ".dockerignore").exists() or (p.parent / f"{p.name}.dockerignore").exists()
                    res.findings += analyze_dockerfile(text, rel, ignore)
            except OSError:
                continue
        res.findings.sort(key=lambda f: (-int(f.severity), f.evidence[0].file or "", f.evidence[0].line_start or 0, f.rule_id))
        res.stats["by_rule"] = {}
        for f in res.findings:
            res.stats["by_rule"][f.rule_id] = res.stats["by_rule"].get(f.rule_id, 0) + 1
        res.notes.append("static analysis only (no Snap layer); secret values are never printed, only variable names")
        return res
