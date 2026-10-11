"""--check-security: static Python (ast + regex) security rules. Local only, nothing is uploaded."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from checksnap.checks.optimization import SKIP_DIRS, _is_test
from checksnap import adapters
from checksnap import verify
from checksnap.core import Check, CheckResult, Context, CostEstimate, register

from .rules import RULES, RuleInfo  # noqa: F401
from .scan import analyze

TEXT_EXTS = {".py", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".sh", ".js", ".ts"}   # non-.py files get the token regex only
MAX_BYTES = 2_000_000


def _root(args: argparse.Namespace) -> Path:
    v = getattr(args, "check_security", None)
    if not isinstance(v, (str, os.PathLike)):
        v = getattr(args, "check_all", None)
    return Path(v if isinstance(v, (str, os.PathLike)) else ".")


def _base(args: argparse.Namespace) -> Path:
    r = _root(args)
    return r.parent if r.is_file() else r


def collect(root: Path, tests: bool) -> list[tuple[str, Path]]:
    if root.is_file():
        return [(root.name, root)]
    found = []
    for dp, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(names):
            p = Path(dp) / n
            rel = p.relative_to(root).as_posix()
            if p.suffix in TEXT_EXTS and (tests or not _is_test(rel)):
                found.append((rel, p))
    return sorted(found)


@register
class SecurityCheck(Check):
    name = "security"
    flag = "--check-security"
    summary = "Find security problems in code: unsafe deserialization, injection, hard-coded secrets, weak crypto"
    uses_snap = True        # only used by --snap-verify; without it nothing is uploaded

    def snap_wanted(self, args) -> bool:
        return bool(getattr(args, "snap_verify", False))

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        adapters.add_option(parser)
        verify.add_flag(parser)

    def estimate(self, ctx: Context, args: argparse.Namespace) -> CostEstimate:
        if not verify.wanted(args):
            return CostEstimate(notes="static analysis only; nothing is uploaded")
        return verify.estimate(ctx, _base(args), self._run(args).findings)

    def run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        def go() -> CheckResult:
            res = self._run(args)
            if verify.wanted(args) and not res.error:
                verify.apply(ctx, _base(args), res)
            return res
        return self.timed(go)

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
                res.findings += analyze(text, rel)
            except OSError:
                continue
            except (SyntaxError, ValueError, RecursionError) as e:
                res.notes.append(f"could not parse {rel}: {type(e).__name__}")
        if getattr(args, "with_adapters", False):
            tests = bool(getattr(args, "include_tests", False))
            extra, notes = adapters.run(self.name, root, res.findings, lambda r: not (set(Path(r).parts) & SKIP_DIRS) and (tests or not _is_test(r)))
            res.findings += extra
            res.notes += notes
        res.findings.sort(key=lambda f: (-int(f.severity), f.evidence[0].file or "", f.evidence[0].line_start or 0, f.rule_id))
        res.stats["by_rule"] = {}
        for f in res.findings:
            res.stats["by_rule"][f.rule_id] = res.stats["by_rule"].get(f.rule_id, 0) + 1
        res.notes.append("static analysis only (no Snap layer unless --snap-verify); secrets are masked to 4 characters + length")
        return res
