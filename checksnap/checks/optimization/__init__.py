"""--check-optimization: static `ast` rules (Python) plus Snap questions for cross-file inefficiencies."""
from __future__ import annotations

import argparse
import fnmatch
import os
from pathlib import Path

from checksnap.core import Check, CheckResult, Context, CostEstimate, Finding, Severity, register

from . import snap_layer, static
from .rules import STATIC_RULES, RuleInfo

RULES: dict[str, RuleInfo] = {**STATIC_RULES, **snap_layer.SNAP_RULE_INFO}

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", ".tox", ".mypy_cache", ".pytest_cache", ".checksnap-cache"}
SNAP_EXTS = {".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp"}
MAX_STATIC_BYTES = 2_000_000      # ast on a multi-MB generated file is slow and never useful
DEFAULT_MAX_FILES = 2000


def _is_test(rel: str) -> bool:
    p = Path(rel)
    return (any(part in ("tests", "test") for part in p.parts[:-1]) or p.name.startswith("test_")
            or p.stem.endswith("_test") or p.name == "conftest.py")


def _matches(rel: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(Path(rel).name, g) for g in globs)


def _root(args: argparse.Namespace) -> Path:
    v = getattr(args, "check_optimization", None)
    if not isinstance(v, (str, os.PathLike)):
        v = getattr(args, "check_all", None)
    return Path(v if isinstance(v, (str, os.PathLike)) else ".")


def collect(args: argparse.Namespace) -> tuple[Path, list[tuple[str, Path]], list[str]]:
    """Source files under the target as (relpath, path), sorted, filtered by --include/--exclude/tests/--max-files."""
    root = _root(args)
    inc, exc = list(getattr(args, "include", None) or []), list(getattr(args, "exclude", None) or [])
    tests = bool(getattr(args, "include_tests", False))
    cap = getattr(args, "max_files", None) or DEFAULT_MAX_FILES
    notes: list[str] = []
    if root.is_file():
        return root.parent, [(root.name, root)], notes
    found: list[tuple[str, Path]] = []
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(names):
            p = Path(dirpath) / n
            rel = p.relative_to(root).as_posix()
            if p.suffix not in SNAP_EXTS or (inc and not _matches(rel, inc)) or _matches(rel, exc) or (not tests and _is_test(rel)):
                continue
            found.append((rel, p))
    found.sort()
    if len(found) > cap:
        notes.append(f"{len(found)} source files found; only the first {cap} (by path) were checked (raise --max-files)")
        found = found[:cap]
    return root, found, notes


def _read(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


@register
class OptimizationCheck(Check):
    name = "optimization"
    flag = "--check-optimization"
    summary = "Find performance problems in code: static Python/PyTorch rules plus Snap for cross-file patterns"
    uses_snap = True

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        g = parser.add_argument_group("optimization check")
        g.add_argument("--profile", choices=["auto", "ml", "general"], default="auto", help="ML rules: auto = only files importing torch")
        g.add_argument("--include", action="append", metavar="GLOB", help="only files matching GLOB (repeatable)")
        g.add_argument("--exclude", action="append", metavar="GLOB", help="skip files matching GLOB (repeatable)")
        g.add_argument("--include-tests", action="store_true", help="also check test files (skipped by default)")
        g.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help="cap on files checked (default %(default)s)")
        g.add_argument("--static-only", action="store_true", help="skip the Snap layer")
        g.add_argument("--snap-only", action="store_true", help="skip the static layer")

    # -- snap helpers
    def _window_size(self, ctx: Context) -> int:
        return max(10_000, int(getattr(ctx.snap, "window_chars", 800_000)) - 1000)

    def _snap_wanted(self, ctx: Context, args: argparse.Namespace) -> bool:
        return not getattr(args, "static_only", False) and not ctx.no_snap

    def estimate(self, ctx: Context, args: argparse.Namespace) -> CostEstimate:
        if not self._snap_wanted(ctx, args):
            return CostEstimate(notes="static analysis only; nothing is uploaded")
        _, files, _ = collect(args)
        chars = sum(len(t) + len(r) + 20 for r, p in files if (t := _read(p)))
        if ctx.snap is not None and hasattr(ctx.snap, "estimate"):
            est = ctx.snap.estimate(chars, len(snap_layer.SNAP_RULES))
            est.uploads_bytes = chars
            return est
        windows = max(1, -(-chars // 800_000)) if chars else 0
        return CostEstimate(windows, int(chars / 3.0), chars, "approximate: no engine attached")

    def run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        return self.timed(lambda: self._run(ctx, args))

    def _run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        res = CheckResult(self.name)
        root = _root(args)
        if not root.exists():
            res.error = f"path not found: {root}"
            return res
        root, files, notes = collect(args)
        res.notes += notes
        res.stats["files"] = len(files)
        if not files:
            res.notes.append("no source files found (check --include/--exclude, tests are skipped without --include-tests)")
        texts: dict[str, str] = {}
        for rel, p in files:
            t = _read(p)
            if t is not None:
                texts[rel] = t
        static_by_file: dict[str, list[Finding]] = {}
        if not getattr(args, "snap_only", False):
            profile = getattr(args, "profile", "auto") or "auto"
            skipped = 0
            for rel, t in texts.items():
                if not rel.endswith(".py"):
                    continue
                if len(t) > MAX_STATIC_BYTES:
                    skipped += 1
                    continue
                try:
                    fs = static.analyze(t, rel, profile)
                except (SyntaxError, ValueError, RecursionError) as e:
                    res.notes.append(f"static: could not parse {rel}: {type(e).__name__}")
                    continue
                static_by_file[rel] = fs
                res.findings += fs
            if skipped:
                res.notes.append(f"static: {skipped} file(s) over {MAX_STATIC_BYTES // 1_000_000} MB skipped")
            res.stats["static_findings"] = len(res.findings)
            if any(not r.endswith(".py") for r in texts):
                res.notes.append("non-Python files are covered by the Snap layer only")
        if getattr(args, "static_only", False):
            res.notes.append("Snap layer skipped: --static-only")
        elif ctx.no_snap or ctx.snap is None:
            res.notes.append("Snap layer skipped: --no-snap or no engine/API key available; only static rules ran")
        elif texts:
            self._snap(ctx, texts, static_by_file, res)
        res.findings.sort(key=lambda f: (-int(f.severity), f.evidence[0].file or "" if f.evidence else "", f.evidence[0].line_start or 0 if f.evidence else 0, f.rule_id))
        res.stats["by_rule"] = {}
        for f in res.findings:
            res.stats["by_rule"][f.rule_id] = res.stats["by_rule"].get(f.rule_id, 0) + 1
        return res

    def _snap(self, ctx: Context, texts: dict[str, str], static_by_file: dict[str, list[Finding]], res: CheckResult) -> None:
        from checksnap import snap as snap_mod          # lazy: the engine is only needed when Snap runs

        windows, spans = snap_layer.pack(sorted(texts.items()), self._window_size(ctx), snap_mod)
        qs = snap_layer.questions(snap_mod)
        res.stats["snap_windows"] = len(windows)
        try:
            scan = ctx.snap.scan_windows(windows, qs, label="optimization", progress=ctx.progress)
        except snap_mod.BudgetExceeded as e:
            scan = e.partial
            res.notes.append(f"Snap budget exceeded; results are partial ({e})")
            res.error = "token budget exceeded; results are partial"      # spec: budget/auth/quota => exit 3
        except snap_mod.SnapError as e:
            res.notes.append(f"Snap layer failed: {type(e).__name__}: {e}")
            if isinstance(e, (snap_mod.SnapAuthError, snap_mod.SnapQuotaError)):
                res.error = f"Snap {type(e).__name__}: {e}"
            return
        if scan is None:
            return
        res.usage["snap_calls"] += scan.calls
        res.usage["input_tokens"] += scan.input_tokens
        cal = scan.calibration
        res.stats["snap"] = {"windows": scan.windows, "calls": scan.calls, "cached_calls": scan.cached_calls, "partial": scan.partial,
                             "false_positive_rate": cal.false_positive_rate(ctx.threshold), "canary_recall": cal.canary_recall(ctx.threshold),
                             "decoys": cal.decoys, "canaries": cal.canaries}
        res.stats["calibration"] = {k: res.stats["snap"][k] for k in ("decoys", "false_positive_rate", "canaries", "canary_recall")}   # shown in the report summary
        res.notes += [f"Snap: {e}" for e in scan.errors]
        res.findings += snap_layer.interpret(scan, windows, spans, ctx, snap_mod, static_by_file, res.notes)
