"""--check-bank: a bank of ready-made questions ("monkey pointing at a shape") that Snap answers about your files.

The user picks nothing per item: the bank filters itself by category and by what kinds of files are present, asks every
relevant question in one pass over the packed files, and returns the top-ranked candidates. `--no-snap` still runs a
free regex-hint pre-screen. `--bank-list` prints the bank (as INFO findings) and needs no path or Snap.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from checksnap.core import Check, CheckResult, Context, CostEstimate, Finding, Severity, register
from checksnap.checks.optimization import snap_layer
from checksnap.checks.optimization.rules import RuleInfo

from . import engine

DEFAULT_TOP = 25
_ITEMS, _LOAD_NOTES = engine.load_items()
RULES: dict[str, RuleInfo] = {
    it["id"]: RuleInfo(it["id"], it["severity"], it["title"], f"Snap question: {it['question']} {it['why']}", it["fix"], needs_snap=True)
    for it in _ITEMS}


def _root(args: argparse.Namespace) -> Path:
    v = getattr(args, "check_bank", None)
    if not isinstance(v, (str, os.PathLike)):
        v = getattr(args, "check_all", None)
    return Path(v if isinstance(v, (str, os.PathLike)) else ".")


@register
class BankCheck(Check):
    name = "bank"
    flag = "--check-bank"
    summary = "Ask Snap a bank of ready-made architecture, reliability, security, data, docs and testing questions about your files"
    uses_snap = True

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        g = parser.add_argument_group("bank check")
        g.add_argument("--bank-categories", metavar="A,B", help="only these categories (default: all)")
        g.add_argument("--bank-applies", choices=[*engine.KINDS, "any"], default=None, help="file kind to check (default: auto from extensions)")
        g.add_argument("--bank-file", metavar="FILE.json", help="extra items, same schema as the built-in ones")
        g.add_argument("--bank-top", type=int, default=DEFAULT_TOP, help="report at most N findings (default %(default)s)")
        g.add_argument("--bank-include-absence", action="store_true",
                       help=f"also ask absence-style items (something is missing/never done); by default only when the scan covers >= {engine.MIN_ABSENCE_FILES} files")
        g.add_argument("--bank-list", action="store_true", help="list categories, counts and items instead of checking")

    # -- shared setup
    def _setup(self, args: argparse.Namespace):
        items, notes = engine.load_items(getattr(args, "bank_file", None))
        cats = {c.strip() for c in (getattr(args, "bank_categories", None) or "").split(",") if c.strip()}
        unknown = cats - {it["category"] for it in items}
        if unknown:
            notes.append(f"unknown categories ignored: {sorted(unknown)}; available: {sorted({it['category'] for it in items})}")
        return items, cats & {it["category"] for it in items} or None, notes

    def _files(self, args: argparse.Namespace):
        ap = getattr(args, "bank_applies", None)
        return engine.collect_files(_root(args), None if ap in (None, "any") else {ap}), ap

    def estimate(self, ctx: Context, args: argparse.Namespace) -> CostEstimate:
        if ctx.no_snap or getattr(args, "bank_list", False):
            return CostEstimate(notes="nothing is uploaded")
        items, cats, _ = self._setup(args)
        (files, found, _), ap = self._files(args)
        chosen = engine.select_items(items, cats, None if ap == "any" else ({ap} if ap else found))
        chosen, _ = engine.drop_absence(chosen, len(files), getattr(args, "bank_include_absence", False))
        chars = sum(len(t) + len(r) + 20 for r, t in files)
        if ctx.snap is not None and hasattr(ctx.snap, "estimate"):
            est = ctx.snap.estimate(chars, len(chosen))      # engine counts every question batch re-reading every window
            if chosen:                                       # but each file is its own window, so at least one call per file and question batch
                est.snap_calls = max(est.snap_calls, len(files) * -(-len(chosen) // getattr(ctx.snap, 'per_call', 55)))
                cache = getattr(ctx.snap, "cache", None)
                base, n_todo = engine.baseline_pending(chosen, cache.root.parent if cache is not None else ctx.cache_dir)
                if n_todo:                                   # one-time clean-code baseline; free once cached
                    est = est + ctx.snap.estimate(base, n_todo)
                    est.notes += "; includes the bundled clean-code baseline"
            return est
        windows = max(1, -(-chars // 800_000)) * max(1, -(-len(chosen) // 56)) if chars and chosen else 0
        return CostEstimate(windows, int(chars * max(1, -(-len(chosen) // 56)) / 3.0), chars, "approximate: no engine attached")

    def run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        return self.timed(lambda: self._run(ctx, args))

    def _run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        res = CheckResult(self.name)
        items, cats, res.notes = self._setup(args)
        if getattr(args, "bank_list", False):
            return self._list(res, engine.select_items(items, cats, None))
        root = _root(args)
        if not root.exists():
            res.error = f"path not found: {root}"
            return res
        (files, found, fnotes), ap = self._files(args)
        res.notes += fnotes
        chosen = engine.select_items(items, cats, None if ap == "any" else ({ap} if ap else found))
        if files:
            chosen, skipped = engine.drop_absence(chosen, len(files), getattr(args, "bank_include_absence", False))
            if skipped:
                res.notes.append(f"{skipped} absence items skipped: only {len(files)} files scanned (need {engine.MIN_ABSENCE_FILES}, or pass --bank-include-absence)")
        res.stats.update(files=len(files), items_asked=len(chosen), kinds=sorted(found))
        if not files:
            res.notes.append("no files of a known kind found (try --bank-applies)")
            return res
        top = max(1, getattr(args, "bank_top", DEFAULT_TOP) or DEFAULT_TOP)
        hints = engine.compile_hints(chosen, res.notes)
        if ctx.no_snap or ctx.snap is None:
            res.notes.append("Snap skipped: --no-snap or no engine/API key; only the free regex-hint pre-screen ran (INFO candidates, nothing was judged)")
            res.findings = engine.local_hints(files, chosen, hints)[:top]
        elif chosen:
            self._snap(ctx, files, chosen, hints, res, top)
        res.stats["by_rule"] = {}
        for f in res.findings:
            res.stats["by_rule"][f.rule_id] = res.stats["by_rule"].get(f.rule_id, 0) + 1
        return res

    def _list(self, res: CheckResult, items: list[dict]) -> CheckResult:
        counts: dict[str, int] = {}
        for it in items:
            counts[it["category"]] = counts.get(it["category"], 0) + 1
            res.findings.append(Finding("bank", it["id"], Severity.INFO, it["title"],
                                        f"[{it['category']}] severity {it['severity'].name}, applies to {','.join(it['applies_to'])}"))
        res.stats["categories"] = counts
        res.notes += [f"category {c}: {n} item(s)" for c, n in sorted(counts.items())] + [f"total: {len(items)} item(s)"]
        return res

    def _snap(self, ctx: Context, files, chosen, hints, res: CheckResult, top: int) -> None:
        from checksnap import snap as snap_mod          # lazy: only needed when Snap runs
        size = max(10_000, int(getattr(ctx.snap, "window_chars", 800_000)) - 1000)
        windows, spans = engine.pack_per_file(files, size, snap_mod)
        res.stats["snap_windows"] = len(windows)
        try:
            scan = ctx.snap.scan_windows(windows, engine.questions(snap_mod, chosen), label="bank", progress=ctx.progress)
        except snap_mod.BudgetExceeded as e:
            scan = e.partial
            res.notes.append(f"Snap budget exceeded; results are partial ({e})")
            res.error = "token budget exceeded; results are partial"
        except snap_mod.SnapError as e:
            res.notes.append(f"Snap failed: {type(e).__name__}: {e}")
            if isinstance(e, (snap_mod.SnapAuthError, snap_mod.SnapQuotaError)):
                res.error = f"Snap {type(e).__name__}: {e}"
            return
        if scan is None:
            return
        res.usage["snap_calls"] += scan.calls
        res.usage["input_tokens"] += scan.input_tokens
        cal = scan.calibration
        res.stats["calibration"] = {"decoys": cal.decoys, "false_positive_rate": cal.false_positive_rate(ctx.threshold),
                                    "canaries": cal.canaries, "canary_recall": cal.canary_recall(ctx.threshold)}
        res.stats["snap"] = {"windows": scan.windows, "calls": scan.calls, "cached_calls": scan.cached_calls, "partial": scan.partial}
        res.notes += [f"Snap: {e}" for e in scan.errors]
        flagged = sum(qr.max_score >= ctx.threshold for qr in scan.per_question.values())
        res.stats["flagged"] = flagged
        baseline = self._baseline(ctx, chosen, snap_mod, res)
        res.findings += engine.interpret(scan, chosen, hints, windows, spans, ctx, snap_mod, res.notes, top, baseline, res.stats)
        shown = len(res.findings)
        if flagged - res.stats.get("suppressed", 0) > shown:
            res.notes.append(f"{flagged - res.stats.get('suppressed', 0)} items flagged; showing the top {top} by score x severity (raise --bank-top)")
        res.notes.append(self._calibration_line(res, baseline, ctx.threshold, flagged, shown))

    def _baseline(self, ctx: Context, chosen, snap_mod, res: CheckResult) -> dict[str, float] | None:
        cache = getattr(ctx.snap, "cache", None)
        cache_dir = cache.root.parent if cache is not None else ctx.cache_dir
        try:
            base, scan = engine.baseline_scores(ctx.snap, chosen, cache_dir, snap_mod)
        except snap_mod.SnapError as e:
            res.notes.append(f"clean-code baseline unavailable, no demotion applied: {type(e).__name__}: {e}")
            return None
        if scan is not None:
            res.usage["snap_calls"] += scan.calls
            res.usage["input_tokens"] += scan.input_tokens
        return base or None

    @staticmethod
    def _calibration_line(res: CheckResult, baseline, thr: float, flagged: int, shown: int) -> str:
        cal = res.stats["calibration"]
        pct = lambda v: "n/a" if v is None else f"{v:.0%}"  # noqa: E731
        line = f"calibration: decoy false-positive rate {pct(cal['false_positive_rate'])} ({cal['decoys']} decoys), canary recall {pct(cal['canary_recall'])}"
        if baseline:
            hot = sum(v >= thr for v in baseline.values())
            res.stats["clean_code_fire_rate"] = round(hot / len(baseline), 3)
            line += f"; clean-code baseline: {hot}/{len(baseline)} items score >= {thr:g} on typical clean Python (real false-positive rate of this bank)"
        return line + f"; {flagged} flagged, {res.stats.get('suppressed', 0)} suppressed, {shown} shown"
