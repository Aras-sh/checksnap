"""--snap-verify: ask Snap one yes/no question per local finding on a ~2 KB excerpt; lower the severity of unlikely ones.

Excerpts are packed ### EXCERPT n into ONE window per call (<= engine.per_call questions), so a batch costs one call.
Findings are never deleted. Secret findings are not uploaded (their excerpt would contain the secret).
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path

from .core import CheckResult, Context, CostEstimate, Finding, Severity, severity_counts

RADIUS, MAX_CHARS, MAX_LINE = 25, 2048, 200
UNLIKELY = 0.5
NO_UPLOAD = {"SEC-006", "EXT-BANDIT-B105", "EXT-BANDIT-B106", "EXT-BANDIT-B107"}   # hard-coded secret: the excerpt would ship the secret itself
NOTE = "snap judged unlikely"


def add_flag(parser: argparse.ArgumentParser) -> None:
    """Both checks call this; the second call is a no-op."""
    if "--snap-verify" not in parser._option_string_actions:
        parser.add_argument("--snap-verify", action="store_true",
                            help="ask Snap whether each local finding is real; unlikely ones drop one severity level (never deleted)")


def wanted(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "snap_verify", False))


def excerpt(base: Path, f: Finding) -> str | None:
    ev = f.evidence[0] if f.evidence else None
    if not ev or not ev.file:
        return None
    try:
        lines = (base / ev.file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    c, r = (ev.line_start or 1) - 1, RADIUS
    while True:
        lo, hi = max(0, c - r), min(len(lines), c + r + 1)
        out = "\n".join(f"{i + 1}{'>' if i == c else ':'} {lines[i][:MAX_LINE]}" for i in range(lo, hi))
        if len(out) <= MAX_CHARS or r <= 1:
            return f"{ev.file}\n{out[:MAX_CHARS]}"
        r -= 3


def candidates(base: Path, findings: list[Finding]) -> list[tuple[Finding, str]]:
    return [(f, x) for f in findings
            if f.source != "snap" and f.severity > Severity.INFO and f.rule_id not in NO_UPLOAD and not f.rule_id.startswith("EXT-DETECT-SECRETS") and (x := excerpt(base, f))]


def _question(n: int, f: Finding):
    from .snap import Question
    return Question(f"v{n}", f"Look only at '### EXCERPT {n}'. Is this a real \"{f.title}\" problem in this code, not a test, example or safe usage? "
                    "Answer true only if clearly real.", f"EXCERPT {n} is clearly a real {f.title} problem",
                    f"EXCERPT {n} is a test, example, safe usage or not clearly a problem")


def estimate(ctx: Context, base: Path, findings: list[Finding]) -> CostEstimate:
    """Free: no network. One call per batch of per_call excerpts."""
    cand = candidates(base, findings)
    if not cand:
        return CostEstimate(notes="snap-verify: no findings to verify")
    chars = sum(len(x) + 20 for _, x in cand)
    per = getattr(ctx.snap, "per_call", 55)
    cpt = getattr(getattr(ctx.snap, "cpt", None), "value", 3.0)
    return CostEstimate(math.ceil(len(cand) / per), math.ceil(chars / cpt), chars,
                        f"snap-verify: {len(cand)} finding excerpt(s) of ~2 KB, {per} per call")


def apply(ctx: Context, base: Path, res: CheckResult) -> None:
    """Judge res.findings in place. Never raises for Snap problems: they become notes / res.error."""
    from . import snap as snap_mod
    from .snap.windows import Window
    if ctx.no_snap or ctx.snap is None:
        res.notes.append("snap-verify skipped: needs a Snap engine (no --no-snap, API key, confirmed upload)")
        return
    cand = candidates(base, res.findings)
    before = severity_counts(res.findings)
    st = res.stats["verify"] = {"checked": 0, "lowered": 0, "candidates": len(cand), "before": before, "after": before}
    per = getattr(ctx.snap, "per_call", 55)
    for i in range(0, len(cand), per):
        batch = cand[i:i + per]
        text = "".join(f"### EXCERPT {n}\n{x}\n\n" for n, (_, x) in enumerate(batch))
        qs = [_question(n, f) for n, (f, _) in enumerate(batch)]
        try:
            scan = ctx.snap.scan_windows([Window(0, len(text), text)], qs, label="verify", progress=ctx.progress)
        except snap_mod.BudgetExceeded as e:
            res.notes.append(f"snap-verify: budget exceeded, remaining findings unjudged ({e})")
            res.error = "token budget exceeded; results are partial"
            break
        except snap_mod.SnapError as e:
            res.notes.append(f"snap-verify failed: {type(e).__name__}: {e}")
            if isinstance(e, (snap_mod.SnapAuthError, snap_mod.SnapQuotaError)):
                res.error = f"Snap {type(e).__name__}: {e}"
            break
        res.usage["snap_calls"] += scan.calls
        res.usage["input_tokens"] += scan.input_tokens
        res.notes += [f"snap-verify: {e}" for e in scan.errors]
        recall = scan.calibration.canary_recall(ctx.threshold)
        if recall is not None and recall < 1:
            res.notes.append("snap-verify: canary missed in a batch, scores not trusted; those findings are unchanged")
            continue
        for n, (f, _) in enumerate(batch):
            q = scan.per_question.get(f"v{n}")
            if not q or not q.window_scores:
                continue
            st["checked"] += 1
            f.score = q.max_score
            if q.max_score < UNLIKELY:
                f.severity = Severity(max(0, f.severity - 1))
                f.detail = f"{f.detail} [{NOTE}: score {q.max_score:.2f}]".strip()
                st["lowered"] += 1
    st["after"] = severity_counts(res.findings)
    res.findings.sort(key=lambda f: (-int(f.severity), f.evidence[0].file or "" if f.evidence else "",
                                     f.evidence[0].line_start or 0 if f.evidence else 0, f.rule_id))
