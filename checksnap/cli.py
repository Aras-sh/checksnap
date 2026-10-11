"""Command line entry point. Wires registered checks, the privacy gate, the Snap engine and the reports together.

Exit codes: 0 ok, 1 findings >= --fail-on, 2 usage error, 3 a check failed / budget / auth / quota.
"""
from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .config import ConfigError, apply_defaults, load_config
from .core import Check, CheckResult, Context, CostEstimate, Severity, all_checks
from .privacy import confirm_upload, estimate_table, load_api_key
from .report import FORMATS, render

FAIL_ON = ("none", "low", "medium", "high")


def build_parser(checks: Sequence[Check]) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="checksnap", description="Check datasets and code with SubQ Snap plus local analysis.")
    for c in checks:
        p.add_argument(c.flag, nargs="?", const=".", default=None, metavar="PATH", help=c.summary)
    p.add_argument("--check-all", nargs="?", const=".", default=None, metavar="PATH", help="run every check on PATH")
    p.add_argument("--list-checks", action="store_true", help="list available checks and exit")
    p.add_argument("--explain", metavar="RULE_ID", help="explain a rule and exit")
    p.add_argument("--format", choices=FORMATS, default="text")
    p.add_argument("-o", "--out", metavar="FILE", help="write the report to FILE instead of stdout")
    p.add_argument("--fail-on", choices=FAIL_ON, default="high", help="lowest severity that gives exit code 1")
    p.add_argument("--no-snap", action="store_true", help="local analysis only")
    p.add_argument("--yes", action="store_true", help="skip the upload confirmation")
    p.add_argument("--dry-run", action="store_true", help="show estimate and upload size, spend nothing")
    p.add_argument("--budget-tokens", type=int, default=5_000_000)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--cache-dir", default=".checksnap-cache")
    p.add_argument("--config", metavar="FILE", help="TOML file (default ./.checksnap.toml); flags override it")
    p.add_argument("--version", action="version", version=f"checksnap {__version__}")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-q", "--quiet", action="store_true")
    g.add_argument("-v", "--verbose", action="store_true")
    for c in checks:
        c.add_arguments(p)
    return p


def _rule_catalog(checks: Sequence[Check]) -> dict[str, object]:
    rules: dict[str, object] = {}
    for c in checks:
        try:
            rules.update(getattr(importlib.import_module(type(c).__module__), "RULES", {}))
        except Exception:  # noqa: BLE001  (a broken check package must not break --explain for the others)
            continue
    return rules


def _explain(rule_id: str, checks: Sequence[Check]) -> int:
    r = _rule_catalog(checks).get(rule_id.upper())
    if r is None:
        print(f"unknown rule: {rule_id}", file=sys.stderr)
        return 2
    sev = getattr(r.severity, "name", r.severity)
    print(f"{r.id}  [{sev}]  {r.title}\n\n{r.explanation}\n\nFix: {r.fix_hint}\nNeeds Snap: {'yes' if r.needs_snap else 'no'}")
    return 0


def _make_engine(key: str, args: argparse.Namespace):
    """Build the Snap engine; construction does no network. Returns (engine, note)."""
    try:
        from .snap import SnapClient, SnapEngine
        return SnapEngine(SnapClient(api_key=key), cache_dir=Path(args.cache_dir), workers=args.workers,
                          budget_tokens=args.budget_tokens), ""
    except Exception as exc:  # noqa: BLE001
        return None, f"Snap unavailable ({type(exc).__name__}: {exc})"


def _run_one(check: Check, ctx: Context, args: argparse.Namespace) -> CheckResult:
    """Run a check; any exception becomes result.error so the other checks still run."""
    try:
        return check.run(ctx, args)
    except Exception as exc:  # noqa: BLE001
        kind = type(exc).__name__
        res = CheckResult(check=check.name, error=f"{kind}: {exc}")
        partial = getattr(exc, "partial", None)
        if kind == "BudgetExceeded":
            res.error = "token budget exceeded; results are partial"
            res.notes.append(f"partial scan: {getattr(partial, 'calls', '?')} calls made before the budget stopped it")
        return res


def exit_code(results: Sequence[CheckResult], fail_on: str) -> int:
    if any(r.error for r in results):
        return 3
    if fail_on != "none":
        limit = Severity.parse(fail_on)
        if any(f.severity >= limit for r in results for f in r.findings):
            return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _main(argv)
    except SystemExit as e:  # argparse: 2 on bad usage, 0 for --help/--version
        return e.code if isinstance(e.code, int) else 2


def _main(argv: Sequence[str] | None) -> int:
    checks = all_checks()
    parser = build_parser(checks)
    pre, _ = parser.parse_known_args(argv)
    try:
        cfg = load_config(Path(pre.config) if pre.config else None)
    except ConfigError as exc:
        print(f"checksnap: {exc}", file=sys.stderr)
        return 2
    unknown_cfg = apply_defaults(parser, cfg)
    args = parser.parse_args(argv)

    if args.list_checks:
        w = max([len(c.flag) for c in checks] + [22]) + 2
        for c in checks:
            print(f"{c.flag:<{w}}{c.summary}")
        from . import checks as pkg
        for name, err in getattr(pkg, "_LOAD_ERRORS", {}).items():
            print(f"{'(unavailable) ' + name:<{w}}{err}")
        return 0
    if args.explain:
        return _explain(args.explain, checks)

    if args.check_all is not None:
        for c in checks:
            if getattr(args, c.flag[2:].replace("-", "_")) is None:
                setattr(args, c.flag[2:].replace("-", "_"), args.check_all)
    selected = [c for c in checks if getattr(args, c.flag[2:].replace("-", "_")) is not None]
    if not selected:
        parser.print_usage(sys.stderr)
        print("checksnap: choose a check (see --list-checks)", file=sys.stderr)
        return 2
    if args.workers < 1 or not 0 <= args.threshold <= 1 or args.budget_tokens < 0:
        print("checksnap: --workers must be >= 1, --threshold in [0,1], --budget-tokens >= 0", file=sys.stderr)
        return 2

    def progress(msg: str) -> None:
        if not args.quiet:
            print(msg, file=sys.stderr)

    ctx = Context(no_snap=args.no_snap, budget_tokens=args.budget_tokens, cache_dir=Path(args.cache_dir),
                  workers=args.workers, threshold=args.threshold, quiet=args.quiet,
                  progress=progress if args.verbose else (lambda m: None))
    cli_notes = [f"config: ignored unknown key '{k}'" for k in unknown_cfg]

    # Snap decision: estimates are free, the gate runs before the first call.
    key = None if args.no_snap else load_api_key()
    if key:
        ctx.snap, note = _make_engine(key, args)
        if note:
            cli_notes.append(note)
    snap_checks = [c for c in selected if c.uses_snap and not args.no_snap]
    rows: list[tuple[str, CostEstimate]] = []
    estimate_failed = False
    for c in snap_checks:
        try:
            rows.append((c.name, c.estimate(ctx, args)))
        except Exception as exc:  # noqa: BLE001
            estimate_failed = True
            cli_notes.append(f"estimate failed for {c.name}: {type(exc).__name__}: {exc}")
    total = sum((e for _, e in rows), CostEstimate())

    if args.dry_run:
        print(estimate_table(rows) if rows else "Nothing would be uploaded (--no-snap or no Snap-using check).")
        if not key and snap_checks:
            print("note: SUBQ_API_KEY not set; Snap parts would be skipped.")
        return 0

    snap_note = ""
    if args.no_snap or not snap_checks:
        ctx.snap = None
    elif not key:
        snap_note = "Snap skipped: SUBQ_API_KEY not set (env or .env)"
    elif ctx.snap is None:
        snap_note = "Snap skipped: engine unavailable"
    elif estimate_failed:
        snap_note = "Snap skipped: upload size could not be estimated, so it cannot be confirmed"
    elif total.snap_calls or total.uploads_bytes:
        print(estimate_table(rows), file=sys.stderr)
        ok, snap_note = confirm_upload(total, yes=args.yes, interactive=sys.stdin.isatty(),
                                       ask=lambda q: input(q))
        if not ok:
            ctx.snap = None
    if snap_note:
        ctx.snap, ctx.no_snap = None, True

    results = []
    for c in selected:
        res = _run_one(c, ctx, args)
        stop = getattr(ctx.snap, "fatal", None)    # checks degrade Snap errors to notes; auth/quota/budget must still exit 3
        if stop is not None and not res.error:
            res.error = "token budget exceeded; results are partial" if type(stop).__name__ == "BudgetExceeded" else f"{type(stop).__name__}: {stop}"
        if stop is not None:
            ctx.snap.fatal = None
        if snap_note and c in snap_checks:
            res.notes.append(snap_note)
        results.append(res)
    if cli_notes and results:
        results[0].notes.extend(cli_notes)

    color = args.format == "text" and not args.out and sys.stdout.isatty()
    text = render(results, args.format, color)
    if args.out:
        try:
            Path(args.out).write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"checksnap: cannot write {args.out}: {exc}", file=sys.stderr)
            return 3
    else:
        sys.stdout.write(text)
    return exit_code(results, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
