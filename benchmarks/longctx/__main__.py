"""CLI: python -m benchmarks.longctx {plan,run,canary,decoy,order,needles,hop,cost,report} ... (see README.md)."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path
from typing import Callable

from checksnap.snap import SnapAuthError

from .backends import make_backend
from .core import DEFAULT_LENGTHS, SUITES, Config, parse_tokens, plan_calls, plan_summary, plan_text
from .report import build_report, render_markdown
from .runner import load_records, run_calls

SHORTCUTS = {"canary": "canary,decoy", "decoy": "canary,decoy", "order": "order", "needles": "needles", "hop": "hop"}
HELP = {"canary": "recall by length/position (same calls as decoy)", "decoy": "false-alarm rates (same calls as canary)",
        "order": "order sensitivity (runs the base call it compares against, 1 seed)", "needles": "multi-needle k=1,5,20", "hop": "two-hop question"}


def _csv(s: str, conv=str) -> tuple:
    return tuple(conv(x) for x in s.split(",") if x.strip())


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--backend", choices=["snap", "chat"], default="snap")
    p.add_argument("--chat-config", help="JSON file with the chat API shape (see README); url/model also from SUBQ_API_URL/SUBQ_MODEL")
    p.add_argument("--url", help="endpoint (default: $SUBQ_API_URL, else the Snap URL; chat has no default)")
    p.add_argument("--model", help="model name (default: $SUBQ_MODEL, else subq-snap-preview; the 12M model name is not known yet)")
    p.add_argument("--lengths", type=lambda s: _csv(s, parse_tokens), default=DEFAULT_LENGTHS, help="e.g. 50k,500k,1M,12M")
    p.add_argument("--max-length", type=parse_tokens, default=None, help="drop longer lengths; adds itself if not in the list")
    p.add_argument("--seeds", type=lambda s: _csv(s, int), default=(1, 2, 3))
    p.add_argument("--aux-seeds", type=int, default=1, help="order/needles/hop use the first N seeds")
    p.add_argument("--mode", choices=["synthetic", "text"], default="synthetic")
    p.add_argument("--text-path", help="file or directory of public .txt/.md/.rst for --mode text")
    p.add_argument("--decoys", type=int, default=5)
    p.add_argument("--ks", type=lambda s: _csv(s, int), default=(1, 5, 20))
    p.add_argument("--price", type=float, default=0.09, help="dollars per million input tokens")
    p.add_argument("--chars-per-token", type=float, default=None, help="override calibrate.py's conservative prose ratio")
    p.add_argument("--threshold", type=float, default=0.5, help="snap: probability >= this counts as true")


def _config(a: argparse.Namespace) -> Config:
    lengths = sorted(set(a.lengths))
    if a.max_length:
        lengths = [x for x in lengths if x <= a.max_length]
        if a.max_length not in lengths:
            lengths.append(a.max_length)
    suites = tuple(s for s in a.suites.split(",") if s)
    if bad := set(suites) - set(SUITES):
        raise ValueError(f"unknown suites {sorted(bad)}")
    return Config(tuple(lengths), a.seeds, min(a.aux_seeds, len(a.seeds)), suites, a.mode, a.text_path, a.decoys, a.ks, a.price, a.chars_per_token)


def _backend(a: argparse.Namespace, offline: bool, sleep: Callable[[float], None]):
    return make_backend(a.backend, url=a.url, model=a.model, timeout=getattr(a, "timeout", None), max_retries=getattr(a, "max_retries", 6),
                        threshold=a.threshold, chat_config=a.chat_config, sleep=sleep, offline=offline)


def _meta(a: argparse.Namespace, cfg: Config, be) -> dict:
    if a.backend == "snap":
        model, url = be.client.model, be.client.url
        chat = None
    else:
        model, url, chat = be.cfg.model, be.cfg.url, be.cfg.public()
    return {"backend": a.backend, "model": model, "url": url, "chat_config": chat, "config": cfg.public(), "threshold": a.threshold,
            "workers": a.workers, "started": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}


def _write(out_dir: Path, meta: dict, say) -> None:
    rep = build_report(list(load_records(out_dir).values()), meta)
    (out_dir / "results.json").write_text(json.dumps({**rep, "calls": list(load_records(out_dir).values())}, indent=1))
    md = render_markdown(rep)
    (out_dir / "results.md").write_text(md)
    say(md)
    say(f"\nresults: {out_dir}/results.json, results.md")


def main(argv: list[str] | None = None, *, input_fn: Callable[[str], str] = input, out=None, sleep: Callable[[float], None] = time.sleep) -> int:
    out = out or sys.stdout
    say = lambda s="": print(s, file=out, flush=True)
    ap = argparse.ArgumentParser(prog="python -m benchmarks.longctx", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan", help="calls, tokens and dollars for the full suite; no network, no key").set_defaults(run=False)
    for name in ("run", *SHORTCUTS):
        sub.add_parser(name, help="run the selected suites (shows the plan, asks for confirmation)" if name == "run" else HELP[name]).set_defaults(run=True)
    for name in ("cost", "report"):
        p = sub.add_parser(name, help="re-render results from a finished or partial run directory")
        p.add_argument("dir")
    for name, p in sub.choices.items():
        if name in ("cost", "report"):
            continue
        _common(p)
        if name in ("run", "plan"):
            p.add_argument("--suites", default=",".join(SUITES), help="comma list of " + ",".join(SUITES))
        if p.get_default("run"):
            p.add_argument("--max-dollars", type=float, default=20.0)
            p.add_argument("--max-tokens", type=parse_tokens, default=250_000_000)
            p.add_argument("--dry-run", action="store_true", help="print the plan only")
            p.add_argument("--workers", type=int, default=2)
            p.add_argument("--timeout", type=float, default=1800.0)
            p.add_argument("--max-retries", type=int, default=6, help="per request, backoff on 429/503/network errors")
            p.add_argument("--out", type=Path, default=None, help="run directory; an existing one is resumed")
    a = ap.parse_args(argv)
    try:
        if a.cmd in ("cost", "report"):
            d = Path(a.dir)
            meta = json.loads((d / "meta.json").read_text())
            rep = build_report(list(load_records(d).values()), meta)
            say(render_markdown(rep) if a.cmd == "report" else "\n".join(l for l in render_markdown(rep).split("## ") if l.startswith("4.")))
            return 0
        if a.cmd in SHORTCUTS:
            a.suites = SHORTCUTS[a.cmd]
        cfg = _config(a)
        specs = plan_calls(cfg)
        planner = _backend(a, offline=True, sleep=sleep)
        plan = plan_summary(cfg, specs, planner)
        say(plan_text(cfg, plan))
        if not a.run:
            return 0
        over = plan["dollars"] > a.max_dollars or plan["tokens"] > a.max_tokens
        if a.dry_run:
            say("\n--dry-run: nothing sent." + (f" This plan EXCEEDS the caps (${a.max_dollars}, {a.max_tokens:,} tokens): a real run would refuse." if over else ""))
            return 0
        if over:
            say(f"\nREFUSED: plan exceeds --max-dollars {a.max_dollars} / --max-tokens {a.max_tokens:,}. Narrow --suites/--lengths/--seeds or raise the cap.")
            return 2
        be = _backend(a, offline=False, sleep=sleep)       # fails here, before any prompt, if SUBQ_API_KEY is unset
    except SnapAuthError:
        say("SUBQ_API_KEY is not set (the key is read only from that environment variable).")
        return 2
    except (ValueError, OSError) as e:
        say(f"error: {e}")
        return 2
    try:
        say(f"\nbackend {a.backend}, model {_meta(a, cfg, be)['model']!r}, endpoint {_meta(a, cfg, be)['url']}")
        try:
            ok = input_fn(f"Type RUN to send ~{plan['calls']} calls (~${plan['dollars']:,.2f}, hard caps ${a.max_dollars} / {a.max_tokens:,} tokens): ").strip() == "RUN"
        except EOFError:
            ok = False
        if not ok:
            say("Aborted: nothing sent.")
            return 1
        out_dir = a.out or Path(__file__).parent / "results" / f"run-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}"
        out_dir.mkdir(parents=True, exist_ok=True)
        meta = _meta(a, cfg, be)
        if (out_dir / "meta.json").exists():
            meta["started"] = json.loads((out_dir / "meta.json").read_text()).get("started", meta["started"])
        (out_dir / "meta.json").write_text(json.dumps(meta, indent=1))
        s = run_calls(specs, cfg, be, out_dir, workers=a.workers, max_tokens=a.max_tokens, max_dollars=a.max_dollars, progress=say)
        _write(out_dir, meta, say)
        say(f"\nran {s['ran']} calls ({s['already_done']} already done), billed {s['billed_tokens']:,} tokens")
        if s["fatal"]:
            say(f"STOPPED: {s['fatal']}")
        if s["skipped_cap"]:
            say(f"STOPPED AT CAP: {len(s['skipped_cap'])} calls not sent (results are partial; rerun with the same --out and higher caps to resume)")
        return 3 if s["fatal"] or s["skipped_cap"] else 0
    finally:
        be.close()


if __name__ == "__main__":
    sys.exit(main())
