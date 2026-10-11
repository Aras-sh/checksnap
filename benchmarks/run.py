"""Plant known problems, run checksnap, measure recall and false positives.

Default: in-process FakeSnapServer (free, offline). It only matches verbatim needles, so Snap recall here proves the
plumbing, not Snap's skill at paraphrases. `--real` talks to api.subq.ai (needs SUBQ_API_KEY, spends tokens, skips the upload prompt).

Usage: python -m benchmarks.run [--quick] [--real] [--seed N]
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import random
import sys
import tempfile
from pathlib import Path


WORDS = ("amber basil cedar dune ember fjord glade harbor iris jade kelp lunar maple north opal pine quartz reed slate "
         "thorn umber vale willow xenon yarrow zephyr").split()


def _sentence(rng: random.Random, n: int = 14) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(n))


def make_dataset(root: Path, rng: random.Random, n_bench: int, n_planted: int, n_filler: int):
    """Benchmark items carry a unique tag so findings can be matched back to items."""
    items = [f"Item tag{i:03d}x: {_sentence(rng, 20)}?" for i in range(n_bench)]
    planted = set(rng.sample(range(n_bench), n_planted))
    (root / "bench.jsonl").write_text("\n".join(json.dumps({"question": q}) for q in items), encoding="utf-8")
    recs = [{"id": i, "text": _sentence(rng, 30)} for i in range(n_filler)]
    for k, i in enumerate(sorted(planted)):
        recs.insert(rng.randrange(len(recs) + 1), {"id": 10_000 + k, "text": f"{_sentence(rng, 6)} {items[i]} {_sentence(rng, 6)}"})
    (root / "data.jsonl").write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")
    return items, planted


def score_contam(findings, items, planted, rule_prefix: str) -> dict:
    hit = {i for i, q in enumerate(items) if any(f["rule_id"].startswith(rule_prefix) and (f"tag{i:03d}x" in ftext(f) or f"bench.jsonl:{i + 1} " in ftext(f)) for f in findings)}
    tp, fp = hit & planted, hit - planted
    return {"planted": len(planted), "found": len(tp), "recall": len(tp) / max(1, len(planted)), "false_positives": len(fp)}


# Planted slow code: (file, source, line numbers expected to be flagged). Lines are 1-based.
SLOW = {
    "concat.py": ("def f(rows):\n    out = ''\n    for r in rows:\n        out += str(r)\n    return out\n", {4}),
    "reglo.py": ("import re\n\ndef f(ls):\n    for l in ls:\n        re.findall(r'\\d+', l)\n", {5}),
    "rangelen.py": ("def f(xs):\n    for i in range(len(xs)):\n        print(xs[i])\n", {2}),
    "asleep.py": ("import time\n\nasync def f():\n    time.sleep(1)\n", {4}),
    "sync.py": ("import torch\n\ndef train(m, loader, opt):\n    for x in loader:\n        loss = m(x)\n        loss.backward()\n        opt.step()\n        print(loss.item())\n", {9}),
}
CLEAN = {
    "ok1.py": "def f(rows):\n    return ''.join(str(r) for r in rows)\n",
    "ok2.py": "import re\nP = re.compile(r'\\d+')\n\ndef f(ls):\n    return [P.findall(l) for l in ls]\n",
    "ok3.py": "def f(xs):\n    for x in xs:\n        print(x)\n",
}


def score_static(findings, planted: dict[str, set[int]]) -> dict:
    exp = {(n, ln) for n, lines in planted.items() for ln in lines}
    got = {(Path(e["file"] or "").name, e["line_start"]) for f in findings for e in f["evidence"] if e["line_start"]}
    found = {x for x in exp if any(x[0] == g[0] and g[1] is not None and abs(g[1] - x[1]) <= 1 for g in got)}
    clean_hits = [f["rule_id"] for f in findings if any(Path(e["file"] or "").name in CLEAN for e in f["evidence"])]
    return {"planted": len(exp), "found": len(found), "recall": len(found) / max(1, len(exp)), "false_positives": len(clean_hits)}


def run_cli(argv: list[str], fake_url: str | None = None, out: Path | None = None) -> tuple[int, list[dict]]:
    """Run the real CLI in-process with --format json. With fake_url the Snap client is pointed at the fake server."""
    from checksnap import cli
    from checksnap.snap import SnapClient, SnapEngine

    orig = cli._make_engine
    if fake_url:
        def fake_engine(key, a):
            return SnapEngine(SnapClient(api_key=key, url=fake_url), cache_dir=Path(a.cache_dir), workers=a.workers,
                              budget_tokens=a.budget_tokens), ""
        cli._make_engine = fake_engine
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(argv + ["--format", "json", "--yes", "--fail-on", "none"])
    finally:
        cli._make_engine = orig
    doc = json.loads(buf.getvalue())
    return code, (doc["results"] if isinstance(doc, dict) and "results" in doc else doc)


def findings(results: list[dict]) -> list[dict]:
    return [f for r in results for f in r["findings"]]


def ftext(f: dict) -> str:
    return " ".join([f["title"], f["detail"]] + [e["snippet"] for e in f["evidence"]])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true", help="smaller sizes (CI)")
    ap.add_argument("--real", action="store_true", help="use the real API (SUBQ_API_KEY required, spends tokens)")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)
    if args.real and not os.environ.get("SUBQ_API_KEY"):
        print("--real needs SUBQ_API_KEY in the environment", file=sys.stderr)
        return 2
    rng = random.Random(args.seed)
    n_bench, n_planted, n_filler = (10, 3, 40) if args.quick else (40, 12, 400)
    report: dict = {"mode": "real" if args.real else "fake"}

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        ds = root / "ds"
        ds.mkdir()
        items, planted = make_dataset(ds, rng, n_bench, n_planted, n_filler)
        common = ["--check-dataset", str(ds / "data.jsonl"), "--benchmark", str(ds / "bench.jsonl"), "--cache-dir", str(root / "c")]
        _, res = run_cli(common + ["--no-snap"])
        report["dataset_local_DS-CONTAM-002"] = score_contam(findings(res), items, planted, "DS-CONTAM-002")
        if args.real:
            _, res = run_cli(common)
            report["dataset_snap_DS-CONTAM-001"] = score_contam(findings(res), items, planted, "DS-CONTAM-001")
        else:
            from checksnap.snap.fake_server import FakeSnapServer
            os.environ.setdefault("SUBQ_API_KEY", "fake-key-for-local-server")
            with FakeSnapServer() as srv:
                _, res = run_cli(common, fake_url=srv.url)
                report["dataset_snap_DS-CONTAM-001"] = score_contam(findings(res), items, planted, "DS-CONTAM-001")
                report["fake_server_calls"] = srv.calls

        src = root / "src"
        src.mkdir()
        for n, (code, _) in SLOW.items():
            (src / n).write_text(code, encoding="utf-8")
        for n, code in CLEAN.items():
            (src / n).write_text(code, encoding="utf-8")
        _, res = run_cli(["--check-optimization", str(src), "--static-only", "--no-snap", "--cache-dir", str(root / "c")])
        report["optimization_static"] = score_static(findings(res), {n: ls for n, (_, ls) in SLOW.items() if ls})

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
