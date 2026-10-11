"""Bank scan quality: one window per file, absence gating, clean-code baseline demotion, calibration line."""
from __future__ import annotations

import argparse
from pathlib import Path

from checksnap.checks.bank import BankCheck, engine
from checksnap.core import Context
from checksnap.snap import FakeSnapServer, SnapClient, SnapEngine

ITEMS = {i["id"]: i for i in engine.load_items()[0]}


def args(root, **kw):
    ns = argparse.Namespace(check_bank=str(root), bank_categories="perf-general,testing,docs", bank_applies=None, bank_file=None,
                            bank_top=25, bank_list=False, bank_include_absence=False)
    ns.__dict__.update(kw)
    return ns


def eng(srv, tmp_path):
    return SnapEngine(SnapClient(api_key="k", url=srv.url, sleep=lambda s: None), cache_dir=tmp_path / "c", workers=2)


def item_of(q):
    return next((i["id"] for i in ITEMS.values() if i["question"] in q["instructions"]), None)      # None: decoy or canary


def make_files(root: Path, n: int, marked: dict[str, str]):
    root.mkdir()
    for k in range(n):
        (root / f"f{k}.py").write_text(f"def f{k}():\n    return {k}\n" + marked.get(f"f{k}.py", ""))
    return root


def test_absence_flags_and_titles():
    absent = [i for i in ITEMS.values() if i["absence"]]
    assert len(absent) >= 40 and all(i["title"].startswith("[absence]") for i in absent)
    assert not ITEMS["PERF-GEN-003"]["absence"] and ITEMS["BANK-DOCS-014"]["absence"]


def test_absence_gate(tmp_path):
    small, big = make_files(tmp_path / "s", 3, {}), make_files(tmp_path / "b", 10, {})
    asked = {}
    for name, root, inc in (("small", small, False), ("forced", small, True), ("big", big, False)):
        asked[name] = set()
        with FakeSnapServer(lambda s, q, name=name: asked[name].add(item_of(q)) or 0.04) as srv:
            res = BankCheck().run(Context(snap=eng(srv, tmp_path / name)), args(root, bank_include_absence=inc, bank_categories="docs"))
        if name == "small":
            assert any("absence items skipped" in n for n in res.notes)
    ab = {i for i, it in ITEMS.items() if it["absence"] and it["category"] == "docs"}
    assert not asked["small"] & ab and ab <= asked["forced"] and ab <= asked["big"]


def big_files(root: Path, n: int, marked: dict[str, str]):
    """n files of ~4 KB; a mark goes in the middle of the file so a localized snippet stays inside it."""
    root.mkdir()
    for k in range(n):
        half = "x = 1\n" * 350
        (root / f"f{k}.py").write_text(half + marked.get(f"f{k}.py", "") + half)
    return root


def test_packed_window_localizes_to_the_marked_file(tmp_path):
    root = big_files(tmp_path / "p", 6, {"f2.py": "# MARK\n"})

    def sc(state, q):
        return 0.9 if item_of(q) == "PERF-GEN-003" and "MARK" in state else 0.04
    with FakeSnapServer(sc) as srv:
        res = BankCheck().run(Context(snap=eng(srv, tmp_path)), args(root))
        scan_calls = [r for r in srv.requests if r["n_questions"] > 1]
    f = next(f for f in res.findings if f.rule_id == "PERF-GEN-003")
    assert res.stats["snap_windows"] == 1 and [e.file for e in f.evidence] == ["f2.py"] and f.evidence[0].extra["localized"]
    assert len(scan_calls) <= 2 * -(-res.stats["items_asked"] // 55)      # (1 window + baseline) x question batches, not files x batches


def _span(rel, start, end, header=10):
    return type("S", (), {"rel": rel, "start": start, "end": end, "header_len": header, "first_line": 1, "window": 0})()


def test_attribute_never_guesses_one_file():
    text = "### FILE: a.py\n" + "x\n" * 20 + "### FILE: b.py\n" + "y = SLOW\n" + "### FILE: c.py\n" + "z\n" * 5
    w = type("W", (), {"start": 0, "end": len(text), "text": text})()
    a, b = text.index("### FILE: b"), text.index("### FILE: c")
    spans = [_span("a.py", 0, a, 15), _span("b.py", a, b, 15), _span("c.py", b, len(text), 15)]
    import re
    hint = engine._AnyOf([re.compile("SLOW")])
    ev = engine.attribute(0, len(text), False, spans, [w], hint, {})          # regex hint lands in one file only
    assert [e.file for e in ev] == ["b.py"] and ev[0].extra["line_from"] == "regex hint"
    ev = engine.attribute(0, len(text), False, spans, [w], None, {})          # nothing to go on: say so, do not pick
    assert len(ev) == 1 and ev[0].file is None and "somewhere in these 3 files: a.py, b.py, c.py" in ev[0].snippet
    ev = engine.attribute(a, b, True, spans, [w], None, {})                   # snippet inside one file
    assert [e.file for e in ev] == ["b.py"] and ev[0].extra["localized"]


def test_max_items_keeps_highest_severity():
    items = list(ITEMS.values())
    kept = engine.cap_items(items, 20)
    assert len(kept) == 20 and min(int(i["severity"]) for i in kept) >= sorted((int(i["severity"]) for i in items), reverse=True)[19]
    assert engine.cap_items(items, None) is items and engine.cap_items(items, 10_000) is items


def test_estimate_is_an_upper_bound_within_2x(tmp_path):
    """60 small files like the benchmark project; every item flagged so localization really runs (25 of them)."""
    files = {f"f{k}.py": "# MARK\n" if k == 40 else "" for k in range(60)}
    root = make_files(tmp_path / "p", 60, files)
    for p in root.glob("*.py"):
        p.write_text(p.read_text() + "x = 1\n" * 30)

    def sc(state, q):
        return 0.9 if item_of(q) and "MARK" in state else 0.04
    with FakeSnapServer(sc, chars_per_token=3.2) as srv:
        ctx = Context(snap=eng(srv, tmp_path))
        a = args(root, bank_categories=None)
        est = BankCheck().estimate(ctx, a)
        res = BankCheck().run(ctx, a)
        actual = sum(r["input_tokens"] for r in srv.requests)
    assert res.usage["input_tokens"] == actual and ctx.snap.spent_tokens == actual     # localization is counted too
    assert actual <= est.input_tokens <= 2 * actual, (actual, est.input_tokens)
    assert est.snap_calls >= len(srv.requests)


def test_max_items_cuts_the_asked_questions(tmp_path):
    root = make_files(tmp_path / "p", 3, {})
    with FakeSnapServer() as srv:
        res = BankCheck().run(Context(snap=eng(srv, tmp_path)), args(root, bank_categories=None, bank_max_items=10))
    assert res.stats["items_asked"] == 10


def test_baseline_demotes_items_that_fire_on_clean_code(tmp_path):
    root = make_files(tmp_path / "p", 2, {"f1.py": "# MARK\n"})

    def sc(state, q):
        i = item_of(q)
        return 0.9 if i == "PERF-GEN-003" else (0.9 if i == "TEST-001" and "MARK" in state else 0.04)
    with FakeSnapServer(sc) as srv:
        ctx = Context(snap=eng(srv, tmp_path))
        res = BankCheck().run(ctx, args(root))
        calls = srv.calls
        res2 = BankCheck().run(ctx, args(root))
        cached_extra = srv.calls - calls
    assert [f.rule_id for f in res.findings] == ["TEST-001"]
    assert res.stats["suppressed"] == 1 and any("1 items suppressed: fire on clean code" in n for n in res.notes)
    cal = next(n for n in res.notes if n.startswith("calibration:"))
    assert "clean-code baseline: 1/" in cal and "1 suppressed" in cal
    assert (tmp_path / "c" / "bank_baseline.json").exists() and [f.rule_id for f in res2.findings] == ["TEST-001"]
    assert cached_extra == 0       # second run: engine cache for the scan, json cache for the baseline


def test_baseline_margin(tmp_path):
    """A score barely above its clean-code baseline is not evidence."""
    root = make_files(tmp_path / "p", 2, {"f1.py": "# MARK\n"})

    def sc(state, q):
        return (0.6 if "MARK" in state else 0.5) if item_of(q) == "PERF-GEN-003" else 0.04
    with FakeSnapServer(sc) as srv:
        res = BankCheck().run(Context(snap=eng(srv, tmp_path)), args(root))
    assert not res.findings and res.stats["suppressed"] == 1
