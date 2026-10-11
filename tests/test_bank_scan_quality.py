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


def test_one_window_per_file_maps_to_one_file(tmp_path):
    root = make_files(tmp_path / "p", 4, {"f2.py": "# MARK\n"})

    def sc(state, q):
        return 0.9 if item_of(q) == "PERF-GEN-003" and "MARK" in state else 0.04
    with FakeSnapServer(sc) as srv:
        res = BankCheck().run(Context(snap=eng(srv, tmp_path)), args(root))
    f = next(f for f in res.findings if f.rule_id == "PERF-GEN-003")
    assert res.stats["snap_windows"] == 4 and [e.file for e in f.evidence] == ["f2.py"]


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
