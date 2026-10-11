"""--check-bank: loading, validation, selection, local pre-screen and the Snap path on the fake server (scored per item)."""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import pytest

from checksnap.checks.bank import RULES, BankCheck, engine
from checksnap.core import REGISTRY, Context, Severity
from checksnap.snap import FakeSnapServer, SnapClient, SnapEngine

FIX = Path(__file__).parent / "fixtures" / "bank"
HOT = {"PERF-GEN-003", "TEST-001"}      # items the fake scorer calls true whenever the state has the marker file


def make_args(root, **kw):
    ns = argparse.Namespace(check_bank=str(root), bank_categories=None, bank_applies=None, bank_file=None, bank_top=25, bank_list=False)
    ns.__dict__.update(kw)
    return ns


def scorer(state: str, q: dict) -> float:
    """Score by item id: the question text of a HOT item is its own marker, so find the item whose question matches."""
    item = next((i for i in engine.load_items()[0] if i["question"] in q["instructions"]), None)
    return 0.9 if item and item["id"] in HOT and "BANK_MARKER_TIMEOUT" in state else 0.04


@pytest.fixture
def proj(tmp_path):
    shutil.copytree(FIX / "proj", tmp_path / "p")
    return tmp_path / "p"


def engine_for(srv, tmp_path):
    return SnapEngine(SnapClient(api_key="k", url=srv.url, sleep=lambda s: None), cache_dir=tmp_path / "c", workers=2)


def test_registered_and_rules():
    assert REGISTRY["bank"].flag == "--check-bank" and REGISTRY["bank"].uses_snap
    assert len(RULES) >= 30 and RULES["TEST-001"].needs_snap


def test_load_items_dedupes_and_validates(tmp_path):
    items, notes = engine.load_items(str(FIX / "extra.json"))
    ids = [i["id"] for i in items]
    assert len(ids) == len(set(ids)) and "USR-001" in ids and "USR-BAD" not in ids
    assert any("USR-BAD" in n and "schema error" in n for n in notes)
    assert any("--bank-file" in n for n in engine.load_items(str(tmp_path / "nope.json"))[1])


def test_validate_rejects():
    base = dict(id="X", category="c", title="t", severity="LOW", applies_to=["code"], question="q", true="t", false="f", why="w", fix="f", hints=[])
    assert engine.validate(base, "o")[1] is None
    for bad in ({"severity": "HUGE"}, {"applies_to": ["video"]}, {"hints": [1]}, {"id": "__decoy_x"}):
        assert engine.validate({**base, **bad}, "o")[0] is None


def test_select_items():
    items = engine.load_items()[0]
    only_docs = engine.select_items(items, {"testing"}, {"docs"})
    assert not any(i["category"] != "testing" for i in only_docs)
    assert all({"docs", "any"} & set(i["applies_to"]) for i in only_docs)


def test_list_needs_no_path():
    res = BankCheck().run(Context(no_snap=True), make_args("/does/not/exist", bank_list=True, bank_categories="testing"))
    assert res.error is None and len(res.findings) == 16 and all(f.severity == Severity.INFO for f in res.findings)
    assert res.stats["categories"] == {"testing": 16}


def test_no_snap_prescreen(proj):
    chk, ctx = BankCheck(), Context(no_snap=True)
    assert chk.estimate(ctx, make_args(proj)).snap_calls == 0
    res = chk.run(ctx, make_args(proj))
    assert any("Snap skipped" in n for n in res.notes)
    assert res.findings and {f.source for f in res.findings} == {"local-hint"} and all(f.severity == Severity.INFO for f in res.findings)
    assert any(f.rule_id == "PERF-GEN-003" and f.evidence[0].file == "app.py" for f in res.findings)
    assert len(chk.run(ctx, make_args(proj, bank_top=2)).findings) == 2


def test_applies_filter_changes_files(proj):
    files, _, _ = engine.collect_files(proj, {"docs"})
    assert [r for r, _ in files] == ["notes.md"]


def test_snap_path_ranks_and_localizes(proj, tmp_path):
    with FakeSnapServer(scorer=scorer) as srv:
        eng = engine_for(srv, tmp_path)
        chk, ctx = BankCheck(), Context(snap=eng, threshold=0.5, cache_dir=tmp_path / "c")
        est = chk.estimate(ctx, make_args(proj))
        assert est.snap_calls >= 1 and est.uploads_bytes > 0
        res = chk.run(ctx, make_args(proj, bank_categories="perf-general,testing"))
    assert res.error is None and {f.rule_id for f in res.findings} == HOT
    top = res.findings[0]
    assert top.source == "snap" and top.score >= 0.9 and top.fix_hint and top.evidence[0].file in ("app.py", "sample_tests.py")
    assert res.stats["calibration"]["decoys"] >= 0 and res.usage["snap_calls"] >= 1
    assert any(f.evidence[0].line_start for f in res.findings if f.rule_id == "PERF-GEN-003")


def test_snap_top_cap_and_bank_file(proj, tmp_path):
    (proj / "x.py").write_text("CUSTOM_MARK = 1\n")

    def sc(state, q):
        return 0.9 if "CUSTOM_MARK" in q["instructions"] and "CUSTOM_MARK" in state else 0.04
    with FakeSnapServer(scorer=sc) as srv:
        ctx = Context(snap=engine_for(srv, tmp_path), threshold=0.5)
        res = BankCheck().run(ctx, make_args(proj, bank_file=str(FIX / "extra.json"), bank_categories="custom,bogus"))
    assert [f.rule_id for f in res.findings] == ["USR-001"] and res.findings[0].evidence[0].file == "x.py"
    assert any("unknown categories" in n for n in res.notes)


def test_auth_error_sets_error(proj, tmp_path):
    with FakeSnapServer(fail=401) as srv:
        res = BankCheck().run(Context(snap=engine_for(srv, tmp_path)), make_args(proj))
    assert res.error and "Auth" in res.error


def test_missing_path_and_empty(tmp_path):
    assert BankCheck().run(Context(no_snap=True), make_args(tmp_path / "nope")).error
    assert any("no files" in n for n in BankCheck().run(Context(no_snap=True), make_args(tmp_path)).notes)


def test_broken_module_is_a_note(monkeypatch):
    import types
    import sys
    monkeypatch.setitem(sys.modules, "checksnap.checks.bank.items_arch", types.ModuleType("items_arch"))
    items, notes = engine.load_items()
    assert any("items_arch" in n for n in notes) and items
