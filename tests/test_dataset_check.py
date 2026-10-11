from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

import checksnap.snap as snap_pkg
from checksnap.core import Context, REGISTRY, Severity
from checksnap.checks.dataset import RULES, DatasetCheck
from checksnap.checks.dataset.pii import find_pii, iban_ok, luhn, tckn_ok
from checksnap.checks.dataset.textutil import DupIndex, norm

if not hasattr(snap_pkg, "Question"):  # engine package not assembled yet: pull names from its modules
    from checksnap.snap import client as _c, errors as _e, windows as _w
    for _n, _m in (("Question", _c), ("Window", _w), ("SnapError", _e), ("BudgetExceeded", _e)):
        setattr(snap_pkg, _n, getattr(_m, _n))

CHECK = REGISTRY["dataset"]
LONG = " ".join(f"word{i}" for i in range(60))
Q = "Natalia sold clips to 48 of her friends in April, and then she sold half as many clips in May. How many clips did she sell altogether?"


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    CHECK.add_arguments(p)
    return p


def args(path, *extra):
    ns = parser().parse_args(list(extra))
    ns.check_dataset = str(path)
    return ns


def write_jsonl(p, rows):
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return p


def ids(res):
    return {f.rule_id for f in res.findings}


def run(path, *extra, ctx=None):
    r = CHECK.run(ctx or Context(no_snap=True), args(path, *extra))
    assert r.error is None, r.error
    return r


class StubEngine:
    """Implements scan_windows/estimate/localize like the real engine; scores 0.95 when a needle is in the window."""
    def __init__(self):
        self.calls = 0

    @staticmethod
    def _needle(q):
        return q.instructions.split("[[needle]]")[1].split("[[/needle]]")[0]

    def estimate(self, n_chars, n_questions):
        from checksnap.core import CostEstimate
        return CostEstimate(1, n_chars // 3, n_chars)

    def scan_windows(self, windows, questions, *, label="", progress=None):
        per = {}
        for q in questions:
            best, rng = 0.04, (windows[0].start, windows[0].end)
            if q.id != "lic":
                for w in windows:
                    if self._needle(q) in w.text:
                        best, rng = 0.95, (w.start, w.end)
            elif any("all rights reserved" in w.text.lower() for w in windows):
                best = 0.9
            per[q.id] = SimpleNamespace(id=q.id, max_score=best, best_window=rng)
        self.calls += len(windows)
        cal = SimpleNamespace(decoys=8, decoy_scores=[0.04] * 8, canaries=1, canaries_found=1,
                              canary_recall=lambda t: 1.0)
        return SimpleNamespace(per_question=per, windows=len(windows), calls=len(windows), cached_calls=0,
                               input_tokens=sum(len(w.text) for w in windows) // 3, calibration=cal, partial=False, errors=[])

    def localize(self, window, question):
        n = self._needle(question)
        i = window.text.find(n)
        return snap_pkg.Window(window.start + i, window.start + i + len(n), n) if i >= 0 else None


def test_registered_and_rules():
    assert CHECK.flag == "--check-dataset" and isinstance(CHECK, DatasetCheck)
    assert {"DS-CONTAM-001", "DS-CONTAM-002", "DS-DUP-001", "DS-DUP-002", "DS-LEAK-001", "DS-LEAK-002", "DS-PII-001",
            "DS-HYG-001", "DS-LIC-001", "DS-IMG-001", "DS-IMG-002", "DS-IMG-003"} <= set(RULES)
    assert RULES["DS-CONTAM-001"].needs_snap


def test_missing_path_is_an_error_not_a_traceback(tmp_path):
    r = CHECK.run(Context(no_snap=True), args(tmp_path / "nope"))
    assert r.error and "not found" in r.error


def test_exact_and_near_duplicates(tmp_path):
    near = LONG.replace("word30", "changed")
    write_jsonl(tmp_path / "d.jsonl", [{"text": LONG}, {"text": LONG.upper()}, {"text": near}, {"text": "something else entirely " * 8}])
    r = run(tmp_path)
    assert {"DS-DUP-001", "DS-DUP-002"} <= ids(r)
    r2 = run(tmp_path / "d.jsonl", "--dup-threshold", "0.99")
    assert "DS-DUP-002" not in ids(r2) and "DS-DUP-001" in ids(r2)


def test_no_dups_negative(tmp_path):
    write_jsonl(tmp_path / "d.jsonl", [{"text": f"unique record number {i} " + " ".join(f"w{i}x{j}" for j in range(30))} for i in range(10)])
    assert not ids(run(tmp_path)) & {"DS-DUP-001", "DS-DUP-002"}


def test_dupindex_query_does_not_insert():
    ix = DupIndex()
    ix.add("a", 1, LONG)
    ex, near = ix.query(LONG)
    assert ex == [0] and len(ix.refs) == 1
    assert ix.query("nothing like it")[0] == [] and norm("A, b!") == "a b"


def test_leak_eval(tmp_path):
    (tmp_path / "train").mkdir()
    (tmp_path / "test").mkdir()
    write_jsonl(tmp_path / "train" / "t.jsonl", [{"text": LONG, "id": "v1", "label": "a"}, {"text": "foo " * 30, "id": "v2", "label": "a"}])
    write_jsonl(tmp_path / "test" / "e.jsonl", [{"text": LONG, "id": "v9", "label": "b"}, {"text": LONG.replace("word3 ", "x "), "id": "v2", "label": "b"}])
    r = run(tmp_path / "train", "--eval", str(tmp_path / "test"), "--id-field", "id", "--label-field", "label", "--text-field", "text")
    assert {"DS-LEAK-001", "DS-LEAK-003", "DS-HYG-007"} <= ids(r)
    ok = run(tmp_path / "train", "--eval", str(tmp_path / "train"))  # sanity: same data is of course a leak
    assert "DS-LEAK-001" in ids(ok)


def test_no_leak_negative(tmp_path):
    a = write_jsonl(tmp_path / "a.jsonl", [{"text": "alpha " * 30}])
    b = write_jsonl(tmp_path / "b.jsonl", [{"text": "omega " * 30 + "zeta"}])
    assert not ids(run(a, "--eval", str(b))) & {"DS-LEAK-001", "DS-LEAK-002", "DS-LEAK-003"}


def test_pii_validators_and_masking(tmp_path):
    assert luhn("4111111111111111") and not luhn("4111111111111112")
    assert iban_ok("GB82WEST12345698765432") and not iban_ok("GB82WEST12345698765433")
    assert tckn_ok("10000000146") and not tckn_ok("10000000147")
    text = ("mail me at jane.doe@example.com or +90 532 123 4567; card 4111 1111 1111 1111; iban GB82 WEST 1234 5698 7654 32; "
            "ssn 123-45-6789; ip 8.8.8.8; key AKIAABCDEFGHIJKLMNOP")
    kinds = {k for k, _, _ in find_pii(text)}
    assert {"email", "phone number", "credit card", "IBAN", "US SSN", "IPv4 address", "AWS access key"} <= kinds
    (tmp_path / "d.txt").write_text(text)
    r = run(tmp_path)
    shown = json.dumps(r.to_dict())
    assert "AKIAABCDEFGHIJKLMNOP" not in shown and "jane.doe@example.com" not in shown and "AKIA..." in shown
    assert any(f.severity == Severity.HIGH and f.rule_id == "DS-PII-001" for f in r.findings)


def test_pii_negative():
    assert find_pii("The year 2020-12-31 and version 1.2.3 and number 4111111111111112 and ip 192.168.0.1") == []


def test_hygiene(tmp_path):
    rows = [{"text": f"normal text number {i} with some words in it", "id": str(i % 40), "label": "a"} for i in range(60)]
    rows[0]["text"] = ""
    rows[1]["text"] = "cafÃ© â€™ broken"
    rows[2]["text"] = "x" * 5000
    rows[3] = {"other": "key"}
    for i in range(10, 60):
        rows[i]["label"] = "a"
    rows[5]["label"] = "b"
    p = tmp_path / "d.jsonl"
    write_jsonl(p, rows)
    with p.open("a") as f:
        f.write('{"text": "cut off here\n')
    r = run(p, "--id-field", "id", "--label-field", "label")
    assert {"DS-HYG-001", "DS-HYG-002", "DS-HYG-003", "DS-HYG-004", "DS-HYG-005", "DS-HYG-006", "DS-HYG-008"} <= ids(r)


def test_hygiene_clean(tmp_path):
    write_jsonl(tmp_path / "d.jsonl", [{"text": f"clean record {i} about topic {i * 7} with enough words to be fine", "label": "ab"[i % 2]} for i in range(40)])
    assert not [f for f in run(tmp_path, "--label-field", "label").findings if f.rule_id.startswith("DS-HYG")]


def test_mixed_languages(tmp_path):
    rows = [{"text": "the cat is in the house and that is it for this one"} for _ in range(10)] + \
           [{"text": "это очень длинный русский текст про кошек и собак"} for _ in range(4)]
    write_jsonl(tmp_path / "d.jsonl", rows)
    assert "DS-HYG-009" in ids(run(tmp_path))


def test_contam_local_levels(tmp_path):
    item = "If a train travels sixty miles in one hour how far does it travel in three hours at the same speed please answer"
    bench = write_jsonl(tmp_path / "b.jsonl", [{"question": item}, {"question": "short q"}, {"question": "completely unrelated benchmark question about volcanoes erupting on distant moons today"}])
    data = tmp_path / "data"
    data.mkdir()
    write_jsonl(data / "d.jsonl", [{"text": "intro. " + item + " Answer: 180"}, {"text": "other stuff entirely " * 9}])
    r = run(data, "--benchmark", str(bench))
    c2 = [f for f in r.findings if f.rule_id == "DS-CONTAM-002"]
    assert any(f.severity == Severity.HIGH and "exact" in f.title for f in c2)
    assert any(f.severity == Severity.INFO and "blind" in f.title for f in c2)
    assert len([f for f in c2 if f.severity != Severity.INFO]) == 1


def test_contam_local_8gram_only(tmp_path):
    item = "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen"
    bench = write_jsonl(tmp_path / "b.jsonl", [{"question": item}])
    write_jsonl(tmp_path / "d.jsonl", [{"text": "zzz one two three four five six seven eight qqq"}])
    f = [x for x in run(tmp_path / "d.jsonl", "--benchmark", str(bench)).findings if x.rule_id == "DS-CONTAM-002"]
    assert len(f) == 1 and f[0].severity == Severity.LOW and "8-gram" in f[0].title


def test_license(tmp_path):
    write_jsonl(tmp_path / "d.jsonl", [{"text": "hello world " * 5, "license": "mit"}, {"text": "all rights reserved. " * 3, "license": "cc-by-nc-4.0"},
                                       {"text": "plain " * 8, "license": "apache-2.0"}])
    r = run(tmp_path, "--license-field", "license", "--allowed-licenses", "MIT,apache-2.0")
    lic = [f for f in r.findings if f.rule_id == "DS-LIC-001"]
    assert len(lic) == 2 and any("cc-by-nc" in f.detail for f in lic)
    assert not [f for f in run(tmp_path, "--license-field", "license", "--allowed-licenses", "mit,apache-2.0,cc-by-nc-4.0").findings
                if f.title.startswith("Licence/source")]


def test_formats(tmp_path):
    (tmp_path / "a.csv").write_text("text,label\nhello csv row here,x\n")
    (tmp_path / "b.tsv").write_text("text\tlabel\nhello tsv row here\tx\n")
    (tmp_path / "c.json").write_text(json.dumps([{"text": "json one"}, {"text": "json two"}]))
    (tmp_path / "d.txt").write_text("just text")
    (tmp_path / "e.jsonl").write_text('{"text":"j1"}\n\n{"text":"j2"}\n')
    assert run(tmp_path).stats["records"] == 7
    assert run(tmp_path, "--max-records", "3").stats["records"] == 3


def test_estimate_free_and_scales(tmp_path):
    bench = write_jsonl(tmp_path / "b.jsonl", [{"question": f"q {i} " * 5} for i in range(60)])
    (tmp_path / "data").mkdir()
    write_jsonl(tmp_path / "data" / "d.jsonl", [{"text": "x " * 500}])
    a = args(tmp_path / "data", "--benchmark", str(bench))
    est = CHECK.estimate(Context(snap=StubEngine()), a)
    assert est.snap_calls >= 3 and est.uploads_bytes > 0           # 2 batches of items + 1 licence sample
    assert CHECK.estimate(Context(no_snap=True), a).snap_calls == 0


def test_snap_contamination_with_stub(tmp_path):
    bench = write_jsonl(tmp_path / "b.jsonl", [{"question": Q}, {"question": "A question that is nowhere in the data at all, honestly."}])
    data = tmp_path / "data"
    data.mkdir()
    write_jsonl(data / "d.jsonl", [{"text": "padding " * 20}, {"text": "pre " + Q + " post"}])
    eng = StubEngine()
    r = run(data, "--benchmark", str(bench), ctx=Context(snap=eng))
    c1 = [f for f in r.findings if f.rule_id == "DS-CONTAM-001"]
    assert len(c1) == 1 and c1[0].source == "snap" and c1[0].severity == Severity.HIGH and c1[0].score == 0.95
    e = c1[0].evidence[0]
    assert e.file == "d.jsonl" and e.line_start == 2 and Q in e.snippet and e.extra["window"]
    assert r.stats["calibration"]["false_positive_rate"] == 0.0 and r.usage["snap_calls"] >= 1


def test_snap_licence_and_no_snap_note(tmp_path):
    write_jsonl(tmp_path / "d.jsonl", [{"text": "Copyright. All rights reserved. " * 3}])
    r = run(tmp_path, ctx=Context(snap=StubEngine()))
    assert any(f.source == "snap" and f.rule_id == "DS-LIC-001" for f in r.findings)
    assert any("skipped" in n for n in run(tmp_path).notes)


def test_snap_failure_degrades(tmp_path):
    class Boom(StubEngine):
        def scan_windows(self, *a, **k):
            raise snap_pkg.SnapError("no credits")
    bench = write_jsonl(tmp_path / "b.jsonl", [{"question": Q}])
    write_jsonl(tmp_path / "d.jsonl", [{"text": Q}])
    r = run(tmp_path / "d.jsonl", "--benchmark", str(bench), ctx=Context(snap=Boom()))
    assert any("Snap failed" in n for n in r.notes) and "DS-CONTAM-002" in ids(r)


def test_prefiltered_mode_sends_less(tmp_path):
    bench = write_jsonl(tmp_path / "b.jsonl", [{"question": Q}])
    write_jsonl(tmp_path / "d.jsonl", [{"text": "irrelevant " * 200}, {"text": Q}])
    a = run(tmp_path / "d.jsonl", "--benchmark", str(bench), ctx=Context(snap=StubEngine()))
    b = run(tmp_path / "d.jsonl", "--benchmark", str(bench), "--contam-mode", "prefiltered", ctx=Context(snap=StubEngine()))
    assert b.usage["input_tokens"] < a.usage["input_tokens"]
    assert any(f.rule_id == "DS-CONTAM-001" for f in b.findings)


def test_truncation_hard_cap(tmp_path):
    rows = [{"text": "w " * 64} for _ in range(12)] + [{"text": f"s{i} " * (i % 5 + 1)} for i in range(12)]
    assert "DS-HYG-008" in ids(run(write_jsonl(tmp_path / "d.jsonl", rows)))


def test_with_real_fake_server(tmp_path):
    from checksnap.snap import FakeSnapServer, SnapClient, SnapEngine
    bench = write_jsonl(tmp_path / "b.jsonl", [{"question": Q}, {"question": "Never seen anywhere: purple elephants juggle quantum teapots on Tuesdays."}])
    write_jsonl(tmp_path / "d.jsonl", [{"text": "padding " * 50}, {"text": "pre " + Q + " post"}])
    with FakeSnapServer() as srv:
        eng = SnapEngine(SnapClient(api_key="test", url=srv.url, sleep=lambda s: None), cache_dir=tmp_path / "cache", workers=2)
        ctx = Context(snap=eng, cache_dir=tmp_path / "cache")
        a = args(tmp_path / "d.jsonl", "--benchmark", str(bench))
        est = CHECK.estimate(ctx, a)
        assert est.snap_calls >= 1 and srv.calls == 0          # estimate is free
        r = CHECK.run(ctx, a)
    assert r.error is None
    c1 = [f for f in r.findings if f.rule_id == "DS-CONTAM-001"]
    assert len(c1) == 1 and c1[0].score >= 0.9 and c1[0].evidence[0].line_start == 2
    assert r.stats["calibration"]["false_positive_rate"] == 0.0 and r.usage["snap_calls"] >= 1


def test_scalar_json_file_does_not_abort_check(tmp_path):
    (tmp_path / "s.json").write_text("5")
    assert run(tmp_path).error is None


def test_save_in_nested_loop_of_train_loop_is_flagged():
    from checksnap.checks.optimization.static import analyze
    src = "import torch\nfor x in dl:\n    loss.backward()\n    for p in ps:\n        torch.save(p, 'a')\n"
    assert any(f.rule_id == "OPT-ML-009" for f in analyze(src, "t.py"))
