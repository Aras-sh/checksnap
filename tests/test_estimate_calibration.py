import json

from checksnap.privacy import estimate_table
from checksnap.snap import SnapEngine
from checksnap.snap.calibrate import CharsPerToken, detect_kind

PY = "def f(x):\n    return {'a': [x, (x + 1) * 2]}\n" * 10


def test_detect_kind():
    assert detect_kind(name="a.py") == "code" and detect_kind(name="a.json") == "json" and detect_kind(name="r.md") == "prose"
    assert detect_kind(PY) == "code"
    assert detect_kind('{"a": "b", "c": "d"}' * 50) == "json"
    assert detect_kind("This is plain English prose about nothing in particular. " * 20) == "prose"


def test_benchmark_case_not_underestimated(snap_client):
    # benchmark: 12,936 tokens at 3.3 chars/token -> ~42.7k chars; real usage was 30,913
    e = SnapEngine(snap_client).estimate(int(12_936 * 3.3), 1, "code")
    assert e.input_tokens >= 30_913
    assert e.notes.startswith("13k-33k tokens")


def test_calibrated_per_kind_and_legacy_file(snap_client, tmp_path):
    (tmp_path / "calibration.json").write_text(json.dumps({"chars": 6000, "tokens": 2000}))   # old format loads
    c = CharsPerToken(tmp_path)
    assert c.value == 3.0 and c.bounds("code")[1] == 1.3        # no per-kind data: seed
    c.add(4000, 2000, "code")
    c.save()
    opt, cons = CharsPerToken(tmp_path).bounds("code")
    assert abs(opt - 2.0) < 1e-9 and cons < opt
    assert CharsPerToken(tmp_path).bounds("prose")[1] == 3.0


def test_gate_prints_range(snap_client):
    e = SnapEngine(snap_client).estimate(100_000, 10)
    assert "k tokens" in estimate_table([("bank", e)]) and "-" in e.notes
