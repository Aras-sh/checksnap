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
    # real run on the 60-file project: 13,689 chars of state, 152 questions of ~359 chars, one window, 3 batches -> 30,913 tokens
    e = SnapEngine(snap_client).estimate(13_689, 152, "code", q_chars=152 * 359, n_windows=1)
    assert 30_913 <= e.input_tokens <= 2 * 30_913
    assert e.snap_calls == 3 and "each call carries its questions" in e.notes


def test_questions_dominate_when_state_is_small(snap_client):
    one, many = (SnapEngine(snap_client).estimate(1000, n, "code", n_windows=1) for n in (1, 55))
    assert many.input_tokens > 5 * one.input_tokens


def test_calibrated_per_kind_and_stale_file(snap_client, tmp_path):
    (tmp_path / "calibration.json").write_text(json.dumps({"chars": 6000, "tokens": 2000}))   # old format folded question tokens in: ignored
    c = CharsPerToken(tmp_path)
    assert c.value == 3.3 and c.bounds("code")[1] == 2.5        # no usable data: seed
    c.add(4000, 2000, "code")
    c.save()
    opt, cons = CharsPerToken(tmp_path).bounds("code")
    assert abs(opt - 2.0) < 1e-9 and cons < opt
    assert CharsPerToken(tmp_path).bounds("prose")[1] == 3.0


def test_gate_prints_range(snap_client):
    e = SnapEngine(snap_client).estimate(100_000, 10)
    assert "k tokens" in estimate_table([("bank", e)]) and "-" in e.notes


def test_budget_counts_question_tokens(snap_client):
    import pytest
    from checksnap.snap import BudgetExceeded, Question
    qs = [Question(f"q{i}", "Is there a bug of this kind in the code? " * 8, "yes", "no") for i in range(20)]
    with pytest.raises(BudgetExceeded):
        SnapEngine(snap_client, budget_tokens=1500).scan("x = 1\n", qs)      # ~6 chars of state, but ~2k tokens of questions
