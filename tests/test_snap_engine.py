from __future__ import annotations

import pytest

from checksnap.snap import (BudgetExceeded, FakeSnapServer, Question, SnapAuthError, SnapClient, SnapEngine,
                            SnapQuotaError, Window)


def q(i: str, needle: str) -> Question:
    return Question(i, f"Is this in the text? [[needle]]{needle}[[/needle]]", "present", "absent")


TEXT = ("filler line\n" * 2000) + "the secret zebra recipe\n" + ("more filler\n" * 2000)


def test_scan_finds_needle_and_hides_extras(snap_engine, fake_snap):
    r = snap_engine.scan(TEXT, [q("hit", "secret zebra recipe"), q("miss", "purple lion")])
    assert r.per_question["hit"].max_score == 0.95 and r.per_question["miss"].max_score == 0.04
    assert set(r.per_question) == {"hit", "miss"} and r.calls == 1 and not r.partial
    assert r.calibration.decoys == 8 and r.calibration.false_positive_rate(0.5) == 0.0
    assert r.calibration.canaries == 1 and r.calibration.canary_recall(0.5) == 1.0
    assert fake_snap.requests[0]["n_questions"] == 2 + 8 + 1


def test_no_decoys_no_canaries(snap_client, fake_snap):
    e = SnapEngine(snap_client, decoys=0, canaries=False)
    r = e.scan("zebra", [q("a", "zebra")])
    assert fake_snap.requests[0]["n_questions"] == 1 and r.calibration.false_positive_rate(0.5) is None
    assert r.calibration.canary_recall(0.5) is None


def test_cache_second_scan_free(snap_engine, fake_snap):
    qs = [q("hit", "zebra")]
    first = snap_engine.scan(TEXT, qs)
    n = fake_snap.calls
    second = snap_engine.scan(TEXT, qs)
    assert fake_snap.calls == n and second.calls == 0 and second.cached_calls == first.calls
    assert second.per_question["hit"].max_score == first.per_question["hit"].max_score
    assert second.calibration.decoys == first.calibration.decoys


def test_batching_over_per_call(snap_engine, fake_snap):
    qs = [q(f"q{i}", f"needle{i}") for i in range(60)]     # per_call = 55 -> 2 calls
    r = snap_engine.scan("needle3 and needle59", qs)
    assert r.calls == 2 and r.per_question["q3"].max_score == 0.95 and r.per_question["q59"].max_score == 0.95
    assert list(r.per_question) == [x.id for x in qs]


def test_multiple_windows_ordered_and_best_window(snap_client):
    e = SnapEngine(snap_client, workers=4, window_chars=1000, overlap_chars=100)
    text = ("x" * 99 + "\n") * 50 + "NEEDLE" + ("y" * 99 + "\n") * 5
    r = e.scan(text, [q("n", "NEEDLE")])
    ws = r.per_question["n"].window_scores
    assert r.windows == len(ws) > 3 and [w[0] for w in ws] == sorted(w[0] for w in ws)
    s, en = r.per_question["n"].best_window
    assert "NEEDLE" in text[s:en]


def test_scan_windows_custom(snap_engine):
    ws = [Window(0, 5, "alpha"), Window(10, 14, "beta")]
    r = snap_engine.scan_windows(ws, [q("b", "beta")])
    assert r.per_question["b"].best_window == (10, 14) and r.windows == 2


def test_reserved_and_duplicate_ids(snap_engine):
    with pytest.raises(ValueError):
        snap_engine.scan("x", [q("__decoy_1", "x")])
    with pytest.raises(ValueError):
        snap_engine.scan("x", [q("a", "x"), q("a", "y")])


def test_empty_inputs(snap_engine, fake_snap):
    assert snap_engine.scan("", [q("a", "x")]).calls == 0
    assert snap_engine.scan("text", []).calls == 0 and fake_snap.calls == 0


def test_estimate_free_and_sane(snap_engine, fake_snap):
    e = snap_engine.estimate(1_000_000, 100)
    assert e.snap_calls == 2 * 2 and e.uploads_bytes == (1_000_000 + 5000) * 2 and e.input_tokens > 0
    assert snap_engine.estimate(0, 5).snap_calls == 0 and fake_snap.calls == 0


def test_calibration_learned_and_persisted(snap_client, tmp_path):
    e = SnapEngine(snap_client, cache_dir=tmp_path)
    e.scan("a" * 30_000, [q("a", "zzz")])
    assert (tmp_path / "calibration.json").exists()
    assert abs(SnapEngine(snap_client, cache_dir=tmp_path).cpt.value - 3.0) < 0.1     # fake counts 1 token / 3 chars


def test_budget_exceeded_has_partial(snap_client, fake_snap):
    e = SnapEngine(snap_client, workers=1, window_chars=3000, overlap_chars=100, budget_tokens=2500)
    with pytest.raises(BudgetExceeded) as ei:
        e.scan("x" * 20_000, [q("a", "x")])
    p = ei.value.partial
    assert p.partial and 0 < p.calls < 7 and fake_snap.calls == p.calls and e.spent_tokens <= 2500


def test_budget_checked_before_any_call(snap_client, fake_snap):
    e = SnapEngine(snap_client, budget_tokens=10)
    with pytest.raises(BudgetExceeded) as ei:
        e.scan("x" * 1000, [q("a", "x")])
    assert fake_snap.calls == 0 and ei.value.partial.calls == 0


@pytest.mark.parametrize("status,exc", [(401, SnapAuthError), (402, SnapQuotaError), (403, SnapAuthError)])
def test_fatal_errors_abort(status, exc):
    with FakeSnapServer(fail=status) as srv:
        e = SnapEngine(SnapClient("k", url=srv.url), workers=1, window_chars=3000, overlap_chars=100)
        with pytest.raises(exc):
            e.scan("x" * 30_000, [q("a", "x")])
        assert srv.calls == 1        # pending windows cancelled


def test_too_large_halves(snap_client):
    with FakeSnapServer(fail="too-large-above-6000") as srv:
        e = SnapEngine(SnapClient("k", url=srv.url), workers=1, window_chars=20_000, overlap_chars=200)
        text = "a" * 7000 + "NEEDLE" + "b" * 9000
        r = e.scan(text, [q("n", "NEEDLE")])
        assert not r.partial and r.per_question["n"].max_score == 0.95
        assert all(w[1] - w[0] <= 6000 for w in r.per_question["n"].window_scores)
        assert srv.requests[0]["status"] == 400 and srv.ok_calls >= 3


def test_too_large_hopeless_becomes_error(snap_client):
    with FakeSnapServer(fail="too-large-above-10") as srv:
        r = SnapEngine(SnapClient("k", url=srv.url), canaries=False, decoys=0).scan("x" * 9000, [q("a", "x")])
        assert r.partial and r.errors and r.per_question["a"].max_score == 0.0 and srv.calls < 30


def test_rate_limit_retried_transparently():
    with FakeSnapServer(fail="429-once") as srv:
        e = SnapEngine(SnapClient("k", url=srv.url, sleep=lambda s: None))
        assert e.scan("zebra", [q("a", "zebra")]).per_question["a"].max_score == 0.95


def test_canary_missing_is_measured():
    with FakeSnapServer(scorer=lambda s, qu: 0.04) as srv:
        r = SnapEngine(SnapClient("k", url=srv.url)).scan("zebra", [q("a", "zebra")])
        assert r.calibration.canary_recall(0.5) == 0.0


def test_localize(snap_engine, fake_snap):
    text = "a" * 100_000 + "NEEDLE" + "b" * 100_000
    hit = snap_engine.localize(Window(0, len(text), text), q("n", "NEEDLE"))
    assert hit and len(hit.text) <= 2000 and "NEEDLE" in hit.text
    assert snap_engine.localize(Window(0, 3000, "a" * 3000), q("n", "NEEDLE")) is None


def test_localize_budget_stop(snap_client):
    e = SnapEngine(snap_client, budget_tokens=5)
    assert e.localize(Window(0, 9000, "NEEDLE" * 1500), q("n", "NEEDLE")) is None


def test_progress_called(snap_engine):
    msgs = []
    snap_engine.scan("zebra", [q("a", "zebra")], label="L", progress=msgs.append)
    assert msgs and msgs[-1].startswith("L")


def test_deterministic_with_many_workers(snap_client):
    e = SnapEngine(snap_client, workers=8, window_chars=500, overlap_chars=50)
    text = "".join(f"w{i} " for i in range(1000))
    a = e.scan(text, [q("a", "w500 ")]).per_question["a"].window_scores
    b = SnapEngine(snap_client, workers=1, window_chars=500, overlap_chars=50).scan(text, [q("a", "w500 ")]).per_question["a"].window_scores
    assert a == b
