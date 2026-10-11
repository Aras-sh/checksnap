"""The optimization check end to end: file collection, estimate, static-only, and the Snap layer on the fake server."""
from __future__ import annotations

import argparse

import pytest

from checksnap.checks.optimization import OptimizationCheck, collect, snap_layer
from checksnap.core import Context, REGISTRY, Severity
from checksnap.snap import FakeSnapServer, SnapClient, SnapEngine
from checksnap.snap.fake_server import default_scorer

MARK = "SLOW_PATTERN_MARKER"


def make_args(root, **kw):
    ns = argparse.Namespace(check_optimization=str(root), profile="auto", include=None, exclude=None, include_tests=False,
                            max_files=2000, static_only=False, snap_only=False)
    ns.__dict__.update(kw)
    return ns


@pytest.fixture
def project(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "a.py").write_text("s = ''\nfor x in xs:\n    s += str(x)\n")
    (tmp_path / "app" / "b.py").write_text(f"def fetch(i):\n    return requests.get(i)  # {MARK}\n\n" + "x = 1\n" * 50)
    (tmp_path / "app" / "c.js").write_text("console.log(1)\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("for i in range(len(x)):\n    pass\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "z.js").write_text("1")
    (tmp_path / "app" / "broken.py").write_text("def (:\n")
    return tmp_path


def test_registered():
    assert REGISTRY["optimization"].flag == "--check-optimization"


def test_add_arguments_parse():
    p = argparse.ArgumentParser()
    OptimizationCheck().add_arguments(p)
    a = p.parse_args(["--profile", "ml", "--include", "*.py", "--exclude", "x*", "--static-only", "--max-files", "5"])
    assert a.profile == "ml" and a.include == ["*.py"] and a.static_only and a.max_files == 5


def test_collect_filters(project):
    _, files, notes = collect(make_args(project))
    assert [r for r, _ in files] == ["app/a.py", "app/b.py", "app/broken.py", "app/c.js"]
    assert "tests/test_a.py" in [r for r, _ in collect(make_args(project, include_tests=True))[1]]
    assert [r for r, _ in collect(make_args(project, include=["*.js"]))[1]] == ["app/c.js"]
    assert "app/a.py" not in [r for r, _ in collect(make_args(project, exclude=["a.py"]))[1]]
    _, capped, n = collect(make_args(project, max_files=2))
    assert len(capped) == 2 and n


def test_static_only_run_and_estimate(project):
    chk, ctx = OptimizationCheck(), Context(no_snap=True)
    est = chk.estimate(ctx, make_args(project))
    assert est.snap_calls == 0 and est.uploads_bytes == 0
    res = chk.run(ctx, make_args(project))
    assert res.error is None and any(f.rule_id == "OPT-PY-001" and f.evidence[0].file == "app/a.py" for f in res.findings)
    assert any("broken.py" in n for n in res.notes) and any("Snap layer skipped" in n for n in res.notes)
    assert not any(f.evidence[0].file == "tests/test_a.py" for f in res.findings)


def test_missing_path():
    res = OptimizationCheck().run(Context(no_snap=True), make_args("/nonexistent/zzz"))
    assert res.error


def test_single_file_target(project):
    res = OptimizationCheck().run(Context(no_snap=True), make_args(project / "app" / "a.py"))
    assert [f.rule_id for f in res.findings] == ["OPT-PY-001"]


def test_pack_headers_and_split():
    files = [("a.py", "x = 1\n" * 10), ("big.py", "line\n" * 400), ("b.py", "y = 2\n")]
    import checksnap.snap as sm
    windows, spans = snap_layer.pack(files, 1200, sm)
    assert all(len(w.text) <= 1200 for w in windows)
    assert "### FILE: a.py\n" in windows[0].text
    assert sum(1 for s in spans if s.rel == "big.py") > 1
    # offsets are contiguous across windows and every span lies inside its window
    assert windows[1].start == windows[0].end
    for s in spans:
        w = windows[s.window]
        assert w.start <= s.start < s.end <= w.end
        assert w.text[s.start - w.start:].startswith("### FILE: ")
    parts = [s for s in spans if s.rel == "big.py"]
    assert parts[1].first_line > 1


def test_questions_bank():
    qs = snap_layer.questions(__import__("checksnap.snap", fromlist=["x"]))
    assert len(qs) >= 25 and len({q.id for q in qs}) == len(qs)
    assert all(q.id.startswith("OPT-SNAP-") and q.instructions and q.true and q.false for q in qs)


def _scorer(target_idx: int):
    """Fires one bank question when MARK is in the state; everything else (decoys/canaries) uses the default scorer."""
    qid = f"OPT-SNAP-{target_idx:03d}"
    inst = snap_layer.SNAP_RULES[target_idx - 1].instruction

    def score(state: str, q: dict) -> float:
        if q.get("instructions") == inst:
            return 0.93 if MARK in state else 0.03
        if "[[needle]]" in q.get("instructions", ""):
            return default_scorer(state, q)
        return 0.03
    return qid, score


def test_snap_layer_on_fake_server(project, tmp_path):
    qid, scorer = _scorer(2)
    with FakeSnapServer(scorer=scorer) as srv:
        client = SnapClient(api_key="test-key", url=srv.url, sleep=lambda s: None)
        eng = SnapEngine(client, cache_dir=tmp_path / "cache", workers=2)
        chk, ctx = OptimizationCheck(), Context(snap=eng, threshold=0.5)
        args = make_args(project)
        est = chk.estimate(ctx, args)
        assert est.snap_calls >= 1 and est.uploads_bytes > 0
        res = chk.run(ctx, args)
        snap = [f for f in res.findings if f.source == "snap"]
        assert [f.rule_id for f in snap] == [qid]
        f = snap[0]
        assert f.score == pytest.approx(0.93) and f.severity == Severity.HIGH
        ev = f.evidence[0]
        assert ev.file == "app/b.py" and ev.extra["window"] and ev.line_start == 2     # lexical hint pins the line
        assert res.stats["snap"]["false_positive_rate"] == 0.0 and res.stats["snap"]["canary_recall"] == 1.0
        assert res.usage["snap_calls"] >= 1
        # static findings are still there and ranking is severity first
        assert any(x.source == "static" for x in res.findings)
        sevs = [int(x.severity) for x in res.findings]
        assert sevs == sorted(sevs, reverse=True)
        # second run is free: cache
        calls = srv.calls
        chk.run(Context(snap=eng, threshold=0.5), args)
        assert srv.calls == calls
        client.close()


def test_snap_only_and_static_only_flags(project):
    ctx = Context(no_snap=True)
    res = OptimizationCheck().run(ctx, make_args(project, snap_only=True))
    assert not any(f.source == "static" for f in res.findings)
    res = OptimizationCheck().run(ctx, make_args(project, static_only=True))
    assert any("--static-only" in n for n in res.notes)


def test_snap_auth_error_becomes_note(project, tmp_path):
    with FakeSnapServer(fail=401) as srv:
        client = SnapClient(api_key="k", url=srv.url, sleep=lambda s: None)
        eng = SnapEngine(client, cache_dir=tmp_path / "c")
        res = OptimizationCheck().run(Context(snap=eng), make_args(project))
        assert any("Snap layer failed" in n for n in res.notes) and res.findings   # static findings survive
        assert res.error and "SnapAuthError" in res.error     # spec section 7: auth => exit 3
        client.close()
