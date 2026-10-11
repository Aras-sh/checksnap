"""--snap-verify: severity lowered (never deleted) for findings Snap scores < 0.5; estimate is free; skipped without an engine."""
from __future__ import annotations

import argparse
import re

from checksnap import verify
from checksnap.checks.optimization import OptimizationCheck
from checksnap.checks.security import SecurityCheck
from checksnap.core import Context, Severity
from checksnap.snap import FakeSnapServer, SnapClient, SnapEngine
from checksnap.snap.fake_server import default_scorer

REAL = "import os\nos.system('ls ' + p)\n"
SAFE = "import os\n# example only\nos.system('ls ' + p)\n"


def scorer(state: str, q: dict) -> float:
    m = re.search(r"EXCERPT (\d+)'", q.get("instructions", ""))
    if not m:
        return default_scorer(state, q)         # decoys and canary behave normally
    block = state.split(f"### EXCERPT {m.group(1)}\n")[1].split("### EXCERPT")[0]
    return 0.1 if "example only" in block else 0.9


def project(tmp_path, n_real=1, n_safe=1):
    for i in range(n_real):
        (tmp_path / f"real{i}.py").write_text(REAL)
    for i in range(n_safe):
        (tmp_path / f"safe{i}.py").write_text(SAFE)
    return tmp_path


def engine(srv, tmp_path):
    return SnapEngine(SnapClient(api_key="k", url=srv.url, sleep=lambda s: None), cache_dir=tmp_path / "c", workers=1)


def args(path, **kw):
    return argparse.Namespace(check_security=str(path), check_optimization=str(path), snap_verify=True, include_tests=False, **kw)


def test_security_lowers_unlikely_and_keeps_all(tmp_path):
    root = project(tmp_path / "p", 2, 2) if (tmp_path / "p").mkdir() is None else None
    with FakeSnapServer(scorer) as srv:
        res = SecurityCheck().run(Context(snap=engine(srv, tmp_path)), args(root))
        assert srv.ok_calls == 1                       # 4 excerpts, one window, one call
    v = res.stats["verify"]
    assert len(res.findings) == 4 and v["checked"] == 4 and v["lowered"] == 2
    assert v["before"]["MEDIUM"] == 4 and v["after"] == {**v["before"], "MEDIUM": 2, "LOW": 2}
    low = [f for f in res.findings if f.severity == Severity.LOW]
    assert all(verify.NOTE in f.detail and f.evidence[0].file.startswith("safe") for f in low)
    assert res.usage["snap_calls"] == 1


def test_batches_of_55(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    project(root, 60, 0)
    with FakeSnapServer(scorer) as srv:
        res = SecurityCheck().run(Context(snap=engine(srv, tmp_path)), args(root))
        assert srv.ok_calls == 2 and res.stats["verify"]["checked"] == 60 and res.stats["verify"]["lowered"] == 0


def test_estimate_is_free_and_counts_excerpts(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    project(root, 1, 1)
    with FakeSnapServer(scorer) as srv:
        ctx = Context(snap=engine(srv, tmp_path))
        e = SecurityCheck().estimate(ctx, args(root))
        assert srv.calls == 0
    assert e.snap_calls == 1 and 0 < e.uploads_bytes < 2 * verify.MAX_CHARS * 2
    assert SecurityCheck().estimate(ctx, argparse.Namespace(check_security=str(root), snap_verify=False)).uploads_bytes == 0


def test_skipped_without_engine(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    project(root, 1, 0)
    res = SecurityCheck().run(Context(no_snap=True), args(root))
    assert "verify" not in res.stats and res.findings[0].severity == Severity.MEDIUM
    assert any("snap-verify skipped" in n for n in res.notes)


def test_secrets_are_never_uploaded(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    (root / "k.py").write_text("API_KEY = 'sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2'\n")
    with FakeSnapServer(scorer) as srv:
        res = SecurityCheck().run(Context(snap=engine(srv, tmp_path)), args(root))
        assert srv.calls == 0
    assert res.findings and res.findings[0].severity > Severity.LOW


def test_optimization_verifies_static_findings(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    (root / "m.py").write_text("def f(xs, ys):\n    ys_list = list(ys)\n    out = []\n    for x in xs:\n        if x in ys_list:\n            out.append(x)\n    return out\n")
    check = OptimizationCheck()
    with FakeSnapServer(lambda s, q: 0.1 if "EXCERPT" in q.get("instructions", "") else default_scorer(s, q)) as srv:
        ctx = Context(snap=engine(srv, tmp_path))
        a = args(root, static_only=True, snap_only=False, profile="auto", include=None, exclude=None, max_files=100)
        res = check.run(ctx, a)
        assert check.estimate(ctx, a).snap_calls == 1
    v = res.stats["verify"]
    assert v["candidates"] >= 1 and v["lowered"] == v["checked"] >= 1
    assert sum(v["before"].values()) == sum(v["after"].values())


def test_adapter_secret_findings_are_never_uploaded(tmp_path):
    from checksnap.core import Evidence, Finding, Severity
    from checksnap.verify import candidates
    (tmp_path / "a.py").write_text("x = 1\n")
    mk = lambda rid: Finding("security", rid, Severity.MEDIUM, "t", "d", [Evidence("a.py", 1, 1, "")], source="x")  # noqa: E731
    fs = [mk("EXT-DETECT-SECRETS-HEX-HIGH-ENTROPY-STRING"), mk("EXT-BANDIT-B105"), mk("EXT-BANDIT-B602")]
    assert [f.rule_id for f, _ in candidates(tmp_path, fs)] == ["EXT-BANDIT-B602"]
