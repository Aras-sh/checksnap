"""End to end: the real CLI, in-process, against the fake Snap server. No network, no real key."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.run import findings, make_dataset, run_cli
from checksnap import cli

import random

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def data(tmp_path):
    items, planted = make_dataset(tmp_path, random.Random(1), 8, 3, 30)
    return tmp_path, items, planted


def test_dataset_no_snap_finds_planted(data, tmp_path):
    root, _, planted = data
    code, res = run_cli(["--check-dataset", str(root / "data.jsonl"), "--benchmark", str(root / "bench.jsonl"),
                         "--no-snap", "--cache-dir", str(tmp_path / "c")])
    assert code == 0
    assert sum(f["rule_id"] == "DS-CONTAM-002" for f in findings(res)) >= len(planted)


def test_dataset_snap_with_fake_server(data, tmp_path, monkeypatch):
    from checksnap.snap.fake_server import FakeSnapServer
    monkeypatch.setenv("SUBQ_API_KEY", "fake-key-for-local-server")
    root, _, planted = data
    with FakeSnapServer() as srv:
        argv = ["--check-dataset", str(root / "data.jsonl"), "--benchmark", str(root / "bench.jsonl"), "--cache-dir", str(tmp_path / "c")]
        _, res = run_cli(argv, fake_url=srv.url)
        n_calls = srv.calls
        hits = [f for f in findings(res) if f["rule_id"] == "DS-CONTAM-001"]
        assert len(hits) == len(planted) and n_calls > 0
        run_cli(argv, fake_url=srv.url)
        assert srv.calls == n_calls, "second run must be served from the cache"


def test_no_key_skips_snap_with_note(data, tmp_path, monkeypatch):
    monkeypatch.delenv("SUBQ_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)           # no .env here
    root, _, _ = data
    code, res = run_cli(["--check-dataset", str(root / "data.jsonl"), "--benchmark", str(root / "bench.jsonl")])
    assert code == 0 and any("SUBQ_API_KEY" in n for r in res for n in r["notes"])


def test_dry_run_spends_nothing(data, tmp_path, monkeypatch, capsys):
    from checksnap.snap.fake_server import FakeSnapServer
    monkeypatch.setenv("SUBQ_API_KEY", "fake-key-for-local-server")
    root, _, _ = data
    with FakeSnapServer() as srv:
        monkeypatch.setattr(cli, "_make_engine", lambda k, a: (__import__("checksnap.snap", fromlist=["x"]).SnapEngine(
            __import__("checksnap.snap", fromlist=["x"]).SnapClient(api_key=k, url=srv.url), cache_dir=tmp_path / "c"), ""))
        code = cli.main(["--check-dataset", str(root / "data.jsonl"), "--benchmark", str(root / "bench.jsonl"), "--dry-run"])
        assert code == 0 and srv.calls == 0


def test_optimization_examples():
    code, res = run_cli(["--check-optimization", str(EXAMPLES / "optimization"), "--static-only", "--no-snap"])
    ids = {f["rule_id"] for f in findings(res)}
    assert code == 0 and len(ids) >= 4


def test_dataset_examples():
    ex = EXAMPLES / "dataset"
    code, res = run_cli(["--check-dataset", str(ex / "train.jsonl"), "--benchmark", str(ex / "benchmark.jsonl"), "--no-snap"])
    ids = {f["rule_id"] for f in findings(res)}
    assert "DS-CONTAM-002" in ids and "DS-PII-001" in ids and any(i.startswith("DS-DUP") for i in ids)


def test_fail_on_exit_code(tmp_path):
    (tmp_path / "a.py").write_text("import time\nasync def f():\n    time.sleep(1)\n")
    assert cli.main(["--check-optimization", str(tmp_path), "--static-only", "--no-snap", "--format", "json", "-o", str(tmp_path / "o.json")]) == 1
    assert json.loads((tmp_path / "o.json").read_text())["results"]


def test_usage_error_and_list_and_explain(capsys):
    assert cli.main([]) == 2
    assert cli.main(["--list-checks"]) == 0
    assert cli.main(["--explain", "DS-CONTAM-001"]) == 0
    assert cli.main(["--explain", "NOPE-1"]) == 2


def test_sarif_and_md_render(tmp_path):
    (tmp_path / "a.py").write_text("import time\nasync def f():\n    time.sleep(1)\n")
    for fmt in ("sarif", "md"):
        out = tmp_path / f"o.{fmt}"
        cli.main(["--check-optimization", str(tmp_path), "--static-only", "--no-snap", "--format", fmt, "-o", str(out)])
        assert "OPT-PY-007" in out.read_text()


def test_gen_rules_and_benchmark_quick(tmp_path):
    from benchmarks import gen_rules, run
    assert gen_rules.main(["--out", str(tmp_path / "R.md")]) == 0
    assert "DS-CONTAM-001" in (tmp_path / "R.md").read_text()
    assert run.main(["--quick"]) == 0


@pytest.mark.parametrize("status", [401, 402])
def test_snap_auth_or_quota_failure_exits_3(data, tmp_path, monkeypatch, status):
    from checksnap.snap.fake_server import FakeSnapServer
    monkeypatch.setenv("SUBQ_API_KEY", "fake-key-for-local-server")
    root, _, _ = data
    with FakeSnapServer(fail=status) as srv:
        monkeypatch.setattr(cli, "_make_engine", lambda k, a: (__import__("checksnap.snap", fromlist=["x"]).SnapEngine(
            __import__("checksnap.snap", fromlist=["x"]).SnapClient(api_key=k, url=srv.url), cache_dir=tmp_path / "c"), ""))
        code = cli.main(["--check-dataset", str(root / "data.jsonl"), "--benchmark", str(root / "bench.jsonl"), "--yes", "-q"])
    assert code == 3
