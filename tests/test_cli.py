from __future__ import annotations

import json

import pytest

from checksnap import cli
from checksnap.core import REGISTRY, Check, CheckResult, CostEstimate, Evidence, Finding, Severity, register
from checksnap.privacy import confirm_upload, estimate_table, load_api_key
from checksnap.config import ConfigError, load_config
from checksnap.report import render, summarize

SEEN: dict = {}


@pytest.fixture(autouse=True)
def dummy(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SUBQ_API_KEY", raising=False)
    monkeypatch.setattr("checksnap.core.REGISTRY", dict(REGISTRY))
    import checksnap.core as core
    SEEN.clear()

    @core.register
    class Dummy(Check):
        name, flag, summary = "dummy", "--check-dummy", "dummy check"

        def add_arguments(self, parser):
            parser.add_argument("--sev", default="HIGH")

        def estimate(self, ctx, args):
            return CostEstimate(1, 1000, 2048)

        def run(self, ctx, args):
            SEEN.update(path=args.check_dummy, snap=ctx.snap, no_snap=ctx.no_snap)
            f = Finding("dummy", "DUM-001", Severity.parse(args.sev), "bad thing", "detail", [Evidence("a.py", 3, 4, "x=1")],
                        score=0.9, source="snap", fix_hint="fix it")
            return CheckResult("dummy", [f], stats={"calibration": {"fp_rate": 0.0}}, usage={"snap_calls": 2, "input_tokens": 50})


def test_list_and_no_check(capsys):
    assert cli.main(["--list-checks"]) == 0
    assert "--check-dummy" in capsys.readouterr().out
    assert cli.main([]) == 2


def test_bad_usage():
    assert cli.main(["--format", "nope"]) == 2
    assert cli.main(["--check-dummy", "--workers", "0"]) == 2


def test_exit_codes_and_fail_on():
    assert cli.main(["--check-dummy", "--no-snap"]) == 1
    assert cli.main(["--check-dummy", "--no-snap", "--sev", "LOW"]) == 0
    assert cli.main(["--check-dummy", "--no-snap", "--fail-on", "none"]) == 0
    assert cli.main(["--check-dummy", "--no-snap", "--sev", "LOW", "--fail-on", "low"]) == 1


def test_check_all_gives_path(capsys):
    cli.main(["--check-all", "somewhere", "--no-snap"])
    assert SEEN["path"] == "somewhere" and SEEN["no_snap"] is True


def test_missing_key_skips_snap_with_note(capsys):
    cli.main(["--check-dummy", "--yes", "--fail-on", "none"])
    assert SEEN["snap"] is None
    assert "SUBQ_API_KEY not set" in capsys.readouterr().out


def test_dry_run_spends_nothing(capsys):
    assert cli.main(["--check-dummy", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "api.subq.ai" in out and "2.0 KB" in out and not SEEN


def test_non_interactive_without_yes_skips(monkeypatch, capsys):
    monkeypatch.setenv("SUBQ_API_KEY", "k-test")
    monkeypatch.setattr(cli, "_make_engine", lambda key, args: (object(), ""))
    cli.main(["--check-dummy", "--fail-on", "none"])
    assert SEEN["snap"] is None and "non-interactive" in capsys.readouterr().out
    cli.main(["--check-dummy", "--yes", "--fail-on", "none"])
    assert SEEN["snap"] is not None


def test_check_error_exit_3():
    @register
    class Boom(Check):
        name, flag, summary = "boom", "--check-boom", "x"
        def estimate(self, ctx, args): return CostEstimate()
        def run(self, ctx, args): raise RuntimeError("kaput")
    assert cli.main(["--check-boom", "--no-snap"]) == 3


def test_config_file_and_cli_wins(tmp_path):
    (tmp_path / ".checksnap.toml").write_text('fail-on = "none"\nsev = "LOW"\nbogus = 1\n')
    assert cli.main(["--check-dummy", "--no-snap"]) == 0
    assert cli.main(["--check-dummy", "--no-snap", "--fail-on", "low"]) == 1
    assert cli.main(["--check-dummy", "--no-snap", "--config", "missing.toml"]) == 2


def test_out_file_json(tmp_path):
    cli.main(["--check-dummy", "--no-snap", "--format", "json", "-o", "r.json"])
    d = json.loads((tmp_path / "r.json").read_text())
    assert d["results"][0]["findings"][0]["rule_id"] == "DUM-001" and d["summary"]["snap_calls"] == 2


def test_explain(capsys):
    assert cli.main(["--explain", "NOPE-1"]) == 2


def test_config_errors(tmp_path):
    (tmp_path / "bad.toml").write_text("= nope")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "bad.toml")
    assert load_config(None) == {}


def test_api_key_from_dotenv(tmp_path):
    (tmp_path / ".env").write_text("OTHER=1\nexport SUBQ_API_KEY='abc'\n")
    assert load_api_key({}, tmp_path) == "abc"
    assert load_api_key({"SUBQ_API_KEY": "env"}, tmp_path) == "env"
    assert load_api_key({}, tmp_path / "nowhere") is None


def test_confirm_upload():
    e = CostEstimate(1, 1, 5 * 2**20)
    assert confirm_upload(e, yes=True, interactive=False)[0]
    assert not confirm_upload(e, yes=False, interactive=False)[0]
    asked = []
    assert confirm_upload(e, yes=False, interactive=True, ask=lambda q: asked.append(q) or "y")[0]
    assert "5.0 MB to api.subq.ai" in asked[0]
    assert not confirm_upload(e, yes=False, interactive=True, ask=lambda q: "")[0]
    assert "TOTAL" in estimate_table([("a", e)])
