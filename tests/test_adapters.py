import argparse
import json
import stat

import pytest

from checksnap import adapters
from checksnap.checks import optimization, security
from checksnap.core import Context

BANDIT = {"results": [
    {"test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true", "issue_severity": "HIGH", "issue_text": "shell", "filename": "./a.py", "line_number": 3, "code": "x"},
    {"test_id": "B105", "test_name": "hardcoded_password_string", "issue_severity": "LOW", "issue_text": "pw", "filename": "./a.py", "line_number": 1, "code": "pw = 'hunter2hunter2'"},
    {"test_id": "B101", "test_name": "assert_used", "issue_severity": "LOW", "issue_text": "assert", "filename": "./a.py", "line_number": 9, "code": "assert x"}]}
RUFF = [{"code": "PERF401", "message": "use a comprehension", "filename": "a.py", "location": {"row": 4, "column": 1}}]


def fake(tmp_path, monkeypatch, name, payload):
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    f = bin_ / name
    f.write_text(f"#!/bin/sh\necho '{json.dumps(payload)}'\nexit 1\n")
    f.chmod(f.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_}:/usr/bin:/bin")


def args(**kw):
    return argparse.Namespace(**{"check_all": None, "with_adapters": True, **kw})


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "proj"
    p.mkdir()
    (p / "a.py").write_text("pw = 'hunter2hunter2'\nimport subprocess\nsubprocess.run(f'ls {pw}', shell=True)\nassert pw\nx = 1\nassert x\n")
    return p


def test_bandit_merged_and_deduped(tmp_path, monkeypatch, proj):
    fake(tmp_path, monkeypatch, "bandit", BANDIT)
    monkeypatch.setattr(adapters, "_command", lambda t, m=None: [adapters.shutil.which(t)] if t == "bandit" else None)
    a = args(check_security=str(proj))
    res = security.SecurityCheck().run(Context(), a)
    ids = [f.rule_id for f in res.findings]
    assert "EXT-BANDIT-B602" not in ids          # same line+class as SEC-004
    b105 = next(f for f in res.findings if f.rule_id == "EXT-BANDIT-B105")
    assert b105.evidence[0].snippet == ""        # secret text is never copied
    assert "EXT-BANDIT-B101" in ids              # line 9: new
    ext = next(f for f in res.findings if f.rule_id == "EXT-BANDIT-B101")
    assert ext.source == "bandit"
    assert any("detect-secrets not found, skipped" in n for n in res.notes)


def test_missing_tool_is_a_note(monkeypatch, proj):
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setattr(adapters, "_command", lambda t, m=None: None)
    res = security.SecurityCheck().run(Context(), args(check_security=str(proj)))
    assert res.error is None and "bandit not found, skipped" in res.notes


def test_ruff_on_optimization(tmp_path, monkeypatch, proj):
    fake(tmp_path, monkeypatch, "ruff", RUFF)
    res = optimization.OptimizationCheck().run(Context(no_snap=True), args(check_optimization=str(proj), static_only=True))
    f = next(f for f in res.findings if f.rule_id == "EXT-RUFF-PERF401")
    assert (f.evidence[0].file, f.evidence[0].line_start, f.source) == ("a.py", 4, "ruff")


def test_bad_json_and_timeout_do_not_crash(tmp_path, monkeypatch, proj):
    fake(tmp_path, monkeypatch, "ruff", RUFF)
    (tmp_path / "bin" / "ruff").write_text("#!/bin/sh\necho not json\n")
    out, notes = adapters.run("optimization", proj, [])
    assert out == [] and "ruff failed (JSONDecodeError), skipped" in notes
    (tmp_path / "bin" / "ruff").write_text("#!/bin/sh\nsleep 5\n")
    monkeypatch.setattr(adapters, "TIMEOUT_S", 0.2)
    assert "ruff timed out after 0.2 s, skipped" in adapters.run("optimization", proj, [])[1]


def test_option_registered_once():
    p = argparse.ArgumentParser()
    adapters.add_option(p)
    adapters.add_option(p)
    assert p.parse_args(["--with-adapters"]).with_adapters
