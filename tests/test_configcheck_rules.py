"""Every config rule: one positive (right id, right line) and one negative source; secrets are never printed in full."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

import pytest

from checksnap.checks.configcheck import RULES, ConfigCheck
from checksnap.checks.configcheck.scan import analyze
from checksnap.core import Context

FIX = Path(__file__).parent / "fixtures" / "configcheck"
KEY = "abcd1234efgh5678ijkl"
# rule id -> (file name, positive text, expected line, negative text)
CASES = {
    "CFG-001": (".env", "A=1\nB=2\nA=3\n", 3, "A=1\nB=2\n"),
    "CFG-002": (".env.production", "DEBUG=true\n", 1, "DEBUG=false\n"),
    "CFG-003": (".env", f"API_KEY={KEY}\n", 1, "API_KEY=${API_KEY}\nAPI_KEY_PATH=/x\nMAX_TOKENS=4096\n"),
    "CFG-004": (".env", "DB_PASSWORD=changeme\n", 1, "DB_PASSWORD=<your password>\n"),
    "CFG-005": ("settings.prod.yml", "db:\n  host: localhost\n", 2, "db:\n  host: db.internal.acme.io\n"),
    "CFG-007": (".env", "HOST=db \n", 1, "HOST=db\nHOST2=\"db \"\n"),
    "CFG-008": (".env", "NAME=my app\n", 1, "NAME=\"my app\"\nURL=a # comment\n"),
    "CFG-009": ("a.json", '{"a": 1,}\n', 1, '{"a": 1}\n'),
    "CFG-010": ("a.yml", "a:\n\tb: 1\n", 2, "a:\n  b: 1\n"),
    "CFG-011": ("a.yml", "url: http://api.acme-corp.com/x\n", 1, "url: http://localhost:8000/x\nxmlns: http://www.w3.org/x\nu: https://a.com\n"),
    "CFG-012": ("a.ini", "[db]\nconnect_timeout = -1\n", 2, "[db]\nconnect_timeout = 30\nread_timeout_ms = 30000\npool_size = 5\n"),
    "CFG-013": ("a.yml", "cors:\n  allowed_origins: [\"*\"]\n", 2, "cors:\n  allowed_origins: [\"https://a.com\"]\nglob: '*.py'\n"),
}


@pytest.mark.parametrize("rid", sorted(CASES))
def test_rule(rid):
    name, pos, line, neg = CASES[rid]
    kind = {"json": "json", "yml": "yaml", "ini": "kv"}.get(name.rsplit(".", 1)[-1], "env")
    hits = [f for f in analyze(pos, name, kind) if f.rule_id == rid]
    assert hits and hits[0].evidence[0].line_start == line
    assert not [f for f in analyze(neg, name, kind) if f.rule_id == rid]
    assert not [f for f in analyze(neg, name, kind) if f.rule_id in ("CFG-003", "CFG-004")] or rid in ("CFG-003", "CFG-004")


def test_secret_masked():
    out = analyze(f"API_KEY={KEY}\n", ".env", "env")
    dumped = repr([f.to_dict() for f in out])
    assert KEY not in dumped and "abcd" in dumped and "len 20" in dumped


def test_toml_invalid_and_valid():
    assert [f.rule_id for f in analyze("a = \n", "a.toml", "toml")] == ["CFG-009"]
    assert not analyze("[a]\nb = 1\n", "a.toml", "toml")


def test_json_duplicate_key():
    assert [f.rule_id for f in analyze('{"a": 1, "a": 2}', "a.json", "json")] == ["CFG-001"]


def test_yaml_list_items_not_duplicates():
    assert not analyze("s:\n  - name: a\n    p: 1\n  - name: b\n    p: 2\n", "a.yml", "yaml")


def test_example_files_not_flagged_for_secrets():
    assert not analyze(f"API_KEY={KEY}\nDB_PASSWORD=admin\n", ".env.example", "env")


def test_cfg014_world_readable(tmp_path):
    k = tmp_path / "server.key"
    k.write_text("x")
    k.chmod(0o644)
    text = "ssl_certificate_key: server.key\n"
    assert [f.rule_id for f in analyze(text, "a.yml", "yaml", tmp_path)] == ["CFG-014"]
    k.chmod(0o600)
    assert not analyze(text, "a.yml", "yaml", tmp_path)
    assert [f.rule_id for f in analyze("key_file: /tmp/x.key\n", "a.yml", "yaml", tmp_path)] == ["CFG-014"]


def _run(path):
    return ConfigCheck().run(Context(no_snap=True), argparse.Namespace(check_config=str(path), include_tests=False))


def test_cfg006_and_cfg015_on_fixture():
    res = _run(FIX / "bad")
    ids = {f.rule_id for f in res.findings}
    assert {"CFG-006", "CFG-015"} <= ids
    c15 = [f for f in res.findings if f.rule_id == "CFG-015"]
    assert [f.evidence[0].snippet for f in c15] == ["MISSING_VAR"]     # OK_DEF has a default
    assert len([f for f in res.findings if f.rule_id == "CFG-006"]) == 2


def test_clean_fixture_has_no_findings():
    assert _run(FIX / "good").findings == []


def test_all_rules_covered():
    assert set(RULES) == {f"CFG-{i:03d}" for i in range(1, 16)}
    assert set(CASES) | {"CFG-006", "CFG-014", "CFG-015"} == set(RULES)


def test_missing_path():
    assert _run("/nonexistent/zzz").error


def test_github_secrets_reference_is_not_a_plaintext_secret(tmp_path):
    from checksnap.checks.configcheck.scan import PLACEHOLDER
    assert PLACEHOLDER.match("${{ secrets.API_TOKEN }}")
    assert PLACEHOLDER.match("${DB_PASSWORD}")
