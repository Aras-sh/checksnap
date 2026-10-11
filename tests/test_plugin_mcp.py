"""Drive mcp_server.py over stdio, the way Claude Code does."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"


class Server:
    def __init__(self, env=None):
        e = {**os.environ, "SUBQ_API_KEY": "", **(env or {})}
        self.p = subprocess.Popen([sys.executable, str(ROOT / "mcp_server.py")], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=e)
        self.n = 0

    def rpc(self, method, params=None):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def tool(self, name, **args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})["result"]
        return r["content"][0]["text"], r.get("isError", False)

    def close(self):
        self.p.stdin.close()
        self.p.wait(10)


@pytest.fixture
def srv():
    s = Server()
    yield s
    s.close()


def test_handshake_and_tools(srv):
    assert srv.rpc("initialize", {"protocolVersion": "2025-03-26"})["result"]["serverInfo"]["name"] == "checksnap"
    assert srv.rpc("ping")["result"] == {}
    names = {t["name"] for t in srv.rpc("tools/list")["result"]["tools"]}
    assert names == {"checksnap_list", "checksnap_scan", "checksnap_detail", "checksnap_estimate"}
    assert "error" in srv.rpc("nope")


def test_list_is_one_line_per_check(srv):
    text, err = srv.tool("checksnap_list")
    assert not err and "security" in text and "docker" in text and len(text) <= 3000
    assert all(len(l) <= 120 for l in text.splitlines()[1:])


def test_scan_finds_known_rules_and_is_capped(srv):
    text, err = srv.tool("checksnap_scan", path=str(FIX), top=100, min_severity="info")
    assert not err and len(text) <= 3000
    assert "DOC-008" in text and "CFG-009" in text
    assert text.splitlines()[-1].startswith("Next: checksnap_detail")
    assert "```" not in text


def test_top_limits_lines(srv):
    text, _ = srv.tool("checksnap_scan", path=str(FIX / "docker"), top=2)
    rows = [l for l in text.splitlines() if l.split(" ")[0] in ("HIGH", "MEDIUM", "LOW", "INFO")]
    assert len(rows) == 2 and "more groups" in text


def test_dedupe_per_rule_and_file(srv):
    text, _ = srv.tool("checksnap_scan", path=str(FIX / "security"), top=100, min_severity="info")
    keys = [tuple(l.split(" ")[1:3][:1] + [l.split(" ")[2].split(":")[0]]) for l in text.splitlines()
            if l.split(" ")[0] in ("HIGH", "MEDIUM", "LOW", "INFO")]
    assert len(keys) == len(set(keys))


def test_auto_selects_by_tree(srv, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:latest\nUSER root\n")
    (tmp_path / "q.sql").write_text("delete from t;\n")
    text, _ = srv.tool("checksnap_scan", path=str(tmp_path))
    checks = text.splitlines()[0].split("checks: ")[1].split(" |")[0].split(",")
    assert set(checks) == {"docker", "sql", "repo"}
    (tmp_path / "a.py").write_text("import random\nx = random.random()\n")
    text, _ = srv.tool("checksnap_scan", path=str(tmp_path))
    assert {"optimization", "security", "reproducibility"} <= set(text.splitlines()[0].split("checks: ")[1].split(" |")[0].split(","))
    assert "bank" not in text.splitlines()[0] and "dataset" not in text.splitlines()[0]


def test_unknown_check_is_error(srv):
    text, err = srv.tool("checksnap_scan", path=str(FIX), checks=["nope"])
    assert err and "unknown check" in text


def test_detail_uses_cache_and_has_fix(srv):
    srv.tool("checksnap_scan", path=str(FIX / "docker"))
    text, err = srv.tool("checksnap_detail", rule_id="DOC-008")
    assert not err and "DOC-008" in text and "fix:" in text and len(text.splitlines()) <= 20
    assert srv.tool("checksnap_detail", rule_id="NOPE-1")[1]


def test_snap_refused_without_confirm(srv):
    text, err = srv.tool("checksnap_scan", path=str(FIX / "security"), checks=["optimization"], use_snap=True)
    assert text.startswith("REFUSED") and "api.subq.ai" in text and "confirm_upload" in text
    assert "B" in text and "upload" in text.lower()


def test_snap_confirmed_without_key_is_skipped(srv):
    text, _ = srv.tool("checksnap_scan", path=str(FIX / "security"), checks=["optimization"],
                       use_snap=True, confirm_upload=True)
    assert "SUBQ_API_KEY not set" in text


def test_estimate_is_free_table(srv):
    text, err = srv.tool("checksnap_estimate", path=str(FIX / "security"), checks=["optimization"])
    assert not err and "api.subq.ai" in text and "TOTAL" in text


def test_local_checks_work_without_httpx(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:latest\n")
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "httpx.py").write_text("raise ImportError('no httpx')\n")
    s = Server({"PYTHONPATH": str(shim)})
    try:
        text, err = s.tool("checksnap_scan", path=str(tmp_path), min_severity="info")
        assert not err and "DOC-" in text
    finally:
        s.close()
