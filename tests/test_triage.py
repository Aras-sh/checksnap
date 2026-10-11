"""--triage (free) replaces --snap-verify. Offline check against the hand-graded table A of benchmarks/compare/verify_grading.md."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import pytest

from checksnap import cli, triage
from checksnap.core import Evidence, Finding, Severity

CMP = Path(__file__).resolve().parent.parent / "benchmarks" / "compare"
SRC = CMP / "data" / "t1" / "verify_vuln"


def test_graded_table_a():
    """0 of 16 real findings lowered, >= 27 of 31 correct downgrades (docs/REDESIGN.md roadmap 3)."""
    raw = CMP / "raw" / "verify_vulnerable_12.json"
    if not (SRC.is_dir() and raw.is_file()):
        pytest.skip("benchmark data not present")
    rows = re.findall(r"^\| \d+ \| (\S+) (\S+?):(\d+) \| (BAD|correct)", (CMP / "verify_grading.md").read_text(), re.M)
    assert len(rows) == 47
    verdict = {(r, f, int(ln)): v for r, f, ln, v in rows}
    fs = []
    for d in json.load(raw.open())["result"]["findings"]:
        e = d["evidence"][0]
        key = (d["rule_id"], e["file"], e["line_start"])
        if key in verdict:
            fs.append((verdict[key], Finding("security", d["rule_id"], Severity.MEDIUM, d["title"],
                                             evidence=[Evidence(e["file"], e["line_start"], e["line_end"])])))
    assert len(fs) == 47
    triage.lower(SRC, [f for _, f in fs])
    bad_lowered = sum(v == "BAD" and f.severity == Severity.INFO for v, f in fs)
    good_lowered = sum(v == "correct" and f.severity == Severity.INFO for v, f in fs)
    assert bad_lowered == 0 and good_lowered >= 27, (bad_lowered, good_lowered)


def test_name_resolution_uses_nearest_assignment(tmp_path):
    (tmp_path / "a.py").write_text("import subprocess\ncmd = 'pwd'\nsubprocess.call(cmd, shell=True)\n"
                                   "cmd = 'ls' + f()\nsubprocess.call(cmd, shell=True)\n"
                                   "def g(cmd):\n    subprocess.call(cmd, shell=True)\n")
    fs = [Finding("security", "EXT-BANDIT-B602", Severity.HIGH, "t", evidence=[Evidence("a.py", n, n)]) for n in (3, 5, 7)]
    triage.lower(tmp_path, fs)
    assert [f.severity for f in fs] == [Severity.INFO, Severity.HIGH, Severity.HIGH]


def test_snap_verify_is_deprecated_alias(tmp_path, capsys):
    (tmp_path / "a.py").write_text("import os\nos.system('ls')\n")
    out = tmp_path / "r.json"
    code = cli.main(["--check-security", str(tmp_path), "--snap-verify", "--format", "json", "-o", str(out), "--yes"])
    res = json.loads(out.read_text())["results"][0]
    assert code == 0 and res["stats"]["triage"]["lowered"] == 1 and any("deprecated" in n for n in res["notes"])
    assert res["usage"]["snap_calls"] == 0
