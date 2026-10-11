from __future__ import annotations

import json

import pytest

from checksnap.core import CheckResult, Evidence, Finding, Severity
from checksnap.report import FORMATS, render, summarize


def _results():
    f1 = Finding("opt", "OPT-PY-001", Severity.MEDIUM, "slow | loop", "d", [Evidence("x.py", 5, 6, "s")], fix_hint="h")
    f2 = Finding("opt", "OPT-ML-001", Severity.HIGH, "sync", score=0.91, source="snap", evidence=[Evidence(extra={"window": [0, 9]})])
    return [CheckResult("opt", [f1, f2], notes=["Snap skipped: --no-snap"], usage={"snap_calls": 3, "input_tokens": 7},
                        stats={"calibration": {"decoy_fp_rate": 0.0}}),
            CheckResult("ds", error="broke")]


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_renders(fmt):
    out = render(_results(), fmt)
    assert "OPT-ML-001" in out and "Snap skipped" in out or fmt in ("json", "sarif")


def test_text_orders_by_severity_and_colors():
    plain = render(_results(), "text")
    assert plain.index("OPT-ML-001") < plain.index("OPT-PY-001") and "\033" not in plain
    assert "ERROR: broke" in plain and "decoy_fp_rate=0.0" in plain
    assert "\033[" in render(_results(), "text", color=True)


def test_md_escapes_pipes():
    assert "slow \\| loop" in render(_results(), "md")


def test_json_schema():
    d = json.loads(render(_results(), "json"))
    assert d["results"][0]["check"] == "opt" and d["summary"]["severity_counts"]["HIGH"] == 1
    assert d["summary"]["errors"] == {"ds": "broke"} and d["summary"]["input_tokens"] == 7


def test_sarif():
    d = json.loads(render(_results(), "sarif"))
    run = d["runs"][0]
    assert d["version"] == "2.1.0" and {r["id"] for r in run["tool"]["driver"]["rules"]} == {"OPT-PY-001", "OPT-ML-001"}
    by = {r["ruleId"]: r for r in run["results"]}
    assert by["OPT-ML-001"]["level"] == "error" and by["OPT-ML-001"]["locations"] == []
    loc = by["OPT-PY-001"]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "x.py" and loc["region"] == {"startLine": 5, "endLine": 6}


def test_summarize_empty():
    assert summarize([])["findings"] == 0
