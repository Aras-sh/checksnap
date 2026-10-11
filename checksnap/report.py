"""Render CheckResults as text, markdown, json or SARIF 2.1.0. Pure functions: no I/O, no globals."""
from __future__ import annotations

import json
from typing import Any, Sequence

from . import __version__
from .core import CheckResult, Finding, Severity, severity_counts

FORMATS = ("text", "json", "md", "sarif")
_COLOR = {Severity.HIGH: "31", Severity.MEDIUM: "33", Severity.LOW: "36", Severity.INFO: "2"}
_SARIF_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}


def summarize(results: Sequence[CheckResult]) -> dict[str, Any]:
    """Totals across checks. `calibration` is passed through from each check's stats (decoy FP rate, canary recall)."""
    findings = [f for r in results for f in r.findings]
    return {
        "severity_counts": severity_counts(findings),
        "findings": len(findings),
        "snap_calls": sum(r.usage.get("snap_calls", 0) for r in results),
        "input_tokens": sum(r.usage.get("input_tokens", 0) for r in results),
        "calibration": {r.check: r.stats["calibration"] for r in results if r.stats.get("calibration")},
        "errors": {r.check: r.error for r in results if r.error},
        "notes": [f"[{r.check}] {n}" for r in results for n in r.notes],
    }


def _c(text: str, code: str, color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if color else text


def _where(f: Finding) -> str:
    for ev in f.evidence:
        if ev.file:
            return ev.file + (f":{ev.line_start}" if ev.line_start else "")
    return ""


def _ordered(r: CheckResult) -> list[Finding]:
    return sorted(r.findings, key=lambda f: (-f.severity, f.rule_id, _where(f)))


def to_text(results: Sequence[CheckResult], color: bool = False) -> str:
    out: list[str] = []
    for r in results:
        out.append(_c(f"== {r.check} ({r.duration_s:.1f}s) ==", "1", color))
        if r.error:
            out.append(_c(f"ERROR: {r.error}", "31", color))
        for f in _ordered(r):
            score = f" score={f.score:.2f}" if f.score is not None else ""
            out.append(f"{_c(f'[{f.severity.name}]', _COLOR[f.severity], color)} {f.rule_id} {f.title} "
                       f"({f.source}{score}) {_where(f)}".rstrip())
            if f.detail:
                out.append(f"    {f.detail}")
            for ev in f.evidence:
                win = ev.extra.get("window")
                if ev.snippet:
                    out.append(f"    > {ev.snippet.strip()[:300]!r}" + (f" window={win}" if win else ""))
                elif win:
                    out.append(f"    window={win}")
            if f.fix_hint:
                out.append(f"    fix: {f.fix_hint}")
        if not r.findings and not r.error:
            out.append("no findings")
    out += ["", *_summary_lines(summarize(results))]
    return "\n".join(out) + "\n"


def _summary_lines(s: dict[str, Any]) -> list[str]:
    counts = s["severity_counts"]
    lines = ["Summary: " + ", ".join(f"{counts[n]} {n.lower()}" for n in ("HIGH", "MEDIUM", "LOW", "INFO")),
             f"Snap usage: {s['snap_calls']} calls, {s['input_tokens']:,} input tokens"]
    for check, cal in s["calibration"].items():
        lines.append(f"Calibration [{check}]: " + (", ".join(f"{k}={v}" for k, v in cal.items())
                                                   if isinstance(cal, dict) else str(cal)))
    lines.append("Flags are candidates, not proof; see the calibration line for this run's measured false-positive rate.")
    lines += [f"Note {n}" for n in s["notes"]]
    return lines


def to_md(results: Sequence[CheckResult]) -> str:
    out = ["# checksnap report", ""]
    for r in results:
        out += [f"## {r.check}", ""]
        if r.error:
            out += [f"**ERROR:** {r.error}", ""]
        if r.findings:
            out += ["| Severity | Rule | Title | Where | Source | Score |", "|---|---|---|---|---|---|"]
            for f in _ordered(r):
                cells = [f.severity.name, f.rule_id, f.title, _where(f), f.source,
                         "" if f.score is None else f"{f.score:.2f}"]
                out.append("| " + " | ".join(c.replace("|", "\\|").replace("\n", " ") for c in cells) + " |")
            out.append("")
            for f in _ordered(r):
                if f.detail or f.fix_hint:
                    out.append(f"- **{f.rule_id}** {f.detail} {('Fix: ' + f.fix_hint) if f.fix_hint else ''}".rstrip())
            out.append("")
        elif not r.error:
            out += ["No findings.", ""]
    s = summarize(results)
    out += ["## Summary", "", *[f"- {line}" for line in _summary_lines(s)], ""]
    return "\n".join(out)


def to_json(results: Sequence[CheckResult]) -> str:
    return json.dumps({"version": __version__, "results": [r.to_dict() for r in results],
                       "summary": summarize(results)}, indent=2, default=str) + "\n"


def to_sarif(results: Sequence[CheckResult]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    for r in results:
        for f in r.findings:
            rules.setdefault(f.rule_id, {"id": f.rule_id, "name": f.rule_id, "shortDescription": {"text": f.title},
                                         "help": {"text": f.fix_hint or f.title}})
            locs = []
            for ev in f.evidence:
                if not ev.file:
                    continue
                loc: dict[str, Any] = {"artifactLocation": {"uri": ev.file}}
                if ev.line_start:
                    region: dict[str, Any] = {"startLine": ev.line_start}
                    if ev.line_end:
                        region["endLine"] = ev.line_end
                    loc["region"] = region
                locs.append({"physicalLocation": loc})
            res: dict[str, Any] = {"ruleId": f.rule_id, "level": _SARIF_LEVEL[f.severity],
                                   "message": {"text": f.title + (f": {f.detail}" if f.detail else "")},
                                   "locations": locs, "properties": {"source": f.source, "check": f.check}}
            if f.score is not None:
                res["properties"]["score"] = f.score
            sarif_results.append(res)
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "checksnap", "version": __version__,
                                         "rules": list(rules.values())}},
                     "results": sarif_results}]}
    return json.dumps(doc, indent=2) + "\n"


def render(results: Sequence[CheckResult], fmt: str, color: bool = False) -> str:
    if fmt == "text":
        return to_text(results, color)
    return {"md": to_md, "json": to_json, "sarif": to_sarif}[fmt](results)
