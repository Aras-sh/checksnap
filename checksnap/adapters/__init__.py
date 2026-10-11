"""Optional wrappers for bandit, ruff and detect-secrets (--with-adapters). A missing tool is a note, never an error.

Findings get rule ids like EXT-BANDIT-B602 and are dropped when checksnap already reported the same
(file, line, rough class), so the report shows each problem once.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

from checksnap.core import Evidence, Finding, Severity

TIMEOUT_S = 60

# rough problem classes, so "bandit B602" and "SEC-004" on one line count as the same thing
_OWN = {"SEC-001": "deser", "SEC-002": "yaml", "SEC-003": "eval", "SEC-004": "shell", "SEC-005": "shell", "SEC-006": "secret",
        "SEC-007": "tmp", "SEC-008": "tls", "SEC-009": "assert", "SEC-010": "extract", "SEC-011": "sql", "SEC-012": "debug",
        "SEC-013": "bind", "SEC-014": "hash", "SEC-015": "chmod", "OPT-PY-012": "listcopy"}
_EXT = {**{c: "deser" for c in ("B301", "B302", "B614")}, "B506": "yaml", "B307": "eval", "B102": "eval",
        **{c: "shell" for c in ("B602", "B603", "B604", "B605", "B606", "B607")}, **{c: "secret" for c in ("B105", "B106", "B107")},
        "B108": "tmp", "B306": "tmp", "B501": "tls", "B101": "assert", "B202": "extract", "B608": "sql", "B201": "debug",
        "B104": "bind", "B303": "hash", "B324": "hash", "B103": "chmod", "C419": "listcopy"}
_SEV = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def add_option(parser: argparse.ArgumentParser) -> None:
    """Register --with-adapters; several checks call this on one parser, so a repeat is ignored."""
    try:
        parser.add_argument("--with-adapters", action="store_true",
                            help="also run bandit / ruff / detect-secrets if installed and merge their findings (EXT-* rule ids)")
    except argparse.ArgumentError:
        pass


def _klass(f: Finding) -> str:
    return _OWN.get(f.rule_id) or _EXT.get(f.rule_id.rsplit("-", 1)[-1]) or f.rule_id


def _command(tool: str, module: str | None = None) -> list[str] | None:
    exe = shutil.which(tool)
    if exe:
        return [exe]
    mod = module or tool
    if importlib.util.find_spec(mod) is not None:
        return [sys.executable, "-m", mod]
    return None


def _exec(cmd: list[str], cwd: Path):
    """Run low priority with a timeout; parse stdout as JSON (bandit/ruff exit 1 when they find something)."""
    nice = shutil.which("nice")
    p = subprocess.run((["nice", "-n", "10"] if nice else []) + cmd, cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT_S, stdin=subprocess.DEVNULL)
    return json.loads(p.stdout)


def _rel(path: str) -> str:
    return re.sub(r"^(\./)+", "", path.replace("\\", "/"))


def _finding(check, tool, code, sev, title, path, line, snippet="") -> Finding:
    return Finding(check, f"EXT-{tool.upper()}-{code}", sev, title, f"reported by {tool}", [Evidence(path, line, line, snippet[:200])], source=tool)


def _bandit(cmd, root, target, check):
    data = _exec(cmd + ["-r", target, "-f", "json", "-q", "-x", ",".join(f"*/{d}" for d in _SKIP)], root)
    return [_finding(check, "bandit", r["test_id"], _SEV.get(r.get("issue_severity", "").upper(), Severity.LOW), f'{r.get("test_name", r["test_id"])}: {r.get("issue_text", "")}',
                     _rel(r["filename"]), r.get("line_number"), "" if _EXT.get(r["test_id"]) == "secret" else r.get("code", "").strip())
            for r in data.get("results", [])]


def _ruff(cmd, root, target, check):
    data = _exec(cmd + ["check", target, "--select", "PERF,B,SIM,C4", "--output-format", "json", "--no-cache"], root)
    return [_finding(check, "ruff", r["code"], Severity.LOW, r.get("message", ""), _rel(r["filename"]), (r.get("location") or {}).get("row")) for r in data]


def _detect_secrets(cmd, root, target, check):
    data = _exec(cmd + ["scan", "--all-files", target], root)
    # never copy the secret: detect-secrets only gives a hash and the line, and we add no snippet
    return [_finding(check, "detect-secrets", re.sub(r"\W+", "-", s["type"]).strip("-").upper(), Severity.MEDIUM, f'Possible secret: {s["type"]}', _rel(fn), s.get("line_number"))
            for fn, hits in data.get("results", {}).items() for s in hits]


_SKIP = (".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", ".tox", ".mypy_cache", ".pytest_cache", ".checksnap-cache")
_TOOLS = {"security": [("bandit", "bandit", _bandit), ("detect-secrets", "detect_secrets", _detect_secrets)],
          "optimization": [("ruff", "ruff", _ruff)]}


def run(check: str, root: Path, own: list[Finding], keep: Callable[[str], bool] = lambda rel: True) -> tuple[list[Finding], list[str]]:
    """External findings for `check` ("security" | "optimization") that are not already in `own`, plus notes."""
    root = Path(root)
    cwd, target = (root.parent, root.name) if root.is_file() else (root, ".")
    seen = {(f.evidence[0].file, f.evidence[0].line_start, _klass(f)) for f in own if f.evidence}
    out: list[Finding] = []
    notes: list[str] = []
    for name, module, fn in _TOOLS.get(check, []):
        cmd = _command(name, module)
        if cmd is None:
            notes.append(f"{name} not found, skipped")
            continue
        try:
            found = fn(cmd, cwd, target, check)
        except subprocess.TimeoutExpired:
            notes.append(f"{name} timed out after {TIMEOUT_S} s, skipped")
            continue
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            notes.append(f"{name} failed ({type(e).__name__}), skipped")
            continue
        n = 0
        for f in found:
            key = (f.evidence[0].file, f.evidence[0].line_start, _klass(f))
            if key in seen or not keep(key[0] or ""):
                continue
            seen.add(key)
            out.append(f)
            n += 1
        notes.append(f"{name}: {n} extra finding(s), {len(found) - n} duplicate or filtered")
    return out, notes
