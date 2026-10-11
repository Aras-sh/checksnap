"""--check-config: lint .env/ini/toml/json/yaml/properties/nginx config files. Local only, nothing is uploaded."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from checksnap.checks.optimization import SKIP_DIRS, _is_test
from checksnap.core import Check, CheckResult, Context, CostEstimate, Evidence, Finding, register

from .rules import RULES, RuleInfo  # noqa: F401
from .scan import CODE_EXTS, JSON_SKIP, analyze, code_env_refs, env_keys, is_example, kind_of, STD_VARS

MAX_BYTES = 2_000_000
JSON_MAX_BYTES = 200_000   # bigger JSON is data (COCO labels, yt-dlp dumps), not config; line lookup is quadratic on it
EXAMPLE_ENVS = (".env.example", ".env.sample", ".env.template", ".env.dist", "env.example", "example.env")


def _root(args: argparse.Namespace) -> Path:
    v = getattr(args, "check_config", None)
    if not isinstance(v, (str, os.PathLike)):
        v = getattr(args, "check_all", None)
    return Path(v if isinstance(v, (str, os.PathLike)) else ".")


def _walk(root: Path, tests: bool):
    if root.is_file():
        yield root.name, root
        return
    for dp, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(names):
            p = Path(dp) / n
            rel = p.relative_to(root).as_posix()
            if tests or not _is_test(rel):
                yield rel, p


def _finding(rid: str, rel: str, line: int | None, snippet: str, detail: str = "") -> Finding:
    r = RULES[rid]
    return Finding("config", rid, r.severity, r.title, detail, [Evidence(rel, line, line, snippet[:120])], source="static", fix_hint=r.fix_hint)


@register
class ConfigCheck(Check):
    name = "config"
    flag = "--check-config"
    summary = "Lint config files: duplicate keys, plain-text secrets, weak passwords, debug in prod, bad syntax, .env drift"
    uses_snap = False

    def estimate(self, ctx: Context, args: argparse.Namespace) -> CostEstimate:
        return CostEstimate(notes="static analysis only; nothing is uploaded")

    def run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        return self.timed(lambda: self._run(args))

    def _run(self, args: argparse.Namespace) -> CheckResult:
        res = CheckResult(self.name)
        root = _root(args)
        if not root.exists():
            res.error = f"path not found: {root}"
            return res
        tests = bool(getattr(args, "include_tests", False))
        base = root if root.is_dir() else root.parent
        envs: dict[str, dict[str, int]] = {}      # rel path -> keys, for .env / example pairs
        example_keys: set[str] = set()
        have_example = False
        code: list[tuple[str, Path]] = []
        nfiles = 0
        for rel, p in _walk(root, tests):
            name = p.name
            if p.suffix in CODE_EXTS:
                code.append((rel, p))
                continue
            kind = kind_of(name)
            if kind is None or (kind == "json" and JSON_SKIP.search(rel)) or (kind == "env" and name.lower().endswith((".py", ".md"))):
                continue
            try:
                size = p.stat().st_size
                if kind == "json" and size > JSON_MAX_BYTES:
                    continue
                if size > MAX_BYTES:
                    res.notes.append(f"skipped {rel}: over {MAX_BYTES // 1_000_000} MB")
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            nfiles += 1
            res.findings += analyze(text, rel, kind, p.parent)
            if kind == "env":
                keys = env_keys(text)
                if name.lower() in EXAMPLE_ENVS:
                    have_example = True
                    example_keys |= set(keys)
                envs[rel] = keys
        res.stats["files"] = nfiles
        for rel, keys in envs.items():       # .env vs .env.example in the same directory
            d, _, name = rel.rpartition("/")
            if name.lower() in EXAMPLE_ENVS:
                continue
            if name == ".env":
                ex = next((envs[f"{d}/{e}" if d else e] for e in (".env.example", ".env.sample", ".env.template", ".env.dist") if (f"{d}/{e}" if d else e) in envs), None)
                if ex is not None:
                    missing, extra = sorted(set(ex) - set(keys)), sorted(set(keys) - set(ex))
                    if missing:
                        res.findings.append(_finding("CFG-006", rel, 1, ", ".join(missing[:8]), f"in the example but missing from {rel}: {', '.join(missing)}"))
                    if extra:
                        res.findings.append(_finding("CFG-006", rel, 1, ", ".join(extra[:8]), f"in {rel} but missing from the example: {', '.join(extra)}"))
        if have_example:
            seen: set[str] = set()
            for rel, p in code:
                try:
                    if p.stat().st_size > MAX_BYTES:
                        continue
                    refs = code_env_refs(p.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
                for var, line in refs:
                    if var not in example_keys and var not in STD_VARS and var not in seen:
                        seen.add(var)
                        res.findings.append(_finding("CFG-015", rel, line, var, f"{var} is read here but absent from every .env.example"))
        else:
            res.notes.append("no .env.example found: CFG-015 (undocumented env vars) skipped")
        res.findings.sort(key=lambda f: (-int(f.severity), f.evidence[0].file or "", f.evidence[0].line_start or 0, f.rule_id))
        res.stats["by_rule"] = {}
        for f in res.findings:
            res.stats["by_rule"][f.rule_id] = res.stats["by_rule"].get(f.rule_id, 0) + 1
        res.notes.append("static analysis only (no Snap layer); secrets are masked to 4 characters + length")
        return res
