"""--check-repo: repository hygiene by walking the tree. Needs no git binary and no network; Snap adds nothing here."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
from pathlib import Path

from checksnap.core import Check, CheckResult, Context, CostEstimate, Evidence, Finding, register

from .rules import RULES, RuleInfo

__all__ = ["RULES", "RuleInfo", "RepoCheck", "scan", "Gitignore"]

LARGE_BYTES = 50 * 1024 * 1024
DUP_MIN_BYTES = 1024            # smaller duplicates (empty __init__.py ...) are noise
NOTEBOOK_OUTPUT_BYTES = 500_000
MAX_TEXT_BYTES = 2_000_000
MAX_FILES = 50_000
MAX_PATH = 200
ALWAYS_SKIP = {".git", ".venv", "venv", "node_modules", ".tox", ".mypy_cache", ".pytest_cache", ".checksnap-cache"}
ARTIFACT_EXTS = {".pt", ".pth", ".ckpt", ".safetensors", ".h5", ".hdf5", ".npy", ".npz", ".zip", ".parquet", ".onnx", ".pkl", ".pickle",
                 ".bin", ".tar", ".gz", ".7z", ".tfrecord", ".feather", ".joblib"}
SECRET_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials.json", ".pgpass"}
SECRET_GLOBS = ["*.pem", "*.p12", "*.pfx", ".env", ".env.*"]
SECRET_SAFE = re.compile(r"\.(example|sample|template|dist)$")
TODO_RE = re.compile(r"\b(TODO|FIXME)\b")
# entries REPO-004 looks for: (label, path, is_dir)
EXPECTED_IGNORES = [("__pycache__/", "__pycache__", True), (".env", ".env", False), (".venv/", ".venv", True), ("runs/", "runs", True), ("data/", "data", True)]


class Gitignore:
    """Root .gitignore only, last match wins, `!` negation supported. Not a full git implementation
    (ponytail: nested .gitignore files and `[]` edge cases ignored; use `git check-ignore` if that ever matters)."""

    def __init__(self, text: str = ""):
        self.rules: list[tuple[str, bool, bool, bool]] = []      # pattern, negated, dir_only, has_slash
        for line in text.splitlines():
            line = line.rstrip("\n").strip()
            if not line or line.startswith("#"):
                continue
            neg = line.startswith("!")
            line = line[1:] if neg else line
            dir_only = line.endswith("/")
            line = line.rstrip("/")
            if line.startswith("**/"):
                line = line[3:]
            slash = "/" in line
            self.rules.append((line.lstrip("/"), neg, dir_only, slash))

    def ignored(self, rel: str, is_dir: bool = False) -> bool:
        parts = rel.split("/")
        result = False
        for pat, neg, dir_only, slash in self.rules:
            for i in range(len(parts)):
                d = i < len(parts) - 1 or is_dir
                if dir_only and not d:
                    continue
                target = "/".join(parts[:i + 1]) if slash else parts[i]
                if fnmatch.fnmatchcase(target, pat):
                    result = not neg
                    break
        return result


def _root(args: argparse.Namespace) -> Path:
    v = getattr(args, "check_repo", None)
    if not isinstance(v, (str, os.PathLike)):
        v = getattr(args, "check_all", None)
    return Path(v if isinstance(v, (str, os.PathLike)) else ".")


def _is_secret(name: str) -> bool:
    if SECRET_SAFE.search(name):
        return False
    return name in SECRET_NAMES or any(fnmatch.fnmatchcase(name, g) for g in SECRET_GLOBS)


def _mk(rule: str, detail: str = "", files: list[str] | None = None, snippet: str = "", **extra) -> Finding:
    r = RULES[rule]
    ev = [Evidence(file=f, snippet=snippet, extra=dict(extra)) for f in (files or [])[:20]]
    return Finding("repo", r.id, r.severity, r.title, detail, ev, source="local", fix_hint=r.fix_hint)


def _read_text(p: Path) -> bytes | None:
    try:
        if p.stat().st_size > MAX_TEXT_BYTES:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    return None if b"\0" in data[:8192] else data


def _hash(p: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def scan(root: Path) -> tuple[list[Finding], dict, list[str]]:
    """Walk `root` once, return (findings, stats, notes). Files covered by .gitignore are not walked: they are not committed."""
    findings: list[Finding] = []
    notes: list[str] = []
    gi_path = root / ".gitignore"
    gi_text = gi_path.read_text(encoding="utf-8", errors="replace") if gi_path.is_file() else ""
    gi = Gitignore(gi_text)
    files: list[tuple[str, Path, int]] = []
    broken: list[str] = []
    seen_dirs: set[str] = set()
    present = {label: False for label, _, _ in EXPECTED_IGNORES}
    case: dict[tuple[str, str], list[str]] = {}
    for dirpath, dirs, names in os.walk(root):
        base = Path(dirpath)
        reld = base.relative_to(root).as_posix()
        reld = "" if reld == "." else reld
        keep = []
        for d in sorted(dirs):
            rel = f"{reld}/{d}" if reld else d
            if os.path.islink(base / d):
                if not (base / d).exists():
                    broken.append(rel)
                continue
            for label, nm, is_dir in EXPECTED_IGNORES:
                if is_dir and d == nm:
                    present[label] = True
            if d in ALWAYS_SKIP or gi.ignored(rel, True):
                continue
            keep.append(d)
        dirs[:] = keep
        for n in sorted(names + keep):
            case.setdefault((reld, n.lower()), []).append(f"{reld}/{n}" if reld else n)
        for n in sorted(names):
            p = base / n
            rel = f"{reld}/{n}" if reld else n
            if n == ".env":
                present[".env"] = True
            if os.path.islink(p):
                if not p.exists():
                    broken.append(rel)
                continue
            if gi.ignored(rel):
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            files.append((rel, p, size))
        if len(files) > MAX_FILES:
            notes.append(f"more than {MAX_FILES} files; the rest of the tree was not checked")
            break
    rels = [r for r, _, _ in files]

    # ignore-file hygiene
    if not gi_path.is_file():
        findings.append(_mk("REPO-003"))
    else:
        missing = [label for label, nm, is_dir in EXPECTED_IGNORES if present[label] and not gi.ignored(nm, is_dir)]
        if missing:
            findings.append(_mk("REPO-004", "Missing entries: " + ", ".join(missing), [".gitignore"]))
    if not any(Path(r).name.lower().startswith("readme") for r in rels if "/" not in r):
        findings.append(_mk("REPO-006"))
    if not any(Path(r).name.lower().split(".")[0] in ("license", "licence", "copying") for r in rels if "/" not in r):
        findings.append(_mk("REPO-007"))

    todo_total, todo_by_file = 0, {}
    by_size: dict[int, list[tuple[str, Path]]] = {}
    for rel, p, size in files:
        name = Path(rel).name
        if size > LARGE_BYTES:
            findings.append(_mk("REPO-001", f"{size / 1e6:.0f} MB", [rel], size=size))
        elif Path(rel).suffix.lower() in ARTIFACT_EXTS:
            findings.append(_mk("REPO-002", f"{size / 1e6:.1f} MB", [rel], size=size))
        if _is_secret(name):
            findings.append(_mk("REPO-005", f"{name} is not covered by .gitignore", [rel]))
        if len(rel) > MAX_PATH:
            findings.append(_mk("REPO-012", f"{len(rel)} characters", [rel]))
        if size >= DUP_MIN_BYTES:
            by_size.setdefault(size, []).append((rel, p))
        if name.endswith(".ipynb"):
            try:
                nb = json.loads(p.read_text(encoding="utf-8", errors="replace")) if size < 200_000_000 else {}
                out = sum(len(json.dumps(c.get("outputs", []))) for c in nb.get("cells", []) if isinstance(c, dict))
            except (ValueError, OSError, AttributeError):
                out = 0
            if out > NOTEBOOK_OUTPUT_BYTES:
                findings.append(_mk("REPO-008", f"{out / 1e6:.1f} MB of saved outputs", [rel], output_bytes=out))
            continue
        data = _read_text(p)
        if data is None:
            continue
        crlf = data.count(b"\r\n")
        if crlf and data.count(b"\n") > crlf:
            lf = data.count(b"\n") - crlf
            findings.append(_mk("REPO-013", f"{crlf} CRLF vs {lf} LF lines", [rel]))
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        start = next((i for i, l in enumerate(lines) if l.startswith("<<<<<<< ")), None)
        if start is not None and any(l.startswith(">>>>>>> ") for l in lines[start:]):
            findings.append(_mk("REPO-014", "", [rel], snippet=lines[start][:80], line=start + 1))
        n = len(TODO_RE.findall(text))
        if n:
            todo_total += n
            todo_by_file[rel] = n

    for rel in broken:
        findings.append(_mk("REPO-009", "", [rel]))
    for group in case.values():
        if len(group) > 1:
            findings.append(_mk("REPO-011", ", ".join(group), group))

    dup_groups, wasted = [], 0
    for size, items in by_size.items():
        if len(items) < 2:
            continue
        by_hash: dict[str, list[str]] = {}
        for rel, p in items:
            h = _hash(p)
            if h:
                by_hash.setdefault(h, []).append(rel)
        for grp in by_hash.values():
            if len(grp) > 1:
                dup_groups.append((size * (len(grp) - 1), grp))
                wasted += size * (len(grp) - 1)
    for waste, grp in sorted(dup_groups, reverse=True)[:20]:
        findings.append(_mk("REPO-010", f"{len(grp)} identical copies, {waste} bytes wasted", grp, wasted_bytes=waste))

    if todo_total:
        top = sorted(todo_by_file, key=lambda f: -todo_by_file[f])
        findings.append(_mk("REPO-015", f"{todo_total} markers in {len(todo_by_file)} files", top, count=todo_total))
    stats = {"files": len(files), "duplicate_groups": len(dup_groups), "wasted_bytes": wasted, "todo_count": todo_total}
    return findings, stats, notes


@register
class RepoCheck(Check):
    name = "repo"
    flag = "--check-repo"
    summary = "Repo hygiene: big files and artifacts, .gitignore, secrets files, duplicates, conflict markers, line endings (no git needed)"
    uses_snap = False

    def estimate(self, ctx: Context, args: argparse.Namespace) -> CostEstimate:
        return CostEstimate(notes="local analysis only; nothing is uploaded")

    def run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        return self.timed(lambda: self._run(args))

    def _run(self, args: argparse.Namespace) -> CheckResult:
        res = CheckResult(self.name)
        root = _root(args)
        if not root.is_dir():
            res.error = f"directory not found: {root}"
            return res
        res.findings, res.stats, res.notes = scan(root)
        res.findings.sort(key=lambda f: (-int(f.severity), f.rule_id, f.evidence[0].file or "" if f.evidence else ""))
        res.stats["by_rule"] = {}
        for f in res.findings:
            res.stats["by_rule"][f.rule_id] = res.stats["by_rule"].get(f.rule_id, 0) + 1
        return res
