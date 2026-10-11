"""--check-dependencies: local analysis of dependency manifests against the code. Free, no Snap, no network."""
from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from pathlib import Path

from checksnap.core import Check, CheckResult, Context, CostEstimate, Evidence, Finding, register

from .parsers import Dep, Opt, Parsed, is_manifest, norm, parse_file
from .rules import RULES, RuleInfo  # noqa: F401  (RULES is the catalog the CLI reads)

SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", "build", "dist", ".tox", ".mypy_cache", ".pytest_cache", ".checksnap-cache", "site-packages"}
MAX_PY_BYTES = 2_000_000

# HEURISTIC, hand-maintained: oldest (major, minor) we would still recommend pinning. Not a vulnerability database.
MIN_VERSIONS: dict[str, tuple[int, int]] = {
    "numpy": (1, 24), "torch": (2, 0), "tensorflow": (2, 12), "pillow": (10, 0), "requests": (2, 31),
    "django": (4, 2), "flask": (2, 3), "urllib3": (2, 0), "pyyaml": (6, 0),
}

# import name -> distribution name, only where they differ (the rest is matched by normalization)
IMPORT_TO_DIST = {"PIL": "pillow", "yaml": "pyyaml", "cv2": "opencv-python", "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
                  "dateutil": "python-dateutil", "dotenv": "python-dotenv", "jwt": "pyjwt", "OpenSSL": "pyopenssl", "attr": "attrs",
                  "skimage": "scikit-image", "serial": "pyserial", "docx": "python-docx", "git": "gitpython", "magic": "python-magic",
                  "Crypto": "pycryptodome", "MySQLdb": "mysqlclient", "psycopg2": "psycopg2-binary", "zmq": "pyzmq", "mpl_toolkits": "matplotlib"}
ALIAS_GROUPS = [{"opencv-python", "opencv-python-headless", "opencv-contrib-python", "opencv-contrib-python-headless"},
                {"psycopg2", "psycopg2-binary"}, {"pillow", "pillow-simd"}]
# namespace packages whose import root says nothing about the distribution
NAMESPACE_ROOTS = {"google", "azure", "backports", "ruamel", "zope"}
TOOL_DISTS = {"setuptools", "wheel", "pip", "pytest", "pytest-cov", "black", "ruff", "flake8", "mypy", "isort", "pylint", "tox", "twine", "build", "pre-commit"}


def _root(args: argparse.Namespace) -> Path:
    v = getattr(args, "check_dependencies", None)
    if not isinstance(v, (str, os.PathLike)):
        v = getattr(args, "check_all", None)
    return Path(v if isinstance(v, (str, os.PathLike)) else ".")


def _walk(root: Path):
    if root.is_file():
        yield root.parent, [root.name]
        return
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        yield Path(dirpath), sorted(names)


def _is_test(rel: str) -> bool:
    p = Path(rel)
    return any(x in ("tests", "test") for x in p.parts[:-1]) or p.name.startswith("test_") or p.stem.endswith("_test") or p.name == "conftest.py"


def _dev_file(rel: str) -> bool:
    return bool(re.search(r"dev|test|doc|lint|ci", Path(rel).name.lower()))


def _version(spec: str) -> tuple[int, int] | None:
    m = re.search(r"(?:^|,)===?(\d+)(?:\.(\d+))?", spec)
    return (int(m.group(1)), int(m.group(2) or 0)) if m else None


def _strength(spec: str) -> str:
    toks = [t for t in spec.split(",") if t]
    if not toks:
        return "none"
    if any(t.startswith(("==", "===", "~=", "^", "~")) for t in toks):
        return "pinned"
    return "bounded" if any(t.startswith("<") for t in toks) else "lower"


def _git_ref(url: str) -> str | None:
    """Ref after `@` in the path of a VCS URL (not the `user@` in ssh://git@host)."""
    if "://" not in url:
        return None
    path = url.split("://", 1)[1].split("#")[0]
    path = path.split("/", 1)[1] if "/" in path else ""
    return path.split("@", 1)[1] if "@" in path else None


def _imports(py: Path) -> tuple[set[str], str | None]:
    try:
        tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError, RecursionError):
        return set(), f"could not parse {py.name}"
    guarded: set[int] = set()        # imports inside try/except ImportError are optional by design
    for n in ast.walk(tree):
        if isinstance(n, ast.Try) and any("Import" in ast.dump(h.type) or "ModuleNotFound" in ast.dump(h.type) for h in n.handlers if h.type):
            guarded |= {id(c) for b in n.body for c in ast.walk(b)}
    found: set[str] = set()
    for n in ast.walk(tree):
        if id(n) in guarded:
            continue
        if isinstance(n, ast.Import):
            found |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
            found.add(n.module.split(".")[0])
    return found, None


@register
class DependenciesCheck(Check):
    name = "dependencies"
    flag = "--check-dependencies"
    summary = "Audit dependency manifests: loose pins, conflicts, undeclared/unused imports, risky index and git URLs"
    uses_snap = False

    def estimate(self, ctx: Context, args: argparse.Namespace) -> CostEstimate:
        return CostEstimate(notes="local analysis only; nothing is uploaded")

    def run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        return self.timed(lambda: self._run(args))

    def _run(self, args: argparse.Namespace) -> CheckResult:
        res = CheckResult(self.name)
        root = _root(args)
        if not root.exists():
            res.error = f"path not found: {root}"
            return res
        base = root.parent if root.is_file() else root
        parsed: dict[str, Parsed] = {}
        pyfiles: list[tuple[str, Path]] = []
        local: set[str] = set()
        pyver_file = False
        for d, names in _walk(root):
            for n in names:
                p = d / n
                rel = p.relative_to(base).as_posix()
                if is_manifest(n) or (d.name == "requirements" and n.endswith(".txt")):
                    try:
                        parsed[rel] = parse_file(p, rel)
                    except Exception as e:  # noqa: BLE001  (bad TOML etc. must not kill the run)
                        res.notes.append(f"could not parse {rel}: {type(e).__name__}: {e}")
                elif n == ".python-version":
                    pyver_file = True
                elif n.endswith(".py"):
                    local.add(p.stem)
                    if "__init__.py" in names:
                        local.add(d.name)
                    if p.stat().st_size <= MAX_PY_BYTES and not _is_test(rel):
                        pyfiles.append((rel, p))
        res.stats["manifests"] = sorted(parsed)
        if not parsed:
            res.notes.append("no dependency manifest found (requirements*.txt, pyproject.toml, setup.cfg, environment.yml, Pipfile)")
            return res
        deps = [x for p in parsed.values() for x in p.deps]
        res.stats["dependencies"] = len(deps)
        add = lambda rid, detail, file, line, snippet="": res.findings.append(self._f(rid, detail, file, line, snippet))  # noqa: E731

        for rel, p in parsed.items():
            for o in p.opts:
                self._opt(o, add)
            seen: dict[tuple[str, str], Dep] = {}
            for d in p.deps:
                self._dep(d, add)
                k = (norm(d.name), d.group)
                if k in seen and not (d.marker or seen[k].marker):
                    add("DEP-004", f"`{d.name}` is already declared on line {seen[k].line}", rel, d.line, d.name + d.spec)
                seen.setdefault(k, d)

        by_name: dict[str, list[Dep]] = {}
        for d in deps:
            if not d.marker:
                by_name.setdefault(norm(d.name), []).append(d)
        for name, ds in sorted(by_name.items()):
            first = ds[0]
            for other in ds[1:]:
                if other.file != first.file and other.spec != first.spec and not (other.url or first.url):
                    add("DEP-003", f"`{name}`: `{first.spec or '(any)'}` in {first.file}:{first.line} vs `{other.spec or '(any)'}` in {other.file}:{other.line}",
                        other.file, other.line, f"{other.name}{other.spec}")
                    break

        if not any(p.pythons for p in parsed.values()) and not pyver_file:
            add("DEP-012", "no Python version constraint in any manifest", sorted(parsed)[0], 1)

        self._imports(res, parsed, deps, pyfiles, local, add)
        res.findings.sort(key=lambda f: (-int(f.severity), f.evidence[0].file or "", f.evidence[0].line_start or 0, f.rule_id))
        res.stats["by_rule"] = {}
        for f in res.findings:
            res.stats["by_rule"][f.rule_id] = res.stats["by_rule"].get(f.rule_id, 0) + 1
        return res

    @staticmethod
    def _f(rid: str, detail: str, file: str, line: int, snippet: str) -> Finding:
        r = RULES[rid]
        return Finding("dependencies", rid, r.severity, r.title, detail, [Evidence(file, line, line, snippet)], source="local", fix_hint=r.fix_hint)

    def _opt(self, o: Opt, add) -> None:
        if o.kind in ("index-url", "find-links") and o.value.startswith("http://"):
            add("DEP-008", f"{o.kind} uses plain http: {o.value}", o.file, o.line, o.value)
        elif o.kind == "extra-index-url":
            add("DEP-009", f"extra index {o.value}", o.file, o.line, o.value)
            if o.value.startswith("http://"):
                add("DEP-008", f"extra-index-url uses plain http: {o.value}", o.file, o.line, o.value)
        elif o.kind in ("trusted-host", "verify-ssl-off"):
            add("DEP-010", f"TLS checks disabled for {o.value}", o.file, o.line, o.value)

    def _dep(self, d: Dep, add) -> None:
        if d.url:
            if d.url.startswith(("git+", "hg+", "svn+", "bzr+")):
                ref = _git_ref(d.url)
                if not (ref and re.fullmatch(r"[0-9a-fA-F]{7,40}", ref)):
                    add("DEP-007", f"`{d.name}` installs from {d.url} with {'ref ' + ref if ref else 'no ref'}, not a commit hash", d.file, d.line, d.url)
            elif d.url.startswith("http://"):
                add("DEP-008", f"`{d.name}` downloaded over plain http: {d.url}", d.file, d.line, d.url)
            return
        s = _strength(d.spec)
        if s == "none":
            add("DEP-001", f"`{d.name}` has no version constraint", d.file, d.line, d.name)
        elif s == "lower":
            add("DEP-002", f"`{d.name}{d.spec}` has no upper bound", d.file, d.line, d.name + d.spec)
        v, mn = _version(d.spec), MIN_VERSIONS.get(norm(d.name))
        if v and mn and v < mn:
            add("DEP-011", f"`{d.name}` pinned to {v[0]}.{v[1]}, below the heuristic minimum {mn[0]}.{mn[1]}", d.file, d.line, d.name + d.spec)

    def _imports(self, res: CheckResult, parsed, deps: list[Dep], pyfiles, local: set[str], add) -> None:
        if not pyfiles:
            return
        stdlib = set(sys.stdlib_module_names)
        used: dict[str, tuple[str, str]] = {}          # import root -> first file
        for rel, p in pyfiles:
            names, err = _imports(p)
            if err:
                res.notes.append(err)
            for n in names:
                used.setdefault(n, (rel, n))
        declared = {norm(d.name) for d in deps}

        def dists(n: str) -> set[str]:
            c = {norm(IMPORT_TO_DIST.get(n, n)), norm(n)}
            for g in ALIAS_GROUPS:
                if c & g:
                    c |= g
            return c
        res.stats["imports"] = len(used)
        for n, (rel, _) in sorted(used.items()):
            if n in stdlib or n in local or n in NAMESPACE_ROOTS or n.startswith("_") or n == "__future__":
                continue
            if not dists(n) & declared:
                add("DEP-005", f"`import {n}` but no manifest declares it", rel, 1, n)
        import_cands = set().union(*(dists(n) for n in used))
        for d in deps:
            k = norm(d.name)
            if d.group != "main" or _dev_file(d.file) or k in TOOL_DISTS or k.startswith("types-") or d.marker or k in import_cands:
                continue
            add("DEP-006", f"`{d.name}` is declared but nothing imports it", d.file, d.line, d.name + d.spec)
