"""--triage: free, deterministic downgrade of findings that are provably harmless. No Snap call, no network.

Replaces --snap-verify (docs/REDESIGN.md, roadmap 3). Lowers to INFO, never deletes:
  - command execution (eval/exec, os.system, subprocess shell/Popen) whose command argument is constant. A variable counts
    as constant only if its nearest earlier assignment in the same scope is a plain constant assignment at the top level
    of that scope (so `command = "ls" + f()` stays flagged and a later `command = 'pwd'` is lowered)
  - import-only notices (bandit B403, B404)
  - crypt METHOD_BLOWFISH under B324
  - extractall(members=[]) under B202 / SEC-010
Never touches verify=False, chmod, tar filters, hashes or config families: they are not in the rule sets below.
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path

from .core import CheckResult, Finding, Severity, severity_counts

EXEC = {"SEC-003", "SEC-004", "SEC-005", "EXT-BANDIT-B102", "EXT-BANDIT-B307", "EXT-BANDIT-B602", "EXT-BANDIT-B603",
        "EXT-BANDIT-B604", "EXT-BANDIT-B605", "EXT-BANDIT-B606"}
IMPORT_NOTICE = {"EXT-BANDIT-B403", "EXT-BANDIT-B404"}
TAR = {"SEC-010", "EXT-BANDIT-B202"}
RUNNERS = {"eval", "exec", "system", "popen", "Popen", "pop", "call", "run", "check_call", "check_output", "getoutput", "getstatusoutput"}
NOTE = "triage: constant arguments"
DEPRECATED = "--snap-verify is deprecated: it now runs the free, local --triage rule (no Snap call, nothing uploaded)"


def add_flag(parser: argparse.ArgumentParser) -> None:
    """Both checks call this; the second call is a no-op."""
    if "--triage" not in parser._option_string_actions:
        parser.add_argument("--triage", action="store_true",
                            help="free local rule: lower provably harmless findings (constant-argument command execution, import notices, "
                                 "blowfish crypt, extractall(members=[])) to INFO; never deleted")
        parser.add_argument("--snap-verify", action="store_true", help="deprecated alias of --triage (no Snap call any more)")


def wanted(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "triage", False) or getattr(args, "snap_verify", False))


# ---- constant resolution ---------------------------------------------------------------------------------------------
def _scopes(tree: ast.AST) -> dict[int, ast.AST]:
    """id(node) -> the innermost enclosing function/module node."""
    out: dict[int, ast.AST] = {}

    def walk(node: ast.AST, scope: ast.AST) -> None:
        out[id(node)] = scope
        inner = node if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) else scope
        for ch in ast.iter_child_nodes(node):
            walk(ch, inner)

    walk(tree, tree)
    return out


def _binding(name: str, scope: ast.AST, before: int, scopes: dict[int, ast.AST]):
    """Nearest binding of `name` in `scope` above line `before`: (value node | None, top_level_assign)."""
    best, best_line = None, 0
    top = {id(s) for s in getattr(scope, "body", [])}
    for n in ast.walk(scope):
        if scopes.get(id(n)) is not scope or getattr(n, "lineno", before) >= before:
            continue
        val, hit = None, False
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            val, hit = (n.value if id(n) in top else None), True
        elif isinstance(n, (ast.AugAssign, ast.AnnAssign, ast.For, ast.AsyncFor, ast.NamedExpr)) and any(
                isinstance(t, ast.Name) and t.id == name for t in ast.walk(getattr(n, "target", ast.Pass()))):
            hit = True
        elif isinstance(n, ast.withitem) and n.optional_vars is not None and any(
                isinstance(t, ast.Name) and t.id == name for t in ast.walk(n.optional_vars)):
            hit = True
        if hit and n.lineno >= best_line:
            best, best_line = val, n.lineno
    return best


def _const(n: ast.AST, scope: ast.AST, line: int, scopes: dict[int, ast.AST], depth: int = 0) -> bool:
    if depth > 6:
        return False
    rec = lambda x: _const(x, scope, line, scopes, depth + 1)      # noqa: E731
    if isinstance(n, ast.Constant):
        return True
    if isinstance(n, (ast.List, ast.Tuple)):
        return all(rec(e) for e in n.elts)
    if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
        return rec(n.left) and rec(n.right)
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format" and rec(n.func.value):
        return all(rec(a) for a in n.args) and all(rec(k.value) for k in n.keywords)
    if isinstance(n, ast.Name):
        v = _binding(n.id, scope, line, scopes)
        return v is not None and rec(v)
    return False


def _calls_at(tree: ast.AST, line: int) -> list[ast.Call]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == line]


def _command_args(c: ast.Call) -> list[ast.AST]:
    return list(c.args) + [k.value for k in c.keywords if k.arg == "args"]


def _harmless(f: Finding, text: str, tree: ast.AST, scopes: dict[int, ast.AST]) -> bool:
    ev = f.evidence[0]
    line = ev.line_start or 0
    if f.rule_id in IMPORT_NOTICE:
        return True
    if f.rule_id == "EXT-BANDIT-B324":
        src = text.splitlines()
        return 0 < line <= len(src) and "METHOD_BLOWFISH" in src[line - 1]
    calls = _calls_at(tree, line)
    if f.rule_id in TAR:
        return any(isinstance(k.value, ast.List) and not k.value.elts for c in calls for k in c.keywords if k.arg == "members")
    if f.rule_id in EXEC:
        run = [c for c in calls if (c.func.attr if isinstance(c.func, ast.Attribute) else getattr(c.func, "id", "")) in RUNNERS]
        return bool(run) and all(_command_args(c) and all(_const(a, scopes[id(c)], line, scopes) for a in _command_args(c)) for c in run)
    return False


def lower(base: Path, findings: list[Finding]) -> int:
    """Lower harmless findings to INFO in place. Returns how many changed."""
    cache: dict[str, tuple | None] = {}
    n = 0
    for f in findings:
        if f.severity <= Severity.INFO or not f.evidence or not f.evidence[0].file or not (
                f.rule_id in EXEC or f.rule_id in TAR or f.rule_id in IMPORT_NOTICE or f.rule_id == "EXT-BANDIT-B324"):
            continue
        rel = f.evidence[0].file
        if rel not in cache:
            try:
                text = (base / rel).read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(text)
                cache[rel] = (text, tree, _scopes(tree))
            except (OSError, SyntaxError, ValueError, RecursionError):
                cache[rel] = None
        if cache[rel] and _harmless(f, *cache[rel]):
            f.severity = Severity.INFO
            f.detail = f"{f.detail} [{NOTE}]".strip()
            n += 1
    return n


def apply(base: Path, res: CheckResult, args: argparse.Namespace | None = None) -> None:
    before = severity_counts(res.findings)
    n = lower(base, res.findings)
    res.stats["triage"] = {"lowered": n, "before": before, "after": severity_counts(res.findings)}
    if args is not None and getattr(args, "snap_verify", False):
        res.notes.append(DEPRECATED)
    res.findings.sort(key=lambda f: (-int(f.severity), f.evidence[0].file or "" if f.evidence else "",
                                     f.evidence[0].line_start or 0 if f.evidence else 0, f.rule_id))
