"""Static layer for --check-security: stdlib `ast` plus a regex pass for secrets. Free, line-accurate heuristics:
they prefer missing a case to crying wolf, and never put a full secret into a finding."""
from __future__ import annotations

import ast
import re
from typing import Iterator

from checksnap.core import Evidence, Finding

from .rules import RULES

Hit = tuple[ast.AST, str]

SECRET_NAME = re.compile(r"(^|_)(password|passwd|pwd|secret|secret_?key|api_?key|apikey|access_?key|auth_?token|token|private_?key)$", re.I)
PLACEHOLDER = re.compile(r"^(<.*>|\$\{.*\}|\{\{.*\}\}|\$\w+|your[-_ ]|change|xxx|example|dummy|test|todo|none|null|env|os\.)", re.I)
TOKEN_PATTERNS = [re.compile(p) for p in (
    r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{30,}", r"sk-[A-Za-z0-9_-]{20,}", r"xox[abprs]-[A-Za-z0-9-]{10,}",
    r"AIza[0-9A-Za-z_-]{35}", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", r"hf_[A-Za-z0-9]{30,}")]
SQL_WORDS = re.compile(r"\b(select|insert\s+into|update|delete\s+from|drop|create\s+table|alter)\b", re.I)
LONG_STR = re.compile(r"""(["'])[^"'\n]{20,}\1""")
UNSAFE_YAML = {"Loader", "UnsafeLoader", "FullLoader", "yaml.Loader", "yaml.UnsafeLoader", "yaml.FullLoader", "yaml.CLoader"}


def mask(s: str) -> str:
    return f"{s[:4]}**** (len {len(s)})"


def dotted(n: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return ".".join(reversed(parts))
    return ""


def kw(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def is_str(n: ast.AST | None) -> bool:
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


def formatted(n: ast.AST | None) -> bool:
    """A string built from variables: f-string, `%`, `+`, or `.format`."""
    if isinstance(n, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in n.values)
    if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Mod, ast.Add)):
        return (is_str(n.left) or is_str(n.right) or formatted(n.left) or formatted(n.right)) and not (is_str(n.left) and is_str(n.right))
    return isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format" and is_str(n.func.value)


def text_of(n: ast.AST) -> str:
    return "".join(c.value for c in ast.walk(n) if isinstance(c, ast.Constant) and isinstance(c.value, str))


class Scan(ast.NodeVisitor):
    def __init__(self, tree: ast.Module) -> None:
        self.alias: dict[str, str] = {}
        self.hits: list[tuple[str, ast.AST, str]] = []
        self.funcs: list[set[str]] = []
        self.imports: set[str] = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
                    self.imports.add(a.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                self.imports.add(n.module.split(".")[0])
                for a in n.names:
                    self.alias[a.asname or a.name] = f"{n.module}.{a.name}"
        self.visit(tree)

    def name(self, f: ast.AST) -> str:
        d = dotted(f)
        head, _, rest = d.partition(".")
        return self.alias.get(head, head) + ("." + rest if rest else "") if d else ""

    def add(self, rule: str, node: ast.AST, detail: str) -> None:
        self.hits.append((rule, node, detail))

    def visit_FunctionDef(self, n: ast.FunctionDef) -> None:
        a = n.args
        self.funcs.append({x.arg for x in a.posonlyargs + a.args + a.kwonlyargs} - {"self", "cls"})
        self.generic_visit(n)
        self.funcs.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assert(self, n: ast.Assert) -> None:
        if self.funcs and self.funcs[-1] & {x.id for x in ast.walk(n.test) if isinstance(x, ast.Name)}:
            self.add("SEC-009", n, "assert on a function argument")
        self.generic_visit(n)

    def visit_Constant(self, n: ast.Constant) -> None:
        if n.value == "0.0.0.0":
            self.add("SEC-013", n, "0.0.0.0")

    def secret(self, name: str, value: ast.AST | None, node: ast.AST) -> None:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            v = value.value
            if len(v) >= 8 and SECRET_NAME.search(name) and " " not in v and not PLACEHOLDER.match(v):
                self.add("SEC-006", node, f"`{name}` = {mask(v)}")

    def visit_Assign(self, n: ast.Assign) -> None:
        for t in n.targets:
            if isinstance(t, (ast.Name, ast.Attribute)):
                self.secret(t.id if isinstance(t, ast.Name) else t.attr, n.value, n)
            elif isinstance(t, ast.Subscript) and is_str(t.slice):
                self.secret(t.slice.value, n.value, n)  # type: ignore[attr-defined]
        self.generic_visit(n)

    def visit_AnnAssign(self, n: ast.AnnAssign) -> None:
        if isinstance(n.target, ast.Name):
            self.secret(n.target.id, n.value, n)
        self.generic_visit(n)

    def visit_Dict(self, n: ast.Dict) -> None:
        for k, v in zip(n.keys, n.values):
            if is_str(k):
                self.secret(k.value, v, v)  # type: ignore[attr-defined]
        self.generic_visit(n)

    def visit_Call(self, n: ast.Call) -> None:
        f = self.name(n.func)
        arg0 = n.args[0] if n.args else None
        for k in n.keywords:
            if k.arg:
                self.secret(k.arg, k.value, k.value)
        wo = kw(n, "weights_only")
        if f in ("pickle.load", "pickle.loads", "pickle.Unpickler", "cPickle.load", "cPickle.loads", "dill.load", "dill.loads", "marshal.load", "marshal.loads"):
            self.add("SEC-001", n, f)
        elif f == "torch.load" and not (isinstance(wo, ast.Constant) and wo.value is True):
            self.add("SEC-001", n, "torch.load without weights_only=True")
        elif f in ("yaml.load", "yaml.load_all"):
            ld = kw(n, "Loader") or (n.args[1] if len(n.args) > 1 else None)
            if ld is None or self.name(ld) in UNSAFE_YAML:
                self.add("SEC-002", n, f"{f} with {'no Loader' if ld is None else 'an unsafe Loader'}")
        elif f in ("eval", "exec") and arg0 is not None and not isinstance(arg0, ast.Constant):
            self.add("SEC-003", n, f)
        elif f.startswith("subprocess.") and isinstance(kw(n, "shell"), ast.Constant) and kw(n, "shell").value is True and formatted(arg0):  # type: ignore[union-attr]
            self.add("SEC-004", n, f"{f}(shell=True) with a formatted command")
        elif f in ("os.system", "os.popen"):
            self.add("SEC-005", n, f)
        elif f == "tempfile.mktemp":
            self.add("SEC-007", n, f)
        elif f.split(".")[0] in ("requests", "httpx", "session", "s") and isinstance(kw(n, "verify"), ast.Constant) and kw(n, "verify").value is False:  # type: ignore[union-attr]
            self.add("SEC-008", n, "verify=False")
        elif isinstance(n.func, ast.Attribute) and n.func.attr in ("extractall", "extract") and self.imports & {"tarfile", "zipfile"} \
                and kw(n, "filter") is None and kw(n, "members") is None and (n.func.attr == "extractall" or len(n.args) < 2):
            if n.func.attr == "extractall" or "tarfile" in self.imports:
                self.add("SEC-010", n, f".{n.func.attr}() with no filter/members")
        elif isinstance(n.func, ast.Attribute) and n.func.attr in ("execute", "executemany", "executescript") and formatted(arg0) and SQL_WORDS.search(text_of(arg0)):
            self.add("SEC-011", n, "query built by string formatting")
        elif n.func and isinstance(n.func, ast.Attribute) and n.func.attr == "run" and isinstance(kw(n, "debug"), ast.Constant) and kw(n, "debug").value is True:  # type: ignore[union-attr]
            self.add("SEC-012", n, "run(debug=True)")
        elif f in ("hashlib.md5", "hashlib.sha1") or (f == "hashlib.new" and is_str(arg0) and arg0.value.lower() in ("md5", "sha1")):  # type: ignore[attr-defined]
            u = kw(n, "usedforsecurity")
            if not (isinstance(u, ast.Constant) and u.value is False):
                self.add("SEC-014", n, f)
        elif f in ("os.chmod", "os.fchmod", "os.lchmod") or (isinstance(n.func, ast.Attribute) and n.func.attr == "chmod"):
            mode = n.args[-1] if n.args else kw(n, "mode")
            if mode is not None and self.world_writable(mode):
                self.add("SEC-015", n, "world-writable mode")
        self.generic_visit(n)

    @staticmethod
    def world_writable(m: ast.AST) -> bool:
        if isinstance(m, ast.Constant) and isinstance(m.value, int):
            return bool(m.value & 0o002)
        return any(dotted(x).split(".")[-1] in ("S_IWOTH", "S_IRWXO") for x in ast.walk(m))


def analyze(source: str, rel: str) -> list[Finding]:
    """Findings for one file. Raises SyntaxError for unparseable Python (caller notes it)."""
    lines = source.splitlines()
    hits = Scan(ast.parse(source)).hits if rel.endswith(".py") else []
    raw = [(r, getattr(n, "lineno", 1), d) for r, n, d in hits]
    seen = {ln for r, ln, _ in raw if r == "SEC-006"}
    for i, line in enumerate(lines, 1):                   # regex pass: provider tokens in any text file, even in comments
        if i in seen:
            continue
        for p in TOKEN_PATTERNS:
            m = p.search(line)
            if m:
                raw.append(("SEC-006", i, f"token-like string {mask(m.group(0))}"))
                seen.add(i)
                break
    out, done = [], set()
    for rule, ln, detail in raw:
        if (rule, ln) in done:
            continue
        done.add((rule, ln))
        info = RULES[rule]
        snippet = "" if rule == "SEC-006" else LONG_STR.sub('"****"', lines[ln - 1].strip())[:160] if 0 < ln <= len(lines) else ""
        out.append(Finding("security", rule, info.severity, info.title, detail, [Evidence(rel, ln, ln, snippet)],
                           source="static", fix_hint=info.fix_hint))
    return out
