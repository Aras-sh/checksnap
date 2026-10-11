"""Static analysis for reproducibility. `analyze_project` takes in-memory sources so tests need no disk."""
from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field

from checksnap.core import Evidence, Finding

from .rules import RULES

try:
    import tomllib
except ImportError:  # Python 3.10
    tomllib = None  # type: ignore[assignment]

LIBS = ("random", "numpy", "torch", "tensorflow")
GENERIC_SEEDERS = {"seed_everything", "set_seed", "set_random_seed", "seed_all"}
TORCH_RAND = {"rand", "randn", "randint", "randperm", "normal", "bernoulli", "multinomial", "rand_like", "randn_like", "randint_like"}
TORCH_LAYERS = {"Linear", "Conv1d", "Conv2d", "Conv3d", "Dropout", "Dropout2d", "Embedding", "LSTM", "GRU", "MultiheadAttention", "TransformerEncoderLayer"}
TF_LAYERS = {"Dense", "Conv1D", "Conv2D", "Dropout", "Embedding", "LSTM", "GRU"}
NONDET_OPS = {"index_add_", "index_add", "scatter_", "scatter_add_", "scatter_add", "scatter_reduce", "scatter_reduce_", "put_", "index_put_", "bincount"}
TIME_CALLS = {"datetime.datetime.now", "datetime.datetime.utcnow", "datetime.datetime.today", "datetime.date.today",
              "time.time", "time.strftime", "time.localtime", "time.ctime", "time.time_ns"}
PATH_SINKS = {"open", "makedirs", "mkdir", "save", "savefig", "join", "Path", "to_csv", "to_json", "dump", "SummaryWriter", "FileHandler", "rename"}
PATHISH = re.compile(r"(dir|path|file|name|out|ckpt|checkpoint|run|log|save)", re.I)
SORT_OK = {"sorted", "len", "set", "frozenset", "min", "max", "sum"}
ML_IMPORTS = {"torch", "tensorflow", "keras", "sklearn", "jax", "xgboost", "lightgbm"}
TRACKERS = re.compile(r"\b(wandb|mlflow|comet_ml|neptune|hydra|sacred|clearml|dvc)\b")
GIT_RX = re.compile(r"rev-parse|git\.Repo|GitPython|git_commit|git_hash|git_sha|get_git|git describe|__git|['\"]git['\"]")
CFG_RX = re.compile(r"vars\(args\)|save_config|dump_config|OmegaConf\.save|yaml\.(safe_)?dump|save_hyperparameters|log_hyperparams|config\.json|hparams|json\.dump\(.*(config|cfg|args)")
LOCKS = {"poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "conda-lock.yml", "pnpm-lock.yaml"}
MANIFESTS = {"pyproject.toml", "environment.yml", "environment.yaml", "Pipfile", "setup.py", "setup.cfg"}


@dataclass
class Hit:
    rule: str
    file: str
    line: int
    snippet: str = ""
    detail: str = ""


@dataclass
class FileFacts:
    rel: str
    tree: ast.Module
    lines: list[str]
    aliases: dict[str, str] = field(default_factory=dict)
    parents: dict[ast.AST, ast.AST] = field(default_factory=dict)

    def snip(self, line: int) -> str:
        return self.lines[line - 1].strip()[:160] if 0 < line <= len(self.lines) else ""

    def q(self, n: ast.AST) -> str:
        """Dotted name with the first segment resolved through imports ('np.random.seed' -> 'numpy.random.seed')."""
        if isinstance(n, ast.Name):
            return self.aliases.get(n.id, n.id)
        if isinstance(n, ast.Attribute):
            b = self.q(n.value)
            return f"{b}.{n.attr}" if b else ""
        if isinstance(n, ast.Call):
            b = self.q(n.func)
            return b + "()" if b else ""
        return ""

    def ancestors(self, n: ast.AST):
        while n in self.parents:
            n = self.parents[n]
            yield n


def parse(rel: str, text: str) -> FileFacts | None:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None
    f = FileFacts(rel, tree, text.splitlines())
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            f.parents[c] = p
        if isinstance(p, ast.Import):
            for a in p.names:
                f.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(p, ast.ImportFrom) and p.module and not p.level:
            for a in p.names:
                f.aliases[a.asname or a.name] = f"{p.module}.{a.name}"
    return f


def _kw(c: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in c.keywords if k.arg == name), None)


def _is_true(n: ast.expr | None) -> bool:
    return isinstance(n, ast.Constant) and n.value is True


def seed_lib(f: FileFacts, c: ast.Call) -> set[str]:
    """Libraries this call seeds (empty set if it is not a seeding call)."""
    q = f.q(c.func)
    last = q.rsplit(".", 1)[-1]
    if last in GENERIC_SEEDERS:
        return set(LIBS)
    if q == "random.seed":
        return {"random"}
    if q == "numpy.random.seed" or (q in ("numpy.random.default_rng", "numpy.random.RandomState") and (c.args or c.keywords)):
        return {"numpy"}
    if q in ("torch.manual_seed", "torch.random.manual_seed", "torch.cuda.manual_seed", "torch.cuda.manual_seed_all"):
        return {"torch"}
    if q.startswith("tensorflow.") and last in ("set_seed", "set_random_seed"):
        return {"tensorflow"}
    return set()


def use_lib(f: FileFacts, c: ast.Call) -> str | None:
    """Library whose randomness this call draws on (None if not a random draw)."""
    q = f.q(c.func)
    if seed_lib(f, c):
        return None
    last = q.rsplit(".", 1)[-1]
    if q.startswith("random.") and q.count(".") == 1:
        return "random"
    if q.startswith("numpy.random."):
        return "numpy"
    if q.startswith("torch.") and (last in TORCH_RAND and q.count(".") == 1 or ".init." in q or (".nn." in q and last in TORCH_LAYERS)):
        return "torch"
    if q.startswith("torch.nn.") and last in TORCH_LAYERS:
        return "torch"
    if last == "DataLoader" and _is_true(_kw(c, "shuffle")):
        return "torch"
    if q.startswith("tensorflow.random.") or (q.startswith(("tensorflow.keras.layers.", "keras.layers.")) and last in TF_LAYERS):
        return "tensorflow"
    return None


def _calls(scope: ast.AST):
    """Calls in this scope only (nested defs/classes excluded), in source order."""
    out: list[ast.Call] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(n, ast.Call):
            out.append(n)
        stack.extend(ast.iter_child_nodes(n))
    return sorted(out, key=lambda c: (c.lineno, c.col_offset))


def _set_expr(f: FileFacts, n: ast.AST, set_names: set[str]) -> bool:
    return (isinstance(n, (ast.Set, ast.SetComp)) or (isinstance(n, ast.Call) and f.q(n.func) in ("set", "frozenset"))
            or (isinstance(n, ast.Name) and n.id in set_names))


def _set_names(f: FileFacts) -> set[str]:
    good: set[str] = set()
    bad: set[str] = set()
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            (good if _set_expr(f, n.value, set()) else bad).add(n.targets[0].id)
    return good - bad


def per_file(f: FileFacts) -> tuple[list[Hit], dict[str, list[Hit]], set[str], dict[str, bool]]:
    """Returns (hits, uses by lib, libs seeded, flags). `uses`/seeded feed the project-level rules."""
    hits: list[Hit] = []
    uses: dict[str, list[Hit]] = {k: [] for k in LIBS}
    seeded: set[str] = set()
    flags = {"det_cudnn": False, "det_algos": False, "nondet": False}
    set_names = _set_names(f)

    def add(rule: str, n: ast.AST, detail: str = "") -> None:
        hits.append(Hit(rule, f.rel, n.lineno, f.snip(n.lineno), detail))

    for n in ast.walk(f.tree):
        if isinstance(n, ast.Call):
            q = f.q(n.func)
            last = q.rsplit(".", 1)[-1]
            seeded |= seed_lib(f, n)
            if (u := use_lib(f, n)):
                uses[u].append(Hit(f"REP-{LIBS.index(u) + 1:03d}", f.rel, n.lineno, f.snip(n.lineno)))
            if q == "torch.use_deterministic_algorithms":
                flags["det_algos"] = True
            if last == "DataLoader" and (_is_true(_kw(n, "shuffle")) or (_kw(n, "num_workers") is not None and not (isinstance(_kw(n, "num_workers"), ast.Constant) and _kw(n, "num_workers").value == 0))):
                if _kw(n, "worker_init_fn") is None and _kw(n, "generator") is None and not any(k.arg is None for k in n.keywords):
                    add("REP-008", n)
            # REP-009 unsorted listing
            listing = q in ("os.listdir", "os.scandir", "glob.glob", "glob.iglob") or (isinstance(n.func, ast.Attribute) and n.func.attr in ("glob", "rglob", "iterdir") and q.split(".")[0] != "glob")
            if listing and not any(isinstance(a, ast.Call) and f.q(a.func) in SORT_OK for a in f.ancestors(n)):
                p = f.parents.get(n)
                name = p.targets[0].id if isinstance(p, ast.Assign) and isinstance(p.targets[0], ast.Name) else None
                if not (name and re.search(rf"\b{re.escape(name)}\.sort\(|sorted\(\s*{re.escape(name)}\b", "\n".join(f.lines))):
                    add("REP-009", n)
            # REP-011
            if isinstance(n.func, ast.Attribute) and n.func.attr == "popitem" and not n.args:
                add("REP-011", n, "dict.popitem()")
            elif isinstance(n.func, ast.Attribute) and n.func.attr == "pop" and not n.args and _set_expr(f, n.func.value, set_names) and not isinstance(n.func.value, ast.Name) or (
                    isinstance(n.func, ast.Attribute) and n.func.attr == "pop" and not n.args and isinstance(n.func.value, ast.Name) and n.func.value.id in set_names):
                add("REP-011", n, "set.pop()")
            elif q == "next" and n.args and isinstance(n.args[0], ast.Call) and f.q(n.args[0].func) == "iter" and n.args[0].args and _set_expr(f, n.args[0].args[0], set_names):
                add("REP-011", n, "next(iter(set))")
            elif q == "hash" and n.args and not isinstance(n.args[0], ast.Constant):
                fn = next((a for a in f.ancestors(n) if isinstance(a, ast.FunctionDef)), None)
                if not (fn and fn.name == "__hash__"):
                    add("REP-011", n, "builtin hash()")
            # REP-010 list(set(..))
            if q in ("list", "tuple") and n.args and _set_expr(f, n.args[0], set_names):
                add("REP-010", n)
            # REP-012 time in path
            if q.split("().")[0] in TIME_CALLS:
                chain = []
                for a in f.ancestors(n):
                    if isinstance(a, ast.stmt):
                        break
                    chain.append(a)
                st = next((a for a in f.ancestors(n) if isinstance(a, ast.stmt)), None)
                builds = any(isinstance(a, (ast.JoinedStr, ast.BinOp)) and not (isinstance(a, ast.BinOp) and not isinstance(a.op, (ast.Add, ast.Mod)))
                             or (isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr in ("format", "strftime")) for a in chain)
                builds = builds or ".strftime" in q
                sink = any(isinstance(a, ast.Call) and f.q(a.func).rsplit(".", 1)[-1] in PATH_SINKS for a in chain)
                pathish = isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and PATHISH.search(t.id) for t in st.targets)
                if builds and (sink or pathish) and not any(h.rule == "REP-012" and h.line == n.lineno for h in hits):
                    add("REP-012", n)
            # REP-018
            if isinstance(n.func, ast.Attribute) and n.func.attr in NONDET_OPS and not (n.func.attr in ("index_put_", "put_") and not _is_true(_kw(n, "accumulate"))):
                flags["nondet"] = True
                add("REP-018", n, n.func.attr)
        elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Attribute):
            tq = f.q(n.targets[0])
            if tq == "torch.backends.cudnn.benchmark" and _is_true(n.value):
                add("REP-006", n, "benchmark = True")
            elif tq == "torch.backends.cudnn.deterministic":
                if isinstance(n.value, ast.Constant) and n.value.value is False:
                    add("REP-006", n, "deterministic = False")
                elif _is_true(n.value):
                    flags["det_cudnn"] = True
        elif isinstance(n, (ast.For, ast.comprehension)) and _set_expr(f, n.iter, set_names):
            add("REP-010", n.iter if isinstance(n, ast.comprehension) else n)
    # REP-005 seed after use, per scope
    for scope in [f.tree] + [s for s in ast.walk(f.tree) if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        first_use: dict[str, ast.Call] = {}
        for c in _calls(scope):
            for lib in seed_lib(f, c):
                if lib in first_use:
                    add("REP-005", c, f"{lib}: used at line {first_use.pop(lib).lineno}, seeded here")
            if (u := use_lib(f, c)) and u not in first_use:
                first_use[u] = c
    # nondet flag only counts with torch imported
    if "torch" not in {v.split(".")[0] for v in f.aliases.values()}:
        hits = [h for h in hits if h.rule != "REP-018"]
        flags["nondet"] = False
    return hits, uses, seeded, flags


# ---- project-level files -------------------------------------------------------------------------

def _req_lines(text: str) -> list[tuple[int, str]]:
    out = []
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.split(" #")[0].strip()
        if s and not s.startswith(("#", "-", "git+", "http")):
            out.append((i, s))
    return out


def _pinned(spec: str) -> bool:
    return "==" in spec or " @ " in spec or "@" in spec


def unpinned_requirements(name: str, text: str) -> list[tuple[int, str]]:
    base = name.rsplit("/", 1)[-1]
    if base.endswith(".toml"):
        if tomllib is None:
            return []
        try:
            d = tomllib.loads(text)
        except Exception:  # noqa: BLE001
            return []
        deps = list(d.get("project", {}).get("dependencies", []))
        for v in d.get("project", {}).get("optional-dependencies", {}).values():
            deps += v
        return [(0, s) for s in deps if not _pinned(s)]
    if base.startswith("environment") and base.endswith((".yml", ".yaml")):
        return [(i, m.group(1)) for i, l in enumerate(text.splitlines(), 1) if (m := re.match(r"^\s*-\s+([A-Za-z0-9_.\-]+)\s*$", l)) and m.group(1) != "pip"]
    return [(i, s) for i, s in _req_lines(text) if not _pinned(s)]


def _is_req(name: str) -> bool:
    b = name.rsplit("/", 1)[-1]
    return (b.startswith("requirements") and b.endswith((".txt", ".in"))) or ("requirements/" in name and b.endswith(".txt"))


def _mk(rule: str, detail: str, ev: list[Evidence]) -> Finding:
    r = RULES[rule]
    return Finding("repro", rule, r.severity, r.title, detail, ev, source="static", fix_hint=r.fix_hint)


def analyze_project(py: dict[str, str], other: dict[str, str] | None = None, project_files: bool = True) -> tuple[list[Finding], list[str]]:
    """py: relpath -> source; other: relpath -> text of requirement/manifest files (lock files may map to ''). Returns (findings, notes)."""
    other = other or {}
    notes: list[str] = []
    out: list[Finding] = []
    uses: dict[str, list[Hit]] = {k: [] for k in LIBS}
    seeded: set[str] = set()
    hits: list[Hit] = []
    det_cudnn = det_algos = False
    imports: set[str] = set()
    ml_file = None
    for rel in sorted(py):
        f = parse(rel, py[rel])
        if f is None:
            notes.append(f"could not parse {rel}")
            continue
        h, u, s, fl = per_file(f)
        hits += h
        seeded |= s
        det_cudnn |= fl["det_cudnn"]
        det_algos |= fl["det_algos"]
        for k in LIBS:
            uses[k] += u[k]
        for p in ast.walk(f.tree):
            if isinstance(p, ast.Import):
                imports |= {a.name.split(".")[0] for a in p.names}
            elif isinstance(p, ast.ImportFrom) and p.module and not p.level:
                imports.add(p.module.split(".")[0])
        if ml_file is None and imports & ML_IMPORTS:
            ml_file = rel
    if det_algos:
        hits = [h for h in hits if h.rule != "REP-018"]
    for lib, rid in zip(LIBS, ("REP-001", "REP-002", "REP-003", "REP-004")):
        if uses[lib] and lib not in seeded:
            u = uses[lib][0]
            out.append(_mk(rid, f"{len(uses[lib])} random use(s); first at {u.file}:{u.line}", [Evidence(u.file, u.line, u.line, u.snippet)]))
    if uses["torch"] and not (det_cudnn or det_algos):
        u = uses["torch"][0]
        out.append(_mk("REP-007", "", [Evidence(u.file, u.line, u.line, u.snippet)]))
    for h in hits:
        out.append(_mk(h.rule, h.detail, [Evidence(h.file, h.line, h.line, h.snippet)]))
    # project-level rules
    if project_files and py:
        names = set(other)
        reqs = {n: t for n, t in other.items() if _is_req(n) or n.rsplit("/", 1)[-1] in MANIFESTS}
        for n, t in sorted(reqs.items()):
            bad = unpinned_requirements(n, t)
            if bad:
                out.append(_mk("REP-013", f"{len(bad)} unpinned in {n}: " + ", ".join(s for _, s in bad[:5]),
                               [Evidence(n, i or None, i or None, s) for i, s in bad[:5]]))
        local = {p.split("/")[0].removesuffix(".py") for p in py}
        third = sorted(m for m in imports if m not in sys.stdlib_module_names and m not in local and m != "__future__")
        has_manifest = bool(reqs) or any(n.rsplit("/", 1)[-1] in LOCKS for n in names)
        if third and not has_manifest:
            out.append(_mk("REP-014", "imports: " + ", ".join(third[:8]), []))
        if reqs and not any(n.rsplit("/", 1)[-1] in LOCKS for n in names):
            pinned_txt = any(_is_req(n) and _req_lines(t) and not unpinned_requirements(n, t) for n, t in reqs.items())
            if not pinned_txt:
                out.append(_mk("REP-015", "", []))
        blob = "\n".join(py.values())
        if imports & ML_IMPORTS and not TRACKERS.search(blob):
            if not GIT_RX.search(blob):
                out.append(_mk("REP-016", "", [Evidence(ml_file)] if ml_file else []))
            if not CFG_RX.search(blob):
                out.append(_mk("REP-017", "", [Evidence(ml_file)] if ml_file else []))
    out.sort(key=lambda f: (-int(f.severity), f.evidence[0].file or "" if f.evidence else "", f.evidence[0].line_start or 0 if f.evidence else 0, f.rule_id))
    return out, notes
