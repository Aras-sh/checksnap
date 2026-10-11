"""Static layer: stdlib `ast` rules, free and line-accurate.

Each rule is a function `FileInfo -> Iterator[(node, detail)]`; `analyze` runs them and turns hits into Findings.
Rules are heuristics ("candidates"): they prefer missing a case to crying wolf, e.g. file-open-in-loop only fires
when the path does not change between iterations.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Callable, Iterator

from checksnap.core import Evidence, Finding

from .rules import STATIC_RULES

LOOPS = (ast.For, ast.AsyncFor, ast.While)
COMPS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
Hit = tuple[ast.AST, str]


# ---------------------------------------------------------------- helpers

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
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def has_star_kwargs(call: ast.Call) -> bool:
    return any(k.arg is None for k in call.keywords)


def is_const(n: ast.AST | None, value: object) -> bool:
    return isinstance(n, ast.Constant) and n.value == value and type(n.value) is type(value)


def _inside(cur: ast.AST, p: ast.AST) -> bool:
    """Is `cur` (a direct child of loop/comprehension node `p`) evaluated once per iteration?"""
    if isinstance(p, (ast.For, ast.AsyncFor)):
        return any(cur is s for s in p.body)
    if isinstance(p, ast.While):
        return not any(cur is s for s in p.orelse)
    return False


def loops_around(node: ast.AST, comps: bool = True) -> list[ast.AST]:
    """Loops (innermost first) whose per-iteration code contains `node`; stops at the function boundary."""
    out: list[ast.AST] = []
    cur = node
    while True:
        p = getattr(cur, "_p", None)
        if p is None or isinstance(p, FUNCS + (ast.ClassDef,)):
            return out
        if isinstance(p, LOOPS):
            if _inside(cur, p):
                out.append(p)
        elif comps and isinstance(p, ast.comprehension):
            owner = p._p  # type: ignore[attr-defined]
            first = owner.generators[0] is p
            if not (cur is p.iter and first) and cur is not p.target:
                out.append(owner)
        elif comps and isinstance(p, COMPS) and not isinstance(cur, ast.comprehension):
            out.append(p)
        cur = p


def _own_nodes(loop: ast.AST) -> Iterator[ast.AST]:
    """Nodes of a loop body, not descending into nested loops or functions."""
    stack = list(getattr(loop, "body", []))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, LOOPS + FUNCS):
            continue
        stack.extend(ast.iter_child_nodes(n))


def is_train_loop(loop: ast.AST) -> bool:
    """A for/while whose own body calls `.backward()` or `<optimizer>.step()`."""
    cached = getattr(loop, "_train", None)
    if cached is not None:
        return cached
    res = False
    if isinstance(loop, LOOPS):
        for n in _own_nodes(loop):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                a = n.func.attr
                recv = dotted(n.func.value).lower()
                if a == "backward" or (a == "step" and re.search(r"opt|scaler|sched", recv)):
                    res = True
                    break
    loop._train = res  # type: ignore[attr-defined]
    return res


def train_loops_around(node: ast.AST) -> list[ast.AST]:
    return [lp for lp in loops_around(node, comps=False) if is_train_loop(lp)]


def stored_names(loop: ast.AST) -> set[str]:
    cached = getattr(loop, "_stored", None)
    if cached is None:
        cached = {n.id for n in ast.walk(loop) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        loop._stored = cached  # type: ignore[attr-defined]
    return cached


def invariant(expr: ast.AST | None, loop: ast.AST) -> bool:
    """True when no name read by `expr` is assigned inside `loop` (the value cannot change per iteration)."""
    if expr is None:
        return False
    st = stored_names(loop)
    return not any(isinstance(n, ast.Name) and n.id in st for n in ast.walk(expr))


def enclosing(node: ast.AST, types: tuple) -> ast.AST | None:
    cur = getattr(node, "_p", None)
    while cur is not None and not isinstance(cur, types):
        cur = getattr(cur, "_p", None)
    return cur


def _kind(v: ast.AST) -> str:
    if isinstance(v, (ast.List, ast.ListComp)):
        return "list"
    if isinstance(v, (ast.Constant, ast.JoinedStr)) and (isinstance(v, ast.JoinedStr) or isinstance(v.value, str)):
        return "str"
    if isinstance(v, (ast.Set, ast.SetComp)):
        return "set"
    if isinstance(v, (ast.Dict, ast.DictComp)):
        return "dict"
    if isinstance(v, ast.Call):
        n = dotted(v.func)
        if n in ("list", "sorted"):
            return "list"
        if n in ("set", "frozenset"):
            return "set"
        if n == "dict":
            return "dict"
        if isinstance(v.func, ast.Attribute) and v.func.attr in ("split", "splitlines"):
            return "list"
    return "other"


def bindings(scope: ast.AST) -> dict[str, set[str]]:
    """name -> kinds it is assigned in this function/module scope (ambiguity = several kinds)."""
    cached = getattr(scope, "_bind", None)
    if cached is not None:
        return cached
    out: dict[str, set[str]] = {}
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        a = scope.args
        for arg in a.posonlyargs + a.args + a.kwonlyargs:
            ann = ast.unparse(arg.annotation) if arg.annotation else ""
            if re.match(r"(typing\.)?(list|List)\b", ann):
                out.setdefault(arg.arg, set()).add("list")
            else:
                out.setdefault(arg.arg, set()).add("other")
    stack = list(getattr(scope, "body", []))
    while stack:
        n = stack.pop()
        if isinstance(n, FUNCS + (ast.ClassDef,)):
            continue
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out.setdefault(t.id, set()).add(_kind(n.value))
                else:
                    stack.append(t)  # tuple unpacking etc. registers as "other" below
            stack.append(n.value)
            continue
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            out.setdefault(n.target.id, set()).add(_kind(n.value) if n.value else "other")
            if n.value:
                stack.append(n.value)
            continue
        if isinstance(n, ast.AugAssign):
            stack.append(n.value)  # `s += x` keeps the type of s
            continue
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            out.setdefault(n.id, set()).add("other")  # for-targets, with-targets, walrus...
        stack.extend(ast.iter_child_nodes(n))
    scope._bind = out  # type: ignore[attr-defined]
    return out


def name_kind(node: ast.Name) -> str | None:
    scope = enclosing(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module))
    kinds = bindings(scope).get(node.id) if scope is not None else None
    return next(iter(kinds)) if kinds and len(kinds) == 1 else None


@dataclass
class FileInfo:
    tree: ast.Module
    source: str
    ml: bool
    lines: list[str] = field(default_factory=list)

    def src_has(self, pattern: str) -> bool:
        return re.search(pattern, self.source) is not None


# ---------------------------------------------------------------- general rules

def py001(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Add) and loops_around(n):
            # `x += <str>`: strings are immutable. Names that only hold ints/lists are skipped.
            strish = _kind(n.value) == "str" or (isinstance(n.target, ast.Name) and name_kind(n.target) == "str")
            if strish:
                yield n, "string `+=` in a loop copies the string each iteration"
        elif (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
              and isinstance(n.value, ast.BinOp) and isinstance(n.value.op, ast.Add)
              and isinstance(n.value.left, ast.Name) and n.value.left.id == n.targets[0].id and loops_around(n)):
            kind = _kind(n.value.right)
            if kind in ("str", "list") or name_kind(n.targets[0]) in ("str", "list"):
                yield n, f"`{n.targets[0].id} = {n.targets[0].id} + ...` rebuilds the {kind if kind != 'other' else 'sequence'} each iteration"


_RE_FUNCS = {"compile", "match", "search", "sub", "subn", "findall", "finditer", "fullmatch", "split"}


def py002(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if (isinstance(n, ast.Call) and dotted(n.func).startswith("re.") and dotted(n.func)[3:] in _RE_FUNCS
                and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) and loops_around(n)):
            yield n, f"{dotted(n.func)}() with a constant pattern inside a loop"


def py003(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if (isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], (ast.In, ast.NotIn))
                and isinstance(n.comparators[0], ast.Name) and name_kind(n.comparators[0]) == "list"):
            loops = loops_around(n)
            # skip when the list itself is rebuilt inside the loop (then a set would not help)
            if loops and invariant(n.comparators[0], loops[0]):
                yield n, f"membership test against list `{n.comparators[0].id}` inside a loop"


def py004(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if (isinstance(n, (ast.For, ast.AsyncFor)) and isinstance(n.iter, ast.Call) and dotted(n.iter.func) == "range"
                and len(n.iter.args) == 1 and isinstance(n.iter.args[0], ast.Call) and dotted(n.iter.args[0].func) == "len"):
            yield n, "`range(len(...))` index loop"


_LOADERS = {"json.load", "json.loads", "pickle.load", "pickle.loads", "yaml.safe_load", "yaml.load", "tomllib.load", "tomllib.loads"}


def _is_open_like(n: ast.Call) -> bool:
    d = dotted(n.func)
    return d in ("open", "io.open") or (isinstance(n.func, ast.Attribute) and n.func.attr in ("read_text", "read_bytes"))


def _open_path(n: ast.Call) -> ast.AST | None:
    if isinstance(n.func, ast.Attribute) and n.func.attr in ("read_text", "read_bytes"):
        return n.func.value
    return n.args[0] if n.args else None


def py005(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Call) and _is_open_like(n):
            p = getattr(n, "_p", None)
            if isinstance(p, ast.Call) and dotted(p.func) in _LOADERS:
                continue  # reported by OPT-PY-010
            loops = loops_around(n)
            if loops and invariant(_open_path(n), loops[0]):
                yield n, "same file opened/read on every iteration"


def py006(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if not isinstance(n, ast.Call):
            continue
        target = None
        if dotted(n.func) == "sorted" and n.args:
            target = n.args[0]
        elif isinstance(n.func, ast.Attribute) and n.func.attr == "sort":
            target = n.func.value
        loops = loops_around(n) if target is not None else []
        if loops and invariant(target, loops[0]):
            yield n, "sorting a collection that does not change per iteration (or grows incrementally)"


_BLOCKING = {"time.sleep", "urllib.request.urlopen", "subprocess.run", "subprocess.call", "subprocess.check_output", "subprocess.check_call",
             *(f"requests.{m}" for m in ("get", "post", "put", "delete", "head", "patch", "request"))}


def py007(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Call) and dotted(n.func) in _BLOCKING and isinstance(enclosing(n, FUNCS), ast.AsyncFunctionDef):
            yield n, f"blocking `{dotted(n.func)}` inside async def"


def py008(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("execute", "fetchone", "fetchall")
                and loops_around(n)):
            yield n, f"`.{n.func.attr}()` inside a loop (one round trip per item)"


def py009(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr == "iterrows" and not n.args:
                yield n, "`iterrows()` iterates rows in Python"
            elif n.func.attr == "apply":
                ax = kw(n, "axis")
                if is_const(ax, 1) or is_const(ax, "columns"):
                    yield n, "`apply(axis=1)` runs a Python function per row"


def py010(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Call) and dotted(n.func) in _LOADERS and n.args:
            loops = loops_around(n)
            if not loops:
                continue
            for sub in ast.walk(n.args[0]):
                if isinstance(sub, ast.Call) and _is_open_like(sub) and invariant(_open_path(sub), loops[0]):
                    yield n, "same file parsed on every iteration"
                    break


def py011(f: FileInfo) -> Iterator[Hit]:
    for cls in ast.walk(f.tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        for fn in cls.body:
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or not fn.args.args or fn.args.args[0].arg not in ("self", "cls"):
                continue
            decos = [dotted(d.func if isinstance(d, ast.Call) else d) for d in fn.decorator_list]
            if any(x in ("staticmethod",) for x in decos):
                continue
            for d in fn.decorator_list:
                name = dotted(d.func if isinstance(d, ast.Call) else d)
                if name.split(".")[-1] == "cache" and not isinstance(d, ast.Call):
                    yield d, f"`@{name}` on method `{fn.name}` keeps every instance alive"
                elif name.split(".")[-1] == "lru_cache" and isinstance(d, ast.Call):
                    size = kw(d, "maxsize") or (d.args[0] if d.args else None)
                    if is_const(size, None):
                        yield d, f"`lru_cache(maxsize=None)` on method `{fn.name}` keeps every instance alive"


def py012(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Call) and dotted(n.func) in ("sum", "any", "all", "min", "max") and n.args:
            a = n.args[0]
            if isinstance(a, ast.Call) and dotted(a.func) == "list":
                yield n, f"`{dotted(n.func)}(list(...))` allocates a throwaway list"
            elif isinstance(a, ast.ListComp) and dotted(n.func) in ("any", "all"):
                yield n, f"`{dotted(n.func)}([...])` builds the whole list and loses short-circuiting"


def py013(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and loops_around(n):
            a = n.func.attr
            zero_first = n.args and is_const(n.args[0], 0)
            if (a == "pop" and len(n.args) == 1 and zero_first) or (a == "insert" and len(n.args) == 2 and zero_first):
                if not (isinstance(n.func.value, ast.Name) and name_kind(n.func.value) == "dict"):
                    yield n, f"`list.{a}(0 ...)` shifts every element"


# ---------------------------------------------------------------- ML rules

_HOST_SYNC = {"item", "cpu", "numpy"}


def _guarded(node: ast.AST, stop: ast.AST, mod_only: bool) -> bool:
    """Is there an `if` between node and `stop` (with a `%` in its test when mod_only)?"""
    cur = getattr(node, "_p", None)
    while cur is not None and cur is not stop:
        if isinstance(cur, ast.If) and (not mod_only or any(isinstance(x, ast.Mod) for x in ast.walk(cur.test))):
            return True
        cur = getattr(cur, "_p", None)
    return False


def ml001(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if not isinstance(n, ast.Call):
            continue
        what = None
        if isinstance(n.func, ast.Attribute) and n.func.attr in _HOST_SYNC and not n.args:
            what = f".{n.func.attr}()"
        elif dotted(n.func) == "float" and len(n.args) == 1 and re.search(r"loss|logit|output|pred|acc|tensor|norm|score", ast.unparse(n.args[0]).lower()):
            what = "float(tensor)"
        if what:
            tl = train_loops_around(n)
            if tl and not _guarded(n, tl[0], mod_only=True):
                yield n, f"{what} inside a training loop forces a GPU sync every step"


def ml002(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Call) and dotted(n.func).split(".")[-1] == "DataLoader" and not has_star_kwargs(n):
            nw = kw(n, "num_workers")
            issues = []
            if nw is None or is_const(nw, 0):
                issues.append("num_workers missing/0")
            pm = kw(n, "pin_memory")
            if pm is None or is_const(pm, False):
                issues.append("pin_memory not set")
            if nw is not None and not is_const(nw, 0):
                pw = kw(n, "persistent_workers")
                if pw is None or is_const(pw, False):
                    issues.append("persistent_workers not set")
            if issues:
                yield n, "DataLoader: " + ", ".join(issues)


_AMP = r"autocast|GradScaler|Accelerator|Fabric|Trainer\(|bf16|fp16|mixed_precision|\bamp\b"


def ml003(f: FileInfo) -> Iterator[Hit]:
    if f.src_has(_AMP):
        return
    for n in ast.walk(f.tree):
        if isinstance(n, LOOPS) and is_train_loop(n) and not any(is_train_loop(x) for x in loops_around(n, comps=False)):
            yield n, "training loop with no autocast/AMP anywhere in the file"


_EVAL_NAME = re.compile(r"^_*(eval|valid|test|predict|infer)|_(eval|valid|test|predict|infer)")


def ml004(f: FileInfo) -> Iterator[Hit]:
    for fn in ast.walk(f.tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name.startswith("__"):
            continue
        nodes = list(ast.walk(fn))
        calls_eval = any(isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and x.func.attr == "eval" and not x.args for x in nodes)
        if not (_EVAL_NAME.search(fn.name) or calls_eval):
            continue
        text = " ".join(dotted(x.func) if isinstance(x, ast.Call) else dotted(x) for x in nodes if isinstance(x, (ast.Call, ast.Attribute)))
        decos = " ".join(ast.unparse(d) for d in fn.decorator_list)
        if re.search(r"no_grad|inference_mode", text + decos):
            continue
        if any(isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and x.func.attr == "backward" for x in nodes):
            continue
        if any(isinstance(x, LOOPS) for x in nodes):
            yield fn, f"`{fn.name}` runs a loop in eval mode without no_grad/inference_mode"


def ml005(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if not isinstance(n, (ast.For, ast.AsyncFor)):
            continue
        it = n.iter
        if isinstance(it, ast.Call) and dotted(it.func) == "range" and len(it.args) == 1:
            a = it.args[0]
            tensor = None
            if isinstance(a, ast.Subscript) and isinstance(a.value, ast.Attribute) and a.value.attr == "shape":
                tensor = a.value.value
            elif isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr == "size":
                tensor = a.func.value
            if isinstance(tensor, ast.Name) and isinstance(n.target, ast.Name):
                if any(isinstance(s, ast.Subscript) and isinstance(s.value, ast.Name) and s.value.id == tensor.id
                       and any(isinstance(x, ast.Name) and x.id == n.target.id for x in ast.walk(s.slice)) for b in n.body for s in ast.walk(b)):
                    yield n, f"Python loop indexing tensor `{tensor.id}` element by element"
        elif isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) and (
                it.func.attr in ("flatten", "ravel") or (it.func.attr in ("view", "reshape") and it.args and is_const(it.args[0], -1))):
            yield n, f"Python loop over `.{it.func.attr}()` elements of a tensor"


_CREATORS = {f"torch.{c}" for c in ("tensor", "zeros", "ones", "empty", "rand", "randn", "arange", "full", "eye", "as_tensor",
                                     "from_numpy", "randint", "linspace", "zeros_like", "ones_like")}
_MOVES = ("to", "cuda")


def _is_move(c: ast.AST) -> bool:
    return isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr in _MOVES


def ml006(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if not (isinstance(n, ast.Call) and dotted(n.func) in _CREATORS and kw(n, "device") is None):
            continue
        p = getattr(n, "_p", None)
        chained = isinstance(p, ast.Attribute) and p.attr in _MOVES and _is_move(getattr(p, "_p", None))
        if "_like" in dotted(n.func) and not chained:
            continue
        if not chained:
            tl = train_loops_around(n)
            chained = bool(tl) and any(_is_move(x) for x in ast.walk(tl[0]))
            hit = chained
        else:
            hit = bool(loops_around(n, comps=False))
        if hit:
            yield n, f"{dotted(n.func)}(...) created on CPU each step, then moved to the device"


def ml007(f: FileInfo) -> Iterator[Hit]:
    if not f.src_has(r"pin_memory\s*=\s*True"):
        return
    for n in ast.walk(f.tree):
        if _is_move(n) and kw(n, "non_blocking") is None and (n.args or n.func.attr == "cuda") and train_loops_around(n):
            recv = ast.unparse(n.func.value).lower()
            arg = ast.unparse(n.args[0]) if n.args else ""
            if re.search(r"model|net|loss|criterion|module", recv) or arg.startswith("torch.") and not arg.startswith("torch.device"):
                continue
            yield n, "`.to(...)`/`.cuda()` on pinned data without non_blocking=True"


def ml008(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Call) and dotted(n.func).endswith("cuda.synchronize") and loops_around(n, comps=False):
            yield n, "torch.cuda.synchronize() inside a loop"


_SAVERS = {"save_checkpoint", "save_pretrained"}


def ml009(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if not isinstance(n, ast.Call):
            continue
        if dotted(n.func) == "torch.save" or (isinstance(n.func, ast.Attribute) and n.func.attr in _SAVERS):
            loops = train_loops_around(n)
            if loops and not _guarded(n, loops[0], mod_only=False):
                yield n, "checkpoint written on every step"


def ml010(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "zero_grad" and kw(n, "set_to_none") is None:
            yield n, "zero_grad() without set_to_none=True"


_CONVS = {"Conv1d", "Conv2d", "Conv3d", "ConvTranspose1d", "ConvTranspose2d", "ConvTranspose3d"}


def ml011(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Call) and dotted(n.func).split(".")[-1] in _CONVS:
            groups = kw(n, "groups") or (n.args[6] if len(n.args) > 6 else None)
            first = kw(n, "in_channels") or (n.args[0] if n.args else None)
            if groups is None or first is None or is_const(groups, 1):
                continue
            g, c = ast.unparse(groups), ast.unparse(first)
            if g == c or re.search(r"in_?ch|^channels$|^dim$|^c$", g):
                yield n, f"{dotted(n.func)} with groups={g} (depthwise)"


_DYNAMIC = r"pad_sequence|multi[_-]?scale|variable[_-]?(length|size)|dynamic[_-]?shape|ragged"


def ml012(f: FileInfo) -> Iterator[Hit]:
    if not f.src_has(_DYNAMIC):
        return
    for n in ast.walk(f.tree):
        if isinstance(n, ast.Assign) and is_const(n.value, True) and any(dotted(t).endswith("cudnn.benchmark") for t in n.targets):
            yield n, "cudnn.benchmark=True while the file handles variable-shaped inputs"


_F64_NP = r"zeros|ones|empty|linspace|eye|random\.(rand|randn|random|uniform|normal)"
_TORCH_WRAP = {"torch.from_numpy", "torch.tensor", "torch.as_tensor"}


def ml013(f: FileInfo) -> Iterator[Hit]:
    for n in ast.walk(f.tree):
        if not isinstance(n, ast.Call):
            continue
        d = dotted(n.func)
        dt = kw(n, "dtype")
        if dt is not None and ast.unparse(dt) in ("torch.float64", "torch.double", "np.float64", "numpy.float64") and d.startswith("torch."):
            yield n, f"explicit float64 dtype in {d}"
        elif isinstance(n.func, ast.Attribute) and n.func.attr == "double" and not n.args and has_torch_receiver(n):
            yield n, "`.double()` converts to float64"
        elif d in _TORCH_WRAP and n.args and kw(n, "dtype") is None:
            a = n.args[0]
            if isinstance(a, ast.Call) and re.fullmatch(r"(np|numpy)\." + _F64_NP, dotted(a.func)) and kw(a, "dtype") is None:
                yield n, f"{d}({dotted(a.func)}(...)) produces float64"


def has_torch_receiver(n: ast.Call) -> bool:
    """`.double()` is also a plain method on non-torch objects; require a tensor-ish receiver name."""
    return bool(re.search(r"model|net|tensor|^x$|^y$|batch|input|target|data|weights|module", ast.unparse(n.func.value).lower()))


GENERAL: list[tuple[str, Callable[[FileInfo], Iterator[Hit]]]] = [
    ("OPT-PY-001", py001), ("OPT-PY-002", py002), ("OPT-PY-003", py003), ("OPT-PY-004", py004), ("OPT-PY-005", py005),
    ("OPT-PY-006", py006), ("OPT-PY-007", py007), ("OPT-PY-008", py008), ("OPT-PY-009", py009), ("OPT-PY-010", py010),
    ("OPT-PY-011", py011), ("OPT-PY-012", py012), ("OPT-PY-013", py013),
]
ML: list[tuple[str, Callable[[FileInfo], Iterator[Hit]]]] = [
    ("OPT-ML-001", ml001), ("OPT-ML-002", ml002), ("OPT-ML-003", ml003), ("OPT-ML-004", ml004), ("OPT-ML-005", ml005),
    ("OPT-ML-006", ml006), ("OPT-ML-007", ml007), ("OPT-ML-008", ml008), ("OPT-ML-009", ml009), ("OPT-ML-010", ml010),
    ("OPT-ML-011", ml011), ("OPT-ML-012", ml012), ("OPT-ML-013", ml013),
]


# ---------------------------------------------------------------- entry points

def _imports_torch(tree: ast.Module) -> bool:
    for n in ast.walk(tree):
        mods = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""] if isinstance(n, ast.ImportFrom) else []
        if any(m.split(".")[0] in ("torch", "torchvision", "lightning", "pytorch_lightning") for m in mods):
            return True
    return False


def analyze(source: str, relpath: str, profile: str = "auto") -> list[Finding]:
    """Run every static rule on one Python source. Raises SyntaxError for unparsable input (caller reports it)."""
    tree = ast.parse(source, filename=relpath)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._p = parent  # type: ignore[attr-defined]
    ml = profile == "ml" or (profile == "auto" and _imports_torch(tree))
    info = FileInfo(tree, source, ml, source.splitlines())
    rules = GENERAL + (ML if ml else [])
    out: list[Finding] = []
    for rule_id, fn in rules:
        r = STATIC_RULES[rule_id]
        seen: set[int] = set()
        for node, detail in fn(info):
            line = getattr(node, "lineno", 1)
            if line in seen:
                continue
            seen.add(line)
            end = getattr(node, "end_lineno", line) or line
            snippet = "\n".join(l.rstrip() for l in info.lines[line - 1:min(end, line + 5)])[:300]
            out.append(Finding("optimization", rule_id, r.severity, r.title, detail,
                               [Evidence(relpath, line, end, snippet)], None, "static", r.fix_hint))
    return out
