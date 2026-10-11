"""Rules TL-001..TL-010 over the records of one log file. Each rule yields at most one finding per file so reports stay short."""
from __future__ import annotations

import math
import re
import statistics as st
from collections import Counter

from checksnap.core import Evidence, Finding

from .parse import STEP_KEYS, Record, finite
from .rules import RULES

_VAL = re.compile(r"(^|_)(val|valid|validation|eval)_.*loss|loss_(val|valid|validation|eval)")
_TRAIN = {"loss", "train_loss", "training_loss", "loss_train", "train_loss_epoch", "train_loss_step"}
_MEM = ("gpu_mem", "gpu_memory", "mem_alloc", "memory_allocated", "max_memory", "cuda_mem", "vram")
_TIME = ("epoch_time", "time_per_epoch", "epoch_duration", "sec_per_epoch", "step_time", "iter_time", "time_per_step", "epoch_sec")


def kind(name: str) -> str | None:
    n = re.sub(r"[/.\- ]", "_", name.lower())
    if _VAL.search(n):
        return "val"
    if n in _TRAIN:
        return "train"
    if n in ("lr", "learning_rate", "train_lr") or n.startswith("lr_"):
        return "lr"
    if any(s in n for s in ("grad_norm", "gradnorm", "gradient_norm")):
        return "grad"
    if any(s in n for s in _TIME):
        return "time"
    if any(s in n for s in _MEM):
        return "mem"
    return None


Series = list[tuple[int, float | None, float]]      # (line, epoch-or-step key, value), finite values only


def _key(r: Record) -> float | None:
    for k in ("epoch", *STEP_KEYS):
        if k in r.vals:
            return r.vals[k]
    return None


def series(recs: list[Record], want: str) -> tuple[str, Series] | None:
    by: dict[str, Series] = {}
    for r in recs:
        for k, v in r.vals.items():
            if kind(k) == want and finite(v):
                by.setdefault(k, []).append((r.line, _key(r), v))
    if not by:
        return None
    name = max(sorted(by), key=lambda k: len(by[k]))      # most populated series wins, ties by name
    return name, by[name]


def _pair(t: Series, v: Series) -> list[tuple[int, float, float]]:
    if all(k is not None for _, k, _ in t + v):
        vd = {k: x for _, k, x in v}
        return [(ln, x, vd[k]) for ln, k, x in t if k in vd]
    return [(t[i][0], t[i][2], v[i][2]) for i in range(min(len(t), len(v)))]


def _m(xs: list[float]) -> float:
    return sum(xs) / len(xs)


def _f(rule: str, file: str, line: int, detail: str, snippet: str = "") -> Finding:
    r = RULES[rule]
    return Finding("traininglog", rule, r.severity, r.title, detail, [Evidence(file, line, line, snippet)], source="local", fix_hint=r.fix_hint)


def analyze(recs: list[Record], file: str) -> list[Finding]:
    out: list[Finding] = []
    # TL-001
    bad = [(r.line, k) for r in recs for k, v in r.vals.items() if not finite(v)]
    if bad:
        names = sorted({k for _, k in bad})
        out.append(_f("TL-001", file, bad[0][0], f"{len(bad)} non-finite value(s) in {', '.join(names[:5])}; first at line {bad[0][0]}", f"{bad[0][1]} is not finite"))
    tr, va = series(recs, "train"), series(recs, "val")
    if tr:
        name, s = tr
        x = [v for _, _, v in s]
        # TL-002
        for i in range(5, len(x)):
            med = st.median(x[max(0, i - 20):i])
            if med > 0 and x[i] > 3 * med:
                out.append(_f("TL-002", file, s[i][0], f"{name} = {x[i]:.4g} is {x[i] / med:.1f}x the median {med:.4g} of the previous steps", f"{name}={x[i]:.4g}"))
                break
        # TL-003
        n = len(x)
        if n >= 20:
            tail = max(10, n // 4)
            head_best, tail_best = min(x[:-tail]), min(x[-tail:])
            if head_best > 1e-4 and (head_best - tail_best) / head_best < 0.001:
                out.append(_f("TL-003", file, s[-tail][0], f"best {name} in the last {tail} points is {tail_best:.4g} vs {head_best:.4g} before: no progress"))
    if tr and va:
        p = _pair(tr[1], va[1])
        n = len(p)
        if n >= 6:
            th = n // 3
            t, v = [a for _, a, _ in p], [b for _, _, b in p]
            g1, g3 = _m([b - a for a, b in zip(t[:th], v[:th])]), _m([b - a for a, b in zip(t[-th:], v[-th:])])
            base = max(g1, 0.0)
            if g3 > 2 * base and g3 - base > 0.1 * abs(_m(v[-th:])):                       # TL-004
                out.append(_f("TL-004", file, p[-th][0], f"gap val-train grew from {g1:.4g} (first third) to {g3:.4g} (last third)"))
            pv, lv, pt, lt = _m(v[-2 * th:-th]), _m(v[-th:]), _m(t[-2 * th:-th]), _m(t[-th:])
            if lv > pv * 1.02 and lt < pt:                                                  # TL-005
                out.append(_f("TL-005", file, p[-th][0], f"val loss {pv:.4g} -> {lv:.4g} while train loss {pt:.4g} -> {lt:.4g} over the last two thirds"))
    # TL-006
    if lr := series(recs, "lr"):
        name, s = lr
        x, n, why = [v for _, _, v in s], len(s), None
        for i, (ln, _, v) in enumerate(s):
            if v < 0 or (v == 0 and i < n - max(1, n // 20) - 1 and i > 0):
                why = (ln, f"{name} = {v:g} before the end of the run")
                break
            if i > max(2, n // 10) and x[i - 1] > 0 and v / x[i - 1] >= 10:
                why = (ln, f"{name} jumped {x[i - 1]:.3g} -> {v:.3g} after warmup")
                break
        if why:
            out.append(_f("TL-006", file, why[0], why[1]))
    # TL-007
    if g := series(recs, "grad"):
        name, s = g
        x = [v for _, _, v in s]
        med = st.median(x)
        for ln, _, v in s:
            if v > 10 * med and v >= 5:
                out.append(_f("TL-007", file, ln, f"{name} = {v:.4g}, median {med:.4g}", f"{name}={v:.4g}"))
                break
    # TL-008 / TL-009
    for rule, w in (("TL-008", "time"), ("TL-009", "mem")):
        sr = series(recs, w)
        if not sr or len(sr[1]) < 6:
            continue
        name, s = sr
        x, th = [v for _, _, v in s], len(s) // 3
        if rule == "TL-008":
            a, b = st.median(x[:th]), st.median(x[-th:])
            if a > 0 and b > 1.5 * a:
                out.append(_f("TL-008", file, s[-th][0], f"median {name} rose from {a:.4g} to {b:.4g} ({b / a:.1f}x)"))
        else:
            a, b = _m(x[:th]), _m(x[-th:])
            up = sum(1 for i in range(1, len(x)) if x[i] >= x[i - 1])
            if a > 0 and b > 1.2 * a and up >= 0.8 * (len(x) - 1):
                out.append(_f("TL-009", file, s[-th][0], f"{name} grew from {a:.4g} to {b:.4g} (+{(b / a - 1) * 100:.0f}%) and rarely decreased"))
    # TL-010
    use_step = any(k in r.vals for r in recs for k in STEP_KEYS)
    seen: dict[float, set[str]] = {}
    dups: list[tuple[int, float]] = []
    for r in recs:
        k = next((r.vals[s] for s in STEP_KEYS if s in r.vals), None) if use_step else r.vals.get("epoch")
        if k is None:
            continue
        m = {n for n in r.vals if n != "epoch" and n not in STEP_KEYS}
        if m & seen.get(k, set()):
            dups.append((r.line, k))
        seen.setdefault(k, set()).update(m)
    if dups:
        c = Counter(k for _, k in dups)
        out.append(_f("TL-010", file, dups[0][0], f"{len(c)} {'step' if use_step else 'epoch'}(s) logged again, e.g. {dups[0][1]:g} at line {dups[0][0]}"))
    return out
