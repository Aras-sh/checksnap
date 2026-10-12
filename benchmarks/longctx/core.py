"""Run configuration, the call plan (what gets asked, deterministic) and the cost estimate."""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from checksnap.snap.calibrate import CharsPerToken

from .haystack import Item, base_items, build_haystack, hop_items, load_paragraphs, needle_items

DEFAULT_LENGTHS = (50_000, 100_000, 250_000, 500_000, 1_000_000, 2_000_000, 4_000_000, 8_000_000, 12_000_000)
SUITES = ("canary", "decoy", "order", "needles", "hop")     # canary, decoy and order share the 'base' call


def parse_tokens(s: str) -> int:
    s = s.strip().lower().replace("_", "")
    mult = {"k": 1_000, "m": 1_000_000}.get(s[-1:], 1)
    return int(float(s[:-1] if mult > 1 else s) * mult)


@dataclass
class Config:
    lengths: tuple[int, ...] = DEFAULT_LENGTHS
    seeds: tuple[int, ...] = (1, 2, 3)
    aux_seeds: int = 1              # order / needles / hop use only the first N seeds (cost)
    suites: tuple[str, ...] = SUITES
    mode: str = "synthetic"         # or "text" (needs text_path)
    text_path: str | None = None
    decoys: int = 5
    ks: tuple[int, ...] = (1, 5, 20)
    price: float = 0.09             # dollars per million input tokens
    chars_per_token: float | None = None
    _paras: list[str] | None = field(default=None, repr=False)

    @property
    def cpt(self) -> float:
        # conservative (low) chars/token from calibrate.py: haystacks come out at or under their nominal token length
        return self.chars_per_token or CharsPerToken(None).bounds("prose")[1]

    @property
    def paragraphs(self) -> list[str] | None:
        if self.mode != "text":
            return None
        if self._paras is None:
            if not self.text_path:
                raise ValueError("--mode text needs --text-path")
            self._paras = load_paragraphs(self.text_path)
        return self._paras

    def public(self) -> dict:
        return {"lengths": list(self.lengths), "seeds": list(self.seeds), "aux_seeds": self.aux_seeds, "suites": list(self.suites),
                "mode": self.mode, "text_path": self.text_path, "decoys": self.decoys, "ks": list(self.ks),
                "price_per_mtok": self.price, "chars_per_token": self.cpt}


@dataclass(frozen=True)
class CallSpec:
    id: str
    kind: str       # base | qshuf | hshuf | needles | hop
    length: int
    seed: int
    k: int = 0

    @property
    def label(self) -> str:
        return f"{self.kind}-k{self.k}" if self.k else self.kind


def plan_calls(cfg: Config) -> list[CallSpec]:
    S, aux = set(cfg.suites), cfg.seeds[:cfg.aux_seeds]
    base_seeds = cfg.seeds if S & {"canary", "decoy"} else aux if "order" in S else ()
    out = []
    def add(kind: str, L: int, s: int, k: int = 0) -> None:
        out.append(CallSpec(f"{kind}{'-k' + str(k) if k else ''}|L{L}|s{s}", kind, L, s, k))
    for L in sorted(set(cfg.lengths)):
        for s in base_seeds:
            add("base", L, s)
        if "order" in S:
            for s in aux:
                add("qshuf", L, s)
                add("hshuf", L, s)
        if "needles" in S:
            for k in cfg.ks:
                for s in aux:
                    add("needles", L, s, k)
        if "hop" in S:
            for s in aux:
                add("hop", L, s)
    return out


def items_for(spec: CallSpec, cfg: Config) -> tuple[list[Item], list[tuple[float, str]]]:
    if spec.kind in ("base", "qshuf", "hshuf"):
        items, plants = base_items(spec.seed, spec.length, cfg.decoys)
    elif spec.kind == "needles":
        items, plants = needle_items(spec.seed, spec.length, spec.k)
    else:
        items, plants = hop_items(spec.seed, spec.length)
    def shuffled(tag: str) -> list[Item]:
        r = random.Random(f"qorder:{tag}:{spec.seed}:{spec.length}:{spec.k}")
        x = items[:]
        r.shuffle(x)
        return x
    ordered = shuffled("base")
    if spec.kind == "qshuf":
        ordered = shuffled("qshuf")
        if [i.qid for i in ordered] == [i.qid for i in shuffled("base")]:
            ordered.reverse()
    return ordered, plants


def build_state(spec: CallSpec, cfg: Config, plants: list[tuple[float, str]]) -> tuple[str, float]:
    return build_haystack(spec.seed, spec.length, cfg.cpt, plants, paragraphs=cfg.paragraphs, shuffle_records=spec.kind == "hshuf")


def estimate(spec: CallSpec, cfg: Config, backend) -> tuple[int, int]:
    """(HTTP requests, input tokens) for one call. Chat with questions_per_request=1 repeats the haystack per question."""
    items, _ = items_for(spec, cfg)
    return backend.estimate(items, spec.length)


def plan_summary(cfg: Config, specs: list[CallSpec], backend) -> dict:
    by_label: dict[str, list[int]] = {}
    by_len: dict[int, list[int]] = {}
    for s in specs:
        req, tok = estimate(s, cfg, backend)
        for d, key in ((by_label, s.label), (by_len, s.length)):
            row = d.setdefault(key, [0, 0, 0])
            row[0] += 1
            row[1] += req
            row[2] += tok
    total = [sum(r[i] for r in by_len.values()) for i in range(3)]
    return {"calls": total[0], "requests": total[1], "tokens": total[2], "dollars": total[2] / 1e6 * cfg.price,
            "by_label": by_label, "by_length": by_len}


def plan_text(cfg: Config, plan: dict) -> str:
    def table(title: str, rows: dict, fmt) -> list[str]:
        out = [f"| {title} | calls | requests | tokens | est. $ |", "|---|---:|---:|---:|---:|"]
        out += [f"| {fmt(k)} | {r[0]} | {r[1]} | {r[2]:,} | {r[2] / 1e6 * cfg.price:,.2f} |" for k, r in rows.items()]
        return out
    lines = table("call kind", plan["by_label"], str) + [""] + table("length (tokens)", plan["by_length"], lambda k: f"{k:,}")
    lines += ["", f"TOTAL: {plan['calls']} calls, {plan['requests']} HTTP requests, {plan['tokens']:,} input tokens, "
              f"${plan['dollars']:,.2f} at ${cfg.price}/M tokens (before retries; haystack sized at {cfg.cpt:.2f} chars/token)"]
    return "\n".join(lines)
