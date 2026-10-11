"""Streaming local analyzers. Each has feed(...) per record and findings() at the end; none keeps whole records."""
from __future__ import annotations

import math
import random
import re
from collections import Counter
from typing import Any

from checksnap.core import Evidence, Finding, Severity

from .pii import find_pii
from .records import BItem, Rec
from .rules import RULES
from .textutil import DupIndex, Ref, words

MAX_EV = 6


def mk(rule: str, title: str | None = None, detail: str = "", evidence: list[Evidence] | None = None,
       score: float | None = None, source: str = "local", severity: Severity | None = None) -> Finding:
    r = RULES[rule]
    return Finding("dataset", rule, severity if severity is not None else r.severity, title or r.title, detail,
                   evidence or [], score, source, r.fix_hint)


def ev(file: str, idx: int | None, snippet: str = "", **extra: Any) -> Evidence:
    return Evidence(file, idx, idx, snippet[:160], extra)


# ---------------------------------------------------------------- duplicates / leaks
def dup_findings(ix: DupIndex) -> list[Finding]:
    out = []
    ex = sorted(ix.exact_clusters(), key=len, reverse=True)
    if ex:
        n = sum(len(c) - 1 for c in ex)
        out.append(mk("DS-DUP-001", detail=f"{len(ex)} groups, {n} redundant records. Largest group: {len(ex[0])} copies.",
                      evidence=[ev(ix.refs[i].file, ix.refs[i].idx, ix.refs[i].snippet, group=len(c))
                                for c in ex[:MAX_EV] for i in c[:2]][:MAX_EV * 2], source="hash"))
    nr = sorted(ix.near_clusters(), key=len, reverse=True)
    if nr:
        out.append(mk("DS-DUP-002", detail=f"{len(nr)} clusters, {sum(len(c) for c in nr)} records (est. Jaccard >= {ix.threshold}).",
                      evidence=[ev(ix.refs[i].file, ix.refs[i].idx, ix.refs[i].snippet, cluster=len(c))
                                for c in nr[:MAX_EV] for i in c[:2]][:MAX_EV * 2], source="hash"))
    return out




def leak_findings(ds: DupIndex, ev_recs: list[Rec], ds_ids: set[str], ev_ids: dict[str, Ref]) -> list[Finding]:
    exact: list[Evidence] = []
    near: list[Evidence] = []
    n_ex = n_near = 0
    for r in ev_recs:
        e, nr = ds.query(r.text)
        if e:
            n_ex += 1
            exact.append(ev(r.file, r.idx, r.text, dataset_match=f"{ds.refs[e[0]].file}:{ds.refs[e[0]].idx}"))
        elif nr:
            c, j = max(nr, key=lambda t: t[1])
            n_near += 1
            near.append(ev(r.file, r.idx, r.text, dataset_match=f"{ds.refs[c].file}:{ds.refs[c].idx}", jaccard=round(j, 2)))
    out = []
    if n_ex:
        out.append(mk("DS-LEAK-001", detail=f"{n_ex} of {len(ev_recs)} eval records occur exactly in the dataset.", evidence=exact[:MAX_EV],
                      source="hash"))
    if n_near:
        out.append(mk("DS-LEAK-002", detail=f"{n_near} eval records are near-duplicates of dataset records.", evidence=near[:MAX_EV], source="hash"))
    shared = sorted(ds_ids & set(ev_ids))
    if shared:
        out.append(mk("DS-LEAK-003", detail=f"{len(shared)} ids occur in both splits, e.g. {', '.join(shared[:5])}.",
                      evidence=[ev(ev_ids[s].file, ev_ids[s].idx, s) for s in shared[:MAX_EV]]))
    return out


# ---------------------------------------------------------------- PII
class Pii:
    def __init__(self) -> None:
        self.by_kind: dict[str, dict[str, Any]] = {}

    def feed(self, rec: Rec) -> None:
        for kind, sev, masked in find_pii(rec.text):
            d = self.by_kind.setdefault(kind, {"sev": sev, "n": 0, "recs": set(), "ex": []})
            d["n"] += 1
            d["recs"].add((rec.file, rec.idx))
            if len(d["ex"]) < MAX_EV:
                d["ex"].append(ev(rec.file, rec.idx, masked))

    def findings(self) -> list[Finding]:
        return [mk("DS-PII-001", title=f"{k} found in records", detail=f"{d['n']} matches in {len(d['recs'])} records.",
                   evidence=d["ex"], severity=d["sev"])
                for k, d in sorted(self.by_kind.items(), key=lambda kv: (-kv[1]["sev"], kv[0]))]


# ---------------------------------------------------------------- local contamination (n-gram)
class LocalContam:
    """8/13-gram overlap of benchmark items with dataset records. Hashing of word windows, one pass over the data."""

    def __init__(self, items: list[BItem]) -> None:
        self.items = items
        self.ws = [words(it.text) for it in items]
        self.g: dict[int, dict[int, set[int]]] = {8: {}, 13: {}}
        self.total: dict[int, list[int]] = {8: [], 13: []}
        self.eq: dict[str, list[int]] = {}
        self.blind = 0
        for i, ws in enumerate(self.ws):
            if len(ws) < 8:
                self.blind += 1
            if ws:
                self.eq.setdefault(" ".join(ws), []).append(i)
            for n in (8, 13):
                grams = {hash(" ".join(ws[j:j + n])) for j in range(len(ws) - n + 1)}
                self.total[n].append(len(grams))
                for h in grams:
                    self.g[n].setdefault(h, set()).add(i)
        self.hits: dict[int, dict[str, Any]] = {}

    def _hit(self, i: int, rec: Rec) -> dict[str, Any]:
        return self.hits.setdefault(i, {8: set(), 13: set(), "exact": False, "at": (rec.file, rec.idx)})

    def feed(self, rec: Rec) -> None:
        ws = words(rec.text)
        if not ws:
            return
        for i in self.eq.get(" ".join(ws), ()):
            self._hit(i, rec)["exact"] = True
        cand: set[int] = set()
        for n in (8, 13):
            table = self.g[n]
            for j in range(len(ws) - n + 1):
                h = hash(" ".join(ws[j:j + n]))
                if h in table:
                    for i in table[h]:
                        self._hit(i, rec)[n].add(h)
                        cand.add(i)
        if cand:
            padded = " " + " ".join(ws) + " "
            for i in cand:
                if not self.hits[i]["exact"] and len(self.ws[i]) >= 8 and " " + " ".join(self.ws[i]) + " " in padded:
                    self.hits[i]["exact"] = True

    def level(self, i: int) -> tuple[str, float] | None:
        h = self.hits.get(i)
        if not h:
            return None
        if h["exact"]:
            return "exact", 1.0
        for n in (13, 8):
            if h[n]:
                return f"{n}-gram", len(h[n]) / max(1, self.total[n][i])
        return None

    def findings(self) -> list[Finding]:
        out = []
        for i in sorted(self.hits):
            lv = self.level(i)
            if not lv:
                continue
            kind, frac = lv
            sev = (Severity.HIGH if kind == "exact" or (kind == "13-gram" and frac >= 0.5) else
                   Severity.MEDIUM if kind == "13-gram" or frac >= 0.5 else Severity.LOW)
            it = self.items[i]
            f, ln = self.hits[i]["at"]
            out.append(mk("DS-CONTAM-002", title=f"Benchmark item overlaps the data ({kind})",
                          detail=f"{it.file}:{it.line}: {kind} match, {frac:.0%} of its n-grams found. First seen in {f}:{ln}.",
                          evidence=[ev(f, ln, it.text, benchmark=f"{it.file}:{it.line}", level=kind, fraction=round(frac, 3))],
                          score=round(frac, 3), source="hash", severity=sev))
        if self.blind:
            out.append(mk("DS-CONTAM-002", title="Short benchmark items are blind to n-gram matching",
                          detail=f"{self.blind} of {len(self.items)} items have fewer than 8 words; only whole-record equality can catch them.",
                          severity=Severity.INFO))
        return out


# ---------------------------------------------------------------- hygiene
_MOJI = re.compile("�|Ã[\u0080-¿]|â€|Â[ -¿]")
_NULLS = {"nan", "null", "none"}
_STOP = {
    "en": {"the", "and", "of", "to", "is", "in", "that", "it", "with", "for", "this"},
    "de": {"der", "die", "und", "das", "ist", "nicht", "ein", "zu", "mit", "auf", "ich"},
    "fr": {"le", "la", "les", "et", "est", "des", "un", "une", "que", "pour", "dans"},
    "es": {"el", "los", "las", "es", "una", "que", "por", "con", "para", "del", "y"},
    "tr": {"ve", "bir", "bu", "için", "ile", "çok", "da", "de", "ne", "gibi", "değil"},
    "it": {"il", "di", "che", "è", "per", "una", "sono", "con", "non", "della", "gli"},
}
_SCRIPTS = [("cyrillic", 0x400, 0x4FF), ("greek", 0x370, 0x3FF), ("arabic", 0x600, 0x6FF), ("hebrew", 0x590, 0x5FF),
            ("devanagari", 0x900, 0x97F), ("thai", 0xE00, 0xE7F), ("cjk", 0x3040, 0x30FF), ("cjk", 0x4E00, 0x9FFF),
            ("hangul", 0xAC00, 0xD7AF)]


def lang_of(text: str) -> str | None:
    c: Counter[str] = Counter()
    for ch in text[:2000]:
        if ch.isalpha():
            o = ord(ch)
            c[next((n for n, lo, hi in _SCRIPTS if lo <= o <= hi), "latin")] += 1
    if sum(c.values()) < 20:
        return None
    script = c.most_common(1)[0][0]
    if script != "latin":
        return script
    ws = set(words(text[:2000]))
    best = max(_STOP, key=lambda k: len(ws & _STOP[k]))
    return f"latin:{best}" if len(ws & _STOP[best]) >= 3 else None


def _empty(v: Any) -> bool:
    return (v is None or (isinstance(v, float) and math.isnan(v)) or
            (isinstance(v, str) and (not v.strip() or v.strip().lower() in _NULLS)))


class Hygiene:
    def __init__(self, label_field: str | None, id_field: str | None) -> None:
        self.label_field, self.id_field = label_field, id_field
        self.n = 0
        self.lens: list[tuple[int, str, int]] = []
        self.keysets: Counter[frozenset] = Counter()
        self.key_ex: dict[frozenset, tuple[str, int]] = {}
        self.empty: dict[str, list[Any]] = {}
        self.ids: dict[str, tuple[str, int]] = {}
        self.dup_ids: dict[str, int] = {}
        self.moji: list[Evidence] = []
        self.moji_n = 0
        self.labels: Counter[str] = Counter()
        self.langs: Counter[str] = Counter()

    def feed(self, rec: Rec) -> None:
        self.n += 1
        self.lens.append((len(rec.text), rec.file, rec.idx))
        raw = rec.raw
        if raw is not None:
            ks = frozenset(raw)
            self.keysets[ks] += 1
            self.key_ex.setdefault(ks, (rec.file, rec.idx))
            for k, v in raw.items():
                if _empty(v):
                    d = self.empty.setdefault(k, [0, rec.file, rec.idx])
                    d[0] += 1
            if self.id_field and self.id_field in raw and raw[self.id_field] is not None:
                i = str(raw[self.id_field])
                if i in self.ids:
                    self.dup_ids[i] = self.dup_ids.get(i, 1) + 1
                else:
                    self.ids[i] = (rec.file, rec.idx)
            if self.label_field and self.label_field in raw and not _empty(raw[self.label_field]):
                self.labels[str(raw[self.label_field])] += 1
        elif not rec.text.strip():
            d = self.empty.setdefault("(text)", [0, rec.file, rec.idx])
            d[0] += 1
        if _MOJI.search(rec.text):
            self.moji_n += 1
            if len(self.moji) < MAX_EV:
                m = _MOJI.search(rec.text)
                self.moji.append(ev(rec.file, rec.idx, rec.text[max(0, m.start() - 30):m.end() + 30]))
        lg = lang_of(rec.text)
        if lg:
            self.langs[lg] += 1

    def findings(self, eval_labels: Counter[str] | None = None, bad_lines: list[tuple[str, int, str]] | None = None) -> list[Finding]:
        out: list[Finding] = []
        if self.empty:
            out.append(mk("DS-HYG-001", detail="; ".join(f"{k}: {d[0]}" for k, d in sorted(self.empty.items(), key=lambda kv: -kv[1][0])[:10]),
                          evidence=[ev(d[1], d[2], f"field {k}") for k, d in list(self.empty.items())[:MAX_EV]]))
        if len(self.keysets) > 1:
            (major, mc), *rest = self.keysets.most_common()
            rows = []
            for ks, c in rest[:MAX_EV]:
                rows.append(ev(*self.key_ex[ks], f"keys differ: +{sorted(ks - major)[:4]} -{sorted(major - ks)[:4]}", records=c))
            out.append(mk("DS-HYG-002", detail=f"{len(self.keysets)} distinct key sets; the most common covers {mc} of {sum(self.keysets.values())} records.",
                          evidence=rows))
        if self.dup_ids:
            out.append(mk("DS-HYG-003", detail=f"{len(self.dup_ids)} ids repeat, e.g. {', '.join(list(self.dup_ids)[:5])}.",
                          evidence=[ev(*self.ids[i], f"id {i} x{c}") for i, c in list(self.dup_ids.items())[:MAX_EV]]))
        if self.n >= 20:
            s = sorted(x[0] for x in self.lens)
            q1, q3 = s[len(s) // 4], s[(3 * len(s)) // 4]
            iqr = q3 - q1
            if iqr > 0:
                hi, lo = q3 + 3 * iqr, q1 - 3 * iqr
                bad = [x for x in self.lens if x[0] > hi or x[0] < lo]
                if bad:
                    bad.sort(key=lambda x: -abs(x[0] - (q1 + q3) / 2))
                    out.append(mk("DS-HYG-004", detail=f"{len(bad)} records outside [{max(0, lo):.0f}, {hi:.0f}] chars (quartiles {q1}..{q3}).",
                                  evidence=[ev(f, i, f"{n} chars") for n, f, i in bad[:MAX_EV]]))
        if self.moji_n:
            out.append(mk("DS-HYG-005", detail=f"{self.moji_n} records.", evidence=self.moji))
        if self.labels and len(self.labels) > 1:
            tot = sum(self.labels.values())
            (top, tc), *_ = self.labels.most_common()
            mn = min(self.labels.values())
            if tc / tot > 0.9 or tc / mn >= 10:
                out.append(mk("DS-HYG-006", detail=f"{len(self.labels)} classes; '{top}' is {tc / tot:.0%}; largest/smallest = {tc / mn:.0f}x."))
        if eval_labels and self.labels:
            ta, tb = sum(self.labels.values()), sum(eval_labels.values())
            keys = set(self.labels) | set(eval_labels)
            tvd = 0.5 * sum(abs(self.labels[k] / ta - eval_labels[k] / tb) for k in keys)
            only = sorted(set(eval_labels) ^ set(self.labels))
            if tvd >= 0.15 or only:
                out.append(mk("DS-HYG-007", detail=f"label distribution distance (TV) {tvd:.2f}" + (f"; classes in only one split: {only[:8]}" if only else "")))
        bad_lines = bad_lines or []
        mx = max((x[0] for x in self.lens), default=0)
        at_max = [x for x in self.lens if x[0] == mx]
        hard_cap = self.n >= 20 and mx >= 128 and len(at_max) >= 10 and len(at_max) / self.n >= 0.05
        if bad_lines or hard_cap:
            d = []
            if bad_lines:
                d.append(f"{len(bad_lines)} unparsable lines")
            if hard_cap:
                d.append(f"{len(at_max)} records have exactly {mx} chars (hard truncation limit?)")
            out.append(mk("DS-HYG-008", detail="; ".join(d),
                          evidence=[ev(f, ln, why) for f, ln, why in bad_lines[:MAX_EV]] or [ev(f, i, f"{n} chars") for n, f, i in at_max[:MAX_EV]]))
        classified = sum(self.langs.values())
        if classified >= 10 and len(self.langs) > 1:
            second = self.langs.most_common()[1]
            if second[1] / classified >= 0.05:
                out.append(mk("DS-HYG-009", detail="; ".join(f"{k}: {c / classified:.0%}" for k, c in self.langs.most_common(5))))
        return out


# ---------------------------------------------------------------- licences
_LIC_RX = re.compile(r"all rights reserved|non-?\s?commercial|\bno[- ]deriv(?:s|ative)|cc[- ]by[- ]n[cd]|not for commercial", re.I)


class License:
    SAMPLE = 300          # records kept for the Snap licence question (reservoir), 1000 chars each

    def __init__(self, lic_field: str | None, src_field: str | None, allowed: set[str], seed: int = 0) -> None:
        self.lic_field, self.src_field, self.allowed = lic_field, src_field, allowed
        self.values: Counter[str] = Counter()
        self.first: dict[str, tuple[str, int]] = {}
        self.lex: list[Evidence] = []
        self.lex_n = 0
        self.sample: list[str] = []
        self.heads: dict[str, str] = {}
        self.seen = 0
        self.rng = random.Random(seed)

    def feed(self, rec: Rec) -> None:
        if rec.file not in self.heads and len(self.heads) < 100:
            self.heads[rec.file] = rec.text[:2000]
        self.seen += 1
        if len(self.sample) < self.SAMPLE:
            self.sample.append(rec.text[:1000])
        elif (j := self.rng.randrange(self.seen)) < self.SAMPLE:
            self.sample[j] = rec.text[:1000]
        for fld in (self.lic_field, self.src_field):
            if fld and rec.raw is not None:
                v = rec.raw.get(fld)
                key = f"{fld}={'(missing)' if _empty(v) else str(v).strip()}"
                self.values[key] += 1
                self.first.setdefault(key, (rec.file, rec.idx))
        m = _LIC_RX.search(rec.text)
        if m:
            self.lex_n += 1
            if len(self.lex) < MAX_EV:
                self.lex.append(ev(rec.file, rec.idx, rec.text[max(0, m.start() - 40):m.end() + 40]))

    def snap_text(self) -> str:
        return "\n\n".join([*self.heads.values(), *self.sample])

    def findings(self) -> list[Finding]:
        out = []
        if self.allowed:
            bad = [(k, c) for k, c in self.values.items() if k.split("=", 1)[1].lower() not in self.allowed]
            if bad:
                out.append(mk("DS-LIC-001", title="Licence/source not in --allowed-licenses",
                              detail="; ".join(f"{k} x{c}" for k, c in sorted(bad, key=lambda kv: -kv[1])[:10]),
                              evidence=[ev(*self.first[k], k) for k, _ in bad[:MAX_EV]]))
        if self.lex_n:
            out.append(mk("DS-LIC-001", title="Restrictive licence wording in records", severity=Severity.LOW,
                          detail=f"{self.lex_n} records mention non-commercial / no-derivatives / all rights reserved.", evidence=self.lex))
        return out
