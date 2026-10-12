"""Aggregate per-call records into the five measurements. Every rate carries n and a Wilson 95% interval; nothing is dropped
silently: errored calls are counted, and 'valid-only' figures sit next to the all-calls figures, never instead of them."""
from __future__ import annotations

import math
import statistics
from collections import defaultdict
from typing import Iterable


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float | None, float | None]:
    if n == 0:
        return None, None
    p, d = k / n, 1 + z * z / n
    c, h = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (c - h) / d), min(1.0, (c + h) / d)


def cell(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": k / n if n else None, "lo": lo, "hi": hi}


def fmt(c: dict | None) -> str:
    if not c or not c["n"]:
        return "n/a (n=0)"
    return f"{c['rate']:.2f} [{c['lo']:.2f}-{c['hi']:.2f}] n={c['n']}"


def _ok(recs: Iterable[dict], *kinds: str) -> list[dict]:
    return [r for r in recs if r["status"] == "ok" and r["kind"] in kinds]


def _valid(r: dict) -> bool:
    """checksnap's guard: a call whose canary was missed cannot vouch for its other answers."""
    return all(i["ok"] for i in r["items"] if i["group"] == "canary")


def _by_len(recs: list[dict]) -> dict[int, list[dict]]:
    d: dict[int, list[dict]] = defaultdict(list)
    for r in recs:
        d[r["length"]].append(r)
    return dict(sorted(d.items()))


def _errors(recs: list[dict], *kinds: str) -> dict[int, int]:
    d: dict[int, int] = defaultdict(int)
    for r in recs:
        if r["status"] != "ok" and r["kind"] in kinds:
            d[r["length"]] += 1
    return d


def measure_canary(recs: list[dict]) -> list[dict]:
    rows, err = [], _errors(recs, "base")
    for L, rs in _by_len(_ok(recs, "base")).items():
        pos: dict[str, list[bool]] = defaultdict(list)
        for r in rs:
            for i in r["items"]:
                if i["group"] == "canary":
                    pos[f"{round(i['target'] * 100)}%"].append(i["ok"])
        allv = [x for v in pos.values() for x in v]
        rows.append({"length": L, "calls": len(rs), "errored_calls": err.get(L, 0),
                     "by_position": {p: cell(sum(v), len(v)) for p, v in sorted(pos.items(), key=lambda kv: int(kv[0][:-1]))},
                     "all": cell(sum(allv), len(allv)),
                     "mean_actual_position": {p: statistics.mean(i["actual"] for r in rs for i in r["items"]
                                                                  if i["group"] == "canary" and f"{round(i['target'] * 100)}%" == p) for p in pos}})
    return rows


def measure_decoy(recs: list[dict]) -> list[dict]:
    rows = []
    for L, rs in _by_len(_ok(recs, "base")).items():
        def rate(group: str, only_valid: bool) -> dict:
            xs = [i["said"] for r in rs if not only_valid or _valid(r) for i in r["items"] if i["group"] == group]
            return cell(sum(xs), len(xs))
        rows.append({"length": L, "calls": len(rs), "invalid_calls": sum(not _valid(r) for r in rs),
                     "decoy_fa_all": rate("decoy", False), "decoy_fa_valid": rate("decoy", True),
                     "distractor_fa_all": rate("distractor", False), "distractor_fa_valid": rate("distractor", True)})
    return rows


def _flip(a: dict, b: dict) -> tuple[bool, float | None]:
    """snap: probabilities cross the threshold by more than 0.5. chat: the normalised answer text changed."""
    if isinstance(a["raw"], float) and isinstance(b["raw"], float):
        d = abs(a["raw"] - b["raw"])
        return a["said"] != b["said"] and d > 0.5, d
    return a["raw"] != b["raw"], None


def measure_order(recs: list[dict]) -> list[dict]:
    base = {(r["length"], r["seed"]): r for r in _ok(recs, "base")}
    rows = []
    for var in ("qshuf", "hshuf"):
        for L, rs in _by_len(_ok(recs, var)).items():
            def stats(only_valid: bool) -> dict:
                flips, ds = [], []
                for r in rs:
                    b = base.get((L, r["seed"]))
                    if b is None or (only_valid and not (_valid(b) and _valid(r))):
                        continue
                    bi = {i["qid"]: i for i in b["items"]}
                    for i in r["items"]:
                        f, d = _flip(bi[i["qid"]], i)
                        flips.append(f)
                        if d is not None:
                            ds.append(d)
                return {"flips": cell(sum(flips), len(flips)), "mean_abs_dp": statistics.mean(ds) if ds else None}
            rows.append({"length": L, "variant": "question order" if var == "qshuf" else "record order", "calls": len(rs),
                         "all": stats(False), "valid": stats(True)})
    return sorted(rows, key=lambda r: (r["length"], r["variant"]))


def measure_cost(recs: list[dict], price: float) -> dict:
    rows = []
    for L, rs in _by_len(recs).items():
        ok = [r for r in rs if r["status"] == "ok"]
        secs = [r["seconds"] for r in ok]
        billed = sum(r["billed_in"] for r in ok)
        rows.append({"length": L, "calls_ok": len(ok), "calls_error": len(rs) - len(ok), "requests": sum(r["requests"] for r in ok),
                     "billed_tokens": billed, "est_tokens": sum(r["est_tokens"] for r in ok),
                     "sec_mean": statistics.mean(secs) if secs else None, "sec_max": max(secs) if secs else None,
                     "dollars": billed / 1e6 * price})
    ok = [r for r in recs if r["status"] == "ok"]
    chars, billed = sum(r["state_chars"] for r in ok), sum(r["billed_in"] for r in ok)
    return {"rows": rows, "total_calls": len(ok), "total_billed_tokens": billed, "total_dollars": billed / 1e6 * price,
            "observed_chars_per_token": chars / billed if billed else None,
            "unparsed_answers": sum(r.get("unparsed", 0) for r in ok), "usage_estimated_calls": sum(bool(r.get("usage_estimated")) for r in ok)}


def measure_needles(recs: list[dict]) -> list[dict]:
    rows = []
    for k in sorted({r["k"] for r in recs if r["kind"] == "needles"}):
        for L, rs in _by_len(_ok([r for r in recs if r["k"] == k], "needles")).items():
            xs = [i["ok"] for r in rs for i in r["items"]]
            full = sum(all(i["ok"] for i in r["items"]) for r in rs)
            rows.append({"k": k, "length": L, "calls": len(rs), "recall": cell(sum(xs), len(xs)), "calls_all_found": f"{full}/{len(rs)}"})
    return rows


def measure_hop(recs: list[dict]) -> list[dict]:
    rows = []
    for L, rs in _by_len(_ok(recs, "hop")).items():
        g = lambda name: [i["ok"] for r in rs for i in r["items"] if i["group"] == name]
        both = [all(i["ok"] for i in r["items"]) for r in rs]
        rows.append({"length": L, "calls": len(rs), "true_question_correct": cell(sum(g("hop_true")), len(g("hop_true"))),
                     "false_question_correct": cell(sum(g("hop_false")), len(g("hop_false"))), "both_correct": cell(sum(both), len(both))})
    return rows


def build_report(recs: list[dict], meta: dict) -> dict:
    price = meta["config"]["price_per_mtok"]
    return {"meta": meta, "canary": measure_canary(recs), "decoy": measure_decoy(recs), "order": measure_order(recs),
            "cost": measure_cost(recs, price), "needles": measure_needles(recs), "hop": measure_hop(recs),
            "rules": RULES}


RULES = ["n is reported in every cell; intervals are Wilson 95%. With 3 seeds per position expect wide intervals.",
         "Canary recall counts every call, missed or not. A call whose canary was missed is INVALID for decoy / order statistics; "
         "both all-calls and valid-only figures are shown, never only the better one.",
         "Errored calls (too large, rate limited out) are counted and excluded from rates, never retried silently.",
         "Chat backend: a hit is the exact token; a false alarm is any answer other than NOT FOUND. Snap backend: p >= threshold."]


def _t(headers: list[str], rows: list[list]) -> str:
    return "\n".join(["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)] + ["| " + " | ".join(map(str, r)) + " |" for r in rows])


def render_markdown(rep: dict) -> str:
    m, out = rep["meta"], []
    out += [f"# Long-context benchmark ({m['backend']} backend)", "",
            f"model `{m['model']}`, seeds {m['config']['seeds']} (aux suites use the first {m['config']['aux_seeds']}), mode {m['config']['mode']}, "
            f"started {m['started']}", ""]
    out += [f"- {r}" for r in rep["rules"]] + [""]
    if rep["canary"]:
        pos = sorted({p for r in rep["canary"] for p in r["by_position"]}, key=lambda p: int(p[:-1]))
        out += ["## 1. Canary recall by length and position", "",
                _t(["tokens", "calls", "errored"] + pos + ["all"],
                   [[f"{r['length']:,}", r["calls"], r["errored_calls"]] + [fmt(r["by_position"].get(p)) for p in pos] + [fmt(r["all"])]
                    for r in rep["canary"]]), ""]
    if rep["decoy"]:
        out += ["## 2. False alarms (always-false decoys; hard distractors = canary with one detail changed)", "",
                _t(["tokens", "calls", "invalid calls", "decoy FA (all)", "decoy FA (valid)", "distractor FA (all)", "distractor FA (valid)"],
                   [[f"{r['length']:,}", r["calls"], r["invalid_calls"], fmt(r["decoy_fa_all"]), fmt(r["decoy_fa_valid"]),
                     fmt(r["distractor_fa_all"]), fmt(r["distractor_fa_valid"])] for r in rep["decoy"]]), ""]
    if rep["order"]:
        f = lambda s: "n/a" if s["mean_abs_dp"] is None else f"{s['mean_abs_dp']:.3f}"
        out += ["## 3. Order sensitivity (flip = answer changed vs the unshuffled call)", "",
                _t(["tokens", "shuffled", "calls", "flips (all)", "mean abs dp (all)", "flips (valid)", "mean abs dp (valid)"],
                   [[f"{r['length']:,}", r["variant"], r["calls"], fmt(r["all"]["flips"]), f(r["all"]), fmt(r["valid"]["flips"]), f(r["valid"])]
                    for r in rep["order"]]), ""]
    c = rep["cost"]
    if c["rows"]:
        s = lambda x: "n/a" if x is None else f"{x:.1f}"
        out += ["## 4. Cost and latency", "",
                _t(["tokens", "calls ok", "errors", "requests", "billed tokens", "estimated", "s/call mean", "s/call max", "$"],
                   [[f"{r['length']:,}", r["calls_ok"], r["calls_error"], r["requests"], f"{r['billed_tokens']:,}", f"{r['est_tokens']:,}",
                     s(r["sec_mean"]), s(r["sec_max"]), f"{r['dollars']:.2f}"] for r in c["rows"]]), "",
                f"Total: {c['total_calls']} calls, {c['total_billed_tokens']:,} billed tokens, ${c['total_dollars']:.2f}; observed chars/token "
                f"{'n/a' if not c['observed_chars_per_token'] else format(c['observed_chars_per_token'], '.2f')}; "
                f"unparsed answers {c['unparsed_answers']}; calls with estimated usage {c['usage_estimated_calls']}.", ""]
    if rep["needles"]:
        out += ["## 5a. Multi-needle (k facts retrieved in one call)", "",
                _t(["k", "tokens", "calls", "recall", "calls with all k found"],
                   [[r["k"], f"{r['length']:,}", r["calls"], fmt(r["recall"]), r["calls_all_found"]] for r in rep["needles"]]), ""]
    if rep["hop"]:
        out += ["## 5b. Two-hop (fact A names the entity, fact B gives its property)", "",
                _t(["tokens", "calls", "true question", "false question", "both correct"],
                   [[f"{r['length']:,}", r["calls"], fmt(r["true_question_correct"]), fmt(r["false_question_correct"]), fmt(r["both_correct"])]
                    for r in rep["hop"]]), ""]
    return "\n".join(out)
