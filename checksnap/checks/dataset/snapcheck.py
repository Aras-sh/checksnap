"""Snap-backed parts: DS-CONTAM-001 (benchmark items in the data) and the DS-LIC-001 licence question.
checksnap.snap is imported lazily so local-only runs and the CLI start even if the engine is missing."""
from __future__ import annotations

import bisect
import math
from collections import defaultdict
from typing import Any, Iterable

from checksnap.core import CostEstimate, Evidence, Finding, Severity

from .analyzers import License, LocalContam, mk
from .records import BItem, Rec
from .textutil import words

PER_CALL_ITEMS = 55         # engine adds 8 decoys + 1 canary to each 64-question call; 56 would split into 55+1 and double the calls
WINDOW_CHARS = 300_000     # canary vs window curve (demo/README.md): 104k tokens/call passed, 126k missed both canaries
NEEDLE_CHARS = 600
CHARS_PER_TOKEN = 3.3
LIC_SAMPLE_CHARS = 340_000
LOCALIZE_MAX = 10           # localisation bisects with extra calls, so only the top hits get it

LIC_INSTRUCTIONS = ("Does this text state a restrictive licence for the data it contains, such as non-commercial use only, "
                    "no derivatives, or all rights reserved?")


def estimate_cost(engine: Any, total_chars: int, n_items: int, with_license: bool) -> CostEstimate:
    """Free. Contamination: every window is read once per batch of <=56 items; data is re-sent per batch."""
    def one(n_chars: int, n_q: int) -> CostEstimate:
        if engine is not None:
            try:
                return engine.estimate(n_chars, n_q)
            except Exception:  # noqa: BLE001  (estimate must never break the privacy prompt)
                pass
        return CostEstimate(max(1, math.ceil(n_chars / WINDOW_CHARS)), int(n_chars / CHARS_PER_TOKEN), n_chars)

    est = CostEstimate()
    if n_items and total_chars:
        for k in range(0, n_items, PER_CALL_ITEMS):
            est = est + one(total_chars, min(PER_CALL_ITEMS, n_items - k))
    if with_license and total_chars:
        est = est + one(min(total_chars, LIC_SAMPLE_CHARS), 1)
    est.notes = ("upper bound from file sizes; prefiltered mode sends less; localising hits adds a few calls each"
                 if est.snap_calls else "")
    return est


def contam_question(i: int, item: BItem):
    from checksnap.snap import Question
    needle = item.text[:NEEDLE_CHARS]
    return Question(
        f"b{i}",
        "Does the text contain the following benchmark item, either copied verbatim, reworded, translated into another language, "
        f"or only its solution/answer? [[needle]]{needle}[[/needle]]",
        "The text contains this item, or a close rewording, translation, or its solution.",
        "The text does not contain this item.")


def prefilter(records: Iterable[Rec], items: list[BItem], min_shared: int = 4) -> Iterable[Rec]:
    """Keep records sharing at least half (max 4) of an item's long words with that item. Cheap, but loses
    paraphrases that share few words: that is the documented recall cost of --contam-mode prefiltered."""
    index: dict[str, set[int]] = defaultdict(set)
    need: dict[int, int] = {}
    for i, it in enumerate(items):
        long_words = {w for w in words(it.text) if len(w) >= 6}
        need[i] = min(min_shared, max(1, math.ceil(len(long_words) / 2)))
        for w in long_words:
            index[w].add(i)
    for rec in records:
        hit: dict[int, int] = defaultdict(int)
        for w in set(words(rec.text)):
            for i in index.get(w, ()):
                hit[i] += 1
        if any(c >= need[i] for i, c in hit.items()):
            yield rec


def build_windows(records: Iterable[Rec], size: int = WINDOW_CHARS):
    """Pack whole records into windows of ~size chars. Returns (windows, maps) where maps[k] is a sorted
    list of (offset_in_window, file, idx) so a hit range can be traced back to a record."""
    from checksnap.snap import Window
    wins, maps, buf, starts, pos, base = [], [], [], [], 0, 0

    def flush():
        nonlocal buf, starts, base, pos
        if buf:
            text = "".join(buf)
            wins.append(Window(base, base + len(text), text))
            maps.append(starts)
            base += len(text)
        buf, starts, pos = [], [], 0

    for rec in records:
        piece = rec.text + "\n"
        if pos and pos + len(piece) > size:
            flush()
        starts.append((pos, rec.file, rec.idx))
        buf.append(piece)
        pos += len(piece)
    flush()
    return wins, maps


def locate(win, maps_k, abs_pos: int) -> tuple[str, int]:
    off = abs_pos - win.start
    k = bisect.bisect_right([s[0] for s in maps_k], off) - 1
    _, f, i = maps_k[max(k, 0)]
    return f, i


def _merge_calibration(results: list, threshold: float) -> dict[str, Any]:
    decoys = [s for r in results for s in r.calibration.decoy_scores]
    canaries = sum(r.calibration.canaries for r in results)
    found = 0.0
    for r in results:
        rec = r.calibration.canary_recall(threshold)
        if rec is not None:
            found += rec * r.calibration.canaries
    return {"decoys": len(decoys),
            "false_positive_rate": (sum(s >= threshold for s in decoys) / len(decoys)) if decoys else None,
            "canaries": canaries, "canary_recall": (found / canaries) if canaries else None}


def run_contamination(engine: Any, records: Iterable[Rec], items: list[BItem], local: LocalContam | None,
                      threshold: float, notes: list[str], progress=lambda m: None,
                      errors: list[str] | None = None) -> tuple[list[Finding], dict[str, Any], dict[str, int]]:
    """DS-CONTAM-001. Returns (findings, calibration stats, usage). Never raises for Snap errors."""
    from checksnap.snap import BudgetExceeded, SnapAuthError, SnapError, SnapQuotaError
    errors = [] if errors is None else errors
    wins, maps = build_windows(records)
    usage = {"snap_calls": 0, "input_tokens": 0}
    if not wins:
        notes.append("DS-CONTAM-001: no text to scan (after prefilter)")
        return [], {}, usage
    questions = [contam_question(i, it) for i, it in enumerate(items)]
    best: dict[str, Any] = {}
    results = []
    for k in range(0, len(questions), PER_CALL_ITEMS):
        chunk = questions[k:k + PER_CALL_ITEMS]
        progress(f"contamination: items {k + 1}-{k + len(chunk)} of {len(questions)}")
        try:
            res = engine.scan_windows(wins, chunk, label="contamination", progress=None)
        except BudgetExceeded as exc:
            res = getattr(exc, "partial", None)
            notes.append(f"DS-CONTAM-001: token budget exceeded, partial results only ({exc})")
            errors.append("token budget exceeded; results are partial")     # spec: budget/auth/quota => exit 3
            if res is not None:
                results.append(res)
                best.update(res.per_question)
            break
        except SnapError as exc:
            notes.append(f"DS-CONTAM-001: Snap failed ({type(exc).__name__}: {exc}); local results only")
            if isinstance(exc, (SnapAuthError, SnapQuotaError)):
                errors.append(f"Snap {type(exc).__name__}: {exc}")
            break
        results.append(res)
        best.update(res.per_question)
        if res.partial:
            notes.append("DS-CONTAM-001: partial result (some windows failed)")
        notes.extend(f"DS-CONTAM-001: {e}" for e in res.errors[:3])
    for r in results:
        usage["snap_calls"] += r.calls
        usage["input_tokens"] += r.input_tokens
    hits = sorted(((q.max_score, qid, q) for qid, q in best.items() if q.max_score >= threshold), key=lambda t: -t[0])
    findings = []
    for rank, (score, qid, q) in enumerate(hits):
        i = int(qid[1:])
        it = items[i]
        s, e = q.best_window
        wk = next((j for j, w in enumerate(wins) if w.start <= s < max(w.end, w.start + 1)), 0)
        snippet = ""
        if rank < LOCALIZE_MAX:
            try:
                from checksnap.snap import Window
                snip = engine.localize(Window(s, e, wins[wk].text[max(0, s - wins[wk].start):e - wins[wk].start]), questions[i])
                snippet = snip.text if snip else ""
                if snip:
                    s, e = snip.start, snip.end
            except SnapError as exc:
                notes.append(f"localize skipped for item {it.file}:{it.line} ({type(exc).__name__})")
        verbatim = wins[wk].text.find(it.text[:NEEDLE_CHARS])      # exact copies: point at the record itself, not the ~2 KB snippet start
        f, ln = locate(wins[wk], maps[wk], wins[wk].start + verbatim if verbatim >= 0 else s)
        lv = local.level(i) if local else None
        corr = f"13-gram corroboration: {'yes' if lv and lv[0] in ('exact', '13-gram') else 'no'}" + (f" ({lv[0]})" if lv else "")
        findings.append(mk("DS-CONTAM-001", detail=f"{it.file}:{it.line} scored {score:.2f}; window chars {q.best_window[0]}-{q.best_window[1]}; {corr}.",
                           evidence=[Evidence(f, ln, ln, (snippet or it.text)[:300],
                                              {"window": list(q.best_window), "benchmark": f"{it.file}:{it.line}", "item": it.text[:160]})],
                           score=round(score, 4), source="snap",
                           severity=Severity.HIGH if score >= 0.8 else Severity.MEDIUM))
    return findings, _merge_calibration(results, threshold) if results else {}, usage


def run_license(engine: Any, text: str, threshold: float, notes: list[str],
                errors: list[str] | None = None) -> tuple[list[Finding], dict[str, int]]:
    from checksnap.snap import Question, SnapAuthError, SnapError, SnapQuotaError, Window
    usage = {"snap_calls": 0, "input_tokens": 0}
    if not text.strip():
        return [], usage
    text = text[:LIC_SAMPLE_CHARS]
    q = Question("lic", LIC_INSTRUCTIONS, "The text states a restrictive licence.", "The text states no restrictive licence.")
    try:
        res = engine.scan_windows([Window(0, len(text), text)], [q], label="licence")
    except SnapError as exc:
        notes.append(f"DS-LIC-001: Snap failed ({type(exc).__name__}: {exc})")
        if errors is not None and isinstance(exc, (SnapAuthError, SnapQuotaError)):
            errors.append(f"Snap {type(exc).__name__}: {exc}")
        return [], usage
    usage = {"snap_calls": res.calls, "input_tokens": res.input_tokens}
    sc = res.per_question["lic"].max_score
    if sc < threshold:
        return [], usage
    return [mk("DS-LIC-001", title="Sampled text states a restrictive licence (Snap)",
               detail=f"score {sc:.2f} on a sample of {len(text)} chars (file heads + {License.SAMPLE} random records). Candidate, not proof.",
               score=round(sc, 4), source="snap", evidence=[Evidence(None, None, None, "", {"sample_chars": len(text)})])], usage

