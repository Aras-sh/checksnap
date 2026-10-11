"""SnapEngine: windows + batching + cache + budget + parallel calls + decoy/canary calibration."""
from __future__ import annotations

import hashlib
import math
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from ..core import CostEstimate
from .cache import DiskCache
from .calibrate import (CALL_OVERHEAD_TOKENS, CANARY_THRESHOLD, QUESTION_CHARS_PER_TOKEN, Calibration, CharsPerToken,
                        detect_kind, question_chars)
from .client import Question, SnapClient
from .errors import BudgetExceeded, SnapAuthError, SnapError, SnapQuotaError, SnapTooLargeError
from .localize import bisect_hit
from .windows import Window, split_windows

MIN_WINDOW = 2_000          # never halve below this: a 2 KB state rejected as too large is a different problem
DECOY_PREFIX, CANARY_PREFIX = "__decoy_", "__canary_"
AVG_QUESTION_CHARS = 360    # measured mean of the bank's questions (instructions + criteria); used when the caller has no texts
QUESTION_OPT_CHARS_PER_TOKEN = 3.6


@dataclass
class QuestionResult:
    id: str
    max_score: float
    best_window: tuple[int, int]
    window_scores: list[tuple[int, int, float]]


@dataclass
class ScanResult:
    """`calls` = network calls made this scan; `cached_calls` = answered from disk (cost nothing)."""
    per_question: dict[str, QuestionResult] = field(default_factory=dict)
    windows: int = 0
    calls: int = 0
    cached_calls: int = 0
    input_tokens: int = 0
    calibration: Calibration = field(default_factory=Calibration)
    partial: bool = False
    errors: list[str] = field(default_factory=list)


@dataclass
class _Run:
    """Mutable per-scan accumulator; only touched under the engine lock."""
    calls: int = 0
    cached: int = 0
    tokens: int = 0
    decoy_scores: list[float] = field(default_factory=list)
    canary_scores: list[float] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    fatal: Exception | None = None
    budget: BudgetExceeded | None = None
    abort: threading.Event = field(default_factory=threading.Event)


def _k(n: int) -> str:
    return f"{n / 1000:.0f}k" if n >= 1000 else str(n)


class SnapEngine:
    def __init__(self, client: SnapClient, cache_dir: Path | None = None, workers: int = 4,
                 budget_tokens: int | None = None, window_chars: int = 800_000, overlap_chars: int = 5_000,
                 batch: int = 64, decoys: int = 8, canaries: bool = True):
        self.client = client
        self.cache = DiskCache(cache_dir) if cache_dir else None
        self.cpt = CharsPerToken(cache_dir)
        self.workers, self.budget_tokens = max(1, workers), budget_tokens
        self.window_chars, self.overlap_chars = window_chars, overlap_chars
        self.batch, self.decoys, self.canaries = batch, decoys, canaries
        self.per_call = batch - decoys - (1 if canaries else 0)     # real questions that fit in one call
        if self.per_call < 1:
            raise ValueError("batch too small for decoys + canary")
        if not 0 <= overlap_chars < window_chars:
            raise ValueError("need 0 <= overlap_chars < window_chars")
        self._lock = threading.Lock()
        self._spent = 0         # real input tokens used so far, across scans (the budget is per run)
        self._inflight = 0      # estimated tokens of calls in progress
        self._cap = math.inf    # largest state the service accepted, learned from 400s
        self.localize_calls = self.localize_tokens = 0     # spent by localize(), which the scan results do not include
        self.fatal: Exception | None = None     # last auth/quota/budget stop; the CLI turns it into exit 3 even if a check swallowed it

    @property
    def spent_tokens(self) -> int:
        return self._spent

    # ---- estimate (free) ----
    def estimate(self, n_chars: int, n_questions: int, kind: str | None = None, *, q_chars: int | None = None,
                 n_windows: int | None = None, localize: int = 0) -> CostEstimate:
        """input_tokens is the conservative upper bound (budgets and the privacy gate use it); notes carry the range.

        Every call bills the state AND its questions (the real ones plus the decoys and canary), so
        cost = windows x (state tokens + all question tokens) + one-question localization calls.
        `q_chars` = total chars of the n_questions real questions (default: AVG_QUESTION_CHARS each); `n_windows` = the
        caller's own (packed, non-overlapping) windows, whose chars are already in n_chars; `localize` = how many hits
        may be bisected (worst case: both halves asked at every step). `kind` is code|json|prose; unknown means code."""
        if n_chars <= 0 or n_questions <= 0:
            return CostEstimate(notes="nothing to send")
        size, ov = self.window_chars, self.overlap_chars
        if n_windows is None:
            windows = 1 if n_chars <= size else math.ceil((n_chars - ov) / (size - ov))
            sent_once = n_chars + (windows - 1) * ov
        else:
            windows, sent_once = max(1, n_windows), n_chars
        chunks = math.ceil(n_questions / self.per_call)
        calls = windows * chunks
        kind = kind or "code"
        opt, cons = self.cpt.bounds(kind)
        extra_chars = sum(question_chars(q) for q in self._extras("x")[1])
        q_total = q_chars if q_chars is not None else n_questions * (AVG_QUESTION_CHARS + 30)   # incl. per-question envelope
        q_chars_sent = q_total + extra_chars * chunks         # question chars one window carries across all its chunks
        state_lo, state_hi = math.ceil(sent_once * chunks / opt), math.ceil(sent_once * chunks / cons)
        q_lo = math.ceil(windows * q_chars_sent / QUESTION_OPT_CHARS_PER_TOKEN) + calls * CALL_OVERHEAD_TOKENS
        q_hi = math.ceil(windows * q_chars_sent / QUESTION_CHARS_PER_TOKEN) + calls * CALL_OVERHEAD_TOKENS
        lo, hi, uploads = state_lo + q_lo, state_hi + q_hi, sent_once * chunks
        loc_note = ""
        if localize > 0:
            n, steps, loc_chars = n_chars / windows, 0, 0.0
            while n > 2000:                                 # mirrors bisect_hit: halves overlap by min(overlap, n/8); both are asked
                n = n / 2 + min(self.overlap_chars, n / 8)
                loc_chars, steps = loc_chars + 2 * n, steps + 1
            per_q = q_total / n_questions + 30
            loc_hi = localize * (math.ceil(loc_chars / cons) + 2 * steps * (math.ceil(per_q / QUESTION_CHARS_PER_TOKEN) + CALL_OVERHEAD_TOKENS))
            hi, calls, uploads = hi + loc_hi, calls + localize * 2 * steps, uploads + int(localize * loc_chars)
            loc_note = f"; includes up to {localize} localizations (<= {_k(loc_hi)} tokens, {steps * 2} one-question calls each)"
        return CostEstimate(snap_calls=calls, input_tokens=hi, uploads_bytes=uploads,
                            notes=f"{_k(lo)}-{_k(hi)} tokens; {windows} window(s) x {chunks} question batch(es), each call carries its questions "
                                  f"(~{_k(q_hi)} of the total), {kind} at {cons:.2f}-{opt:.2f} chars/token{loc_note}")

    # ---- scanning ----
    def scan(self, text: str, questions: Sequence[Question], *, label: str = "", progress=None) -> ScanResult:
        return self.scan_windows(split_windows(text, self.window_chars, self.overlap_chars), questions,
                                 label=label, progress=progress)

    def scan_windows(self, windows: Sequence[Window], questions: Sequence[Question], *, label: str = "",
                     progress: Callable[[str], None] | None = None) -> ScanResult:
        questions = list(questions)
        ids = [q.id for q in questions]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate question ids")
        if any(i.startswith((DECOY_PREFIX, CANARY_PREFIX)) for i in ids):
            raise ValueError("question ids may not start with __decoy_ or __canary_")
        run = _Run()
        chunks = [questions[i:i + self.per_call] for i in range(0, len(questions), self.per_call)]
        tasks = [(w, c) for w in windows for c in chunks]
        results: list[list[tuple[int, int, dict[str, float]]] | None] = [None] * len(tasks)
        done = [0]

        def work(i: int) -> None:
            if run.abort.is_set():
                return
            w, chunk = tasks[i]
            try:
                results[i] = self._run_window(w, chunk, run)
            except (SnapAuthError, SnapQuotaError) as e:        # fail fast: cancel everything pending
                run.fatal = run.fatal or e
                run.abort.set()
            except BudgetExceeded as e:
                run.budget = run.budget or e
                run.abort.set()
            except SnapError as e:
                with self._lock:
                    run.errors.append(f"{label or 'scan'} window {w.start}-{w.end}: {e}")
            with self._lock:
                done[0] += 1
                n = done[0]
            if progress:
                progress(f"{label or 'snap'}: {n}/{len(tasks)} calls")

        if tasks:
            with ThreadPoolExecutor(max_workers=self.workers) as ex:
                list(ex.map(work, range(len(tasks))))
        self.cpt.save()
        if run.fatal:
            self.fatal = run.fatal
            raise run.fatal
        result = self._build(run, windows, questions, results, bool(run.budget))
        if run.budget:
            self.fatal = run.budget
            raise BudgetExceeded(str(run.budget), partial=result)
        return result

    def _build(self, run: _Run, windows: Sequence[Window], questions: list[Question], results: list,
               aborted: bool) -> ScanResult:
        per: dict[str, QuestionResult] = {}
        for q in questions:
            ws = [(s, e, sc[q.id]) for r in results if r for (s, e, sc) in r if q.id in sc]
            if ws:
                best = max(ws, key=lambda x: x[2])      # first max wins: deterministic
                per[q.id] = QuestionResult(q.id, best[2], (best[0], best[1]), ws)
            else:
                per[q.id] = QuestionResult(q.id, 0.0, (0, 0), [])
        cal = Calibration(decoys=len(run.decoy_scores), decoy_scores=list(run.decoy_scores),
                          canaries=len(run.canary_scores),
                          canaries_found=sum(s >= CANARY_THRESHOLD for s in run.canary_scores),
                          canary_scores=list(run.canary_scores))
        errors = list(run.errors)
        if aborted:
            errors.append("token budget reached; results are partial")
        return ScanResult(per, len(windows), run.calls, run.cached, run.tokens, cal,
                          partial=bool(errors) or aborted, errors=errors)

    def _extras(self, text: str) -> tuple[str, list[Question]]:
        """Canary sentence to append + decoy/canary questions. Derived from the text hash so the cache stays valid."""
        h = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        suffix, extra = "", []
        for i in range(self.decoys):
            s = f"The harbour inspector {h[i * 4:i * 4 + 4]}{i} logged crate {h[32 + i:40 + i]} on {h[8 + i:14 + i]} quay."
            extra.append(Question(f"{DECOY_PREFIX}{i}", f"Does the text contain this exact sentence? [[needle]]{s}[[/needle]]",
                                  "The text contains this exact sentence", "The sentence is not in the text"))
        if self.canaries:
            s = f"Checksnap canary {h[:24]}."
            suffix = "\n\n" + s
            extra.append(Question(f"{CANARY_PREFIX}0", f"Does the text contain this exact sentence? [[needle]]{s}[[/needle]]",
                                  "The text contains this exact sentence", "The sentence is not in the text"))
        return suffix, extra

    def _run_window(self, w: Window, chunk: list[Question], run: _Run) -> list[tuple[int, int, dict[str, float]]]:
        n = len(w.text)
        if n > self._cap and n > MIN_WINDOW:
            return self._halve(w, chunk, run)
        suffix, extra = self._extras(w.text)
        try:
            scores, _ = self._call(w.text + suffix, chunk + extra, run)
        except SnapTooLargeError:
            if n <= MIN_WINDOW:
                raise
            self._cap = min(self._cap, n // 2 + min(self.overlap_chars, n // 8))
            return self._halve(w, chunk, run)
        with self._lock:
            for q in extra:
                (run.decoy_scores if q.id.startswith(DECOY_PREFIX) else run.canary_scores).append(scores[q.id])
        return [(w.start, w.end, {q.id: scores[q.id] for q in chunk})]

    def _halve(self, w: Window, chunk: list[Question], run: _Run) -> list[tuple[int, int, dict[str, float]]]:
        n = len(w.text)
        ov, mid = min(self.overlap_chars, n // 8), n // 2
        left = Window(w.start, w.start + mid + ov, w.text[:mid + ov])
        right = Window(w.start + mid - ov, w.end, w.text[mid - ov:])
        return self._run_window(left, chunk, run) + self._run_window(right, chunk, run)

    # ---- one cached, budgeted call ----
    def _call(self, state: str, questions: list[Question], run: _Run) -> tuple[dict[str, float], bool]:
        key = None
        if self.cache:
            key = self.cache.key(self.client.model, state, [(q.id, q.payload()) for q in questions])
            hit = self.cache.get(key)
            if hit and all(q.id in hit.get("scores", {}) for q in questions):
                with self._lock:
                    run.cached += 1
                return {q.id: float(hit["scores"][q.id]) for q in questions}, True
        kind = detect_kind(state)
        q_tok = sum(question_chars(q) for q in questions) / QUESTION_CHARS_PER_TOKEN + CALL_OVERHEAD_TOKENS     # questions are billed too
        est = math.ceil(len(state) / self.cpt.bounds(kind)[1] + q_tok)     # conservative, so the budget is never overrun by a bad guess
        with self._lock:
            if self.budget_tokens is not None and self._spent + self._inflight + est > self.budget_tokens:
                raise BudgetExceeded(f"budget of {self.budget_tokens} tokens would be exceeded "
                                     f"(used {self._spent}, next call ~{est})")
            self._inflight += est
        try:
            res = self.client.ask(state, questions)
        except BaseException:
            with self._lock:
                self._inflight -= est
            raise
        with self._lock:
            self._inflight -= est
            self._spent += res.input_tokens
            if res.input_tokens - q_tok > 0.1 * res.input_tokens:      # state-only ratio: the questions are billed too
                self.cpt.add(len(state), int(res.input_tokens - q_tok), kind)
            run.calls += 1
            run.tokens += res.input_tokens
        if key:
            self.cache.put(key, {"scores": res.scores, "input_tokens": res.input_tokens,
                                 "output_tokens": res.output_tokens})
        return res.scores, False

    # ---- localize ----
    def localize(self, window: Window, question: Question, target_chars: int = 2000,
                 threshold: float = 0.5) -> Window | None:
        """Bisect a hit to ~target_chars. None when it cannot be pinned down or the budget ran out."""
        run = _Run()

        def score(text: str) -> float:
            return self._call(text, [question], run)[0][question.id]

        try:
            return bisect_hit(score, window, target_chars, self.overlap_chars, threshold)
        except BudgetExceeded:
            return None     # ponytail: no partial snippet on budget stop; keep the whole-window evidence instead
        finally:
            self.localize_calls += run.calls
            self.localize_tokens += run.tokens
            self.cpt.save()
