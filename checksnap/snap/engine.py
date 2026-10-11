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
from .calibrate import CANARY_THRESHOLD, Calibration, CharsPerToken
from .client import Question, SnapClient
from .errors import BudgetExceeded, SnapAuthError, SnapError, SnapQuotaError, SnapTooLargeError
from .localize import bisect_hit
from .windows import Window, split_windows

MIN_WINDOW = 2_000          # never halve below this: a 2 KB state rejected as too large is a different problem
DECOY_PREFIX, CANARY_PREFIX = "__decoy_", "__canary_"


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
        self.fatal: Exception | None = None     # last auth/quota/budget stop; the CLI turns it into exit 3 even if a check swallowed it

    @property
    def spent_tokens(self) -> int:
        return self._spent

    # ---- estimate (free) ----
    def estimate(self, n_chars: int, n_questions: int) -> CostEstimate:
        if n_chars <= 0 or n_questions <= 0:
            return CostEstimate(notes="nothing to send")
        size, ov = self.window_chars, self.overlap_chars
        windows = 1 if n_chars <= size else math.ceil((n_chars - ov) / (size - ov))
        chunks = math.ceil(n_questions / self.per_call)
        sent = (n_chars + (windows - 1) * ov) * chunks      # every question chunk re-reads every window
        cpt = self.cpt.value
        return CostEstimate(snap_calls=windows * chunks, input_tokens=math.ceil(sent / cpt), uploads_bytes=sent,
                            notes=f"{windows} window(s) x {chunks} question batch(es) at {cpt:.2f} chars/token")

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
        est = math.ceil(len(state) / self.cpt.value)
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
            self.cpt.add(len(state), res.input_tokens)
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
            self.cpt.save()
