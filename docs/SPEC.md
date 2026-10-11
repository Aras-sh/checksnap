# checksnap: build spec (v0.1)

One CLI that checks things with SubQ Snap (a long-context decision model) plus cheap local analysis.
Each check is a flag: `--check-dataset`, `--check-optimization`, more later.

```
checksnap --check-dataset data/ --benchmark gsm8k_test.jsonl
checksnap --check-optimization ./myproject
checksnap --check-all . --dry-run          # estimate + what would be uploaded, spends nothing
```

Principles
1. **Local first, Snap second.** Every check does as much as possible locally for free. Snap is used where only a
   long-context semantic judgement works (paraphrased leaks, cross-file patterns). `--no-snap` must still give a useful report.
2. **Never spend or upload by surprise.** `estimate()` is free. Before the first Snap call the CLI shows destination
   (api.subq.ai), bytes that leave the machine, estimated calls/tokens and asks for confirmation (or `--yes`).
3. **Honest output.** Flags are candidates, not proof. Every Snap finding carries its score, the window it came from and,
   where possible, a snippet. The report states the measured false-positive rate of THIS run (decoys) and any partial results.
4. **Boring and robust.** Python 3.10+, runtime dependency: `httpx` only (Pillow optional for images). Results survive
   crashes (cache), failures degrade to notes instead of tracebacks.

## 1. Layout and ownership (one owner per file; do not edit files you do not own)

| Owner | Files |
|---|---|
| **core** (done) | `checksnap/core.py`, `checksnap/__init__.py`, `checksnap/checks/__init__.py`, `docs/SPEC.md` |
| **A1 cli** | `checksnap/cli.py`, `checksnap/__main__.py`, `checksnap/report.py`, `checksnap/config.py`, `checksnap/privacy.py`, `pyproject.toml`, `tests/test_cli*.py`, `tests/test_report*.py`, `tests/test_config*.py` |
| **A2 engine** | `checksnap/snap/*` (client, windows, engine, cache, calibrate, localize, fake_server, errors), `tests/conftest.py`, `tests/test_snap_*.py` |
| **A3 dataset** | `checksnap/checks/dataset/*`, `tests/test_dataset_*.py`, `tests/fixtures/dataset/*` |
| **A4 optimization** | `checksnap/checks/optimization/*`, `tests/test_optimization_*.py`, `tests/fixtures/optimization/*` |
| **A5 benchmarks+docs** | `benchmarks/*`, `docs/USAGE.md`, `docs/RULES.md` (generated), `README.md`, `examples/*`, `.github/workflows/ci.yml`, `tests/test_e2e*.py` |

Shared types live in `checksnap/core.py` (read it first): `Finding`, `Evidence`, `Severity`, `CostEstimate`, `CheckResult`,
`Context`, `Check`, `register`, `all_checks`. If you need a change there, write it as a request in your final report; do not edit it.

## 2. The Snap API (what the real service does)

`POST https://api.subq.ai/v1/systemone`, header `Authorization: Bearer <key>`, JSON body
```json
{"model": "subq-snap-preview", "state": "<the whole text, ~200K tokens max>",
 "questions": {"q0": {"type": "noul", "instructions": "...", "criteria": {"true": "...", "false": "..."}}, "q1": {...}}}
```
Response: `{"model": "...", "answers": {"q0": {"type": "noul", "noul": 0.9699}}, "usage": {"input_tokens": 35293, "output_tokens": 0}}`.
`noul` is the probability that the criterion "true" holds for the whole `state`. Up to 64 questions per call worked in practice
(the call reads the state once, so questions are nearly free; the state is the cost). Roughly 200K tokens (~800K English characters)
per window; code/JSON tokenize heavier (~3 chars per token or less). ~7 seconds per 200K-token call.
Status codes: 401/403 bad key or no access (fail fast), 402 no credits (fail fast), 429/503 retry with backoff,
400/413/422 state too large (halve the window and retry, never loop forever), others raise. No price is published; no cost
field in responses; only `usage.input_tokens`. Reference implementation to read: `/home/aras/Projects/_scan_test/snap-contamination-scanner/scanner/__init__.py`
and `scan.py` (public, MIT). The key is in the environment as `SUBQ_API_KEY` for the CLI only. **Builders never need it: all tests use the fake server.**

## 3. Findings and report contract

Rule ids are stable strings: `DS-<AREA>-NNN` for dataset, `OPT-PY-NNN` / `OPT-ML-NNN` / `OPT-SNAP-NNN` for optimization.
Every rule has: id, severity, title, one-paragraph explanation, fix hint, and is listed by `checksnap --explain RULE_ID`.
Each check exposes its rule catalog as `RULES: dict[str, RuleInfo]` in its package `__init__` (RuleInfo = dataclass with
`id, severity, title, explanation, fix_hint, needs_snap: bool`). `docs/RULES.md` is generated from those catalogs.

## 4. Snap engine API (A2 implements; A3/A4 consume; import everything from `checksnap.snap`)

```python
class SnapError(Exception); SnapAuthError(SnapError)   # 401/403
class SnapQuotaError(SnapError)                         # 402
class SnapTooLargeError(SnapError)                      # 400/413/422
class SnapRateLimitError(SnapError)                     # 429/503 after retries exhausted
class BudgetExceeded(SnapError)                         # carries .partial (ScanResult so far)

@dataclass(frozen=True)
class Question: id: str; instructions: str; true: str; false: str          # .payload() -> the {"type":"noul",...} dict

class SnapClient:                                       # one HTTP call, no windows/caching
    def __init__(self, api_key=None, url=DEFAULT_URL, model="subq-snap-preview", timeout=300.0,
                 max_retries=6, transport=None, sleep=time.sleep)      # key from arg or SUBQ_API_KEY; never logged
    def ask(self, state: str, questions: Sequence[Question]) -> AskResult   # AskResult(scores: dict[id,float], input_tokens, output_tokens, ms)

@dataclass
class Window: start: int; end: int; text: str

def split_windows(text: str, size: int = 800_000, overlap: int = 5_000) -> list[Window]   # covers every char; overlap < size enforced

class SnapEngine:
    def __init__(self, client: SnapClient, cache_dir: Path | None = None, workers: int = 4, budget_tokens: int | None = None,
                 window_chars: int = 800_000, overlap_chars: int = 5_000, batch: int = 64, decoys: int = 8, canaries: bool = True)
    def estimate(self, n_chars: int, n_questions: int) -> CostEstimate   # free; uses calibrated chars/token (default 3.3, learned in cache_dir/calibration.json)
    def scan(self, text: str, questions: Sequence[Question], *, label: str = "", progress=None) -> ScanResult
    def scan_windows(self, windows: Sequence[Window], questions, *, label="", progress=None) -> ScanResult   # caller-chosen windows (e.g. one file each)
    def localize(self, window: Window, question: Question, target_chars: int = 2000) -> Window | None       # bisect a hit down to a ~2 KB snippet

@dataclass
class QuestionResult: id: str; max_score: float; best_window: tuple[int, int]; window_scores: list[tuple[int, int, float]]
@dataclass
class Calibration: decoys: int; decoy_scores: list[float]; canaries: int; canaries_found: int
    def false_positive_rate(self, threshold: float) -> float | None
    def canary_recall(self, threshold: float) -> float | None
@dataclass
class ScanResult: per_question: dict[str, QuestionResult]; windows: int; calls: int; cached_calls: int; input_tokens: int
                  calibration: Calibration; partial: bool; errors: list[str]
```
Engine rules: (1) decoys are extra always-false questions and canaries are extra always-true questions appended to every call
(a canary is a unique sentence the engine appends to each window; its question asks about that exact sentence); they use the spare 64-question
capacity so they cost no extra calls. Decoy/canary ids are prefixed `__decoy_`/`__canary_` and never appear in `per_question`.
(2) results are cached on disk by sha256(model + window text + question payload); a repeated scan costs 0 calls. (3) the budget is checked BEFORE each call using
the calibrated estimate, and `BudgetExceeded` carries the partial result; the CLI prints it and exits 3. (4) workers call in parallel with exponential backoff
on 429/503; 401/402/403 abort everything immediately (cancel pending work). (5) a too-large window is halved and retried (never for auth/quota errors).
(6) thread-safe; deterministic ordering of results. (7) `fake_server.py`: `FakeSnapServer(scorer=None, fail=None, latency=0.0)` context manager with `.url`;
default scorer returns 0.95 when the question's instructions contain a needle between `[[needle]]` and `[[/needle]]` markers that appears verbatim in the state (and the canary question works the same way),
0.04 otherwise; `fail` can force 401/402/403/429-once/503-once/400-too-large-above-N-chars. `tests/conftest.py` exposes pytest fixtures `fake_snap` (server), `snap_client`, `snap_engine`.

## 5. `--check-dataset` (A3)

`--check-dataset [PATH]` (file, or directory of files). Options (add via `add_arguments`): `--benchmark PATH` (repeatable JSONL),
`--field NAME` (default `question`, field of benchmark items), `--eval PATH` (eval/test split for leakage), `--text-field NAME`
(field of dataset records holding text; default auto: join all string values), `--label-field`, `--id-field`, `--id-regex`
(video/channel id from file names), `--source-field`, `--license-field`, `--allowed-licenses a,b,c`, `--modality auto|text|image`,
`--max-records N`, `--contam-mode exhaustive|prefiltered` (default exhaustive; prefiltered documents its measured recall loss),
`--dup-threshold F` (near-duplicate Jaccard, default 0.8). Inputs: `.txt`, `.jsonl`, `.json` (list), `.csv`/`.tsv`; directories are walked;
images (`.jpg/.png/...`) go to the image engine if Pillow is present, else a note. Streaming-friendly: never load a whole big file twice.

| Rule | Where | What |
|---|---|---|
| DS-CONTAM-001 | Snap | benchmark item present in data (copied, reworded, translated, solution-only). Score, window range, 13-gram corroboration, optional snippet via `localize`. HIGH when score >= 0.8, MEDIUM otherwise |
| DS-CONTAM-002 | local | exact / 13-gram / 8-gram benchmark overlap. Runs with `--no-snap`. Short items (< n words) are reported as "blind to n-gram" |
| DS-DUP-001/002 | local | exact duplicate records / near duplicates (MinHash over word shingles, LSH buckets, no external libs) |
| DS-LEAK-001/002 | local | records of `--eval` present in the dataset exactly / near-duplicate (+ same `--id-field` or `--id-regex` ids in both) |
| DS-PII-001 | local | emails, phone numbers, IBAN/credit cards (Luhn), government-id-like numbers, IPs, API keys / private keys / tokens (never print the full secret: show first 4 chars + length) |
| DS-HYG-001.. | local | empty/NaN fields, inconsistent keys, duplicate ids, length outliers, mojibake/encoding errors, label imbalance and train/eval label shift, truncated records, mixed languages share |
| DS-LIC-001 | local+Snap | metadata licence/source not in `--allowed-licenses`; Snap question "does this text state a restrictive licence (non-commercial, no-derivatives, all rights reserved)" on sampled windows |
| DS-IMG-001..003 | local | near-duplicate images (dHash), leaks between dataset and `--eval` dir, same ids across splits, corrupt/blank/tiny images |

Snap cost control: DS-CONTAM-001 batches all benchmark items into <=56 questions per call (the rest of the 64 are decoys/canaries). Estimate before any call. Report `calibration` stats in `result.stats`.

## 6. `--check-optimization` (A4)

`--check-optimization [PATH]` (dir or file, default `.`). Options: `--profile auto|ml|general`, `--include GLOB`, `--exclude GLOB` (defaults skip
`.git`, `.venv`, `node_modules`, `__pycache__`, `build`, `dist`, tests unless `--include-tests`), `--max-files N`, `--static-only`, `--snap-only`.
Static layer (free, stdlib `ast`): at least 12 general Python rules and 10 ML rules, each with line-accurate evidence, a fix hint, and unit tests with a positive
and a negative fixture. Required coverage:

* general: string/list `+=` in loops (quadratic), `re.compile`/`re.*` with constant pattern in loops, `x in list` membership in loops, `for i in range(len(x))`,
  file open/read per iteration, sort inside loops, blocking calls (`time.sleep`, `requests`) inside `async def`, DB `execute`/query inside loops (N+1),
  `df.iterrows()`/`apply(axis=1)`, repeated `json.loads(open(...))` in loops, `lru_cache(maxsize=None)` on methods, `list(...)` wrapping in `sum/any/all/min/max`.
* ML/PyTorch: `.item()/.cpu()/.numpy()/float(tensor)` inside training loops (host sync), DataLoader without `num_workers`/`pin_memory`/`persistent_workers`,
  no `autocast`/AMP in a training loop, eval code without `torch.no_grad()`/`inference_mode()`, Python loops over tensor elements, per-step `torch.tensor(...)`/`torch.zeros(...)` on CPU then `.to(device)`,
  `.to(device)` without `non_blocking` for pinned data, `torch.cuda.synchronize()` in loops, checkpoint saving every step, `optimizer.zero_grad()` without `set_to_none=True`,
  depthwise/grouped conv (`groups=in_channels`) flagged as an AMD-ROCm slow path (see rule text), `cudnn.benchmark` with dynamic shapes, float64 tensors from numpy.
Snap layer (`OPT-SNAP-NNN`, needs the engine): a question bank of at least 25 "is this pattern present?" questions for things static analysis cannot see
(same expensive computation repeated across modules, per-item network/db/model calls hidden behind function boundaries, missing caching where inputs repeat, unbatched per-item inference,
synchronous I/O on hot paths, unnecessary data copies, unbounded growth of in-memory structures, polling loops without backoff, config re-read on every call, ...).
Source is packed into windows with `### FILE: <relpath>` headers (file boundaries respected, big files split) so a window range maps back to files; flagged questions are
localized to files, and to lines when a static rule or lexical hint overlaps. Output ranks findings by severity then file. Python is first class; other languages
(`.js .ts .go .rs .java .c .cpp`) get the Snap layer only.

## 7. CLI behaviour (A1)

`checksnap [--check-dataset [PATH]] [--check-optimization [PATH]] [--check-all [PATH]] [common options] [check options]`
Common: `--list-checks`, `--explain RULE_ID`, `--format text|json|md|sarif` (default text), `-o/--out FILE`, `--fail-on none|low|medium|high` (default high),
`--no-snap`, `--yes`, `--dry-run`, `--budget-tokens N` (default 5_000_000), `--workers N` (default 4), `--threshold F` (default 0.5), `--cache-dir DIR`, `--config FILE`
(`.checksnap.toml`, parsed with `tomllib`; CLI wins over file), `--version`, `-q/-v`.
Exit codes: 0 ok / below `--fail-on`; 1 findings at or above `--fail-on`; 2 usage error; 3 a check failed to run, budget exceeded or auth/quota error.
Privacy gate (`privacy.py`): before the first Snap call print host, bytes that would be uploaded (sum of `estimate().uploads_bytes`), calls, tokens; ask `Upload N MB to api.subq.ai? [y/N]`;
`--yes` skips; non-interactive without `--yes` => Snap parts are skipped with a note (local parts still run). `--dry-run` prints the table and exits 0, spending nothing.
API key: `SUBQ_API_KEY` env, else a `.env` file in the current directory (parsed, never printed, never written). Missing key => Snap parts skipped with a clear note, exit code unaffected.
Reports: `text` (colour only on a TTY), `md`, `json` (stable schema = `CheckResult.to_dict()` list + summary), `sarif` 2.1.0 (rule ids as rules, evidence as locations). The summary shows severity counts, Snap usage, calibration (decoy false-positive rate, canary recall) and every note.

## 8. Rules for everyone

* Tests: `pytest` only, **no network, no real key**: use `FakeSnapServer`. Every public function has at least one test; every rule has a positive and a negative fixture.
  Run `/home/aras/Projects/checksnap/.venv/bin/python -m pytest tests/<your files> -q` yourself and fix until green. Keep tests fast (< 20 s per file).
* Never print, log, store or read API keys. Do not read `/home/aras/Projects/_scan_test/**/.env`. Do not read any file under `~/` outside this repo except the public reference scanner named above.
* Do not send anything to any network. Do not modify anything outside `/home/aras/Projects/checksnap/` (the vision-lab project on this machine is off limits, a training machine; keep CPU use light: `nice -n 10` for anything heavy, no multi-GB allocations).
* Only edit files you own (section 1). No git commands: the lead commits. If a contract in this spec is wrong or missing, follow the spec anyway and report the problem in your final message.
* Keep the code plain and typed (`from __future__ import annotations`, dataclasses, `pathlib`), docstrings that say WHY, no clever metaprogramming, no new runtime dependencies (stdlib + httpx; Pillow only inside the image module behind a try/except).
* Time box: about 70 minutes of work. A complete, tested, smaller feature set beats a big half-working one. Order your work: contract first, happy path, tests, edge cases, then extras.
