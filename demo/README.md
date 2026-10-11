# checksnap launch demo (public data only)

Everything here was run on 2026-10-11 against public data: psf/requests (`src/requests`, 19 files, 216 KB, commit 49a6929) and GSM8K (openai/grade-school-math `train.jsonl` 7,473 rows and `test.jsonl` 1,319 rows, same files as HF `openai/gsm8k` main). Raw outputs are in this folder (`part*.txt`, `part*.log`). Big data is gitignored (`data/`, `requests/`, `.cache/`).

Setup used: `export PYTHONPATH=/home/aras/Projects/checksnap` (checksnap is not pip-installed in the venv), key loaded in-shell from the scanner `.env`, everything under `nice -n 10`. `$SRC=showcase/claude-code/work_requests/src/requests`.

## 1. Commands

```
# Part 1, free
python -m checksnap --check-all $SRC --no-snap -o part1_free.txt
# Part 1, Snap (each preceded by --dry-run)
python -m checksnap --check-optimization $SRC --snap-verify --budget-tokens 300000 --yes -o part1_opt_full.txt
python -m checksnap --check-bank $SRC --budget-tokens 1000000 --yes -o part1_bank.txt
# Part 2, free (full sets)
python -m checksnap --check-dataset data/train.jsonl --benchmark data/test.jsonl --field question --no-snap -o part2_free.txt
# Part 2, Snap on slices (train first 1400 / 5000 rows x 56 test items: first 54 + test rows 603 and 633 as controls)
python -m checksnap --check-dataset data/train5000.jsonl --benchmark data/test56.jsonl --field question \
   --contam-mode prefiltered --budget-tokens 600000 --yes -o part2_snap5000.txt
```
(`part2_snap.txt` is the same with train1400; `part1_snap.txt` is an earlier 2-file optimization pilot.)

## 2. Results (trimmed)

**Free `--check-all` on requests: 0.57 s, 43 findings.** 25 are bank "local-hint" regex candidates that the tool itself labels "nothing was judged" (they fire on `from __future__ import annotations` as "future information in features", an ASCII-art banner as "business rule duplicated", etc.: pure noise, see below). Real static hits: 4 x OPT-PY-003 (list membership in loop, cookies.py), 9 x SEC-009 (assert in non-test code), plus repo-hygiene notes that only exist because we scanned a subfolder (no README/.gitignore).

**Snap optimization, `--snap-verify`, full src:** 14 findings (0 high, 4 medium, 10 low). Calibration line: decoys=8, false_positive_rate=0.0, canary_recall=1.0. 62,418 tokens, 13 s.

**Snap bank, full, no item cap:** 98 calls, 972,177 tokens, 40 s; 19 non-hint findings (5 HIGH, 8 MEDIUM, 6 LOW).

**GSM8K free pass (full train x full test, 14 s):** 0 exact matches, 0 duplicates (DS-DUP) at Jaccard 0.8. 3 13-gram hits (1 HIGH, 2 MEDIUM) and 79 8-gram hits (LOW). PII: 1 credit-card + 1 phone, both false positives (arithmetic numbers such as `1000`, `960-...` in solutions). 1 length-outlier note.

**GSM8K Snap (DS-CONTAM-001):** train rows 1-1400: 3 calls, 154,443 tokens, 9 s. Train rows 1-5000: 3 calls, 377,966 tokens, 20 s. Both: **0 Snap contamination findings** (but only the 1,400-row run is valid: the 5,000-row run missed both canaries, canary_recall=0.0, so Snap did not read that text); decoy false-positive rate 0% at threshold 0.5. Mode `prefiltered` (only records sharing rare words are sent).

## 3. Tokens and time

| Run | Calls | Input tokens | Wall |
|---|---|---|---|
| optimization pilot (2 files) | 1 | 19,546 | 6 s |
| optimization full + snap-verify | 2 | 62,418 | 13 s |
| bank full | 98 | 972,177 | 40 s |
| dataset Snap, train 1-1400 | 3 | 154,443 | 9 s |
| dataset Snap, train 1-5000 | 3 | 377,966 | 20 s |
| **Total** | 107 | **1,586,550** | ~90 s |

At ~$0.09 per 1M tokens (SubQ console figure given to us) that is about $0.14 total. Not measured by us: the invoice itself. Dry-run estimates were upper bounds: bank est. 5.0M (actual 0.97M), dataset est. 0.77M for the 1400 slice (actual 0.15M).

## 4. Hand-graded findings (requests)

Grade = I read the code at the cited line. "real-minor" = true but low impact.

| # | Finding | Where | Verdict |
|---|---|---|---|
| 1 | OPT-PY-003 (static, MEDIUM) | cookies.py:306 `list_domains`, `not in domains` list | real-minor (O(n^2) on cookie count; jars are small) |
| 2 | OPT-PY-003 (static, MEDIUM) | cookies.py:314 `list_paths` | real-minor |
| 3 | OPT-PY-003 (static, MEDIUM) | cookies.py:598 `cookiejar_from_dict`, `name not in names_from_jar` | real-minor |
| 4 | OPT-PY-003 (static, LOW, "snap judged unlikely") | cookies.py:326 `multiple_domains` | real-minor (early return, still a list scan) |
| 5 | SNAP-017 quadratic helpers | cookies.py:598 | same code as #3, corroborates it |
| 6 | SNAP-013 object recreated per call | _internal_utils.py:13 | false positive: the cited lines are module-level compiles and docstring examples. (auth.py:295 does compile per call in a 401 handler, but `re` caches it) |
| 7 | SNAP-006 sync I/O on hot path | __init__.py:14 | false positive: a docstring example |
| 8 | SNAP-007 unnecessary copies | auth.py:302 `r.request.copy()` | false positive: the copy is needed to resend a request |
| 9 | SNAP-008 unbounded growth | __init__.py:70 | false positive: 3-element version list |
| 10 | SNAP-010 config re-read per call | adapters.py:696 | false positive: that line is `conn.urlopen`; env reads elsewhere are cheap |
| 11 | SNAP-029 temp file round trip | utils.py:19 (`extract_zipped_paths`) | false positive / design: callers need a real file path for certs |
| 12 | SNAP-001 repeated computation | no location | unverifiable (no line, no evidence) |
| 13 | SNAP-004 missing caching | no location | unverifiable |
| 14 | SNAP-025 list used for lookups | no location | unverifiable (plausibly the same cookies.py code) |
| 15 | PERF-GEN-008 payload in memory (bank) | models.py:239 `fdata = fp.read()` | debatable design: multipart upload reads each file into memory; a real limitation, documented tradeoff |

Tally of 15: real-minor 4 distinct locations (5 rows with the duplicate), debatable 1, false positive 6, unverifiable 3. Strict precision about 4-5/15 (27-33%); 40% if debatable counts. **All real hits came from the free static rule; 0 of the Snap-only optimization findings was a confirmed defect** (the Snap layer corroborated one).

Bank findings I also read (all except the first are false positives for a client library):

| Finding | Verdict |
|---|---|
| BANK-RELIAB-001 bare-pass swallow, __init__.py:103 | debatable: `except ValueError: return` skips a version check on unparseable input, intentional |
| BANK-DATA-010 email, __version__.py:11 | literally true, but it is intentional author metadata |
| BANK-SEC-016 SSRF "user URL" (score 0.97), __init__.py:14 | false positive: docstring example `requests.get(...)`; fetching a caller URL is the product |
| BANK-RELIAB-038 batch failures dropped, __init__.py:1 | false positive: points at the ASCII banner |
| BANK-ARCH-005 duplicated rule | unverifiable: "somewhere in these 19 files" |
| BANK-DOCS-029 deprecated w/o replacement | unverifiable: "somewhere in these 5 files" |
| BANK-RELIAB-035 naive timestamps (api.py, auth.py) | false positive: neither file uses datetime |
| BANK-API-006 return type varies, auth.py:59 | false positive: `_basic_auth_str` always returns str |
| BANK-SEC-020/022/032/033 (cookie flags, logout, CSRF, rate limit) | false positives: server concepts, requests is a client; SEC-033 points at a cert-path check |

Bank result: of 12 non-hint findings read, 0 confirmed defects. Scores are poorly calibrated: the 0.97 finding is a false positive.

## 5. GSM8K pairs I read

I read 10 train/test pairs from the free pass (3 x 13-gram, 7 x 8-gram):
- 13-gram train1315/test603 (plane vs train, "additional hours"): same template, different numbers (270/3/180 vs 1200/3/2000). Different answer. Not a leak.
- 13-gram train21/test633 (stamps): same template, name and all numbers changed (Bella 11 vs Max 16). Different answer. Not a leak.
- 13-gram train407/test582 (movies): shared first sentence only; different problem.
- 7 x 8-gram pairs (1102/239, 121/881, 1274/281, 1181/507, 1351/844, 1145/1288, 1072/995): shared phrases like "how much money will she have left over after she buys", "the sum of the ages". Different problems. Not leaks.

Verdict: **no verbatim or answer-level leak found in the pairs I read.** 2 of 3 strongest hits are template siblings with changed numbers, which is a known property of GSM8K, not memorisable answers. Snap flagged neither of the two template siblings (both were in the Snap slices as controls), so on this evidence Snap's recall on same-template/different-numbers items is 0 of 2, and this is consistent with them not being rewordings of the same question.

## 6. What to say at launch

- One command runs ~13 checks; on psf/requests the free pass takes 0.6 s and the full Snap optimization run takes 13 s and 62k tokens (~$0.006 at $0.09/M).
- Cost: the whole demo used 1.59M tokens (~$0.14 at $0.09/M, derived from the SubQ console, not an invoice). Dry-run estimates ran 4-5x HIGH (an upper bound, not a prediction), and `--budget-tokens` stopped runs.
- On GSM8K, the free exact/13-gram/duplicate checks across the full 7,473 x 1,319 ran in 14 s and found no exact or near-duplicate records; I read 10 flagged pairs and none is a leak. Snap: the 1,400-row slice passed its canaries (canary recall 1.0) and found nothing. The 5,000-row Snap run is INVALID: it missed both canaries (canary_recall 0.0, `part2_snap5000.txt:51`), meaning Snap did not read that text, so it says nothing about contamination there.
- On requests, the free static rule found real (minor) quadratic list-membership code in cookies.py, 4 locations. The Snap-only layers produced no confirmed defects when hand-graded (optimization ~27-33% precision, bank 0/12); their 0% decoy false-positive rate only shows the model can retrieve an exact sentence, not that its code findings are right.
- Findings are candidates to review, not verdicts; the tool says so in its own output.

## 7. Limitations (say these too)

- Hand-graded precision on requests is low: about 4-5/15 for optimization (all real ones from the free static rule), 0/12 for the bank. Snap-only findings were mostly docstring/example text, wrong lines, or concepts that do not apply to a client library. Do not claim "finds real bugs in requests".
- The built-in decoy calibration (0% FP) measures decoy items, not whether a code finding is useful; it did not predict the code-finding false positives.
- The 25 bank "local-hint" items are noise and should be hidden by default in `--check-all`.
- Free dataset PII rule fires on arithmetic numbers (both PII hits were false positives).
- GSM8K Snap covered 5,000 of 7,473 train rows against 56 of 1,319 test items, in `prefiltered` mode (can miss paraphrases with few shared words). Full train x full test would cost >2M tokens by dry-run (est. 41.5M upper bound). "Nothing found" applies to that slice only; the free pass covered everything.
- Snap missed 2 of 2 same-template controls; whether it should flag those is a definition question, but do not claim it catches them.
- One run per config, single repo, single dataset; no ground truth for the optimization findings beyond my own reading.

## 5. Canary vs window size (added after the redesign review)

The original 5,000-row GSM8K Snap run missed both canaries, so it was invalid. Re-running it reproduced the miss (`part2_snap5000_rerun.txt`: canary_recall=0.0, the CLI now errors and exits 3). Slices of 1,000-4,000 rows (`curve_*.txt`) all passed. So the limit is the tokens in one call, not the dataset.

| Train rows | Snap calls | Input tokens | ~tokens/call | Canary recall |
|---|---|---|---|---|
| 1,000 | 3 | 127,045 | 42k | 1.0 |
| 2,000 | 3 | 197,609 | 66k | 1.0 |
| 3,000 | 3 | 257,288 | 86k | 1.0 |
| 4,000 | 3 | 313,133 | 104k | 1.0 |
| 5,000 (800k-char window) | 3 | 377,966 | 126k | **0.0** (twice) |
| 5,000 (300k-char window, new default) | 5 | 388,510 | ~78k | 1.0 |

One dataset, one run per row (n=1), so the exact boundary (between 104k and 126k tokens/call) is only roughly known. The dataset check now uses 300,000-character windows. With valid canaries (1.0) the full 5,000 train rows x 56 test items give **0 Snap contamination findings**; this covers 5,000 of 7,473 train rows and 56 of 1,319 test items, not the whole benchmark. Extra cost of this section: about 1.66M tokens (~$0.15).
