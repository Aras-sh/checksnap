# checksnap redesign

Date: 2026-10-11. Based on: the diagnosis, 3 design proposals (P1 evidence-or-nothing, P2 per-file routing, P3 referent-only), 3 judge reviews, and spot checks on the repo.

## 1. Verdict

Snap works when the question carries the thing to look for, its **referent**: in contamination the benchmark item sits inside the question, and that path measured well. Snap fails when it must decide alone whether a whole class of bug applies, because on real code it answers "is this topic here?", not "is this bug here?", and checksnap's own attribution code then pointed at the wrong file and line. So the fix is mostly deletion. Snap stays for contamination only, and a missed canary becomes a hard error. The bank, the Snap optimization questions and `--snap-verify` leave the product, and a free deterministic triage rule replaces `--snap-verify`. The free static rules, already the strongest part, become the headline. Snap comes back to code only if it passes a line-level test on real repos (roadmap 9), and if that test shows it adds nothing, the README says so. **Next action: rewrite demo/README.md lines 101-103 before launch, because two of them are false today (roadmap 1).**

## 2. Root causes (ranked)

1. **No referent, so Snap matches topics, not bugs.** Bank questions ask "does the text contain X anywhere?" with nothing specific to find. Snap fires on vocabulary, comments, docstrings and file names. Examples: API-006 at 0.91 on code that always returns str, and RELIAB-035 "naive timestamps" at 0.82 on files that never use datetime. `--snap-verify` followed a `# Okay` comment and lowered all 11 httpx `verify=False` lines (score 0.04). Planted bugs scored well only because they were written from the question text.
2. **checksnap's own attribution is wrong.** This error comes before any model error.
   - Bisection takes the left half whenever it clears 0.5 (`localize.py:24`), so findings drift to the files that sort first (`__init__.py`, `__version__.py`, ...).
   - The cited line is the first regex-hint match, docstrings included. The 0.97 SSRF "finding" at `__init__.py:14` is a docstring example.
3. **The questions don't fit the project.** Items are filtered by file kind only, so a client library gets asked about CSRF, login rate limits and cookie flags. Absence items switch on by themselves at 10+ files. 5 of the 19 bank findings shown on requests were absence items. SEC-016 is filed as an absence item but is really a presence question.
4. **Calibration measures the wrong thing.** Decoys and canaries are exact-sentence lookups, the same task as contamination. They certify retrieval, not code judgement. That is why runs reported "0% FP" while the graded findings were mostly false. The clean-code baseline cost 3 real planted bugs (ARCH-018, RELIAB-011, RELIAB-033) and missed every domain false positive.
5. **Contamination is certified only at small windows.** This cause is new; the diagnosis missed it. The 1,400-row run passed its canaries at an average of about 51k tokens per call. The 5,000-row run missed both canaries at an average of about 126k tokens per call. Both averages are the logged totals divided over 3 calls, and those 3 include the small licence call, so the contamination calls themselves were larger. Window size matters for retrieval. It is *not* what drives the code false positives: the bank fire rate tracks topic diversity, not input size.
6. **The unit of work was shaped by cost, not by the task.** Questions are billed on every call, which pushed checksnap toward packed windows plus one-question bisection. On requests that came to about 92 of 98 calls and about 770k of 972k tokens, with wrong pins anyway.

Not a Snap failure: Snap missed the GSM8K same-template pairs (test 603 and 633), but the free 13-gram pass already flagged both. That is a definition gap, not a recall bug.

## 3. Target pipeline

```
 inputs: code dir | train data + benchmark
        |
 [L] collect files
        |
        +--> [L] static rules (security, optimization, dataset hygiene) ----+
        |          |                                                        |
        |    [L] triage: lower constant-arg exec + import notices to INFO   |
        |        (never touches verify=False, chmod, tar filter, hashes)    |
        |                                                                   |
        +--> [L] contamination prefilter: exact, 13-gram, MinHash ----------+
                   |                                                        |
             [S] Snap contamination                                         |
                 - benchmark item inside [[needle]]                         |
                 - packed train text, capped window                         |
                 - 1 canary per call, no per-call decoys                    |
                 - canary missed -> retry once on a split window            |
                                 -> still missed: window UNTRUSTED, exit 3  |
                   |                                                        |
             [L] localize hit (both halves, or local word overlap)          |
                   |                                                        |
                   +------------------------------------------------------> [L] report
                                     findings + canary status + "not checked" counts
```

`[L]` = local and free. `[S]` = Snap, paid.

Snap appears in one box. Snap never lowers or creates a code finding. If Snap ever returns to code, it comes back as one more `[S]` box behind the measured gate (roadmap 10): one question per specific site or claim, and abstain by default.

## 4. Delete or de-emphasize

Tomorrow: hide from `--check-all`, README and the plugin text. Delete next, once Aras OKs this file list (his rule 4):

- `checksnap/checks/bank/` (whole package: `engine.py`, `items_*.py`, `bank_extra_items.py`, `baseline/` with 8 files). Measured 0/12 real on requests, with 8-15% of items firing on clean code.
- `local_hints` and `--bank-hints`: 25 noise findings.
- In `checksnap/checks/optimization/snap_layer.py`: the 30 OPT-SNAP questions (`_BANK`), `interpret`, `_snippet_evidence`, `STATIC_LINK`, plus `--snap-only`. 0 confirmed defects, ~30% precision. Keep `pack()` and `Span` if contamination still needs them.
- `checksnap/verify.py` and `--snap-verify`: it lowered 16 of 47 real findings.
- Tests that go with them: `tests/test_bank_check.py`, `tests/test_bank_scan_quality.py`, `tests/test_verify.py`, and the OPT-SNAP parts of `tests/test_optimization_check.py`.
- Bisection for code paths, and the "somewhere in these N files" evidence.
- Per-call decoys as a default, and any output that calls decoy results a "false-positive rate".
- The 3 separate estimate formulas (engine, snapcheck, verify). They get replaced in roadmap 7.

## 5. Roadmap

### Before / at launch (tomorrow, about 7h, no Snap calls needed)

| # | Item | Hours | Success criterion |
|---|------|-------|-------------------|
| 1 | Fix the launch text in demo/README.md section 6. **Line 102** claims "the Snap pass on 5,000 train rows ... found nothing", but that run missed both canaries (`demo/part2_snap5000.txt:51`, `canary_recall=0.0`), so claim only the 1,400-row slice (`demo/part2_snap.txt:27`, `canary_recall=1.0`). **Line 103** puts "decoy FP 0, canary 1.0" next to 14 Snap optimization findings that had 0 confirmed defects, so drop the Snap half. **Line 101** says "cost is predictable" while estimates ran 4-5x high, so say "small and capped by `--budget-tokens`". In code: `run_contamination` appends a missed canary to its existing `errors` list, the same way the budget case does at `snapcheck.py:146`, so it exits 3. | 1 | Lines 101-103 rewritten. A FakeSnapServer test that drops the canary gives exit 3 and an "untrusted window" note. |
| 2 | Bank, OPT-SNAP and local_hints come out of `--check-all`, README, plugin text and the showcase. Print the delete list for Aras. | 2 | `checksnap --check-all <requests> --dry-run` with Snap on plans **0 bank and 0 OPT-SNAP calls and tokens** (today the bank alone is estimated at 5.0M). The 4 real OPT-PY-003 findings in cookies.py stay. pytest green. |
| 3 | A deterministic `--triage` replaces `--snap-verify`. It lowers command-execution findings to INFO when every argument is a constant. A variable name counts as constant only if its **nearest earlier assignment in the same scope** is constant: in `subprocess_shell.py`, line 41 (`command = "/bin/ls" + unknown_function()`) must stay flagged and lines 46+ (`command = 'pwd'`) get lowered, so a plain `ast.Constant` check is not enough. It also lowers import-only notices (B403/B404), crypt `METHOD_BLOWFISH` under B324, and `extractall(members=[])` to INFO. Config families are never touched. | 4 | Ship table A of verify_grading.md as test fixtures. My hand count against that table: 26 of 31 come from constants plus name resolution, and 29 once the blowfish and `members=[]` rules are added. The 2 it misses are #2 (pickle of self-made data) and #30 (no-op closure). Pass = **0 of 16** real findings lowered and **≥ 27 of 31** correct downgrades, at 0 tokens and under 0.2 s. Then re-check on the 30 stdlib files with no real finding lowered. 11 of the 16 are one httpx pattern, so this is still a small test. |

Optional tomorrow, needs Snap (about 250k tokens, about $0.02): re-run the GSM8K 5,000 slice with smaller windows. Only if canary recall is 1.0 can line 102 keep its 5,000-row claim.

### After launch (ranked)

| # | Item | Hours | Success criterion |
|---|------|-------|-------------------|
| 4 | Canary recall vs state length. Run 4-5 window sizes and set `WINDOW_CHARS` from the curve. Decoys go to 0 per call, so 63 real questions fit per call and the 55+1 split ends. Re-measure the planted-paraphrase recall at the chosen size and **write down the window size**. | 4 | Canary 1.0 in every window at the chosen cap. Planted paraphrase recall ≥ 39/40 with 0 FP, recorded in RESULTS.md with tokens per call. 56 items take 1 call per window. |
| 5 | Actually delete the section 4 list (after Aras OKs it). | 2 | Files gone, pytest green, `docs/RULES.md` regenerated, no dead flags left. |
| 6 | Localization for contamination: first test whether local word-overlap ranking finds the planted record. If yes, delete bisection. If no, fix `localize.py`: score both halves, keep the higher, return None on a dead end. | 3 | Local ranking puts the planted record in the top 3 for ≥ 36/40 → delete `localize.py`. Otherwise the fixed bisection pins ≥ 36/40. |
| 7 | One `plan()` drives both `--dry-run` and the scan. It skips calls already in the cache and runs the prefilter inside the dataset estimate. | 5 | Estimate/actual between 0.8x and 1.3x on 5 runs (today 4.4-5.1x). A fully cached re-run estimates 0 tokens and makes 0 calls. |
| 8 | Replay harness: one command that re-scores the saved outputs (`benchmarks/compare/raw/*.json`, `demo/*.txt`). The cache holds only 5 entries and the raw files keep only emitted findings, so this can re-check emitted findings but **cannot** refit thresholds or reproduce 39/40 without live calls. | 4 | Reproduces bank 0/12, verify 31 correct / 16 wrong and T5 27/30 from disk with 0 tokens. |
| 9 | Go/kill test for Snap on code. Pick real-repo bug-fix pairs, not T5. The local clones are depth-1, so mining history needs `git fetch` (network, Aras approves). Without it, use hand-graded sites only. Blank comments and docstrings, use neutral file ids, and ask one question per quoted line about the buggy line and the fixed line. Add an applicability gate (server / client / db tags) and abstain counts by reason. | 8 + labelling | **Pass:** bug beats fix in ≥ 80% of ≥ 30 pairs and the fix scores < 0.5 in ≥ 2/3. **Kill:** bug beats fix in < 70% → Snap stays out of the code path for good, and the README says so. Also kill if Snap adds < 15 points of precision over a local rule alone. |
| 10 | `measured.json` gate. A Snap rule shows findings only if it has real-repo precision ≥ 0.6, printed with n, model id, corpus and date. If the model id changes, it must be re-measured. | 4 | Every visible Snap finding has a measured line. A rule with no entry shows nothing unless `--unmeasured` is passed. |
| 11 | Docs-vs-code drift (P3), only if item 9 or its own one-day test passes. The doc claim goes inside the question, an `ast` resolver settles what it can for free, and a cross-repo control runs. The changelog part needs `git fetch --deepen` (network, Aras approves). | 8 (+8 changelog) | Snap part: precision ≥ 0.7 at recall ≥ 0.5 on real claims, ≤ 1 FP per 100 true claims, cross-repo control AUC ≤ 0.6. Fail → ship the free `ast` resolver only. |

Skipped on purpose:
- **A new "template sibling" detector.** The free 13-gram pass already catches the GSM8K pairs; at most, relabel those hits.
- **P2's per-file routing for the bank.** It makes a feature that doesn't work cheaper.

## 6. Launch claims

**Can say (measured, in the repo):**
- Free static pass on psf/requests: 0.6 s. It found 4 real (minor) quadratic list-membership spots in `cookies.py`.
- Free GSM8K checks over the full 7,473 x 1,319 in 14 s: no exact or near-duplicate records. The 13-gram pass flagged 2 template-sibling pairs (test 603, 633). Hand-read, these are different numbers and answers, not leaks.
- Snap contamination on the 1,400-row slice x 56 items: canary recall 1.0, no Snap hits, 154k tokens.
- The whole demo cost about $0.14, and `--budget-tokens` stops runs.
- Findings are candidates to review, not verdicts.

**Cannot say:**
- "Snap finds real bugs in code." Bank 0/12, Snap optimization 0 confirmed.
- "Snap found nothing on 5,000 GSM8K rows." The canaries failed.
- "Decoy FP 0%" as a quality signal. It measures decoys, not findings.
- "Snap catches same-template leaks." It went 0 of 2.
- "Cost is predictable." Estimates were 4-5x high.
- "39/40 paraphrase recall, 0 FP over 61 windows." This is not recorded anywhere in the repo, and its window size is unknown. Re-run it (roadmap 4) before quoting.
- Anything about `--snap-verify` reducing noise safely. It lowered 16 of 47 real findings.

## 7. Open questions for Aras

1. **Tomorrow: hide or delete?** Default is to hide the bank, OPT-SNAP and `--snap-verify` now, then delete after you OK the section 4 list.
2. **Re-run GSM8K 5,000 with smaller windows tomorrow** (about $0.02, Snap API)? Or launch with the 1,400-row claim only?
3. **Where did "39/40, 0 FP over 61 windows" come from?** What window size? If nobody knows, roadmap 4 re-measures it.
4. **Is Snap-on-code still a goal?** If "static rules + contamination" is the product, skip items 9-11 and save about 30h.
5. **Network for the changelog drift check** (`git fetch --deepen=500` on requests and flask): yes or no, when we get there?
6. **Labels:** every grade so far came from one LLM grader. Will you spot-check 20 rows per labelled set?
