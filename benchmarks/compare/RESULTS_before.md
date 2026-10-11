# checksnap vs existing tools: benchmark results (2026-10-11)

All numbers come from `run_all.py` -> `results.json` (raw per-finding dumps in `raw/`). CPU only, `nice -n 10`, one machine, single run per timing (no repeats, so treat timings as +/-20%). Synthetic data was written by the benchmark author; see Limitations before quoting any number.

## 1. Tables

### T1 Security: bandit's own labelled examples (76 vulnerable files) + 30 stdlib files

Ground truth: `examples/*.py` whose expected issue count in bandit's own `tests/functional/test_functional.py` is > 0 (76 files), plus 4 expected-clean examples. "In scope" = the 20 of those 76 files that map to one of checksnap's 15 security rules (hand mapping in `run_all.py: IN_SCOPE`). The labels come from bandit itself, so bandit scoring 100% is circular; read bandit's row as an upper bound.

| Tool | 76 vulnerable files with any finding | In-scope 20: any finding / right class | Expected-clean examples flagged (of 4) | Stdlib 30 files: files flagged / findings | Wall time (examples + stdlib) |
|---|---|---|---|---|---|
| bandit 1.9.4 | 76/76 (100%, circular) | 20/20 / 19/20 | 1 | 10/30 / 26 (16 are B101 `assert`) | 0.17 s + 0.30 s |
| semgrep 1.180 `p/python` | 16/76 (21%) | 7/20 / n/a | 0 | 0/30 / 0 | 1.34 s + 1.51 s |
| checksnap `--check-security` | 21/76 (27.6%) | 17/20 / 17/20 | 0 | 6/30 / 7 | 0.08 s + 0.11 s |

Stdlib findings for checksnap (7): 2x SEC-003 (`exec(code, g)` in runpy, `eval(expr, ns)` in rlcompleter: both are real eval, by design of those modules), 1x SEC-001 (`pickle.load` in tracemalloc), 4x SEC-009 (`assert`, LOW). No stdlib finding was a bug; 3 are genuine uses of dangerous primitives, 4 are LOW noise.
checksnap in-scope misses: `assert.py` (`assert True`), `exec.py` (`exec("do evil")`, constant string, deliberately not flagged by SEC-003), `django_sql_injection_raw.py`.

### T2 Secrets: 60 planted fake secrets (6 kinds x 10 files, 6 file formats) + 60 decoys

Decoys (each rendered in the same 6 formats as the planted files, 10 per format): hashes, UUIDs, base64 PNG, lorem ipsum, version strings, SRI hashes, `PASSWORD_FIELD=password`-style non-secrets. Precision/F1 are file-level. (A first run used `.py`-only decoys, which `--check-config` never scans; fixed after review.)

| Tool | Recall (files) | Decoy files flagged (of 60) | Precision | F1 | Time (120 files) |
|---|---|---|---|---|---|
| detect-secrets 1.5.0 (default) | 54/60 = 0.90 | 21 | 0.72 | 0.80 | 1.1 s |
| detect-secrets (entropy plugins off) | 48/60 = 0.80 | 4 | 0.92 | 0.86 | 1.5 s |
| checksnap `--check-security` only | 32/60 = 0.53 | 0 | 1.00 | 0.70 | 0.12 s |
| checksnap `--check-config` only | 29/60 = 0.48 | 0 | 1.00 | 0.65 | 0.12 s |
| checksnap security + config (what `--check-all` runs) | 47/60 = 0.78 | 0 | 1.00 | 0.88 | 0.24 s |

Per format (files detected of 10): detect-secrets default env 10, json 9, py 10, sh 10, txt 6, yaml 9. checksnap union: env 10, json 10, py 10, yaml 10, sh 7, **txt 0** (plain `.txt` is never scanned). Per kind, checksnap union: aws 9, ghp 9, slack 8, pkey 8, jwt 6, password 7 (of 10); detect-secrets default: aws 10, ghp 10, pkey 10, jwt 10, password 8, slack 6.
JSONL records (15 planted, 15 decoy lines): checksnap `--check-dataset` DS-PII-001 flagged 13/15 planted lines, 0 decoys; detect-secrets flagged 7/15, 0 decoys.

### T3 Performance / code smells: 40 labelled slow snippets + 40 clean snippets

28 snippets target rule families checksnap documents (biased toward checksnap); 12 (`O_*`) are real perf/smell issues outside its documented rules. "Line recall" = a finding reported on the labelled line. Clean = findings on the 40 clean snippets. "Other" = findings on unlabelled lines of the slow snippets. Precision/F1 count clean + other findings as false positives (strict; some are arguably true).

| Tool | Line recall all | Recall in checksnap's 28 | Recall in outside 12 | Clean files flagged | Clean findings | Other | Precision | F1 | Time |
|---|---|---|---|---|---|---|---|---|---|
| checksnap `--check-optimization --static-only` | 22/40 | 21/28 | 1/12 | 3/40 | 3 | 5 | 0.73 | 0.63 | 0.14 s |
| ruff 0.17 `PERF,SIM,C4,B` | 9/40 | 5/28 | 4/12 | 5/40 | 6 | 5 | 0.45 | 0.30 | 0.02 s |
| pylint 4.1.3 default | 7/40 | 5/28 | 2/12 | 40/40 | 102 | 108 | 0.03 | 0.05 | 1.7 s |
| pylint, docstring/naming (C0114/5/6/3/4) off | 7/40 | 5/28 | 2/12 | 12/40 | 19 | 15 | 0.17 | 0.17 | 1.8 s |
| flake8 7.4.1 default | 1/40 | 1/28 | 0/12 | 22/40 | 28 | 17 | 0.02 | 0.02 | 0.14 s |

checksnap missed inside its own families (7): `concat_while` (`s = s + x` in a while loop), `sort_in_loop` (x2), `nplus1_orm` (SQLAlchemy `.query()` in a loop), `no_amp`, `no_grad` (model call in eval loop without `no_grad`), `zero_grad` (no `set_to_none`). Its 3 clean-file findings are OPT-ML-003 x2 / OPT-ML-002 (arguably correct but unlabelled). Pylint's E0401/E0602 on the synthetic files are import/undefined-name artifacts of snippet files, not code smells.

### T4 Config / Docker / CI / SQL: public real-world samples, overlap + manual true/false

Samples: 20 Dockerfiles (docker/awesome-compose, tiangolo/uvicorn-gunicorn-docker, PyCQA/bandit), 20 GitHub workflows (requests, flask, fastapi, bandit), 20 YAML files, 15 SQL files (sakila, datacharmer/test_db; sqlfluff run per-dialect). Manual judgement: 15 random findings per tool by the benchmark author (an LLM; subjective), criterion = "true of that line and not a valid pattern". Method and notes in `judgments.json`.

| Area | Tool | Findings | Time | Manual correct (of sample) | Notes |
|---|---|---|---|---|---|
| Docker | hadolint 2.15.1 | 26 (+10 parse failures) | 0.04 s | 12/15 | 10/20 files fail to parse (DL1000, heredoc `RUN <<EOF` + comment); 3 DL3022 false positives on `COPY --from=<image>` |
| Docker | checksnap `--check-docker` | 52 (29 on the 10 files hadolint parsed) | 0.06 s | 15/15 | all 20 files: DOC-010 x17, DOC-002 x16, DOC-011 x16, DOC-007 x2, DOC-009 x1; 5 of 15 sampled are dev-only stages |
| CI | actionlint 1.7.12 | 15 | 0.10 s | 15/15 | all shellcheck inside `run:` (no syntax/expression errors in these files) |
| CI | checksnap `--check-ci` | 54 | 0.07 s | 15/15 | 28 are INFO `ubuntu-latest`, 13 no `timeout-minutes`, 8 no `concurrency`, 4 tag-not-SHA, 1 branch ref |
| YAML | yamllint 1.38 (default) | 167 | 0.12 s | 12/15 | style only: line-length 52, comments 45, indentation 36, document-start 20, truthy 12 (GitHub `on:`) |
| YAML/config | checksnap `--check-config` | 12 | 0.07 s | **0/12** | every finding is CFG-003 "Secret in plain text" on `${{ secrets.X }}` references |
| SQL | sqlfluff 4.4.0 | 1274 (4 parse errors) | 4.6 s | 14/15 | all layout/style (LT01 537, LT02 330, LT05 100, CP01 86, CV06 70) |
| SQL | checksnap `--check-sql` | 110 | 0.09 s | 15/15 literally, ~1/15 real | 96 are DELETE-without-WHERE / DROP-without-IF-EXISTS inside teardown scripts that exist to do exactly that |

Overlap (same file and line): Docker 2 of 26/29; CI 0 (actionlint is shellcheck-only here, checksnap is hygiene-only); YAML 1; SQL 67 of 1274/110 (sqlfluff flags the same statements for formatting). The tools are mostly complementary; the only same-concern pairs on Dockerfiles were 1 (pip `--no-cache-dir`). hadolint's DL3018/DL3013 (version pinning), DL3019 (apk cache), DL3059 (layer consolidation), DL3067 (`COPY --from /`) have no checksnap equivalent; checksnap's DOC-010 (`.dockerignore`), DOC-011 (HEALTHCHECK), DOC-002 (no USER) have no hadolint equivalent (hadolint only flags an explicit `USER root`).

### T5 Snap bank (real API): 30 planted semantic bugs + 30 clean twins

30 distinct bank items (13 SEC, 13 RELIAB, API-002, ARCH-018, ARCH-037, PERF-GEN-003), each with a buggy file and a clean twin (bug fixed), neutral shuffled file names, 60 files / 12 KB. 152 code-applicable items asked.

| Metric | Result |
|---|---|
| Planted item flagged >= 0.5 anywhere (one 60-file project) | 30/30 |
| Precision@k of the global ranking (planted items among the first k findings) | @5 5/5, @10 9/10, @25 19/25, @50 26/50 |
| Recall@k (ceiling 30) | @25 19/30, @50 26/30 |
| Items flagged >= 0.5 in total (of 152 asked) | 74 = 49% base rate (44 off-target); in the 10-file projects ~26% |
| Planted findings that got a file/line (only the top 10 findings are localized) | 9; correct file in 5 of them; 2 clean files wrongly blamed |
| Six 10-file projects (5 buggy + 5 clean files each): planted flagged / planted within the first 5 findings (ceiling 30) | 28/30, 18/30 |
| Off-target flags in those 10-file projects | 211 over 6 projects = 35 per 10-file project (33-37 of 38-42 flagged), i.e. 3.5 per file |
| Off-target flags whose own regex hint matches nothing in the code | 133 of 209 hinted (64%) |
| Calibration reported by checksnap itself | decoy FPR 0.0, canary recall 1.0 |
| Tokens | 30,913 input (60-file project; the pre-run estimate said 12,936) + 127,245 (six batches) = 158,158 of the 400,000 cap |
| Time | 19.8 s (project), 3.6 s per 10-file project (cached tokens re-run: 0 s) |

My read of 14 random off-target flags (against code I wrote): 2 are defensible (API-005 undocumented functions, ARCH-037 `sleep` in retry code), the other 12 have no basis in the code (e.g. "Session not rotated on login", "Long-lived token", "Logout does not invalidate token" on files with no session code).

Static comparators on the same 60 files ("relevant" = hand-listed rule codes that actually describe the planted bug, so most of the 30 items cannot be counted by construction):

| Tool | Buggy files with relevant finding | Buggy files with any finding | Clean files with any finding (of 30) | Clean findings |
|---|---|---|---|---|
| checksnap static security + optimization | 0/30 | 1/30 | 0/30 | 0 |
| ruff `B,S,PERF,SIM,BLE,ASYNC,RUF,E,F` | 7/30 | 19/30 | 18/30 | 33 (mostly F821 undefined name from non-self-contained snippets, E501, E401) |
| pylint default minus C | 5/30 | 21/30 | 14/30 | 25 (E0401/E0602 import/undefined artifacts) |
| bandit | 5/30 | 5/30 | 3/30 | 7 (B404/B603/B607 on subprocess) |

### T6 Speed and size

| Tool | checksnap repo copy (114 .py files, 15.0k lines) | requests (37 .py, 12.0k lines) |
|---|---|---|
| checksnap `--check-all --no-snap` (13 checks) | 3.0 s (189 findings) | 1.45 s (108 findings) |
| bandit -r | 0.96 s | 0.45 s |
| semgrep p/python | 2.76 s | 1.57 s |
| detect-secrets | 0.48 s | 0.51 s |
| ruff PERF,SIM,C4,B | 0.01 s | 0.01 s |
| pylint default | 6.67 s | 5.94 s |
| flake8 | 0.28 s | 0.27 s |
| yamllint | 0.05 s | 0.07 s |
| sqlfluff ansi | 0.31 s | 0.15 s |
| checksnap raw JSON output | 140,645 chars | 79,200 chars |
| Raw output of the other eight tools combined | 2,270,902 chars | 1,171,289 chars |
| Plugin digest (`mcp_server.checksnap_scan`, defaults: min severity medium, top 15, 3000 char cap) | 1,918 chars (~480 tokens) | 1,417 chars (~354 tokens) |

The digest is 0.08% / 0.12% of the combined raw output. That is not a like-for-like compression: it contains only the top 15 medium+ groups of checksnap findings, not the other tools' findings, and the raw outputs include code snippets and every low-severity message. hadolint/actionlint were not timed on these trees (no Dockerfile/workflow in the checksnap copy; see T4 for their per-file speed: 0.04 s and 0.10 s). Most of checksnap's 3.0 s is the `bank` local pre-screen (1.5 s) and `optimization` (0.7 s).

## 2. Verdicts

**Security (T1).** checksnap loses this category against bandit. It has 15 rules versus bandit's ~70 tests: it detects 21 of 76 bandit example files (28%) against bandit's 76, and 17 of the 20 files in its own scope with the right rule (bandit 19/20 by the same mapping). It does beat semgrep `p/python` (16/76 on these examples, because the registry rules are mostly taint-based and these files are bare calls). It is quieter than bandit on real stdlib code (0.23 findings/file against 0.87; bandit's are mostly `assert`) and is 2-4x faster, but the 4 SEC-009 findings it produces are the same assert noise. Not designed for: library/import-level checks, Django/Jinja XSS, crypto-mode checks, SSH/paramiko, XML/ftplib/telnet.

**Secrets (T2).** On my synthetic set checksnap's security + config checks together (47/60, no false positives, F1 0.88) beat detect-secrets default (54/60 but 21 decoy files flagged, F1 0.80) and edged out detect-secrets with entropy plugins off (48/60, 4 decoy files, F1 0.86). The recall gap is real, not a tuning difference: checksnap never scans `.txt`, misses 3 `.sh`, is weak on JWT (6/10) and relies on running two checks (`--check-security` alone is 53%, `--check-config` alone 48%). detect-secrets is better on raw recall (and on Slack only via entropy), checksnap is better on precision with no tuning. The decoy set favours rule-based tools and punishes entropy detection, which is a choice I made.

**Performance (T3).** checksnap wins on its own families (21/28 vs ruff 5/28 and pylint 5/28, precision 0.73, F1 0.63 vs ruff 0.30) but that is by construction: 28 of the 40 snippets were written from checksnap's rule list. On the 12 outside issues ruff is better (4/12 vs checksnap 1/12). Pylint's and flake8's default configs are not performance tools: pylint's raw output is mostly docstring noise (all 40 clean files flagged by default), flake8 flagged one labelled line. checksnap missed 7 of the 28 in-family cases, including `no_grad` and `no_amp`, so the rule implementations are narrower than the rule titles suggest.

**Config/Docker/CI/SQL (T4).** Complementary, not replacement. hadolint finds package pinning and layer issues checksnap lacks, but it failed to parse half the sampled Dockerfiles (modern heredoc syntax) and has 3/15 false positives on valid `COPY --from`. checksnap's Docker rules are correct on all 15 sampled findings but are generic hygiene (no USER, no HEALTHCHECK, no .dockerignore). actionlint covered shellcheck-level problems that checksnap has no rule for; checksnap `--check-ci` covered pinning/timeouts/concurrency that actionlint does not check; both were 15/15 correct. yamllint is a style tool with 167 style findings on 20 files; checksnap `--check-config` produced 12 findings on the same files and **all 12 are false positives** (it treats `${{ secrets.X }}` as a plaintext secret), which would fire on essentially every GitHub repository. sqlfluff is a formatter-style linter (1274 style hits, 4.6 s); checksnap SQL rules are semantic but on this corpus 96 of 110 findings are intentional teardown statements. checksnap is 50-100x faster than sqlfluff.

**Snap bank (T5).** This is the one category where the other tools are not competitors: ruff/pylint/bandit found a relevant issue in 5-7 of 30 buggy files (checksnap static rules 0), while the bank flagged all 30 planted items. Against a 49% base rate (74 of 152 items cross 0.5 on the 60-file project; about 26% in 10-file projects) the 30/30 and 28/30 are real signal, not just everything-is-flagged. The head of the ranking is clean (precision@5 5/5, @10 9/10, @25 19/25) and the noise sits in the tail (@50 26/50). Weaknesses: attribution is project-level, not file-level (only the top 10 findings carry a file/line, and 5 of 9 localized planted findings pointed at the right file, 2 clean files were blamed); off-target flags are many (35 per 10-file project) and 64% of them have nothing in the code matching the item's own regex hint; calibration reported a 0.0 false-positive rate, which does not reflect the real-code rate measured here. Cost: 30.9k input tokens for 12 KB of code; the dry-run estimate (12.9k) understated it 2.4x. With a reader taking the first 10-25 findings it is useful; as a full checklist on 60 files half the items fire.

**Speed and size (T6).** checksnap runs 13 checks in 1.5-3 s, between bandit (0.5-1 s) and pylint (6-7 s), and is faster than semgrep. Raw output is 80-140 kB JSON, while the plugin digest is 1.4-1.9 kB (~350-480 tokens), a large saving for LLM context but lossy (top 15 groups at medium+).

## 3. Reproduce

```
cd /home/aras/Projects/checksnap
python3 -m venv .bench-venv
.bench-venv/bin/pip install bandit semgrep detect-secrets ruff pylint flake8 yamllint sqlfluff     # versions below
mkdir -p benchmarks/compare/{data,bin,dl,raw}
cd benchmarks/compare/data
for r in PyCQA/bandit psf/requests pallets/flask tiangolo/fastapi docker/awesome-compose tiangolo/uvicorn-gunicorn-docker datacharmer/test_db jOOQ/sakila; do git clone --depth 1 https://github.com/$r; done
cd ..
curl -sL -o bin/hadolint https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-linux-x86_64 && chmod +x bin/hadolint
curl -sL -o dl/al.tgz https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz && mkdir dl/al && tar xzf dl/al.tgz -C dl/al && cp dl/al/actionlint bin/
# T5 spends real tokens; key is sourced inside the run (set -a; . <env file>; set +a), never printed
../../.bench-venv/bin/python run_all.py            # all tasks, writes results.json (~2 min, ~160k Snap input tokens)
../../.bench-venv/bin/python run_all.py t1 t2 t3   # or any subset
```
Real-API results are cached in `raw/bank_*.json` and `.snapcache/`; re-running `t5` re-uses them and spends nothing (delete both to re-spend). Data generators: `gen_secrets.py`, `gen_perf.py`, `gen_bank.py` (seeded). Semgrep and ruff need `--no-git-ignore` / `--no-respect-gitignore` because `data/` is gitignored (without it semgrep silently scanned 0 files).

Versions: bandit 1.9.4, semgrep 1.180.0 (`--config p/python`, registry reachable, `--metrics=off`), detect-secrets 1.5.0, ruff 0.17.0, pylint 4.1.3, flake8 7.4.1, yamllint 1.38.0, sqlfluff 4.4.0, hadolint 2.15.1, actionlint 1.7.12, checksnap 0.1.0 (run as `python -m checksnap --no-snap` from `.venv`, i.e. includes Python and httpx start-up in its wall times), Python 3.12.3. Commands per tool are in `run_all.py` (e.g. `ruff check --select PERF,SIM,C4,B --isolated`, `bandit -r -f json`, `detect-secrets scan --all-files`, `checksnap --check-optimization DIR --static-only`).

## 4. Limitations

- **Synthetic and self-authored data.** T2, T3 and T5 inputs were written by the same author (an LLM) who read checksnap's rule list. T3's 28 in-family snippets are biased toward checksnap by construction; T5's buggy files are short, single-bug, unmistakable snippets, easier than real code, and the clean twins are tidy rewrites, not typical production code.
- **Labelling bias.** T1 labels come from bandit's test-suite, so bandit is circular (100%). "Right class" mapping for checksnap/bandit is hand-made. T3 line-level recall accepts any finding on the line (generous to noisy tools); precision treats unlabelled findings as false positives (harsh; some are true). T5 "relevant finding" for static tools uses a hand-written code list. T4 true/false judgement is one (LLM) reviewer on 15 samples per tool with a tolerant "literally true" criterion; no inter-rater check. n=15 gives wide intervals.
- **Corpus effects.** T4 SQL corpus is dominated by teardown scripts (adversarial for SQL-002/003); the Docker sample is dominated by awesome-compose templates; stdlib is not "clean" (it intentionally uses exec/eval/pickle). Pylint import/undefined-name findings are artifacts of non-self-contained snippets.
- **Not run / not comparable.** semgrep only with `p/python` (no `p/security-audit`, no login/Pro rules). No taint-mode or LLM-based scanner was compared for the bank. checksnap's Snap-backed modes other than `--check-bank` (dataset contamination, Snap optimization layer) were not benchmarked here; `--check-dataset` only via its local PII rule. `--check-dependencies`, `--check-repo`, `--check-reproducibility`, `--check-web`, `--check-training-log` have no comparator here.
- **Timing.** Single runs, shared 10-core machine under `nice`; sub-0.1 s timings are noise. checksnap numbers include interpreter and httpx import; the standalone tools' do not except where they pay their own start-up (semgrep ~1 s fixed).
- **T5 design adaptation.** The bank returns one best window per item, not per file, and localizes only the top 10 findings. "Top 5 / top 25 for its file" was therefore measured as global rank of the planted item plus file attribution where available, and per-file false-positive rate is approximated by off-target items per 10-file project. The 10-file batches reuse the same code, so they are not independent samples.
