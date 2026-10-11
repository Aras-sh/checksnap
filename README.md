# checksnap

![checksnap demo](showcase/showcase.gif)

One CLI that checks things with [SubQ Snap](https://subq.ai) (a long-context decision model) plus free local analysis.
Each check is a flag.

```
checksnap --check-dataset data/ --benchmark gsm8k_test.jsonl   # contamination, duplicates, leaks, PII, hygiene
checksnap --check-optimization ./myproject                     # slow-code patterns (static + Snap)
checksnap --check-all . --dry-run                              # estimate and show what would be uploaded
```

## Checks

| Flag | What it checks | Snap |
|---|---|---|
| `--check-bank` | 211 ready-made questions (architecture, reliability, security, data, docs, testing) Snap answers about your files; `--bank-list` prints them, `--no-snap` runs a free regex pre-screen; findings are checked against a bundled clean-code baseline and absence-style items need 10+ files (`--bank-include-absence`) | yes |
| `--check-dataset` | benchmark contamination, duplicates, eval leaks, PII, licences, images | optional |
| `--check-optimization` | slow Python/PyTorch patterns; also `--snap-verify` and `--with-adapters` (ruff) | optional |
| `--check-security` | unsafe deserialization, injection, hard-coded secrets, weak crypto; `--snap-verify` has Snap judge each finding, `--with-adapters` merges bandit/detect-secrets | optional |
| `--check-dependencies` | loose pins, conflicts, undeclared/unused imports | no |
| `--check-repo` | big files, missing .gitignore entries, secrets files, conflict markers | no |
| `--check-reproducibility` | unseeded randomness, unordered data, unpinned deps | no |
| `--check-training-log` | NaNs, spikes, plateaus, overfitting in training logs | no |
| `--check-docker` | Dockerfile and compose: `:latest` images, root user, secrets, exposed ports | no |
| `--check-ci` | GitHub Actions and GitLab CI: unpinned actions, script injection, loose permissions | no |
| `--check-sql` | `.sql` and migrations: missing WHERE, risky DDL, missing indexes, money as float | no |
| `--check-config` | config files: duplicate keys, plain-text secrets, weak passwords, `.env` drift | no |
| `--check-web` | HTML/CSS/JS: accessibility, SEO basics, mixed content, heavy assets | no |

`--check-all` runs every check; `checksnap --explain RULE_ID` explains a rule; all rules are in [docs/RULES.md](docs/RULES.md).

## Install

```
pip install -e .            # runtime dependency: httpx only
pip install -e '.[images]'  # optional: Pillow for image checks
```

Python 3.10+.

## Quickstart (no key, no network)

```
checksnap --check-dataset examples/dataset --benchmark examples/dataset/benchmark.jsonl --no-snap
checksnap --check-optimization examples/optimization --static-only
```

`--no-snap` still gives a useful report: exact and n-gram overlap, duplicates, PII, hygiene, and all static code rules.

To use Snap, set `SUBQ_API_KEY` (environment or a `.env` file in the current directory), then run with `--dry-run` first.

## Privacy and cost, honestly

* Snap checks upload your text to `api.subq.ai`. Before the first call checksnap prints the host, the bytes that leave
  the machine, and the estimated calls and tokens, then asks `[y/N]`. `--yes` skips the prompt; without a terminal and without
  `--yes` the Snap parts are skipped (local parts still run). `--dry-run` spends and uploads nothing.
* No price is published and responses carry no cost field, so checksnap reports **tokens**, not money. The token estimate is a
  conservative upper bound (per file type) that gets calibrated from real usage. `--budget-tokens` (default 5,000,000) is a hard ceiling; hitting it stops the run
  with exit code 3 and prints the partial result.
* The API key is read from the environment or `.env`, never printed, logged or written. Results are cached on disk
  (`--cache-dir`); a repeated scan costs 0 calls. Delete the cache directory if your data is sensitive.

## Limits

* Findings are **candidates, not proof**. Every Snap finding shows its score and the window it came from. Each run also reports
  its own measured false-positive rate (decoy questions that should never fire) and canary recall (planted sentences it should find).
* A Snap score is a probability for one window, not a verdict. Raise `--threshold` to cut false positives and lose recall.
* N-gram checks are blind to items shorter than n words and to paraphrases; that is what Snap is for.
* Static optimization rules are heuristics over Python `ast`; other languages get the Snap layer only.
* `--contam-mode prefiltered` is cheaper but loses some recall; `exhaustive` (default) does not.

## Claude plugin

Let Claude Code find bugs with checksnap while spending very little of your usage.

```
/plugin marketplace add Aras-sh/checksnap
/plugin install checksnap@checksnap
```

Tools: `checksnap_list` (checks, one line each), `checksnap_scan` (digest of the top findings), `checksnap_detail` (one finding with
evidence and fix, no rescan), `checksnap_estimate` (free upload/cost table). The `bugscan` skill tells Claude to scan first and
read only what the digest points at.

Why it is cheap: the checks run locally and are free; a scan returns at most ~3,000 characters (one line per finding, repeats
collapsed as `x7`, no snippets); Claude never reads the repo to look for bugs; Snap runs only after you agree, because the call
refuses without `confirm_upload=true` and states what would be uploaded to `api.subq.ai`. See [docs/PLUGIN.md](docs/PLUGIN.md).

## More

* [docs/USAGE.md](docs/USAGE.md): all options, exit codes, config file, CI use
* [docs/RULES.md](docs/RULES.md): every rule id (generated by `benchmarks/gen_rules.py`)
* [docs/SPEC.md](docs/SPEC.md): design spec
* `python -m benchmarks.run`: planted-contamination benchmark against the fake server
