# Usage

```
checksnap [--check-dataset [PATH]] [--check-optimization [PATH]] [--check-all [PATH]] [common options] [check options]
```

## Common options

| Option | Meaning |
|---|---|
| `--list-checks` | list registered checks (and any that failed to load) |
| `--explain RULE_ID` | explanation and fix hint for one rule |
| `--format text\|json\|md\|sarif` | report format (default text); `-o FILE` writes it to a file |
| `--fail-on none\|low\|medium\|high` | lowest severity that gives exit code 1 (default high) |
| `--no-snap` | local analysis only |
| `--yes` | skip the upload confirmation |
| `--dry-run` | print estimate and upload size, spend nothing, exit 0 |
| `--budget-tokens N` | hard ceiling on Snap input tokens (default 5,000,000) |
| `--workers N`, `--threshold F` | parallel calls (4); score above which an item is flagged (0.5) |
| `--cache-dir DIR` | result cache; repeated scans cost 0 calls |
| `--config FILE` | `.checksnap.toml`; command line wins over the file |

Exit codes: 0 ok, 1 findings at or above `--fail-on`, 2 usage error, 3 a check failed, budget exceeded, or auth/quota error.

## Checks

| Flag | What it checks | Snap |
|---|---|---|
| `--check-bank` | 211 ready-made questions (architecture, reliability, security, data, docs, testing) Snap answers about your files; `--bank-list` prints them, `--no-snap` runs a free regex pre-screen | yes |
| `--check-dataset` | benchmark contamination, duplicates, eval leaks, PII, licences, images | optional |
| `--check-optimization` | slow Python/PyTorch patterns | optional |
| `--check-security` | unsafe deserialization, injection, hard-coded secrets, weak crypto | no |
| `--check-dependencies` | loose pins, conflicts, undeclared/unused imports | no |
| `--check-repo` | big files, missing .gitignore entries, secrets files, conflict markers | no |
| `--check-reproducibility` | unseeded randomness, unordered data, unpinned deps | no |
| `--check-training-log` | NaNs, spikes, plateaus, overfitting in training logs | no |
| `--check-docker` | Dockerfile and compose: `:latest` images, root user, secrets, exposed ports | no |
| `--check-ci` | GitHub Actions and GitLab CI: unpinned actions, script injection, loose permissions | no |
| `--check-sql` | `.sql` and migrations: missing WHERE, risky DDL, missing indexes, money as float | no |
| `--check-config` | config files: duplicate keys, plain-text secrets, weak passwords, `.env` drift | no |
| `--check-web` | HTML/CSS/JS: accessibility, SEO basics, mixed content, heavy assets | no |

`--check-all` runs every check; `checksnap --explain RULE_ID` explains a rule; all rules are in [docs/RULES.md](RULES.md).

All take an optional PATH (default `.`) and honour `--include-tests`, `--format`, `--fail-on`. Details for the two Snap-backed checks follow.

## --check-dataset

```
checksnap --check-dataset data/ --benchmark gsm8k_test.jsonl --field question
checksnap --check-dataset train.jsonl --eval test.jsonl --id-field id
checksnap --check-dataset data/ --allowed-licenses mit,apache-2.0 --license-field license
```

Inputs: `.txt .jsonl .json .csv .tsv`, directories are walked, images need Pillow. Options: `--benchmark PATH` (repeatable),
`--field`, `--eval PATH`, `--text-field`, `--label-field`, `--id-field`, `--id-regex`, `--source-field`, `--license-field`,
`--allowed-licenses`, `--modality auto|text|image`, `--max-records`, `--contam-mode exhaustive|prefiltered`, `--dup-threshold`.

## --check-optimization

```
checksnap --check-optimization ./myproject --profile ml --static-only
checksnap --check-optimization . --snap-only --exclude 'vendor/*'
```

Options: `--profile auto|ml|general`, `--include GLOB`, `--exclude GLOB`, `--max-files N`, `--static-only`, `--snap-only`, `--include-tests`.
Static rules are free; Snap questions look for cross-file patterns (repeated work, hidden per-item calls, missing caching).

## Config file

```toml
# .checksnap.toml
fail_on = "medium"
budget_tokens = 2000000
```

## CI

`.github/workflows/ci.yml` runs the tests. To gate a repo, run `checksnap --check-optimization . --static-only --fail-on medium`;
add `--format sarif -o checksnap.sarif` to upload to code scanning. Use `--no-snap` in CI unless you accept uploads there.

## Benchmark

`python -m benchmarks.run` plants known contaminated records and known slow code, and reports recall and false positives against
the in-process fake Snap server. `--real` uses the real API (needs `SUBQ_API_KEY`, spends tokens). The fake server only matches
verbatim needles, so its recall says the plumbing works, not how good Snap is at paraphrases.

## --check-bank

```
checksnap --check-bank src/                      # ask every relevant question in one Snap pass
checksnap --check-bank --bank-list               # print the bank, no path or Snap needed
checksnap --check-bank . --bank-categories SEC,DOCS --bank-top 10
checksnap --check-bank . --bank-file mine.json   # add your own items (same schema)
checksnap --explain BANK-SEC-011
```

Items filter themselves by file kind (`--bank-applies`). Flags are candidates, not proof. With `--no-snap` only regex hints run (INFO).
