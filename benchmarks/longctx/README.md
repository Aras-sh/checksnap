# Long-context benchmark harness (SubQ 12M)

Offline and ready for when beta access arrives. Nothing here calls a real API until you run `run`/`canary`/... with
`SUBQ_API_KEY` set and type `RUN` at the prompt. Tests use local fake servers only. The key is read only from
`SUBQ_API_KEY` (never from a file, never printed or written to results). `.env` is never read.

**What is NOT known yet:** the target model is SubQ from Subquantific, not the Snap decision model. Its model name and API
shape are unknown until access arrives, so the `chat` backend is configuration, not code (see below). The `snap` backend is
the existing checksnap client and works today.

## Commands (from the repo root, `.venv/bin/python -m benchmarks.longctx ...`)

| command | what |
|---|---|
| `plan --max-length 12M` | calls, tokens and dollars for the full suite. No network, no key. |
| `run --dry-run ...` | same plan, plus whether it would exceed the caps. |
| `run` | everything: shows the plan, needs a typed `RUN`, refuses if over `--max-dollars` (20) or `--max-tokens` (250M). |
| `canary`, `decoy` | measurements 1 and 2 (same calls: one haystack answers both). |
| `order` | measurement 3 (1 seed by default, `--aux-seeds N`). |
| `needles`, `hop` | measurement 5 (k = 1, 5, 20; one 2-hop pair). |
| `cost DIR`, `report DIR` | re-render measurement 4 / everything from a run directory. |

Common flags: `--lengths 50k,500k,12M`, `--max-length`, `--seeds 1,2,3`, `--mode synthetic|text --text-path DIR`,
`--price 0.09` (dollars per million input tokens), `--workers 2`, `--out DIR` (an existing DIR is resumed, finished calls are
not re-sent; every call is appended to `calls.jsonl` as it completes), `--url`, `--model`, `--backend snap|chat`.
Start small: `run --lengths 50k,500k --seeds 1,2,3` before anything at 12M.

## What is measured

1. **Canary recall** by length x position (0/25/50/75/100%). Each call plants 5 unique canaries, one per position, each its
   own question; 3 seeds. Positions are also measured on the final text (`mean_actual_position` in the JSON).
2. **False alarms**: always-false decoys (a fresh sentence never planted) and hard distractors (a planted canary with one
   detail changed: id, adjective or noun). Same call as 1.
3. **Order sensitivity**: the base call re-asked with question order shuffled, and with haystack record order shuffled
   (all records, canaries included, so canary positions change). Flip = answer changed. Snap: `|p1-p2| > 0.5` crossing the
   threshold, plus mean `|dp|`. Chat: the normalised answer text changed (no `|dp|`).
4. **Cost and latency**: billed input tokens (`usage`), seconds per call, requests, dollars at `--price`, observed
   chars/token. Estimates use the conservative prose ratio from `checksnap/snap/calibrate.py` (3.0 chars/token), so a
   haystack labelled N tokens is at most about N tokens; real billing will differ (compare "estimated" vs "billed").
5. **Multi-needle** (k = 1, 5, 20 facts in one call, positions spread) and **two-hop** (fact A names a courier for a project
   early, fact B gives that courier's badge colour late, plus 3 decoy couriers so a colour guess is not enough).

Honesty rules: n per cell and Wilson 95% intervals everywhere (3 seeds x 1 canary per position gives n = 3: wide
intervals, by design visible); seeds recorded in `meta.json`/`results.json`; recall counts every call; a call whose canary
was missed is INVALID for decoy/order statistics and both "all" and "valid-only" figures are shown; errored calls
(too large, rate-limited out) are counted, never dropped silently; nothing is retried behind your back beyond
429/503/network backoff (`--max-retries`, via checksnap's client logic). Caps are enforced on actual billed tokens plus
in-flight estimates; a capped run stops cleanly with partial, resumable results (exit code 3).

Haystack text: `synthetic` is a seeded generator of plausible filler (deterministic per seed and length). `text` takes
public `.txt/.md/.rst` files under `--text-path` (paragraphs, cycled if the corpus is shorter than the context; the reuse
factor is recorded per call, treat heavily repeated text as a weaker test). Neither mode is a real-world-document
distribution; the model may have seen public text in training.

## Backends

**snap** (default): `SnapClient`, yes/no probability per question, threshold `--threshold 0.5`. The `[[needle]]` markers
in questions are the FakeSnapServer convention checksnap already uses; a real model just sees them as text.

**chat**: any text-generation endpoint. The haystack and the questions go in one prompt (or `questions_per_request: 1` for
one request per question, which bills the whole haystack each time: the plan shows the multiplier). The model is told to
answer one numbered line per question with the exact token, or `NOT FOUND`. Scoring is exact match after trimming
whitespace, wrapping quotes/backticks/asterisks and one trailing period (case kept):

- canary: "In the sentence that starts with '...', what is the code?" must return the exact code token;
- decoys and hard distractors: the quoted sentence start is not in the text; correct answer is `NOT FOUND`, any other
  answer is a false alarm;
- needles/hop: exact value; the false 2-hop asks about a project with no courier (`NOT FOUND`);
- unparsable replies count as misses and are tallied as "unparsed answers" in the cost table.

Fill in these fields when access arrives (JSON file via `--chat-config FILE`; `url` and `model` can instead come from
`SUBQ_API_URL` / `SUBQ_MODEL` or `--url` / `--model`, which win in that order; the key only from `SUBQ_API_KEY`):

```json
{
  "url": "https://.../v1/chat/completions",
  "model": "<12M model name>",
  "mode": "openai",
  "auth_header": "Authorization", "auth_scheme": "Bearer ",
  "extra_headers": {},
  "response_text_path": "choices.0.message.content",
  "input_tokens_path": "usage.prompt_tokens",
  "output_tokens_path": "usage.completion_tokens",
  "max_output_tokens": 0, "questions_per_request": 0, "temperature": 0.0,
  "timeout": 1800, "max_retries": 6
}
```

`"mode": "openai"` sends `{model, temperature, max_tokens, messages: [system, user]}`. For any other shape use
`"mode": "custom"` with a `request_template` JSON in which the strings `$MODEL`, `$SYSTEM`, `$PROMPT`, `$MAX_TOKENS` are
substituted (a string that is exactly a placeholder keeps its type), and set the three `*_path` fields (dotted, list
indices as numbers). Raw key header: `"auth_header": "x-api-key", "auth_scheme": ""`. If usage is missing from responses the
harness estimates tokens (so caps still bite) and flags `usage_estimated_calls`. A config file containing `api_key` is
rejected. Statuses: 401/403 stop the run, 402 stops it, 429/503 back off and retry, 400/413/422 are recorded as "too large"
for that call and the run continues.

## Files

`haystack.py` (generators, planted facts, questions in both forms), `core.py` (config, call plan, cost estimate),
`backends.py` (snap + chat clients, config, scoring), `runner.py` (workers, caps, JSONL), `report.py` (measurements, Wilson,
markdown), `fake_chat.py` (offline chat server with an oracle model). Tests: `tests/test_longctx_*.py`.
Results go to `benchmarks/longctx/results/run-<UTC>/` (`meta.json`, `calls.jsonl`, `results.json`, `results.md`); decide
yourself whether to commit them.

## Untested until the real model exists

Real chat wire format, whether the model follows the `N: answer` format and obeys `NOT FOUND`, real chars/token and
billing (including whether input tokens are reported), latency and timeouts at millions of tokens, request size limits,
rate limits, how it behaves on the exact-sentence question form, and any prompt-caching effects.
