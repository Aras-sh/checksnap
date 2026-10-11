# checksnap inside Claude Code (showcase)

`claude-code.gif` / `.mp4` (~56 s): hook card, install card (labelled card, not run live because it edits your config),
a real interactive Claude Code v2.1.296 session (haiku) scanning a copy of `../demo_project` and fixing the worst bug, numbers card.
Regenerate: `python3 make_cc.py && vhs claude-code.tape` (the tape copies the demo into /tmp/shop so no home path shows).

Hidden in the tape: an alias adding `--setting-sources project --permission-mode acceptEdits --allowedTools <checksnap tools>`,
and one trust-dialog accept for the temp folder before recording. Edit approvals are pressed with Enter on screen.

## Measured (`measure.sh`, raw JSON in `raw/`, `claude -p --output-format json --model haiku`, one run each)

| project | mode | cost | turns | time | input | output | cache write | cache read |
|---|---|---|---|---|---|---|---|---|
| demo_project (4 files) | plugin | $0.0037 | 8 | 9.6s | 8 | 1,729 | 10,552 | 75,748 |
| demo_project (4 files) | plain | $0.0039 | 10 | 16.8s | 14 | 2,940 | 4,309 | 152,604 |
| psf/requests (depth 1) | plugin | $0.0056 | 13 | 18.3s | 14 | 3,115 | 12,580 | 148,658 |
| psf/requests (depth 1) | plain | $0.0280 | 23 | 77.3s | 36 | 15,707 | 58,732 | 839,834 |

Honest reading: on the tiny project the saving is negligible; on requests the plugin run costs about a fifth. n=1 per cell, so
expect noise. Prompts: plugin = "Use the checksnap plugin to scan $PWD for bugs and list the top 5." (absolute path needed: the
tool requires `path`, and without it the model once scanned the wrong tree); plain = "Find the top 5 bugs in this project by reading the files."
(Read/Glob/Grep/ls/cat only). Quality differs: plain on requests reports it found only 1-2 real defects; plugin lists scanner findings, some in test certs.
