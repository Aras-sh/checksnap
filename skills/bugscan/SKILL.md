---
name: bugscan
description: Find and fix bugs in a project cheaply with checksnap. Use when the user asks to find bugs, audit, lint, review security, check Docker/CI/SQL/config/dependencies, or "scan" a repo.
---

# Bug scan (token-lean)

Use the `checksnap` MCP tools. They run locally and return short digests, so never read or grep the whole repo yourself.

1. **Scan first.** Call `checksnap_scan(path=<absolute project path>)`. Default `checks="auto"` picks checks from the file types.
   Name checks explicitly (see `checksnap_list`) only if the user asks for a specific area. `dataset`, `training-log` and `bank` run only when named; `bank` is experimental (0/12 real findings measured), avoid it.
2. **Triage the digest.** Each line is `SEV RULE path:line title`, `xN` means N repeats in that file. Work from the top (HIGH first).
   Ignore low-value lines; the digest is candidates, not proof.
3. **Detail only what you will act on.** Call `checksnap_detail(rule_id, path?, index?)` for those findings. It does not rescan.
4. **Verify before changing anything.** Read just the lines around `path:line` (use a small line range). Real bug: fix it, smallest change.
   False positive: say so in one line and move on.
5. **Report.** Per finding: fixed, false positive, or needs the user. Keep it short.

## Budget rules

- Do NOT use Snap (`use_snap=true`) without asking the user. It uploads file contents to api.subq.ai and costs tokens.
- Before asking, call `checksnap_estimate` and show the user the table (bytes, calls, tokens).
- Set `confirm_upload=true` only after the user agrees in this conversation. Without it the scan refuses.
- Do not raise `top` or lower `min_severity` unless the digest says there are more and you need them.
- Do not call `checksnap_scan` again to "see more"; use `checksnap_detail`. Rescan only after you changed files.
- A missing SubQ key is fine: local checks need none.
