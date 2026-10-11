# Claude plugin

Repo root is the plugin root: `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `mcp_server.py`, `skills/bugscan/SKILL.md`.
Install: `/plugin marketplace add Aras-sh/checksnap`, then `/plugin install checksnap@checksnap`. Needs `python3` on PATH.
The server imports `checksnap` straight from the plugin root (`${CLAUDE_PLUGIN_ROOT}`), so no pip install is needed for local checks.

| Tool | Does | Cost |
|---|---|---|
| `checksnap_list` | checks and what they cover | free |
| `checksnap_scan(path, checks="auto", use_snap=false, top=15, min_severity="medium")` | digest: counts, then `SEV RULE path:line title [xN]` per rule+file | free, <=3000 chars |
| `checksnap_detail(rule_id, path?, index?)` | one finding of the last scan: <=12 snippet lines, fix hint | free, no rescan |
| `checksnap_estimate(path, checks)` | bytes, calls, tokens Snap would use | free |

Defaults: `auto` picks checks from the tree (Dockerfile -> docker, workflows -> ci, `.sql` -> sql, requirements/pyproject -> dependencies,
`.py` -> optimization+security+reproducibility, `.html` -> web, yaml/json/toml/`.env*` -> config, always repo). `dataset`, `training-log`
and `bank` run only when named. Each check has a 60 s limit (`time_limit`); a slower one is skipped with a note.

Snap: `use_snap=true` is refused unless `confirm_upload=true`; the refusal lists the bytes and `api.subq.ai`. The key comes from the
plugin option `subq_api_key` (env `SUBQ_API_KEY`); the server never reads `.env` files. Without httpx the local checks still run.
