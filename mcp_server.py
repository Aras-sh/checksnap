"""Token-lean MCP server for checksnap (stdlib only, stdio JSON-RPC, one JSON message per line).

Local checks run in-process and cost nothing; every tool result is a compact digest capped at CAP characters.
Snap (uploads to api.subq.ai) only runs when the caller passes confirm_upload=true. Stdout is the MCP channel:
anything a check prints is routed to stderr.
"""
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent)
sys.path.insert(0, str(ROOT))
OUT = sys.stdout
sys.stdout = sys.stderr

CAP = 3000
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3}
SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".checksnap-cache", "build", "dist", ".tox", ".mypy_cache"}
EXPLICIT = {"dataset", "training-log", "bank"}         # never picked by "auto"
CACHE: dict = {}                                       # resolved path -> {"findings": [...], "root": str}
LAST: list = []                                        # [resolved path] of the most recent scan
DATA = Path(os.environ.get("CLAUDE_PLUGIN_DATA") or Path(tempfile.gettempdir()) / "checksnap-plugin")


# ---- checksnap glue -------------------------------------------------------------------------------------------------
def _checks():
    from checksnap.core import all_checks
    return {c.flag[len("--check-"):]: c for c in all_checks()}


def _auto(root: Path) -> list:
    """Pick checks by looking at the tree (names only, no file is read)."""
    found = {"repo"}
    entries = []
    if root.is_file():
        entries.append((root.parent.name, [], [root.name]))
    else:
        n = 0
        for dp, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP]
            entries.append((Path(dp).as_posix(), dirs, names))
            n += len(names)
            if n > 20000:
                break
    for dp, _, names in entries:
        if dp.endswith(".github/workflows"):
            found.add("ci")
        for nm in names:
            low, ext = nm.lower(), Path(nm).suffix.lower()
            if low.startswith("dockerfile") or low.startswith("docker-compose") or ext == ".dockerfile":
                found.add("docker")
            if low == ".gitlab-ci.yml":
                found.add("ci")
            if ext == ".sql":
                found.add("sql")
            if low.startswith("requirements") or low in ("pyproject.toml", "pipfile", "setup.py", "setup.cfg"):
                found.add("dependencies")
            if ext == ".py":
                found |= {"optimization", "security", "reproducibility"}
            if ext in (".html", ".htm"):
                found.add("web")
            if low.startswith(".env") or ext in (".yml", ".yaml", ".json", ".toml"):
                found.add("config")
    return sorted(found)


def _resolve(path) -> Path:
    p = Path(str(path)).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    if not p.exists():
        raise ValueError(f"path not found: {p}")
    return p.resolve()


def _select(root: Path, checks) -> tuple:
    avail = _checks()
    names = _auto(root) if checks in (None, "", "auto", ["auto"]) else (
        [checks] if isinstance(checks, str) else list(checks))
    by_name = {c.name: k for k, c in avail.items()}
    out, bad = [], []
    for n in names:
        k = by_name.get(n, n.removeprefix("check-").removeprefix("--check-"))
        (out if k in avail else bad).append(k if k in avail else n)
    if bad:
        raise ValueError(f"unknown check(s): {', '.join(bad)}; see checksnap_list")
    return list(dict.fromkeys(out)), avail


def _engine(key, cache):
    """Snap engine; construction does no network. Returns (engine, note)."""
    try:
        from checksnap.snap import SnapClient, SnapEngine
        return SnapEngine(SnapClient(api_key=key), cache_dir=cache), ""
    except Exception as exc:  # noqa: BLE001  (httpx missing, no key, ...)
        return None, f"Snap unavailable ({type(exc).__name__})"


def _args_for(names, avail, root: Path, snap: bool):
    from checksnap.cli import build_parser
    args = build_parser(list(avail.values())).parse_args([])
    for n in names:
        setattr(args, avail[n].flag[2:].replace("-", "_"), str(root))
    args.no_snap, args.static_only = not snap, not snap
    return args


def _ctx(snap_engine, budget=None):
    from checksnap.core import Context
    return Context(no_snap=snap_engine is None, snap=snap_engine, budget_tokens=budget, cache_dir=DATA / "cache")


def _run_check(check, ctx, args, limit):
    """Run one check in a daemon thread; (result, note). A check over `limit` seconds is abandoned."""
    from checksnap.core import CheckResult, invalidate_on_missed_canary
    box = []

    def work():
        try:
            res = check.run(ctx, args)
            invalidate_on_missed_canary(res)
            box.append(res)
        except Exception as exc:  # noqa: BLE001
            box.append(CheckResult(check=check.name, error=f"{type(exc).__name__}: {exc}"))
    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(limit)
    if box:
        return box[0], ""
    return None, f"{check.name} skipped: over {limit:g}s"


# ---- digest -----------------------------------------------------------------------------------------------------------
def _where(f) -> tuple:
    for ev in f.evidence:
        if ev.file:
            return ev.file, ev.line_start or 0
    return "-", 0


def _rank(findings):
    return sorted(findings, key=lambda f: (-int(f.severity), -(f.score or 0), f.rule_id, _where(f)))


def _clip(s, n):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def digest(root, findings, notes, top, min_sev, names):
    counts = {k: sum(1 for f in findings if f.severity.name.lower() == k) for k in ("high", "medium", "low", "info")}
    groups: dict = {}
    for f in _rank(findings):
        if int(f.severity) < SEV[min_sev]:
            continue
        file, line = _where(f)
        g = groups.setdefault((f.rule_id, file), [f, line, 0])
        g[2] += 1
    head = [f"checksnap {root}: " + ", ".join(f"{counts[k]} {k}" for k in counts) +
            f" | checks: {','.join(names)} | min={min_sev}"]
    foot = ["Next: checksnap_detail(rule_id[, path, index]) for evidence + fix; do not re-read the repo."]
    notes_l = [_clip("note: " + n, 160) for n in notes[:4]]
    body, room = [], CAP - sum(len(x) + 1 for x in head + foot + notes_l) - 40
    shown = 0
    for f, line, n in list(groups.values())[:top]:
        file = _where(f)[0]
        row = f"{f.severity.name} {f.rule_id} {file}{':' + str(line) if line else ''} {_clip(f.title, 80)}" + (f" x{n}" if n > 1 else "")
        if len(row) + 1 > room:
            break
        body.append(row)
        room -= len(row) + 1
        shown += 1
    more = len(groups) - shown
    if more > 0:
        body.append(f"(+{more} more groups; raise top or min_severity)")
    if not groups:
        body.append("no findings at this severity")
    return "\n".join(head + body + notes_l + foot)[:CAP]


# ---- tools ------------------------------------------------------------------------------------------------------------
def t_list(a):
    rows = [f"{k:<16}{'snap' if c.uses_snap else 'local':<6}{_clip(c.summary, 70)}" for k, c in sorted(_checks().items())]
    return _cap("auto picks by file types; dataset/training-log/bank only when named.\n" + "\n".join(rows))


def _cap(s):
    return s if len(s) <= CAP else s[: CAP - 1] + "…"


def _key():
    return os.environ.get("SUBQ_API_KEY") or None      # env only; this server never reads .env files


def t_scan(a):
    root = _resolve(a.get("path", "."))
    min_sev = str(a.get("min_severity", "medium")).lower()
    if min_sev not in SEV:
        raise ValueError("min_severity must be info|low|medium|high")
    names, avail = _select(root, a.get("checks", "auto"))
    top, limit = max(1, int(a.get("top", 15))), float(a.get("time_limit", 60))
    notes, snap = [], bool(a.get("use_snap"))
    engine = None
    if snap:
        args = _args_for(names, avail, root, True)
        key = _key()
        est = _estimate_rows(names, avail, args, key)
        if not a.get("confirm_upload"):
            return _cap("REFUSED: use_snap=true needs confirm_upload=true, which only the user may approve. "
                        "Ask them first. If approved, this uploads the files below to api.subq.ai.\n" + _fmt_est(est) +
                        ("" if key else "\nNo SUBQ_API_KEY is set, so Snap would be skipped."))
        if not key:
            notes.append("Snap skipped: SUBQ_API_KEY not set")
            snap = False
        else:
            engine, note = _engine(key, DATA / "cache")
            if note:
                notes.append(note)
                snap = False
    args = _args_for(names, avail, root, snap and engine is not None)
    ctx = _ctx(engine if snap else None, int(a.get("budget_tokens", 1_000_000)))
    findings = []
    for n in names:
        res, note = _run_check(avail[n], ctx, args, limit)
        if res is None:
            notes.append(note)
            continue
        if res.error:
            notes.append(f"{n} error: {res.error}")
        notes += [f"{n}: {x}" for x in res.notes if "skipped" in x and "static" not in x]
        findings += res.findings
    key = str(root)
    CACHE[key] = {"findings": _rank(findings), "root": key}
    LAST[:] = [key]
    return digest(root, findings, notes, top, min_sev, names)


def _estimate_rows(names, avail, args, key):
    from checksnap.core import CostEstimate
    engine, _ = _engine(key or "estimate-only", DATA / "cache")      # placeholder key: construction does no network
    ctx = _ctx(engine)
    rows = []
    for n in names:
        if avail[n].uses_snap:
            try:
                rows.append((n, avail[n].estimate(ctx, args)))
            except Exception as exc:  # noqa: BLE001
                rows.append((n, CostEstimate(notes=f"estimate failed: {type(exc).__name__}")))
    return rows


def _fmt_est(rows):
    if not rows:
        return "Nothing would be uploaded (no Snap-capable check selected)."
    from checksnap.privacy import estimate_table
    return estimate_table(rows)


def t_estimate(a):
    root = _resolve(a.get("path", "."))
    c = a.get("checks")
    if c in (None, "", "auto", ["auto"]):
        c = ["optimization"]
    names, avail = _select(root, c)
    args = _args_for(names, avail, root, True)
    return _cap("Free estimate, nothing sent.\n" + _fmt_est(_estimate_rows(names, avail, args, _key())))


def t_detail(a):
    rule = str(a.get("rule_id", "")).upper()
    if not LAST:
        raise ValueError("no scan yet; call checksnap_scan first")
    fl = [f for f in CACHE[LAST[0]]["findings"] if f.rule_id.upper() == rule and (not a.get("path") or a["path"] in _where(f)[0])]
    if not fl:
        raise ValueError(f"no finding {rule}" + (f" in {a['path']}" if a.get("path") else "") + " in the last scan")
    i = int(a.get("index", 0))
    if not 0 <= i < len(fl):
        raise ValueError(f"index out of range 0..{len(fl) - 1}")
    f = fl[i]
    file, line = _where(f)
    out = [f"{f.severity.name} {f.rule_id} {file}{':' + str(line) if line else ''}  [{i + 1} of {len(fl)}]", _clip(f.title, 160)]
    if f.detail:
        out.append(_clip(f.detail, 300))
    snippet = next((e.snippet for e in f.evidence if e.snippet), "")
    out += [_clip(s, 140) for s in snippet.strip().splitlines()[:12]]
    hint = f.fix_hint
    if not hint:
        from checksnap.cli import _rule_catalog
        from checksnap.core import all_checks
        r = _rule_catalog(all_checks()).get(rule)
        hint = getattr(r, "fix_hint", "")
    if hint:
        out.append("fix: " + _clip(hint, 300))
    if len(fl) > 1:
        out.append("others: " + ", ".join(f"[{j}] {_where(g)[0]}:{_where(g)[1]}" for j, g in enumerate(fl) if j != i)[:400])
    return _cap("\n".join(out))


PATH = {"path": {"type": "string", "description": "Absolute path of the project (or one file). Optional: defaults to the current directory."}}
TOOLS = {
    "checksnap_list": (t_list, "List checksnap checks and what they cover, one line each. Free.",
                       {"type": "object", "properties": {}}),
    "checksnap_scan": (t_scan,
        "Run checksnap's local checks (free, nothing uploaded) and return a compact digest: counts plus the top findings, "
        "one line each. Call this FIRST instead of reading or grepping the repo. use_snap=true (only the dataset check uses Snap; "
        "the bank and the Snap optimization layer are never run from here) uploads file contents to api.subq.ai and is refused unless confirm_upload=true; NEVER set confirm_upload without asking the user first.",
        {"type": "object", "properties": {
            **PATH, "checks": {"description": "'auto' (default) or a list such as ['security','docker'].",
                               "anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
            "use_snap": {"type": "boolean", "default": False},
            "confirm_upload": {"type": "boolean", "default": False, "description": "Only after the user agreed to the upload."},
            "top": {"type": "integer", "default": 15}, "min_severity": {"type": "string", "default": "medium"},
            "time_limit": {"type": "number", "default": 60, "description": "Seconds per check."}}}),
    "checksnap_detail": (t_detail,
        "One finding from the last scan, with evidence snippet (max 12 lines) and fix hint. No rescan.",
        {"type": "object", "required": ["rule_id"], "properties": {
            "rule_id": {"type": "string"}, "path": {"type": "string", "description": "File path (substring) to narrow."},
            "index": {"type": "integer", "default": 0, "description": "0-based among matches."}}}),
    "checksnap_estimate": (t_estimate,
        "Free table of what the Snap parts would upload and cost (bytes, calls, tokens). Nothing is sent.",
        {"type": "object", "properties": {**PATH, "checks": {
            "anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]}}}),
}


def call(name, a):
    if name not in TOOLS:
        return {"content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}
    try:
        return {"content": [{"type": "text", "text": TOOLS[name][0](a or {})}]}
    except Exception as exc:  # noqa: BLE001
        return {"content": [{"type": "text", "text": _cap(f"error: {type(exc).__name__}: {exc}")}], "isError": True}


def handle(m):
    mid, method = m.get("id"), m.get("method")
    if mid is None:
        return None                                   # notification
    if method == "initialize":
        res = {"protocolVersion": (m.get("params") or {}).get("protocolVersion", "2024-11-05"),
               "capabilities": {"tools": {}}, "serverInfo": {"name": "checksnap", "version": "0.1.0"}}
    elif method == "ping":
        res = {}
    elif method == "tools/list":
        res = {"tools": [{"name": k, "description": d, "inputSchema": s} for k, (_, d, s) in TOOLS.items()]}
    elif method == "tools/call":
        p = m.get("params") or {}
        res = call(p.get("name"), p.get("arguments"))
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": res}


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            out = handle(json.loads(line))
        except json.JSONDecodeError:
            out = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        if out is not None:
            OUT.write(json.dumps(out) + "\n")
            OUT.flush()


if __name__ == "__main__":
    main()
