"""Snap layer: cross-file inefficiencies that `ast` cannot see.

Source files are packed into windows with `### FILE: <relpath>` headers (file boundaries respected, big files split into
parts) so a window range maps back to files. Flagged questions are localized (bisected) to a ~2 KB snippet, then to a file
and, via static findings or lexical hints, to a line. Everything is a candidate; scores and windows are in the evidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Sequence

from checksnap.core import Evidence, Finding, Severity

from .rules import RuleInfo

L, M, H = Severity.LOW, Severity.MEDIUM, Severity.HIGH

# (title, severity, what to look for, why it hurts + fix, lexical line hints)
_BANK: list[tuple[str, Severity, str, str, str]] = [
    ("Same expensive computation repeated across modules", M,
     "the same expensive computation (parsing, feature extraction, model forward pass, big aggregation) is performed independently in several functions or modules instead of once and shared",
     "Redundant work multiplies runtime. Compute once and pass the result, or memoize.", ""),
    ("Per-item network call hidden behind helper functions", H,
     "a function that makes an HTTP/RPC call is itself called once per item inside a loop elsewhere (N+1 requests hidden behind a function boundary)",
     "Latency is paid per item. Batch the requests, use bulk endpoints, or run them concurrently.", r"requests\.|httpx\.|urlopen|aiohttp|\.fetch\("),
    ("Per-item database query hidden behind helper functions", H,
     "a function that runs a database query is called once per item in a loop elsewhere (N+1 queries hidden behind a function boundary)",
     "One round trip per row. Fetch in bulk with IN/JOIN or prefetch relations.", r"\.execute\(|\.query\(|SELECT\s|\.filter\("),
    ("Missing caching where inputs repeat", M,
     "a pure or slow function is called repeatedly with the same arguments (e.g. lookups, parsing, remote fetches) and its results are not cached",
     "Repeated identical work. Add functools.lru_cache (on functions, not methods) or a small dict cache.", ""),
    ("Unbatched per-item model inference", H,
     "a machine-learning model, embedding or LLM is called on one item at a time inside a loop where batching the inputs would be possible",
     "Per-item inference wastes accelerator throughput. Batch inputs.", r"model\(|\.predict\(|\.infer|\.generate\(|\.encode\(|\.embed"),
    ("Synchronous I/O on a hot path", M,
     "request handlers, event loops or per-item processing functions perform blocking file, network or subprocess I/O synchronously",
     "Blocking I/O serializes the hot path. Use async I/O, a thread pool, or move it off the hot path.", r"open\(|requests\.|time\.sleep|subprocess"),
    ("Unnecessary data copies", L,
     "large data structures (lists, arrays, dataframes, bytes) are copied, deep-copied or converted back and forth where a view or in-place operation would do",
     "Copies cost time and memory. Use views, in-place ops, memoryview or iterate lazily.", r"deepcopy|\.copy\(\)|np\.array\(|\.tobytes\("),
    ("Unbounded growth of in-memory structures", M,
     "module-level or long-lived lists, dicts or caches grow with every request or item and are never evicted, trimmed or bounded",
     "Memory grows until the process dies. Bound with LRU/maxlen/TTL.", r"\.append\(|cache\[|_cache"),
    ("Polling loop without backoff", M,
     "a loop repeatedly polls a resource (file, endpoint, queue, flag) with no sleep, no backoff, or a very short fixed sleep",
     "Busy polling burns CPU and load. Use events/conditions, blocking reads, or exponential backoff.", r"while True|while not|\.sleep\("),
    ("Configuration re-read on every call", M,
     "a configuration file, environment, or settings object is read and parsed inside a function that is called frequently instead of once at startup",
     "Repeated I/O and parsing of constant data. Load once and pass or cache it.", r"os\.environ|getenv|json\.load|yaml\.|toml|configparser|open\("),
    ("Whole file or table loaded when streaming would do", M,
     "an entire large file, query result or dataset is read into memory at once (read(), readlines(), fetchall(), read_csv) only to be processed item by item",
     "Peak memory scales with input size. Stream or chunk.", r"\.read\(\)|readlines\(|read_csv|json\.load\(|\.fetchall\("),
    ("Quadratic string or list rebuilding across calls", L,
     "large strings or lists are repeatedly rebuilt by concatenation or copying, e.g. accumulated across recursive or repeated function calls",
     "Each rebuild copies everything so far. Use join, extend, or generators.", r"\+=|\+ \["),
    ("Expensive object recreated per call", H,
     "expensive objects (HTTP sessions, database connections, clients, compiled regexes, loaded models, tokenizers) are created inside functions called many times rather than once and reused",
     "Setup cost is paid on every call. Create once (module level or injected) and reuse.", r"Session\(|Client\(|connect\(|re\.compile|load_model|from_pretrained|create_engine|Tokenizer"),
    ("In-process serialization round trips", L,
     "data is serialized and immediately deserialized inside the same process (json.dumps then loads, pickle round trips) for copying or passing between functions",
     "Pure overhead. Pass the object directly.", r"json\.dumps|pickle\.|\.loads\("),
    ("Sequential independent I/O that could be concurrent", M,
     "several independent network or disk operations are awaited or executed one after another in sequence when they could run concurrently",
     "Total time is the sum instead of the max. Use asyncio.gather, a thread pool, or batch calls.", r"await |requests\.|\.get\("),
    ("Unbounded query or listing without pagination", M,
     "queries or API listings fetch every row or object (no LIMIT, no pagination, .all()) before filtering in Python",
     "Transfers and holds more than needed. Filter and paginate server-side.", r"SELECT|\.all\(\)|fetchall|list_objects|\.find\("),
    ("Quadratic algorithm spread across helpers", M,
     "a helper that scans a whole collection linearly (search, membership, count, index) is called inside a loop over a similarly sized collection, making the algorithm quadratic",
     "O(n*m) hidden by function boundaries. Index with a dict/set first.", r"\.index\(|\.count\(| in \["),
    ("Expensive logging or printing in hot loops", L,
     "logging, printing or debug formatting happens inside tight per-item loops, with arguments formatted eagerly even when the level is disabled",
     "I/O and string formatting dominate. Use lazy %-style logging args, log every N items.", r"logging\.|logger\.|print\("),
    ("Coarse locking around slow work", M,
     "a global or coarse lock is held while doing slow work (I/O, model calls, computation), serializing otherwise parallel threads",
     "Contention removes parallelism. Narrow the critical section.", r"Lock\(|\.acquire\(|with \w*lock"),
    ("Unbuffered or tiny reads and writes", L,
     "files are read or written in tiny pieces (byte by byte, line by line with flush on every write, unbuffered mode)",
     "Syscall overhead dominates. Use buffered I/O and larger chunks.", r"\.flush\(|\.read\(1\)|buffering=0"),
    ("Preprocessing repeated every epoch or request", M,
     "deterministic preprocessing (tokenization, decoding, resizing, feature extraction) is recomputed on every epoch or request instead of being cached or precomputed",
     "Same work repeated. Cache preprocessed data to disk or memory.", r"tokenize|transform|augment|preprocess"),
    ("Heavy work inside the training step", M,
     "file decoding, tokenization, image loading or other CPU preprocessing is done synchronously in the main training/inference process instead of in data-loader workers",
     "The accelerator idles while the CPU prepares data. Move it into dataset workers or precompute.", r"tokenizer\(|\.encode\(|cv2\.imread|Image\.open"),
    ("Retries without backoff or limit", L,
     "retry loops re-attempt failing operations immediately, forever, or without jitter",
     "Retry storms amplify outages. Cap attempts and use exponential backoff with jitter.", r"retry|while True|continue"),
    ("Heavy imports or model loads at call time", M,
     "heavy modules are imported or models are loaded inside functions that run repeatedly",
     "Import and load cost on every call. Import at module level, load once.", r"^\s+import |^\s+from \w+ import |load_model|from_pretrained"),
    ("List used for hot lookups", M,
     "lists or arrays are used for frequent membership or key lookups where a set or dict would be much faster",
     "Linear scans per lookup. Use set/dict.", r" in \[|\.index\("),
    ("Row-wise dataframe work hidden behind helpers", M,
     "helper functions apply row-by-row pandas operations (apply, iterrows, per-row loc/iloc) that are called on whole dataframes",
     "Per-row Python overhead. Vectorize.", r"\.apply\(|iterrows|itertuples|\.iloc\[|\.loc\["),
    ("Repeated full sort or scan for min/max/top-k", L,
     "collections are fully sorted or scanned repeatedly just to get the minimum, maximum or top-k items",
     "O(n log n) per query. Use heapq/min/max or keep a sorted structure.", r"sorted\(|\.sort\(|max\(|min\("),
    ("Accumulating tensors with autograd history or unclosed resources", M,
     "values that keep references to large objects accumulate in lists (e.g. appending loss tensors with their graph, unclosed files, sessions or handles) so memory grows over time",
     "Memory leak. Append `.item()` / `.detach()` and close handles with `with`.", r"losses\.append|\.append\(loss|open\("),
    ("Temporary files written and re-read in the same process", L,
     "data is written to temporary files or disk caches and read back by the same process where it could stay in memory",
     "Disk round trip. Keep it in memory or use a pipe.", r"tempfile|NamedTemporary|\.tmp"),
    ("Blocking calls reachable from async code across modules", M,
     "async functions call helpers (in other modules) that block with synchronous I/O or sleep, stalling the event loop",
     "Blocks every concurrent task. Make the helper async or run it in a thread.", r"async def|time\.sleep|requests\."),
]


@dataclass(frozen=True)
class SnapRule:
    info: RuleInfo
    instruction: str
    hint: re.Pattern[str] | None


def _build() -> list[SnapRule]:
    out = []
    for i, (title, sev, look, why, hint) in enumerate(_BANK, 1):
        rid = f"OPT-SNAP-{i:03d}"
        out.append(SnapRule(
            RuleInfo(rid, sev, title, f"Snap question: is it true that {look}? {why}", why.split(". ")[-1] if ". " in why else why, needs_snap=True),
            "The text is a codebase; every file starts with a '### FILE: <path>' header. "
            f"Is the following inefficiency clearly present in at least one place in the code: {look}? "
            "Comments, docstrings and tests that merely mention it do not count.",
            re.compile(hint, re.M) if hint else None))
    return out


SNAP_RULES = _build()
SNAP_RULE_INFO: dict[str, RuleInfo] = {r.info.id: r.info for r in SNAP_RULES}
_TRUE = "At least one place in the code clearly has this inefficiency."
_FALSE = "No place in the code has this inefficiency, or it is only mentioned in comments or docstrings."
# snap rule -> static rule that detects the same thing at one line, used to pin a snippet to a line
STATIC_LINK = {"OPT-SNAP-003": "OPT-PY-008", "OPT-SNAP-012": "OPT-PY-001", "OPT-SNAP-017": "OPT-PY-003", "OPT-SNAP-025": "OPT-PY-003",
               "OPT-SNAP-026": "OPT-PY-009", "OPT-SNAP-027": "OPT-PY-006", "OPT-SNAP-030": "OPT-PY-007", "OPT-SNAP-006": "OPT-PY-007"}
MAX_LOCALIZE = 10         # bisecting costs calls; beyond this, report window-level evidence only
SEC = "### FILE: "


@dataclass
class Span:
    """A section of a window that holds (part of) one file."""
    start: int            # absolute offset of the header
    end: int
    rel: str
    first_line: int       # file line number of the section's first body line
    header_len: int
    window: int           # index into the window list


def questions(snap_mod: Any) -> list[Any]:
    return [snap_mod.Question(r.info.id, r.instruction, _TRUE, _FALSE) for r in SNAP_RULES]


def pack(files: Sequence[tuple[str, str]], size: int, snap_mod: Any) -> tuple[list[Any], list[Span]]:
    """Greedy-pack (relpath, text) into windows of <= size chars with file headers; offsets are cumulative."""
    sections: list[tuple[str, int, str, str]] = []      # rel, first_line, header, body
    for rel, text in files:
        if not text.strip():
            continue
        room = max(1000, size - len(SEC) - len(rel) - 80)
        pos, line, parts = 0, 1, []
        while pos < len(text):
            end = min(len(text), pos + room)
            if end < len(text):
                nl = text.rfind("\n", pos, end)
                end = nl + 1 if nl > pos else end
            parts.append((line, text[pos:end]))
            line += text.count("\n", pos, end)
            pos = end
        for k, (ln, body) in enumerate(parts, 1):
            tag = f" (part {k}/{len(parts)}, starts at line {ln})" if len(parts) > 1 else ""
            sections.append((rel, ln, f"{SEC}{rel}{tag}\n", body if body.endswith("\n") else body + "\n"))
    windows: list[Any] = []
    spans: list[Span] = []
    cur: list[str] = []
    cur_spans: list[tuple[int, int, str, int, int]] = []
    base = 0
    cur_len = 0

    def flush() -> None:
        nonlocal base, cur, cur_spans, cur_len
        if not cur:
            return
        text = "".join(cur)
        for s, e, rel, ln, hl in cur_spans:
            spans.append(Span(base + s, base + e, rel, ln, hl, len(windows)))
        windows.append(snap_mod.Window(base, base + len(text), text))
        base += len(text)
        cur, cur_spans, cur_len = [], [], 0

    for rel, ln, header, body in sections:
        piece = header + body
        if cur_len + len(piece) > size:
            flush()
        cur_spans.append((cur_len, cur_len + len(piece), rel, ln, len(header)))
        cur.append(piece)
        cur_len += len(piece)
    flush()
    return windows, spans


def _line_at(span: Span, windows: Sequence[Any], off: int) -> int:
    w = windows[span.window]
    return span.first_line + w.text.count("\n", span.start - w.start + span.header_len, max(off - w.start, span.start - w.start + span.header_len))


def _text_of(windows: Sequence[Any], start: int, end: int, snap_mod: Any) -> Any | None:
    w = next((w for w in windows if w.start <= start < w.end), None)
    if w is None:
        return None
    end = min(end, w.end)
    return snap_mod.Window(start, end, w.text[start - w.start:end - w.start])


def _snippet_evidence(snip: Any, spans: Sequence[Span], windows: Sequence[Any], rule: SnapRule,
                      static_by_file: dict[str, list[Finding]], extra: dict[str, Any]) -> list[Evidence]:
    """File and line for a localized snippet. A snippet can straddle files: prefer the file where a static finding
    or a lexical hint lands inside it, else the first file."""
    pieces = []
    for sp in spans:
        a, b = max(sp.start + sp.header_len, snip.start), min(sp.end, snip.end)
        if a < b:
            w = windows[sp.window]
            piece = w.text[a - w.start:b - w.start]
            l0 = _line_at(sp, windows, a)
            pieces.append((sp, piece, l0, l0 + piece.count("\n")))
    link = STATIC_LINK.get(rule.info.id)
    for sp, piece, l0, l1 in pieces:                      # 1) lexical hint inside the snippet
        if rule.hint:
            for i, ln in enumerate(piece.splitlines()):
                if rule.hint.search(ln):
                    return [Evidence(sp.rel, l0 + i, l0 + i, piece[:400], {**extra, "localized": True, "line_from": "lexical hint"})]
    for sp, piece, l0, l1 in pieces:                      # 2) a related static finding inside the snippet
        hit = next((f for f in static_by_file.get(sp.rel, []) if f.rule_id == link and f.evidence
                    and l0 <= (f.evidence[0].line_start or 0) <= l1), None)
        if hit:
            e = hit.evidence[0]
            return [Evidence(sp.rel, e.line_start, e.line_end, piece[:400], {**extra, "localized": True, "line_from": f"static {hit.rule_id}"})]
    if pieces:                                            # 3) the snippet's own range
        sp, piece, l0, l1 = pieces[0]
        return [Evidence(sp.rel, l0, l1, piece[:400], {**extra, "localized": True, "line_from": "snippet range"})]
    return []


def interpret(res: Any, windows: Sequence[Any], spans: Sequence[Span], ctx: Any, snap_mod: Any,
              static_by_file: dict[str, list[Finding]], notes: list[str]) -> list[Finding]:
    """Turn a ScanResult into findings: threshold, localize the top hits, map to files/lines."""
    rules = {r.info.id: r for r in SNAP_RULES}
    flagged: list[tuple[float, str, tuple[int, int]]] = []
    for qid, qr in res.per_question.items():
        # one finding per question: its best window (a codebase-wide pattern rarely needs a finding per window)
        if qr.max_score >= ctx.threshold:
            flagged.append((qr.max_score, qid, qr.best_window))
    flagged.sort(key=lambda t: (-t[0], t[1]))
    out: list[Finding] = []
    qmap = {q.id: q for q in questions(snap_mod)}
    for rank, (score, qid, (ws, we)) in enumerate(flagged):
        rule = rules[qid]
        sev = rule.info.severity if score >= 0.8 else Severity(max(int(rule.info.severity) - 1, int(Severity.LOW)))
        evidence: list[Evidence] = []
        snippet_win = None
        if rank < MAX_LOCALIZE and ctx.snap is not None and hasattr(ctx.snap, "localize"):
            win = _text_of(windows, ws, we, snap_mod)
            try:
                snippet_win = ctx.snap.localize(win, qmap[qid]) if win else None
            except snap_mod.SnapError as e:
                notes.append(f"localize {qid} failed: {e}")
        extra = {"window": [ws, we], "score": round(score, 4)}
        if snippet_win is not None:
            evidence = _snippet_evidence(snippet_win, spans, windows, rule, static_by_file, extra)
        if not evidence:
            # window-level: list the files in the window, with lexical hint lines where we can find them
            w = next((w for w in windows if w.start <= ws < w.end), None)
            files = []
            for sp in spans:
                if ws <= sp.start < we and sp.rel not in files:
                    files.append(sp.rel)
            for sp in spans:
                if len(evidence) >= 5 or not (ws <= sp.start < we) or rule.hint is None or w is None:
                    continue
                body = w.text[sp.start - w.start + sp.header_len:sp.end - w.start]
                for i, ln in enumerate(body.splitlines()):
                    if rule.hint.search(ln):
                        evidence.append(Evidence(sp.rel, sp.first_line + i, sp.first_line + i, ln.strip()[:200], {**extra, "localized": False, "line_from": "lexical hint"}))
                        break
            if not evidence:
                evidence.append(Evidence(None, None, None, "", {**extra, "localized": False, "files_in_window": files[:20]}))
        out.append(Finding("optimization", qid, sev, rule.info.title,
                           f"Snap score {score:.2f} (candidate, not proof). {rule.info.explanation}",
                           evidence, score, "snap", rule.info.fix_hint))
    return out
