"""Bank engine: load and validate question items, pick the relevant ones, pack files, ask Snap, rank findings.

Items are plain dicts (see REQUIRED) so teams can add their own with --bank-file. A broken module or item is a note,
never a crash. Packing, localizing and line pinning reuse the optimization snap layer's helpers.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from checksnap.core import Evidence, Finding, Severity
from checksnap.checks.optimization import SKIP_DIRS
from checksnap.checks.optimization import snap_layer

REQUIRED = ("id", "category", "title", "severity", "applies_to", "question", "true", "false", "why", "fix", "hints")
KINDS = ("code", "text", "data", "config", "docs", "logs")
BUILTIN_MODULES = ("items_arch", "items_reliab", "items_sec", "items_data", "items_docs", "bank_extra_items")
PKG = "checksnap.checks.bank"
MAX_FILE_BYTES = 2_000_000
LOCAL_HITS_PER_ITEM = 3
MIN_ABSENCE_FILES = 10     # "nothing like X anywhere" claims are only meaningful when the scan sees enough of the project
BASELINE_MARGIN, BASELINE_MAX = 0.15, 0.5
BASELINE_DIR = Path(__file__).parent / "baseline"
MAX_LOCALIZE = 25          # each localize bisects with extra calls; beyond this, regex-hint / window-level attribution only
MAX_HINT_FILES = 3         # a regex hint matching more files than this says nothing about where the bug is
EXT_KINDS: dict[str, set[str]] = {}
for _k, _exts in {
    "code": ".py .js .ts .tsx .jsx .go .rs .java .c .cpp .h .rb .php .sh .cs .kt",
    "text": ".txt .md .rst",
    "docs": ".md .rst .txt",
    "data": ".csv .tsv .json .jsonl .ndjson",
    "config": ".toml .yaml .yml .ini .cfg .json .env .conf",
    "logs": ".log",
}.items():
    for _e in _exts.split():
        EXT_KINDS.setdefault(_e, set()).add(_k)


def validate(raw: Any, origin: str) -> tuple[dict | None, str | None]:
    """Return (clean item, None) or (None, schema error)."""
    if not isinstance(raw, dict):
        return None, f"{origin}: item is not an object"
    missing = [k for k in REQUIRED if k not in raw]
    if missing:
        return None, f"{origin}: item {raw.get('id', '?')!r} missing keys {missing}"
    if not all(isinstance(raw[k], str) and raw[k].strip() for k in ("id", "category", "title", "question", "true", "false")):
        return None, f"{origin}: item {raw['id']!r} needs non-empty string id/category/title/question/true/false"
    if raw["id"].startswith(("__decoy_", "__canary_")):
        return None, f"{origin}: item id {raw['id']!r} uses a reserved prefix"
    try:
        sev = Severity.parse(raw["severity"])
    except (KeyError, ValueError):
        return None, f"{origin}: item {raw['id']!r} has bad severity {raw['severity']!r}"
    ap = [raw["applies_to"]] if isinstance(raw["applies_to"], str) else raw["applies_to"]
    if not isinstance(ap, list) or not ap or any(a not in (*KINDS, "any") for a in ap):
        return None, f"{origin}: item {raw['id']!r} applies_to must be a list of {list(KINDS) + ['any']}"
    hints = raw["hints"]
    if isinstance(hints, str):
        hints = [hints]
    if not isinstance(hints, list) or any(not isinstance(h, str) for h in hints):
        return None, f"{origin}: item {raw['id']!r} hints must be a list of regex strings"
    absence = raw.get("absence", False)
    if not isinstance(absence, bool):
        return None, f"{origin}: item {raw['id']!r} absence must be true or false"
    title = f"[absence] {raw['title']}" if absence and "absence" not in raw["title"].lower() else raw["title"]
    return {**raw, "title": title, "severity": sev, "applies_to": ap, "hints": hints, "absence": absence}, None


def load_items(extra_file: str | None = None) -> tuple[list[dict], list[str]]:
    """Items from every bank module plus an optional JSON file, validated and deduped by id (first wins)."""
    notes: list[str] = []
    batches: list[tuple[str, Any]] = []
    pkg_dir = Path(__file__).parent
    names = list(BUILTIN_MODULES) + sorted(p.stem for p in pkg_dir.glob("items_*.py") if p.stem not in BUILTIN_MODULES)
    for name in names:
        if not (pkg_dir / f"{name}.py").exists():
            notes.append(f"bank module {name} not found; its items are missing")
            continue
        try:
            batches.append((name, importlib.import_module(f"{PKG}.{name}").ITEMS))
        except Exception as e:  # noqa: BLE001  (a broken writer's module must not take the check down)
            notes.append(f"bank module {name} failed to load: {type(e).__name__}: {e}")
    if extra_file:
        try:
            data = json.loads(Path(extra_file).read_text(encoding="utf-8"))
            batches.append((Path(extra_file).name, data["items"] if isinstance(data, dict) and "items" in data else data))
        except (OSError, ValueError, TypeError) as e:
            notes.append(f"--bank-file {extra_file}: {type(e).__name__}: {e}")
    items: list[dict] = []
    seen: set[str] = set()
    for origin, raw_items in batches:
        if not isinstance(raw_items, list):
            notes.append(f"{origin}: ITEMS is not a list")
            continue
        for raw in raw_items:
            item, err = validate(raw, origin)
            if err:
                notes.append(f"schema error, {err}")
            elif item["id"] in seen:
                notes.append(f"duplicate item id {item['id']} in {origin} ignored")
            else:
                seen.add(item["id"])
                items.append(item)
    return items, notes


class _AnyOf:
    """Several hint regexes, each keeping its own flags (a joined pattern would reject inline (?i))."""

    def __init__(self, pats: list[re.Pattern[str]]) -> None:
        self.pats = pats

    def search(self, text: str):
        return next((m for p in self.pats if (m := p.search(text))), None)


def compile_hints(items: list[dict], notes: list[str]) -> dict[str, list[re.Pattern[str]]]:
    out: dict[str, list[re.Pattern[str]]] = {}
    for it in items:
        pats = []
        for h in it["hints"]:
            try:
                pats.append(re.compile(h, re.M))
            except re.error as e:
                notes.append(f"item {it['id']}: bad hint regex {h!r} ignored ({e})")
        out[it["id"]] = pats
    return out


def select_items(items: list[dict], categories: set[str] | None, kinds: set[str] | None) -> list[dict]:
    """Items in the wanted categories whose applies_to meets `kinds` (None = no kind filter)."""
    return [it for it in items
            if (not categories or it["category"] in categories)
            and (kinds is None or "any" in it["applies_to"] or kinds & set(it["applies_to"]))]


def drop_absence(items: list[dict], n_files: int, include: bool) -> tuple[list[dict], int]:
    """Absence-style items need a broad scan: with fewer than MIN_ABSENCE_FILES files they are skipped unless asked for."""
    if include or n_files >= MIN_ABSENCE_FILES:
        return items, 0
    kept = [it for it in items if not it.get("absence")]
    return kept, len(items) - len(kept)


def cap_items(items: list[dict], n: int | None) -> list[dict]:
    """The n highest-severity items (stable: ties keep bank order); None or n >= len keeps all."""
    if not n or n >= len(items):
        return items
    keep = {id(it) for it in sorted(items, key=lambda it: -int(it["severity"]))[:n]}
    return [it for it in items if id(it) in keep]


def _baseline_state(items: list[dict], cache_dir: Path):
    files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted(BASELINE_DIR.glob("*.py"))]
    corpus = hashlib.sha256("".join(t for _, t in files).encode()).hexdigest()[:12]
    path = Path(cache_dir) / "bank_baseline.json"
    try:
        cache = json.loads(path.read_text())
    except (OSError, ValueError):
        cache = {}
    ver = lambda it: hashlib.sha256(f"{corpus}\0{it['question']}\0{it['true']}\0{it['false']}".encode()).hexdigest()[:16]  # noqa: E731
    todo = [it for it in items if cache.get(it["id"], {}).get("v") != ver(it)]
    return files, path, cache, ver, todo


def baseline_pending(items: list[dict], cache_dir: Path) -> tuple[int, int]:
    """(chars of baseline corpus, items not yet cached): what a baseline run would still cost. (0, 0) when fully cached."""
    files, _, _, _, todo = _baseline_state(items, cache_dir)
    return (sum(len(t) + len(rel) + 100 for rel, t in files), len(todo)) if todo else (0, 0)    # + '### FILE:' header per file


def baseline_scores(snap: Any, items: list[dict], cache_dir: Path, snap_mod: Any) -> tuple[dict[str, float], Any]:
    """Max score of each item over the bundled clean corpus. Asked once per item (and corpus/question version), then cached.

    Returns (scores, ScanResult or None when everything was cached). Raises the engine's SnapError on failure.
    """
    files, path, cache, ver, todo = _baseline_state(items, cache_dir)
    scan = None
    if todo and files:
        windows, _ = snap_layer.pack(files, 100_000, snap_mod)      # one packed window, same question batches as the real scan
        scan = snap.scan_windows(windows, questions(snap_mod, todo), label="bank-baseline")
        for it in todo:
            cache[it["id"]] = {"v": ver(it), "score": scan.per_question[it["id"]].max_score}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(cache))
        except OSError:
            pass            # cache is an optimization; the scores in hand are still used
    return {it["id"]: cache[it["id"]]["score"] for it in items if it["id"] in cache}, scan


def collect_files(root: Path, kinds: set[str] | None) -> tuple[list[tuple[str, str]], set[str], list[str]]:
    """(relpath, text) for known file types under root, the union of their kinds, and notes. kinds=None keeps all."""
    paths = [(root.name, root)] if root.is_file() else []
    if root.is_dir():
        for dirpath, dirs, names in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            paths += [(((p := Path(dirpath) / n).relative_to(root)).as_posix(), p) for n in sorted(names)]
    files, found, notes = [], set(), []
    for rel, p in paths:
        k = EXT_KINDS.get(p.suffix.lower())
        if not k or (kinds is not None and not kinds & k):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                notes.append(f"{rel} skipped: over {MAX_FILE_BYTES // 1_000_000} MB")
                continue
            files.append((rel, p.read_text(encoding="utf-8", errors="replace")))
            found |= k
        except OSError:
            continue
    return files, found, notes


def local_hints(files: list[tuple[str, str]], items: list[dict], hints: dict[str, list[re.Pattern[str]]]) -> list[Finding]:
    """Free pre-screen: lines matching an item's regex hints, INFO severity, at most a few per item."""
    out: list[Finding] = []
    for it in items:
        pats = hints.get(it["id"]) or []
        n = 0
        for rel, text in files if pats else ():
            for pat in pats:
                m = pat.search(text)
                if m and n < LOCAL_HITS_PER_ITEM:
                    line = text.count("\n", 0, m.start()) + 1
                    snip = text.splitlines()[line - 1].strip()[:200] if text else ""
                    out.append(Finding("bank", it["id"], Severity.INFO, it["title"],
                                       f"Regex hint only (candidate, nothing was judged). {it['why']}",
                                       [Evidence(rel, line, line, snip, {"hint": pat.pattern})], None, "local-hint", it["fix"]))
                    n += 1
                    break
    out.sort(key=lambda f: (-int(next(i["severity"] for i in items if i["id"] == f.rule_id)), f.rule_id, f.evidence[0].file or ""))
    return out


def questions(snap_mod: Any, items: list[dict]) -> list[Any]:
    pre = "The text is a set of files; every file starts with a '### FILE: <path>' header. "
    return [snap_mod.Question(it["id"], pre + it["question"], it["true"], it["false"]) for it in items]


def rank(score: float, sev: Severity) -> float:
    return score * (int(sev) + 1)


def interpret(scan: Any, items: list[dict], hints: dict[str, list[re.Pattern[str]]], windows: list[Any], spans: list[Any],
              ctx: Any, snap_mod: Any, notes: list[str], top: int,
              baseline: dict[str, float] | None = None, stats: dict | None = None) -> list[Finding]:
    """Flagged questions ranked by score*severity, capped at `top`; the best few are localized to file and line."""
    by_id = {it["id"]: it for it in items}
    flagged = sorted(((qr.max_score, qid, qr.best_window) for qid, qr in scan.per_question.items()
                      if qr.max_score >= ctx.threshold and qid in by_id),
                     key=lambda t: (-rank(t[0], by_id[t[1]]["severity"]), t[1]))
    if baseline:
        # an item that also fires on clean code says little about this project
        keep = [t for t in flagged if t[1] not in baseline
                or (baseline[t[1]] <= BASELINE_MAX and t[0] > baseline[t[1]] + BASELINE_MARGIN)]
        if len(keep) < len(flagged):
            notes.append(f"{len(flagged) - len(keep)} items suppressed: fire on clean code")
        if stats is not None:
            stats["suppressed"] = len(flagged) - len(keep)
        flagged = keep
    flagged = flagged[:top]
    qmap = {q.id: q for q in questions(snap_mod, items)}
    out: list[Finding] = []
    for n, (score, qid, (ws, we)) in enumerate(flagged):
        it = by_id[qid]
        pats = hints.get(qid) or []
        shim = SimpleNamespace(info=SimpleNamespace(id=qid), hint=_AnyOf(pats) if pats else None)
        extra = {"window": [ws, we], "score": round(score, 4), "category": it["category"]}
        snip = None
        if n < MAX_LOCALIZE and hasattr(ctx.snap, "localize"):
            win = snap_layer._text_of(windows, ws, we, snap_mod)
            try:
                snip = ctx.snap.localize(win, qmap[qid]) if win else None
            except snap_mod.SnapError as e:
                notes.append(f"localize {qid} failed: {e}")
        ev = attribute(snip.start if snip else ws, snip.end if snip else we, snip is not None, spans, windows, shim.hint, extra)
        out.append(Finding("bank", qid, it["severity"], it["title"],
                           f"Snap score {score:.2f} (candidate, not proof). {it['why']}", ev, score, "snap", it["fix"]))
    return out


def attribute(lo: int, hi: int, localized: bool, spans: list[Any], windows: list[Any], hint: Any, extra: dict) -> list[Evidence]:
    """Files for the text range [lo, hi): a snippet Snap localized, or else the whole window it flagged.

    One file only when the range holds one file or a regex hint lands in at most MAX_HINT_FILES files; otherwise
    one entry saying "somewhere in these N files" (never a guess at a single file)."""
    secs = [sp for sp in spans if sp.start + sp.header_len < hi and sp.end > lo and (localized or lo <= sp.start < hi)]
    hits: list[Evidence] = []
    for sp in secs:
        w = windows[sp.window]
        a, b = max(sp.start + sp.header_len, lo), min(sp.end, hi)
        l0 = snap_layer._line_at(sp, windows, a)
        for i, ln in enumerate(w.text[a - w.start:b - w.start].splitlines()):
            if hint and hint.search(ln):
                hits.append(Evidence(sp.rel, l0 + i, l0 + i, ln.strip()[:200], {**extra, "localized": localized, "line_from": "regex hint"}))
                break
    if localized and len(secs) == 1:
        sp = secs[0]
        if hits:
            return hits
        w = windows[sp.window]
        a, b = max(sp.start + sp.header_len, lo), min(sp.end, hi)
        l0 = snap_layer._line_at(sp, windows, a)
        piece = w.text[a - w.start:b - w.start]
        return [Evidence(sp.rel, l0, l0 + piece.count("\n"), piece[:400], {**extra, "localized": True, "line_from": "snippet range"})]
    if 0 < len(hits) <= MAX_HINT_FILES:
        return hits
    files = [h.file for h in hits] if hits else [sp.rel for sp in secs]
    shown = ", ".join(files[:10]) + (f" (+{len(files) - 10} more)" if len(files) > 10 else "")
    return [Evidence(None, None, None, f"somewhere in these {len(files)} files: {shown}" if files else "", {**extra, "localized": False, "files": files})]
