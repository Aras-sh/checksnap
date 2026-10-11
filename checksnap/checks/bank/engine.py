"""Bank engine: load and validate question items, pick the relevant ones, pack files, ask Snap, rank findings.

Items are plain dicts (see REQUIRED) so teams can add their own with --bank-file. A broken module or item is a note,
never a crash. Packing, localizing and line pinning reuse the optimization snap layer's helpers.
"""
from __future__ import annotations

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
MAX_LOCALIZE = 10          # each localize bisects with extra calls; beyond this, window-level evidence only
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
    return {**raw, "severity": sev, "applies_to": ap, "hints": hints}, None


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
              ctx: Any, snap_mod: Any, notes: list[str], top: int) -> list[Finding]:
    """Flagged questions ranked by score*severity, capped at `top`; the best few are localized to file and line."""
    by_id = {it["id"]: it for it in items}
    flagged = sorted(((qr.max_score, qid, qr.best_window) for qid, qr in scan.per_question.items()
                      if qr.max_score >= ctx.threshold and qid in by_id),
                     key=lambda t: (-rank(t[0], by_id[t[1]]["severity"]), t[1]))[:top]
    qmap = {q.id: q for q in questions(snap_mod, items)}
    out: list[Finding] = []
    for n, (score, qid, (ws, we)) in enumerate(flagged):
        it = by_id[qid]
        pats = hints.get(qid) or []
        shim = SimpleNamespace(info=SimpleNamespace(id=qid), hint=re.compile("|".join(f"(?:{p.pattern})" for p in pats), re.M) if pats else None)
        extra = {"window": [ws, we], "score": round(score, 4), "category": it["category"]}
        ev: list[Evidence] = []
        if n < MAX_LOCALIZE and hasattr(ctx.snap, "localize"):
            win = snap_layer._text_of(windows, ws, we, snap_mod)
            try:
                snip = ctx.snap.localize(win, qmap[qid]) if win else None
            except snap_mod.SnapError as e:
                notes.append(f"localize {qid} failed: {e}")
                snip = None
            if snip is not None:
                ev = snap_layer._snippet_evidence(snip, spans, windows, shim, {}, extra)
        if not ev:       # window level: the files inside it, with the first hint line per file when there is one
            w = next((w for w in windows if w.start <= ws < w.end), None)
            for sp in spans:
                if len(ev) >= 5 or not (ws <= sp.start < we) or w is None:
                    continue
                body = w.text[sp.start - w.start + sp.header_len:sp.end - w.start]
                line = next((i for i, ln in enumerate(body.splitlines()) if shim.hint and shim.hint.search(ln)), None)
                ev.append(Evidence(sp.rel, None if line is None else sp.first_line + line, None if line is None else sp.first_line + line,
                                   "" if line is None else body.splitlines()[line].strip()[:200], {**extra, "localized": False}))
            ev = ev or [Evidence(None, None, None, "", {**extra, "localized": False})]
        out.append(Finding("bank", qid, it["severity"], it["title"],
                           f"Snap score {score:.2f} (candidate, not proof). {it['why']}", ev, score, "snap", it["fix"]))
    return out
