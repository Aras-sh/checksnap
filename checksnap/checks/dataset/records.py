"""Streaming readers for .txt/.jsonl/.json/.csv/.tsv. One Rec per record; unparsable lines are reported, not raised."""
from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

TEXT_EXT = {".txt", ".jsonl", ".json", ".csv", ".tsv"}
IMG_EXT = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp", ".tif", ".tiff"}

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:  # pragma: no cover (32-bit)
    csv.field_size_limit(2**31 - 1)


@dataclass
class Rec:
    file: str                       # relative to the scanned root
    idx: int                        # 1-based line / row / list position
    text: str
    raw: dict[str, Any] | None = None


def list_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*") if p.is_file()
                  and not any(part.startswith(".") for part in p.relative_to(path).parts))


def rel(p: Path, root: Path) -> str:
    return p.name if root.is_file() else p.relative_to(root).as_posix()


def _text(raw: Any, text_field: str | None) -> str:
    if not isinstance(raw, dict):
        return "" if raw is None else str(raw)
    if text_field:
        v = raw.get(text_field)
        return "" if v is None else str(v)
    return "\n".join(v for v in raw.values() if isinstance(v, str))


def iter_records(files: list[Path], root: Path, text_field: str | None = None, max_records: int | None = None,
                 issues: list[tuple[str, int, str]] | None = None) -> Iterator[Rec]:
    """Yield records from the text-like files. issues collects (file, line, problem) for bad lines/files."""
    n = 0
    for p in files:
        ext = p.suffix.lower()
        if ext not in TEXT_EXT:
            continue
        name = rel(p, root)
        try:
            for rec in _read(p, ext, name, text_field, issues):
                if max_records is not None and n >= max_records:
                    return
                n += 1
                yield rec
        except (OSError, UnicodeError, ValueError, csv.Error) as exc:
            if issues is not None:
                issues.append((name, 0, f"unreadable: {type(exc).__name__}: {exc}"))


def _read(p: Path, ext: str, name: str, tf: str | None, issues) -> Iterator[Rec]:
    if ext == ".txt":
        # one record per file: a prose file is one document, and n-gram checks need text across lines
        yield Rec(name, 1, p.read_text(encoding="utf-8-sig", errors="replace"))
    elif ext == ".jsonl":
        with p.open(encoding="utf-8-sig", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except ValueError:
                    if issues is not None:
                        issues.append((name, i, "unparsable JSON line"))
                    continue
                yield Rec(name, i, _text(raw, tf), raw if isinstance(raw, dict) else None)
    elif ext == ".json":
        # ponytail: a .json list is loaded whole (no streaming JSON parser in stdlib); use .jsonl for big data
        data = json.loads(p.read_text(encoding="utf-8-sig", errors="replace"))
        if isinstance(data, dict):
            data = next((v for v in data.values() if isinstance(v, list)), [data])
        if not isinstance(data, list):
            data = [data]
        for i, raw in enumerate(data, 1):
            yield Rec(name, i, _text(raw, tf), raw if isinstance(raw, dict) else None)
    else:
        with p.open(encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.DictReader(f, delimiter="\t" if ext == ".tsv" else ",")
            for raw in reader:
                raw = {k: v for k, v in raw.items() if k is not None}
                yield Rec(name, reader.line_num, _text(raw, tf), raw)


@dataclass
class BItem:
    file: str
    line: int
    text: str


def load_benchmarks(paths: list[str], field: str, notes: list[str]) -> list[BItem]:
    items: list[BItem] = []
    for bp in paths:
        p = Path(bp)
        if not p.is_file():
            notes.append(f"benchmark {bp}: file not found")
            continue
        bad = 0
        issues: list = []
        for rec in iter_records([p], p, None, None, issues):
            v = rec.raw.get(field) if rec.raw is not None else rec.text
            if isinstance(v, str) and v.strip():
                items.append(BItem(p.name, rec.idx, v.strip()))
            else:
                bad += 1
        if bad or issues:
            notes.append(f"benchmark {p.name}: {bad} records without a text '{field}' field, {len(issues)} unreadable lines skipped")
    return items


def file_id(name: str, id_regex: str | None) -> str | None:
    """Id from a file name (video/channel id): group 1 of the regex, else the whole match."""
    if not id_regex:
        return None
    m = re.search(id_regex, Path(name).name)
    return (m.group(1) if m.groups() else m.group(0)) if m else None
