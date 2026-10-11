"""Turn training logs into records: {"line", "vals": {metric: float}}. Handles JSONL, JSON, CSV/TSV and `epoch 3 loss 0.41` text."""
from __future__ import annotations

import csv
import io
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

_NUM = r"(?:[+-]?(?:nan|inf(?:inity)?)|[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)"
KV = re.compile(rf"(?<![\w.])([A-Za-z_][\w./-]*)\s*[=:\s]\s*({_NUM})(?![\w.])", re.I)
STEP_KEYS = ("step", "_step", "global_step", "iter", "iteration", "iterations")


@dataclass
class Record:
    line: int
    vals: dict[str, float] = field(default_factory=dict)


def _num(v: object) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return None
    return None


def _flatten(d: dict, prefix: str = "") -> dict[str, float]:
    out: dict[str, float] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(_flatten(v, f"{prefix}{k}/"))
        elif (x := _num(v)) is not None:
            out[f"{prefix}{k}"] = x
    return out


def _rec(line: int, d: dict) -> Record | None:
    vals = _flatten(d)
    return Record(line, vals) if vals else None


def _jsonl_or_text(text: str) -> list[Record]:
    out: list[Record] = []
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        r = None
        if s.startswith("{"):
            try:
                obj = json.loads(s)
                r = _rec(i, obj) if isinstance(obj, dict) else None
            except ValueError:
                pass
        if r is None and not s.startswith("{"):
            vals = {k.lower(): float(v) for k, v in KV.findall(s)}
            r = Record(i, vals) if len(vals) >= 2 or (vals and "loss" in s.lower()) else None
        if r:
            out.append(r)
    return out


def _json_doc(text: str) -> list[Record] | None:
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    if isinstance(obj, dict):
        for k in ("log_history", "history", "records", "logs"):
            if isinstance(obj.get(k), (list, dict)):
                obj = obj[k]
                break
    if isinstance(obj, list):
        return [r for i, d in enumerate(obj, 1) if isinstance(d, dict) and (r := _rec(i, d))]
    if isinstance(obj, dict) and obj and all(isinstance(v, list) for v in obj.values()):   # Keras History: {"loss": [..]}
        n = max(len(v) for v in obj.values())
        rows = [{k: v[i] for k, v in obj.items() if i < len(v)} for i in range(n)]
        recs = [_rec(i + 1, d) for i, d in enumerate(rows)]
        return [r for r in recs if r]
    return []


def _csv(text: str, delim: str) -> list[Record]:
    out = []
    for i, row in enumerate(csv.DictReader(io.StringIO(text), delimiter=delim), 2):    # line 1 is the header
        vals = {k.strip(): x for k, v in row.items() if k and (x := _num(v)) is not None}
        if vals:
            out.append(Record(i, vals))
    return out


def parse_text(text: str, suffix: str) -> list[Record]:
    if suffix == ".csv":
        return _csv(text, ",")
    if suffix == ".tsv":
        return _csv(text, "\t")
    if suffix == ".json":
        recs = _json_doc(text)
        if recs is not None:
            return recs
    return _jsonl_or_text(text)


def parse_file(path: Path) -> list[Record]:
    return parse_text(path.read_text(encoding="utf-8", errors="replace"), path.suffix.lower())


def finite(x: float) -> bool:
    return math.isfinite(x)
