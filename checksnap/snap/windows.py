"""Splitting long text into overlapping windows that each fit one Snap call."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Window:
    start: int      # char offset in the original text (inclusive)
    end: int        # char offset (exclusive)
    text: str


def split_windows(text: str, size: int = 800_000, overlap: int = 5_000) -> list[Window]:
    """Cover every char of `text` with windows of at most `size` chars.

    Consecutive windows share `overlap` chars so an item straddling a cut is still whole in one of them.
    Cuts prefer a newline in the last 10% of a window so records are not sliced mid-line.
    """
    if size <= 0 or overlap < 0 or overlap >= size:
        raise ValueError("need 0 <= overlap < size")
    n = len(text)
    if n == 0:
        return []
    out: list[Window] = []
    start = 0
    while True:
        end = min(n, start + size)
        if end < n:
            nl = text.rfind("\n", start + int(size * 0.9), end)
            if nl != -1 and nl + 1 - overlap > start:
                end = nl + 1
        out.append(Window(start, end, text[start:end]))
        if end >= n:
            return out
        start = end - overlap
