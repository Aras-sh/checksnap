"""Bisect a flagged window down to a small snippet."""
from __future__ import annotations

from typing import Callable

from .windows import Window


def bisect_hit(score: Callable[[str], float], window: Window, target_chars: int = 2000,
               overlap: int = 5_000, threshold: float = 0.5) -> Window | None:
    """Narrow `window` to <= target_chars by asking about halves (left first, then right).

    Halves overlap a little so an item on the cut survives in one of them. Returns None when not even the first
    split reproduces the hit (a diffuse match, nothing to point at); later dead ends return the narrowest hit so far.
    """
    cur = window
    first = True
    while len(cur.text) > target_chars:
        n = len(cur.text)
        ov = min(overlap, n // 8)
        mid = n // 2
        halves = (Window(cur.start, cur.start + mid + ov, cur.text[:mid + ov]),
                  Window(cur.start + mid - ov, cur.end, cur.text[mid - ov:]))
        nxt = next((h for h in halves if score(h.text) >= threshold), None)
        if nxt is None:
            return None if first else cur
        cur, first = nxt, False
    return cur
