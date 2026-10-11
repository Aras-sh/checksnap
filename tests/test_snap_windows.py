from __future__ import annotations

import pytest

from checksnap.snap import bisect_hit, split_windows, Window


def test_short_and_empty():
    assert split_windows("") == []
    w = split_windows("abc", 10, 2)
    assert [(x.start, x.end, x.text) for x in w] == [(0, 3, "abc")]


@pytest.mark.parametrize("size,overlap", [(100, 10), (97, 0), (50, 49)])
def test_covers_every_char_with_overlap(size, overlap):
    text = "".join(f"line {i}\n" if i % 7 else "x" * 30 for i in range(200))
    ws = split_windows(text, size, overlap)
    assert all(w.text == text[w.start:w.end] and len(w.text) <= size for w in ws)
    assert ws[0].start == 0 and ws[-1].end == len(text)
    for a, b in zip(ws, ws[1:]):
        assert b.start <= a.end - overlap and b.start > a.start


def test_bad_args():
    for size, ov in [(10, 10), (0, 0), (10, -1)]:
        with pytest.raises(ValueError):
            split_windows("x", size, ov)


def test_bisect_hit():
    text = "a" * 50_000 + "NEEDLE" + "b" * 50_000
    w = Window(0, len(text), text)
    hit = bisect_hit(lambda t: 0.9 if "NEEDLE" in t else 0.1, w, 2000, 100)
    assert len(hit.text) <= 2000 and "NEEDLE" in hit.text and hit.text == text[hit.start:hit.end]
    assert bisect_hit(lambda t: 0.1, w) is None
