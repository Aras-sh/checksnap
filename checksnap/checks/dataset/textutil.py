"""Text normalisation and MinHash/LSH, stdlib only. Shared by duplicate, leak and contamination code."""
from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass, field

_WORD = re.compile(r"\w+", re.UNICODE)


def words(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def norm(text: str) -> str:
    return " ".join(words(text))


def digest(s: str) -> bytes:
    return hashlib.blake2b(s.encode("utf-8", "replace"), digest_size=8).digest()


_P = (1 << 61) - 1
NUM_PERM = 64
BAND_ROWS = 4          # 16 bands x 4 rows: catches Jaccard 0.8 with p > 0.999, verified by the signature afterwards
_rng = random.Random(1234)
_AB = [(_rng.randrange(1, _P), _rng.randrange(_P)) for _ in range(NUM_PERM)]


def signature(ws: list[str], k: int = 3) -> tuple[int, ...] | None:
    if not ws:
        return None
    k = min(k, len(ws))
    hs = {int.from_bytes(hashlib.blake2b(" ".join(ws[i:i + k]).encode(), digest_size=8).digest(), "big") % _P
          for i in range(len(ws) - k + 1)}
    # ponytail: 64 pure-Python permutations per shingle, ~10 ms for a 1000-word record; numpy if this gets slow
    return tuple(min((a * h + b) % _P for h in hs) for a, b in _AB)


def est_jaccard(a: tuple[int, ...], b: tuple[int, ...]) -> float:
    return sum(x == y for x, y in zip(a, b)) / len(a)


@dataclass
class Ref:
    file: str
    idx: int
    snippet: str = ""


@dataclass
class DupIndex:
    """Exact (hash of normalised text) and near (MinHash+LSH) lookup. Add records, or query without adding."""
    threshold: float = 0.8
    refs: list[Ref] = field(default_factory=list)
    sigs: list[tuple[int, ...] | None] = field(default_factory=list)
    exact: dict[bytes, list[int]] = field(default_factory=dict)
    buckets: dict[tuple, list[int]] = field(default_factory=dict)
    parent: list[int] = field(default_factory=list)
    hashes: list[bytes] = field(default_factory=list)
    near_edges: int = 0

    def _find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def _bands(self, sig):
        return [(b, sig[b * BAND_ROWS:(b + 1) * BAND_ROWS]) for b in range(NUM_PERM // BAND_ROWS)]

    def query(self, text: str) -> tuple[list[int], list[tuple[int, float]]]:
        """Return (exact match ids, [(near match id, est jaccard)]) among records added so far."""
        ws = words(text)
        if not ws:
            return [], []
        h = digest(" ".join(ws))
        ex = list(self.exact.get(h, ()))
        sig = signature(ws)
        cands: set[int] = set()
        for key in self._bands(sig):
            cands.update(self.buckets.get(key, ())[:50])
        near = []
        for c in cands:
            if c in ex or self.sigs[c] is None:
                continue
            j = est_jaccard(sig, self.sigs[c])
            if j >= self.threshold:
                near.append((c, j))
        return ex, near

    def add(self, file: str, idx: int, text: str) -> int | None:
        ws = words(text)
        if not ws:
            return None
        ex, near = self.query(text)
        i = len(self.refs)
        self.refs.append(Ref(file, idx, text[:100].replace("\n", " ")))
        sig = signature(ws)
        self.sigs.append(sig)
        self.parent.append(i)
        h = digest(" ".join(ws))
        self.hashes.append(h)
        self.exact.setdefault(h, []).append(i)
        for key in self._bands(sig):
            self.buckets.setdefault(key, []).append(i)
        for c, _ in near:
            self.parent[self._find(c)] = self._find(i)
            self.near_edges += 1
        return i

    def exact_clusters(self) -> list[list[int]]:
        return [v for v in self.exact.values() if len(v) > 1]

    def near_clusters(self) -> list[list[int]]:
        """Union-find groups that are not just exact copies of one text."""
        groups: dict[int, list[int]] = {}
        for i in range(len(self.refs)):
            groups.setdefault(self._find(i), []).append(i)
        return [g for g in groups.values() if len(g) > 1 and len({self.hashes[i] for i in g}) > 1]
