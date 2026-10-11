"""DS-IMG-001..003 with Pillow (optional). dHash near-duplicates, split leaks, corrupt/blank/tiny files."""
from __future__ import annotations

from pathlib import Path

from checksnap.core import Evidence, Finding

from .analyzers import MAX_EV, ev, mk
from .records import file_id, rel

try:  # Pillow is an optional dependency
    from PIL import Image, ImageStat
except ImportError:  # pragma: no cover
    Image = None

MAX_DIST = 4          # Hamming distance on 64-bit dHash; 5 chunks of <=13 bits => pigeonhole finds every pair


def pillow_available() -> bool:
    return Image is not None


def dhash(path: Path) -> tuple[int | None, str | None]:
    """Return (hash, problem). problem is 'corrupt', 'tiny' or 'blank' (hash None for those)."""
    try:
        with Image.open(path) as im:
            im.load()
            w, h = im.size
            g = im.convert("L")
    except Exception:  # noqa: BLE001  (Pillow raises many types on bad files)
        return None, "corrupt"
    if min(w, h) < 32:
        return None, "tiny"
    if ImageStat.Stat(g).stddev[0] < 1.0:
        return None, "blank"
    px = list(g.resize((9, 8)).tobytes())
    bits = 0
    for r in range(8):
        for c in range(8):
            bits = (bits << 1) | (px[r * 9 + c] > px[r * 9 + c + 1])
    return bits, None


def _chunks(h: int) -> list[tuple[int, int]]:
    return [(k, (h >> (13 * k)) & 0x1FFF) for k in range(5)]


def _near(table: dict, h: int) -> list[int]:
    seen: dict[int, None] = {}
    for key in _chunks(h):
        for i in table.get(key, ()):
            seen[i] = None
    return list(seen)


def scan_images(files: list[Path], root: Path, eval_files: list[Path], eval_root: Path | None,
                id_regex: str | None) -> tuple[list[Finding], dict]:
    names = [rel(p, root) for p in files]
    hashes: list[int | None] = []
    bad: dict[str, list[Evidence]] = {"corrupt": [], "tiny": [], "blank": []}
    counts = dict.fromkeys(bad, 0)
    table: dict[tuple[int, int], list[int]] = {}
    parent: list[int] = list(range(len(files)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, p in enumerate(files):
        h, prob = dhash(p)
        hashes.append(h)
        if prob:
            counts[prob] += 1
            if len(bad[prob]) < MAX_EV:
                bad[prob].append(ev(names[i], None, prob))
            continue
        for j in _near(table, h):
            if bin(h ^ hashes[j]).count("1") <= MAX_DIST:
                parent[find(j)] = find(i)
        for key in _chunks(h):
            table.setdefault(key, []).append(i)

    out: list[Finding] = []
    for prob, label in (("corrupt", "cannot be decoded"), ("tiny", "smaller than 32 px"), ("blank", "blank (no pixel variation)")):
        if counts[prob]:
            out.append(mk("DS-IMG-003", title=f"Images {label}", detail=f"{counts[prob]} files.", evidence=bad[prob], source="hash"))
    groups: dict[int, list[int]] = {}
    for i in range(len(files)):
        if hashes[i] is not None:
            groups.setdefault(find(i), []).append(i)
    clusters = sorted((g for g in groups.values() if len(g) > 1), key=len, reverse=True)
    if clusters:
        out.append(mk("DS-IMG-001", detail=f"{len(clusters)} clusters, {sum(len(c) - 1 for c in clusters)} redundant images.",
                      evidence=[ev(names[i], None, f"cluster of {len(c)}") for c in clusters[:MAX_EV] for i in c[:2]][:MAX_EV * 2], source="hash"))

    stats = {"images": len(files), "images_corrupt": counts["corrupt"], "images_tiny": counts["tiny"], "images_blank": counts["blank"]}
    if eval_files and eval_root is not None:
        leaks: list[Evidence] = []
        n_leak = 0
        for p in eval_files:
            h, prob = dhash(p)
            if h is None:
                continue
            for j in _near(table, h):
                if bin(h ^ hashes[j]).count("1") <= MAX_DIST:
                    n_leak += 1
                    if len(leaks) < MAX_EV:
                        leaks.append(ev(rel(p, eval_root), None, "near-duplicate of dataset image", dataset_match=names[j]))
                    break
        if n_leak:
            out.append(mk("DS-IMG-002", title="Eval image is a near-duplicate of a dataset image", detail=f"{n_leak} eval images.",
                          evidence=leaks, source="hash"))
        ids = {file_id(n, id_regex) for n in names} - {None}
        shared = sorted(ids & ({file_id(rel(p, eval_root), id_regex) for p in eval_files} - {None}))
        if shared:
            out.append(mk("DS-IMG-002", title="Same ids across dataset and eval images", detail=f"{len(shared)} shared ids, e.g. {', '.join(shared[:5])}."))
        stats["images_eval"] = len(eval_files)
    return out, stats
