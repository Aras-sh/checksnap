from __future__ import annotations

import argparse
import random

import pytest

PIL = pytest.importorskip("PIL")
from PIL import Image

from checksnap.core import REGISTRY, Context

CHECK = REGISTRY["dataset"]


def img(path, seed, size=(64, 64), noise=0):
    rng = random.Random(seed)
    im = Image.new("RGB", size)
    # smooth random gradient so dHash is stable under small noise
    ox, oy, k = rng.random() * 9, rng.random() * 9, rng.randint(2, 6)
    im.putdata([(int(127 + 120 * ((x * k + ox) % 7 - 3) / 3), int(127 + 120 * ((y * k + oy) % 5 - 2) / 2), (x * y) % 256)
                for y in range(size[1]) for x in range(size[0])])
    path.parent.mkdir(parents=True, exist_ok=True)
    im.save(path)


def run(path, *extra):
    p = argparse.ArgumentParser()
    CHECK.add_arguments(p)
    a = p.parse_args(list(extra))
    a.check_dataset = str(path)
    r = CHECK.run(Context(no_snap=True), a)
    assert r.error is None, r.error
    return r


def rules(r):
    return {f.rule_id: f for f in r.findings}


def test_near_duplicates_and_bad_files(tmp_path):
    img(tmp_path / "a.png", 1)
    img(tmp_path / "a_copy.png", 1)
    img(tmp_path / "b.png", 2)
    Image.new("RGB", (64, 64), (10, 10, 10)).save(tmp_path / "blank.png")
    Image.new("RGB", (8, 8)).save(tmp_path / "tiny.png")
    (tmp_path / "broken.jpg").write_bytes(b"not an image")
    r = run(tmp_path)
    f = rules(r)
    assert "DS-IMG-001" in f and "a_copy.png" in json_ev(f["DS-IMG-001"]) and "b.png" not in json_ev(f["DS-IMG-001"])
    titles = " ".join(x.title for x in r.findings if x.rule_id == "DS-IMG-003")
    assert "decoded" in titles and "tiny" not in titles and "smaller" in titles and "blank" in titles
    assert r.stats["images"] == 6


def json_ev(f):
    return " ".join(e.file or "" for e in f.evidence)


def test_clean_images(tmp_path):
    for i in range(4):
        img(tmp_path / f"{i}.png", 10 + i * 7)
    assert not [f for f in run(tmp_path).findings if f.rule_id.startswith("DS-IMG")]


def test_eval_leak_and_shared_ids(tmp_path):
    img(tmp_path / "train" / "vid123_001.png", 5)
    img(tmp_path / "test" / "vid123_900.png", 5)
    img(tmp_path / "test" / "other_1.png", 99)
    r = run(tmp_path / "train", "--eval", str(tmp_path / "test"), "--id-regex", r"^(vid\d+)")
    img_leaks = [f for f in r.findings if f.rule_id == "DS-IMG-002"]
    assert len(img_leaks) == 2 and any("shared ids" in f.detail for f in img_leaks)


def test_modality_text_skips_images(tmp_path):
    img(tmp_path / "a.png", 1)
    assert run(tmp_path, "--modality", "text").stats.get("images") is None
