"""--check-repo: one positive and one negative per rule, on small tmp trees (no git, no network)."""
from __future__ import annotations

import argparse
import os

import pytest

from checksnap.checks import gitrepo
from checksnap.checks.gitrepo import Gitignore, RULES, RepoCheck
from checksnap.core import Context, REGISTRY


def run(root):
    return RepoCheck().run(Context(no_snap=True), argparse.Namespace(check_repo=str(root)))


def ids(root):
    return {f.rule_id for f in run(root).findings}


def w(root, rel, content="x\n", binary=False):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content if binary else content.encode())
    return p


@pytest.fixture
def clean(tmp_path):
    w(tmp_path, "README.md", "hi")
    w(tmp_path, "LICENSE", "MIT")
    w(tmp_path, ".gitignore", "__pycache__/\n.env\n.venv/\nruns/\ndata/\n*.pt\n")
    w(tmp_path, "a.py", "print(1)\n")
    return tmp_path


def test_registered_and_rules():
    assert REGISTRY["repo"].flag == "--check-repo" and not REGISTRY["repo"].uses_snap
    assert len(RULES) == 15 and all(r.explanation and r.fix_hint for r in RULES.values())
    assert RepoCheck().estimate(Context(), argparse.Namespace()).uploads_bytes == 0


def test_clean_tree_has_no_findings(clean):
    assert ids(clean) == set()


def test_missing_dir_is_error(tmp_path):
    assert run(tmp_path / "nope").error


def test_gitignore_matcher():
    g = Gitignore("*.log\n/build\ndata/\n!keep.log\nsub/x.txt\n")
    assert g.ignored("a/b.log") and not g.ignored("keep.log") and g.ignored("build") and not g.ignored("a/build")
    assert g.ignored("data", True) and g.ignored("data/f.csv") and not g.ignored("data")
    assert g.ignored("sub/x.txt") and not g.ignored("x.txt")


def test_large_and_artifact(clean, monkeypatch):
    monkeypatch.setattr(gitrepo, "LARGE_BYTES", 500)
    w(clean, "big.dat", "a" * 600)
    w(clean, "m.ckpt", "a")
    w(clean, "ok.pt", "a")                       # ignored by *.pt
    f = run(clean).findings
    assert {(x.rule_id, x.evidence[0].file) for x in f if x.rule_id in ("REPO-001", "REPO-002")} == {("REPO-001", "big.dat"), ("REPO-002", "m.ckpt")}


def test_gitignore_missing_and_entries(tmp_path):
    w(tmp_path, "README.md")
    assert "REPO-003" in ids(tmp_path)
    w(tmp_path, ".gitignore", "*.pyc\n")
    w(tmp_path, "runs/log.txt")
    w(tmp_path, ".env")
    w(tmp_path, "pkg/__pycache__/a.pyc")
    r = run(tmp_path)
    d = [f for f in r.findings if f.rule_id == "REPO-004"][0].detail
    assert "runs/" in d and ".env" in d and "__pycache__/" in d and "data/" not in d and "REPO-003" not in {f.rule_id for f in r.findings}


def test_secrets(clean):
    w(clean, "deploy/id_rsa")
    w(clean, "cert.pem")
    w(clean, "credentials.json", "{}")
    w(clean, ".env.example")                     # safe template
    w(clean, ".env")                             # ignored by .gitignore
    hits = {f.evidence[0].file for f in run(clean).findings if f.rule_id == "REPO-005"}
    assert hits == {"deploy/id_rsa", "cert.pem", "credentials.json"}


def test_readme_license(tmp_path):
    w(tmp_path, ".gitignore")
    assert {"REPO-006", "REPO-007"} <= ids(tmp_path)


def test_notebook_outputs(clean):
    import json
    big = {"cells": [{"cell_type": "code", "outputs": [{"data": {"image/png": "A" * 600_000}}]}]}
    small = {"cells": [{"cell_type": "code", "outputs": []}]}
    w(clean, "big.ipynb", json.dumps(big))
    w(clean, "small.ipynb", json.dumps(small))
    assert [f.evidence[0].file for f in run(clean).findings if f.rule_id == "REPO-008"] == ["big.ipynb"]


def test_symlinks(clean):
    os.symlink("missing.txt", clean / "dead")
    os.symlink("a.py", clean / "alive")
    assert [f.evidence[0].file for f in run(clean).findings if f.rule_id == "REPO-009"] == ["dead"]


def test_duplicates(clean):
    w(clean, "one.txt", "z" * 2000)
    w(clean, "sub/two.txt", "z" * 2000)
    w(clean, "three.txt", "y" * 2000)            # same size, different content
    w(clean, "e1.txt", "")
    w(clean, "e2.txt", "")                       # tiny/empty duplicates ignored
    r = run(clean)
    dup = [f for f in r.findings if f.rule_id == "REPO-010"]
    assert len(dup) == 1 and {e.file for e in dup[0].evidence} == {"one.txt", "sub/two.txt"}
    assert r.stats["wasted_bytes"] == 2000


def test_case_collision(clean):
    w(clean, "Foo.py")
    w(clean, "foo.py")
    w(clean, "other/bar.py")
    hits = [f for f in run(clean).findings if f.rule_id == "REPO-011"]
    assert len(hits) == 1 and {e.file for e in hits[0].evidence} == {"Foo.py", "foo.py"}


def test_long_path(clean):
    w(clean, "/".join(["d" * 40] * 5) + "/f.py")
    assert "REPO-012" in ids(clean)


def test_line_endings(clean):
    w(clean, "mixed.py", "a\r\nb\nc\r\n", binary=False)
    w(clean, "crlf.py", "a\r\nb\r\n")
    w(clean, "lf.py", "a\nb\n")
    assert [f.evidence[0].file for f in run(clean).findings if f.rule_id == "REPO-013"] == ["mixed.py"]


def test_conflict_markers(clean):
    w(clean, "bad.py", "a\n<<<<<<< HEAD\nx\n=======\ny\n>>>>>>> br\n")
    w(clean, "doc.md", "Title\n=======\ntext\n")      # setext heading, not a conflict
    assert [f.evidence[0].file for f in run(clean).findings if f.rule_id == "REPO-014"] == ["bad.py"]


def test_todo_count(clean):
    w(clean, "t.py", "# TODO a\n# FIXME b\nTODOS = 1\n")
    r = run(clean)
    f = [x for x in r.findings if x.rule_id == "REPO-015"]
    assert len(f) == 1 and r.stats["todo_count"] == 2
