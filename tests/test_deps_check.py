"""--check-dependencies: one positive and one negative per rule, plus parsers and the end-to-end run."""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from checksnap.checks.deps import RULES, DependenciesCheck
from checksnap.checks.deps.parsers import parse_environment_yml, parse_pipfile, parse_pyproject, parse_requirements, parse_setup_cfg
from checksnap.core import REGISTRY, Context

FIX = Path(__file__).parent / "fixtures" / "deps"


def run(root, **kw):
    ns = argparse.Namespace(check_dependencies=str(root), **kw)
    return DependenciesCheck().run(Context(no_snap=True), ns)


def ids(res):
    return {f.rule_id for f in res.findings}


def test_registered():
    c = REGISTRY["dependencies"]
    assert c.flag == "--check-dependencies" and not c.uses_snap
    assert c.estimate(Context(), argparse.Namespace()).input_tokens == 0


def test_every_rule_documented():
    assert sorted(RULES) == [f"DEP-{i:03d}" for i in range(1, 13)]
    assert all(r.explanation and r.fix_hint and r.title for r in RULES.values())


BAD_EXPECTED = ["DEP-001", "DEP-002", "DEP-003", "DEP-004", "DEP-005", "DEP-006", "DEP-007", "DEP-008", "DEP-009", "DEP-010", "DEP-011", "DEP-012"]


def test_bad_fixture_hits_every_rule():
    res = run(FIX / "bad")
    assert ids(res) == set(BAD_EXPECTED)
    by = {}
    for f in res.findings:
        by.setdefault(f.rule_id, []).append(f)
    assert any("pandas" in f.detail for f in by["DEP-005"])
    assert not any("requests" in f.detail or "numpy" in f.detail for f in by["DEP-005"])   # declared; PIL maps to pillow
    assert any("left-pad-py" in f.detail for f in by["DEP-006"])
    assert {f.detail.split("`")[1] for f in by["DEP-011"]} == {"requests", "django", "flask"}
    assert by["DEP-007"][0].evidence[0].line_start == 11


def test_good_fixture_is_clean():
    res = run(FIX / "good")
    assert res.findings == [] and res.error is None


def test_missing_path_and_no_manifest(tmp_path):
    assert run(tmp_path / "nope").error
    assert "no dependency manifest" in run(tmp_path).notes[0]


def test_git_commit_pin_ok_and_branch_flagged(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "pkg @ git+https://github.com/a/b.git@0123456789abcdef0123456789abcdef01234567\n"
        "git+ssh://git@github.com/a/c.git@main#egg=c\n")
    res = run(tmp_path)
    d7 = [f for f in res.findings if f.rule_id == "DEP-007"]
    assert len(d7) == 1 and "ref main" in d7[0].detail


def test_http_extra_index_and_no_flags_on_https(tmp_path):
    (tmp_path / "requirements.txt").write_text("--index-url https://pypi.org/simple\nrequests==2.31.0\n")
    assert not ids(run(tmp_path)) & {"DEP-008", "DEP-009", "DEP-010"}
    (tmp_path / "requirements.txt").write_text("--extra-index-url http://x.example/simple\n")
    assert {"DEP-008", "DEP-009"} <= ids(run(tmp_path))


def test_python_version_sources(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    assert "DEP-012" in ids(run(tmp_path))
    (tmp_path / ".python-version").write_text("3.12\n")
    assert "DEP-012" not in ids(run(tmp_path))


def test_marker_deps_not_conflicts(tmp_path):
    (tmp_path / "requirements.txt").write_text("numpy==1.24.0 ; python_version < '3.9'\n")
    (tmp_path / "requirements-b.txt").write_text("numpy==1.26.0\n")
    assert "DEP-003" not in ids(run(tmp_path))


def test_parse_requirements_continuation_and_hash():
    p = parse_requirements("foo==1.0 \\\n    --hash=sha256:abc\n# c\n-r base.txt\nbar[x]>=2 # note\n", "r.txt")
    assert [(d.name, d.spec) for d in p.deps] == [("foo", "==1.0"), ("bar", ">=2")]


def test_parse_pyproject_pep621_and_poetry():
    p = parse_pyproject('[project]\nrequires-python=">=3.9"\ndependencies=["a>=1"]\n[project.optional-dependencies]\ndev=["b"]\n'
                        '[tool.poetry.dependencies]\npython="^3.9"\nc="1.2.3"\nd={git="https://h/x/d.git", branch="main"}\n', "p.toml")
    got = {d.name: (d.spec, d.group, d.url) for d in p.deps}
    assert got["a"] == (">=1", "main", "") and got["b"][1] == "dev" and got["c"][0] == "==1.2.3" and got["d"][2].endswith("@main")
    assert p.pythons == [">=3.9", "^3.9"]


def test_parse_setup_cfg_pipfile_conda():
    p = parse_setup_cfg("[options]\npython_requires = >=3.8\ninstall_requires =\n    a==1\n    b\n", "s.cfg")
    assert p.pythons == [">=3.8"] and [d.name for d in p.deps] == ["a", "b"]
    p = parse_pipfile('[[source]]\nurl="http://x/simple"\nverify_ssl=false\nname="x"\n[packages]\na="*"\nb="==1.0"\n[requires]\npython_version="3.11"\n', "Pipfile")
    assert [(d.name, d.spec) for d in p.deps] == [("a", ""), ("b", "==1.0")] and {o.kind for o in p.opts} == {"index-url", "verify-ssl-off"}
    p = parse_environment_yml("channels:\n  - defaults\ndependencies:\n  - python=3.10\n  - numpy=1.20.1=py39\n  - conda-forge::scipy>=1.5\n  - pip:\n    - requests==2.31.0\n", "environment.yml")
    assert p.pythons == ["==3.10"] and {(d.name, d.spec) for d in p.deps} == {("numpy", "==1.20.1"), ("scipy", ">=1.5"), ("requests", "==2.31.0")}


def test_cli_smoke(tmp_path, capsys):
    from checksnap.cli import main
    code = main(["--check-dependencies", str(FIX / "bad"), "--no-snap", "--fail-on", "none"])
    assert code == 0 and "DEP-007" in capsys.readouterr().out
