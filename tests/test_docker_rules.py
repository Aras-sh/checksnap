"""Every docker rule: one positive (right id, right line) and one negative source."""
from __future__ import annotations

import argparse

import pytest

from checksnap.checks.docker import RULES, DockerCheck
from checksnap.checks.docker.scan import analyze_compose, analyze_dockerfile
from checksnap.core import Context

GOOD = "FROM python:3.12-slim\nUSER app\nHEALTHCHECK CMD true\nCMD [\"a\"]\n"
# rule -> (kind, positive, expected line, negative)
CASES = {
    "DOC-001": ("d", "FROM python\n", 1, "FROM python:3.12\nFROM scratch\nFROM a@sha256:abc\n"),
    "DOC-002": ("d", "FROM python:3.12\nCMD [\"a\"]\n", 1, "FROM python:3.12\nUSER app\n"),
    "DOC-003": ("d", "FROM a:1\nADD x /y\n", 2, "FROM a:1\nADD x.tar.gz /y\nADD https://h/f /f\nCOPY x /y\n"),
    "DOC-004": ("d", "FROM a:1\nRUN apt-get install -y git\n", 2, "FROM a:1\nRUN apt-get install -y --no-install-recommends git\n"),
    "DOC-005": ("d", "FROM a:1\nRUN apt-get install -y git\n", 2, "FROM a:1\nRUN apt-get install -y git && rm -rf /var/lib/apt/lists/*\n"),
    "DOC-006": ("d", "FROM a:1\nRUN apt-get update\n", 2, "FROM a:1\nRUN apt-get update && apt-get install -y git\n"),
    "DOC-007": ("d", "FROM a:1\nRUN pip install flask\n", 2, "FROM a:1\nRUN pip install --no-cache-dir flask\n"),
    "DOC-008": ("d", "FROM a:1\nENV API_TOKEN=abcdef123456\n", 2, "FROM a:1\nENV API_TOKEN=${TOKEN}\nARG TOKEN\nENV PATH=/x\n"),
    "DOC-009": ("d", "FROM a:1\nCOPY . .\nRUN pip install -r requirements.txt\n", 2,
                "FROM a:1\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\nCOPY . .\n"),
    "DOC-010": ("n", "FROM a:1\n", 1, None),
    "DOC-011": ("d", "FROM a:1\nCMD [\"a\"]\n", 1, "FROM a:1\nHEALTHCHECK CMD true\nCMD [\"a\"]\n"),
    "DOC-012": ("d", "FROM a:1\nRUN curl -fsSL https://x/i.sh | bash\n", 2, "FROM a:1\nRUN curl -fsSL https://x/i.sh -o i.sh && sha256sum -c s\n"),
    "DOC-013": ("d", "FROM a:1\nCMD [\"a\"]\nCMD [\"b\"]\n", 3, "FROM a:1\nCMD [\"a\"]\nFROM b:1\nCMD [\"b\"]\n"),
    "DOC-014": ("d", "FROM a:1\nEXPOSE 22\n", 2, "FROM a:1\nEXPOSE 2222 8080\n"),
    "DOC-015": ("c", "services:\n  a:\n    image: x:1\n    privileged: true\n", 4, "services:\n  a:\n    image: x:1\n    privileged: false\n"),
    "DOC-016": ("c", "services:\n  a:\n    image: x:1\n    network_mode: host\n", 4, "services:\n  a:\n    image: x:1\n    network_mode: bridge\n"),
    "DOC-017": ("c", "services:\n  a:\n    image: x:1\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n", 5,
                "services:\n  a:\n    image: x:1\n    volumes:\n      - ./data:/data\n"),
    "DOC-018": ("c", "services:\n  a:\n    image: x:1\n    environment:\n      - DB_PASSWORD=abc12345\n", 5,
                "services:\n  a:\n    image: x:1\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n      DB_PASSWORD_FILE: /run/s\n"),
    "DOC-019": ("c", "services:\n  a:\n    image: redis\n", 3, "services:\n  a:\n    image: redis:7\n  b:\n    image: app\n    build: .\n"),
    "DOC-020": ("c", "services:\n  a:\n    image: x:1\n", 2, "services:\n  a:\n    image: x:1\n    restart: always\n"),
    "DOC-021": ("c", "services:\n  a:\n    image: x:1\n", 2, "services:\n  a:\n    image: x:1\n    healthcheck:\n      test: ['CMD', 'true']\n"),
    "DOC-022": ("c", "services:\n  a:\n    image: x:1\n    ports:\n      - \"5432:5432\"\n", 5,
                "services:\n  a:\n    image: x:1\n    ports:\n      - \"127.0.0.1:5432:5432\"\n      - \"8080:80\"\n"),
}


def run(kind, src):
    if kind == "c":
        return {(f.rule_id, f.evidence[0].line_start) for f in analyze_compose(src, "docker-compose.yml")}
    return {(f.rule_id, f.evidence[0].line_start) for f in analyze_dockerfile(src, "Dockerfile", kind != "n")}


def test_every_rule_has_a_case():
    assert set(CASES) == set(RULES)
    assert all(r.explanation and r.fix_hint and r.title for r in RULES.values())


@pytest.mark.parametrize("rule", sorted(CASES))
def test_positive(rule):
    kind, pos, line, _ = CASES[rule]
    assert (rule, line) in run(kind, pos)


@pytest.mark.parametrize("rule", sorted(CASES))
def test_negative(rule):
    kind, _, _, neg = CASES[rule]
    if kind == "n":
        assert "DOC-010" not in {r for r, _ in run("d", GOOD)}
    else:
        assert rule not in {r for r, _ in run(kind, neg)}


def test_clean_dockerfile():
    assert run("d", GOOD) == set()


def test_secret_value_never_printed():
    fs = analyze_dockerfile("FROM a:1\nENV DB_PASSWORD=hunter2hunter2\n", "Dockerfile")
    assert "hunter2" not in repr([f.to_dict() for f in fs])


def test_multistage_user_inherited_and_alias_from():
    src = "FROM python:3.12 AS base\nUSER app\nFROM base\nCMD x\n"
    assert "DOC-002" not in {r for r, _ in run("d", src)} and "DOC-001" not in {r for r, _ in run("d", src)}


def test_check_end_to_end(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "Dockerfile").write_text("FROM python\n")
    chk = DockerCheck()
    args = argparse.Namespace(check_docker=str(tmp_path), include_tests=False)
    assert chk.estimate(Context(no_snap=True), args).uploads_bytes == 0
    res = chk.run(Context(no_snap=True), args)
    assert {f.rule_id for f in res.findings} == {"DOC-001", "DOC-002", "DOC-010"} and res.stats["files"] == 1
    args.check_docker = str(tmp_path / "nope")
    assert chk.run(Context(no_snap=True), args).error
