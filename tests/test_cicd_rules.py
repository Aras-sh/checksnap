"""Every CI rule: one positive (right id, right line) and one negative source."""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from checksnap.checks.cicd import CICheck, RULES
from checksnap.checks.cicd.scan import analyze
from checksnap.core import Context

SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


def gh(body: str, head: str = "permissions: read-all\n") -> str:
    """A workflow with one job `build` (timeout set) so only the rule under test fires."""
    return f"name: t\non: push\n{head}jobs:\n  build:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n{body}"


def run(cmd: str) -> str:
    return gh(f"      - run: {cmd}\n")


# rule -> (positive source, line, negative source, filename)
GL = ".gitlab-ci.yml"
CASES = {
    "CI-001": (gh(f"      - uses: actions/checkout@v4\n"), 9, gh(f"      - uses: actions/checkout@{SHA}\n      - uses: ./local\n"), "w.yml"),
    "CI-002": (gh("      - uses: foo/bar@main\n"), 9, gh("      - uses: foo/bar@v1.2.3\n"), "w.yml"),
    "CI-003": ("on: pull_request_target\npermissions: read-all\njobs:\n  a:\n    timeout-minutes: 1\n    steps:\n      - uses: actions/checkout@%s\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n" % SHA, 9,
               "on: pull_request\npermissions: read-all\njobs:\n  a:\n    timeout-minutes: 1\n    steps:\n      - uses: actions/checkout@%s\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n" % SHA, "w.yml"),
    "CI-004": (run("echo ${{ github.event.issue.title }}"), 9, run("echo ${{ github.sha }} ${{ github.event.repository.name }}"), "w.yml"),
    "CI-005": (gh("      - run: ls\n", head=""), 4, gh("      - run: ls\n"), "w.yml"),
    "CI-006": (gh("      - run: ls\n", head="permissions: write-all\n"), 3, gh("      - run: ls\n", head="permissions:\n  contents: read\n"), "w.yml"),
    "CI-007": (run('echo "${{ secrets.TOKEN }}"'), 9, run('echo "${{ secrets.TOKEN }}" | docker login --password-stdin'), "w.yml"),
    "CI-008": ("permissions: read-all\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: ls\n", 3, "permissions: read-all\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 3\n    steps:\n      - run: ls\n", "w.yml"),
    "CI-009": ("permissions: read-all\njobs:\n  deploy:\n    timeout-minutes: 3\n    steps:\n      - run: ls\n", 3, "permissions: read-all\nconcurrency: x\njobs:\n  deploy:\n    timeout-minutes: 3\n    steps:\n      - run: ls\n", "w.yml"),
    "CI-010": (run("curl -sSL https://x.sh | sudo bash"), 9, run("curl -sSLo x.sh https://x.sh && sha256sum -c x.sum"), "w.yml"),
    "CI-011": (gh("      - name: Run tests\n        run: pytest\n        continue-on-error: true\n"), 11, gh("      - name: Experimental\n        run: ./try.sh\n        continue-on-error: true\n"), "w.yml"),
    "CI-012": (run("npm ci"), 9, gh("      - uses: actions/setup-node@%s\n        with:\n          cache: npm\n      - run: npm ci\n" % SHA), "w.yml"),
    "CI-013": (run('echo "::set-output name=a::b"'), 9, run('echo "a=b" >> "$GITHUB_OUTPUT"'), "w.yml"),
    "CI-014": (gh("      - run: ls\n").replace("ubuntu-24.04", "ubuntu-latest"), 6, gh("      - run: ls\n"), "w.yml"),
    "CI-015": (gh("      - run: a\n" * 8 + "      - run: pytest\n"), 5, gh("      - run: a\n" * 8 + "      - run: pytest\n").replace("    steps:", "    strategy:\n      matrix:\n        py: ['3.11']\n    steps:"), "w.yml"),
    "CI-016": ("image: python:latest\nbuild:\n  script:\n    - make\n", 1, "image: python:3.12\nbuild:\n  script:\n    - make\n", GL),
    "CI-017": ("deploy_prod:\n  script:\n    - ./deploy.sh\n", 1, "deploy_prod:\n  script:\n    - ./deploy.sh\n  rules:\n    - if: $CI_COMMIT_BRANCH == \"main\"\n", GL),
    "CI-018": ("variables:\n  DB_PASSWORD: hunter2hunter2\n", 2, "variables:\n  DB_PASSWORD: $DB_PASSWORD\n  API_TOKEN: \"\"\n  TOKEN_URL: https://x\n", GL),
}


def ids(src, fn):
    return {(f.rule_id, f.evidence[0].line_start) for f in analyze(src, fn)}


def test_every_rule_has_a_case():
    assert set(CASES) == set(RULES)
    assert all(r.explanation and r.fix_hint and r.title for r in RULES.values())


@pytest.mark.parametrize("rule", sorted(CASES))
def test_positive(rule):
    pos, line, _, fn = CASES[rule]
    assert (rule, line) in ids(pos, fn)


@pytest.mark.parametrize("rule", sorted(CASES))
def test_negative(rule):
    assert rule not in {r for r, _ in ids(CASES[rule][2], CASES[rule][3])}


def test_clean_workflow_has_no_findings():
    assert analyze(Path("tests/fixtures/cicd/good.yml").read_text(), "w.yml") == []


def test_secret_value_never_reported():
    fs = analyze("variables:\n  DB_PASSWORD: hunter2hunter2\n", GL)
    assert "hunter2" not in repr([f.to_dict() for f in fs])


def test_check_end_to_end(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(Path("tests/fixtures/cicd/bad.yml").read_text())
    (tmp_path / "other.yml").write_text("permissions: write-all\n")      # outside workflows: ignored
    res = CICheck().run(Context(no_snap=True), argparse.Namespace(check_ci=str(tmp_path)))
    got = {f.rule_id for f in res.findings}
    assert {"CI-003", "CI-004", "CI-002"} - got == {"CI-002"} and "CI-006" not in got
    assert res.stats["files"] == 1 and res.error is None
    assert CICheck().run(Context(no_snap=True), argparse.Namespace(check_ci=str(tmp_path / "nope"))).error
