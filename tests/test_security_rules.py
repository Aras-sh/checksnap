"""Every security rule: one positive (right id, right line) and one negative source; secrets are never printed in full."""
from __future__ import annotations

import argparse

import pytest

from checksnap.checks.security import RULES, SecurityCheck
from checksnap.checks.security.scan import analyze
from checksnap.core import Context

KEY = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2"
# rule id -> (positive source, expected line, negative source)
CASES = {
    "SEC-001": ("import torch\nm = torch.load('a.pt')\n", 2, "import torch\nm = torch.load('a.pt', weights_only=True)\nimport json\njson.load(f)\n"),
    "SEC-002": ("import yaml\nd = yaml.load(f)\n", 2, "import yaml\nd = yaml.load(f, Loader=yaml.SafeLoader)\nd = yaml.safe_load(f)\n"),
    "SEC-003": ("x = eval(s)\n", 1, "import ast\nx = ast.literal_eval(s)\nm.eval()\ny = eval('1+1')\n"),
    "SEC-004": ("import subprocess\nsubprocess.run(f'ls {p}', shell=True)\n", 2, "import subprocess\nsubprocess.run('ls', shell=True)\nsubprocess.run(['ls', p])\n"),
    "SEC-005": ("import os\nos.system('ls ' + p)\n", 2, "import subprocess\nsubprocess.run(['ls'])\n"),
    "SEC-006": (f"API_KEY = '{KEY}'\n", 1, "API_KEY = os.environ['API_KEY']\npassword = '<your password>'\nmax_tokens = 'abcdefghijkl'\n"),
    "SEC-007": ("import tempfile\nn = tempfile.mktemp()\n", 2, "import tempfile\nn = tempfile.mkstemp()\n"),
    "SEC-008": ("import requests\nrequests.get(u, verify=False)\n", 2, "import requests\nrequests.get(u, verify=True)\n"),
    "SEC-009": ("def f(x):\n    assert x > 0\n", 2, "def f(x):\n    if x <= 0:\n        raise ValueError\nassert 1 == 1\n"),
    "SEC-010": ("import tarfile\nt = tarfile.open('a')\nt.extractall('d')\n", 3, "import tarfile\nt = tarfile.open('a')\nt.extractall('d', filter='data')\n"),
    "SEC-011": ("cur.execute(f'SELECT * FROM t WHERE id={i}')\n", 1, "cur.execute('SELECT * FROM t WHERE id=?', (i,))\n"),
    "SEC-012": ("app.run(debug=True)\n", 1, "app.run(debug=False)\n"),
    "SEC-013": ("app.run(host='0.0.0.0')\n", 1, "app.run(host='127.0.0.1')\n"),
    "SEC-014": ("import hashlib\nh = hashlib.md5(b)\n", 2, "import hashlib\nh = hashlib.md5(b, usedforsecurity=False)\nh = hashlib.sha256(b)\n"),
    "SEC-015": ("import os\nos.chmod(p, 0o777)\n", 2, "import os\nos.chmod(p, 0o600)\n"),
}


def ids(src):
    return {(f.rule_id, f.evidence[0].line_start) for f in analyze(src, "a.py")}


def test_every_rule_has_a_case():
    assert set(CASES) == set(RULES)
    assert all(r.explanation and r.fix_hint and r.title for r in RULES.values())


@pytest.mark.parametrize("rule", sorted(CASES))
def test_positive(rule):
    pos, line, _ = CASES[rule]
    assert (rule, line) in ids(pos)


@pytest.mark.parametrize("rule", sorted(CASES))
def test_negative(rule):
    assert rule not in {r for r, _ in ids(CASES[rule][2])}


def test_aliases_resolved():
    assert ("SEC-014", 2) in ids("from hashlib import md5\nmd5(b)\n")


def test_secret_masked_everywhere():
    fs = analyze(f"API_KEY = '{KEY}'\nx = requests.get(u, headers={{'a': '{KEY}'}}, verify=False)\n", "a.py")
    assert {f.rule_id for f in fs} >= {"SEC-006", "SEC-008"}
    blob = repr([f.to_dict() for f in fs])
    assert KEY not in blob and "sk-A" in blob and "len 27" in blob


def test_token_regex_in_non_python_file():
    fs = analyze("token: ghp_" + "a" * 36 + "\n", "ci.yml")
    assert [f.rule_id for f in fs] == ["SEC-006"] and "ghp_aaaa" not in repr(fs).replace("ghp_****", "")


def test_check_end_to_end(tmp_path):
    (tmp_path / "a.py").write_text("import os\nos.system('x' + y)\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("eval(x)\n")
    (tmp_path / "bad.py").write_text("def (:\n")
    chk = SecurityCheck()
    args = argparse.Namespace(check_security=str(tmp_path), include_tests=False)
    assert chk.estimate(Context(no_snap=True), args).uploads_bytes == 0
    res = chk.run(Context(no_snap=True), args)
    assert [f.rule_id for f in res.findings] == ["SEC-005"] and res.error is None
    assert any("bad.py" in n for n in res.notes)
    args.check_security = str(tmp_path / "nope")
    assert chk.run(Context(no_snap=True), args).error
