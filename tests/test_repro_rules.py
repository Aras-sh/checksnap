"""Every REP rule: one positive and one negative source, checked for the right id and line."""
from __future__ import annotations

import argparse

import pytest

from checksnap.checks.repro import RULES, ReproCheck
from checksnap.checks.repro.analyze import analyze_project
from checksnap.core import Context

SEEDED = "import random, numpy as np, torch\nrandom.seed(0)\nnp.random.seed(0)\ntorch.manual_seed(0)\ntorch.backends.cudnn.deterministic = True\n"

# rule -> (positive source, expected line, negative source)
CASES = {
    "REP-001": ("import random\nx = random.random()\n", 2, "import random\nrandom.seed(1)\nx = random.random()\n"),
    "REP-002": ("import numpy as np\nx = np.random.rand(3)\n", 2, "import numpy as np\nrng = np.random.default_rng(3)\nnp.random.seed(1)\nx = np.random.rand(3)\n"),
    "REP-003": ("import torch\nx = torch.randn(3)\n", 2, "import torch\ntorch.manual_seed(0)\nx = torch.randn(3)\n"),
    "REP-004": ("import tensorflow as tf\nx = tf.random.normal([2])\n", 2, "import tensorflow as tf\ntf.random.set_seed(0)\nx = tf.random.normal([2])\n"),
    "REP-005": ("import random\nx = random.random()\nrandom.seed(0)\n", 3, "import random\nrandom.seed(0)\nx = random.random()\n"),
    "REP-006": ("import torch\ntorch.backends.cudnn.benchmark = True\n", 2, "import torch\ntorch.backends.cudnn.benchmark = False\n"),
    "REP-007": ("import torch\nx = torch.randn(3)\n", 2, "import torch\ntorch.backends.cudnn.deterministic = True\nx = torch.randn(3)\n"),
    "REP-008": ("from torch.utils.data import DataLoader\nd = DataLoader(ds, shuffle=True)\n", 2,
                "from torch.utils.data import DataLoader\nd = DataLoader(ds, shuffle=True, generator=g)\ne = DataLoader(ds)\n"),
    "REP-009": ("import os\nfs = os.listdir('d')\nfor f in fs:\n    pass\n", 2,
                "import os\nfs = sorted(os.listdir('d'))\ngs = os.listdir('e')\ngs.sort()\n"),
    "REP-010": ("for x in set(items):\n    pass\n", 1, "for x in sorted(set(items)):\n    pass\n"),
    "REP-011": ("d = {}\nk = d.popitem()\n", 2, "d = {}\nk = d.pop('a')\nh = hash(1)\n"),
    "REP-012": ("from datetime import datetime\nout = f'runs/{datetime.now():%Y}'\n", 2,
                "import time\nfrom datetime import datetime\nt0 = time.time()\nprint(f'took {time.time() - t0}')\nstart = datetime.now()\n"),
    "REP-018": ("import torch\nx.index_add_(0, i, y)\n", 2, "import torch\nx.index_add_(0, i, y)\ntorch.use_deterministic_algorithms(True)\n"),
}


def ids(findings):
    return {f.rule_id: f.evidence[0].line_start if f.evidence else None for f in findings}


@pytest.mark.parametrize("rule", sorted(CASES))
def test_rule(rule):
    pos, line, neg = CASES[rule]
    assert ids(analyze_project({"a.py": pos}, project_files=False)[0]).get(rule) == line
    assert rule not in ids(analyze_project({"a.py": neg}, project_files=False)[0])


def test_seeder_helper_seeds_everything():
    src = "import random, torch\nfrom lightning import seed_everything\nseed_everything(1)\nrandom.random()\ntorch.randn(1)\n"
    got = ids(analyze_project({"a.py": src}, project_files=False)[0])
    assert not {"REP-001", "REP-003", "REP-005"} & set(got)


def test_generator_seed_is_not_global_seed():
    src = "import torch\ng = torch.Generator().manual_seed(1)\nx = torch.randn(3)\n"
    assert "REP-003" in ids(analyze_project({"a.py": src}, project_files=False)[0])


def _proj(py_extra=None, other=None, src="import numpy\nimport requests\n"):
    return ids(analyze_project({"a.py": src, **(py_extra or {})}, other or {})[0])


def test_rep013_unpinned_and_negative():
    assert "REP-013" in _proj(other={"requirements.txt": "numpy>=1\n"})
    assert "REP-013" not in _proj(other={"requirements.txt": "numpy==1.2\n# c\n-r other.txt\n"})
    assert "REP-013" in _proj(other={"pyproject.toml": '[project]\nname="x"\ndependencies=["numpy"]\n'})


def test_rep014_no_manifest():
    assert "REP-014" in _proj()
    assert "REP-014" not in _proj(other={"requirements.txt": "requests==1\n"})
    assert "REP-014" not in _proj(src="import os\nimport json\n")


def test_rep015_lockfile():
    assert "REP-015" in _proj(other={"requirements.txt": "numpy>=1\n"})
    assert "REP-015" not in _proj(other={"requirements.txt": "numpy>=1\n", "uv.lock": ""})
    assert "REP-015" not in _proj(other={"requirements.txt": "numpy==1\n"})


def test_rep016_017_provenance():
    ml = "import torch\n"
    got = _proj(src=ml)
    assert "REP-016" in got and "REP-017" in got
    ok = ml + "import subprocess\nc = subprocess.check_output(['git', 'rev-parse', 'HEAD'])\nsave_config(args)\n"
    got = _proj(src=ok)
    assert "REP-016" not in got and "REP-017" not in got
    assert "REP-016" not in _proj(src=ml + "import wandb\n")
    assert "REP-016" not in _proj(src="import os\n")


def test_every_rule_has_a_case():
    covered = set(CASES) | {"REP-013", "REP-014", "REP-015", "REP-016", "REP-017"}
    assert covered == set(RULES) and len(RULES) == 18
    for r in RULES.values():
        assert r.explanation and r.fix_hint and r.title


def test_check_runs_on_fixtures_and_good_is_clean(tmp_path):
    c = ReproCheck()
    args = argparse.Namespace(check_reproducibility="tests/fixtures/repro/bad", check_all=None)
    bad = c.run(Context(no_snap=True), args)
    assert len(bad.stats["by_rule"]) >= 10 and bad.usage["snap_calls"] == 0
    args.check_reproducibility = "tests/fixtures/repro/good"
    assert [f.rule_id for f in c.run(Context(no_snap=True), args).findings] == []
    args.check_reproducibility = str(tmp_path / "nope")
    assert c.run(Context(no_snap=True), args).error
    assert c.estimate(Context(), args).snap_calls == 0
