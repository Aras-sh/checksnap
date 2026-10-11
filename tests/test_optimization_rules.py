"""Every static rule: one positive and one negative fixture, checked for the right id and line."""
from __future__ import annotations

import pytest

from checksnap.checks.optimization import RULES
from checksnap.checks.optimization.static import ML, GENERAL, analyze

# rule id -> (positive source, expected line of the hit, negative source)
CASES = {
    "OPT-PY-001": ("s = ''\nfor x in xs:\n    s += str(x)\n", 3, "n = 0\nfor x in xs:\n    n += 1\nparts = []\nfor x in xs:\n    parts += [x]\n"),
    "OPT-PY-002": ("import re\nfor l in lines:\n    re.match('a+', l)\n", 3, "import re\nP = re.compile('a+')\nfor l in lines:\n    P.match(l)\n"),
    "OPT-PY-003": ("seen = []\nfor x in xs:\n    if x in seen:\n        pass\n", 3, "seen = set()\nfor x in xs:\n    if x in seen:\n        pass\n"),
    "OPT-PY-004": ("for i in range(len(xs)):\n    print(xs[i])\n", 1, "for i, x in enumerate(xs):\n    print(x)\n"),
    "OPT-PY-005": ("for x in xs:\n    d = open('cfg.txt').read()\n", 2, "for p in paths:\n    d = open(p).read()\n"),
    "OPT-PY-006": ("for x in xs:\n    acc.append(x)\n    acc.sort()\n", 3, "for row in rows:\n    sorted(row)\nacc.sort()\n"),
    "OPT-PY-007": ("import time\nasync def f():\n    time.sleep(1)\n", 3, "import time\ndef f():\n    time.sleep(1)\n"),
    "OPT-PY-008": ("for i in ids:\n    cur.execute('select 1')\n", 2, "cur.execute('select 1')\nfor r in cur.fetchall():\n    pass\n"),
    "OPT-PY-009": ("for i, r in df.iterrows():\n    pass\n", 1, "for r in df.itertuples():\n    pass\nx = df.apply(f, axis=0)\n"),
    "OPT-PY-010": ("import json\nfor x in xs:\n    c = json.load(open('c.json'))\n", 3, "import json\nc = json.load(open('c.json'))\nfor p in ps:\n    d = json.load(open(p))\n"),
    "OPT-PY-011": ("import functools\nclass A:\n    @functools.lru_cache(maxsize=None)\n    def f(self, x):\n        return x\n", 3,
                   "import functools\n@functools.lru_cache(maxsize=None)\ndef f(x):\n    return x\nclass A:\n    @functools.lru_cache(maxsize=32)\n    def g(self, x):\n        return x\n"),
    "OPT-PY-012": ("t = sum(list(xs))\n", 1, "t = sum(x for x in xs)\n"),
    "OPT-PY-013": ("while q:\n    x = q.pop(0)\n", 2, "while q:\n    x = q.pop()\nd = {}\nfor k in ks:\n    d.pop(k)\n"),
    "OPT-ML-001": ("import torch\nfor x, y in dl:\n    loss = f(x)\n    loss.backward()\n    opt.step()\n    print(loss.item())\n", 6,
                   "import torch\nfor x, y in dl:\n    loss = f(x)\n    loss.backward()\n    opt.step()\n    if i % 100 == 0:\n        print(loss.item())\n"),
    "OPT-ML-002": ("import torch\nfrom torch.utils.data import DataLoader\ndl = DataLoader(ds, batch_size=8)\n", 3,
                   "from torch.utils.data import DataLoader\ndl = DataLoader(ds, num_workers=4, pin_memory=True, persistent_workers=True)\n"),
    "OPT-ML-003": ("import torch\nfor x in dl:\n    loss.backward()\n", 2,
                   "import torch\nfor x in dl:\n    with torch.autocast('cuda'):\n        out = m(x)\n    loss.backward()\n"),
    "OPT-ML-004": ("import torch\ndef evaluate(m, dl):\n    for x in dl:\n        m(x)\n", 2,
                   "import torch\n@torch.no_grad()\ndef evaluate(m, dl):\n    for x in dl:\n        m(x)\n"),
    "OPT-ML-005": ("import torch\nfor i in range(t.shape[0]):\n    s = t[i] * 2\n", 2, "import torch\nfor i in range(t.shape[0]):\n    print(i)\n"),
    "OPT-ML-006": ("import torch\nfor x in dl:\n    m = torch.zeros(3).to(dev)\n    loss.backward()\n", 3,
                   "import torch\nfor x in dl:\n    m = torch.zeros(3, device=dev)\n    loss.backward()\n"),
    "OPT-ML-007": ("import torch\ndl = DataLoader(d, pin_memory=True)\nfor x in dl:\n    x = x.to(dev)\n    loss.backward()\n", 4,
                   "import torch\ndl = DataLoader(d, pin_memory=True)\nfor x in dl:\n    x = x.to(dev, non_blocking=True)\n    loss.backward()\n"),
    "OPT-ML-008": ("import torch\nfor x in dl:\n    torch.cuda.synchronize()\n", 3, "import torch\ntorch.cuda.synchronize()\n"),
    "OPT-ML-009": ("import torch\nfor x in dl:\n    loss.backward()\n    torch.save(m.state_dict(), 'a.pt')\n", 4,
                   "import torch\nfor x in dl:\n    loss.backward()\n    if step % 500 == 0:\n        torch.save(m.state_dict(), 'a.pt')\n"),
    "OPT-ML-010": ("import torch\nopt.zero_grad()\n", 2, "import torch\nopt.zero_grad(set_to_none=True)\n"),
    "OPT-ML-011": ("import torch.nn as nn\nc = nn.Conv2d(64, 64, 3, groups=64)\n", 2, "import torch.nn as nn\nc = nn.Conv2d(64, 64, 3)\n"),
    "OPT-ML-012": ("import torch\nfrom torch.nn.utils.rnn import pad_sequence\ntorch.backends.cudnn.benchmark = True\n", 3,
                   "import torch\ntorch.backends.cudnn.benchmark = True\n"),
    "OPT-ML-013": ("import torch, numpy as np\nt = torch.from_numpy(np.zeros(3))\n", 2,
                   "import torch, numpy as np\nt = torch.from_numpy(np.zeros(3, dtype=np.float32))\n"),
}


def test_every_rule_has_a_case_and_a_catalog_entry():
    ids = {r for r, _ in GENERAL + ML}
    assert ids == set(CASES)
    assert ids <= set(RULES)
    assert len([i for i in ids if "-PY-" in i]) >= 12 and len([i for i in ids if "-ML-" in i]) >= 10
    assert sum(1 for r in RULES.values() if r.needs_snap) >= 25


@pytest.mark.parametrize("rule", sorted(CASES))
def test_positive(rule):
    pos, line, _ = CASES[rule]
    hits = [f for f in analyze(pos, "x.py") if f.rule_id == rule]
    assert hits, f"{rule} did not fire"
    assert hits[0].evidence[0].line_start == line and hits[0].fix_hint and hits[0].source == "static"


@pytest.mark.parametrize("rule", sorted(CASES))
def test_negative(rule):
    _, _, neg = CASES[rule]
    assert not [f for f in analyze(neg, "x.py") if f.rule_id == rule]


def test_profile_switches():
    src = CASES["OPT-ML-010"][0]
    assert any(f.rule_id == "OPT-ML-010" for f in analyze(src, "x.py", "auto"))
    assert not any(f.rule_id.startswith("OPT-ML") for f in analyze(src, "x.py", "general"))
    assert any(f.rule_id == "OPT-ML-010" for f in analyze("opt.zero_grad()\n", "x.py", "ml"))
    assert not any(f.rule_id.startswith("OPT-ML") for f in analyze("opt.zero_grad()\n", "x.py", "auto"))


def test_comprehension_first_iterable_is_not_a_loop():
    assert not analyze("ys = [x for x in sorted(xs)]\n", "x.py")
    assert any(f.rule_id == "OPT-PY-006" for f in analyze("ys = [sorted(xs) for _ in range(3)]\n", "x.py"))


def test_syntax_error_raises():
    with pytest.raises(SyntaxError):
        analyze("def (:\n", "bad.py")
