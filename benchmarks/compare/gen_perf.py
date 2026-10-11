"""40 hand-written slow snippets (bug line marked `# BUG`, stripped on write) and 40 clean idiomatic snippets.
First 28 target rule families that checksnap documents; the 12 `O_*` are real perf/smell issues OUTSIDE checksnap's
documented rules (included so comparators get a fair shot)."""
import json, sys
from pathlib import Path

BUG = {
"concat_loop": "def f(rows):\n    out = ''\n    for r in rows:\n        out += str(r) + ','  # BUG\n    return out\n",
"concat_while": "def f(parts):\n    s = ''\n    i = 0\n    while i < len(parts):\n        s = s + parts[i]  # BUG\n        i += 1\n    return s\n",
"regex_loop": "import re\n\ndef f(lines):\n    res = []\n    for l in lines:\n        res.append(re.findall(r'\\d+', l))  # BUG\n    return res\n",
"regex_loop2": "import re\n\ndef count(lines):\n    n = 0\n    for l in lines:\n        if re.match(r'^ERROR', l):  # BUG\n            n += 1\n    return n\n",
"member_list": "def f(items, banned):\n    banned_list = ['a', 'b', 'c', 'd']\n    out = []\n    for x in items:\n        if x in banned_list:  # BUG\n            continue\n        out.append(x)\n    return out\n",
"member_list2": "def dedupe(xs):\n    seen = []\n    for x in xs:\n        if x not in seen:  # BUG\n            seen.append(x)\n    return seen\n",
"rangelen": "def f(xs):\n    total = 0\n    for i in range(len(xs)):  # BUG\n        total += xs[i]\n    return total\n",
"file_in_loop": "def f(keys):\n    res = []\n    for k in keys:\n        with open('table.txt') as fh:  # BUG\n            res.append(k in fh.read())\n    return res\n",
"sort_in_loop": "def f(groups):\n    for g in groups:\n        g.append(1)\n        g.sort()  # BUG\n    return groups\n",
"sort_in_loop2": "def top(data):\n    best = []\n    for x in data:\n        best.append(x)\n        best = sorted(best)[:3]  # BUG\n    return best\n",
"async_sleep": "import time\n\nasync def handler():\n    time.sleep(2)  # BUG\n    return 1\n",
"async_requests": "import requests\n\nasync def fetch(u):\n    r = requests.get(u, timeout=5)  # BUG\n    return r.text\n",
"nplus1": "def f(cur, ids):\n    out = []\n    for i in ids:\n        cur.execute('SELECT * FROM t WHERE id = %s', (i,))  # BUG\n        out.append(cur.fetchone())\n    return out\n",
"nplus1_orm": "def f(session, users):\n    for u in users:\n        u.orders = session.query(Order).filter(Order.user_id == u.id).all()  # BUG\n    return users\n",
"iterrows": "def f(df):\n    total = 0\n    for _, row in df.iterrows():  # BUG\n        total += row['a'] * row['b']\n    return total\n",
"apply_axis1": "def f(df):\n    return df.apply(lambda r: r['a'] + r['b'], axis=1)  # BUG\n",
"json_loop": "import json\n\ndef f(names):\n    out = []\n    for n in names:\n        cfg = json.load(open('config.json'))  # BUG\n        out.append(cfg[n])\n    return out\n",
"lru_method": "from functools import lru_cache\n\nclass A:\n    @lru_cache(maxsize=None)  # BUG\n    def g(self, x):\n        return x * 2\n",
"list_copy_sum": "def f(xs):\n    return sum(list(x * 2 for x in xs))  # BUG\n",
"pop0": "def f(q):\n    out = []\n    while q:\n        out.append(q.pop(0))  # BUG\n    return out\n",
"item_loop": "import torch\n\ndef train(m, loader, opt):\n    for x in loader:\n        loss = m(x)\n        loss.backward()\n        opt.step()\n        print(loss.item())  # BUG\n",
"dataloader": "from torch.utils.data import DataLoader\n\ndef mk(ds):\n    return DataLoader(ds, batch_size=32, shuffle=True)  # BUG\n",
"no_amp": "import torch\n\ndef train(m, loader, opt):\n    for x, y in loader:\n        opt.zero_grad()\n        loss = m(x).sum()\n        loss.backward()  # BUG\n        opt.step()\n",
"no_grad": "def evaluate(model, loader):\n    model.eval()\n    outs = []\n    for x in loader:\n        outs.append(model(x))  # BUG\n    return outs\n",
"tensor_loop": "import torch\n\ndef f(t):\n    s = 0.0\n    for i in range(t.shape[0]):  # BUG\n        s += t[i]\n    return s\n",
"cpu_tensor": "import torch\n\ndef step(model, dev):\n    for _ in range(100):\n        x = torch.randn(32, 3).to(dev)  # BUG\n        model(x)\n",
"zero_grad": "def train(opt, steps):\n    for _ in steps:\n        opt.zero_grad()  # BUG\n        opt.step()\n",
"ckpt_step": "import torch\n\ndef train(model, loader, opt):\n    for i, x in enumerate(loader):\n        opt.step()\n        torch.save(model.state_dict(), 'ck.pt')  # BUG\n",
"O_manual_listcomp": "def f(xs):\n    out = []\n    for x in xs:  # BUG\n        out.append(x * 2)\n    return out\n",
"O_manual_copy": "def f(xs):\n    out = []\n    for x in xs:  # BUG\n        out.append(x)\n    return out\n",
"O_try_loop": "def f(xs):\n    out = []\n    for x in xs:\n        try:  # BUG\n            out.append(int(x))\n        except ValueError:\n            continue\n    return out\n",
"O_keys_iter": "def f(d):\n    for k in d.keys():  # BUG\n        print(k, d[k])\n",
"O_unnecessary_listcomp": "def f(xs):\n    return any([x > 3 for x in xs])  # BUG\n",
"O_sorted_first": "def f(xs):\n    return sorted(xs)[0]  # BUG\n",
"O_len_zero": "def f(xs):\n    if len(xs) == 0:  # BUG\n        return None\n    return xs[0]\n",
"O_dict_in_loop": "def f(xs):\n    out = {}\n    for x in xs:\n        out = {**out, x: 1}  # BUG\n    return out\n",
"O_listcomp_set": "def f(xs):\n    return set([x % 7 for x in xs])  # BUG\n",
"O_repeat_len": "def f(xs):\n    i = 0\n    while i < len(xs):  # BUG\n        if len(xs) > 100 and xs[i]:\n            pass\n        i += 1\n",
"O_readlines": "def f(p):\n    with open(p) as fh:\n        for line in fh.readlines():  # BUG\n            print(line)\n",
"O_unneeded_gen": "def f(xs):\n    return list(map(lambda x: x + 1, xs))  # BUG\n",
}

CLEAN = [
"def f(rows):\n    return ','.join(str(r) for r in rows)\n",
"import re\n\nPAT = re.compile(r'\\d+')\n\ndef f(lines):\n    return [PAT.findall(l) for l in lines]\n",
"def f(items, banned):\n    banned_set = {'a', 'b', 'c'}\n    return [x for x in items if x not in banned_set]\n",
"def f(xs):\n    return sum(xs)\n",
"def f(a, b):\n    return [x * y for x, y in zip(a, b)]\n",
"def f(xs):\n    for i, x in enumerate(xs):\n        print(i, x)\n",
"import json\n\nCFG = json.load(open('config.json'))\n\ndef f(names):\n    return [CFG[n] for n in names]\n",
"def f(groups):\n    for g in groups:\n        g.append(1)\n    return [sorted(g) for g in groups]\n",
"import asyncio\n\nasync def handler():\n    await asyncio.sleep(2)\n    return 1\n",
"def f(cur, ids):\n    cur.execute('SELECT * FROM t WHERE id = ANY(%s)', (list(ids),))\n    return cur.fetchall()\n",
"def f(df):\n    return (df['a'] * df['b']).sum()\n",
"from functools import lru_cache\n\n@lru_cache(maxsize=128)\ndef g(x):\n    return x * 2\n",
"from collections import deque\n\ndef f(q):\n    d = deque(q)\n    out = []\n    while d:\n        out.append(d.popleft())\n    return out\n",
"import torch\n\ndef train(m, loader, opt):\n    total = 0.0\n    for x in loader:\n        loss = m(x)\n        loss.backward()\n        opt.step()\n        total += loss.detach()\n    return total\n",
"from torch.utils.data import DataLoader\n\ndef mk(ds):\n    return DataLoader(ds, batch_size=32, shuffle=True, num_workers=4, pin_memory=True)\n",
"import torch\n\n@torch.no_grad()\ndef evaluate(model, loader):\n    model.eval()\n    return [model(x) for x in loader]\n",
"import torch\n\ndef f(t):\n    return t.sum()\n",
"import torch\n\ndef step(model, dev):\n    for _ in range(100):\n        x = torch.randn(32, 3, device=dev)\n        model(x)\n",
"def train(opt, steps):\n    for _ in steps:\n        opt.zero_grad(set_to_none=True)\n        opt.step()\n",
"import torch\n\ndef train(model, loader, opt):\n    for i, x in enumerate(loader):\n        opt.step()\n    torch.save(model.state_dict(), 'ck.pt')\n",
"def f(xs):\n    return [x * 2 for x in xs]\n",
"def f(d):\n    for k, v in d.items():\n        print(k, v)\n",
"def f(xs):\n    return min(xs)\n",
"def f(xs):\n    if not xs:\n        return None\n    return xs[0]\n",
"def f(xs):\n    return {x: 1 for x in xs}\n",
"def f(p):\n    with open(p) as fh:\n        for line in fh:\n            print(line.rstrip())\n",
"def f(xs):\n    return [x + 1 for x in xs]\n",
"from dataclasses import dataclass\n\n@dataclass\nclass P:\n    x: float\n    y: float\n\n    def norm(self) -> float:\n        return (self.x ** 2 + self.y ** 2) ** 0.5\n",
"import logging\n\nlog = logging.getLogger(__name__)\n\ndef f(x):\n    try:\n        return int(x)\n    except ValueError:\n        log.warning('bad value %s', x)\n        return None\n",
"import argparse\n\ndef main():\n    ap = argparse.ArgumentParser()\n    ap.add_argument('--n', type=int, default=3)\n    args = ap.parse_args()\n    print(args.n)\n\nif __name__ == '__main__':\n    main()\n",
"from pathlib import Path\n\ndef read_all(root):\n    return {p.name: p.read_text() for p in Path(root).glob('*.txt')}\n",
"import csv\n\ndef load(path):\n    with open(path, newline='') as fh:\n        return list(csv.DictReader(fh))\n",
"import itertools\n\ndef pairs(xs):\n    return list(itertools.combinations(xs, 2))\n",
"from collections import Counter\n\ndef top(words, n=3):\n    return Counter(words).most_common(n)\n",
"import heapq\n\ndef top(data, k=3):\n    return heapq.nlargest(k, data)\n",
"import time\n\ndef timed(fn):\n    def wrap(*a, **k):\n        t = time.perf_counter()\n        r = fn(*a, **k)\n        print(time.perf_counter() - t)\n        return r\n    return wrap\n",
"import numpy as np\n\ndef norm(x):\n    return (x - x.mean(axis=0)) / x.std(axis=0)\n",
"import torch\n\ndef train(m, loader, opt, scaler):\n    for x, y in loader:\n        with torch.autocast('cuda'):\n            loss = m(x).sum()\n        scaler.scale(loss).backward()\n        scaler.step(opt)\n        scaler.update()\n",
"def chunked(xs, n):\n    return [xs[i:i + n] for i in range(0, len(xs), n)]\n",
"class Stack:\n    def __init__(self):\n        self._d = []\n\n    def push(self, x):\n        self._d.append(x)\n\n    def pop(self):\n        return self._d.pop()\n",
]


def main(out: Path):
    bd, cd = out / "perf" / "bug", out / "perf" / "clean"
    bd.mkdir(parents=True, exist_ok=True); cd.mkdir(parents=True, exist_ok=True)
    truth = {}
    assert len(BUG) == 40 and len(CLEAN) == 40, (len(BUG), len(CLEAN))
    for n, src in BUG.items():
        lines = [i + 1 for i, l in enumerate(src.splitlines()) if "# BUG" in l]
        assert lines, n
        (bd / f"{n}.py").write_text(src.replace("  # BUG", ""))
        truth[f"{n}.py"] = {"lines": lines, "in_scope": not n.startswith("O_")}
    for i, src in enumerate(CLEAN):
        (cd / f"clean_{i:02d}.py").write_text(src)
    (out / "perf" / "truth.json").write_text(json.dumps(truth, indent=1))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
