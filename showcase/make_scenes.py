"""Regenerate showcase/{bin,demo_project,scenes,showcase.tape}. Numbers come from benchmarks/compare/RESULTS.md."""
from pathlib import Path
HERE = Path(__file__).parent
ROOT = HERE.parent
E = "\x1b"
B, RST = f"{E}[1m", f"{E}[0m"
RED, GRN, YEL, BLU, MAG, CYN, GRY = (f"{E}[38;5;{c}m" for c in (203, 114, 221, 111, 176, 116, 245))

def w(path, s, mode=None):
    p = HERE / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s)
    if mode: p.chmod(mode)

# shim: visible command is just `checksnap ...`
w("bin/checksnap", f'#!/bin/sh\nPYTHONPATH="{ROOT}" exec "{ROOT}/.venv/bin/python" -m checksnap "$@"\n', 0o755)

# tiny synthetic project (nothing real)
w("demo_project/app.py", '''import pickle
import subprocess
import requests

def load_model(path):
    return pickle.load(open(path, "rb"))

def fetch(url):
    return requests.get(url, verify=False).text

def list_dir(name):
    return subprocess.run(f"ls {name}", shell=True)
''')
w("demo_project/train.py", '''import torch

def train(model, loader, opt, loss_fn):
    for x, y in loader:
        opt.zero_grad()
        loss = loss_fn(model(x.cuda()), y.cuda())
        loss.backward()
        opt.step()
        print(loss.item())
''')
w("demo_project/Dockerfile", "FROM python:latest\nENV DB_PASSWORD=hunter2\nCOPY . /app\nRUN pip install -r /app/requirements.txt\nCMD [\"python\", \"/app/app.py\"]\n")
w("demo_project/.github/workflows/ci.yml", """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - uses: some-org/deploy-action@v2
      - run: echo "${{ github.event.pull_request.title }}"
""")

def card(*lines): return "\n\n\n" + "\n\n".join("   " + l for l in lines) + "\n"
w("scenes/hook.txt", card(f"{B}{RED}One CLI.{RST}", f"{B}A dozen things that quietly break your project.{RST}",
                          f"{GRY}checksnap: free local checks, optional SubQ Snap{RST}"))
w("scenes/security.txt", card(f"{B}{BLU}Security{RST}  {GRY}pickle, TLS off, shell=True{RST}"))
w("scenes/gate.txt", card(f"{B}{YEL}Privacy gate{RST}  {GRY}(offline demo, fake key, we answer n){RST}",
                          f"{GRY}Cost table first, then ask. Nothing leaves the machine.{RST}",
                          f"{GRY}Each Snap call carries 8 decoys + 1 canary to measure its own false-positive rate.{RST}"))
w("scenes/close.txt", card(f"{B}{GRN}Honest numbers{RST}  {GRY}benchmarks/compare/RESULTS.md{RST}",
    f"{GRN}+{RST} Claude plugin digest: 1.4-1.9 kB vs 80-140 kB raw output",
    f"{GRN}+{RST} Bank: 9/10 precision@10, 27/30 planted bugs found",
    f"{YEL}!{RST} Limit: security recall 28% of bandit's examples without --with-adapters",
    f"{B}github.com/Aras-sh/checksnap{RST}"))

def cmd(c, hold, pre=""):
    return f'''Hide
Type "clear" Enter
Show
Type "{c}" Sleep 500ms Enter
Sleep {hold}
'''
def scene(name, hold): return f'Hide\nType "clear; cat scenes/{name}.txt" Enter\nShow\nSleep {hold}\n'

tape = f'''Output showcase.mp4
Output showcase.gif
Set Shell "bash"
Set FontSize 22
Set Width 1400
Set Height 800
Set Padding 30
Set Theme "Catppuccin Mocha"
Set TypingSpeed 18ms
Set Framerate 20
Set WindowBar Colorful

Hide
Type "PS1='$ '; export PATH=$PWD/bin:$PATH; export PYTHONDONTWRITEBYTECODE=1; cd $PWD; clear" Enter
Show
Sleep 300ms

{scene("hook", "3s")}
Hide
Type "clear" Enter
Show
Type "checksnap --list-checks | cut -c1-92" Sleep 500ms Enter
Sleep 5s

{scene("security", "1s")}
Type "checksnap --check-security demo_project | cut -c1-92 | head -22" Sleep 500ms Enter
Sleep 6s

Hide
Type "clear" Enter
Show
Type "checksnap --check-optimization demo_project --static-only | cut -c1-92 | head -12" Sleep 500ms Enter
Sleep 4s

Hide
Type "clear" Enter
Show
Type "checksnap --check-docker demo_project | cut -c1-92 | head -10" Sleep 500ms Enter
Sleep 3500ms
Hide
Type "clear" Enter
Show
Type "checksnap --check-ci demo_project | cut -c1-92 | head -12" Sleep 500ms Enter
Sleep 4500ms

Hide
Type "export SUBQ_API_KEY=demo-not-a-real-key" Enter
Show
{scene("gate", "4s")}
Type "checksnap --check-dataset ../examples/dataset --benchmark ../examples/dataset/benchmark.jsonl" Sleep 500ms Enter
Sleep 4s
Type "n" Sleep 300ms Enter
Sleep 1500ms
Hide
Type "unset SUBQ_API_KEY" Enter
Show
Sleep 1s

{scene("close", "8s")}
'''
w("showcase.tape", tape)
