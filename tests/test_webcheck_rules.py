"""Every web rule: one positive (right id) and one negative source."""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from checksnap.checks.webcheck import RULES, WebCheck
from checksnap.checks.webcheck.scan import analyze
from checksnap.core import Context

FIX = Path(__file__).parent / "fixtures" / "webcheck"
GOOD_HEAD = ('<html lang="en"><head><title>t</title><meta name="viewport" content="x"><meta name="description" content="d">'
             '<link rel="icon" href="/f.ico"><link rel="canonical" href="https://e.com/">')
PAGE = GOOD_HEAD + "</head><body>%s</body></html>"
HTTPS = '<link rel="canonical" href="https://e.com/">'
B64 = "data:image/png;base64," + "A" * 140_000

# rule -> (positive, negative, filename)
CASES = {
    "WEB-001": (PAGE % '<img src=a width=1 height=1>', PAGE % '<img src=a alt="" width=1 height=1>', "a.html"),
    "WEB-002": ("<html><head><title>t</title></head></html>", '<html lang="en"><head><title>t</title></head></html>', "a.html"),
    "WEB-003": ('<html lang="en"><head></head></html>', '<html lang="en"><head><title>t</title></head></html>', "a.html"),
    "WEB-004": ('<html lang="en"><head><title>t</title></head></html>', PAGE % "", "a.html"),
    "WEB-005": ('<html lang="en"><head><title>t</title></head></html>', PAGE % "", "a.html"),
    "WEB-006": (PAGE % '<input id="q">', PAGE % '<label for="q">Q</label><input id="q"><input type="hidden">', "a.html"),
    "WEB-007": (PAGE % "<button></button>", PAGE % '<button>Go</button>', "a.html"),
    "WEB-008": (PAGE % '<p id=a></p><p id=a></p>', PAGE % '<p id=a></p><p id=b></p>', "a.html"),
    "WEB-009": (PAGE % "<h1>a</h1><h3>b</h3>", PAGE % "<h1>a</h1><h2>b</h2><h3>c</h3><h1>d</h1>", "a.html"),
    "WEB-010": (PAGE % '<a href="#">x</a>', PAGE % '<a href="/x">x</a>', "a.html"),
    "WEB-011": (PAGE % '<a href="/x" target="_blank">x</a>', PAGE % '<a href="/x" target="_blank" rel="noopener">x</a>', "a.html"),
    "WEB-012": (PAGE % '<script src="http://e.com/a.js" defer></script>', '<html><head><script src="http://e.com/a.js" defer></script></head></html>', "a.html"),
    "WEB-013": ('<html lang=en><head><script src="a.js"></script></head></html>', '<html lang=en><head><script src="a.js" defer></script></head></html>', "a.html"),
    "WEB-014": (PAGE % '<img src=a alt=x>', PAGE % '<img src=a alt=x width=1 height=2>', "a.html"),
    "WEB-015": (PAGE % '<p onclick="f()">x</p>', PAGE % '<p>one</p>', "a.html"),
    "WEB-016": (PAGE % '<script src="https://cdn.x.com/a.js"></script>', PAGE % '<script src="/a.js"></script>', "a.html"),
    "WEB-017": (f'<img src="{B64}">', '<img src="data:image/png;base64,AAAA">', "a.html"),
    "WEB-018": ("x" * 1_100_000, "x" * 1000, "a.css"),
    "WEB-019": (PAGE % '<script src="js/jquery-1.12.4.min.js" defer></script>', PAGE % '<script src="js/jquery-3.7.1.min.js" defer></script>', "a.html"),
    "WEB-020": ('<html lang=en><head><title>t</title></head></html>', PAGE % "", "a.html"),
    "WEB-021": ('<html lang=en><head><title>t</title></head></html>', PAGE % "", "a.html"),
    "WEB-022": ("function f(){\n  console.log(1);\n}\n", "// console.log(1)\nconsole.error(1);\n", "a.js"),
}


def ids(src, name):
    return {f.rule_id for f in analyze(src, name)}


def test_every_rule_has_a_case():
    assert set(CASES) == set(RULES)
    assert all(r.explanation and r.fix_hint and r.title for r in RULES.values())


@pytest.mark.parametrize("rule", sorted(CASES))
def test_positive(rule):
    pos, _, name = CASES[rule]
    if rule == "WEB-012":
        pos = pos.replace("<script", HTTPS + "<script", 1)
    assert rule in ids(pos, name)


@pytest.mark.parametrize("rule", sorted(CASES))
def test_negative(rule):
    assert rule not in ids(CASES[rule][1], CASES[rule][2])


def test_fragment_skips_document_rules():
    assert ids("<div><p>hi</p></div>", "t.html") == set()


def test_wrapped_label_and_img_button_ok():
    assert not ids(PAGE % '<label>N <input></label><button><img src=x alt="Go" width=1 height=1></button>', "a.html") & {"WEB-006", "WEB-007"}


def _args(path):
    return argparse.Namespace(check_web=str(path), check_all=None)


def test_fixtures_end_to_end():
    r = WebCheck().run(Context(no_snap=True), _args(FIX))
    by = {}
    for f in r.findings:
        by.setdefault(f.evidence[0].file, set()).add(f.rule_id)
    assert not by.get("good.html")
    assert {"WEB-001", "WEB-002", "WEB-006", "WEB-007", "WEB-008", "WEB-009", "WEB-010", "WEB-011", "WEB-013", "WEB-016", "WEB-019"} <= by["bad.html"]


def test_missing_path_is_an_error():
    assert WebCheck().run(Context(no_snap=True), _args("/nonexistent/zz")).error
