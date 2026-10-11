"""Deliberately slow code for trying `checksnap --check-optimization`."""
import re
import time


def build_report(rows):
    out = ""
    for r in rows:
        out += str(r) + "\n"          # quadratic string building
    return out


def count_known(items, known):
    n = 0
    for i in range(len(items)):       # range(len(...))
        if items[i] in known:         # membership in a list
            n += 1
    return n


def find_digits(lines):
    hits = []
    for line in lines:
        hits.append(re.findall(r"\d+", line))   # constant pattern inside loop
    return hits


async def fetch():
    time.sleep(1)                     # blocks the event loop
