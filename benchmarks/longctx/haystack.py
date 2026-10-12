"""Deterministic haystacks and planted facts. Pure functions of (seed, length); nothing here touches the network."""
from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path

from checksnap.snap import Question

POSITIONS = (0.0, 0.25, 0.5, 0.75, 1.0)
MIN_RECORDS = 20

_V = {
    "p": "Amara Boris Chen Dalia Emeka Farid Greta Hana Ivo Jonas Kaia Leon Mira Nikos Orla Pavel Quinn Rhea Sven Tamsin Uri Vera Wen Xavi Yara Zoran".split(),
    "s": "Abbott Barros Castellan Dvorak Eriksen Fontaine Grigoryan Halvorsen Iwata Jankowski Kowalczyk Lindqvist Moreau Nakamura Okafor Petrov Quesada Rinaldi Sato Tanaka Ulloa Varga Whitfield Yilmaz".split(),
    "place": "Aldermoor Brightwater Cobblestone Dunmere Eastvale Foxhollow Glenrock Harrowgate Ironbridge Juniper Kingsmead Larkfield Millbrook Northcliff Oakhurst Pinecrest Ravenscar Stonebridge Thornbury Underhill Wexford".split(),
    "org": "council committee cooperative ministry laboratory library society survey office institute board guild consortium".split(),
    "noun": "bridge ledger harvest archive turbine orchard schedule survey filter barge lantern manifest compass kiln quarry depot signal furnace gallery reservoir".split(),
    "adj": "northern careful early quiet revised partial seasonal narrow durable unusual modest rural central coastal weekly".split(),
    "vp": "reviewed approved postponed inspected measured replaced documented relocated summarised audited restored catalogued".split(),
    "mon": "January February March April May June July August September October November December".split(),
    "topic": "drainage tariffs bee populations bus timetables grain storage road salt census returns flood defences apprenticeships harbour dredging street lighting".split(),
    "w": "amber basalt cedar delta ember fjord garnet harbor indigo jasper kestrel lotus maple nectar onyx pebble quartz russet saffron tundra umber velvet willow zephyr".split(),
    "colour": "teal plum amber crimson ivory olive slate coral indigo mustard".split(),
}
_T = [
    "{p} {s} of the {place} {org} {vp} the {adj} {noun} on {d} {mon}.",
    "According to the {place} {org}, {topic} remained a standing item on the agenda throughout the {adj} season.",
    "The {adj} {noun} was {vp} by a team led by {p} {s}, who had worked in {place} for {n} years.",
    "In {mon}, the {org} in {place} recorded {n} separate requests concerning {topic}.",
    "{p} {s} wrote that the {noun} had been {vp} twice before and would likely be {vp} again.",
    "Nobody in {place} could say for certain when the {adj} {noun} had first been {vp}.",
    "A short note from {p} {s} explains that {topic} cost roughly {n} units per quarter.",
    "The {org} met on {d} {mon} to discuss {topic}, and the minutes were {vp} the following week.",
    "Residents of {place} generally agreed that the {adj} {noun} was the best-kept in the district.",
    "{p} and {p2} {s} spent {n} days travelling from {place} to {place2} to inspect the {noun}.",
    "Local records show that the {noun} at {place} was {vp} in {mon} and again in the autumn.",
    "Despite repeated requests, the {org} never published its findings on {topic}.",
    "The report on {topic} ran to {n} pages and was mostly concerned with the {adj} {noun}.",
    "{p} {s} described the {place} {noun} as {adj}, though {p2} {s2} disagreed.",
    "By {d} {mon} the {adj} {noun} had been {vp}, and attention turned to {topic}.",
]


class _Fill(dict):
    def __init__(self, rng: random.Random):
        super().__init__()
        self.rng = rng

    def __missing__(self, k: str) -> str:
        r = self.rng
        if k == "n":
            return str(r.randint(2, 980))
        if k == "d":
            return str(r.randint(1, 28))
        base = k.rstrip("2")
        return r.choice(_V[base])


def filler_paragraph(rng: random.Random) -> str:
    f = _Fill(rng)
    return " ".join(rng.choice(_T).format_map(f) for _ in range(rng.randint(3, 7)))


def load_paragraphs(path: str) -> list[str]:
    """Paragraphs (blank-line separated) of every .txt/.md/.rst file under path, in sorted file order."""
    p = Path(path)
    files = [p] if p.is_file() else sorted(f for f in p.rglob("*") if f.suffix.lower() in (".txt", ".md", ".rst"))
    paras = []
    for f in files:
        for para in f.read_text(errors="replace").replace("\r\n", "\n").split("\n\n"):
            para = " ".join(para.split())
            if len(para) >= 40:
                paras.append(para)
    if not paras:
        raise ValueError(f"no usable text (.txt/.md/.rst paragraphs of 40+ chars) under {path}")
    return paras


# ---- planted facts -------------------------------------------------------------------------------------------

NOT_FOUND = "NOT FOUND"


@dataclass
class Item:
    """One question, in both wire forms: `snap` (yes/no probability) and `chat` (exact-match text answer)."""
    qid: str
    group: str                  # canary | decoy | distractor | needle | hop_true | hop_false
    truth: bool                 # does the haystack support the claim / contain the answer?
    snap: Question
    chat: str                   # question text for the chat backend
    expected: str               # chat: exact answer (NOT_FOUND when truth is False)
    target: float | None = None     # intended position (fraction of the context) of the planted sentence
    sentence: str | None = None     # the planted sentence, used to measure the position actually achieved


_VAULT = ["The access code for the {adj} {noun} vault {id} is {code}.",
          "Vault {id}, the {adj} {noun} annex, opens with the code {code}.",
          "The {adj} {noun} vault numbered {id} uses the access code {code}."]
_EXACT_TRUE = "The exact sentence appears in the text."
_EXACT_FALSE = "The exact sentence does not appear in the text; a similar sentence with a different detail does not count."


def _vault(rng: random.Random, used: set[str]) -> dict:
    while True:
        d = {"t": rng.randrange(len(_VAULT)), "adj": rng.choice(_V["adj"]), "noun": rng.choice(_V["noun"]),
             "id": f"{rng.randrange(10**5):05d}",
             "code": f"{rng.choice(_V['w'])}-{rng.choice(_V['w'])}-{rng.randrange(10**4):04d}"}
        if d["id"] not in used:
            used.add(d["id"])
            return d


def _render(d: dict) -> str:
    return _VAULT[d["t"]].format(**d)


def _prefix(d: dict) -> str:
    """The sentence up to (not including) the code: what the chat question quotes."""
    return _VAULT[d["t"]].split("{code}")[0].format(**d).rstrip()


def _near_duplicate(rng: random.Random, d: dict, which: str) -> dict:
    """Same sentence with exactly one detail (id, adj or noun) changed. All three sit before the code, so the chat
    question's quoted prefix no longer matches anything and the right answer is NOT FOUND."""
    e = dict(d)
    while e[which] == d[which]:
        e[which] = f"{rng.randrange(10**5):05d}" if which == "id" else rng.choice(_V[which])
    return e


def _vault_item(qid: str, group: str, d: dict, truth: bool, real_code: str, pos: float | None = None, s: str | None = None) -> Item:
    sent = _render(d)
    snap = Question(qid, f"Does the text contain this exact sentence, word for word? [[needle]]{sent}[[/needle]]", _EXACT_TRUE, _EXACT_FALSE)
    chat = f'In the sentence that starts with "{_prefix(d)}", what is the code?'
    return Item(qid, group, truth, snap, chat, real_code if truth else NOT_FOUND, pos, s)


def base_items(seed: int, length: int, n_decoys: int) -> tuple[list[Item], list[tuple[float, str]]]:
    """5 canaries (true, one per position), n_decoys always-false, 5 hard distractors (canary with one detail changed)."""
    rng, used = random.Random(f"base:{seed}:{length}"), set()
    items, plants = [], []
    for i, pos in enumerate(POSITIONS):
        d = _vault(rng, used)
        s = _render(d)
        items.append(_vault_item(f"canary-{i}", "canary", d, True, d["code"], pos, s))
        plants.append((pos, s))
        items.append(_vault_item(f"distractor-{i}", "distractor", _near_duplicate(rng, d, ("id", "adj", "noun")[(i + seed) % 3]), False, d["code"]))
    for i in range(n_decoys):
        items.append(_vault_item(f"decoy-{i}", "decoy", _vault(rng, used), False, ""))
    return items, plants


_ATTR = ["calibration key", "shipping reference", "maintenance token", "audit tag", "routing label"]


def needle_items(seed: int, length: int, k: int) -> tuple[list[Item], list[tuple[float, str]]]:
    """k true facts, one question each, spread over the context in one call (stratified random positions)."""
    rng, used = random.Random(f"needle{k}:{seed}:{length}"), set()
    items, plants = [], []
    for i in range(k):
        while True:
            sid = f"{rng.choice('KMRTX')}-{rng.randrange(10**4):04d}"
            if sid not in used:
                used.add(sid)
                break
        attr, val = rng.choice(_ATTR), f"{rng.choice(_V['w'])}-{rng.randrange(10**3):03d}"
        s, pos = f"The {attr} for station {sid} is {val}.", min(1.0, (i + rng.random()) / k)
        snap = Question(f"needle-{i}", f"Does the text say the {attr} for station {sid} is {val}? [[needle]]{s}[[/needle]]",
                        "The text states this value for this station.", "The text does not state this value for this station.")
        items.append(Item(f"needle-{i}", "needle", True, snap, f"What is the {attr} for station {sid}?", val, pos, s))
        plants.append((pos, s))
    return items, plants


def hop_items(seed: int, length: int) -> tuple[list[Item], list[tuple[float, str]]]:
    """Fact A (courier X is assigned to project P) early, fact B (X's badge colour) late; 3 decoy couriers with other colours
    so a lucky colour guess is not enough. One true and one false question, both needing the hop. No [[needle]] in the snap
    form: a marker would name the courier and remove the hop, so the fake snap server needs a custom scorer (see tests).
    Chat false question: a project that has no courier (answer NOT FOUND); snap false question: the wrong colour."""
    rng = random.Random(f"hop:{seed}:{length}")
    names, colours = [], rng.sample(_V["colour"], 5)
    while len(names) < 4:
        n = f"{rng.choice(_V['p'])} {rng.choice(_V['s'])}"
        if n not in names:
            names.append(n)
    pids = rng.sample(range(1000, 10000), 5)
    plants = []
    for n, pid, col in zip(names, pids, colours):
        a, b = rng.uniform(0.1, 0.4), rng.uniform(0.6, 0.9)
        plants += [(a, f"{n} is the courier assigned to project P-{pid}."), (b, f"The badge colour of {n} is {col}.")]

    def snap(qid: str, col: str) -> Question:
        return Question(qid, f"Project P-{pids[0]} has an assigned courier. Is the badge colour of that courier {col}?",
                        "The courier assigned to this project has this badge colour.", "The courier assigned to this project has a different badge colour.")
    ask = "Project P-{} has an assigned courier. What is the badge colour of that courier?"
    return [Item("hop-true", "hop_true", True, snap("hop-true", colours[0]), ask.format(pids[0]), colours[0]),
            Item("hop-false", "hop_false", False, snap("hop-false", colours[4]), ask.format(pids[4]), NOT_FOUND)], plants


# ---- haystack ------------------------------------------------------------------------------------------------

def build_haystack(seed: int, length: int, chars_per_token: float, plants: list[tuple[float, str]], *,
                   paragraphs: list[str] | None = None, shuffle_records: bool = False) -> tuple[str, float]:
    """(text, text_reuse_factor). Records are paragraphs joined by blank lines; each planted sentence is appended to the
    record at its target fraction. shuffle_records shuffles ALL records (planted ones too), so positions change."""
    target = int(length * chars_per_token)
    rng = random.Random(f"filler:{seed}:{length}")
    recs: list[str] = []
    total, reuse = 0, 1.0
    if paragraphs is None:
        while total < target or len(recs) < MIN_RECORDS:
            p = filler_paragraph(rng)
            recs.append(p)
            total += len(p) + 2
    else:
        start = (seed * 7919) % len(paragraphs)
        corpus = sum(len(p) + 2 for p in paragraphs)
        reuse = max(1.0, target / corpus)
        i = 0
        while total < target or len(recs) < MIN_RECORDS:
            p = paragraphs[(start + i) % len(paragraphs)]
            recs.append(p)
            total += len(p) + 2
            i += 1
    for frac, s in plants:
        j = min(len(recs) - 1, int(frac * len(recs)))
        recs[j] += " " + s
    if shuffle_records:
        random.Random(f"hshuf:{seed}:{length}").shuffle(recs)
    return "\n\n".join(recs), reuse
