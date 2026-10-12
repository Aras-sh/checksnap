from __future__ import annotations

import pytest

from benchmarks.longctx.core import Config, CallSpec, build_state, items_for, parse_tokens, plan_calls, plan_summary
from benchmarks.longctx.backends import SnapBackend, normalize, parse_numbered
from benchmarks.longctx.haystack import NOT_FOUND, base_items, build_haystack, load_paragraphs
from benchmarks.longctx.report import wilson


def test_parse_tokens():
    assert parse_tokens("50k") == 50_000 and parse_tokens("1.5M") == 1_500_000 and parse_tokens("12_000_000") == 12_000_000


def test_wilson_known_values():
    lo, hi = wilson(0, 3)
    assert lo == 0 and 0.55 < hi < 0.57        # 0/3: upper bound ~0.56, not 0
    lo, hi = wilson(15, 15)
    assert hi == 1 and 0.78 < lo < 0.80
    assert wilson(0, 0) == (None, None)


def test_haystack_deterministic_and_sized():
    items, plants = base_items(1, 20_000, 5)
    a, _ = build_haystack(1, 20_000, 3.0, plants)
    b, _ = build_haystack(1, 20_000, 3.0, plants)
    c, _ = build_haystack(2, 20_000, 3.0, plants)
    assert a == b and a != c
    assert 60_000 <= len(a) <= 64_000


def test_canaries_unique_positioned_and_distractors_absent():
    items, plants = base_items(1, 50_000, 5)
    state, _ = build_haystack(1, 50_000, 3.0, plants)
    canaries = [i for i in items if i.group == "canary"]
    assert len({i.sentence for i in canaries}) == 5
    for c in canaries:
        assert state.count(c.sentence) == 1
        assert abs(state.find(c.sentence) / len(state) - c.target) < 0.05
    for i in items:
        if i.group in ("distractor", "decoy"):
            assert "[[needle]]" in i.snap.instructions and i.expected == NOT_FOUND
            sent = i.snap.instructions.split("[[needle]]")[1].split("[[/needle]]")[0]
            assert sent not in state
    # a distractor differs from its canary by exactly one detail
    can = canaries[0].sentence.split()
    dis = next(i for i in items if i.qid == "distractor-0").snap.instructions.split("[[needle]]")[1].split("[[/needle]]")[0].split()
    assert len(can) == len(dis) and sum(x != y for x, y in zip(can, dis)) == 1


def test_record_shuffle_keeps_records_moves_positions():
    _, plants = base_items(1, 20_000, 5)
    a, _ = build_haystack(1, 20_000, 3.0, plants)
    b, _ = build_haystack(1, 20_000, 3.0, plants, shuffle_records=True)
    assert sorted(a.split("\n\n")) == sorted(b.split("\n\n")) and a != b


def test_text_mode_reuses_and_reports(tmp_path):
    (tmp_path / "a.txt").write_text("\n\n".join(f"Paragraph number {i} of a short public domain sample text, long enough to keep." for i in range(10)))
    paras = load_paragraphs(str(tmp_path))
    state, reuse = build_haystack(1, 20_000, 3.0, [], paragraphs=paras)
    assert reuse > 50 and len(state) > 59_000
    with pytest.raises(ValueError):
        load_paragraphs(str(tmp_path / "missing_dir"))


def test_parse_rules():
    assert normalize('  "amber-cedar-0042."  ') == "amber-cedar-0042" and normalize("`NOT FOUND`") == "NOT FOUND"
    got = parse_numbered("1: a\nsome chatter\n2) b.\n2: ignored\n9: out of range", 3)
    assert got == {1: "a", 2: "b"}


def test_plan_counts_and_question_shuffle():
    cfg = Config(lengths=(20_000, 50_000))
    specs = plan_calls(cfg)
    assert len(specs) == 2 * (3 + 2 + 3 + 1)       # base x3 seeds, qshuf+hshuf, k=1,5,20, hop
    base = next(s for s in specs if s.kind == "base")
    q = next(s for s in specs if s.kind == "qshuf" and s.seed == base.seed and s.length == base.length)
    ib, pb = items_for(base, cfg)
    iq, pq = items_for(q, cfg)
    assert [i.qid for i in ib] != [i.qid for i in iq] and sorted(i.qid for i in ib) == sorted(i.qid for i in iq) and pb == pq
    plan = plan_summary(cfg, specs, SnapBackend(None))
    assert plan["calls"] == len(specs) and plan["tokens"] > sum(s.length for s in specs)


def test_plan_at_12m_is_over_the_default_caps():
    cfg = Config()
    plan = plan_summary(cfg, plan_calls(cfg), SnapBackend(None))
    assert plan["calls"] == 81 and 240e6 < plan["tokens"] < 260e6 and plan["dollars"] > 20
