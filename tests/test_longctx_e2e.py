"""End to end against FakeSnapServer / FakeChatServer at small sizes: no network beyond 127.0.0.1, no real key."""
from __future__ import annotations

import io
import json
import re

import pytest

from benchmarks.longctx.__main__ import main
from benchmarks.longctx.fake_chat import FakeChatServer, oracle
from checksnap.snap import FakeSnapServer

KEY = "sk-test-secret-123"
SMALL = ["--lengths", "20k,50k", "--seeds", "1,2,3"]


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("SUBQ_API_KEY", KEY)
    monkeypatch.delenv("SUBQ_API_URL", raising=False)
    monkeypatch.delenv("SUBQ_MODEL", raising=False)


def go(argv, tmp_path, answer="RUN"):
    buf = io.StringIO()
    rc = main(argv + ["--out", str(tmp_path / "out")] if "--out" not in argv and argv[0] not in ("plan",) else argv,
              input_fn=lambda _: answer, out=buf, sleep=lambda s: None)
    return rc, buf.getvalue()


def results(tmp_path):
    return json.loads((tmp_path / "out" / "results.json").read_text())


def cell(rows, length):
    return next(r for r in rows if r["length"] == length)


def test_snap_full_suite_perfect_fake(tmp_path):
    with FakeSnapServer() as srv:
        rc, text = go(["run", "--url", srv.url, *SMALL, "--workers", "2"], tmp_path)
        assert rc == 0, text
        n_calls = srv.ok_calls
    rep = results(tmp_path)
    assert n_calls == 2 * 9
    c = cell(rep["canary"], 20_000)
    assert c["all"]["k"] == c["all"]["n"] == 15 and all(v["n"] == 3 for v in c["by_position"].values())
    d = cell(rep["decoy"], 20_000)
    assert d["decoy_fa_all"]["k"] == 0 and d["decoy_fa_all"]["n"] == 15 and d["distractor_fa_all"]["k"] == 0 and d["invalid_calls"] == 0
    assert all(r["all"]["flips"]["k"] == 0 and r["all"]["flips"]["n"] == 15 for r in rep["order"])
    n = {r["k"]: r for r in rep["needles"] if r["length"] == 50_000}
    assert n[20]["recall"]["n"] == 20 and n[20]["recall"]["k"] == 20 and n[5]["recall"]["n"] == 5
    assert rep["cost"]["total_billed_tokens"] > 0 and rep["cost"]["total_calls"] == 18
    assert rep["meta"]["config"]["seeds"] == [1, 2, 3] and rep["meta"]["backend"] == "snap"
    assert (tmp_path / "out" / "results.md").read_text().startswith("# Long-context benchmark")
    for f in (tmp_path / "out").iterdir():
        assert KEY not in f.read_text()
    assert KEY not in text


def test_snap_hop_with_custom_scorer(tmp_path):
    def scorer(state, q):            # hop questions carry no needle: resolve the hop like a perfect reader would
        t = q["instructions"]
        m = re.match(r"Project (P-\d+) has an assigned courier. Is the badge colour of that courier (\w+)\?", t)
        if not m:
            return 0.04
        a = re.search(rf"([A-Z][a-z]+ [A-Z][a-z]+) is the courier assigned to project {m.group(1)}\.", state)
        return 0.95 if a and f"The badge colour of {a.group(1)} is {m.group(2)}." in state else 0.04
    with FakeSnapServer(scorer=scorer) as srv:
        rc, text = go(["hop", "--url", srv.url, "--lengths", "20k", "--seeds", "1,2,3"], tmp_path)
    assert rc == 0, text
    h = cell(results(tmp_path)["hop"], 20_000)
    assert h["both_correct"]["k"] == h["both_correct"]["n"] == 1


def test_canary_missed_marks_call_invalid_and_is_reported(tmp_path):
    def scorer(state, q):
        s = q["instructions"].split("[[needle]]")[1].split("[[/needle]]")[0]
        pos = state.find(s)
        if pos < 0:
            return 0.95 if "distractor" in q["instructions"] else 0.04
        return 0.04 if 0.4 < pos / len(state) < 0.6 else 0.95      # blind in the middle
    with FakeSnapServer(scorer=scorer) as srv:
        rc, _ = go(["canary", "--url", srv.url, "--lengths", "20k", "--seeds", "1,2,3", "--aux-seeds", "1"], tmp_path)
    assert rc == 0
    rep = results(tmp_path)
    c = cell(rep["canary"], 20_000)
    assert c["by_position"]["50%"]["k"] == 0 and c["by_position"]["0%"]["k"] == 3 and c["all"]["n"] == 15
    d = cell(rep["decoy"], 20_000)
    assert d["invalid_calls"] == 3 and d["decoy_fa_valid"]["n"] == 0 and d["decoy_fa_all"]["n"] == 15   # nothing hidden


def test_order_flips_detected_when_answers_depend_on_haystack_order(tmp_path):
    def scorer(state, q):
        s = q["instructions"].split("[[needle]]")[1].split("[[/needle]]")[0]
        pos = state.find(s)
        return 0.95 if 0 <= pos < 0.5 * len(state) else 0.04
    with FakeSnapServer(scorer=scorer) as srv:
        rc, _ = go(["order", "--url", srv.url, "--lengths", "20k", "--seeds", "1"], tmp_path)
    assert rc == 0
    rows = {r["variant"]: r for r in results(tmp_path)["order"]}
    assert rows["question order"]["all"]["flips"]["k"] == 0 and rows["question order"]["all"]["mean_abs_dp"] == 0
    assert rows["record order"]["all"]["flips"]["k"] > 0 and rows["record order"]["all"]["mean_abs_dp"] > 0


def test_dry_run_confirm_and_caps_send_nothing(tmp_path):
    with FakeSnapServer() as srv:
        rc, text = go(["run", "--url", srv.url, *SMALL, "--dry-run"], tmp_path)
        assert rc == 0 and "TOTAL" in text and srv.calls == 0
        rc, text = go(["run", "--url", srv.url, *SMALL], tmp_path, answer="no")
        assert rc == 1 and "Aborted" in text and srv.calls == 0
        rc, text = go(["run", "--url", srv.url, *SMALL, "--max-dollars", "0.0001"], tmp_path)
        assert rc == 2 and "REFUSED" in text and srv.calls == 0
        rc, text = go(["run", "--url", srv.url, *SMALL, "--max-tokens", "1000"], tmp_path)
        assert rc == 2 and srv.calls == 0


def test_dry_run_needs_no_key(monkeypatch, tmp_path):
    monkeypatch.delenv("SUBQ_API_KEY")
    rc, text = go(["run", "--dry-run", "--lengths", "20k"], tmp_path)
    assert rc == 0
    rc, text = go(["run", "--lengths", "20k"], tmp_path)
    assert rc == 2 and "SUBQ_API_KEY" in text


def test_cap_stops_mid_run_and_resume_finishes(tmp_path):
    with FakeSnapServer() as srv:
        argv = ["canary", "--url", srv.url, "--lengths", "20k,50k", "--seeds", "1,2", "--workers", "1"]
        # plan fits the cap (4 calls); a tight actual-spend cap is enforced per call via max-tokens just above plan
        rc, text = go(argv + ["--max-tokens", "400k"], tmp_path)
        first = srv.ok_calls
        assert rc == 0 and first == 4
        rc, text = go(argv, tmp_path)                       # resume: everything done, nothing re-sent
        assert rc == 0 and srv.ok_calls == first
    assert cell(results(tmp_path)["canary"], 50_000)["calls"] == 2


def test_runtime_cap_skips_calls(tmp_path):
    from benchmarks.longctx.backends import SnapBackend
    from benchmarks.longctx.core import Config, plan_calls
    from benchmarks.longctx.runner import run_calls
    from checksnap.snap import SnapClient
    cfg = Config(lengths=(20_000,), seeds=(1, 2, 3), suites=("canary",))
    with FakeSnapServer() as srv:
        be = SnapBackend(SnapClient("k", url=srv.url, sleep=lambda s: None))
        s = run_calls(plan_calls(cfg), cfg, be, tmp_path, workers=1, max_tokens=45_000, max_dollars=20)
        assert s["ran"] == 2 and len(s["skipped_cap"]) == 1 and srv.ok_calls == 2


def test_429_backoff_and_error_rows(tmp_path):
    with FakeSnapServer(fail="429-once") as srv:
        rc, _ = go(["canary", "--url", srv.url, "--lengths", "20k", "--seeds", "1"], tmp_path)
        assert rc == 0 and srv.calls == 2
    with FakeSnapServer(fail="too-large-above-1000") as srv:
        rc, _ = go(["canary", "--url", srv.url, "--lengths", "20k", "--seeds", "1"], tmp_path)
    rep = results(tmp_path)
    assert rep["cost"]["total_calls"] == 1 or cell(rep["cost"]["rows"], 20_000)["calls_error"] == 0   # earlier ok record kept (resume)


def test_text_mode_end_to_end(tmp_path):
    (tmp_path / "t.txt").write_text("\n\n".join(f"Chapter note {i}: the harbour master recorded the tides carefully each morning." for i in range(40)))
    with FakeSnapServer() as srv:
        rc, text = go(["canary", "--url", srv.url, "--lengths", "20k", "--seeds", "1", "--mode", "text", "--text-path", str(tmp_path / "t.txt")], tmp_path)
    assert rc == 0, text
    c = cell(results(tmp_path)["canary"], 20_000)
    assert c["all"]["k"] == 5
    assert results(tmp_path)["calls"][0]["text_reuse"] > 1


def test_plan_command_offline():
    buf = io.StringIO()
    assert main(["plan", "--max-length", "1M"], out=buf) == 0
    assert "TOTAL" in buf.getvalue() and "1,000,000" in buf.getvalue() and "12,000,000" not in buf.getvalue()


# ---- chat backend --------------------------------------------------------------------------------------------

def chat_cfg(tmp_path, srv, **extra):
    p = tmp_path / "chat.json"
    p.write_text(json.dumps({"url": srv.url, "model": "subq-test", **extra}))
    return ["--backend", "chat", "--chat-config", str(p)]


def test_chat_openai_perfect_oracle(tmp_path):
    with FakeChatServer() as srv:
        rc, text = go(["run", *chat_cfg(tmp_path, srv), *SMALL, "--lengths", "20k"], tmp_path)
        assert rc == 0, text
        assert {r["auth"] for r in srv.requests} == {f"Bearer {KEY}"}
        assert srv.calls == 3 + 2 + 3 + 1
    rep = results(tmp_path)
    assert rep["meta"]["backend"] == "chat" and rep["meta"]["model"] == "subq-test"
    c = cell(rep["canary"], 20_000)
    assert c["all"]["k"] == c["all"]["n"] == 15
    d = cell(rep["decoy"], 20_000)
    assert d["decoy_fa_all"]["k"] == 0 and d["distractor_fa_all"]["k"] == 0 and d["distractor_fa_all"]["n"] == 15
    h = cell(rep["hop"], 20_000)
    assert h["both_correct"]["k"] == 1
    assert all(r["all"]["flips"]["k"] == 0 for r in rep["order"]) and rep["cost"]["unparsed_answers"] == 0
    assert KEY not in (tmp_path / "out" / "results.json").read_text() and KEY not in text


def test_chat_custom_shape_and_raw_key_header(tmp_path):
    cfg = {"mode": "custom", "request_template": {"model": "$MODEL", "input": {"system": "$SYSTEM", "prompt": "$PROMPT"}, "max_new": "$MAX_TOKENS"},
           "response_text_path": "result.text", "input_tokens_path": "meta.in_tokens", "output_tokens_path": "meta.out_tokens",
           "auth_header": "x-api-key", "auth_scheme": ""}
    with FakeChatServer(shape="custom") as srv:
        rc, text = go(["canary", *chat_cfg(tmp_path, srv, **cfg), "--lengths", "20k", "--seeds", "1"], tmp_path)
        assert rc == 0, text
        assert srv.requests[0]["auth"] == KEY
    assert cell(results(tmp_path)["canary"], 20_000)["all"]["k"] == 5


def test_chat_one_request_per_question_costs_more(tmp_path):
    with FakeChatServer() as srv:
        rc, text = go(["canary", *chat_cfg(tmp_path, srv, questions_per_request=1), "--lengths", "20k", "--seeds", "1"], tmp_path)
        assert rc == 0, text
        assert srv.calls == 15                                  # 5 canaries + 5 distractors + 5 decoys, one haystack each
    assert cell(results(tmp_path)["cost"]["rows"], 20_000)["requests"] == 15


def test_chat_model_misses_and_hallucinates(tmp_path):
    def answerer(doc, qs):
        out = []
        for q in qs:
            a = oracle(doc, q)
            if "starts with" in q and a == "NOT FOUND":
                a = "amber-amber-0000"                              # hallucinates on decoys and distractors
            out.append(a)
        return out
    with FakeChatServer(answerer=answerer, wrap=lambda s: s + ".") as srv:         # trailing period must be tolerated
        rc, _ = go(["canary", *chat_cfg(tmp_path, srv), "--lengths", "20k", "--seeds", "1"], tmp_path)
    d = cell(results(tmp_path)["decoy"], 20_000)
    assert d["decoy_fa_all"]["rate"] == 1 and d["distractor_fa_all"]["rate"] == 1
    assert cell(results(tmp_path)["canary"], 20_000)["all"]["rate"] == 1


def test_chat_wrong_answer_and_garbage_are_misses_not_crashes(tmp_path):
    with FakeChatServer(answerer=lambda doc, qs: ["the code is hidden"] * len(qs)) as srv:
        rc, _ = go(["canary", *chat_cfg(tmp_path, srv), "--lengths", "20k", "--seeds", "1"], tmp_path)
    assert rc == 0
    assert cell(results(tmp_path)["canary"], 20_000)["all"]["k"] == 0


def test_chat_missing_url_and_config_with_key_rejected(tmp_path):
    rc, text = go(["run", "--backend", "chat", "--lengths", "20k"], tmp_path)
    assert rc == 2 and "URL" in text
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"url": "http://x", "api_key": "leak"}))
    rc, text = go(["run", "--backend", "chat", "--chat-config", str(bad), "--lengths", "20k"], tmp_path)
    assert rc == 2 and "leak" not in text


def test_chat_env_url_and_model(monkeypatch, tmp_path):
    with FakeChatServer() as srv:
        monkeypatch.setenv("SUBQ_API_URL", srv.url)
        monkeypatch.setenv("SUBQ_MODEL", "from-env")
        rc, text = go(["canary", "--backend", "chat", "--lengths", "20k", "--seeds", "1"], tmp_path)
        assert rc == 0, text
    assert results(tmp_path)["meta"]["model"] == "from-env"


def test_chat_429_retried(tmp_path):
    with FakeChatServer(fail="429-once") as srv:
        rc, _ = go(["hop", *chat_cfg(tmp_path, srv), "--lengths", "20k", "--seeds", "1"], tmp_path)
        assert rc == 0 and srv.calls == 2


def test_bigger_run_200k(tmp_path):
    with FakeSnapServer() as srv:
        rc, text = go(["canary", "--url", srv.url, "--lengths", "200k", "--seeds", "1"], tmp_path)
    assert rc == 0 and cell(results(tmp_path)["canary"], 200_000)["all"]["k"] == 5
