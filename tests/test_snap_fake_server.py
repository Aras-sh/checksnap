from __future__ import annotations

import httpx

from checksnap.snap import FakeSnapServer


def post(srv, state, instr, headers=None):
    body = {"model": "m", "state": state, "questions": {"q0": {"type": "noul", "instructions": instr, "criteria": {}}}}
    return httpx.post(srv.url, json=body, headers={"Authorization": "Bearer k"} if headers is None else headers)


def test_default_scorer_and_usage():
    with FakeSnapServer() as srv:
        r = post(srv, "hello zebra", "[[needle]]zebra[[/needle]]").json()
        assert r["answers"]["q0"]["noul"] == 0.95
        req = srv.requests[0]
        assert req["q_chars"] > 0 and r["usage"]["input_tokens"] == req["input_tokens"] == -(-(len("hello zebra") + req["q_chars"]) // 3)   # questions are billed too
        assert post(srv, "hello", "[[needle]]zebra[[/needle]]").json()["answers"]["q0"]["noul"] == 0.04
        assert post(srv, "hello", "no markers").json()["answers"]["q0"]["noul"] == 0.04
        assert srv.calls == 3 and srv.last_state == "hello"


def test_custom_scorer_latency_and_auth():
    with FakeSnapServer(scorer=lambda s, q: 0.5, latency=0.01) as srv:
        assert post(srv, "x", "y").json()["answers"]["q0"]["noul"] == 0.5
        assert post(srv, "x", "y", headers={}).status_code == 401


def test_fail_modes():
    with FakeSnapServer(fail="503-once") as srv:
        assert [post(srv, "x", "y").status_code for _ in range(2)] == [503, 200]
    with FakeSnapServer(fail="too-large-above-3") as srv:
        assert [post(srv, s, "y").status_code for s in ("abc", "abcd")] == [200, 400]
    with FakeSnapServer(fail=402) as srv:
        assert post(srv, "x", "y").status_code == 402
