from __future__ import annotations

import httpx
import pytest

from checksnap.snap import (FakeSnapServer, Question, SnapAuthError, SnapClient, SnapError, SnapQuotaError,
                            SnapRateLimitError, SnapTooLargeError)

Q = Question("a", "Is it here? [[needle]]zebra[[/needle]]", "yes", "no")


def test_payload():
    assert Q.payload()["criteria"] == {"true": "yes", "false": "no"} and Q.payload()["type"] == "noul"


def test_ask_scores_and_tokens(snap_client):
    r = snap_client.ask("a zebra here", [Q, Question("b", "x [[needle]]lion[[/needle]]", "y", "n")])
    assert r.scores == {"a": 0.95, "b": 0.04} and r.input_tokens > 0


def test_key_from_env(monkeypatch, fake_snap):
    monkeypatch.setenv("SUBQ_API_KEY", "k")
    assert SnapClient(url=fake_snap.url).ask("zebra", [Q]).scores["a"] == 0.95
    monkeypatch.delenv("SUBQ_API_KEY")
    with pytest.raises(SnapAuthError):
        SnapClient(url=fake_snap.url)


def test_repr_hides_key(fake_snap):
    assert "secret-key" not in repr(SnapClient(api_key="secret-key", url=fake_snap.url))


@pytest.mark.parametrize("status,exc", [(401, SnapAuthError), (403, SnapAuthError), (402, SnapQuotaError),
                                        ("too-large-above-5", SnapTooLargeError), (500, SnapError)])
def test_error_mapping(status, exc):
    with FakeSnapServer(fail=status) as srv:
        c = SnapClient("k", url=srv.url, sleep=lambda s: None)
        with pytest.raises(exc):
            c.ask("a long enough state", [Q])
        assert srv.calls == 1       # no retries for these


@pytest.mark.parametrize("spec", ["429-once", "503-once"])
def test_retry_once(spec):
    sleeps = []
    with FakeSnapServer(fail=spec) as srv:
        c = SnapClient("k", url=srv.url, sleep=sleeps.append)
        assert c.ask("zebra", [Q]).scores["a"] == 0.95
        assert srv.calls == 2 and len(sleeps) == 1


def test_rate_limit_exhausted():
    sleeps = []
    with FakeSnapServer(fail=429) as srv:
        c = SnapClient("k", url=srv.url, max_retries=3, sleep=sleeps.append)
        with pytest.raises(SnapRateLimitError):
            c.ask("zebra", [Q])
        assert srv.calls == 4 and len(sleeps) == 3


def test_backoff_grows_without_retry_after():
    assert SnapClient._backoff(0, None) < SnapClient._backoff(3, None) <= 60
    assert SnapClient._backoff(0, "2") == 2.0


def test_network_error_and_bad_shape():
    def boom(req):
        raise httpx.ConnectError("nope")
    c = SnapClient("k", transport=httpx.MockTransport(boom), max_retries=1, sleep=lambda s: None)
    with pytest.raises(SnapError):
        c.ask("x", [Q])
    c = SnapClient("k", transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"nope": 1})))
    with pytest.raises(SnapError):
        c.ask("x", [Q])


def test_duplicate_ids(snap_client):
    with pytest.raises(ValueError):
        snap_client.ask("x", [Q, Q])
