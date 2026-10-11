"""Shared fixtures: a fake Snap server, a client pointed at it, and an engine with a temp cache."""
from __future__ import annotations

import pytest

from checksnap.snap import FakeSnapServer, SnapClient, SnapEngine


@pytest.fixture
def fake_snap():
    with FakeSnapServer() as srv:
        yield srv


@pytest.fixture
def snap_client(fake_snap):
    c = SnapClient(api_key="test-key", url=fake_snap.url, sleep=lambda s: None)
    yield c
    c.close()


@pytest.fixture
def snap_engine(snap_client, tmp_path):
    return SnapEngine(snap_client, cache_dir=tmp_path / "cache", workers=2)
