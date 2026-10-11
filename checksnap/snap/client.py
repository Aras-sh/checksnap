"""One HTTP call to the Snap API: auth, retries with backoff, status code mapping. No windows, no caching."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Callable, Sequence

import httpx

from .errors import (SnapAuthError, SnapError, SnapQuotaError, SnapRateLimitError, SnapTooLargeError)

DEFAULT_URL = "https://api.subq.ai/v1/systemone"


@dataclass(frozen=True)
class Question:
    id: str
    instructions: str
    true: str
    false: str

    def payload(self) -> dict:
        return {"type": "noul", "instructions": self.instructions,
                "criteria": {"true": self.true, "false": self.false}}


@dataclass
class AskResult:
    scores: dict[str, float]
    input_tokens: int
    output_tokens: int
    ms: float


class SnapClient:
    def __init__(self, api_key: str | None = None, url: str = DEFAULT_URL, model: str = "subq-snap-preview",
                 timeout: float = 300.0, max_retries: int = 6, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        key = api_key or os.environ.get("SUBQ_API_KEY")
        if not key:
            raise SnapAuthError("No API key: pass api_key or set SUBQ_API_KEY")
        self._key = key         # never logged, never in repr or error messages
        self.url, self.model, self.max_retries, self._sleep = url, model, max_retries, sleep
        self._http = httpx.Client(timeout=timeout, transport=transport)

    def __repr__(self) -> str:
        return f"SnapClient(url={self.url!r}, model={self.model!r})"

    def close(self) -> None:
        self._http.close()

    @staticmethod
    def _backoff(attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return min(60.0, max(0.0, float(retry_after)))
            except ValueError:
                pass
        return min(60.0, 1.5 * 2 ** attempt)

    def ask(self, state: str, questions: Sequence[Question]) -> AskResult:
        ids = [q.id for q in questions]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate question ids")
        # Wire ids are q0..qN so odd characters in our ids can never upset the service.
        body = {"model": self.model, "state": state,
                "questions": {f"q{i}": q.payload() for i, q in enumerate(questions)}}
        headers = {"Authorization": f"Bearer {self._key}"}
        for attempt in range(self.max_retries + 1):
            t = time.perf_counter()
            try:
                r = self._http.post(self.url, json=body, headers=headers)
            except httpx.HTTPError as e:
                if attempt >= self.max_retries:
                    raise SnapError(f"network error: {type(e).__name__}") from None
                self._sleep(self._backoff(attempt, None))
                continue
            code = r.status_code
            if code == 200:
                return self._parse(r, ids, (time.perf_counter() - t) * 1000)
            if code in (401, 403):
                raise SnapAuthError(f"HTTP {code}: bad key or no access")
            if code == 402:
                raise SnapQuotaError("HTTP 402: no credits")
            if code in (429, 503):
                if attempt >= self.max_retries:
                    raise SnapRateLimitError(f"HTTP {code} after {self.max_retries} retries")
                self._sleep(self._backoff(attempt, r.headers.get("retry-after")))
                continue
            if code in (400, 413, 422):
                raise SnapTooLargeError(f"HTTP {code}: state too large or rejected ({len(state)} chars)")
            raise SnapError(f"HTTP {code}: {r.text[:200]}")
        raise SnapError("unreachable")  # pragma: no cover

    @staticmethod
    def _parse(r: httpx.Response, ids: list[str], ms: float) -> AskResult:
        try:
            data = r.json()
            answers = data["answers"]
            scores = {qid: float(answers[f"q{i}"]["noul"]) for i, qid in enumerate(ids)}
            usage = data.get("usage") or {}
            return AskResult(scores, int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0)), ms)
        except (ValueError, KeyError, TypeError) as e:
            raise SnapError(f"unexpected response shape ({type(e).__name__})") from None
