"""Backends: how a haystack plus questions become API calls, and how replies become answers.

snap: SnapClient, yes/no probabilities ('noul').   chat: any text-generation endpoint (OpenAI-compatible or a custom
JSON shape), exact-match answers. The real SubQ 12M API is unknown until access arrives, so everything about the chat
wire format is configuration (ChatConfig), not code.
"""
from __future__ import annotations

import json
import math
import os
import re
import time
from dataclasses import dataclass, field, fields
from typing import Any, Callable, Sequence

import httpx

from checksnap.snap import (DEFAULT_URL, SnapAuthError, SnapClient, SnapError, SnapQuotaError, SnapRateLimitError,
                            SnapTooLargeError)
from checksnap.snap.calibrate import CALL_OVERHEAD_TOKENS, QUESTION_CHARS_PER_TOKEN, question_chars

from .haystack import NOT_FOUND, Item

SYSTEM_PROMPT = ("You answer questions about a long document. Use ONLY the document. For each question reply with one "
                 "line of the form `N: <answer>`, where <answer> is the exact token asked for (no quotes, no explanation) "
                 f"or {NOT_FOUND} if the document does not contain it. Output nothing else.")


@dataclass
class Answer:
    raw: float | str | None     # snap: probability; chat: normalised answer text (None = no parsable line)
    said: bool                  # snap: p >= threshold; chat: claimed to find something (answer is not NOT FOUND)
    ok: bool                    # matches the truth: snap said==truth; chat exact token (truth) or NOT FOUND (false)


@dataclass
class Reply:
    answers: dict[str, Answer]
    input_tokens: int
    output_tokens: int
    requests: int = 1
    unparsed: int = 0
    usage_estimated: bool = False


class SnapBackend:
    name = "snap"

    def __init__(self, client: SnapClient, threshold: float = 0.5):
        self.client, self.threshold = client, threshold

    def estimate(self, items: Sequence[Item], length: int) -> tuple[int, int]:
        q = sum(question_chars(i.snap) for i in items) / QUESTION_CHARS_PER_TOKEN
        return 1, int(length + q + CALL_OVERHEAD_TOKENS)

    def ask(self, state: str, items: Sequence[Item]) -> Reply:
        r = self.client.ask(state, [i.snap for i in items])
        t = self.threshold
        return Reply({i.qid: Answer(r.scores[i.qid], r.scores[i.qid] >= t, (r.scores[i.qid] >= t) == i.truth) for i in items},
                     r.input_tokens, r.output_tokens)

    def close(self) -> None:
        self.client.close()


# ---- chat ----------------------------------------------------------------------------------------------------

@dataclass
class ChatConfig:
    """Everything about the target API that is unknown until access arrives. Fill in via --chat-config FILE (JSON with
    these keys) and/or SUBQ_API_URL / SUBQ_MODEL. The API key is NEVER read from the file: only from SUBQ_API_KEY."""
    url: str = ""
    model: str = ""
    mode: str = "openai"                        # "openai" or "custom"
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer "                # text put before the key; "" for a raw key header (e.g. x-api-key)
    extra_headers: dict[str, str] = field(default_factory=dict)
    request_template: dict | None = None        # custom mode: JSON body; strings $MODEL $SYSTEM $PROMPT $MAX_TOKENS are substituted
    response_text_path: str = "choices.0.message.content"
    input_tokens_path: str = "usage.prompt_tokens"
    output_tokens_path: str = "usage.completion_tokens"
    max_output_tokens: int = 0                  # 0 = 16 + 24 per question
    questions_per_request: int = 0              # 0 = all questions in one prompt; 1 = one request per question (costs a full haystack each)
    temperature: float = 0.0
    timeout: float = 1800.0
    max_retries: int = 6
    system_prompt: str = SYSTEM_PROMPT

    @classmethod
    def load(cls, path: str | None = None, env: dict[str, str] | None = None, url: str | None = None,
             model: str | None = None) -> "ChatConfig":
        """Precedence: CLI flag > env (SUBQ_API_URL, SUBQ_MODEL) > file > defaults. Never reads .env."""
        env = os.environ if env is None else env
        data: dict[str, Any] = {}
        if path:
            with open(path) as f:
                data = json.load(f)
        bad = set(data) - {f.name for f in fields(cls)}
        if bad:
            raise ValueError(f"unknown chat config keys {sorted(bad)} (api keys do not belong in the file: use SUBQ_API_KEY)")
        cfg = cls(**data)
        cfg.url = url or env.get("SUBQ_API_URL") or cfg.url
        cfg.model = model or env.get("SUBQ_MODEL") or cfg.model
        if cfg.mode not in ("openai", "custom"):
            raise ValueError("mode must be 'openai' or 'custom'")
        if cfg.mode == "custom" and not cfg.request_template:
            raise ValueError("custom mode needs request_template")
        return cfg

    def public(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "system_prompt"}


def dig(obj: Any, path: str) -> Any:
    """'choices.0.message.content' style lookup; None when anything on the way is missing."""
    for part in path.split(".") if path else []:
        try:
            obj = obj[int(part)] if isinstance(obj, list) else obj[part]
        except (KeyError, IndexError, ValueError, TypeError):
            return None
    return obj


def _subst(node: Any, vals: dict[str, Any]) -> Any:
    if isinstance(node, str):
        if node in vals:
            return vals[node]
        for k, v in vals.items():
            node = node.replace(k, str(v))
        return node
    if isinstance(node, list):
        return [_subst(x, vals) for x in node]
    if isinstance(node, dict):
        return {k: _subst(v, vals) for k, v in node.items()}
    return node


class ChatHTTP(SnapClient):
    """Reuses SnapClient's key handling, repr, backoff and httpx client; one JSON POST with the same status mapping."""

    def __init__(self, cfg: ChatConfig, **kw: Any):
        super().__init__(url=cfg.url, model=cfg.model, timeout=cfg.timeout, max_retries=cfg.max_retries, **kw)
        self.cfg = cfg

    def post(self, body: dict) -> dict:
        headers = {self.cfg.auth_header: self.cfg.auth_scheme + self._key, **self.cfg.extra_headers}
        for attempt in range(self.max_retries + 1):
            try:
                r = self._http.post(self.url, json=body, headers=headers)
            except httpx.HTTPError as e:
                if attempt >= self.max_retries:
                    raise SnapError(f"network error: {type(e).__name__}") from None
                self._sleep(self._backoff(attempt, None))
                continue
            code = r.status_code
            if code == 200:
                try:
                    return r.json()
                except ValueError:
                    raise SnapError("response is not JSON") from None
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
                raise SnapTooLargeError(f"HTTP {code}: request too large or rejected ({r.text[:200]})")
            raise SnapError(f"HTTP {code}: {r.text[:200]}")
        raise SnapError("unreachable")  # pragma: no cover


_LINE = re.compile(r"^\s*(?:q(?:uestion)?\s*)?(\d+)\s*[:.)\-]\s*(.*?)\s*$", re.I)


def normalize(text: str) -> str:
    """Exact-match rule: strip whitespace, wrapping quotes/backticks/asterisks and one trailing period. Case is kept."""
    t = text.strip()
    while t and (t[0] in "`*\"'" and t[-1] == t[0] and len(t) > 1):
        t = t[1:-1].strip()
    return t[:-1].rstrip() if t.endswith(".") else t


def parse_numbered(text: str, n: int) -> dict[int, str]:
    out: dict[int, str] = {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if m and 1 <= int(m.group(1)) <= n and int(m.group(1)) not in out:
            out[int(m.group(1))] = normalize(m.group(2))
    return out


def judge_chat(item: Item, norm: str | None) -> Answer:
    if norm is None:
        return Answer(None, False, False)
    nf = norm.casefold() == NOT_FOUND.casefold()
    return Answer(NOT_FOUND if nf else norm, not nf and norm != "", nf if not item.truth else norm == item.expected)


class ChatBackend:
    name = "chat"

    def __init__(self, cfg: ChatConfig, http: ChatHTTP | None = None):    # http=None: planning only, no key needed
        self.cfg, self.http = cfg, http

    def _chunks(self, items: Sequence[Item]) -> list[Sequence[Item]]:
        n = self.cfg.questions_per_request or len(items)
        return [items[i:i + n] for i in range(0, len(items), n)]

    @staticmethod
    def _questions(items: Sequence[Item]) -> str:
        return "Questions:\n" + "\n".join(f"{n}. {i.chat}" for n, i in enumerate(items, 1))

    def estimate(self, items: Sequence[Item], length: int) -> tuple[int, int]:
        chunks = self._chunks(items)
        extra = sum((len(self.cfg.system_prompt) + len(self._questions(c))) / QUESTION_CHARS_PER_TOKEN + CALL_OVERHEAD_TOKENS
                    for c in chunks)
        return len(chunks), int(len(chunks) * length + extra)

    def _body(self, state: str, items: Sequence[Item]) -> dict:
        prompt = f"<document>\n{state}\n</document>\n\n{self._questions(items)}"
        max_tokens = self.cfg.max_output_tokens or 16 + 24 * len(items)
        if self.cfg.mode == "openai":
            return {"model": self.cfg.model, "temperature": self.cfg.temperature, "max_tokens": max_tokens,
                    "messages": [{"role": "system", "content": self.cfg.system_prompt}, {"role": "user", "content": prompt}]}
        return _subst(self.cfg.request_template, {"$MODEL": self.cfg.model, "$SYSTEM": self.cfg.system_prompt,
                                                  "$PROMPT": prompt, "$MAX_TOKENS": max_tokens})

    def ask(self, state: str, items: Sequence[Item]) -> Reply:
        answers, tin, tout, unparsed, est = {}, 0, 0, 0, False
        chunks = self._chunks(items)
        for chunk in chunks:
            data = self.http.post(self._body(state, chunk))
            text = dig(data, self.cfg.response_text_path)
            if not isinstance(text, str):
                raise SnapError(f"no text at response_text_path={self.cfg.response_text_path!r}")
            got = parse_numbered(text, len(chunk))
            for n, item in enumerate(chunk, 1):
                answers[item.qid] = judge_chat(item, got.get(n))
                unparsed += n not in got
            ti, to = dig(data, self.cfg.input_tokens_path), dig(data, self.cfg.output_tokens_path)
            if isinstance(ti, int) and isinstance(to, int):
                tin, tout = tin + ti, tout + to
            else:       # usage missing: estimate so the caps still bite; flagged in the results
                est = True
                tin += math.ceil((len(state) + len(self._questions(chunk))) / 3.0)
                tout += math.ceil(len(text) / 3.0)
        return Reply(answers, tin, tout, len(chunks), unparsed, est)

    def close(self) -> None:
        if self.http:
            self.http.close()


def make_backend(name: str, *, url: str | None, model: str | None, timeout: float | None, max_retries: int,
                 threshold: float, chat_config: str | None, sleep: Callable[[float], None] = time.sleep,
                 offline: bool = False):
    """Raises SnapAuthError when SUBQ_API_KEY is unset (unless offline: plan/dry-run); ValueError for bad chat config."""
    if name == "snap":
        if offline:
            return SnapBackend(None, threshold)
        kw = {"model": model or os.environ.get("SUBQ_MODEL") or "subq-snap-preview"}
        return SnapBackend(SnapClient(url=url or os.environ.get("SUBQ_API_URL") or DEFAULT_URL, timeout=timeout or 1800.0,
                                      max_retries=max_retries, sleep=sleep, **kw), threshold)
    cfg = ChatConfig.load(chat_config, url=url, model=model)
    if offline:
        return ChatBackend(cfg)
    if not cfg.url:
        raise ValueError("chat backend needs a URL: --url, SUBQ_API_URL or 'url' in --chat-config")
    if timeout:
        cfg.timeout = timeout
    cfg.max_retries = max_retries
    return ChatBackend(cfg, ChatHTTP(cfg, sleep=sleep))
