"""A local stand-in for the Snap API so tests (and --dry demos) never touch the network or a real key.

Default scorer: 0.95 when a question's instructions hold a `[[needle]]...[[/needle]]` string that appears
verbatim in the state, else 0.04. `fail` forces errors: an int status (always, e.g. 401/402/403/500),
"429-once" / "503-once" (first request only), or "too-large-above-N" (400 when the state is longer than N chars).
"""
from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

NEEDLE = re.compile(r"\[\[needle\]\](.*?)\[\[/needle\]\]", re.S)


def default_scorer(state: str, question: dict) -> float:
    needles = NEEDLE.findall(question.get("instructions", ""))
    return 0.95 if any(n and n in state for n in needles) else 0.04


class FakeSnapServer:
    def __init__(self, scorer: Callable[[str, dict], float] | None = None, fail: int | str | None = None,
                 latency: float = 0.0):
        self.scorer = scorer or default_scorer
        self.fail = fail
        self.latency = latency
        self.requests: list[dict[str, Any]] = []     # one entry per HTTP request, failed ones too
        self.last_state: str = ""
        self._lock = threading.Lock()
        self._failed_once = False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                outer._handle(self, self.rfile.read(n))

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}/v1/systemone"

    @property
    def calls(self) -> int:
        return len(self.requests)

    @property
    def ok_calls(self) -> int:
        return sum(r["status"] == 200 for r in self.requests)

    def __enter__(self) -> "FakeSnapServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def _forced_status(self, state_len: int) -> int | None:
        f = self.fail
        if f is None:
            return None
        if isinstance(f, int):
            return f
        m = re.fullmatch(r"(\d+)-once", f)
        if m:
            if self._failed_once:
                return None
            self._failed_once = True
            return int(m.group(1))
        m = re.fullmatch(r"too-large-above-(\d+)", f)
        if m:
            return 400 if state_len > int(m.group(1)) else None
        raise ValueError(f"unknown fail spec {f!r}")

    def _handle(self, h: BaseHTTPRequestHandler, raw: bytes) -> None:
        if self.latency:
            time.sleep(self.latency)
        status, out = 200, {}
        state, questions = "", {}
        try:
            body = json.loads(raw)
            state, questions = body["state"], body["questions"]
        except (ValueError, KeyError, TypeError):
            status = 400
        if status == 200 and not (h.headers.get("Authorization") or "").startswith("Bearer "):
            status = 401
        with self._lock:
            if status == 200:
                status = self._forced_status(len(state)) or 200
            self.requests.append({"status": status, "state_chars": len(state), "n_questions": len(questions)})
            if status == 200:
                self.last_state = state
        if status == 200:
            out = {"model": "subq-snap-preview",
                   "answers": {qid: {"type": "noul", "noul": self.scorer(state, q)} for qid, q in questions.items()},
                   "usage": {"input_tokens": -(-len(state) // 3), "output_tokens": 0}}
        data = json.dumps(out if status == 200 else {"error": f"fake {status}"}).encode()
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(data)))
        if status in (429, 503):
            h.send_header("Retry-After", "0")
        h.end_headers()
        h.wfile.write(data)
