"""A local stand-in for a chat/completions endpoint, so the chat backend can be tested (and demoed) with no network.

The default 'model' is an oracle: it reads the document in the prompt and answers each numbered question exactly, or
NOT FOUND. `answerer(doc, questions) -> list[str]` replaces it to simulate a model that misses things. `shape` is
'openai' (messages in, choices out) or 'custom' ({"input": {"system", "prompt"}} in, {"result": {"text"}, "meta": {...}} out).
"""
from __future__ import annotations

import json
import math
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable


def oracle(doc: str, q: str) -> str:
    if m := re.fullmatch(r'In the sentence that starts with "(.+)", what is the code\?', q):
        m = re.search(re.escape(m.group(1)) + r" (\S+?)\.", doc)
        return m.group(1) if m else "NOT FOUND"
    if m := re.fullmatch(r"What is the (.+?) for station (\S+)\?", q):
        m = re.search(rf"The {re.escape(m.group(1))} for station {re.escape(m.group(2))} is (\S+?)\.", doc)
        return m.group(1) if m else "NOT FOUND"
    if m := re.match(r"Project (P-\d+) has an assigned courier", q):
        a = re.search(rf"([A-Z][a-z]+ [A-Z][a-z]+) is the courier assigned to project {m.group(1)}\.", doc)
        b = a and re.search(rf"The badge colour of {re.escape(a.group(1))} is (\w+)\.", doc)
        return b.group(1) if b else "NOT FOUND"
    return "NOT FOUND"


class FakeChatServer:
    def __init__(self, answerer: Callable[[str, list[str]], list[str]] | None = None, shape: str = "openai",
                 fail: int | str | None = None, usage: bool = True, wrap: Callable[[str], str] = lambda s: s):
        self.answerer, self.shape, self.fail, self.usage, self.wrap = answerer, shape, fail, usage, wrap
        self.requests: list[dict[str, Any]] = []     # {"status", "auth", "n_questions", "doc_chars", "headers"}
        self._lock = threading.Lock()
        self._failed_once = False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def do_POST(self) -> None:
                outer._handle(self, self.rfile.read(int(self.headers.get("Content-Length") or 0)))

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    url = property(lambda self: f"http://127.0.0.1:{self._httpd.server_address[1]}/v1/chat")
    calls = property(lambda self: len(self.requests))

    def __enter__(self) -> "FakeChatServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def _handle(self, h: BaseHTTPRequestHandler, raw: bytes) -> None:
        status, text, tin = 200, "", 0
        qs: list[str] = []
        doc = ""
        try:
            body = json.loads(raw)
            prompt = body["messages"][-1]["content"] if self.shape == "openai" else body["input"]["prompt"]
            doc = prompt.split("<document>\n", 1)[1].split("\n</document>", 1)[0]
            qs = re.findall(r"^\d+\. (.+)$", prompt.split("Questions:\n", 1)[1], re.M)
            tin = math.ceil(len(prompt) / 3)
        except (ValueError, KeyError, IndexError, TypeError):
            status = 400
        with self._lock:
            if self.fail is not None and status == 200:
                if isinstance(self.fail, int):
                    status = self.fail
                elif not self._failed_once:
                    self._failed_once, status = True, int(self.fail.split("-")[0])
            self.requests.append({"status": status, "auth": h.headers.get("Authorization") or h.headers.get("x-api-key"),
                                  "n_questions": len(qs), "doc_chars": len(doc)})
        if status == 200:
            ans = self.answerer(doc, qs) if self.answerer else [oracle(doc, q) for q in qs]
            text = "\n".join(self.wrap(f"{n}: {a}") for n, a in enumerate(ans, 1))
            tout = math.ceil(len(text) / 3)
            if self.shape == "openai":
                out = {"choices": [{"message": {"role": "assistant", "content": text}}]}
                if self.usage:
                    out["usage"] = {"prompt_tokens": tin, "completion_tokens": tout}
            else:
                out = {"result": {"text": text}, "meta": {"in_tokens": tin, "out_tokens": tout} if self.usage else {}}
        else:
            out = {"error": f"fake {status}"}
        data = json.dumps(out).encode()
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(data)))
        if status in (429, 503):
            h.send_header("Retry-After", "0")
        h.end_headers()
        h.wfile.write(data)
