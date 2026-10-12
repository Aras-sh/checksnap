"""Execute a call plan: worker pool, hard token/dollar caps on actual spend, append-only JSONL so a crash loses nothing."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from checksnap.snap import SnapAuthError, SnapError, SnapQuotaError

from .core import CallSpec, Config, build_state, estimate, items_for


def load_records(out_dir: Path) -> dict[str, dict]:
    """Last record per call id (a retried call supersedes its earlier error)."""
    recs: dict[str, dict] = {}
    f = Path(out_dir) / "calls.jsonl"
    if f.exists():
        for line in f.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                recs[r["id"]] = r
    return recs


def run_calls(specs: list[CallSpec], cfg: Config, backend, out_dir: Path, *, workers: int, max_tokens: int, max_dollars: float,
              progress: Callable[[str], None] = lambda s: None) -> dict:
    """Skips calls already 'ok' in out_dir (resume). A call that would push reserved spend over a cap is skipped, never
    sent. Reserved = billed tokens so far + estimates of calls in flight. Failed requests are assumed not billed."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    done = {i for i, r in load_records(out_dir).items() if r["status"] == "ok"}
    todo = [s for s in specs if s.id not in done]
    lock, stop = threading.Lock(), threading.Event()
    st = {"reserved": 0, "billed": 0, "skipped": [], "fatal": None, "ran": 0}
    tok_cap = min(max_tokens, int(max_dollars / cfg.price * 1e6))
    log = out_dir / "calls.jsonl"

    def one(spec: CallSpec) -> None:
        if stop.is_set():
            return
        items, plants = items_for(spec, cfg)
        _, est = estimate(spec, cfg, backend)
        with lock:
            if st["reserved"] + est > tok_cap:
                st["skipped"].append(spec.id)
                return
            st["reserved"] += est
        rec = {"id": spec.id, "kind": spec.kind, "length": spec.length, "seed": spec.seed, "k": spec.k, "est_tokens": est,
               "status": "ok", "error": None}
        try:
            state, reuse = build_state(spec, cfg, plants)
            t = time.perf_counter()
            reply = backend.ask(state, items)
            rec.update(seconds=time.perf_counter() - t, state_chars=len(state), text_reuse=reuse, billed_in=reply.input_tokens,
                       billed_out=reply.output_tokens, requests=reply.requests, unparsed=reply.unparsed,
                       usage_estimated=reply.usage_estimated)
            rec["items"] = [{"qid": i.qid, "group": i.group, "truth": i.truth, "target": i.target,
                             "actual": state.find(i.sentence) / len(state) if i.sentence else None,
                             "raw": reply.answers[i.qid].raw, "said": reply.answers[i.qid].said, "ok": reply.answers[i.qid].ok}
                            for i in items]
        except (SnapAuthError, SnapQuotaError) as e:
            with lock:
                st["fatal"] = f"{type(e).__name__}: {e}"
                st["reserved"] -= est
            stop.set()
            return
        except SnapError as e:
            rec.update(status="error", error=f"{type(e).__name__}: {e}", seconds=None, billed_in=0, billed_out=0)
        with lock:
            st["reserved"] += rec.get("billed_in", 0) - est if rec["status"] == "ok" else -est
            st["billed"] += rec.get("billed_in", 0)
            st["ran"] += 1
            with log.open("a") as f:
                f.write(json.dumps(rec) + "\n")
            progress(f"{rec['id']}: {rec['status']}" + (f" ({rec['seconds']:.1f}s, {rec['billed_in']:,} tok)" if rec["status"] == "ok" else f" {rec['error']}"))

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        list(ex.map(one, todo))
    return {"ran": st["ran"], "already_done": len(done & {s.id for s in specs}), "skipped_cap": st["skipped"],
            "billed_tokens": st["billed"], "fatal": st["fatal"]}
