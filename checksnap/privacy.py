"""Privacy gate and API key lookup. The gate exists so nothing leaves the machine by surprise."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Iterable

from .core import CostEstimate

HOST = "api.subq.ai"


def load_api_key(env: dict[str, str] | None = None, cwd: Path | None = None) -> str | None:
    """SUBQ_API_KEY from the environment, else from ./.env. Parsed only; never printed or written."""
    env = os.environ if env is None else env
    if env.get("SUBQ_API_KEY"):
        return env["SUBQ_API_KEY"]
    dotenv = (cwd or Path.cwd()) / ".env"
    try:
        lines = dotenv.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        line = line.strip()
        if line.startswith("export "):
            line = line[7:]
        name, sep, value = line.partition("=")
        if sep and name.strip() == "SUBQ_API_KEY":
            return value.strip().strip("'\"") or None
    return None


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return ""


def estimate_table(rows: Iterable[tuple[str, CostEstimate]]) -> str:
    """Plain table of what each check would upload and spend."""
    rows = list(rows)
    total = sum((e for _, e in rows), CostEstimate())
    out = [f"Destination: {HOST}", f"{'check':<14}{'upload':>12}{'calls':>8}{'tokens':>14}"]
    for name, e in rows + [("TOTAL", total)]:
        out.append(f"{name:<14}{human_bytes(e.uploads_bytes):>12}{e.snap_calls:>8}{e.input_tokens:>14,}")
    out += [f"note ({n}): {e.notes}" for n, e in rows if e.notes]
    return "\n".join(out)


def confirm_upload(total: CostEstimate, *, yes: bool, interactive: bool,
                   ask: Callable[[str], str] = input) -> tuple[bool, str]:
    """Decide whether Snap parts may run. Returns (allowed, note-if-not)."""
    if yes:
        return True, ""
    if not interactive:
        return False, "Snap skipped: non-interactive and no --yes (nothing was uploaded)"
    try:
        answer = ask(f"Upload {human_bytes(total.uploads_bytes)} to {HOST}? [y/N] ")
    except EOFError:
        answer = ""
    if answer.strip().lower() in ("y", "yes"):
        return True, ""
    return False, "Snap skipped: upload declined"
