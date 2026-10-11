"""On-disk cache of Snap answers so a crashed or repeated scan does not pay twice."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Sequence


class DiskCache:
    def __init__(self, root: Path):
        self.root = Path(root) / "snap"

    @staticmethod
    def key(model: str, state: str, payloads: Sequence[tuple[str, dict]]) -> str:
        """sha256(model + window text + question payloads). Ids are included: they label the cached scores."""
        h = hashlib.sha256()
        h.update(model.encode())
        h.update(b"\0")
        h.update(state.encode("utf-8", "surrogatepass"))
        h.update(b"\0")
        h.update(json.dumps(list(payloads), sort_keys=True, ensure_ascii=False).encode("utf-8", "surrogatepass"))
        return h.hexdigest()

    def get(self, key: str) -> dict[str, Any] | None:
        try:
            return json.loads((self.root / f"{key}.json").read_text())
        except (OSError, ValueError):
            return None     # missing or corrupt (crash mid-write): treat as a miss

    def put(self, key: str, value: dict[str, Any]) -> None:
        """Atomic write (tmp + rename) so readers never see half a file. Cache failures are never fatal."""
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.root, suffix=".tmp")
            with os.fdopen(fd, "w") as f:
                json.dump(value, f)
            os.replace(tmp, self.root / f"{key}.json")
        except OSError:
            pass
