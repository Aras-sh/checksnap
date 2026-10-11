"""`.checksnap.toml` loading. The file only supplies argparse defaults, so a flag on the command line always wins."""
from __future__ import annotations

import argparse
import tomllib
from pathlib import Path
from typing import Any

DEFAULT_NAME = ".checksnap.toml"


class ConfigError(Exception):
    pass


def load_config(path: Path | None) -> dict[str, Any]:
    """Read a TOML file. An explicit path must exist; the implicit ./.checksnap.toml is optional.
    Keys may sit at top level or under a [checksnap] table; `-` and `_` are interchangeable."""
    explicit = path is not None
    p = path if explicit else Path(DEFAULT_NAME)
    if not p.is_file():
        if explicit:
            raise ConfigError(f"config file not found: {p}")
        return {}
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read {p}: {exc}") from exc
    data = {**data, **data.pop("checksnap", {})} if isinstance(data.get("checksnap"), dict) else data
    return {k.replace("-", "_"): v for k, v in data.items() if not isinstance(v, dict)}


def apply_defaults(parser: argparse.ArgumentParser, cfg: dict[str, Any]) -> list[str]:
    """Install config values as parser defaults. Returns the keys that match no option (reported as a note)."""
    known = {a.dest for a in parser._actions}  # noqa: SLF001  (argparse has no public accessor)
    parser.set_defaults(**{k: v for k, v in cfg.items() if k in known})
    return sorted(k for k in cfg if k not in known)
