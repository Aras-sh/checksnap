"""Load settings from a TOML file, falling back to defaults."""
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    name: str = "app"
    retries: int = 3
    verbose: bool = False


def load_settings(path: Path | None = None) -> Settings:
    if path is None or not path.exists():
        return Settings()
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    known = {k: v for k, v in data.items() if k in Settings.__dataclass_fields__}
    return Settings(**known)
