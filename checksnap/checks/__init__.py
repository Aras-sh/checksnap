"""Importing this package registers the built-in checks. A missing or broken check module must never
take the CLI down: it is skipped and reported by `checksnap --list-checks`."""
import importlib

_LOAD_ERRORS: dict[str, str] = {}
for _name in ("dataset", "optimization", "traininglog", "repro", "security", "deps", "gitrepo"):
    try:
        importlib.import_module(f"{__name__}.{_name}")
    except Exception as exc:  # noqa: BLE001
        _LOAD_ERRORS[_name] = f"{type(exc).__name__}: {exc}"
