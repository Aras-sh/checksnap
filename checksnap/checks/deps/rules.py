"""Rule catalog for --check-dependencies. One place for ids, severities and texts (`--explain`, docs/RULES.md)."""
from __future__ import annotations

from dataclasses import dataclass

from checksnap.core import Severity


@dataclass(frozen=True)
class RuleInfo:
    id: str
    severity: Severity
    title: str
    explanation: str
    fix_hint: str
    needs_snap: bool = False


L, M, H = Severity.LOW, Severity.MEDIUM, Severity.HIGH

_RULES = [
    ("DEP-001", M, "Dependency has no version constraint",
     "Any release, including a future breaking or compromised one, satisfies the requirement, so two installs of the same repo can differ.",
     "Pin it (`pkg==1.2.3`) or at least bound it (`pkg>=1.2,<2`); lock the full tree with pip-tools, uv or poetry."),
    ("DEP-002", L, "Dependency only has a lower bound",
     "`>=` without an upper bound lets a new major release break the build silently.",
     "Add an upper bound (`>=1.2,<2`), use a compatible release (`~=1.2`), or pin exactly."),
    ("DEP-003", M, "Conflicting specs for the same package across files",
     "The same package is declared with different constraints in different manifests, so the environment depends on which file was installed last.",
     "Keep one source of truth (e.g. pyproject.toml) and generate the other files from it."),
    ("DEP-004", L, "Package declared twice in the same file",
     "A duplicate entry is at best noise and at worst two different constraints where only one wins.",
     "Remove the duplicate."),
    ("DEP-005", M, "Imported package has no declared dependency",
     "Code imports a third-party module that no manifest lists; a clean install will fail with ImportError. "
     "The import-name to package-name mapping is a small built-in table plus name normalization, so exotic packages can be false positives.",
     "Add the package to the manifest (or, if it is a local module, ignore this finding)."),
    ("DEP-006", L, "Declared dependency is never imported",
     "Nothing in the scanned code imports it. It may be dead weight, a plugin or CLI tool used indirectly, or its import name differs from its package name.",
     "Remove it if unused; keep it and ignore the finding if it is a plugin or tool."),
    ("DEP-007", H, "Git dependency without a pinned commit",
     "A `git+` URL with no ref, or a branch/tag ref, resolves to whatever is there at install time; history can be rewritten or the repo taken over.",
     "Pin a full commit hash: `git+https://host/org/repo.git@<40-hex-sha>`."),
    ("DEP-008", H, "Plain http:// index or package URL",
     "Packages fetched over http can be tampered with in transit and run arbitrary code on install.",
     "Use https:// URLs."),
    ("DEP-009", M, "Extra package index (dependency-confusion risk)",
     "With `--extra-index-url`, pip takes the highest version from ANY index, so an attacker can publish a higher version of an internal package name on PyPI.",
     "Use a single `--index-url` that proxies PyPI, or pin hashes (`--require-hashes`)."),
    ("DEP-010", H, "TLS verification disabled for a package host",
     "`--trusted-host` (or `verify_ssl = false`) turns off certificate checks for that host.",
     "Remove it and fix the certificate instead."),
    ("DEP-011", M, "Pinned version older than the recommended minimum (heuristic)",
     "HEURISTIC: a small built-in table of minimum recommended versions (see MIN_VERSIONS in checksnap/checks/deps/__init__.py) "
     "for popular packages; older pins miss years of security and compatibility fixes. The table is hand-maintained, not a vulnerability database.",
     "Upgrade to a maintained release, or ignore if you deliberately support an old platform."),
    ("DEP-012", L, "No Python version constraint",
     "No `requires-python`, `python_requires`, Pipfile `python_version`, `python` entry or .python-version was found, so installs on unsupported interpreters are not rejected.",
     "Set `requires-python = \">=3.10\"` in pyproject.toml (or the equivalent for your manifest)."),
]

RULES: dict[str, RuleInfo] = {r[0]: RuleInfo(*r) for r in _RULES}
