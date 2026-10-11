"""Rule catalog for --check-config (feeds --explain)."""
from __future__ import annotations

from checksnap.checks.security.rules import RuleInfo
from checksnap.core import Severity

L, M, H = Severity.LOW, Severity.MEDIUM, Severity.HIGH

_RULES = [
    ("CFG-001", M, "Duplicate key in a config file",
     "The same key appears twice in one scope. Parsers silently keep the last (or first) value, so the line you edited may be ignored.",
     "Delete the duplicate; keep one definition per key."),
    ("CFG-002", H, "Debug mode enabled in a production-looking config",
     "DEBUG=true in a prod file exposes stack traces, internal paths and sometimes an interactive console, and slows the app.",
     "Set debug to false in production files; drive it from the environment."),
    ("CFG-003", H, "Secret in plain text",
     "Passwords, tokens and keys in config files end up in version control, backups and images. Only the first 4 characters and the length are shown.",
     "Move it to a secret manager or an untracked environment variable, rotate it, and keep a placeholder in the file."),
    ("CFG-004", H, "Default or weak password",
     "Values like admin, password, changeme or 123456 are the first thing attackers try.",
     "Generate a long random password and inject it at deploy time."),
    ("CFG-005", M, "localhost or hard-coded IP in a production-looking config",
     "localhost/127.0.0.1 points at the wrong machine once deployed, and literal IPs break when hosts move.",
     "Use a DNS name or a service name supplied by the environment."),
    ("CFG-006", M, ".env and .env.example keys differ",
     "Keys missing from .env break the app at runtime; keys missing from .env.example leave new developers guessing.",
     "Keep both files in sync (values may differ, key names should not)."),
    ("CFG-007", L, "Trailing whitespace in a value",
     "Many parsers keep the trailing space, so `HOST=db ` is a different host than `HOST=db`. Invisible and hard to debug.",
     "Remove the trailing whitespace or quote the value."),
    ("CFG-008", L, "Unquoted value with spaces in a .env file",
     "Shells that `source` the file split on the space or run the second word as a command; dotenv libraries differ on how they treat it.",
     "Wrap the value in quotes: KEY=\"a b\"."),
    ("CFG-009", H, "Invalid JSON / TOML syntax",
     "The file does not parse, so the application will fail to start or fall back to defaults.",
     "Fix the reported line; validate in CI (python -m json.tool, tomllib)."),
    ("CFG-010", H, "YAML indented with tabs",
     "YAML forbids tab indentation; parsers reject the file.",
     "Indent with spaces only and configure the editor accordingly."),
    ("CFG-011", L, "http:// URL where https is likely",
     "Plain HTTP sends credentials and data unencrypted and can be tampered with in transit.",
     "Use https:// for anything that leaves the machine or private network."),
    ("CFG-012", M, "Zero, negative or very long timeout / pool size",
     "A zero or negative timeout often means 'wait forever'; a pool size of 0 or less means no connections; hour-long timeouts hold resources during outages.",
     "Use a bounded timeout (seconds to a minute) and a positive pool size."),
    ("CFG-013", M, "Wildcard CORS origin",
     "Access-Control-Allow-Origin: * lets any website call the API from a visitor's browser; combined with credentials it is a data-theft risk.",
     "List the exact origins that need access."),
    ("CFG-014", M, "Private key path world-readable or in a temp directory",
     "A key file readable by every local user (or kept in /tmp) can be copied by any other account or process on the machine.",
     "chmod 600 the key, store it outside /tmp, and keep it out of the repository."),
    ("CFG-015", L, "Env var read in code but missing from .env.example",
     "Developers cannot discover required variables, and deployments fail only when that code path runs.",
     "Add the variable (with a placeholder value) to .env.example, or give the code a default."),
]
RULES: dict[str, RuleInfo] = {r[0]: RuleInfo(*r) for r in _RULES}
