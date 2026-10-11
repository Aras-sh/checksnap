"""Rule catalog for --check-security: ids, severities and texts in one place (feeds --explain and docs/RULES.md)."""
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
    ("SEC-001", H, "Unsafe deserialization (pickle / torch.load without weights_only)",
     "pickle, dill, marshal and `torch.load` with the default (or `weights_only=False`) execute arbitrary code embedded in the file. "
     "A downloaded checkpoint or a cached object is enough for remote code execution.",
     "Use `torch.load(path, weights_only=True)`, safetensors, or JSON; only unpickle data you produced and signed."),
    ("SEC-002", H, "yaml.load without a safe loader",
     "`yaml.load` with the default or `Loader=yaml.Loader/UnsafeLoader/FullLoader` can construct arbitrary Python objects from the document.",
     "Use `yaml.safe_load(...)` or pass `Loader=yaml.SafeLoader`."),
    ("SEC-003", H, "eval / exec on a non-constant expression",
     "`eval` and `exec` run whatever string they are given; if any part comes from input, files or the network it is code injection.",
     "Use `ast.literal_eval` for literals, a dispatch dict for choices, or a real parser."),
    ("SEC-004", H, "subprocess with shell=True and a formatted command string",
     "With `shell=True` the command goes through the shell; f-strings, `%`, `.format` or `+` put variables into it, so a value containing `;` or `$(...)` runs extra commands.",
     "Pass a list of arguments without `shell=True` (`subprocess.run([\"ls\", path])`), or `shlex.quote` every inserted value."),
    ("SEC-005", M, "os.system / os.popen",
     "These always go through the shell, so any interpolated value is a command-injection risk and errors are easy to ignore.",
     "Use `subprocess.run([...], check=True)` with an argument list."),
    ("SEC-006", H, "Hard-coded secret or token",
     "Credentials in source end up in version control, logs and container images. The report shows only the first 4 characters and the length.",
     "Move it to an environment variable or secret manager, remove it from history and rotate it now."),
    ("SEC-007", M, "tempfile.mktemp",
     "`mktemp` returns a name without creating the file, so another process can create it first (race, symlink attack).",
     "Use `tempfile.mkstemp`, `NamedTemporaryFile` or `TemporaryDirectory`."),
    ("SEC-008", H, "TLS verification disabled (verify=False)",
     "`requests`/`httpx` with `verify=False` accept any certificate, so a man-in-the-middle can read and alter the traffic.",
     "Remove `verify=False`; to trust a private CA pass `verify=\"/path/ca.pem\"`."),
    ("SEC-009", L, "assert used to validate input",
     "`assert` is stripped when Python runs with `-O`, so a check on function arguments silently disappears.",
     "Raise `ValueError` / `TypeError` explicitly for validation; keep `assert` for internal invariants and tests."),
    ("SEC-010", M, "tar/zip extractall without member filtering (path traversal)",
     "Archive members named `../../x` or absolute paths can write outside the target directory. `tarfile.extractall` is only safe with `filter=\"data\"` (3.12+).",
     "Use `tar.extractall(dest, filter=\"data\")`, or check each member's resolved path stays inside `dest` before extracting."),
    ("SEC-011", H, "SQL built with string formatting",
     "Formatting values into a query with f-strings, `%`, `.format` or `+` allows SQL injection.",
     "Use placeholders: `cur.execute(\"SELECT * FROM t WHERE id = ?\", (x,))` (or `%s` with the driver)."),
    ("SEC-012", H, "Flask/Django app run with debug=True",
     "The Werkzeug debugger exposes an interactive console that gives code execution to anyone who can reach the port.",
     "Read the flag from the environment and keep it off in production; use a WSGI server."),
    ("SEC-013", M, "Binding to 0.0.0.0",
     "Listening on all interfaces exposes the service to the whole network, often unintentionally on shared or cloud machines.",
     "Bind to `127.0.0.1` unless remote access is intended; then put it behind auth and a firewall."),
    ("SEC-014", M, "Weak hash (md5 / sha1)",
     "MD5 and SHA-1 have practical collisions and are far too fast for passwords.",
     "Use `hashlib.sha256`/`blake2b` for integrity, `hashlib.scrypt` / argon2 / bcrypt for passwords; `usedforsecurity=False` marks a non-security use."),
    ("SEC-015", H, "World-writable file permissions (chmod)",
     "Mode bits like 0o777 or 0o666 let any local user modify the file, enabling tampering or privilege escalation.",
     "Use 0o600 for private files, 0o644 / 0o755 for public ones."),
]
RULES: dict[str, RuleInfo] = {r[0]: RuleInfo(*r) for r in _RULES}
