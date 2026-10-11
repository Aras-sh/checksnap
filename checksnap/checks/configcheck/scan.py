"""Config-file heuristics for --check-config: regex line scans plus json/tomllib. They prefer missing a case to
crying wolf, and never put a full secret into a finding."""
from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path

from checksnap.core import Evidence, Finding

from .rules import RULES

SECRET_KEY = re.compile(r"(^|[_.\-])(password|passwd|pwd|secret|secret_?key|api_?key|apikey|access_?key|auth_?token|token|private_?key)$", re.I)
PASS_KEY = re.compile(r"(^|[_.\-])(password|passwd|pwd|secret)$", re.I)
PLACEHOLDER = re.compile(r"^(<.*>|\$\{+\s*\w.*|\{\{.*|%\(.*|enc\(|vault:|your[-_ ]|xxx|\*+$|example|dummy|todo|none$|null$|true$|false$|env|os\.)", re.I)
TOKEN = re.compile(r"(?<![A-Za-z0-9_-])(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)")
URL_PASS = re.compile(r"://[^/\s:@]+:([^@\s/]+)@")
WEAK = {"admin", "password", "changeme", "change_me", "123456", "12345678", "123456789", "secret", "root", "letmein", "qwerty",
        "default", "test", "passw0rd", "admin123", "password1", "pass", "1234"}
IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
LOCAL = re.compile(r"localhost|127\.0\.0\.1|\[?::1\]?(?![:\w])", re.I)
PRIVATE_HOST = re.compile(r"^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[::1\]|[^.:]+(:\d+)?$|.*\.(local|test|internal|localhost|example|invalid|lan|svc)(:\d+)?$|(www\.)?example\.(com|org|net))", re.I)
HTTP_URL = re.compile(r"http://([^/\s\"'?#]+)", re.I)
CORS_LINE = re.compile(r"cors|allow[-_]?origin|allowed[-_]?origins|access-control-allow-origin", re.I)
STAR = re.compile(r"""(^|[\s\[,:"'])\*($|[\s\],"';])""")
PROD = re.compile(r"(^|[/._-])prod(uction)?($|[/._-])", re.I)
KEYFILE = re.compile(r"\.(key|pem|p12|pfx|jks)$|id_rsa|id_ed25519|id_ecdsa", re.I)
KEYNAME = re.compile(r"key|priv|identity|id_rsa|id_ed", re.I)
JSON_SKIP = re.compile(r"(^|/)(tsconfig[^/]*|jsconfig[^/]*|package-lock|composer|[^/]*\.lock)\.json$|(^|/)(\.vscode|\.devcontainer)/|(^|/)(tsconfig|jsconfig)[^/]*\.json$", re.I)
EXAMPLE = re.compile(r"example|sample|template|\.dist$", re.I)
EXT = {".ini", ".cfg", ".toml", ".json", ".yml", ".yaml", ".properties"}
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][\w.\-]*)\s*=(.*)$")
KV_LINE = re.compile(r"^\s*([^\s=:#;!\[][^=:]*?)\s*[=:]\s*(.*)$")
YAML_LINE = re.compile(r"""^(\s*)(-\s+)?("[^"]+"|'[^']+'|[\w.\-/ ]+?)\s*:(?:\s+(.*))?$""")
YAML_ITEM_ENV = re.compile(r"^(\s*)-\s+([A-Za-z_][\w]*)=(.*)$")
NGINX_LINE = re.compile(r"^\s*([A-Za-z_]\w*)\s+(.*?);\s*(#.*)?$")
NODE_ENV_KEYS = {"env", "app_env", "node_env", "environment", "flask_env", "rails_env"}
STD_VARS = {"HOME", "PATH", "USER", "PWD", "CI", "NODE_ENV", "TERM", "SHELL", "LANG", "TMPDIR", "DEBUG", "PYTHONPATH", "HOSTNAME", "LOGNAME",
            "TZ", "PORT", "HOST", "PYTHONUNBUFFERED", "VIRTUAL_ENV", "GITHUB_ACTIONS", "NO_COLOR", "FORCE_COLOR", "COLUMNS", "LINES", "EDITOR", "DISPLAY"}
CODE_RE = [re.compile(p) for p in (
    r"""os\.environ\[\s*['"](\w+)['"]\s*\]""", r"""os\.environ\.get\(\s*['"](\w+)['"]\s*\)""", r"""os\.getenv\(\s*['"](\w+)['"]\s*\)""",
    r"""process\.env\.([A-Za-z_]\w*)(?!\s*(?:\|\||\?\?))(?![\w])""", r"""process\.env\[\s*['"](\w+)['"]\s*\](?!\s*(?:\|\||\?\?))""")]
CODE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

# entry: (line, key, value, quoted)
Entry = tuple[int, str, str, bool]


def mask(s: str) -> str:
    return f"{s[:4]}**** (len {len(s)})"


def is_example(name: str) -> bool:
    return bool(EXAMPLE.search(name))


def kind_of(name: str) -> str | None:
    low = name.lower()
    if low.startswith(".env") or low.endswith(".env"):
        return "env"
    if low == "nginx.conf":
        return "nginx"
    ext = Path(low).suffix
    return {".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml", ".properties": "kv", ".ini": "kv", ".cfg": "kv"}.get(ext)


def _clean(raw: str, comments: bool) -> tuple[str, bool]:
    v = raw.strip()
    if v[:1] in "\"'" and len(v) > 1:
        end = v.find(v[0], 1)
        if end > 0:
            return v[1:end], True
    if comments:
        v = re.split(r"\s+#", v, 1)[0].strip()
    return v, False


def _line_of(lines: list[str], needle: str) -> int:
    for i, ln in enumerate(lines, 1):
        if needle in ln:
            return i
    return 1


def _flat(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict,)):
                yield from _flat(v, f"{prefix}{k}.")
            elif isinstance(v, list) and any(isinstance(x, dict) for x in v):
                for x in v:
                    yield from _flat(x, f"{prefix}{k}.")
            else:
                yield f"{prefix}{k}", v
    elif isinstance(obj, list):
        for x in obj:
            yield from _flat(x, prefix)


def _val(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple)):
        return json.dumps(v)
    return "" if v is None else str(v)


def parse(text: str, kind: str, relname: str):
    """Returns (entries, dupes[(line,key)], syntax[(rule,line,msg)], trailing[(line,key)], spaces[(line,key)])."""
    lines = text.splitlines()
    entries: list[Entry] = []
    dupes: list[tuple[int, str]] = []
    syntax: list[tuple[str, int, str]] = []
    trailing: list[tuple[int, str]] = []
    spaces: list[tuple[int, str]] = []
    if kind == "json":
        def hook(pairs):
            ks = [k for k, _ in pairs]
            for k in {k for k in ks if ks.count(k) > 1}:
                dupes.append((_line_of(lines, f'"{k}"'), k))
            return dict(pairs)
        try:
            obj = json.loads(text, object_pairs_hook=hook)
        except json.JSONDecodeError as e:
            syntax.append(("CFG-009", e.lineno, f"JSON: {e.msg}"))
            return entries, dupes, syntax, trailing, spaces
        for k, v in _flat(obj):
            entries.append((_line_of(lines, f'"{k.rsplit(".", 1)[-1]}"'), k, _val(v), False))
    elif kind == "toml":
        try:
            obj = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            m = re.search(r"line (\d+)", str(e))
            syntax.append(("CFG-009", int(m.group(1)) if m else 1, f"TOML: {e}"))
            return entries, dupes, syntax, trailing, spaces
        for k, v in _flat(obj):
            entries.append((_line_of(lines, k.rsplit(".", 1)[-1]), k, _val(v), False))
    elif kind == "yaml":
        stack: list[tuple[int, str]] = []
        seen: dict[tuple, set] = {}
        skip_indent = -1
        for n, ln in enumerate(lines, 1):
            if re.match(r"^\s*\t", ln):
                syntax.append(("CFG-010", n, "tab in indentation"))
                continue
            body = ln.strip()
            ind = len(ln) - len(ln.lstrip(" "))
            if not body or body.startswith("#"):
                continue
            if skip_indent >= 0:
                if ind > skip_indent:
                    continue
                skip_indent = -1
            if body in ("---", "..."):
                stack.clear(); seen.clear()
                continue
            mi = YAML_ITEM_ENV.match(ln)
            if mi:
                v, q = _clean(mi.group(3), True)
                entries.append((n, mi.group(2), v, q))
                continue
            m = YAML_LINE.match(ln)
            if not m:
                continue
            key = m.group(3).strip("\"'")
            eff = ind + (len(m.group(2)) if m.group(2) else 0)
            if m.group(2):
                for k in [k for k in seen if k[0] >= ind]:
                    del seen[k]
            while stack and stack[-1][0] >= eff:
                stack.pop()
            for k in [k for k in seen if k[0] > eff]:
                del seen[k]
            path = tuple(s[1] for s in stack)
            bucket = seen.setdefault((eff, path), set())
            if key in bucket:
                dupes.append((n, key))
            bucket.add(key)
            val, q = _clean(m.group(4) or "", True)
            if val in ("|", ">", "|-", ">-", "|+", ">+"):
                skip_indent = ind
                val = ""
            stack.append((eff, key))
            if val:
                entries.append((n, ".".join(path + (key,)), val, q))
    else:   # env, kv, nginx
        seen_k: set = set()
        section = ""
        for n, ln in enumerate(lines, 1):
            s = ln.strip()
            if not s or s[0] in "#;!" or s in ("{", "}"):
                continue
            if kind == "nginx":
                m = NGINX_LINE.match(ln)
                if m:
                    entries.append((n, m.group(1), m.group(2).strip(), False))
                continue
            if kind == "kv" and s.startswith("[") and s.endswith("]"):
                section = s[1:-1]
                continue
            m = (ENV_LINE if kind == "env" else KV_LINE).match(ln)
            if not m:
                continue
            key, raw = m.group(1).strip(), m.group(2)
            v, q = _clean(raw, kind == "env")
            ident = (section, key.lower() if kind == "kv" else key)
            if ident in seen_k:
                dupes.append((n, key))
            seen_k.add(ident)
            if raw != raw.rstrip() and raw.strip() and not q and not re.search(r"\s#", raw):
                trailing.append((n, key))
            if kind == "env" and not q and re.search(r"\s", v) and v:
                spaces.append((n, key))
            entries.append((n, f"{section}.{key}" if section else key, v, q))
    return entries, dupes, syntax, trailing, spaces


def _num(v: str) -> float | None:
    try:
        return float(v)
    except ValueError:
        return None


def analyze(text: str, rel: str, kind: str, base: Path | None = None) -> list[Finding]:
    out: list[Finding] = []
    name = rel.rsplit("/", 1)[-1]
    example = is_example(name)
    entries, dupes, syntax, trailing, spaces = parse(text, kind, rel)
    lines = text.splitlines()

    def add(rid: str, line: int, snippet: str, detail: str = "") -> None:
        r = RULES[rid]
        out.append(Finding("config", rid, r.severity, r.title, detail, [Evidence(rel, line, line, snippet[:120])], source="static", fix_hint=r.fix_hint))

    def raw(line: int) -> str:
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    for rid, line, msg in syntax:
        add(rid, line, raw(line), msg)
    for line, key in dupes:
        add("CFG-001", line, f"{key} (defined more than once)")
    for line, key in trailing:
        add("CFG-007", line, f"{key}=<value ends with whitespace>")
    for line, key in spaces:
        add("CFG-008", line, raw(line) if not SECRET_KEY.search(key) else f"{key}=<value with spaces>")
    prod = bool(PROD.search(rel)) or any(k.lower().rsplit(".", 1)[-1] in NODE_ENV_KEYS and v.lower() in ("prod", "production") for _, k, v, _q in entries)
    if example:
        prod = False
    for line, key, v, _q in entries:
        last = key.lower().rsplit(".", 1)[-1]
        low = v.lower()
        shown = f"{key}: {v[:60]}"
        pw = URL_PASS.search(v)
        secret_val = pw.group(1) if pw else (v if SECRET_KEY.search(last) else "")
        if not example:
            if TOKEN.search(v) or (secret_val and not PLACEHOLDER.match(secret_val) and (len(secret_val) >= 8 or secret_val.lower() in WEAK)):
                sv = secret_val or v
                if sv.lower() in WEAK and (pw or PASS_KEY.search(last)):
                    add("CFG-004", line, f"{key}: {mask(sv)}")
                else:
                    add("CFG-003", line, f"{key}: {mask(sv)}")
                continue
            if secret_val and secret_val.lower() in WEAK:
                add("CFG-004", line, f"{key}: {mask(secret_val)}")
                continue
        if prod:
            if last in ("debug", "flask_debug", "app_debug", "django_debug") and low in ("true", "1", "yes", "on"):
                add("CFG-002", line, shown)
            ips = [i for i in IPV4.findall(v) if all(int(o) <= 255 for o in i.split(".")) and i not in ("0.0.0.0", "127.0.0.1")]
            if LOCAL.search(v) and not re.search(r"bind|listen", last):
                add("CFG-005", line, shown, "points at localhost")
            elif ips and not re.search(r"version|cidr|subnet|mask|allow|trusted|proxy|dns|bind|listen", last):
                add("CFG-005", line, shown, "hard-coded IP address")
        for m in HTTP_URL.finditer(v):
            if not PRIVATE_HOST.match(m.group(1).split("@")[-1]) and "xmlns" not in last and "schema" not in last:
                add("CFG-011", line, shown)
                break
        if "timeout" in last or ("pool" in last and re.search(r"size|max", last)):
            n = _num(v)
            if n is not None:
                if "timeout" in last:
                    secs = n / 1000 if re.search(r"ms|milli", last) else n
                    limit = 3600 if re.search(r"(^|[_-])(s|sec|secs|seconds)$", last) else 3600 * 1000
                    bad = n <= 0 or (secs > 3600 and (n > limit if limit != 3600 else True))
                    if bad:
                        add("CFG-012", line, shown)
                elif n <= 0:
                    add("CFG-012", line, shown)
        whole = f"{key} {v}"
        if (CORS_LINE.search(whole) and STAR.search(v)) or (kind == "nginx" and CORS_LINE.search(v) and STAR.search(" " + v + " ")):
            add("CFG-013", line, shown)
        if KEYFILE.search(v) and "\n" not in v and (KEYNAME.search(last) or KEYNAME.search(v.rsplit("/", 1)[-1])) and not v.startswith(("http", "$")):
            reason = ""
            if v.startswith(("/tmp/", "/var/tmp/")):
                reason = "key stored in a temp directory"
            elif base is not None:
                p = Path(v).expanduser()
                p = p if p.is_absolute() else base / p
                try:
                    if p.is_file() and p.stat().st_mode & 0o004:
                        reason = f"mode {oct(p.stat().st_mode & 0o777)} is world-readable"
                except OSError:
                    pass
            if reason:
                add("CFG-014", line, shown, reason)
    return out


def env_keys(text: str) -> dict[str, int]:
    return {k: n for n, k, _v, _q in parse(text, "env", "")[0]}


def code_env_refs(text: str) -> list[tuple[str, int]]:
    refs = []
    for rx in CODE_RE:
        for m in rx.finditer(text):
            refs.append((m.group(1), text.count("\n", 0, m.start()) + 1))
    return refs
