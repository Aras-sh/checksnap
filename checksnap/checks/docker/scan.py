"""Static layer for --check-docker: a line scanner for Dockerfiles and a tiny indentation scanner for compose files
(no YAML library). Heuristics prefer missing a case to crying wolf; secret values are never put in a finding."""
from __future__ import annotations

import re

from checksnap.core import Evidence, Finding

from .rules import RULES

SECRET_NAME = re.compile(r"(^|_)(password|passwd|pwd|secret|secret_?key|api_?key|apikey|access_?key|auth_?token|token|private_?key)$", re.I)
PLACEHOLDER = re.compile(r"^(<.*>|\$\{.*\}|\{\{.*\}\}|\$\w+|your[-_ ]|change|xxx|example|dummy|test|todo|none|null|env)", re.I)
DEP_INSTALL = re.compile(r"\bpip3?\s+install\b.*\s-r\b|\bnpm\s+(ci|install)\b(?!.*\s-g\b)|\byarn(\s+install)?\s*($|&|;)|\bpnpm\s+install\b|"
                         r"\bbundle\s+install\b|\bcomposer\s+install\b|\bgo\s+mod\s+download\b|\bpoetry\s+install\b|\bpipenv\s+install\b")
CURL_SH = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(ba|z)?sh\s+<\(\s*(curl|wget)\b")
DB_PORTS = {"3306", "5432", "27017", "6379", "1433", "9200", "5984", "11211", "1521", "9042", "26257", "8086"}
ARCHIVE = re.compile(r"\.(tar|tgz|tar\.gz|tar\.xz|tar\.bz2|txz|tbz2)$", re.I)


def _f(check_rule: str, rel: str, ln: int, snippet: str, detail: str = "") -> Finding:
    info = RULES[check_rule]
    return Finding("docker", check_rule, info.severity, info.title, detail or info.explanation,
                   [Evidence(rel, ln, ln, snippet[:160])], source="static", fix_hint=info.fix_hint)


def _secret(name: str, value: str) -> bool:
    v = value.strip().strip("\"'")
    return bool(SECRET_NAME.search(name.strip())) and bool(v) and not PLACEHOLDER.match(v)


def _untagged(image: str) -> bool:
    image = image.strip().strip("\"'")
    if not image or "$" in image or "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest")


# ---------------------------------------------------------------- Dockerfile
def instructions(text: str) -> list[tuple[int, str, str]]:
    """(first line number, KEYWORD, rest) with backslash continuations joined and comments dropped."""
    out, buf, start = [], "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not buf and (not s or s.startswith("#")):
            continue
        if buf and s.startswith("#"):
            continue
        if not buf:
            start = n
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        buf += s
        kw, _, rest = buf.partition(" ")
        out.append((start, kw.upper(), rest.strip()))
        buf = ""
    if buf:
        kw, _, rest = buf.partition(" ")
        out.append((start, kw.upper(), rest.strip()))
    return out


def analyze_dockerfile(text: str, rel: str, has_ignore: bool = True) -> list[Finding]:
    out: list[Finding] = []
    ins = instructions(text)
    stages: list[dict] = []
    names: dict[str, dict] = {}
    for ln, kw, rest in ins:
        if kw == "FROM":
            toks = [t for t in rest.split() if not t.startswith("--")]
            image = toks[0] if toks else ""
            alias = toks[2].lower() if len(toks) >= 3 and toks[1].upper() == "AS" else ""
            st = {"ln": ln, "image": image, "ins": [], "parent": names.get(image.lower())}
            stages.append(st)
            if alias:
                names[alias] = st
            if image.lower() != "scratch" and image.lower() not in names and _untagged(image):
                out.append(_f("DOC-001", rel, ln, f"FROM {rest}"))
        elif stages:
            stages[-1]["ins"].append((ln, kw, rest))
    if not stages:
        return out
    pip_cache_env = any(kw == "ENV" and "PIP_NO_CACHE_DIR" in rest for _, kw, rest in ins)

    for st in stages:
        cmds = [ln for ln, kw, _ in st["ins"] if kw == "CMD"]
        if len(cmds) > 1:
            out.append(_f("DOC-013", rel, cmds[-1], "CMD (multiple)"))
        seen_install = False
        copy_all = 0
        for ln, kw, rest in st["ins"]:
            if kw == "ADD":
                args = [t for t in rest.split() if not t.startswith("--")]
                if args and not any(a.startswith(("http://", "https://", "git@")) or ARCHIVE.search(a) for a in args[:-1]):
                    out.append(_f("DOC-003", rel, ln, f"ADD {rest}"))
            elif kw in ("ENV", "ARG"):
                for name, value in _env_pairs(rest, kw):
                    if _secret(name, value):
                        out.append(_f("DOC-008", rel, ln, f"{kw} {name}=****"))
            elif kw == "EXPOSE" and any(re.fullmatch(r"22(/(tcp|udp))?", p) for p in rest.split()):
                out.append(_f("DOC-014", rel, ln, f"EXPOSE {rest}"))
            elif kw == "COPY":
                args = [t for t in rest.split() if not t.startswith("--")]
                if not any(t.startswith("--from") for t in rest.split()) and len(args) >= 2 and any(a in (".", "./") for a in args[:-1]):
                    copy_all = copy_all or ln
            elif kw == "RUN":
                if DEP_INSTALL.search(rest):
                    if copy_all and not seen_install:
                        out.append(_f("DOC-009", rel, copy_all, "COPY . ... (before dependency install)"))
                    seen_install = True
                cache_mount = "--mount=type=cache" in rest
                if re.search(r"\bapt(-get)?\s+(-\S+\s+)*install\b", rest):
                    if "--no-install-recommends" not in rest and "APT::Install-Recommends" not in rest:
                        out.append(_f("DOC-004", rel, ln, rest))
                    if not cache_mount and not re.search(r"rm\s+-\S*\s+/var/lib/apt/lists|apt(-get)?\s+clean", rest):
                        out.append(_f("DOC-005", rel, ln, rest))
                elif re.search(r"\bapt(-get)?\s+(-\S+\s+)*update\b", rest) and not cache_mount:
                    out.append(_f("DOC-006", rel, ln, rest))
                if re.search(r"\bpip3?\s+install\b", rest) and "--no-cache-dir" not in rest and not pip_cache_env and not cache_mount:
                    out.append(_f("DOC-007", rel, ln, rest))
                if CURL_SH.search(rest):
                    out.append(_f("DOC-012", rel, ln, rest))

    final = stages[-1]
    if final["image"].lower() != "scratch":
        chain, st = [], final
        while st:
            chain = [x for x in st["ins"] if x[1] == "USER"] + chain
            st = st["parent"]
        last = chain[-1][2].split(":")[0].strip().lower() if chain else ""
        if not chain or last in ("root", "0"):
            out.append(_f("DOC-002", rel, chain[-1][0] if chain else final["ln"], chain[-1][1] + " " + chain[-1][2] if chain else f"FROM {final['image']}"))
    if not any(kw == "HEALTHCHECK" for _, kw, _ in ins) and any(kw in ("CMD", "ENTRYPOINT") for _, kw, _ in final["ins"]):
        out.append(_f("DOC-011", rel, final["ln"], f"FROM {final['image']}"))
    if not has_ignore:
        out.append(_f("DOC-010", rel, stages[0]["ln"], "(no .dockerignore)"))
    return out


def _env_pairs(rest: str, kw: str) -> list[tuple[str, str]]:
    toks = rest.split()
    if toks and "=" in toks[0]:
        return [(m.group(1), m.group(2)) for m in re.finditer(r"([A-Za-z_]\w*)=(\"[^\"]*\"|'[^']*'|\S*)", rest)]
    if kw == "ENV":
        name, _, value = rest.partition(" ")
        return [(name, value)]
    return []


# ---------------------------------------------------------------- compose
def _strip(v: str) -> str:
    v = re.sub(r"\s+#.*$", "", v.strip())
    return v.strip().strip("\"'")


def _services(text: str) -> list[tuple[str, int, list[tuple[int, int, str]]]]:
    """[(service name, line, [(lineno, indent, stripped text)])] from the top-level `services:` map."""
    rows = []
    for n, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if s and not s.startswith("#"):
            rows.append((n, len(raw) - len(raw.lstrip(" ")), s))
    out, i = [], 0
    while i < len(rows) and not (rows[i][1] == 0 and rows[i][2].rstrip() == "services:"):
        i += 1
    i += 1
    child = None
    cur = None
    while i < len(rows):
        n, ind, s = rows[i]
        if ind == 0:
            break
        child = ind if child is None else child
        if ind == child and s.endswith(":"):
            cur = (s[:-1].strip("\"'"), n, [])
            out.append(cur)
        elif cur and ind > child:
            cur[2].append(rows[i])
        i += 1
    return out


def _section(body: list[tuple[int, int, str]], key: str):
    """(key line, scalar value, [(lineno, text)] of nested lines) for a direct key of the service, or None."""
    if not body:
        return None
    base = body[0][1]
    for idx, (n, ind, s) in enumerate(body):
        if ind == base and (s == f"{key}:" or s.startswith(f"{key}: ")):
            nested = []
            for n2, ind2, s2 in body[idx + 1:]:
                if ind2 > base or (ind2 == base and s2.startswith("- ")):
                    nested.append((n2, s2))
                else:
                    break
            return n, _strip(s[len(key) + 1:]), nested
    return None


def analyze_compose(text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    dev = bool(re.search(r"dev|test|override|local|debug", rel.rsplit("/", 1)[-1], re.I))
    for name, _line, body in _services(text):
        sec = lambda k: _section(body, k)  # noqa: E731
        if (s := sec("privileged")) and s[1].lower() in ("true", "yes"):
            out.append(_f("DOC-015", rel, s[0], f"{name}: privileged: true"))
        if (s := sec("network_mode")) and s[1] == "host":
            out.append(_f("DOC-016", rel, s[0], f"{name}: network_mode: host"))
        for n, _ind, s in body:
            if re.search(r"/(var/)?run/docker\.sock", s):
                out.append(_f("DOC-017", rel, n, s))
        if (s := sec("environment")):
            for n, item in s[2]:
                item = item[2:].strip() if item.startswith("- ") else item
                m = re.match(r"([A-Za-z_]\w*)\s*[=:]\s*(.*)$", item)
                if m and _secret(m.group(1), _strip(m.group(2))):
                    out.append(_f("DOC-018", rel, n, f"{name}: {m.group(1)}=****"))
        img = sec("image")
        if img and not sec("build") and _untagged(img[1]):
            out.append(_f("DOC-019", rel, img[0], f"{name}: image: {img[1]}"))
        if (p := sec("ports")):
            for n, item in p[2]:
                item = _strip(item[2:] if item.startswith("- ") else item)
                parts = item.split("/")[0].split(":")
                if parts[0].startswith("[") or not parts[0]:
                    continue
                container = parts[-1]
                ip = parts[0] if len(parts) == 3 else ""
                if container in DB_PORTS and (len(parts) < 3 or ip in ("", "0.0.0.0", "::")) and "$" not in item:
                    out.append(_f("DOC-022", rel, n, f"{name}: {item}"))
        if not dev and (img or sec("build")) and not sec("profiles"):
            if not sec("restart") and not sec("deploy"):
                out.append(_f("DOC-020", rel, _line, f"service {name}"))
            if not sec("healthcheck"):
                out.append(_f("DOC-021", rel, _line, f"service {name}"))
    return out
