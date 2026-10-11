"""Manifest parsers: each returns a Parsed (deps, pip-style options, python constraints). Stdlib only, no network.
Line numbers are exact for requirements files and best-effort (first line mentioning the name) for the others."""
from __future__ import annotations

import configparser
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Dep:
    name: str
    spec: str            # normalized, no spaces: ">=1.2,<2"; "" when unconstrained
    file: str
    line: int
    group: str = "main"  # "main" or an extra/dev/group name
    url: str = ""        # direct reference (git+..., http...), if any
    marker: str = ""


@dataclass
class Opt:
    kind: str            # "index-url" | "extra-index-url" | "trusted-host" | "find-links" | "verify-ssl-off"
    value: str
    file: str
    line: int


@dataclass
class Parsed:
    deps: list[Dep] = field(default_factory=list)
    opts: list[Opt] = field(default_factory=list)
    pythons: list[str] = field(default_factory=list)


_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_EGG = re.compile(r"[#&]egg=([A-Za-z0-9._-]+)")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_req(s: str) -> tuple[str, str, str, str] | None:
    """PEP 508-ish string or pip URL line -> (name, spec, url, marker). None if it is not a requirement."""
    s = s.strip()
    if s.startswith("-e "):
        s = s[3:].strip()
    marker = ""
    if ";" in s:
        s, marker = (p.strip() for p in s.split(";", 1))
    if re.match(r"^(git\+|hg\+|svn\+|bzr\+|https?://|file:)", s):
        m = _EGG.search(s)
        name = m.group(1) if m else re.sub(r"\.git$", "", s.split("#")[0].rstrip("/").rsplit("/", 1)[-1].split("@")[0])
        return name, "", s, marker
    m = _REQ.match(s)
    if not m:
        return None
    name, rest = m.group(1), m.group(3).strip()
    if rest.startswith("@"):
        return name, "", rest[1:].strip(), marker
    return name, re.sub(r"[\s()]", "", rest), "", marker


def _find_line(text: str, needle: str) -> int:
    n = needle.lower()
    for i, ln in enumerate(text.splitlines(), 1):
        if n in ln.lower():
            return i
    return 1


_OPTS = {"--index-url": "index-url", "-i": "index-url", "--extra-index-url": "extra-index-url",
         "--trusted-host": "trusted-host", "--find-links": "find-links", "-f": "find-links"}


def _req_line(raw: str, rel: str, ln: int, out: Parsed, group: str = "main") -> None:
    line = re.sub(r"\s--hash=\S+", "", raw)
    line = re.sub(r"(^|\s)#.*$", "", line).strip()
    if not line:
        return
    if line.startswith("-") and not line.startswith("-e "):
        parts = re.split(r"[=\s]+", line, maxsplit=1)
        if parts[0] in _OPTS and len(parts) == 2:
            out.opts.append(Opt(_OPTS[parts[0]], parts[1].strip(), rel, ln))
        return
    r = parse_req(line)
    if r:
        out.deps.append(Dep(r[0], r[1], rel, ln, group, r[2], r[3]))


def parse_requirements(text: str, rel: str) -> Parsed:
    out = Parsed()
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        if raw.rstrip().endswith("\\"):
            buf, start = buf + raw.rstrip()[:-1] + " ", start or i
            continue
        _req_line(buf + raw, rel, start or i, out)
        buf, start = "", 0
    if buf:
        _req_line(buf, rel, start, out)
    return out


def _poetry_spec(v: str) -> str:
    v = v.strip()
    if v == "*":
        return ""
    return "==" + v if v[:1].isdigit() and "," not in v else v.replace(" ", "")


def _poetry(deps: dict, text: str, rel: str, out: Parsed, group: str) -> None:
    for name, v in deps.items():
        if name.lower() == "python":
            out.pythons.append(str(v))
            continue
        ln = _find_line(text, name)
        if isinstance(v, str):
            out.deps.append(Dep(name, _poetry_spec(v), rel, ln, group))
        elif isinstance(v, dict):
            url = v.get("git", "") or v.get("url", "")
            if url and v.get("git"):
                ref = v.get("rev", "")
                url = f"git+{url}" + (f"@{ref}" if ref else (f"@{v['tag']}" if v.get("tag") else (f"@{v['branch']}" if v.get("branch") else "")))
            out.deps.append(Dep(name, _poetry_spec(str(v.get("version", "*"))), rel, ln, group, url))
        elif isinstance(v, list):
            for item in v:
                out.deps.append(Dep(name, _poetry_spec(str(item.get("version", "*"))) if isinstance(item, dict) else "", rel, ln, group))


def parse_pyproject(text: str, rel: str) -> Parsed:
    out = Parsed()
    data = tomllib.loads(text)
    proj = data.get("project", {})
    if proj.get("requires-python"):
        out.pythons.append(proj["requires-python"])
    def add(strs: list, group: str) -> None:
        for s in strs:
            if isinstance(s, str) and (r := parse_req(s)):
                out.deps.append(Dep(r[0], r[1], rel, _find_line(text, r[0]), group, r[2], r[3]))
    add(proj.get("dependencies", []), "main")
    for g, strs in proj.get("optional-dependencies", {}).items():
        add(strs, g)
    for g, strs in data.get("dependency-groups", {}).items():
        add([s for s in strs if isinstance(s, str)], g)
    poetry = data.get("tool", {}).get("poetry", {})
    _poetry(poetry.get("dependencies", {}), text, rel, out, "main")
    _poetry(poetry.get("dev-dependencies", {}), text, rel, out, "dev")
    for g, body in poetry.get("group", {}).items():
        _poetry(body.get("dependencies", {}), text, rel, out, g)
    for src in poetry.get("source", []) if isinstance(poetry.get("source"), list) else []:
        if isinstance(src, dict) and src.get("url"):
            out.opts.append(Opt("index-url", src["url"], rel, _find_line(text, src["url"])))
    return out


def parse_setup_cfg(text: str, rel: str) -> Parsed:
    out = Parsed()
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_string(text)
    if cp.has_option("options", "python_requires"):
        out.pythons.append(cp.get("options", "python_requires").strip())
    def add(blob: str, group: str) -> None:
        for raw in blob.splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and (r := parse_req(line)):
                out.deps.append(Dep(r[0], r[1], rel, _find_line(text, line), group, r[2], r[3]))
    if cp.has_option("options", "install_requires"):
        add(cp.get("options", "install_requires"), "main")
    if cp.has_section("options.extras_require"):
        for g, blob in cp.items("options.extras_require"):
            add(blob, g)
    return out


def parse_pipfile(text: str, rel: str) -> Parsed:
    out = Parsed()
    data = tomllib.loads(text)
    for sec, group in (("packages", "main"), ("dev-packages", "dev")):
        _poetry({k: ("*" if v == "*" else v) for k, v in data.get(sec, {}).items()}, text, rel, out, group)
    req = data.get("requires", {})
    for k in ("python_version", "python_full_version"):
        if req.get(k):
            out.pythons.append(str(req[k]))
    for src in data.get("source", []):
        ln = _find_line(text, src.get("url", "") or "source")
        if src.get("url"):
            out.opts.append(Opt("index-url", src["url"], rel, ln))
        if src.get("verify_ssl") is False:
            out.opts.append(Opt("verify-ssl-off", src.get("name", src.get("url", "")), rel, ln))
    return out


def parse_environment_yml(text: str, rel: str) -> Parsed:
    """Minimal line parser for the two shapes conda files use (no PyYAML): `dependencies:` list with an optional nested `- pip:` list."""
    out = Parsed()
    section, in_pip = "", False
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #")[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "-")) and line.endswith(":"):
            section, in_pip = line[:-1].strip(), False
            continue
        item = line.strip()
        if not item.startswith("- "):
            continue
        item = item[2:].strip()
        if section == "channels":
            if item.startswith("http://"):
                out.opts.append(Opt("index-url", item, rel, i))
        elif section == "dependencies":
            if item.rstrip(":") == "pip":
                in_pip = True
            elif in_pip and line.startswith("    "):
                _req_line(item, rel, i, out, "pip")
            else:
                in_pip = False
                item = item.split("::")[-1]
                m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$", item)
                if not m:
                    continue
                name, spec = m.group(1), m.group(2).replace(" ", "")
                if spec.startswith("=") and not spec.startswith("=="):
                    spec = "==" + spec[1:].split("=")[0]
                elif spec and spec[0].isdigit():
                    spec = "==" + spec.split("=")[0]
                if name == "python":
                    out.pythons.append(spec or "*")
                else:
                    out.deps.append(Dep(name, spec, rel, i))
    return out


def parse_file(path: Path, rel: str) -> Parsed | None:
    n = path.name.lower()
    text = path.read_text(encoding="utf-8", errors="replace")
    if n == "pyproject.toml":
        return parse_pyproject(text, rel)
    if n == "setup.cfg":
        return parse_setup_cfg(text, rel)
    if n == "pipfile":
        return parse_pipfile(text, rel)
    if n in ("environment.yml", "environment.yaml"):
        return parse_environment_yml(text, rel)
    return parse_requirements(text, rel)


def is_manifest(name: str) -> bool:
    n = name.lower()
    return (n.startswith("requirements") and n.endswith(".txt")) or n in ("pyproject.toml", "setup.cfg", "pipfile", "environment.yml", "environment.yaml")
