"""Line-based scanner for GitHub Actions and GitLab CI files. No YAML parser: stdlib only, so the
structure we need (jobs, steps, run blocks) is recovered from indentation. Heuristic by design."""
from __future__ import annotations

import re
from typing import Iterator

from checksnap.core import Evidence, Finding

from .rules import RULES

Lines = list[str]


def ind(l: str) -> int:
    return len(l) - len(l.lstrip(" "))


def blank(l: str) -> bool:
    s = l.strip()
    return not s or s.startswith("#")


def _f(rule: str, rel: str, line: int, lines: Lines, detail: str = "", snippet: str | None = None) -> Finding:
    r = RULES[rule]
    snip = (snippet if snippet is not None else lines[line - 1].strip())[:160]
    return Finding("cicd", rule, r.severity, r.title, detail or r.explanation,
                   [Evidence(rel, line, line, snip)], source="static", fix_hint=r.fix_hint)


def run_lines(lines: Lines) -> Iterator[tuple[int, str]]:
    """Yield (lineno, text) for every shell line under a GitHub `run:` key (inline or block)."""
    for i, l in enumerate(lines):
        m = re.match(r"^(\s*)(-\s+)?run:\s*(.*)$", l)
        if not m:
            continue
        col = len(m.group(1)) + len(m.group(2) or "")
        val = m.group(3).strip()
        if val and not re.match(r"^[|>][+-]?\d?\s*(#.*)?$", val):
            yield i + 1, val
            continue
        for j in range(i + 1, len(lines)):
            if not lines[j].strip():
                continue
            if ind(lines[j]) <= col:
                break
            if not lines[j].strip().startswith("#"):
                yield j + 1, lines[j].strip()


def gitlab_script_lines(lines: Lines) -> Iterator[tuple[int, str]]:
    for i, l in enumerate(lines):
        m = re.match(r"^(\s*)(?:before_|after_)?script:\s*(.*)$", l)
        if not m:
            continue
        if m.group(2).strip() and not m.group(2).startswith("#"):
            yield i + 1, m.group(2).strip()
        for j in range(i + 1, len(lines)):
            if not lines[j].strip():
                continue
            if ind(lines[j]) <= len(m.group(1)):
                break
            if not lines[j].strip().startswith("#"):
                yield j + 1, re.sub(r"^-\s+", "", lines[j].strip())


def github_jobs(lines: Lines) -> list[dict]:
    """Each job: id, start (0-based header line), end (exclusive), n (indent of its keys)."""
    start = next((i for i, l in enumerate(lines) if re.match(r"^jobs:\s*$", l)), None)
    if start is None:
        return []
    n = next((ind(l) for l in lines[start + 1:] if not blank(l)), None)
    if n is None:
        return []
    heads = []
    for i in range(start + 1, len(lines)):
        l = lines[i]
        if blank(l):
            continue
        if ind(l) < n:
            break
        m = re.match(r"^ {%d}([\w.-]+):\s*(#.*)?$" % n, l)
        if m:
            heads.append((m.group(1), i))
    out = []
    for k, (jid, i) in enumerate(heads):
        end = heads[k + 1][1] if k + 1 < len(heads) else len(lines)
        for j in range(i + 1, end):
            if not blank(lines[j]) and ind(lines[j]) < n:
                end = j
                break
        key_ind = next((ind(l) for l in lines[i + 1:end] if not blank(l)), n + 2)
        keys = {m.group(1) for l in lines[i + 1:end] if ind(l) == key_ind and (m := re.match(r"^\s*([\w-]+):", l))}
        out.append({"id": jid, "start": i, "end": end, "keys": keys, "kind": "job"})
    return out


# ---------------------------------------------------------------- generic (both CI systems)
CURL_BASH = re.compile(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:ba)?sh\s+<\(\s*(?:curl|wget)\b")
SECRET_KEY = re.compile(r"^\s*-?\s*([\w.-]*(?:password|passwd|secret|token|api_?key|private_?key|access_?key)):\s*(.*?)\s*(#.*)?$", re.I)
PLACEHOLDER = re.compile(r"^(?:\$|\$\{|\{\{|<|\[|%|true$|false$|null$|~$|none$|changeme|xxx|\*+$|example|your|dummy|test$|\.{3})", re.I)
INSTALL = re.compile(r"\b(?:npm\s+(?:ci|install)|yarn(?:\s+install)?|pnpm\s+install|poetry\s+install|bundle\s+install|composer\s+install)\s*(?:--[\w-]+(?:=\S+)?\s*)*$|\bpip3?\s+install\b.*(?:\s-r\s|\s-e\s|\s\.(?:\[|\s|$))")
CACHE = re.compile(r"actions/cache|^\s*-?\s*cache:|cache-dependency-path|setup-uv|cache-from", re.M)


def generic(lines: Lines, rel: str, scripts: list[tuple[int, str]]) -> list[Finding]:
    out: list[Finding] = []
    for no, s in scripts:
        if CURL_BASH.search(s):
            out.append(_f("CI-010", rel, no, lines))
    for i, l in enumerate(lines):
        if blank(l):
            continue
        m = SECRET_KEY.match(l)
        if m:
            v = m.group(2).strip().strip("'\"")
            if len(v) >= 6 and not PLACEHOLDER.match(v) and " " not in v:
                out.append(_f("CI-018", rel, i + 1, lines, snippet=f"{m.group(1)}: <{len(v)} chars, hidden>"))
    text = "\n".join(l for l in lines if not l.strip().startswith("#"))
    if not CACHE.search(text):
        first = next((no for no, s in scripts if INSTALL.search(s)), None)
        if first:
            out.append(_f("CI-012", rel, first, lines))
    return out


# ---------------------------------------------------------------- GitHub Actions
BRANCHY = re.compile(r"^(?:main|master|dev|develop|development|trunk|head|latest|stable|release|next)$|^[a-z][\w./-]*$", re.I)
SHA = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)
VERSION = re.compile(r"^v?\d[\w.+-]*$")
INJECT = re.compile(
    r"\$\{\{\s*(?:github\.head_ref\b|github\.event\.(?:inputs\.|(?!repository\.)[\w.\[\]*]*?\.(?:title|body|ref|label|message|name|email|default_branch)\b|commits|pages))")
CRITICAL = re.compile(r"deploy|publish|release|pytest|(?:npm|yarn|pnpm)\s+(?:run\s+)?test|go\s+test|cargo\s+test|mvn\b.*\btest|audit|security|codeql|trivy|snyk|lint|terraform\s+apply|\btest(?:s)?\b", re.I)
TEST_CMD = re.compile(r"pytest|(?:npm|yarn|pnpm)\s+(?:run\s+)?test|go\s+test|cargo\s+test|mvn\b.*\btest|gradle\w*\s+test|rspec|phpunit", re.I)
DEPLOY_ID = re.compile(r"deploy|release|publish", re.I)


def analyze_github(text: str, rel: str) -> list[Finding]:
    lines = text.splitlines()
    out: list[Finding] = []
    scripts = list(run_lines(lines))
    out += generic(lines, rel, scripts)
    prt = any(re.search(r"\bpull_request_target\b", l) for l in lines if not blank(l))
    for i, l in enumerate(lines):
        if blank(l):
            continue
        m = re.search(r"\buses:\s*['\"]?([^@\s'\"]+)@([^\s'\"#]+)", l)
        if m and not m.group(1).startswith(("./", "docker://")):
            ref = m.group(2)
            if not SHA.match(ref):
                out.append(_f("CI-002" if BRANCHY.match(ref) and not VERSION.match(ref) else "CI-001", rel, i + 1, lines))
        if prt and re.match(r"^\s*(?:ref|repository):.*(?:pull_request\.head\.(?:sha|ref|repo)|github\.head_ref|workflow_run\.head_)", l):
            out.append(_f("CI-003", rel, i + 1, lines))
        if re.match(r"^\s*permissions:\s*write-all\b", l):
            out.append(_f("CI-006", rel, i + 1, lines))
        if re.match(r"^\s*(?:-\s+)?runs-on:\s*\[?\s*['\"]?(?:ubuntu|windows|macos)-latest\b", l):
            out.append(_f("CI-014", rel, i + 1, lines))
        if re.match(r"^\s*-?\s*continue-on-error:\s*true\b", l):
            lo = i
            while lo > 0 and not (re.match(r"^\s*-\s", lines[lo]) and ind(lines[lo]) <= ind(l)):
                lo -= 1
            d = ind(lines[lo])
            hi = next((j for j in range(i + 1, len(lines)) if not blank(lines[j]) and ind(lines[j]) <= d), len(lines))
            if lines[lo].lstrip().startswith("-") and CRITICAL.search("\n".join(lines[lo:hi])):
                out.append(_f("CI-011", rel, i + 1, lines))
    for no, s in scripts:
        if INJECT.search(s):
            out.append(_f("CI-004", rel, no, lines))
        if re.search(r"\b(?:echo|printf)\b[^|>]*(?:\$\{\{\s*secrets\.|\$\{?\w*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY)\w*)", s) and not re.search(r"[|>]", s.split("secrets.")[-1] if "secrets." in s else s):
            out.append(_f("CI-007", rel, no, lines))
        if re.search(r"::(?:set-output|save-state|set-env|add-path)\b", s):
            out.append(_f("CI-013", rel, no, lines))
    jobs = github_jobs(lines)
    top_perm = any(re.match(r"^permissions:", l) for l in lines)
    top_conc = any(re.match(r"^concurrency:", l) for l in lines)
    missing = [j for j in jobs if "permissions" not in j["keys"] and "uses" not in j["keys"]]
    if jobs and not top_perm and missing:
        out.append(_f("CI-005", rel, missing[0]["start"] + 1, lines,
                      f"{len(missing)} job(s) have no permissions and the workflow sets none. " + RULES["CI-005"].explanation))
    for j in jobs:
        seg = lines[j["start"]:j["end"]]
        if "uses" in j["keys"]:
            continue
        if "timeout-minutes" not in j["keys"]:
            out.append(_f("CI-008", rel, j["start"] + 1, lines))
        if DEPLOY_ID.search(j["id"]) and not top_conc and "concurrency" not in j["keys"]:
            out.append(_f("CI-009", rel, j["start"] + 1, lines))
        steps = sum(1 for l in seg if re.match(r"^\s*-\s+(?:name|uses|run|id|if|with|env):", l))
        if steps >= 8 and "strategy" not in j["keys"] and any(TEST_CMD.search(s) for no, s in scripts if j["start"] < no <= j["end"]):
            out.append(_f("CI-015", rel, j["start"] + 1, lines))
    return out


# ---------------------------------------------------------------- GitLab CI
RESERVED = {"stages", "variables", "default", "include", "workflow", "image", "services", "cache", "before_script", "after_script", "pages_url"}
GL_DEPLOY = re.compile(r"deploy|release|publish|prod", re.I)
IMG = re.compile(r"^\s*(?:image:|name:|-)\s*['\"]?([\w.\-/:@]+):latest['\"]?\s*$|^\s*image:\s*['\"]?([\w.\-/]+):latest['\"]?\s*$")


def analyze_gitlab(text: str, rel: str) -> list[Finding]:
    lines = text.splitlines()
    scripts = list(gitlab_script_lines(lines))
    out = generic(lines, rel, scripts)
    for i, l in enumerate(lines):
        if not blank(l) and IMG.match(l):
            out.append(_f("CI-016", rel, i + 1, lines))
    heads = [(m.group(1), i) for i, l in enumerate(lines) if (m := re.match(r"^([\w.-]+):", l))]
    for k, (name, i) in enumerate(heads):
        if name.startswith(".") or name in RESERVED or not GL_DEPLOY.search(name):
            continue
        end = heads[k + 1][1] if k + 1 < len(heads) else len(lines)
        body = "\n".join(l for l in lines[i + 1:end] if not l.strip().startswith("#"))
        if "script" in body and not re.search(r"^\s+(?:rules|only|except|extends):|^\s+when:\s*manual", body, re.M):
            out.append(_f("CI-017", rel, i + 1, lines))
    return out


def analyze(text: str, rel: str) -> list[Finding]:
    if rel.rsplit("/", 1)[-1].endswith(".gitlab-ci.yml"):
        return analyze_gitlab(text, rel)
    return analyze_github(text, rel)
