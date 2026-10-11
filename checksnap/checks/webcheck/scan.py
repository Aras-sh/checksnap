"""Static HTML / CSS / JS audit with html.parser + regex. Pure functions, no I/O."""
from __future__ import annotations

import re
from html.parser import HTMLParser

from checksnap.core import Evidence, Finding

from .rules import RULES

CAP = 10                                              # max findings per rule per file; keeps noisy pages readable
B64 = re.compile(r"data:[\w/+.-]+;base64,[A-Za-z0-9+/=]{136000,}")      # 136k chars ~ 100 KB decoded
OLD = re.compile(r"(jquery|bootstrap)[/@.-]v?(\d+)\.(\d+)", re.I)
CONSOLE = re.compile(r"^\s*(console\.log\s*\(|debugger\s*;?\s*$)")
SKIP_INPUT = {"hidden", "submit", "button", "reset", "image"}
VOID_OK = {"img", "br", "input", "meta", "link", "hr"}
SUBRES = {"script": "src", "img": "src", "iframe": "src", "source": "src", "video": "src", "audio": "src", "link": "href"}


def outdated(ref: str) -> str | None:
    m = OLD.search(ref)
    if not m:
        return None
    lib, major = m.group(1).lower(), int(m.group(2))
    if (lib == "jquery" and major < 3) or (lib == "bootstrap" and major < 5):
        return f"{lib} {m.group(2)}.{m.group(3)}"
    return None


class Audit(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hits: list[tuple[str, int, str]] = []
        self.ids: dict[str, int] = {}
        self.labels_for: set[str] = set()
        self.controls: list[tuple[int, dict, bool]] = []     # (line, attrs, inside <label>)
        self.mixed: list[tuple[int, str]] = []
        self.open: list[list] = []                            # [tag, line, ok] for a / button
        self.label_depth = 0
        self.in_head = False
        self.is_doc = False
        self.has = set()
        self.last_h = 0
        self.title_text = ""
        self.in_title = False
        self.https = False

    def hit(self, rule: str, line: int, detail: str = "") -> None:
        self.hits.append((rule, line, detail))

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        line = self.getpos()[0]
        for o in self.open:                                   # nested content that names the link/button
            if a.get("aria-label", "").strip() or (tag == "img" and a.get("alt", "").strip()) or tag == "svg":
                o[2] = True
        if tag == "html":
            self.is_doc = True
            if not a.get("lang", "").strip():
                self.hit("WEB-002", line)
        elif tag == "head":
            self.in_head = True
        elif tag == "title":
            self.in_title = True
            self.has.add("title")
        elif tag == "meta":
            n = a.get("name", "").lower()
            if n == "viewport":
                self.has.add("viewport")
            elif n == "description" and a.get("content", "").strip():
                self.has.add("description")
            if a.get("property", "").lower() == "og:url" and a.get("content", "").startswith("https://"):
                self.https = True
        elif tag == "link":
            rel = a.get("rel", "").lower().split()
            if "canonical" in rel:
                self.has.add("canonical")
                if a.get("href", "").startswith("https://"):
                    self.https = True
            if any(r in ("icon", "apple-touch-icon", "shortcut") for r in rel):
                self.has.add("icon")
        if a.get("id"):
            if a["id"] in self.ids:
                self.hit("WEB-008", line, f"id \"{a['id']}\" also used on line {self.ids[a['id']]}")
            else:
                self.ids[a["id"]] = line
        if tag == "img":
            if "alt" not in a:
                self.hit("WEB-001", line)
            if not ("width" in a and "height" in a) and "aspect-ratio" not in a.get("style", ""):
                self.hit("WEB-014", line)
        if re.fullmatch(r"h[1-6]", tag):
            lvl = int(tag[1])
            if self.last_h and lvl > self.last_h + 1:
                self.hit("WEB-009", line, f"h{self.last_h} followed by h{lvl}")
            self.last_h = lvl
        if tag == "label":
            self.label_depth += 1
            if a.get("for"):
                self.labels_for.add(a["for"])
        if tag in ("input", "select", "textarea") and a.get("type", "text").lower() not in SKIP_INPUT:
            self.controls.append((line, a, self.label_depth > 0))
        if tag == "a":
            href = a.get("href")
            if href is not None and (href.strip() in ("", "#") or href.strip().lower().startswith("javascript:")):
                self.hit("WEB-010", line, f"href=\"{href.strip()[:30]}\"")
            if a.get("target", "").lower() == "_blank" and "noopener" not in a.get("rel", "").lower() and "noreferrer" not in a.get("rel", "").lower():
                self.hit("WEB-011", line)
            if href is not None:
                self.open.append(["a", line, bool(a.get("aria-label", "").strip() or a.get("title", "").strip())])
        if tag == "button":
            self.open.append(["button", line, bool(a.get("aria-label", "").strip() or a.get("aria-labelledby") or a.get("title", "").strip()
                                                    or a.get("value", "").strip())])
        for k in a:
            if k.startswith("on") and len(k) > 2 and tag not in ("html",):
                self.hit("WEB-015", line, k)
                break
        src = a.get(SUBRES.get(tag, "src"), "")
        if tag in SUBRES and src.lower().startswith("http://") and not (tag == "link" and "stylesheet" not in a.get("rel", "").lower()):
            self.mixed.append((line, src[:80]))
        if tag == "script":
            if src:
                if self.in_head and "defer" not in a and "async" not in a and a.get("type", "").lower() != "module":
                    self.hit("WEB-013", line, src[:80])
                if re.match(r"(https?:)?//", src, re.I) and "integrity" not in a and "localhost" not in src:
                    self.hit("WEB-016", line, src[:80])
        if tag == "link" and "stylesheet" in a.get("rel", "").lower():
            h = a.get("href", "")
            if re.match(r"(https?:)?//", h, re.I) and "integrity" not in a and "localhost" not in h and "fonts.googleapis.com" not in h:
                self.hit("WEB-016", line, h[:80])
        for ref in (src, a.get("href", "") if tag in ("link", "a") else ""):
            o = ref and outdated(ref)
            if o and tag in ("script", "link"):
                self.hit("WEB-019", line, o)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "head":
            self.in_head = False
        elif tag == "title":
            self.in_title = False
        elif tag == "label":
            self.label_depth = max(0, self.label_depth - 1)
        elif tag in ("a", "button"):
            for i in range(len(self.open) - 1, -1, -1):
                if self.open[i][0] == tag:
                    _, line, ok = self.open.pop(i)
                    if not ok:
                        self.hit("WEB-010" if tag == "a" else "WEB-007", line, "no text" if tag == "a" else "")
                    break

    def handle_data(self, data):
        if self.in_title:
            self.title_text += data
        if data.strip():
            for o in self.open:
                o[2] = True

    def finish(self) -> list[tuple[str, int, str]]:
        self.close()
        for line, a, wrapped in self.controls:
            named = (wrapped or a.get("id") in self.labels_for or a.get("aria-label", "").strip() or a.get("aria-labelledby")
                     or a.get("title", "").strip())
            if not named:
                self.hit("WEB-006", line)
        if self.https:
            for line, src in self.mixed:
                self.hit("WEB-012", line, src)
        if self.is_doc:                                       # fragments/templates have no <head>: skip document-level rules
            if "title" not in self.has or not self.title_text.strip():
                self.hit("WEB-003", 1)
            for r, key in (("WEB-004", "viewport"), ("WEB-005", "description"), ("WEB-020", "icon"), ("WEB-021", "canonical")):
                if key not in self.has:
                    self.hit(r, 1)
        return self.hits


def _mk(rule: str, rel: str, line: int, detail: str, snippet: str = "") -> Finding:
    i = RULES[rule]
    return Finding("web", rule, i.severity, i.title, detail, [Evidence(rel, line, line, snippet[:160])], source="static", fix_hint=i.fix_hint)


def analyze(text: str, rel: str, has_favicon_file: bool = False, size: int | None = None) -> list[Finding]:
    """Findings for one .html/.htm/.js/.mjs/.css file."""
    lines = text.splitlines()
    ext = rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
    raw: list[tuple[str, int, str]] = []
    if ext in ("html", "htm"):
        p = Audit()
        p.feed(text)
        raw += [h for h in p.finish() if not (h[0] == "WEB-020" and has_favicon_file)]
    else:
        if (size if size is not None else len(text)) > 1_000_000:
            raw.append(("WEB-018", 1, f"{(size or len(text)) / 1e6:.1f} MB"))
        o = outdated(rel.rsplit("/", 1)[-1])
        if o:
            raw.append(("WEB-019", 1, o))
        if ext in ("js", "mjs") and ".min." not in rel and len(text) <= 1_000_000:
            raw += [("WEB-022", i, "") for i, ln in enumerate(lines, 1) if CONSOLE.match(ln)]
    for m in B64.finditer(text):
        raw.append(("WEB-017", text.count("\n", 0, m.start()) + 1, f"~{len(m.group(0)) * 3 // 4 // 1000} KB"))
    out, per = [], {}
    for rule, ln, detail in raw:
        per[rule] = per.get(rule, 0) + 1
        if per[rule] <= CAP:
            snip = "" if rule == "WEB-017" else (lines[ln - 1].strip() if 0 < ln <= len(lines) else "")
            out.append(_mk(rule, rel, ln, detail, snip))
    return out
