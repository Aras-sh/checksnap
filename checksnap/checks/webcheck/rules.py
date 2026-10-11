"""Rule catalog for --check-web: ids, severities and texts in one place (feeds --explain and docs/RULES.md)."""
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
    ("WEB-001", M, "Image without alt attribute",
     "Screen readers have nothing to announce, and the text is lost when the image fails to load.",
     "Add a short `alt` describing the image, or `alt=\"\"` if it is purely decorative."),
    ("WEB-002", L, "Missing lang attribute on <html>",
     "Screen readers and translation tools guess the language, often wrongly.",
     "Use `<html lang=\"en\">` (or the page's real language)."),
    ("WEB-003", M, "Missing or empty <title>",
     "The title is the tab label, the search-result headline and the first thing a screen reader reads.",
     "Add a unique, descriptive `<title>` in `<head>`."),
    ("WEB-004", M, "Missing meta viewport",
     "Without it mobile browsers render a ~980px desktop layout and shrink it.",
     "Add `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">`."),
    ("WEB-005", L, "Missing meta description",
     "Search engines fall back to random page text for the snippet.",
     "Add `<meta name=\"description\" content=\"...\">` (about 150 characters)."),
    ("WEB-006", M, "Form control without a label",
     "Inputs with no label, aria-label or title are unusable with a screen reader and have a tiny click target.",
     "Wrap it in `<label>`, or add `<label for=ID>` or `aria-label`. A placeholder is not a label."),
    ("WEB-007", M, "Button without accessible text",
     "An icon-only button with no text or aria-label is announced just as \"button\".",
     "Add visible text, `aria-label`, or `title`."),
    ("WEB-008", M, "Duplicate id",
     "Ids must be unique: `getElementById`, label `for=` and anchors only reach the first one.",
     "Rename one of them, or use a class."),
    ("WEB-009", L, "Heading level skipped",
     "Jumping from h2 to h4 breaks the outline that screen-reader users navigate by.",
     "Use consecutive heading levels; style with CSS instead of picking a smaller tag."),
    ("WEB-010", L, "Empty link, href=\"#\" or javascript: href",
     "Such links have no destination or no name: they jump to the page top, break middle-click and are invisible to assistive tech.",
     "Use a real URL, or a `<button>` for actions; give every link text."),
    ("WEB-011", M, "target=_blank without rel=noopener",
     "Older browsers give the opened page `window.opener`, letting it redirect your tab (reverse tabnabbing).",
     "Add `rel=\"noopener noreferrer\"`."),
    ("WEB-012", H, "Mixed content: http:// resource on an https page",
     "Browsers block or warn about insecure scripts, styles and frames, and anything on the wire can be rewritten.",
     "Use https:// (or a relative URL) for every subresource."),
    ("WEB-013", L, "Render-blocking script in <head>",
     "A classic script without defer/async stops HTML parsing until it is downloaded and run.",
     "Add `defer` (keeps order) or `async`, or move it to the end of `<body>`."),
    ("WEB-014", L, "Image without width/height",
     "The browser cannot reserve space, so content jumps when the image loads (layout shift).",
     "Set `width` and `height` attributes (or CSS `aspect-ratio`)."),
    ("WEB-015", L, "Inline event handler attribute",
     "onclick= and friends mix behaviour into markup and block a strict Content-Security-Policy.",
     "Use `addEventListener` in a script file."),
    ("WEB-016", M, "Third-party script/stylesheet without integrity (SRI)",
     "If the CDN is compromised, the code runs on your page unchecked.",
     "Add `integrity=\"sha384-...\" crossorigin=\"anonymous\"`, or self-host the file."),
    ("WEB-017", M, "Large inline base64 blob (> 100 KB)",
     "Inlined data bloats the HTML/CSS/JS, can't be cached separately and delays first paint.",
     "Ship it as a separate file (compressed, cacheable)."),
    ("WEB-018", M, "Huge JS/CSS file (> 1 MB)",
     "Big bundles slow the first load on mobile networks and parse time grows with size.",
     "Minify, split by route, tree-shake, and serve with gzip/brotli."),
    ("WEB-019", M, "Outdated jQuery / Bootstrap version",
     "jQuery < 3 and Bootstrap < 5 are end-of-life and have known XSS issues. Detected from the file name or URL (heuristic).",
     "Upgrade to a maintained release (jQuery 3.x, Bootstrap 5.x)."),
    ("WEB-020", L, "Missing favicon",
     "Browsers request /favicon.ico anyway and log a 404; tabs and bookmarks show a blank icon.",
     "Add `<link rel=\"icon\" href=\"/favicon.ico\">`."),
    ("WEB-021", L, "Missing canonical link",
     "Duplicate URLs (query strings, trailing slashes) split search ranking.",
     "Add `<link rel=\"canonical\" href=\"https://...\">`."),
    ("WEB-022", L, "console.log / debugger left in JavaScript",
     "Debug output leaks internals to users, and `debugger` halts execution when DevTools is open.",
     "Remove it, or strip it in the build (e.g. esbuild `drop: [\"console\", \"debugger\"]`)."),
]
RULES: dict[str, RuleInfo] = {r[0]: RuleInfo(*r) for r in _RULES}
