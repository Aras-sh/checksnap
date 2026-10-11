"""Small text helpers."""
import re


def slugify(text: str) -> str:
    """Lowercase, replace runs of non-alphanumerics with a dash."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def wrap(text: str, width: int = 72) -> list[str]:
    lines, current = [], []
    for word in text.split():
        if sum(len(w) + 1 for w in current) + len(word) > width:
            lines.append(" ".join(current))
            current = []
        current.append(word)
    if current:
        lines.append(" ".join(current))
    return lines


def truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."
