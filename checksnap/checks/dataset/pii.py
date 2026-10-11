"""DS-PII-001: regex + checksum PII and secret detection. Matches are masked, never returned in full."""
from __future__ import annotations

import ipaddress
import re

from checksnap.core import Severity

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<![\w.])(?:\+\d{10,14}|(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]\d{3,4}[\s.-]\d{3,4})(?![\w-])")
_CARD = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b")
_SSN = re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])")
_TCKN = re.compile(r"(?<!\d)[1-9]\d{10}(?!\d)")
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_SECRETS = [
    ("private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("API key (sk-)", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
]


def luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0 and len(set(digits)) > 1


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1


def tckn_ok(s: str) -> bool:
    d = [int(c) for c in s]
    return (((sum(d[0:9:2]) * 7 - sum(d[1:8:2])) % 10) == d[9]) and sum(d[:10]) % 10 == d[10]


def mask(s: str) -> str:
    return f"{s[:4]}... ({len(s)} chars)"


def find_pii(text: str) -> list[tuple[str, Severity, str]]:
    """Return (kind, severity, masked match) for every hit in text."""
    out: list[tuple[str, Severity, str]] = []
    for kind, rx in _SECRETS:
        out += [(kind, Severity.HIGH, mask(m.group())) for m in rx.finditer(text)]
    out += [("credit card", Severity.MEDIUM, mask(m.group())) for m in _CARD.finditer(text)
            if luhn(re.sub(r"\D", "", m.group()))]
    out += [("IBAN", Severity.MEDIUM, mask(m.group())) for m in _IBAN.finditer(text) if iban_ok(m.group())]
    out += [("US SSN", Severity.MEDIUM, mask(m.group())) for m in _SSN.finditer(text)]
    out += [("Turkish TC kimlik no", Severity.MEDIUM, mask(m.group())) for m in _TCKN.finditer(text) if tckn_ok(m.group())]
    out += [("email", Severity.LOW, mask(m.group())) for m in _EMAIL.finditer(text)]
    out += [("phone number", Severity.LOW, mask(m.group())) for m in _PHONE.finditer(text)]
    for m in _IPV4.finditer(text):
        if ipaddress.ip_address(m.group()).is_global:
            out.append(("IPv4 address", Severity.LOW, mask(m.group())))
    return out
