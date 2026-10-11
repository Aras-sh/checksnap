"""Summarise a CSV of orders by customer."""
import csv
from collections import defaultdict
from pathlib import Path


def totals_by_customer(path: Path) -> dict[str, float]:
    totals: dict[str, float] = defaultdict(float)
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            totals[row["customer"]] += float(row["amount"])
    return dict(totals)


def top_customers(totals: dict[str, float], n: int = 3) -> list[tuple[str, float]]:
    return sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:n]


def format_report(totals: dict[str, float]) -> str:
    lines = [f"{name}: {amount:.2f}" for name, amount in sorted(totals.items())]
    return "\n".join(lines)
