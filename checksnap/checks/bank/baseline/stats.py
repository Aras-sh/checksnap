"""Basic descriptive statistics on lists of numbers."""
import math


def mean(values: list[float]) -> float:
    if not values:
        raise ValueError("mean of empty list")
    return sum(values) / len(values)


def variance(values: list[float]) -> float:
    m = mean(values)
    return sum((v - m) ** 2 for v in values) / len(values)


def stdev(values: list[float]) -> float:
    return math.sqrt(variance(values))


def median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2
