"""Matrix helpers on lists of lists."""


def transpose(m: list[list[float]]) -> list[list[float]]:
    return [list(row) for row in zip(*m)]


def multiply(a: list[list[float]], b: list[list[float]]) -> list[list[float]]:
    if len(a[0]) != len(b):
        raise ValueError("shape mismatch")
    cols = transpose(b)
    return [[sum(x * y for x, y in zip(row, col)) for col in cols] for row in a]


def identity(n: int) -> list[list[float]]:
    return [[1.0 if i == j else 0.0 for j in range(n)] for i in range(n)]
