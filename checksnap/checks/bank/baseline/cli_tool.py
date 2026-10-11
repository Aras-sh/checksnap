"""Command line tool that counts words in files."""
import argparse
import sys
from pathlib import Path


def count_words(path: Path) -> int:
    with path.open(encoding="utf-8") as fh:
        return sum(len(line.split()) for line in fh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Count words in files")
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args(argv)
    status = 0
    for path in args.files:
        try:
            print(f"{count_words(path)}\t{path}")
        except OSError as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
