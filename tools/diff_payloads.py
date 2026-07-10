#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path


def diff_ranges(a: bytes, b: bytes):
    limit = min(len(a), len(b))
    ranges = []
    start = None

    for offset in range(limit):
        different = a[offset] != b[offset]

        if different and start is None:
            start = offset
        elif not different and start is not None:
            ranges.append((start, offset))
            start = None

    if start is not None:
        ranges.append((start, limit))

    if len(a) != len(b):
        ranges.append((limit, max(len(a), len(b))))

    return ranges


def hex_line(data: bytes, start: int, end: int) -> str:
    return " ".join(f"{byte:02x}" for byte in data[start:end])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    parser.add_argument("modified", type=Path)
    parser.add_argument("--context", type=int, default=16)
    args = parser.parse_args()

    original = args.original.read_bytes()
    modified = args.modified.read_bytes()

    print(f"Original: {args.original} ({len(original)} bytes)")
    print(f"Modified: {args.modified} ({len(modified)} bytes)")

    ranges = diff_ranges(original, modified)
    changed_shared = sum(
        1 for x, y in zip(original, modified) if x != y
    )

    print(f"Changed bytes in shared range: {changed_shared}")
    print(f"Contiguous differing ranges:   {len(ranges)}")

    for index, (start, end) in enumerate(ranges, start=1):
        left = max(0, start - args.context)
        right_original = min(len(original), end + args.context)
        right_modified = min(len(modified), end + args.context)

        print()
        print(
            f"[{index}] 0x{start:08X}–0x{end - 1:08X} "
            f"({end - start} bytes)"
        )
        print(
            f"  ORIGINAL 0x{left:08X}: "
            f"{hex_line(original, left, right_original)}"
        )
        print(
            f"  MODIFIED 0x{left:08X}: "
            f"{hex_line(modified, left, right_modified)}"
        )


if __name__ == "__main__":
    main()
