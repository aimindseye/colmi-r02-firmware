#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path


Pattern = tuple[int | None, ...]


PATTERNS: list[tuple[str, Pattern, int]] = [
    (
        "strong",
        (
            0xF0, 0xB5, 0x85, 0xB0,
            0x00, 0x24, 0x06, 0x46,
            0x00, 0x94, 0x01, 0x94,
            0x02, 0x94, 0x03, 0x94,
            0x40, 0x78,
            None, 0x27,       # movs r7, #immediate
            None, 0x4D,       # ldr r5, [pc, #...]
            0xFF, 0x00,       # lsls r7, r7, #3
            0x01, 0x28,
        ),
        18,
    ),
    (
        "medium",
        (
            0x00, 0x94, 0x01, 0x94,
            0x02, 0x94, 0x03, 0x94,
            0x40, 0x78,
            None, 0x27,
            None, 0x4D,
            0xFF, 0x00,
            0x01, 0x28,
        ),
        10,
    ),
    (
        "weak",
        (
            0x40, 0x78,
            None, 0x27,
            None, 0x4D,
            0xFF, 0x00,
            0x01, 0x28,
        ),
        2,
    ),
]


def masked_matches(data: bytes, pattern: Pattern):
    size = len(pattern)

    for start in range(0, len(data) - size + 1):
        for index, expected in enumerate(pattern):
            if expected is not None and data[start + index] != expected:
                break
        else:
            yield start


def format_hex(data: bytes, start: int, end: int) -> str:
    return " ".join(f"{byte:02x}" for byte in data[start:end])


def analyze(path: Path) -> None:
    data = path.read_bytes()
    candidates: dict[int, set[str]] = defaultdict(set)

    for name, pattern, immediate_index in PATTERNS:
        for start in masked_matches(data, pattern):
            immediate_offset = start + immediate_index
            candidates[immediate_offset].add(name)

    print()
    print(f"===== {path} =====")
    print(f"Size: {len(data)} bytes / 0x{len(data):X}")

    if not candidates:
        print("No matching interval signature found.")
        return

    print(f"Unique candidate immediates: {len(candidates)}")

    for number, immediate_offset in enumerate(sorted(candidates), start=1):
        immediate = data[immediate_offset]
        effective = immediate << 3

        context_start = max(0, immediate_offset - 32)
        context_end = min(len(data), immediate_offset + 34)

        labels = ",".join(sorted(candidates[immediate_offset]))

        print()
        print(f"[{number}] Match strength: {labels}")
        print(f"Immediate payload offset: 0x{immediate_offset:08X}")
        print(f"Current immediate:         0x{immediate:02X} / {immediate}")
        print(f"Effective value (<< 3):    {effective}")
        print(
            f"RY02 container offset:     "
            f"0x{immediate_offset + 0x50:08X}"
        )
        print(
            f"Context 0x{context_start:08X}: "
            f"{format_hex(data, context_start, context_end)}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Locate the raw-reporting interval constant."
    )
    parser.add_argument("payloads", nargs="+", type=Path)
    args = parser.parse_args()

    for payload in args.payloads:
        analyze(payload)


if __name__ == "__main__":
    main()
