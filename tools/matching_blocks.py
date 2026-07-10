#!/usr/bin/env python3

from __future__ import annotations

import argparse
import difflib
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("--minimum", type=int, default=32)
    args = parser.parse_args()

    old = args.old.read_bytes()
    new = args.new.read_bytes()

    matcher = difflib.SequenceMatcher(
        None,
        old,
        new,
        autojunk=False,
    )

    blocks = [
        block
        for block in matcher.get_matching_blocks()
        if block.size >= args.minimum
    ]

    total = sum(block.size for block in blocks)

    print(f"Old size:                  {len(old)}")
    print(f"New size:                  {len(new)}")
    print(f"Matched bytes in blocks:   {total}")
    print(f"Old payload matched:       {total / len(old) * 100:.2f}%")
    print(f"New payload matched:       {total / len(new) * 100:.2f}%")
    print(f"Blocks >= {args.minimum}:             {len(blocks)}")
    print()

    for block in sorted(blocks, key=lambda item: item.size, reverse=True)[:50]:
        delta = block.b - block.a
        print(
            f"size={block.size:6d} "
            f"old=0x{block.a:08X} "
            f"new=0x{block.b:08X} "
            f"delta={delta:+d}"
        )


if __name__ == "__main__":
    main()
