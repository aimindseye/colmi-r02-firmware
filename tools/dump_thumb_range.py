#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
)


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Disassemble a selected Thumb payload range."
    )
    parser.add_argument("payload", type=Path)
    parser.add_argument("--start", required=True, type=parse_int)
    parser.add_argument("--end", required=True, type=parse_int)
    args = parser.parse_args()

    data = args.payload.read_bytes()

    if args.start < 0:
        raise SystemExit("Start offset cannot be negative.")

    if args.end <= args.start:
        raise SystemExit("End offset must be greater than start offset.")

    if args.end > len(data):
        raise SystemExit(
            f"End offset 0x{args.end:X} exceeds payload size "
            f"0x{len(data):X}."
        )

    md = Cs(
        CS_ARCH_ARM,
        CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
    )
    md.skipdata = True

    print(f"Payload: {args.payload}")
    print(f"Range:   0x{args.start:08X}-0x{args.end:08X}")
    print()

    region = data[args.start:args.end]

    for insn in md.disasm(region, args.start):
        raw = " ".join(f"{byte:02x}" for byte in insn.bytes)
        print(
            f"0x{insn.address:08X}: "
            f"{raw:<12} "
            f"{insn.mnemonic:<8} "
            f"{insn.op_str}"
        )


if __name__ == "__main__":
    main()
