#!/usr/bin/env python3
"""Validate the known RY02 0x50-byte OTA container format."""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
from pathlib import Path

HEADER_SIZE = 0x50
MAGIC = bytes.fromhex("e5c3bd81")


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    args = parser.parse_args()

    data = args.image.read_bytes()
    if len(data) < HEADER_SIZE:
        raise SystemExit("image is smaller than the 0x50-byte header")

    payload = data[HEADER_SIZE:]
    length_1 = u32le(data, 0x04)
    length_2 = u32le(data, 0x08)
    stored_sum = u32le(data, 0x0C)
    calculated_sum = sum(payload) & 0xFFFFFFFF
    strings = sorted(
        {
            match.group().decode("ascii", errors="replace")
            for match in re.finditer(
                rb"(?:RY02|R02)[A-Za-z0-9_.-]{3,48}", data
            )
        }
    )

    print(f"Path: {args.image}")
    print(f"Size: {len(data)}")
    print(f"SHA-256: {hashlib.sha256(data).hexdigest()}")
    print(f"Magic: {data[:4].hex()}")
    print(f"Length fields: {length_1}, {length_2}")
    print(f"Payload length: {len(payload)}")
    print(f"Stored sum32: 0x{stored_sum:08x}")
    print(f"Calculated sum32: 0x{calculated_sum:08x}")
    print("Identifiers:")
    for value in strings:
        print(f"  {value}")

    valid = (
        data[:4] == MAGIC
        and length_1 == len(payload)
        and length_2 == len(payload)
        and stored_sum == calculated_sum
    )
    print("Basic container validation:", "PASS" if valid else "FAIL")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
