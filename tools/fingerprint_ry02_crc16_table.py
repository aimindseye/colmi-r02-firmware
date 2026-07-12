#!/usr/bin/env python3

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path


OUTER_HEADER_SIZE = 0x50
IMAGE_BASE = 0x00824000


@dataclass(frozen=True)
class TableSpec:
    path: Path
    runtime_address: int


def parse_spec(value: str) -> TableSpec:
    if "@" not in value:
        raise argparse.ArgumentTypeError(
            "Expected PATH@TABLE_RUNTIME_ADDRESS"
        )

    path_text, address_text = value.rsplit("@", 1)

    return TableSpec(
        path=Path(path_text),
        runtime_address=int(address_text, 0),
    )


def generate_reflected_table(
    polynomial: int,
) -> list[int]:
    table = []

    for index in range(256):
        crc = index

        for _ in range(8):
            if crc & 1:
                crc = (
                    (crc >> 1)
                    ^ polynomial
                )
            else:
                crc >>= 1

        table.append(crc & 0xFFFF)

    return table


def identify_polynomial(
    table: list[int],
) -> list[int]:
    matches = []

    for polynomial in range(1, 0x10000, 2):
        candidate = generate_reflected_table(
            polynomial
        )

        if candidate == table:
            matches.append(polynomial)

    return matches


def known_name(polynomial: int) -> str:
    names = {
        0xA001: (
            "reflected polynomial for "
            "CRC-16/IBM, ARC and MODBUS"
        ),
        0x8408: (
            "reflected polynomial for "
            "CRC-16/CCITT, KERMIT and X-25"
        ),
        0xD175: (
            "reflected polynomial 0xD175"
        ),
    }

    return names.get(
        polynomial,
        "unidentified reflected polynomial",
    )


def analyze(spec: TableSpec) -> None:
    container = spec.path.read_bytes()
    payload = container[OUTER_HEADER_SIZE:]

    table_offset = (
        spec.runtime_address
        - IMAGE_BASE
    )

    if not (
        0 <= table_offset
        <= len(payload) - 512
    ):
        raise ValueError(
            f"{spec.path}: table is outside payload"
        )

    raw = payload[
        table_offset:
        table_offset + 512
    ]

    table = list(
        struct.unpack("<256H", raw)
    )

    matches = identify_polynomial(table)

    print("=" * 88)
    print(spec.path)
    print("=" * 88)
    print(
        f"Table runtime: 0x"
        f"{spec.runtime_address:08X}"
    )
    print(
        f"Table payload offset: "
        f"0x{table_offset:X}"
    )

    print("\nFirst 16 entries:")

    for index, value in enumerate(
        table[:16]
    ):
        print(
            f"  [{index:02X}] = 0x{value:04X}"
        )

    print("\nMatching reflected polynomials:")

    if not matches:
        print("  none")
    else:
        for polynomial in matches:
            print(
                f"  0x{polynomial:04X}: "
                f"{known_name(polynomial)}"
            )

    print("\nRecovered helper parameters:")
    print("  width:    16")
    print("  init:     0xFFFF")
    print("  refin:    true")
    print("  refout:   true")
    print("  xorout:   0x0000 in helper")

    if len(matches) == 1:
        print(
            f"  poly-ref: 0x{matches[0]:04X}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "tables",
        nargs="+",
        type=parse_spec,
        metavar="PATH@TABLE_RUNTIME_ADDRESS",
    )

    args = parser.parse_args()

    for spec in args.tables:
        analyze(spec)


if __name__ == "__main__":
    main()
