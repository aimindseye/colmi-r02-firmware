#!/usr/bin/env python3
"""Compare the known A1 raw-command path between RY02 .33 and .38."""

from __future__ import annotations

import argparse
import difflib
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB

HEADER_SIZE = 0x50
MAGIC = bytes.fromhex("e5c3bd81")
RAW_TIMER_SEQUENCE = bytes.fromhex("7d220123d200")


@dataclass
class InstructionLine:
    address: int
    raw: str
    mnemonic: str
    operands: str


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def load_payload(path: Path) -> bytes:
    data = path.read_bytes()
    payload = data[HEADER_SIZE:]
    if data[:4] != MAGIC:
        raise RuntimeError(f"{path}: unexpected magic")
    if u32le(data, 0x04) != len(payload) or u32le(data, 0x08) != len(payload):
        raise RuntimeError(f"{path}: payload length mismatch")
    if u32le(data, 0x0C) != (sum(payload) & 0xFFFFFFFF):
        raise RuntimeError(f"{path}: checksum mismatch")
    return payload


def find_all(data: bytes, pattern: bytes) -> list[int]:
    results: list[int] = []
    start = 0
    while True:
        offset = data.find(pattern, start)
        if offset < 0:
            return results
        results.append(offset)
        start = offset + 1


def disassemble(payload: bytes, start: int, size: int) -> list[InstructionLine]:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    return [
        InstructionLine(ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str)
        for ins in md.disasm(payload[start : start + size], start)
    ]


def normalized_lines(base: int, lines: list[InstructionLine]) -> list[str]:
    result: list[str] = []
    for line in lines:
        operands = line.operands
        if line.mnemonic.startswith("b"):
            match = re.fullmatch(r"#0x([0-9a-fA-F]+)", operands)
            if match:
                target = int(match.group(1), 16)
                operands = f"#FUNCTION_RELATIVE({target - base:+#x})"
        result.append(f"{line.mnemonic} {operands}".rstrip())
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--v33",
        type=Path,
        default=Path("vendor/atc-ota-firmwares/RY02_3.00.33_250117.bin"),
    )
    parser.add_argument(
        "--v38",
        type=Path,
        default=Path("downloads/qring-latest/RY02_3.00.38_250403.bin"),
    )
    args = parser.parse_args()

    images = {
        ".33": {"path": args.v33, "handler": 0x1CE2, "wrapper": 0x36B4},
        ".38": {"path": args.v38, "handler": 0x1D02, "wrapper": 0x376C},
    }
    payloads: dict[str, bytes] = {}
    handler_lines: dict[str, list[InstructionLine]] = {}

    for label, meta in images.items():
        payload = load_payload(meta["path"])
        payloads[label] = payload
        hits = [
            offset
            for offset in find_all(payload, RAW_TIMER_SEQUENCE)
            if meta["handler"] - 0x20 <= offset < meta["handler"] + 0x180
        ]
        meta["hits"] = hits
        print("=" * 90)
        print(label)
        print("=" * 90)
        print(f"File: {meta['path']}")
        print(f"A1 handler: 0x{meta['handler']:X}")
        print(f"Timer wrapper: 0x{meta['wrapper']:X}")
        print(
            "Raw timer sequence near A1 handler: "
            + (", ".join(f"0x{x:x}" for x in hits) if hits else "NONE")
        )
        handler_lines[label] = disassemble(payload, meta["handler"], 0x140)

    print("\n" + "=" * 90)
    print("NORMALIZED HANDLER DIFF")
    print("=" * 90)
    for line in difflib.unified_diff(
        normalized_lines(images[".33"]["handler"], handler_lines[".33"]),
        normalized_lines(images[".38"]["handler"], handler_lines[".38"]),
        fromfile=".33 A1 handler",
        tofile=".38 A1 handler",
        lineterm="",
    ):
        print(line)

    hits_33 = images[".33"]["hits"]
    hits_38 = images[".38"]["hits"]
    print("\n" + "=" * 90)
    print("FOCUSED RESULT")
    print("=" * 90)
    if len(hits_33) == 1 and len(hits_38) == 1:
        delta = hits_38[0] - hits_33[0]
        print(f".33 timer site: 0x{hits_33[0]:x}")
        print(f".38 timer site: 0x{hits_38[0]:x}")
        print(f"Timer-site relocation delta: {delta:+#x}")
        if hits_38[0] == 0x1DDE:
            print("PASS: .38 raw timer site matches payload offset 0x1DDE.")
            return 0
    print("WARNING: expected exactly one known timer sequence near each handler.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
