#!/usr/bin/env python3
"""Disassemble the RY02 .38 raw streaming callback and list timer callers."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from capstone.arm_const import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

HEADER_SIZE = 0x50
MAGIC = bytes.fromhex("e5c3bd81")
IMAGE_BASE = 0x00824000
CALLBACK_OFFSET = 0x1B44
CALLBACK_SIZE = 0x200
TIMER_WRAPPER = 0x376C
TIMER_STOP = 0x3798
CALLBACK_ABSOLUTE = 0x00825B45
TIMER_BASE_LITERAL = 0x002098C4
TIMER_OBJECT = TIMER_BASE_LITERAL + 0x10


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def load_payload(path: Path) -> bytes:
    data = path.read_bytes()
    payload = data[HEADER_SIZE:]
    if data[:4] != MAGIC:
        raise RuntimeError("unexpected container magic")
    if u32le(data, 0x04) != len(payload) or u32le(data, 0x08) != len(payload):
        raise RuntimeError("payload length mismatch")
    if u32le(data, 0x0C) != (sum(payload) & 0xFFFFFFFF):
        raise RuntimeError("payload checksum mismatch")
    return payload


def md() -> Cs:
    instance = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    instance.detail = True
    return instance


def immediate_target(instruction) -> int | None:
    if not (instruction.mnemonic.startswith("b") or instruction.mnemonic in {"cbz", "cbnz"}):
        return None
    for operand in instruction.operands:
        if operand.type == ARM_OP_IMM:
            return operand.imm
    return None


def literal_value(payload: bytes, instruction) -> tuple[int, int] | None:
    for operand in instruction.operands:
        if operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
            address = ((instruction.address + 4) & ~3) + operand.mem.disp
            if 0 <= address <= len(payload) - 4:
                return address, u32le(payload, address)
    return None


def occurrences(data: bytes, value: int) -> list[int]:
    pattern = struct.pack("<I", value)
    result: list[int] = []
    start = 0
    while True:
        offset = data.find(pattern, start)
        if offset < 0:
            return result
        result.append(offset)
        start = offset + 1


def find_calls_to(payload: bytes, target: int) -> list[int]:
    result: list[int] = []
    decoder = md()
    for offset in range(0, len(payload) - 4, 2):
        decoded = list(decoder.disasm(payload[offset : offset + 4], offset, count=1))
        if decoded and decoded[0].mnemonic in {"bl", "blx"}:
            if immediate_target(decoded[0]) == target:
                result.append(offset)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "image",
        nargs="?",
        type=Path,
        default=Path("downloads/qring-latest/RY02_3.00.38_250403.bin"),
    )
    args = parser.parse_args()
    payload = load_payload(args.image)

    print("=" * 96)
    print("RY02 .38 RAW TIMER CALLBACK")
    print("=" * 96)
    print(f"Image:              {args.image}")
    print(f"Image base:         0x{IMAGE_BASE:08X}")
    print(f"Callback pointer:   0x{CALLBACK_ABSOLUTE:08X}")
    print(f"Mapped callback:    payload+0x{((CALLBACK_ABSOLUTE & ~1) - IMAGE_BASE):X}")
    print(f"Timer object:       0x{TIMER_OBJECT:08X}")

    print("\nCALLBACK DISASSEMBLY")
    print("-" * 96)
    for ins in md().disasm(payload[CALLBACK_OFFSET : CALLBACK_OFFSET + CALLBACK_SIZE], CALLBACK_OFFSET):
        notes: list[str] = []
        target = immediate_target(ins)
        if target is not None:
            notes.append(f"target=0x{target:X}")
        literal = literal_value(payload, ins)
        if literal:
            text = f"literal[0x{literal[0]:X}]=0x{literal[1]:08X}"
            if IMAGE_BASE <= (literal[1] & ~1) < IMAGE_BASE + len(payload):
                text += f" -> payload+0x{((literal[1] & ~1) - IMAGE_BASE):X}"
            notes.append(text)
        suffix = "  <== " + " | ".join(notes) if notes else ""
        print(
            f"0x{ins.address:06X}: {ins.bytes.hex():<10} "
            f"{ins.mnemonic:<8} {ins.op_str}{suffix}"
        )

    print("\nLITERAL OCCURRENCES")
    print("-" * 96)
    for label, value in (
        ("callback pointer", CALLBACK_ABSOLUTE),
        ("timer base", TIMER_BASE_LITERAL),
        ("timer object", TIMER_OBJECT),
    ):
        found = occurrences(payload, value)
        print(
            f"{label:<18} 0x{value:08X}: "
            + (", ".join(f"0x{x:X}" for x in found) if found else "NONE")
        )

    print("\nDIRECT CALLERS")
    print("-" * 96)
    for label, target in (
        ("callback 0x1B44", CALLBACK_OFFSET),
        ("timer start 0x376C", TIMER_WRAPPER),
        ("timer stop 0x3798", TIMER_STOP),
    ):
        callers = find_calls_to(payload, target)
        print(f"{label}: {len(callers)} caller(s)")
        for caller in callers:
            print(f"  0x{caller:06X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
