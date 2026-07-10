#!/usr/bin/env python3
"""Trace the first call after the known RY02 raw timer sequence."""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from capstone.arm_const import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

HEADER_SIZE = 0x50
MAGIC = bytes.fromhex("e5c3bd81")
RAW_TIMER_SEQUENCE = bytes.fromhex("7d220123d200")


@dataclass
class CallInfo:
    address: int
    target: int


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def load_payload(path: Path) -> bytes:
    data = path.read_bytes()
    payload = data[HEADER_SIZE:]
    if data[:4] != MAGIC:
        raise RuntimeError(f"{path}: unexpected magic")
    if u32le(data, 0x04) != len(payload) or u32le(data, 0x08) != len(payload):
        raise RuntimeError(f"{path}: length mismatch")
    if u32le(data, 0x0C) != (sum(payload) & 0xFFFFFFFF):
        raise RuntimeError(f"{path}: checksum mismatch")
    return payload


def md() -> Cs:
    instance = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    instance.detail = True
    return instance


def branch_target(instruction) -> int | None:
    if not instruction.mnemonic.startswith("b"):
        return None
    for operand in instruction.operands:
        if operand.type == ARM_OP_IMM:
            return operand.imm
    return None


def literal_reference(payload: bytes, instruction) -> tuple[int, int] | None:
    for operand in instruction.operands:
        if operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
            address = ((instruction.address + 4) & ~3) + operand.mem.disp
            if 0 <= address <= len(payload) - 4:
                return address, u32le(payload, address)
    return None


def find_near(payload: bytes, pattern: bytes, start: int, end: int) -> list[int]:
    hits: list[int] = []
    cursor = start
    while True:
        offset = payload.find(pattern, cursor, end)
        if offset < 0:
            return hits
        hits.append(offset)
        cursor = offset + 1


def analyze(label: str, path: Path, handler: int, expected_wrapper: int) -> None:
    payload = load_payload(path)
    hits = find_near(payload, RAW_TIMER_SEQUENCE, handler, handler + 0x180)
    print("\n" + "=" * 96)
    print(f"{label} RAW TIMER CALL TRACE")
    print("=" * 96)
    if len(hits) != 1:
        print(f"RESULT: FAIL — expected one timer sequence, found {len(hits)}")
        return

    timer_site = hits[0]
    first_call: CallInfo | None = None
    for ins in md().disasm(payload[timer_site + len(RAW_TIMER_SEQUENCE) : timer_site + 0x60], timer_site + len(RAW_TIMER_SEQUENCE)):
        if ins.mnemonic in {"bl", "blx"}:
            target = branch_target(ins)
            if target is not None:
                first_call = CallInfo(ins.address, target)
                break

    print(f"Confirmed site:   0x{timer_site:X}")
    if first_call:
        print(f"First call:       0x{first_call.address:X} -> 0x{first_call.target:X}")
        print(f"Matches wrapper:  {'YES' if first_call.target == expected_wrapper else 'NO'}")
    else:
        print("First call:       NONE")

    print("\nCALL-SITE DISASSEMBLY")
    print("-" * 96)
    for ins in md().disasm(payload[max(handler, timer_site - 0x40) : timer_site + 0x70], max(handler, timer_site - 0x40)):
        notes: list[str] = []
        if ins.address == timer_site:
            notes.append("RAW TIMER SITE")
        if first_call and ins.address == first_call.address:
            notes.append("FIRST CALL AFTER TIMER")
        target = branch_target(ins)
        if target is not None:
            notes.append(f"TARGET=0x{target:X}")
        literal = literal_reference(payload, ins)
        if literal:
            notes.append(f"LITERAL[0x{literal[0]:X}]=0x{literal[1]:08X}")
        suffix = "  <== " + " | ".join(notes) if notes else ""
        print(
            f"0x{ins.address:06X}: {ins.bytes.hex():<10} "
            f"{ins.mnemonic:<8} {ins.op_str}{suffix}"
        )

    if first_call:
        print("\nR2 WRITES FROM TIMER SITE THROUGH CALL")
        print("-" * 96)
        for ins in md().disasm(payload[timer_site : first_call.address], timer_site):
            operands = ins.op_str.replace(" ", "")
            if operands == "r2" or operands.startswith("r2,"):
                print(f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")

    print("\nEXPECTED TIMER-WRAPPER DISASSEMBLY")
    print("-" * 96)
    for ins in md().disasm(payload[expected_wrapper : expected_wrapper + 0x80], expected_wrapper):
        target = branch_target(ins)
        suffix = f"  <== TARGET=0x{target:X}" if target is not None else ""
        print(
            f"0x{ins.address:06X}: {ins.bytes.hex():<10} "
            f"{ins.mnemonic:<8} {ins.op_str}{suffix}"
        )


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
    analyze(".33", args.v33, 0x1CE2, 0x36B4)
    analyze(".38", args.v38, 0x1D02, 0x376C)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
