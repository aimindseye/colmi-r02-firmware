#!/usr/bin/env python3
"""Infer immediate timer periods used by callers of the RY02 .38 wrapper."""

from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from capstone.arm_const import ARM_OP_IMM

HEADER_SIZE = 0x50
MAGIC = bytes.fromhex("e5c3bd81")
TIMER_WRAPPER = 0x376C
CONTEXT_BYTES = 48


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


def branch_target(instruction) -> int | None:
    if instruction.mnemonic not in {"bl", "blx"}:
        return None
    for operand in instruction.operands:
        if operand.type == ARM_OP_IMM:
            return operand.imm
    return None


def find_callers(payload: bytes) -> list[int]:
    result: list[int] = []
    decoder = md()
    for offset in range(0, len(payload) - 4, 2):
        decoded = list(decoder.disasm(payload[offset : offset + 4], offset, count=1))
        if decoded and branch_target(decoded[0]) == TIMER_WRAPPER:
            result.append(offset)
    return result


def context_for(payload: bytes, caller: int):
    decoder = md()
    best = []
    for start in range(max(0, caller - CONTEXT_BYTES), caller + 1, 2):
        decoded = list(decoder.disasm(payload[start : caller + 4], start))
        indexes = [
            index
            for index, ins in enumerate(decoded)
            if ins.address == caller and branch_target(ins) == TIMER_WRAPPER
        ]
        if indexes:
            candidate = decoded[: indexes[0] + 1]
            if len(candidate) > len(best):
                best = candidate
    return best[-16:]


def parse_immediate(text: str) -> int | None:
    match = re.fullmatch(r"#(0x[0-9a-fA-F]+|\d+)", text.strip())
    return int(match.group(1), 0) if match else None


def register_name(text: str) -> str | None:
    value = text.strip().lower()
    return value if re.fullmatch(r"r(?:[0-9]|1[0-2])", value) else None


def infer_registers(instructions) -> dict[str, int | None]:
    state: dict[str, int | None] = {f"r{number}": None for number in range(4)}
    for ins in instructions[:-1]:
        mnemonic = ins.mnemonic.lower()
        operands = [item.strip().lower() for item in ins.op_str.split(",")]
        if mnemonic in {"bl", "blx"}:
            for register in state:
                state[register] = None
            continue
        if not operands:
            continue
        dest = register_name(operands[0])
        if dest not in state:
            continue
        handled = False
        if mnemonic in {"mov", "movs", "movw"} and len(operands) == 2:
            immediate = parse_immediate(operands[1])
            source = register_name(operands[1])
            if immediate is not None:
                state[dest] = immediate
                handled = True
            elif source in state:
                state[dest] = state[source]
                handled = True
        elif mnemonic in {"lsls", "lsrs"} and len(operands) == 3:
            source = register_name(operands[1])
            shift = parse_immediate(operands[2])
            if source in state and state[source] is not None and shift is not None:
                state[dest] = (
                    (state[source] << shift) & 0xFFFFFFFF
                    if mnemonic == "lsls"
                    else state[source] >> shift
                )
                handled = True
        elif mnemonic in {"adds", "subs"}:
            if len(operands) == 2:
                source_value = state.get(dest)
                immediate = parse_immediate(operands[1])
            elif len(operands) == 3:
                source_value = state.get(register_name(operands[1]))
                immediate = parse_immediate(operands[2])
            else:
                source_value = immediate = None
            if source_value is not None and immediate is not None:
                state[dest] = (
                    (source_value + immediate) & 0xFFFFFFFF
                    if mnemonic == "adds"
                    else (source_value - immediate) & 0xFFFFFFFF
                )
                handled = True
        if not handled:
            state[dest] = None
    return state


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
    callers = find_callers(payload)
    known: list[tuple[int, int, int | None]] = []

    print(f"Timer-wrapper caller count: {len(callers)}\n")
    for caller in callers:
        context = context_for(payload, caller)
        state = infer_registers(context)
        period, mode = state["r2"], state["r3"]
        if period is not None:
            known.append((caller, period, mode))
        print(
            f"CALLER 0x{caller:06X}: "
            f"r2_period={period if period is not None else 'UNKNOWN'} "
            f"r3_mode={mode if mode is not None else 'UNKNOWN'}"
        )
        for ins in context:
            print(f"  0x{ins.address:06X}: {ins.mnemonic:<7} {ins.op_str}")
        print()

    print("=" * 80)
    print("KNOWN PERIOD SUMMARY")
    print("=" * 80)
    for caller, period, mode in sorted(known, key=lambda item: (item[1], item[0])):
        marker = " < 1000" if period < 1000 else ""
        print(f"0x{caller:06X}: period={period} mode={mode}{marker}")
    subsecond = [item for item in known if item[1] < 1000]
    print(f"\nKnown periods:       {len(known)}")
    print(f"Known below 1000:    {len(subsecond)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
