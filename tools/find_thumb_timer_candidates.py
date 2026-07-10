#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
)


@dataclass
class TimerCandidate:
    offset: int
    register: int
    immediate: int
    shift: int
    effective: int


def u16le(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def decode_movs_immediate(data: bytes, offset: int):
    if offset + 2 > len(data):
        return None

    halfword = u16le(data, offset)

    # Thumb MOVS Rd, #imm8:
    # 00100 Rd imm8
    if (halfword & 0xF800) != 0x2000:
        return None

    register = (halfword >> 8) & 0x7
    immediate = halfword & 0xFF
    return register, immediate


def decode_lsls_immediate(data: bytes, offset: int):
    if offset + 2 > len(data):
        return None

    halfword = u16le(data, offset)

    # Thumb LSLS Rd, Rm, #imm5:
    # 00000 imm5 Rm Rd
    if (halfword & 0xF800) != 0x0000:
        return None

    shift = (halfword >> 6) & 0x1F
    source_register = (halfword >> 3) & 0x7
    destination_register = halfword & 0x7

    return destination_register, source_register, shift


def find_candidates(data: bytes) -> list[TimerCandidate]:
    results: list[TimerCandidate] = []

    for offset in range(0, len(data) - 2, 2):
        movs = decode_movs_immediate(data, offset)

        if movs is None:
            continue

        register, immediate = movs

        # Search the following eight Thumb halfwords for:
        # LSLS same_register, same_register, #shift.
        for following in range(offset + 2, min(offset + 18, len(data) - 1), 2):
            lsls = decode_lsls_immediate(data, following)

            if lsls is None:
                continue

            destination, source, shift = lsls

            if destination != register or source != register:
                continue

            effective = immediate << shift

            # Include a generous range around a nominal 1000-unit delay.
            if 700 <= effective <= 1300:
                results.append(
                    TimerCandidate(
                        offset=offset,
                        register=register,
                        immediate=immediate,
                        shift=shift,
                        effective=effective,
                    )
                )

    return results


def print_disassembly(
    md: Cs,
    data: bytes,
    candidate: TimerCandidate,
) -> None:
    start = max(0, candidate.offset - 48) & ~1
    end = min(len(data), candidate.offset + 128)

    print(
        f"offset=0x{candidate.offset:08X} "
        f"r{candidate.register}, "
        f"imm={candidate.immediate}, "
        f"shift={candidate.shift}, "
        f"effective={candidate.effective}"
    )

    for insn in md.disasm(data[start:end], start):
        marker = ">>" if insn.address == candidate.offset else "  "
        raw = " ".join(f"{byte:02x}" for byte in insn.bytes)
        print(
            f"{marker} 0x{insn.address:08X}: "
            f"{raw:<12} "
            f"{insn.mnemonic:<7} "
            f"{insn.op_str}"
        )


def analyze(path: Path) -> None:
    data = path.read_bytes()
    candidates = find_candidates(data)

    md = Cs(
        CS_ARCH_ARM,
        CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
    )
    md.skipdata = True

    literal_1000 = []
    marker = (1000).to_bytes(4, "little")
    start = 0

    while True:
        found = data.find(marker, start)

        if found < 0:
            break

        literal_1000.append(found)
        start = found + 1

    print()
    print(f"===== {path} =====")
    print(f"Size:                         {len(data)}")
    print(f"Shift-derived timer candidates: {len(candidates)}")
    print(f"Literal uint32 1000 offsets:    {len(literal_1000)}")

    if literal_1000:
        print(
            "Literal offsets: "
            + ", ".join(f"0x{offset:08X}" for offset in literal_1000)
        )

    for number, candidate in enumerate(candidates, start=1):
        print()
        print(f"[{number}]")
        print_disassembly(md, data, candidate)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("payloads", nargs="+", type=Path)
    args = parser.parse_args()

    for payload in args.payloads:
        analyze(payload)


if __name__ == "__main__":
    main()
