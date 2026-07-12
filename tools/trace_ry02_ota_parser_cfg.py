#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import struct
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB


OUTER_HEADER_SIZE = 0x50
IMAGE_BASE = 0x00824000


@dataclass(frozen=True)
class ImageSpec:
    path: Path
    parser: int


def parse_image_spec(value: str) -> ImageSpec:
    if "@" not in value:
        raise argparse.ArgumentTypeError(
            "Expected PATH@PARSER_OFFSET"
        )

    path_text, offset_text = value.rsplit("@", 1)

    return ImageSpec(
        path=Path(path_text),
        parser=int(offset_text, 0),
    )


def parse_immediates(text: str) -> list[int]:
    return [
        int(match.group(1), 0)
        for match in re.finditer(
            r"#(-?0x[0-9a-fA-F]+|-?[0-9]+)",
            text,
        )
    ]


def decode_one(md: Cs, data: bytes, address: int):
    if not 0 <= address < len(data):
        return None

    decoded = list(
        md.disasm(
            data[address:address + 4],
            address,
            count=1,
        )
    )

    return decoded[0] if decoded else None


def direct_target(instruction) -> int | None:
    values = parse_immediates(
        instruction.op_str
    )

    return values[-1] if values else None


def is_return(instruction) -> bool:
    if (
        instruction.mnemonic == "bx"
        and instruction.op_str.strip() == "lr"
    ):
        return True

    return (
        instruction.mnemonic == "pop"
        and "pc" in instruction.op_str
    )


def is_call(instruction) -> bool:
    return instruction.mnemonic in {
        "bl",
        "blx",
    }


def is_conditional_branch(instruction) -> bool:
    mnemonic = instruction.mnemonic

    if mnemonic in {"cbz", "cbnz"}:
        return True

    return (
        mnemonic.startswith("b")
        and mnemonic not in {
            "b",
            "bl",
            "blx",
            "bx",
        }
    )


def is_unconditional_branch(instruction) -> bool:
    return instruction.mnemonic == "b"


def resolve_pc_literal(
    instruction,
    data: bytes,
) -> tuple[int, int] | None:
    if (
        instruction.mnemonic != "ldr"
        or "[pc" not in instruction.op_str.lower()
    ):
        return None

    values = parse_immediates(
        instruction.op_str
    )

    displacement = values[-1] if values else 0

    literal_offset = (
        ((instruction.address + 4) & ~3)
        + displacement
    )

    if not 0 <= literal_offset <= len(data) - 4:
        return None

    value = struct.unpack_from(
        "<I",
        data,
        literal_offset,
    )[0]

    return literal_offset, value


def build_cfg(
    md: Cs,
    payload: bytes,
    parser: int,
    window: int,
) -> dict[int, list]:
    lower = parser
    upper = min(
        len(payload),
        parser + window,
    )

    pending = deque([parser])
    visited_starts: set[int] = set()
    blocks: dict[int, list] = {}

    while pending:
        start = pending.popleft()

        if start in visited_starts:
            continue

        if not lower <= start < upper:
            continue

        visited_starts.add(start)

        instructions = []
        address = start
        seen_in_block: set[int] = set()

        while lower <= address < upper:
            if address in seen_in_block:
                break

            seen_in_block.add(address)

            instruction = decode_one(
                md,
                payload,
                address,
            )

            if instruction is None:
                break

            instructions.append(instruction)
            next_address = (
                instruction.address
                + instruction.size
            )

            if is_return(instruction):
                break

            if is_unconditional_branch(
                instruction
            ):
                target = direct_target(
                    instruction
                )

                if target is not None:
                    pending.append(target)

                break

            if is_conditional_branch(
                instruction
            ):
                target = direct_target(
                    instruction
                )

                if target is not None:
                    pending.append(target)

                pending.append(next_address)
                break

            address = next_address

        blocks[start] = instructions

    return blocks


def scan_direct_callers(
    md: Cs,
    payload: bytes,
    parser: int,
) -> list[int]:
    callers = []

    for offset in range(
        0,
        len(payload) - 2,
        2,
    ):
        instruction = decode_one(
            md,
            payload,
            offset,
        )

        if (
            instruction is None
            or not is_call(instruction)
        ):
            continue

        if direct_target(instruction) == parser:
            callers.append(offset)

    return callers


def find_pointer_xrefs(
    payload: bytes,
    parser: int,
) -> list[tuple[int, int, str]]:
    values = {
        parser: "payload offset",
        parser | 1: "payload Thumb offset",
        IMAGE_BASE + parser: "runtime address",
        (IMAGE_BASE + parser) | 1:
            "runtime Thumb address",
    }

    results = []

    for value, description in values.items():
        encoded = struct.pack(
            "<I",
            value,
        )

        start = 0

        while True:
            offset = payload.find(
                encoded,
                start,
            )

            if offset < 0:
                break

            results.append(
                (
                    offset,
                    value,
                    description,
                )
            )

            start = offset + 1

    return sorted(results)


def print_instruction(
    instruction,
    payload: bytes,
) -> None:
    literal_note = ""

    literal = resolve_pc_literal(
        instruction,
        payload,
    )

    if literal is not None:
        literal_offset, value = literal
        literal_note = (
            f" ; literal payload+0x"
            f"{literal_offset:X}=0x{value:08X}"
        )

    print(
        f"  payload+0x{instruction.address:06X} "
        f"runtime=0x"
        f"{IMAGE_BASE + instruction.address:08X} "
        f"{instruction.bytes.hex(' '):<18s} "
        f"{instruction.mnemonic:<8s} "
        f"{instruction.op_str}"
        f"{literal_note}"
    )


def analyze(
    spec: ImageSpec,
    window: int,
) -> None:
    container = spec.path.read_bytes()

    if len(container) <= OUTER_HEADER_SIZE:
        raise ValueError(
            f"{spec.path}: image is too small"
        )

    payload = container[
        OUTER_HEADER_SIZE:
    ]

    md = Cs(
        CS_ARCH_ARM,
        CS_MODE_THUMB,
    )

    blocks = build_cfg(
        md,
        payload,
        spec.parser,
        window,
    )

    instructions = {
        instruction.address: instruction
        for block in blocks.values()
        for instruction in block
    }

    print("=" * 100)
    print(spec.path)
    print("=" * 100)
    print(
        f"Parser payload offset: "
        f"0x{spec.parser:06X}"
    )
    print(
        f"Parser runtime address: "
        f"0x{IMAGE_BASE + spec.parser:08X}"
    )
    print(
        f"CFG blocks:            "
        f"{len(blocks)}"
    )
    print(
        f"Unique instructions:   "
        f"{len(instructions)}"
    )

    print("\nCONTROL-FLOW BLOCKS")
    print("-" * 100)

    for block_start in sorted(blocks):
        print(
            f"\nBLOCK payload+0x"
            f"{block_start:06X} "
            f"runtime=0x"
            f"{IMAGE_BASE + block_start:08X}"
        )

        for instruction in blocks[
            block_start
        ]:
            print_instruction(
                instruction,
                payload,
            )

    print("\nCOMMAND COMPARISONS")
    print("-" * 100)

    comparisons = []

    for instruction in instructions.values():
        if instruction.mnemonic != "cmp":
            continue

        values = parse_immediates(
            instruction.op_str
        )

        for value in values:
            if value in {1, 2, 3, 4, 5, 6}:
                comparisons.append(
                    (
                        instruction.address,
                        value,
                    )
                )

    if comparisons:
        for address, value in sorted(
            comparisons
        ):
            print(
                f"payload+0x{address:06X} "
                f"runtime=0x"
                f"{IMAGE_BASE + address:08X} "
                f"compares #{value}"
            )
    else:
        print("No command comparisons found.")

    print("\nDIRECT CALLEES FROM CFG")
    print("-" * 100)

    calls = []

    for instruction in instructions.values():
        if not is_call(instruction):
            continue

        calls.append(
            (
                instruction.address,
                direct_target(instruction),
                instruction.op_str,
            )
        )

    for address, target, operands in sorted(
        calls
    ):
        target_text = (
            f"payload+0x{target:06X}"
            if target is not None
            and 0 <= target < len(payload)
            else str(operands)
        )

        print(
            f"caller payload+0x{address:06X} "
            f"runtime=0x"
            f"{IMAGE_BASE + address:08X} "
            f"-> {target_text}"
        )

    print("\nDIRECT CALL XREFS TO PARSER")
    print("-" * 100)

    callers = scan_direct_callers(
        md,
        payload,
        spec.parser,
    )

    if callers:
        for caller in callers:
            print(
                f"payload+0x{caller:06X} "
                f"runtime=0x"
                f"{IMAGE_BASE + caller:08X}"
            )
    else:
        print("No direct BL/BLX callers found.")

    print("\nPOINTER XREFS TO PARSER")
    print("-" * 100)

    pointer_xrefs = find_pointer_xrefs(
        payload,
        spec.parser,
    )

    if pointer_xrefs:
        for offset, value, description in (
            pointer_xrefs
        ):
            print(
                f"payload+0x{offset:06X} "
                f"value=0x{value:08X} "
                f"{description}"
            )
    else:
        print("No raw parser pointers found.")

    print("\nRAM LITERALS USED BY CFG")
    print("-" * 100)

    ram_literals = set()

    for instruction in instructions.values():
        literal = resolve_pc_literal(
            instruction,
            payload,
        )

        if literal is None:
            continue

        literal_offset, value = literal

        if 0x00100000 <= value < 0x00300000:
            ram_literals.add(
                (
                    literal_offset,
                    value,
                )
            )

    if ram_literals:
        for literal_offset, value in sorted(
            ram_literals
        ):
            occurrences = []

            encoded = struct.pack(
                "<I",
                value,
            )

            start = 0

            while True:
                offset = payload.find(
                    encoded,
                    start,
                )

                if offset < 0:
                    break

                occurrences.append(offset)
                start = offset + 1

            print(
                f"value=0x{value:08X} "
                f"literal payload+0x"
                f"{literal_offset:06X} "
                f"all occurrences="
                + ", ".join(
                    f"0x{offset:06X}"
                    for offset in occurrences
                )
            )
    else:
        print("No RAM literals found.")


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "images",
        nargs="+",
        type=parse_image_spec,
        metavar="PATH@PARSER_OFFSET",
    )

    parser.add_argument(
        "--window",
        type=lambda value: int(
            value,
            0,
        ),
        default=0x200,
    )

    args = parser.parse_args()

    for spec in args.images:
        analyze(
            spec,
            args.window,
        )


if __name__ == "__main__":
    main()
