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
    state_address: int


@dataclass(frozen=True)
class StateXref:
    instruction_offset: int
    literal_offset: int
    destination_register: str


def parse_spec(value: str) -> ImageSpec:
    if "@" not in value:
        raise argparse.ArgumentTypeError(
            "Expected PATH@STATE_ADDRESS"
        )

    path_text, address_text = value.rsplit("@", 1)

    return ImageSpec(
        path=Path(path_text),
        state_address=int(address_text, 0),
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


def resolve_pc_literal(
    instruction,
    payload: bytes,
) -> tuple[int, int] | None:
    if (
        instruction.mnemonic != "ldr"
        or "[pc" not in instruction.op_str.lower()
    ):
        return None

    values = parse_immediates(instruction.op_str)
    displacement = values[-1] if values else 0

    literal_offset = (
        ((instruction.address + 4) & ~3)
        + displacement
    )

    if not 0 <= literal_offset <= len(payload) - 4:
        return None

    value = struct.unpack_from(
        "<I",
        payload,
        literal_offset,
    )[0]

    return literal_offset, value


def destination_register(instruction) -> str:
    return instruction.op_str.split(",", 1)[0].strip()


def find_state_xrefs(
    md: Cs,
    payload: bytes,
    state_address: int,
) -> list[StateXref]:
    results: list[StateXref] = []

    for offset in range(0, len(payload) - 4, 2):
        instruction = decode_one(
            md,
            payload,
            offset,
        )

        if instruction is None:
            continue

        literal = resolve_pc_literal(
            instruction,
            payload,
        )

        if literal is None:
            continue

        literal_offset, value = literal

        if value != state_address:
            continue

        results.append(
            StateXref(
                instruction_offset=offset,
                literal_offset=literal_offset,
                destination_register=destination_register(
                    instruction
                ),
            )
        )

    return results


def is_push_lr(instruction) -> bool:
    return (
        instruction.mnemonic == "push"
        and "lr" in instruction.op_str
    )


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


def direct_target(instruction) -> int | None:
    values = parse_immediates(
        instruction.op_str
    )

    return values[-1] if values else None


def is_unconditional_branch(instruction) -> bool:
    return instruction.mnemonic == "b"


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


def nearest_function_start(
    md: Cs,
    payload: bytes,
    target: int,
    backtrack: int,
) -> int | None:
    lower = max(0, target - backtrack)

    for start in range(
        target & ~1,
        (lower & ~1) - 1,
        -2,
    ):
        first = decode_one(
            md,
            payload,
            start,
        )

        if first is None or not is_push_lr(first):
            continue

        expected = start
        reached = False

        for instruction in md.disasm(
            payload[start:target + 4],
            start,
        ):
            if instruction.address != expected:
                break

            if instruction.address == target:
                reached = True
                break

            expected += instruction.size

        if reached:
            return start

    return None


def build_cfg(
    md: Cs,
    payload: bytes,
    start: int,
    window: int,
) -> dict[int, list]:
    upper = min(
        len(payload),
        start + window,
    )

    pending = deque([start])
    visited: set[int] = set()
    blocks: dict[int, list] = {}

    while pending:
        block_start = pending.popleft()

        if block_start in visited:
            continue

        if not start <= block_start < upper:
            continue

        visited.add(block_start)

        instructions = []
        address = block_start
        seen: set[int] = set()

        while start <= address < upper:
            if address in seen:
                break

            seen.add(address)

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

            if is_unconditional_branch(instruction):
                target = direct_target(instruction)

                if target is not None:
                    pending.append(target)

                break

            if is_conditional_branch(instruction):
                target = direct_target(instruction)

                if target is not None:
                    pending.append(target)

                pending.append(next_address)
                break

            address = next_address

        blocks[block_start] = instructions

    return blocks


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
            f" ; literal payload+0x{literal_offset:X}"
            f"=0x{value:08X}"
        )

    print(
        f"  payload+0x{instruction.address:06X} "
        f"runtime=0x{IMAGE_BASE + instruction.address:08X} "
        f"{instruction.bytes.hex(' '):<18s} "
        f"{instruction.mnemonic:<8s} "
        f"{instruction.op_str}"
        f"{literal_note}"
    )


def state_accesses(
    instructions: list,
    registers: set[str],
) -> list:
    results = []

    for instruction in instructions:
        operand_text = instruction.op_str.lower()

        if any(
            f"[{register}" in operand_text
            for register in registers
        ):
            results.append(instruction)

    return results


def analyze(
    spec: ImageSpec,
    backtrack: int,
    window: int,
) -> None:
    container = spec.path.read_bytes()
    payload = container[OUTER_HEADER_SIZE:]

    md = Cs(
        CS_ARCH_ARM,
        CS_MODE_THUMB,
    )

    xrefs = find_state_xrefs(
        md,
        payload,
        spec.state_address,
    )

    print("=" * 104)
    print(spec.path)
    print("=" * 104)
    print(
        f"State address: 0x{spec.state_address:08X}"
    )
    print(
        f"State literal xrefs: {len(xrefs)}"
    )

    print("\nSTATE LITERAL XREFS")
    print("-" * 104)

    for xref in xrefs:
        print(
            f"payload+0x{xref.instruction_offset:06X} "
            f"runtime=0x"
            f"{IMAGE_BASE + xref.instruction_offset:08X} "
            f"literal=payload+0x{xref.literal_offset:06X} "
            f"register={xref.destination_register}"
        )

    functions: dict[int, list[StateXref]] = {}

    for xref in xrefs:
        start = nearest_function_start(
            md,
            payload,
            xref.instruction_offset,
            backtrack,
        )

        if start is None:
            continue

        functions.setdefault(start, []).append(xref)

    print("\nFUNCTIONS USING STATE")
    print("-" * 104)
    print(f"Functions found: {len(functions)}")

    for rank, start in enumerate(
        sorted(functions),
        start=1,
    ):
        function_xrefs = functions[start]

        blocks = build_cfg(
            md,
            payload,
            start,
            window,
        )

        instructions = {
            instruction.address: instruction
            for block in blocks.values()
            for instruction in block
        }

        ordered = [
            instructions[address]
            for address in sorted(instructions)
        ]

        registers = {
            xref.destination_register.lower()
            for xref in function_xrefs
        }

        comparisons = []

        for instruction in ordered:
            if instruction.mnemonic != "cmp":
                continue

            for value in parse_immediates(
                instruction.op_str
            ):
                if value in {
                    1, 2, 3, 4, 5,
                    0x10, 0x21, 0x31,
                }:
                    comparisons.append(
                        (
                            instruction.address,
                            value,
                        )
                    )

        accesses = state_accesses(
            ordered,
            registers,
        )

        calls = [
            instruction
            for instruction in ordered
            if is_call(instruction)
        ]

        print("\n" + "-" * 104)
        print(
            f"#{rank} function=payload+0x{start:06X} "
            f"runtime=0x{IMAGE_BASE + start:08X}"
        )
        print(
            "State registers: "
            + ", ".join(sorted(registers))
        )
        print(
            f"CFG blocks: {len(blocks)} "
            f"instructions: {len(ordered)}"
        )

        print("Relevant comparisons:")

        if comparisons:
            for address, value in comparisons:
                print(
                    f"  payload+0x{address:06X} "
                    f"cmp immediate #0x{value:X}"
                )
        else:
            print("  none")

        print("State-relative accesses:")

        if accesses:
            for instruction in accesses:
                print_instruction(
                    instruction,
                    payload,
                )
        else:
            print("  none")

        print("Direct calls:")

        if calls:
            for instruction in calls:
                target = direct_target(
                    instruction
                )

                print(
                    f"  payload+0x"
                    f"{instruction.address:06X} "
                    f"{instruction.mnemonic} "
                    f"{instruction.op_str} "
                    f"target="
                    + (
                        f"payload+0x{target:06X}"
                        if target is not None
                        and 0 <= target < len(payload)
                        else str(target)
                    )
                )
        else:
            print("  none")

        print("Full CFG disassembly:")

        for block_start in sorted(blocks):
            print(
                f"\n  BLOCK payload+0x"
                f"{block_start:06X}"
            )

            for instruction in blocks[block_start]:
                print_instruction(
                    instruction,
                    payload,
                )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "images",
        nargs="+",
        type=parse_spec,
        metavar="PATH@STATE_ADDRESS",
    )

    parser.add_argument(
        "--backtrack",
        type=lambda value: int(value, 0),
        default=0x500,
    )

    parser.add_argument(
        "--window",
        type=lambda value: int(value, 0),
        default=0x1200,
    )

    args = parser.parse_args()

    for spec in args.images:
        analyze(
            spec,
            args.backtrack,
            args.window,
        )


if __name__ == "__main__":
    main()
