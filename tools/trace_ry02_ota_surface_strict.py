#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB


UUIDS = {
    "service": bytes.fromhex(
        "de5bf728d7114e47af2665e3012a5dc7"
    ),
    "notify": bytes.fromhex(
        "de5bf729d7114e47af2665e3012a5dc7"
    ),
    "write": bytes.fromhex(
        "de5bf72ad7114e47af2665e3012a5dc7"
    ),
}


@dataclass(frozen=True)
class MarkerHit:
    offset: int
    reason: str


def find_all(data: bytes, needle: bytes) -> list[int]:
    offsets: list[int] = []
    start = 0

    while True:
        offset = data.find(needle, start)

        if offset < 0:
            return offsets

        offsets.append(offset)
        start = offset + 1


def parse_immediates(text: str) -> list[int]:
    values: list[int] = []

    for match in re.finditer(
        r"#(-?0x[0-9a-fA-F]+|-?[0-9]+)",
        text,
    ):
        values.append(int(match.group(1), 0))

    return values


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


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


def resolve_pc_literal(
    instruction,
    payload: bytes,
) -> tuple[int, int] | None:
    if (
        instruction.mnemonic != "ldr"
        or "[pc" not in instruction.op_str.lower()
    ):
        return None

    immediates = parse_immediates(
        instruction.op_str
    )

    displacement = (
        immediates[-1]
        if immediates
        else 0
    )

    literal_offset = (
        ((instruction.address + 4) & ~3)
        + displacement
    )

    if not (
        0 <= literal_offset
        <= len(payload) - 4
    ):
        return None

    return (
        literal_offset,
        read_u32(payload, literal_offset),
    )


def strict_marker_reason(
    instruction,
    payload: bytes,
) -> str | None:
    immediates = parse_immediates(
        instruction.op_str
    )

    if (
        instruction.mnemonic == "cmp"
        and 0xBC in immediates
    ):
        return "direct CMP immediate #0xBC"

    if (
        instruction.mnemonic in {"mov", "movs"}
        and 0xBC in immediates
    ):
        return (
            f"direct {instruction.mnemonic.upper()} "
            "immediate #0xBC"
        )

    literal = resolve_pc_literal(
        instruction,
        payload,
    )

    if literal is not None:
        literal_offset, value = literal

        if value == 0x000000BC:
            return (
                "PC-relative literal 0x000000BC "
                f"at payload+0x{literal_offset:X}"
            )

    return None


def find_strict_marker_hits(
    md: Cs,
    payload: bytes,
) -> list[MarkerHit]:
    hits: list[MarkerHit] = []

    for offset in range(0, len(payload) - 2, 2):
        decoded = list(
            md.disasm(
                payload[offset:offset + 4],
                offset,
                count=1,
            )
        )

        if not decoded:
            continue

        reason = strict_marker_reason(
            decoded[0],
            payload,
        )

        if reason is not None:
            hits.append(
                MarkerHit(
                    offset=offset,
                    reason=reason,
                )
            )

    return hits


def nearest_function_start(
    md: Cs,
    payload: bytes,
    target: int,
    maximum_backtrack: int,
) -> int | None:
    lower = max(
        0,
        target - maximum_backtrack,
    )

    for start in range(
        target & ~1,
        (lower & ~1) - 1,
        -2,
    ):
        decoded = list(
            md.disasm(
                payload[start:start + 4],
                start,
                count=1,
            )
        )

        if (
            not decoded
            or not is_push_lr(decoded[0])
        ):
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


def disassemble_function(
    md: Cs,
    payload: bytes,
    start: int,
    marker: int,
    maximum_size: int,
) -> list:
    instructions = []

    for instruction in md.disasm(
        payload[start:start + maximum_size],
        start,
    ):
        instructions.append(instruction)

        if (
            instruction.address >= marker
            and is_return(instruction)
        ):
            break

    return instructions


def instruction_summary(
    instructions: list,
) -> tuple[set[int], set[int], int]:
    commands: set[int] = set()
    byte_offsets: set[int] = set()
    calls = 0

    for instruction in instructions:
        immediates = parse_immediates(
            instruction.op_str
        )

        if (
            instruction.mnemonic == "cmp"
            and immediates
        ):
            commands.update(
                value
                for value in immediates
                if value in {1, 2, 3, 4, 5}
            )

        if (
            instruction.mnemonic.startswith(
                "ldrb"
            )
            and "[" in instruction.op_str
        ):
            if "#" not in instruction.op_str:
                byte_offsets.add(0)
            else:
                byte_offsets.update(
                    value
                    for value in immediates
                    if 0 <= value <= 0x100
                )

        if instruction.mnemonic in {
            "bl",
            "blx",
        }:
            calls += 1

    return commands, byte_offsets, calls


def print_instructions(
    instructions: list,
    image_base: int,
    payload: bytes,
    marker_offset: int | None = None,
) -> None:
    for instruction in instructions:
        marker = (
            ">>"
            if instruction.address == marker_offset
            else "  "
        )

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
            f"{marker} payload+0x"
            f"{instruction.address:06X} "
            f"runtime=0x"
            f"{image_base + instruction.address:08X} "
            f"{instruction.bytes.hex(' '):<18s} "
            f"{instruction.mnemonic:<8s} "
            f"{instruction.op_str}"
            f"{literal_note}"
        )


def classify_word(
    value: int,
    payload_length: int,
    image_base: int,
) -> str:
    if value & 1:
        target = (value & ~1) - image_base

        if 0 <= target < payload_length:
            return (
                f"Thumb pointer -> "
                f"payload+0x{target:X}"
            )

    target = value - image_base

    if 0 <= target < payload_length:
        return (
            f"data pointer -> "
            f"payload+0x{target:X}"
        )

    if value == 0x000000BC:
        return "literal protocol marker 0xBC"

    return ""


def dump_uuid_region(
    payload: bytes,
    hit: int,
    image_base: int,
    radius: int,
) -> None:
    start = max(0, hit - radius)
    end = min(
        len(payload),
        hit + 16 + radius,
    )

    aligned_start = start & ~3
    aligned_end = min(
        len(payload),
        (end + 3) & ~3,
    )

    for offset in range(
        aligned_start,
        aligned_end,
        4,
    ):
        chunk = payload[offset:offset + 4]

        if len(chunk) < 4:
            break

        value = int.from_bytes(
            chunk,
            "little",
        )

        relative = offset - hit
        note = classify_word(
            value,
            len(payload),
            image_base,
        )

        print(
            f"  table{relative:+#06x} "
            f"payload+0x{offset:06X} "
            f"runtime=0x"
            f"{image_base + offset:08X} "
            f"bytes={chunk.hex(' ')} "
            f"word=0x{value:08X}"
            + (f"  {note}" if note else "")
        )


def analyze(
    path: Path,
    outer_header_size: int,
    image_base: int,
    uuid_radius: int,
    maximum_backtrack: int,
    maximum_function_size: int,
) -> None:
    container = path.read_bytes()

    if len(container) <= outer_header_size:
        raise ValueError(
            f"{path}: invalid outer header size"
        )

    payload = container[outer_header_size:]

    md = Cs(
        CS_ARCH_ARM,
        CS_MODE_THUMB,
    )

    print("=" * 100)
    print(path)
    print("=" * 100)
    print(
        f"Container bytes: 0x{len(container):X}"
    )
    print(
        f"Payload bytes:   0x{len(payload):X}"
    )
    print(
        f"Runtime base:    0x{image_base:08X}"
    )

    print("\nOTA UUID HITS")
    print("-" * 100)

    uuid_hits: list[
        tuple[str, str, int]
    ] = []

    for name, canonical in UUIDS.items():
        for representation, needle in (
            ("canonical", canonical),
            ("reversed", canonical[::-1]),
        ):
            for offset in find_all(
                payload,
                needle,
            ):
                uuid_hits.append(
                    (
                        name,
                        representation,
                        offset,
                    )
                )

    uuid_hits.sort(
        key=lambda item: item[2]
    )

    if not uuid_hits:
        print("No OTA UUIDs found.")
    else:
        for name, representation, offset in uuid_hits:
            print(
                f"{name:8s} "
                f"{representation:9s} "
                f"payload+0x{offset:06X} "
                f"container+0x"
                f"{offset + outer_header_size:06X} "
                f"runtime=0x"
                f"{image_base + offset:08X}"
            )

    print("\nDIRECT UUID ADDRESS REFERENCES")
    print("-" * 100)

    xref_count = 0

    for name, representation, hit in uuid_hits:
        values = {
            hit,
            hit + outer_header_size,
            image_base + hit,
            (image_base + hit) | 1,
        }

        for value in sorted(values):
            encoded = struct.pack(
                "<I",
                value,
            )

            for xref in find_all(
                payload,
                encoded,
            ):
                print(
                    f"{name:8s} "
                    f"{representation:9s} "
                    f"xref payload+0x{xref:06X} "
                    f"value=0x{value:08X}"
                )
                xref_count += 1

    if xref_count == 0:
        print("No direct UUID-address references.")

    print("\nNARROW UUID TABLE DUMPS")
    print("-" * 100)

    for name, representation, hit in uuid_hits:
        print(
            f"\n[{name} {representation} "
            f"payload+0x{hit:X}]"
        )

        dump_uuid_region(
            payload,
            hit,
            image_base,
            uuid_radius,
        )

    print("\nSTRICT 0xBC INSTRUCTION HITS")
    print("-" * 100)

    marker_hits = find_strict_marker_hits(
        md,
        payload,
    )

    print(
        f"Strict marker hits: "
        f"{len(marker_hits)}"
    )

    for rank, hit in enumerate(
        marker_hits,
        start=1,
    ):
        start = nearest_function_start(
            md,
            payload,
            hit.offset,
            maximum_backtrack,
        )

        print("\n" + "-" * 100)
        print(
            f"#{rank} marker=payload+0x"
            f"{hit.offset:06X} "
            f"runtime=0x"
            f"{image_base + hit.offset:08X}"
        )
        print(f"Reason: {hit.reason}")

        if start is None:
            print(
                "No PUSH-with-LR function start "
                "found in backtrack window."
            )

            window_start = max(
                0,
                hit.offset - 0x40,
            )

            instructions = list(
                md.disasm(
                    payload[
                        window_start:
                        hit.offset + 0x80
                    ],
                    window_start,
                )
            )
        else:
            instructions = disassemble_function(
                md,
                payload,
                start,
                hit.offset,
                maximum_function_size,
            )

            commands, offsets, calls = (
                instruction_summary(
                    instructions
                )
            )

            print(
                f"Function start: "
                f"payload+0x{start:06X} "
                f"runtime=0x"
                f"{image_base + start:08X}"
            )
            print(
                f"Compared commands: "
                f"{sorted(commands)}"
            )
            print(
                f"LDRB offsets:      "
                f"{sorted(offsets)}"
            )
            print(
                f"Calls:             {calls}"
            )

        print_instructions(
            instructions,
            image_base,
            payload,
            marker_offset=hit.offset,
        )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "images",
        nargs="+",
        type=Path,
    )

    parser.add_argument(
        "--outer-header-size",
        type=lambda value: int(value, 0),
        default=0x50,
    )

    parser.add_argument(
        "--image-base",
        type=lambda value: int(value, 0),
        default=0x00824000,
    )

    parser.add_argument(
        "--uuid-radius",
        type=lambda value: int(value, 0),
        default=0x80,
    )

    parser.add_argument(
        "--maximum-backtrack",
        type=lambda value: int(value, 0),
        default=0x300,
    )

    parser.add_argument(
        "--maximum-function-size",
        type=lambda value: int(value, 0),
        default=0x800,
    )

    args = parser.parse_args()

    for image in args.images:
        analyze(
            image,
            args.outer_header_size,
            args.image_base,
            args.uuid_radius,
            args.maximum_backtrack,
            args.maximum_function_size,
        )


if __name__ == "__main__":
    main()
