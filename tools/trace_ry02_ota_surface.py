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
class UuidHit:
    name: str
    representation: str
    offset: int


@dataclass
class MarkerCandidate:
    marker_offset: int
    function_start: int
    score: int
    commands: set[int]
    byte_offsets: set[int]
    call_count: int
    instructions: list


def find_all(data: bytes, needle: bytes) -> list[int]:
    offsets: list[int] = []
    start = 0

    while True:
        offset = data.find(needle, start)

        if offset < 0:
            return offsets

        offsets.append(offset)
        start = offset + 1


def parse_immediates(operand_text: str) -> list[int]:
    values: list[int] = []

    for match in re.finditer(
        r"#(0x[0-9a-fA-F]+|[0-9]+)",
        operand_text,
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


def nearest_function_start(
    md: Cs,
    payload: bytes,
    target: int,
    maximum_backtrack: int = 0x200,
) -> int | None:
    lower = max(0, target - maximum_backtrack)
    lower &= ~1

    for start in range(target & ~1, lower - 1, -2):
        first = list(
            md.disasm(
                payload[start:start + 4],
                start,
                count=1,
            )
        )

        if not first or not is_push_lr(first[0]):
            continue

        instructions = list(
            md.disasm(
                payload[start:target + 4],
                start,
            )
        )

        expected = start
        reaches_target = False

        for instruction in instructions:
            if instruction.address != expected:
                break

            if instruction.address == target:
                reaches_target = True
                break

            expected += instruction.size

        if reaches_target:
            return start

    return None


def disassemble_function_window(
    md: Cs,
    payload: bytes,
    start: int,
    important_offset: int,
    maximum_size: int = 0x500,
) -> list:
    instructions = []

    for instruction in md.disasm(
        payload[start:start + maximum_size],
        start,
    ):
        instructions.append(instruction)

        if (
            instruction.address >= important_offset
            and is_return(instruction)
        ):
            break

    return instructions


def extract_ldrb_offsets(operand_text: str) -> set[int]:
    values: set[int] = set()

    if "[" not in operand_text:
        return values

    values.update(parse_immediates(operand_text))

    # [register] means offset zero.
    if "#" not in operand_text:
        values.add(0)

    return values


def collect_marker_candidates(
    md: Cs,
    payload: bytes,
) -> list[MarkerCandidate]:
    marker_hits: set[int] = set()

    for offset in range(0, len(payload) - 4, 2):
        instructions = list(
            md.disasm(
                payload[offset:offset + 4],
                offset,
                count=1,
            )
        )

        if not instructions:
            continue

        immediates = parse_immediates(
            instructions[0].op_str
        )

        if 0xBC in immediates:
            marker_hits.add(offset)

    candidates: dict[int, MarkerCandidate] = {}

    for marker_offset in sorted(marker_hits):
        function_start = nearest_function_start(
            md,
            payload,
            marker_offset,
        )

        if function_start is None:
            continue

        instructions = disassemble_function_window(
            md,
            payload,
            function_start,
            marker_offset,
        )

        commands: set[int] = set()
        byte_offsets: set[int] = set()
        call_count = 0
        marker_count = 0

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

            if instruction.mnemonic.startswith(
                "ldrb"
            ):
                byte_offsets.update(
                    extract_ldrb_offsets(
                        instruction.op_str
                    )
                )

            if instruction.mnemonic in {
                "bl",
                "blx",
            }:
                call_count += 1

            if 0xBC in immediates:
                marker_count += 1

        score = marker_count * 30
        score += len(commands) * 12
        score += min(call_count, 16)

        for useful_offset in (0, 1, 2, 3, 4, 5, 6):
            if useful_offset in byte_offsets:
                score += 5

        if {0, 1}.issubset(byte_offsets):
            score += 15

        if {2, 3}.intersection(byte_offsets):
            score += 5

        if {4, 5}.intersection(byte_offsets):
            score += 5

        if 6 in byte_offsets:
            score += 10

        candidate = MarkerCandidate(
            marker_offset=marker_offset,
            function_start=function_start,
            score=score,
            commands=commands,
            byte_offsets=byte_offsets,
            call_count=call_count,
            instructions=instructions,
        )

        current = candidates.get(function_start)

        if (
            current is None
            or candidate.score > current.score
        ):
            candidates[function_start] = candidate

    return sorted(
        candidates.values(),
        key=lambda item: (
            -item.score,
            item.function_start,
        ),
    )


def find_uuid_hits(payload: bytes) -> list[UuidHit]:
    hits: list[UuidHit] = []

    for name, canonical in UUIDS.items():
        for representation, needle in (
            ("canonical", canonical),
            ("reversed", canonical[::-1]),
        ):
            for offset in find_all(payload, needle):
                hits.append(
                    UuidHit(
                        name=name,
                        representation=representation,
                        offset=offset,
                    )
                )

    return sorted(
        hits,
        key=lambda item: item.offset,
    )


def pointer_xrefs(
    payload: bytes,
    values: set[int],
) -> list[tuple[int, int]]:
    results: list[tuple[int, int]] = []

    for value in sorted(values):
        encoded = struct.pack("<I", value)

        for offset in find_all(payload, encoded):
            results.append((offset, value))

    return sorted(results)


def nearby_thumb_pointers(
    payload: bytes,
    center: int,
    image_base: int,
    radius: int,
) -> list[tuple[int, int, int]]:
    start = max(0, center - radius)
    end = min(len(payload) - 4, center + radius)

    start = (start + 3) & ~3

    pointers: list[tuple[int, int, int]] = []

    for offset in range(start, end + 1, 4):
        value = read_u32(payload, offset)

        if value & 1 == 0:
            continue

        target = (value & ~1) - image_base

        if 0 <= target < len(payload):
            pointers.append(
                (offset, value, target)
            )

    return pointers


def print_instructions(
    instructions: list,
    image_base: int,
) -> None:
    for instruction in instructions:
        runtime = image_base + instruction.address
        raw = instruction.bytes.hex(" ")

        print(
            f"  payload+0x{instruction.address:06X} "
            f"runtime=0x{runtime:08X} "
            f"{raw:<18s} "
            f"{instruction.mnemonic:<8s} "
            f"{instruction.op_str}"
        )


def analyze_image(
    path: Path,
    header_size: int,
    image_base: int,
    radius: int,
    top: int,
) -> None:
    container = path.read_bytes()

    if len(container) <= header_size:
        raise ValueError(
            f"{path}: smaller than configured header"
        )

    payload = container[header_size:]

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.skipdata = True

    print("=" * 96)
    print(path)
    print("=" * 96)
    print(
        f"Container bytes: 0x{len(container):X}"
    )
    print(
        f"Payload bytes:   0x{len(payload):X}"
    )
    print(
        f"Runtime base:    0x{image_base:08X}"
    )

    uuid_hits = find_uuid_hits(payload)

    print("\nUUID HITS")
    print("-" * 96)

    if not uuid_hits:
        print("No OTA UUID representations found.")
    else:
        for hit in uuid_hits:
            print(
                f"{hit.name:8s} "
                f"{hit.representation:9s} "
                f"payload+0x{hit.offset:06X} "
                f"container+0x"
                f"{hit.offset + header_size:06X} "
                f"runtime=0x"
                f"{image_base + hit.offset:08X}"
            )

    print("\nDIRECT UUID POINTER XREFS")
    print("-" * 96)

    pointer_values: set[int] = set()

    for hit in uuid_hits:
        runtime = image_base + hit.offset

        pointer_values.update(
            {
                runtime,
                runtime | 1,
                hit.offset,
                hit.offset + header_size,
            }
        )

    xrefs = pointer_xrefs(
        payload,
        pointer_values,
    )

    if not xrefs:
        print(
            "No direct 32-bit UUID-address "
            "references found."
        )
    else:
        for offset, value in xrefs:
            print(
                f"payload+0x{offset:06X} "
                f"runtime=0x"
                f"{image_base + offset:08X} "
                f"value=0x{value:08X}"
            )

    print("\nTHUMB POINTERS NEAR UUID TABLES")
    print("-" * 96)

    emitted_targets: set[int] = set()

    for hit in uuid_hits:
        print(
            f"\n[{hit.name} {hit.representation} "
            f"at payload+0x{hit.offset:X}]"
        )

        pointers = nearby_thumb_pointers(
            payload,
            hit.offset,
            image_base,
            radius,
        )

        if not pointers:
            print(
                "  No nearby application Thumb pointers."
            )
            continue

        for word_offset, value, target in pointers:
            print(
                f"  table+0x"
                f"{word_offset - hit.offset:+X} "
                f"payload+0x{word_offset:06X} "
                f"value=0x{value:08X} "
                f"target=payload+0x{target:06X}"
            )

            if target in emitted_targets:
                continue

            emitted_targets.add(target)

            instructions = list(
                md.disasm(
                    payload[target:target + 0x100],
                    target,
                )
            )

            print(
                "  Candidate target disassembly:"
            )

            print_instructions(
                instructions[:64],
                image_base,
            )

    print("\n0xBC FRAME-MARKER FUNCTION CANDIDATES")
    print("-" * 96)

    candidates = collect_marker_candidates(
        md,
        payload,
    )

    print(
        f"Candidates found: {len(candidates)}"
    )

    for rank, candidate in enumerate(
        candidates[:top],
        start=1,
    ):
        print("\n" + "-" * 96)
        print(
            f"#{rank} score={candidate.score} "
            f"function=payload+0x"
            f"{candidate.function_start:06X} "
            f"runtime=0x"
            f"{image_base + candidate.function_start:08X}"
        )
        print(
            f"marker=payload+0x"
            f"{candidate.marker_offset:06X} "
            f"commands={sorted(candidate.commands)} "
            f"ldrb_offsets="
            f"{sorted(candidate.byte_offsets)} "
            f"calls={candidate.call_count}"
        )

        print_instructions(
            candidate.instructions,
            image_base,
        )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "images",
        nargs="+",
        type=Path,
    )

    parser.add_argument(
        "--header-size",
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
        default=0x200,
    )

    parser.add_argument(
        "--top",
        type=int,
        default=30,
    )

    args = parser.parse_args()

    for image in args.images:
        analyze_image(
            image,
            args.header_size,
            args.image_base,
            args.uuid_radius,
            args.top,
        )


if __name__ == "__main__":
    main()
