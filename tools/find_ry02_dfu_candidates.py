#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB


OTA_UUID = bytes.fromhex(
    "de5bf728d7114e47af2665e3012a5dc7"
)
OTA_UUID_REVERSED = OTA_UUID[::-1]

LITERAL_40000 = (0x00040000).to_bytes(4, "little")
LITERAL_80000 = (0x00080000).to_bytes(4, "little")


@dataclass
class Candidate:
    offset: int
    score: int
    cmp_values: set[int]
    ldrb_count: int
    call_count: int
    has_uuid: bool
    has_40000: bool
    has_80000: bool
    instructions: list


def parse_immediate(text: str) -> int | None:
    match = re.search(r"#(0x[0-9a-fA-F]+|[0-9]+)", text)

    if match is None:
        return None

    return int(match.group(1), 0)


def is_return(mnemonic: str, operands: str) -> bool:
    if mnemonic == "bx" and operands.strip() == "lr":
        return True

    return mnemonic == "pop" and "pc" in operands


def inspect_candidate(
    md: Cs,
    payload: bytes,
    offset: int,
    window_size: int,
) -> Candidate | None:
    code = payload[offset:offset + window_size]
    instructions = list(md.disasm(code, offset))

    if not instructions:
        return None

    first = instructions[0]

    if first.mnemonic != "push" or "lr" not in first.op_str:
        return None

    cmp_values: set[int] = set()
    ldrb_count = 0
    call_count = 0
    retained = []

    for instruction in instructions:
        retained.append(instruction)

        if instruction.mnemonic == "cmp":
            immediate = parse_immediate(instruction.op_str)

            if immediate is not None:
                cmp_values.add(immediate)

        if instruction.mnemonic.startswith("ldrb"):
            ldrb_count += 1

        if instruction.mnemonic in {"bl", "blx"}:
            call_count += 1

        if (
            len(retained) >= 16
            and is_return(
                instruction.mnemonic,
                instruction.op_str,
            )
        ):
            break

    command_values = cmp_values.intersection(
        {1, 2, 3, 4, 5}
    )

    raw = payload[offset:offset + window_size]

    has_uuid = (
        OTA_UUID in raw
        or OTA_UUID_REVERSED in raw
    )

    has_40000 = LITERAL_40000 in raw
    has_80000 = LITERAL_80000 in raw

    score = 0
    score += len(command_values) * 12

    if command_values == {1, 2, 3, 4, 5}:
        score += 40

    if 0xBC in cmp_values:
        score += 25

    score += min(ldrb_count, 12)
    score += min(call_count, 12)

    if has_uuid:
        score += 30

    if has_40000:
        score += 8

    if has_80000:
        score += 8

    if len(command_values) < 3:
        return None

    return Candidate(
        offset=offset,
        score=score,
        cmp_values=cmp_values,
        ldrb_count=ldrb_count,
        call_count=call_count,
        has_uuid=has_uuid,
        has_40000=has_40000,
        has_80000=has_80000,
        instructions=retained,
    )


def scan_image(
    path: Path,
    header_size: int,
    image_base: int,
    top: int,
    window_size: int,
) -> None:
    container = path.read_bytes()

    if len(container) <= header_size:
        raise ValueError(
            f"{path}: image is smaller than header"
        )

    payload = container[header_size:]

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.skipdata = True

    uuid_offsets = []

    for needle_name, needle in (
        ("canonical", OTA_UUID),
        ("reversed", OTA_UUID_REVERSED),
    ):
        start = 0

        while True:
            offset = payload.find(needle, start)

            if offset < 0:
                break

            uuid_offsets.append(
                (needle_name, offset)
            )
            start = offset + 1

    candidates = []

    for offset in range(0, len(payload) - 2, 2):
        first = list(
            md.disasm(
                payload[offset:offset + 4],
                offset,
                count=1,
            )
        )

        if not first:
            continue

        if (
            first[0].mnemonic != "push"
            or "lr" not in first[0].op_str
        ):
            continue

        candidate = inspect_candidate(
            md,
            payload,
            offset,
            window_size,
        )

        if candidate is not None:
            candidates.append(candidate)

    candidates.sort(
        key=lambda item: (
            -item.score,
            item.offset,
        )
    )

    print("=" * 88)
    print(path)
    print("=" * 88)
    print(
        f"Container: 0x{len(container):X} bytes"
    )
    print(
        f"Payload:   0x{len(payload):X} bytes"
    )
    print(
        f"Base:      0x{image_base:08X}"
    )

    print("\nOTA UUID occurrences:")

    if uuid_offsets:
        for order, offset in uuid_offsets:
            print(
                f"  {order:9s} "
                f"payload+0x{offset:X} "
                f"runtime=0x{image_base + offset:08X}"
            )
    else:
        print("  none")

    print(
        f"\nDispatcher candidates: "
        f"{len(candidates)}"
    )

    for rank, candidate in enumerate(
        candidates[:top],
        start=1,
    ):
        command_values = sorted(
            candidate.cmp_values.intersection(
                {1, 2, 3, 4, 5}
            )
        )

        print("\n" + "-" * 88)
        print(
            f"#{rank} score={candidate.score} "
            f"payload+0x{candidate.offset:X} "
            f"runtime=0x{image_base + candidate.offset:08X}"
        )
        print(
            f"commands={command_values} "
            f"cmp_bc={0xBC in candidate.cmp_values} "
            f"ldrb={candidate.ldrb_count} "
            f"calls={candidate.call_count} "
            f"uuid={candidate.has_uuid} "
            f"literal_40000={candidate.has_40000} "
            f"literal_80000={candidate.has_80000}"
        )

        for instruction in candidate.instructions:
            raw = instruction.bytes.hex(" ")
            print(
                f"0x{instruction.address:08X}: "
                f"{raw:<18s} "
                f"{instruction.mnemonic:<8s} "
                f"{instruction.op_str}"
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
        "--window-size",
        type=lambda value: int(value, 0),
        default=0x500,
    )

    parser.add_argument(
        "--top",
        type=int,
        default=20,
    )

    args = parser.parse_args()

    for image in args.images:
        scan_image(
            image,
            args.header_size,
            args.image_base,
            args.top,
            args.window_size,
        )


if __name__ == "__main__":
    main()
