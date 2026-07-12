#!/usr/bin/env python3
"""
Find direct Thumb BL/BLX-immediate callers of low runtime/ROM targets in RY02
firmware images.

Important addressing rule:
  RY02 payload offset 0 maps to runtime 0x00824000.

Disassembling the payload at address 0 incorrectly makes low-address calls look
like 0xFFxxxxxx. This tool disassembles at the real runtime base, so a call such
as the command-5 timer callback's apparent 0xFF7DC29C target is reported as
runtime 0x0000029C.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    from capstone import (
        CS_ARCH_ARM,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_THUMB,
        Cs,
    )
    from capstone.arm import ARM_OP_IMM
except ImportError as exc:
    raise SystemExit(
        "capstone is required. Activate the project venv and run:\n"
        "  python3 -m pip install capstone"
    ) from exc


OUTER_MAGIC = b"\xE5\xC3\xBD\x81"
DEFAULT_OUTER_HEADER = 0x50
DEFAULT_IMAGE_BASE = 0x00824000
DEFAULT_SCAN_START = 0x400

DEFAULT_TARGETS = (
    0x0000029C,  # delayed command-5 terminal action
    0x00007B1E,  # persistent-state read-like operation
    0x00007B32,  # persistent-state write-like operation
    0x00012ED6,  # event/queue helper used by payload+0x898
    0x00013634,  # timer/object registration helper
    0x00013694,  # timer/object arm/update helper
    0x0003F848,  # memcpy-like helper
    0x0003F918,  # memset-like helper
)

TARGET_LABELS = {
    0x0000029C: "command-5 delayed terminal action",
    0x00007B1E: "persistent-state read-like operation",
    0x00007B32: "persistent-state write-like operation",
    0x00012ED6: "event/queue helper",
    0x00013634: "timer/object registration",
    0x00013694: "timer/object arm/update",
    0x0003F848: "memcpy-like helper",
    0x0003F918: "memset-like helper",
}


@dataclass(frozen=True)
class Image:
    path: Path
    container: bytes
    payload: bytes
    payload_file_offset: int
    image_base: int


@dataclass(frozen=True)
class CallHit:
    payload_offset: int
    runtime_address: int
    size: int
    raw_bytes: bytes
    mnemonic: str
    op_str: str
    target: int


def parse_int(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {text!r}") from exc


def load_image(path: Path, image_base: int, outer_header: int) -> Image:
    data = path.read_bytes()
    if len(data) >= outer_header and data[:4] == OUTER_MAGIC:
        payload_offset = outer_header
        payload = data[payload_offset:]

        # Validate the duplicated outer payload-length fields when present.
        if len(data) >= 12:
            length_a, length_b = struct.unpack_from("<II", data, 4)
            if length_a != len(payload) or length_b != len(payload):
                print(
                    f"warning: {path}: outer lengths "
                    f"0x{length_a:X}/0x{length_b:X} do not equal "
                    f"payload size 0x{len(payload):X}",
                    file=sys.stderr,
                )
    else:
        payload_offset = 0
        payload = data

    return Image(
        path=path,
        container=data,
        payload=payload,
        payload_file_offset=payload_offset,
        image_base=image_base,
    )


def make_disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = False
    return md


def decode_one(md: Cs, payload: bytes, offset: int, image_base: int):
    if offset < 0 or offset >= len(payload):
        return None
    instructions = list(
        md.disasm(payload[offset : offset + 4], image_base + offset, count=1)
    )
    return instructions[0] if instructions else None


def direct_call_target(insn) -> int | None:
    if insn.mnemonic not in {"bl", "blx"}:
        return None
    if not insn.operands or insn.operands[0].type != ARM_OP_IMM:
        return None
    return int(insn.operands[0].imm) & 0xFFFFFFFF


def scan_calls(
    image: Image,
    targets: set[int],
    scan_start: int,
    scan_end: int | None,
) -> list[CallHit]:
    md = make_disassembler()
    payload = image.payload
    end = len(payload) if scan_end is None else min(scan_end, len(payload))
    start = max(0, scan_start) & ~1
    end &= ~1

    normalized_targets = {target & 0xFFFFFFFE for target in targets}
    hits: list[CallHit] = []

    # Scan every Thumb halfword. This intentionally does not assume that the
    # complete payload is one uninterrupted code stream.
    for offset in range(start, max(start, end - 1), 2):
        insn = decode_one(md, payload, offset, image.image_base)
        if insn is None:
            continue
        target = direct_call_target(insn)
        if target is None:
            continue
        if (target & 0xFFFFFFFE) not in normalized_targets:
            continue
        hits.append(
            CallHit(
                payload_offset=offset,
                runtime_address=image.image_base + offset,
                size=insn.size,
                raw_bytes=bytes(insn.bytes),
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                target=target,
            )
        )

    # A valid BL is four bytes. Sorting and deduplicating protects against any
    # decoder aliases encountered while scanning arbitrary data.
    unique: dict[tuple[int, int], CallHit] = {}
    for hit in hits:
        unique[(hit.payload_offset, hit.target & 0xFFFFFFFE)] = hit
    return sorted(unique.values(), key=lambda hit: (hit.target, hit.payload_offset))


def nearest_function_start(
    image: Image,
    call_offset: int,
    backtrack: int,
) -> int | None:
    md = make_disassembler()
    lower = max(DEFAULT_SCAN_START, call_offset - backtrack) & ~1

    for offset in range(call_offset, lower - 1, -2):
        insn = decode_one(md, image.payload, offset, image.image_base)
        if insn is None:
            continue
        if insn.mnemonic == "push" and "lr" in insn.op_str:
            return offset
        if insn.mnemonic == "stmdb" and insn.op_str.startswith("sp!") and "lr" in insn.op_str:
            return offset
    return None


def disassemble_range(
    image: Image,
    start: int,
    end: int,
) -> Iterable[str]:
    md = make_disassembler()
    start = max(0, start) & ~1
    end = min(len(image.payload), end)
    for insn in md.disasm(
        image.payload[start:end],
        image.image_base + start,
    ):
        payload_offset = insn.address - image.image_base
        raw = " ".join(f"{byte:02x}" for byte in insn.bytes)
        yield (
            f"  payload+0x{payload_offset:06X} "
            f"runtime=0x{insn.address:08X} "
            f"{raw:<12} {insn.mnemonic:<8} {insn.op_str}"
        )


def print_image_report(
    image: Image,
    targets: list[int],
    hits: list[CallHit],
    backtrack: int,
    context_before: int,
    context_after: int,
) -> None:
    print("=" * 104)
    print(image.path)
    print("=" * 104)
    print(f"Container bytes:      0x{len(image.container):X}")
    print(f"Container SHA256:     {hashlib.sha256(image.container).hexdigest()}")
    print(f"Payload file offset:  0x{image.payload_file_offset:X}")
    print(f"Payload bytes:        0x{len(image.payload):X}")
    print(f"Payload runtime base: 0x{image.image_base:08X}")
    print()

    by_target: dict[int, list[CallHit]] = {
        target & 0xFFFFFFFE: [] for target in targets
    }
    for hit in hits:
        by_target.setdefault(hit.target & 0xFFFFFFFE, []).append(hit)

    for requested in targets:
        target = requested & 0xFFFFFFFE
        label = TARGET_LABELS.get(target, "unlabelled target")
        target_hits = by_target.get(target, [])

        print("-" * 104)
        print(
            f"TARGET 0x{target:08X}  {label}  "
            f"direct callers={len(target_hits)}"
        )

        if not target_hits:
            print("  No direct BL/BLX-immediate callers found.")
            continue

        for index, hit in enumerate(target_hits, 1):
            function_start = nearest_function_start(
                image, hit.payload_offset, backtrack
            )
            if function_start is None:
                context_start = max(
                    DEFAULT_SCAN_START,
                    hit.payload_offset - context_before,
                )
                function_text = "not found"
            else:
                context_start = function_start
                function_text = (
                    f"payload+0x{function_start:06X} "
                    f"runtime=0x{image.image_base + function_start:08X}"
                )

            context_end = min(
                len(image.payload),
                hit.payload_offset + hit.size + context_after,
            )

            print()
            print(
                f"  [{index}] caller payload+0x{hit.payload_offset:06X} "
                f"runtime=0x{hit.runtime_address:08X}"
            )
            print(
                f"      instruction: {hit.raw_bytes.hex(' ')}  "
                f"{hit.mnemonic} {hit.op_str}"
            )
            print(f"      decoded target: 0x{hit.target:08X}")
            print(f"      nearest function start: {function_text}")
            print("      context:")
            for line in disassemble_range(image, context_start, context_end):
                marker = ">>" if (
                    f"payload+0x{hit.payload_offset:06X}" in line
                ) else "  "
                print(f"      {marker}{line}")

    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Find direct callers of selected low runtime/ROM targets in "
            "RY02 Thumb firmware payloads."
        )
    )
    parser.add_argument("images", nargs="+", type=Path)
    parser.add_argument(
        "--target",
        action="append",
        type=parse_int,
        default=[],
        help=(
            "Runtime target address; repeat as needed. "
            "Defaults to the known OTA/persistence targets."
        ),
    )
    parser.add_argument(
        "--image-base",
        type=parse_int,
        default=DEFAULT_IMAGE_BASE,
        help="Runtime address corresponding to payload offset 0.",
    )
    parser.add_argument(
        "--outer-header",
        type=parse_int,
        default=DEFAULT_OUTER_HEADER,
        help="Outer QRing container header length.",
    )
    parser.add_argument(
        "--scan-start",
        type=parse_int,
        default=DEFAULT_SCAN_START,
        help="First payload offset to scan.",
    )
    parser.add_argument(
        "--scan-end",
        type=parse_int,
        default=None,
        help="Exclusive payload offset at which scanning stops.",
    )
    parser.add_argument(
        "--backtrack",
        type=parse_int,
        default=0x180,
        help="Maximum distance to search backward for a PUSH containing LR.",
    )
    parser.add_argument(
        "--context-before",
        type=parse_int,
        default=0x30,
        help="Fallback bytes shown before a caller when no function start is found.",
    )
    parser.add_argument(
        "--context-after",
        type=parse_int,
        default=0x10,
        help="Bytes shown after each caller.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    targets = args.target or list(DEFAULT_TARGETS)
    target_set = {target & 0xFFFFFFFE for target in targets}

    failed = False
    for path in args.images:
        try:
            image = load_image(path, args.image_base, args.outer_header)
            hits = scan_calls(
                image,
                target_set,
                args.scan_start,
                args.scan_end,
            )
            print_image_report(
                image,
                targets,
                hits,
                args.backtrack,
                args.context_before,
                args.context_after,
            )
        except (OSError, ValueError) as exc:
            failed = True
            print(f"error: {path}: {exc}", file=sys.stderr)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
