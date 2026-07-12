#!/usr/bin/env python3
"""
Trace the RY02 source/category-1 D0 producer subsystem.

The tool is deliberately descriptive. It inventories:
  * the three known source-1/D0 producers and their parents;
  * exact RAM literal references and derived-address contexts;
  * direct callers, raw pointers, and Thumb pointers;
  * CFG-reachable calls and literals;
  * six-byte compare/copy call patterns;
  * heuristic .33 counterparts.

It does not assign a vendor subsystem name, identify 0x29C as bx_public,
or interpret D0/D3 as reset messages.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import platform
import string
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

try:
    import capstone
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
    from capstone.arm import (
        ARM_OP_IMM,
        ARM_OP_MEM,
        ARM_OP_REG,
        ARM_REG_LR,
        ARM_REG_PC,
        ARM_REG_R0,
        ARM_REG_R1,
        ARM_REG_R2,
        ARM_REG_R3,
        ARM_REG_SP,
    )
except ImportError as exc:
    raise SystemExit(
        "capstone is required. Install it with:\n"
        "  python3 -m pip install capstone"
    ) from exc


TOOL_REVISION = "r2"
HEADER_SIZE = 0x50
DEFAULT_BASE = 0x00824000
DEFAULT_CODE_START = 0x400
PUBLISH_TARGET = 0x0000029C

RAM_MIN = 0x00200000
RAM_MAX = 0x00220000

KNOWN_PERIPHERAL_RANGES = (
    (0x20100000, 0x20300000),
    (0x40000000, 0x60000000),
    (0xE0000000, 0xE0100000),
)

CALLER_SAVED = {ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3}

FUNCTION_TARGETS: tuple[tuple[str, int], ...] = (
    ("source1_D0_completion_publisher", 0x00826FF8),
    ("source1_D0_state_update_publisher", 0x00828DD2),
    ("source1_D0_configuration_publisher", 0x00829E70),
    ("completion_parent_candidate", 0x00825476),
    ("state_dispatch_parent_candidate", 0x008291E6),
    ("configuration_startup_parent", 0x00824988),
    ("state_update_shared_tail_target", 0x008288C0),
)

RAM_TARGETS: tuple[tuple[str, int], ...] = (
    ("completion_callback_or_service_object", 0x00200120),
    ("completion_state_object", 0x002098F0),
    ("configuration_primary_object", 0x00208670),
    ("six_byte_state_derived_base", 0x00208690),
    ("six_byte_state_literal_anchor", 0x00208696),
    ("six_byte_state_change_flag", 0x002086D0),
    ("configuration_byte_object", 0x00208449),
    ("configuration_aux_object", 0x00209A0F),
)

SIX_BYTE_HELPERS: tuple[tuple[str, int], ...] = (
    ("six_byte_compare_candidate", 0x0003F7A8),
    ("six_byte_copy_candidate", 0x0003F848),
)


@dataclass(frozen=True)
class Image:
    path: Path
    container: bytes
    payload: bytes
    base: int
    code_start: int
    md: Cs

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        base: int,
        code_start: int,
        header_size: int,
    ) -> "Image":
        container = path.read_bytes()
        if len(container) <= header_size:
            raise ValueError(
                f"{path}: too small for 0x{header_size:X}-byte outer header"
            )
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        return cls(
            path=path,
            container=container,
            payload=container[header_size:],
            base=base,
            code_start=code_start,
            md=md,
        )

    def offset_for_runtime(self, address: int) -> int:
        return address - self.base

    def runtime_for_offset(self, offset: int) -> int:
        return self.base + offset

    def in_payload_runtime(self, address: int) -> bool:
        return self.base <= address < self.base + len(self.payload)

    def decode_one(self, offset: int):
        if not 0 <= offset < len(self.payload):
            return None
        decoded = list(
            self.md.disasm(
                self.payload[offset : offset + 4],
                self.runtime_for_offset(offset),
                count=1,
            )
        )
        return decoded[0] if decoded else None

    def sha256(self) -> str:
        return hashlib.sha256(self.container).hexdigest()


@dataclass
class FunctionGraph:
    start: int
    instructions: dict[int, object]
    returns: list[int]
    external_tail_branches: list[tuple[int, int]]
    decode_failures: list[int]

    def ordered(self) -> list:
        return [self.instructions[address] for address in sorted(self.instructions)]


def parse_int(text: str) -> int:
    return int(text, 0)


def direct_branch_target(insn) -> int | None:
    if insn is None:
        return None
    if insn.mnemonic not in {
        "bl", "blx", "b", "b.w",
        "beq", "bne", "bhi", "bhs", "blo", "bls",
        "bge", "bgt", "ble", "blt", "bpl", "bmi",
        "bvs", "bvc", "bcs", "bcc",
    }:
        return None
    if not insn.operands or insn.operands[0].type != ARM_OP_IMM:
        return None
    return insn.operands[0].imm & 0xFFFFFFFF


def cb_target(insn) -> int | None:
    if insn is None or insn.mnemonic not in {"cbz", "cbnz"}:
        return None
    if len(insn.operands) < 2 or insn.operands[1].type != ARM_OP_IMM:
        return None
    return insn.operands[1].imm & 0xFFFFFFFF


def is_call(insn) -> bool:
    return insn is not None and insn.mnemonic in {"bl", "blx"}


def is_unconditional_branch(insn) -> bool:
    return insn is not None and insn.mnemonic in {"b", "b.w"}


def is_conditional_branch(insn) -> bool:
    if insn is None:
        return False
    if insn.mnemonic in {"cbz", "cbnz"}:
        return True
    return insn.mnemonic.startswith("b") and insn.mnemonic not in {
        "b", "b.w", "bl", "blx", "bx"
    }


def is_return(insn) -> bool:
    if insn is None:
        return False
    if insn.mnemonic == "bx" and insn.operands:
        op = insn.operands[0]
        return op.type == ARM_OP_REG and op.reg == ARM_REG_LR
    return insn.mnemonic == "pop" and "pc" in insn.op_str


def is_probable_function_start(insn) -> bool:
    return insn is not None and insn.mnemonic == "push" and "lr" in insn.op_str


def build_function_cfg(
    image: Image,
    start_address: int,
    *,
    max_forward: int = 0x1000,
    max_backward: int = 0x80,
    max_instructions: int = 1600,
) -> FunctionGraph:
    lower = max(image.base + image.code_start, start_address - max_backward)
    upper = min(image.base + len(image.payload), start_address + max_forward)

    worklist = [start_address]
    visited_blocks: set[int] = set()
    instructions: dict[int, object] = {}
    returns: list[int] = []
    external_tails: list[tuple[int, int]] = []
    failures: list[int] = []

    while worklist and len(instructions) < max_instructions:
        block = worklist.pop()
        if block in visited_blocks:
            continue
        visited_blocks.add(block)

        current = block
        while lower <= current < upper and len(instructions) < max_instructions:
            if current in instructions:
                break
            insn = image.decode_one(image.offset_for_runtime(current))
            if insn is None:
                failures.append(current)
                break

            instructions[current] = insn
            next_address = current + insn.size

            if is_return(insn):
                returns.append(current)
                break

            if is_call(insn):
                current = next_address
                continue

            if is_unconditional_branch(insn):
                target = direct_branch_target(insn)
                if target is None:
                    break
                if lower <= target < upper:
                    worklist.append(target)
                else:
                    external_tails.append((current, target))
                break

            if is_conditional_branch(insn):
                target = cb_target(insn)
                if target is None:
                    target = direct_branch_target(insn)
                if target is not None:
                    if lower <= target < upper:
                        worklist.append(target)
                    else:
                        external_tails.append((current, target))
                current = next_address
                continue

            if insn.mnemonic == "bx":
                break

            current = next_address

    return FunctionGraph(
        start=start_address,
        instructions=instructions,
        returns=sorted(set(returns)),
        external_tail_branches=sorted(set(external_tails)),
        decode_failures=sorted(set(failures)),
    )


def scan_direct_callers(image: Image, target: int) -> list[int]:
    result: list[int] = []
    for offset in range(image.code_start, len(image.payload) - 4, 2):
        insn = image.decode_one(offset)
        if is_call(insn) and direct_branch_target(insn) == target:
            result.append(image.runtime_for_offset(offset))
    return result


def scan_raw_references(image: Image, value: int) -> list[int]:
    needle = value.to_bytes(4, "little")
    result: list[int] = []
    start = 0
    while True:
        offset = image.payload.find(needle, start)
        if offset < 0:
            break
        result.append(image.runtime_for_offset(offset))
        start = offset + 1
    return result


def probable_enclosing_start(
    image: Image,
    address: int,
    *,
    window: int = 0x240,
) -> int | None:
    address_offset = image.offset_for_runtime(address)
    lower = max(image.code_start, address_offset - window)
    candidates: list[int] = []

    for offset in range(lower, address_offset, 2):
        insn = image.decode_one(offset)
        if not is_probable_function_start(insn):
            continue
        start = image.runtime_for_offset(offset)
        graph = build_function_cfg(
            image,
            start,
            max_forward=max(0x300, address - start + 0x80),
        )
        if address in graph.instructions:
            candidates.append(start)

    return candidates[-1] if candidates else None


def contiguous_predecessors(
    image: Image,
    address: int,
    *,
    window: int = 0x80,
) -> list:
    address_offset = image.offset_for_runtime(address)
    lower = max(image.code_start, address_offset - window)
    best: list = []

    for start in range(lower, address_offset, 2):
        sequence = []
        current = start
        valid = True
        while current < address_offset:
            insn = image.decode_one(current)
            if insn is None:
                valid = False
                break
            sequence.append(insn)
            current += insn.size
        if valid and current == address_offset and len(sequence) > len(best):
            best = sequence
    return best


def local_register_provenance(
    image: Image,
    address: int,
    register: int,
) -> str:
    sequence = contiguous_predecessors(image, address)

    for insn in reversed(sequence):
        if is_call(insn) and register in CALLER_SAVED:
            return (
                f"unknown: {image.md.reg_name(register)} may be clobbered "
                f"by {insn.mnemonic} at 0x{insn.address:08X}"
            )

        try:
            _, written = insn.regs_access()
        except Exception:
            written = []

        if register not in written:
            continue

        if (
            insn.mnemonic in {"mov", "movs"}
            and len(insn.operands) >= 2
            and insn.operands[0].type == ARM_OP_REG
            and insn.operands[0].reg == register
        ):
            source = insn.operands[1]
            if source.type == ARM_OP_IMM:
                return (
                    f"immediate 0x{source.imm & 0xFFFFFFFF:X} "
                    f"at 0x{insn.address:08X}"
                )
            if source.type == ARM_OP_REG:
                return (
                    f"copied from {insn.reg_name(source.reg)} "
                    f"at 0x{insn.address:08X}"
                )

        return f"{insn.mnemonic} {insn.op_str} at 0x{insn.address:08X}"

    return "no local writer found"


def ldr_literal_value(image: Image, insn) -> tuple[int, int] | None:
    # Whole-payload scans intentionally probe every halfword-aligned offset.
    # Some offsets are data, literal pools, padding, or otherwise undecodable.
    # Treat those positions as non-instructions rather than aborting the report.
    if insn is None:
        return None

    if not insn.mnemonic.startswith("ldr") or len(insn.operands) < 2:
        return None
    operand = insn.operands[1]
    if operand.type != ARM_OP_MEM or operand.mem.base != ARM_REG_PC:
        return None

    literal_address = ((insn.address + 4) & ~3) + operand.mem.disp
    offset = image.offset_for_runtime(literal_address)
    if not 0 <= offset <= len(image.payload) - 4:
        return None

    value = int.from_bytes(image.payload[offset : offset + 4], "little")
    return literal_address, value


def scan_literal_loads(image: Image, value: int) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for offset in range(image.code_start, len(image.payload) - 4, 2):
        insn = image.decode_one(offset)
        resolved = ldr_literal_value(image, insn)
        if resolved is None:
            continue
        literal_address, loaded = resolved
        if loaded == value:
            result.append((insn.address, literal_address))
    return result


def classify_value(image: Image, value: int) -> str:
    if RAM_MIN <= value < RAM_MAX:
        return "RAM"
    if image.in_payload_runtime(value):
        return "image"
    for low, high in KNOWN_PERIPHERAL_RANGES:
        if low <= value < high:
            return "known-peripheral-range"
    if value >= 0x01000000:
        return "high-constant"
    return "scalar-or-low-address"


def ascii_at_runtime(
    image: Image,
    runtime_address: int,
    *,
    min_length: int = 4,
    max_length: int = 96,
) -> str | None:
    if not image.in_payload_runtime(runtime_address):
        return None
    offset = image.offset_for_runtime(runtime_address)
    chars: list[str] = []
    for byte in image.payload[offset : offset + max_length]:
        if byte == 0:
            break
        character = chr(byte)
        if character not in string.printable or character in "\r\n\t\x0b\x0c":
            return None
        chars.append(character)
    text = "".join(chars)
    return text if len(text) >= min_length else None


def normalized_token(insn, image: Image) -> str:
    parts = [insn.mnemonic]

    target = direct_branch_target(insn)
    if target is not None:
        parts.append("BR_LOCAL" if image.in_payload_runtime(target) else f"BR_LOW_{target & 0xFFF:X}")
        return ":".join(parts)

    target = cb_target(insn)
    if target is not None:
        parts.append("CB_LOCAL" if image.in_payload_runtime(target) else "CB_EXTERNAL")
        return ":".join(parts)

    resolved = ldr_literal_value(image, insn)
    if resolved is not None:
        _, value = resolved
        parts.append(f"LIT_{classify_value(image, value)}")
        return ":".join(parts)

    for operand in insn.operands:
        if operand.type == ARM_OP_REG:
            parts.append(f"R{operand.reg}")
        elif operand.type == ARM_OP_IMM:
            value = operand.imm & 0xFFFFFFFF
            parts.append(f"I{value:X}" if value <= 0xFF else "I_BIG")
        elif operand.type == ARM_OP_MEM:
            if operand.mem.base == ARM_REG_SP:
                parts.append("MEM_SP")
            elif operand.mem.base == ARM_REG_PC:
                parts.append("MEM_PC")
            else:
                parts.append("MEM_REG")
    return ":".join(parts)


def probable_function_starts(image: Image) -> Iterator[int]:
    for offset in range(image.code_start, len(image.payload) - 2, 2):
        insn = image.decode_one(offset)
        if is_probable_function_start(insn):
            yield image.runtime_for_offset(offset)


def counterpart_candidates(
    source_image: Image,
    graph: FunctionGraph,
    comparison_image: Image,
    *,
    top_n: int = 3,
) -> list[tuple[float, int, int]]:
    source_tokens = [
        normalized_token(insn, source_image)
        for insn in graph.ordered()[:96]
    ]
    if len(source_tokens) < 3:
        return []

    candidates: list[tuple[float, int, int]] = []
    for start in probable_function_starts(comparison_image):
        candidate = build_function_cfg(comparison_image, start)
        candidate_tokens = [
            normalized_token(insn, comparison_image)
            for insn in candidate.ordered()[:96]
        ]
        if len(candidate_tokens) < 3:
            continue
        score = difflib.SequenceMatcher(
            a=source_tokens,
            b=candidate_tokens,
            autojunk=False,
        ).ratio()
        candidates.append((score, start, len(candidate.instructions)))

    candidates.sort(reverse=True)
    return candidates[:top_n]


def format_instruction(image: Image, insn, marker: str = "  ") -> str:
    target = direct_branch_target(insn)
    if target is None:
        target = cb_target(insn)
    suffix = f" ; target=0x{target:08X}" if target is not None else ""
    return (
        f"{marker} payload+0x{image.offset_for_runtime(insn.address):05X} "
        f"runtime=0x{insn.address:08X} "
        f"{insn.bytes.hex(' '):<13} "
        f"{insn.mnemonic:<9} {insn.op_str}{suffix}"
    )


def print_context(
    image: Image,
    center: int,
    *,
    before: int = 0x30,
    after: int = 0x40,
) -> None:
    start = max(image.code_start, image.offset_for_runtime(center) - before)
    end = min(len(image.payload), image.offset_for_runtime(center) + after)
    current = start

    while current < end:
        insn = image.decode_one(current)
        if insn is None:
            print(
                f"   payload+0x{current:05X} "
                f"runtime=0x{image.runtime_for_offset(current):08X} "
                "<undecoded>"
            )
            current += 2
            continue
        marker = ">>" if insn.address == center else "  "
        print(format_instruction(image, insn, marker))
        current += insn.size

        # Context is explanatory only, but do not continue into a literal pool
        # or adjacent function after a visible return/tail branch.
        if insn.address >= center and (
            is_return(insn) or is_unconditional_branch(insn)
        ):
            break


def report_ram_target(image: Image, label: str, value: int) -> None:
    print("=" * 110)
    print(f"RAM target: {label}")
    print(f"value: 0x{value:08X}")

    raw = scan_raw_references(image, value)
    loads = scan_literal_loads(image, value)

    print(f"raw occurrences: {len(raw)}")
    for address in raw:
        print(f"  0x{address:08X}")

    print(f"literal-load references: {len(loads)}")
    for insn_address, literal_address in loads:
        parent = probable_enclosing_start(image, insn_address)
        print(
            f"  load=0x{insn_address:08X} "
            f"literal=0x{literal_address:08X} "
            f"parent={f'0x{parent:08X}' if parent is not None else 'unresolved'}"
        )
        print_context(image, insn_address, before=0x18, after=0x28)
    print()


def report_function(
    image: Image,
    label: str,
    address: int,
    comparison: Image | None,
) -> None:
    graph = build_function_cfg(image, address)

    print("=" * 110)
    print(f"function: {label}")
    print(f"start: 0x{address:08X}")
    print(f"reachable instructions: {len(graph.instructions)}")
    print(f"returns: {len(graph.returns)}")
    for ret in graph.returns:
        print(f"  0x{ret:08X}")
    print(f"external tail branches: {len(graph.external_tail_branches)}")
    for site, target in graph.external_tail_branches:
        print(f"  0x{site:08X} -> 0x{target:08X}")

    callers = scan_direct_callers(image, address)
    raw = scan_raw_references(image, address)
    thumb = scan_raw_references(image, address | 1)

    print()
    print(f"direct callers: {len(callers)}")
    for caller in callers:
        parent = probable_enclosing_start(image, caller)
        print(
            f"  call=0x{caller:08X} "
            f"parent={f'0x{parent:08X}' if parent is not None else 'unresolved'}"
        )
        for register, name in (
            (ARM_REG_R0, "r0"),
            (ARM_REG_R1, "r1"),
            (ARM_REG_R2, "r2"),
            (ARM_REG_R3, "r3"),
        ):
            print(f"    {name}: {local_register_provenance(image, caller, register)}")

    print(f"raw exact refs: {len(raw)}")
    print(f"Thumb pointer refs: {len(thumb)}")
    for pointer in thumb:
        print(f"  0x{pointer:08X}")

    print()
    print("reachable direct calls:")
    direct_calls = []
    for insn in graph.ordered():
        if not is_call(insn):
            continue
        target = direct_branch_target(insn)
        direct_calls.append((insn.address, target))
    if not direct_calls:
        print("  none")
    for site, target in direct_calls:
        print(
            f"  0x{site:08X} -> "
            f"{f'0x{target:08X}' if target is not None else 'indirect'}"
        )

    print()
    print("reachable literals:")
    literals = []
    for insn in graph.ordered():
        resolved = ldr_literal_value(image, insn)
        if resolved is None:
            continue
        literal_address, value = resolved
        literals.append((insn.address, literal_address, value))
    if not literals:
        print("  none")
    for site, literal, value in literals:
        classification = classify_value(image, value)
        text = ascii_at_runtime(image, value)
        suffix = f', ASCII="{text}"' if text is not None else ""
        print(
            f"  insn=0x{site:08X} literal=0x{literal:08X} "
            f"value=0x{value:08X} [{classification}{suffix}]"
        )

    print()
    print("publication sites in function:")
    publish_sites = [
        insn.address
        for insn in graph.ordered()
        if is_call(insn) and direct_branch_target(insn) == PUBLISH_TARGET
    ]
    if not publish_sites:
        print("  none")
    for site in publish_sites:
        print(f"  0x{site:08X}")
        print_context(image, site, before=0x20, after=0x20)

    print()
    print(".33 heuristic counterparts:")
    if comparison is None:
        print("  comparison image unavailable")
    else:
        for score, candidate, count in counterpart_candidates(
            image,
            graph,
            comparison,
        ):
            level = (
                "strong heuristic"
                if score >= 0.85
                else "moderate heuristic"
                if score >= 0.65
                else "weak heuristic"
            )
            print(
                f"  score={score:.3f} start=0x{candidate:08X} "
                f"reachable_instructions={count} [{level}]"
            )
    print()


def report_six_byte_helpers(image: Image) -> None:
    print("=" * 110)
    print("SIX-BYTE COMPARE/COPY CALL SITES")

    for label, target in SIX_BYTE_HELPERS:
        print()
        print(f"{label}: 0x{target:08X}")
        callers = scan_direct_callers(image, target)
        print(f"all direct callers: {len(callers)}")
        for caller in callers:
            r2 = local_register_provenance(image, caller, ARM_REG_R2)
            if "0x6 " not in r2 and "0x6 at" not in r2:
                continue
            parent = probable_enclosing_start(image, caller)
            print(
                f"  six-byte call=0x{caller:08X} "
                f"parent={f'0x{parent:08X}' if parent is not None else 'unresolved'}"
            )
            print(f"    r0: {local_register_provenance(image, caller, ARM_REG_R0)}")
            print(f"    r1: {local_register_provenance(image, caller, ARM_REG_R1)}")
            print(f"    r2: {r2}")
            print_context(image, caller, before=0x18, after=0x20)
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Trace source/category-1 D0 producers, parents, RAM objects, "
            "six-byte data operations, and heuristic .33 counterparts."
        )
    )
    parser.add_argument(
        "firmware38",
        nargs="?",
        type=Path,
        default=Path(
            "release/ry02-3.00.38-faster-raw-r1/"
            "RY02_3.00.38_250403.bin"
        ),
    )
    parser.add_argument(
        "--firmware33",
        type=Path,
        default=Path("vendor/RY02_3.00.33_250117.bin"),
    )
    parser.add_argument("--no-firmware33", action="store_true")
    parser.add_argument("--base", type=parse_int, default=DEFAULT_BASE)
    parser.add_argument("--header-size", type=parse_int, default=HEADER_SIZE)
    parser.add_argument("--code-start", type=parse_int, default=DEFAULT_CODE_START)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.firmware38.is_file():
        raise SystemExit(f"firmware not found: {args.firmware38}")

    image38 = Image.load(
        args.firmware38,
        base=args.base,
        code_start=args.code_start,
        header_size=args.header_size,
    )

    image33 = None
    if not args.no_firmware33:
        if args.firmware33.is_file():
            image33 = Image.load(
                args.firmware33,
                base=args.base,
                code_start=args.code_start,
                header_size=args.header_size,
            )
        else:
            print(
                f"warning: comparison firmware not found: {args.firmware33}",
                file=sys.stderr,
            )

    print("RY02 SOURCE-1 D0 SUBSYSTEM PROVENANCE REPORT")
    print(f"tool revision: {TOOL_REVISION}")
    print()
    print(f"firmware38: {image38.path}")
    print(f"firmware38 SHA256: {image38.sha256()}")
    print(f"firmware38 payload length: 0x{len(image38.payload):X}")
    if image33 is not None:
        print(f"firmware33: {image33.path}")
        print(f"firmware33 SHA256: {image33.sha256()}")
        print(f"firmware33 payload length: 0x{len(image33.payload):X}")
    print(f"runtime base: 0x{args.base:08X}")
    print(f"Python: {platform.python_version()}")
    print(f"Capstone: {capstone.__version__}")
    print()
    print("Interpretation constraints:")
    print("  - only CFG-reachable instructions are assigned to functions")
    print("  - whole-payload literal scans skip undecodable halfword offsets")
    print("  - r0-r3 provenance stops at intervening BL/BLX calls")
    print("  - six-byte data shape does not prove MAC/BLE-address semantics")
    print("  - RAM-object names are descriptive candidates only")
    print("  - .33 counterpart scores are heuristic")
    print("  - D0 remains an event-class label, not a vendor message name")
    print()

    print("# FUNCTION PROVENANCE")
    for label, address in FUNCTION_TARGETS:
        report_function(image38, label, address, image33)

    print("# RAM-OBJECT PROVENANCE")
    for label, value in RAM_TARGETS:
        report_ram_target(image38, label, value)

    report_six_byte_helpers(image38)

    print("=" * 110)
    print("SUMMARY")
    for label, address in FUNCTION_TARGETS:
        graph = build_function_cfg(image38, address)
        print(
            f"function 0x{address:08X} {label}: "
            f"reachable={len(graph.instructions)} "
            f"callers={len(scan_direct_callers(image38, address))} "
            f"thumb_refs={len(scan_raw_references(image38, address | 1))} "
            f"tails={len(graph.external_tail_branches)}"
        )
    for label, value in RAM_TARGETS:
        print(
            f"RAM 0x{value:08X} {label}: "
            f"raw={len(scan_raw_references(image38, value))} "
            f"literal_loads={len(scan_literal_loads(image38, value))}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
