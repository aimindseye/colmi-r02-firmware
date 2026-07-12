#!/usr/bin/env python3
"""
Trace the RY02 masked-record service used by the six-byte source-1/D0 flow.

The already demonstrated record shape is:

    descriptor:
        +0x00  uint16 field_type
        +0x02  uint8  length
        +0x04  pointer to value[length]
        +0x08  pointer to mask[length]

    serialized entry:
        +0x00  uint16 field_type
        +0x02  uint8  length
        +0x03  value[length]
        +0x03+length  mask[length]

    serialized size = 3 + 2*length

This tool focuses on:
  * 0x008385F8 type-0x33/length-6 setter wrapper;
  * 0x00839CA4 type-0x33/length-6 getter wrapper;
  * 0x008386AC service/context validation candidate;
  * 0x00838914 record install/update core candidate;
  * 0x00838AFC masked-record finder/parser;
  * all direct callers and pointer references;
  * ADR/PC-relative strings used by the service family;
  * record field-type and length constants near core call sites;
  * cross-version counterpart candidates;
  * optional keyword searches in local SDK/source trees.

It does not claim that field type 0x33 is a BLE address, MAC address, bonding
identity, or any other vendor-level field without corroborating evidence.
"""

from __future__ import annotations

import argparse
import collections
import difflib
import hashlib
import os
import platform
import re
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


TOOL_REVISION = "r1"
HEADER_SIZE = 0x50
DEFAULT_BASE = 0x00824000
DEFAULT_CODE_START = 0x400

SERVICE_CONTEXT = 0x00801400
FIELD_TYPE_33 = 0x33
FIELD_LENGTH_6 = 6

CALLER_SAVED = {ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3}

FUNCTION_TARGETS: tuple[tuple[str, int], ...] = (
    ("type33_len6_exact_mask_setter_wrapper", 0x008385F8),
    ("masked_record_service_validate_candidate", 0x008386AC),
    ("masked_record_install_update_core_candidate", 0x00838914),
    ("masked_record_find_candidate", 0x00838AFC),
    ("type33_len6_exact_mask_getter_wrapper", 0x00839CA4),
)

CORE_CALL_TARGETS = {
    0x008386AC,
    0x00838914,
    0x00838AFC,
}

DEFAULT_SOURCE_ROOTS = (
    Path("reference/bluex-sdk3-v3.3.8-20250117"),
    Path("reference/bluex-sdk3-demo"),
)

SOURCE_KEYWORDS = (
    "mask",
    "masked",
    "filter",
    "field_type",
    "field type",
    "value_mask",
    "addr_mask",
    "bd_addr",
    "device address",
    "whitelist",
    "white list",
    "resolving list",
    "0x33",
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
                f"{path}: file too small for 0x{header_size:X}-byte header"
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
        operand = insn.operands[0]
        return operand.type == ARM_OP_REG and operand.reg == ARM_REG_LR
    return insn.mnemonic == "pop" and "pc" in insn.op_str


def is_probable_function_start(insn) -> bool:
    return insn is not None and insn.mnemonic == "push" and "lr" in insn.op_str


def build_function_cfg(
    image: Image,
    start_address: int,
    *,
    max_forward: int = 0x1200,
    max_backward: int = 0x80,
    max_instructions: int = 2200,
) -> FunctionGraph:
    lower = max(image.base + image.code_start, start_address - max_backward)
    upper = min(image.base + len(image.payload), start_address + max_forward)

    worklist = [start_address]
    visited_blocks: set[int] = set()
    instructions: dict[int, object] = {}
    returns: list[int] = []
    tails: list[tuple[int, int]] = []
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
                if target is not None and lower <= target < upper:
                    worklist.append(target)
                elif target is not None:
                    tails.append((current, target))
                break

            if is_conditional_branch(insn):
                target = cb_target(insn)
                if target is None:
                    target = direct_branch_target(insn)
                if target is not None:
                    if lower <= target < upper:
                        worklist.append(target)
                    else:
                        tails.append((current, target))
                current = next_address
                continue

            if insn.mnemonic == "bx":
                break

            current = next_address

    return FunctionGraph(
        start=start_address,
        instructions=instructions,
        returns=sorted(set(returns)),
        external_tail_branches=sorted(set(tails)),
        decode_failures=sorted(set(failures)),
    )


def scan_direct_callers(image: Image, target: int) -> list[int]:
    result = []
    for offset in range(image.code_start, len(image.payload) - 4, 2):
        insn = image.decode_one(offset)
        if is_call(insn) and direct_branch_target(insn) == target:
            result.append(image.runtime_for_offset(offset))
    return result


def scan_raw_references(image: Image, value: int) -> list[int]:
    needle = value.to_bytes(4, "little")
    result = []
    start = 0
    while True:
        offset = image.payload.find(needle, start)
        if offset < 0:
            break
        result.append(image.runtime_for_offset(offset))
        start = offset + 1
    return result


def ldr_literal_value(image: Image, insn) -> tuple[int, int] | None:
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


def adr_target(insn) -> int | None:
    if insn is None or insn.mnemonic not in {"adr", "adr.w"}:
        return None
    if len(insn.operands) < 2:
        return None
    source = insn.operands[1]
    if source.type != ARM_OP_IMM:
        return None
    return source.imm & 0xFFFFFFFF


def ascii_at_runtime(
    image: Image,
    address: int,
    *,
    min_length: int = 4,
    max_length: int = 240,
) -> str | None:
    if not image.in_payload_runtime(address):
        return None

    offset = image.offset_for_runtime(address)
    result: list[str] = []

    for byte in image.payload[offset : offset + max_length]:
        if byte == 0:
            break
        char = chr(byte)
        if char not in string.printable or char in "\r\n\t\x0b\x0c":
            return None
        result.append(char)

    text = "".join(result)
    return text if len(text) >= min_length else None


def probable_enclosing_start(
    image: Image,
    address: int,
    *,
    window: int = 0x300,
) -> int | None:
    address_offset = image.offset_for_runtime(address)
    lower = max(image.code_start, address_offset - window)
    candidates = []

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
    window: int = 0x90,
) -> list:
    address_offset = image.offset_for_runtime(address)
    lower = max(image.code_start, address_offset - window)
    best = []

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


def format_instruction(image: Image, insn, marker: str = "  ") -> str:
    target = direct_branch_target(insn)
    if target is None:
        target = cb_target(insn)

    suffixes = []
    if target is not None:
        suffixes.append(f"target=0x{target:08X}")

    resolved = ldr_literal_value(image, insn)
    if resolved is not None:
        literal, value = resolved
        suffixes.append(f"literal=0x{literal:08X}->0x{value:08X}")

    adr = adr_target(insn)
    if adr is not None:
        suffixes.append(f"adr=0x{adr:08X}")

    suffix = f" ; {', '.join(suffixes)}" if suffixes else ""

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
    before: int = 0x38,
    after: int = 0x58,
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

        if insn.address >= center and (
            is_return(insn) or is_unconditional_branch(insn)
        ):
            break


def normalized_token(insn, image: Image) -> str:
    parts = [insn.mnemonic]

    target = direct_branch_target(insn)
    if target is not None:
        parts.append(
            "BR_LOCAL"
            if image.in_payload_runtime(target)
            else f"BR_LOW_{target & 0xFFF:X}"
        )
        return ":".join(parts)

    resolved = ldr_literal_value(image, insn)
    if resolved is not None:
        _, value = resolved
        if value == SERVICE_CONTEXT:
            parts.append("LIT_SERVICE_CONTEXT")
        elif image.in_payload_runtime(value):
            parts.append("LIT_IMAGE")
        elif 0x00200000 <= value < 0x00220000:
            parts.append("LIT_RAM")
        else:
            parts.append("LIT_OTHER")
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
        for insn in graph.ordered()[:128]
    ]
    if len(source_tokens) < 3:
        return []

    candidates = []
    for start in probable_function_starts(comparison_image):
        graph2 = build_function_cfg(comparison_image, start)
        tokens = [
            normalized_token(insn, comparison_image)
            for insn in graph2.ordered()[:128]
        ]
        if len(tokens) < 3:
            continue

        score = difflib.SequenceMatcher(
            a=source_tokens,
            b=tokens,
            autojunk=False,
        ).ratio()
        candidates.append((score, start, len(graph2.instructions)))

    candidates.sort(reverse=True)
    return candidates[:top_n]


def report_strings(image: Image, graph: FunctionGraph) -> None:
    seen: set[tuple[int, str]] = set()
    strings_found = []

    for insn in graph.ordered():
        targets = []

        adr = adr_target(insn)
        if adr is not None:
            targets.append(("ADR", adr))

        resolved = ldr_literal_value(image, insn)
        if resolved is not None:
            _, value = resolved
            if image.in_payload_runtime(value):
                targets.append(("LDR", value))

        for source, address in targets:
            text = ascii_at_runtime(image, address)
            if text is None:
                continue
            key = (address, text)
            if key in seen:
                continue
            seen.add(key)
            strings_found.append((insn.address, source, address, text))

    print("reachable strings:")
    if not strings_found:
        print("  none")
    for site, source, address, text in strings_found:
        print(
            f"  site=0x{site:08X} source={source} "
            f"address=0x{address:08X} text={text!r}"
        )


def report_function(
    image: Image,
    label: str,
    address: int,
    comparison: Image | None,
) -> None:
    graph = build_function_cfg(image, address)

    print("=" * 112)
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

    exact = scan_raw_references(image, address)
    thumb = scan_raw_references(image, address | 1)
    print(f"raw exact refs: {len(exact)}")
    print(f"Thumb pointer refs: {len(thumb)}")
    for ref in thumb:
        print(f"  0x{ref:08X}")

    print("reachable calls:")
    for insn in graph.ordered():
        if is_call(insn):
            target = direct_branch_target(insn)
            print(
                f"  0x{insn.address:08X} -> "
                f"{f'0x{target:08X}' if target is not None else 'indirect'}"
            )

    report_strings(image, graph)

    print("reachable CFG:")
    for insn in graph.ordered():
        marker = (
            ">>"
            if is_call(insn) and direct_branch_target(insn) in CORE_CALL_TARGETS
            else "  "
        )
        print(format_instruction(image, insn, marker))

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
                f"reachable={count} [{level}]"
            )
    print()


def scan_immediate_occurrences(
    image: Image,
    value: int,
) -> list[int]:
    result = []
    for offset in range(image.code_start, len(image.payload) - 4, 2):
        insn = image.decode_one(offset)
        if insn is None:
            continue
        for operand in insn.operands:
            if operand.type == ARM_OP_IMM and (operand.imm & 0xFFFFFFFF) == value:
                result.append(insn.address)
                break
    return result


def report_type33_contexts(image: Image) -> None:
    print("=" * 112)
    print("FIELD TYPE 0x33 IMMEDIATE CONTEXTS")

    sites = scan_immediate_occurrences(image, FIELD_TYPE_33)
    print(f"instruction sites using immediate 0x33: {len(sites)}")

    for site in sites:
        parent = probable_enclosing_start(image, site)
        print()
        print(
            f"site=0x{site:08X} "
            f"parent={f'0x{parent:08X}' if parent is not None else 'unresolved'}"
        )
        print_context(image, site, before=0x28, after=0x44)
    print()


def report_service_context_refs(image: Image) -> None:
    print("=" * 112)
    print(f"SERVICE CONTEXT REFERENCES 0x{SERVICE_CONTEXT:08X}")

    raw = scan_raw_references(image, SERVICE_CONTEXT)
    print(f"raw occurrences: {len(raw)}")
    for address in raw:
        print(f"  0x{address:08X}")

    loads = []
    for offset in range(image.code_start, len(image.payload) - 4, 2):
        insn = image.decode_one(offset)
        resolved = ldr_literal_value(image, insn)
        if resolved is None:
            continue
        literal, value = resolved
        if value == SERVICE_CONTEXT:
            loads.append((insn.address, literal))

    print(f"literal-load references: {len(loads)}")
    for site, literal in loads:
        parent = probable_enclosing_start(image, site)
        print(
            f"  load=0x{site:08X} literal=0x{literal:08X} "
            f"parent={f'0x{parent:08X}' if parent is not None else 'unresolved'}"
        )
    print()


def report_core_callers(image: Image) -> None:
    print("=" * 112)
    print("CORE SERVICE CALLER INVENTORY")

    for label, target in (
        ("validate_candidate", 0x008386AC),
        ("install_update_candidate", 0x00838914),
        ("find_candidate", 0x00838AFC),
    ):
        print()
        print(f"{label}: 0x{target:08X}")
        callers = scan_direct_callers(image, target)
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
                print(
                    f"    {name}: "
                    f"{local_register_provenance(image, caller, register)}"
                )
    print()


def is_text_candidate(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.stat().st_size > 2_000_000:
        return False
    return path.suffix.lower() in {
        ".c", ".h", ".cpp", ".hpp", ".s", ".asm",
        ".py", ".txt", ".md", ".rst", ".ini", ".cfg",
        ".mk", ".cmake", ".json", ".yaml", ".yml",
    } or path.name in {"Makefile", "CMakeLists.txt"}


def report_source_search(roots: Sequence[Path]) -> None:
    print("=" * 112)
    print("LOCAL SOURCE KEYWORD SEARCH")

    existing = [root for root in roots if root.exists()]
    if not existing:
        print("no source roots found")
        return

    pattern = re.compile(
        "|".join(re.escape(keyword) for keyword in SOURCE_KEYWORDS),
        re.IGNORECASE,
    )

    matches = []
    scanned = 0

    for root in existing:
        for path in root.rglob("*"):
            if not is_text_candidate(path):
                continue
            scanned += 1
            try:
                lines = path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                ).splitlines()
            except OSError:
                continue

            for line_number, line in enumerate(lines, start=1):
                if not pattern.search(line):
                    continue
                matches.append((path, line_number, line.strip()))

    print(f"source roots: {len(existing)}")
    for root in existing:
        print(f"  {root}")
    print(f"text files scanned: {scanned}")
    print(f"keyword matches: {len(matches)}")

    for path, line_number, line in matches[:500]:
        print(f"  {path}:{line_number}: {line}")

    if len(matches) > 500:
        print(f"  ... truncated {len(matches) - 500} additional matches")
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Trace the RY02 type-0x33 masked-record setter/getter, "
            "service core, strings, caller family, and source matches."
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
    parser.add_argument(
        "--source-root",
        action="append",
        type=Path,
        default=[],
        help=(
            "source tree to search for mask/filter/address terminology; "
            "may be repeated"
        ),
    )
    parser.add_argument(
        "--no-source-search",
        action="store_true",
        help="skip local SDK/source keyword search",
    )
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

    print("RY02 MASKED-RECORD SERVICE REPORT")
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
    print(f"service context candidate: 0x{SERVICE_CONTEXT:08X}")
    print(f"field type under study: 0x{FIELD_TYPE_33:02X}")
    print(f"field length under study: {FIELD_LENGTH_6}")
    print(f"Python: {platform.python_version()}")
    print(f"Capstone: {capstone.__version__}")
    print()
    print("Accepted structural model:")
    print("  descriptor +0x00: uint16 field_type")
    print("  descriptor +0x02: uint8 length")
    print("  descriptor +0x04: value pointer")
    print("  descriptor +0x08: mask pointer")
    print("  serialized entry: type[2], length[1], value[N], mask[N]")
    print("  serialized size: 3 + 2*N")
    print()
    print("Interpretation constraints:")
    print("  - all-FF mask means exact matching across all six bytes")
    print("  - field type 0x33 vendor meaning remains unresolved")
    print("  - six-byte width does not prove BLE/MAC semantics")
    print("  - only CFG-reachable instructions are assigned to functions")
    print("  - .33 counterpart scores remain heuristic")
    print()

    print("# TARGET FUNCTIONS")
    for label, address in FUNCTION_TARGETS:
        report_function(image38, label, address, image33)

    print("# SERVICE FAMILY")
    report_core_callers(image38)
    report_service_context_refs(image38)
    report_type33_contexts(image38)

    if not args.no_source_search:
        roots = (
            tuple(args.source_root)
            if args.source_root
            else DEFAULT_SOURCE_ROOTS
        )
        report_source_search(roots)

    print("=" * 112)
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

    print(
        f"service context 0x{SERVICE_CONTEXT:08X}: "
        f"raw_refs={len(scan_raw_references(image38, SERVICE_CONTEXT))}"
    )
    print(
        f"immediate field-type 0x{FIELD_TYPE_33:02X}: "
        f"instruction_sites={len(scan_immediate_occurrences(image38, FIELD_TYPE_33))}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
