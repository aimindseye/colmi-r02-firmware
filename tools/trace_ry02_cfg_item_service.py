#!/usr/bin/env python3
"""
Trace the RY02 configuration-item service around the exact binary string
"cfg_add_item".

This is an offline static-analysis tool. It does not modify firmware or interact
with the ring.

Primary goals:
  * promote 0x00838914 from a generic masked-record core to cfg_add_item;
  * decode ADR targets correctly and recover nearby log/diagnostic strings;
  * inventory all cfg_* strings in the application payload and their references;
  * trace the cfg service family:
        0x008385F8  type-0x33/len-6 exact-mask setter wrapper
        0x008386AC  config blob validity check candidate
        0x008386FC  config blob commit/replace candidate
        0x00838914  cfg_add_item
        0x00838AFC  cfg_find_item candidate
        0x00839CA4  type-0x33/len-6 exact-mask getter wrapper
        0x00837198  config integrity/token helper candidate
  * inventory references to config blob base 0x00801400 and magic 0x8721BEE2;
  * compare functions with firmware .33;
  * perform exact, low-noise source searches for cfg identifiers and magic values.

Interpretation boundary:
  field type 0x33 remains vendor-defined. The service name and record mechanics
  do not prove BLE-address, MAC-address, bonding, whitelist, or resolving-list
  semantics.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
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

CFG_BLOB_BASE = 0x00801400
CFG_MAGIC = 0x8721BEE2

CALLER_SAVED = {ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3}

TARGETS: tuple[tuple[str, int], ...] = (
    ("type33_len6_exact_mask_setter", 0x008385F8),
    ("cfg_blob_valid_candidate", 0x008386AC),
    ("cfg_blob_commit_replace_candidate", 0x008386FC),
    ("cfg_add_item", 0x00838914),
    ("cfg_find_item_candidate", 0x00838AFC),
    ("type33_len6_exact_mask_getter", 0x00839CA4),
    ("cfg_integrity_token_candidate", 0x00837198),
)

DEFAULT_SOURCE_ROOTS = (
    Path("reference/bluex-sdk3-v3.3.8-20250117"),
    Path("reference/bluex-sdk3-demo"),
)

EXACT_SOURCE_PATTERNS = (
    "cfg_add_item",
    "cfg_find_item",
    "cfg_get_item",
    "cfg_del_item",
    "cfg_delete_item",
    "cfg_update_item",
    "cfg_replace",
    "cfg_commit",
    "8721BEE2",
    "0x8721BEE2",
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
    external_tails: list[tuple[int, int]]
    decode_failures: list[int]

    def ordered(self) -> list:
        return [self.instructions[a] for a in sorted(self.instructions)]


def parse_int(value: str) -> int:
    return int(value, 0)


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


def build_cfg(
    image: Image,
    start_address: int,
    *,
    max_forward: int = 0x1400,
    max_backward: int = 0x80,
    max_instructions: int = 2400,
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
        external_tails=sorted(set(tails)),
        decode_failures=sorted(set(failures)),
    )


def ldr_literal_value(image: Image, insn) -> tuple[int, int] | None:
    if insn is None:
        return None
    if not insn.mnemonic.startswith("ldr") or len(insn.operands) < 2:
        return None

    op = insn.operands[1]
    if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC:
        return None

    literal_address = ((insn.address + 4) & ~3) + op.mem.disp
    offset = image.offset_for_runtime(literal_address)

    if not 0 <= offset <= len(image.payload) - 4:
        return None

    value = int.from_bytes(image.payload[offset : offset + 4], "little")
    return literal_address, value


def adr_runtime_target(insn) -> int | None:
    """
    Capstone 5 reports Thumb ADR's second operand as a displacement in this
    firmware. Resolve it against aligned PC. Preserve already-absolute values.
    """
    if insn is None or insn.mnemonic not in {"adr", "adr.w"}:
        return None
    if len(insn.operands) < 2 or insn.operands[1].type != ARM_OP_IMM:
        return None

    value = insn.operands[1].imm & 0xFFFFFFFF
    if value >= 0x00100000:
        return value

    return (((insn.address + 4) & ~3) + value) & 0xFFFFFFFF


def ascii_at(
    image: Image,
    address: int,
    *,
    minimum: int = 4,
    maximum: int = 256,
) -> str | None:
    if not image.in_payload_runtime(address):
        return None

    offset = image.offset_for_runtime(address)
    chars: list[str] = []

    for byte in image.payload[offset : offset + maximum]:
        if byte == 0:
            break
        char = chr(byte)
        if char not in string.printable or char in "\r\n\t\x0b\x0c":
            return None
        chars.append(char)

    result = "".join(chars)
    return result if len(result) >= minimum else None


def all_ascii_strings(
    image: Image,
    *,
    minimum: int = 4,
) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    start: int | None = None

    for offset, byte in enumerate(image.payload + b"\x00"):
        printable = 0x20 <= byte <= 0x7E

        if printable and start is None:
            start = offset
            continue

        if printable:
            continue

        if start is not None and offset - start >= minimum:
            text = image.payload[start:offset].decode("ascii", errors="ignore")
            result.append((image.runtime_for_offset(start), text))

        start = None

    return result


def scan_direct_callers(image: Image, target: int) -> list[int]:
    result = []
    for offset in range(image.code_start, len(image.payload) - 4, 2):
        insn = image.decode_one(offset)
        if is_call(insn) and direct_branch_target(insn) == target:
            result.append(image.runtime_for_offset(offset))
    return result


def scan_raw_refs(image: Image, value: int) -> list[int]:
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


def probable_enclosing_start(
    image: Image,
    address: int,
    *,
    window: int = 0x300,
) -> int | None:
    offset = image.offset_for_runtime(address)
    lower = max(image.code_start, offset - window)
    candidates = []

    for candidate_offset in range(lower, offset, 2):
        insn = image.decode_one(candidate_offset)
        if not is_probable_function_start(insn):
            continue

        candidate = image.runtime_for_offset(candidate_offset)
        graph = build_cfg(
            image,
            candidate,
            max_forward=max(0x300, address - candidate + 0x80),
        )

        if address in graph.instructions:
            candidates.append(candidate)

    return candidates[-1] if candidates else None


def contiguous_predecessors(
    image: Image,
    address: int,
    *,
    window: int = 0x90,
) -> list:
    target_offset = image.offset_for_runtime(address)
    lower = max(image.code_start, target_offset - window)
    best = []

    for start in range(lower, target_offset, 2):
        sequence = []
        current = start
        valid = True

        while current < target_offset:
            insn = image.decode_one(current)
            if insn is None:
                valid = False
                break
            sequence.append(insn)
            current += insn.size

        if valid and current == target_offset and len(sequence) > len(best):
            best = sequence

    return best


def local_register_provenance(
    image: Image,
    address: int,
    register: int,
) -> str:
    for insn in reversed(contiguous_predecessors(image, address)):
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
    annotations = []

    target = direct_branch_target(insn)
    if target is None:
        target = cb_target(insn)
    if target is not None:
        annotations.append(f"target=0x{target:08X}")

    literal = ldr_literal_value(image, insn)
    if literal is not None:
        literal_address, value = literal
        annotations.append(
            f"literal=0x{literal_address:08X}->0x{value:08X}"
        )

    adr = adr_runtime_target(insn)
    if adr is not None:
        annotations.append(f"adr=0x{adr:08X}")
        text = ascii_at(image, adr)
        if text is not None:
            annotations.append(f"text={text!r}")

    suffix = f" ; {', '.join(annotations)}" if annotations else ""

    return (
        f"{marker} payload+0x{image.offset_for_runtime(insn.address):05X} "
        f"runtime=0x{insn.address:08X} "
        f"{insn.bytes.hex(' '):<13} "
        f"{insn.mnemonic:<9} {insn.op_str}{suffix}"
    )


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

    literal = ldr_literal_value(image, insn)
    if literal is not None:
        _, value = literal
        if value == CFG_BLOB_BASE:
            parts.append("LIT_CFG_BASE")
        elif value == CFG_MAGIC:
            parts.append("LIT_CFG_MAGIC")
        elif image.in_payload_runtime(value):
            parts.append("LIT_IMAGE")
        elif 0x00200000 <= value < 0x00220000:
            parts.append("LIT_RAM")
        else:
            parts.append("LIT_OTHER")
        return ":".join(parts)

    for op in insn.operands:
        if op.type == ARM_OP_REG:
            parts.append(f"R{op.reg}")
        elif op.type == ARM_OP_IMM:
            value = op.imm & 0xFFFFFFFF
            parts.append(f"I{value:X}" if value <= 0xFF else "I_BIG")
        elif op.type == ARM_OP_MEM:
            if op.mem.base == ARM_REG_SP:
                parts.append("MEM_SP")
            elif op.mem.base == ARM_REG_PC:
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
    image: Image,
    graph: FunctionGraph,
    comparison: Image,
    *,
    top_n: int = 3,
) -> list[tuple[float, int, int]]:
    source_tokens = [
        normalized_token(insn, image)
        for insn in graph.ordered()[:160]
    ]
    if len(source_tokens) < 3:
        return []

    candidates = []
    for start in probable_function_starts(comparison):
        graph2 = build_cfg(comparison, start)
        tokens = [
            normalized_token(insn, comparison)
            for insn in graph2.ordered()[:160]
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


def function_strings(image: Image, graph: FunctionGraph) -> list[tuple[int, str, int, str]]:
    found = []
    seen = set()

    for insn in graph.ordered():
        candidates = []

        adr = adr_runtime_target(insn)
        if adr is not None:
            candidates.append(("ADR", adr))

        literal = ldr_literal_value(image, insn)
        if literal is not None:
            _, value = literal
            if image.in_payload_runtime(value):
                candidates.append(("LDR", value))

        for source, address in candidates:
            text = ascii_at(image, address)
            if text is None:
                continue
            key = (source, address, text)
            if key in seen:
                continue
            seen.add(key)
            found.append((insn.address, source, address, text))

    return found


def report_function(
    image: Image,
    label: str,
    address: int,
    comparison: Image | None,
) -> None:
    graph = build_cfg(image, address)

    print("=" * 116)
    print(f"function: {label}")
    print(f"start: 0x{address:08X}")
    print(f"reachable instructions: {len(graph.instructions)}")
    print(f"returns: {len(graph.returns)}")
    for value in graph.returns:
        print(f"  0x{value:08X}")
    print(f"external tail branches: {len(graph.external_tails)}")
    for site, target in graph.external_tails:
        print(f"  0x{site:08X} -> 0x{target:08X}")

    callers = scan_direct_callers(image, address)
    print(f"direct callers: {len(callers)}")
    for caller in callers:
        parent = probable_enclosing_start(image, caller)
        print(
            f"  call=0x{caller:08X} "
            f"parent={f'0x{parent:08X}' if parent is not None else 'unresolved'}"
        )
        for reg, name in (
            (ARM_REG_R0, "r0"),
            (ARM_REG_R1, "r1"),
            (ARM_REG_R2, "r2"),
            (ARM_REG_R3, "r3"),
        ):
            print(f"    {name}: {local_register_provenance(image, caller, reg)}")

    print(f"raw exact refs: {len(scan_raw_refs(image, address))}")
    thumb_refs = scan_raw_refs(image, address | 1)
    print(f"Thumb pointer refs: {len(thumb_refs)}")
    for ref in thumb_refs:
        print(f"  0x{ref:08X}")

    print("reachable strings:")
    strings_found = function_strings(image, graph)
    if not strings_found:
        print("  none")
    for site, source, string_address, value in strings_found:
        print(
            f"  site=0x{site:08X} source={source} "
            f"address=0x{string_address:08X} text={value!r}"
        )

    print("reachable calls:")
    for insn in graph.ordered():
        if is_call(insn):
            target = direct_branch_target(insn)
            print(
                f"  0x{insn.address:08X} -> "
                f"{f'0x{target:08X}' if target is not None else 'indirect'}"
            )

    print("reachable CFG:")
    for insn in graph.ordered():
        print(format_instruction(image, insn))

    print(".33 heuristic counterparts:")
    if comparison is None:
        print("  comparison image unavailable")
    else:
        for score, candidate, count in counterpart_candidates(
            image,
            graph,
            comparison,
        ):
            classification = (
                "strong heuristic"
                if score >= 0.85
                else "moderate heuristic"
                if score >= 0.65
                else "weak heuristic"
            )
            print(
                f"  score={score:.3f} start=0x{candidate:08X} "
                f"reachable={count} [{classification}]"
            )
    print()


def report_cfg_strings(image: Image) -> None:
    print("=" * 116)
    print("CFG STRING INVENTORY")

    strings_found = [
        (address, value)
        for address, value in all_ascii_strings(image)
        if re.search(r"(?i)(^|[^a-z0-9])cfg[_a-z0-9]*", value)
        or re.search(r"(?i)config(?:uration)?[_ a-z0-9]*", value)
    ]

    print(f"matching strings: {len(strings_found)}")
    for address, value in strings_found:
        print(f"  0x{address:08X}: {value!r}")

        raw = scan_raw_refs(image, address)
        if raw:
            print(f"    raw pointer occurrences: {len(raw)}")
            for ref in raw:
                print(f"      0x{ref:08X}")

        ldr_sites = []
        adr_sites = []

        for offset in range(image.code_start, len(image.payload) - 4, 2):
            insn = image.decode_one(offset)
            literal = ldr_literal_value(image, insn)
            if literal is not None and literal[1] == address:
                ldr_sites.append(insn.address)

            if adr_runtime_target(insn) == address:
                adr_sites.append(insn.address)

        print(f"    LDR references: {len(ldr_sites)}")
        for site in ldr_sites:
            parent = probable_enclosing_start(image, site)
            print(
                f"      site=0x{site:08X} "
                f"parent={f'0x{parent:08X}' if parent is not None else 'unresolved'}"
            )

        print(f"    ADR references: {len(adr_sites)}")
        for site in adr_sites:
            parent = probable_enclosing_start(image, site)
            print(
                f"      site=0x{site:08X} "
                f"parent={f'0x{parent:08X}' if parent is not None else 'unresolved'}"
            )
    print()


def report_constant_refs(image: Image, name: str, value: int) -> None:
    print("=" * 116)
    print(f"{name}: 0x{value:08X}")

    raw = scan_raw_refs(image, value)
    print(f"raw occurrences: {len(raw)}")
    for address in raw:
        print(f"  0x{address:08X}")

    loads = []
    for offset in range(image.code_start, len(image.payload) - 4, 2):
        insn = image.decode_one(offset)
        literal = ldr_literal_value(image, insn)
        if literal is not None and literal[1] == value:
            loads.append((insn.address, literal[0]))

    print(f"literal-load references: {len(loads)}")
    for site, literal_address in loads:
        parent = probable_enclosing_start(image, site)
        print(
            f"  load=0x{site:08X} literal=0x{literal_address:08X} "
            f"parent={f'0x{parent:08X}' if parent is not None else 'unresolved'}"
        )
    print()


def is_text_file(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        if path.stat().st_size > 2_000_000:
            return False
    except OSError:
        return False

    return path.suffix.lower() in {
        ".c", ".h", ".cpp", ".hpp", ".s", ".asm",
        ".txt", ".md", ".rst", ".py", ".json", ".ini",
        ".cfg", ".mk", ".cmake", ".yaml", ".yml",
    } or path.name in {"Makefile", "CMakeLists.txt"}


def report_exact_source_search(roots: Sequence[Path]) -> None:
    print("=" * 116)
    print("EXACT SOURCE SEARCH")

    existing = [root for root in roots if root.exists()]
    print(f"source roots present: {len(existing)}")
    for root in existing:
        print(f"  {root}")

    matches = []
    files_scanned = 0

    for root in existing:
        for path in root.rglob("*"):
            if not is_text_file(path):
                continue
            files_scanned += 1

            try:
                lines = path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                ).splitlines()
            except OSError:
                continue

            for line_number, line in enumerate(lines, start=1):
                lowered = line.lower()
                for pattern in EXACT_SOURCE_PATTERNS:
                    if pattern.lower() in lowered:
                        matches.append(
                            (path, line_number, pattern, line.strip())
                        )
                        break

    print(f"text files scanned: {files_scanned}")
    print(f"exact matches: {len(matches)}")
    for path, line_number, pattern, line in matches:
        print(
            f"  {path}:{line_number}: "
            f"pattern={pattern!r}: {line}"
        )
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Trace the RY02 cfg_add_item service, recover cfg strings with "
            "correct ADR resolution, and search exact SDK identifiers."
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
    )
    parser.add_argument("--no-source-search", action="store_true")
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

    print("RY02 CONFIGURATION-ITEM SERVICE REPORT")
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
    print(f"config blob base candidate: 0x{CFG_BLOB_BASE:08X}")
    print(f"config integrity magic candidate: 0x{CFG_MAGIC:08X}")
    print(f"Python: {platform.python_version()}")
    print(f"Capstone: {capstone.__version__}")
    print()
    print("Accepted before this gate:")
    print("  0x00838914 references exact string 'cfg_add_item'")
    print("  record descriptor: type, length, value pointer, mask pointer")
    print("  serialized item: type[2], length[1], value[N], mask[N]")
    print("  serialized size: 3 + 2*N")
    print("  type 0x33 uses length 6 and all-FF exact mask")
    print()
    print("Interpretation constraints:")
    print("  field type 0x33 remains vendor-defined")
    print("  cfg service membership does not prove BLE/MAC semantics")
    print("  corrected ADR decoding is required before accepting inline strings")
    print("  .33 counterpart scores remain heuristic")
    print()

    print("# CONFIGURATION SERVICE FUNCTIONS")
    for label, address in TARGETS:
        report_function(image38, label, address, image33)

    print("# CONFIGURATION STRINGS")
    report_cfg_strings(image38)

    print("# CONFIGURATION CONSTANTS")
    report_constant_refs(
        image38,
        "CONFIG BLOB BASE CANDIDATE",
        CFG_BLOB_BASE,
    )
    report_constant_refs(
        image38,
        "CONFIG INTEGRITY MAGIC CANDIDATE",
        CFG_MAGIC,
    )

    if not args.no_source_search:
        roots = (
            tuple(args.source_root)
            if args.source_root
            else DEFAULT_SOURCE_ROOTS
        )
        report_exact_source_search(roots)

    print("=" * 116)
    print("SUMMARY")
    for label, address in TARGETS:
        graph = build_cfg(image38, address)
        strings_found = function_strings(image38, graph)
        print(
            f"function 0x{address:08X} {label}: "
            f"reachable={len(graph.instructions)} "
            f"callers={len(scan_direct_callers(image38, address))} "
            f"thumb_refs={len(scan_raw_refs(image38, address | 1))} "
            f"strings={len(strings_found)}"
        )

    cfg_strings = [
        value
        for _, value in all_ascii_strings(image38)
        if re.search(r"(?i)(^|[^a-z0-9])cfg[_a-z0-9]*", value)
        or re.search(r"(?i)config(?:uration)?[_ a-z0-9]*", value)
    ]
    print(f"cfg/config strings in payload: {len(cfg_strings)}")
    print(f"config blob raw refs: {len(scan_raw_refs(image38, CFG_BLOB_BASE))}")
    print(f"config magic raw refs: {len(scan_raw_refs(image38, CFG_MAGIC))}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
