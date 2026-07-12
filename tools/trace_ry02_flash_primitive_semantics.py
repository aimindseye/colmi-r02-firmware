#!/usr/bin/env python3
"""
Trace the semantic contracts of the four low RY02 flash primitives.

Accepted before this gate:
  * 0x00008600 is called as (destination, length, source) and strongly matches
    the public flash_program(offset, length, buffer) ABI shape.
  * 0x000081A0 is called as (selector, address), with selector values 2 or 4;
    this does not match the public flash_erase(offset, type) wrapper order.
  * 0x0000893C and 0x00008916 bracket erase/program sequences using a saved
    one-byte state.
  * exact address searches over the available SDK ROM/linker/map corpus returned
    zero matches for all four targets.

This tool avoids repeating generic address scans. It instead:
  * resolves literals and local arguments at every target call;
  * prints CFGs for the application wrappers that expose the primitive ABIs;
  * extracts the public erase_t enumeration and flash wrapper bodies;
  * extracts lower-level flash integration declarations and implementations;
  * extracts boot_ram.asm blocks for flash/cache/program/erase operations;
  * searches for source signatures resembling selector/address and saved-state
    begin/end APIs;
  * compares .38 and .33 call families;
  * emits a conservative semantic matrix.

It is offline and does not communicate with the ring or modify firmware.
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import re
import string
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

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

CALLER_SAVED = {ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3}

LOW_TARGETS: tuple[tuple[str, int], ...] = (
    ("flash_operation_begin_candidate", 0x0000893C),
    ("flash_erase_selector_address_candidate", 0x000081A0),
    ("flash_program_abi_match_candidate", 0x00008600),
    ("flash_operation_end_candidate", 0x00008916),
)

WRAPPER_FUNCTIONS: tuple[tuple[str, int], ...] = (
    ("program_and_verify_wrapper_candidate", 0x00824A78),
    ("flash_begin_global_wrapper_candidate", 0x00824CDC),
    ("flash_end_global_wrapper_candidate", 0x00824D0E),
    ("erase_selector2_wrapper_candidate", 0x00824F84),
    ("erase_selector4_wrapper_candidate", 0x00824FA4),
    ("locked_erase_selector2_wrapper_candidate", 0x00827064),
    ("locked_erase_selector4_wrapper_candidate", 0x00827088),
    ("locked_program_wrapper_candidate", 0x008270AC),
    ("locked_program_verify_wrapper_candidate", 0x008270D6),
    ("_cfg_write_to_flash", 0x008386FC),
)

DEFAULT_SOURCE_ROOTS = (
    Path("reference/bluex-sdk3-v3.3.8-20250117"),
    Path("reference/bluex-sdk3-demo"),
)

C_BLOCK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("erase_t enum", re.compile(r"\berase_t\b", re.IGNORECASE)),
    ("flash_program", re.compile(r"\bflash_program\s*\(", re.IGNORECASE)),
    ("flash_erase", re.compile(r"\bflash_erase\s*\(", re.IGNORECASE)),
    (
        "flash_program_operation",
        re.compile(r"\bflash_program_operation(?:_with_4byte_addr)?\s*\(", re.IGNORECASE),
    ),
    (
        "flash_program_operation_start",
        re.compile(r"\bflash_program_operation_start\s*\(", re.IGNORECASE),
    ),
    (
        "flash_erase_operation",
        re.compile(r"\bflash_erase_operation(?:_with_4byte_addr)?\s*\(", re.IGNORECASE),
    ),
    (
        "flash_cache_disable",
        re.compile(r"\bflash_cache_disable\s*\(", re.IGNORECASE),
    ),
    (
        "flash_cache_enable",
        re.compile(r"\bflash_cache_enable\s*\(", re.IGNORECASE),
    ),
    (
        "flash_cache_config",
        re.compile(r"\bflash_cache_config\s*\(", re.IGNORECASE),
    ),
)

ASM_SYMBOL_PATTERNS = (
    "flash_program",
    "flash_erase",
    "flash_program_operation",
    "flash_program_operation_start",
    "flash_erase_operation",
    "flash_cache_disable",
    "flash_cache_enable",
    "flash_cache_config",
)

SIGNATURE_TERMS = (
    "flash",
    "cache",
    "xip",
    "critical",
    "interrupt",
    "irq",
    "lock",
    "unlock",
    "save",
    "restore",
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

    def runtime_for_offset(self, offset: int) -> int:
        return self.base + offset

    def offset_for_runtime(self, address: int) -> int:
        return address - self.base

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
    failures: list[int]

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


def is_return(insn) -> bool:
    if insn is None:
        return False

    if insn.mnemonic == "bx" and insn.operands:
        operand = insn.operands[0]
        return operand.type == ARM_OP_REG and operand.reg == ARM_REG_LR

    return insn.mnemonic == "pop" and "pc" in insn.op_str


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


def build_cfg(
    image: Image,
    start_address: int,
    *,
    max_forward: int = 0x1600,
    max_backward: int = 0x80,
    max_instructions: int = 2600,
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
        failures=sorted(set(failures)),
    )


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
    maximum: int = 192,
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

    text = "".join(chars)
    return text if len(text) >= minimum else None


def scan_direct_callers(image: Image, target: int) -> list[int]:
    result = []

    for offset in range(image.code_start, len(image.payload) - 4, 2):
        insn = image.decode_one(offset)

        if is_call(insn) and direct_branch_target(insn) == target:
            result.append(image.runtime_for_offset(offset))

    return result


def contiguous_predecessors(
    image: Image,
    address: int,
    *,
    window: int = 0xA0,
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

        resolved = ldr_literal_value(image, insn)
        if resolved is not None:
            literal_address, value = resolved
            return (
                f"literal 0x{value:08X} via 0x{literal_address:08X} "
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

    resolved = ldr_literal_value(image, insn)
    if resolved is not None:
        literal_address, value = resolved
        annotations.append(
            f"literal=0x{literal_address:08X}->0x{value:08X}"
        )

    adr = adr_target(insn)
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


def report_call_family(image: Image, label: str) -> None:
    print("=" * 116)
    print(f"{label} LOW PRIMITIVE CALL FAMILIES")
    print(f"image: {image.path}")
    print(f"SHA256: {image.sha256()}")

    for target_label, target in LOW_TARGETS:
        callers = scan_direct_callers(image, target)

        print()
        print(f"{target_label}: 0x{target:08X}")
        print(f"direct callers: {len(callers)}")

        for caller in callers:
            print(f"  call=0x{caller:08X}")

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


def report_wrapper(
    image: Image,
    label: str,
    address: int,
) -> None:
    graph = build_cfg(image, address)

    print("=" * 116)
    print(f"wrapper: {label}")
    print(f"start: 0x{address:08X}")
    print(f"reachable instructions: {len(graph.instructions)}")
    print(f"returns: {len(graph.returns)}")
    print(f"external tails: {len(graph.external_tails)}")
    print(f"decode failures: {len(graph.failures)}")

    low_calls = []

    for insn in graph.ordered():
        target = direct_branch_target(insn)

        if target in {address for _, address in LOW_TARGETS}:
            low_calls.append((insn.address, target))

    print(f"low-target calls: {len(low_calls)}")

    for site, target in low_calls:
        print(f"  0x{site:08X} -> 0x{target:08X}")

        for register, name in (
            (ARM_REG_R0, "r0"),
            (ARM_REG_R1, "r1"),
            (ARM_REG_R2, "r2"),
            (ARM_REG_R3, "r3"),
        ):
            print(
                f"    {name}: "
                f"{local_register_provenance(image, site, register)}"
            )

    print("reachable CFG:")

    for insn in graph.ordered():
        marker = (
            ">>"
            if direct_branch_target(insn)
            in {address for _, address in LOW_TARGETS}
            else "  "
        )
        print(format_instruction(image, insn, marker))

    print()


def text_file(path: Path) -> bool:
    if not path.is_file():
        return False

    try:
        if path.stat().st_size > 8_000_000:
            return False
    except OSError:
        return False

    return path.suffix.lower() in {
        ".c", ".h", ".s", ".asm", ".txt", ".map", ".lst",
        ".sym", ".sct", ".scf", ".ld", ".md", ".rst", ".ini",
        ".cfg", ".mk", ".cmake",
    } or path.name in {"Makefile", "CMakeLists.txt"}


def read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines()
    except OSError:
        return []


def extract_balanced_block(
    lines: Sequence[str],
    index: int,
    *,
    context_before: int = 4,
    max_lines: int = 220,
) -> tuple[int, int]:
    start = max(0, index - context_before)

    # Enum typedefs may begin several lines before the erase_t token.
    for candidate in range(index, max(-1, index - 20), -1):
        if re.search(r"\btypedef\s+enum\b", lines[candidate]):
            start = candidate
            break

    brace_seen = False
    balance = 0
    end = min(len(lines), index + 1)

    for cursor in range(start, min(len(lines), start + max_lines)):
        line = lines[cursor]
        opens = line.count("{")
        closes = line.count("}")

        if opens:
            brace_seen = True

        balance += opens
        balance -= closes
        end = cursor + 1

        if brace_seen and balance <= 0 and cursor >= index:
            break

        if not brace_seen and cursor >= index + 12:
            break

    return start, end


def report_c_source_blocks(roots: Sequence[Path]) -> None:
    print("=" * 116)
    print("PUBLIC SDK FLASH SOURCE BLOCKS")

    existing = [root for root in roots if root.exists()]
    files_scanned = 0
    emitted: set[tuple[Path, int, str]] = set()
    blocks_emitted = 0

    for root in existing:
        for path in root.rglob("*"):
            if not text_file(path):
                continue

            if path.suffix.lower() not in {".c", ".h", ".s"}:
                continue

            files_scanned += 1
            lines = read_lines(path)

            for index, line in enumerate(lines):
                for label, pattern in C_BLOCK_PATTERNS:
                    if not pattern.search(line):
                        continue

                    key = (path, index, label)

                    if key in emitted:
                        continue

                    emitted.add(key)
                    start, end = extract_balanced_block(lines, index)

                    print()
                    print(
                        f"--- {label}: {path}:{index + 1} "
                        f"(block {start + 1}-{end}) ---"
                    )

                    for line_number in range(start, end):
                        print(
                            f"{line_number + 1:6d}: "
                            f"{lines[line_number]}"
                        )

                    blocks_emitted += 1

                    if blocks_emitted >= 80:
                        print(
                            "\n... source block output truncated at 80 blocks"
                        )
                        print(f"text source files scanned: {files_scanned}")
                        return

    print()
    print(f"text source files scanned: {files_scanned}")
    print(f"source blocks emitted: {blocks_emitted}")
    print()


def report_asm_blocks(roots: Sequence[Path]) -> None:
    print("=" * 116)
    print("BOOT/ROM ASSEMBLY SYMBOL BLOCKS")

    blocks = []
    files_scanned = 0

    for root in roots:
        if not root.exists():
            continue

        for path in root.rglob("*"):
            if path.suffix.lower() not in {".asm", ".lst"}:
                continue

            files_scanned += 1
            lines = read_lines(path)

            for index, line in enumerate(lines):
                lowered = line.lower()

                if not any(
                    symbol.lower() in lowered
                    for symbol in ASM_SYMBOL_PATTERNS
                ):
                    continue

                start = max(0, index - 8)
                end = min(len(lines), index + 24)
                blocks.append((path, index, start, end, lines))

    print(f"assembly/listing files scanned: {files_scanned}")
    print(f"matching blocks: {len(blocks)}")

    for path, index, start, end, lines in blocks[:80]:
        print()
        print(
            f"--- {path}:{index + 1} "
            f"(context {start + 1}-{end}) ---"
        )

        for line_number in range(start, end):
            print(f"{line_number + 1:6d}: {lines[line_number]}")

    if len(blocks) > 80:
        print(f"\n... truncated {len(blocks) - 80} additional blocks")

    print()


def signature_line(line: str) -> bool:
    stripped = line.strip()

    if not stripped or stripped.startswith(("//", "/*", "*", "#")):
        return False

    if "(" not in stripped or ")" not in stripped:
        return False

    lowered = stripped.lower()

    return any(term in lowered for term in SIGNATURE_TERMS)


def report_candidate_signatures(roots: Sequence[Path]) -> None:
    print("=" * 116)
    print("FLASH/CACHE/STATE SIGNATURE INVENTORY")

    matches = []
    files_scanned = 0

    for root in roots:
        if not root.exists():
            continue

        for path in root.rglob("*"):
            if path.suffix.lower() not in {".c", ".h", ".s"}:
                continue

            if not text_file(path):
                continue

            files_scanned += 1

            for line_number, line in enumerate(read_lines(path), start=1):
                if not signature_line(line):
                    continue

                matches.append((path, line_number, line.strip()))

    print(f"source files scanned: {files_scanned}")
    print(f"candidate signature lines: {len(matches)}")

    preferred = []
    secondary = []

    for match in matches:
        lowered = match[2].lower()

        if (
            "uint8_t *" in lowered
            or "uint8_t*" in lowered
            or "bool *" in lowered
            or "bool*" in lowered
            or "erase_t" in lowered
            or "flash_cache" in lowered
            or "flash_program_operation" in lowered
            or "flash_erase_operation" in lowered
        ):
            preferred.append(match)
        else:
            secondary.append(match)

    print("high-value signatures:")

    for path, line_number, line in preferred[:300]:
        print(f"  {path}:{line_number}: {line}")

    if len(preferred) > 300:
        print(
            f"  ... truncated {len(preferred) - 300} high-value lines"
        )

    print("selected secondary signatures:")

    for path, line_number, line in secondary[:120]:
        print(f"  {path}:{line_number}: {line}")

    if len(secondary) > 120:
        print(
            f"  ... truncated {len(secondary) - 120} secondary lines"
        )

    print()


def report_semantic_matrix() -> None:
    print("=" * 116)
    print("CONSERVATIVE SEMANTIC MATRIX")
    print()
    print("0x00008600")
    print("  proven application ABI: (destination, length, source)")
    print("  public-source match: flash_program(offset, length, buffer)")
    print("  exact address-to-symbol match: none in available corpus")
    print("  accepted label: flash_program_abi_match_candidate")
    print("  confidence: medium-high")
    print()
    print("0x000081A0")
    print("  proven application ABI: (selector, address)")
    print("  observed selectors: 2 and 4")
    print("  public wrapper flash_erase ABI: (offset, erase_t)")
    print("  exact address-to-symbol match: none in available corpus")
    print("  accepted label: flash_erase_selector_address_candidate")
    print("  confidence: medium")
    print()
    print("0x0000893C")
    print("  proven role: called before erase/program operations")
    print("  arguments: flash/XIP address and writable saved-state pointer")
    print("  paired with 0x00008916")
    print("  exact cache/IRQ/XIP name: unresolved")
    print("  accepted label: flash_operation_begin_candidate")
    print("  confidence: medium")
    print()
    print("0x00008916")
    print("  proven role: called after erase/program operations")
    print("  argument: saved one-byte state")
    print("  paired with 0x0000893C")
    print("  exact cache/IRQ/XIP name: unresolved")
    print("  accepted label: flash_operation_end_candidate")
    print("  confidence: medium")
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Extract RY02 low-flash wrapper semantics and compare them with "
            "BlueX flash source, erase enums, integration APIs, and boot ASM."
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

    parser.add_argument("--no-source-analysis", action="store_true")
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

    roots = (
        tuple(args.source_root)
        if args.source_root
        else DEFAULT_SOURCE_ROOTS
    )

    print("RY02 FLASH PRIMITIVE SEMANTICS REPORT")
    print(f"tool revision: {TOOL_REVISION}")
    print()
    print(f"firmware38: {image38.path}")
    print(f"firmware38 SHA256: {image38.sha256()}")

    if image33 is not None:
        print(f"firmware33: {image33.path}")
        print(f"firmware33 SHA256: {image33.sha256()}")

    print(f"Python: {platform.python_version()}")
    print(f"Capstone: {capstone.__version__}")
    print()
    print("Accepted boundary:")
    print("  exact ROM-address correlation failed for all four targets")
    print("  this gate performs semantic/source correlation, not another")
    print("  generic address scan")
    print("  0x8600 remains an ABI match, not an exact vendor symbol")
    print("  0x81A0 remains a selector/address erase primitive candidate")
    print("  0x893C/0x8916 remain paired begin/end candidates")
    print("  no device interaction is performed")
    print()

    report_call_family(image38, "FIRMWARE .38")

    if image33 is not None:
        report_call_family(image33, "FIRMWARE .33")

    print("# APPLICATION WRAPPERS")

    for label, address in WRAPPER_FUNCTIONS:
        report_wrapper(image38, label, address)

    if not args.no_source_analysis:
        report_c_source_blocks(roots)
        report_asm_blocks(roots)
        report_candidate_signatures(roots)

    report_semantic_matrix()

    print("=" * 116)
    print("SUMMARY")

    for label, target in LOW_TARGETS:
        count38 = len(scan_direct_callers(image38, target))
        count33 = (
            len(scan_direct_callers(image33, target))
            if image33 is not None
            else 0
        )

        print(
            f"0x{target:08X} {label}: "
            f"callers38={count38} callers33={count33}"
        )

    print("ROM-address search route: closed for available SDK corpus")
    print("next evidence type: source semantic and wrapper-contract correlation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
