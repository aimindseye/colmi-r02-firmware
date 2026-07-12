#!/usr/bin/env python3
"""
Correlate the RY02 low flash call targets with BlueX SDK ROM symbols and
public flash APIs.

Accepted application-side evidence:
  0x008386FC  _cfg_write_to_flash
  0x00008600  called three times as (destination, length, source)
  0x000081A0  called as (erase_selector, address)
  0x0000893C  called before erase as (address, saved_state_pointer)
  0x00008916  called after programming as (saved_state_byte)

This tool:
  * inventories all direct callers in firmware .38 and .33;
  * prints ABI-safe local r0-r3 provenance and call context;
  * searches ROM-symbol/linker/map files for exact target addresses;
  * searches SDK source for exact flash prototypes and definitions;
  * distinguishes address-level matches from source-level semantic matches;
  * reports the public flash_program and flash_erase signatures.

It is an offline static-analysis tool. It does not communicate with the ring or
modify firmware.
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
from typing import Iterable, Sequence

try:
    import capstone
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
    from capstone.arm import (
        ARM_OP_IMM,
        ARM_OP_REG,
        ARM_REG_R0,
        ARM_REG_R1,
        ARM_REG_R2,
        ARM_REG_R3,
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

TARGETS: tuple[tuple[str, int], ...] = (
    ("flash_operation_begin_candidate", 0x0000893C),
    ("flash_erase_candidate", 0x000081A0),
    ("flash_program_abi_match_candidate", 0x00008600),
    ("flash_operation_end_candidate", 0x00008916),
)

WRITER_START = 0x008386FC
WRITER_CALLS = {
    0x0083874C: 0x0000893C,
    0x00838754: 0x000081A0,
    0x0083875E: 0x00008600,
    0x00838768: 0x00008600,
    0x00838774: 0x00008600,
    0x0083877C: 0x00008916,
}

CALLER_SAVED = {ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3}

DEFAULT_SOURCE_ROOTS = (
    Path("reference/bluex-sdk3-v3.3.8-20250117"),
    Path("reference/bluex-sdk3-demo"),
)

SYMBOL_FILE_HINTS = (
    "rom_sym",
    "romsym",
    "symdefs",
    "symbol",
    "link",
    "scatter",
    "map",
)

SOURCE_PATTERNS = (
    "flash_program(",
    "flash_erase(",
    "flash_program_0_16M",
    "flash_erase_0_16m",
    "flash_program_operation",
    "flash_erase_operation",
    "flash_cache",
    "flash_prepare",
    "flash_restore",
    "flash_operation",
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

    def runtime_for_offset(self, offset: int) -> int:
        return self.base + offset

    def offset_for_runtime(self, address: int) -> int:
        return address - self.base

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


def parse_int(value: str) -> int:
    return int(value, 0)


def direct_branch_target(insn) -> int | None:
    if insn is None or insn.mnemonic not in {"bl", "blx"}:
        return None

    if not insn.operands or insn.operands[0].type != ARM_OP_IMM:
        return None

    return insn.operands[0].imm & 0xFFFFFFFF


def is_call(insn) -> bool:
    return direct_branch_target(insn) is not None


def scan_direct_callers(image: Image, target: int) -> list[int]:
    callers = []

    for offset in range(image.code_start, len(image.payload) - 4, 2):
        insn = image.decode_one(offset)
        if direct_branch_target(insn) == target:
            callers.append(image.runtime_for_offset(offset))

    return callers


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
        current = start
        sequence = []
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


def print_context(
    image: Image,
    center: int,
    *,
    before: int = 0x20,
    after: int = 0x18,
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
        target = direct_branch_target(insn)
        suffix = (
            f" ; target=0x{target:08X}"
            if target is not None
            else ""
        )

        print(
            f"{marker} payload+0x{current:05X} "
            f"runtime=0x{insn.address:08X} "
            f"{insn.bytes.hex(' '):<13} "
            f"{insn.mnemonic:<8} {insn.op_str}{suffix}"
        )
        current += insn.size


def report_image_callers(image: Image, image_label: str) -> None:
    print("=" * 116)
    print(f"{image_label} LOW FLASH CALLERS")
    print(f"image: {image.path}")
    print(f"SHA256: {image.sha256()}")

    for label, target in TARGETS:
        callers = scan_direct_callers(image, target)

        print()
        print(f"{label}: 0x{target:08X}")
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

            print("    context:")
            print_context(image, caller)

    print()


def report_writer_contract(image: Image) -> None:
    print("=" * 116)
    print("WRITER-SPECIFIC CONTRACT")
    print(f"writer start: 0x{WRITER_START:08X}")

    for site, expected_target in WRITER_CALLS.items():
        insn = image.decode_one(image.offset_for_runtime(site))
        actual = direct_branch_target(insn)

        print()
        print(
            f"call site 0x{site:08X}: "
            f"expected=0x{expected_target:08X} "
            f"actual={f'0x{actual:08X}' if actual is not None else 'unresolved'}"
        )

        for register, name in (
            (ARM_REG_R0, "r0"),
            (ARM_REG_R1, "r1"),
            (ARM_REG_R2, "r2"),
            (ARM_REG_R3, "r3"),
        ):
            print(
                f"  {name}: "
                f"{local_register_provenance(image, site, register)}"
            )

    print()
    print("public SDK semantic comparison:")
    print(
        "  flash_program(uint32_t offset, uint32_t length, uint8_t *buffer)"
    )
    print(
        "  writer 0x8600 calls use r0=destination, r1=length, r2=source"
    )
    print("  result: ABI-shape match")
    print()
    print("  flash_erase(uint32_t offset, erase_t type)")
    print(
        "  writer 0x81A0 call uses r0=2, r1=sector address"
    )
    print("  result: argument order does not match the public wrapper ABI")
    print()


def text_candidate(path: Path) -> bool:
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


def symbol_file_candidate(path: Path) -> bool:
    name = path.name.lower()
    return (
        any(hint in name for hint in SYMBOL_FILE_HINTS)
        or path.suffix.lower() in {".map", ".sym", ".sct", ".scf", ".ld"}
    )


def address_regexes(address: int) -> tuple[re.Pattern[str], ...]:
    value = address & 0xFFFFFFFF
    short = f"{value:X}"
    full = f"{value:08X}"

    return (
        re.compile(rf"(?i)(?<![0-9a-f])0x0*{short}(?![0-9a-f])"),
        re.compile(rf"(?i)(?<![0-9a-f]){full}(?![0-9a-f])"),
        re.compile(rf"(?i)(?<![0-9a-f])0*{short}H(?![0-9a-f])"),
    )


def iter_text_lines(path: Path) -> Iterable[tuple[int, str]]:
    try:
        lines = path.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines()
    except OSError:
        return

    for line_number, line in enumerate(lines, start=1):
        yield line_number, line


def report_rom_symbol_matches(roots: Sequence[Path]) -> None:
    print("=" * 116)
    print("ROM-SYMBOL ADDRESS CORRELATION")

    existing = [root for root in roots if root.exists()]
    print(f"source roots present: {len(existing)}")

    files_scanned = 0
    symbol_files_scanned = 0
    matches: dict[int, list[tuple[Path, int, str]]] = {
        target: []
        for _, target in TARGETS
    }

    for root in existing:
        for path in root.rglob("*"):
            if not text_candidate(path):
                continue

            files_scanned += 1

            if not symbol_file_candidate(path):
                continue

            symbol_files_scanned += 1
            regexes = {
                target: address_regexes(target)
                for _, target in TARGETS
            }

            for line_number, line in iter_text_lines(path):
                for target, patterns in regexes.items():
                    if any(pattern.search(line) for pattern in patterns):
                        matches[target].append(
                            (path, line_number, line.strip())
                        )

    print(f"text files considered: {files_scanned}")
    print(f"symbol/linker/map files scanned: {symbol_files_scanned}")

    for label, target in TARGETS:
        print()
        print(f"{label}: 0x{target:08X}")
        print(f"address-line matches: {len(matches[target])}")

        for path, line_number, line in matches[target][:100]:
            print(f"  {path}:{line_number}: {line}")

        if len(matches[target]) > 100:
            print(
                f"  ... truncated "
                f"{len(matches[target]) - 100} additional matches"
            )

    print()


def report_public_flash_apis(roots: Sequence[Path]) -> None:
    print("=" * 116)
    print("PUBLIC FLASH API DEFINITIONS")

    existing = [root for root in roots if root.exists()]
    matches = []
    files_scanned = 0

    for root in existing:
        for path in root.rglob("*"):
            if not text_candidate(path):
                continue

            files_scanned += 1

            for line_number, line in iter_text_lines(path):
                lowered = line.lower()

                if any(pattern.lower() in lowered for pattern in SOURCE_PATTERNS):
                    matches.append(
                        (path, line_number, line.strip())
                    )

    print(f"text files scanned: {files_scanned}")
    print(f"matching source lines: {len(matches)}")

    high_value = []
    remaining = []

    for item in matches:
        line = item[2]
        if (
            re.search(
                r"\bflash_program\s*\(\s*uint32_t\s+\w+\s*,"
                r"\s*uint32_t\s+\w+\s*,\s*uint8_t\s*\*",
                line,
                re.IGNORECASE,
            )
            or re.search(
                r"\bflash_erase\s*\(\s*uint32_t\s+\w+\s*,"
                r"\s*erase_t\s+\w+",
                line,
                re.IGNORECASE,
            )
            or "rom_syms" in str(item[0]).lower()
        ):
            high_value.append(item)
        else:
            remaining.append(item)

    print("high-value declarations/mappings:")
    if not high_value:
        print("  none")

    for path, line_number, line in high_value[:200]:
        print(f"  {path}:{line_number}: {line}")

    print("selected supporting uses:")
    for path, line_number, line in remaining[:120]:
        print(f"  {path}:{line_number}: {line}")

    if len(remaining) > 120:
        print(
            f"  ... truncated {len(remaining) - 120} additional uses"
        )

    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Correlate RY02 low flash call targets with BlueX ROM symbols, "
            "public flash prototypes, and firmware .33 call families."
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

    roots = (
        tuple(args.source_root)
        if args.source_root
        else DEFAULT_SOURCE_ROOTS
    )

    print("RY02 BLUEX FLASH ROM ABI REPORT")
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
    print("Interpretation constraints:")
    print("  - address-line ROM symbol matches are strongest naming evidence")
    print("  - source prototype similarity alone does not prove address identity")
    print("  - 0x8600 has a strong flash_program ABI-shape match")
    print("  - 0x81A0 argument order differs from public flash_erase")
    print("  - 0x893C and 0x8916 remain begin/end candidates")
    print("  - no device interaction is performed")
    print()

    report_image_callers(image38, "FIRMWARE .38")
    report_writer_contract(image38)

    if image33 is not None:
        report_image_callers(image33, "FIRMWARE .33")

    if not args.no_source_search:
        report_rom_symbol_matches(roots)
        report_public_flash_apis(roots)

    print("=" * 116)
    print("SUMMARY")

    for label, target in TARGETS:
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

    print(
        "0x00008600: application ABI matches "
        "flash_program(offset,length,buffer)"
    )
    print(
        "0x000081A0: application ABI appears "
        "(erase_selector,address), not public flash_erase(offset,type)"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
