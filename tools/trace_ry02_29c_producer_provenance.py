#!/usr/bin/env python3
"""
RY02 0x29C producer-provenance tracer, revision r2.

Repairs over r1:
  * walks reachable Thumb control flow instead of decoding linearly through
    adjacent functions after an unconditional tail branch;
  * reports external tail branches explicitly;
  * invalidates r0-r3 provenance across intervening BL/BLX calls;
  * classifies broad high constants separately from known peripheral ranges.

This is an offline static-analysis tool. It does not communicate with the ring,
modify firmware, or infer that event 0xD3 directly means reset.
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
LOW_PUBLISH_TARGET = 0x0000029C

RAM_MIN = 0x00200000
RAM_MAX = 0x00220000

# Public BlueX and common Cortex-M peripheral windows. Values outside these
# windows are not described as MMIO merely because they are numerically high.
KNOWN_PERIPHERAL_RANGES = (
    (0x20100000, 0x20300000),
    (0x40000000, 0x60000000),
    (0xE0000000, 0xE0100000),
)

CALLER_SAVED = {ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3}

DEFAULT_PRODUCERS: tuple[tuple[str, int], ...] = (
    ("source1_D3_retained_publisher", 0x00824B6A),
    ("source3_D4_D5_publisher", 0x00824B86),
    ("source1_D0_completion_publisher", 0x00826FF8),
    ("source1_D0_state_update_publisher", 0x00828DD2),
    ("source1_D0_configuration_publisher", 0x00829E70),
    ("source1_D3_timer_callback", 0x0082AC4A),
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
                f"{path}: file too small for header size 0x{header_size:X}"
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

    def in_payload_runtime(self, value: int) -> bool:
        return self.base <= value < self.base + len(self.payload)

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
        return [self.instructions[a] for a in sorted(self.instructions)]


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
    max_forward: int = 0x800,
    max_backward: int = 0x80,
    max_instructions: int = 1000,
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
            next_addr = current + insn.size

            if is_return(insn):
                returns.append(current)
                break

            if is_call(insn):
                current = next_addr
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
                current = next_addr
                continue

            # Indirect BX/BLX through a register terminates the local CFG unless
            # it is an ordinary BLX call, which was handled above.
            if insn.mnemonic == "bx":
                break

            current = next_addr

    return FunctionGraph(
        start=start_address,
        instructions=instructions,
        returns=sorted(set(returns)),
        external_tail_branches=sorted(set(external_tails)),
        decode_failures=sorted(set(failures)),
    )


def scan_direct_callers(image: Image, target_address: int) -> list[int]:
    result: list[int] = []
    for off in range(image.code_start, len(image.payload) - 4, 2):
        insn = image.decode_one(off)
        if is_call(insn) and direct_branch_target(insn) == target_address:
            result.append(image.runtime_for_offset(off))
    return result


def scan_raw_references(image: Image, value: int) -> list[int]:
    needle = value.to_bytes(4, "little")
    found: list[int] = []
    start = 0
    while True:
        off = image.payload.find(needle, start)
        if off < 0:
            break
        found.append(image.runtime_for_offset(off))
        start = off + 1
    return found


def probable_enclosing_start(
    image: Image,
    call_address: int,
    *,
    window: int = 0x180,
) -> int | None:
    call_off = image.offset_for_runtime(call_address)
    lower = max(image.code_start, call_off - window)
    candidates: list[int] = []

    for off in range(lower, call_off, 2):
        insn = image.decode_one(off)
        if not is_probable_function_start(insn):
            continue
        graph = build_function_cfg(
            image,
            image.runtime_for_offset(off),
            max_forward=max(0x200, call_address - image.runtime_for_offset(off) + 0x40),
        )
        if call_address in graph.instructions:
            candidates.append(image.runtime_for_offset(off))

    return candidates[-1] if candidates else None


def contiguous_predecessors(
    image: Image,
    call_address: int,
    *,
    window: int = 0x70,
) -> list:
    call_off = image.offset_for_runtime(call_address)
    lower = max(image.code_start, call_off - window)
    best: list = []

    for start in range(lower, call_off, 2):
        seq = []
        cur = start
        valid = True
        while cur < call_off:
            insn = image.decode_one(cur)
            if insn is None:
                valid = False
                break
            seq.append(insn)
            cur += insn.size
        if valid and cur == call_off and len(seq) > len(best):
            best = seq
    return best


def local_register_provenance(
    image: Image,
    call_address: int,
    register: int,
) -> str:
    sequence = contiguous_predecessors(image, call_address)

    for insn in reversed(sequence):
        # Any intervening call may clobber r0-r3. Stop before attributing a
        # stale writer from earlier in the block.
        if is_call(insn) and register in CALLER_SAVED:
            return (
                f"unknown: {image.md.reg_name(register)} may be clobbered by "
                f"{insn.mnemonic} at 0x{insn.address:08X}"
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
    if not insn.mnemonic.startswith("ldr") or len(insn.operands) < 2:
        return None
    op = insn.operands[1]
    if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC:
        return None

    literal_address = ((insn.address + 4) & ~3) + op.mem.disp
    off = image.offset_for_runtime(literal_address)
    if not 0 <= off <= len(image.payload) - 4:
        return None
    value = int.from_bytes(image.payload[off : off + 4], "little")
    return literal_address, value


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
    off = image.offset_for_runtime(runtime_address)
    chars: list[str] = []
    for b in image.payload[off : off + max_length]:
        if b == 0:
            break
        c = chr(b)
        if c not in string.printable or c in "\r\n\t\x0b\x0c":
            return None
        chars.append(c)
    text = "".join(chars)
    return text if len(text) >= min_length else None


def normalized_token(insn, image: Image) -> str:
    parts = [insn.mnemonic]

    target = direct_branch_target(insn)
    if target is not None:
        if image.in_payload_runtime(target):
            parts.append("BR_LOCAL")
        else:
            parts.append(f"BR_LOW_{target & 0xFFF:X}")
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
    for off in range(image.code_start, len(image.payload) - 2, 2):
        insn = image.decode_one(off)
        if is_probable_function_start(insn):
            yield image.runtime_for_offset(off)


def counterpart_candidates(
    source_image: Image,
    source_graph: FunctionGraph,
    comparison_image: Image,
    *,
    top_n: int = 3,
) -> list[tuple[float, int, int]]:
    source_tokens = [
        normalized_token(insn, source_image)
        for insn in source_graph.ordered()[:64]
    ]
    if len(source_tokens) < 3:
        return []

    candidates: list[tuple[float, int, int]] = []
    for start in probable_function_starts(comparison_image):
        graph = build_function_cfg(comparison_image, start)
        tokens = [
            normalized_token(insn, comparison_image)
            for insn in graph.ordered()[:64]
        ]
        if len(tokens) < 3:
            continue
        score = difflib.SequenceMatcher(
            a=source_tokens,
            b=tokens,
            autojunk=False,
        ).ratio()
        candidates.append((score, start, len(graph.instructions)))

    candidates.sort(reverse=True)
    return candidates[:top_n]


def format_instruction(image: Image, insn, marker: str = "  ") -> str:
    target = direct_branch_target(insn)
    if target is None:
        target = cb_target(insn)
    target_text = f" ; target=0x{target:08X}" if target is not None else ""
    return (
        f"{marker} payload+0x{image.offset_for_runtime(insn.address):05X} "
        f"runtime=0x{insn.address:08X} "
        f"{insn.bytes.hex(' '):<13} "
        f"{insn.mnemonic:<9} {insn.op_str}{target_text}"
    )


def print_context(
    image: Image,
    center_address: int,
    *,
    before: int = 0x28,
    after: int = 0x28,
) -> None:
    start = max(
        image.code_start,
        image.offset_for_runtime(center_address) - before,
    )
    end = min(
        len(image.payload),
        image.offset_for_runtime(center_address) + after,
    )
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
        marker = ">>" if insn.address == center_address else "  "
        print(format_instruction(image, insn, marker))
        current += insn.size


def report_producer(
    image38: Image,
    name: str,
    start_address: int,
    image33: Image | None,
) -> None:
    graph = build_function_cfg(image38, start_address)

    print("=" * 108)
    print(f"producer: {name}")
    print(f"start: 0x{start_address:08X}")
    print(f"reachable instruction count: {len(graph.instructions)}")
    print(f"recognized returns: {len(graph.returns)}")
    for address in graph.returns:
        print(f"  return at 0x{address:08X}")
    print(f"external tail branches: {len(graph.external_tail_branches)}")
    for site, target in graph.external_tail_branches:
        print(f"  0x{site:08X} -> 0x{target:08X}")
    if graph.decode_failures:
        print("decode failures:")
        for address in graph.decode_failures:
            print(f"  0x{address:08X}")

    callers = scan_direct_callers(image38, start_address)
    print()
    print("direct callers:")
    if not callers:
        print("  none")
    for caller in callers:
        parent = probable_enclosing_start(image38, caller)
        print(
            f"  call=0x{caller:08X} "
            f"parent={f'0x{parent:08X}' if parent is not None else 'unresolved'}"
        )
        for reg, name_ in (
            (ARM_REG_R0, "r0"),
            (ARM_REG_R1, "r1"),
            (ARM_REG_R2, "r2"),
            (ARM_REG_R3, "r3"),
        ):
            print(f"    {name_}: {local_register_provenance(image38, caller, reg)}")
        print("    context:")
        print_context(image38, caller)

    raw_even = scan_raw_references(image38, start_address)
    raw_thumb = scan_raw_references(image38, start_address | 1)
    print()
    print("raw/pointer references:")
    print(f"  exact 0x{start_address:08X}: {len(raw_even)}")
    for address in raw_even:
        print(f"    0x{address:08X}")
    print(f"  Thumb 0x{start_address | 1:08X}: {len(raw_thumb)}")
    for address in raw_thumb:
        print(f"    0x{address:08X}")

    print()
    print("reachable PC-relative literals:")
    literals = []
    for insn in graph.ordered():
        resolved = ldr_literal_value(image38, insn)
        if resolved is None:
            continue
        literal_address, value = resolved
        literals.append((insn.address, literal_address, value))
    if not literals:
        print("  none")
    for insn_address, literal_address, value in literals:
        classification = classify_value(image38, value)
        text = ascii_at_runtime(image38, value)
        suffix = f', ASCII="{text}"' if text is not None else ""
        print(
            f"  insn=0x{insn_address:08X} "
            f"literal=0x{literal_address:08X} "
            f"value=0x{value:08X} "
            f"[{classification}{suffix}]"
        )

    print()
    print("reachable RAM objects:")
    ram_values = sorted(
        {
            value
            for _, _, value in literals
            if RAM_MIN <= value < RAM_MAX
        }
    )
    if not ram_values:
        print("  none")
    for value in ram_values:
        print(f"  0x{value:08X}")

    print()
    print("reachable producer CFG instructions:")
    for insn in graph.ordered():
        marker = ">>" if direct_branch_target(insn) == LOW_PUBLISH_TARGET else "  "
        print(format_instruction(image38, insn, marker))

    print()
    print(".33 heuristic counterpart candidates:")
    if image33 is None:
        print("  comparison image not supplied")
    else:
        for score, candidate, count in counterpart_candidates(
            image38,
            graph,
            image33,
        ):
            classification = (
                "strong heuristic"
                if score >= 0.85
                else "moderate heuristic"
                if score >= 0.65
                else "weak heuristic"
            )
            print(
                f"  score={score:.3f} "
                f"start=0x{candidate:08X} "
                f"reachable_instructions={count} "
                f"[{classification}]"
            )
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "CFG-aware provenance analysis for the six known RY02 producers "
            "that publish through low target 0x29C."
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
        "--producer",
        action="append",
        default=[],
        metavar="NAME=ADDRESS",
    )
    return parser


def parse_producers(values: Sequence[str]) -> tuple[tuple[str, int], ...]:
    if not values:
        return DEFAULT_PRODUCERS
    result = []
    for value in values:
        if "=" not in value:
            raise ValueError(f"invalid producer {value!r}; use NAME=ADDRESS")
        name, address = value.split("=", 1)
        result.append((name.strip(), parse_int(address.strip())))
    return tuple(result)


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

    print("RY02 0x29C PRODUCER PROVENANCE REPORT")
    print(f"tool revision: {TOOL_REVISION}")
    print()
    print(f"firmware38: {image38.path}")
    print(f"firmware38 SHA256: {image38.sha256()}")
    print(f"firmware38 container length: 0x{len(image38.container):X}")
    print(f"firmware38 payload length: 0x{len(image38.payload):X}")
    if image33 is not None:
        print(f"firmware33: {image33.path}")
        print(f"firmware33 SHA256: {image33.sha256()}")
        print(f"firmware33 container length: 0x{len(image33.container):X}")
        print(f"firmware33 payload length: 0x{len(image33.payload):X}")
    print(f"runtime base: 0x{args.base:08X}")
    print(f"code-start payload offset: 0x{args.code_start:X}")
    print(f"low publication target: 0x{LOW_PUBLISH_TARGET:08X}")
    print(f"Python: {platform.python_version()}")
    print(f"Capstone: {capstone.__version__}")
    print()
    print("Interpretation constraints:")
    print("  - only CFG-reachable instructions are attributed to a producer")
    print("  - external tail branches terminate the local function")
    print("  - r0-r3 provenance is invalidated by intervening BL/BLX calls")
    print("  - exact pointers and direct calls are positive reachability evidence")
    print("  - .33 counterpart scores remain heuristic")
    print("  - do not rename 0x29C to bx_public without an ABI-level match")
    print("  - do not interpret event 0xD3 as reset solely from this report")
    print()

    producers = parse_producers(args.producer)
    for name, address in producers:
        report_producer(image38, name, address, image33)

    print("=" * 108)
    print("SUMMARY TARGETS")
    for name, address in producers:
        graph = build_function_cfg(image38, address)
        print(
            f"0x{address:08X} {name}: "
            f"reachable_instructions={len(graph.instructions)} "
            f"direct_callers={len(scan_direct_callers(image38, address))} "
            f"thumb_pointer_refs={len(scan_raw_references(image38, address | 1))} "
            f"external_tail_branches={len(graph.external_tail_branches)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
