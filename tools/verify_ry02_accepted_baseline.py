#!/usr/bin/env python3
"""
Verify the accepted RY02 .38 reverse-engineering baseline.

This is a deterministic, offline regression gate. It does not attempt to name
unresolved ROM functions, patch firmware, communicate with the ring, or infer a
bootloader contract beyond the accepted evidence.

Checks include:
  * stock firmware identity and container geometry;
  * outer/inner magic and hardware-version anchors;
  * command-5 direct-call chain;
  * 1000 ms delayed-timer construction;
  * timer callback pointer and callback behavior;
  * complete six-caller family for low dispatcher 0x29C;
  * ordinary post-dispatch continuation in a D0 path;
  * absence of raw 0x29C/0x29D pointers;
  * absence of direct AIRCR literal use;
  * accepted configuration strings and magic;
  * stable low-flash call-family counts;
  * optional .33 identity and low-flash count comparison.

Exit status:
  0  all required checks passed
  1  one or more required checks failed
  2  input/dependency error
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

try:
    import capstone
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
    from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_REG_LR
except ImportError as exc:
    raise SystemExit(
        "capstone is required. Install it with:\n"
        "  python3 -m pip install capstone"
    ) from exc


TOOL_REVISION = "r1"

HEADER_SIZE = 0x50
RUNTIME_BASE = 0x00824000
CODE_START = 0x400

EXPECTED_SHA38 = "dbf64e3dc9aef112a4d69e46e516efb27f2ed2e3dc1d2d3f1af75939cc46487e"
EXPECTED_CONTAINER38 = 0x1CD64
EXPECTED_PAYLOAD38 = 0x1CD14

EXPECTED_SHA33 = "3eaad32f25a1734b93b63b86c6a0032c3444b68e7027faf3724bd5148dd4dbcd"
EXPECTED_PAYLOAD33 = 0x1B884

OUTER_MAGIC = 0x81BDC3E5
INNER_MAGIC = 0x0981000C
HARDWARE_VERSION = b"RY02_V3.0"

COMMAND5 = 0x0082AE62
COMMAND5_EXPECTED_CALLS = (
    0x00824F26,
    0x00825E30,
    0x008259DA,
    0x0082545E,
    0x0082723E,
    0x0082AC3C,
    0x0082B2C4,
    0x00829C1A,
    0x008253A8,
)

TIMER_RESTART_WRAPPER = 0x0082AC3C
TIMER_CALLBACK = 0x0082AC4A
TIMER_CALLBACK_THUMB = 0x0082AC4B
TIMER_CALLBACK_POINTER_RUNTIME = 0x0082AF04
CURRENT_TIME_GETTER = 0x0082580E

EVENT_DISPATCH = 0x0000029C
EVENT_DISPATCH_CALLERS = (
    0x00824B80,
    0x00824BA6,
    0x00827032,
    0x00828E08,
    0x00829EFA,
    0x0082AC58,
)

D0_CONTINUATION_CALL = 0x00829C94

AIRCR = 0xE000ED0C

CFG_MAGIC = 0x8721BEE2
REQUIRED_STRINGS = (
    b"cfg_add_item",
    b"_cfg_write_to_flash",
    b"cfg_del_item",
)

LOW_FLASH_COUNTS = {
    0x0000893C: 2,
    0x000081A0: 5,
    0x00008600: 6,
    0x00008916: 2,
}


@dataclass(frozen=True)
class Image:
    path: Path
    container: bytes
    payload: bytes
    md: Cs

    @classmethod
    def load(cls, path: Path) -> "Image":
        container = path.read_bytes()

        if len(container) <= HEADER_SIZE:
            raise ValueError(
                f"{path}: file too small for 0x{HEADER_SIZE:X}-byte outer header"
            )

        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        md.detail = True

        return cls(
            path=path,
            container=container,
            payload=container[HEADER_SIZE:],
            md=md,
        )

    def sha256(self) -> str:
        return hashlib.sha256(self.container).hexdigest()

    def runtime_for_offset(self, offset: int) -> int:
        return RUNTIME_BASE + offset

    def offset_for_runtime(self, address: int) -> int:
        return address - RUNTIME_BASE

    def decode_one_runtime(self, address: int):
        offset = self.offset_for_runtime(address)

        if not 0 <= offset < len(self.payload):
            return None

        decoded = list(
            self.md.disasm(
                self.payload[offset : offset + 4],
                address,
                count=1,
            )
        )
        return decoded[0] if decoded else None


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str
    required: bool = True


class Verifier:
    def __init__(self) -> None:
        self.results: list[CheckResult] = []

    def add(
        self,
        name: str,
        passed: bool,
        detail: str,
        *,
        required: bool = True,
    ) -> None:
        self.results.append(
            CheckResult(
                name=name,
                passed=passed,
                detail=detail,
                required=required,
            )
        )

    def equality(
        self,
        name: str,
        actual,
        expected,
        *,
        formatter: Callable[[object], str] = str,
        required: bool = True,
    ) -> None:
        self.add(
            name,
            actual == expected,
            f"actual={formatter(actual)} expected={formatter(expected)}",
            required=required,
        )

    def summary(self) -> tuple[int, int, int]:
        passed = sum(1 for result in self.results if result.passed)
        failed_required = sum(
            1
            for result in self.results
            if result.required and not result.passed
        )
        failed_optional = sum(
            1
            for result in self.results
            if not result.required and not result.passed
        )
        return passed, failed_required, failed_optional


def u32_le(data: bytes, offset: int) -> int | None:
    if not 0 <= offset <= len(data) - 4:
        return None
    return int.from_bytes(data[offset : offset + 4], "little")


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


def conditional_target(insn) -> int | None:
    if insn is None:
        return None

    if insn.mnemonic in {"cbz", "cbnz"}:
        if len(insn.operands) >= 2 and insn.operands[1].type == ARM_OP_IMM:
            return insn.operands[1].imm & 0xFFFFFFFF
        return None

    return direct_branch_target(insn)


def reachable_instructions(
    image: Image,
    start: int,
    *,
    max_forward: int = 0x500,
    max_instructions: int = 512,
) -> dict[int, object]:
    lower = start
    upper = min(RUNTIME_BASE + len(image.payload), start + max_forward)
    worklist = [start]
    visited_blocks: set[int] = set()
    instructions: dict[int, object] = {}

    while worklist and len(instructions) < max_instructions:
        block = worklist.pop()

        if block in visited_blocks:
            continue

        visited_blocks.add(block)
        current = block

        while lower <= current < upper and len(instructions) < max_instructions:
            if current in instructions:
                break

            insn = image.decode_one_runtime(current)

            if insn is None:
                break

            instructions[current] = insn
            next_address = current + insn.size

            if is_return(insn):
                break

            if is_call(insn):
                current = next_address
                continue

            if is_unconditional_branch(insn):
                target = direct_branch_target(insn)

                if target is not None and lower <= target < upper:
                    worklist.append(target)

                break

            if is_conditional_branch(insn):
                target = conditional_target(insn)

                if target is not None and lower <= target < upper:
                    worklist.append(target)

                current = next_address
                continue

            if insn.mnemonic == "bx":
                break

            current = next_address

    return instructions


def reachable_call_sequence(
    image: Image,
    start: int,
    *,
    max_forward: int = 0x500,
) -> list[tuple[int, int]]:
    instructions = reachable_instructions(
        image,
        start,
        max_forward=max_forward,
    )

    calls = []

    for address in sorted(instructions):
        insn = instructions[address]

        if not is_call(insn):
            continue

        target = direct_branch_target(insn)

        if target is not None:
            calls.append((address, target))

    return calls


def scan_direct_callers(image: Image, target: int) -> list[int]:
    result = []

    for offset in range(CODE_START, len(image.payload) - 4, 2):
        address = image.runtime_for_offset(offset)
        insn = image.decode_one_runtime(address)

        if is_call(insn) and direct_branch_target(insn) == target:
            result.append(address)

    return result


def raw_u32_offsets(data: bytes, value: int) -> list[int]:
    needle = value.to_bytes(4, "little")
    result = []
    start = 0

    while True:
        offset = data.find(needle, start)

        if offset < 0:
            break

        result.append(offset)
        start = offset + 1

    return result


def prior_instruction_sequence(
    image: Image,
    target_address: int,
    *,
    window: int = 0x20,
) -> list:
    target_offset = image.offset_for_runtime(target_address)
    lower = max(CODE_START, target_offset - window)
    best = []

    for start in range(lower, target_offset, 2):
        current = start
        sequence = []
        valid = True

        while current < target_offset:
            insn = image.decode_one_runtime(image.runtime_for_offset(current))

            if insn is None:
                valid = False
                break

            sequence.append(insn)
            current += insn.size

        if valid and current == target_offset and len(sequence) > len(best):
            best = sequence

    return best


def has_immediate_setup(
    image: Image,
    call_address: int,
    *,
    register_name: str,
    immediate: int,
    lookback: int = 0x18,
) -> bool:
    for insn in reversed(
        prior_instruction_sequence(
            image,
            call_address,
            window=lookback,
        )
    ):
        if is_call(insn):
            return False

        if insn.mnemonic not in {"mov", "movs"}:
            continue

        if len(insn.operands) < 2:
            continue

        destination, source = insn.operands[:2]

        if destination.type != ARM_OP_REG or source.type != ARM_OP_IMM:
            continue

        if insn.reg_name(destination.reg) != register_name:
            continue

        return (source.imm & 0xFFFFFFFF) == immediate

    return False


def verify_stock38(image: Image, verifier: Verifier) -> None:
    verifier.equality(
        "stock .38 SHA256",
        image.sha256(),
        EXPECTED_SHA38,
    )
    verifier.equality(
        "stock .38 container length",
        len(image.container),
        EXPECTED_CONTAINER38,
        formatter=lambda value: f"0x{int(value):X}",
    )
    verifier.equality(
        "stock .38 payload length",
        len(image.payload),
        EXPECTED_PAYLOAD38,
        formatter=lambda value: f"0x{int(value):X}",
    )
    verifier.equality(
        "outer magic",
        u32_le(image.container, 0),
        OUTER_MAGIC,
        formatter=lambda value: (
            "None" if value is None else f"0x{int(value):08X}"
        ),
    )
    verifier.equality(
        "inner magic",
        u32_le(image.payload, 0),
        INNER_MAGIC,
        formatter=lambda value: (
            "None" if value is None else f"0x{int(value):08X}"
        ),
    )

    hw_offsets = []
    start = 0

    while True:
        offset = image.container.find(HARDWARE_VERSION, start)

        if offset < 0:
            break

        hw_offsets.append(offset)
        start = offset + 1

    verifier.add(
        "hardware-version string present",
        bool(hw_offsets),
        "offsets=" + (
            ",".join(f"0x{offset:X}" for offset in hw_offsets)
            if hw_offsets
            else "none"
        ),
    )

    command5_calls = reachable_call_sequence(
        image,
        COMMAND5,
        max_forward=0x180,
    )
    command5_targets = tuple(target for _, target in command5_calls)

    verifier.equality(
        "command-5 direct-call sequence",
        command5_targets,
        COMMAND5_EXPECTED_CALLS,
        formatter=lambda values: (
            "[" + ",".join(f"0x{value:08X}" for value in values) + "]"
        ),
    )

    timer_sites = [
        site
        for site, target in command5_calls
        if target == TIMER_RESTART_WRAPPER
    ]

    verifier.add(
        "command-5 has one delayed-timer restart",
        len(timer_sites) == 1,
        "sites=" + (
            ",".join(f"0x{site:08X}" for site in timer_sites)
            if timer_sites
            else "none"
        ),
    )

    delay_ok = False

    if len(timer_sites) == 1:
        sequence = prior_instruction_sequence(
            image,
            timer_sites[0],
            window=0x10,
        )
        mnemonics = [
            (insn.mnemonic, insn.op_str)
            for insn in sequence[-4:]
        ]

        # Accepted code constructs 1000 as 0x7D << 3.
        delay_ok = any(
            insn.mnemonic in {"mov", "movs"}
            and "#0x7d" in insn.op_str.lower()
            for insn in sequence
        ) and any(
            insn.mnemonic == "lsls"
            and "#3" in insn.op_str.lower()
            for insn in sequence
        )

        delay_detail = repr(mnemonics)
    else:
        delay_detail = "timer restart call unresolved"

    verifier.add(
        "command-5 constructs 1000 ms delay",
        delay_ok,
        delay_detail,
    )

    pointer_offset = image.offset_for_runtime(TIMER_CALLBACK_POINTER_RUNTIME)
    pointer_value = u32_le(image.payload, pointer_offset)

    verifier.equality(
        "active delayed-callback Thumb pointer",
        pointer_value,
        TIMER_CALLBACK_THUMB,
        formatter=lambda value: (
            "None" if value is None else f"0x{int(value):08X}"
        ),
    )

    callback_calls = reachable_call_sequence(
        image,
        TIMER_CALLBACK,
        max_forward=0x40,
    )
    callback_targets = tuple(target for _, target in callback_calls)

    verifier.equality(
        "delayed callback direct calls",
        callback_targets,
        (CURRENT_TIME_GETTER, EVENT_DISPATCH),
        formatter=lambda values: (
            "[" + ",".join(f"0x{value:08X}" for value in values) + "]"
        ),
    )

    event_sites = [
        site
        for site, target in callback_calls
        if target == EVENT_DISPATCH
    ]

    callback_args_ok = (
        len(event_sites) == 1
        and has_immediate_setup(
            image,
            event_sites[0],
            register_name="r0",
            immediate=1,
        )
        and has_immediate_setup(
            image,
            event_sites[0],
            register_name="r1",
            immediate=0xD3,
        )
    )

    verifier.add(
        "delayed callback publishes source 1 / D3",
        callback_args_ok,
        "site=" + (
            f"0x{event_sites[0]:08X}"
            if len(event_sites) == 1
            else "unresolved"
        ),
    )

    dispatcher_callers = tuple(scan_direct_callers(image, EVENT_DISPATCH))

    verifier.equality(
        "complete 0x29C direct-caller family",
        dispatcher_callers,
        EVENT_DISPATCH_CALLERS,
        formatter=lambda values: (
            "[" + ",".join(f"0x{value:08X}" for value in values) + "]"
        ),
    )

    d0_next = image.decode_one_runtime(0x00829EFE)
    d0_next_target = direct_branch_target(d0_next)

    verifier.equality(
        "D0 path continues after 0x29C",
        d0_next_target,
        D0_CONTINUATION_CALL,
        formatter=lambda value: (
            "None" if value is None else f"0x{int(value):08X}"
        ),
    )

    callback_next = image.decode_one_runtime(0x0082AC5C)

    verifier.add(
        "D3 callback returns after 0x29C",
        is_return(callback_next),
        (
            "undecoded"
            if callback_next is None
            else f"{callback_next.mnemonic} {callback_next.op_str}"
        ),
    )

    exact_refs = raw_u32_offsets(image.payload, EVENT_DISPATCH)
    thumb_refs = raw_u32_offsets(image.payload, EVENT_DISPATCH | 1)

    verifier.add(
        "no raw 0x29C/0x29D pointers",
        not exact_refs and not thumb_refs,
        (
            f"exact={','.join(f'0x{x:X}' for x in exact_refs) or 'none'} "
            f"thumb={','.join(f'0x{x:X}' for x in thumb_refs) or 'none'}"
        ),
    )

    aircr_refs = raw_u32_offsets(image.payload, AIRCR)

    verifier.add(
        "no direct AIRCR literal",
        not aircr_refs,
        "offsets=" + (
            ",".join(f"0x{offset:X}" for offset in aircr_refs)
            if aircr_refs
            else "none"
        ),
    )

    cfg_magic_refs = raw_u32_offsets(image.payload, CFG_MAGIC)

    verifier.add(
        "configuration magic literal present",
        bool(cfg_magic_refs),
        "offsets=" + (
            ",".join(f"0x{offset:X}" for offset in cfg_magic_refs)
            if cfg_magic_refs
            else "none"
        ),
    )

    for required_string in REQUIRED_STRINGS:
        offsets = []
        start = 0

        while True:
            offset = image.payload.find(required_string, start)

            if offset < 0:
                break

            offsets.append(offset)
            start = offset + 1

        verifier.add(
            f"string {required_string.decode('ascii')} present",
            bool(offsets),
            "offsets=" + (
                ",".join(f"0x{offset:X}" for offset in offsets)
                if offsets
                else "none"
            ),
        )

    for target, expected_count in LOW_FLASH_COUNTS.items():
        callers = scan_direct_callers(image, target)

        verifier.equality(
            f"low-flash caller count 0x{target:08X}",
            len(callers),
            expected_count,
        )


def verify_optional33(image: Image, verifier: Verifier) -> None:
    verifier.equality(
        "stock .33 SHA256",
        image.sha256(),
        EXPECTED_SHA33,
        required=False,
    )
    verifier.equality(
        "stock .33 payload length",
        len(image.payload),
        EXPECTED_PAYLOAD33,
        formatter=lambda value: f"0x{int(value):X}",
        required=False,
    )

    for target, expected_count in LOW_FLASH_COUNTS.items():
        callers = scan_direct_callers(image, target)

        verifier.equality(
            f".33 low-flash caller count 0x{target:08X}",
            len(callers),
            expected_count,
            required=False,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the accepted RY02 .38 OTA/configuration static-analysis "
            "baseline and optionally compare stable .33 low-flash counts."
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

    parser.add_argument(
        "--no-firmware33",
        action="store_true",
        help="skip optional .33 identity and caller-count checks",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.firmware38.is_file():
        print(f"firmware not found: {args.firmware38}", file=sys.stderr)
        return 2

    try:
        image38 = Image.load(args.firmware38)
    except (OSError, ValueError) as exc:
        print(f"failed to load .38 firmware: {exc}", file=sys.stderr)
        return 2

    verifier = Verifier()

    print("RY02 ACCEPTED BASELINE VERIFICATION REPORT")
    print(f"tool revision: {TOOL_REVISION}")
    print(f"Python: {platform.python_version()}")
    print(f"Capstone: {capstone.__version__}")
    print()
    print(f"firmware38: {image38.path}")
    print()

    verify_stock38(image38, verifier)

    if not args.no_firmware33:
        if args.firmware33.is_file():
            try:
                image33 = Image.load(args.firmware33)
            except (OSError, ValueError) as exc:
                verifier.add(
                    "optional .33 image load",
                    False,
                    str(exc),
                    required=False,
                )
            else:
                print(f"firmware33: {image33.path}")
                print()
                verify_optional33(image33, verifier)
        else:
            verifier.add(
                "optional .33 image present",
                False,
                f"not found: {args.firmware33}",
                required=False,
            )

    print("=" * 116)
    print("CHECKS")

    for result in verifier.results:
        status = "PASS" if result.passed else (
            "FAIL" if result.required else "WARN"
        )
        requirement = "required" if result.required else "optional"

        print(
            f"[{status}] {result.name} ({requirement})\n"
            f"       {result.detail}"
        )

    passed, failed_required, failed_optional = verifier.summary()

    print("=" * 116)
    print("SUMMARY")
    print(f"checks passed: {passed}")
    print(f"required failures: {failed_required}")
    print(f"optional warnings: {failed_optional}")

    if failed_required:
        print("accepted baseline: FAILED")
        return 1

    print("accepted baseline: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
