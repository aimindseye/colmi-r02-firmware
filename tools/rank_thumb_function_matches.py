#!/usr/bin/env python3

from __future__ import annotations

import argparse
import difflib
import re
from dataclasses import dataclass
from pathlib import Path

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
)


REGISTER_RE = re.compile(
    r"\b(?:r(?:1[0-2]|[0-9])|sp|lr|pc)\b",
    re.IGNORECASE,
)

IMMEDIATE_RE = re.compile(r"#(?:0x[0-9a-f]+|\d+)", re.IGNORECASE)

# Preserve constants that help describe the target function's switch and
# packet-building behavior. Normalize larger addresses and timer constants.
PRESERVED_IMMEDIATES = {
    0,
    1,
    2,
    3,
    4,
    5,
    0xA1,
}


@dataclass
class Candidate:
    offset: int
    similarity: float
    anchor_score: int
    instructions: list


def make_disassembler() -> Cs:
    md = Cs(
        CS_ARCH_ARM,
        CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
    )
    md.skipdata = True
    return md


def u16le(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def is_push_instruction(data: bytes, offset: int) -> bool:
    if offset < 0 or offset + 2 > len(data):
        return False

    halfword = u16le(data, offset)

    # Thumb PUSH encoding:
    # 1011 0 10 0 M register_list
    return (halfword & 0xFE00) == 0xB400


def function_candidates(data: bytes) -> list[int]:
    return [
        offset
        for offset in range(0, len(data) - 1, 2)
        if is_push_instruction(data, offset)
    ]


def disassemble_window(
    md: Cs,
    data: bytes,
    start: int,
    window_bytes: int,
):
    end = min(len(data), start + window_bytes)
    return list(md.disasm(data[start:end], start))


def parse_immediate(text: str) -> int | None:
    text = text.removeprefix("#")

    try:
        return int(text, 0)
    except ValueError:
        return None


def normalize_instruction(insn) -> str:
    operands = insn.op_str.lower()
    operands = REGISTER_RE.sub("r", operands)

    def replace_immediate(match: re.Match[str]) -> str:
        value = parse_immediate(match.group(0))

        if value in PRESERVED_IMMEDIATES:
            return f"#{value}"

        return "#imm"

    operands = IMMEDIATE_RE.sub(replace_immediate, operands)
    operands = re.sub(r"\s+", " ", operands).strip()

    if operands:
        return f"{insn.mnemonic.lower()} {operands}"

    return insn.mnemonic.lower()


def normalized_tokens(instructions: list) -> list[str]:
    return [
        normalize_instruction(insn)
        for insn in instructions
        if insn.mnemonic != ".byte"
    ]


def immediate_value(op_str: str) -> int | None:
    match = IMMEDIATE_RE.search(op_str)

    if not match:
        return None

    return parse_immediate(match.group(0))


def anchor_score(instructions: list) -> int:
    score = 0
    compare_values: set[int] = set()
    branch_equal_count = 0

    for insn in instructions:
        mnemonic = insn.mnemonic.lower()
        operand_text = insn.op_str.lower()
        immediate = immediate_value(operand_text)

        if mnemonic == "ldrb":
            score += 1

        if mnemonic == "strb":
            score += 1

        if mnemonic == "beq":
            branch_equal_count += 1

        if mnemonic in {"cmp", "cmn"} and immediate is not None:
            if immediate in {1, 2, 3, 4, 5}:
                compare_values.add(immediate)

        if mnemonic in {"movs", "mov"} and immediate == 0xA1:
            score += 5

        if mnemonic in {"lsls", "lsl"} and immediate == 3:
            score += 3

    score += len(compare_values) * 2

    if {1, 2, 3, 4, 5}.issubset(compare_values):
        score += 8

    if branch_equal_count >= 3:
        score += 4

    return score


def find_matches(
    reference_tokens: list[str],
    target_path: Path,
    window_bytes: int,
    top_count: int,
) -> None:
    data = target_path.read_bytes()
    md = make_disassembler()
    results: list[Candidate] = []

    for offset in function_candidates(data):
        instructions = disassemble_window(
            md,
            data,
            offset,
            window_bytes,
        )

        tokens = normalized_tokens(instructions)

        if len(tokens) < 12:
            continue

        similarity = difflib.SequenceMatcher(
            None,
            reference_tokens,
            tokens,
            autojunk=False,
        ).ratio()

        anchors = anchor_score(instructions)

        results.append(
            Candidate(
                offset=offset,
                similarity=similarity,
                anchor_score=anchors,
                instructions=instructions,
            )
        )

    results.sort(
        key=lambda item: (
            item.similarity,
            item.anchor_score,
        ),
        reverse=True,
    )

    print()
    print(f"===== TARGET: {target_path} =====")
    print(f"Payload size:       {len(data)} / 0x{len(data):X}")
    print(f"PUSH candidates:    {len(results)}")
    print(f"Showing top:        {min(top_count, len(results))}")

    for number, result in enumerate(results[:top_count], start=1):
        print()
        print(
            f"[{number}] offset=0x{result.offset:08X} "
            f"similarity={result.similarity:.4f} "
            f"anchors={result.anchor_score}"
        )

        for insn in result.instructions[:55]:
            raw = " ".join(f"{byte:02x}" for byte in insn.bytes)
            print(
                f"  0x{insn.address:08X}: "
                f"{raw:<12} "
                f"{insn.mnemonic:<7} "
                f"{insn.op_str}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Rank Thumb PUSH-delimited function candidates against "
            "the known R02 raw-reporting function."
        )
    )
    parser.add_argument(
        "--reference",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--reference-offset",
        required=True,
        type=lambda value: int(value, 0),
    )
    parser.add_argument(
        "--window-bytes",
        type=lambda value: int(value, 0),
        default=0x180,
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
    )
    parser.add_argument(
        "targets",
        nargs="+",
        type=Path,
    )
    args = parser.parse_args()

    reference_data = args.reference.read_bytes()
    reference_md = make_disassembler()

    reference_instructions = disassemble_window(
        reference_md,
        reference_data,
        args.reference_offset,
        args.window_bytes,
    )

    reference_tokens = normalized_tokens(reference_instructions)

    print("===== REFERENCE =====")
    print(f"Payload:            {args.reference}")
    print(f"Function offset:    0x{args.reference_offset:08X}")
    print(f"Window bytes:       0x{args.window_bytes:X}")
    print(f"Instructions:       {len(reference_instructions)}")
    print(f"Normalized tokens:  {len(reference_tokens)}")
    print(f"Anchor score:       {anchor_score(reference_instructions)}")

    for target in args.targets:
        find_matches(
            reference_tokens,
            target,
            args.window_bytes,
            args.top,
        )


if __name__ == "__main__":
    main()
