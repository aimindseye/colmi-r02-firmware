#!/usr/bin/env python3
"""
Validate the promoted RY02 accepted-baseline evidence bundle.

This checks the generated verification report, machine-readable manifest,
required documentation, and key symbol-map labels. It does not disassemble
firmware; use verify_ry02_accepted_baseline.py for firmware-level assertions.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Sequence


REQUIRED_DOCS = (
    "docs/reverse-engineering/ry02-command5-ota-architecture.md",
    "docs/reverse-engineering/ry02-evidence-index.md",
    "docs/reverse-engineering/ry02-accepted-baseline-verifier.md",
    "docs/reverse-engineering/ry02-accepted-baseline.md",
    "docs/reverse-engineering/ry02-cfg-item-service.md",
    "docs/reverse-engineering/ry02-cfg-flash-layout.md",
    "docs/reverse-engineering/ry02-flash-primitive-semantics.md",
)

REQUIRED_SYMBOLS = {
    "0x0000029C": "publish_event2_candidate",
    "0x000081A0": "flash_erase_selector_address_candidate",
    "0x00008600": "flash_program_abi_match_candidate",
    "0x00008916": "flash_operation_end_candidate",
    "0x0000893C": "flash_operation_begin_candidate",
    "0x00801400": "cfg_blob_slot_base",
    "0x0082AC4A": "write_flag_delayed_D3_callback",
    "0x008386FC": "_cfg_write_to_flash",
    "0x00838914": "cfg_add_item",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the promoted RY02 accepted-baseline bundle."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="repository root; defaults to current directory",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    failures: list[str] = []

    report_path = root / "analysis/ry02-v38-accepted-baseline-verification.txt"
    manifest_path = root / "analysis/ry02-accepted-baseline.json"
    symbol_path = root / "analysis/ry02-v38-symbol-map.csv"

    for relative in REQUIRED_DOCS:
        path = root / relative
        if not path.is_file():
            failures.append(f"missing required document: {relative}")

    if not report_path.is_file():
        failures.append(
            "missing verification report: "
            "analysis/ry02-v38-accepted-baseline-verification.txt"
        )
    else:
        report = report_path.read_text(encoding="utf-8", errors="replace")
        required_report_lines = (
            "checks passed: 31",
            "required failures: 0",
            "optional warnings: 0",
            "accepted baseline: PASS",
        )
        for line in required_report_lines:
            if line not in report:
                failures.append(f"verification report missing: {line!r}")

        if "[FAIL]" in report:
            failures.append("verification report contains [FAIL]")
        if "[WARN]" in report:
            failures.append("verification report contains [WARN]")

    if not manifest_path.is_file():
        failures.append(
            "missing machine-readable manifest: "
            "analysis/ry02-accepted-baseline.json"
        )
    else:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"invalid baseline JSON: {exc}")
        else:
            verification = manifest.get("verification", {})
            if manifest.get("status") != "accepted":
                failures.append("baseline JSON status is not 'accepted'")
            if verification.get("checks_passed") != 31:
                failures.append("baseline JSON checks_passed is not 31")
            if verification.get("required_failures") != 0:
                failures.append("baseline JSON required_failures is not 0")
            if verification.get("optional_warnings") != 0:
                failures.append("baseline JSON optional_warnings is not 0")
            if verification.get("accepted_baseline") is not True:
                failures.append("baseline JSON accepted_baseline is not true")

    if not symbol_path.is_file():
        failures.append("missing symbol map: analysis/ry02-v38-symbol-map.csv")
    else:
        with symbol_path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))

        by_address = {row.get("address", ""): row for row in rows}

        for address, expected_fragment in REQUIRED_SYMBOLS.items():
            row = by_address.get(address)
            if row is None:
                failures.append(f"symbol map missing {address}")
                continue

            label = row.get("label", "")
            if expected_fragment not in label:
                failures.append(
                    f"symbol {address} label {label!r} does not contain "
                    f"{expected_fragment!r}"
                )

    architecture = root / "docs/reverse-engineering/ry02-command5-ota-architecture.md"
    if architecture.is_file():
        text = architecture.read_text(encoding="utf-8", errors="replace")
        for phrase in (
            "accepted baseline verified",
            "publish_event2_candidate",
        ):
            if phrase not in text:
                failures.append(
                    f"architecture document missing required phrase: {phrase!r}"
                )

    accepted_baseline = root / "docs/reverse-engineering/ry02-accepted-baseline.md"
    if accepted_baseline.is_file():
        text = accepted_baseline.read_text(encoding="utf-8", errors="replace")
        for phrase in (
            "_cfg_write_to_flash",
            "cfg_add_item",
            "31 checks passed",
        ):
            if phrase not in text:
                failures.append(
                    f"accepted baseline document missing required phrase: {phrase!r}"
                )

    evidence = root / "docs/reverse-engineering/ry02-evidence-index.md"
    if evidence.is_file():
        text = evidence.read_text(encoding="utf-8", errors="replace")
        for phrase in (
            "E-077",
            "ry02-v38-accepted-baseline-verification.txt",
            "31 checks",
        ):
            if phrase not in text:
                failures.append(
                    f"evidence index missing required phrase: {phrase!r}"
                )

    print("RY02 ACCEPTED BASELINE BUNDLE VALIDATION")
    print(f"root: {root}")
    print()

    if failures:
        for failure in failures:
            print(f"[FAIL] {failure}")
        print()
        print(f"failures: {len(failures)}")
        print("bundle status: FAILED")
        return 1

    print("[PASS] verification report")
    print("[PASS] machine-readable manifest")
    print("[PASS] required documentation")
    print("[PASS] key symbol-map labels")
    print("[PASS] architecture/evidence promotion markers")
    print()
    print("failures: 0")
    print("bundle status: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
