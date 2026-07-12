#!/usr/bin/env python3
"""Validate the repository overlay and an optional materialized SDK3 tree."""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence


DEFAULT_OVERLAY = Path(
    "prototype/bluex_sdk3_ringcli_adapter/overlay/code"
)
DEFAULT_SOURCE_GATE = Path(
    "analysis/ry02-bluex-sdk3-ringcli-adapter-source-gate.txt"
)
DEFAULT_MATERIALIZED = Path(
    "build/ry02-bluex-sdk3-ringcli-adapter"
)

UUID_BYTES = {
    "command_service": "9E CA DC 24 0E E5 A9 E0 93 F3 A3 B5 F0 FF 40 6E",
    "command_write": "9E CA DC 24 0E E5 A9 E0 93 F3 A3 B5 02 00 40 6E",
    "command_notify": "9E CA DC 24 0E E5 A9 E0 93 F3 A3 B5 03 00 40 6E",
    "data_service": "C7 5D 2A 01 E3 65 26 AF 47 4E 11 D7 28 F7 5B DE",
    "data_write": "C7 5D 2A 01 E3 65 26 AF 47 4E 11 D7 2A F7 5B DE",
    "data_notify": "C7 5D 2A 01 E3 65 26 AF 47 4E 11 D7 29 F7 5B DE",
}


def extract_hex_bytes(text: str) -> list[int]:
    return [
        int(match.group(1), 16)
        for match in re.finditer(r"0x([0-9A-Fa-f]{2})", text)
    ]


def contains_subsequence(haystack: list[int], needle: list[int]) -> bool:
    if not needle or len(needle) > len(haystack):
        return False
    width = len(needle)
    return any(
        haystack[index:index + width] == needle
        for index in range(len(haystack) - width + 1)
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY)
    parser.add_argument("--source-gate", type=Path, default=DEFAULT_SOURCE_GATE)
    parser.add_argument("--materialized", type=Path, default=DEFAULT_MATERIALIZED)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    failures = []

    required = (
        "user_profile.c",
        "user_profile.h",
        "user_profile_task.c",
        "user_profile_task.h",
        "ry02_ringcli_protocol.c",
        "ry02_ringcli_protocol.h",
    )

    for name in required:
        if not (args.overlay / name).is_file():
            failures.append(f"missing overlay file {name}")

    source_gate_status = "not checked"
    if args.source_gate.is_file():
        text = args.source_gate.read_text(encoding="utf-8", errors="replace")
        source_gate_status = (
            "PASS"
            if "required failures: 0" in text
            and "source gate: PASS" in text
            else "FAILED"
        )
        if source_gate_status != "PASS":
            failures.append("source-gate report is not a clean pass")
    else:
        failures.append(f"missing source-gate report {args.source_gate}")

    profile_path = args.overlay / "user_profile.c"
    if profile_path.is_file():
        profile = profile_path.read_text(encoding="utf-8", errors="replace")
        profile_bytes = extract_hex_bytes(profile)

        for name, expected in UUID_BYTES.items():
            expected_bytes = [
                int(value, 16)
                for value in expected.split()
            ]
            if not contains_subsequence(profile_bytes, expected_bytes):
                failures.append(f"missing UUID byte array {name}")

        for marker in (
            "command_att_db",
            "data_att_db",
            "PERM(WRITE_REQ, ENABLE)",
            "PERM(NTF, ENABLE)",
            "PERM(UUID_LEN, UUID_128)",
            "attm_svc_create_db_128",
        ):
            if marker not in profile:
                failures.append(f"profile missing marker {marker}")

    task_path = args.overlay / "user_profile_task.c"
    if task_path.is_file():
        task = task_path.read_text(encoding="utf-8", errors="replace")
        for marker in (
            "GATTC_WRITE_REQ_IND",
            "GATTC_SEND_EVT_CMD",
            "GATTC_NOTIFY",
            "GATTC_WRITE_CFM",
            "ry02_handle_command",
            "ry02_parse_data_request",
            "command_notify_enabled",
            "data_notify_enabled",
        ):
            if marker not in task:
                failures.append(f"task missing marker {marker}")

    materialized_status = "not present"
    if args.materialized.is_dir():
        materialized_status = "PASS"
        for relative in (
            "code/user_profile.c",
            "code/user_profile_task.c",
            "code/ry02_ringcli_protocol.c",
            "mdk/ble_custom_profile.uvprojx",
            "config/user_link.txt",
            "BUILD_ONLY.txt",
        ):
            if not (args.materialized / relative).is_file():
                failures.append(f"materialized tree missing {relative}")
                materialized_status = "FAILED"

        project = args.materialized / "mdk" / "ble_custom_profile.uvprojx"
        if project.is_file():
            project_text = project.read_text(
                encoding="utf-8",
                errors="replace",
            )
            for marker in (
                "ry02_ringcli_protocol.c",
                "ry02_ringcli_protocol.h",
                "startup_apollo00_ble.s",
                "user_link.txt",
            ):
                if marker not in project_text:
                    failures.append(f"project missing marker {marker}")
                    materialized_status = "FAILED"

        linker = args.materialized / "config" / "user_link.txt"
        if linker.is_file():
            linker_text = linker.read_text(
                encoding="utf-8",
                errors="replace",
            )
            if "0x00800000" not in linker_text:
                failures.append("generic SDK linker base changed")
                materialized_status = "FAILED"

    print("RY02 BLUEX SDK3 ADAPTER VALIDATION")
    print(f"source gate: {source_gate_status}")
    print(f"overlay files: {len(required)}")
    print(f"materialized tree: {materialized_status}")
    print("target R02 linker substitution: none")
    print("OTA packaging: none")
    print("device action: none")
    print()
    print(f"failures: {len(failures)}")
    for failure in failures:
        print(f"[FAIL] {failure}")

    status = "PASS" if not failures else "FAILED"
    print(f"adapter overlay status: {status}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
