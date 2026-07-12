#!/usr/bin/env python3
"""
Extract the exact BlueX SDK3 source contract needed for a build-only
RingCLI-compatible GATT adapter.

The tool is offline and read-only. It validates the selected SDK3 example,
prints file identities, extracts the custom 128-bit service database,
write/attribute-info handlers, notification send path, advertising setup,
startup file, and scatter/linker configuration.

It does not modify the SDK, build firmware, generate an OTA image, or interact
with the ring.
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import re
import sys
from pathlib import Path
from typing import Iterable, Sequence


TOOL_REVISION = "r2"
DEFAULT_SDK3 = Path("reference/bluex-sdk3-v3.3.8-20250117")

SELECTED_EXAMPLE = Path("examples/demo/ble_custom_profile")

FILES = {
    "profile_db": SELECTED_EXAMPLE / "code/user_profile.c",
    "profile_task": SELECTED_EXAMPLE / "code/user_profile_task.c",
    "profile_task_header": SELECTED_EXAMPLE / "code/user_profile_task.h",
    "profile_header": SELECTED_EXAMPLE / "code/user_profile.h",
    "app": SELECTED_EXAMPLE / "code/app.c",
    "app_header": SELECTED_EXAMPLE / "code/app.h",
    "ble": SELECTED_EXAMPLE / "code/ble.c",
    "ble_header": SELECTED_EXAMPLE / "code/ble.h",
    "project": SELECTED_EXAMPLE / "mdk/ble_custom_profile.uvprojx",
    "base_project": Path("examples/base/base/mdk/base.uvprojx"),
    "base_linker": Path("examples/base/base/config/user_link.txt"),
    "base_startup": Path("examples/base/base/code/startup_apollo00_ble.s"),
}

SECONDARY_FILES = {
    "led_profile_db": Path(
        "examples/demo/ble_led_control/code/profile/user_profile.c"
    ),
    "led_profile_task": Path(
        "examples/demo/ble_led_control/code/profile/user_profile_task.c"
    ),
    "report_profile_db": Path(
        "examples/demo/ble_report/code/profile/user_profile.c"
    ),
    "report_profile_task": Path(
        "examples/demo/ble_report/code/profile/user_profile_task.c"
    ),
    "report_ble": Path("examples/demo/ble_report/code/ble.c"),
    "speed_profile_db": Path(
        "examples/demo/ble_speed_test/code/user_profile.c"
    ),
    "speed_profile_task": Path(
        "examples/demo/ble_speed_test/code/user_profile_task.c"
    ),
    "speed_ble": Path("examples/demo/ble_speed_test/code/ble.c"),
}

REQUIRED_ANCHORS = {
    "profile_db": (
        "ATT_UUID_128_LEN",
        "PERM(UUID_LEN,UUID_128)",
        "attm_svc_create_db_128",
        "PERM(SVC_UUID_LEN,UUID_128)",
    ),
    "profile_task": (
        "GATTC_WRITE_REQ_IND",
        "gattc_write_req_ind_handler",
    ),
    "app": (
        "gapm_start_advertise_cmd",
        "ble_advertising_start",
    ),
    "ble": (
        "GAPM_START_ADVERTISE_CMD",
        "KE_MSG_ALLOC",
    ),
    "base_project": (
        "startup_apollo00_ble.s",
        "user_link.txt",
    ),
    "base_linker": (
        "FLASH_MAPPED_ADDR",
        "0x00800000",
    ),
    "base_startup": (
        "__Vectors",
        "Reset_Handler",
    ),
}

SEARCH_PATTERNS = {
    "profile_db": (
        r"#define\s+\w*(?:SVC|CHAR)\w*UUID_128",
        r"enum\s+\w*IDX",
        r"attm_desc_128",
        r"attm_svc_create_db_128",
        r"user_prf_init",
        r"PERM\(UUID_LEN,UUID_128\)",
        r"PERM\(SVC_UUID_LEN,UUID_128\)",
    ),
    "profile_task": (
        r"gattc_write_req_ind_handler",
        r"gattc_att_info_req_ind_handler",
        r"GATTC_WRITE_REQ_IND",
        r"GATTC_ATT_INFO_REQ_IND",
        r"GATTC_SEND_EVT_CMD",
        r"gattc_send_evt_cmd",
        r"user_profile_data_send",
        r"user_prf",
    ),
    "app": (
        r"gapm_start_advertise_cmd",
        r"ble_advertising_start",
        r"adv_data",
        r"scan_rsp",
        r"advert",
    ),
    "ble": (
        r"ble_advertising_start",
        r"GAPM_START_ADVERTISE_CMD",
        r"KE_MSG_ALLOC",
        r"ke_msg_send",
    ),
    "project": (
        r"startup_apollo00_ble",
        r"ScatterFile",
        r"user_link",
        r"OutputName",
        r"TargetName",
    ),
    "base_project": (
        r"startup_apollo00_ble",
        r"ScatterFile",
        r"user_link",
        r"OutputName",
        r"TargetName",
    ),
    "base_linker": (
        r"FLASH_MAPPED_ADDR",
        r"LOAD_REGION",
        r"EXEC_REGION",
        r"LR_",
        r"ER_",
        r"0x[0-9A-Fa-f]{6,8}",
    ),
    "base_startup": (
        r"__Vectors",
        r"Reset_Handler",
        r"BLE_LP_IRQHandler",
        r"BLE_MAC_IRQHandler",
        r"xip_section",
        r"Stack_Size",
        r"Heap_Size",
    ),
}

FULL_DUMP_KEYS = {
    "profile_db",
    "profile_task",
    "profile_task_header",
    "profile_header",
    "base_linker",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def line_numbered(text: str, start: int = 1) -> str:
    return "\n".join(
        f"{index:05d}: {line}"
        for index, line in enumerate(text.splitlines(), start=start)
    )


def merged_ranges(
    line_count: int,
    hit_lines: Iterable[int],
    before: int,
    after: int,
) -> list[tuple[int, int]]:
    raw = []
    for line in sorted(set(hit_lines)):
        raw.append((max(1, line - before), min(line_count, line + after)))

    merged: list[tuple[int, int]] = []
    for start, end in raw:
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def extract_windows(
    text: str,
    patterns: Sequence[str],
    before: int = 8,
    after: int = 18,
) -> tuple[list[tuple[int, int]], list[str]]:
    lines = text.splitlines()
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    hits = []

    for index, line in enumerate(lines, start=1):
        if any(pattern.search(line) for pattern in compiled):
            hits.append(index)

    ranges = merged_ranges(len(lines), hits, before, after)
    blocks = []
    for start, end in ranges:
        block = "\n".join(
            f"{line_no:05d}: {lines[line_no - 1]}"
            for line_no in range(start, end + 1)
        )
        blocks.append(block)

    return ranges, blocks


def find_all_sdk_examples(sdk3: Path) -> dict[str, list[str]]:
    roots = sdk3 / "examples"
    result = {
        "custom_128_db": [],
        "write_handler": [],
        "notify_send": [],
    }

    if not roots.is_dir():
        return result

    for path in roots.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".c", ".h"}:
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        relative = str(path.relative_to(sdk3))

        if (
            "PERM(UUID_LEN,UUID_128)" in text
            or "attm_svc_create_db_128" in text
        ):
            result["custom_128_db"].append(relative)

        if (
            "GATTC_WRITE_REQ_IND" in text
            and "gattc_write_req_ind_handler" in text
        ):
            result["write_handler"].append(relative)

        if (
            "GATTC_SEND_EVT_CMD" in text
            or "gattc_send_evt_cmd" in text
        ):
            result["notify_send"].append(relative)

    for values in result.values():
        values.sort()

    return result


def print_file_section(
    key: str,
    path: Path,
    patterns: Sequence[str] = (),
    full: bool = False,
) -> tuple[bool, list[str]]:
    print("=" * 116)
    print(f"FILE: {key}")
    print(f"path: {path}")

    if not path.is_file():
        print("status: MISSING")
        print()
        return False, []

    text = path.read_text(encoding="utf-8", errors="replace")
    print("status: present")
    print(f"size: {path.stat().st_size}")
    print(f"sha256: {sha256_file(path)}")
    print(f"lines: {len(text.splitlines())}")

    anchor_failures = []
    for anchor in REQUIRED_ANCHORS.get(key, ()):
        present = anchor in text
        print(f"anchor {anchor!r}: {'PASS' if present else 'FAIL'}")
        if not present:
            anchor_failures.append(anchor)

    if full:
        print()
        print("FULL CONTENT")
        print(line_numbered(text))
    elif patterns:
        ranges, blocks = extract_windows(text, patterns)
        print()
        print(f"matched windows: {len(ranges)}")
        for (start, end), block in zip(ranges, blocks):
            print()
            print(f"--- lines {start}..{end} ---")
            print(block)

    print()
    return True, anchor_failures


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Extract the exact SDK3 custom-profile source contract needed "
            "for a build-only RingCLI-compatible adapter."
        )
    )
    parser.add_argument("--sdk3", type=Path, default=DEFAULT_SDK3)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    sdk3 = args.sdk3

    print("RY02 BLUEX SDK3 RINGCLI ADAPTER SOURCE GATE")
    print(f"tool revision: {TOOL_REVISION}")
    print(f"Python: {platform.python_version()}")
    print(f"SDK3 root: {sdk3}")
    print(f"selected example: {SELECTED_EXAMPLE}")
    print()
    print("Interpretation boundary:")
    print("  source extraction only")
    print("  no SDK files are modified")
    print("  no firmware image is built")
    print("  no OTA or ring interaction occurs")
    print()

    failures = []
    identities = {}

    for key, relative in FILES.items():
        path = sdk3 / relative
        present, anchor_failures = print_file_section(
            key,
            path,
            SEARCH_PATTERNS.get(key, ()),
            full=key in FULL_DUMP_KEYS,
        )
        identities[key] = {
            "relative": str(relative),
            "present": present,
            "sha256": sha256_file(path) if present else None,
        }

        if not present:
            failures.append(f"missing {key}: {relative}")

        for anchor in anchor_failures:
            failures.append(f"{key} missing anchor: {anchor}")

    print("=" * 116)
    print("SECONDARY NOTIFICATION REFERENCES")
    for key, relative in SECONDARY_FILES.items():
        path = sdk3 / relative
        if not path.is_file():
            print(f"{key}: MISSING {relative}")
            continue

        text = path.read_text(encoding="utf-8", errors="replace")
        patterns = (
            r"GATTC_SEND_EVT_CMD",
            r"gattc_send_evt_cmd",
            r"GATTC_WRITE_REQ_IND",
            r"gattc_write_req_ind_handler",
            r"KE_MSG_ALLOC_DYN",
            r"operation\s*=",
            r"handle\s*=",
            r"length\s*=",
            r"seq_num\s*=",
            r"ke_msg_send",
        )
        ranges, blocks = extract_windows(text, patterns, before=6, after=16)
        print()
        print(f"{key}: {relative}")
        print(f"sha256: {sha256_file(path)}")
        print(f"matched windows: {len(ranges)}")
        for (start, end), block in zip(ranges, blocks):
            print(f"--- lines {start}..{end} ---")
            print(block)

    print()
    print("=" * 116)
    print("SDK3 EXAMPLE INDEX")
    index = find_all_sdk_examples(sdk3)
    for category, values in index.items():
        print()
        print(f"{category}: {len(values)}")
        for value in values:
            print(f"  {value}")

    print()
    print("=" * 116)
    print("SELECTED ADAPTER MODEL")
    print("base example:")
    print("  examples/demo/ble_custom_profile")
    print()
    print("service creation:")
    print("  128-bit UUID arrays in SDK byte order")
    print("  attm_svc_create_db_128")
    print("  attribute descriptors with PERM(UUID_LEN,UUID_128)")
    print()
    print("write path:")
    print("  GATTC_WRITE_REQ_IND")
    print("  gattc_write_req_ind_handler")
    print("  value handle selects command-write versus data-write")
    print()
    print("notify path:")
    print("  GATTC_SEND_EVT_CMD / gattc_send_evt_cmd")
    print("  command and data notify handles")
    print("  CCCD state must gate notifications")
    print()
    print("advertising path:")
    print("  gapm_start_advertise_cmd")
    print("  ble_advertising_start")
    print()
    print("build path:")
    print("  startup_apollo00_ble.s")
    print("  user_link.txt")
    print("  FLASH_MAPPED_ADDR 0x00800000 is generic SDK placement")
    print("  do not substitute the accepted R02 application base yet")

    print()
    print("=" * 116)
    print("SUMMARY")
    print(f"required failures: {len(failures)}")
    for failure in failures:
        print(f"[FAIL] {failure}")

    if failures:
        print("source gate: FAILED")
        return 1

    print("source gate: PASS")
    print("next decision: generate build-only SDK3 adapter overlay")
    print("device action: none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
