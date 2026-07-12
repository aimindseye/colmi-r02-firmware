#!/usr/bin/env python3
"""
Materialize a build-only SDK3 RingCLI-compatible adapter project.

The source SDK is never modified. The selected ble_custom_profile example is
copied into a build directory, then the verified adapter files are overlaid.

No compiler, image tool, OTA packager, or device command is invoked.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence


DEFAULT_SDK3 = Path("reference/bluex-sdk3-v3.3.8-20250117")
DEFAULT_OVERLAY = Path(
    "prototype/bluex_sdk3_ringcli_adapter/overlay/code"
)
DEFAULT_DESTINATION = Path("build/ry02-bluex-sdk3-ringcli-adapter")

EXAMPLE = Path("examples/demo/ble_custom_profile")

REQUIRED_SDK_FILES = (
    "code/user_profile.c",
    "code/user_profile.h",
    "code/user_profile_task.c",
    "code/user_profile_task.h",
    "code/app.c",
    "code/ble.c",
    "mdk/ble_custom_profile.uvprojx",
    "config/user_link.txt",
    "code/startup_apollo00_ble.s",
)

OVERLAY_FILES = (
    "user_profile.c",
    "user_profile.h",
    "user_profile_task.c",
    "user_profile_task.h",
    "ry02_ringcli_protocol.c",
    "ry02_ringcli_protocol.h",
)


def replace_advertising_name(app_path: Path) -> None:
    text = app_path.read_text(encoding="utf-8", errors="replace")

    scan_pattern = re.compile(
        r"uint8_t\s+user_scan_rsp_data\[\]\s*=\s*\{.*?\};",
        re.DOTALL,
    )
    adv_pattern = re.compile(
        r"uint8_t\s+user_adv_data\[\]\s*=\s*\{.*?\};",
        re.DOTALL,
    )

    scan_replacement = """uint8_t user_scan_rsp_data[] = {
    0x09,
    GAP_AD_TYPE_COMPLETE_NAME,
    'R','0','2','_','F','1','0','3'
};"""

    adv_replacement = """uint8_t user_adv_data[] = {
    0x09,
    GAP_AD_TYPE_SHORTENED_NAME,
    'R','0','2','_','F','1','0','3'
};"""

    text, scan_count = scan_pattern.subn(scan_replacement, text, count=1)
    text, adv_count = adv_pattern.subn(adv_replacement, text, count=1)

    if scan_count != 1 or adv_count != 1:
        raise RuntimeError(
            "unable to patch SDK3 advertising arrays "
            f"(scan={scan_count}, adv={adv_count})"
        )

    app_path.write_text(text, encoding="utf-8")


def add_project_file(group: ET.Element, name: str, file_type: str, path: str) -> None:
    files = group.find("Files")
    if files is None:
        files = ET.SubElement(group, "Files")

    for file_node in files.findall("File"):
        existing = file_node.findtext("FileName")
        if existing == name:
            return

    file_node = ET.SubElement(files, "File")
    ET.SubElement(file_node, "FileName").text = name
    ET.SubElement(file_node, "FileType").text = file_type
    ET.SubElement(file_node, "FilePath").text = path


def patch_project(project_path: Path) -> None:
    tree = ET.parse(project_path)
    root = tree.getroot()

    target = None
    for candidate in root.findall("./Targets/Target"):
        if candidate.findtext("TargetName") == "template":
            target = candidate
            break

    if target is None:
        raise RuntimeError("template target not found in uvprojx")

    selected_group = None
    groups = target.find("Groups")
    if groups is None:
        raise RuntimeError("Groups node not found in uvprojx")

    for group in groups.findall("Group"):
        files = group.find("Files")
        if files is None:
            continue
        names = {
            node.findtext("FileName")
            for node in files.findall("File")
        }
        if "user_profile.c" in names or "app.c" in names:
            selected_group = group
            if "user_profile.c" in names:
                break

    if selected_group is None:
        selected_group = ET.SubElement(groups, "Group")
        ET.SubElement(selected_group, "GroupName").text = "ry02/ringcli"

    add_project_file(
        selected_group,
        "ry02_ringcli_protocol.c",
        "1",
        r"..\code\ry02_ringcli_protocol.c",
    )
    add_project_file(
        selected_group,
        "ry02_ringcli_protocol.h",
        "5",
        r"..\code\ry02_ringcli_protocol.h",
    )

    ET.indent(tree, space="  ")
    tree.write(project_path, encoding="utf-8", xml_declaration=True)


def validate_materialized(destination: Path) -> dict:
    code = destination / "code"
    project = destination / "mdk" / "ble_custom_profile.uvprojx"
    linker = destination / "config" / "user_link.txt"

    required_markers = {
        code / "user_profile.c": (
            "RY02_COMMAND_SERVICE_UUID_128",
            "RY02_DATA_SERVICE_UUID_128",
            "attm_svc_create_db_128",
            "command_att_db",
            "data_att_db",
        ),
        code / "user_profile_task.c": (
            "GATTC_WRITE_REQ_IND",
            "GATTC_SEND_EVT_CMD",
            "ry02_handle_command",
            "ry02_parse_data_request",
            "command_notify_enabled",
            "data_notify_enabled",
        ),
        code / "ry02_ringcli_protocol.c": (
            "ry02_handle_command",
            "ry02_make_realtime_value_notification",
        ),
        code / "app.c": (
            "'R','0','2','_','F','1','0','3'",
            "ble_advertising_start",
        ),
        project: (
            "ry02_ringcli_protocol.c",
            "ry02_ringcli_protocol.h",
            "startup_apollo00_ble.s",
            "user_link.txt",
        ),
        linker: (
            "FLASH_MAPPED_ADDR",
            "0x00800000",
        ),
    }

    failures = []

    for path, markers in required_markers.items():
        if not path.is_file():
            failures.append(f"missing {path}")
            continue

        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in markers:
            if marker not in text:
                failures.append(f"{path}: missing marker {marker}")

    forbidden = (
        "0x00824000",
        "0x824000",
        "0x0084D000",
        "0x84D000",
        "RY02_3.00.38_250403.bin",
    )

    for path in code.glob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in forbidden:
            if marker in text:
                failures.append(f"{path}: forbidden target marker {marker}")

    return {
        "destination": str(destination),
        "failures": failures,
        "status": "PASS" if not failures else "FAILED",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk3", type=Path, default=DEFAULT_SDK3)
    parser.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--json-out", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    source = args.sdk3 / EXAMPLE

    missing = [
        relative
        for relative in REQUIRED_SDK_FILES
        if not (source / relative).is_file()
    ]

    if missing:
        for relative in missing:
            print(f"[FAIL] missing SDK source: {source / relative}")
        return 2

    missing_overlay = [
        name for name in OVERLAY_FILES
        if not (args.overlay / name).is_file()
    ]

    if missing_overlay:
        for name in missing_overlay:
            print(f"[FAIL] missing overlay source: {args.overlay / name}")
        return 2

    if args.destination.exists():
        if not args.force:
            print(
                f"destination exists: {args.destination}; "
                "pass --force to replace it",
                file=sys.stderr,
            )
            return 2
        shutil.rmtree(args.destination)

    args.destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, args.destination)

    for name in OVERLAY_FILES:
        shutil.copy2(args.overlay / name, args.destination / "code" / name)

    replace_advertising_name(args.destination / "code" / "app.c")
    patch_project(
        args.destination / "mdk" / "ble_custom_profile.uvprojx"
    )

    marker = args.destination / "BUILD_ONLY.txt"
    marker.write_text(
        "RY02 BlueX SDK3 RingCLI adapter\n"
        "Build-only source tree.\n"
        "Generic SDK linker retained.\n"
        "No OTA packaging or device installation authorized.\n",
        encoding="utf-8",
    )

    result = validate_materialized(args.destination)

    print("RY02 BLUEX SDK3 ADAPTER MATERIALIZATION")
    print(f"source: {source}")
    print(f"destination: {args.destination}")
    print("source SDK modified: no")
    print("generic linker retained: yes")
    print("OTA packaging invoked: no")
    print("device action: none")
    print()
    print(f"validation failures: {len(result['failures'])}")
    for failure in result["failures"]:
        print(f"[FAIL] {failure}")
    print(f"materialization status: {result['status']}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
