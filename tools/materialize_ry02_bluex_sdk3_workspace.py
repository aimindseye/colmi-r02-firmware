#!/usr/bin/env python3
"""
Create a compile-ready, build-only BlueX SDK3 workspace while preserving all
original project-relative paths.

The r1 materializer copied only examples/demo/ble_custom_profile. That was
sufficient for source/overlay validation but not for an actual Keil build,
because the .uvprojx references components through paths such as
../../../../components/... .

This r2 tool copies the complete SDK3 tree into build/, overlays the accepted
RingCLI adapter in place, disables HEX generation for the template target, and
validates every local FilePath in that target.

It never modifies the reference SDK, invokes a compiler, packages OTA, or
communicates with the ring.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence


TOOL_REVISION = "r2"

DEFAULT_SDK3 = Path("reference/bluex-sdk3-v3.3.8-20250117")
DEFAULT_OVERLAY = Path(
    "prototype/bluex_sdk3_ringcli_adapter/overlay/code"
)
DEFAULT_DESTINATION = Path(
    "build/ry02-bluex-sdk3-ringcli-workspace"
)

EXAMPLE_REL = Path("examples/demo/ble_custom_profile")
PROJECT_REL = EXAMPLE_REL / "mdk/ble_custom_profile.uvprojx"
APP_REL = EXAMPLE_REL / "code/app.c"
CODE_REL = EXAMPLE_REL / "code"
LINKER_REL = EXAMPLE_REL / "config/user_link.txt"
STARTUP_REL = EXAMPLE_REL / "code/startup_apollo00_ble.s"

OVERLAY_FILES = (
    "user_profile.c",
    "user_profile.h",
    "user_profile_task.c",
    "user_profile_task.h",
    "ry02_ringcli_protocol.c",
    "ry02_ringcli_protocol.h",
)

KEY_SOURCE_FILES = (
    PROJECT_REL,
    APP_REL,
    LINKER_REL,
    STARTUP_REL,
    Path("components/bluex/ble/controller/rom_syms_armcc.txt"),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_head(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip() or None


def key_manifest(root: Path) -> dict[str, str | None]:
    result = {}
    for relative in KEY_SOURCE_FILES:
        path = root / relative
        result[str(relative)] = sha256_file(path) if path.is_file() else None
    return result


def ignore_copy(directory: str, names: list[str]) -> set[str]:
    ignored = set()
    for name in names:
        if name in {
            ".git",
            ".DS_Store",
            "__pycache__",
            "Objects",
            "Listings",
        }:
            ignored.add(name)
        elif name.endswith((".pyc", ".pyo")):
            ignored.add(name)
    return ignored


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


def add_project_file(
    group: ET.Element,
    name: str,
    file_type: str,
    file_path: str,
) -> None:
    files = group.find("Files")
    if files is None:
        files = ET.SubElement(group, "Files")

    for file_node in files.findall("File"):
        if file_node.findtext("FileName") == name:
            path_node = file_node.find("FilePath")
            if path_node is not None:
                path_node.text = file_path
            return

    file_node = ET.SubElement(files, "File")
    ET.SubElement(file_node, "FileName").text = name
    ET.SubElement(file_node, "FileType").text = file_type
    ET.SubElement(file_node, "FilePath").text = file_path


def find_target(root: ET.Element, name: str) -> ET.Element:
    for target in root.findall("./Targets/Target"):
        if target.findtext("TargetName") == name:
            return target
    raise RuntimeError(f"target not found: {name}")


def patch_project(project_path: Path) -> None:
    tree = ET.parse(project_path)
    root = tree.getroot()
    target = find_target(root, "template")

    groups = target.find("Groups")
    if groups is None:
        raise RuntimeError("Groups node not found in template target")

    selected_group = None
    for group in groups.findall("Group"):
        files = group.find("Files")
        if files is None:
            continue
        names = {
            node.findtext("FileName")
            for node in files.findall("File")
        }
        if "user_profile.c" in names:
            selected_group = group
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

    output_name = target.find(
        "./TargetOption/TargetCommonOption/OutputName"
    )
    if output_name is not None:
        output_name.text = "ry02_ringcli_adapter_buildonly"

    create_hex = target.find(
        "./TargetOption/TargetCommonOption/CreateHexFile"
    )
    if create_hex is not None:
        create_hex.text = "0"

    ET.indent(tree, space="  ")
    tree.write(project_path, encoding="utf-8", xml_declaration=True)


def resolve_project_paths(project_path: Path) -> dict:
    tree = ET.parse(project_path)
    root = tree.getroot()
    target = find_target(root, "template")
    project_dir = project_path.parent

    checked = []
    unresolved = []

    for file_path_node in target.findall(".//FilePath"):
        raw = (file_path_node.text or "").strip()
        if not raw:
            continue

        if "$" in raw or raw.startswith(("/", "\\")):
            continue

        normalized = raw.replace("\\", "/")
        resolved = (project_dir / normalized).resolve()
        entry = {
            "raw": raw,
            "resolved": str(resolved),
            "exists": resolved.is_file(),
        }
        checked.append(entry)
        if not entry["exists"]:
            unresolved.append(entry)

    scatter_node = target.find(
        "./TargetOption/TargetArmAds/LDads/ScatterFile"
    )
    scatter_raw = (
        (scatter_node.text or "").strip()
        if scatter_node is not None
        else ""
    )
    scatter_resolved = None
    if scatter_raw:
        scatter_resolved = (
            project_dir / scatter_raw.replace("\\", "/")
        ).resolve()

    return {
        "checked": checked,
        "unresolved": unresolved,
        "scatter_raw": scatter_raw,
        "scatter_resolved": (
            str(scatter_resolved)
            if scatter_resolved is not None
            else None
        ),
        "scatter_exists": (
            scatter_resolved.is_file()
            if scatter_resolved is not None
            else False
        ),
    }


def validate_workspace(
    source: Path,
    destination: Path,
    source_before: dict,
) -> dict:
    failures = []

    project = destination / PROJECT_REL
    app = destination / APP_REL
    linker = destination / LINKER_REL
    startup = destination / STARTUP_REL
    code = destination / CODE_REL

    for path in (project, app, linker, startup):
        if not path.is_file():
            failures.append(f"missing workspace file: {path}")

    for name in OVERLAY_FILES:
        if not (code / name).is_file():
            failures.append(f"missing overlay file: {code / name}")

    path_report = {
        "checked": [],
        "unresolved": [],
        "scatter_exists": False,
    }
    if project.is_file():
        path_report = resolve_project_paths(project)
        for entry in path_report["unresolved"]:
            failures.append(
                "unresolved project FilePath: "
                f"{entry['raw']} -> {entry['resolved']}"
            )
        if not path_report["scatter_exists"]:
            failures.append(
                "scatter file does not resolve: "
                f"{path_report.get('scatter_raw')}"
            )

        project_text = project.read_text(
            encoding="utf-8",
            errors="replace",
        )
        for marker in (
            "ry02_ringcli_protocol.c",
            "ry02_ringcli_protocol.h",
            "startup_apollo00_ble.s",
            "user_link.txt",
            "<CreateHexFile>0</CreateHexFile>",
            "<OutputName>ry02_ringcli_adapter_buildonly</OutputName>",
        ):
            if marker not in project_text:
                failures.append(f"project missing marker: {marker}")

    if linker.is_file():
        linker_text = linker.read_text(
            encoding="utf-8",
            errors="replace",
        )
        if "0x00800000" not in linker_text:
            failures.append("generic SDK linker base changed")

    if app.is_file():
        app_text = app.read_text(
            encoding="utf-8",
            errors="replace",
        )
        if "'R','0','2','_','F','1','0','3'" not in app_text:
            failures.append("advertising name patch missing")

    source_after = key_manifest(source)
    if source_before != source_after:
        failures.append("reference SDK key-file manifest changed")

    forbidden = (
        "0x00824000",
        "0x824000",
        "0x0084D000",
        "0x84D000",
        "RY02_3.00.38_250403.bin",
    )

    for name in OVERLAY_FILES:
        path = code / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in forbidden:
            if marker in text:
                failures.append(
                    f"overlay contains forbidden target marker "
                    f"{marker}: {path}"
                )

    return {
        "schema": "ry02.bluex-sdk3-workspace-materialization.v2",
        "tool_revision": TOOL_REVISION,
        "source": str(source),
        "source_git_head": git_head(source),
        "destination": str(destination),
        "source_key_manifest_before": source_before,
        "source_key_manifest_after": source_after,
        "project_paths_checked": len(path_report.get("checked", [])),
        "unresolved_project_paths": path_report.get("unresolved", []),
        "scatter_file": path_report.get("scatter_resolved"),
        "scatter_exists": path_report.get("scatter_exists", False),
        "failures": failures,
        "status": "PASS" if not failures else "FAILED",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk3", type=Path, default=DEFAULT_SDK3)
    parser.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY)
    parser.add_argument(
        "--destination",
        type=Path,
        default=DEFAULT_DESTINATION,
    )
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--json-out", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.sdk3.is_dir():
        print(f"[FAIL] SDK3 root not found: {args.sdk3}")
        return 2

    missing_overlay = [
        name
        for name in OVERLAY_FILES
        if not (args.overlay / name).is_file()
    ]
    if missing_overlay:
        for name in missing_overlay:
            print(f"[FAIL] missing overlay source: {args.overlay / name}")
        return 2

    source_before = key_manifest(args.sdk3)
    missing_keys = [
        relative
        for relative, digest in source_before.items()
        if digest is None
    ]
    if missing_keys:
        for relative in missing_keys:
            print(f"[FAIL] missing SDK3 key file: {relative}")
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

    shutil.copytree(
        args.sdk3,
        args.destination,
        ignore=ignore_copy,
    )

    destination_code = args.destination / CODE_REL
    for name in OVERLAY_FILES:
        shutil.copy2(
            args.overlay / name,
            destination_code / name,
        )

    replace_advertising_name(args.destination / APP_REL)
    patch_project(args.destination / PROJECT_REL)

    (args.destination / "BUILD_ONLY.txt").write_text(
        "RY02 BlueX SDK3 RingCLI workspace\n"
        "Complete SDK copy with project-relative paths preserved.\n"
        "Generic linker retained at 0x00800000.\n"
        "HEX generation disabled for template target.\n"
        "No OTA packaging or device installation authorized.\n",
        encoding="utf-8",
    )

    result = validate_workspace(
        args.sdk3,
        args.destination,
        source_before,
    )

    print("RY02 BLUEX SDK3 COMPILE-WORKSPACE MATERIALIZATION")
    print(f"tool revision: {TOOL_REVISION}")
    print(f"source SDK: {args.sdk3}")
    print(f"source git HEAD: {result['source_git_head'] or 'unresolved'}")
    print(f"destination: {args.destination}")
    print("complete SDK tree copied: yes")
    print("project-relative paths preserved: yes")
    print("source SDK modified: no")
    print("generic linker retained: yes")
    print("HEX generation enabled: no")
    print("compiler invoked: no")
    print("OTA packaging invoked: no")
    print("device action: none")
    print()
    print(
        "project FilePath entries checked: "
        f"{result['project_paths_checked']}"
    )
    print(
        "unresolved project paths: "
        f"{len(result['unresolved_project_paths'])}"
    )
    print(f"scatter file: {result['scatter_file']}")
    print(f"scatter exists: {result['scatter_exists']}")
    print()
    print(f"validation failures: {len(result['failures'])}")
    for failure in result["failures"]:
        print(f"[FAIL] {failure}")
    print(f"workspace status: {result['status']}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
