#!/usr/bin/env python3
"""Validate an r2 complete-SDK compile workspace."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence


DEFAULT_WORKSPACE = Path(
    "build/ry02-bluex-sdk3-ringcli-workspace"
)
DEFAULT_REPORT = Path(
    "analysis/ry02-bluex-sdk3-workspace-materialization.json"
)

PROJECT_REL = Path(
    "examples/demo/ble_custom_profile/mdk/ble_custom_profile.uvprojx"
)
LINKER_REL = Path(
    "examples/demo/ble_custom_profile/config/user_link.txt"
)
CODE_REL = Path(
    "examples/demo/ble_custom_profile/code"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    failures = []

    if not args.workspace.is_dir():
        failures.append(f"workspace missing: {args.workspace}")

    report = None
    if args.report.is_file():
        report = json.loads(args.report.read_text(encoding="utf-8"))
        if report.get("status") != "PASS":
            failures.append("materialization report is not PASS")
        if report.get("unresolved_project_paths"):
            failures.append("materialization report has unresolved paths")
        if not report.get("scatter_exists"):
            failures.append("scatter file was not resolved")
    else:
        failures.append(f"report missing: {args.report}")

    required = (
        PROJECT_REL,
        LINKER_REL,
        CODE_REL / "startup_apollo00_ble.s",
        CODE_REL / "user_profile.c",
        CODE_REL / "user_profile_task.c",
        CODE_REL / "ry02_ringcli_protocol.c",
        CODE_REL / "ry02_ringcli_protocol.h",
        Path("components/bluex/ble/controller/rom_syms_armcc.txt"),
        Path("BUILD_ONLY.txt"),
    )

    for relative in required:
        if not (args.workspace / relative).is_file():
            failures.append(f"workspace file missing: {relative}")

    project = args.workspace / PROJECT_REL
    if project.is_file():
        text = project.read_text(encoding="utf-8", errors="replace")
        for marker in (
            "<TargetName>template</TargetName>",
            "<ToolsetName>ARM-ADS</ToolsetName>",
            "ry02_ringcli_protocol.c",
            "ry02_ringcli_protocol.h",
            "startup_apollo00_ble.s",
            "user_link.txt",
            "<CreateHexFile>0</CreateHexFile>",
            "<OutputName>ry02_ringcli_adapter_buildonly</OutputName>",
        ):
            if marker not in text:
                failures.append(f"project missing marker: {marker}")

    linker = args.workspace / LINKER_REL
    if linker.is_file():
        text = linker.read_text(encoding="utf-8", errors="replace")
        if "0x00800000" not in text:
            failures.append("generic SDK linker base changed")

    print("RY02 BLUEX SDK3 COMPILE-WORKSPACE VALIDATION")
    print(f"workspace: {args.workspace}")
    print(f"materialization report: {args.report}")
    print("full SDK-relative layout required: yes")
    print("generic linker retained: yes")
    print("HEX generation enabled: no")
    print("compiler invoked: no")
    print("OTA packaging: none")
    print("device action: none")
    print()
    print(f"failures: {len(failures)}")
    for failure in failures:
        print(f"[FAIL] {failure}")

    status = "PASS" if not failures else "FAILED"
    print(f"compile-workspace status: {status}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
