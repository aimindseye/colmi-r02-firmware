#!/usr/bin/env python3
"""
Inspect whether the accepted complete SDK3 workspace and an ARMCC 5 / Keil
uVision build environment are available.

This tool never invokes the compiler or modifies the workspace.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence


TOOL_REVISION = "r2"
DEFAULT_WORKSPACE = Path("build/ry02-bluex-sdk3-ringcli-workspace")
PROJECT_REL = Path(
    "examples/demo/ble_custom_profile/mdk/ble_custom_profile.uvprojx"
)


def existing_file(candidates: list[Path]) -> Path | None:
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def which_path(name: str) -> Path | None:
    value = shutil.which(name)
    return Path(value).resolve() if value else None


def uv4_candidates(explicit: Path | None) -> list[Path]:
    result: list[Path] = []

    if explicit is not None:
        result.append(explicit)

    for key in ("UV4_PATH", "KEIL_UV4"):
        value = os.environ.get(key)
        if value:
            result.append(Path(value))

    result.extend(
        (
            Path(r"C:\Keil_v5\UV4\UV4.exe"),
            Path(r"C:\Keil\UV4\UV4.exe"),
        )
    )

    found = which_path("UV4.exe") or which_path("UV4")
    if found is not None:
        result.append(found)

    return result


def armcc_bin_candidates(explicit: Path | None) -> list[Path]:
    result: list[Path] = []

    if explicit is not None:
        result.append(explicit)

    for key in ("ARMCC5_BIN", "ARMCC_BIN"):
        value = os.environ.get(key)
        if value:
            result.append(Path(value))

    result.extend(
        (
            Path(r"C:\Keil_v5\ARM\ARMCC\bin"),
            Path(r"C:\Keil\ARM\ARMCC\bin"),
        )
    )
    return result


def find_tool(name: str, bins: list[Path]) -> Path | None:
    suffixes = (".exe", "") if platform.system() == "Windows" else ("", ".exe")

    for directory in bins:
        for suffix in suffixes:
            candidate = directory / f"{name}{suffix}"
            if candidate.is_file():
                return candidate.resolve()

    return which_path(name) or which_path(f"{name}.exe")


def project_settings(project: Path) -> dict:
    tree = ET.parse(project)
    root = tree.getroot()

    target = None
    for candidate in root.findall("./Targets/Target"):
        if candidate.findtext("TargetName") == "template":
            target = candidate
            break

    if target is None:
        raise RuntimeError("template target not found")

    return {
        "toolset": target.findtext("ToolsetName"),
        "compiler": (
            target.findtext("pCCUsed")
            or target.findtext(
                "./TargetOption/TargetCommonOption/pCCUsed"
            )
        ),
        "output_name": target.findtext(
            "./TargetOption/TargetCommonOption/OutputName"
        ),
        "create_hex": target.findtext(
            "./TargetOption/TargetCommonOption/CreateHexFile"
        ),
        "scatter": target.findtext(
            "./TargetOption/TargetArmAds/LDads/ScatterFile"
        ),
    }


def query_version(tool: Path) -> str:
    for argument in ("--vsn", "--version", "-V"):
        try:
            completed = subprocess.run(
                [str(tool), argument],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue

        text = (completed.stdout + completed.stderr).strip()
        if text:
            return text.splitlines()[0][:300]

    return "version query unavailable"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    parser.add_argument("--uv4", type=Path)
    parser.add_argument("--armcc-bin", type=Path)
    parser.add_argument("--json-out", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    failures = []

    project = args.workspace / PROJECT_REL
    if not project.is_file():
        failures.append(f"project missing: {project}")
        settings = {}
    else:
        try:
            settings = project_settings(project)
        except Exception as exc:
            settings = {}
            failures.append(f"project parse failed: {exc}")

    if settings:
        if settings.get("toolset") != "ARM-ADS":
            failures.append(
                f"unexpected toolset: {settings.get('toolset')!r}"
            )

        compiler = settings.get("compiler") or ""
        if "V5.06" not in compiler and "ARMCC" not in compiler:
            failures.append(
                f"unexpected compiler declaration: {compiler!r}"
            )

        if settings.get("create_hex") != "0":
            failures.append("template target still enables HEX generation")
        if settings.get("output_name") != "ry02_ringcli_adapter_buildonly":
            failures.append(
                f"unexpected output name: {settings.get('output_name')!r}"
            )

    uv4 = existing_file(uv4_candidates(args.uv4))
    bins = armcc_bin_candidates(args.armcc_bin)
    armcc = find_tool("armcc", bins)
    armasm = find_tool("armasm", bins)
    armlink = find_tool("armlink", bins)
    fromelf = find_tool("fromelf", bins)

    toolchain_complete = all(
        value is not None
        for value in (uv4, armcc, armasm, armlink, fromelf)
    )

    print("RY02 BLUEX ARMCC5 ENVIRONMENT INSPECTION")
    print(f"tool revision: {TOOL_REVISION}")
    print(f"host: {platform.system()} {platform.machine()}")
    print(f"workspace: {args.workspace}")
    print(f"project: {project}")
    print()
    print("project settings:")
    for key in (
        "toolset",
        "compiler",
        "output_name",
        "create_hex",
        "scatter",
    ):
        print(f"  {key}: {settings.get(key, 'unresolved')}")
    print()
    print("toolchain:")
    print(f"  UV4: {uv4 or 'not found'}")
    print(f"  armcc: {armcc or 'not found'}")
    print(f"  armasm: {armasm or 'not found'}")
    print(f"  armlink: {armlink or 'not found'}")
    print(f"  fromelf: {fromelf or 'not found'}")

    versions = {}
    for name, path in (
        ("armcc", armcc),
        ("armasm", armasm),
        ("armlink", armlink),
        ("fromelf", fromelf),
    ):
        if path is not None:
            versions[name] = query_version(path)
            print(f"  {name} version: {versions[name]}")

    print()
    print(f"workspace failures: {len(failures)}")
    for failure in failures:
        print(f"[FAIL] {failure}")
    print(f"ARMCC5 toolchain complete: {toolchain_complete}")
    print("compiler invoked: no")
    print("OTA packaging: none")
    print("device action: none")

    if failures:
        status = "WORKSPACE_FAILED"
        exit_code = 1
    elif not toolchain_complete:
        status = "TOOLCHAIN_UNAVAILABLE"
        exit_code = 3
    else:
        status = "READY_FOR_COMPILE"
        exit_code = 0

    print(f"environment status: {status}")

    if args.json_out:
        payload = {
            "schema": "ry02.bluex-armcc5-environment.v1",
            "tool_revision": TOOL_REVISION,
            "host": {
                "system": platform.system(),
                "machine": platform.machine(),
            },
            "workspace": str(args.workspace),
            "project": str(project),
            "project_settings": settings,
            "tools": {
                "uv4": str(uv4) if uv4 else None,
                "armcc": str(armcc) if armcc else None,
                "armasm": str(armasm) if armasm else None,
                "armlink": str(armlink) if armlink else None,
                "fromelf": str(fromelf) if fromelf else None,
            },
            "versions": versions,
            "failures": failures,
            "toolchain_complete": toolchain_complete,
            "status": status,
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
