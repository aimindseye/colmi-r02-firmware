#!/usr/bin/env python3
"""
Verify the first build-only ARMCC 5 compilation of the materialized SDK3
RingCLI adapter.

The gate requires:
  * template target still has HEX generation disabled;
  * uVision log reports zero errors;
  * expected AXF exists and is non-empty;
  * no HEX/BIN/OTA artifact was generated.

Warnings are reported but do not fail r1.
"""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence


DEFAULT_WORKSPACE = Path("build/ry02-bluex-sdk3-ringcli-workspace")
PROJECT_REL = Path(
    "examples/demo/ble_custom_profile/mdk/ble_custom_profile.uvprojx"
)
DEFAULT_LOG_REL = Path(
    "examples/demo/ble_custom_profile/mdk/ry02-bluex-armcc5-build.log"
)


def target_settings(project: Path) -> dict:
    tree = ET.parse(project)
    root = tree.getroot()

    for target in root.findall("./Targets/Target"):
        if target.findtext("TargetName") == "template":
            common = target.find("./TargetOption/TargetCommonOption")
            if common is None:
                raise RuntimeError("TargetCommonOption missing")
            return {
                "output_directory": common.findtext("OutputDirectory"),
                "output_name": common.findtext("OutputName"),
                "create_hex": common.findtext("CreateHexFile"),
                "toolset": target.findtext("ToolsetName"),
                "compiler": common.findtext("pCCUsed"),
            }

    raise RuntimeError("template target not found")


def parse_build_log(text: str) -> dict:
    errors = None
    warnings = None

    patterns = (
        re.compile(
            r"(?P<errors>\d+)\s+Error\(s\),\s*"
            r"(?P<warnings>\d+)\s+Warning\(s\)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?P<errors>\d+)\s+Errors?,\s*"
            r"(?P<warnings>\d+)\s+Warnings?",
            re.IGNORECASE,
        ),
    )

    for pattern in patterns:
        matches = list(pattern.finditer(text))
        if matches:
            match = matches[-1]
            errors = int(match.group("errors"))
            warnings = int(match.group("warnings"))
            break

    if errors is None and re.search(
        r"\b0\s+Error\(s\)",
        text,
        re.IGNORECASE,
    ):
        errors = 0

    fatal_markers = [
        line
        for line in text.splitlines()
        if re.search(
            r"\b(?:fatal error|build failed|error L\d+|error C\d+)",
            line,
            re.IGNORECASE,
        )
    ][:50]

    return {
        "errors": errors,
        "warnings": warnings,
        "fatal_markers": fatal_markers,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--json-out", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    failures = []

    project = args.workspace / PROJECT_REL
    log_path = args.log or (args.workspace / DEFAULT_LOG_REL)

    if not project.is_file():
        failures.append(f"project missing: {project}")
        settings = {}
    else:
        try:
            settings = target_settings(project)
        except Exception as exc:
            settings = {}
            failures.append(f"project parse failed: {exc}")

    if settings:
        if settings.get("toolset") != "ARM-ADS":
            failures.append(
                f"unexpected toolset: {settings.get('toolset')!r}"
            )
        if settings.get("create_hex") != "0":
            failures.append("HEX generation is not disabled")
        if settings.get("output_name") != "ry02_ringcli_adapter_buildonly":
            failures.append(
                f"unexpected output name: {settings.get('output_name')!r}"
            )

    output_directory = settings.get("output_directory") or r".\Objects\\"
    output_name = settings.get("output_name") or "ry02_ringcli_adapter_buildonly"

    mdk_dir = project.parent
    objects = (
        mdk_dir / output_directory.replace("\\", "/")
    ).resolve()
    axf = objects / f"{output_name}.axf"

    if not log_path.is_file():
        failures.append(f"build log missing: {log_path}")
        log_info = {
            "errors": None,
            "warnings": None,
            "fatal_markers": [],
        }
    else:
        log_info = parse_build_log(
            log_path.read_text(encoding="utf-8", errors="replace")
        )
        if log_info["errors"] is None:
            failures.append("unable to parse error count from build log")
        elif log_info["errors"] != 0:
            failures.append(
                f"build log reports {log_info['errors']} errors"
            )
        if log_info["fatal_markers"]:
            failures.append("fatal/error markers found in build log")

    if not axf.is_file():
        failures.append(f"AXF missing: {axf}")
    elif axf.stat().st_size == 0:
        failures.append(f"AXF is empty: {axf}")

    forbidden_artifacts = []
    if objects.is_dir():
        for pattern in ("*.hex", "*.bin", "*.ota", "*.38"):
            forbidden_artifacts.extend(objects.rglob(pattern))

    if forbidden_artifacts:
        failures.append(
            "installable/packaged artifacts were generated: "
            + ", ".join(str(path) for path in forbidden_artifacts)
        )

    print("RY02 BLUEX ARMCC5 COMPILE GATE")
    print(f"workspace: {args.workspace}")
    print(f"project: {project}")
    print("target: template")
    print(f"build log: {log_path}")
    print(f"objects: {objects}")
    print(f"AXF: {axf}")
    print()
    print("project settings:")
    print(f"  toolset: {settings.get('toolset', 'unresolved')}")
    print(f"  compiler: {settings.get('compiler', 'unresolved')}")
    print(f"  output name: {settings.get('output_name', 'unresolved')}")
    print(f"  HEX generation: {settings.get('create_hex', 'unresolved')}")
    print()
    print(f"log errors: {log_info['errors']}")
    print(f"log warnings: {log_info['warnings']}")
    print(f"AXF present: {axf.is_file()}")
    print(f"AXF size: {axf.stat().st_size if axf.is_file() else 0}")
    print(f"forbidden artifacts: {len(forbidden_artifacts)}")
    print("OTA packaging: none")
    print("device action: none")
    print()
    print(f"failures: {len(failures)}")
    for failure in failures:
        print(f"[FAIL] {failure}")

    status = "PASS" if not failures else "FAILED"
    print(f"ARMCC5 compile gate: {status}")

    if args.json_out:
        payload = {
            "schema": "ry02.bluex-armcc5-compile-gate.v1",
            "workspace": str(args.workspace),
            "project": str(project),
            "target": "template",
            "log": str(log_path),
            "objects": str(objects),
            "axf": str(axf),
            "project_settings": settings,
            "log_info": log_info,
            "axf_present": axf.is_file(),
            "axf_size": axf.stat().st_size if axf.is_file() else 0,
            "forbidden_artifacts": [
                str(path) for path in forbidden_artifacts
            ],
            "failures": failures,
            "status": status,
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
