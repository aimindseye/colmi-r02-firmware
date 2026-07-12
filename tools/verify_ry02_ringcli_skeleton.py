#!/usr/bin/env python3
"""Build and test the host-only RY02 RingCLI protocol skeleton."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


EXPECTED_FIXTURES = {
    "battery_request": "03000000000000000000000000000003",
    "flash_led_request": "10000000000000000000000000000010",
    "heart_period_get": "16010000000000000000000000000017",
    "heart_period_set_enabled_60": "1602013c000000000000000000000055",
    "oxygen_data_request": "bc2a0000ffff",
    "realtime_hr_batch_continue": "6901030000000000000000000000006d",
    "realtime_hr_batch_start": "6901010000000000000000000000006b",
    "realtime_hr_batch_stop": "6a01000000000000000000000000006b",
    "set_time_2025_04_09_12_34_56_en": "012504091234560100000000000000d0",
    "shutdown_request": "08010000000000000000000000000009",
    "sleep_data_request": "bc270000ffff",
    "steps_offset_0": "43000f005f01000000000000000000b2",
}


def run(command: list[str], *, cwd: Path | None = None) -> None:
    print("+", " ".join(command))
    subprocess.run(command, cwd=cwd, check=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("prototype/ringcli_compat"),
    )
    parser.add_argument(
        "--contract-json",
        type=Path,
        default=Path("analysis/ry02-ringcli-protocol-contract.json"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.source.is_dir():
        print(f"source directory not found: {args.source}", file=sys.stderr)
        return 2

    for tool in ("cmake",):
        if shutil.which(tool) is None:
            print(f"required tool not found: {tool}", file=sys.stderr)
            return 2

    if args.contract_json.is_file():
        contract = json.loads(args.contract_json.read_text(encoding="utf-8"))
        fixtures = contract.get("fixtures", {})

        mismatches = {
            name: (fixtures.get(name), expected)
            for name, expected in EXPECTED_FIXTURES.items()
            if fixtures.get(name) != expected
        }

        if mismatches:
            for name, pair in mismatches.items():
                print(
                    f"[FAIL] fixture {name}: actual={pair[0]!r} "
                    f"expected={pair[1]!r}"
                )
            return 1

        print("[PASS] protocol JSON fixtures")
    else:
        print(
            f"[WARN] contract JSON not found: {args.contract_json}; "
            "running C tests only"
        )

    with tempfile.TemporaryDirectory(prefix="ry02-ringcli-build-") as temp:
        build = Path(temp) / "build"
        run(["cmake", "-S", str(args.source.resolve()), "-B", str(build)])
        run(["cmake", "--build", str(build)])
        run(["ctest", "--test-dir", str(build), "--output-on-failure"])

    print("RY02 RingCLI skeleton verification: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
