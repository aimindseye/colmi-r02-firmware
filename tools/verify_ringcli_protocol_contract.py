#!/usr/bin/env python3
"""
Verify the RingCLI Colmi BLE protocol contract and correlate its UUIDs with the
accepted RY02 .38 firmware image.

This tool is offline and read-only. It:
  * extracts RingCLI command constants and service/characteristic UUIDs;
  * verifies the 16-byte command-UART packet and additive checksum contract;
  * verifies the 6-byte data-UART request contract;
  * generates canonical host-side request fixtures;
  * scans the stock RY02 payload for canonical and reversed UUID byte forms;
  * emits a conservative compatibility report and optional JSON.

It does not connect to the ring, send BLE commands, modify firmware, or create
an installable image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


TOOL_REVISION = "r1"

DEFAULT_RINGCLI = Path("reference/ringcli")
DEFAULT_FIRMWARE = Path(
    "release/ry02-3.00.38-faster-raw-r1/RY02_3.00.38_250403.bin"
)

HEADER_SIZE = 0x50
EXPECTED_FIRMWARE_SHA256 = (
    "dbf64e3dc9aef112a4d69e46e516efb27f2ed2e3dc1d2d3f1af75939cc46487e"
)

EXPECTED_BYTE_CONSTANTS = {
    "COMMAND_SET_TIME": 0x01,
    "COMMAND_BATTERY_INFO": 0x03,
    "COMMAND_SHUTDOWN": 0x08,
    "COMMAND_BATTERY_FLASH_LED": 0x10,
    "COMMAND_HEART_RATE_READ": 0x15,
    "COMMAND_HEART_RATE_PERIOD": 0x16,
    "COMMAND_GET_ACTIVITY_DATA": 0x43,
    "COMMAND_START_REAL_TIME": 0x69,
    "COMMAND_STOP_REAL_TIME": 0x6A,
    "COMMAND_GET_ACTIVITY_UNKNOWN": 0x73,
    "COMMAND_ERROR": 0xFF,
    "DATA_REQUEST_ID_SLEEP": 0x27,
    "DATA_REQUEST_ID_OXYGEN": 0x2A,
    "DATA_REQUEST_MAGIC_VALUE": 0xBC,
    "LANGUAGE_CHINESE": 0x00,
    "LANGUAGE_ENGLISH": 0x01,
    "REAL_TIME_HEART_RATE_CONTINUOUS": 0x06,
    "REAL_TIME_HEART_RATE_BATCH": 0x01,
    "REAL_TIME_BLOOD_OXYGEN": 0x03,
    "REAL_TIME_HRV": 0x0A,
    "REAL_TIME_ACTION_START": 0x01,
    "REAL_TIME_ACTION_PAUSE": 0x02,
    "REAL_TIME_ACTION_CONT": 0x03,
    "REAL_TIME_ACTION_STOP": 0x04,
}

EXPECTED_UUIDS = {
    "UUID_BLE_COMMAND_UART_SERVICE": "6E40FFF0-B5A3-F393-E0A9-E50E24DCCA9E",
    "UUID_BLE_COMMAND_UART_TX_CHAR": "6E400002-B5A3-F393-E0A9-E50E24DCCA9E",
    "UUID_BLE_COMMAND_UART_RX_CHAR": "6E400003-B5A3-F393-E0A9-E50E24DCCA9E",
    "UUID_BLE_DATA_UART_SERVICE": "DE5BF728-D711-4E47-AF26-65E3012A5DC7",
    "UUID_BLE_DATA_UART_TX_CHAR": "DE5BF72A-D711-4E47-AF26-65E3012A5DC7",
    "UUID_BLE_DATA_UART_RX_CHAR": "DE5BF729-D711-4E47-AF26-65E3012A5DC7",
}

REQUIRED_FILES = (
    "lib/colmi/commands.go",
    "lib/colmi/packet.go",
    "lib/colmi/time.go",
    "lib/colmi/steps.go",
    "lib/colmi/battery.go",
    "lib/colmi/shutdown.go",
    "lib/colmi/led.go",
    "lib/colmi/heartrate.go",
    "lib/colmi/sleep.go",
    "lib/colmi/oxygen.go",
)


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


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


def extract_byte_constants(text: str) -> dict[str, int]:
    result = {}
    pattern = re.compile(
        r"^\s*([A-Z][A-Z0-9_]+)\s+byte\s*=\s*(0x[0-9A-Fa-f]+|\d+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        result[match.group(1)] = int(match.group(2), 0)
    return result


def extract_uuid_constants(text: str) -> dict[str, str]:
    result = {}
    pattern = re.compile(
        r'^\s*(UUID_[A-Z0-9_]+)\s+string\s*=\s*"([0-9A-Fa-f-]{36})"',
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        result[match.group(1)] = match.group(2).upper()
    return result


def additive_checksum(packet_without_checksum: bytes) -> int:
    return sum(packet_without_checksum) & 0xFF


def make_command_packet(command: int, payload: bytes = b"") -> bytes:
    if len(payload) > 14:
        raise ValueError("command payload exceeds 14 bytes")
    packet = bytearray(16)
    packet[0] = command & 0xFF
    packet[1 : 1 + len(payload)] = payload
    packet[15] = additive_checksum(packet[:15])
    return bytes(packet)


def make_data_packet(command: int) -> bytes:
    return bytes((0xBC, command & 0xFF, 0x00, 0x00, 0xFF, 0xFF))


def bcd(value: int) -> int:
    if not 0 <= value <= 99:
        raise ValueError(value)
    return ((value // 10) << 4) | (value % 10)


def canonical_fixtures(constants: dict[str, int]) -> dict[str, bytes]:
    return {
        "battery_request": make_command_packet(
            constants["COMMAND_BATTERY_INFO"]
        ),
        "shutdown_request": make_command_packet(
            constants["COMMAND_SHUTDOWN"], bytes((0x01,))
        ),
        "flash_led_request": make_command_packet(
            constants["COMMAND_BATTERY_FLASH_LED"]
        ),
        "heart_period_get": make_command_packet(
            constants["COMMAND_HEART_RATE_PERIOD"], bytes((0x01,))
        ),
        "heart_period_set_enabled_60": make_command_packet(
            constants["COMMAND_HEART_RATE_PERIOD"],
            bytes((0x02, 0x01, 60)),
        ),
        "realtime_hr_batch_start": make_command_packet(
            constants["COMMAND_START_REAL_TIME"],
            bytes(
                (
                    constants["REAL_TIME_HEART_RATE_BATCH"],
                    constants["REAL_TIME_ACTION_START"],
                )
            ),
        ),
        "realtime_hr_batch_continue": make_command_packet(
            constants["COMMAND_START_REAL_TIME"],
            bytes(
                (
                    constants["REAL_TIME_HEART_RATE_BATCH"],
                    constants["REAL_TIME_ACTION_CONT"],
                )
            ),
        ),
        "realtime_hr_batch_stop": make_command_packet(
            constants["COMMAND_STOP_REAL_TIME"],
            bytes((constants["REAL_TIME_HEART_RATE_BATCH"],)),
        ),
        "steps_offset_0": make_command_packet(
            constants["COMMAND_GET_ACTIVITY_DATA"],
            bytes((0x00, 0x0F, 0x00, 0x5F, 0x01)),
        ),
        "set_time_2025_04_09_12_34_56_en": make_command_packet(
            constants["COMMAND_SET_TIME"],
            bytes(
                (
                    bcd(25),
                    bcd(4),
                    bcd(9),
                    bcd(12),
                    bcd(34),
                    bcd(56),
                    constants["LANGUAGE_ENGLISH"],
                )
            ),
        ),
        "sleep_data_request": make_data_packet(
            constants["DATA_REQUEST_ID_SLEEP"]
        ),
        "oxygen_data_request": make_data_packet(
            constants["DATA_REQUEST_ID_OXYGEN"]
        ),
    }


def uuid_forms(value: str) -> dict[str, bytes]:
    canonical = uuid.UUID(value).bytes
    return {
        "canonical": canonical,
        "full_reverse": canonical[::-1],
        "guid_bytes_le": uuid.UUID(value).bytes_le,
    }


def find_all(data: bytes, needle: bytes) -> list[int]:
    offsets = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return offsets
        offsets.append(offset)
        start = offset + 1


def source_contract_checks(root: Path) -> tuple[list[Check], dict]:
    checks: list[Check] = []
    missing = [
        relative for relative in REQUIRED_FILES
        if not (root / relative).is_file()
    ]
    checks.append(
        Check(
            "required RingCLI source files",
            not missing,
            "missing=" + (",".join(missing) if missing else "none"),
        )
    )
    if missing:
        return checks, {}

    commands_text = read_text(root / "lib/colmi/commands.go")
    packet_text = read_text(root / "lib/colmi/packet.go")
    time_text = read_text(root / "lib/colmi/time.go")
    steps_text = read_text(root / "lib/colmi/steps.go")

    constants = extract_byte_constants(commands_text)
    uuids = extract_uuid_constants(commands_text)

    for name, expected in EXPECTED_BYTE_CONSTANTS.items():
        actual = constants.get(name)
        checks.append(
            Check(
                f"constant {name}",
                actual == expected,
                f"actual={actual!r} expected=0x{expected:02X}",
            )
        )

    for name, expected in EXPECTED_UUIDS.items():
        actual = uuids.get(name)
        checks.append(
            Check(
                f"UUID {name}",
                actual == expected,
                f"actual={actual!r} expected={expected}",
            )
        )

    packet_markers = {
        "16-byte command packet": "make([]byte, 16, 16)",
        "command at byte 0": "packet[0] = command",
        "checksum at byte 15": "packet[15] = checksum(packet)",
        "checksum verifies bytes 0..14": "checksum(packet[0:15])",
        "6-byte data request": "make([]byte, 6, 6)",
        "data magic byte": "packet[0] = DATA_REQUEST_MAGIC_VALUE",
        "data request FF tail 1": "packet[4] = 0xFF",
        "data request FF tail 2": "packet[5] = 0xFF",
    }
    for name, marker in packet_markers.items():
        checks.append(Check(name, marker in packet_text, f"marker={marker!r}"))

    checksum_shape = (
        "var count byte = 0" in packet_text
        and "count += aByte" in packet_text
        and "return count" in packet_text
    )
    checks.append(
        Check(
            "8-bit additive checksum implementation",
            checksum_shape,
            "byte accumulator adds every supplied byte",
        )
    )

    time_shape = all(
        marker in time_text
        for marker in (
            "targetDate.Year() % 2000",
            "targetDate.Month()",
            "targetDate.Day()",
            "targetDate.Hour()",
            "targetDate.Minute()",
            "targetDate.Second()",
            "payload[6] = LANGUAGE_ENGLISH",
        )
    )
    checks.append(
        Check(
            "time payload BCD Y/M/D/h/m/s plus language",
            time_shape,
            "source markers present",
        )
    )

    steps_shape = (
        "COMMAND_GET_ACTIVITY_DATA" in steps_text
        and "[]byte{byte(offset), 0x0F, 0x00, 0x5F, 0x01}" in steps_text
    )
    checks.append(
        Check(
            "steps request payload",
            steps_shape,
            "offset,0F,00,5F,01",
        )
    )

    return checks, {
        "constants": constants,
        "uuids": uuids,
        "fixtures": canonical_fixtures(constants)
        if all(name in constants for name in EXPECTED_BYTE_CONSTANTS)
        else {},
    }


def firmware_scan(path: Path, uuids: dict[str, str]) -> dict:
    if not path.is_file():
        return {
            "present": False,
            "error": f"not found: {path}",
            "sha256": None,
            "sha_match": False,
            "matches": {},
        }

    container = path.read_bytes()
    payload = container[HEADER_SIZE:] if len(container) > HEADER_SIZE else b""
    sha = hashlib.sha256(container).hexdigest()
    matches = {}

    for name, value in uuids.items():
        form_matches = {}
        for form_name, needle in uuid_forms(value).items():
            form_matches[form_name] = {
                "container_offsets": find_all(container, needle),
                "payload_offsets": find_all(payload, needle),
                "needle_hex": needle.hex(),
            }
        matches[name] = form_matches

    command_counts = {
        f"0x{value:02X}": payload.count(bytes((value,)))
        for name, value in EXPECTED_BYTE_CONSTANTS.items()
        if name.startswith("COMMAND_")
    }

    return {
        "present": True,
        "error": None,
        "sha256": sha,
        "sha_match": sha == EXPECTED_FIRMWARE_SHA256,
        "container_length": len(container),
        "payload_length": len(payload),
        "matches": matches,
        "command_byte_counts_nonsemantic": command_counts,
    }


def print_report(
    root: Path,
    firmware: Path,
    checks: list[Check],
    extracted: dict,
    scan: dict,
) -> None:
    print("RY02 RINGCLI BLE PROTOCOL CONTRACT REPORT")
    print(f"tool revision: {TOOL_REVISION}")
    print(f"RingCLI root: {root}")
    print(f"RingCLI git HEAD: {git_head(root) or 'unresolved'}")
    print(f"firmware: {firmware}")
    print()
    print("Interpretation boundary:")
    print("  RingCLI is host-side protocol evidence")
    print("  packet/UUID agreement does not establish bootloader compatibility")
    print("  isolated command-byte counts in firmware are non-semantic")
    print("  no BLE traffic or device interaction is performed")
    print()

    print("=" * 116)
    print("SOURCE CONTRACT CHECKS")
    for check in checks:
        print(f"[{'PASS' if check.passed else 'FAIL'}] {check.name}")
        print(f"       {check.detail}")

    print()
    print("=" * 116)
    print("EXTRACTED COMMAND CONSTANTS")
    for name, value in sorted(extracted.get("constants", {}).items()):
        print(f"{name:<38} 0x{value:02X}")

    print()
    print("=" * 116)
    print("EXTRACTED UUIDS")
    for name, value in sorted(extracted.get("uuids", {}).items()):
        print(f"{name:<38} {value}")

    print()
    print("=" * 116)
    print("CANONICAL REQUEST FIXTURES")
    for name, packet in sorted(extracted.get("fixtures", {}).items()):
        kind = "data-uart" if len(packet) == 6 else "command-uart"
        print(f"{name:<38} len={len(packet):2d} {kind:<12} {packet.hex(' ')}")

    print()
    print("=" * 116)
    print("RY02 FIRMWARE UUID CORRELATION")
    if not scan.get("present"):
        print(f"firmware unavailable: {scan.get('error')}")
    else:
        print(f"SHA256: {scan['sha256']}")
        print(f"accepted stock SHA match: {scan['sha_match']}")
        print(f"container length: 0x{scan['container_length']:X}")
        print(f"payload length: 0x{scan['payload_length']:X}")
        for name, forms in scan["matches"].items():
            print()
            print(name)
            for form_name, result in forms.items():
                container_offsets = result["container_offsets"]
                payload_offsets = result["payload_offsets"]
                print(
                    f"  {form_name:<14} "
                    f"container={','.join(f'0x{x:X}' for x in container_offsets) or 'none'} "
                    f"payload={','.join(f'0x{x:X}' for x in payload_offsets) or 'none'}"
                )

    print()
    print("=" * 116)
    print("PROTOCOL MODEL")
    print("command UART:")
    print("  service  6E40FFF0-B5A3-F393-E0A9-E50E24DCCA9E")
    print("  write    6E400002-B5A3-F393-E0A9-E50E24DCCA9E")
    print("  notify   6E400003-B5A3-F393-E0A9-E50E24DCCA9E")
    print("  request  16 bytes: command, payload[0..13], checksum")
    print("  checksum sum(bytes[0..14]) modulo 256")
    print()
    print("data UART:")
    print("  service  DE5BF728-D711-4E47-AF26-65E3012A5DC7")
    print("  write    DE5BF72A-D711-4E47-AF26-65E3012A5DC7")
    print("  notify   DE5BF729-D711-4E47-AF26-65E3012A5DC7")
    print("  request  6 bytes: BC, request-id, 00, 00, FF, FF")
    print("  sleep request-id 27; oxygen request-id 2A")
    print()
    print("real-time control:")
    print("  start/continue command 69")
    print("  stop command 6A")
    print("  payload byte 1 selects measurement type")
    print("  payload byte 2 selects action for command 69")

    failed = [check for check in checks if not check.passed]
    uuid_hits = 0
    for forms in scan.get("matches", {}).values():
        for result in forms.values():
            uuid_hits += len(result["container_offsets"])

    print()
    print("=" * 116)
    print("SUMMARY")
    print(f"source checks: {len(checks)}")
    print(f"source failures: {len(failed)}")
    print(f"firmware UUID byte-form hits: {uuid_hits}")
    print(
        "protocol contract: "
        + ("PASS" if not failed else "FAILED")
    )
    print("device action: none")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify RingCLI's Colmi command/data UART protocol and correlate "
            "its UUIDs with the accepted RY02 .38 firmware."
        )
    )
    parser.add_argument("--ringcli", type=Path, default=DEFAULT_RINGCLI)
    parser.add_argument("--firmware", type=Path, default=DEFAULT_FIRMWARE)
    parser.add_argument("--json-out", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    checks, extracted = source_contract_checks(args.ringcli)
    scan = firmware_scan(args.firmware, extracted.get("uuids", EXPECTED_UUIDS))
    print_report(args.ringcli, args.firmware, checks, extracted, scan)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        serializable = {
            "schema": "ry02.ringcli-protocol-contract.v1",
            "tool_revision": TOOL_REVISION,
            "ringcli_root": str(args.ringcli),
            "ringcli_git_head": git_head(args.ringcli),
            "checks": [
                {
                    "name": check.name,
                    "passed": check.passed,
                    "detail": check.detail,
                }
                for check in checks
            ],
            "constants": extracted.get("constants", {}),
            "uuids": extracted.get("uuids", {}),
            "fixtures": {
                name: packet.hex()
                for name, packet in extracted.get("fixtures", {}).items()
            },
            "firmware_scan": scan,
        }
        args.json_out.write_text(
            json.dumps(serializable, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return 1 if any(not check.passed for check in checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
