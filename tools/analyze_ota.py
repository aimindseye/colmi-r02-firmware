#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import struct
import zlib
from pathlib import Path


def u32le(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise ValueError(f"Cannot read u32 at 0x{offset:X}")
    return struct.unpack_from("<I", data, offset)[0]


def c_string(data: bytes, start: int, end: int) -> str:
    value = data[start:end].split(b"\x00", 1)[0]
    return value.decode("ascii", errors="replace")


def detect_format(data: bytes) -> tuple[str, int, int, int]:
    total = len(data)

    field_04 = u32le(data, 0x04)
    field_08 = u32le(data, 0x08)
    field_0c = u32le(data, 0x0C)

    # Newer RY02 format observed in RY02_V3.0 firmware.
    if (
        field_04 == field_08
        and total - field_04 == 0x50
    ):
        return "RY02-header-0x50", 0x50, field_04, field_0c

    # Older documented ATC/R02 container:
    # integrity at 0x04, payload length at 0x08,
    # payload beginning at 0x100.
    if total - field_08 == 0x100:
        return "R02-header-0x100", 0x100, field_08, field_04

    # Show the most plausible interpretation even if not recognized.
    for header_size in (0x50, 0x80, 0x100):
        expected = total - header_size
        if field_04 == expected:
            return f"candidate-header-0x{header_size:X}", header_size, field_04, field_0c
        if field_08 == expected:
            return f"candidate-header-0x{header_size:X}", header_size, field_08, field_04

    raise ValueError(
        "Unrecognized container: "
        f"size={total}, @04=0x{field_04:08X}, "
        f"@08=0x{field_08:08X}, @0C=0x{field_0c:08X}"
    )


def checksum_candidates(payload: bytes) -> dict[str, int]:
    standard_crc = zlib.crc32(payload) & 0xFFFFFFFF
    seeded_crc = zlib.crc32(payload, 0xFFFFFFFF) & 0xFFFFFFFF

    return {
        "crc32_zlib": standard_crc,
        "crc32_zlib_xor": standard_crc ^ 0xFFFFFFFF,
        "crc32_seed_ffffffff": seeded_crc,
        "crc32_seed_ffffffff_xor": seeded_crc ^ 0xFFFFFFFF,
        "adler32": zlib.adler32(payload) & 0xFFFFFFFF,
        "byte_sum32": sum(payload) & 0xFFFFFFFF,
    }


def analyze(path: Path, output_dir: Path) -> None:
    data = path.read_bytes()
    fmt, header_size, declared_length, integrity = detect_format(data)

    payload = data[header_size:]
    firmware = c_string(data, 0x10, 0x30)
    hardware = c_string(data, 0x30, 0x50)

    output_dir.mkdir(parents=True, exist_ok=True)
    payload_path = output_dir / f"{path.stem}.payload.bin"
    payload_path.write_bytes(payload)

    print(f"\n===== {path} =====")
    print(f"Format:              {fmt}")
    print(f"Total size:          {len(data)} bytes / 0x{len(data):X}")
    print(f"Header size:         {header_size} bytes / 0x{header_size:X}")
    print(f"Declared payload:    {declared_length} bytes / 0x{declared_length:X}")
    print(f"Actual payload:      {len(payload)} bytes / 0x{len(payload):X}")
    print(f"Length valid:        {declared_length == len(payload)}")
    print(f"Firmware string:     {firmware!r}")
    print(f"Hardware string:     {hardware!r}")
    print(f"Integrity field:     0x{integrity:08X}")
    print(f"Container SHA-256:   {hashlib.sha256(data).hexdigest()}")
    print(f"Payload SHA-256:     {hashlib.sha256(payload).hexdigest()}")
    print(f"Extracted payload:   {payload_path}")

    matches = []
    print("Checksum candidates:")
    for name, value in checksum_candidates(payload).items():
        marker = " MATCH" if value == integrity else ""
        if marker:
            matches.append(name)
        print(f"  {name:28s} 0x{value:08X}{marker}")

    if not matches:
        print("Integrity algorithm: not one of the tested common variants")
    else:
        print(f"Integrity algorithm: {', '.join(matches)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("images", nargs="+", type=Path)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("analysis/payloads"),
    )
    args = parser.parse_args()

    for image in args.images:
        try:
            analyze(image, args.output_dir)
        except Exception as exc:
            print(f"\nERROR analyzing {image}: {exc}")


if __name__ == "__main__":
    main()
