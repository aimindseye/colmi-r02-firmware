#!/usr/bin/env python3
"""Compare stock and modified OTA images without claiming flash safety."""

from __future__ import annotations

import argparse
import hashlib
import struct
import zlib
from pathlib import Path


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def c_string(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("ascii", errors="replace")


def analyze(path: Path) -> dict:
    data = path.read_bytes()
    if data[:4] == bytes.fromhex("e5c3bd81"):
        header_size = 0x50
        payload = data[header_size:]
        stored = u32le(data, 0x0C)
        calculated = sum(payload) & 0xFFFFFFFF
        return {
            "path": path,
            "data": data,
            "payload": payload,
            "header_size": header_size,
            "format": "SUM32-0x50",
            "firmware": c_string(data[0x10:0x30]),
            "hardware": c_string(data[0x30:0x50]),
            "length_valid": u32le(data, 0x04) == len(payload)
            and u32le(data, 0x08) == len(payload),
            "stored": stored,
            "calculated": calculated,
            "integrity_valid": stored == calculated,
        }

    header_size = 0x100
    payload = data[header_size:]
    stored = u32le(data, 0x04)
    calculated = zlib.crc32(payload) & 0xFFFFFFFF
    return {
        "path": path,
        "data": data,
        "payload": payload,
        "header_size": header_size,
        "format": "CRC32-0x100",
        "firmware": c_string(data[0x10:0x30]),
        "hardware": c_string(data[0x30:0x50]),
        "length_valid": u32le(data, 0x08) == len(payload)
        and u32le(data, 0x0C) == len(payload),
        "stored": stored,
        "calculated": calculated,
        "integrity_valid": stored == calculated,
    }


def compare(label: str, stock: dict, modified: dict) -> None:
    common = min(len(stock["data"]), len(modified["data"]))
    diffs = [i for i in range(common) if stock["data"][i] != modified["data"][i]]
    diffs.extend(range(common, max(len(stock["data"]), len(modified["data"]))))
    header_limit = min(stock["header_size"], modified["header_size"])
    header_diffs = [i for i in diffs if i < header_limit]
    payload_diffs = [i for i in diffs if i >= header_limit]

    print("=" * 96)
    print(label)
    print("=" * 96)
    print(f"Firmware string unchanged: {stock['firmware'] == modified['firmware']}")
    print(f"Hardware string unchanged: {stock['hardware'] == modified['hardware']}")
    print(f"Container size unchanged:  {len(stock['data']) == len(modified['data'])}")
    print(f"Total differing bytes:     {len(diffs)}")
    print(f"Header differing bytes:    {len(header_diffs)}")
    print(f"Payload differing bytes:   {len(payload_diffs)}")
    print(
        "Header difference offsets: "
        + (", ".join(f"0x{x:X}" for x in header_diffs) if header_diffs else "NONE")
    )
    print(
        "Payload difference offsets: "
        + (", ".join(f"0x{x:X}" for x in payload_diffs) if payload_diffs else "NONE")
    )
    for offset in diffs[:32]:
        before = stock["data"][offset] if offset < len(stock["data"]) else None
        after = modified["data"][offset] if offset < len(modified["data"]) else None
        print(
            f"  offset 0x{offset:06X}: "
            f"{f'0x{before:02X}' if before is not None else 'EOF'} -> "
            f"{f'0x{after:02X}' if after is not None else 'EOF'}"
        )
    print(f"Modified integrity valid: {modified['integrity_valid']}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ry02-stock",
        type=Path,
        default=Path("downloads/qring-latest/RY02_3.00.38_250403.bin"),
    )
    parser.add_argument(
        "--ry02-patched",
        type=Path,
        default=Path(
            "release/ry02-3.00.38-faster-raw-r1/"
            "RY02_3.00.38_250403_FasterRawValuesMOD.bin"
        ),
    )
    parser.add_argument(
        "--r02-stock",
        type=Path,
        default=Path("vendor/atc-ota-firmwares/R02_3.00.06_240523.bin"),
    )
    parser.add_argument(
        "--r02-patched",
        type=Path,
        default=Path("vendor/ATC_RF03_Ring/R02_3.00.06_FasterRawValuesMOD.bin"),
    )
    args = parser.parse_args()

    paths = [args.ry02_stock, args.ry02_patched, args.r02_stock, args.r02_patched]
    missing = [path for path in paths if not path.exists()]
    if missing:
        raise SystemExit("missing required local file(s):\n" + "\n".join(f"  {x}" for x in missing))

    ry02_stock = analyze(args.ry02_stock)
    ry02_patched = analyze(args.ry02_patched)
    r02_stock = analyze(args.r02_stock)
    r02_patched = analyze(args.r02_patched)

    for image in (ry02_stock, ry02_patched, r02_stock, r02_patched):
        print("=" * 96)
        print(image["path"])
        print("=" * 96)
        print(f"Format:          {image['format']}")
        print(f"Size:            {len(image['data'])}")
        print(f"SHA-256:         {hashlib.sha256(image['data']).hexdigest()}")
        print(f"Firmware:        {image['firmware']}")
        print(f"Hardware:        {image['hardware']}")
        print(f"Length valid:    {image['length_valid']}")
        print(f"Stored value:    0x{image['stored']:08X}")
        print(f"Calculated:      0x{image['calculated']:08X}")
        print(f"Integrity valid: {image['integrity_valid']}\n")

    compare("RY02 .38 STOCK -> LOCAL EXPERIMENT", ry02_stock, ry02_patched)
    compare("R02 .06 STOCK -> PUBLIC ATC EXPERIMENT", r02_stock, r02_patched)
    print("Validation of outer-container mechanics does not establish flash safety.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
