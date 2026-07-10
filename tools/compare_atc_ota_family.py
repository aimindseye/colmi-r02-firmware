#!/usr/bin/env python3
"""Rank public RF03/R02 firmware images by similarity to RY02 .38."""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

BLOCK_SIZE = 32
SUM32_MAGIC = bytes.fromhex("e5c3bd81")


@dataclass
class Image:
    path: Path
    container: bytes
    payload: bytes
    header_size: int
    format_name: str
    integrity_name: str
    integrity_valid: bool
    firmware_strings: list[str]


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_identifiers(data: bytes) -> list[str]:
    found: set[str] = set()
    for pattern in (
        rb"(?:RY02|R02|R01|SR1)[A-Za-z0-9_.-]{3,48}",
        rb"(?:RY02|R02|R01|SR1)_V[0-9A-Za-z_.-]+",
    ):
        for match in re.finditer(pattern, data):
            found.add(match.group().decode("ascii", errors="replace"))
    return sorted(found)


def detect_image(path: Path) -> Image:
    data = path.read_bytes()

    if (
        len(data) >= 0x50
        and data[:4] == SUM32_MAGIC
        and u32le(data, 0x04) == len(data) - 0x50
        and u32le(data, 0x08) == len(data) - 0x50
    ):
        payload = data[0x50:]
        return Image(
            path=path,
            container=data,
            payload=payload,
            header_size=0x50,
            format_name="SUM32-0x50",
            integrity_name="byte_sum32",
            integrity_valid=u32le(data, 0x0C) == (sum(payload) & 0xFFFFFFFF),
            firmware_strings=extract_identifiers(data),
        )

    if path.name.startswith("R02_3.") and len(data) > 0x100:
        payload = data[0x100:]
        encoded_crc = struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)
        return Image(
            path=path,
            container=data,
            payload=payload,
            header_size=0x100,
            format_name="CRC32-0x100",
            integrity_name="crc32-in-header",
            integrity_valid=encoded_crc in data[:0x100],
            firmware_strings=extract_identifiers(data),
        )

    return Image(
        path=path,
        container=data,
        payload=data,
        header_size=0,
        format_name="unknown/raw",
        integrity_name="unknown",
        integrity_valid=False,
        firmware_strings=extract_identifiers(data),
    )


def rolling_windows(data: bytes, size: int) -> set[bytes]:
    if len(data) < size:
        return set()
    return {data[offset : offset + size] for offset in range(len(data) - size + 1)}


def block_coverage(
    source: bytes, reference_windows: set[bytes], size: int
) -> tuple[int, int, float]:
    blocks = [
        source[offset : offset + size]
        for offset in range(0, len(source) - size + 1, size)
    ]
    if not blocks:
        return 0, 0, 0.0
    matched = sum(block in reference_windows for block in blocks)
    return matched, len(blocks), 100.0 * matched / len(blocks)


def aligned_similarity(left: bytes, right: bytes) -> float:
    length = min(len(left), len(right))
    if not length:
        return 0.0
    equal = sum(a == b for a, b in zip(left[:length], right[:length]))
    return 100.0 * equal / length


def find_timer_sequences(payload: bytes) -> list[str]:
    patterns = {
        "r0:125<<3": bytes.fromhex("7d20c000"),
        "r2:125<<3": bytes.fromhex("7d22d200"),
        "r7:125<<3": bytes.fromhex("7d27ff00"),
        "r2:125<<4": bytes.fromhex("7d221201"),
        "r2:125;r3=1;r2<<3": bytes.fromhex("7d220123d200"),
    }
    results: list[str] = []
    for label, pattern in patterns.items():
        start = 0
        while True:
            offset = payload.find(pattern, start)
            if offset < 0:
                break
            results.append(f"{label}@0x{offset:X}")
            start = offset + 1
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--latest",
        type=Path,
        default=Path("downloads/qring-latest/RY02_3.00.38_250403.bin"),
    )
    parser.add_argument(
        "--corpus", type=Path, default=Path("vendor/atc-ota-firmwares")
    )
    args = parser.parse_args()

    latest = detect_image(args.latest)
    candidates = [detect_image(path) for path in sorted(args.corpus.glob("*.bin"))]
    if not candidates:
        raise SystemExit(f"no .bin files found in {args.corpus}")

    latest_windows = rolling_windows(latest.payload, BLOCK_SIZE)
    rows = []
    for candidate in candidates:
        candidate_windows = rolling_windows(candidate.payload, BLOCK_SIZE)
        candidate_in_latest = block_coverage(
            candidate.payload, latest_windows, BLOCK_SIZE
        )
        latest_in_candidate = block_coverage(
            latest.payload, candidate_windows, BLOCK_SIZE
        )
        rows.append(
            (
                latest_in_candidate[2],
                candidate_in_latest[2],
                aligned_similarity(latest.payload, candidate.payload),
                candidate,
                latest_in_candidate,
                candidate_in_latest,
            )
        )
    rows.sort(key=lambda row: row[0], reverse=True)

    print("=" * 88)
    print("REFERENCE IMAGE")
    print("=" * 88)
    print(f"File:            {latest.path}")
    print(f"Container size:  {len(latest.container)}")
    print(f"Header size:     0x{latest.header_size:X}")
    print(f"Payload size:    {len(latest.payload)}")
    print(f"Format:          {latest.format_name}")
    print(f"Integrity:       {latest.integrity_name}")
    print(f"Integrity valid: {latest.integrity_valid}")
    print(f"SHA-256:         {sha256(latest.container)}")
    print(f"Identifiers:     {latest.firmware_strings}")
    print(f"Timer patterns:  {find_timer_sequences(latest.payload)}")

    print("\n" + "=" * 88)
    print("SIMILARITY RANKING")
    print("=" * 88)
    for latest_cov, candidate_cov, aligned, candidate, latest_counts, candidate_counts in rows:
        print(f"\nFile: {candidate.path.name}")
        print(f"  Container size:          {len(candidate.container)}")
        print(f"  Header size:             0x{candidate.header_size:X}")
        print(f"  Payload size:            {len(candidate.payload)}")
        print(f"  Format:                  {candidate.format_name}")
        print(
            f"  Integrity:               {candidate.integrity_name} "
            f"valid={candidate.integrity_valid}"
        )
        print(f"  SHA-256:                 {sha256(candidate.container)}")
        print(f"  Identifiers:             {candidate.firmware_strings}")
        print(
            f"  Latest blocks found:     {latest_counts[0]}/{latest_counts[1]} "
            f"({latest_cov:.2f}%)"
        )
        print(
            f"  Candidate blocks found:  {candidate_counts[0]}/{candidate_counts[1]} "
            f"({candidate_cov:.2f}%)"
        )
        print(f"  Same-offset bytes:       {aligned:.2f}%")
        print(f"  Timer patterns:          {find_timer_sequences(candidate.payload)}")

    print("\nOnly matching SUM32-0x50 RY02 images should be treated as direct lineage.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
