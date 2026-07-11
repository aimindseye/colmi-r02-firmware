#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import struct
import zlib
from pathlib import Path
from typing import Callable


OUTER_HEADER_SIZE = 0x50
INNER_HEADER_SIZE = 0x400

FIELD32_OFFSET = 0x174
FIELD32_LENGTH = 32

FIELD16_OFFSET = 0x1DC
FIELD16_LENGTH = 2


def crc16_arc(data: bytes) -> int:
    crc = 0x0000

    for value in data:
        crc ^= value

        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1

    return crc & 0xFFFF


def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF

    for value in data:
        crc ^= value

        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1

    return crc & 0xFFFF


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF

    for value in data:
        crc ^= value << 8

        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF

    return crc


def crc16_xmodem(data: bytes) -> int:
    crc = 0x0000

    for value in data:
        crc ^= value << 8

        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF

    return crc


def crc16_kermit(data: bytes) -> int:
    crc = 0x0000

    for value in data:
        crc ^= value

        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1

    return crc & 0xFFFF


def crc16_x25(data: bytes) -> int:
    crc = 0xFFFF

    for value in data:
        crc ^= value

        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1

    return crc ^ 0xFFFF


def fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0

    for value in data:
        sum1 = (sum1 + value) % 255
        sum2 = (sum2 + sum1) % 255

    return (sum2 << 8) | sum1


def sum16_bytes(data: bytes) -> int:
    return sum(data) & 0xFFFF


def sum16_words_le(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"

    total = 0

    for offset in range(0, len(data), 2):
        total += int.from_bytes(
            data[offset:offset + 2],
            "little",
        )

    return total & 0xFFFF


def first_differences(
    left: bytes,
    right: bytes,
    limit: int = 32,
) -> list[int]:
    return [
        offset
        for offset, (a, b) in enumerate(zip(left, right))
        if a != b
    ][:limit]


def regions(
    payload: bytes,
    inner: bytes,
    body: bytes,
) -> dict[str, bytes]:
    inner_field32_zero = bytearray(inner)
    inner_field32_zero[
        FIELD32_OFFSET:FIELD32_OFFSET + FIELD32_LENGTH
    ] = b"\x00" * FIELD32_LENGTH

    inner_field32_ff = bytearray(inner)
    inner_field32_ff[
        FIELD32_OFFSET:FIELD32_OFFSET + FIELD32_LENGTH
    ] = b"\xFF" * FIELD32_LENGTH

    inner_integrity_zero = bytearray(inner_field32_zero)
    inner_integrity_zero[
        FIELD16_OFFSET:FIELD16_OFFSET + FIELD16_LENGTH
    ] = b"\x00" * FIELD16_LENGTH

    payload_field32_zero = bytearray(payload)
    payload_field32_zero[
        FIELD32_OFFSET:FIELD32_OFFSET + FIELD32_LENGTH
    ] = b"\x00" * FIELD32_LENGTH

    payload_integrity_zero = bytearray(payload_field32_zero)
    payload_integrity_zero[
        FIELD16_OFFSET:FIELD16_OFFSET + FIELD16_LENGTH
    ] = b"\x00" * FIELD16_LENGTH

    body_zero_padded = body.ljust(
        (len(body) + 0xFFF) & ~0xFFF,
        b"\x00",
    )

    body_ff_padded = body.ljust(
        (len(body) + 0xFFF) & ~0xFFF,
        b"\xFF",
    )

    return {
        "body": body,
        "body-zero-padded-4K": body_zero_padded,
        "body-ff-padded-4K": body_ff_padded,
        "internal-header": inner,
        "internal-header-field32-zero":
            bytes(inner_field32_zero),
        "internal-header-field32-ff":
            bytes(inner_field32_ff),
        "internal-header-integrity-zero":
            bytes(inner_integrity_zero),
        "payload": payload,
        "payload-field32-zero":
            bytes(payload_field32_zero),
        "payload-integrity-zero":
            bytes(payload_integrity_zero),
        "header-zero-plus-body":
            bytes(inner_integrity_zero) + body,
    }


def analyze(path: Path) -> dict[str, bytes | Path]:
    container = path.read_bytes()
    payload = container[OUTER_HEADER_SIZE:]
    inner = payload[:INNER_HEADER_SIZE]
    body = payload[INNER_HEADER_SIZE:]

    stored32 = inner[
        FIELD32_OFFSET:FIELD32_OFFSET + FIELD32_LENGTH
    ]

    stored16_bytes = inner[
        FIELD16_OFFSET:FIELD16_OFFSET + FIELD16_LENGTH
    ]

    stored16_le = int.from_bytes(stored16_bytes, "little")
    stored16_be = int.from_bytes(stored16_bytes, "big")

    print("=" * 96)
    print(path)
    print("=" * 96)
    print(f"Container SHA256: {hashlib.sha256(container).hexdigest()}")
    print(f"Payload length:   0x{len(payload):X}")
    print(f"Body length:      0x{len(body):X}")
    print(
        f"Stored field32:   "
        f"inner+0x{FIELD32_OFFSET:X} "
        f"{stored32.hex()}"
    )
    print(
        f"Stored field16:   "
        f"inner+0x{FIELD16_OFFSET:X} "
        f"{stored16_bytes.hex()} "
        f"LE=0x{stored16_le:04X} "
        f"BE=0x{stored16_be:04X}"
    )

    candidate_regions = regions(
        payload,
        inner,
        body,
    )

    print("\n32-BYTE DIGEST TESTS")

    digest_functions: dict[
        str,
        Callable[[bytes], bytes],
    ] = {
        "SHA256": lambda data:
            hashlib.sha256(data).digest(),
        "double-SHA256": lambda data:
            hashlib.sha256(
                hashlib.sha256(data).digest()
            ).digest(),
        "BLAKE2s-256": lambda data:
            hashlib.blake2s(data).digest(),
        "SHA3-256": lambda data:
            hashlib.sha3_256(data).digest(),
    }

    digest_matches = []

    for region_name, data in candidate_regions.items():
        for digest_name, function in digest_functions.items():
            digest = function(data)
            match = digest == stored32

            if match:
                digest_matches.append(
                    (digest_name, region_name)
                )

            print(
                f"  {digest_name:14s} "
                f"{region_name:34s} "
                f"{digest.hex()} "
                f"{'MATCH' if match else ''}"
            )

    print("\n32-byte matches:")

    if digest_matches:
        for digest_name, region_name in digest_matches:
            print(f"  {digest_name}({region_name})")
    else:
        print("  none")

    print("\n16-BIT CHECKSUM TESTS")

    checksum_functions: dict[
        str,
        Callable[[bytes], int],
    ] = {
        "CRC16-ARC": crc16_arc,
        "CRC16-MODBUS": crc16_modbus,
        "CRC16-CCITT-FALSE": crc16_ccitt_false,
        "CRC16-XMODEM": crc16_xmodem,
        "CRC16-KERMIT": crc16_kermit,
        "CRC16-X25": crc16_x25,
        "FLETCHER16": fletcher16,
        "SUM16-BYTES": sum16_bytes,
        "SUM16-WORDS-LE": sum16_words_le,
    }

    checksum_matches = []

    for region_name, data in candidate_regions.items():
        for checksum_name, function in checksum_functions.items():
            value = function(data)

            match_le = value == stored16_le
            match_be = value == stored16_be

            if match_le or match_be:
                checksum_matches.append(
                    (
                        checksum_name,
                        region_name,
                        "LE" if match_le else "BE",
                    )
                )

            marker = (
                "MATCH-LE"
                if match_le
                else "MATCH-BE"
                if match_be
                else ""
            )

            print(
                f"  {checksum_name:18s} "
                f"{region_name:34s} "
                f"0x{value:04X} "
                f"{marker}"
            )

    print("\n16-bit matches:")

    if checksum_matches:
        for checksum_name, region_name, endian in checksum_matches:
            print(
                f"  {checksum_name}({region_name}) "
                f"[{endian}]"
            )
    else:
        print("  none")

    print("\nOTHER BODY DIGESTS")
    print(f"  MD5:       {hashlib.md5(body).hexdigest()}")
    print(f"  SHA1:      {hashlib.sha1(body).hexdigest()}")
    print(f"  SHA224:    {hashlib.sha224(body).hexdigest()}")
    print(f"  SHA256:    {hashlib.sha256(body).hexdigest()}")
    print(f"  SHA384:    {hashlib.sha384(body).hexdigest()}")
    print(f"  SHA512:    {hashlib.sha512(body).hexdigest()}")
    print(f"  CRC32:     0x{zlib.crc32(body):08X}")

    return {
        "path": path,
        "container": container,
        "payload": payload,
        "inner": inner,
        "body": body,
        "field32": stored32,
        "field16": stored16_bytes,
    }


def compare(
    left: dict[str, bytes | Path],
    right: dict[str, bytes | Path],
) -> None:
    left_path = left["path"]
    right_path = right["path"]

    assert isinstance(left_path, Path)
    assert isinstance(right_path, Path)

    print("\n" + "=" * 96)
    print("IMAGE COMPARISON")
    print("=" * 96)
    print(f"Left:  {left_path}")
    print(f"Right: {right_path}")

    for key in (
        "container",
        "payload",
        "inner",
        "body",
        "field32",
        "field16",
    ):
        left_data = left[key]
        right_data = right[key]

        assert isinstance(left_data, bytes)
        assert isinstance(right_data, bytes)

        differences = sum(
            1
            for a, b in zip(left_data, right_data)
            if a != b
        )

        differences += abs(
            len(left_data) - len(right_data)
        )

        print(
            f"{key:10s}: "
            f"left=0x{len(left_data):X} "
            f"right=0x{len(right_data):X} "
            f"differences={differences}"
        )

        if len(left_data) == len(right_data):
            offsets = first_differences(
                left_data,
                right_data,
            )

            if offsets:
                print(
                    " " * 12
                    + "first offsets: "
                    + ", ".join(
                        f"0x{offset:X}"
                        for offset in offsets
                    )
                )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "images",
        nargs="+",
        type=Path,
    )

    args = parser.parse_args()

    results = [analyze(path) for path in args.images]

    for index in range(len(results) - 1):
        compare(
            results[index],
            results[index + 1],
        )


if __name__ == "__main__":
    main()
