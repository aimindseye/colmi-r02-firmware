#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import struct
import zlib
from pathlib import Path


OUTER_HEADER_SIZE = 0x50
INNER_HEADER_SIZE = 0x400

EXPECTED_STOCK_SHA256 = {
    "RY02_3.00.33_250117.bin":
        "3eaad32f25a1734b93b63b86c6a0032c3444b68e7027faf3724bd5148dd4dbcd",
    "RY02_3.00.38_250403.bin":
        "dbf64e3dc9aef112a4d69e46e516efb27f2ed2e3dc1d2d3f1af75939cc46487e",
}


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def sum_bytes(data: bytes, bits: int) -> int:
    mask = (1 << bits) - 1
    return sum(data) & mask


def sum_words_le(data: bytes, word_size: int) -> int:
    padded_length = (
        (len(data) + word_size - 1)
        // word_size
        * word_size
    )

    padded = data.ljust(padded_length, b"\x00")
    total = 0
    mask = (1 << (word_size * 8)) - 1

    for offset in range(0, len(padded), word_size):
        total += int.from_bytes(
            padded[offset:offset + word_size],
            "little",
        )

    return total & mask


def find_ascii_strings(
    data: bytes,
    minimum_length: int = 4,
) -> list[tuple[int, str]]:
    strings: list[tuple[int, str]] = []
    start: int | None = None

    for index, value in enumerate(data + b"\x00"):
        printable = 0x20 <= value <= 0x7E

        if printable and start is None:
            start = index
        elif not printable and start is not None:
            if index - start >= minimum_length:
                text = data[start:index].decode(
                    "ascii",
                    errors="replace",
                )
                strings.append((start, text))

            start = None

    return strings


def print_digest_test(
    label: str,
    expected: bytes,
    candidate: bytes,
) -> None:
    status = "MATCH" if candidate == expected else "no"

    print(
        f"  {label:34s} "
        f"{candidate.hex()}  {status}"
    )


def analyze(path: Path) -> dict[str, object]:
    container = path.read_bytes()

    if len(container) <= OUTER_HEADER_SIZE + INNER_HEADER_SIZE:
        raise ValueError(
            f"{path}: image is too small for both headers"
        )

    outer = container[:OUTER_HEADER_SIZE]
    payload = container[OUTER_HEADER_SIZE:]
    inner = payload[:INNER_HEADER_SIZE]
    body = payload[INNER_HEADER_SIZE:]

    outer_payload_length_1 = u32(outer, 0x04)
    outer_payload_length_2 = u32(outer, 0x08)
    outer_sum32 = u32(outer, 0x0C)

    internal_magic = u32(inner, 0x00)
    internal_field_04 = u32(inner, 0x04)
    internal_body_length = u32(inner, 0x08)
    internal_digest = inner[0x0C:0x1C]

    code_base_1 = u32(inner, 0x1C)
    code_base_2 = u32(inner, 0x20)
    image_base = u32(inner, 0x28)

    expected_code_base = image_base + INNER_HEADER_SIZE
    expected_body_end = code_base_1 + len(body)

    calculated_outer_sum32 = sum_bytes(payload, 32)

    print("=" * 88)
    print(path)
    print("=" * 88)

    print(f"Container SHA256:          {sha256(container)}")
    print(f"Container bytes:           0x{len(container):X}")
    print(f"Outer header bytes:        0x{len(outer):X}")
    print(f"Payload bytes:             0x{len(payload):X}")
    print(f"Internal header bytes:     0x{len(inner):X}")
    print(f"Executable/body bytes:     0x{len(body):X}")

    expected_hash = EXPECTED_STOCK_SHA256.get(path.name)

    if expected_hash is not None:
        print(
            f"Expected stock SHA256:     {expected_hash}"
        )
        print(
            "Stock identity:            "
            + (
                "MATCH"
                if sha256(container) == expected_hash
                else "MISMATCH"
            )
        )

    print("\nOUTER 0x50 HEADER")
    print(f"Magic:                     0x{u32(outer, 0):08X}")
    print(
        f"Length field 1:            "
        f"0x{outer_payload_length_1:X}"
    )
    print(
        f"Length field 2:            "
        f"0x{outer_payload_length_2:X}"
    )
    print(
        f"Actual payload length:     "
        f"0x{len(payload):X}"
    )
    print(
        "Length fields valid:       "
        + str(
            outer_payload_length_1 == len(payload)
            and outer_payload_length_2 == len(payload)
        )
    )
    print(f"Stored outer SUM32:        0x{outer_sum32:08X}")
    print(
        f"Calculated outer SUM32:    "
        f"0x{calculated_outer_sum32:08X}"
    )
    print(
        "Outer SUM32 valid:         "
        + str(outer_sum32 == calculated_outer_sum32)
    )

    print("\nINTERNAL 0x400 HEADER")
    print(f"Word +0x00:                0x{internal_magic:08X}")
    print(f"Word +0x04:                0x{internal_field_04:08X}")
    print(
        f"Body length field +0x08:   "
        f"0x{internal_body_length:X}"
    )
    print(f"Actual body length:        0x{len(body):X}")
    print(
        "Body length valid:        "
        + str(internal_body_length == len(body))
    )
    print(
        f"Stored 16-byte field:      "
        f"{internal_digest.hex()}"
    )
    print(f"Code base 1 +0x1C:         0x{code_base_1:08X}")
    print(f"Code base 2 +0x20:         0x{code_base_2:08X}")
    print(f"Image base +0x28:          0x{image_base:08X}")
    print(
        f"Expected code base:        "
        f"0x{expected_code_base:08X}"
    )
    print(
        "Code-base relation valid: "
        + str(
            code_base_1 == expected_code_base
            and code_base_2 == expected_code_base
        )
    )
    print(
        f"Projected body end:        "
        f"0x{expected_body_end:08X}"
    )

    print("\n16-BYTE FIELD TESTS")
    print_digest_test(
        "MD5(body)",
        internal_digest,
        md5(body),
    )
    print_digest_test(
        "MD5(internal header + body)",
        internal_digest,
        md5(payload),
    )
    print_digest_test(
        "MD5(body plus zero padding)",
        internal_digest,
        md5(body.ljust((len(body) + 0xFFF) & ~0xFFF, b"\x00")),
    )
    print_digest_test(
        "MD5(body plus FF padding)",
        internal_digest,
        md5(body.ljust((len(body) + 0xFFF) & ~0xFFF, b"\xFF")),
    )

    digest_zeroed = bytearray(payload)
    digest_zeroed[0x0C:0x1C] = b"\x00" * 16

    print_digest_test(
        "MD5(payload, digest zeroed)",
        internal_digest,
        md5(bytes(digest_zeroed)),
    )

    digest_ff = bytearray(payload)
    digest_ff[0x0C:0x1C] = b"\xFF" * 16

    print_digest_test(
        "MD5(payload, digest FF)",
        internal_digest,
        md5(bytes(digest_ff)),
    )

    print("\nBODY CHECKSUM CANDIDATES")
    print(f"CRC32(body):               0x{zlib.crc32(body):08X}")
    print(f"SUM16 bytes(body):         0x{sum_bytes(body, 16):04X}")
    print(f"SUM32 bytes(body):         0x{sum_bytes(body, 32):08X}")
    print(f"SUM16 LE words(body):      0x{sum_words_le(body, 2):04X}")
    print(f"SUM32 LE words(body):      0x{sum_words_le(body, 4):08X}")
    print(
        f"Internal +0x04 low16:      "
        f"0x{internal_field_04 & 0xFFFF:04X}"
    )
    print(
        f"Internal +0x04 high16:     "
        f"0x{internal_field_04 >> 16:04X}"
    )

    print("\nFIRST 32 INTERNAL HEADER WORDS")

    for offset in range(0, 0x80, 4):
        print(
            f"  +0x{offset:03X}: "
            f"0x{u32(inner, offset):08X}"
        )

    print("\nASCII STRINGS IN INTERNAL HEADER")

    strings = find_ascii_strings(inner)

    if not strings:
        print("  none")
    else:
        for offset, text in strings:
            print(f"  +0x{offset:03X}: {text!r}")

    return {
        "path": path,
        "container": container,
        "payload": payload,
        "inner": inner,
        "body": body,
        "digest": internal_digest,
        "body_length": internal_body_length,
        "image_base": image_base,
        "code_base": code_base_1,
    }


def compare(first: dict[str, object], second: dict[str, object]) -> None:
    first_path = first["path"]
    second_path = second["path"]
    first_inner = first["inner"]
    second_inner = second["inner"]

    assert isinstance(first_path, Path)
    assert isinstance(second_path, Path)
    assert isinstance(first_inner, bytes)
    assert isinstance(second_inner, bytes)

    print("\n" + "=" * 88)
    print("INTERNAL HEADER COMPARISON")
    print("=" * 88)
    print(f"First:  {first_path}")
    print(f"Second: {second_path}")

    differing_offsets = [
        offset
        for offset, (left, right) in enumerate(
            zip(first_inner, second_inner)
        )
        if left != right
    ]

    print(
        f"Differing header bytes:   "
        f"{len(differing_offsets)}"
    )

    if not differing_offsets:
        return

    ranges: list[tuple[int, int]] = []
    range_start = differing_offsets[0]
    previous = differing_offsets[0]

    for offset in differing_offsets[1:]:
        if offset != previous + 1:
            ranges.append((range_start, previous + 1))
            range_start = offset

        previous = offset

    ranges.append((range_start, previous + 1))

    print("Differing ranges:")

    for start, end in ranges:
        left = first_inner[start:end]
        right = second_inner[start:end]

        print(
            f"  +0x{start:03X}..+0x{end - 1:03X} "
            f"({end - start} bytes)"
        )
        print(f"    first:  {left.hex()}")
        print(f"    second: {right.hex()}")


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "images",
        nargs="+",
        type=Path,
    )

    args = parser.parse_args()

    results = [analyze(path) for path in args.images]

    if len(results) >= 2:
        for index in range(len(results) - 1):
            compare(
                results[index],
                results[index + 1],
            )


if __name__ == "__main__":
    main()
