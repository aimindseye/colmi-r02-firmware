#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import struct
from pathlib import Path


SOURCE = Path("vendor/RY02_3.00.38_250403.bin")
OUTPUT = Path("vendor/RY02_3.00.38_250403_FasterRawValuesMOD.bin")

EXPECTED_SOURCE_SHA256 = (
    "dbf64e3dc9aef112a4d69e46e516efb27f2ed2e3dc1d2d3f1af75939cc46487e"
)

EXPECTED_SIZE = 118116
HEADER_SIZE = 0x50

PAYLOAD_PATCH_OFFSET = 0x1DDE
CONTAINER_PATCH_OFFSET = HEADER_SIZE + PAYLOAD_PATCH_OFFSET

EXPECTED_OLD_CHECKSUM = 0x00AD12FC
EXPECTED_NEW_CHECKSUM = 0x00AD129F

EXPECTED_CONTEXT = bytes.fromhex(
    "7d 22 01 23 d2 00"
)
PATCHED_CONTEXT = bytes.fromhex(
    "20 22 01 23 d2 00"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_c_string(data: bytes | bytearray, start: int, end: int) -> str:
    raw = bytes(data[start:end]).split(b"\x00", 1)[0]
    return raw.decode("ascii")


def main() -> None:
    if not SOURCE.exists():
        raise SystemExit(f"Source image not found: {SOURCE}")

    original = SOURCE.read_bytes()

    if len(original) != EXPECTED_SIZE:
        raise SystemExit(
            f"Wrong source size: {len(original)}; expected {EXPECTED_SIZE}"
        )

    actual_sha = sha256(original)

    if actual_sha != EXPECTED_SOURCE_SHA256:
        raise SystemExit(
            "Source SHA-256 mismatch.\n"
            f"Expected: {EXPECTED_SOURCE_SHA256}\n"
            f"Actual:   {actual_sha}"
        )

    if original[0:4] != bytes.fromhex("e5 c3 bd 81"):
        raise SystemExit("Unexpected RY02 OTA magic.")

    declared_length_1 = read_u32(original, 0x04)
    declared_length_2 = read_u32(original, 0x08)
    expected_payload_length = len(original) - HEADER_SIZE

    if declared_length_1 != expected_payload_length:
        raise SystemExit(
            f"First payload length is invalid: {declared_length_1}"
        )

    if declared_length_2 != expected_payload_length:
        raise SystemExit(
            f"Second payload length is invalid: {declared_length_2}"
        )

    firmware = read_c_string(original, 0x10, 0x30)
    hardware = read_c_string(original, 0x30, 0x50)

    if firmware != "RY02_3.00.38_250403":
        raise SystemExit(f"Unexpected firmware identifier: {firmware!r}")

    if hardware != "RY02_V3.0":
        raise SystemExit(f"Unexpected hardware identifier: {hardware!r}")

    stored_checksum = read_u32(original, 0x0C)
    calculated_checksum = sum(original[HEADER_SIZE:]) & 0xFFFFFFFF

    if stored_checksum != EXPECTED_OLD_CHECKSUM:
        raise SystemExit(
            f"Unexpected stored checksum: 0x{stored_checksum:08X}"
        )

    if calculated_checksum != EXPECTED_OLD_CHECKSUM:
        raise SystemExit(
            f"Source payload checksum mismatch: 0x{calculated_checksum:08X}"
        )

    actual_context = original[
        CONTAINER_PATCH_OFFSET:
        CONTAINER_PATCH_OFFSET + len(EXPECTED_CONTEXT)
    ]

    if actual_context != EXPECTED_CONTEXT:
        raise SystemExit(
            "Patch context mismatch.\n"
            f"Expected: {EXPECTED_CONTEXT.hex(' ')}\n"
            f"Actual:   {actual_context.hex(' ')}"
        )

    modified = bytearray(original)

    modified[
        CONTAINER_PATCH_OFFSET:
        CONTAINER_PATCH_OFFSET + len(PATCHED_CONTEXT)
    ] = PATCHED_CONTEXT

    new_checksum = sum(modified[HEADER_SIZE:]) & 0xFFFFFFFF

    if new_checksum != EXPECTED_NEW_CHECKSUM:
        raise SystemExit(
            "Unexpected patched checksum.\n"
            f"Expected: 0x{EXPECTED_NEW_CHECKSUM:08X}\n"
            f"Actual:   0x{new_checksum:08X}"
        )

    struct.pack_into("<I", modified, 0x0C, new_checksum)

    changed_offsets = [
        offset
        for offset, (old_byte, new_byte) in enumerate(
            zip(original, modified)
        )
        if old_byte != new_byte
    ]

    expected_changed_offsets = [
        0x0C,
        CONTAINER_PATCH_OFFSET,
    ]

    if changed_offsets != expected_changed_offsets:
        formatted = ", ".join(
            f"0x{offset:08X}" for offset in changed_offsets
        )
        raise SystemExit(
            "Unexpected modified offsets: "
            + formatted
        )

    final_payload_checksum = (
        sum(modified[HEADER_SIZE:]) & 0xFFFFFFFF
    )
    final_stored_checksum = read_u32(modified, 0x0C)

    if final_payload_checksum != final_stored_checksum:
        raise SystemExit("Final checksum verification failed.")

    OUTPUT.write_bytes(modified)

    print("RY02 FasterRawValues candidate created successfully.")
    print()
    print(f"Source:              {SOURCE}")
    print(f"Output:              {OUTPUT}")
    print(f"Size:                {len(modified)} bytes")
    print(f"Firmware identifier: {firmware}")
    print(f"Hardware identifier: {hardware}")
    print()
    print(
        f"Patch payload offset:   "
        f"0x{PAYLOAD_PATCH_OFFSET:08X}"
    )
    print(
        f"Patch container offset: "
        f"0x{CONTAINER_PATCH_OFFSET:08X}"
    )
    print("Instruction change:     movs r2,#125 → movs r2,#32")
    print("Timer change:           1000 → 256")
    print()
    print(
        f"Old payload checksum:   "
        f"0x{EXPECTED_OLD_CHECKSUM:08X}"
    )
    print(
        f"New payload checksum:   "
        f"0x{new_checksum:08X}"
    )
    print()
    print(f"Source SHA-256: {sha256(original)}")
    print(f"Output SHA-256: {sha256(modified)}")
    print()
    print("Changed container offsets:")
    for offset in changed_offsets:
        print(
            f"  0x{offset:08X}: "
            f"{original[offset]:02X} → {modified[offset]:02X}"
        )


if __name__ == "__main__":
    main()
