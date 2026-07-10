#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

try:
    from capstone import (
        Cs,
        CS_ARCH_ARM,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_THUMB,
    )
except ImportError as error:
    raise SystemExit(
        "Capstone is required. Install it with:\n"
        "  python -m pip install capstone"
    ) from error


ORIGINAL = Path(
    "vendor/RY02_3.00.38_250403.bin"
)

PATCHED = Path(
    "release/ry02-3.00.38-faster-raw-r1/"
    "RY02_3.00.38_250403_FasterRawValuesMOD.bin"
)

EXPECTED_ORIGINAL_SHA256 = (
    "dbf64e3dc9aef112a4d69e46e516efb27f2ed2e3dc1d2d3f1af75939cc46487e"
)

EXPECTED_PATCHED_SHA256 = (
    "94d8c531bcaa8fc610afc22a55df37f57db420cb0e613edc501c914bc410b336"
)

HEADER_SIZE = 0x50
PATCH_PAYLOAD_OFFSET = 0x1DDE
PATCH_CONTAINER_OFFSET = HEADER_SIZE + PATCH_PAYLOAD_OFFSET

EXPECTED_MAGIC = bytes.fromhex("e5c3bd81")
EXPECTED_SIZE = 118116

ORIGINAL_INSTRUCTION = bytes.fromhex("7d22")
PATCHED_INSTRUCTION = bytes.fromhex("2022")

ORIGINAL_SEQUENCE = bytes.fromhex(
    "7d220123d200"
)

PATCHED_SEQUENCE = bytes.fromhex(
    "20220123d200"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def find_all(data: bytes, pattern: bytes) -> list[int]:
    offsets: list[int] = []
    start = 0

    while True:
        position = data.find(pattern, start)

        if position < 0:
            break

        offsets.append(position)
        start = position + 1

    return offsets


def describe_image(
    label: str,
    path: Path,
    expected_sha256: str,
) -> tuple[bytes, bytes]:
    if not path.exists():
        raise SystemExit(f"Missing {label} image: {path}")

    container = path.read_bytes()
    digest = sha256(container)

    print("=" * 78)
    print(label)
    print("=" * 78)
    print(f"Path:                  {path}")
    print(f"Size:                  {len(container)}")
    print(f"SHA-256:               {digest}")
    print(f"Expected SHA-256:      {expected_sha256}")
    print(
        "SHA-256 match:         "
        + ("YES" if digest == expected_sha256 else "NO")
    )

    if len(container) < HEADER_SIZE:
        raise SystemExit(f"{label} image is smaller than its header")

    magic = container[:4]
    length_1 = u32le(container, 0x04)
    length_2 = u32le(container, 0x08)
    stored_checksum = u32le(container, 0x0C)

    payload = container[HEADER_SIZE:]
    calculated_checksum = sum(payload) & 0xFFFFFFFF

    print(f"Magic:                 {magic.hex()}")
    print(
        "Magic match:           "
        + ("YES" if magic == EXPECTED_MAGIC else "NO")
    )
    print(f"Header length field 1: {length_1}")
    print(f"Header length field 2: {length_2}")
    print(f"Actual payload length: {len(payload)}")
    print(f"Stored payload sum32:  0x{stored_checksum:08x}")
    print(f"Actual payload sum32:  0x{calculated_checksum:08x}")
    print(
        "Payload checksum match:"
        + (" YES" if stored_checksum == calculated_checksum else " NO")
    )

    firmware_marker = b"RY02_3.00.38_250403"
    hardware_marker = b"RY02_V3.0"

    print(
        f"Firmware marker offset: "
        f"0x{container.find(firmware_marker):x}"
    )
    print(
        f"Hardware marker offset: "
        f"0x{container.find(hardware_marker):x}"
    )

    return container, payload


def disassemble_window(
    label: str,
    payload: bytes,
) -> None:
    start = PATCH_PAYLOAD_OFFSET - 0x18
    end = PATCH_PAYLOAD_OFFSET + 0x28
    code = payload[start:end]

    disassembler = Cs(
        CS_ARCH_ARM,
        CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
    )

    print()
    print(f"{label} disassembly around payload offset 0x1DDE")
    print("-" * 78)

    for instruction in disassembler.disasm(code, start):
        marker = (
            "  <== PATCH"
            if instruction.address == PATCH_PAYLOAD_OFFSET
            else ""
        )

        raw = instruction.bytes.hex()

        print(
            f"0x{instruction.address:06x}: "
            f"{raw:<10} "
            f"{instruction.mnemonic:<8} "
            f"{instruction.op_str}"
            f"{marker}"
        )


def main() -> None:
    original_container, original_payload = describe_image(
        "ORIGINAL",
        ORIGINAL,
        EXPECTED_ORIGINAL_SHA256,
    )

    print()

    patched_container, patched_payload = describe_image(
        "PATCHED",
        PATCHED,
        EXPECTED_PATCHED_SHA256,
    )

    print()
    print("=" * 78)
    print("CONTAINER DIFFERENCES")
    print("=" * 78)

    if len(original_container) != len(patched_container):
        print(
            "ERROR: sizes differ: "
            f"{len(original_container)} vs "
            f"{len(patched_container)}"
        )
    else:
        differences = [
            (offset, before, after)
            for offset, (before, after) in enumerate(
                zip(original_container, patched_container)
            )
            if before != after
        ]

        print(f"Difference count: {len(differences)}")

        for offset, before, after in differences:
            region = (
                "header"
                if offset < HEADER_SIZE
                else f"payload+0x{offset - HEADER_SIZE:x}"
            )

            print(
                f"0x{offset:08x}: "
                f"0x{before:02x} -> 0x{after:02x} "
                f"({region})"
            )

    print()
    print("=" * 78)
    print("PATCH LOCATION")
    print("=" * 78)
    print(
        f"Payload offset:         "
        f"0x{PATCH_PAYLOAD_OFFSET:x}"
    )
    print(
        f"Container offset:       "
        f"0x{PATCH_CONTAINER_OFFSET:x}"
    )

    original_bytes = original_container[
        PATCH_CONTAINER_OFFSET:
        PATCH_CONTAINER_OFFSET + 2
    ]

    patched_bytes = patched_container[
        PATCH_CONTAINER_OFFSET:
        PATCH_CONTAINER_OFFSET + 2
    ]

    print(f"Original instruction:   {original_bytes.hex()}")
    print(f"Patched instruction:    {patched_bytes.hex()}")
    print(
        "Expected original:      "
        f"{ORIGINAL_INSTRUCTION.hex()}"
    )
    print(
        "Expected patched:       "
        f"{PATCHED_INSTRUCTION.hex()}"
    )

    original_sequence_offsets = find_all(
        original_payload,
        ORIGINAL_SEQUENCE,
    )

    patched_sequence_offsets = find_all(
        patched_payload,
        PATCHED_SEQUENCE,
    )

    print()
    print(
        "Original timer sequence "
        f"{ORIGINAL_SEQUENCE.hex()} occurrences:"
    )

    for offset in original_sequence_offsets:
        print(f"  payload offset 0x{offset:x}")

    print(
        "Patched timer sequence "
        f"{PATCHED_SEQUENCE.hex()} occurrences:"
    )

    for offset in patched_sequence_offsets:
        print(f"  payload offset 0x{offset:x}")

    disassemble_window("ORIGINAL", original_payload)
    disassemble_window("PATCHED", patched_payload)

    print()
    print("=" * 78)
    print("OTA TRANSFER LENGTH CORRELATION")
    print("=" * 78)

    image_size = len(patched_container)
    ota_data_per_part = 0x400
    part_number_size = 2
    ota_header_size = 6
    ble_fragment_size = 200

    total_parts = (
        image_size + ota_data_per_part - 1
    ) // ota_data_per_part

    final_firmware_bytes = (
        image_size % ota_data_per_part
    )

    if final_firmware_bytes == 0:
        final_firmware_bytes = ota_data_per_part

    final_packet_bytes = (
        final_firmware_bytes
        + part_number_size
        + ota_header_size
    )

    fragment_sizes: list[int] = []
    remaining = final_packet_bytes

    while remaining > 0:
        fragment = min(ble_fragment_size, remaining)
        fragment_sizes.append(fragment)
        remaining -= fragment

    print(f"Image size:             {image_size}")
    print(f"OTA data per part:      {ota_data_per_part}")
    print(f"Total OTA parts:        {total_parts}")
    print(f"Final firmware bytes:   {final_firmware_bytes}")
    print(f"Final framed packet:    {final_packet_bytes}")
    print(
        "Final BLE fragments:   "
        + " + ".join(str(value) for value in fragment_sizes)
    )

    print()
    print("=" * 78)
    print("STATIC RESULT")
    print("=" * 78)

    static_ok = all(
        [
            len(original_container) == EXPECTED_SIZE,
            len(patched_container) == EXPECTED_SIZE,
            sha256(original_container)
            == EXPECTED_ORIGINAL_SHA256,
            sha256(patched_container)
            == EXPECTED_PATCHED_SHA256,
            original_bytes == ORIGINAL_INSTRUCTION,
            patched_bytes == PATCHED_INSTRUCTION,
            PATCH_PAYLOAD_OFFSET
            in original_sequence_offsets,
            PATCH_PAYLOAD_OFFSET
            in patched_sequence_offsets,
        ]
    )

    if static_ok:
        print(
            "PASS: the frozen release contains the intended "
            "single-instruction timer patch."
        )
    else:
        print(
            "FAIL: one or more static patch assumptions did "
            "not validate."
        )

    print()
    print(
        "Hardware result remains separate: the exact R02 "
        "continued reporting approximately 1000 ms after reboot."
    )


if __name__ == "__main__":
    main()
