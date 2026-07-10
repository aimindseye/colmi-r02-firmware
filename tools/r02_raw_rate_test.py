#!/usr/bin/env python3

from __future__ import annotations

import asyncio
import time

from bleak import BleakClient, BleakScanner


MAIN_SERVICE = "6e40fff0-b5a3-f393-e0a9-e50e24dcca9e"
WRITE_CHAR = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
NOTIFY_CHAR = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

TARGET_NAMES = ("R02", "RY02")
SCAN_SECONDS = 30.0
RAW_TEST_SECONDS = 10.0


def make_command(prefix: bytes) -> bytes:
    """
    Create the ring's 16-byte command packet:
      bytes 0..14 = command plus zero padding
      byte 15     = additive checksum
    """
    if len(prefix) > 15:
        raise ValueError("Command prefix cannot exceed 15 bytes")

    packet = bytearray(16)
    packet[:len(prefix)] = prefix
    packet[15] = sum(packet[:15]) & 0xFF
    return bytes(packet)


BATTERY_COMMAND = make_command(bytes.fromhex("03"))
RAW_START_COMMAND = make_command(bytes.fromhex("A10404"))
RAW_STOP_COMMAND = make_command(bytes.fromhex("A102"))


async def find_ring():
    print(f"Scanning for the R02 for {SCAN_SECONDS:.0f} seconds...")

    def filter_device(device, advertisement):
        name = (
            advertisement.local_name
            or device.name
            or ""
        ).upper()

        services = {
            value.lower()
            for value in (advertisement.service_uuids or [])
        }

        return (
            any(token in name for token in TARGET_NAMES)
            or MAIN_SERVICE in services
            or "0000fee7-0000-1000-8000-00805f9b34fb" in services
        )

    device = await BleakScanner.find_device_by_filter(
        filter_device,
        timeout=SCAN_SECONDS,
    )

    if device is None:
        raise RuntimeError("R02 was not found during the scan")

    print(f"Found: {device.name or '<unnamed>'}")
    print(f"ID:    {device.address}")
    return device


async def main() -> None:
    device = await find_ring()

    accelerometer_times: list[float] = []
    packet_counts = {
        "a101": 0,
        "a102": 0,
        "a103": 0,
        "other": 0,
    }

    test_start: float | None = None

    def notification_handler(_, data: bytearray) -> None:
        nonlocal test_start

        payload = bytes(data)
        now = time.monotonic()
        hex_data = payload.hex()

        if payload.startswith(b"\xA1\x01"):
            packet_counts["a101"] += 1
            packet_type = "A101"
        elif payload.startswith(b"\xA1\x02"):
            packet_counts["a102"] += 1
            packet_type = "A102"
        elif payload.startswith(b"\xA1\x03"):
            packet_counts["a103"] += 1
            accelerometer_times.append(now)
            packet_type = "A103"
        else:
            packet_counts["other"] += 1
            packet_type = "OTHER"

        elapsed = 0.0 if test_start is None else now - test_start
        print(f"{elapsed:7.3f}s  {packet_type}  {hex_data}")

    async with BleakClient(device, timeout=20.0) as client:
        print(f"Connected: {client.is_connected}")

        services = client.services
        service_uuids = {service.uuid.lower() for service in services}

        if MAIN_SERVICE not in service_uuids:
            print("Discovered services:")
            for service in services:
                print(f"  {service.uuid}")
            raise RuntimeError("R02 command service was not found")

        write_characteristic = services.get_characteristic(WRITE_CHAR)
        notify_characteristic = services.get_characteristic(NOTIFY_CHAR)

        if write_characteristic is None:
            raise RuntimeError("R02 write characteristic was not found")

        if notify_characteristic is None:
            raise RuntimeError("R02 notify characteristic was not found")

        await client.start_notify(
            notify_characteristic,
            notification_handler,
        )

        try:
            print("\nRequesting battery status...")
            await client.write_gatt_char(
                write_characteristic,
                BATTERY_COMMAND,
                response=False,
            )
            await asyncio.sleep(1.0)

            print(
                f"\nStarting raw stream for "
                f"{RAW_TEST_SECONDS:.0f} seconds..."
            )

            test_start = time.monotonic()

            await client.write_gatt_char(
                write_characteristic,
                RAW_START_COMMAND,
                response=False,
            )

            await asyncio.sleep(RAW_TEST_SECONDS)

        finally:
            print("\nStopping raw stream...")

            try:
                await client.write_gatt_char(
                    write_characteristic,
                    RAW_STOP_COMMAND,
                    response=False,
                )
                await asyncio.sleep(0.5)
            finally:
                await client.stop_notify(notify_characteristic)

    print("\n===== RAW RATE RESULT =====")
    print(f"Test duration: {RAW_TEST_SECONDS:.1f} seconds")
    print(f"A101 packets:  {packet_counts['a101']}")
    print(f"A102 packets:  {packet_counts['a102']}")
    print(f"A103 packets:  {packet_counts['a103']}")
    print(f"Other packets: {packet_counts['other']}")

    a103_count = packet_counts["a103"]
    approximate_rate = a103_count / RAW_TEST_SECONDS

    print(f"A103 rate:     {approximate_rate:.2f} packets/second")

    if len(accelerometer_times) >= 2:
        intervals = [
            later - earlier
            for earlier, later in zip(
                accelerometer_times,
                accelerometer_times[1:],
            )
        ]

        average_interval = sum(intervals) / len(intervals)

        print(
            f"Average A103 interval: "
            f"{average_interval * 1000:.1f} ms"
        )
        print(
            f"Minimum A103 interval: "
            f"{min(intervals) * 1000:.1f} ms"
        )
        print(
            f"Maximum A103 interval: "
            f"{max(intervals) * 1000:.1f} ms"
        )

    print()
    if approximate_rate < 2.0:
        print("Interpretation: original ~1-second timer remains active.")
    elif 3.0 <= approximate_rate <= 5.5:
        print("Interpretation: faster ~256-ms timer appears active.")
    else:
        print(
            "Interpretation: unexpected rate; inspect the timestamps "
            "and packet sequence."
        )


if __name__ == "__main__":
    asyncio.run(main())
