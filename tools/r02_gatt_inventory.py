#!/usr/bin/env python3

from __future__ import annotations

import asyncio
from bleak import BleakClient, BleakScanner


TARGET_ID = "7DD85D6F-9867-D096-0ECD-54877726C18E"


def printable_ascii(data: bytes) -> str:
    return "".join(
        chr(value) if 32 <= value <= 126 else "."
        for value in data
    )


async def find_r02():
    def matches(device, advertisement):
        name = (
            advertisement.local_name
            or device.name
            or ""
        ).upper()

        return (
            device.address.upper() == TARGET_ID
            or "R02" in name
            or "RY02" in name
        )

    device = await BleakScanner.find_device_by_filter(
        matches,
        timeout=30.0,
    )

    if device is None:
        raise RuntimeError("Exact R02 was not found")

    return device


async def main() -> None:
    device = await find_r02()

    print(f"Device name: {device.name or '<unnamed>'}")
    print(f"Device ID:   {device.address}")
    print()

    async with BleakClient(device, timeout=20.0) as client:
        print(f"Connected:   {client.is_connected}")
        print()

        for service in client.services:
            print("=" * 72)
            print(f"SERVICE {service.uuid}")
            print(f"Description: {service.description}")

            for characteristic in service.characteristics:
                properties = ", ".join(characteristic.properties)

                print()
                print(f"  CHARACTERISTIC {characteristic.uuid}")
                print(f"  Description:    {characteristic.description}")
                print(f"  Properties:     {properties}")

                if "read" in characteristic.properties:
                    try:
                        value = bytes(
                            await client.read_gatt_char(
                                characteristic
                            )
                        )

                        print(f"  Length:         {len(value)}")
                        print(f"  Hex:            {value.hex()}")
                        print(
                            f"  ASCII:          "
                            f"{printable_ascii(value)}"
                        )
                    except Exception as error:
                        print(f"  Read error:     {error}")

                for descriptor in characteristic.descriptors:
                    print(
                        f"    Descriptor:   "
                        f"{descriptor.uuid} "
                        f"handle={descriptor.handle}"
                    )

        print()
        print("Inventory complete.")


if __name__ == "__main__":
    asyncio.run(main())
