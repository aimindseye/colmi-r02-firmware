# RY02 BlueX SDK3 RingCLI Adapter

This directory contains a build-only overlay for:

```text
reference/bluex-sdk3-v3.3.8-20250117/
  examples/demo/ble_custom_profile
```

It creates two 128-bit GATT services using the exact reverse-byte UUIDs found
in the accepted R02 `.38` payload.

## Command service

```text
service  6E40FFF0-B5A3-F393-E0A9-E50E24DCCA9E
write    6E400002-B5A3-F393-E0A9-E50E24DCCA9E
notify   6E400003-B5A3-F393-E0A9-E50E24DCCA9E
```

## Data service

```text
service  DE5BF728-D711-4E47-AF26-65E3012A5DC7
write    DE5BF72A-D711-4E47-AF26-65E3012A5DC7
notify   DE5BF729-D711-4E47-AF26-65E3012A5DC7
```

## Implemented SDK3 routing

```text
two 128-bit service databases
command/data write-handle routing
command/data CCCD state
write confirmations
command notifications through GATTC_SEND_EVT_CMD
portable RingCLI protocol core
synthetic battery/time/LED/realtime behavior
```

## Deliberately inert

```text
physical LED
RTC writes
shutdown
sensor acquisition
sleep/oxygen history responses
persistent storage
OTA packaging
R02-specific linker placement
device installation
```

The materializer copies the SDK example into `build/` and never modifies the
reference SDK.
