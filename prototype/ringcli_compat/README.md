# RY02 RingCLI-Compatible Protocol Skeleton

This is a **build-only, host-tested protocol core**. It is not an R02 firmware
image and contains no OTA packaging or device installation path.

## Implemented

```text
16-byte command-UART packet creation and validation
8-bit additive checksum
6-byte data-UART request parsing
battery response
time-set parsing and acknowledgement
LED/find acknowledgement
shutdown effect without response
heart-rate period get/set
real-time start, continue, and stop state
synthetic real-time value notification
BlueX integration callback boundary
```

## Deliberately not implemented

```text
BlueX GATT registration APIs
board GPIO or LED control
RTC writes
power-down implementation
sensor drivers
sleep/oxygen history response encoding
persistent storage
OTA or bootloader integration
```

## Verified UUIDs

```text
Command service  6E40FFF0-B5A3-F393-E0A9-E50E24DCCA9E
Command write    6E400002-B5A3-F393-E0A9-E50E24DCCA9E
Command notify   6E400003-B5A3-F393-E0A9-E50E24DCCA9E

Data service     DE5BF728-D711-4E47-AF26-65E3012A5DC7
Data write       DE5BF72A-D711-4E47-AF26-65E3012A5DC7
Data notify      DE5BF729-D711-4E47-AF26-65E3012A5DC7
```

All six UUIDs occur in reverse-byte storage form in the accepted stock `.38`
payload.

## Host build

```bash
cmake -S prototype/ringcli_compat       -B build/ringcli-compat

cmake --build build/ringcli-compat

ctest   --test-dir build/ringcli-compat   --output-on-failure
```

Expected test output:

```text
RY02 RingCLI protocol skeleton tests: PASS
```

## Integration rule

The BlueX adapter should call `ry02_bluex_on_command_write()` from the verified
command write characteristic and publish responses through the verified command
notify characteristic.

The adapter contract is intentionally SDK-neutral until an exact SDK3 GATT
example and build target are selected.
