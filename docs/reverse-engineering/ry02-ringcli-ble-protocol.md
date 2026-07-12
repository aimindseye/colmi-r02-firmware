# RY02 RingCLI BLE Protocol Contract

**Reference:** `smittytone/RingCLI`  
**Status:** Next offline protocol-correlation gate  
**Device interaction:** None

## Accepted host-side protocol

RingCLI defines two independent UART-style BLE services.

### Command UART

```text
service  6E40FFF0-B5A3-F393-E0A9-E50E24DCCA9E
write    6E400002-B5A3-F393-E0A9-E50E24DCCA9E
notify   6E400003-B5A3-F393-E0A9-E50E24DCCA9E
```

Requests are 16 bytes:

```text
byte 0       command
bytes 1..14  zero-padded payload
byte 15      additive 8-bit checksum of bytes 0..14
```

Known commands:

```text
01 set time
03 battery
08 shutdown
10 flash LED
15 stored heart-rate data
16 heart-rate period/configuration
43 activity/steps
69 start or continue real-time measurement
6A stop real-time measurement
73 activity-related unknown
FF error response marker
```

Real-time measurement types:

```text
01 heart-rate batch
03 blood oxygen
06 heart-rate continuous
0A HRV
```

Real-time actions:

```text
01 start
02 pause
03 continue
04 stop
```

### Data UART

```text
service  DE5BF728-D711-4E47-AF26-65E3012A5DC7
write    DE5BF72A-D711-4E47-AF26-65E3012A5DC7
notify   DE5BF729-D711-4E47-AF26-65E3012A5DC7
```

Requests are six bytes:

```text
BC <request-id> 00 00 FF FF
```

Known request IDs:

```text
27 sleep history
2A blood-oxygen history
```

## Separation from the OTA protocol

The RingCLI command/data UART protocols are not the previously analyzed OTA
transport:

```text
RingCLI command UART:
  fixed 16-byte request
  additive 8-bit checksum

RingCLI data UART:
  fixed 6-byte request
  variable history response

OTA transport:
  BC command length CRC16 frame
  CRC-16/MODBUS
  staged-image command sequence
```

The shared byte `BC` is insufficient to merge these protocols.

## Value for custom firmware

This protocol is suitable as the external compatibility contract for a future
custom application. A build-only prototype can implement the UUIDs and a small
safe subset first:

```text
battery query
time set
LED/find
real-time start/stop state machine with synthetic values
```

Sensor acquisition and persistent history should remain separate later phases.

## Gate objective

Run `tools/verify_ringcli_protocol_contract.py` to:

```text
verify constants and packet constructors against the pinned RingCLI source
generate canonical request fixtures
scan stock .38 for UUID byte representations
emit a JSON protocol manifest
```

A clean source-contract pass establishes a host compatibility target. UUID
absence in a raw firmware scan does not disprove the service because UUID tables
may be encoded or assembled differently.
