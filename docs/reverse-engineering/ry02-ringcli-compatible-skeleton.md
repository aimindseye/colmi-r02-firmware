# RY02 RingCLI-Compatible Skeleton

**Status:** Build-only protocol-core gate  
**Device interaction:** None

## Accepted input evidence

The RingCLI contract verifier passed:

```text
source checks: 42
source failures: 0
protocol contract: PASS
```

The pinned RingCLI commit is:

```text
3cc884d943c4b4052d20ad6bb8697d75cf713060
```

All six command/data UART UUIDs are present in the accepted stock `.38` payload
in full reverse-byte order. This closes static source-to-firmware correlation
for the BLE service identities.

## Deliverable scope

The skeleton provides a C99 protocol core and host tests. It deliberately stops
before BlueX GATT registration or R02 hardware control.

Implemented commands:

```text
01 set time
03 battery
08 shutdown effect
10 LED/find effect
16 heart-rate period get/set
69 real-time start/continue
6A real-time stop
```

Recognized Data UART requests:

```text
27 sleep history
2A oxygen history
```

History responses remain unsupported.

## Acceptance rule

The skeleton is accepted only when:

```text
analysis fixture JSON matches all 12 canonical packets
CMake build succeeds with warnings as errors
all C tests pass
no target image is generated
```

## Next boundary

After this host-only gate passes, inspect one SDK3 BLE example and create an
adapter that registers only the six verified UUIDs and routes writes into the
protocol core.

That later adapter remains build-only until recovery and bootloader acceptance
are established.
