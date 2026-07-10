# COLMI R02 / RY02 Firmware Research

Reverse-engineering notes and offline analysis tools for the COLMI R02 / RF03-family smart ring firmware and BLE DFU protocol.

> [!CAUTION]
> This repository is a research workspace, not a safe flashing package. The current ring has no validated SWD recovery path. Do not flash modified firmware based only on these notes. The active workstream is intentionally halted at offline analysis.

## Goal

The long-term goal is to understand the R02/RY02 firmware and protocol well enough to:

- build reliable open-source BLE tooling for ring telemetry and remote-control events;
- document raw sensor and health-data packet formats;
- understand the OTA container, transfer protocol, boot validation, and rollback behavior;
- evaluate whether navigation-oriented gestures or a custom firmware path are feasible without risking hardware;
- produce reproducible analysis rather than opaque one-off binary patches.

This is **not medical software**. Ring health readings and raw optical data must not be treated as diagnostic measurements.

## Target device

Observed device:

| Property | Value |
|---|---|
| BLE name | `R02_F103` |
| Hardware revision | `RY02_V3.0` |
| Stock firmware | `RY02_3.00.38_250403` |
| Main service | `6e40fff0-b5a3-f393-e0a9-e50e24dcca9e` |
| Main write characteristic | `6e400002-b5a3-f393-e0a9-e50e24dcca9e` |
| Main notify characteristic | `6e400003-b5a3-f393-e0a9-e50e24dcca9e` |
| OTA service | `de5bf728-d711-4e47-af26-65e3012a5dc7` |
| OTA notify characteristic | `de5bf729-d711-4e47-af26-65e3012a5dc7` |
| OTA write characteristic | `de5bf72a-d711-4e47-af26-65e3012a5dc7` |

## Current verified status

### Canonical stock firmware

The firmware cached by the official QRing Android app is byte-for-byte identical to the independently downloaded vendor image:

| Property | Value |
|---|---|
| File | `RY02_3.00.38_250403.bin` |
| Size | `118116` bytes |
| SHA-256 | `dbf64e3dc9aef112a4d69e46e516efb27f2ed2e3dc1d2d3f1af75939cc46487e` |
| QRing cache path | `/sdcard/Android/data/com.app.cq.ring/files/dfu/RY02_3.00.38_250403.bin` |

The repository does not redistribute this firmware. Obtain it from hardware and services you are authorized to use.

### RY02 OTA container

The `.33` and `.38` RY02 images use the same newer container:

- header size: `0x50` bytes;
- magic: `e5 c3 bd 81`;
- duplicated payload-length fields at `0x04` and `0x08`;
- little-endian payload byte-sum32 at `0x0C`;
- firmware string in the header;
- hardware string in the header.

For `.38`:

- container length: `118116`;
- payload length: `118036`;
- integrity validation: passed.

Older `R02_V3.0` images such as `.06` and `.17` use a different `0x100`-byte CRC32 container and are not direct binary patch donors for RY02.

### Firmware lineage

`RY02_3.00.33_250117.bin` is the only direct predecessor found in the public ATC firmware corpus:

- same `RY02_V3.0` hardware string;
- same `0x50` sum32 container;
- strong relocated block similarity;
- the raw-command handler and timer setup move together by exactly `+0x20` between `.33` and `.38`.

Relevant public reference: [atc1441/ATC_RF03_Ring](https://github.com/atc1441/ATC_RF03_Ring).

### Raw-data protocol

Observed commands on the main UART-like BLE service:

| Command | Meaning observed |
|---|---|
| `A1 04 04` | start raw streaming |
| `A1 02` | stop raw streaming |
| `A1 01 ...` | optical / blood-related raw packet |
| `A1 02 ...` | heart-related raw packet |
| `A1 03 ...` | accelerometer packet |
| `02 04` | camera/remote mode enable |
| `02 02` | camera/remote event |
| `02 06` | camera/remote mode disable |

On stock `.38`, A101, A102, and A103 are each observed at approximately `1.00 Hz`.

### Raw timer trace

The raw timer path is now statically established:

| Item | `.33` | `.38` |
|---|---:|---:|
| A1 handler | `0x1CE2` | `0x1D02` |
| raw timer site | `0x1DBE` | `0x1DDE` |
| timer wrapper | `0x36B4` | `0x376C` |
| callback | `0x1B24` lineage | `0x1B44` |

At `.38` payload offset `0x1DDE`, the firmware executes:

```asm
movs r2, #125
movs r3, #1
lsls r2, r2, #3    ; r2 = 1000
bl   0x376c
```

No instruction overwrites `r2` before the timer wrapper call.

The callback pointer `0x00825B45` maps to payload offset `0x1B44` when the application image base is `0x00824000`. The callback constructs and sends A101, A102, and A103 on every invocation. No independent one-second throttle was found before those sends.

The timer wrapper forwards the period unchanged to the platform timer implementation. The same scheduler is used elsewhere with periodic values of `10`, `30`, `40`, `100`, `320`, and `400` milliseconds. Therefore, a `256 ms` periodic timer is supported by the scheduler.

### Patch experiment and conclusion

A one-byte experimental patch changed the timer constant from `125` to `32`:

```text
1000 ms = 125 << 3
 256 ms =  32 << 3
```

Patch differences from stock:

- payload byte at container offset `0x1E2E`: `0x7D -> 0x20`;
- sum32 byte at header offset `0x0C`: updated;
- total changed bytes: `2`;
- container lengths and integrity: valid.

This mirrors the public ATC `.06` experiment structurally: one payload byte plus the required outer integrity field.

The OTA transfer completed through command 4 and command 5 was sent, but after reboot the ring still streamed at exactly `1 Hz`. Static analysis shows that an executing patched image should have produced approximately `3.906` callback cycles per second. The best current conclusion is:

> The modified application was not the application executing after reboot.

This is not proof of exactly where activation failed.

### Official QRing DFU state machine

The QRing app uses the same custom OTA service and `0xBC` frame protocol as the research writer:

```text
byte 0      0xBC
byte 1      command
bytes 2-3   payload length
bytes 4-5   CRC16(payload)
bytes 6...  payload
```

Successful command flow:

1. command 1: start;
2. command 2: image type, total length, whole-file CRC16, checksum16;
3. command 3: numbered 1024-byte data blocks;
4. command 4: check/final validation;
5. command 5: end/release/reboot transition.

The official app does not wait for a command-5 acknowledgement. After a successful command-4 result it queues command 5, clears its result callback, clears the BLE callback, and then disconnects shortly afterward.

No missing QRing-only command 6, separate activation hash, or explicit bank-selection BLE command was found in the Android implementation.

## Remaining hypotheses

The leading unresolved explanations are:

1. **Boot-time internal validation** — the bootloader may validate metadata, an internal checksum, digest, or signature not covered by the outer OTA container.
2. **Same-version activation policy** — the RY02 bootloader may suppress activation when the incoming and installed version strings are both `.38`.
3. **Trial boot and rollback** — the modified image may start and fail an application-confirmation or health check, causing automatic fallback.
4. **Command-5 delivery race** — possible but less likely; the browser writer uses a direct asynchronous Web Bluetooth write while QRing uses its internal request queue.

## Safety status

- The ring is currently healthy.
- No validated SWD recovery path is available.
- No additional OTA attempts are planned.
- Work is parked at **offline boot-validation and startup-analysis**.
- A valid container checksum does **not** make a modified image safe to flash.

## Repository layout

```text
docs/
  FINDINGS-2026-07-10.md
  FIRMWARE-PROVENANCE.md
  REPRODUCIBILITY.md
scripts/
  check_repo.sh
tools/
  analyze_ota_acceptance_headers.py
  compare_atc_ota_family.py
  compare_ry02_33_38_raw_path.py
  inspect_ry02_raw_callback.py
  list_ry02_timer_periods.py
  trace_ry02_raw_timer_call.py
  validate_ry02_container.py
requirements-analysis.txt
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-analysis.txt
```

The tools default to the local research layout used during this investigation:

```text
downloads/qring-latest/RY02_3.00.38_250403.bin
vendor/atc-ota-firmwares/RY02_3.00.33_250117.bin
vendor/ATC_RF03_Ring/
```

Most tools also accept path arguments. Run `--help` for details.

## Quick validation

```bash
python3 tools/validate_ry02_container.py \
  downloads/qring-latest/RY02_3.00.38_250403.bin

python3 tools/compare_ry02_33_38_raw_path.py
python3 tools/trace_ry02_raw_timer_call.py
python3 tools/inspect_ry02_raw_callback.py
python3 tools/list_ry02_timer_periods.py

./scripts/check_repo.sh
```

## Data handling

Do not commit:

- vendor firmware binaries;
- patched firmware images;
- APK files;
- JADX output from proprietary applications;
- Bluetooth dumps containing device identifiers;
- logs containing authentication tokens or personal account data.

The included `.gitignore` blocks the common private and binary paths used by this project.

## Next offline work

1. identify the application vector table and reset path;
2. search `.33` and `.38` for internal image descriptors and digest-sized regions;
3. locate bootloader-facing image-confirmation or rollback calls;
4. inspect startup writes to retained/flash metadata;
5. determine whether same-version updates are intentionally ignored;
6. document findings before considering any future hardware experiment.

## Acknowledgements

- [atc1441/ATC_RF03_Ring](https://github.com/atc1441/ATC_RF03_Ring) for public RF03/R02 firmware research and comparison images.
- QRing Android app behavior was studied locally for protocol interoperability and documentation.

## License

No license has been selected yet. Until a license is added, normal copyright rules apply to the original material in this repository. Third-party firmware, applications, and decompiled output are not part of this repository and remain subject to their respective rights.
