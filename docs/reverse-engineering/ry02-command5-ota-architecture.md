# RY02 Command-5 / OTA Architecture Report

**Firmware:** `RY02_3.00.38_250403.bin`  
**Hardware string:** `RY02_V3.0`  
**Runtime application base:** `0x00824000`  
**Report status:** Consolidated static-analysis baseline  
**Date:** 2026-07-11

## 1. Executive conclusion

The RY02 OTA implementation is a five-command application protocol that receives, validates at a limited structural level, and stages the inner firmware image. Command 5 does not directly reset the MCU, select a boot bank, jump to a new image, or write any known reset controller.

The application-visible command-5 chain is:

```text
Command 5 handler
  -> verify OTA phase 4
  -> transition OTA state to phase 5
  -> perform subsystem cleanup
  -> persist a 0xA4-byte application/time-state record
  -> restart timer object 0x0020A7B8 for 1000 ms
  -> perform additional cleanup
  -> return

After 1000 ms:
  timer callback 0x0082AC4A
    -> calculate current wall-clock seconds
    -> store the refreshed value at state record +0x04
    -> call low dispatcher candidate 0x0000029C with (1, 0xD3)
    -> return
```

The static application image contains no demonstrated reset after this event call. The final disconnect, platform reset, and staged-image activation therefore occur below the currently visible application boundary, most plausibly in ROM, controller/event infrastructure, or a different RF03 platform layer.

This report distinguishes proven behavior from inference. It does not claim that event `0xD3` itself means reset.

---

## 2. Evidence scope

Primary evidence comes from static analysis of:

```text
release/ry02-3.00.38-faster-raw-r1/RY02_3.00.38_250403.bin
```

Comparison firmware:

```text
vendor/RY02_3.00.33_250117.bin
```

Architectural reference:

```text
reference/bluex-sdk3-v3.3.8-20250117
reference/bluex-sdk3-doc
reference/bluex-sdk3-demo
```

The SDK3 documentation and demo repositories are source-only references. They contain no committed `.map`, `.axf`, `.elf`, `.lst`, `.asm`, or application `.bin` build artifacts suitable for direct binary matching.

No conclusion in this report depends on another OTA attempt, SWD access, or live device instrumentation.

---

## 3. Firmware and container model

### 3.1 Outer container

The `.38` OTA file contains:

```text
outer header size:  0x50
outer magic:        0x81BDC3E5
inner payload size: 0x1CD14
```

The outer header includes a simple additive payload checksum used by the official OTA container. It is not evidence of a cryptographic signature.

### 3.2 Inner image

The staged inner image begins with a `0x400`-byte inner header:

```text
inner magic:             0x0981000C
application image base:  0x00824000
executable body base:    0x00824400
physical image base:     0x00024000
physical code body:      0x00024400
```

Opaque metadata fields remain in the inner header. Tests against common digest algorithms did not identify the 32-byte field at inner `+0x174` as a standard digest of the obvious image ranges.

### 3.3 Active and staging regions

Accepted application-side layout:

```text
active application:      physical 0x24000 ...
staged inner image:      physical 0x4D000 ...
next likely boundary:    physical 0x70000
```

Command 3 removes the outer `0x50` bytes before writing the staged image. The staged content is therefore the inner image, not the complete downloaded container.

---

## 4. OTA transport and framing

The OTA receive path is implemented in the application and includes:

```text
GATT receive callback
  -> fragmented frame reassembly
  -> completed-frame handler
  -> CRC-16/MODBUS verification
  -> OTA worker / command dispatch
```

CRC characteristics:

```text
algorithm: CRC-16/MODBUS
polynomial: 0xA001, reflected
initial:    0xFFFF
refin:      true
refout:     true
xorout:     0x0000
```

Frame model:

```text
byte 0:     0xBC
byte 1:     command
bytes 2-3:  little-endian payload length
bytes 4-5:  CRC
byte 6...:  command payload
```

The official client sequence is:

```text
Command 1: start
Command 2: send image metadata
Command 3: send indexed data blocks
Command 4: check transfer completion
Command 5: finalize/release
```

The client waits for successful acknowledgements through command 4. It sends command 5 after command-4 success and does not wait for a command-5 success acknowledgement.

---

## 5. Command dispatch

For firmware `.38`, the decoded inline switch table maps:

| Command | Wrapper payload offset | Handler payload offset | Handler runtime |
|---|---:|---:|---:|
| 1 | `0x07204` | `0x06C80` | `0x0082AC80` |
| 2 | `0x0720C` | `0x06C92` | `0x0082AC92` |
| 3 | `0x07214` | `0x06D2A` | `0x0082AD2A` |
| 4 | `0x0721C` | `0x06E26` | `0x0082AE26` |
| 5 | `0x07224` | `0x06E62` | `0x0082AE62` |
| 6/default | `0x071CA` | cleanup/default | — |

The switch pattern is ARMCC-style inline return-address dispatch rather than a conventional table of absolute function pointers.

---

## 6. Command responsibilities

### 6.1 Command 1 — start/reset transfer state

Command 1 initializes the OTA session and invokes a registered callback with command/status information. It is the entry into the command-phase state machine.

### 6.2 Command 2 — receive metadata

The official client sends:

```text
image type byte
container length
whole-image CRC16
whole-image checksum16
```

Command 2 records expected transfer metadata and moves the OTA state forward.

### 6.3 Command 3 — receive and stage blocks

Command 3:

1. receives one-based block indices;
2. validates expected ordering/state;
3. processes the first block specially;
4. checks the outer magic `0x81BDC3E5`;
5. checks the RY02 type/version-family string in the outer header;
6. removes the outer `0x50` bytes;
7. erases and writes the inner image to staging flash beginning at physical `0x4D000`;
8. tracks staged byte count.

No evidence shows command 3 selecting an active boot bank.

### 6.4 Command 4 — transfer-completeness gate

Command 4 checks:

```text
current OTA phase == 3
staged byte count == container length - 0x50
```

On success it transitions to phase 4 and reports command-4 success.

No application-side evidence shows command 4 performing:

```text
cryptographic signature verification
semantic version rejection
inner-header authentication
active-bank selection
bootloader activation
```

Command-4 success should therefore be described as a transfer-completeness/structural gate, not proof that a new image has been activated.

### 6.5 Command 5 — finalize and schedule delayed event

Command 5 requires phase 4 and transitions state to phase 5.

Accepted `.38` call sequence:

```text
0x00824F26
0x00825E30
conditional 0x008259DA      ; currently a BX LR no-op
0x0082545E
0x0082723E                  ; persist application/time-state record
0x0082AC3C(1000)            ; restart delayed timer
0x0082B2C4
0x00829C1A
0x008253A8
return 0
```

Several calls are cleanup or subsystem-state operations whose exact public names are unknown. The two important identified operations are persistent-state save and delayed timer restart.

No successful command-5 callback or direct reset is visible in the handler.

---

## 7. Persistent application/time-state record

The record base is:

```text
0x002087BC
```

Observed layout:

| Offset | Working interpretation |
|---:|---|
| `+0x00` | marker `0xA1B2C3E5` |
| `+0x04` | seconds-based current/base time |
| `+0x08` | low-frequency hardware-counter reference |
| `+0x0D` | timekeeping/status flag |
| total persisted size | `0xA4` bytes |

The persistence routine at `0x0082723E`:

1. writes marker `0xA1B2C3E5`;
2. passes the record base and size `0xA4` to a low persistent-write operation.

This marker is an application-state record marker. It is not an OTA activation flag.

The same save-plus-timer pattern occurs outside the OTA command handler, which demonstrates that it is general application infrastructure rather than a dedicated boot-bank handoff.

---

## 8. Timer subsystem

### 8.1 Timer object

```text
timer/work object:       0x0020A7B8
saved caller argument:   0x0020A7D0
literal base:            0x0020A7D4
descriptor string:       a_write_flag_id
```

### 8.2 Registration

Registration wrapper:

```text
runtime: 0x0082AC5E
```

It calls low target `0x00013634` with an argument shape consistent with timer/work registration:

```text
r0: timer object
r1: descriptor/name
r2: 1
r3: 2000
stack[0]: 0
stack[1]: callback pointer 0x0082AC4B
```

Working low-target labels:

```text
0x00013634  timer/work create-or-register candidate
0x00013670  timer/work start-or-enable candidate
0x00013694  timer/work restart/update-timeout candidate
0x000136BC  timer/work stop-or-cancel candidate
```

### 8.3 Command-5 restart

Command 5 invokes:

```text
0x0082AC3C(1000)
  -> 0x00013694(timer_object, 1000)
```

The original timer delay is 1000 ms. The earlier one-byte experimental patch changed this to approximately 256 ms but did not change observable 1 Hz behavior. That result is consistent with the timer not being the source of the ring’s normal 1 Hz sensor cadence.

No further timer patching is recommended.

---

## 9. Delayed callback and event boundary

Timer callback:

```text
runtime: 0x0082AC4A
```

Effective behavior:

```c
void delayed_callback(void)
{
    state.base_seconds = current_time_getter();
    low_dispatcher_candidate(1, 0xD3);
}
```

The callback:

1. calls `0x0082580E`;
2. stores the returned value at record `+0x04`;
3. calls low target `0x0000029C` with `r0=1`, `r1=0xD3`;
4. returns normally.

### 9.1 Current-time getter

`0x0082580E` is a general current-time getter. It:

1. reads a low-frequency hardware counter;
2. subtracts the saved counter reference;
3. handles counter wrap;
4. divides by either 32000 or 32768 ticks per second;
5. adds the stored base time and another accumulator;
6. returns seconds.

Its many unrelated callers confirm it is not an OTA flag, reset-reason getter, or bank-selection helper.

### 9.2 Low target `0x29C`

Accepted label:

```text
0x0000029C
    two-argument event/public-notification dispatcher candidate
```

It must not be named `bx_public` because the public SDK function takes four arguments and no exact binary/symbol match has been established.

The application has six direct calls to `0x29C` in `.38`, with event-like values including `0xD0`, `0xD3`, `0xD4`, and `0xD5`.

No direct application-side consumer of event `0xD3` has been found.

---

## 10. Retired hypotheses

### 10.1 `0xA1B2C3E5` is not an activation flag

It belongs to a general persisted application/time-state record.

### 10.2 The `0x4926` D0-D3 wrappers are unrelated

The four selector wrappers around payload `0x11A08..0x11A50` have:

```text
direct callers:        0
raw address refs:      0
Thumb pointer refs:    0
```

They belong to a large generated ROM-API veneer family and are best treated as retained unused wrappers. Their numeric selector `0xD3` is not evidence of a connection to event `(1, 0xD3)`.

### 10.3 The other D3 publisher is not part of command 5

Function `0x00824B6A` publishes `(1,0xD3)`, but has:

```text
direct calls: 0
raw pointers: 0
```

It is an unused-retained-code candidate and should not be used to infer the meaning of the active timer callback’s `0xD3` event.

### 10.4 Command 5 is not a direct reset routine

No reset, branch to a new vector, staging-bank selector, or boot jump is visible in its body or delayed callback.

---

## 11. Reset-mechanism analysis

### 11.1 Cortex-M AIRCR

Absent from the application:

```text
SCB AIRCR 0xE000ED0C
VECTKEY | SYSRESETREQ 0x05FA0004
recognized AIRCR load/store sequence
```

Conclusion:

```text
direct NVIC_SystemReset/AIRCR reset: not present
```

### 11.2 Watchdog

Public SDK watchdog base:

```text
0x20131000
```

RY02 results:

```text
WDT-range constants:      0
WDT literal references:   0
MOVS #0x76 feed patterns: 0
```

Conclusion:

```text
direct application-side watchdog reset/control: unsupported
```

This does not exclude watchdog behavior implemented entirely in ROM.

### 11.3 Public SDK jump-table reset shape

The public SDK normally exposes:

```c
platform_reset(error)
    -> jump_table[PLATFORM_RESET](error)
```

A scan found 71 indirect `BLX` instructions and 15 loose candidates, but no credible call satisfying both:

```text
live r0 == 0
function loaded from jump-table slot +4
```

Conclusion:

```text
obvious SDK-style jump_table[PLATFORM_RESET](0): not found
```

### 11.4 BlueX AWO reset controller

The public SDK’s actual reset implementation is:

```c
GLOBAL_INT_STOP();
unloaded_area->error = error;

if (error != RESET_AND_LOAD_FW && error != RESET_TO_ROM) {
#if HW_BX_VERSION == 00
    srst_awo(CHIP_SRST_AWO);
#elif HW_BX_VERSION == 01
    sysc_awo_sft_rst_set(SRST_ALL_CLR);
#endif
}
```

Relevant public SDK MMIO signature:

```text
AWO base: 0x20201000
AWO SRST: 0x20201040
```

RY02 results:

```text
0x20201000 constants:        0
0x20201040 constants:        0
0x2020xxxx literal loads:    0
AWO reset-register refs:     0
```

Conclusion:

```text
direct public-SDK-style AWO reset in application image: not present
```

---

## 12. Proven architecture versus inferred architecture

### 12.1 Proven

```text
Official client sends commands 1-5.
Command 3 stages the stripped inner image at physical 0x4D000.
Command 4 checks phase and transferred byte count.
Command 5 saves application state and schedules a 1000 ms timer.
The timer callback checkpoints current time.
The callback calls 0x29C(1,0xD3).
The callback returns.
No known direct reset primitive exists in the application image.
```

### 12.2 Strongly supported

```text
0x29C crosses into low ROM/controller/event infrastructure.
Final reboot handling is outside the statically visible command-5 chain.
```

### 12.3 Inferred but unresolved

```text
The low layer disconnects or shuts down BLE.
The low layer requests platform reset.
The bootloader recognizes and activates the staged image.
The exact meaning of event 0xD3.
The exact staged-image acceptance and rollback rules.
```

---

## 13. Confidence matrix

| Finding | Confidence |
|---|---|
| Command-5 handler address and direct call chain | High |
| Persistent record at `0x002087BC` | High |
| Timer object and 1000 ms restart | High |
| Callback at `0x0082AC4A` | High |
| `0x0082580E` is a seconds-based current-time getter | High |
| `0x29C(1,0xD3)` is the application-visible terminal action | High |
| No inline AIRCR reset | High |
| No direct WDT control | High |
| No direct public AWO reset signature | High |
| No credible public SDK jump-table reset call | Medium-high |
| `0x29C` is an event/public-notification dispatcher | Medium |
| Final reset occurs in ROM/controller infrastructure | Medium-high |
| Event `0xD3` directly means reset | Low / unproven |
| Bootloader bank-selection mechanism | Unknown |

---

## 14. Recommended next steps

### Priority 0 — Freeze and preserve the accepted baseline

1. Add this report to the repository at:

   ```text
   docs/reverse-engineering/ry02-command5-ota-architecture.md
   ```

   Do not place the only copy under `analysis/`, because that directory is currently ignored.

2. Add an evidence index:

   ```text
   docs/reverse-engineering/ry02-evidence-index.md
   ```

   Map each conclusion to the report/script that produced it.

3. Add a machine-readable symbol map:

   ```text
   analysis/ry02-v38-symbol-map.csv
   ```

   Suggested columns:

   ```text
   address,label,confidence,category,evidence,notes
   ```

4. Record exact firmware hashes and tool versions used by every script.

### Priority 1 — Recover the low boundary without touching the device

1. Inventory SDK static libraries and object files:

   ```bash
   find reference/bluex-sdk3-v3.3.8-20250117 \
     reference/bluex-sdk3-demo \
     -type f \
     \( -iname '*.a' -o -iname '*.lib' -o -iname '*.o' -o -iname '*.obj' \) \
     -print | sort
   ```

   Search symbol tables for:

   ```text
   bx_public
   bx_post
   bx_subscibe
   platform_reset
   srst_awo
   sysc_awo_sft_rst_set
   jump_table
   ```

   This is the best remaining chance of recovering a compiler-generated signature for the low event/reset boundary from official material.

2. Build one minimal official SDK3 example, only when a legitimate compatible ARMCC/Keil toolchain is available. Compile calls to:

   ```c
   bx_public(src, msg, 0, 0);
   platform_reset(0);
   bx_dwork(callback, data, 1000, 1);
   ```

   Compare the resulting Thumb call shapes with RY02. This can test architectural similarity but cannot prove address identity across ROM revisions.

3. Perform a structured six-caller analysis of `0x29C`:

   ```text
   caller function boundaries
   live r0/r1 provenance
   surrounding state transitions
   post-call control flow
   .33 versus .38 differences
   ```

   The goal is to classify the dispatcher’s ABI, not to force a public SDK symbol name.

### Priority 2 — Improve bootloader understanding from official/offline artifacts

1. Search official SDK tools, docs, tags, and image-tool sources for:

   ```text
   ota_process
   RESET_AND_LOAD_FW
   image activation
   staging address
   copy-on-boot
   rollback
   image-valid marker
   unloaded_area
   ```

2. Collect additional official RY02 firmware versions without flashing them. Compare:

   ```text
   outer headers
   inner opaque metadata
   application/staging addresses
   command-3 validation logic
   command-5 call chain
   boot-related constants
   ```

   Cross-version invariants may expose the bootloader contract more reliably than another scan of a single image.

3. Continue examining the official QRing application only for static protocol and endpoint behavior. Do not use it to trigger another firmware update.

### Priority 3 — Reproducibility deliverables

Create:

```text
tools/verify_ry02_ota_findings.py
docs/reverse-engineering/ry02-symbol-map.md
docs/reverse-engineering/ry02-open-questions.md
```

The verifier should assert the accepted offsets, literals, call targets, and negative reset signatures against the stock `.38` SHA256.

---

## 15. Work that should stop

The following paths are exhausted or too low value:

```text
additional D0-D5 immediate scans
further analysis of the unused 0x4926 D0-D3 veneers
generic AIRCR scans
generic watchdog scans
generic public AWO reset scans
repeating indirect BLX scans without a new ABI signature
changing the timer delay
another OTA attempt
SWD/device probing
```

Do not interpret absence of an application reset primitive as permission to inject one. The bootloader’s staged-image acceptance rules remain unresolved.

---

## 16. Final accepted statement

```text
RY02 command 5 is an application-level finalize/cleanup and delayed-notification
operation. It persists general application/time state, schedules a 1000 ms timer,
and terminates at low dispatcher call 0x29C(1,0xD3).

The application image does not directly perform the final reset or staged-image
activation through any identified Cortex-M AIRCR, watchdog, public SDK jump-table,
or BlueX AWO reset mechanism.

The reset and boot transition remain below the visible application boundary and
must be treated as ROM/controller/bootloader behavior until stronger evidence is
obtained.
```
