# RY02 Reverse-Engineering Evidence Index

**Firmware:** `RY02_3.00.38_250403.bin`  
**Container under analysis:** `release/ry02-3.00.38-faster-raw-r1/RY02_3.00.38_250403.bin`  
**Application runtime base:** `0x00824000`  
**Inner executable body:** `0x00824400`  
**Status:** Accepted offline static-analysis baseline  
**Updated:** 2026-07-11

This index maps the accepted command-5/OTA conclusions to the analysis reports that support them. It distinguishes positive evidence from absence-of-signature findings.

## Confidence legend

| Level | Meaning |
|---|---|
| High | Directly demonstrated by coherent disassembly, literals, call flow, or repeated cross-reference evidence |
| Medium-high | Strongly supported, but an exact vendor symbol or full downstream implementation is unavailable |
| Medium | Best current interpretation from multiple observations; alternative implementations remain possible |
| Low | Tentative label retained only to guide future analysis |

## Address conventions

- Payload offset `0x00000` maps to runtime `0x00824000`.
- Container file offset equals payload offset plus outer header size `0x50`.
- Low targets such as `0x0000029C` and `0x00013694` are outside the extracted application payload and are treated as ROM/platform targets unless later evidence contradicts that model.
- Physical staging address `0x0004D000` corresponds to staging XIP address `0x0084D000`.

## Accepted findings

| ID | Finding | Confidence | Primary evidence |
|---|---|---:|---|
| E-001 | The `.38` payload length is `0x1CD14`; application runtime base is `0x00824000`. | High | Container/header analysis; all runtime-target reports |
| E-002 | Command dispatch maps commands 1–5 to handlers `0x0082AC80`, `0x0082AC92`, `0x0082AD2A`, `0x0082AE26`, and `0x0082AE62`. | High | Command-switch and wrapper disassembly reports |
| E-003 | Command 3 strips the outer `0x50`-byte container header and stages the inner image at physical `0x4D000` / XIP `0x0084D000`. | High | Command-3 handler and flash-wrapper analysis |
| E-004 | Command 4 validates OTA phase and staged byte count; no application-side signature, version-rejection, or activation step has been demonstrated. | High for observed checks; medium-high for negative scope | Command-4 handler analysis |
| E-005 | Command 5 requires phase 4, moves to phase 5, performs cleanup, saves persistent state, restarts a timer for 1000 ms, and returns without a success ACK. | High | Command-5 handler disassembly; `ry02-v38-time-d3-persistence-xrefs.txt` |
| E-006 | `0x002087BC` is the base of a persisted `0xA4`-byte application/time-state record whose marker is `0xA1B2C3E5`. | High | Persistent-record initialization/save analysis; `ry02-v38-helper-82580e-and-state-2087c0.txt` |
| E-007 | `0xA1B2C3E5` is a general record marker, not an OTA activation flag. | High | Record initialization, validation, and save paths |
| E-008 | Timer/work object `0x0020A7B8` is restarted by command 5 through wrapper `0x0082AC3C` with delay 1000 ms. | High | Timer literal/caller analysis; exact entrypoint disassembly |
| E-009 | Timer callback `0x0082AC4A` calls `0x0082580E`, stores the result at state `+0x04`, publishes `(1,0xD3)` through low target `0x29C`, and returns. | High | Exact callback disassembly; `ry02-v38-time-d3-persistence-xrefs.txt` |
| E-010 | `0x0082580E` is a seconds-based current-time getter using a low-frequency counter, a saved reference, and 32000/32768 ticks-per-second conversion. | High | `ry02-v38-helper-82580e-and-state-2087c0.txt`; caller analysis |
| E-011 | `0x008371AE` behaves as an unsigned quotient/remainder helper. | High | Repeated callers with divisors 60 and other time units |
| E-012 | Low target `0x0000029C` is a two-argument event/public-notification dispatcher candidate, but it is not proven to be SDK `bx_public`. | Medium | Six direct callers; D0/D3/D4/D5 argument patterns |
| E-013 | The separate D3 publisher at `0x00824B6A` has no direct callers or raw pointers and is an unused-retained-code candidate. | Medium-high | `ry02-v38-d3-d5-publisher-family.txt` |
| E-014 | The `0x4926` D0–D3 selector wrappers have no callers or pointers and are unrelated retained ROM-API veneers. | High | `ry02-v38-low-4926-wrapper-callers.txt`; pointer-reference report |
| E-015 | The application contains no conventional AIRCR / `NVIC_SystemReset()` sequence. | High | `ry02-v38-reset-primitive-scan.txt` |
| E-016 | No credible SDK-style `jump_table[PLATFORM_RESET](0)` call shape was found among indirect `BLX` sites. | Medium-high | `ry02-v38-platform-reset-indirect-call-candidates.txt` |
| E-017 | No direct application-side BlueX watchdog MMIO reference or `0x76` feed signature was found. | High | `ry02-v38-watchdog-mmio-scan.txt` |
| E-018 | Public SDK3 `platform_reset()` uses BlueX AWO reset helpers, not AIRCR, for normal reset errors. | High | `sdk3-v338-platform-reset-source-body.txt`; `sdk3-v338-awo-reset-signatures.txt` |
| E-019 | The RY02 application contains neither public SDK AWO base `0x20201000` nor reset register `0x20201040`. | High | `ry02-v38-awo-reset-mmio-scan.txt` |
| E-020 | The proven application-visible OTA chain terminates at `0x29C(1,0xD3)`; final reset and staged-image activation remain below the visible application boundary. | Medium-high | E-005 through E-019 |

## Evidence reports

The following reports should be preserved under `analysis/` or an equivalent evidence archive:

| Report | Purpose |
|---|---|
| `ry02-v38-helper-82580e-and-state-2087c0.txt` | Current-time getter, callers, and state-record references |
| `ry02-v38-time-d3-persistence-xrefs.txt` | Time helpers, persistent-save calls, command-5 callback, and related cross-references |
| `ry02-v38-low-4926-wrapper-callers.txt` | Generated `0x4926` ROM-API veneer family and D0–D3 wrapper reachability |
| `ry02-v38-d3-d5-publisher-family.txt` | D3/D4/D5 publisher functions, call counts, and pointer counts |
| `ry02-v38-reset-primitive-scan.txt` | AIRCR, VTOR, SCB, and reset-key scan |
| `sdk3-v338-reset-source-anchors.txt` | Public SDK reset/watchdog source inventory |
| `ry02-v38-platform-reset-indirect-call-candidates.txt` | Indirect `BLX` candidates for SDK jump-table reset ABI |
| `ry02-v38-watchdog-mmio-scan.txt` | BlueX watchdog base and feed-signature scan |
| `sdk3-v338-platform-reset-implementation.txt` | SDK callers and available ELF/symbol inventory |
| `sdk3-v338-platform-reset-source-body.txt` | Exact SDK `platform_reset()` source implementation |
| `sdk3-doc-demo-revisions.txt` | SDK3_DOC and SDK3_Demo revisions and tags |
| `sdk3-doc-demo-ota-reset-search.txt` | OTA, event, delayed-work, and reset references in companion repositories |
| `sdk3-v338-awo-reset-signatures.txt` | Public SDK AWO reset base, register, masks, and helper paths |
| `ry02-v38-awo-reset-mmio-scan.txt` | RY02 scan for `0x20201000`, `0x20201040`, and related literals |

## Negative-evidence interpretation

A zero signature result means only that the scanned mechanism is not directly represented in the extracted application image using the tested form.

It does not exclude:

- ROM-resident reset implementation;
- a controller task consuming an application event;
- an indirect dispatch table owned outside the application image;
- a different RF03 platform ABI;
- bootloader behavior after reset;
- computed addresses that do not leave literal constants in the application.

The accepted conclusion is therefore not “event `0xD3` is reset.” It is:

```text
The application-visible command-5 path ends at low dispatcher call
0x29C(1,0xD3). The final reset and boot transition remain unresolved
below that boundary.
```

## Open questions

1. What exact ABI and subsystem does low target `0x0000029C` implement?
2. What entity consumes source/category `1`, event `0xD3`?
3. How does the RF03 platform perform reset if it differs from public Apollo00 SDK3?
4. What bootloader condition marks the staged image at physical `0x4D000` as acceptable?
5. Is activation copy-based, bank-based, or metadata-driven?
6. What rollback behavior applies after an invalid staged image?
7. What do the opaque inner-header fields represent?

## Recommended maintenance

- Keep `docs/reverse-engineering/ry02-command5-ota-architecture.md` as the human-readable accepted architecture.
- Keep `analysis/ry02-v38-symbol-map.csv` as the machine-readable address map.
- Add new labels only when backed by a report and update both this index and the CSV.
- Preserve unknown labels as candidates; do not replace them with public SDK names based only on similarity.
- Do not perform another OTA or timer patch solely to resolve the remaining ROM-side questions.
