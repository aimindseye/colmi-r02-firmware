# RY02 `0x29C` Producer-Provenance Findings

**Firmware:** `RY02_3.00.38_250403.bin`  
**Comparison:** `RY02_3.00.33_250117.bin`  
**Status:** r2 CFG-corrected provenance accepted  
**Date:** 2026-07-11

## Executive finding

The six direct `0x29C` publishers form a stable cross-version event family:

| Producer | `.38` address | Visible event | Reachability |
|---|---:|---:|---|
| retained D3 helper | `0x00824B6A` | `(1,D3)` | no direct caller or raw/Thumb pointer |
| D4/D5 status helper | `0x00824B86` | `(3,D4/D5)` | one direct caller; known path passes `1`, therefore D4 |
| D0 completion helper | `0x00826FF8` | `(1,D0)` | one direct caller |
| D0 state-update helper | `0x00828DD2` | `(1,D0)` | one direct caller |
| D0 configuration helper | `0x00829E70` | `(1,D0)` | one direct caller |
| active D3 timer callback | `0x0082AC4A` | `(1,D3)` | one Thumb callback pointer at `0x0082AF04` |

The active D3 callback pointer is direct positive reachability evidence. The callback is registered as data, not reached by an ordinary `BL`.

## Stable `.33` counterparts

The r1 comparison produced exact normalized instruction matches for:

```text
.38 0x00824B6A -> .33 0x00824B62
.38 0x00824B86 -> .33 0x00824B7E
.38 0x00828DD2 -> .33 0x00828D12
.38 0x00829E70 -> .33 0x00829DA0
.38 0x0082AC4A -> .33 0x0082AB8A
```

These are strong heuristic counterparts, not formal symbol identities. They show that the D0/D3/D4/D5 producer architecture predates `.38` and is not an OTA-specific addition introduced only by the later firmware.

The D0 completion helper at `.38` `0x00826FF8` did not obtain a strong automatic `.33` match and remains unresolved for cross-version identity.

## Producer-specific findings

### Retained source-1 D3 helper

`0x00824B6A` has no direct caller, exact raw pointer, or Thumb pointer. It remains retained unreachable code under the current static reachability model.

Its literal `0x23103102` is a high constant. Static analysis does not establish that it is an MMIO address.

### Source-3 D4/D5 helper

`0x00824B86` has one direct caller at `0x008296E4`. The caller clears a byte flag and immediately passes `r0=1`, so the demonstrated active path selects event `D4`.

No active direct path selecting `D5` has been demonstrated.

### Source-1 D0 completion helper

`0x00826FF8` is called from parent candidate `0x00825476` after a polling/wait sequence. It performs additional completion cleanup, clears a state byte, waits for another condition, publishes `(1,D0)`, and returns.

This supports a completion/state-transition class for D0.

### Source-1 D0 state-update helper

The reachable producer begins at `0x00828DD2`, compares and copies six bytes, sets a state flag, invokes update helpers, publishes `(1,D0)`, and then performs an external tail branch to shared code at `0x008288C0`.

The r1 linear decoder incorrectly continued into the adjacent function beginning at `0x00828E0E`. Therefore:

```text
0x00828E0E..0x00828E30
```

must not be attributed to producer `0x00828DD2`.

In particular, the `0x002087BC` literal loaded by the adjacent function is not evidence that the D0 state-update producer directly accesses the persistent time-state record.

### Source-1 D0 configuration helper

`0x00829E70` is called once from startup/initialization parent `0x00824988`. It builds configuration-like structures, compares and transforms a six-byte value, publishes `(1,D0)`, and continues through substantial ordinary initialization/configuration work.

This proves source/category `1` is broader than OTA finalization.

### Active source-1 D3 timer callback

`0x0082AC4A` has:

```text
direct callers:       0
Thumb pointer refs:   1
pointer location:     0x0082AF04
```

It refreshes the current-time value in record `0x002087BC`, publishes `(1,D3)`, and returns normally.

This is the only demonstrated active D3 producer.

## Corrected event-family interpretation

Accepted working model:

```text
source/category 1:
    D0 = general completion/configuration/state-change publication
    D3 = delayed write/state publication

source/category 3:
    D4/D5 = paired boolean/status publication
```

The exact vendor subsystem and message names remain unresolved.

The producer family supports `0x29C` as a returning two-argument publication boundary. It does not support naming `0x29C` as `bx_public`, and it does not establish `D3 == reset`.

## r2 validation

The CFG-corrected r2 report validates the repair:

- producer `0x00828DD2` has 25 reachable instructions;
- it has no local return and exits through external tail branch `0x00828E0C -> 0x008288C0`;
- its only reachable RAM literal is `0x00208696`;
- adjacent function `0x00828E0E` and its `0x002087BC` literal are excluded;
- caller-saved `r0-r3` values are reported unknown after intervening calls rather than receiving stale provenance.

The r1 output may be retained as historical evidence, but r2 is the accepted producer-boundary report.

## Next gate

Trace the source/category-1 D0 subsystem through its parent callgraphs, exact RAM-object references, derived six-byte state addresses, and six-byte compare/copy helpers. The goal is to classify the subsystem without assuming that six-byte values are BLE addresses.
