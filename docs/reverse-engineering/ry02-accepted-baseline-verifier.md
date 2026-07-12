# RY02 Accepted Baseline Verifier

**Firmware:** `RY02_3.00.38_250403.bin`  
**Optional comparison:** `RY02_3.00.33_250117.bin`  
**Status:** Accepted; 31 checks passed with no failures or warnings  
**Date:** 2026-07-12

## Purpose

The exploratory static-analysis phase has established a large accepted baseline.
This verifier converts the highest-value conclusions into machine-checkable
assertions against the stock `.38` image.

It is intended to detect:

```text
wrong input firmware
accidental analysis against a patched image
offset drift
call-chain regressions
incorrect callback or event-boundary assumptions
loss of accepted configuration anchors
```

It does not attempt to discover new semantics.

## Required `.38` checks

```text
stock SHA256
container and payload lengths
outer magic 0x81BDC3E5
inner magic 0x0981000C
RY02_V3.0 hardware-version anchor

command-5 direct-call sequence
1000 ms timer-delay construction
active callback pointer 0x0082AC4B
callback calls current-time getter then 0x29C
callback publishes source 1 / event D3

complete six-caller 0x29C family
ordinary D0 continuation after 0x29C
normal D3 callback return
no raw 0x29C/0x29D pointers
no direct AIRCR literal

configuration magic 0x8721BEE2
cfg_add_item string
_cfg_write_to_flash string
cfg_del_item retained string

stable low-flash caller counts
```

## Optional `.33` checks

```text
stock SHA256
payload length
stable low-flash caller counts 2/5/6/2
```

Optional `.33` failures are warnings rather than required-gate failures.

## Output

```text
analysis/ry02-v38-accepted-baseline-verification.txt
```

The process exits nonzero if any required `.38` assertion fails.

## Interpretation boundary

A passing verifier means the accepted static anchors are present in the stock
firmware. It does not prove:

```text
the vendor name of low ROM functions
the downstream D3 event consumer
the reset implementation
bootloader staged-image acceptance
cryptographic OTA validation
```


## Accepted execution result

```text
checks passed: 31
required failures: 0
optional warnings: 0
accepted baseline: PASS
```

The stock `.38` identity, command-5 call chain, delayed source-1/D3 callback,
complete `0x29C` family, negative reset anchors, configuration strings/magic,
and low-flash caller counts all passed.

The optional `.33` identity and caller-count checks also passed.


## Bundle-validator repair

Promotion repair r2 corrects two repository-validator expectations:

```text
0x0082AC4A symbol label:
  expected write_flag_delayed_D3_callback

_cfg_write_to_flash anchor:
  checked in ry02-accepted-baseline.md rather than the command-5 architecture
```

This changes only repository evidence validation. It does not alter any
firmware-level verifier result or accepted static-analysis finding.
