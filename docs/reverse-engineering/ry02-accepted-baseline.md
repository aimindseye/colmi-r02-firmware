# RY02 Accepted Static-Analysis Baseline

**Firmware:** `RY02_3.00.38_250403.bin`  
**Comparison firmware:** `RY02_3.00.33_250117.bin`  
**Status:** Accepted and machine-verified  
**Verification:** 31 checks passed, 0 required failures, 0 optional warnings

## Firmware identity

```text
.38 SHA256: dbf64e3dc9aef112a4d69e46e516efb27f2ed2e3dc1d2d3f1af75939cc46487e
container:  0x1CD64 bytes
payload:    0x1CD14 bytes
outer magic 0x81BDC3E5
inner magic 0x0981000C
hardware     RY02_V3.0
```

Optional comparison image:

```text
.33 SHA256: 3eaad32f25a1734b93b63b86c6a0032c3444b68e7027faf3724bd5148dd4dbcd
payload:    0x1B884 bytes
```

## Accepted command-5 application path

```text
command 5 at 0x0082AE62
  -> phase/state transition and cleanup
  -> persistent application/time state save
  -> restart timer for 1000 ms through 0x0082AC3C
  -> additional cleanup
  -> return

active timer callback 0x0082AC4A
  -> current-time getter 0x0082580E
  -> update persistent state timestamp
  -> publish source 1 / event D3 through 0x29C
  -> return
```

The callback pointer is stored as Thumb pointer `0x0082AC4B`.

## Accepted `0x29C` model

Preferred label:

```text
publish_event2_candidate(source_or_category, event_id)
```

The complete direct-caller family is:

```text
0x00824B80
0x00824BA6
0x00827032
0x00828E08
0x00829EFA
0x0082AC58
```

The demonstrated event family includes D0, D3, D4, and D5 under source/category
values 1 and 3.

`0x29C` returns in ordinary paths. It is not a general synchronous reset
primitive and is not proven to be `bx_public`.

## Accepted configuration persistence model

```text
cfg blob slot:    0x00801400..0x008017FF
slot size:        0x400
header:
  +0x00 u32 magic 0x8721BEE2
  +0x04 u16 serialized-item length
  +0x06 serialized items

containing sector: 0x00801000..0x00801FFF
sector size:       0x1000
```

The configuration service uses serialized items:

```text
uint16 type
uint8  length
uint8  value[length]
uint8  mask[length]
```

The source-1/D0 six-byte flow uses type `0x33`, length `6`, and an all-`FF`
exact mask.

Exact binary names:

```text
0x00838914  cfg_add_item
0x008386FC  _cfg_write_to_flash
```

The vendor meaning of item type `0x33` remains unresolved.

## Accepted low-flash boundary

```text
0x0000893C  flash_operation_begin_candidate
0x000081A0  flash_erase_selector_address_candidate
0x00008600  flash_program_abi_match_candidate
0x00008916  flash_operation_end_candidate
```

The `.38` and `.33` direct-caller counts are stable:

```text
2 / 5 / 6 / 2
```

`0x8600` has strong flash-program semantics through its
destination/length/source ABI. Exact vendor ROM names are not available in the
current symbol corpus.

## Negative evidence and boundaries

Accepted negative findings:

```text
no direct AIRCR literal in the application payload
no raw 0x29C or 0x29D function pointers
no demonstrated reset inside command 5
no demonstrated reset inside the delayed callback
cfg_del_item string exists but has no established code reference
```

Still unresolved:

```text
downstream source-1/D3 event consumer
exact reset implementation
bootloader staged-image validation and activation
vendor meaning of configuration item type 0x33
exact vendor names for the four low flash ROM functions
```

## Maintenance contract

Firmware-level verification:

```bash
python3 tools/verify_ry02_accepted_baseline.py   release/ry02-3.00.38-faster-raw-r1/RY02_3.00.38_250403.bin   --firmware33 vendor/RY02_3.00.33_250117.bin
```

Repository evidence-bundle validation:

```bash
python3 tools/validate_ry02_baseline_bundle.py
```

A baseline promotion is accepted only when both commands pass.
