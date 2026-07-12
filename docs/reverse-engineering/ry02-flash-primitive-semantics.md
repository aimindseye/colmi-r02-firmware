# RY02 Low Flash Primitive Semantics

**Firmware:** `RY02_3.00.38_250403.bin`  
**Comparison:** `RY02_3.00.33_250117.bin`  
**Status:** source-semantics gate accepted; low-flash naming path closed  
**Date:** 2026-07-12

## Why this gate exists

The address-to-symbol report found no exact mapping for:

```text
0x0000893C
0x000081A0
0x00008600
0x00008916
```

across 121 available ROM-symbol, linker, map, and scatter files.

The next gate therefore changes evidence type. It compares application wrapper
contracts with public source implementations, erase enums, lower-level flash
integration APIs, and boot assembly.

## Accepted current labels

### `0x00008600`

```text
label:       flash_program_abi_match_candidate
confidence:  medium-high
```

Proven call shape:

```text
r0 = destination/offset
r1 = byte length
r2 = source buffer
```

This matches:

```c
flash_program(uint32_t offset, uint32_t length, uint8_t *buffer);
```

No exact address-to-symbol mapping exists in the available corpus.

### `0x000081A0`

```text
label:       flash_erase_selector_address_candidate
confidence:  medium
```

Proven call shape:

```text
r0 = selector 2 or 4
r1 = flash address
```

This is not the public wrapper order:

```c
flash_erase(uint32_t offset, erase_t type);
```

The selector values may map to erase modes or lower-level command classes, but
that mapping is not yet proven.

### `0x0000893C`

```text
label:       flash_operation_begin_candidate
confidence:  medium
```

Observed before erase/program operations:

```text
r0 = flash or XIP address
r1 = writable one-byte saved-state location
```

### `0x00008916`

```text
label:       flash_operation_end_candidate
confidence:  medium
```

Observed after erase/program operations:

```text
r0 = saved one-byte state
```

The pair may manage flash cache, XIP, interrupt, or critical-section state.
Those exact semantics remain unresolved.

## Target application wrappers

```text
0x00824A78  program-and-verify wrapper candidate
0x00824CDC  global flash-begin wrapper candidate
0x00824D0E  global flash-end wrapper candidate
0x00824F84  selector-2 erase wrapper candidate
0x00824FA4  selector-4 erase wrapper candidate
0x00827064  locked selector-2 erase wrapper candidate
0x00827088  locked selector-4 erase wrapper candidate
0x008270AC  locked program wrapper candidate
0x008270D6  locked program/verify wrapper candidate
0x008386FC  _cfg_write_to_flash
```

## Source material to extract

The next report should preserve complete relevant blocks for:

```text
erase_t
flash_program
flash_erase
flash_program_operation
flash_program_operation_start
flash_erase_operation
flash_cache_disable
flash_cache_enable
flash_cache_config
```

It should also include boot/listing contexts for matching flash/cache symbols.

## Promotion rule

An exact vendor name requires one of:

1. a source/assembly body whose ABI and control sequence uniquely match the
   application target;
2. generated wrapper code that directly resolves to the target;
3. an address mapping from a newly obtained compatible ROM symbol file.

Loose name similarity is insufficient.


## Accepted r1 result

The report completed through `SUMMARY`.

It did not produce a uniquely matching source or assembly contract for the four
low target addresses. The conservative labels remain unchanged.

### Erase-selector result

The public `erase_t` values are positional:

```text
0  Page_Erase
1  Sector_Erase
2  Block_32KB_Erase
3  Block_64KB_Erase
4  Chip_Erase
```

Application target `0x000081A0` receives selectors `2` and `4` in `r0`.
The configuration writer passes selector `2` while rewriting a known 4-KiB
sector. Therefore these values cannot be interpreted directly as the public
`erase_t` enumeration.

Accepted label:

```text
flash_erase_selector_address_candidate
```

### Program result

All six `0x00008600` call sites use a destination/length/source data shape.
The public source confirms the same shape for `flash_program`.

No exact address mapping or uniquely matching compiled wrapper was found, so the
accepted label remains:

```text
flash_program_abi_match_candidate
```

### Begin/end result

The SDK and boot assembly contain explicit flash-cache disable/enable/config
routines. Those public routines are zero-argument operations, while the RY02 pair
uses:

```text
begin(address, saved_state_pointer)
end(saved_state_byte)
```

This supports a broader flash/XIP state-guard interpretation but does not prove
that the targets are direct cache-disable/cache-enable functions.

Accepted labels remain:

```text
flash_operation_begin_candidate
flash_operation_end_candidate
```

## Closed path

Stop further generic source-signature, ROM-address, and common flash-name scans
for these four targets. Exact vendor names require a compatible ROM image or
symbol map not present in the current evidence corpus.

The application-level configuration persistence contract is already closed and
does not depend on those exact vendor names.
