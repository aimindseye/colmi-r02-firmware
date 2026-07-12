# RY02 BlueX Flash ROM ABI Correlation

**Firmware:** `RY02_3.00.38_250403.bin`  
**Comparison:** `RY02_3.00.33_250117.bin`  
**Status:** gate accepted; available ROM-address correlation route closed  
**Date:** 2026-07-12

## Objective

Resolve the four low flash targets used by `_cfg_write_to_flash`:

```text
0x0000893C
0x000081A0
0x00008600
0x00008916
```

The configuration writer is already proven. This gate is limited to the low flash ABI and exact BlueX symbol correlation.

## Accepted application-side contract

### `0x00008600`

Writer calls:

```text
0x0083875E:
    destination = 0x00801000
    length      = 0x400
    source      = prefix backup

0x00838768:
    destination = caller-supplied configuration slot
    length      = rebuilt configuration length
    source      = rebuilt configuration buffer

0x00838774:
    destination = 0x00801800
    length      = 0x800
    source      = suffix backup
```

This is an ABI-shape match for:

```c
flash_program(offset, length, buffer)
```

Current label:

```text
flash_program_abi_match_candidate
```

### `0x000081A0`

Observed call:

```text
r0 = 2
r1 = 0x00801000
```

Other callers use selector values `2` and `4`.

This is consistent with an erase-mode selector plus address, but its order differs from the public SDK wrapper:

```c
flash_erase(offset, type)
```

Current label:

```text
flash_erase_candidate
```

### `0x0000893C` and `0x00008916`

Observed pair:

```text
0x0000893C(sector_address, &saved_state)
...
0x00008916(saved_state)
```

Current labels:

```text
flash_operation_begin_candidate
flash_operation_end_candidate
```

These may manage XIP/cache/interrupt state around erase and program operations.

## Evidence hierarchy

Address-to-symbol naming should use this order:

1. exact target address and symbol on one ROM-symbol/map line;
2. exact target address in a linker import/absolute-symbol file;
3. ABI-identical wrapper tied to the target by generated code;
4. application call-shape similarity;
5. call-order inference.

Only levels 1–3 justify promoting an exact vendor symbol.

## Gate outputs

The report should provide:

```text
all .38 callers
all .33 callers
writer-specific r0-r3 contract
exact ROM-symbol address matches
public SDK flash prototypes
address/prototype agreement or conflict
```

No firmware modification or device interaction is required.


## Accepted report result

The report completed through `SUMMARY`.

It searched:

```text
4,841 text files
121 ROM-symbol, linker, map, scatter, and related files
```

Exact address-line matches:

```text
0x0000893C  0
0x000081A0  0
0x00008600  0
0x00008916  0
```

No exact vendor symbol can be promoted from the available SDK corpus.

The `.38` and `.33` caller counts are identical:

```text
0x0000893C  2 / 2
0x000081A0  5 / 5
0x00008600  6 / 6
0x00008916  2 / 2
```

The low flash contract is therefore stable across the two firmware versions.

The public SDK confirms:

```c
flash_program(uint32_t offset, uint32_t length, uint8_t *buffer);
flash_erase(uint32_t offset, erase_t type);
```

Application target `0x00008600` matches the first ABI shape. Target
`0x000081A0` does not match the second argument order.

## Closed route

Do not repeat generic exact-address searches over the same SDK corpus. The
available symbol/linker/map files contain no address mapping for these four
targets.

Further progress requires semantic comparison with:

```text
erase_t values
flash_wrapper.c bodies
flash_integration functions
boot_ram.asm flash/cache routines
application wrapper contracts
```
