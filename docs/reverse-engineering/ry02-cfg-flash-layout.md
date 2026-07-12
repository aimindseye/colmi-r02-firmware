# RY02 Configuration Blob and Flash Layout

**Firmware:** `RY02_3.00.38_250403.bin`  
**Comparison:** `RY02_3.00.33_250117.bin`  
**Status:** configuration layout accepted; ROM flash ABI correlation pending  
**Date:** 2026-07-11

## Proven configuration header

The configuration blob begins at XIP address:

```text
0x00801400
```

Its header is:

```text
+0x00  u32 magic, little-endian
+0x04  u16 serialized-item length, little-endian
+0x06  first serialized item
```

The required magic is:

```text
0x8721BEE2
```

Function `0x00837198` merely reads a little-endian `u32` from the first four bytes. Function `0x008386AC` compares that value with the magic and returns a boolean.

Accepted labels:

```text
0x00837198  load_u32_le
0x008386AC  cfg_blob_magic_valid
0x8721BEE2  cfg_blob_magic
```

## Proven slot geometry

The parser and writer establish:

```text
configuration slot size:       0x400 bytes
header size:                   0x006 bytes
serialized-item capacity:      0x3FA bytes
slot range:                    0x00801400..0x008017FF
```

`cfg_find_item` starts its item scan at offset `6` and bounds traversal by `0x3FA`.

## `_cfg_write_to_flash`

Function `0x008386FC` references exact string:

```text
_cfg_write_to_flash
```

It receives:

```text
r0  destination configuration address
r1  replacement configuration blob
r2  replacement length
```

For destination `0x00801400`, it:

1. allocates a `0x400`-byte prefix backup;
2. allocates a `0x800`-byte suffix backup;
3. copies `0x00801000..0x008013FF` into the prefix backup;
4. copies `0x00801800..0x00801FFF` into the suffix backup;
5. performs a low-level flash preparation/erase sequence for sector `0x00801000`;
6. rewrites the prefix backup;
7. writes the replacement configuration at `0x00801400`;
8. rewrites the suffix backup;
9. finalizes the low-level flash operation;
10. frees both buffers.

This establishes a 4-KiB containing sector:

```text
sector range: 0x00801000..0x00801FFF
sector size:  0x1000
```

### Sector partition

```text
0x00801000..0x008013FF  0x400-byte preserved prefix
0x00801400..0x008017FF  0x400-byte configuration slot
0x00801800..0x00801FFF  0x800-byte preserved suffix
```

## Low flash functions

The writer calls:

```text
0x0000893C  flash preparation/unlock candidate
0x000081A0  erase candidate
0x00008600  program/write candidate
0x00008916  finish/restore candidate
```

These names are inferred from call order and arguments. They are not exact SDK names.

## `cfg_del_item`

The binary contains ASCII:

```text
cfg_del_item
```

The accepted cfg-item report found no raw pointer, LDR, or ADR reference. It must be treated as retained unreferenced string data until code reachability is demonstrated.

## Next questions

1. What exact ABIs do the four low flash functions implement?
2. Does `0x000081A0(2, 0x00801000)` erase one 4-KiB sector?
3. Is `0x00008600(destination, length, source)` the exact program ABI?
4. What state is saved by `0x0000893C` and restored by `0x00008916`?
5. Does firmware `.33` use identical sector geometry?
6. Is `cfg_del_item` genuinely dead, or referenced through a nonstandard mechanism?


## Accepted flash-layout report findings

The r1 report completed through its final summary without a runtime error.

Caller-family counts in `.38`:

```text
0x0000893C  2 direct callers
0x000081A0  5 direct callers
0x00008600  6 direct callers
0x00008916  2 direct callers
```

Within `_cfg_write_to_flash`, target `0x00008600` is called three times with:

```text
r0 = destination address
r1 = byte length
r2 = source buffer
```

The three writes restore the `0x400`-byte prefix, write the replacement configuration blob, and restore the `0x800`-byte suffix.

This call shape matches the public SDK declaration:

```c
periph_err_t flash_program(
    uint32_t offset,
    uint32_t length,
    uint8_t *buffer
);
```

That is strong ABI-level semantic evidence, but exact address-to-symbol identity still requires a ROM-symbol mapping.

Target `0x000081A0` is called with:

```text
r0 = 2 or 4
r1 = flash address
```

The public SDK wrapper instead declares:

```c
periph_err_t flash_erase(
    uint32_t offset,
    erase_t type
);
```

The observed argument order does not match that wrapper. `0x000081A0` must therefore remain a lower-level erase candidate until a ROM symbol or matching prototype is found.

The begin/end pair is:

```text
0x0000893C(address, &saved_state)
...
0x00008916(saved_state)
```

This supports a paired flash-operation preparation/restoration contract, but exact names remain unresolved.

## Source-search refinement

The flash-layout report found 171 source matches because `flash_program` and `flash_erase` are common SDK APIs. The useful declarations include:

```c
periph_err_t flash_program(
    uint32_t offset,
    uint32_t length,
    uint8_t *buffer
);

periph_err_t flash_erase(
    uint32_t offset,
    erase_t type
);
```

These declarations support ABI comparison only. They do not map the low target addresses.

The next gate searches linker, map, scatter, and ROM-symbol files for exact addresses `0x8600`, `0x81A0`, `0x893C`, and `0x8916`.


## ROM ABI gate result

The exact-address gate found zero matches for all four low targets in 121
available symbol/linker/map/scatter files. The ROM-address route is closed for
the current SDK corpus.

The `.38` and `.33` call-family counts are identical, and the configuration
writer sequence is stable. Target `0x00008600` remains a strong
`flash_program(offset,length,buffer)` ABI match; the remaining targets retain
candidate labels.

The next analysis is source-semantic correlation rather than another address
scan.
