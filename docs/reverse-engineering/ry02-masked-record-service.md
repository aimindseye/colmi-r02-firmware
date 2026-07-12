# RY02 Masked-Record Service

**Firmware:** `RY02_3.00.38_250403.bin`  
**Comparison:** `RY02_3.00.33_250117.bin`  
**Status:** service identified as configuration-item subsystem  
**Date:** 2026-07-11

## Structural conclusion

The source-1/D0 six-byte value is stored and retrieved through a generic masked-record service.

### Descriptor layout

```text
+0x00  uint16 field_type
+0x02  uint8  length
+0x03  padding
+0x04  pointer to value[length]
+0x08  pointer to mask[length]
```

### Serialized record layout

```text
+0x00  uint16 field_type
+0x02  uint8  length
+0x03  value[length]
+0x03+length  mask[length]
```

### Serialized stride

```text
3 + 2 * length
```

## Type-0x33 exact-mask wrappers

### Setter: `0x008385F8`

```text
copy caller input[6]
fill mask[6] with FF
descriptor.type = 0x33
descriptor.length = 6
descriptor.value = input copy
descriptor.mask = FF mask
call service core 0x00838914
```

The wrapper has exactly two callers: the runtime six-byte state updater and startup/configuration mismatch path.

### Getter: `0x00839CA4`

```text
fill mask[6] with FF
descriptor.type = 0x33
descriptor.length = 6
descriptor.mask = FF mask
validate service/context through 0x008386AC
find matching serialized entry through 0x00838AFC
copy matched entry.value[6] to caller output
```

Return values appear to distinguish success and two failure classes, but exact status names remain unresolved.

## Parser behavior: `0x00838AFC`

The parser:

1. validates the service/context;
2. initializes from a serialized record area;
3. reads each entry's type and length;
4. derives value and mask pointers;
5. compares requested type and length;
6. compares the record mask with the requested mask;
7. on match, returns success and optionally the serialized offset;
8. otherwise advances by `3 + 2*length`.

For the type-0x33 wrapper, an all-`FF` requested mask means that the selected entry also has an all-`FF` mask.

## Current naming boundary

Supported:

```text
masked-record service
type-0x33 record
six-byte value
six-byte exact mask
setter/getter wrappers
record install/update core candidate
record find/parser candidate
```

Unsupported without further evidence:

```text
BLE address
MAC address
bonding peer
whitelist entry
resolving-list identity
advertising filter address
```

## Next questions

1. What strings are referenced by the service family?
2. What are the full callers and operation modes of `0x00838914`?
3. What does `0x008386AC` validate or initialize?
4. Is service context `0x00801400` used by other record types?
5. Which field types besides `0x33` use the same service?
6. Does the official SDK source contain a matching value/mask descriptor or serialized stride?
7. Can field type `0x33` be tied to a named protocol field?


## Accepted service-report findings

The service report completed through its final summary.

The strongest new anchor is the exact embedded string:

```text
cfg_add_item
```

referenced from function `0x00838914`. This supports promoting that function from a generic install/update candidate to:

```text
cfg_add_item
```

The function:

```text
accepts at most 0x20 item descriptors
checks whether each item already exists
computes the rebuilt serialized blob size
allocates a replacement buffer
initializes the buffer with 0xFF
copies retained items
appends or replaces supplied value/mask records
commits the rebuilt blob through 0x008386FC
frees the temporary buffer
returns success/failure
```

The setter wrapper passes:

```text
r0 = 0x00801400
r1 = 0x00801400
r2 = descriptor
r3 = 1
```

so the core signature is consistent with source blob, destination/commit target, descriptor array, and descriptor count. The identical first two arguments indicate an in-place update request at the wrapper level.

The prior label `service context 0x00801400` should be refined to:

```text
configuration blob/base candidate
```

The parser `0x00838AFC` is now best labeled `cfg_find_item_candidate`.

The validator `0x008386AC` calls `0x00837198` and compares the result with constant `0x8721BEE2`. This is consistent with a configuration validity/integrity token, but the exact algorithm and token meaning remain unresolved.

## Source-search result

The broad SDK keyword scan produced more than eleven thousand mostly unrelated `mask` and `0x33` matches. It is not useful evidence for naming this service.

The next gate replaces it with exact searches for:

```text
cfg_add_item
cfg_find_item
cfg_get_item
cfg_del_item
cfg_update_item
0x8721BEE2
```

and corrects Thumb ADR resolution so inline diagnostic strings can be recovered.


## Configuration flash refinement

The configuration service stores its serialized item blob in a dedicated `0x400`-byte slot at `0x00801400`. The slot begins with magic `0x8721BEE2` and a 16-bit serialized-item length.

The exact writer name `_cfg_write_to_flash` and the surrounding 4-KiB sector-preservation behavior are now documented in `ry02-cfg-flash-layout.md`.
