# RY02 Configuration-Item Service

**Firmware:** `RY02_3.00.38_250403.bin`  
**Comparison:** `RY02_3.00.33_250117.bin`  
**Status:** cfg naming and string-recovery gate accepted  
**Date:** 2026-07-11

## Accepted findings

### Exact core name

Function `0x00838914` references embedded ASCII string:

```text
cfg_add_item
```

This is direct binary evidence for the function family. The accepted label is:

```text
0x00838914  cfg_add_item
```

### Core behavior

The function accepts an array of item descriptors and a count no greater than `0x20`.

For each requested item, it:

1. searches the existing configuration blob through `0x00838AFC`;
2. records whether the item is present;
3. computes the size of the rebuilt blob;
4. allocates and fills a replacement buffer;
5. copies existing items or appends new serialized records;
6. commits the replacement through `0x008386FC`;
7. frees the temporary buffer.

### Item representation

```text
descriptor:
  uint16 type
  uint8  length
  pointer value
  pointer mask

serialized:
  uint16 type
  uint8  length
  value[length]
  mask[length]
```

The serialized item size is `3 + 2*length`.

### Type `0x33`

The source-1/D0 wrappers use:

```text
type   0x33
length 6
mask   FF FF FF FF FF FF
```

This is a configuration item requiring exact six-byte matching. The vendor meaning of type `0x33` is still unresolved.

### Configuration blob base

Address `0x00801400` is passed as both the source and destination/commit target by the type-0x33 setter and is read by the getter. It is better classified as:

```text
configuration blob/base candidate
```

rather than a generic service context.

### Integrity check

`0x008386AC` calls `0x00837198` and compares the returned value with:

```text
0x8721BEE2
```

It returns true only on equality. This is consistent with a configuration integrity or validity token.

## Remaining questions

1. What exact inline diagnostic strings surround `cfg_add_item`, finder, validator, and commit functions?
2. Are there other `cfg_*` strings in the image?
3. Does `0x008386FC` replace, persist, or validate the rebuilt blob?
4. What exact name best fits `0x00838AFC`?
5. Is `0x8721BEE2` a checksum residue, signature, or fixed header token?
6. Does the public SDK contain exact cfg symbols or magic constants?
7. What vendor meaning is assigned to item type `0x33`?

## Naming boundary

Accepted:

```text
cfg_add_item
configuration item descriptor
configuration blob/base candidate
cfg_find_item_candidate
cfg_blob_valid_candidate
cfg_blob_commit_replace_candidate
type-0x33 length-6 exact-mask item
```

Not accepted:

```text
BLE address item
MAC item
bonding item
whitelist item
resolving-list item
```


## Accepted string-recovery findings

Correct Thumb ADR resolution recovered:

```text
old config len %d
item[%d] len %d
malloc %d bytes fail!
new config len %d, backup_len %d
item[%02x] found!
```

The writer references exact string:

```text
_cfg_write_to_flash
```

This supports promoting `0x008386FC` to `_cfg_write_to_flash`.

The payload also contains:

```text
cfg_del_item
```

but the report found no raw pointer, LDR, or ADR reference to that string. It is retained string data only under the current static model and does not prove that a reachable delete implementation exists.

## Header and flash-layout refinement

`0x00837198` is not an integrity algorithm. It simply assembles four bytes from `r0[0..3]` into a little-endian `u32`.

Therefore:

```text
0x00837198  load_u32_le
0x008386AC  cfg_blob_magic_valid
0x8721BEE2  cfg_blob_magic
```

The configuration blob layout is:

```text
0x00801400 +0x00  u32 magic = 0x8721BEE2
0x00801400 +0x04  u16 serialized item length
0x00801400 +0x06  serialized items
```

The slot occupies `0x400` bytes. The maximum serialized-item area is `0x3FA` bytes.

`_cfg_write_to_flash` preserves the surrounding 4-KiB sector:

```text
0x00801000..0x008013FF  preserve 0x400-byte prefix
0x00801400..0x008017FF  replace  0x400-byte config slot
0x00801800..0x00801FFF  preserve 0x800-byte suffix
```

The exact low erase/program helper names remain candidates pending ABI or SDK evidence.


## Low flash ABI boundary

The configuration-item and slot-level contracts are closed. The only remaining persistence ambiguity is the exact BlueX naming of low targets `0x893C`, `0x81A0`, `0x8600`, and `0x8916`.

Target `0x8600` matches the public `flash_program(offset,length,buffer)` ABI in all three writer calls. The other three names remain candidates.


## ROM correlation closure

No exact symbol mapping was found for the low flash calls used by
`_cfg_write_to_flash`. This does not change the accepted configuration-item or
flash-slot architecture.

Only the vendor names of the low primitives remain open.
