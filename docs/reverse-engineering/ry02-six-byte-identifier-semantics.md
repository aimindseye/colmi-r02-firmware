# RY02 Six-Byte Identifier Semantics

**Firmware:** `RY02_3.00.38_250403.bin`  
**Comparison:** `RY02_3.00.33_250117.bin`  
**Status:** r1 semantics report accepted; masked-record service identified structurally  
**Date:** 2026-07-11

## Proven dataflow

### Runtime state-update path

```text
incoming pointer
  -> compare 6 bytes with state at derived address 0x00208690
  -> return without publication when equal
  -> copy incoming 6 bytes to 0x00208690 when different
  -> set derived flag 0x002086D0 to 1
  -> invoke state/persistence helper
  -> call common helper 0x008385F8(incoming)
  -> publish source 1 / D0
  -> tail-return through shared epilogue
```

### Startup/configuration path

```text
0x00839CA4(output=stack+0x48)
  -> locate a record through 0x00838AFC
  -> copy six bytes from record offset +3

copy another six-byte field from configuration object +8
reverse the six copied bytes into a third buffer
compare extracted field with reversed field
  -> equal: no D0 publication
  -> different:
       call 0x008385F8(reversed field)
       publish source 1 / D0
continue configuration registration
```

## Common helper observation

The visible beginning of `0x008385F8`:

```text
copies input[6] into a local buffer
fills a second six-byte buffer with 0xFF
builds a local record beginning with value 0x0033
stores length 6
stores pointers to both six-byte buffers
```

This resembles construction of a six-byte command or service request, but the downstream call and exact semantics require full CFG analysis.

## Generic-helper observation

Low target `0x3F7A8` behaves like a comparison routine in the two known D0 paths: callers branch on zero for equality.

Low target `0x3F848` behaves like a copy routine and has many callers with varied sizes. The next report will quantify the immediate-size distributions before promoting these labels.

## Interpretation boundary

Currently justified:

```text
six-byte identifier/configuration candidate
byte-order-normalized six-byte state
common six-byte apply/submit helper
record field at offset +3
```

Not currently justified:

```text
BLE public address
BLE random address
MAC address
bonding peer address
device serial number
```


## Accepted semantics-report findings

The completed report validates both the setter and getter paths and reaches the final summary without a runtime error.

### Masked-record descriptor

The service uses this in-memory descriptor:

```c
struct masked_record_descriptor {
    uint16_t field_type;    // +0x00
    uint8_t  length;        // +0x02
    uint8_t *value;         // +0x04
    uint8_t *mask;          // +0x08
};
```

The parser reconstructs serialized entries as:

```text
uint16 type
uint8  length
uint8  value[length]
uint8  mask[length]
```

and advances by:

```text
3 + 2 * length
```

This record structure is proven by the parser CFG.

### Type `0x33`, length `6`

The setter wrapper builds:

```text
type  = 0x0033
len   = 6
value = caller-supplied six bytes
mask  = FF FF FF FF FF FF
```

The getter wrapper builds the same type/length/mask descriptor, searches the serialized record service, and copies six bytes from the matched entry's value field.

The all-`FF` mask establishes exact matching across all six bytes.

### Stable cross-version implementation

Strong `.33` counterparts exist for:

```text
setter wrapper
getter wrapper
record parser
configuration builder
state synchronization helper
```

The masked-record mechanism therefore predates `.38`.

## Revised interpretation

Promoted:

```text
generic six-byte identifier/configuration candidate
    ->
type-0x33 exact-mask record value
```

Still unresolved:

```text
vendor meaning of field type 0x33
service/context meaning of 0x00801400
exact operation performed by core 0x00838914
whether type 0x33 corresponds to a BLE address or another six-byte key
```

The next gate should resolve the service family, not perform more generic six-byte scans.


## Configuration-item service refinement

The exact string `cfg_add_item` identifies the masked-record subsystem as a configuration-item manager.

The six-byte value should now be described as:

```text
type-0x33, length-6, exact-mask configuration item value
```

This is a stronger and safer label than a generic six-byte identifier. The field's protocol meaning remains unresolved.


## Persistent configuration-slot refinement

Type-`0x33` is stored in the serialized configuration blob at `0x00801400`, whose total slot size is `0x400` bytes. Updating the item rebuilds the blob and invokes `_cfg_write_to_flash`.

The item remains vendor-defined despite its persistence in flash.
