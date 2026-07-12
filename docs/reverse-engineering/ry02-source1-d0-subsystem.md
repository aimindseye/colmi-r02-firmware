# RY02 Source-1 / D0 Subsystem Investigation

**Firmware:** `RY02_3.00.38_250403.bin`  
**Comparison:** `RY02_3.00.33_250117.bin`  
**Status:** r2 complete report accepted  
**Date:** 2026-07-11

## Motivation

The accepted `0x29C` producer report establishes that source/category `1` is used by:

```text
D0 completion flow          0x00826FF8
D0 state-update flow        0x00828DD2
D0 startup/config flow      0x00829E70
D3 delayed timer callback   0x0082AC4A
```

It is therefore a broad application category rather than an OTA-only source.

The three D0 producers are the best remaining path to identify the category semantically.

## Accepted producer facts

### Completion producer

```text
function:       0x00826FF8
caller:         0x008254D4
parent:         0x00825476
RAM literals:   0x00200120, 0x002098F0
event:          (1,D0)
termination:    normal return
```

The caller invokes another function immediately before the producer, so incoming `r0-r3` values are unknown under the ABI-safe provenance model.

### State-update producer

```text
function:       0x00828DD2
caller:         0x00829262
parent:         0x008291E6
RAM literal:    0x00208696
derived base:   0x00208690  (literal - 6)
derived flag:   0x002086D0  (literal + 0x3A)
event:          (1,D0)
termination:    tail branch 0x00828E0C -> 0x008288C0
```

It compares and copies six bytes before publishing D0.

The six-byte shape is consistent with several possible data types, including an address or identifier, but does not prove BLE/MAC semantics.

### Startup/configuration producer

```text
function:       0x00829E70
caller:         0x008249A4
parent:         0x00824988
RAM literals:   0x00208670, 0x00208449, 0x00209A0F
event:          (1,D0)
termination:    normal return
```

It constructs a larger configuration structure, transforms/reverses six bytes, compares those six bytes, publishes D0 on change, and continues through extensive configuration registration.

Its `.33` counterpart at `0x00829DA0` has a strong normalized CFG match.


## Tool execution status

The first r1 execution completed all function-provenance sections but aborted at the start of RAM-object provenance:

```text
RAM target: completion_callback_or_service_object
value: 0x00200120
AttributeError: 'NoneType' object has no attribute 'mnemonic'
```

Cause:

```text
scan_literal_loads()
  -> decoded every halfword-aligned payload position
  -> some positions were data or otherwise undecodable
  -> ldr_literal_value() dereferenced a None instruction
```

This is a tooling defect, not firmware evidence.

Accepted from the partial r1 output:

```text
function CFG boundaries
direct callers
parent candidates
reachable calls and literals
source-1/D0 publication sites
strong .33 counterparts already printed
```

Not accepted from the partial r1 output because those sections never completed:

```text
whole-image RAM-object reference counts
derived RAM-object parent contexts
six-byte helper caller inventory
final summary counts
```

Revision r2 treats undecodable halfword positions as non-instructions and continues the literal scan.

Revision r2 also stops explanatory context windows after a visible return or unconditional tail branch, preventing adjacent functions or literal-pool bytes from appearing as post-call context.

## Investigation targets

The next report should answer:

1. Which functions read and write each D0-associated RAM object?
2. Does `0x00208690` form part of the same structure as `0x00208670`?
3. What selector or message path in parent `0x008291E6` reaches the six-byte state updater?
4. Are the six-byte compare/copy helpers used elsewhere for clearly identifiable data?
5. Does startup parent `0x00824988` initialize the same object family?
6. Are corresponding `.33` objects and parent paths structurally stable?

## Interpretation boundary

The gate may justify labels such as:

```text
six_byte_identifier_state_candidate
configuration_change_event_candidate
completion_state_object_candidate
```

It must not assign:

```text
BLE address
MAC address
device identity
bonding record
```

without corroborating protocol, string, register, or callgraph evidence.


## Accepted r2 findings

The repaired report reaches the final summary without a traceback.

Exact inventory:

```text
0x00200120: raw 7, literal loads 9
0x002098F0: raw 1, literal loads 14
0x00208670: raw 4, literal loads 20
0x00208690: raw 0, literal loads 0
0x00208696: raw 1, literal loads 5
0x002086D0: raw 2, literal loads 4
0x00208449: raw 3, literal loads 5
0x00209A0F: raw 1, literal loads 4
```

`0x00208690` is a derived address, so zero exact literals are expected. The state-update producer derives it from `0x00208696 - 6`.

The six-byte compare candidate has 12 direct callers but only two locally proven six-byte calls; both belong to the source-1/D0 state/configuration producers. The copy candidate has 93 direct callers and thirteen locally proven six-byte calls across unrelated functions. The six-byte width is therefore a generic data shape and not enough to identify the value as a BLE address.

Two D0 paths converge on helper `0x008385F8`:

```text
state updater:
    compare incoming[6] with RAM state
    copy on change
    set change flag
    call 0x008385F8(incoming)
    publish (1,D0)

startup/configuration:
    extract six-byte field through 0x00839CA4
    copy another six-byte field
    reverse its byte order
    compare the two forms
    call 0x008385F8(reversed) on change
    publish (1,D0)
```

This establishes a common six-byte apply/submit pipeline but not its vendor-level meaning.

## Next gate

Analyze the common helper `0x008385F8`, record-field extractor `0x00839CA4`, parser `0x00838AFC`, and RAM window `0x00208640..0x002086DF`. Also measure argument-size distributions for low targets `0x3F7A8` and `0x3F848`.

The goal is to distinguish among:

```text
generic six-byte identifier/configuration
controller address-like record
serialized protocol field
device-address or bonding-related value
```

No BLE/MAC label should be accepted without corroborating helper or protocol evidence.


## Masked-record refinement

The six-byte flow is no longer merely a raw configuration blob. It is the value field of a generic masked-record descriptor with:

```text
field type 0x33
length 6
value caller-supplied
mask FF:FF:FF:FF:FF:FF
```

A paired getter locates a serialized record with the same type, length, and exact mask and returns its six-byte value.

This supports `type33_exact_mask_value_candidate`. It still does not establish the protocol meaning of type `0x33`.


## Configuration-item manager refinement

Both source-1/D0 six-byte update paths converge on a wrapper that invokes exact binary function `cfg_add_item`.

The D0 event therefore follows successful or attempted synchronization of type-`0x33` configuration state. This does not establish the vendor meaning of the item.


## Flash-persistence refinement

The two demonstrated source-1/D0 update paths call `cfg_add_item`, which rebuilds the persistent configuration blob and commits it through `_cfg_write_to_flash`.

For these paths, D0 is now strongly associated with configuration-item synchronization/change rather than a generic unrelated state update. This does not prove the meaning of every D0 producer.
