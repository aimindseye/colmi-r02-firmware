# RY02 Reverse-Engineering Evidence Index

**Firmware:** `RY02_3.00.38_250403.bin`  
**Container under analysis:** `release/ry02-3.00.38-faster-raw-r1/RY02_3.00.38_250403.bin`  
**Application runtime base:** `0x00824000`  
**Inner executable body:** `0x00824400`  
**Status:** Accepted offline static-analysis baseline; machine verification passed  
**Updated:** 2026-07-11

This index maps the accepted command-5/OTA conclusions to the analysis reports that support them. It distinguishes positive evidence from absence-of-signature findings.

## Confidence legend

| Level | Meaning |
|---|---|
| High | Directly demonstrated by coherent disassembly, literals, call flow, or repeated cross-reference evidence |
| Medium-high | Strongly supported, but an exact vendor symbol or full downstream implementation is unavailable |
| Medium | Best current interpretation from multiple observations; alternative implementations remain possible |
| Low | Tentative label retained only to guide future analysis |

## Address conventions

- Payload offset `0x00000` maps to runtime `0x00824000`.
- Container file offset equals payload offset plus outer header size `0x50`.
- Low targets such as `0x0000029C` and `0x00013694` are outside the extracted application payload and are treated as ROM/platform targets unless later evidence contradicts that model.
- Physical staging address `0x0004D000` corresponds to staging XIP address `0x0084D000`.

## Accepted findings

| ID | Finding | Confidence | Primary evidence |
|---|---|---:|---|
| E-001 | The `.38` payload length is `0x1CD14`; application runtime base is `0x00824000`. | High | Container/header analysis; all runtime-target reports |
| E-002 | Command dispatch maps commands 1–5 to handlers `0x0082AC80`, `0x0082AC92`, `0x0082AD2A`, `0x0082AE26`, and `0x0082AE62`. | High | Command-switch and wrapper disassembly reports |
| E-003 | Command 3 strips the outer `0x50`-byte container header and stages the inner image at physical `0x4D000` / XIP `0x0084D000`. | High | Command-3 handler and flash-wrapper analysis |
| E-004 | Command 4 validates OTA phase and staged byte count; no application-side signature, version-rejection, or activation step has been demonstrated. | High for observed checks; medium-high for negative scope | Command-4 handler analysis |
| E-005 | Command 5 requires phase 4, moves to phase 5, performs cleanup, saves persistent state, restarts a timer for 1000 ms, and returns without a success ACK. | High | Command-5 handler disassembly; `ry02-v38-time-d3-persistence-xrefs.txt` |
| E-006 | `0x002087BC` is the base of a persisted `0xA4`-byte application/time-state record whose marker is `0xA1B2C3E5`. | High | Persistent-record initialization/save analysis; `ry02-v38-helper-82580e-and-state-2087c0.txt` |
| E-007 | `0xA1B2C3E5` is a general record marker, not an OTA activation flag. | High | Record initialization, validation, and save paths |
| E-008 | Timer/work object `0x0020A7B8` is restarted by command 5 through wrapper `0x0082AC3C` with delay 1000 ms. | High | Timer literal/caller analysis; exact entrypoint disassembly |
| E-009 | Timer callback `0x0082AC4A` calls `0x0082580E`, stores the result at state `+0x04`, publishes `(1,0xD3)` through low target `0x29C`, and returns. | High | Exact callback disassembly; `ry02-v38-time-d3-persistence-xrefs.txt` |
| E-010 | `0x0082580E` is a seconds-based current-time getter using a low-frequency counter, a saved reference, and 32000/32768 ticks-per-second conversion. | High | `ry02-v38-helper-82580e-and-state-2087c0.txt`; caller analysis |
| E-011 | `0x008371AE` behaves as an unsigned quotient/remainder helper. | High | Repeated callers with divisors 60 and other time units |
| E-012 | Low target `0x0000029C` is a returning two-argument publication candidate; `r0` behaves as source/category and `r1` as event ID. It is not proven to be SDK `bx_public`. | Medium-high | `ry02-v38-low-29c-caller-family.txt` |
| E-013 | The separate D3 publisher at `0x00824B6A` has no direct callers or raw pointers and is an unused-retained-code candidate. | Medium-high | `ry02-v38-d3-d5-publisher-family.txt` |
| E-014 | The `0x4926` D0–D3 selector wrappers have no callers or pointers and are unrelated retained ROM-API veneers. | High | `ry02-v38-low-4926-wrapper-callers.txt`; pointer-reference report |
| E-015 | The application contains no conventional AIRCR / `NVIC_SystemReset()` sequence. | High | `ry02-v38-reset-primitive-scan.txt` |
| E-016 | No credible SDK-style `jump_table[PLATFORM_RESET](0)` call shape was found among indirect `BLX` sites. | Medium-high | `ry02-v38-platform-reset-indirect-call-candidates.txt` |
| E-017 | No direct application-side BlueX watchdog MMIO reference or `0x76` feed signature was found. | High | `ry02-v38-watchdog-mmio-scan.txt` |
| E-018 | Public SDK3 `platform_reset()` uses BlueX AWO reset helpers, not AIRCR, for normal reset errors. | High | `sdk3-v338-platform-reset-source-body.txt`; `sdk3-v338-awo-reset-signatures.txt` |
| E-019 | The RY02 application contains neither public SDK AWO base `0x20201000` nor reset register `0x20201040`. | High | `ry02-v38-awo-reset-mmio-scan.txt` |
| E-020 | The proven application-visible OTA chain reaches `0x29C(1,0xD3)` and then returns normally; final reset and staged-image activation remain below the visible application boundary. | Medium-high | E-005 through E-019; E-021 through E-023 |
| E-021 | The six `0x29C` callers form a coherent family: source/category `1` publishes D0 or D3, while source/category `3` publishes paired D4/D5 status events. | Medium-high | `ry02-v38-low-29c-caller-family.txt` |
| E-022 | `0x29C` is not a general synchronous reset primitive: D0 callers continue through ordinary application code and the active D3 callback contains a normal return after the call. | High | `ry02-v38-low-29c-caller-family.txt` |
| E-023 | The SDK object/library inventory contains only unrelated MPU9250 motion and pedometer algorithm libraries; strict symbol matching found no BlueX event, OTA, delayed-work, jump-table, or reset symbols. | High | `sdk3-object-library-inventory.txt`; `sdk3-object-library-reset-symbol-check-strict.txt` |
| E-024 | The active D3 callback `0x0082AC4A` has one Thumb pointer reference at `0x0082AF04`, proving data-driven timer/work reachability. | High | `ry02-v38-29c-producer-provenance.txt` |
| E-025 | The retained D3 helper `0x00824B6A` has no direct caller or raw/Thumb pointer; it remains unreachable under the current static model. | High for measured reachability | `ry02-v38-29c-producer-provenance.txt` |
| E-026 | The demonstrated source-3 D4/D5 caller passes `1`, so the known active path publishes D4; no direct active D5 path is demonstrated. | High | `ry02-v38-29c-producer-provenance.txt` |
| E-027 | Source/category `1` participates in completion, state-update, startup/configuration, and delayed-write flows, so it is not OTA-specific. | Medium-high | `ry02-v38-29c-producer-provenance.txt` |
| E-028 | Strong heuristic `.33` counterparts exist for five producer functions, showing that the event-producer family predates `.38`. | Medium-high | `ry02-v38-29c-producer-provenance.txt` |
| E-029 | The r1 linear decoder crossed the external tail branch at `0x00828E0C`; bytes at `0x00828E0E..0x00828E30` and their `0x002087BC` literal belong to an adjacent function, not producer `0x00828DD2`. | High | Manual review of `ry02-v38-29c-producer-provenance.txt`; repaired r2 tool |
| E-030 | The r2 report confirms producer `0x00828DD2` contains 25 CFG-reachable instructions and exits through tail branch `0x00828E0C -> 0x008288C0`; its only reachable RAM literal is `0x00208696`. | High | `ry02-v38-29c-producer-provenance-r2.txt` |
| E-031 | The three source-1/D0 producers reference distinct but potentially related RAM object families: `0x00200120`/`0x002098F0`, `0x00208696`, and `0x00208670`/`0x00208449`/`0x00209A0F`. | High for references; semantics unresolved | `ry02-v38-29c-producer-provenance-r2.txt` |
| E-032 | The state-update path derives six-byte state base `0x00208690` from literal `0x00208696 - 6` and change flag `0x002086D0` from `0x00208696 + 0x3A`. | High | `ry02-v38-29c-producer-provenance-r2.txt` |
| E-033 | The first source-1/D0 r1 report aborted when a whole-payload literal scan encountered an undecodable halfword and dereferenced a null instruction. This is a tool failure; RAM-object counts and six-byte-helper inventory from that run are unavailable. | High | r1 execution log; repaired `trace_ry02_source1_d0_subsystem.py` r2 |
| E-034 | The repaired source-1/D0 r2 report reaches the final summary and completes RAM-object and six-byte-helper inventories without a traceback. | High | `ry02-v38-source1-d0-subsystem-provenance-r2.txt` |
| E-035 | The D0 state updater derives six-byte state address `0x00208690` from anchor `0x00208696 - 6`, copies incoming data only on change, sets flag `0x002086D0`, calls common helper `0x008385F8`, then publishes `(1,D0)`. | High | `ry02-v38-source1-d0-subsystem-provenance-r2.txt` |
| E-036 | The startup/configuration path extracts one six-byte field through `0x00839CA4`, reverses another six-byte field, compares them, calls `0x008385F8` on mismatch, and publishes `(1,D0)`. | High | `ry02-v38-source1-d0-subsystem-provenance-r2.txt` |
| E-037 | Six-byte width is not subsystem-specific: the compare candidate has two six-byte calls in the D0 family, while the copy candidate has thirteen six-byte calls across unrelated functions. | High | `ry02-v38-source1-d0-subsystem-provenance-r2.txt` |
| E-038 | `0x00200120` is broadly referenced by unrelated code and is better treated as a shared callback/service object than a source-1-specific object. | Medium-high | `ry02-v38-source1-d0-subsystem-provenance-r2.txt` |
| E-039 | The six-byte setter and getter use a descriptor containing 16-bit field type, 8-bit length, value pointer, and mask pointer. | High | `ry02-v38-six-byte-identifier-semantics.txt` |
| E-040 | Serialized records contain type, length, value[length], and mask[length], with stride `3 + 2*length`. | High | parser `0x00838AFC` in `ry02-v38-six-byte-identifier-semantics.txt` |
| E-041 | Both wrappers use field type `0x33`, length `6`, and an all-`FF` six-byte mask; the mask represents exact matching across all bytes. | High | setter `0x008385F8`; getter `0x00839CA4` |
| E-042 | Setter `0x008385F8` has exactly two callers, both source-1/D0 change paths, and forwards the descriptor to core `0x00838914`. | High | `ry02-v38-six-byte-identifier-semantics.txt` |
| E-043 | Getter `0x00839CA4` validates context `0x00801400`, locates the type-0x33 exact-mask record through `0x00838AFC`, and copies its six-byte value. | High | `ry02-v38-six-byte-identifier-semantics.txt` |
| E-044 | Strong `.33` counterparts exist for the setter, getter, parser, configuration builder, and state-sync helpers, so the masked-record service predates `.38`. | Medium-high | `ry02-v38-six-byte-identifier-semantics.txt` |
| E-045 | The vendor meaning of field type `0x33` remains unresolved; BLE/MAC/bonding interpretations are not yet justified. | High as an interpretation boundary | current evidence set |
| E-046 | Function `0x00838914` references exact embedded string `cfg_add_item`; this is direct naming evidence for the configuration-item core. | High | `ry02-v38-masked-record-service.txt` |
| E-047 | `cfg_add_item` accepts at most `0x20` descriptors, checks existing items, computes rebuilt size, allocates a replacement blob, copies/appends records, calls `0x008386FC`, frees the buffer, and returns status. | High | CFG of `0x00838914` |
| E-048 | The type-0x33 setter invokes `cfg_add_item(0x00801400, 0x00801400, descriptor, 1)`, supporting an in-place configuration-blob update model. | High | caller `0x00838636` |
| E-049 | Address `0x00801400` is better classified as a configuration blob/base candidate than a generic service context. | Medium-high | setter/getter argument use and parser field access |
| E-050 | Validator `0x008386AC` compares helper `0x00837198` output with fixed value `0x8721BEE2`; this is consistent with a configuration integrity/validity token. | Medium-high | validator CFG |
| E-051 | The broad SDK keyword search yielded 11,254 mostly unrelated matches and is not useful naming evidence; exact symbol/magic searches are required. | High | `ry02-v38-masked-record-service.txt` |
| E-052 | Correct ADR recovery identifies `_cfg_write_to_flash`, `old config len %d`, `item[%d] len %d`, `new config len %d, backup_len %d`, and `item[%02x] found!`. | High | `ry02-v38-cfg-item-service.txt` |
| E-053 | Function `0x008386FC` references exact string `_cfg_write_to_flash` and is the persistent configuration writer. | High | `ry02-v38-cfg-item-service.txt` |
| E-054 | Function `0x00837198` is a plain little-endian four-byte loader, not an integrity algorithm; `0x008386AC` is a magic-value validity check. | High | CFGs of `0x00837198` and `0x008386AC` |
| E-055 | The configuration header is `u32 magic 0x8721BEE2`, `u16 item_length`, followed by serialized items at offset `6`. | High | cfg validity, finder, and add-item CFGs |
| E-056 | The configuration slot occupies `0x00801400..0x008017FF` (`0x400` bytes), leaving `0x3FA` bytes for serialized items after the six-byte header. | High | parser bound and writer geometry |
| E-057 | `_cfg_write_to_flash` preserves a `0x400`-byte prefix and `0x800`-byte suffix while replacing the `0x400`-byte configuration slot inside 4-KiB sector `0x00801000..0x00801FFF`. | High | writer CFG |
| E-058 | The payload contains `cfg_del_item`, but the cfg-item report found no raw, LDR, or ADR reference; no reachable delete implementation is established. | High for measured reachability | `ry02-v38-cfg-item-service.txt` |
| E-059 | Exact searches of 4,945 SDK/demo text files found no cfg symbols or magic constant matches. | High | `ry02-v38-cfg-item-service.txt` |
| E-060 | The configuration flash-layout report completed through `SUMMARY` and confirms the six-byte header, `0x400`-byte slot, and 4-KiB containing-sector model. | High | `ry02-v38-cfg-flash-layout.txt` |
| E-061 | Target `0x00008600` is called by `_cfg_write_to_flash` three times as `(destination, length, source)`, matching the public SDK `flash_program(offset,length,buffer)` ABI shape. | High for ABI shape; address identity pending | `ry02-v38-cfg-flash-layout.txt`; SDK `flash_wrapper.h` |
| E-062 | Target `0x000081A0` receives selector `2` or `4` in `r0` and address in `r1`; this differs from public `flash_erase(offset,type)` argument order. | High | `ry02-v38-cfg-flash-layout.txt`; SDK `flash_wrapper.h` |
| E-063 | Targets `0x0000893C` and `0x00008916` form a begin/end pair around erase/program operations using an address plus saved-state byte. | Medium-high | `_cfg_write_to_flash` and second caller family |
| E-064 | `cfg_del_item` remains unreferenced: one string occurrence, zero raw pointers, zero LDR references, and zero ADR references. | High | `ry02-v38-cfg-flash-layout.txt` |
| E-065 | The flash source scan returned 171 API-name matches; these establish public prototypes but do not map low ROM addresses to symbols. | High as an interpretation boundary | `ry02-v38-cfg-flash-layout.txt` |
| E-066 | Exact address correlation scanned 121 ROM-symbol/linker/map/scatter files and found zero matches for `0x893C`, `0x81A0`, `0x8600`, and `0x8916`. | High | `ry02-v38-flash-rom-abi.txt` |
| E-067 | The four low-target caller counts are identical in `.38` and `.33`: `2`, `5`, `6`, and `2`, respectively. | High | `ry02-v38-flash-rom-abi.txt` |
| E-068 | Public SDK definitions confirm `flash_program(offset,length,buffer)` and `flash_erase(offset,type)`; `0x8600` matches the former ABI shape while `0x81A0` conflicts with the latter argument order. | High for ABI comparison | `ry02-v38-flash-rom-abi.txt` |
| E-069 | No exact vendor symbol can be promoted for the four low targets from the available SDK corpus. Repeating the same address scan is not useful. | High as an interpretation boundary | `ry02-v38-flash-rom-abi.txt` |
| E-070 | Further low-flash progress requires source-semantic comparison of erase enums, integration APIs, cache routines, boot assembly, and application wrappers. | High as next-gate rationale | current evidence set |
| E-071 | The public `erase_t` enumeration assigns values `0..4` to page, sector, 32-KiB block, 64-KiB block, and chip erase. | High | `ry02-v38-flash-primitive-semantics.txt` |
| E-072 | RY02 selector `2` is used while erasing the known 4-KiB configuration sector, so `0x81A0` cannot consume the public `erase_t` values directly. | High | `_cfg_write_to_flash`; public `erase_t` definition |
| E-073 | Public/boot flash-cache routines exist, but their zero-argument contracts do not match the RY02 begin/end pair `(address,&state)` and `(state)`. | High for ABI mismatch | `ry02-v38-flash-primitive-semantics.txt` |
| E-074 | The source-semantics report did not produce a unique source/assembly identity for any of the four low addresses; their conservative candidate labels remain appropriate. | High as an interpretation boundary | `ry02-v38-flash-primitive-semantics.txt` |
| E-075 | Generic low-flash address, signature, and common-name scans are closed for the current corpus. Exact naming requires a compatible ROM image or symbol map. | High as a stop condition | current evidence set |
| E-076 | A deterministic verifier is required to assert the accepted `.38` SHA, command-5 chain, delayed D3 callback, `0x29C` family, negative reset anchors, configuration anchors, and low-flash counts. | High as next-gate rationale | `ry02-accepted-baseline-verifier.md` |
| E-077 | The accepted-baseline verifier completed with 31 checks passed, 0 required failures, 0 optional warnings, and final status `PASS`. | High | `ry02-v38-accepted-baseline-verification.txt` |
| E-078 | The verified `.38` image matches stock SHA256 `dbf64e3d...6487e`, container length `0x1CD64`, and payload length `0x1CD14`. | High | `ry02-v38-accepted-baseline-verification.txt` |
| E-079 | The exact command-5 call sequence, 1000-ms timer construction, callback pointer `0x0082AC4B`, source-1/D3 publication, and callback return all pass deterministic assertions. | High | `ry02-v38-accepted-baseline-verification.txt` |
| E-080 | The complete six-caller `0x29C` family, ordinary D0 continuation, absence of raw `0x29C/0x29D` pointers, and absence of direct AIRCR literal all pass deterministic assertions. | High | `ry02-v38-accepted-baseline-verification.txt` |
| E-081 | Configuration magic/string anchors and low-flash caller counts `2/5/6/2` pass for `.38`; optional `.33` identity and count checks also pass. | High | `ry02-v38-accepted-baseline-verification.txt` |
| E-082 | The exploratory application-side baseline is promoted. Future maintenance uses the firmware verifier and repository bundle validator rather than additional generic scans. | High as process state | `ry02-accepted-baseline.md` |

## Evidence reports

The following reports should be preserved under `analysis/` or an equivalent evidence archive:

| Report | Purpose |
|---|---|
| `ry02-v38-helper-82580e-and-state-2087c0.txt` | Current-time getter, callers, and state-record references |
| `ry02-v38-time-d3-persistence-xrefs.txt` | Time helpers, persistent-save calls, command-5 callback, and related cross-references |
| `ry02-v38-low-4926-wrapper-callers.txt` | Generated `0x4926` ROM-API veneer family and D0–D3 wrapper reachability |
| `ry02-v38-d3-d5-publisher-family.txt` | D3/D4/D5 publisher functions, call counts, and pointer counts |
| `ry02-v38-reset-primitive-scan.txt` | AIRCR, VTOR, SCB, and reset-key scan |
| `sdk3-v338-reset-source-anchors.txt` | Public SDK reset/watchdog source inventory |
| `ry02-v38-platform-reset-indirect-call-candidates.txt` | Indirect `BLX` candidates for SDK jump-table reset ABI |
| `ry02-v38-watchdog-mmio-scan.txt` | BlueX watchdog base and feed-signature scan |
| `sdk3-v338-platform-reset-implementation.txt` | SDK callers and available ELF/symbol inventory |
| `sdk3-v338-platform-reset-source-body.txt` | Exact SDK `platform_reset()` source implementation |
| `sdk3-doc-demo-revisions.txt` | SDK3_DOC and SDK3_Demo revisions and tags |
| `sdk3-doc-demo-ota-reset-search.txt` | OTA, event, delayed-work, and reset references in companion repositories |
| `sdk3-v338-awo-reset-signatures.txt` | Public SDK AWO reset base, register, masks, and helper paths |
| `ry02-v38-awo-reset-mmio-scan.txt` | RY02 scan for `0x20201000`, `0x20201040`, and related literals |
| `ry02-v38-low-29c-caller-family.txt` | Six direct callers, local argument provenance, return behavior, and D0/D3/D4/D5 family classification |
| `sdk3-object-library-inventory.txt` | Inventory proving that available SDK archives are unrelated MPU9250 algorithm libraries |
| `sdk3-object-library-reset-symbol-check-strict.txt` | Token-aware closure scan showing no relevant BlueX OTA/event/reset symbols |
| `ry02-v38-29c-producer-provenance.txt` | r1 producer reachability, pointers, parents, RAM literals, and `.33` heuristic counterparts; retain with documented boundary caveat |
| `ry02-v38-29c-producer-provenance-r2.txt` | CFG-corrected replacement report generated by the r2 tool |
| `docs/reverse-engineering/ry02-source1-d0-subsystem.md` | Scope and interpretation limits for the next source-1/D0 provenance gate |
| `ry02-v38-source1-d0-subsystem-provenance.txt` | Partial r1 report: function-provenance sections completed, but RAM-object scan aborted before completion; do not use as a complete evidence report |
| `ry02-v38-source1-d0-subsystem-provenance-r2.txt` | Complete repaired report generated by tool revision r2 |
| `docs/reverse-engineering/ry02-six-byte-identifier-semantics.md` | Proven six-byte flow and interpretation limits for the next helper-semantics gate |
| `ry02-v38-six-byte-identifier-semantics.txt` | Generated helper CFG, size-distribution, RAM-window, and cross-version report |
| `docs/reverse-engineering/ry02-masked-record-service.md` | Proven record layout and scope for the service-semantics gate |
| `ry02-v38-masked-record-service.txt` | Generated service-core, string, field-type, context, and SDK-source report |
| `docs/reverse-engineering/ry02-cfg-item-service.md` | Accepted cfg_add_item naming evidence and next-gate scope |
| `ry02-v38-cfg-item-service.txt` | Generated cfg-string, ADR, commit, finder, integrity, and exact-source report |
| `docs/reverse-engineering/ry02-cfg-flash-layout.md` | Accepted header/slot/sector model and low-flash scope |
| `ry02-v38-cfg-flash-layout.txt` | Generated flash-helper ABI, geometry, string-reachability, and cross-version report |
| `docs/reverse-engineering/ry02-flash-rom-abi.md` | Scope and evidence hierarchy for low flash address-to-symbol correlation |
| `ry02-v38-flash-rom-abi.txt` | Generated .38/.33 caller, ROM-symbol address, and public-prototype report |
| `docs/reverse-engineering/ry02-flash-primitive-semantics.md` | Accepted low-target contracts and source-semantic gate scope |
| `ry02-v38-flash-primitive-semantics.txt` | Generated wrapper CFG, erase-enum, flash-source, boot-ASM, and semantic-matrix report |
| `docs/reverse-engineering/ry02-accepted-baseline-verifier.md` | Scope and acceptance contract for the deterministic regression gate |
| `ry02-v38-accepted-baseline-verification.txt` | Generated PASS/FAIL report for accepted `.38` static anchors |
| `docs/reverse-engineering/ry02-accepted-baseline.md` | Authoritative promoted application-side static-analysis baseline |
| `analysis/ry02-accepted-baseline.json` | Machine-readable accepted baseline and interpretation boundaries |
| `tools/validate_ry02_baseline_bundle.py` | Repository evidence-bundle integrity validator |
| `docs/reverse-engineering/ry02-29c-producer-provenance.md` | Accepted producer findings and r1 boundary correction |

## Negative-evidence interpretation

A zero signature result means only that the scanned mechanism is not directly represented in the extracted application image using the tested form.

It does not exclude:

- ROM-resident reset implementation;
- a controller task consuming an application event;
- an indirect dispatch table owned outside the application image;
- a different RF03 platform ABI;
- bootloader behavior after reset;
- computed addresses that do not leave literal constants in the application.

The accepted conclusion is therefore not “event `0xD3` is reset.” It is:

```text
The application-visible command-5 path ends at low dispatcher call
0x29C(1,0xD3). The final reset and boot transition remain unresolved
below that boundary.
```

## Open questions

1. Which subsystem owns source/category `1`, and which subsystem owns source/category `3`?
2. What entity consumes source/category `1`, event `0xD3` after the returning publication call?
3. How does the RF03 platform perform reset if it differs from public Apollo00 SDK3?
4. What bootloader condition marks the staged image at physical `0x4D000` as acceptable?
5. Is activation copy-based, bank-based, or metadata-driven?
6. What rollback behavior applies after an invalid staged image?
7. What do the opaque inner-header fields represent?

## Recommended maintenance

- Keep `docs/reverse-engineering/ry02-command5-ota-architecture.md` as the human-readable accepted architecture.
- Keep `analysis/ry02-v38-symbol-map.csv` as the machine-readable address map.
- Generate `analysis/ry02-v38-29c-producer-provenance.txt` with `tools/trace_ry02_29c_producer_provenance.py` before assigning subsystem names to the producer family.
- Add new labels only when backed by a report and update both this index and the CSV.
- Preserve unknown labels as candidates; do not replace them with public SDK names based only on similarity.
- Do not perform another OTA or timer patch solely to resolve the remaining ROM-side questions.
