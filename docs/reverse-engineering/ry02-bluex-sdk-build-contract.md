# RY02 BlueX SDK Build Contract

**Reference SDKm:** `release-v3.3-20210804`  
**Reference SDK3:** `release-v3.3.8-20250117`  
**Status:** Next offline build-contract gate  
**Device interaction:** None

## Accepted preliminary findings

### Startup

The two SDKm startup files are functionally the same. They define:

```text
Cortex-M0+ CMSIS startup
stack size 0x1000
heap size 0x100
35 vector-table words
19 external interrupt vectors
RESET data section
xip_section code section
Reset_Handler -> ARM runtime __main
```

Their only observed difference is spacing on the `EXPORT Reset_Handler` line.

This establishes the generic Apollo00 startup shape, not the R02 load address.
The Keil project or scatter configuration controls placement.

### Generic image-tool configuration

SDKm exposes defaults:

```text
ota_base  = 0x40000
data_base = 0x70000
total_size = 0x80000
```

These do not match the accepted R02 OTA staging base `0x4D000`.

### Boot RAM

The bundled `boot_ram` contains a 0x20-byte header with:

```text
bx_flag
base_addr
length
entry_point
ota_base
data_base
flash configuration
```

It is a RAM-resident boot/image helper and must not be equated automatically
with the R02 on-flash bootloader or the R02 application inner header.

### Current comparison limitation

The previously generated `bluex-sdkm-image-tool-comparison.txt` and
`bluex-sdkm-bootloader-comparison.txt` contain headings only. They provide no
sizes, hashes, or address ranges. No byte-level equality or difference can be
accepted from those reports.

## Gate objective

Run `tools/analyze_bluex_sdk_build_contract.py` to produce one deterministic
report that:

```text
compares artifact SHA256 and sizes
parses bootloader and boot_ram Intel HEX ranges
parses boot_ram ELF load addresses and symbols
decodes the boot_ram header
parses image-tool config.ini
extracts Keil project target/linker settings
compares startup files
searches the R02 payload for plausible vector tables
compares generic SDK defaults with accepted R02 anchors
```

## Interpretation boundary

A successful report may justify beginning a build-only prototype. It does not
prove that a generated SDK image will be accepted by the R02 bootloader and does
not make OTA or direct flashing safe.
