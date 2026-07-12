# RY02 BlueX SDK3 RingCLI Adapter Source Gate

**Selected SDK3 example:** `examples/demo/ble_custom_profile`  
**Status:** Exact-source extraction gate, r2 path repair  
**Device interaction:** None

## Why this example is selected

The SDK3 inventory establishes that `ble_custom_profile` contains the required
combination:

```text
128-bit service and characteristic UUID arrays
PERM(UUID_LEN,UUID_128)
attm_svc_create_db_128
GATTC_WRITE_REQ_IND
gattc_write_req_ind_handler
advertising setup
```

This is a closer match than the generic profile helpers and is the correct base
for the first build-only RingCLI adapter.

## Verified build boundary

The SDK3 base project uses:

```text
startup_apollo00_ble.s
config/user_link.txt
FLASH_MAPPED_ADDR 0x00800000
```

That is the generic SDK build layout. It must not be changed to the accepted
R02 application location until the R02 boot and linker contract is independently
closed.

## Gate objective

Run:

```text
tools/extract_bluex_sdk3_ringcli_adapter_contract.py
```

The generated report must provide exact source for:

```text
service/attribute index order
128-bit UUID byte arrays
attribute permissions and maximum lengths
service database creation
write request confirmation
CCCD write handling
notification command allocation and fields
connection index usage
advertising data setup
startup and scatter/linker placement
```

## Acceptance rule

The next adapter overlay is generated only after the source gate reports:

```text
required failures: 0
source gate: PASS
device action: none
```

The adapter remains build-only and may not generate or install an R02 OTA image.


## r2 path repair

The r1 extractor looked for the custom-profile database at:

```text
examples/demo/ble_custom_profile/code/profile/user_profile.c
```

The SDK3 tree places that file at:

```text
examples/demo/ble_custom_profile/code/user_profile.c
```

The r1 report's two failures were therefore one extractor path defect, not an
SDK3 source deficiency. r2 also avoids emitting a duplicate anchor failure when
a required file is absent.
