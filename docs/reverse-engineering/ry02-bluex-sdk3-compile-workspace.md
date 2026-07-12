# RY02 BlueX SDK3 Compile Workspace r2

**Status:** Complete-SDK materialization gate  
**Device interaction:** None

## Why r2 is required

The accepted r1 materialization copied only:

```text
examples/demo/ble_custom_profile
```

That proved the adapter overlay and project edits, but the Keil project contains
relative paths into the surrounding SDK, including:

```text
../../../../components/...
../../../../kernel/...
../../../../platform/...
```

Moving only the example directory into `build/` breaks those paths. Therefore
the r1 materialized tree is not yet compile-ready even though its source
validation passed.

## r2 behavior

The r2 materializer:

```text
copies the complete SDK3 tree into build/
excludes .git and generated Objects/Listings
overlays the accepted RingCLI adapter in place
preserves the original examples/demo/... depth
checks every local FilePath in the template target
checks that the scatter file resolves
retains generic FLASH_MAPPED_ADDR 0x00800000
sets a build-only output name
disables HEX generation
does not invoke ARMCC, image_tool, OTA, or the ring
```

## Acceptance rule

A workspace is accepted only when:

```text
project FilePath entries checked: nonzero
unresolved project paths: 0
scatter exists: True
validation failures: 0
workspace status: PASS
```

After this gate passes, the next step is an ARMCC 5 compile of the `template`
target on a compatible Windows/Keil environment.
