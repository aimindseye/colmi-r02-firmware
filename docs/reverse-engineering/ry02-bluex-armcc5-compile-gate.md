# RY02 BlueX ARMCC 5 Compile Gate r1

**Workspace gate:** accepted  
**Compiler target:** Keil `template` target  
**Mode:** rebuild-only  
**Device interaction:** None

## Accepted precondition

The complete SDK3 workspace passed with:

```text
project FilePath entries checked: 102
unresolved project paths: 0
scatter exists: True
validation failures: 0
workspace status: PASS
compile-workspace status: PASS
```

## Why a Windows/Keil environment is required

The project identifies:

```text
ToolsetName: ARM-ADS
ARMCC 5.06 update 7
startup_apollo00_ble.s
user_link.txt
rom_syms_armcc.txt
```

The first authoritative compile should therefore use the SDK's intended ARMCC 5
toolchain rather than substituting GCC or Clang.

## Gate behavior

The provided PowerShell script:

```text
rebuilds only target template
refuses to run when CreateHexFile is not 0
requires output name ry02_ringcli_adapter_buildonly
requires the AXF output
rejects HEX, BIN, OTA, and .38 outputs
does not run image_tool
does not package or install firmware
```

Warnings are recorded but do not fail r1. Any compiler/linker error fails.

## Expected artifacts

Allowed:

```text
Objects/ry02_ringcli_adapter_buildonly.axf
compiler objects and listings
uVision build log
```

Forbidden:

```text
*.hex
*.bin
*.ota
*.38
```
