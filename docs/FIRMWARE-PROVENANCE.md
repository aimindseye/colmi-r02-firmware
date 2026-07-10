# Firmware Provenance and Known Hashes

This repository does not redistribute vendor firmware.

## RY02 `.38`

```text
Hardware:  RY02_V3.0
Firmware:  RY02_3.00.38_250403
Size:      118116 bytes
SHA-256:   dbf64e3dc9aef112a4d69e46e516efb27f2ed2e3dc1d2d3f1af75939cc46487e
```

The same hash was obtained from:

1. the vendor OTA download used during research; and
2. the file cached by the official QRing Android application at:

```text
/sdcard/Android/data/com.app.cq.ring/files/dfu/RY02_3.00.38_250403.bin
```

The two files matched with `cmp -s`.

## RY02 `.33`

```text
Firmware:  RY02_3.00.33_250117
Hardware:  RY02_V3.0
Size:      112852 bytes
SHA-256:   3eaad32f25a1734b93b63b86c6a0032c3444b68e7027faf3724bd5148dd4dbcd
```

Public comparison source:

- <https://github.com/atc1441/ATC_RF03_Ring/tree/main/OTA_firmwares>

## Older comparison images

```text
R02_3.00.17_240903.bin
SHA-256: df02a578fc90bd88703768cc0f94d17a1f2f65a32c0151b7297d48102a521701

R02_3.00.06_240523.bin
SHA-256: a2e279fc201065b85121d5cc28ded07f3c148952b3524ca3501aa03e657dfc58
```

These older images use a different `0x100` CRC32 container and are retained only for structural and semantic comparison.

## Policy

Before analyzing any local image:

```bash
shasum -a 256 path/to/image.bin
python3 tools/validate_ry02_container.py path/to/image.bin
```

Do not commit `.bin` files to this repository.
