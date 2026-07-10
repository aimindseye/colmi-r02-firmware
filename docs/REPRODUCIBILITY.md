# Reproducing the Offline Analysis

## Requirements

- Python 3.11 or newer recommended;
- Capstone 5.x;
- local, legally obtained firmware images;
- no hardware connection is required for the tools in this repository.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-analysis.txt
```

## Expected local layout

```text
downloads/qring-latest/RY02_3.00.38_250403.bin
vendor/atc-ota-firmwares/RY02_3.00.33_250117.bin
vendor/atc-ota-firmwares/R02_3.00.17_240903.bin
vendor/atc-ota-firmwares/R02_3.00.06_240523.bin
vendor/ATC_RF03_Ring/
```

These paths are ignored by Git.

## Validate stock `.38`

```bash
python3 tools/validate_ry02_container.py \
  downloads/qring-latest/RY02_3.00.38_250403.bin
```

Expected SHA-256:

```text
dbf64e3dc9aef112a4d69e46e516efb27f2ed2e3dc1d2d3f1af75939cc46487e
```

## Compare firmware families

```bash
python3 tools/compare_atc_ota_family.py \
  | tee analysis/atc-ota-family-comparison.txt
```

Expected top direct predecessor: `RY02_3.00.33_250117.bin`.

## Verify `.33 -> .38` raw-path relocation

```bash
python3 tools/compare_ry02_33_38_raw_path.py \
  | tee analysis/ry02-33-38-raw-path-comparison.txt
```

Expected decisive result:

```text
.33 timer site: 0x1dbe
.38 timer site: 0x1dde
Timer-site relocation delta: +0x20
```

## Trace the timer call

```bash
python3 tools/trace_ry02_raw_timer_call.py \
  | tee analysis/ry02-raw-timer-call-trace.txt
```

Expected `.38` call:

```text
0x1DE8 -> 0x376C
```

The last writes to `r2` before the call should be:

```text
movs r2, #0x7d
lsls r2, r2, #3
```

## Inspect the callback

```bash
python3 tools/inspect_ry02_raw_callback.py \
  | tee analysis/ry02-38-raw-callback.txt
```

Expected mapping:

```text
callback pointer 0x00825B45 -> payload+0x1B44
```

## Enumerate timer periods

```bash
python3 tools/list_ry02_timer_periods.py \
  | tee analysis/ry02-timer-period-callers.txt
```

Expected known periodic values below 1000 include `10`, `30`, `40`, `100`, `320`, and `400`.

## Compare stock and modified container mechanics

The acceptance-header tool needs local paths for the public ATC patched `.06` image and the local experimental `.38` image. It validates format and differences; it does not claim flash safety.

```bash
python3 tools/analyze_ota_acceptance_headers.py
```

## Repository check

```bash
./scripts/check_repo.sh
```

This compiles the Python sources and checks that common firmware/APK artifacts are not present in the repository tree.
