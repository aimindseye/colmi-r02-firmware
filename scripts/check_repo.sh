#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "Compiling Python analysis tools..."
python3 -m compileall -q tools

echo "Checking for accidentally included firmware/APK artifacts..."
mapfile_cmd=(find . -type f \( -name '*.bin' -o -name '*.apk' -o -name '*.aab' -o -name '*.dex' \) -not -path './.git/*')

# macOS ships an older Bash, so avoid mapfile/readarray.
artifacts="$(${mapfile_cmd[@]} || true)"
if [[ -n "$artifacts" ]]; then
  echo "ERROR: binary artifacts found in repository tree:" >&2
  printf '%s\n' "$artifacts" >&2
  exit 1
fi

echo "Checking scripts for obvious absolute local paths..."
if grep -R -n -E '/Users/[^/]+/|/home/[^/]+/' README.md docs tools 2>/dev/null; then
  echo "ERROR: absolute user-specific path found." >&2
  exit 1
fi

echo "Repository checks passed."
